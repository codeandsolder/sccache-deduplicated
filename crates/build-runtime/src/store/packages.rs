//! Verify original package bytes, stream archive members into the native
//! store, and retain only the normalized tree and unique uncompressed blobs.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Seek},
};

use anyhow::{Context, Result, bail, ensure};
use redb::ReadableDatabase;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{NativeStore, PACKAGES, StagedBlob, TreeLease};
use crate::{
    ContentId, TreeEntry, TreeId, TreeManifest, TreeMetadata, TreePath, TreeTimestamp,
    identity::typed_digest,
};

/// Compression of the original upstream tar package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PackageCompression {
    Tar,
    Gzip,
    Xz,
}

/// Upstream package identity, independent of the normalized content tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PackageSource {
    pub sha256: [u8; 32],
    pub size: u64,
    pub compression: PackageCompression,
}

impl PackageSource {
    /// Parse an upstream SHA-256 checksum, with explicit archive length and codec.
    /// # Errors
    /// Returns an error for an invalid hexadecimal checksum.
    pub fn from_sha256_hex(hash: &str, size: u64, compression: PackageCompression) -> Result<Self> {
        ensure!(
            hash.len() == 64 && hash.is_ascii(),
            "invalid SHA-256 length"
        );
        let mut sha256 = [0; 32];
        for (index, value) in sha256.iter_mut().enumerate() {
            *value = u8::from_str_radix(&hash[index * 2..index * 2 + 2], 16)?;
        }
        Ok(Self {
            sha256,
            size,
            compression,
        })
    }
}

/// Explicit normalization and expansion limits for an original package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackagePolicy {
    pub directory: TreeMetadata,
    pub modified: TreeTimestamp,
    pub max_entries: usize,
    pub max_expanded_bytes: u64,
}

fn package_key(source: PackageSource, policy: PackagePolicy) -> Result<ContentId> {
    // Admission limits are not part of the resulting normalized tree identity.
    Ok(ContentId(typed_digest(
        b"sccache-upstream-package-v1\0",
        &(source, policy.directory, policy.modified),
    )?))
}

impl NativeStore {
    /// Resolve a previously imported exact package without transferring or
    /// decompressing it again. Expansion limits apply to new imports only.
    ///
    /// # Errors
    /// Returns an error for index or storage failure.
    pub fn lookup_package(
        &self,
        source: PackageSource,
        policy: PackagePolicy,
    ) -> Result<Option<TreeLease>> {
        let key = package_key(source, policy)?;
        let id = {
            let read = self.inner.db.begin_read()?;
            let table = read.open_table(PACKAGES)?;
            table.get(&key.0)?.map(|entry| TreeId(*entry.value()))
        };
        id.map_or_else(|| Ok(None), |id| self.lookup_tree(id))
    }

    /// Verify the compressed package against its upstream SHA-256 and length,
    /// then import its files directly into content-addressed storage.
    ///
    /// # Errors
    /// Returns an error for invalid checksums, unsupported or malformed
    /// archives, exceeded expansion limits, or storage failure.
    pub fn import_package(
        &self,
        source: PackageSource,
        policy: PackagePolicy,
        input: impl Read,
    ) -> Result<TreeId> {
        // Verify *before* decompression. A private staged compressed file
        // prevents verification/decode races and is never published as a
        // second permanent representation of the package.
        let limit = source
            .size
            .checked_add(1)
            .context("package size overflow")?;
        let mut hashed = ShaReader {
            reader: input.take(limit),
            hash: Sha256::new(),
        };
        let archive = self.stage_inner(&mut hashed, Some(limit))?;
        ensure!(
            archive.reference().size == source.size,
            "incorrect original package length"
        );
        let digest: [u8; 32] = hashed.hash.finalize().into();
        ensure!(
            digest == source.sha256,
            "incorrect original package SHA-256"
        );
        let mut reader = archive.file.as_file().try_clone()?;
        reader.rewind()?;
        let (manifest, staged) = match source.compression {
            PackageCompression::Tar => read_tar(self, reader, policy)?,
            PackageCompression::Gzip => {
                read_tar(self, flate2::read::MultiGzDecoder::new(reader), policy)?
            }
            PackageCompression::Xz => {
                read_tar(self, lzma_rust2::XzReader::new(reader, true), policy)?
            }
        };
        drop(archive);
        self.publish_tree_indexed(
            &manifest,
            staged.into_values().collect(),
            Some(package_key(source, policy)?),
        )
    }
}

struct ShaReader<R> {
    reader: R,
    hash: Sha256,
}

impl<R: Read> Read for ShaReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(buffer)?;
        self.hash.update(&buffer[..count]);
        Ok(count)
    }
}

struct ImportedTree {
    manifest: TreeManifest,
    staged: BTreeMap<ContentId, StagedBlob>,
    explicit: BTreeSet<TreePath>,
    count: usize,
    bytes: u64,
    policy: PackagePolicy,
}

impl ImportedTree {
    fn add(&mut self, store: &NativeStore, mut entry: tar::Entry<'_, impl Read>) -> Result<()> {
        self.count = self
            .count
            .checked_add(1)
            .context("package entry count overflow")?;
        ensure!(
            self.count <= self.policy.max_entries,
            "package entry limit exceeded"
        );
        let kind = entry.header().entry_type();
        let path = normalize_path(&entry.path_bytes(), kind.is_dir())?;
        let Some(path) = path else {
            ensure!(kind.is_dir(), "non-directory archive root");
            return Ok(());
        };
        ensure!(
            self.explicit.insert(path.clone()),
            "duplicate archive member"
        );
        self.add_parents(&path)?;
        let metadata = TreeMetadata {
            mode: entry.header().mode()? & 0o7777,
            modified: self.policy.modified,
        };
        let value = if kind.is_dir() {
            TreeEntry::Directory(metadata)
        } else if kind.is_file() || kind.is_gnu_sparse() {
            let size = entry.size();
            self.bytes = self
                .bytes
                .checked_add(size)
                .context("expanded package size overflow")?;
            ensure!(
                self.bytes <= self.policy.max_expanded_bytes,
                "expanded package size limit exceeded"
            );
            let staged = store.stage_inner(&mut entry, Some(size))?;
            let blob = staged.reference();
            ensure!(blob.size == size, "archive member size mismatch");
            self.staged.entry(blob.id).or_insert(staged);
            TreeEntry::File { blob, metadata }
        } else if kind.is_symlink() {
            TreeEntry::Symlink {
                target: entry
                    .link_name_bytes()
                    .context("missing symbolic link target")?
                    .into_owned(),
                modified: self.policy.modified,
            }
        } else if kind.is_hard_link() {
            let name = entry.link_name_bytes().context("missing hardlink target")?;
            let target =
                normalize_path(&name, false)?.context("hardlink target cannot be the root")?;
            TreeEntry::Hardlink(target)
        } else {
            bail!("unsupported tar member type {kind:?}");
        };
        if let Some(previous) = self.manifest.entries.insert(path, value.clone()) {
            // Parent directories may have been synthesized before the actual
            // explicit directory record occurred in the archive.
            ensure!(
                matches!(previous, TreeEntry::Directory(_))
                    && matches!(value, TreeEntry::Directory(_)),
                "archive member conflicts with an ancestor"
            );
        }
        ensure!(
            self.manifest.entries.len() <= self.policy.max_entries,
            "package tree entry limit exceeded"
        );
        Ok(())
    }

    fn add_parents(&mut self, path: &TreePath) -> Result<()> {
        let bytes = path.as_bytes();
        for (index, &byte) in bytes.iter().enumerate() {
            if byte == b'/' {
                let parent = TreePath::new(bytes[..index].to_vec())?;
                let entry = self
                    .manifest
                    .entries
                    .entry(parent)
                    .or_insert(TreeEntry::Directory(self.policy.directory));
                ensure!(
                    matches!(entry, TreeEntry::Directory(_)),
                    "archive member traverses a non-directory"
                );
            }
        }
        Ok(())
    }

    fn resolve_hardlinks(&mut self) -> Result<()> {
        // Tar permits forward links and, in practice, chains. Resolve each
        // to an actual file entry and reject cycles or directory targets.
        let paths = self
            .manifest
            .entries
            .iter()
            .filter_map(|(path, entry)| {
                matches!(entry, TreeEntry::Hardlink(_)).then_some(path.clone())
            })
            .collect::<Vec<_>>();
        for path in paths {
            let mut current = path.clone();
            let mut visited = BTreeSet::new();
            loop {
                ensure!(visited.insert(current.clone()), "cyclic archive hardlink");
                match self
                    .manifest
                    .entries
                    .get(&current)
                    .context("missing archive hardlink target")?
                {
                    TreeEntry::File { .. } => break,
                    TreeEntry::Hardlink(target) => current = target.clone(),
                    _ => bail!("archive hardlink target is not a regular file"),
                }
            }
            self.manifest
                .entries
                .insert(path, TreeEntry::Hardlink(current));
        }
        Ok(())
    }
}

fn read_tar(
    store: &NativeStore,
    reader: impl Read,
    policy: PackagePolicy,
) -> Result<(TreeManifest, BTreeMap<ContentId, StagedBlob>)> {
    let mut archive = tar::Archive::new(reader);
    let mut imported = ImportedTree {
        manifest: TreeManifest {
            root: policy.directory,
            entries: BTreeMap::new(),
        },
        staged: BTreeMap::new(),
        explicit: BTreeSet::new(),
        count: 0,
        bytes: 0,
        policy,
    };
    for entry in archive.entries()? {
        imported.add(store, entry?)?;
    }
    imported.resolve_hardlinks()?;
    imported.manifest.validate()?;
    // Ensure the decompressor validates its final checksum. Tar writers may
    // pad the ending record with zero blocks, but not with another archive.
    let mut reader = archive.into_inner();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        ensure!(
            buffer[..count].iter().all(|&byte| byte == 0),
            "unexpected bytes after tar end"
        );
    }
    Ok((imported.manifest, imported.staged))
}

fn normalize_path(mut bytes: &[u8], directory: bool) -> Result<Option<TreePath>> {
    while let Some(rest) = bytes.strip_prefix(b"./") {
        bytes = rest;
    }
    if directory {
        while let Some(rest) = bytes.strip_suffix(b"/") {
            // A slash by itself is absolute, not an archive root entry.
            ensure!(!rest.is_empty(), "absolute archive directory");
            bytes = rest;
        }
        if bytes == b"." || bytes.is_empty() {
            return Ok(None);
        }
    }
    Ok(Some(TreePath::new(bytes.to_vec())?))
}

mod rust_installer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TreeLayer, TreeRecipe};

    fn policy() -> PackagePolicy {
        let modified = TreeTimestamp {
            seconds: 1234,
            nanoseconds: 0,
        };
        PackagePolicy {
            directory: TreeMetadata {
                mode: 0o755,
                modified,
            },
            modified,
            max_entries: 100,
            max_expanded_bytes: 10000,
        }
    }

    fn source(bytes: &[u8], compression: PackageCompression) -> PackageSource {
        PackageSource {
            sha256: Sha256::digest(bytes).into(),
            size: bytes.len() as u64,
            compression,
        }
    }

    fn example_tar() -> Result<Vec<u8>> {
        let mut builder = tar::Builder::new(Vec::new());
        for name in ["component/bin/compiler", "component/lib/helper"] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o755);
            header.set_size(4);
            header.set_cksum();
            builder.append_data(&mut header, name, &b"same"[..])?;
        }
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append_link(&mut header, "component/bin/alias", "component/bin/compiler")?;
        Ok(builder.into_inner()?)
    }

    #[test]
    fn original_package_import_and_recipe_share_files_without_repacking() -> Result<()> {
        use std::io::Write;
        let tar = example_tar()?;
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(&tar)?;
        let gzip = gzip.finish()?;
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let id =
            store.import_package(source(&gzip, PackageCompression::Gzip), policy(), &gzip[..])?;
        assert_eq!(store.stats()?.blobs, 1);
        assert_eq!(store.stats()?.logical_bytes, 4);
        let existing = store
            .lookup_package(source(&gzip, PackageCompression::Gzip), policy())?
            .context("missing original package mapping")?;
        assert_eq!(existing.id(), id);
        drop(existing);
        let recipe = TreeRecipe {
            directories: policy().directory,
            layers: vec![TreeLayer {
                tree: id,
                source: Some(TreePath::new(b"component".to_vec())?),
                destination: Some(TreePath::new(b"toolchain".to_vec())?),
            }],
        };
        let composed = store.publish_recipe(&recipe)?;
        assert_ne!(id, composed);
        assert_eq!(store.stats()?.blobs, 1);
        assert_eq!(store.stats()?.trees, 2);
        store.evict_tree(id)?;
        assert!(
            store
                .lookup_package(source(&gzip, PackageCompression::Gzip), policy())?
                .is_none()
        );
        assert_eq!(store.stats()?.pending_gc_blobs, 0);
        assert!(store.lookup_tree(composed)?.is_some());
        Ok(())
    }

    #[test]
    fn checksum_mismatch_and_expansion_limit_do_not_publish() -> Result<()> {
        let bytes = example_tar()?;
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let mut wrong = source(&bytes, PackageCompression::Tar);
        wrong.sha256[0] ^= 1;
        assert!(store.import_package(wrong, policy(), &bytes[..]).is_err());
        let limited = PackagePolicy {
            max_expanded_bytes: 2,
            ..policy()
        };
        assert!(
            store
                .import_package(source(&bytes, PackageCompression::Tar), limited, &bytes[..])
                .is_err()
        );
        assert_eq!(store.stats()?.blobs, 0);
        assert_eq!(store.stats()?.trees, 0);
        Ok(())
    }
}
