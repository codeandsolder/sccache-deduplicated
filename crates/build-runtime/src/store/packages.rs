//! Verify original package bytes, stream archive members into the native
//! store, optionally retaining the original for compressed delivery.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Seek},
    sync::Mutex,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use bincode::Options;
use redb::ReadableDatabase;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{NativeStore, PACKAGES, StagedBlob, TreeLease, encoding};
use crate::{
    ArchiveLength, BlobRef, ContentId, NativeServiceBusy, PackageArchive, PackageIdentity,
    PackageReceipt, PackageSource, TreeEntry, TreeId, TreeManifest, TreeMetadata, TreePath,
    TreeTimestamp, identity::typed_digest,
};

/// Explicit normalization and expansion limits for an original package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackagePolicy {
    /// Keep the verified original compressed representation for transport.
    pub retain_original: bool,
    pub directory: TreeMetadata,
    pub modified: TreeTimestamp,
    pub max_entries: usize,
    pub max_expanded_bytes: u64,
    /// Maximum decoded tar bytes, including metadata, padding and non-file entries.
    pub max_tar_bytes: u64,
    /// Total path and link metadata budget, including implicit directories.
    pub max_metadata_bytes: u64,
}

/// Scheduler-owned limits for live original-package provisioning. All limits
/// are chosen by the store owner, never by an uploading compiler client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageImportLimits {
    pub retain_original: bool,
    /// Maximum distinct original archives being acquired or decoded concurrently.
    pub max_concurrent_imports: usize,
    pub max_archive_bytes: u64,
    pub max_entries: usize,
    pub max_expanded_bytes: u64,
    pub max_tar_bytes: u64,
    pub max_metadata_bytes: u64,
    pub decoder_memory_bytes: u64,
    pub decoder_timeout_secs: u64,
}

impl PackageImportLimits {
    /// Validate limits before enabling the provisioning endpoint.
    /// # Errors
    /// Returns an error for unusable resource limits.
    pub fn validate(self) -> Result<()> {
        ensure!(
            self.max_concurrent_imports > 0
                && self.max_archive_bytes > 0
                && self.max_archive_bytes < u64::MAX
                && self.max_entries > 0
                && self.max_expanded_bytes > 0
                && self.max_tar_bytes > 0
                && self.max_metadata_bytes > 0
                && self.decoder_memory_bytes > 0
                && self.decoder_timeout_secs > 0,
            "invalid native package import limits"
        );
        Ok(())
    }

    /// Validate the service limits and return canonical archive policy.
    /// # Errors
    /// Returns an error for invalid limits or timestamp normalization failure.
    pub fn policy(self) -> Result<PackagePolicy> {
        self.validate()?;
        let mut policy = PackagePolicy::normalized_archive(
            self.max_entries,
            self.max_expanded_bytes,
            self.max_tar_bytes,
            self.max_metadata_bytes,
        )?;
        policy.retain_original = self.retain_original;
        Ok(policy)
    }
}

impl PackagePolicy {
    /// Shared canonical timestamp and directory modes for archive transport imports.
    /// # Errors
    /// Returns an error if the canonical timestamp cannot be represented.
    pub fn normalized_archive(
        max_entries: usize,
        max_expanded_bytes: u64,
        max_tar_bytes: u64,
        max_metadata_bytes: u64,
    ) -> Result<Self> {
        let modified = TreeTimestamp {
            seconds: i64::try_from(tar::DETERMINISTIC_TIMESTAMP)?,
            nanoseconds: 0,
        };
        Ok(Self {
            retain_original: false,
            directory: TreeMetadata {
                mode: 0o755,
                modified,
            },
            modified,
            max_entries,
            max_expanded_bytes,
            max_tar_bytes,
            max_metadata_bytes,
        })
    }
}

/// The transport archive has its own blob reference, rooted at the
/// domain-separated package key. Evicting the package tree releases it
/// together with the provenance record, not with an arbitrary action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PackageRecord {
    pub source: PackageSource,
    pub tree: TreeId,
    pub archive: Option<BlobRef>,
}

impl PackageRecord {
    pub fn archive(&self) -> Option<PackageArchive> {
        Some(PackageArchive {
            source: self.source,
            tree: self.tree,
            blob: self.archive?,
        })
    }
}

/// A compressed package delivery bound to a pin on its verified source tree.
pub struct PackageArchiveLease {
    archive: PackageArchive,
    tree: TreeLease,
}

impl PackageArchiveLease {
    #[must_use = "the archive identifies the verified compressed original"]
    pub const fn archive(&self) -> PackageArchive {
        self.archive
    }

    /// Open the retained original while its package root is pinned.
    /// # Errors
    /// Returns an error for an unavailable archive or filesystem failure.
    pub fn open_file(&self) -> Result<std::fs::File> {
        self.tree
            .inner
            .check_blob(self.archive.blob.id, self.archive.blob.size)?;
        Ok(std::fs::File::open(
            self.tree.inner.blob_path(self.archive.blob.id),
        )?)
    }
}

/// A pinned tree whose provenance was established by verification of an
/// original archive or by its durable package index, not by a supplied tree ID.
pub struct VerifiedPackage {
    source: PackageSource,
    tree: TreeLease,
}

impl VerifiedPackage {
    #[must_use = "the source identifies the verified upstream archive"]
    pub const fn source(&self) -> PackageSource {
        self.source
    }

    #[must_use = "the receipt identifies the verified original and its content tree"]
    pub const fn receipt(&self) -> PackageReceipt {
        PackageReceipt {
            source: self.source,
            tree: self.tree.id(),
        }
    }

    #[must_use = "the tree remains pinned for this package lease"]
    pub const fn tree(&self) -> &TreeLease {
        &self.tree
    }
}

fn package_key(identity: PackageIdentity, policy: PackagePolicy) -> Result<ContentId> {
    // Admission limits are not part of the resulting normalized tree identity.
    Ok(ContentId(typed_digest(
        b"sccache-upstream-package-v2\0",
        &(identity, policy.directory, policy.modified),
    )?))
}

/// Exclusive reservation for one original package import.
pub struct PackageSlot<'a> {
    active: &'a Mutex<BTreeSet<PackageIdentity>>,
    identity: PackageIdentity,
}

impl Drop for PackageSlot<'_> {
    fn drop(&mut self) {
        match self.active.lock() {
            Ok(mut active) => {
                active.remove(&self.identity);
            }
            Err(error) => log::error!("could not release native package reservation: {error:#}"),
        }
    }
}

impl NativeStore {
    /// Reserve one original archive identity for import. Distinct packages
    /// may proceed concurrently within the owner-configured limit.
    /// # Errors
    /// Returns a busy error if the identity or capacity is reserved.
    pub fn package_slot(
        &self,
        identity: PackageIdentity,
        maximum: usize,
    ) -> Result<PackageSlot<'_>> {
        let mut active = self
            .inner
            .package_imports
            .lock()
            .map_err(|_| anyhow!("native package reservation lock poisoned"))?;
        if active.len() >= maximum || !active.insert(identity) {
            return Err(NativeServiceBusy.into());
        }
        drop(active);
        Ok(PackageSlot {
            active: &self.inner.package_imports,
            identity,
        })
    }

    /// Resolve or import an original archive under the store's shared
    /// per-package admission limit. The input factory is invoked only
    /// after admission and a second verified-cache lookup.
    /// # Errors
    /// Returns an error for busy service, invalid input or storage failure.
    pub fn acquire_package<R: Read>(
        &self,
        identity: PackageIdentity,
        length: ArchiveLength,
        limits: PackageImportLimits,
        executable: &std::path::Path,
        acquire: impl FnOnce() -> Result<R>,
    ) -> Result<(VerifiedPackage, bool)> {
        let policy = limits.policy()?;
        let mut package = self.lookup_package(identity, policy)?;
        let reservation = if package.is_none() {
            let reservation = self.package_slot(identity, limits.max_concurrent_imports)?;
            package = self.lookup_package(identity, policy)?;
            Some(reservation)
        } else {
            None
        };
        let result = if let Some(package) = package {
            if let ArchiveLength::Exact(size) = length {
                ensure!(
                    package.source().size == size,
                    "original package length differs from verified source"
                );
            }
            (package, true)
        } else {
            ensure!(
                length.maximum() <= limits.max_archive_bytes,
                "original package exceeds archive size limit"
            );
            (
                self.import_package(
                    identity,
                    length,
                    policy,
                    acquire()?,
                    PackageDecoder::Isolated {
                        executable,
                        memory_bytes: limits.decoder_memory_bytes,
                        timeout: std::time::Duration::from_secs(limits.decoder_timeout_secs),
                    },
                )?,
                false,
            )
        };
        drop(reservation);
        Ok(result)
    }

    /// Resolve a previously imported exact package without transferring or
    /// decompressing it again. Expansion limits apply to new imports only.
    ///
    /// # Errors
    /// Returns an error for index or storage failure.
    pub fn lookup_package(
        &self,
        identity: PackageIdentity,
        policy: PackagePolicy,
    ) -> Result<Option<VerifiedPackage>> {
        let _mutation = self.inner.lock_mutations()?;
        let key = package_key(identity, policy)?;
        let id = {
            let read = self.inner.db.begin_read()?;
            let table = read.open_table(PACKAGES)?;
            table
                .get(&key.0)?
                .map(|entry| encoding().deserialize::<PackageRecord>(entry.value()))
                .transpose()?
        };
        let Some(record) = id else {
            return Ok(None);
        };
        ensure!(
            record.source.identity == identity,
            "inconsistent package identity"
        );
        let tree = self
            .lookup_tree(record.tree)?
            .context("indexed package tree missing")?;
        Ok(Some(VerifiedPackage {
            source: record.source,
            tree,
        }))
    }

    /// Verify the compressed package against its upstream SHA-256 and length,
    /// then import its files directly into content-addressed storage.
    ///
    /// # Errors
    /// Returns an error for invalid checksums, unsupported or malformed
    /// archives, exceeded expansion limits, or storage failure.
    pub fn import_package(
        &self,
        identity: PackageIdentity,
        length: ArchiveLength,
        policy: PackagePolicy,
        input: impl Read,
        decoder: PackageDecoder<'_>,
    ) -> Result<VerifiedPackage> {
        ensure!(
            policy.max_entries > 0 && policy.max_tar_bytes > 0 && policy.max_metadata_bytes > 0,
            "invalid package limits"
        );
        // Verify *before* decompression. A private staged compressed file
        // prevents verification/decode races and is never published as a
        // second permanent representation of the package.
        let limit = length
            .maximum()
            .checked_add(1)
            .context("package size overflow")?;
        let mut hashed = ShaReader {
            reader: input.take(limit),
            hash: Sha256::new(),
        };
        let archive = self.stage_inner(&mut hashed, Some(limit))?;
        ensure!(
            length.accepts(archive.reference().size),
            "incorrect original package length or archive size limit exceeded"
        );
        let source = PackageSource {
            identity,
            size: archive.reference().size,
        };
        let digest: [u8; 32] = hashed.hash.finalize().into();
        ensure!(
            digest == source.identity.sha256,
            "incorrect original package SHA-256"
        );
        let mut reader = archive.file.as_file().try_clone()?;
        reader.rewind()?;
        let mut imported = ImportedTree::new(policy);
        decoder.decode(
            reader,
            source.identity.compression,
            policy,
            |entry, data| imported.add(self, entry, data),
        )?;
        let (manifest, staged) = imported.finish()?;
        let original = policy.retain_original.then_some(archive);
        let tree = self.publish_tree_indexed_pinned(
            &manifest,
            staged.into_values().collect(),
            Some((package_key(source.identity, policy)?, source, original)),
        )?;
        Ok(VerifiedPackage { source, tree })
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
    metadata_bytes: u64,
    policy: PackagePolicy,
}

impl ImportedTree {
    const fn new(policy: PackagePolicy) -> Self {
        Self {
            manifest: TreeManifest {
                root: policy.directory,
                entries: BTreeMap::new(),
            },
            staged: BTreeMap::new(),
            explicit: BTreeSet::new(),
            count: 0,
            bytes: 0,
            metadata_bytes: 0,
            policy,
        }
    }

    fn add(&mut self, store: &NativeStore, entry: ArchiveEntry, data: &mut dyn Read) -> Result<()> {
        self.count = self
            .count
            .checked_add(1)
            .context("package entry count overflow")?;
        ensure!(
            self.count <= self.policy.max_entries,
            "package entry limit exceeded"
        );
        let path = normalize_path(&entry.path, matches!(entry.kind, EntryKind::Directory))?;
        let Some(path) = path else {
            return Ok(());
        };
        self.account_metadata(&path, 128)?;
        ensure!(
            self.explicit.insert(path.clone()),
            "duplicate archive member"
        );
        self.add_parents(&path)?;
        let metadata = TreeMetadata {
            mode: entry.mode & 0o7777,
            modified: self.policy.modified,
        };
        let value = match entry.kind {
            EntryKind::Directory => TreeEntry::Directory(metadata),
            EntryKind::File(size) => {
                self.bytes = self
                    .bytes
                    .checked_add(size)
                    .context("expanded package size overflow")?;
                ensure!(
                    self.bytes <= self.policy.max_expanded_bytes,
                    "expanded package size limit exceeded"
                );
                let staged = store.stage_inner(data.take(size), Some(size))?;
                let blob = staged.reference();
                ensure!(blob.size == size, "archive member size mismatch");
                self.staged.entry(blob.id).or_insert(staged);
                TreeEntry::File { blob, metadata }
            }
            EntryKind::Symlink(target) => {
                self.account_link(&target)?;
                TreeEntry::Symlink {
                    target,
                    modified: self.policy.modified,
                }
            }
            EntryKind::Hardlink(target) => {
                self.account_link(&target)?;
                let target = normalize_path(&target, false)?
                    .context("hardlink target cannot be the root")?;
                TreeEntry::Hardlink(target)
            }
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

    fn account_link(&mut self, target: &[u8]) -> Result<()> {
        ensure!(
            target.len() <= MAX_MEMBER_PATH,
            "archive link path too long"
        );
        self.add_metadata_bytes(u64::try_from(target.len())?)
    }

    fn account_metadata(&mut self, path: &TreePath, overhead: u64) -> Result<()> {
        self.add_metadata_bytes(
            u64::try_from(path.as_bytes().len())?
                .checked_add(overhead)
                .context("package metadata size overflow")?,
        )
    }

    fn add_metadata_bytes(&mut self, count: u64) -> Result<()> {
        self.metadata_bytes = self
            .metadata_bytes
            .checked_add(count)
            .context("package metadata size overflow")?;
        ensure!(
            self.metadata_bytes <= self.policy.max_metadata_bytes,
            "package path metadata budget exceeded"
        );
        Ok(())
    }

    fn add_parents(&mut self, path: &TreePath) -> Result<()> {
        let bytes = path.as_bytes();
        for (index, &byte) in bytes.iter().enumerate() {
            if byte == b'/' {
                let parent = TreePath::new(bytes[..index].to_vec())?;
                if !self.manifest.entries.contains_key(&parent) {
                    ensure!(
                        self.manifest.entries.len() < self.policy.max_entries,
                        "package tree entry limit exceeded"
                    );
                    self.account_metadata(&parent, 128)?;
                }
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
            let mut current = path;
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
            for link in visited {
                if link != current {
                    self.account_link(current.as_bytes())?;
                    self.manifest
                        .entries
                        .insert(link, TreeEntry::Hardlink(current.clone()));
                }
            }
        }
        Ok(())
    }
    fn finish(mut self) -> Result<(TreeManifest, BTreeMap<ContentId, StagedBlob>)> {
        self.resolve_hardlinks()?;
        self.manifest.validate()?;
        Ok((self.manifest, self.staged))
    }
}

fn normalize_path(mut bytes: &[u8], directory: bool) -> Result<Option<TreePath>> {
    ensure!(
        bytes.len() <= MAX_MEMBER_PATH,
        "archive member path too long"
    );
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

mod decoder;
use decoder::{ArchiveEntry, EntryKind, MAX_MEMBER_PATH};
pub use decoder::{PackageDecoder, decode_package_process};
mod rust_installer;
mod transport;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PackageCompression, TreeLayer, TreeRecipe};

    fn policy() -> PackagePolicy {
        let modified = TreeTimestamp {
            seconds: 1234,
            nanoseconds: 0,
        };
        PackagePolicy {
            retain_original: false,
            directory: TreeMetadata {
                mode: 0o755,
                modified,
            },
            modified,
            max_entries: 100,
            max_expanded_bytes: 10000,
            max_tar_bytes: 100_000,
            max_metadata_bytes: 100_000,
        }
    }

    fn source(bytes: &[u8], compression: PackageCompression) -> PackageSource {
        PackageSource {
            identity: PackageIdentity {
                sha256: Sha256::digest(bytes).into(),
                compression,
            },
            size: bytes.len() as u64,
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
        let src = source(&gzip, PackageCompression::Gzip);
        let package = store.import_package(
            src.identity,
            ArchiveLength::Exact(src.size),
            policy(),
            &gzip[..],
            PackageDecoder::InProcess,
        )?;
        let id = package.tree().id();
        assert_eq!(store.evict_tree(id)?, super::super::Eviction::Pinned);
        assert_eq!(store.stats()?.blobs, 1);
        assert_eq!(store.stats()?.logical_bytes, 4);
        let existing = store
            .lookup_package(source(&gzip, PackageCompression::Gzip).identity, policy())?
            .context("missing original package mapping")?;
        assert_eq!(existing.tree().id(), id);
        assert_eq!(existing.source(), package.source());
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
        drop(package);
        store.evict_tree(id)?;
        assert!(
            store
                .lookup_package(source(&gzip, PackageCompression::Gzip).identity, policy())?
                .is_none()
        );
        assert_eq!(store.stats()?.pending_gc_blobs, 0);
        assert!(store.lookup_tree(composed)?.is_some());
        Ok(())
    }

    #[test]
    fn decoded_tar_limit_includes_padding_and_accepts_exact_boundary() -> Result<()> {
        use std::io::Write;

        let mut bytes = example_tar()?;
        bytes.resize(bytes.len() + 16_384, 0);
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(&bytes)?;
        let gzip = gzip.finish()?;
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let src = source(&gzip, PackageCompression::Gzip);
        let mut limits = PackagePolicy {
            max_tar_bytes: u64::try_from(bytes.len())? - 1,
            ..policy()
        };
        assert!(
            store
                .import_package(
                    src.identity,
                    ArchiveLength::Exact(src.size),
                    limits,
                    &gzip[..],
                    PackageDecoder::InProcess
                )
                .is_err()
        );
        assert_eq!(store.stats()?.trees, 0);
        assert_eq!(store.stats()?.blobs, 0);
        limits.max_tar_bytes += 1;
        let package = store.import_package(
            src.identity,
            ArchiveLength::Exact(src.size),
            limits,
            &gzip[..],
            PackageDecoder::InProcess,
        )?;
        assert_eq!(package.source(), src);
        assert_eq!(store.stats()?.blobs, 1);
        Ok(())
    }

    #[test]
    fn zstd_concatenated_frames_are_bounded_and_verified_before_publication() -> Result<()> {
        let tar = example_tar()?;
        let (prefix, suffix) = tar.split_at(tar.len() / 2);
        let mut compressed = zstd::stream::encode_all(prefix, 1)?;
        let second = zstd::stream::encode_all(suffix, 1)?;
        compressed.extend_from_slice(&second);
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let src = source(&compressed, PackageCompression::Zstd);
        let mut limits = PackagePolicy {
            max_tar_bytes: u64::try_from(tar.len())? - 1,
            ..policy()
        };
        assert!(
            store
                .import_package(
                    src.identity,
                    ArchiveLength::Exact(src.size),
                    limits,
                    &compressed[..],
                    PackageDecoder::InProcess
                )
                .is_err()
        );
        limits.max_tar_bytes += 1;
        let mut truncated = compressed.clone();
        truncated.pop();
        for invalid in [
            truncated,
            [compressed.clone(), b"unexpected suffix".to_vec()].concat(),
        ] {
            let wrong = source(&invalid, PackageCompression::Zstd);
            assert!(
                store
                    .import_package(
                        wrong.identity,
                        ArchiveLength::Exact(wrong.size),
                        limits,
                        &invalid[..],
                        PackageDecoder::InProcess
                    )
                    .is_err()
            );
            assert!(store.lookup_package(wrong.identity, limits)?.is_none());
        }
        assert_eq!(store.stats()?.blobs, 0);
        let package = store.import_package(
            src.identity,
            ArchiveLength::Exact(src.size),
            limits,
            &compressed[..],
            PackageDecoder::InProcess,
        )?;
        let raw = source(&tar, PackageCompression::Tar);
        let raw_package = store.import_package(
            raw.identity,
            ArchiveLength::Exact(raw.size),
            limits,
            &tar[..],
            PackageDecoder::InProcess,
        )?;
        assert_eq!(package.tree().id(), raw_package.tree().id());
        assert_eq!(store.stats()?.blobs, 1);
        assert_eq!(store.stats()?.trees, 1);
        Ok(())
    }

    #[test]
    fn checksum_only_ingestion_enforces_compressed_size_and_records_actual_length() -> Result<()> {
        let bytes = example_tar()?;
        let source = source(&bytes, PackageCompression::Tar);
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        assert!(
            store
                .import_package(
                    source.identity,
                    ArchiveLength::AtMost(source.size - 1),
                    policy(),
                    &bytes[..],
                    PackageDecoder::InProcess
                )
                .is_err()
        );
        assert!(
            store
                .import_package(
                    source.identity,
                    ArchiveLength::Exact(source.size + 1),
                    policy(),
                    &bytes[..],
                    PackageDecoder::InProcess
                )
                .is_err()
        );
        assert_eq!(store.stats()?.trees, 0);
        let package = store.import_package(
            source.identity,
            ArchiveLength::AtMost(source.size),
            policy(),
            &bytes[..],
            PackageDecoder::InProcess,
        )?;
        assert_eq!(package.source(), source);
        assert_eq!(
            store
                .lookup_package(source.identity, policy())?
                .context("missing verified source")?
                .source(),
            source
        );
        Ok(())
    }

    #[test]
    fn checksum_mismatch_and_expansion_limit_do_not_publish() -> Result<()> {
        let bytes = example_tar()?;
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let mut wrong = source(&bytes, PackageCompression::Tar);
        wrong.identity.sha256[0] ^= 1;
        assert!(
            store
                .import_package(
                    wrong.identity,
                    ArchiveLength::Exact(wrong.size),
                    policy(),
                    &bytes[..],
                    PackageDecoder::InProcess
                )
                .is_err()
        );
        let limited = PackagePolicy {
            max_expanded_bytes: 2,
            ..policy()
        };
        assert!(
            store
                .import_package(
                    source(&bytes, PackageCompression::Tar).identity,
                    ArchiveLength::Exact(u64::try_from(bytes.len())?),
                    limited,
                    &bytes[..],
                    PackageDecoder::InProcess
                )
                .is_err()
        );
        assert_eq!(store.stats()?.blobs, 0);
        assert_eq!(store.stats()?.trees, 0);
        Ok(())
    }
}
