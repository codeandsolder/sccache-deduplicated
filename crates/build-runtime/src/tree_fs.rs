//! Shared private tree materialization for CAS inputs and direct result delivery.
use crate::{BlobRef, TreeEntry, TreeManifest, TreeMetadata, TreeTimestamp};
use anyhow::{Result, ensure};
use rustix::{
    fs::{AtFlags, CWD, Timestamps, utimensat},
    time::Timespec,
};
use std::{
    ffi::OsStr,
    fs, io,
    os::unix::{
        ffi::OsStrExt,
        fs::{PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
};
use tempfile::TempDir;

/// Materialization work, reporting explicit block clones separately from copies.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MaterializationStats {
    pub cloned_files: u64,
    pub copied_files: u64,
    pub copied_bytes: u64,
}

/// A private materialized input tree.
///
/// The temporary directory owns its files independently of the store.
/// It is removed on drop unless the complete tree has been published.
/// Mutable views must be marked before exposing them through writable mounts.
pub struct MaterializedTree {
    directory: TempDir,
    root: PathBuf,
    directories: Vec<PathBuf>,
    writable: Vec<PathBuf>,
    pub(crate) stats: MaterializationStats,
    published: bool,
}

impl MaterializedTree {
    #[must_use = "the returned path is the materialized root"]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Enable cleanup of a private view that may be modified by a build.
    /// No CAS inode is shared with the view, even when block cloning succeeds.
    #[cfg(feature = "store")]
    pub(crate) fn mark_writable(&mut self, relative: &Path) {
        self.writable.push(self.root.join(relative));
    }

    /// Publish the complete tree at a previously absent destination.
    /// The caller must place the private staging directory on the destination
    /// filesystem. No existing file or directory is replaced.
    /// # Errors
    /// Returns an error if the destination exists or the rename fails.
    pub fn publish(mut self, destination: &Path) -> Result<()> {
        rustix::fs::renameat_with(
            CWD,
            &self.root,
            CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        self.published = true;
        Ok(())
    }

    #[must_use = "the counters distinguish block cloning from copying"]
    pub const fn stats(&self) -> MaterializationStats {
        self.stats
    }
}

impl Drop for MaterializedTree {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // Immutable ancestors are known from the manifest. Never trust that
        // list below a writable mount: a process may replace directories
        // with links, rename them, or create new directories with mode 000.
        for path in std::iter::once(&self.root).chain(&self.directories) {
            if self
                .writable
                .iter()
                .any(|writable| path.starts_with(writable))
            {
                continue;
            }
            if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o700)) {
                log::warn!(
                    "could not restore directory permissions at {}: {error}",
                    path.display()
                );
            }
        }
        for root in &self.writable {
            restore_mutable_directories(root);
        }
        // The owner field keeps the private parent alive through this cleanup.
        let _ = self.directory.path();
    }
}

pub(crate) fn restore_mutable_directories(root: &Path) {
    // Execution has stopped. The private parent is never exposed to the
    // sandbox. Walk the current tree without following replacement links.
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        let result = (|| -> io::Result<()> {
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_dir() {
                return Ok(());
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            for child in fs::read_dir(&path)? {
                let child = child?;
                if child.file_type()?.is_dir() {
                    pending.push(child.path());
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            log::warn!(
                "could not restore mutable view directory {}: {error}",
                path.display()
            );
        }
    }
}

/// Materialize a validated tree in a private staging directory.
///
/// The file callback must supply verified bytes for the reference;
/// it may clone local CAS content or receive it directly from the scheduler.
/// # Errors
/// Returns an error on invalid topology, incomplete content or I/O failure.
pub fn materialize_tree(
    manifest: &TreeManifest,
    parent: &Path,
    mut write_file: impl FnMut(BlobRef, &Path) -> Result<()>,
) -> Result<MaterializedTree> {
    manifest.validate()?;
    let directory = tempfile::Builder::new()
        .prefix("build-tree-")
        .tempdir_in(parent)?;
    let root = directory.path().join("root");
    fs::create_dir(&root)?;
    let mut tree = MaterializedTree {
        directory,
        root,
        directories: Vec::new(),
        writable: Vec::new(),
        stats: MaterializationStats::default(),
        published: false,
    };
    for (relative, entry) in &manifest.entries {
        let path = tree.root.join(OsStr::from_bytes(relative.as_bytes()));
        match entry {
            TreeEntry::Directory(_) => {
                fs::create_dir(&path)?;
                tree.directories.push(path);
            }
            TreeEntry::File { blob, metadata } => {
                write_file(*blob, &path)?;
                let actual = fs::symlink_metadata(&path)?;
                ensure!(
                    actual.is_file() && actual.len() == blob.size,
                    "materialized tree file does not match declared type or length"
                );
                apply_metadata(&path, *metadata)?;
            }
            TreeEntry::Symlink { target, modified } => {
                symlink(OsStr::from_bytes(target), &path)?;
                set_timestamp(&path, *modified)?;
            }
            TreeEntry::Hardlink(_) => {}
        }
    }
    // All file targets exist, even if they sort after their hardlinks.
    for (relative, entry) in &manifest.entries {
        if let TreeEntry::Hardlink(target) = entry {
            fs::hard_link(
                tree.root.join(OsStr::from_bytes(target.as_bytes())),
                tree.root.join(OsStr::from_bytes(relative.as_bytes())),
            )?;
        }
    }
    // Directory creation and linking change parent mtimes. Set their
    // metadata last, in reverse order, so restrictive parent modes do not
    // obstruct restoration of children's metadata.
    for (relative, entry) in manifest.entries.iter().rev() {
        if let TreeEntry::Directory(metadata) = entry {
            apply_metadata(
                &tree.root.join(OsStr::from_bytes(relative.as_bytes())),
                *metadata,
            )?;
        }
    }
    apply_metadata(&tree.root, manifest.root)?;
    Ok(tree)
}

pub(crate) fn apply_metadata(path: &Path, metadata: TreeMetadata) -> Result<()> {
    set_timestamp(path, metadata.modified)?;
    fs::set_permissions(path, fs::Permissions::from_mode(metadata.mode))?;
    Ok(())
}

pub(crate) fn set_timestamp(path: &Path, timestamp: TreeTimestamp) -> Result<()> {
    let time = Timespec {
        tv_sec: timestamp.seconds,
        tv_nsec: timestamp.nanoseconds.into(),
    };
    let timestamps = Timestamps {
        last_access: time,
        last_modification: time,
    };
    utimensat(CWD, path, &timestamps, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(())
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    #[test]
    fn mutable_cleanup_does_not_follow_replacement_symlinks() -> Result<()> {
        let private = tempfile::tempdir()?;
        let external = tempfile::tempdir()?;
        fs::set_permissions(external.path(), fs::Permissions::from_mode(0o755))?;
        let root = private.path().join("root");
        fs::create_dir_all(root.join("out/old"))?;
        fs::create_dir_all(root.join("out/new/restricted"))?;
        fs::set_permissions(
            root.join("out/new/restricted"),
            fs::Permissions::from_mode(0o0),
        )?;
        fs::remove_dir(root.join("out/old"))?;
        symlink(external.path(), root.join("out/old"))?;
        let private_path = private.path().to_owned();
        let view = MaterializedTree {
            directory: private,
            root: root.clone(),
            directories: vec![root.join("out"), root.join("out/old")],
            writable: vec![root.join("out")],
            stats: MaterializationStats::default(),
            published: false,
        };
        drop(view);
        assert_eq!(
            fs::metadata(external.path())?.permissions().mode() & 0o777,
            0o755
        );
        assert!(!private_path.exists());
        Ok(())
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    use crate::{ContentId, TreePath};
    use std::{collections::BTreeMap, os::unix::fs::MetadataExt};

    #[test]
    fn publish_verified_tree_preserves_links_and_never_replaces_destination() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let metadata = TreeMetadata {
            mode: 0o755,
            modified: TreeTimestamp {
                seconds: 1234,
                nanoseconds: 5678,
            },
        };
        let blob = BlobRef {
            id: ContentId::of(b"object"),
            size: 6,
        };
        let manifest = TreeManifest {
            root: metadata,
            entries: BTreeMap::from([
                (
                    TreePath::new(b"nested".to_vec())?,
                    TreeEntry::Directory(metadata),
                ),
                (
                    TreePath::new(b"nested/object".to_vec())?,
                    TreeEntry::File { blob, metadata },
                ),
                (
                    TreePath::new(b"alias".to_vec())?,
                    TreeEntry::Hardlink(TreePath::new(b"nested/object".to_vec())?),
                ),
                (
                    TreePath::new(b"link".to_vec())?,
                    TreeEntry::Symlink {
                        target: b"nested/object".to_vec(),
                        modified: metadata.modified,
                    },
                ),
            ]),
        };
        let prepare = || {
            materialize_tree(&manifest, parent.path(), |reference, path| {
                assert_eq!(reference, blob);
                fs::write(path, b"object")?;
                Ok(())
            })
        };
        let destination = parent.path().join("result");
        fs::create_dir(&destination)?;
        fs::write(destination.join("existing"), b"sentinel")?;
        assert!(prepare()?.publish(&destination).is_err());
        assert_eq!(fs::read(destination.join("existing"))?, b"sentinel");
        fs::remove_dir_all(&destination)?;
        prepare()?.publish(&destination)?;
        let actual = fs::metadata(destination.join("nested/object"))?;
        assert_eq!(actual.ino(), fs::metadata(destination.join("alias"))?.ino());
        assert_eq!(actual.mode() & 0o777, 0o755);
        assert_eq!(actual.mtime(), 1234);
        assert_eq!(
            fs::read_link(destination.join("link"))?,
            Path::new("nested/object")
        );
        assert_eq!(fs::read(destination.join("link"))?, b"object");
        assert_eq!(fs::read_dir(parent.path())?.count(), 1);
        Ok(())
    }
}
