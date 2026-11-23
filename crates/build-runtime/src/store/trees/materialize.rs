use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::{PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use rustix::{
    fs::{AtFlags, CWD, Timestamps, utimensat},
    io::Errno,
    time::Timespec,
};
use tempfile::TempDir;

use super::TreeLease;
use crate::{BlobRef, TreeEntry, TreeMetadata, TreeTimestamp};

/// Materialization work, reporting explicit block clones separately from copies.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MaterializationStats {
    pub cloned_files: u64,
    pub copied_files: u64,
    pub copied_bytes: u64,
}

/// A private materialized input tree.
///
/// The temporary directory owns its files
/// independently of the store's lifetime, and is removed when dropped.
/// Mutable views must be marked before exposing them through writable mounts.
pub struct MaterializedTree {
    directory: TempDir,
    root: PathBuf,
    directories: Vec<PathBuf>,
    writable: Vec<PathBuf>,
    stats: MaterializationStats,
}

impl MaterializedTree {
    #[must_use = "the returned path is the materialized root"]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Enable cleanup of a private view that may be modified by a build.
    /// No CAS inode is shared with the view, even when block cloning succeeds.
    pub fn mark_writable(&mut self, relative: &Path) {
        self.writable.push(self.root.join(relative));
    }

    #[must_use = "the counters distinguish block cloning from copying"]
    pub const fn stats(&self) -> MaterializationStats {
        self.stats
    }
}

impl Drop for MaterializedTree {
    fn drop(&mut self) {
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

fn restore_mutable_directories(root: &Path) {
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

impl TreeLease {
    /// Materialize a validated tree in a fresh private directory on the
    /// selected filesystem. Try a filesystem copy-on-write clone for each regular file,
    /// then a streamed copy if cloning is unsupported. Never hardlink a CAS
    /// inode into a consumer tree: permissions and writers must be isolated.
    ///
    /// # Errors
    /// Returns an error for invalid data or failed filesystem operations.
    pub fn materialize(&self, parent: &Path) -> Result<MaterializedTree> {
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
        };
        for (relative, entry) in &self.manifest.entries {
            let path = tree.root.join(OsStr::from_bytes(relative.as_bytes()));
            match entry {
                TreeEntry::Directory(_) => {
                    fs::create_dir(&path)?;
                    tree.directories.push(path);
                }
                TreeEntry::File { blob, metadata } => {
                    self.materialize_file(*blob, &path, &mut tree.stats)?;
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
        for (relative, entry) in &self.manifest.entries {
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
        for (relative, entry) in self.manifest.entries.iter().rev() {
            if let TreeEntry::Directory(metadata) = entry {
                apply_metadata(
                    &tree.root.join(OsStr::from_bytes(relative.as_bytes())),
                    *metadata,
                )?;
            }
        }
        apply_metadata(&tree.root, self.manifest.root)?;
        Ok(tree)
    }

    fn materialize_file(
        &self,
        blob: BlobRef,
        path: &Path,
        stats: &mut MaterializationStats,
    ) -> Result<()> {
        let source = File::open(self.inner.blob_path(blob.id))?;
        let mut decoded = crate::BlobReader::open(source.try_clone()?)?;
        let mut destination = OpenOptions::new().write(true).create_new(true).open(path)?;
        let cloned = if decoded.is_compressed() {
            Err(Errno::OPNOTSUPP)
        } else {
            rustix::fs::ioctl_ficlone(&destination, &source)
        };
        match cloned {
            Ok(()) => {
                stats.cloned_files = stats
                    .cloned_files
                    .checked_add(1)
                    .context("clone count overflow")?;
            }
            Err(Errno::OPNOTSUPP | Errno::XDEV | Errno::INVAL | Errno::NOTTY | Errno::NOSYS) => {
                // The destination belongs exclusively to us, including if
                // an unsupported clone attempt modified part of its size.
                destination.set_len(0)?;
                let copied = io::copy(&mut decoded, &mut destination)?;
                ensure!(copied == blob.size, "incomplete tree file copy");
                stats.copied_files = stats
                    .copied_files
                    .checked_add(1)
                    .context("copy count overflow")?;
                stats.copied_bytes = stats
                    .copied_bytes
                    .checked_add(copied)
                    .context("copied size overflow")?;
            }
            Err(error) => return Err(error).context("clone native content into build tree"),
        }
        ensure!(
            destination.metadata()?.len() == blob.size,
            "tree file length mismatch"
        );
        Ok(())
    }
}

fn apply_metadata(path: &Path, metadata: TreeMetadata) -> Result<()> {
    set_timestamp(path, metadata.modified)?;
    fs::set_permissions(path, fs::Permissions::from_mode(metadata.mode))?;
    Ok(())
}

fn set_timestamp(path: &Path, timestamp: TreeTimestamp) -> Result<()> {
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
