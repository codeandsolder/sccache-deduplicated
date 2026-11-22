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
/// Expose this root to untrusted builds only through a read-only mount.
pub struct MaterializedTree {
    directory: TempDir,
    root: PathBuf,
    directories: Vec<PathBuf>,
    stats: MaterializationStats,
}

impl MaterializedTree {
    #[must_use = "the returned path is the materialized root"]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use = "the counters distinguish block cloning from copying"]
    pub const fn stats(&self) -> MaterializationStats {
        self.stats
    }
}

impl Drop for MaterializedTree {
    fn drop(&mut self) {
        // Directory permissions may intentionally be read-only or even 000.
        // Restore access in parent-first order while still in the private
        // materialization directory, before tempfile removes it. The caller
        // must not hand the root to an untrusted writable process.
        for path in std::iter::once(&self.root).chain(&self.directories) {
            if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o700)) {
                log::warn!(
                    "could not restore directory permissions at {}: {error}",
                    path.display()
                );
            }
        }
        // The owner field keeps the private parent alive through this cleanup.
        let _ = self.directory.path();
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
        let mut source = File::open(self.inner.blob_path(blob.id))?;
        let mut destination = OpenOptions::new().write(true).create_new(true).open(path)?;
        match rustix::fs::ioctl_ficlone(&destination, &source) {
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
                let copied = io::copy(&mut source, &mut destination)?;
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
