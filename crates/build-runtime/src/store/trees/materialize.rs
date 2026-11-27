use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io,
    os::unix::{ffi::OsStrExt, fs::symlink},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use rustix::io::Errno;
use tempfile::TempDir;

use super::{TreeLease, overlay::OverlayPlan};
use crate::tree_fs::{apply_metadata, restore_mutable_directories, set_timestamp};
use crate::{
    BlobRef, MaterializationStats, MaterializedTree, TreeEntry, TreePath, materialize_tree,
};

/// Private file bindings for changed entries of a composed tree.
/// The target lease pins its blobs; the cached base holds the unchanged files.
pub struct OverlayFiles {
    lease: Arc<TreeLease>,
    directory: TempDir,
    pub(super) replacements: BTreeMap<TreePath, PathBuf>,
    pub(crate) stats: MaterializationStats,
}

impl OverlayFiles {
    pub(super) fn manifest(&self) -> &crate::TreeManifest {
        self.lease.manifest()
    }
}

impl Drop for OverlayFiles {
    fn drop(&mut self) {
        // Per-action directory overlays are immutable inside the sandbox,
        // but may have mode 000 or other restrictive metadata. Restore only
        // directory modes, without following symlinks, before TempDir cleanup.
        for path in self.replacements.values() {
            if path.is_dir() {
                restore_mutable_directories(path);
            }
        }
    }
}

impl TreeLease {
    /// Materialize only planned private file and complete directory overlays
    /// from the target lease, preserving original mode, mtime and hardlinks.
    pub(crate) fn materialize_overlays(
        self: Arc<Self>,
        plan: &OverlayPlan,
        parent: &Path,
    ) -> Result<OverlayFiles> {
        let directory = tempfile::Builder::new()
            .prefix("build-file-overlays-")
            .tempdir_in(parent)?;
        // Own the partially materialized subtrees from the outset. Any
        // mid-operation failure runs the same safe cleanup as success, even
        // if an already-created child directory has restrictive permissions.
        let mut overlays = OverlayFiles {
            lease: self,
            directory,
            replacements: BTreeMap::new(),
            stats: MaterializationStats::default(),
        };
        for (index, path) in plan.files.iter().enumerate() {
            let Some(TreeEntry::File { blob, metadata }) =
                overlays.lease.manifest.entries.get(path)
            else {
                anyhow::bail!("overlay source must be a regular file");
            };
            let physical = overlays.directory.path().join(format!("file-{index}"));
            overlays
                .lease
                .materialize_file(*blob, &physical, &mut overlays.stats)?;
            apply_metadata(&physical, *metadata)?;
            ensure!(
                overlays
                    .replacements
                    .insert(path.clone(), physical)
                    .is_none(),
                "duplicate overlay path"
            );
        }
        for (index, anchor) in plan.directories.iter().enumerate() {
            let physical = overlays.directory.path().join(format!("dir-{index}"));
            ensure!(
                overlays
                    .replacements
                    .insert(anchor.clone(), physical.clone())
                    .is_none(),
                "duplicate overlay directory"
            );
            overlays
                .lease
                .materialize_overlay_subtree(anchor, &physical, &mut overlays.stats)?;
        }
        Ok(overlays)
    }

    /// Build a complete subtree with a private root, using only the files
    /// declared beneath an existing directory in the target manifest.
    fn materialize_overlay_subtree(
        &self,
        anchor: &TreePath,
        destination: &Path,
        stats: &mut MaterializationStats,
    ) -> Result<()> {
        let Some(TreeEntry::Directory(root_metadata)) = self.manifest.entries.get(anchor) else {
            anyhow::bail!("overlay anchor must be a directory");
        };
        fs::create_dir(destination)?;
        let prefix = [anchor.as_bytes(), b"/"].concat();
        let mut links = Vec::new();
        let mut dirs = Vec::new();
        for (path, entry) in &self.manifest.entries {
            let Some(remainder) = path.as_bytes().strip_prefix(prefix.as_slice()) else {
                continue;
            };
            let physical = destination.join(OsStr::from_bytes(remainder));
            match entry {
                TreeEntry::Directory(_) => {
                    fs::create_dir(&physical)?;
                    dirs.push((physical, entry));
                }
                TreeEntry::File { blob, metadata } => {
                    self.materialize_file(*blob, &physical, stats)?;
                    apply_metadata(&physical, *metadata)?;
                }
                TreeEntry::Symlink { target, modified } => {
                    symlink(OsStr::from_bytes(target), &physical)?;
                    set_timestamp(&physical, *modified)?;
                }
                TreeEntry::Hardlink(target) => {
                    let referent = target
                        .as_bytes()
                        .strip_prefix(prefix.as_slice())
                        .context("overlay hardlink target crosses subtree boundary")?;
                    links.push((destination.join(OsStr::from_bytes(referent)), physical));
                }
            }
        }
        // Hardlink target may sort after its aliases; create all regular files
        // first, preserving one inode and st_nlink across the entire group.
        for (target, alias) in links {
            fs::hard_link(target, alias)?;
        }
        // Parent metadata is applied last so creation does not disturb mtime.
        for (path, entry) in dirs.into_iter().rev() {
            if let TreeEntry::Directory(metadata) = entry {
                apply_metadata(&path, *metadata)?;
            }
        }
        apply_metadata(destination, *root_metadata)?;
        Ok(())
    }

    /// Materialize a validated tree in a fresh private directory on the
    /// selected filesystem. Try a filesystem copy-on-write clone for each regular file,
    /// then a streamed copy if cloning is unsupported. Never hardlink a CAS
    /// inode into a consumer tree: permissions and writers must be isolated.
    ///
    /// # Errors
    /// Returns an error for invalid data or failed filesystem operations.
    pub fn materialize(&self, parent: &Path) -> Result<MaterializedTree> {
        let mut stats = MaterializationStats::default();
        let mut tree = materialize_tree(&self.manifest, parent, |blob, path| {
            self.materialize_file(blob, path, &mut stats)
        })?;
        tree.stats = stats;
        Ok(tree)
    }

    fn materialize_file(
        &self,
        blob: BlobRef,
        path: &Path,
        stats: &mut MaterializationStats,
    ) -> Result<()> {
        let source = File::open(self.inner.blob_path(blob.id))?;
        let mut decoded =
            crate::BlobReader::open(source.try_clone()?, self.inner.blob_encoding(blob.id)?)?;
        let mut destination = OpenOptions::new().write(true).create_new(true).open(path)?;
        let cloned = if decoded.is_encoded() {
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

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use crate::{NativeStore, TreeEntry, TreePath};

    #[test]
    fn failed_directory_overlay_cleans_partially_constructed_scratch() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let input = temp.path().join("input");
        fs::create_dir_all(input.join("src/work/inner"))?;
        fs::write(input.join("src/work/inner/good"), b"good")?;
        fs::write(input.join("src/work/zz-broken"), b"missing blob")?;
        let store = NativeStore::open(&temp.path().join("store"))?;
        let lease = store.capture_tree(&input)?;
        let missing_path = TreePath::new(b"src/work/zz-broken".to_vec())?;
        let Some(TreeEntry::File { blob, .. }) = lease.manifest().entries.get(&missing_path) else {
            anyhow::bail!("test blob not captured");
        };
        // Model a storage read failure after the region root, nested
        // directories and preceding regular files have been created.
        fs::remove_file(lease.inner.blob_path(blob.id))?;
        let scratch = temp.path().join("scratch");
        fs::create_dir(&scratch)?;
        let plan = OverlayPlan {
            files: Vec::new(),
            directories: vec![TreePath::new(b"src/work".to_vec())?],
            materialized_entries: 4,
        };
        assert!(
            Arc::new(lease)
                .materialize_overlays(&plan, &scratch)
                .is_err()
        );
        assert_eq!(fs::read_dir(&scratch)?.count(), 0);
        Ok(())
    }
}
