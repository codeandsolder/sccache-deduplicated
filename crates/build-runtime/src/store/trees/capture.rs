//! Import a stable local source/toolchain snapshot without archive creation.

use std::{collections::BTreeMap, fs::File, path::Path};

use anyhow::{Result, ensure};
use rustix::fs::{CWD, FileType, Mode, OFlags, Stat, fstat, openat};

use crate::source::unchanged;
use crate::{NativeStore, StagedBlob, TreeLease};

impl NativeStore {
    /// Capture one stable caller-owned snapshot as a normalized tree.
    ///
    /// Directory traversal is descriptor-relative and never follows symlinks.
    /// File bytes, modes, mtimes and inode aliases are preserved. A per-entry
    /// before/after stat rejects detected mutations; callers must still ensure
    /// the source is quiescent for the entire capture (or use a real snapshot).
    ///
    /// # Errors
    /// Returns an error for unsupported file types, detected mutations,
    /// invalid metadata or storage failure.
    pub fn capture_tree(&self, root: &Path) -> Result<TreeLease> {
        let fd = openat(
            CWD,
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut blobs = BTreeMap::new();
        let manifest = crate::source::capture_tree(&fd, |_, file, stat| {
            let blob = capture_regular(self, &file, stat)?;
            let reference = blob.reference();
            blobs.entry(reference.id).or_insert(blob);
            Ok(reference)
        })?;
        self.publish_tree_pinned(&manifest, blobs.into_values().collect())
    }
}

pub(super) fn capture_regular(store: &NativeStore, file: &File, stat: &Stat) -> Result<StagedBlob> {
    ensure!(
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
        "capture source is not a regular file"
    );
    let size = u64::try_from(stat.st_size)?;
    let blob = store.stage_local_inner(
        file,
        Some(size),
        crate::store::space::StageBudget::new(store),
    )?;
    unchanged(stat, &fstat(file)?)?;
    ensure!(
        blob.reference().size == size,
        "file size changed during capture"
    );
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use crate::TreeEntry;
    use std::{
        fs,
        os::unix::{
            ffi::OsStringExt,
            fs::{PermissionsExt, symlink},
        },
    };

    use super::*;

    #[test]
    fn captures_nonutf8_links_and_modes_without_following_symlinks() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let source = dir.path().join("input");
        fs::create_dir(&source)?;
        let original = source.join(std::ffi::OsString::from_vec(vec![b'a', 0xff]));
        fs::write(&original, b"same file")?;
        fs::set_permissions(&original, fs::Permissions::from_mode(0o751))?;
        fs::hard_link(&original, source.join("alias"))?;
        symlink("/etc/passwd", source.join("link"))?;
        let store = NativeStore::open(&dir.path().join("store"))?;
        let tree = store.capture_tree(&source)?;
        assert_eq!(tree.manifest().blobs()?.len(), 1);
        assert!(
            tree.manifest()
                .entries
                .values()
                .any(|entry| matches!(entry, TreeEntry::Hardlink(_)))
        );
        assert!(tree.manifest().entries.values().any(
            |entry| matches!(entry, TreeEntry::File { metadata, .. } if metadata.mode == 0o751)
        ));
        assert!(tree.manifest().entries.values().any(
            |entry| matches!(entry, TreeEntry::Symlink { target, .. } if target == b"/etc/passwd")
        ));
        assert_eq!(tree.id(), store.capture_tree(&source)?.id());
        fs::write(&original, b"different")?;
        assert_ne!(tree.id(), store.capture_tree(&source)?.id());
        Ok(())
    }
}
