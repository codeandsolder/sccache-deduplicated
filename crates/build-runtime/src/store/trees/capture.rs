//! Import a stable local source/toolchain snapshot without archive creation.

use std::{collections::BTreeMap, ffi::OsStr, fs::File, os::unix::ffi::OsStrExt, path::Path};

use anyhow::{Result, ensure};
use rustix::{
    fd::AsFd,
    fs::{AtFlags, CWD, Dir, FileType, Mode, OFlags, Stat, fstat, openat, readlinkat, statat},
};

use crate::{
    ContentId, NativeStore, StagedBlob, TreeEntry, TreeLease, TreeManifest, TreeMetadata, TreePath,
    TreeTimestamp,
};

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
        let stat = fstat(&fd)?;
        let mut capture = Capture {
            store: self,
            entries: BTreeMap::new(),
            blobs: BTreeMap::new(),
            links: BTreeMap::new(),
        };
        capture.directory(&fd, b"")?;
        unchanged(&stat, &fstat(&fd)?)?;
        let manifest = TreeManifest {
            root: metadata(&stat)?,
            entries: capture.entries,
        };
        self.publish_tree_pinned(&manifest, capture.blobs.into_values().collect())
    }
}

struct Capture<'a> {
    store: &'a NativeStore,
    entries: BTreeMap<TreePath, TreeEntry>,
    blobs: BTreeMap<ContentId, StagedBlob>,
    links: BTreeMap<(u64, u64), TreePath>,
}

impl Capture<'_> {
    fn directory(&mut self, dir: &impl AsFd, prefix: &[u8]) -> Result<()> {
        let mut names = Vec::new();
        for entry in Dir::read_from(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
        }
        names.sort_unstable();
        for name in names {
            let mut path = prefix.to_vec();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(&name);
            let relative = TreePath::new(path)?;
            let name = OsStr::from_bytes(&name);
            let stat = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
            let entry = match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => {
                    let child = openat(
                        dir,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )?;
                    unchanged(&stat, &fstat(&child)?)?;
                    self.directory(&child, relative.as_bytes())?;
                    unchanged(&stat, &fstat(&child)?)?;
                    TreeEntry::Directory(metadata(&stat)?)
                }
                FileType::RegularFile => self.regular(dir, name, &relative, &stat)?,
                FileType::Symlink => TreeEntry::Symlink {
                    target: readlinkat(dir, name, Vec::new())?.into_bytes(),
                    modified: timestamp(&stat)?,
                },
                _ => anyhow::bail!("unsupported entry in native snapshot"),
            };
            unchanged(&stat, &statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?)?;
            self.entries.insert(relative, entry);
        }
        Ok(())
    }

    fn regular(
        &mut self,
        dir: &impl AsFd,
        name: &OsStr,
        path: &TreePath,
        stat: &Stat,
    ) -> Result<TreeEntry> {
        let identity = (stat.st_dev, stat.st_ino);
        if let Some(target) = self.links.get(&identity) {
            return Ok(TreeEntry::Hardlink(target.clone()));
        }
        let file = File::from(openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )?);
        unchanged(stat, &fstat(&file)?)?;
        let blob = self.store.stage(&file)?;
        unchanged(stat, &fstat(&file)?)?;
        let reference = blob.reference();
        ensure!(
            reference.size == u64::try_from(stat.st_size)?,
            "file size changed during capture"
        );
        self.blobs.entry(reference.id).or_insert(blob);
        if stat.st_nlink > 1 {
            self.links.insert(identity, path.clone());
        }
        Ok(TreeEntry::File {
            blob: reference,
            metadata: metadata(stat)?,
        })
    }
}

fn timestamp(stat: &Stat) -> Result<TreeTimestamp> {
    Ok(TreeTimestamp {
        seconds: stat.st_mtime,
        nanoseconds: u32::try_from(stat.st_mtime_nsec)?,
    })
}

fn metadata(stat: &Stat) -> Result<TreeMetadata> {
    Ok(TreeMetadata {
        mode: stat.st_mode & 0o7777,
        modified: timestamp(stat)?,
    })
}

fn unchanged(before: &Stat, after: &Stat) -> Result<()> {
    ensure!(
        before.st_dev == after.st_dev
            && before.st_ino == after.st_ino
            && before.st_mode == after.st_mode
            && before.st_nlink == after.st_nlink
            && before.st_size == after.st_size
            && before.st_mtime == after.st_mtime
            && before.st_mtime_nsec == after.st_mtime_nsec
            && before.st_ctime == after.st_ctime
            && before.st_ctime_nsec == after.st_ctime_nsec,
        "native snapshot changed during capture"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
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
