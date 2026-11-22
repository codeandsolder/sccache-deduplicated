//! Metadata and mutation detection for regular source files and snapshots.
use anyhow::{Result, ensure};
use rustix::fs::Stat;
#[cfg(feature = "store")]
use rustix::{
    fd::AsFd,
    fs::{AtFlags, Dir, FileType, Mode, OFlags, fstat, openat, readlinkat, statat},
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "store")]
use std::{collections::BTreeMap, ffi::OsStr, fs::File, os::unix::ffi::OsStrExt};

#[cfg(feature = "store")]
use crate::{BlobRef, TreeEntry, TreeManifest, TreePath};
use crate::{TreeMetadata, TreeTimestamp};

pub fn timestamp(stat: &Stat) -> Result<TreeTimestamp> {
    Ok(TreeTimestamp {
        seconds: stat.st_mtime,
        nanoseconds: u32::try_from(stat.st_mtime_nsec)?,
    })
}

pub fn metadata(stat: &Stat) -> Result<TreeMetadata> {
    Ok(TreeMetadata {
        mode: stat.st_mode & 0o7777,
        modified: timestamp(stat)?,
    })
}

// Linux stat layouts differ by architecture. Normalize all fields without
// narrowing, including the metadata needed to detect replacement and mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileVersion([i128; 10]);

impl From<&Stat> for FileVersion {
    fn from(stat: &Stat) -> Self {
        Self([
            stat.st_dev.into(),
            stat.st_ino.into(),
            stat.st_mode.into(),
            stat.st_nlink.into(),
            stat.st_size.into(),
            stat.st_mtime.into(),
            stat.st_mtime_nsec.into(),
            stat.st_ctime.into(),
            stat.st_ctime_nsec.into(),
            stat.st_uid.into(),
        ])
    }
}

pub fn same_version(before: &Stat, after: &Stat) -> bool {
    FileVersion::from(before) == FileVersion::from(after)
}

pub fn unchanged(before: &Stat, after: &Stat) -> Result<()> {
    ensure!(
        same_version(before, after),
        "native snapshot changed during capture"
    );
    Ok(())
}

/// Snapshot a quiescent directory through its descriptor. File handling is
/// delegated to the caller; directory topology, symlinks, hardlinks, and
/// mutation checks have a single implementation.
#[cfg(feature = "store")]
pub fn capture_tree(
    fd: &impl AsFd,
    file_sink: impl FnMut(&TreePath, File, &Stat) -> Result<BlobRef>,
) -> Result<TreeManifest> {
    let stat = fstat(fd)?;
    let mut capture = Capture {
        file_sink,
        entries: BTreeMap::new(),
        links: BTreeMap::new(),
    };
    capture.directory(fd, b"")?;
    unchanged(&stat, &fstat(fd)?)?;
    let manifest = TreeManifest {
        root: metadata(&stat)?,
        entries: capture.entries,
    };
    manifest.validate()?;
    Ok(manifest)
}

#[cfg(feature = "store")]
struct Capture<F> {
    file_sink: F,
    entries: BTreeMap<TreePath, TreeEntry>,
    links: BTreeMap<(u64, u64), TreePath>,
}

#[cfg(feature = "store")]
impl<F: FnMut(&TreePath, File, &Stat) -> Result<BlobRef>> Capture<F> {
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
        let reference = (self.file_sink)(path, file, stat)?;
        if stat.st_nlink > 1 {
            self.links.insert(identity, path.clone());
        }
        Ok(TreeEntry::File {
            blob: reference,
            metadata: metadata(stat)?,
        })
    }
}
