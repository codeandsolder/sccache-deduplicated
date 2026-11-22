//! Metadata and mutation detection for regular source files and snapshots.
use anyhow::{Result, ensure};
use rustix::fs::Stat;
use serde::{Deserialize, Serialize};

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
