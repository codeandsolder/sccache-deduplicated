//! Metadata and mutation detection for regular source files and snapshots.
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// Metadata digests cannot safely be memoized while a write can share the
/// same filesystem timestamp tick. ZFS and other Linux filesystems may report
/// equal ctime/mtime for two different same-size writes within one tick.
///
/// Only files older than the entire race window enter a metadata-only cache.
/// In particular, do not save a digest computed for a fresh inode and begin
/// reusing it when time passes: it might already be stale from an intervening
/// same-tick write. The window covers coarse second- and two-second-resolution
/// filesystems and Linux wall-clock rounding.
pub fn version_is_mature(stat: &Stat) -> bool {
    const RACY_WINDOW: Duration = Duration::from_secs(3);
    let Some(cutoff) = SystemTime::now()
        .checked_sub(RACY_WINDOW)
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|duration| i128::try_from(duration.as_nanos()).ok())
    else {
        return false;
    };
    [
        (stat.st_mtime, stat.st_mtime_nsec),
        (stat.st_ctime, stat.st_ctime_nsec),
    ]
    .into_iter()
    .all(|(secs, nanos)| {
        (0..1_000_000_000).contains(&nanos)
            && i128::from(secs)
                .checked_mul(1_000_000_000)
                .and_then(|base| base.checked_add(i128::from(nanos)))
                .is_some_and(|stamp| stamp < cutoff)
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::fstat;

    #[test]
    fn metadata_cache_rejects_fresh_and_future_timestamps() -> Result<()> {
        let file = tempfile::tempfile()?;
        let recent = fstat(&file)?;
        assert!(!version_is_mature(&recent));
        let mut mature = recent;
        mature.st_ctime -= 10;
        mature.st_mtime -= 10;
        assert!(version_is_mature(&mature));
        let mut future = mature;
        future.st_ctime += 30;
        assert!(!version_is_mature(&future));
        Ok(())
    }
}
