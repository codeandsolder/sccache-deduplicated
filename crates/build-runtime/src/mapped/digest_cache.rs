//! Bounded, process-local memoization of installed toolchain file digests.
//! The inventory is always rediscovered. No file contents are cached here.

use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use rustix::fs::{Stat, fstat};

use super::hash_open_source;
use crate::{
    BlobRef,
    source::{same_version, unchanged},
};

type Slot = Arc<Mutex<Option<(Stat, BlobRef)>>>;

#[derive(Default)]
struct Entries {
    by_path: HashMap<PathBuf, Slot>,
    order: VecDeque<PathBuf>,
}

/// Cache file digests, not bytes, for quiescent, trusted installed tools.
///
/// Metadata reuse assumes a filesystem that reports changes to ctime/inode
/// identity reliably. Do not use this for mutable build-source files.
pub struct SourceDigestCache {
    capacity: NonZeroUsize,
    entries: Mutex<Entries>,
}

impl SourceDigestCache {
    #[must_use = "the memo is shared by successive toolchain preparations"]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(Entries::default()),
        }
    }

    fn slot(&self, path: &Path) -> Result<Slot> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("source digest index poisoned"))?;
        if let Some(slot) = entries.by_path.get(path) {
            return Ok(Arc::clone(slot));
        }
        if entries.by_path.len() >= self.capacity.get() {
            let oldest = entries
                .order
                .pop_front()
                .context("source digest index out of sync")?;
            entries.by_path.remove(&oldest);
        }
        let slot = Arc::new(Mutex::new(None));
        entries.order.push_back(path.to_owned());
        entries.by_path.insert(path.to_owned(), Arc::clone(&slot));
        drop(entries);
        Ok(slot)
    }

    pub(super) fn digest(&self, path: &Path, file: &File, version: &Stat) -> Result<BlobRef> {
        let slot = self.slot(path)?;
        // The path-wide lock coalesces simultaneous preparations without
        // serializing hashing of unrelated files.
        let mut cached = slot
            .lock()
            .map_err(|_| anyhow::anyhow!("source digest slot poisoned"))?;
        unchanged(version, &fstat(file)?)?;
        if let Some((old_version, blob)) = cached.as_ref()
            && same_version(old_version, version)
        {
            return Ok(*blob);
        }
        let blob = hash_open_source(file, version)?;
        *cached = Some((*version, blob));
        drop(cached);
        Ok(blob)
    }
}

impl Default for SourceDigestCache {
    fn default() -> Self {
        Self::new(NonZeroUsize::new(32_768).unwrap_or(NonZeroUsize::MIN))
    }
}

#[cfg(all(test, feature = "store"))]
mod tests {
    use super::*;
    use crate::{ContentId, mapped::open_source};
    use std::{
        fs,
        io::{Seek, SeekFrom},
    };

    #[test]
    fn reuse_does_not_read_and_versions_invalidate_memo() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("tool");
        fs::write(&path, b"version1")?;
        let cache = SourceDigestCache::new(NonZeroUsize::MIN);
        let (mut file, version) = open_source(&path)?;
        let initial = cache.digest(&path, &file, &version)?;
        assert_eq!(initial.id, ContentId::of(b"version1"));
        file.seek(SeekFrom::Start(0))?;
        assert_eq!(cache.digest(&path, &file, &version)?, initial);
        assert_eq!(
            file.stream_position()?,
            0,
            "warm digest must not read source"
        );
        let replacement = temp.path().join("replacement");
        fs::write(&replacement, b"version2")?;
        fs::rename(&replacement, &path)?;
        let (file, version) = open_source(&path)?;
        assert_eq!(
            cache.digest(&path, &file, &version)?.id,
            ContentId::of(b"version2")
        );
        fs::write(&path, b"version3")?;
        let (file, version) = open_source(&path)?;
        assert_eq!(
            cache.digest(&path, &file, &version)?.id,
            ContentId::of(b"version3")
        );
        let other = temp.path().join("other");
        fs::write(&other, b"other")?;
        let (file, version) = open_source(&other)?;
        cache.digest(&other, &file, &version)?;
        let entries = cache
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("poisoned memo"))?;
        assert_eq!(entries.by_path.len(), 1);
        assert!(!entries.by_path.contains_key(&path));
        Ok(())
    }
}
