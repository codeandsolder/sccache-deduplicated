//! Bounded, process-local memoization of installed toolchain file digests.
//! The inventory is always rediscovered. No file contents are cached here.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fs::File,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result};
use rustix::fs::{FileType, Stat, fstat};

use super::{
    hash_open_source,
    installation::{self, AttestedFile},
};
use crate::{
    BlobRef, ContentId,
    source::{FileVersion, same_version, unchanged, version_is_mature},
};

type Slot = Arc<Mutex<Option<(Stat, BlobRef)>>>;
/// Optional private executor memo. The file has already been opened with the
/// caller's credentials; the provider must not reopen it by pathname.
pub type DescriptorDigestProvider = Arc<dyn Fn(&File) -> Result<BlobRef> + Send + Sync>;

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
    attested: BTreeMap<PathBuf, AttestedFile>,
    catalog_hits: AtomicU64,
    catalog_bytes: AtomicU64,
    descriptor_provider: Option<DescriptorDigestProvider>,
}

impl SourceDigestCache {
    #[must_use = "the memo is shared by successive toolchain preparations"]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(Entries::default()),
            attested: BTreeMap::new(),
            catalog_hits: AtomicU64::new(0),
            catalog_bytes: AtomicU64::new(0),
            descriptor_provider: None,
        }
    }

    /// Install a trusted private descriptor memo for mature toolchain files.
    #[must_use = "the returned cache owns the descriptor provider"]
    pub fn with_descriptor_provider(mut self, provider: Option<DescriptorDigestProvider>) -> Self {
        self.descriptor_provider = provider;
        self
    }

    /// Load trusted local installation metadata before sharing the memo.
    /// # Errors
    /// Returns an error for stale boot identity, conflicting records or I/O failure.
    pub fn load_catalog(&mut self, path: &Path) -> Result<()> {
        let incoming = installation::InstallationCatalog::load(path)?;
        for (path, record) in &incoming {
            anyhow::ensure!(
                self.attested
                    .get(path)
                    .is_none_or(|previous| previous == record),
                "conflicting installed file attestations"
            );
        }
        let additional = incoming
            .keys()
            .filter(|path| !self.attested.contains_key(*path))
            .count();
        anyhow::ensure!(
            self.attested.len().saturating_add(additional) <= self.capacity.get(),
            "installation catalogs exceed digest memo capacity"
        );
        self.attested.extend(incoming);
        Ok(())
    }

    /// Count file hashes and bytes avoided by verified installation metadata.
    #[must_use = "reports reused verified package file digests"]
    pub fn catalog_hits(&self) -> (u64, u64) {
        (
            self.catalog_hits.load(Ordering::Relaxed),
            self.catalog_bytes.load(Ordering::Relaxed),
        )
    }

    /// Hash an installed regular file through the same memo used by mapped
    /// tree capture. Resolve source links before checking the file version.
    /// # Errors
    /// Returns an error for invalid or unstable file contents.
    pub fn file_digest(&self, path: &Path) -> Result<BlobRef> {
        let path = path.canonicalize()?;
        let (file, version) = super::open_source(&path)?;
        self.digest(&path, &file, &version)
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
        if let Some(blob) = installation::lookup(&self.attested, path, file, version)? {
            self.catalog_hits.fetch_add(1, Ordering::Relaxed);
            self.catalog_bytes.fetch_add(blob.size, Ordering::Relaxed);
            return Ok(blob);
        }
        let slot = self.slot(path)?;
        // The path-wide lock coalesces simultaneous preparations without
        // serializing hashing of unrelated files.
        let mut cached = slot
            .lock()
            .map_err(|_| anyhow::anyhow!("source digest slot poisoned"))?;
        unchanged(version, &fstat(file)?)?;
        // A same-size rewrite can preserve both timestamps within one coarse
        // filesystem tick. A digest first measured during that tick is never
        // safe to reuse, even after it becomes old.
        let mature = version_is_mature(version);
        if mature
            && let Some((old_version, blob)) = cached.as_ref()
            && same_version(old_version, version)
        {
            return Ok(*blob);
        }
        let blob = match self.descriptor_provider.as_ref().filter(|_| mature) {
            Some(provider) => provider(file)?,
            None => hash_open_source(file, version)?,
        };
        unchanged(version, &fstat(file)?)?;
        anyhow::ensure!(
            blob.size == u64::try_from(version.st_size)?,
            "descriptor digest size mismatch"
        );
        *cached = mature.then_some((*version, blob));
        drop(cached);
        Ok(blob)
    }
}

impl Default for SourceDigestCache {
    fn default() -> Self {
        Self::new(NonZeroUsize::new(32_768).unwrap_or(NonZeroUsize::MIN))
    }
}

/// Hash a regular file already opened by the caller, without opening any path.
/// # Errors
/// Returns an error if the file is not regular or changes while being read.
pub fn hash_descriptor(file: &File) -> Result<BlobRef> {
    let version = regular_version(file)?;
    hash_open_source(file, &version)
}

fn regular_version(file: &File) -> Result<Stat> {
    let version = fstat(file)?;
    anyhow::ensure!(
        FileType::from_raw_mode(version.st_mode) == FileType::RegularFile,
        "digest descriptor is not a regular file"
    );
    Ok(version)
}

type DescriptorKey = (ContentId, FileVersion);

#[derive(Default)]
struct DescriptorEntries {
    values: HashMap<DescriptorKey, Option<BlobRef>>,
    order: VecDeque<DescriptorKey>,
}

/// A bounded memo shared by trusted credential-isolated executors. Scope is
/// supplied by their supervisor, not by the executor. It includes credentials
/// and filesystem view identity. The memo never reads a file or opens a path.
pub struct DescriptorMemo {
    capacity: NonZeroUsize,
    entries: Mutex<DescriptorEntries>,
}

pub struct DescriptorProbe {
    key: DescriptorKey,
    version: Stat,
    mature: bool,
}

impl DescriptorMemo {
    #[must_use = "the memo retains verified descriptor versions"]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            entries: Mutex::default(),
        }
    }

    /// Inspect an actual open descriptor and look up its mature version.
    /// # Errors
    /// Returns an error for invalid descriptors or a poisoned memo.
    pub fn probe(
        &self,
        scope: ContentId,
        file: &File,
    ) -> Result<(DescriptorProbe, Option<BlobRef>)> {
        let version = regular_version(file)?;
        let mature = version_is_mature(&version);
        let key = (scope, FileVersion::from(&version));
        let value = if mature {
            self.entries
                .lock()
                .map_err(|_| anyhow::anyhow!("descriptor memo poisoned"))?
                .values
                .get(&key)
                .copied()
                .flatten()
        } else {
            None
        };
        Ok((
            DescriptorProbe {
                key,
                version,
                mature,
            },
            value,
        ))
    }

    /// Publish a digest computed by the private executor under its own
    /// credentials. Reject changed descriptors and conflicting publications.
    /// # Errors
    /// Returns an error for changed versions, wrong size or conflicting digests.
    pub fn remember(&self, probe: DescriptorProbe, file: &File, blob: BlobRef) -> Result<()> {
        unchanged(&probe.version, &regular_version(file)?)?;
        anyhow::ensure!(
            blob.size == u64::try_from(probe.version.st_size)?,
            "descriptor digest size mismatch"
        );
        if !probe.mature {
            return Ok(());
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("descriptor memo poisoned"))?;
        if let Some(previous) = entries.values.get_mut(&probe.key) {
            if *previous != Some(blob) {
                *previous = None;
                anyhow::bail!("conflicting digest for unchanged descriptor");
            }
            return Ok(());
        }
        if entries.values.len() >= self.capacity.get() {
            let oldest = entries
                .order
                .pop_front()
                .context("descriptor memo index out of sync")?;
            entries.values.remove(&oldest);
        }
        entries.values.insert(probe.key, Some(blob));
        entries.order.push_back(probe.key);
        Ok(())
    }
}

impl Default for DescriptorMemo {
    fn default() -> Self {
        Self::new(NonZeroUsize::new(32_768).unwrap_or(NonZeroUsize::MIN))
    }
}

#[cfg(all(test, feature = "store"))]
mod tests {
    use super::*;
    use crate::mapped::open_source;
    use std::{
        fs,
        io::{Seek, SeekFrom},
    };

    #[test]
    fn shared_descriptor_memo_checks_scope_version_and_capacity() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("tool");
        let other = dir.path().join("other");
        fs::write(&path, b"version1")?;
        fs::write(&other, b"version2")?;
        let memo = DescriptorMemo::new(NonZeroUsize::MIN);
        let scope = ContentId::of(b"uid and namespace A");
        let unrelated = ContentId::of(b"uid and namespace B");
        let (fresh, _) = open_source(&path)?;
        let (probe, hit) = memo.probe(scope, &fresh)?;
        assert!(hit.is_none());
        memo.remember(probe, &fresh, hash_descriptor(&fresh)?)?;
        std::thread::sleep(std::time::Duration::from_secs(3));
        let (file, _) = open_source(&path)?;
        let (probe, hit) = memo.probe(scope, &file)?;
        assert!(hit.is_none(), "fresh versions never seed later hits");
        let expected = hash_descriptor(&file)?;
        memo.remember(probe, &file, expected)?;
        let (second, _) = open_source(&path)?;
        assert_eq!(memo.probe(scope, &second)?.1, Some(expected));
        assert!(memo.probe(unrelated, &second)?.1.is_none());
        let (other, _) = open_source(&other)?;
        let (probe, hit) = memo.probe(scope, &other)?;
        assert!(hit.is_none());
        memo.remember(probe, &other, hash_descriptor(&other)?)?;
        assert!(memo.probe(scope, &second)?.1.is_none());
        let (probe, _) = memo.probe(scope, &second)?;
        fs::write(&path, b"modified")?;
        assert!(memo.remember(probe, &second, expected).is_err());
        assert!(memo.probe(scope, &second)?.1.is_none());
        Ok(())
    }

    #[test]
    fn reuse_does_not_read_and_versions_invalidate_memo() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("tool");
        fs::write(&path, b"version1")?;
        // Exercise the stable fast path after the filesystem timestamp tick,
        // then exercise immediate same-size mutations below.
        std::thread::sleep(std::time::Duration::from_secs(3));
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
        drop(entries);
        Ok(())
    }
}
