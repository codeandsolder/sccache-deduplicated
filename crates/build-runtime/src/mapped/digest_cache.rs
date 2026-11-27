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
use crate::{BlobRef, ContentId, source::unchanged};

// A kernel-verified Merkle-tree digest authenticates immutable contents.
// Only use native filesystems that implement fs-verity, not arbitrary FUSE
// implementations which can answer ioctl requests themselves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub(super) struct VerityIdentity {
    algorithm: u16,
    digest: [u8; 32],
}

#[cfg(target_os = "linux")]
pub(super) fn verity_identity(file: &File) -> Option<VerityIdentity> {
    let fs = rustix::fs::fstatfs(file).ok()?;
    // ext4, f2fs and btrfs. All other filesystems use actual byte hashing.
    if !matches!(fs.f_type as u64, 0xef53 | 0xf2f5_2010 | 0x9123_683e) {
        return None;
    }
    #[repr(C)]
    struct Digest {
        algorithm: u16,
        size: u16,
        bytes: [u8; 64],
    }
    const MEASURE: rustix::ioctl::Opcode = rustix::ioctl::opcode::read_write::<u32>(b'f', 134);
    let mut digest = Digest {
        algorithm: 0,
        size: 64,
        bytes: [0; 64],
    };
    // SAFETY: FS_IOC_MEASURE_VERITY reads the 4-byte header, then writes
    // at most the supplied 64 bytes. The ABI uses a flexible array after
    // two u16 fields. The file is an open regular-file descriptor.
    unsafe { rustix::ioctl::ioctl(file, rustix::ioctl::Updater::<MEASURE, _>::new(&mut digest)) }
        .ok()?;
    let identity = match (digest.algorithm, digest.size) {
        (1, 32) | (2, 64) => ContentId::of(&digest.bytes[..usize::from(digest.size)]),
        _ => return None,
    };
    Some(VerityIdentity {
        algorithm: digest.algorithm,
        digest: identity.0,
    })
}

type Slot = Arc<Mutex<Option<BlobRef>>>;
/// Optional private executor memo. The file has already been opened with the
/// caller's credentials; the provider must not reopen it by pathname.
pub type DescriptorDigestProvider = Arc<dyn Fn(&File) -> Result<BlobRef> + Send + Sync>;

#[derive(Default)]
struct Entries {
    by_content: HashMap<VerityIdentity, Slot>,
    order: VecDeque<VerityIdentity>,
}

/// Memoize a BLAKE3 mapping only for kernel-verified immutable contents.
/// Mutable files are hashed on every discovery, irrespective of inode or age.
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

    /// Install a trusted private descriptor memo for immutable toolchain files.
    #[must_use = "the returned cache owns the descriptor provider"]
    pub fn with_descriptor_provider(mut self, provider: Option<DescriptorDigestProvider>) -> Self {
        self.descriptor_provider = provider;
        self
    }

    /// Load trusted local installation metadata before sharing the memo.
    /// # Errors
    /// Returns an error for conflicting records or I/O failure.
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

    fn slot(&self, identity: VerityIdentity) -> Result<Slot> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("source digest index poisoned"))?;
        if let Some(slot) = entries.by_content.get(&identity) {
            return Ok(Arc::clone(slot));
        }
        if entries.by_content.len() >= self.capacity.get() {
            let oldest = entries
                .order
                .pop_front()
                .context("source digest index out of sync")?;
            entries.by_content.remove(&oldest);
        }
        let slot = Arc::new(Mutex::new(None));
        entries.order.push_back(identity);
        entries.by_content.insert(identity, Arc::clone(&slot));
        drop(entries);
        Ok(slot)
    }

    pub(super) fn digest(&self, path: &Path, file: &File, version: &Stat) -> Result<BlobRef> {
        if let Some(blob) = installation::lookup(&self.attested, path, file, version)? {
            self.catalog_hits.fetch_add(1, Ordering::Relaxed);
            self.catalog_bytes.fetch_add(blob.size, Ordering::Relaxed);
            return Ok(blob);
        }
        let Some(identity) = verity_identity(file) else {
            return hash_open_source(file, version);
        };
        let slot = self.slot(identity)?;
        let mut cached = slot
            .lock()
            .map_err(|_| anyhow::anyhow!("source digest slot poisoned"))?;
        if let Some(blob) = *cached {
            return Ok(blob);
        }
        let blob = match &self.descriptor_provider {
            Some(provider) => provider(file)?,
            None => hash_open_source(file, version)?,
        };
        unchanged(version, &fstat(file)?)?;
        anyhow::ensure!(
            blob.size == u64::try_from(version.st_size)?,
            "descriptor digest size mismatch"
        );
        *cached = Some(blob);
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

type DescriptorKey = (ContentId, VerityIdentity);

#[derive(Default)]
struct DescriptorEntries {
    values: HashMap<DescriptorKey, Option<BlobRef>>,
    order: VecDeque<DescriptorKey>,
}

/// A bounded memo shared by trusted credential-isolated executors.
///
/// Scope is supplied by their supervisor, not by the executor. It includes credentials
/// and filesystem view identity. The memo never reads a file or opens a path.
pub struct DescriptorMemo {
    capacity: NonZeroUsize,
    entries: Mutex<DescriptorEntries>,
}

pub struct DescriptorProbe {
    key: Option<DescriptorKey>,
    version: Stat,
}

impl DescriptorMemo {
    #[must_use = "the memo retains verified descriptor versions"]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            entries: Mutex::default(),
        }
    }

    /// Inspect an actual open descriptor and look up its verified content identity.
    /// # Errors
    /// Returns an error for invalid descriptors or a poisoned memo.
    pub fn probe(
        &self,
        scope: ContentId,
        file: &File,
    ) -> Result<(DescriptorProbe, Option<BlobRef>)> {
        let version = regular_version(file)?;
        let key = verity_identity(file).map(|identity| (scope, identity));
        let value = if let Some(key) = &key {
            self.entries
                .lock()
                .map_err(|_| anyhow::anyhow!("descriptor memo poisoned"))?
                .values
                .get(key)
                .copied()
                .flatten()
        } else {
            None
        };
        Ok((DescriptorProbe { key, version }, value))
    }

    /// Publish a digest computed by the private executor under its own
    /// credentials. Reject changed descriptors and conflicting publications.
    /// # Errors
    /// Returns an error for changed versions, wrong size or conflicting digests.
    pub fn remember(&self, probe: &DescriptorProbe, file: &File, blob: BlobRef) -> Result<()> {
        unchanged(&probe.version, &regular_version(file)?)?;
        anyhow::ensure!(
            blob.size == u64::try_from(probe.version.st_size)?,
            "descriptor digest size mismatch"
        );
        let Some(key) = probe.key else {
            return Ok(());
        };
        anyhow::ensure!(
            verity_identity(file) == Some(key.1),
            "verified descriptor identity changed"
        );
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("descriptor memo poisoned"))?;
        if let Some(previous) = entries.values.get_mut(&key) {
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
        entries.values.insert(key, Some(blob));
        entries.order.push_back(key);
        drop(entries);
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
    use std::{fs, time::SystemTime};

    #[test]
    fn mutable_file_same_size_and_mtime_is_never_reused() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("tool");
        fs::write(&path, b"version1")?;
        let old = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(123);
        fs::OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_modified(old)?;
        let cache = SourceDigestCache::new(NonZeroUsize::MIN);
        let (file, version) = open_source(&path)?;
        assert_eq!(
            cache.digest(&path, &file, &version)?.id,
            ContentId::of(b"version1")
        );
        let memo = DescriptorMemo::default();
        let scope = ContentId::of(b"scope");
        let (probe, hit) = memo.probe(scope, &file)?;
        assert!(hit.is_none());
        let (file, _) = open_source(&path)?;
        memo.remember(&probe, &file, hash_descriptor(&file)?)?;
        assert!(memo.probe(scope, &file)?.1.is_none());
        fs::write(&path, b"version2")?;
        fs::OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_modified(old)?;
        let (file, version) = open_source(&path)?;
        assert_eq!(
            cache.digest(&path, &file, &version)?.id,
            ContentId::of(b"version2")
        );
        assert!(memo.probe(scope, &file)?.1.is_none());
        assert!(
            cache
                .entries
                .lock()
                .map_err(|_| anyhow::anyhow!("poisoned memo"))?
                .by_content
                .is_empty()
        );
        Ok(())
    }
}
