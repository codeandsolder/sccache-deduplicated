use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use bincode::Options;
use redb::{
    Database, MultimapTableDefinition, ReadableDatabase, ReadableMultimapTable, ReadableTable,
    ReadableTableMetadata, TableDefinition,
};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use super::{
    ActionFingerprint, ActionKey, BlobRef, ContentId, ResultId, ResultManifest, identity::encoding,
};

const ACTIONS: TableDefinition<'static, &[u8; 32], &[u8]> = TableDefinition::new("actions_v1");
const RESULTS: TableDefinition<'static, &[u8; 32], &[u8]> = TableDefinition::new("results_v1");
const BLOBS: TableDefinition<'static, &[u8; 32], u64> = TableDefinition::new("blobs_v1");
const RESULT_ACTIONS: MultimapTableDefinition<'static, &[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("result_actions_v1");
const BLOB_RESULTS: MultimapTableDefinition<'static, &[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("blob_results_v1");

#[derive(Serialize, Deserialize)]
struct ActionRecord {
    fingerprint: ActionFingerprint,
    result: ResultId,
}

/// A verified immutable blob staged for publication. Dropping it before
/// publication discards the temporary file.
pub struct StagedBlob {
    file: NamedTempFile,
    reference: BlobRef,
    owner: Arc<Inner>,
}

impl StagedBlob {
    #[must_use]
    pub const fn reference(&self) -> BlobRef {
        self.reference
    }
}

/// Result of committing an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Published {
    pub action: ActionKey,
    pub result: ResultId,
    pub new_action: bool,
}

/// Result of an explicit action eviction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eviction {
    Missing,
    Pinned,
    Removed { reclaimed_logical_bytes: u64 },
}

/// Counts logical content, not compressed device usage. On ZFS the dataset
/// quota and referenced/exclusive byte counters govern physical capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub actions: u64,
    pub results: u64,
    pub blobs: u64,
    pub logical_bytes: u64,
}

struct Inner {
    root: PathBuf,
    db: Database,
    // The database serializes metadata transactions. This lock additionally
    // serializes file publication, deletion and lease acquisition.
    pins: Mutex<BTreeMap<ActionKey, usize>>,
}

impl Inner {
    fn lock(&self) -> Result<MutexGuard<'_, BTreeMap<ActionKey, usize>>> {
        self.pins
            .lock()
            .map_err(|_| anyhow!("native store lock poisoned"))
    }

    fn blob_path(&self, id: ContentId) -> PathBuf {
        let hex = blake3::Hash::from_bytes(id.0).to_hex();
        let hex = hex.as_str();
        // A BLAKE3 hex string is always exactly 64 ASCII characters.
        self.root.join("blobs").join(&hex[..2]).join(&hex[2..])
    }

    fn check_blob(&self, id: ContentId, size: u64) -> Result<()> {
        let path = self.blob_path(id);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("missing native store content {id:?}"))?;
        ensure!(
            metadata.is_file() && metadata.len() == size,
            "invalid native store content {id:?}"
        );
        Ok(())
    }

    fn install_blob(&self, blob: StagedBlob) -> Result<()> {
        let path = self.blob_path(blob.reference.id);
        let parent = path.parent().context("invalid blob storage path")?;
        match fs::create_dir(parent) {
            Ok(()) => File::open(self.root.join("blobs"))?.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        // An unindexed file can remain after a failed transaction; replace it
        // with verified bytes rather than trusting its name or its length.
        blob.file.persist(&path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn remove_blob(&self, id: ContentId) -> Result<()> {
        let path = self.blob_path(id);
        match fs::remove_file(&path) {
            Ok(()) => {
                File::open(path.parent().context("invalid blob storage path")?)?.sync_all()?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn recover_orphans(&self) -> Result<()> {
        // Only run at open, while the exclusive database lock prevents a
        // second live store from staging or publishing files.
        for entry in fs::read_dir(self.root.join("staging"))? {
            fs::remove_file(entry?.path())?;
        }
        let read = self.db.begin_read()?;
        let blobs = read.open_table(BLOBS)?;
        for shard in fs::read_dir(self.root.join("blobs"))? {
            let shard = shard?;
            ensure!(shard.file_type()?.is_dir(), "invalid blob shard");
            let prefix = shard.file_name();
            let prefix = prefix.to_str().context("invalid blob shard name")?;
            ensure!(prefix.len() == 2, "invalid blob shard name");
            for entry in fs::read_dir(shard.path())? {
                let entry = entry?;
                let suffix = entry.file_name();
                let suffix = suffix.to_str().context("invalid blob file name")?;
                let id =
                    ContentId(*blake3::Hash::from_hex(format!("{prefix}{suffix}"))?.as_bytes());
                ensure!(
                    entry.file_type()?.is_file() && entry.path() == self.blob_path(id),
                    "invalid blob file"
                );
                if blobs.get(&id.0)?.is_none() {
                    self.remove_blob(id)?;
                }
            }
        }
        Ok(())
    }
}

/// Single-owner, durable action index and content-addressed file storage.
///
/// Blocking storage operations belong on an I/O executor rather than the
/// scheduler's asynchronous control loop. Provision the directory on a
/// dedicated compressed filesystem/dataset; this type does not create pools,
/// change filesystem properties or start other cache services.
pub struct NativeStore {
    inner: Arc<Inner>,
}

impl NativeStore {
    /// Open or initialize an exclusive store and recover unreferenced files.
    ///
    /// # Errors
    /// Returns an error for filesystem, database or recovery failures, including
    /// when another live process owns this directory.
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        let root = fs::canonicalize(root)?;
        let db = Database::create(root.join("index.redb"))?;
        fs::create_dir_all(root.join("staging"))?;
        fs::create_dir_all(root.join("blobs"))?;
        File::open(&root)?.sync_all()?;
        let write = db.begin_write()?;
        write.open_table(ACTIONS)?;
        write.open_table(RESULTS)?;
        write.open_table(BLOBS)?;
        write.open_multimap_table(RESULT_ACTIONS)?;
        write.open_multimap_table(BLOB_RESULTS)?;
        write.commit()?;
        let inner = Arc::new(Inner {
            root,
            db,
            pins: Mutex::new(BTreeMap::new()),
        });
        inner.recover_orphans()?;
        Ok(Self { inner })
    }

    /// Stream uncompressed content into a temporary file, hashing it in the
    /// same pass. This is independent of the index lock.
    ///
    /// # Errors
    /// Returns an error if the stream or filesystem fails.
    pub fn stage(&self, mut reader: impl Read) -> Result<StagedBlob> {
        let mut file = NamedTempFile::new_in(self.inner.root.join("staging"))?;
        let mut hash = blake3::Hasher::new();
        let mut buffer = vec![0; 64 * 1024];
        let mut size = 0_u64;
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    let bytes = &buffer[..count];
                    file.write_all(bytes)?;
                    hash.update(bytes);
                    size = size
                        .checked_add(u64::try_from(count)?)
                        .context("blob length overflow")?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        file.as_file().sync_all()?;
        Ok(StagedBlob {
            file,
            reference: BlobRef {
                id: ContentId(*hash.finalize().as_bytes()),
                size,
            },
            owner: Arc::clone(&self.inner),
        })
    }

    /// Atomically publish a successful result. All newly referenced blobs must
    /// be staged; blobs already in the store can be referenced without upload.
    ///
    /// The same action and result is idempotent. A different result for an
    /// existing action is an error, not a silent replacement.
    ///
    /// # Errors
    /// Returns an error for conflicting actions, missing or inconsistent content,
    /// filesystem or transactional metadata failures.
    pub fn publish(
        &self,
        fingerprint: &ActionFingerprint,
        manifest: &ResultManifest,
        staged: Vec<StagedBlob>,
    ) -> Result<Published> {
        let action = fingerprint.key()?;
        let result = manifest.id()?;
        let blobs = manifest.blobs()?;
        ensure!(
            staged
                .iter()
                .all(|blob| Arc::ptr_eq(&blob.owner, &self.inner)),
            "staged content belongs to a different store"
        );
        let mut staged: BTreeMap<_, _> = staged
            .into_iter()
            .map(|blob| (blob.reference.id, blob))
            .collect();
        ensure!(
            staged.keys().all(|id| blobs.contains_key(id)),
            "unreferenced staged content"
        );
        let _guard = self.inner.lock()?;
        let write = self.inner.db.begin_write()?;
        {
            let mut actions = write.open_table(ACTIONS)?;
            let mut results = write.open_table(RESULTS)?;
            let mut blob_table = write.open_table(BLOBS)?;
            let mut result_actions = write.open_multimap_table(RESULT_ACTIONS)?;
            let mut blob_results = write.open_multimap_table(BLOB_RESULTS)?;
            if let Some(stored) = actions.get(&action.0)? {
                let stored: ActionRecord = encoding().deserialize(stored.value())?;
                ensure!(
                    stored.fingerprint == *fingerprint && stored.result == result,
                    "conflicting result for action {action:?}"
                );
                for (&id, &size) in &blobs {
                    self.inner.check_blob(id, size)?;
                }
                return Ok(Published {
                    action,
                    result,
                    new_action: false,
                });
            }
            let existing_result = results.get(&result.0)?.is_some();
            for (&id, &size) in &blobs {
                if let Some(existing_size) = blob_table.get(&id.0)?.map(|entry| entry.value()) {
                    ensure!(existing_size == size, "content length mismatch for {id:?}");
                    self.inner.check_blob(id, size)?;
                } else {
                    ensure!(!existing_result, "indexed result is missing content {id:?}");
                    let blob = staged
                        .get(&id)
                        .with_context(|| format!("missing staged content {id:?}"))?;
                    ensure!(
                        blob.reference.size == size,
                        "staged length mismatch for {id:?}"
                    );
                }
            }
            for (&id, &size) in &blobs {
                if blob_table.get(&id.0)?.is_none() {
                    let blob = staged
                        .remove(&id)
                        .context("validated staged content disappeared")?;
                    self.inner.install_blob(blob)?;
                    blob_table.insert(&id.0, size)?;
                }
                if !existing_result {
                    blob_results.insert(&id.0, &result.0)?;
                }
            }
            if !existing_result {
                let bytes = encoding().serialize(manifest)?;
                results.insert(&result.0, bytes.as_slice())?;
            }
            let record = ActionRecord {
                fingerprint: fingerprint.clone(),
                result,
            };
            let bytes = encoding().serialize(&record)?;
            actions.insert(&action.0, bytes.as_slice())?;
            result_actions.insert(&result.0, &action.0)?;
        }
        // Files and their directory entries are durable before the index
        // exposes them. Orphans from an interrupted write are harmless.
        write.commit()?;
        Ok(Published {
            action,
            result,
            new_action: true,
        })
    }

    /// Acquire a result lease, pinning its action and all referenced content.
    ///
    /// # Errors
    /// Returns an error for corrupt metadata, missing blobs or I/O failure.
    pub fn lookup(&self, action: ActionKey) -> Result<Option<ResultLease>> {
        let mut pins = self.inner.lock()?;
        let read = self.inner.db.begin_read()?;
        let actions = read.open_table(ACTIONS)?;
        let Some(record) = actions.get(&action.0)? else {
            return Ok(None);
        };
        let record: ActionRecord = encoding().deserialize(record.value())?;
        let results = read.open_table(RESULTS)?;
        let manifest = results
            .get(&record.result.0)?
            .context("missing indexed result")?;
        let manifest: ResultManifest = encoding().deserialize(manifest.value())?;
        let blobs = manifest.blobs()?;
        for (&id, &size) in &blobs {
            self.inner.check_blob(id, size)?;
        }
        let count = pins.entry(action).or_default();
        *count = count.checked_add(1).context("action pin count overflow")?;
        Ok(Some(ResultLease {
            inner: Arc::clone(&self.inner),
            action,
            manifest,
            blobs,
        }))
    }

    /// Find all actions that yielded the same complete result, retaining their
    /// semantic input fingerprints for differential cache-key analysis.
    ///
    /// # Errors
    /// Returns an error for unreadable or inconsistent metadata.
    pub fn equivalent_actions(
        &self,
        result: ResultId,
    ) -> Result<Vec<(ActionKey, ActionFingerprint)>> {
        let read = self.inner.db.begin_read()?;
        let aliases = read.open_multimap_table(RESULT_ACTIONS)?;
        let actions = read.open_table(ACTIONS)?;
        aliases
            .get(&result.0)?
            .map(|entry| {
                let key = ActionKey(*entry?.value());
                let record = actions.get(&key.0)?.context("missing indexed action")?;
                let record: ActionRecord = encoding().deserialize(record.value())?;
                ensure!(record.result == result, "inconsistent result reverse index");
                Ok((key, record.fingerprint))
            })
            .collect()
    }

    /// Remove one action, then reclaim only results and blobs whose last
    /// reference disappeared. Active leases prevent eviction of their action.
    ///
    /// # Errors
    /// Returns an error for inconsistent metadata or storage failures.
    pub fn evict(&self, action: ActionKey) -> Result<Eviction> {
        let pins = self.inner.lock()?;
        if pins.contains_key(&action) {
            return Ok(Eviction::Pinned);
        }
        let write = self.inner.db.begin_write()?;
        let mut reclaim = Vec::new();
        let mut reclaimed_logical_bytes = 0_u64;
        {
            let mut actions = write.open_table(ACTIONS)?;
            let mut results = write.open_table(RESULTS)?;
            let mut blob_table = write.open_table(BLOBS)?;
            let mut result_actions = write.open_multimap_table(RESULT_ACTIONS)?;
            let mut blob_results = write.open_multimap_table(BLOB_RESULTS)?;
            let Some(record) = actions.remove(&action.0)? else {
                return Ok(Eviction::Missing);
            };
            let record: ActionRecord = encoding().deserialize(record.value())?;
            let result = record.result;
            ensure!(
                result_actions.remove(&result.0, &action.0)?,
                "missing result reverse reference"
            );
            if result_actions.get(&result.0)?.next().transpose()?.is_none() {
                let manifest = results
                    .remove(&result.0)?
                    .context("missing indexed result")?;
                let manifest: ResultManifest = encoding().deserialize(manifest.value())?;
                for (id, size) in manifest.blobs()? {
                    ensure!(
                        blob_results.remove(&id.0, &result.0)?,
                        "missing blob reverse reference"
                    );
                    if blob_results.get(&id.0)?.next().transpose()?.is_none() {
                        let indexed_size =
                            blob_table.remove(&id.0)?.context("missing indexed blob")?;
                        ensure!(
                            indexed_size.value() == size,
                            "inconsistent indexed blob length"
                        );
                        reclaim.push(id);
                        reclaimed_logical_bytes = reclaimed_logical_bytes
                            .checked_add(size)
                            .context("reclaimed size overflow")?;
                    }
                }
            }
        }
        // Never remove content before its last index reference is committed.
        write.commit()?;
        for id in reclaim {
            self.inner.remove_blob(id)?;
        }
        Ok(Eviction::Removed {
            reclaimed_logical_bytes,
        })
    }

    /// Return logical accounting from a consistent index snapshot.
    ///
    /// # Errors
    /// Returns an error for metadata failures or a size overflow.
    pub fn stats(&self) -> Result<CacheStats> {
        let read = self.inner.db.begin_read()?;
        let actions = read.open_table(ACTIONS)?;
        let results = read.open_table(RESULTS)?;
        let blobs = read.open_table(BLOBS)?;
        let mut logical_bytes = 0_u64;
        for entry in blobs.iter()? {
            let (_, size) = entry?;
            logical_bytes = logical_bytes
                .checked_add(size.value())
                .context("store size overflow")?;
        }
        Ok(CacheStats {
            actions: actions.len()?,
            results: results.len()?,
            blobs: blobs.len()?,
            logical_bytes,
        })
    }
}

/// A snapshot of a result whose content cannot be evicted during consumption.
pub struct ResultLease {
    inner: Arc<Inner>,
    action: ActionKey,
    manifest: ResultManifest,
    blobs: BTreeMap<ContentId, u64>,
}

impl ResultLease {
    #[must_use]
    pub const fn manifest(&self) -> &ResultManifest {
        &self.manifest
    }

    /// Open a blob belonging to this result. The reader borrows the lease and
    /// cannot outlive the corresponding eviction pin.
    ///
    /// # Errors
    /// Returns an error for an undeclared blob or filesystem failure.
    pub fn open_blob(&self, id: ContentId) -> Result<impl Read + Seek + '_> {
        if !self.blobs.contains_key(&id) {
            bail!("content {id:?} is not part of this result");
        }
        Ok(LeasedReader {
            file: File::open(self.inner.blob_path(id))?,
            _lease: self,
        })
    }
}

impl Drop for ResultLease {
    fn drop(&mut self) {
        match self.inner.lock() {
            Ok(mut pins) => match pins.get_mut(&self.action) {
                Some(count) if *count > 1 => *count -= 1,
                Some(_) => {
                    pins.remove(&self.action);
                }
                None => error!("native store result lease lost its pin"),
            },
            Err(error) => error!("could not release native store result lease: {error:#}"),
        }
    }
}

struct LeasedReader<'a> {
    file: File,
    _lease: &'a ResultLease,
}

impl Read for LeasedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for LeasedReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

#[cfg(test)]
mod tests;
