use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, atomic::AtomicU64},
    time::Instant,
};

use anyhow::{Context, Result, anyhow, ensure};
use bincode::Options;
use redb::{
    Database, MultimapTableDefinition, ReadableDatabase, ReadableMultimapTable, ReadableTable,
    ReadableTableMetadata, TableDefinition, WriteTransaction,
};
use serde::{Deserialize, Serialize};
use tempfile::{NamedTempFile, TempPath};

use super::{
    ActionFingerprint, ActionKey, ActionMode, BlobRef, ContentId, ResultId, ResultManifest,
    identity::encoding,
};

const ACTIONS: TableDefinition<'static, &[u8; 32], &[u8]> = TableDefinition::new("actions_v1");
const RESULTS: TableDefinition<'static, &[u8; 32], &[u8]> = TableDefinition::new("results_v1");
const PACKAGES: TableDefinition<'static, &[u8; 32], &[u8]> = TableDefinition::new("packages_v1");
const BLOB_PACKAGES: MultimapTableDefinition<'static, &[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("blob_packages_v1");
const TREE_PACKAGES: MultimapTableDefinition<'static, &[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("tree_packages_v1");
const TREES: TableDefinition<'static, &[u8; 32], &[u8]> = TableDefinition::new("trees_v1");
const BLOBS: TableDefinition<'static, &[u8; 32], u64> = TableDefinition::new("blobs_v1");
const USAGE: TableDefinition<'static, &[u8; 33], &[u8]> = TableDefinition::new("usage_v1");
const RESULT_ACTIONS: MultimapTableDefinition<'static, &[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("result_actions_v1");
const ACCOUNTING: TableDefinition<'static, u8, u64> = TableDefinition::new("accounting_v1");
const LIVE_BYTES: u8 = 0;
const PENDING_BYTES: u8 = 1;
const PENDING_DELETIONS: TableDefinition<'static, &[u8; 32], u64> =
    TableDefinition::new("pending_deletions_v1");
const BLOB_ROOTS: MultimapTableDefinition<'static, &[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("blob_roots_v1");

#[derive(Serialize, Deserialize)]
struct ActionRecord {
    fingerprint: ActionFingerprint,
    result: ResultId,
}

/// A verified immutable blob staged for publication.
///
/// Dropping it before publication discards the temporary file. Closed, owner-private paths
/// keep descriptor use proportional to active transfers, not manifest size.
pub struct StagedBlob {
    path: TempPath,
    metadata: fs::Metadata,
    reference: BlobRef,
    owner: Arc<Inner>,
    _reservation: space::StagingReservation,
}

impl StagedBlob {
    #[must_use = "the reference identifies the staged content"]
    pub const fn reference(&self) -> BlobRef {
        self.reference
    }

    fn validate_metadata(&self, actual: &fs::Metadata) -> Result<()> {
        let expected = &self.metadata;
        ensure!(
            actual.is_file()
                && actual.dev() == expected.dev()
                && actual.ino() == expected.ino()
                && actual.len() == self.reference.size
                && actual.mode() == expected.mode()
                && actual.mtime() == expected.mtime()
                && actual.mtime_nsec() == expected.mtime_nsec()
                && actual.ctime() == expected.ctime()
                && actual.ctime_nsec() == expected.ctime_nsec(),
            "native staged content changed before publication"
        );
        Ok(())
    }

    fn open_file(&self) -> Result<File> {
        use rustix::fs::{Mode, OFlags, open};
        let file = File::from(open(
            &*self.path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        self.validate_metadata(&file.metadata()?)?;
        Ok(file)
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
    Removed { unreferenced_logical_bytes: u64 },
}

/// Counts logical content, not compressed device usage. On ZFS the dataset
/// quota and referenced/exclusive byte counters govern physical capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub actions: u64,
    pub results: u64,
    pub trees: u64,
    pub blobs: u64,
    pub logical_bytes: u64,
    pub pending_gc_blobs: u64,
    pub pending_gc_bytes: u64,
}

/// Work completed by a bounded garbage collection pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarbageCollected {
    pub blobs: u64,
    pub logical_bytes: u64,
    pub failed: Vec<ContentId>,
}

#[derive(Default)]
struct Pins {
    actions: BTreeMap<ActionKey, usize>,
    trees: BTreeMap<crate::TreeId, usize>,
    blobs: BTreeMap<ContentId, usize>,
    usage: BTreeMap<space::Root, space::UsageRecord>,
    dirty_usage: BTreeSet<space::Root>,
    last_usage_checkpoint: Option<Instant>,
}

impl Pins {
    fn reserve_content<'a>(
        &mut self,
        ids: impl Iterator<Item = &'a ContentId> + Clone,
    ) -> Result<()> {
        for id in ids.clone() {
            ensure!(
                self.blobs.get(id).copied().unwrap_or(0) < usize::MAX,
                "content pin count overflow"
            );
        }
        for &id in ids {
            *self.blobs.entry(id).or_default() += 1;
        }
        Ok(())
    }
}

// A single batched transaction serves both periodic checkpoints and orderly
// shutdown, without any database activity on the lookup critical path.
fn persist_usage(db: &Database, pins: &mut Pins) -> Result<()> {
    if pins.dirty_usage.is_empty() {
        return Ok(());
    }
    let write = db.begin_write()?;
    {
        let mut usage = write.open_table(USAGE)?;
        for root in &pins.dirty_usage {
            if let Some(record) = pins.usage.get(root) {
                let bytes = encoding().serialize(record)?;
                usage.insert(&root.key(), bytes.as_slice())?;
            }
        }
    }
    write.commit()?;
    pins.dirty_usage.clear();
    pins.last_usage_checkpoint = Some(Instant::now());
    Ok(())
}

// All lease categories use the same pin reference-counting invariant.
fn release_pin<K: Ord + std::fmt::Debug>(pins: &mut BTreeMap<K, usize>, key: &K) {
    match pins.get_mut(key) {
        Some(count) if *count > 1 => *count -= 1,
        Some(_) => {
            pins.remove(key);
        }
        None => log::error!("native store lease lost its pin: {key:?}"),
    }
}

struct Inner {
    root: PathBuf,
    db: Database,
    // Mutations serialize filesystem changes with durable metadata commits.
    // Readers only acquire the separate pin lock, not the publication lock.
    mutations: Mutex<()>,
    pins: Mutex<Pins>,
    package_imports: Mutex<BTreeSet<crate::PackageIdentity>>,
    space_policy: Option<SpacePolicy>,
    space: Mutex<space::SpaceState>,
    // Releases never acquire the space admission lock, avoiding lock-order
    // inversion with transactional publication and eviction.
    space_released: AtomicU64,
}

impl Inner {
    fn lock_pins(&self) -> Result<MutexGuard<'_, Pins>> {
        self.pins
            .lock()
            .map_err(|_| anyhow!("native store pin lock poisoned"))
    }

    fn lock_mutations(&self) -> Result<MutexGuard<'_, ()>> {
        self.mutations
            .lock()
            .map_err(|_| anyhow!("native store mutation lock poisoned"))
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

    fn open_declared(&self, blobs: &BTreeMap<ContentId, u64>, id: ContentId) -> Result<File> {
        ensure!(
            blobs.contains_key(&id),
            "content {id:?} is not part of the leased manifest"
        );
        Ok(File::open(self.blob_path(id))?)
    }

    fn install_blob(&self, blob: StagedBlob, directories: &mut BTreeSet<PathBuf>) -> Result<()> {
        let path = self.blob_path(blob.reference.id);
        let parent = path.parent().context("invalid blob storage path")?;
        if directories.insert(parent.to_owned()) {
            match fs::create_dir(parent) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            directories.insert(self.root.join("blobs"));
        }
        // An unindexed file can remain after a failed transaction; replace it
        // with verified bytes rather than trusting its name or its length.
        blob.validate_metadata(&fs::symlink_metadata(&blob.path)?)?;
        blob.path.persist(&path)?;
        Ok(())
    }

    fn remove_blob(&self, id: ContentId) -> Result<()> {
        let path = self.blob_path(id);
        match fs::remove_file(&path) {
            Ok(()) => {
                File::open(path.parent().context("invalid blob storage path")?)?.sync_all()?;
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
        // Pending deletions are all unreferenced, and no readers or uploads
        // can survive a process restart. The scan above removed their files.
        drop(blobs);
        drop(read);
        let write = self.db.begin_write()?;
        {
            let mut pending = write.open_table(PENDING_DELETIONS)?;
            pending.retain(|_, _| false)?;
            let mut accounting = write.open_table(ACCOUNTING)?;
            accounting.insert(PENDING_BYTES, 0)?;
        }
        write.commit()?;
        Ok(())
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Only the final Arc owner can reach this point. An orderly worker
        // shutdown persists recent popularity even inside the flush interval.
        let result = self
            .pins
            .get_mut()
            .map_err(|_| anyhow!("native usage mutex poisoned at shutdown"))
            .and_then(|pins| persist_usage(&self.db, pins));
        if let Err(error) = result {
            log::error!("could not persist native usage on shutdown: {error:#}");
        }
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
        Self::open_inner(root, None)
    }

    fn open_inner(root: &Path, space_policy: Option<SpacePolicy>) -> Result<Self> {
        fs::create_dir_all(root)?;
        let root = fs::canonicalize(root)?;
        let metadata = fs::metadata(&root)?;
        ensure!(
            metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o022 == 0,
            "native store root must be owned by the service and not writable by others"
        );
        let index = root.join("index.redb");
        match fs::symlink_metadata(&index) {
            Ok(metadata) => ensure!(metadata.is_file(), "native index is not a regular file"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                ensure!(
                    fs::read_dir(&root)?.next().is_none(),
                    "native store must start in an empty directory"
                );
            }
            Err(error) => return Err(error.into()),
        }
        let db = Database::create(index)?;
        for name in ["staging", "blobs"] {
            let path = root.join(name);
            fs::create_dir_all(&path)?;
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_dir()
                    && metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.mode() & 0o022 == 0,
                "native store directory is not owner-controlled: {}",
                path.display()
            );
            if name == "staging" {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            }
        }
        File::open(&root)?.sync_all()?;
        let write = db.begin_write()?;
        write.open_table(ACTIONS)?;
        write.open_table(RESULTS)?;
        write.open_table(TREES)?;
        write.open_table(PACKAGES)?;
        write.open_multimap_table(TREE_PACKAGES)?;
        write.open_multimap_table(BLOB_PACKAGES)?;
        write.open_table(BLOBS)?;
        write.open_table(USAGE)?;
        write.open_multimap_table(RESULT_ACTIONS)?;
        write.open_multimap_table(BLOB_ROOTS)?;
        write.open_table(PENDING_DELETIONS)?;
        {
            let mut accounting = write.open_table(ACCOUNTING)?;
            if accounting.get(LIVE_BYTES)?.is_none() {
                accounting.insert(LIVE_BYTES, 0)?;
            }
            if accounting.get(PENDING_BYTES)?.is_none() {
                accounting.insert(PENDING_BYTES, 0)?;
            }
        }
        write.commit()?;
        let mut pins = Pins::default();
        {
            let read = db.begin_read()?;
            for entry in read.open_table(USAGE)?.iter()? {
                let (key, value) = entry?;
                let root = space::Root::from_key(*key.value())?;
                let record: space::UsageRecord = encoding().deserialize(value.value())?;
                pins.usage.insert(root, record);
            }
        }
        let inner = Arc::new(Inner {
            root,
            db,
            mutations: Mutex::new(()),
            pins: Mutex::new(pins),
            package_imports: Mutex::new(BTreeSet::new()),
            space_policy,
            space: Mutex::default(),
            space_released: AtomicU64::new(0),
        });
        inner.recover_orphans()?;
        Ok(Self { inner })
    }

    /// Stream uncompressed content into a temporary file, hashing it in the
    /// same pass. This is independent of the index lock.
    ///
    /// # Errors
    /// Returns an error if the stream or filesystem fails.
    pub fn stage(&self, reader: impl Read) -> Result<StagedBlob> {
        self.stage_inner(reader, None)
    }

    // Size is an upper bound, not a substitute for digest/length validation.
    fn stage_inner(&self, mut reader: impl Read, bound: Option<u64>) -> Result<StagedBlob> {
        let mut budget = space::StageBudget::new(self);
        if let Some(bound) = bound {
            budget.grow_to(bound)?;
        }

        let mut file = NamedTempFile::new_in(self.inner.root.join("staging"))?;
        let mut hash = blake3::Hasher::new();
        let mut buffer = vec![0; 64 * 1024];
        let mut size = 0_u64;
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    let bytes = &buffer[..count];
                    size = size
                        .checked_add(u64::try_from(count)?)
                        .context("blob length overflow")?;
                    if let Some(bound) = bound {
                        ensure!(size <= bound, "native staged stream exceeds upper bound");
                    } else {
                        // Grow unknown-length streams in 4 MiB increments.
                        const CHUNK: u64 = 4 * 1024 * 1024;
                        let reservation = size
                            .div_ceil(CHUNK)
                            .checked_mul(CHUNK)
                            .context("staging budget overflow")?;
                        // A small managed worker must be able to stage a
                        // small object even with a budget below one chunk.
                        let reservation = self.inner.space_policy.map_or(reservation, |policy| {
                            reservation.min(policy.max_resident_bytes)
                        });
                        ensure!(
                            size <= reservation,
                            "native staged content exceeds resident budget"
                        );
                        budget.grow_to(reservation)?;
                    }
                    file.write_all(bytes)?;
                    hash.update(bytes);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        // The inode metadata is not part of the blob identity; callers
        // apply the manifest's mode to copies/materialized outputs.
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        file.as_file().sync_all()?;
        let metadata = file.as_file().metadata()?;
        let reservation = budget.finish(size)?;
        Ok(StagedBlob {
            path: file.into_temp_path(),
            metadata,
            reference: BlobRef {
                id: ContentId(*hash.finalize().as_bytes()),
                size,
            },
            owner: Arc::clone(&self.inner),
            _reservation: reservation,
        })
    }

    /// Stage an advertised blob, rejecting short, long or wrong-content streams.
    /// The length bounds the amount read even if the sender never ends input.
    ///
    /// # Errors
    /// Returns an error for an invalid stream, digest/length mismatch or I/O failure.
    pub fn stage_expected(&self, expected: BlobRef, reader: impl Read) -> Result<StagedBlob> {
        let limit = expected
            .size
            .checked_add(1)
            .context("blob length overflow")?;
        // Read one extra byte to detect overflow, but reserve only the
        // declared content size against the worker's resident limit.
        let staged = self.stage_inner(reader.take(limit), Some(expected.size))?;
        ensure!(
            staged.reference() == expected,
            "uploaded content does not match its declared digest and length"
        );
        Ok(staged)
    }

    /// Reserve already present content during missing-blob negotiation.
    /// Uploads can wait outside the mutation lock while eviction defers
    /// deletion of their reserved content.
    ///
    /// # Errors
    /// Returns an error for malformed manifests, inconsistent metadata or I/O.
    pub fn reserve_upload(&self, manifest: &ResultManifest) -> Result<UploadReservation> {
        self.reserve_blobs(manifest.blobs()?)
    }

    fn reserve_blobs(&self, blobs: BTreeMap<ContentId, u64>) -> Result<UploadReservation> {
        let _mutation = self.inner.lock_mutations()?;
        let read = self.inner.db.begin_read()?;
        let live = read.open_table(BLOBS)?;
        let pending = read.open_table(PENDING_DELETIONS)?;
        let mut missing = Vec::new();
        let mut reserved = Vec::new();
        for (id, size) in blobs {
            let live_size = live.get(&id.0)?.map(|entry| entry.value());
            let pending_size = pending.get(&id.0)?.map(|entry| entry.value());
            if let Some(indexed_size) = live_size.or(pending_size) {
                ensure!(indexed_size == size, "inconsistent indexed content length");
                if live_size.is_some() {
                    self.inner.check_blob(id, size)?;
                    reserved.push(id);
                } else if self.inner.check_blob(id, size).is_ok() {
                    reserved.push(id);
                } else {
                    missing.push(BlobRef { id, size });
                }
            } else {
                missing.push(BlobRef { id, size });
            }
        }
        let mut pins = self.inner.lock_pins()?;
        // Validate every count before changing any pin.
        pins.reserve_content(reserved.iter())?;
        drop(pins);
        Ok(UploadReservation {
            inner: Arc::clone(&self.inner),
            reserved,
            missing,
        })
    }

    /// Atomically publish a successful result. All newly referenced blobs must
    /// be staged; blobs already in the store can be referenced without upload.
    ///
    /// The same action and result is idempotent. A different result requires
    /// explicit refresh mode; a failed refresh leaves the prior action intact.
    ///
    /// # Errors
    /// Returns an error for conflicting actions, missing or inconsistent content,
    /// filesystem or transactional metadata failures.
    pub fn publish(
        &self,
        fingerprint: &ActionFingerprint,
        manifest: &ResultManifest,
        staged: Vec<StagedBlob>,
        mode: ActionMode,
    ) -> Result<Published> {
        let _mutation = self.inner.lock_mutations()?;
        self.publish_locked(fingerprint, manifest, staged, mode)
    }

    /// Publish and pin the resulting action before eviction can remove it.
    ///
    /// # Errors
    /// Returns an error for invalid results, missing content or storage failure.
    pub fn publish_pinned(
        &self,
        fingerprint: &ActionFingerprint,
        manifest: &ResultManifest,
        staged: Vec<StagedBlob>,
        mode: ActionMode,
    ) -> Result<ResultLease> {
        let _mutation = self.inner.lock_mutations()?;
        let published = self.publish_locked(fingerprint, manifest, staged, mode)?;
        self.lookup(published.action)?
            .context("committed result missing")
    }

    fn publish_locked(
        &self,
        fingerprint: &ActionFingerprint,
        manifest: &ResultManifest,
        staged: Vec<StagedBlob>,
        mode: ActionMode,
    ) -> Result<Published> {
        let action = fingerprint.key()?;
        let result = manifest.id()?;
        let blobs = manifest.blobs()?;
        let staged = self.prepare_staging(&blobs, staged)?;
        let write = self.inner.db.begin_write()?;
        let new_action;
        {
            let mut actions = write.open_table(ACTIONS)?;
            let mut results = write.open_table(RESULTS)?;
            let mut result_actions = write.open_multimap_table(RESULT_ACTIONS)?;
            let previous = actions
                .get(&action.0)?
                .map(|value| encoding().deserialize::<ActionRecord>(value.value()))
                .transpose()?;
            new_action = previous.is_none();
            if let Some(stored) = &previous {
                ensure!(
                    stored.fingerprint == *fingerprint,
                    "conflicting native action fingerprint"
                );
                if stored.result == result {
                    for (&id, &size) in &blobs {
                        self.inner.check_blob(id, size)?;
                    }
                    self.inner.lock_pins()?.touch(space::Root::Action(action));
                    return Ok(Published {
                        action,
                        result,
                        new_action: false,
                    });
                }
                ensure!(
                    mode == ActionMode::Refresh,
                    "conflicting result for action {action:?}"
                );
            }
            let existing_result = if let Some(stored) = results.get(&result.0)? {
                let stored: ResultManifest = encoding().deserialize(stored.value())?;
                ensure!(stored == *manifest, "conflicting native result manifest");
                true
            } else {
                false
            };
            self.attach_blobs(&write, &result.0, &blobs, staged, existing_result)?;
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
            if let Some(previous) = previous {
                Self::release_result_reference(
                    &write,
                    &mut results,
                    &mut result_actions,
                    action,
                    previous.result,
                )?;
            }
        }
        // Files and their directory entries are durable before the index
        // exposes them. Orphans from an interrupted write are harmless.
        write.commit()?;
        self.inner.lock_pins()?.touch(space::Root::Action(action));
        Ok(Published {
            action,
            result,
            new_action,
        })
    }

    fn prepare_staging(
        &self,
        blobs: &BTreeMap<ContentId, u64>,
        staged: Vec<StagedBlob>,
    ) -> Result<BTreeMap<ContentId, StagedBlob>> {
        ensure!(
            staged
                .iter()
                .all(|blob| Arc::ptr_eq(&blob.owner, &self.inner)),
            "staged content belongs to a different store"
        );
        let staged: BTreeMap<_, _> = staged
            .into_iter()
            .map(|blob| (blob.reference.id, blob))
            .collect();
        ensure!(
            staged.keys().all(|id| blobs.contains_key(id)),
            "unreferenced staged content"
        );
        Ok(staged)
    }

    fn attach_blobs(
        &self,
        write: &WriteTransaction,
        root: &[u8; 32],
        blobs: &BTreeMap<ContentId, u64>,
        mut staged: BTreeMap<ContentId, StagedBlob>,
        existing_result: bool,
    ) -> Result<()> {
        let mut blob_table = write.open_table(BLOBS)?;
        let mut blob_roots = write.open_multimap_table(BLOB_ROOTS)?;
        let mut pending = write.open_table(PENDING_DELETIONS)?;
        let mut accounting = write.open_table(ACCOUNTING)?;
        let mut resurrected = Vec::new();
        for (&id, &size) in blobs {
            if let Some(existing_size) = blob_table.get(&id.0)?.map(|entry| entry.value()) {
                ensure!(existing_size == size, "content length mismatch for {id:?}");
                self.inner.check_blob(id, size)?;
            } else {
                ensure!(!existing_result, "indexed result is missing content {id:?}");
                if let Some(old_size) = pending.get(&id.0)?.map(|entry| entry.value()) {
                    ensure!(
                        old_size == size,
                        "pending content length mismatch for {id:?}"
                    );
                    if self.inner.check_blob(id, size).is_ok() {
                        resurrected.push(id);
                        continue;
                    }
                }
                let blob = staged
                    .get(&id)
                    .with_context(|| format!("missing staged content {id:?}"))?;
                ensure!(
                    blob.reference.size == size,
                    "staged length mismatch for {id:?}"
                );
            }
        }
        let mut added = 0_u64;
        let mut pending_removed = 0_u64;
        let mut directories = BTreeSet::new();
        for (&id, &size) in blobs {
            if blob_table.get(&id.0)?.is_none() {
                if resurrected.binary_search(&id).is_err() {
                    let blob = staged
                        .remove(&id)
                        .context("validated staged content disappeared")?;
                    self.inner.install_blob(blob, &mut directories)?;
                }
                blob_table.insert(&id.0, size)?;
                added = added.checked_add(size).context("store size overflow")?;
                if let Some(old) = pending.remove(&id.0)? {
                    pending_removed = pending_removed
                        .checked_add(old.value())
                        .context("pending GC size overflow")?;
                }
            }
            if !existing_result {
                blob_roots.insert(&id.0, root)?;
            }
        }
        if added != 0 {
            let previous = accounting
                .get(LIVE_BYTES)?
                .context("missing live accounting")?
                .value();
            accounting.insert(
                LIVE_BYTES,
                previous.checked_add(added).context("store size overflow")?,
            )?;
        }
        if pending_removed != 0 {
            let previous = accounting
                .get(PENDING_BYTES)?
                .context("missing pending accounting")?
                .value();
            accounting.insert(
                PENDING_BYTES,
                previous
                    .checked_sub(pending_removed)
                    .context("pending GC size underflow")?,
            )?;
        }
        // Every staged inode was synced before admission. Sync each affected
        // shard once, before the transaction exposes any of its content.
        for directory in directories.iter().rev() {
            File::open(directory)?.sync_all()?;
        }
        Ok(())
    }

    /// Acquire a result lease, pinning its action and all referenced content.
    ///
    /// # Errors
    /// Returns an error for corrupt metadata, missing blobs or I/O failure.
    pub fn lookup(&self, action: ActionKey) -> Result<Option<ResultLease>> {
        let mut pins = self.inner.lock_pins()?;
        let read = self.inner.db.begin_read()?;
        let actions = read.open_table(ACTIONS)?;
        let Some(record) = actions.get(&action.0)? else {
            return Ok(None);
        };
        let record: ActionRecord = encoding().deserialize(record.value())?;
        ensure!(
            record.fingerprint.key()? == action,
            "invalid indexed action fingerprint"
        );
        let results = read.open_table(RESULTS)?;
        let manifest = results
            .get(&record.result.0)?
            .context("missing indexed result")?;
        let manifest: ResultManifest = encoding().deserialize(manifest.value())?;
        ensure!(
            manifest.id()? == record.result,
            "invalid indexed result manifest"
        );
        let blobs = manifest.blobs()?;
        for (&id, &size) in &blobs {
            self.inner.check_blob(id, size)?;
        }
        let count = pins
            .actions
            .get(&action)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .context("action pin count overflow")?;
        // A refresh can retire the old result while its delivery lease
        // survives. Pin its content independently of the action mapping.
        pins.reserve_content(blobs.keys())?;
        pins.actions.insert(action, count);
        pins.touch(space::Root::Action(action));
        drop(pins);
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
        let _mutation = self.inner.lock_mutations()?;
        let mut pins = self.inner.lock_pins()?;
        if pins.actions.contains_key(&action) {
            return Ok(Eviction::Pinned);
        }
        let write = self.inner.db.begin_write()?;
        let unreferenced_logical_bytes;
        {
            let mut actions = write.open_table(ACTIONS)?;
            let mut results = write.open_table(RESULTS)?;
            let mut result_actions = write.open_multimap_table(RESULT_ACTIONS)?;
            let Some(record) = actions.remove(&action.0)? else {
                return Ok(Eviction::Missing);
            };
            let record: ActionRecord = encoding().deserialize(record.value())?;
            unreferenced_logical_bytes = Self::release_result_reference(
                &write,
                &mut results,
                &mut result_actions,
                action,
                record.result,
            )?;
        }
        // Remove the matching usage record in the same transaction.
        write
            .open_table(USAGE)?
            .remove(&space::Root::Action(action).key())?;
        // Durable deletion intent precedes physical deletion. The collector
        // can batch work and retry failures without scanning the live store.
        write.commit()?;
        // Lookup and eviction must serialize until removal is committed.
        pins.usage.remove(&space::Root::Action(action));
        pins.dirty_usage.remove(&space::Root::Action(action));
        drop(pins);
        Ok(Eviction::Removed {
            unreferenced_logical_bytes,
        })
    }

    fn release_result_reference(
        write: &WriteTransaction,
        results: &mut redb::Table<'_, &[u8; 32], &[u8]>,
        aliases: &mut redb::MultimapTable<'_, &[u8; 32], &[u8; 32]>,
        action: ActionKey,
        result: ResultId,
    ) -> Result<u64> {
        ensure!(
            aliases.remove(&result.0, &action.0)?,
            "missing result reverse reference"
        );
        if aliases.get(&result.0)?.next().transpose()?.is_some() {
            return Ok(0);
        }
        let manifest = results
            .remove(&result.0)?
            .context("missing indexed result")?;
        let manifest: ResultManifest = encoding().deserialize(manifest.value())?;
        Self::detach_blobs(write, &result.0, manifest.blobs()?)
    }

    fn detach_blobs(
        write: &WriteTransaction,
        root: &[u8; 32],
        blobs: BTreeMap<ContentId, u64>,
    ) -> Result<u64> {
        let mut blob_table = write.open_table(BLOBS)?;
        let mut blob_roots = write.open_multimap_table(BLOB_ROOTS)?;
        let mut pending = write.open_table(PENDING_DELETIONS)?;
        let mut accounting = write.open_table(ACCOUNTING)?;
        let mut unreferenced_logical_bytes = 0_u64;
        for (id, size) in blobs {
            ensure!(
                blob_roots.remove(&id.0, root)?,
                "missing blob reverse reference"
            );
            if blob_roots.get(&id.0)?.next().transpose()?.is_none() {
                let indexed_size = blob_table.remove(&id.0)?.context("missing indexed blob")?;
                ensure!(
                    indexed_size.value() == size,
                    "inconsistent indexed blob length"
                );
                ensure!(
                    pending.insert(&id.0, size)?.is_none(),
                    "live blob already pending deletion"
                );
                unreferenced_logical_bytes = unreferenced_logical_bytes
                    .checked_add(size)
                    .context("unreferenced size overflow")?;
            }
        }
        if unreferenced_logical_bytes != 0 {
            let live = accounting
                .get(LIVE_BYTES)?
                .context("missing live accounting")?
                .value();
            let queued = accounting
                .get(PENDING_BYTES)?
                .context("missing pending accounting")?
                .value();
            accounting.insert(
                LIVE_BYTES,
                live.checked_sub(unreferenced_logical_bytes)
                    .context("store size underflow")?,
            )?;
            accounting.insert(
                PENDING_BYTES,
                queued
                    .checked_add(unreferenced_logical_bytes)
                    .context("pending GC size overflow")?,
            )?;
        }
        Ok(unreferenced_logical_bytes)
    }

    /// Reclaim up to `limit` unreferenced content files. Active upload and
    /// result-delivery reservations protect their content from deletion.
    ///
    /// # Errors
    /// Returns an error for database failures; per-file failures remain queued
    /// and are reported in the collection result.
    pub fn collect_garbage(&self, limit: usize) -> Result<GarbageCollected> {
        let _mutation = self.inner.lock_mutations()?;
        let pins = self.inner.lock_pins()?;
        let read = self.inner.db.begin_read()?;
        let pending = read.open_table(PENDING_DELETIONS)?;
        let mut candidates = Vec::new();
        for entry in pending.iter()? {
            if candidates.len() >= limit {
                break;
            }
            let (id, size) = entry?;
            let id = ContentId(*id.value());
            if !pins.blobs.contains_key(&id) {
                candidates.push((id, size.value()));
            }
        }
        drop(pending);
        drop(read);
        // A new upload reservation requires the mutation lock. Committed
        // result readers cannot acquire new pins on pending-only content.
        drop(pins);
        let mut completed = Vec::new();
        let mut failed = Vec::new();
        let mut logical_bytes = 0_u64;
        for (id, size) in candidates {
            match self.inner.remove_blob(id) {
                Ok(()) => {
                    completed.push(id);
                    logical_bytes = logical_bytes
                        .checked_add(size)
                        .context("GC size overflow")?;
                }
                Err(error) => {
                    log::warn!("could not reclaim native content {id:?}: {error:#}");
                    failed.push(id);
                }
            }
        }
        if !completed.is_empty() {
            let write = self.inner.db.begin_write()?;
            {
                let mut pending = write.open_table(PENDING_DELETIONS)?;
                let mut accounting = write.open_table(ACCOUNTING)?;
                for id in &completed {
                    ensure!(pending.remove(&id.0)?.is_some(), "missing pending deletion");
                }
                let queued = accounting
                    .get(PENDING_BYTES)?
                    .context("missing pending accounting")?
                    .value();
                accounting.insert(
                    PENDING_BYTES,
                    queued
                        .checked_sub(logical_bytes)
                        .context("pending GC size underflow")?,
                )?;
            }
            write.commit()?;
        }
        Ok(GarbageCollected {
            blobs: u64::try_from(completed.len())?,
            logical_bytes,
            failed,
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
        let pending = read.open_table(PENDING_DELETIONS)?;
        let accounting = read.open_table(ACCOUNTING)?;
        Ok(CacheStats {
            actions: actions.len()?,
            results: results.len()?,
            trees: read.open_table(TREES)?.len()?,
            blobs: blobs.len()?,
            logical_bytes: accounting
                .get(LIVE_BYTES)?
                .context("missing live accounting")?
                .value(),
            pending_gc_blobs: pending.len()?,
            pending_gc_bytes: accounting
                .get(PENDING_BYTES)?
                .context("missing pending accounting")?
                .value(),
        })
    }
}

/// Missing-blob negotiation lease. Keep it alive until publication or
/// cancellation; dropping it releases the content reservations.
pub struct UploadReservation {
    inner: Arc<Inner>,
    reserved: Vec<ContentId>,
    missing: Vec<BlobRef>,
}

impl UploadReservation {
    #[must_use = "missing blobs must be uploaded before publication"]
    pub fn missing(&self) -> &[BlobRef] {
        &self.missing
    }
}

impl Drop for UploadReservation {
    fn drop(&mut self) {
        match self.inner.lock_pins() {
            Ok(mut pins) => {
                for id in &self.reserved {
                    release_pin(&mut pins.blobs, id);
                }
            }
            Err(error) => {
                log::error!("could not release native store upload reservation: {error:#}");
            }
        }
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
    #[must_use = "the manifest identifies the leased result"]
    pub const fn manifest(&self) -> &ResultManifest {
        &self.manifest
    }

    /// Open a file for transport. Its inode remains valid after unlinking,
    /// so a response can own it independently of this lease.
    ///
    /// # Errors
    /// Returns an error for undeclared content or filesystem failure.
    pub fn open_file(&self, id: ContentId) -> Result<File> {
        self.inner.open_declared(&self.blobs, id)
    }

    /// Open a blob belonging to this result. The reader borrows the lease and
    /// cannot outlive the corresponding eviction pin.
    ///
    /// # Errors
    /// Returns an error for an undeclared blob or filesystem failure.
    pub fn open_blob(&self, id: ContentId) -> Result<impl Read + Seek + '_> {
        Ok(LeasedReader {
            file: self.open_file(id)?,
            _lease: self,
        })
    }
}

impl Drop for ResultLease {
    fn drop(&mut self) {
        match self.inner.lock_pins() {
            Ok(mut pins) => {
                release_pin(&mut pins.actions, &self.action);
                for id in self.blobs.keys() {
                    release_pin(&mut pins.blobs, id);
                }
            }
            Err(error) => log::error!("could not release native store result lease: {error:#}"),
        }
    }
}

struct LeasedReader<'a, L> {
    file: File,
    _lease: &'a L,
}

impl<L> Read for LeasedReader<'_, L> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl<L> Seek for LeasedReader<'_, L> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

mod space;
use crate::SpacePolicy;
pub use space::SpaceReport;
mod audit;
pub use audit::{ComponentAudit, NativeIndexAudit, SchemaInventory};
mod packages;
pub use packages::{
    PackageArchiveLease, PackageDecoder, PackageImportLimits, PackagePolicy, PackageSlot,
    VerifiedPackage, decode_package_process,
};
mod trees;
pub use trees::TreeLease;
#[cfg(target_os = "linux")]
pub use trees::{MaterializationStats, MaterializedTree};

#[cfg(test)]
mod tests;
