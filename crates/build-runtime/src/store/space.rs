//! Shared resident-cache accounting, admission, and restart-safe reuse policy.
//! ZFS controls physical compression and allocation. Logical byte limits are
//! deliberately conservative and do not replace filesystem free-space checks.
use std::{
    collections::{BTreeMap, BTreeSet, BinaryHeap},
    os::unix::fs::MetadataExt,
    sync::{Arc, TryLockError, atomic::Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, ensure};
use bincode::Options;
use redb::{ReadOnlyMultimapTable, ReadableDatabase, ReadableMultimapTable, ReadableTable};
use serde::{Deserialize, Serialize};

use super::{
    ACTIONS, ActionRecord, BLOB_ROOTS, Eviction, Inner, NativeStore, PACKAGES, RESULT_ACTIONS,
    RESULTS, TREE_PACKAGES, TREES, encoding, packages::PackageRecord, persist_usage,
};
use crate::{
    ActionKey, BlobRef, ContentId, ResultId, ResultManifest, SpacePolicy, TreeId, TreeManifest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Root {
    Action(ActionKey),
    Tree(TreeId),
}

impl Root {
    pub(super) fn key(self) -> [u8; 33] {
        let mut out = [0; 33];
        match self {
            Self::Action(id) => {
                out[0] = 0;
                out[1..].copy_from_slice(&id.0);
            }
            Self::Tree(id) => {
                out[0] = 1;
                out[1..].copy_from_slice(&id.0);
            }
        }
        out
    }

    pub(super) fn from_key(key: [u8; 33]) -> Result<Self> {
        let mut digest = [0; 32];
        digest.copy_from_slice(&key[1..]);
        match key[0] {
            0 => Ok(Self::Action(ActionKey(digest))),
            1 => Ok(Self::Tree(TreeId(digest))),
            _ => Err(anyhow!("invalid native usage root type")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EvictionTarget {
    Action(ActionKey, ResultId),
    Tree(TreeId),
}

impl EvictionTarget {
    const fn root(self) -> Root {
        match self {
            Self::Action(key, _) => Root::Action(key),
            Self::Tree(id) => Root::Tree(id),
        }
    }

    fn evict(self, store: &NativeStore) -> Result<Eviction> {
        match self {
            Self::Action(key, result) => store.evict_action(key, Some(result)),
            Self::Tree(id) => store.evict_tree(id),
        }
    }
}

/// Usage is buffered in memory and checkpointed in a single transaction.
/// Last access uses wall time only for eviction heuristics, never identity.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct UsageRecord {
    hits: u64,
    last_used_ms: u64,
}

fn now_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(elapsed).unwrap_or(u64::MAX)
}

#[derive(Default)]
pub(super) struct SpaceState {
    reserved: u64,
    waiting: u64,
}

/// Result of a bounded physical-space and resident-content maintenance pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceReport {
    pub available_bytes: u64,
    pub reserved_bytes: u64,
    pub resident_bytes: u64,
    pub evicted_roots: usize,
    /// Both physical free space and resident-budget admission are satisfied.
    pub minimum_satisfied: bool,
}

/// Read-only filesystem and staging-budget observation. Physical free space
/// and logical resident bytes are distinct quantities on compressed storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceStatus {
    pub available_bytes: u64,
    /// None for unmanaged stores or while an admission/eviction pass owns the lock.
    pub reserved_bytes: Option<u64>,
    pub policy: Option<SpacePolicy>,
}

impl NativeStore {
    pub(super) fn staging_limit(&self, policy: SpacePolicy) -> Result<u64> {
        if let Some(limit) = policy.max_resident_bytes {
            return Ok(limit);
        }
        let stat = rustix::fs::statvfs(&self.inner.root)?;
        let capacity = stat
            .f_blocks
            .checked_mul(stat.f_frsize)
            .context("filesystem capacity overflow")?;
        Ok(capacity.saturating_sub(policy.min_available_bytes))
    }

    pub(crate) fn check_transfer_capacity(&self, bytes: u64) -> Result<()> {
        if let Some(policy) = self.inner.space_policy {
            let limit = self.staging_limit(policy)?;
            ensure!(
                bytes <= limit,
                StageSpaceTooLarge {
                    requested: bytes,
                    limit
                }
            );
        }
        Ok(())
    }

    /// Open a store with a managed resident budget and filesystem admission.
    ///
    /// # Errors
    /// Returns an error for invalid policy or storage initialization failure.
    pub fn open_managed(root: &std::path::Path, policy: SpacePolicy) -> Result<Self> {
        policy.validate()?;
        Self::open_inner(root, Some(policy))
    }

    fn available_bytes(&self) -> Result<u64> {
        let stat = rustix::fs::statvfs(&self.inner.root)?;
        stat.f_bavail
            .checked_mul(stat.f_frsize)
            .context("available filesystem size overflow")
    }

    /// Observe free filesystem space and pending staging reservations without
    /// running reclamation or waiting behind a reclaiming admission.
    ///
    /// # Errors
    /// Returns an error for a failed filesystem query or poisoned lock.
    pub fn space_status(&self) -> Result<SpaceStatus> {
        let reserved_bytes = if self.inner.space_policy.is_some() {
            match self.inner.space.try_lock() {
                Ok(state) => Some(
                    state
                        .reserved
                        .checked_sub(self.inner.space_released.load(Ordering::Acquire))
                        .context("native staging reservation underflow")?,
                ),
                Err(TryLockError::WouldBlock) => None,
                Err(TryLockError::Poisoned(_)) => {
                    return Err(anyhow!("native space lock poisoned"));
                }
            }
        } else {
            None
        };
        Ok(SpaceStatus {
            available_bytes: self.available_bytes()?,
            reserved_bytes,
            policy: self.inner.space_policy,
        })
    }

    fn resident_bytes(&self) -> Result<u64> {
        let read = self.inner.db.begin_read()?;
        let accounting = read.open_table(super::ACCOUNTING)?;
        let live = accounting
            .get(super::LIVE_BYTES)?
            .context("missing live accounting")?
            .value();
        let pending = accounting
            .get(super::PENDING_BYTES)?
            .context("missing pending accounting")?
            .value();
        live.checked_add(pending)
            .context("native resident byte overflow")
    }

    fn apply_releases(&self, state: &mut SpaceState) -> Result<()> {
        // The only additive reservations are serialized under the space lock.
        // Concurrent drops only subtract, and therefore cannot overcommit.
        let released = self.inner.space_released.swap(0, Ordering::AcqRel);
        state.reserved = state
            .reserved
            .checked_sub(released)
            .context("native staging reservation underflow")?;
        Ok(())
    }

    /// Reserve space before starting work whose output will enter this CAS.
    /// The budget transfers directly into staged blobs without a second charge.
    /// # Errors
    /// Returns an error if the managed store cannot admit the reservation.
    pub fn reserve_staging(&self, bytes: u64) -> Result<StageBudget> {
        let mut budget = StageBudget::new(self);
        budget.grow_to(bytes)?;
        Ok(budget)
    }

    /// Build a bounded residency summary from a consistent live-blob index snapshot.
    /// # Errors
    /// Returns an error for index failure.
    pub fn blob_residency(&self) -> Result<Option<crate::BlobResidency>> {
        use redb::ReadableTableMetadata;
        let read = self.inner.db.begin_read()?;
        let blobs = read.open_table(super::BLOBS)?;
        let Some(mut summary) = crate::BlobResidency::for_count(blobs.len()?) else {
            return Ok(None);
        };
        for entry in blobs.iter()? {
            let (id, _) = entry?;
            summary.insert(ContentId(*id.value()));
        }
        Ok(Some(summary))
    }

    /// Persist only dirty usage records in one bounded write transaction,
    /// avoiding synchronous database writes on cache hits.
    /// # Errors
    /// Returns an error if the usage index is unavailable.
    pub fn checkpoint_usage(&self) -> Result<()> {
        let _mutation = self.inner.lock_mutations()?;
        self.checkpoint_usage_locked(false)
    }

    fn checkpoint_usage_locked(&self, only_due: bool) -> Result<()> {
        // Mutation exclusion prevents eviction from removing these roots
        // while their checkpoint is in progress. Readers may still touch
        // them; keep any newer usage dirty for the next checkpoint.
        let records = {
            let pins = self.inner.lock_pins()?;
            if only_due && !pins.usage_checkpoint_due() {
                return Ok(());
            }
            pins.usage_snapshot()
        };
        if !records.is_empty() {
            persist_usage(&self.inner.db, &records)?;
            self.inner.lock_pins()?.finish_usage_checkpoint(&records);
        }
        Ok(())
    }

    fn checkpoint_usage_if_due(&self) -> Result<()> {
        if !self.inner.lock_pins()?.usage_checkpoint_due() {
            return Ok(());
        }
        // Maintenance is opportunistic. A concurrent publication or
        // checkpoint can finish before the next maintenance pass.
        match self.inner.mutations.try_lock() {
            Ok(_mutation) => self.checkpoint_usage_locked(true),
            Err(TryLockError::WouldBlock) => Ok(()),
            Err(TryLockError::Poisoned(_)) => Err(anyhow!("native store mutation lock poisoned")),
        }
    }

    /// Reclaim queued garbage before considering eviction. Keep leases intact
    /// and recheck filesystem allocation after each bounded GC pass.
    ///
    /// # Errors
    /// Returns an error for filesystem, index or synchronization failure.
    pub fn maintain_space(&self) -> Result<Option<SpaceReport>> {
        let Some(policy) = self.inner.space_policy else {
            return Ok(None);
        };
        let _maintenance = match self.inner.space_maintenance.try_lock() {
            Ok(lock) => lock,
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Poisoned(_)) => {
                return Err(anyhow!("native maintenance lock poisoned"));
            }
        };
        self.checkpoint_usage_if_due()?;
        let incoming = {
            let mut state = self
                .inner
                .space
                .lock()
                .map_err(|_| anyhow!("native space lock poisoned"))?;
            self.apply_releases(&mut state)?;
            let incoming = std::mem::take(&mut state.waiting);
            drop(state);
            incoming
        };
        self.reclaim(
            policy,
            || {
                let mut state = self
                    .inner
                    .space
                    .lock()
                    .map_err(|_| anyhow!("native space lock poisoned"))?;
                self.apply_releases(&mut state)?;
                let reserved = state.reserved;
                drop(state);
                Ok(reserved)
            },
            incoming,
            || self.available_bytes(),
        )
        .map(Some)
    }

    fn reclaim(
        &self,
        policy: SpacePolicy,
        mut reservations: impl FnMut() -> Result<u64>,
        incoming: u64,
        mut available: impl FnMut() -> Result<u64>,
    ) -> Result<SpaceReport> {
        // The soft watermarks maintain a ready buffer for new work. A larger
        // observed request can ask the next pass for additional headroom.
        let staging_limit = self.staging_limit(policy)?;
        let resident_target = policy.target_resident_bytes.map_or(u64::MAX, |target| {
            target.min(policy.resident_limit().saturating_sub(incoming))
        });
        let available_target = policy
            .target_available_bytes
            .max(policy.min_available_bytes.saturating_add(incoming));
        self.collect_garbage(policy.gc_batch)?;
        let mut observe = || -> Result<(u64, u64, u64)> {
            let reserved = reservations()?;
            Ok((
                available()?,
                self.resident_bytes()?.saturating_add(reserved),
                reserved,
            ))
        };
        let (mut free, mut resident, mut reserved) = observe()?;
        let mut evicted_roots = 0;
        // A transient inability to admit the requested reservation cannot be
        // solved by eviction if active writers alone exceed the ceiling.
        if reserved <= staging_limit.saturating_sub(incoming)
            && (free.saturating_sub(reserved) < available_target || resident > resident_target)
        {
            #[cfg(target_os = "linux")]
            self.drop_idle_views(None)?;
            let candidates = self.eviction_candidates(
                policy.max_evictions_per_pass,
                free.saturating_sub(reserved) < available_target,
            )?;
            (free, resident, reserved) = observe()?;
            for candidate in candidates {
                if reserved > staging_limit.saturating_sub(incoming)
                    || (free.saturating_sub(reserved) >= available_target
                        && resident <= resident_target)
                {
                    break;
                }
                if matches!(candidate.evict(self)?, Eviction::Removed { .. }) {
                    evicted_roots += 1;
                    self.collect_garbage(policy.gc_batch)?;
                }
                // Observe current reservations after every eviction. The
                // admission lock is never held across eviction or filesystem GC.
                (free, resident, reserved) = observe()?;
            }
        }
        Ok(SpaceReport {
            available_bytes: free,
            reserved_bytes: reserved,
            resident_bytes: resident,
            evicted_roots,
            minimum_satisfied: free.saturating_sub(reserved) >= policy.min_available_bytes
                && resident <= policy.resident_limit(),
        })
    }

    fn reclaimable_potential(
        &self,
        blobs: &BTreeMap<ContentId, u64>,
        disappearing: &BTreeSet<[u8; 32]>,
        pinned_blobs: &BTreeSet<ContentId>,
        owners: &ReadOnlyMultimapTable<&[u8; 32], &[u8; 32]>,
        physical_pressure: bool,
    ) -> Result<u64> {
        let mut potential = 0_u64;
        for (&id, &size) in blobs {
            if pinned_blobs.contains(&id) || disappearing.is_empty() {
                continue;
            }
            let mut has_owner = false;
            let mut exclusive = true;
            for reference in owners.get(&id.0)? {
                has_owner = true;
                if !disappearing.contains(reference?.value()) {
                    exclusive = false;
                    break;
                }
            }
            ensure!(has_owner, "indexed eviction blob has no reverse reference");
            if exclusive {
                // st_blocks reports allocated blocks, including compression,
                // but not snapshot/reflink exclusivity on ZFS. Validate real
                // free space after GC rather than claiming exact release.
                let bytes = if physical_pressure {
                    match std::fs::metadata(self.inner.blob_path(id)) {
                        Ok(metadata) => metadata
                            .blocks()
                            .checked_mul(512)
                            .context("estimated allocated bytes overflow")?,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
                        Err(error) => return Err(error.into()),
                    }
                } else {
                    size
                };
                potential = potential
                    .checked_add(bytes)
                    .context("estimated reclaimable bytes overflow")?;
            }
        }
        Ok(potential)
    }

    fn rank_eviction_candidate(
        &self,
        candidate: EvictionTarget,
        blobs: &BTreeMap<ContentId, u64>,
        disappearing: &BTreeSet<[u8; 32]>,
        owners: &ReadOnlyMultimapTable<&[u8; 32], &[u8; 32]>,
        physical_pressure: bool,
        observed: u64,
    ) -> Result<(u8, u128, std::cmp::Reverse<u64>, u64, EvictionTarget)> {
        // The pin lock must not be held while consulting filesystem blocks:
        // a slow ZFS metadata lookup must not delay normal cache hits.
        let pins = self.inner.lock_pins()?;
        let usage = pins.usage.get(&candidate.root()).copied();
        let pinned_blobs = blobs
            .keys()
            .filter(|id| pins.blobs.contains_key(*id))
            .copied()
            .collect::<BTreeSet<_>>();
        drop(pins);
        let total_bytes = blobs.values().try_fold(0_u64, |sum, &size| {
            sum.checked_add(size)
                .context("eviction root bytes overflow")
        })?;
        let potential = self.reclaimable_potential(
            blobs,
            disappearing,
            &pinned_blobs,
            owners,
            physical_pressure,
        )?;
        Ok((
            u8::from(potential == 0),
            u128::from(reuse_utility(usage.as_ref(), total_bytes, observed))
                .saturating_mul(1 << 20)
                / u128::from(potential.max(1)),
            std::cmp::Reverse(potential),
            usage.map_or(0, |record| record.last_used_ms),
            candidate,
        ))
    }

    fn eviction_candidates(
        &self,
        limit: usize,
        physical_pressure: bool,
    ) -> Result<Vec<EvictionTarget>> {
        // Ranking is advisory: use one committed reverse-index snapshot
        // without blocking writers. Allocation observations can change as
        // files disappear; actual eviction revalidates the action generation
        // and pins, and admission rechecks actual free space afterwards.
        if limit == 0 {
            return Ok(Vec::new());
        }
        let read = self.inner.db.begin_read()?;
        let actions = read.open_table(ACTIONS)?;
        let results = read.open_table(RESULTS)?;
        let result_actions = read.open_multimap_table(RESULT_ACTIONS)?;
        let trees = read.open_table(TREES)?;
        let tree_packages = read.open_multimap_table(TREE_PACKAGES)?;
        let packages = read.open_table(PACKAGES)?;
        let blob_roots = read.open_multimap_table(BLOB_ROOTS)?;
        let observed = now_ms();
        // Bound memory to K candidates even when the backing index is huge.
        let mut candidates = BinaryHeap::new();
        let mut consider = |candidate: EvictionTarget,
                            blobs: &BTreeMap<ContentId, u64>,
                            disappearing: &BTreeSet<[u8; 32]>|
         -> Result<()> {
            let rank = self.rank_eviction_candidate(
                candidate,
                blobs,
                disappearing,
                &blob_roots,
                physical_pressure,
                observed,
            )?;
            if candidates.len() < limit {
                candidates.push(rank);
            } else if candidates.peek().is_some_and(|worst| rank < *worst) {
                candidates.pop();
                candidates.push(rank);
            }
            Ok(())
        };
        for entry in actions.iter()? {
            let (key, value) = entry?;
            let key = ActionKey(*key.value());
            if self.inner.lock_pins()?.actions.contains_key(&key) {
                continue;
            }
            let record: ActionRecord = encoding().deserialize(value.value())?;
            let manifest = results
                .get(&record.result.0)?
                .context("missing native eviction result")?;
            let manifest: ResultManifest = encoding().deserialize(manifest.value())?;
            let mut aliases = result_actions.get(&record.result.0)?;
            ensure!(
                aliases.next().transpose()?.is_some(),
                "missing native result alias"
            );
            let disappearing = if aliases.next().transpose()?.is_none() {
                BTreeSet::from([record.result.0])
            } else {
                BTreeSet::new()
            };
            consider(
                EvictionTarget::Action(key, record.result),
                &manifest.blobs()?,
                &disappearing,
            )?;
        }
        for entry in trees.iter()? {
            let (id, value) = entry?;
            let id = TreeId(*id.value());
            if self.inner.lock_pins()?.trees.contains_key(&id) {
                continue;
            }
            let manifest: TreeManifest = encoding().deserialize(value.value())?;
            let mut blobs = manifest.blobs()?;
            let mut disappearing = BTreeSet::from([id.0]);
            for package in tree_packages.get(&id.0)? {
                let package = *package?.value();
                let record = packages
                    .get(&package)?
                    .context("missing native eviction package")?;
                let record: PackageRecord = encoding().deserialize(record.value())?;
                ensure!(record.tree == id, "inconsistent native package tree");
                disappearing.insert(package);
                if let Some(BlobRef { id, size }) = record.archive
                    && let Some(previous) = blobs.insert(id, size)
                {
                    ensure!(previous == size, "inconsistent archive content size");
                }
            }
            consider(EvictionTarget::Tree(id), &blobs, &disappearing)?;
        }
        Ok(candidates
            .into_sorted_vec()
            .into_iter()
            .map(|(_, _, _, _, root)| root)
            .collect())
    }
}

/// Higher scores mean more expected reuse benefit. Logarithmic hit and
/// transport-size weights prevent an old, very popular artifact from becoming
/// immortal; idle age eventually dominates. Zero-byte roots cannot release
/// blob space and are evicted only after all useful candidates.
fn reuse_utility(usage: Option<&UsageRecord>, bytes: u64, now: u64) -> u64 {
    if bytes == 0 {
        return u64::MAX;
    }
    let usage = usage.copied().unwrap_or_default();
    let frequency = u64::from(usage.hits.max(1).ilog2()) + 1;
    let size_mib = bytes.div_ceil(1 << 20);
    let transfer_cost = u64::from(size_mib.ilog2()) + 1;
    let idle_hours = now.saturating_sub(usage.last_used_ms) / 3_600_000;
    frequency
        .saturating_mul(transfer_cost)
        .saturating_mul(1 << 16)
        / idle_hours.saturating_add(1)
}

impl super::Pins {
    fn usage_checkpoint_due(&self) -> bool {
        const INTERVAL: Duration = Duration::from_secs(60);
        !self.dirty_usage.is_empty()
            && self
                .last_usage_checkpoint
                .is_none_or(|last| last.elapsed() >= INTERVAL)
    }

    pub(super) fn usage_snapshot(&self) -> Vec<(Root, UsageRecord)> {
        self.dirty_usage
            .iter()
            .filter_map(|root| self.usage.get(root).map(|record| (*root, *record)))
            .collect()
    }

    fn finish_usage_checkpoint(&mut self, records: &[(Root, UsageRecord)]) {
        for (root, record) in records {
            if self.usage.get(root) == Some(record) {
                self.dirty_usage.remove(root);
            }
        }
        self.last_usage_checkpoint = Some(super::Instant::now());
    }

    pub(super) fn touch(&mut self, root: Root) {
        let record = self.usage.entry(root).or_default();
        record.hits = record.hits.saturating_add(1);
        record.last_used_ms = now_ms();
        self.dirty_usage.insert(root);
    }
}

/// Uncompressed upper bound on concurrent in-flight writers. Retain the
/// reservation until fsync; completed staging files are already represented
/// by filesystem space counters.
pub struct StageBudget {
    store: NativeStore,
    reserved: u64,
}

#[derive(Debug)]
pub struct StageSpaceExhausted {
    requested: u64,
    reserved: u64,
    resident: u64,
    available: u64,
    limit: u64,
    evicted: usize,
}

#[derive(Debug)]
pub struct StageSpaceTooLarge {
    requested: u64,
    limit: u64,
}

impl std::fmt::Display for StageSpaceTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "native staging request {} exceeds resident budget {}",
            self.requested, self.limit
        )
    }
}

impl std::error::Error for StageSpaceTooLarge {}

impl std::fmt::Display for StageSpaceExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "native CAS pressure: requested={}, reserved={}, projected_resident={}, available={}, resident_limit={}, evicted_roots={}",
            self.requested, self.reserved, self.resident, self.available, self.limit, self.evicted
        )
    }
}

impl std::error::Error for StageSpaceExhausted {}

impl StageBudget {
    pub(super) fn new(store: &NativeStore) -> Self {
        Self {
            store: store.clone(),
            reserved: 0,
        }
    }

    /// Stage a verified blob using space already reserved by this budget.
    /// # Errors
    /// Returns an error for insufficient reserved bytes, invalid content or I/O failure.
    pub fn stage_expected(
        &mut self,
        expected: BlobRef,
        reader: impl std::io::Read,
    ) -> Result<super::StagedBlob> {
        let limit = expected
            .size
            .checked_add(1)
            .context("blob length overflow")?;
        let child = self.split(expected.size)?;
        let staged =
            self.store
                .stage_local_inner(reader.take(limit), Some(expected.size), child)?;
        let actual = staged.reference();
        ensure!(
            actual.size == expected.size,
            super::BlobIntegrityError::Length {
                expected: expected.size,
                actual: actual.size
            }
        );
        ensure!(actual.id == expected.id, super::BlobIntegrityError::Digest);
        Ok(staged)
    }

    fn split(&mut self, size: u64) -> Result<Self> {
        ensure!(
            size <= self.reserved,
            "blob exceeds reserved staging headroom"
        );
        self.reserved -= size;
        Ok(Self {
            store: self.store.clone(),
            reserved: size,
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn belongs_to(&self, store: &NativeStore) -> bool {
        Arc::ptr_eq(&self.store.inner, &store.inner)
    }

    /// Encode and hash a private compiler output straight into its CAS inode.
    /// Durability is deferred until publication, outside compiler admission.
    /// Returns None when the optional local CAS has insufficient headroom.
    ///
    /// # Errors
    /// Returns an error for failed I/O, encoding, or invalid content.
    #[cfg(target_os = "linux")]
    pub(crate) fn try_stage_capture(
        &mut self,
        size: u64,
        reader: impl std::io::Read,
    ) -> Result<Option<super::CapturedStage>> {
        use std::os::unix::fs::PermissionsExt as _;
        match self.grow_to(size) {
            Ok(()) => (),
            Err(error) if error.is::<StageSpaceExhausted>() || error.is::<StageSpaceTooLarge>() => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        let budget = self.split(size)?;
        let limit = size.checked_add(1).context("blob length overflow")?;
        let mut file = tempfile::NamedTempFile::new_in(self.store.inner.root.join("staging"))?;
        let encoding = self.store.physical_encoding();
        let reader = reader.take(limit);
        let reference = match encoding {
            crate::BlobEncoding::Raw => {
                crate::encode_native_raw_blob(reader, file.as_file_mut(), Some(size))?
            }
            crate::BlobEncoding::ZstdChunks => {
                crate::encode_native_blob(reader, file.as_file_mut(), Some(size))?
            }
        };
        ensure!(
            reference.size == size,
            super::BlobIntegrityError::Length {
                expected: size,
                actual: reference.size
            }
        );
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o400))?;
        let metadata = file.as_file().metadata()?;
        let stage = super::StagedBlob {
            path: file.into_temp_path(),
            metadata,
            reference,
            encoding,
            owner: Arc::clone(&self.store.inner),
            _reservation: budget.finish(size)?,
        };
        let file = Arc::new(stage.open_file()?);
        Ok(Some(super::CapturedStage { stage, file }))
    }

    pub(super) fn grow_to(&mut self, size: u64) -> Result<()> {
        let Some(policy) = self.store.inner.space_policy else {
            self.reserved = self.reserved.max(size);
            return Ok(());
        };
        if self.reserved >= size {
            return Ok(());
        }
        let limit = self.store.staging_limit(policy)?;
        ensure!(
            size <= limit,
            StageSpaceTooLarge {
                requested: size,
                limit
            }
        );
        let extra = size - self.reserved;
        let mut state = self
            .store
            .inner
            .space
            .lock()
            .map_err(|_| anyhow!("native space lock poisoned"))?;
        self.store.apply_releases(&mut state)?;
        let need = state
            .reserved
            .checked_add(extra)
            .context("native stage reservation overflow")?;
        let resident = self.store.resident_bytes()?.saturating_add(need);
        let available = self.store.available_bytes()?;
        if available.saturating_sub(need) < policy.min_available_bytes
            || resident > policy.resident_limit()
        {
            // No cache scanning, eviction or garbage collection on the
            // admission path. The maintenance service prepares more room.
            // Maintenance defers eviction while outstanding reservations
            // alone make admission impossible.
            state.waiting = state.waiting.max(extra);
            return Err(StageSpaceExhausted {
                requested: extra,
                reserved: state.reserved,
                resident,
                available,
                limit,
                evicted: 0,
            }
            .into());
        }
        state.reserved = need;
        self.reserved = size;
        drop(state);
        Ok(())
    }
    /// Hold exact staged bytes until the file is committed or discarded.
    /// Streaming round-up is released to avoid inflating small blob charges.
    pub(super) fn finish(mut self, actual_bytes: u64) -> Result<StagingReservation> {
        ensure!(
            actual_bytes <= self.reserved,
            "native staging content exceeds its reservation"
        );
        if self.store.inner.space_policy.is_none() {
            return Ok(StagingReservation::new(&self.store.inner, 0));
        }
        if actual_bytes < self.reserved {
            let surplus = self.reserved - actual_bytes;
            self.store
                .inner
                .space_released
                .fetch_add(surplus, Ordering::Release);
            self.reserved = actual_bytes;
        }
        let reserved = std::mem::take(&mut self.reserved);
        Ok(StagingReservation::new(&self.store.inner, reserved))
    }
}

#[derive(Clone)]
pub struct StagingReservation {
    _charge: Arc<StagingCharge>,
}

impl StagingReservation {
    fn new(inner: &Arc<Inner>, reserved: u64) -> Self {
        Self {
            _charge: Arc::new(StagingCharge {
                inner: Arc::clone(inner),
                reserved,
            }),
        }
    }
}

struct StagingCharge {
    inner: Arc<Inner>,
    reserved: u64,
}

impl Drop for StagingCharge {
    fn drop(&mut self) {
        if self.reserved > 0 {
            self.inner
                .space_released
                .fetch_add(self.reserved, Ordering::Release);
        }
    }
}

impl Drop for StageBudget {
    fn drop(&mut self) {
        if self.reserved > 0 && self.store.inner.space_policy.is_some() {
            self.store
                .inner
                .space_released
                .fetch_add(self.reserved, Ordering::Release);
        }
    }
}

mod analytics;
pub use analytics::CacheAnalyticsSampler;

#[cfg(test)]
mod tests;
