//! Shared resident-cache accounting, admission, and restart-safe reuse policy.
//! ZFS controls physical compression and allocation. Logical byte limits are
//! deliberately conservative and do not replace filesystem free-space checks.
use std::{
    collections::{BTreeMap, BTreeSet, BinaryHeap},
    os::unix::fs::MetadataExt,
    sync::{Arc, atomic::Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, ensure};
use bincode::Options;
use redb::{ReadableDatabase, ReadableMultimapTable, ReadableTable};
use serde::{Deserialize, Serialize};

use super::{
    ACTIONS, ActionRecord, BLOB_ROOTS, Eviction, Inner, NativeStore, PACKAGES, RESULT_ACTIONS,
    RESULTS, TREE_PACKAGES, TREES, encoding, packages::PackageRecord, persist_usage,
};
use crate::{ActionKey, BlobRef, ContentId, ResultManifest, SpacePolicy, TreeId, TreeManifest};

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

impl NativeStore {
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

    fn resident_bytes(&self) -> Result<u64> {
        let stats = self.stats()?;
        stats
            .logical_bytes
            .checked_add(stats.pending_gc_bytes)
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

    /// Recent immutable tree IDs for advisory worker placement. Heartbeats
    /// only clone a bounded MRU index; they never scan the full usage map or
    /// hold the pin lock across filesystem or index I/O.
    ///
    /// # Errors
    /// Returns an error when the store's in-memory pin lock is unavailable.
    pub fn recent_trees(&self, limit: usize) -> Result<Vec<TreeId>> {
        let pins = self.inner.lock_pins()?;
        let ids = pins.cached_trees.iter().take(limit).copied().collect();
        drop(pins);
        Ok(ids)
    }

    /// Persist only dirty usage records in one bounded write transaction,
    /// avoiding synchronous database writes on cache hits.
    ///
    /// # Errors
    /// Returns an error if the usage index is unavailable.
    pub fn checkpoint_usage(&self) -> Result<()> {
        let _mutation = self.inner.lock_mutations()?;
        let mut pins = self.inner.lock_pins()?;
        persist_usage(&self.inner.db, &mut pins)
    }

    fn checkpoint_usage_if_due(&self) -> Result<()> {
        const INTERVAL: Duration = Duration::from_secs(60);
        let due = {
            let pins = self.inner.lock_pins()?;
            !pins.dirty_usage.is_empty()
                && pins
                    .last_usage_checkpoint
                    .is_none_or(|last| last.elapsed() >= INTERVAL)
        };
        if due {
            self.checkpoint_usage()?;
        }
        Ok(())
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
        self.checkpoint_usage_if_due()?;
        let mut state = self
            .inner
            .space
            .lock()
            .map_err(|_| anyhow!("native space lock poisoned"))?;
        self.apply_releases(&mut state)?;
        let report = self.reclaim(policy, state.reserved, 0, || self.available_bytes());
        drop(state);
        report.map(Some)
    }

    fn reclaim(
        &self,
        policy: SpacePolicy,
        reserved: u64,
        incoming: u64,
        mut available: impl FnMut() -> Result<u64>,
    ) -> Result<SpaceReport> {
        let need = reserved
            .checked_add(incoming)
            .context("native space reservation overflow")?;
        let minimum = policy
            .min_available_bytes
            .checked_add(need)
            .context("native minimum space overflow")?;
        let target = policy
            .target_available_bytes
            .checked_add(need)
            .context("native target space overflow")?;
        self.collect_garbage(policy.gc_batch)?;
        let mut free = available()?;
        let mut resident = self
            .resident_bytes()?
            .checked_add(need)
            .context("native resident reservation overflow")?;
        let mut evicted_roots = 0;
        if free < minimum || resident > policy.max_resident_bytes {
            for root in self.eviction_candidates(policy.max_evictions_per_pass, free < minimum)? {
                let result = match root {
                    Root::Action(key) => self.evict(key)?,
                    Root::Tree(id) => self.evict_tree(id)?,
                };
                if matches!(result, Eviction::Removed { .. }) {
                    evicted_roots += 1;
                    self.collect_garbage(policy.gc_batch)?;
                    free = available()?;
                    resident = self
                        .resident_bytes()?
                        .checked_add(need)
                        .context("native resident reservation overflow")?;
                    if free >= target && resident <= policy.target_resident_bytes {
                        break;
                    }
                }
            }
        }
        Ok(SpaceReport {
            available_bytes: free,
            reserved_bytes: reserved,
            resident_bytes: resident,
            evicted_roots,
            minimum_satisfied: free >= minimum && resident <= policy.max_resident_bytes,
        })
    }

    fn eviction_candidates(&self, limit: usize, physical_pressure: bool) -> Result<Vec<Root>> {
        // This is intentionally a pressure-only path: query committed reverse
        // references and actual file allocation, never the lookup hot path.
        let read = self.inner.db.begin_read()?;
        let actions = read.open_table(ACTIONS)?;
        let results = read.open_table(RESULTS)?;
        let result_actions = read.open_multimap_table(RESULT_ACTIONS)?;
        let trees = read.open_table(TREES)?;
        let tree_packages = read.open_multimap_table(TREE_PACKAGES)?;
        let packages = read.open_table(PACKAGES)?;
        let blob_roots = read.open_multimap_table(BLOB_ROOTS)?;
        let pins = self.inner.lock_pins()?;
        let observed = now_ms();
        // Lowest cost-per-reclaimed-byte first; zero-release aliases come
        // last, but can still be evicted to uncover the final shared owner.
        // Keep at most K candidates even for very large stores.
        let mut candidates = BinaryHeap::new();
        let mut consider = |root: Root,
                            blobs: &BTreeMap<ContentId, u64>,
                            disappearing: &BTreeSet<[u8; 32]>|
         -> Result<()> {
            let total_bytes = blobs.values().try_fold(0_u64, |sum, &size| {
                sum.checked_add(size)
                    .context("eviction root bytes overflow")
            })?;
            let mut unique_logical = 0_u64;
            let mut estimated_blocks = 0_u64;
            for (&id, &size) in blobs {
                // A live descriptor may keep even an unreferenced blob in the
                // pending-GC queue, so its bytes cannot relieve this pass.
                if pins.blobs.contains_key(&id) || disappearing.is_empty() {
                    continue;
                }
                let mut has_reference = false;
                let mut exclusive = true;
                for reference in blob_roots.get(&id.0)? {
                    has_reference = true;
                    if !disappearing.contains(reference?.value()) {
                        exclusive = false;
                        break;
                    }
                }
                ensure!(
                    has_reference,
                    "indexed eviction blob has no reverse reference"
                );
                if !exclusive {
                    continue;
                }
                unique_logical = unique_logical
                    .checked_add(size)
                    .context("reclaimable logical bytes overflow")?;
                if physical_pressure {
                    let allocated = std::fs::metadata(self.inner.blob_path(id))?
                        .blocks()
                        .checked_mul(512)
                        .context("estimated allocated bytes overflow")?;
                    estimated_blocks = estimated_blocks
                        .checked_add(allocated)
                        .context("estimated reclaimable bytes overflow")?;
                }
            }
            let potential = if physical_pressure {
                estimated_blocks
            } else {
                unique_logical
            };
            let usage = pins.usage.get(&root);
            // A zero-potential root is only useful as a prerequisite for
            // breaking a shared chain of owners. Prefer any direct recovery.
            let rank = (
                u8::from(potential == 0),
                u128::from(reuse_utility(usage, total_bytes, observed)).saturating_mul(1 << 20)
                    / u128::from(potential.max(1)),
                std::cmp::Reverse(potential),
                usage.map_or(0, |record| record.last_used_ms),
                root,
            );
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
            if pins.actions.contains_key(&key) {
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
            consider(Root::Action(key), &manifest.blobs()?, &disappearing)?;
        }
        for entry in trees.iter()? {
            let (id, value) = entry?;
            let id = TreeId(*id.value());
            if pins.trees.contains_key(&id) {
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
                if let Some(BlobRef { id, size }) = record.archive {
                    if let Some(previous) = blobs.insert(id, size) {
                        ensure!(previous == size, "inconsistent archive content size");
                    }
                }
            }
            consider(Root::Tree(id), &blobs, &disappearing)?;
        }
        drop(pins);
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
    const RECENT_TREE_LIMIT: usize = 32;

    /// Reconstruct the bounded MRU list once on store open. Usage history is
    /// authoritative; the recent-tree list is just a cheap scheduling hint.
    pub(super) fn restore_tree_hints(&mut self) {
        use std::cmp::Reverse;
        let mut recent = BinaryHeap::new();
        for (&root, stats) in &self.usage {
            if let Root::Tree(id) = root {
                let rank = Reverse((stats.last_used_ms, stats.hits, id));
                if recent.len() < Self::RECENT_TREE_LIMIT {
                    recent.push(rank);
                } else if recent.peek().is_some_and(|oldest| rank < *oldest) {
                    recent.pop();
                    recent.push(rank);
                }
            }
        }
        self.cached_trees = recent
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse((_, _, id))| id)
            .collect();
    }

    pub(super) fn touch(&mut self, root: Root) {
        let record = self.usage.entry(root).or_default();
        record.hits = record.hits.saturating_add(1);
        record.last_used_ms = now_ms();
        self.dirty_usage.insert(root);
        if let Root::Tree(id) = root {
            self.cached_trees.retain(|cached| *cached != id);
            self.cached_trees.push_front(id);
            self.cached_trees.truncate(Self::RECENT_TREE_LIMIT);
        }
    }
}

/// Uncompressed upper bound on concurrent in-flight writers. Retain the
/// reservation until fsync; completed staging files are already represented
/// by filesystem space counters.
pub(super) struct StageBudget<'a> {
    store: &'a NativeStore,
    reserved: u64,
}

impl<'a> StageBudget<'a> {
    pub(super) const fn new(store: &'a NativeStore) -> Self {
        Self { store, reserved: 0 }
    }

    pub(super) fn grow_to(&mut self, size: u64) -> Result<()> {
        let Some(policy) = self.store.inner.space_policy else {
            return Ok(());
        };
        if self.reserved >= size {
            return Ok(());
        }
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
        let minimum = policy
            .min_available_bytes
            .checked_add(need)
            .context("native minimum space overflow")?;
        let resident = self
            .store
            .resident_bytes()?
            .checked_add(need)
            .context("native resident reservation overflow")?;
        if self.store.available_bytes()? < minimum || resident > policy.max_resident_bytes {
            let report = self.store.reclaim(policy, state.reserved, extra, || {
                self.store.available_bytes()
            })?;
            ensure!(
                report.minimum_satisfied,
                "native store has insufficient allocatable space or resident budget after bounded reclamation"
            );
        }
        state.reserved = need;
        self.reserved = size;
        drop(state);
        Ok(())
    }
    /// Hold exact staged bytes until the file is committed or discarded.
    /// Streaming round-up is released to avoid inflating small blob charges.
    pub(super) fn finish(mut self, actual_bytes: u64) -> Result<StagingReservation> {
        if self.store.inner.space_policy.is_some() {
            ensure!(
                actual_bytes <= self.reserved,
                "native staging content exceeds its reservation"
            );
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
        Ok(StagingReservation {
            inner: Arc::clone(&self.store.inner),
            reserved,
        })
    }
}

pub(super) struct StagingReservation {
    inner: Arc<Inner>,
    reserved: u64,
}

impl Drop for StagingReservation {
    fn drop(&mut self) {
        if self.reserved > 0 {
            self.inner
                .space_released
                .fetch_add(self.reserved, Ordering::Release);
        }
    }
}

impl Drop for StageBudget<'_> {
    fn drop(&mut self) {
        if self.reserved > 0 {
            self.store
                .inner
                .space_released
                .fetch_add(self.reserved, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests;
