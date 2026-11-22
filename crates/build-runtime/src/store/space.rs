//! Quota-aware admission. The filesystem, not summed logical blob lengths,
//! reports allocatable bytes on compressed or block-cloned storage.
use std::time::Instant;

use anyhow::{Context, Result, anyhow, ensure};
use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};

use super::{ACTIONS, Eviction, NativeStore, TREES};
use crate::{ActionKey, TreeId};

/// Available-space watermarks on a dedicated quota-controlled filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpacePolicy {
    pub min_available_bytes: u64,
    pub target_available_bytes: u64,
    pub max_evictions_per_pass: usize,
    pub gc_batch: usize,
}

impl SpacePolicy {
    /// Validate the watermarks and work bounds.
    ///
    /// # Errors
    /// Returns an error for invalid or zero bounds.
    pub fn validate(self) -> Result<()> {
        ensure!(
            self.min_available_bytes > 0 && self.target_available_bytes >= self.min_available_bytes,
            "invalid native store space watermarks"
        );
        ensure!(
            self.max_evictions_per_pass > 0 && self.gc_batch > 0,
            "native space maintenance requires nonzero work bounds"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Root {
    Action(ActionKey),
    Tree(TreeId),
}

#[derive(Default)]
pub(super) struct SpaceState {
    reserved: u64,
}

/// Result of a bounded physical-space maintenance pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceReport {
    pub available_bytes: u64,
    pub reserved_bytes: u64,
    pub evicted_roots: usize,
    pub minimum_satisfied: bool,
}

impl NativeStore {
    /// Open a store with filesystem-aware admission and retention.
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

    /// Reclaim queued garbage, then evict least-recently-used unpinned roots
    /// when free space is below the low watermark. Recheck real available
    /// space after reclaiming; shared blocks, open inodes and snapshots may
    /// prevent physical reclamation.
    ///
    /// # Errors
    /// Returns an error for filesystem, index or synchronization failure.
    pub fn maintain_space(&self) -> Result<Option<SpaceReport>> {
        let Some(policy) = self.inner.space_policy else {
            return Ok(None);
        };
        let state = self
            .inner
            .space
            .lock()
            .map_err(|_| anyhow!("native space lock poisoned"))?;
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
        let mut evicted_roots = 0;
        if free < minimum {
            for root in self
                .eviction_candidates()?
                .into_iter()
                .take(policy.max_evictions_per_pass)
            {
                let result = match root {
                    Root::Action(key) => self.evict(key)?,
                    Root::Tree(id) => self.evict_tree(id)?,
                };
                if matches!(result, Eviction::Removed { .. }) {
                    evicted_roots += 1;
                    self.collect_garbage(policy.gc_batch)?;
                    free = available()?;
                    if free >= target {
                        break;
                    }
                }
            }
        }
        Ok(SpaceReport {
            available_bytes: free,
            reserved_bytes: reserved,
            evicted_roots,
            minimum_satisfied: free >= minimum,
        })
    }

    fn eviction_candidates(&self) -> Result<Vec<Root>> {
        // Snapshot only the rank and pin state. Actual eviction rechecks pins
        // transactionally; ordinary lookups never take the space lock.
        let read = self.inner.db.begin_read()?;
        let actions = read.open_table(ACTIONS)?;
        let trees = read.open_table(TREES)?;
        let pins = self.inner.lock_pins()?;
        let mut candidates = Vec::new();
        for entry in actions.iter()? {
            let (key, _) = entry?;
            let key = ActionKey(*key.value());
            if !pins.actions.contains_key(&key) {
                let root = Root::Action(key);
                candidates.push((pins.last_used.get(&root).copied(), root));
            }
        }
        for entry in trees.iter()? {
            let (id, _) = entry?;
            let id = TreeId(*id.value());
            if !pins.trees.contains_key(&id) {
                let root = Root::Tree(id);
                candidates.push((pins.last_used.get(&root).copied(), root));
            }
        }
        drop(pins);
        // Unknown recency after restart sorts first. No synchronous DB write on a hit.
        candidates.sort_unstable();
        Ok(candidates.into_iter().map(|(_, root)| root).collect())
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
        let need = state
            .reserved
            .checked_add(extra)
            .context("native stage reservation overflow")?;
        let minimum = policy
            .min_available_bytes
            .checked_add(need)
            .context("native minimum space overflow")?;
        if self.store.available_bytes()? < minimum {
            let report = self.store.reclaim(policy, state.reserved, extra, || {
                self.store.available_bytes()
            })?;
            ensure!(
                report.minimum_satisfied,
                "native store has insufficient allocatable space after bounded reclamation"
            );
        }
        state.reserved = need;
        self.reserved = size;
        drop(state);
        Ok(())
    }
}

impl Drop for StageBudget<'_> {
    fn drop(&mut self) {
        if self.reserved > 0 {
            match self.store.inner.space.lock() {
                Ok(mut state) => state.reserved -= self.reserved,
                Err(error) => log::error!("native space reservation release failed: {error}"),
            }
        }
    }
}

impl super::Pins {
    pub(super) fn touch(&mut self, root: Root) {
        self.last_used.insert(root, Instant::now());
    }
}

#[cfg(test)]
mod tests;
