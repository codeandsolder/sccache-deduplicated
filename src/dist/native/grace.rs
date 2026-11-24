//! A bounded grace tier over the same immutable worker CAS.

use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use crate::build_runtime::{
    ActionFingerprint, ActionMode, CapturedExecution, ContentId, NativeStore, ResultLease,
    ResultManifest, StageBudget,
};

type Contents = BTreeMap<ContentId, u64>;

struct ProtectedResult {
    expires: Instant,
    contents: Contents,
    _lease: ResultLease,
}

#[derive(Default)]
struct State {
    results: VecDeque<ProtectedResult>,
    refs: BTreeMap<ContentId, (u64, usize)>,
    bytes: u64,
    pending: u64,
}

impl State {
    fn release(&mut self, contents: &Contents) {
        for id in contents.keys() {
            if let Entry::Occupied(mut entry) = self.refs.entry(*id) {
                let (size, count) = entry.get_mut();
                *count -= 1;
                if *count == 0 {
                    self.bytes -= *size;
                    entry.remove();
                }
            }
        }
    }

    fn reap(&mut self, now: Instant) {
        while self
            .results
            .front()
            .is_some_and(|entry| entry.expires <= now)
        {
            if let Some(entry) = self.results.pop_front() {
                self.release(&entry.contents);
                drop(entry);
            }
        }
    }
}

/// Logical grace budget, including prospective outputs of running/staging jobs.
#[derive(Clone)]
pub struct ArtifactGrace {
    duration: Duration,
    max_bytes: u64,
    state: Arc<Mutex<State>>,
}

impl ArtifactGrace {
    /// # Errors
    /// Rejects unusable lifetime or storage bounds.
    pub fn new(duration: Duration, max_bytes: u64) -> Result<Self> {
        ensure!(
            !duration.is_zero() && Instant::now().checked_add(duration).is_some() && max_bytes > 0,
            "invalid worker artifact grace policy"
        );
        Ok(Self {
            duration,
            max_bytes,
            state: Arc::new(Mutex::new(State::default())),
        })
    }

    /// Expiry releases only grace leases, not consumer input leases.
    pub fn reap(&self) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reap(Instant::now());
    }

    pub(super) fn reserve(&self, limit: u64) -> Result<Option<GraceReservation>> {
        ensure!(
            limit <= self.max_bytes,
            "result limit exceeds worker artifact grace budget"
        );
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.reap(Instant::now());
        if limit > self.max_bytes - state.bytes - state.pending {
            return Ok(None);
        }
        state.pending += limit;
        drop(state);
        Ok(Some(GraceReservation {
            pool: self.clone(),
            limit,
        }))
    }
}

pub(super) struct GraceReservation {
    pool: ArtifactGrace,
    limit: u64,
}

impl GraceReservation {
    pub(super) fn retain(
        self,
        store: &NativeStore,
        budget: &mut StageBudget,
        fingerprint: &ActionFingerprint,
        manifest: &ResultManifest,
        captured: &CapturedExecution,
    ) -> Result<()> {
        if manifest.outputs.is_empty() {
            return Ok(());
        }
        let existing = store.reserve_upload(manifest)?;
        let mut staged = Vec::new();
        for &blob in existing.missing() {
            staged.push(budget.stage_expected(blob, captured.open_blob(blob.id)?)?);
        }
        let lease = store.publish_pinned(fingerprint, manifest, staged, ActionMode::Refresh)?;
        self.commit(lease)
    }

    fn commit(mut self, lease: ResultLease) -> Result<()> {
        let contents = lease.manifest().blobs()?;
        let mut state = self
            .pool
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let expires = Instant::now()
            .checked_add(self.pool.duration)
            .context("grace deadline overflow")?;
        let mut additional = 0_u64;
        for (&id, &size) in &contents {
            if let Some(&(previous, count)) = state.refs.get(&id) {
                ensure!(
                    previous == size && count < usize::MAX,
                    "invalid grace content accounting"
                );
            } else {
                additional = additional
                    .checked_add(size)
                    .context("grace bytes overflow")?;
            }
        }
        ensure!(
            additional <= self.limit,
            "actual result exceeds reserved grace budget"
        );
        // Convert the upper-bound charge into the actual union of content.
        state.pending -= self.limit;
        self.limit = 0;
        for (&id, &size) in &contents {
            state.refs.entry(id).or_insert((size, 0)).1 += 1;
        }
        state.bytes += additional;
        state.results.push_back(ProtectedResult {
            expires,
            contents,
            _lease: lease,
        });
        drop(state);
        Ok(())
    }
}

impl Drop for GraceReservation {
    fn drop(&mut self) {
        if self.limit != 0 {
            self.pool
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pending -= self.limit;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_runtime::{Artifact, BlobRef, Eviction};

    #[test]
    fn shared_artifacts_charge_once_and_expiry_releases_eviction_pin() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let pool = ArtifactGrace::new(Duration::from_secs(300), 8)?;
        let contents = b"data";
        let blob = BlobRef {
            id: ContentId::of(contents),
            size: 4,
        };
        let manifest = ResultManifest {
            outputs: BTreeMap::from([("obj".into(), Artifact { blob, mode: None })]),
            stdout: None,
            stderr: None,
        };
        let a = ActionFingerprint {
            schema: "test".into(),
            components: BTreeMap::new(),
        };
        let mut b = a.clone();
        b.components.insert("input".into(), ContentId::of(b"other"));
        let first = pool.reserve(8)?.context("first grace reservation")?;
        assert!(pool.reserve(1)?.is_none());
        let lease = store.publish_pinned(
            &a,
            &manifest,
            vec![store.stage_expected(blob, &contents[..])?],
            ActionMode::Reuse,
        )?;
        first.commit(lease)?;
        let second = pool.reserve(4)?.context("second grace reservation")?;
        assert!(pool.reserve(1)?.is_none());
        second.commit(store.publish_pinned(&b, &manifest, Vec::new(), ActionMode::Reuse)?)?;
        let cancelled = pool
            .reserve(4)?
            .context("deduplicated content should be charged once")?;
        assert!(pool.reserve(1)?.is_none());
        drop(cancelled);
        assert!(pool.reserve(4)?.is_some());
        assert_eq!(store.evict(a.key()?)?, Eviction::Pinned);
        assert_eq!(store.evict(b.key()?)?, Eviction::Pinned);
        let mut state = pool.state.lock().unwrap();
        assert_eq!(state.bytes, 4);
        assert_eq!(state.pending, 0);
        state.reap(Instant::now() + Duration::from_secs(301));
        assert_eq!(state.bytes, 0);
        drop(state);
        assert!(matches!(store.evict(a.key()?)?, Eviction::Removed { .. }));
        assert!(matches!(store.evict(b.key()?)?, Eviction::Removed { .. }));
        Ok(())
    }
}
