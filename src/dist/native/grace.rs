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
    publishers: usize,
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
        if state.publishers != 0
            || limit
                > self
                    .max_bytes
                    .saturating_sub(state.bytes)
                    .saturating_sub(state.pending)
        {
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
        wait: (Duration, &dyn Fn() -> Result<()>),
    ) -> Result<Option<Instant>> {
        if manifest.outputs.is_empty() {
            return Ok(None);
        }
        let publication = self.promote();
        let existing = store.reserve_upload(manifest)?;
        let mut staged = Vec::new();
        for &blob in existing.missing() {
            staged.push(budget.stage_expected(blob, captured.open_blob(blob.id)?)?);
        }
        let lease = store.publish_pinned(fingerprint, manifest, staged, ActionMode::Refresh)?;
        publication.commit(lease, wait).map(Some)
    }

    /// Exact publishers supersede forecasts. No publisher can deadlock
    /// waiting for space reserved by another unfinished forecast.
    fn promote(mut self) -> Publication {
        let mut state = self
            .pool
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.pending -= std::mem::take(&mut self.limit);
        state.publishers += 1;
        drop(state);
        Publication {
            pool: self.pool.clone(),
        }
    }
}

struct Publication {
    pool: ArtifactGrace,
}

impl Publication {
    fn commit(
        self,
        lease: ResultLease,
        wait: (Duration, &dyn Fn() -> Result<()>),
    ) -> Result<Instant> {
        let contents = lease.manifest().blobs()?;
        let total = contents.values().try_fold(0_u64, |sum, &size| {
            sum.checked_add(size).context("grace result size overflow")
        })?;
        ensure!(
            total <= self.pool.max_bytes,
            "actual result exceeds worker artifact grace pool"
        );
        let (timeout, check) = wait;
        let started = Instant::now();
        loop {
            check()?;
            let mut state = self
                .pool
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.reap(Instant::now());
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
            // The published result lease pins its content while it waits.
            // Charge only the exact unique union, not outstanding forecasts.
            if additional <= self.pool.max_bytes - state.bytes {
                let expires = Instant::now()
                    .checked_add(self.pool.duration)
                    .context("grace deadline overflow")?;
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
                return Ok(expires);
            }
            drop(state);
            ensure!(
                started.elapsed() < timeout,
                "native artifact grace publication timed out"
            );
            std::thread::sleep(
                Duration::from_millis(100).min(timeout.saturating_sub(started.elapsed())),
            );
        }
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        self.pool
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .publishers -= 1;
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
        first
            .promote()
            .commit(lease, (Duration::ZERO, &|| Ok(())))?;
        let second = pool.reserve(4)?.context("second grace reservation")?;
        assert!(pool.reserve(1)?.is_none());
        second.promote().commit(
            store.publish_pinned(&b, &manifest, Vec::new(), ActionMode::Reuse)?,
            (Duration::ZERO, &|| Ok(())),
        )?;
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

    fn result(store: &NativeStore, bytes: &[u8]) -> Result<ResultLease> {
        let blob = BlobRef {
            id: ContentId::of(bytes),
            size: u64::try_from(bytes.len())?,
        };
        let manifest = ResultManifest {
            outputs: BTreeMap::from([("obj".into(), Artifact { blob, mode: None })]),
            stdout: None,
            stderr: None,
        };
        let fingerprint = ActionFingerprint {
            schema: "test".into(),
            components: BTreeMap::from([("result".into(), blob.id)]),
        };
        store.publish_pinned(
            &fingerprint,
            &manifest,
            vec![store.stage_expected(blob, bytes)?],
            ActionMode::Refresh,
        )
    }

    #[test]
    fn native_grace_exact_publishers_supersede_forecasts_without_early_eviction() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let pool = ArtifactGrace::new(Duration::from_secs(300), 8)?;
        let first = pool.reserve(3)?.context("first forecast")?;
        let second = pool.reserve(3)?.context("second forecast")?;
        let third = pool.reserve(2)?.context("third forecast")?;

        // A surprisingly large result supersedes the remaining forecasts.
        let first = first.promote();
        assert!(pool.reserve(0)?.is_none());
        first.commit(result(&store, b"123456")?, (Duration::ZERO, &|| Ok(())))?;
        {
            let state = pool.state.lock().unwrap();
            assert_eq!(state.bytes, 6);
            assert_eq!(state.pending, 5);
        }
        assert!(pool.reserve(1)?.is_none());
        let second = second.promote();
        second.commit(result(&store, b"78")?, (Duration::ZERO, &|| Ok(())))?;
        // A duplicate manifest consumes no extra grace bytes, even when
        // the entire pool is occupied and the forecast underestimated.
        third
            .promote()
            .commit(result(&store, b"123456")?, (Duration::ZERO, &|| Ok(())))?;
        {
            let state = pool.state.lock().unwrap();
            assert_eq!(state.bytes, 8);
            assert_eq!(state.pending, 0);
            assert_eq!(state.publishers, 0);
            assert_eq!(state.results.len(), 3);
        }
        assert!(pool.reserve(1)?.is_none());
        Ok(())
    }

    #[test]
    fn native_grace_waiting_publication_is_cancellable_and_does_not_release_retained_bytes()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let pool = ArtifactGrace::new(Duration::from_secs(300), 8)?;
        let first = pool.reserve(4)?.context("first forecast")?;
        let second = pool.reserve(4)?.context("second forecast")?;
        first
            .promote()
            .commit(result(&store, b"123456")?, (Duration::ZERO, &|| Ok(())))?;
        let check_count = std::cell::Cell::new(0);
        let failed = second.promote().commit(
            result(&store, b"abcde")?,
            (Duration::from_secs(2), &|| {
                let count = check_count.get();
                check_count.set(count + 1);
                ensure!(count == 0, "cancelled publication");
                Ok(())
            }),
        );
        assert!(failed.is_err());
        assert_eq!(check_count.get(), 2);
        let mut state = pool.state.lock().unwrap();
        assert_eq!(state.bytes, 6);
        assert_eq!(state.pending, 0);
        assert_eq!(state.publishers, 0);
        assert_eq!(state.results.len(), 1);
        state.reap(Instant::now() + Duration::from_secs(301));
        assert_eq!(state.bytes, 0);
        drop(state);
        assert!(pool.reserve(8)?.is_some());
        Ok(())
    }
}
