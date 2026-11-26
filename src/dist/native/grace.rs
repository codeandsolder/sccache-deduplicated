//! A bounded grace tier over the same immutable worker CAS.

use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use crate::build_runtime::{
    ActionFingerprint, ActionMode, CapturedExecution, ContentId, NativeStore, ResultLease,
    StageBudget,
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
    waiting_publishers: usize,
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
        if state.waiting_publishers != 0
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

pub(super) struct RetainedOutput {
    pub deadline: Instant,
    pub warm: bool,
}

pub(super) struct GraceReservation {
    pool: ArtifactGrace,
    limit: u64,
}

impl GraceReservation {
    pub(super) async fn retain(
        self,
        store: NativeStore,
        mut budget: StageBudget,
        fingerprint: ActionFingerprint,
        captured: CapturedExecution,
        wait: (Duration, &super::LeaseCheck<'_>),
    ) -> Result<(CapturedExecution, Option<RetainedOutput>)> {
        let manifest = captured
            .successful_result()
            .context("failed execution cannot be retained")?;
        if manifest.outputs.is_empty() {
            return Ok((captured, None));
        }
        let publication = self.promote();
        let (captured, lease, warm) = tokio::task::spawn_blocking(move || {
            let manifest = captured
                .successful_result()
                .context("failed execution cannot be retained")?;
            let existing = store.reserve_upload(manifest)?;
            let warm = existing.missing().is_empty();
            let mut staged = Vec::new();
            for &blob in existing.missing() {
                staged.push(budget.stage_expected(blob, captured.open_blob(blob.id)?)?);
            }
            let lease =
                store.publish_pinned(&fingerprint, manifest, staged, ActionMode::Refresh)?;
            Ok::<_, anyhow::Error>((captured, lease, warm))
        })
        .await??;
        let (deadline, waited) = publication.commit(lease, wait).await?;
        Ok((
            captured,
            Some(RetainedOutput {
                deadline,
                warm: warm && !waited,
            }),
        ))
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
        drop(state);
        Publication {
            pool: self.pool.clone(),
            waiting: false,
        }
    }
}

struct Publication {
    pool: ArtifactGrace,
    waiting: bool,
}

impl Publication {
    async fn commit(
        mut self,
        lease: ResultLease,
        wait: (Duration, &super::LeaseCheck<'_>),
    ) -> Result<(Instant, bool)> {
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
            {
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
                    return Ok((expires, self.waiting));
                }
                if !self.waiting {
                    state.waiting_publishers += 1;
                    self.waiting = true;
                }
                drop(state);
            }
            ensure!(
                started.elapsed() < timeout,
                "native artifact grace publication timed out"
            );
            tokio::time::sleep(
                Duration::from_millis(100).min(timeout.saturating_sub(started.elapsed())),
            )
            .await;
        }
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        if self.waiting {
            self.pool
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .waiting_publishers -= 1;
        }
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
    use crate::build_runtime::{Artifact, BlobRef, Eviction, ResultManifest};

    #[tokio::test]
    async fn shared_artifacts_charge_once_and_expiry_releases_eviction_pin() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let pool = ArtifactGrace::new(Duration::from_secs(300), 8)?;
        let contents = b"data";
        let blob = BlobRef {
            id: ContentId::of(contents),
            size: 4,
        };
        let manifest = ResultManifest {
            outputs: BTreeMap::from([("obj".into(), Artifact::File { blob, mode: None })]),
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
            .commit(lease, (Duration::ZERO, &|| Ok(())))
            .await?;
        let second = pool.reserve(4)?.context("second grace reservation")?;
        assert!(pool.reserve(1)?.is_none());
        second
            .promote()
            .commit(
                store.publish_pinned(&b, &manifest, Vec::new(), ActionMode::Reuse)?,
                (Duration::ZERO, &|| Ok(())),
            )
            .await?;
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
            outputs: BTreeMap::from([("obj".into(), Artifact::File { blob, mode: None })]),
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

    #[tokio::test]
    async fn native_grace_exact_publishers_supersede_forecasts_without_early_eviction() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let pool = ArtifactGrace::new(Duration::from_secs(300), 8)?;
        let first = pool.reserve(3)?.context("first forecast")?;
        let second = pool.reserve(3)?.context("second forecast")?;
        let third = pool.reserve(2)?.context("third forecast")?;

        // A surprisingly large result supersedes the remaining forecasts.
        let first = first.promote();
        assert!(pool.reserve(3)?.is_some());
        first
            .commit(result(&store, b"123456")?, (Duration::ZERO, &|| Ok(())))
            .await?;
        {
            let state = pool.state.lock().unwrap();
            assert_eq!(state.bytes, 6);
            assert_eq!(state.pending, 5);
        }
        assert!(pool.reserve(1)?.is_none());
        let second = second.promote();
        second
            .commit(result(&store, b"78")?, (Duration::ZERO, &|| Ok(())))
            .await?;
        // A duplicate manifest consumes no extra grace bytes, even when
        // the entire pool is occupied and the forecast underestimated.
        third
            .promote()
            .commit(result(&store, b"123456")?, (Duration::ZERO, &|| Ok(())))
            .await?;
        {
            let state = pool.state.lock().unwrap();
            assert_eq!(state.bytes, 8);
            assert_eq!(state.pending, 0);
            assert_eq!(state.waiting_publishers, 0);
            assert_eq!(state.results.len(), 3);
        }
        assert!(pool.reserve(1)?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn native_grace_waiting_publication_is_cancellable_and_does_not_release_retained_bytes()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let pool = ArtifactGrace::new(Duration::from_secs(300), 8)?;
        let first = pool.reserve(4)?.context("first forecast")?;
        let second = pool.reserve(4)?.context("second forecast")?;
        first
            .promote()
            .commit(result(&store, b"123456")?, (Duration::ZERO, &|| Ok(())))
            .await?;
        let check_count = std::sync::atomic::AtomicUsize::new(0);
        let failed = second
            .promote()
            .commit(
                result(&store, b"abcde")?,
                (Duration::from_secs(2), &|| {
                    let count = check_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if count != 0 {
                        assert!(pool.reserve(0)?.is_none());
                    }
                    ensure!(count == 0, "cancelled publication");
                    Ok(())
                }),
            )
            .await;
        assert!(failed.is_err());
        assert_eq!(check_count.load(std::sync::atomic::Ordering::Relaxed), 2);
        let mut state = pool.state.lock().unwrap();
        assert_eq!(state.bytes, 6);
        assert_eq!(state.pending, 0);
        assert_eq!(state.waiting_publishers, 0);
        assert_eq!(state.results.len(), 1);
        state.reap(Instant::now() + Duration::from_secs(301));
        assert_eq!(state.bytes, 0);
        drop(state);
        assert!(pool.reserve(8)?.is_some());
        Ok(())
    }
}
