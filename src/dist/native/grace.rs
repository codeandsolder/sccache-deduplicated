//! A bounded grace tier over the same immutable worker CAS.

use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use crate::build_runtime::{
    ActionFingerprint, ActionMode, CapturedExecution, ContentId, NativeStore, ResultLease,
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

    fn reap(&mut self, now: Instant) -> Vec<ProtectedResult> {
        let mut expired = Vec::new();
        while self
            .results
            .front()
            .is_some_and(|entry| entry.expires <= now)
        {
            if let Some(entry) = self.results.pop_front() {
                self.release(&entry.contents);
                expired.push(entry);
            }
        }
        expired
    }

    fn next_expiry(&self) -> Option<Instant> {
        self.results.front().map(|result| result.expires)
    }
}

/// Logical grace budget, including prospective outputs of running/staging jobs.
#[derive(Clone)]
pub struct ArtifactGrace {
    duration: Duration,
    max_bytes: u64,
    state: Arc<Mutex<State>>,
    changed: tokio::sync::watch::Sender<()>,
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
            changed: tokio::sync::watch::Sender::new(()),
        })
    }

    /// Expiry releases only grace leases, not consumer input leases.
    pub fn reap(&self) {
        self.with_reaped(|_| ());
    }

    fn notify(&self) {
        self.changed.send_modify(|()| {});
    }

    fn with_reaped<R>(&self, operation: impl FnOnce(&mut State) -> R) -> R {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let expired = state.reap(Instant::now());
        let result = operation(&mut state);
        drop(state);
        if !expired.is_empty() {
            // Release CAS pins outside the grace mutex.
            drop(expired);
            self.notify();
        }
        result
    }

    fn try_reserve(&self, limit: u64) -> Result<(Option<GraceReservation>, Option<Instant>)> {
        ensure!(
            limit <= self.max_bytes,
            "result limit exceeds worker artifact grace budget"
        );
        let (admitted, expires) = self.with_reaped(|state| {
            let admitted = state.waiting_publishers == 0
                && limit
                    <= self
                        .max_bytes
                        .saturating_sub(state.bytes)
                        .saturating_sub(state.pending);
            if admitted {
                state.pending += limit;
            }
            (admitted, state.next_expiry())
        });
        Ok((
            admitted.then(|| GraceReservation {
                pool: self.clone(),
                limit,
            }),
            expires,
        ))
    }

    #[cfg(test)]
    fn reserve(&self, limit: u64) -> Result<Option<GraceReservation>> {
        self.try_reserve(limit).map(|(reservation, _)| reservation)
    }

    pub(super) async fn reserve_until(
        &self,
        limit: u64,
        timeout: Duration,
        check: &super::LeaseCheck<'_>,
    ) -> Result<(GraceReservation, bool)> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("grace admission deadline overflow")?;
        let mut changed = self.changed.subscribe();
        let mut waited = false;
        loop {
            check()?;
            let (reservation, expires) = self.try_reserve(limit)?;
            if let Some(reservation) = reservation {
                return Ok((reservation, waited));
            }
            waited = true;
            wait_for_change(
                &mut changed,
                deadline,
                expires,
                check,
                "native artifact grace admission",
            )
            .await?;
        }
    }
}

// A reservation release or exact publication changes admission immediately.
// The only timer which can change capacity independently is the oldest
// retained result's expiry. Lease checks remain cheap and periodic while
// parked, without repeating the content-accounting scan.
async fn wait_for_change(
    changed: &mut tokio::sync::watch::Receiver<()>,
    deadline: Instant,
    expires: Option<Instant>,
    check: &super::LeaseCheck<'_>,
    operation: &str,
) -> Result<()> {
    ensure!(Instant::now() < deadline, "{operation} timed out");
    let wake = expires.map_or(deadline, |expires| expires.min(deadline));
    let sleep = tokio::time::sleep_until(wake.into());
    tokio::pin!(sleep);
    let period = Duration::from_millis(50);
    let mut cancellation = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    cancellation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            result = changed.changed() => { result?; return Ok(()); }
            () = &mut sleep => {
                ensure!(Instant::now() < deadline, "{operation} timed out");
                return Ok(());
            }
            _ = cancellation.tick() => check()?,
        }
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
        let staging_store = store.clone();
        let (mut captured, manifest, existing, warm) = tokio::task::spawn_blocking(move || {
            let manifest = captured
                .successful_result()
                .context("failed execution cannot be retained")?
                .clone();
            let existing = staging_store.reserve_upload(&manifest)?;
            let warm = existing.missing().is_empty();
            Ok::<_, anyhow::Error>((captured, manifest, existing, warm))
        })
        .await??;
        let staged = captured.seal_staged(existing.missing()).await?;
        let lease = store
            .publish_pinned_async(fingerprint, manifest, staged, ActionMode::Refresh, existing)
            .await?;
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
        self.pool.notify();
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
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("grace publication deadline overflow")?;
        let mut changed = self.pool.changed.subscribe();
        let mut pending = Some((contents, lease));
        loop {
            check()?;
            match self.try_commit(&mut pending)? {
                PublicationAttempt::Committed(expires) => return Ok((expires, self.waiting)),
                PublicationAttempt::Wait(expires) => {
                    wait_for_change(
                        &mut changed,
                        deadline,
                        expires,
                        check,
                        "native artifact grace publication",
                    )
                    .await?;
                }
            }
        }
    }

    fn try_commit(
        &mut self,
        pending: &mut Option<(Contents, ResultLease)>,
    ) -> Result<PublicationAttempt> {
        let outcome = self.pool.with_reaped(|state| -> Result<_> {
            let (contents, _) = pending
                .as_ref()
                .context("missing pending grace publication")?;
            let mut additional = 0_u64;
            for (&id, &size) in contents {
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
            // Exact publications charge only the unique union, not the
            // outstanding forecasts. The pending lease pins its content.
            if additional <= self.pool.max_bytes - state.bytes {
                let expires = Instant::now()
                    .checked_add(self.pool.duration)
                    .context("grace deadline overflow")?;
                let (contents, lease) = pending
                    .take()
                    .context("missing pending grace publication")?;
                for (&id, &size) in &contents {
                    state.refs.entry(id).or_insert((size, 0)).1 += 1;
                }
                state.bytes += additional;
                state.results.push_back(ProtectedResult {
                    expires,
                    contents,
                    _lease: lease,
                });
                Ok(PublicationAttempt::Committed(expires))
            } else {
                if !self.waiting {
                    state.waiting_publishers += 1;
                    self.waiting = true;
                }
                Ok(PublicationAttempt::Wait(state.next_expiry()))
            }
        })?;
        // A newly retained result can reduce another publisher's unique
        // incremental charge, even if total protected bytes increased.
        if matches!(outcome, PublicationAttempt::Committed(_)) {
            self.pool.notify();
        }
        Ok(outcome)
    }
}

enum PublicationAttempt {
    Committed(Instant),
    Wait(Option<Instant>),
}

impl Drop for Publication {
    fn drop(&mut self) {
        if self.waiting {
            self.pool
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .waiting_publishers -= 1;
            self.pool.notify();
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
            self.pool.notify();
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
        let expired = state.reap(Instant::now() + Duration::from_secs(301));
        assert_eq!(state.bytes, 0);
        drop(state);
        drop(expired);
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
    async fn parked_forecast_wakes_on_release() -> Result<()> {
        let pool = ArtifactGrace::new(Duration::from_secs(300), 8)?;
        let held = pool.reserve(8)?.context("initial forecast")?;
        let check = || Ok(());
        let waiting = pool.reserve_until(8, Duration::from_secs(2), &check);
        tokio::pin!(waiting);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(waiting.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(held);
        let (reservation, waited) = waiting.await?;
        assert!(waited);
        assert!(pool.reserve(1)?.is_none());
        drop(reservation);
        assert!(pool.reserve(8)?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn parked_exact_publication_wakes_at_expiry() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let pool = ArtifactGrace::new(Duration::from_millis(100), 8)?;
        let first = pool.reserve(4)?.context("first forecast")?;
        let second = pool.reserve(4)?.context("second forecast")?;
        let lease = result(&store, b"12345678")?;
        let next = result(&store, b"abcdefgh")?;
        let (expiry, _) = first
            .promote()
            .commit(lease, (Duration::ZERO, &|| Ok(())))
            .await?;
        let check = || Ok(());
        let waiting = second
            .promote()
            .commit(next, (Duration::from_secs(2), &check));
        tokio::pin!(waiting);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(waiting.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert!(pool.reserve(0)?.is_none());
        let (_, waited) = waiting.await?;
        assert!(waited);
        assert!(Instant::now() >= expiry);
        let state = pool.state.lock().unwrap();
        assert_eq!(state.bytes, 8);
        assert_eq!(state.results.len(), 1);
        assert_eq!(state.waiting_publishers, 0);
        Ok(())
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
        let expired = state.reap(Instant::now() + Duration::from_secs(301));
        assert_eq!(state.bytes, 0);
        drop(state);
        drop(expired);
        assert!(pool.reserve(8)?.is_some());
        Ok(())
    }
}
