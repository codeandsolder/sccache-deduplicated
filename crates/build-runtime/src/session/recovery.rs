//! Recover scheduler-authoritative result receipts before compiling again.
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, ensure};
use bincode::Options;

use super::{NativeServiceBusy, NativeSessions, UploadSource};
use crate::{
    ActionKey, BlobRef, CompilePermit, NativeStore, ResultLease, ResultManifest, StagedBlob,
    TreeLease, UploadReservation,
};

const RETRY_COOLDOWN: Duration = Duration::from_secs(30);
const DELIVERY_GRACE: Duration = Duration::from_secs(2);

struct RecoveryJob {
    permit: CompilePermit,
    manifest: ResultManifest,
    bytes: usize,
    deadline: Instant,
}

#[derive(Default)]
struct State {
    jobs: VecDeque<RecoveryJob>,
    queued_bytes: usize,
    active: usize,
    active_bytes: usize,
    failed: HashMap<ActionKey, Instant>,
    ready: HashMap<ActionKey, (ResultLease, Instant)>,
}

#[derive(Default)]
pub(super) struct RecoveryQueue {
    state: Arc<Mutex<State>>,
    wake: tokio::sync::Notify,
}

// Keep running recovery charged to the same budget as queued recovery.
struct ActiveRecovery {
    state: Arc<Mutex<State>>,
    bytes: usize,
}

impl Drop for ActiveRecovery {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active -= 1;
        state.active_bytes -= self.bytes;
    }
}

impl State {
    fn prune(&mut self, now: Instant) {
        self.failed.retain(|_, expiry| *expiry > now);
        self.ready.retain(|_, (_, expiry)| *expiry > now);
    }
}

impl RecoveryQueue {
    pub(super) fn telemetry(&self) -> Result<Option<super::RecoveryStatus>> {
        Ok(super::telemetry::observe(&self.state)?.map(|state| {
            let now = Instant::now();
            super::RecoveryStatus {
                queued: state.jobs.len(),
                queued_bytes: state.queued_bytes,
                ready: state
                    .ready
                    .values()
                    .filter(|(_, expires)| *expires > now)
                    .count(),
                cooldown: state
                    .failed
                    .values()
                    .filter(|expires| **expires > now)
                    .count(),
            }
        }))
    }

    pub(super) fn offer(
        &self,
        permit: CompilePermit,
        manifest: ResultManifest,
        max_jobs: usize,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<Option<CompilePermit>> {
        let bytes = usize::try_from(bincode::DefaultOptions::new().serialized_size(&manifest)?)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("result recovery queue poisoned"))?;
        let now = Instant::now();
        state.prune(now);
        if state.failed.contains_key(&permit.key())
            || state.jobs.len().saturating_add(state.active) >= max_jobs
            || bytes > max_bytes.saturating_sub(state.queued_bytes.saturating_add(state.active_bytes))
        {
            return Ok(Some(permit));
        }
        permit.clear_trace()?;
        state.queued_bytes += bytes;
        state.jobs.push_back(RecoveryJob {
            permit,
            manifest,
            bytes,
            deadline: now + timeout,
        });
        drop(state);
        self.wake.notify_one();
        Ok(None)
    }

    async fn take(&self, wait: Duration) -> Result<Option<(RecoveryJob, ActiveRecovery)>> {
        let deadline = Instant::now() + wait;
        loop {
            let mut notified = std::pin::pin!(self.wake.notified());
            notified.as_mut().enable();
            {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| anyhow!("result recovery queue poisoned"))?;
                if let Some(job) = state.jobs.pop_front() {
                    state.queued_bytes -= job.bytes;
                    state.active += 1;
                    state.active_bytes += job.bytes;
                    let active = ActiveRecovery {
                        state: Arc::clone(&self.state),
                        bytes: job.bytes,
                    };
                    drop(state);
                    return Ok(Some((job, active)));
                }
            }
            if Instant::now() >= deadline
                || tokio::time::timeout_at(deadline.into(), notified)
                    .await
                    .is_err()
            {
                return Ok(None);
            }
        }
    }

    pub(super) fn release_ready(&self, key: ActionKey) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| anyhow!("result recovery queue poisoned"))?
            .ready
            .remove(&key);
        Ok(())
    }

    pub(super) fn reap(&self) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| anyhow!("result recovery queue poisoned"))?
            .prune(Instant::now());
        Ok(())
    }

    fn finish(
        &self,
        key: ActionKey,
        recovered: Result<ResultLease>,
        max_entries: usize,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("result recovery queue poisoned"))?;
        let now = Instant::now();
        state.prune(now);
        match recovered {
            Ok(lease) => {
                // Bridge the admission poll to the ordinary result lease.
                if state.ready.len() >= max_entries
                    && let Some(oldest) = state
                        .ready
                        .iter()
                        .min_by_key(|(_, (_, expiry))| *expiry)
                        .map(|(&key, _)| key)
                {
                    state.ready.remove(&oldest);
                }
                state.ready.insert(key, (lease, now + DELIVERY_GRACE));
                state.failed.remove(&key);
            }
            Err(error) => {
                log::debug!("native result recovery unavailable for {key:?}: {error:#}");
                if state.failed.len() >= max_entries
                    && let Some(oldest) = state
                        .failed
                        .iter()
                        .min_by_key(|(_, expiry)| *expiry)
                        .map(|(&key, _)| key)
                {
                    state.failed.remove(&oldest);
                }
                state.failed.insert(key, now + RETRY_COOLDOWN);
            }
        }
        drop(state);
        Ok(())
    }
}

impl NativeSessions {
    /// Start one queued result recovery using exact-content peer fetches.
    /// The returned task owns the action permit and metadata budget until
    /// recovery completes, even if its caller drops the handle.
    ///
    /// # Errors
    /// Returns an error for recovery queue failures.
    pub async fn start_result_recovery<F, Fut>(
        self: &Arc<Self>,
        wait: Duration,
        fetch: F,
    ) -> Result<Option<tokio::task::JoinHandle<Result<()>>>>
    where
        F: Fn(BlobRef, NativeStore, Instant) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<StagedBlob>>> + Send + 'static,
    {
        let Some((job, active)) = self.recovery.take(wait).await? else {
            return Ok(None);
        };
        let sessions = Arc::clone(self);
        Ok(Some(tokio::spawn(async move {
            let _active = active;
            let RecoveryJob {
                permit,
                manifest,
                deadline,
                ..
            } = job;
            let key = permit.key();
            let recovered = sessions
                .recover_result_blobs(&manifest, deadline, fetch)
                .await;
            tokio::task::spawn_blocking(move || {
                let recovered = recovered.and_then(|(_reserved, _acquired)| {
                    permit.publish_pinned(&manifest, Vec::new())
                });
                // Publish the outcome before releasing the action permit.
                sessions
                    .recovery
                    .finish(key, recovered, sessions.limits.max_sessions)?;
                drop(permit);
                Ok(())
            })
            .await?
        })))
    }

    #[cfg(test)]
    pub(super) async fn recover_next_result<F, Fut>(
        self: &Arc<Self>, wait: Duration, fetch: F,
    ) -> Result<bool>
    where
        F: Fn(BlobRef, NativeStore, Instant) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<StagedBlob>>> + Send + 'static,
    {
        if let Some(task) = self.start_result_recovery(wait, fetch).await? {
            task.await??;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn recover_result_blobs<Fut>(
        self: &Arc<Self>,
        manifest: &ResultManifest,
        deadline: Instant,
        fetch: impl Fn(BlobRef, NativeStore, Instant) -> Fut + Send + Sync + 'static,
    ) -> Result<(UploadReservation, Vec<Arc<TreeLease>>)>
    where
        Fut: Future<Output = Result<Option<StagedBlob>>> + Send + 'static,
    {
        let check = || {
            ensure!(
                Instant::now() < deadline,
                "native result recovery deadline exceeded"
            );
            Ok(())
        };
        check()?;
        let store = self.store().clone();
        let manifest = manifest.clone();
        let (reserved, missing) = tokio::task::spawn_blocking(move || {
            let reserved = store.reserve_upload(&manifest)?;
            let mut missing = reserved.missing().to_vec();
            missing.sort_unstable_by_key(|blob| std::cmp::Reverse(blob.size));
            Ok::<_, anyhow::Error>((reserved, missing))
        })
        .await??;
        let mut acquired = Vec::with_capacity(missing.len());
        let fetch = Arc::new(fetch);
        let mut missing = missing.into_iter();
        let mut tasks = tokio::task::JoinSet::new();
        let mut failure = None;
        loop {
            // Bound logical acquisitions by a metadata window, not by the
            // transport permit count. Followers do not consume transfer slots.
            while failure.is_none() && tasks.len() < crate::wire::MAX_SOURCE_BATCH {
                let Some(blob) = missing.next() else { break; };
                let sessions = Arc::clone(self);
                let fetch = Arc::clone(&fetch);
                tasks.spawn(async move {
                    sessions.acquire_peer_blob(blob, deadline, true, &*fetch).await
                });
            }
            let Some(result) = tasks.join_next().await else { break; };
            match result {
                Ok(Ok(lease)) => acquired.push(lease),
                Ok(Err(error)) => { failure.get_or_insert(error); }
                Err(error) => { failure.get_or_insert(error.into()); }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        check()?;
        Ok((reserved, acquired))
    }

    async fn await_peer_upload_slot(&self, deadline: Instant) -> Result<super::UploadSlot> {
        loop {
            ensure!(Instant::now() < deadline, "native peer acquisition deadline exceeded");
            let mut notified = std::pin::pin!(self.peer_wake.notified());
            notified.as_mut().enable();
            match self.upload_slot(UploadSource::Peer) {
                Ok(slot) => return Ok(slot),
                Err(error) if error.is::<NativeServiceBusy>() => {
                    tokio::time::timeout_at(deadline.into(), notified)
                        .await
                        .context("native peer acquisition deadline exceeded")?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    // Only the producer of missing content needs a transfer slot. Cached
    // content and followers of an existing acquisition consume none.
    pub(super) async fn acquire_peer_blob<Fut>(
        &self,
        blob: BlobRef,
        deadline: Instant,
        wait_for_slot: bool,
        fetch: &(impl Fn(BlobRef, NativeStore, Instant) -> Fut + Sync),
    ) -> Result<Arc<TreeLease>>
    where
        Fut: Future<Output = Result<Option<StagedBlob>>> + Send,
    {
        let store = self.store();
        let retention = NativeStore::blob_retention_manifest(blob)?;
        store
            .acquire_tree_async(
                retention.id()?,
                deadline,
                std::future::pending(),
                || async move {
                    let owned = store.clone();
                    let manifest = retention.clone();
                    let reservation =
                        tokio::task::spawn_blocking(move || owned.reserve_tree_upload(&manifest))
                            .await??;
                    let slot = if reservation.missing().is_empty() {
                        None
                    } else if wait_for_slot {
                        Some(self.await_peer_upload_slot(deadline).await?)
                    } else {
                        // This speculative peer lookup must not monopolize
                        // the demand while the originating client could send it.
                        Some(self.upload_slot(UploadSource::Peer)?)
                    };
                    let staged = if slot.is_none() {
                        Vec::new()
                    } else {
                        let staged = fetch(blob, store.clone(), deadline)
                            .await?
                            .context("no peer has the required blob")?;
                        ensure!(
                            staged.reference() == blob,
                            "peer returned unrelated staged content"
                        );
                        vec![staged]
                    };
                    store
                        .publish_tree_pinned_async(retention, staged, reservation)
                        .await
                },
            )
            .await
            .map(|(lease, _)| lease)
    }
}
