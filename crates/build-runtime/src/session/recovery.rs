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
    failed: HashMap<ActionKey, Instant>,
    ready: HashMap<ActionKey, (ResultLease, Instant)>,
}

#[derive(Default)]
pub(super) struct RecoveryQueue {
    state: Mutex<State>,
    wake: tokio::sync::Notify,
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
            || state.jobs.len() >= max_jobs
            || bytes > max_bytes.saturating_sub(state.queued_bytes)
        {
            return Ok(Some(permit));
        }
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

    async fn take(&self, wait: Duration) -> Result<Option<RecoveryJob>> {
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
                    drop(state);
                    return Ok(Some(job));
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
    /// Process one queued result recovery using exact-content peer fetches.
    /// Holds the exclusive action permit until a verified result is restored
    /// or the attempt fails; no compiler slot or ordinary HTTP handler waits.
    ///
    /// # Errors
    /// Returns an error for recovery queue failures.
    pub async fn recover_next_result<F, Fut>(
        self: &Arc<Self>,
        wait: Duration,
        fetch: F,
    ) -> Result<bool>
    where
        F: Fn(BlobRef, NativeStore, Instant) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<StagedBlob>>> + Send + 'static,
    {
        let Some(job) = self.recovery.take(wait).await? else {
            return Ok(false);
        };
        let sessions = Arc::clone(self);
        tokio::spawn(async move {
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
                Ok(true)
            })
            .await?
        })
        .await?
    }

    async fn recover_result_blobs<Fut>(
        &self,
        manifest: &ResultManifest,
        deadline: Instant,
        fetch: impl Fn(BlobRef, NativeStore, Instant) -> Fut + Send + Sync,
    ) -> Result<(UploadReservation, Vec<Arc<TreeLease>>)>
    where
        Fut: Future<Output = Result<Option<StagedBlob>>> + Send,
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
        for blob in missing {
            let _slot = loop {
                check()?;
                let mut notified = std::pin::pin!(self.peer_wake.notified());
                notified.as_mut().enable();
                match self.upload_slot(UploadSource::Peer) {
                    Ok(slot) => break slot,
                    Err(error) if error.is::<NativeServiceBusy>() => {
                        tokio::time::timeout_at(deadline.into(), notified)
                            .await
                            .context("native result recovery deadline exceeded")?;
                    }
                    Err(error) => return Err(error),
                }
            };
            acquired.push(self.acquire_peer_blob(blob, deadline, &fetch).await?);
        }
        check()?;
        Ok((reserved, acquired))
    }

    // Caller owns a bounded upload slot before entering the shared tree
    // flight, so an active producer never waits on slots held by followers.
    pub(super) async fn acquire_peer_blob<Fut>(
        &self,
        blob: BlobRef,
        deadline: Instant,
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
                    let staged = if reservation.missing().is_empty() {
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
                    let owned = store.clone();
                    tokio::task::spawn_blocking(move || {
                        let _reservation = reservation;
                        owned.publish_tree_pinned(&retention, staged)
                    })
                    .await?
                },
            )
            .await
    }
}
