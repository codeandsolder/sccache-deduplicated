// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Cooperative capacity management for shared object-store caches.
//!
//! Cache artifacts stay immutable. Tiny sidecars hold shared temperature
//! metadata and a separate tiny state object tracks an approximate namespace
//! size. Every metadata mutation writes a per-process generation token as the
//! object body, so the S3 `ETag` changes even when only metadata values changed.
//! `ETag`-guarded writes therefore provide real cross-process CAS, allowing many
//! sccache processes, users, and hosts to contribute without a central daemon.
//! Expensive full listings happen only when the shared estimate crosses the
//! high watermark, the shared state is missing/corrupt, or a cache write fails.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures::stream::{self, StreamExt};
use log::{debug, warn};
use opendal::{EntryMode, ErrorKind, Metadata, Operator};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::config::S3CapacityConfig;

const META_VERSION: &str = "1";
const META_VERSION_KEY: &str = "sccache-version";
const META_LAST_ACCESS_KEY: &str = "sccache-last-access";
const META_HEAT_MILLI_KEY: &str = "sccache-heat-milli";
const META_SIZE_KEY: &str = "sccache-size";
const STATE_ESTIMATED_SIZE_KEY: &str = "sccache-estimated-size";
const STATE_UPDATED_KEY: &str = "sccache-state-updated";
const STATE_RECONCILED_KEY: &str = "sccache-state-reconciled";
const LEASE_EXPIRES_KEY: &str = "sccache-lease-expires";
const LEASE_OWNER_KEY: &str = "sccache-lease-owner";
const CAPACITY_STATE_BASENAME: &str = ".capacity-state";
const PRUNE_LEASE_BASENAME: &str = ".prune-lease";
const MAX_TOUCH_ENTRIES: usize = 65_536;
const CAS_ATTEMPTS: usize = 8;

#[derive(Debug, Clone, Copy)]
struct PendingTouch {
    last_flush: Instant,
    pending_hits: u32,
    size: u64,
}

#[derive(Debug)]
struct Candidate {
    path: String,
    size: u64,
    listed_last_access: u64,
}

#[derive(Debug)]
struct ScoredCandidate {
    candidate: Candidate,
    metadata_etag: Option<String>,
    virtual_last_access: u64,
}

#[derive(Debug, Clone)]
struct CapacityStateSnapshot {
    etag: String,
    estimated_size: u64,
}

#[derive(Debug, Clone)]
struct PruneLease {
    etag: String,
    owner: String,
}

#[derive(Debug)]
pub struct ManagedRemoteCache {
    operator: Operator,
    config: S3CapacityConfig,
    touches: Mutex<HashMap<String, PendingTouch>>,
    pending_write_bytes: AtomicU64,
    state_flush_running: AtomicBool,
    last_state_flush: Mutex<Instant>,
    prune_running: AtomicBool,
    known_size: AtomicU64,
    size_known: AtomicBool,
    writer_id: Uuid,
    mutation_seq: AtomicU64,
}

impl ManagedRemoteCache {
    /// Create a shared managed-cache controller.
    ///
    /// # Errors
    ///
    /// Returns an error when the capacity configuration is invalid or the
    /// object-store backend lacks the conditional metadata operations required
    /// for safe multi-process coordination.
    pub fn new(operator: Operator, config: S3CapacityConfig) -> anyhow::Result<Arc<Self>> {
        config.validate()?;
        validate_operator_capabilities(&operator)?;
        let initial_flush = Instant::now()
            .checked_sub(Duration::from_hours(24))
            .unwrap_or_else(Instant::now);
        Ok(Arc::new(Self {
            operator,
            config,
            touches: Mutex::new(HashMap::new()),
            pending_write_bytes: AtomicU64::new(0),
            state_flush_running: AtomicBool::new(false),
            last_state_flush: Mutex::new(initial_flush),
            prune_running: AtomicBool::new(false),
            known_size: AtomicU64::new(0),
            size_known: AtomicBool::new(false),
            writer_id: Uuid::new_v4(),
            mutation_seq: AtomicU64::new(0),
        }))
    }

    pub const fn high_watermark(&self) -> u64 {
        self.config.high_watermark
    }

    pub fn current_size(&self) -> Option<u64> {
        self.size_known
            .load(Ordering::Relaxed)
            .then(|| self.known_size.load(Ordering::Relaxed))
    }

    pub fn record_access(self: &Arc<Self>, data_path: &str, size: u64) {
        let Some((hits, stored_size)) = self.coalesce_touch(data_path, size) else {
            return;
        };
        let this = Arc::clone(self);
        let data_path = data_path.to_owned();
        tokio::spawn(async move {
            if let Err(error) = this.touch_remote(&data_path, stored_size, hits).await {
                warn!("managed cache metadata touch failed for {data_path}: {error:#}");
            }
        });
    }

    pub fn record_write(self: &Arc<Self>, data_path: &str, size: u64) {
        let this = Arc::clone(self);
        let data_path = data_path.to_owned();
        tokio::spawn(async move {
            if let Err(error) = this.touch_remote(&data_path, size, 1).await {
                warn!("managed cache metadata write failed for {data_path}: {error:#}");
            }
        });

        self.pending_write_bytes.fetch_add(size, Ordering::Relaxed);
        self.maybe_schedule_state_flush();
    }

    pub fn record_write_failure(self: &Arc<Self>) {
        self.schedule_reconcile();
    }

    fn coalesce_touch(&self, data_path: &str, size: u64) -> Option<(u32, u64)> {
        let now = Instant::now();
        let interval = Duration::from_secs(self.config.touch_interval_secs);
        let mut touches = self
            .touches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = if let Some(touch) = touches.get_mut(data_path) {
            touch.pending_hits = touch.pending_hits.saturating_add(1);
            touch.size = size;
            if now.duration_since(touch.last_flush) < interval {
                None
            } else {
                let hits = touch.pending_hits;
                touch.pending_hits = 0;
                touch.last_flush = now;
                Some((hits, touch.size))
            }
        } else {
            if touches.len() >= MAX_TOUCH_ENTRIES {
                let stale_after =
                    Duration::from_secs(self.config.heat_half_life_secs.saturating_mul(2));
                touches.retain(|_, touch| now.duration_since(touch.last_flush) < stale_after);
                if touches.len() >= MAX_TOUCH_ENTRIES {
                    // Local coalescing state is only an optimization. Clearing it
                    // costs extra metadata writes but cannot lose cache correctness.
                    touches.clear();
                }
            }
            touches.insert(
                data_path.to_owned(),
                PendingTouch {
                    last_flush: now,
                    pending_hits: 0,
                    size,
                },
            );
            Some((1, size))
        };
        drop(touches);
        result
    }

    fn maybe_schedule_state_flush(self: &Arc<Self>) {
        if self.state_flush_running.load(Ordering::Relaxed) {
            return;
        }
        let interval_elapsed = {
            let last = self
                .last_state_flush
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            last.elapsed() >= Duration::from_secs(self.config.state_flush_interval_secs)
        };
        let pending = self.pending_write_bytes.load(Ordering::Relaxed);
        let delta_threshold = ((self.config.high_watermark - self.config.low_watermark) / 32)
            .clamp(4 * 1024 * 1024, 64 * 1024 * 1024);
        if !interval_elapsed && pending < delta_threshold {
            return;
        }
        if self
            .state_flush_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let this = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(error) = this.flush_capacity_delta().await {
                warn!("managed cache capacity-state update failed: {error:#}");
                this.schedule_reconcile();
            }
            *this
                .last_state_flush
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
            this.state_flush_running.store(false, Ordering::Release);
        });
    }

    async fn flush_capacity_delta(self: &Arc<Self>) -> anyhow::Result<()> {
        let delta = self.pending_write_bytes.swap(0, Ordering::AcqRel);
        if delta == 0 && self.size_known.load(Ordering::Relaxed) {
            return Ok(());
        }

        match self.add_capacity_delta(delta).await {
            Ok(Some(estimated_size)) => {
                self.known_size.store(estimated_size, Ordering::Relaxed);
                self.size_known.store(true, Ordering::Relaxed);
                if estimated_size > self.config.high_watermark {
                    self.schedule_reconcile();
                }
                Ok(())
            }
            Ok(None) => {
                self.pending_write_bytes.fetch_add(delta, Ordering::Relaxed);
                self.schedule_reconcile();
                Ok(())
            }
            Err(error) => {
                self.pending_write_bytes.fetch_add(delta, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    async fn add_capacity_delta(&self, delta: u64) -> anyhow::Result<Option<u64>> {
        let path = self.capacity_state_path();
        for _ in 0..CAS_ATTEMPTS {
            let metadata = match self.operator.stat(&path).await {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let Some(etag) = metadata.etag() else {
                return Ok(None);
            };
            let Some(current) = metadata_u64(&metadata, STATE_ESTIMATED_SIZE_KEY) else {
                return Ok(None);
            };
            let reconciled_at = metadata_u64(&metadata, STATE_RECONCILED_KEY).unwrap_or(0);
            let next = current.saturating_add(delta);
            match self
                .operator
                .write_with(&path, self.mutation_body())
                .if_match(etag)
                .user_metadata(capacity_state_metadata(next, reconciled_at))
                .await
            {
                Ok(_) => return Ok(Some(next)),
                Err(error) if error.kind() == ErrorKind::ConditionNotMatch => {}
                Err(error) => return Err(error.into()),
            }
        }
        debug!("managed cache capacity-state update lost repeated metadata races");
        Ok(None)
    }

    async fn touch_remote(&self, data_path: &str, size: u64, hits: u32) -> anyhow::Result<()> {
        let metadata_path = self.metadata_path(data_path);
        let now = unix_seconds();

        for _ in 0..CAS_ATTEMPTS {
            match self.operator.stat(&metadata_path).await {
                Ok(metadata) => {
                    let previous_last =
                        metadata_u64(&metadata, META_LAST_ACCESS_KEY).unwrap_or(now);
                    let previous_heat = metadata_u64(&metadata, META_HEAT_MILLI_KEY).unwrap_or(0);
                    let stored_size = metadata_u64(&metadata, META_SIZE_KEY).unwrap_or(size);
                    let heat = decayed_heat_milli(
                        previous_heat,
                        previous_last,
                        now,
                        self.config.heat_half_life_secs,
                    )
                    .saturating_add(u64::from(hits) * 1000);
                    let values =
                        entry_metadata(now.max(previous_last), heat, size.max(stored_size));
                    let Some(etag) = metadata.etag() else {
                        // ETag-less services cannot merge concurrent heat exactly. Managed
                        // capacity itself requires ETags, but keep this fallback defensive.
                        self.operator
                            .write_with(&metadata_path, self.mutation_body())
                            .user_metadata(values)
                            .await?;
                        return Ok(());
                    };
                    match self
                        .operator
                        .write_with(&metadata_path, self.mutation_body())
                        .if_match(etag)
                        .user_metadata(values)
                        .await
                    {
                        Ok(_) => return Ok(()),
                        Err(error) if error.kind() == ErrorKind::ConditionNotMatch => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    let values = entry_metadata(now, u64::from(hits) * 1000, size);
                    match self
                        .operator
                        .write_with(&metadata_path, self.mutation_body())
                        .if_not_exists(true)
                        .user_metadata(values)
                        .await
                    {
                        Ok(_) => return Ok(()),
                        Err(error) if error.kind() == ErrorKind::ConditionNotMatch => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }

        debug!("managed cache touch for {data_path} lost repeated metadata races");
        Ok(())
    }

    fn schedule_reconcile(self: &Arc<Self>) {
        if self
            .prune_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(error) = this.reconcile_and_prune().await {
                warn!("managed cache reconciliation failed: {error:#}");
            }
            this.prune_running.store(false, Ordering::Release);
            if this
                .current_size()
                .is_some_and(|size| size > this.config.high_watermark)
            {
                this.schedule_reconcile();
            }
        });
    }

    async fn reconcile_and_prune(self: &Arc<Self>) -> anyhow::Result<()> {
        let Some(acquired_lease) = self.acquire_prune_lease().await? else {
            debug!("managed cache reconciliation skipped: another controller owns the lease");
            return Ok(());
        };
        let lease = Arc::new(Mutex::new(acquired_lease));
        let lease_valid = Arc::new(AtomicBool::new(true));
        let heartbeat_stop = Arc::new(AtomicBool::new(false));
        let heartbeat_wake = Arc::new(Notify::new());
        let heartbeat = tokio::spawn({
            let this = Arc::clone(self);
            let lease = Arc::clone(&lease);
            let lease_valid = Arc::clone(&lease_valid);
            let heartbeat_stop = Arc::clone(&heartbeat_stop);
            let heartbeat_wake = Arc::clone(&heartbeat_wake);
            async move {
                this.prune_lease_heartbeat(&lease, &lease_valid, &heartbeat_stop, &heartbeat_wake)
                    .await;
            }
        });

        // Every pending byte here belongs to an artifact whose PUT already
        // succeeded, so a full listing while we hold the controller lease covers
        // it. Writes that arrive after this swap remain pending for the next state
        // flush and are merged through the shared state object.
        let covered_pending = self.pending_write_bytes.swap(0, Ordering::AcqRel);
        let result = async {
            let state_before = self.read_capacity_state().await?;
            self.reconcile_and_prune_while_leased(state_before.as_ref(), &lease_valid)
                .await
        }
        .await;
        if result.is_err() {
            self.pending_write_bytes
                .fetch_add(covered_pending, Ordering::Relaxed);
        }

        heartbeat_stop.store(true, Ordering::Release);
        heartbeat_wake.notify_one();
        if let Err(error) = heartbeat.await {
            lease_valid.store(false, Ordering::Release);
            warn!("managed cache lease heartbeat task failed: {error}");
        }

        let lease_snapshot = lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let lease_still_valid = lease_valid.load(Ordering::Acquire);
        if lease_still_valid {
            if let Err(error) = self.release_prune_lease(&lease_snapshot.etag).await {
                warn!("managed cache lease release failed: {error:#}");
            }
        } else {
            warn!("managed cache reconciliation lost its prune lease; leaving the lease to expire");
        }

        if !lease_still_valid && result.is_ok() {
            anyhow::bail!("managed cache prune lease was lost during reconciliation");
        }
        result
    }

    async fn reconcile_and_prune_while_leased(
        &self,
        state_before: Option<&CapacityStateSnapshot>,
        lease_valid: &AtomicBool,
    ) -> anyhow::Result<()> {
        let entries = self.operator.list_with("").recursive(true).await?;
        ensure_prune_lease_valid(lease_valid)?;
        let metadata_prefix = format!("{}/", self.metadata_prefix());
        let mut metadata_modified = HashMap::new();
        let mut candidates = Vec::new();
        let mut total = 0_u64;

        for entry in &entries {
            if entry.metadata().mode() != EntryMode::FILE {
                continue;
            }
            let path = entry.path();
            if path.starts_with(&metadata_prefix) {
                if let Some(data_path) = path.strip_prefix(&metadata_prefix) {
                    if matches!(data_path, PRUNE_LEASE_BASENAME | CAPACITY_STATE_BASENAME) {
                        continue;
                    }
                    metadata_modified.insert(
                        data_path.to_owned(),
                        entry
                            .metadata()
                            .last_modified()
                            .map_or(0, timestamp_seconds),
                    );
                }
                continue;
            }
            if path == ".sccache_check" {
                continue;
            }

            let size = entry.metadata().content_length();
            total = total.saturating_add(size);
            candidates.push(Candidate {
                path: path.to_owned(),
                size,
                listed_last_access: entry
                    .metadata()
                    .last_modified()
                    .map_or(0, timestamp_seconds),
            });
        }

        for candidate in &mut candidates {
            if let Some(last) = metadata_modified.get(&candidate.path) {
                candidate.listed_last_access = *last;
            }
        }

        self.cleanup_orphan_sidecars(&metadata_modified, &candidates)
            .await;
        ensure_prune_lease_valid(lease_valid)?;

        let remaining = if total > self.config.high_watermark {
            self.prune_candidates(total, candidates, lease_valid)
                .await?
        } else {
            total
        };
        ensure_prune_lease_valid(lease_valid)?;

        let estimated = self
            .finalize_capacity_state(state_before, remaining)
            .await?;
        self.known_size.store(estimated, Ordering::Relaxed);
        self.size_known.store(true, Ordering::Relaxed);
        debug!(
            "managed cache reconciliation complete: actual={remaining} estimated={estimated} high={} low={}",
            self.config.high_watermark, self.config.low_watermark
        );
        Ok(())
    }

    async fn cleanup_orphan_sidecars(
        &self,
        metadata_modified: &HashMap<String, u64>,
        candidates: &[Candidate],
    ) {
        let data_paths: HashSet<&str> = candidates
            .iter()
            .map(|candidate| candidate.path.as_str())
            .collect();
        let orphan_sidecars: Vec<String> = metadata_modified
            .keys()
            .filter(|path| !data_paths.contains(path.as_str()))
            .map(|path| self.metadata_path(path))
            .collect();
        let concurrency = self.config.eviction_concurrency.max(1);
        stream::iter(orphan_sidecars)
            .for_each_concurrent(concurrency, |path: String| async move {
                if let Err(error) = self.operator.delete(&path).await
                    && error.kind() != ErrorKind::NotFound
                {
                    warn!("managed cache orphan sidecar cleanup failed for {path}: {error}");
                }
            })
            .await;
    }

    async fn prune_candidates(
        &self,
        mut total: u64,
        mut candidates: Vec<Candidate>,
        lease_valid: &AtomicBool,
    ) -> anyhow::Result<u64> {
        candidates.sort_unstable_by_key(|candidate| candidate.listed_last_access);
        let mut candidates = VecDeque::from(candidates);
        let now = unix_seconds();

        while total > self.config.low_watermark && !candidates.is_empty() {
            ensure_prune_lease_valid(lease_valid)?;
            let need = total - self.config.low_watermark;
            let mut selected = Vec::new();
            let mut selected_bytes = 0_u64;
            while !candidates.is_empty()
                && (selected_bytes < need.saturating_mul(2) || selected.len() < 128)
            {
                let Some(candidate) = candidates.pop_front() else {
                    break;
                };
                selected_bytes = selected_bytes.saturating_add(candidate.size);
                selected.push(candidate);
            }

            let concurrency = self.config.eviction_concurrency.max(1);
            let mut scored: Vec<ScoredCandidate> = stream::iter(selected)
                .map(|candidate| async move { self.score_candidate(candidate, now).await })
                .buffer_unordered(concurrency)
                .filter_map(|result| async move {
                    match result {
                        Ok(value) => value,
                        Err(error) => {
                            warn!("managed cache candidate metadata read failed: {error:#}");
                            None
                        }
                    }
                })
                .collect()
                .await;

            scored.sort_unstable_by(|a, b| {
                a.virtual_last_access
                    .cmp(&b.virtual_last_access)
                    .then_with(|| a.candidate.path.cmp(&b.candidate.path))
            });

            for scored_candidate in scored {
                if total <= self.config.low_watermark {
                    break;
                }
                ensure_prune_lease_valid(lease_valid)?;
                match self.evict_candidate(&scored_candidate).await {
                    Ok(true) => {
                        total = total.saturating_sub(scored_candidate.candidate.size);
                    }
                    Ok(false) => {}
                    Err(error) => warn!(
                        "managed cache eviction failed for {}: {error:#}",
                        scored_candidate.candidate.path
                    ),
                }
            }
        }

        if total > self.config.high_watermark {
            warn!(
                "managed cache prune made insufficient progress: {total} bytes remain above high watermark {}",
                self.config.high_watermark
            );
        } else {
            debug!("managed cache prune complete: {total} bytes remain");
        }
        Ok(total)
    }

    async fn score_candidate(
        &self,
        candidate: Candidate,
        now: u64,
    ) -> anyhow::Result<Option<ScoredCandidate>> {
        let metadata_path = self.metadata_path(&candidate.path);
        match self.operator.stat(&metadata_path).await {
            Ok(metadata) => {
                let last_access = metadata_u64(&metadata, META_LAST_ACCESS_KEY)
                    .unwrap_or(candidate.listed_last_access);
                let stored_heat = metadata_u64(&metadata, META_HEAT_MILLI_KEY).unwrap_or(0);
                let effective_heat = decayed_heat_milli(
                    stored_heat,
                    last_access,
                    now,
                    self.config.heat_half_life_secs,
                );
                // Integer fixed-point logarithmic heat bonus. Exact powers retain
                // the intuitive mapping: 1 hit ~= 1 half-life, 15 hits ~= 4, and
                // 255 hits ~= 8. Linear interpolation inside each power-of-two
                // interval avoids floating-point precision/cast issues and keeps
                // the score monotonic.
                let bonus = heat_bonus_seconds(effective_heat, self.config.heat_half_life_secs);
                let virtual_last_access = last_access.saturating_add(bonus);
                Ok(Some(ScoredCandidate {
                    candidate,
                    metadata_etag: metadata.etag().map(str::to_owned),
                    virtual_last_access,
                }))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Some(ScoredCandidate {
                virtual_last_access: candidate.listed_last_access,
                candidate,
                metadata_etag: None,
            })),
            Err(error) => Err(error.into()),
        }
    }

    async fn evict_candidate(&self, candidate: &ScoredCandidate) -> anyhow::Result<bool> {
        let metadata_path = self.metadata_path(&candidate.candidate.path);

        // Optimistic multi-user guard: if anybody touched the entry after we
        // scored it, its metadata ETag changed and it is no longer our victim.
        match candidate.metadata_etag.as_deref() {
            Some(expected_etag) => {
                let current = match self.operator.stat(&metadata_path).await {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
                    Err(error) => return Err(error.into()),
                };
                if current.etag() != Some(expected_etag) {
                    return Ok(false);
                }
            }
            None => match self.operator.stat(&metadata_path).await {
                Ok(_) => return Ok(false),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            },
        }

        // Artifact bytes are immutable, so removal itself is simple. There is
        // an intentionally tiny race between the ETag recheck and this delete;
        // a concurrent touch in that window can lose one cache entry, but it
        // cannot corrupt the cache and the next compile repopulates it.
        self.operator.delete(&candidate.candidate.path).await?;
        if let Some(etag) = candidate.metadata_etag.as_deref()
            && let Err(error) = self
                .operator
                .delete_with(&metadata_path)
                .if_match(etag)
                .await
            && error.kind() != ErrorKind::ConditionNotMatch
            && error.kind() != ErrorKind::NotFound
        {
            return Err(error.into());
        }
        Ok(true)
    }

    async fn read_capacity_state(&self) -> anyhow::Result<Option<CapacityStateSnapshot>> {
        match self.operator.stat(&self.capacity_state_path()).await {
            Ok(metadata) => {
                let Some(etag) = metadata.etag().map(str::to_owned) else {
                    return Ok(None);
                };
                Ok(Some(CapacityStateSnapshot {
                    etag,
                    estimated_size: metadata_u64(&metadata, STATE_ESTIMATED_SIZE_KEY).unwrap_or(0),
                }))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn finalize_capacity_state(
        &self,
        state_before: Option<&CapacityStateSnapshot>,
        actual_remaining: u64,
    ) -> anyhow::Result<u64> {
        let path = self.capacity_state_path();
        let baseline = state_before.map_or(0, |state| state.estimated_size);
        let now = unix_seconds();

        for _ in 0..CAS_ATTEMPTS {
            match self.operator.stat(&path).await {
                Ok(metadata) => {
                    let Some(etag) = metadata.etag() else {
                        anyhow::bail!("managed cache capacity state has no ETag");
                    };
                    let current = metadata_u64(&metadata, STATE_ESTIMATED_SIZE_KEY).unwrap_or(0);
                    let unchanged = state_before.is_some_and(|state| state.etag == etag);
                    let concurrent_delta = if unchanged {
                        0
                    } else {
                        current.saturating_sub(baseline)
                    };
                    let next = actual_remaining.saturating_add(concurrent_delta);
                    match self
                        .operator
                        .write_with(&path, self.mutation_body())
                        .if_match(etag)
                        .user_metadata(capacity_state_metadata(next, now))
                        .await
                    {
                        Ok(_) => return Ok(next),
                        Err(error) if error.kind() == ErrorKind::ConditionNotMatch => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    match self
                        .operator
                        .write_with(&path, self.mutation_body())
                        .if_not_exists(true)
                        .user_metadata(capacity_state_metadata(actual_remaining, now))
                        .await
                    {
                        Ok(_) => return Ok(actual_remaining),
                        Err(error) if error.kind() == ErrorKind::ConditionNotMatch => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("managed cache capacity state lost repeated metadata races")
    }

    async fn prune_lease_heartbeat(
        self: &Arc<Self>,
        lease: &Mutex<PruneLease>,
        lease_valid: &AtomicBool,
        stop: &AtomicBool,
        wake: &Notify,
    ) {
        let renewal_interval = prune_lease_renewal_interval(self.config.lease_ttl_secs);
        loop {
            tokio::select! {
                () = tokio::time::sleep(renewal_interval) => {}
                () = wake.notified() => {}
            }
            if stop.load(Ordering::Acquire) {
                return;
            }

            let snapshot = lease
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            match self.renew_prune_lease(&snapshot).await {
                Ok(Some(etag)) => {
                    lease
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .etag = etag;
                }
                Ok(None) => {
                    lease_valid.store(false, Ordering::Release);
                    warn!("managed cache prune lease renewal lost ownership");
                    return;
                }
                Err(error) => {
                    lease_valid.store(false, Ordering::Release);
                    warn!("managed cache prune lease renewal failed: {error:#}");
                    return;
                }
            }
        }
    }

    async fn renew_prune_lease(&self, lease: &PruneLease) -> anyhow::Result<Option<String>> {
        let path = self.lease_path();
        let expires = unix_seconds().saturating_add(self.config.lease_ttl_secs);
        match self
            .operator
            .write_with(&path, self.mutation_body())
            .if_match(&lease.etag)
            .user_metadata(prune_lease_metadata(&lease.owner, expires))
            .await
        {
            Ok(metadata) => self.lease_etag(&path, metadata).await.map(Some),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConditionNotMatch | ErrorKind::NotFound
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn acquire_prune_lease(&self) -> anyhow::Result<Option<PruneLease>> {
        let path = self.lease_path();
        let now = unix_seconds();
        let expires = now.saturating_add(self.config.lease_ttl_secs);
        let owner = format!(
            "{}-{}-{now}",
            std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_owned()),
            std::process::id()
        );
        let values = prune_lease_metadata(&owner, expires);

        for _ in 0..CAS_ATTEMPTS {
            match self.operator.stat(&path).await {
                Ok(metadata) => {
                    if metadata_u64(&metadata, LEASE_EXPIRES_KEY).unwrap_or(expires) > now {
                        return Ok(None);
                    }
                    let Some(etag) = metadata.etag() else {
                        return Ok(None);
                    };
                    match self
                        .operator
                        .write_with(&path, self.mutation_body())
                        .if_match(etag)
                        .user_metadata(values.clone())
                        .await
                    {
                        Ok(metadata) => {
                            let etag = self.lease_etag(&path, metadata).await?;
                            return Ok(Some(PruneLease {
                                etag,
                                owner: owner.clone(),
                            }));
                        }
                        Err(error) if error.kind() == ErrorKind::ConditionNotMatch => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    match self
                        .operator
                        .write_with(&path, self.mutation_body())
                        .if_not_exists(true)
                        .user_metadata(values.clone())
                        .await
                    {
                        Ok(metadata) => {
                            let etag = self.lease_etag(&path, metadata).await?;
                            return Ok(Some(PruneLease {
                                etag,
                                owner: owner.clone(),
                            }));
                        }
                        Err(error) if error.kind() == ErrorKind::ConditionNotMatch => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(None)
    }

    async fn lease_etag(&self, path: &str, metadata: Metadata) -> anyhow::Result<String> {
        if let Some(etag) = metadata.etag() {
            return Ok(etag.to_owned());
        }
        self.operator
            .stat(path)
            .await?
            .etag()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("managed cache prune lease has no ETag"))
    }

    async fn release_prune_lease(&self, etag: &str) -> anyhow::Result<()> {
        if etag.is_empty() {
            return Ok(());
        }

        // Keep the tiny lease object permanently. Recreating a lock object
        // can fail when the cache is already at its hard object-store quota,
        // precisely when emergency pruning matters most.
        let values = prune_lease_metadata("", 0);
        match self
            .operator
            .write_with(&self.lease_path(), self.mutation_body())
            .if_match(etag)
            .user_metadata(values)
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == ErrorKind::ConditionNotMatch => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn metadata_prefix(&self) -> &str {
        self.config
            .metadata_prefix
            .trim_matches(char::from(0x2f_u8))
    }

    fn metadata_path(&self, data_path: &str) -> String {
        format!(
            "{}/{}",
            self.metadata_prefix(),
            data_path.trim_start_matches(char::from(0x2f_u8))
        )
    }

    fn capacity_state_path(&self) -> String {
        format!("{}/{CAPACITY_STATE_BASENAME}", self.metadata_prefix())
    }

    fn lease_path(&self) -> String {
        format!("{}/{PRUNE_LEASE_BASENAME}", self.metadata_prefix())
    }

    fn mutation_body(&self) -> Bytes {
        let sequence = self.mutation_seq.fetch_add(1, Ordering::Relaxed);
        let mut body = [0_u8; 24];
        body[..16].copy_from_slice(self.writer_id.as_bytes());
        body[16..].copy_from_slice(&sequence.to_be_bytes());
        Bytes::copy_from_slice(&body)
    }
}

fn validate_operator_capabilities(operator: &Operator) -> anyhow::Result<()> {
    let capability = operator.info().capability();
    let supported = capability.stat
        && capability.list
        && capability.list_with_recursive
        && capability.write
        && capability.write_with_if_match
        && capability.write_with_if_not_exists
        && capability.write_with_user_metadata
        && capability.delete
        && capability.delete_with_if_match;
    if !supported {
        anyhow::bail!(
            "managed remote cache requires stat, recursive list, user metadata, conditional writes, and conditional deletes"
        );
    }
    Ok(())
}

fn entry_metadata(last_access: u64, heat_milli: u64, size: u64) -> Vec<(String, String)> {
    vec![
        (META_VERSION_KEY.to_owned(), META_VERSION.to_owned()),
        (META_LAST_ACCESS_KEY.to_owned(), last_access.to_string()),
        (META_HEAT_MILLI_KEY.to_owned(), heat_milli.to_string()),
        (META_SIZE_KEY.to_owned(), size.to_string()),
    ]
}

fn capacity_state_metadata(estimated_size: u64, reconciled_at: u64) -> Vec<(String, String)> {
    vec![
        (META_VERSION_KEY.to_owned(), META_VERSION.to_owned()),
        (
            STATE_ESTIMATED_SIZE_KEY.to_owned(),
            estimated_size.to_string(),
        ),
        (STATE_UPDATED_KEY.to_owned(), unix_seconds().to_string()),
        (STATE_RECONCILED_KEY.to_owned(), reconciled_at.to_string()),
    ]
}

fn prune_lease_metadata(owner: &str, expires: u64) -> Vec<(String, String)> {
    vec![
        (LEASE_EXPIRES_KEY.to_owned(), expires.to_string()),
        (LEASE_OWNER_KEY.to_owned(), owner.to_owned()),
    ]
}

fn prune_lease_renewal_interval(ttl_secs: u64) -> Duration {
    Duration::from_secs((ttl_secs / 3).max(1))
}

fn ensure_prune_lease_valid(lease_valid: &AtomicBool) -> anyhow::Result<()> {
    anyhow::ensure!(
        lease_valid.load(Ordering::Acquire),
        "managed cache prune lease ownership was lost"
    );
    Ok(())
}

fn metadata_u64(metadata: &Metadata, key: &str) -> Option<u64> {
    metadata.user_metadata()?.get(key)?.parse().ok()
}

fn decayed_heat_milli(heat: u64, then: u64, now: u64, half_life_secs: u64) -> u64 {
    if heat == 0 || now <= then || half_life_secs == 0 {
        return heat;
    }

    let elapsed = now - then;
    let full_halves = elapsed / half_life_secs;
    if full_halves >= u64::from(u64::BITS) {
        return 0;
    }
    let shift = u32::try_from(full_halves).unwrap_or(u64::BITS);
    let decayed = heat.checked_shr(shift).unwrap_or(0);
    let remainder = elapsed % half_life_secs;
    if remainder == 0 || decayed == 0 {
        return decayed;
    }

    // Linear interpolation from H to H/2 inside one half-life. It slightly
    // overestimates the true exponential between boundaries, which is a safe
    // bias for eviction: a recently hot object survives a little longer.
    let maximum_loss = decayed / 2;
    let loss = u128::from(maximum_loss) * u128::from(remainder) / u128::from(half_life_secs);
    decayed.saturating_sub(u64::try_from(loss).unwrap_or(maximum_loss))
}

const HEAT_BONUS_UNITS: u64 = 1024;
const MILLI_HIT: u64 = 1000;

fn heat_bonus_seconds(heat_milli: u64, half_life_secs: u64) -> u64 {
    let value = u128::from(MILLI_HIT.saturating_add(heat_milli));
    let mut base = u128::from(MILLI_HIT);
    let mut whole_halves = 0_u64;
    while value >= base.saturating_mul(2) {
        base = base.saturating_mul(2);
        whole_halves = whole_halves.saturating_add(1);
    }

    let fractional_units = (value.saturating_sub(base) * u128::from(HEAT_BONUS_UNITS)) / base;
    let units = u128::from(whole_halves) * u128::from(HEAT_BONUS_UNITS) + fractional_units;
    let seconds = u128::from(half_life_secs) * units / u128::from(HEAT_BONUS_UNITS);
    u64::try_from(seconds).unwrap_or(u64::MAX)
}

fn timestamp_seconds(timestamp: opendal::raw::Timestamp) -> u64 {
    timestamp.into_inner().as_second().max(0).cast_unsigned()
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heat_decay_is_monotonic_and_halves() {
        assert_eq!(decayed_heat_milli(8_000, 100, 100, 10), 8_000);
        assert_eq!(decayed_heat_milli(8_000, 100, 110, 10), 4_000);
        assert_eq!(decayed_heat_milli(8_000, 100, 120, 10), 2_000);
        assert!(decayed_heat_milli(8_000, 100, 119, 10) > 2_000);
    }

    #[test]
    fn heat_bonus_matches_power_of_two_landmarks() {
        let half_life = 10_000;
        assert_eq!(heat_bonus_seconds(0, half_life), 0);
        assert_eq!(heat_bonus_seconds(1_000, half_life), half_life);
        assert_eq!(heat_bonus_seconds(15_000, half_life), 4 * half_life);
        assert_eq!(heat_bonus_seconds(255_000, half_life), 8 * half_life);
        assert!(heat_bonus_seconds(500, half_life) > 0);
        assert!(heat_bonus_seconds(500, half_life) < half_life);
    }

    #[test]
    fn prune_lease_renewal_interval_keeps_margin() {
        assert_eq!(prune_lease_renewal_interval(600), Duration::from_secs(200));
        assert_eq!(prune_lease_renewal_interval(3), Duration::from_secs(1));
        assert_eq!(prune_lease_renewal_interval(1), Duration::from_secs(1));
    }

    #[test]
    fn lost_prune_lease_fails_closed() {
        let lease_valid = AtomicBool::new(true);
        assert!(ensure_prune_lease_valid(&lease_valid).is_ok());
        lease_valid.store(false, Ordering::Release);
        assert!(ensure_prune_lease_valid(&lease_valid).is_err());
    }
}
