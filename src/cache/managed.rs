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
//! Cache artifacts stay immutable. Shared temperature metadata is packed into
//! deterministic CAS-protected shards instead of one sidecar object per cache
//! entry. A separate tiny state object tracks an approximate namespace size.
//! `ETag`-guarded shard writes merge touches from many sccache processes, users,
//! and hosts without a central daemon, while keeping metadata object count
//! bounded. Expensive full listings happen only when the shared estimate crosses
//! the high watermark, the shared state is missing/corrupt, or a cache write
//! fails.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures::stream::{self, StreamExt};
use log::{debug, warn};
use opendal::{EntryMode, ErrorKind, Metadata, Operator};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::config::S3CapacityConfig;

const META_VERSION: &str = "2";
const META_VERSION_KEY: &str = "sccache-version";
const STATE_ESTIMATED_SIZE_KEY: &str = "sccache-estimated-size";
const STATE_UPDATED_KEY: &str = "sccache-state-updated";
const STATE_RECONCILED_KEY: &str = "sccache-state-reconciled";
const LEASE_EXPIRES_KEY: &str = "sccache-lease-expires";
const LEASE_OWNER_KEY: &str = "sccache-lease-owner";
const CAPACITY_STATE_BASENAME: &str = ".capacity-state";
const PRUNE_LEASE_BASENAME: &str = ".prune-lease";
const METADATA_SHARD_DIR: &str = "shards";
const METADATA_SHARD_FORMAT_VERSION: u8 = 1;
const METADATA_SHARD_BITS: u32 = 12;
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
    key: Option<CacheObjectKey>,
    size: u64,
    listed_last_access: u64,
    metadata: Option<EntryMetadata>,
}

#[derive(Debug)]
struct ScoredCandidate {
    candidate: Candidate,
    expected_metadata: Option<EntryMetadata>,
    virtual_last_access: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
struct CacheObjectKey([u8; 32]);

impl CacheObjectKey {
    fn from_data_path(data_path: &str) -> Option<Self> {
        let mut parts = data_path.split('/');
        let first = parts.next()?;
        let second = parts.next()?;
        let third = parts.next()?;
        let key = parts.next()?;
        if parts.next().is_some()
            || key.len() != 64
            || first.len() != 1
            || second.len() != 1
            || third.len() != 1
            || first.as_bytes()[0] != key.as_bytes()[0]
            || second.as_bytes()[0] != key.as_bytes()[1]
            || third.as_bytes()[0] != key.as_bytes()[2]
        {
            return None;
        }
        let (pairs, []) = key.as_bytes().as_chunks::<2>() else {
            return None;
        };
        let mut bytes = [0_u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(pairs) {
            *byte = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Some(Self(bytes))
    }

    const fn shard_index(self) -> u16 {
        u16::from_be_bytes([self.0[0], self.0[1]]) >> (u16::BITS - METADATA_SHARD_BITS)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct EntryMetadata {
    last_access: u64,
    heat_milli: u64,
    size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MetadataShard {
    version: u8,
    entries: BTreeMap<CacheObjectKey, EntryMetadata>,
}

impl MetadataShard {
    const fn new() -> Self {
        Self {
            version: METADATA_SHARD_FORMAT_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
struct MetadataShardSnapshot {
    etag: String,
    shard: MetadataShard,
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
        let key = CacheObjectKey::from_data_path(data_path)
            .ok_or_else(|| anyhow::anyhow!("invalid managed cache data path {data_path}"))?;
        let shard_path = self.metadata_shard_path(key);
        let now = unix_seconds();

        for _ in 0..CAS_ATTEMPTS {
            if let Some(mut snapshot) = self.read_metadata_shard(&shard_path).await? {
                let previous = snapshot.shard.entries.get(&key).copied();
                let next = updated_entry_metadata(
                    previous,
                    now,
                    size,
                    hits,
                    self.config.heat_half_life_secs,
                );
                snapshot.shard.entries.insert(key, next);
                let body = serialize_metadata_shard(&snapshot.shard)?;
                match self
                    .operator
                    .write_with(&shard_path, body)
                    .if_match(&snapshot.etag)
                    .await
                {
                    Ok(_) => return Ok(()),
                    Err(error) if error.kind() == ErrorKind::ConditionNotMatch => {}
                    Err(error) => return Err(error.into()),
                }
            } else {
                let mut shard = MetadataShard::new();
                shard.entries.insert(
                    key,
                    updated_entry_metadata(None, now, size, hits, self.config.heat_half_life_secs),
                );
                let body = serialize_metadata_shard(&shard)?;
                match self
                    .operator
                    .write_with(&shard_path, body)
                    .if_not_exists(true)
                    .await
                {
                    Ok(_) => return Ok(()),
                    Err(error) if error.kind() == ErrorKind::ConditionNotMatch => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }

        debug!("managed cache touch for {data_path} lost repeated metadata shard races");
        Ok(())
    }

    async fn read_metadata_shard(
        &self,
        shard_path: &str,
    ) -> anyhow::Result<Option<MetadataShardSnapshot>> {
        let reader = match self.operator.reader(shard_path).await {
            Ok(reader) => reader,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let body = match reader.read(..).await {
            Ok(body) => body.to_bytes(),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let Some(metadata) = reader.metadata() else {
            anyhow::bail!("managed cache metadata shard {shard_path} read returned no metadata");
        };
        let Some(etag) = metadata.etag().map(str::to_owned) else {
            anyhow::bail!("managed cache metadata shard {shard_path} has no ETag");
        };
        let shard = deserialize_metadata_shard(&body)?;
        Ok(Some(MetadataShardSnapshot { etag, shard }))
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
        let shard_prefix = format!("{metadata_prefix}{METADATA_SHARD_DIR}/");
        let mut shard_paths = Vec::new();
        let mut unrecognized_metadata_paths = Vec::new();
        let mut candidates = Vec::new();
        let mut total = 0_u64;

        for entry in &entries {
            if entry.metadata().mode() != EntryMode::FILE {
                continue;
            }
            let path = entry.path();
            if path.starts_with(&metadata_prefix) {
                if matches!(
                    path.strip_prefix(&metadata_prefix),
                    Some(PRUNE_LEASE_BASENAME | CAPACITY_STATE_BASENAME)
                ) {
                    continue;
                }
                if path.starts_with(&shard_prefix) {
                    shard_paths.push(path.to_owned());
                } else {
                    unrecognized_metadata_paths.push(path.to_owned());
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
                key: CacheObjectKey::from_data_path(path),
                size,
                listed_last_access: entry
                    .metadata()
                    .last_modified()
                    .map_or(0, timestamp_seconds),
                metadata: None,
            });
        }

        let metadata_entries = self.load_metadata_entries(shard_paths).await;
        for candidate in &mut candidates {
            if let Some(key) = candidate.key
                && let Some(metadata) = metadata_entries.get(&key).copied()
            {
                candidate.listed_last_access = metadata.last_access;
                candidate.metadata = Some(metadata);
            }
        }

        self.cleanup_unrecognized_metadata(unrecognized_metadata_paths)
            .await;
        self.cleanup_orphan_metadata_entries(&metadata_entries, &candidates)
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

    async fn load_metadata_entries(
        &self,
        shard_paths: Vec<String>,
    ) -> HashMap<CacheObjectKey, EntryMetadata> {
        let concurrency = self.config.eviction_concurrency.max(1);
        let shards: Vec<(String, MetadataShard)> = stream::iter(shard_paths)
            .map(|path| async move {
                match self.operator.read(&path).await {
                    Ok(body) => match deserialize_metadata_shard(&body.to_bytes()) {
                        Ok(shard) => Some((path, shard)),
                        Err(error) => {
                            warn!(
                                "managed cache metadata shard decode failed for {path}: {error:#}"
                            );
                            None
                        }
                    },
                    Err(error) if error.kind() == ErrorKind::NotFound => None,
                    Err(error) => {
                        warn!("managed cache metadata shard read failed for {path}: {error}");
                        None
                    }
                }
            })
            .buffer_unordered(concurrency)
            .filter_map(|shard| async move { shard })
            .collect()
            .await;

        let entry_count = shards.iter().map(|(_, shard)| shard.entries.len()).sum();
        let mut entries = HashMap::with_capacity(entry_count);
        for (shard_path, shard) in shards {
            for (key, metadata) in shard.entries {
                if self.metadata_shard_path(key) != shard_path {
                    warn!("managed cache metadata entry is stored in the wrong shard {shard_path}");
                    continue;
                }
                entries.insert(key, metadata);
            }
        }
        entries
    }

    async fn cleanup_unrecognized_metadata(&self, paths: Vec<String>) {
        let concurrency = self.config.eviction_concurrency.max(1);
        stream::iter(paths)
            .for_each_concurrent(concurrency, |path| async move {
                if let Err(error) = self.operator.delete(&path).await
                    && error.kind() != ErrorKind::NotFound
                {
                    warn!("managed cache unrecognized metadata cleanup failed for {path}: {error}");
                }
            })
            .await;
    }

    async fn cleanup_orphan_metadata_entries(
        &self,
        metadata_entries: &HashMap<CacheObjectKey, EntryMetadata>,
        candidates: &[Candidate],
    ) {
        let data_keys: HashSet<CacheObjectKey> = candidates
            .iter()
            .filter_map(|candidate| candidate.key)
            .collect();
        let orphans: Vec<(CacheObjectKey, EntryMetadata)> = metadata_entries
            .iter()
            .filter(|(key, _)| !data_keys.contains(key))
            .map(|(key, metadata)| (*key, *metadata))
            .collect();
        let concurrency = self.config.eviction_concurrency.max(1);
        stream::iter(orphans)
            .for_each_concurrent(concurrency, |(key, expected)| async move {
                if let Err(error) = self.remove_metadata_entry_if_unchanged(key, expected).await {
                    warn!("managed cache orphan metadata cleanup failed: {error:#}");
                }
            })
            .await;
    }

    async fn prune_candidates(
        &self,
        mut total: u64,
        candidates: Vec<Candidate>,
        lease_valid: &AtomicBool,
    ) -> anyhow::Result<u64> {
        let now = unix_seconds();
        let mut scored: Vec<ScoredCandidate> = candidates
            .into_iter()
            .map(|candidate| self.score_candidate(candidate, now))
            .collect();
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
                Ok(true) => total = total.saturating_sub(scored_candidate.candidate.size),
                Ok(false) => {}
                Err(error) => warn!(
                    "managed cache eviction failed for {}: {error:#}",
                    scored_candidate.candidate.path
                ),
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

    fn score_candidate(&self, candidate: Candidate, now: u64) -> ScoredCandidate {
        let expected_metadata = candidate.metadata;
        let (last_access, effective_heat) = match expected_metadata {
            Some(metadata) => (
                metadata.last_access,
                decayed_heat_milli(
                    metadata.heat_milli,
                    metadata.last_access,
                    now,
                    self.config.heat_half_life_secs,
                ),
            ),
            None => (candidate.listed_last_access, 0),
        };
        let bonus = heat_bonus_seconds(effective_heat, self.config.heat_half_life_secs);
        ScoredCandidate {
            candidate,
            expected_metadata,
            virtual_last_access: last_access.saturating_add(bonus),
        }
    }

    async fn evict_candidate(&self, candidate: &ScoredCandidate) -> anyhow::Result<bool> {
        if let Some(key) = candidate.candidate.key {
            let shard_path = self.metadata_shard_path(key);
            let current_metadata = self
                .read_metadata_shard(&shard_path)
                .await?
                .and_then(|snapshot| snapshot.shard.entries.get(&key).copied());
            if current_metadata != candidate.expected_metadata {
                return Ok(false);
            }
        } else if candidate.expected_metadata.is_some() {
            return Ok(false);
        }

        // Artifact bytes are immutable. A touch in the narrow interval between
        // this metadata recheck and deletion can still lose one cache entry;
        // it cannot corrupt the cache and the next compile repopulates it.
        self.operator.delete(&candidate.candidate.path).await?;
        if let (Some(key), Some(expected)) = (candidate.candidate.key, candidate.expected_metadata)
            && let Err(error) = self.remove_metadata_entry_if_unchanged(key, expected).await
        {
            // The artifact deletion already succeeded, so metadata cleanup must
            // not make capacity accounting pretend the victim survived.
            warn!(
                "managed cache evicted {} but could not remove its metadata entry: {error:#}",
                candidate.candidate.path
            );
        }
        Ok(true)
    }

    async fn remove_metadata_entry_if_unchanged(
        &self,
        key: CacheObjectKey,
        expected: EntryMetadata,
    ) -> anyhow::Result<()> {
        let shard_path = self.metadata_shard_path(key);
        for _ in 0..CAS_ATTEMPTS {
            let Some(mut snapshot) = self.read_metadata_shard(&shard_path).await? else {
                return Ok(());
            };
            if snapshot.shard.entries.get(&key).copied() != Some(expected) {
                return Ok(());
            }
            snapshot.shard.entries.remove(&key);
            let body = serialize_metadata_shard(&snapshot.shard)?;
            match self
                .operator
                .write_with(&shard_path, body)
                .if_match(&snapshot.etag)
                .await
            {
                Ok(_) => return Ok(()),
                Err(error) if error.kind() == ErrorKind::ConditionNotMatch => {}
                Err(error) => return Err(error.into()),
            }
        }
        debug!("managed cache metadata removal lost repeated shard races");
        Ok(())
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

    fn metadata_shard_path(&self, key: CacheObjectKey) -> String {
        format!(
            "{}/{METADATA_SHARD_DIR}/{:03x}",
            self.metadata_prefix(),
            key.shard_index()
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
        && capability.delete;
    if !supported {
        anyhow::bail!(
            "managed remote cache requires stat, recursive list, user metadata, conditional writes, and delete"
        );
    }
    Ok(())
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn serialize_metadata_shard(shard: &MetadataShard) -> anyhow::Result<Bytes> {
    Ok(Bytes::from(bincode::serialize(shard)?))
}

fn deserialize_metadata_shard(bytes: &[u8]) -> anyhow::Result<MetadataShard> {
    let shard: MetadataShard = bincode::deserialize(bytes)?;
    anyhow::ensure!(
        shard.version == METADATA_SHARD_FORMAT_VERSION,
        "unsupported managed cache metadata shard version {}",
        shard.version
    );
    Ok(shard)
}

fn updated_entry_metadata(
    previous: Option<EntryMetadata>,
    now: u64,
    size: u64,
    hits: u32,
    half_life_secs: u64,
) -> EntryMetadata {
    let previous = previous.unwrap_or(EntryMetadata {
        last_access: now,
        heat_milli: 0,
        size,
    });
    let heat_milli = decayed_heat_milli(
        previous.heat_milli,
        previous.last_access,
        now,
        half_life_secs,
    )
    .saturating_add(u64::from(hits) * MILLI_HIT);
    EntryMetadata {
        last_access: now.max(previous.last_access),
        heat_milli,
        size: size.max(previous.size),
    }
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
    fn cache_object_key_parses_normalized_paths_and_maps_all_shards() {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = CacheObjectKey::from_data_path(&format!("0/1/2/{key_hex}"))
            .expect("normalized test key should parse");
        assert_eq!(key.0[0], 0x01);
        assert_eq!(key.0[1], 0x23);
        assert_eq!(key.0[31], 0xef);
        assert!(CacheObjectKey::from_data_path(&format!("f/1/2/{key_hex}")).is_none());
        assert!(CacheObjectKey::from_data_path("not/a/cache/key").is_none());

        let occupied: HashSet<u16> = (0_u16..(1_u16 << METADATA_SHARD_BITS))
            .map(|index| {
                let mut bytes = [0_u8; 32];
                let prefix = index << (u16::BITS - METADATA_SHARD_BITS);
                bytes[..2].copy_from_slice(&prefix.to_be_bytes());
                CacheObjectKey(bytes).shard_index()
            })
            .collect();
        assert_eq!(occupied.len(), 1_usize << METADATA_SHARD_BITS);
    }

    #[test]
    fn metadata_shard_encoding_is_deterministic() -> anyhow::Result<()> {
        let a = EntryMetadata {
            last_access: 10,
            heat_milli: 2_000,
            size: 30,
        };
        let b = EntryMetadata {
            last_access: 20,
            heat_milli: 3_000,
            size: 40,
        };
        let key_a = CacheObjectKey([1; 32]);
        let key_b = CacheObjectKey([2; 32]);
        let mut first = MetadataShard::new();
        first.entries.insert(key_b, b);
        first.entries.insert(key_a, a);
        let mut second = MetadataShard::new();
        second.entries.insert(key_a, a);
        second.entries.insert(key_b, b);

        let encoded = serialize_metadata_shard(&first)?;
        assert_eq!(encoded, serialize_metadata_shard(&second)?);
        let decoded = deserialize_metadata_shard(&encoded)?;
        assert_eq!(decoded.entries.get(&key_a), Some(&a));
        assert_eq!(decoded.entries.get(&key_b), Some(&b));
        Ok(())
    }

    #[test]
    fn metadata_shard_remains_small_at_above_expected_occupancy() -> anyhow::Result<()> {
        let mut shard = MetadataShard::new();
        for index in 0_u8..40 {
            let mut bytes = [0_u8; 32];
            // All entries deliberately share the same 12-bit shard prefix.
            bytes[0] = 0xab;
            bytes[1] = 0xc0 | (index & 0x0f);
            bytes[31] = index;
            shard.entries.insert(
                CacheObjectKey(bytes),
                EntryMetadata {
                    last_access: 1_800_000_000 + u64::from(index),
                    heat_milli: 1_000 + u64::from(index),
                    size: 100_000 + u64::from(index),
                },
            );
        }
        let encoded = serialize_metadata_shard(&shard)?;
        assert!(
            encoded.len() < 3 * 1024,
            "40-entry shard unexpectedly grew to {} bytes",
            encoded.len()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires an S3 backend with conditional writes"]
    async fn s3_metadata_shard_cas_merges_distinct_entries() -> anyhow::Result<()> {
        use crate::cache::s3::S3Cache;
        use crate::cache::utils::normalize_key;

        let bucket = std::env::var("SCCACHE_BUCKET")?;
        let endpoint = std::env::var("SCCACHE_ENDPOINT")?;
        let region = std::env::var("SCCACHE_REGION").ok();
        let use_ssl = std::env::var("SCCACHE_S3_USE_SSL")
            .ok()
            .and_then(|value| value.parse().ok());
        let root = format!("__sccache-managed-shard-test/{}", Uuid::new_v4());
        let operator = S3Cache::new(bucket, root, false)
            .with_region(region)
            .with_endpoint(Some(endpoint))
            .with_use_ssl(use_ssl)
            .build()?;
        let manager = ManagedRemoteCache::new(
            operator.clone(),
            S3CapacityConfig {
                high_watermark: 1 << 30,
                low_watermark: 1 << 29,
                touch_interval_secs: 60,
                state_flush_interval_secs: 5,
                heat_half_life_secs: 1_000_000,
                eviction_concurrency: 4,
                lease_ttl_secs: 60,
                metadata_prefix: ".sccache-meta/v2".to_owned(),
            },
        )?;

        let key_a = "0120000000000000000000000000000000000000000000000000000000000000";
        let key_b = "012fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let path_a = normalize_key(key_a);
        let path_b = normalize_key(key_b);
        let object_a = CacheObjectKey::from_data_path(&path_a)
            .expect("first normalized test key should parse");
        let object_b = CacheObjectKey::from_data_path(&path_b)
            .expect("second normalized test key should parse");
        anyhow::ensure!(object_a.shard_index() == object_b.shard_index());
        let shard_path = manager.metadata_shard_path(object_a);

        let outcome: anyhow::Result<()> = async {
            for _ in 0..8 {
                let (a, b) = tokio::join!(
                    manager.touch_remote(&path_a, 111, 1),
                    manager.touch_remote(&path_b, 222, 1)
                );
                a?;
                b?;
            }
            let snapshot = manager
                .read_metadata_shard(&shard_path)
                .await?
                .ok_or_else(|| anyhow::anyhow!("metadata shard disappeared"))?;
            let a = snapshot
                .shard
                .entries
                .get(&object_a)
                .ok_or_else(|| anyhow::anyhow!("first racing entry was lost"))?;
            let b = snapshot
                .shard
                .entries
                .get(&object_b)
                .ok_or_else(|| anyhow::anyhow!("second racing entry was lost"))?;
            anyhow::ensure!(a.heat_milli >= 7_900, "first heat was {}", a.heat_milli);
            anyhow::ensure!(b.heat_milli >= 7_900, "second heat was {}", b.heat_milli);
            anyhow::ensure!(a.size == 111 && b.size == 222);
            Ok(())
        }
        .await;
        let cleanup = operator.delete(&shard_path).await;
        outcome?;
        cleanup?;
        Ok(())
    }

    #[test]
    fn metadata_touch_decays_and_merges_hits() {
        let initial = updated_entry_metadata(None, 100, 40, 2, 10);
        assert_eq!(
            initial,
            EntryMetadata {
                last_access: 100,
                heat_milli: 2_000,
                size: 40,
            }
        );
        let updated = updated_entry_metadata(Some(initial), 110, 30, 1, 10);
        assert_eq!(
            updated,
            EntryMetadata {
                last_access: 110,
                heat_milli: 2_000,
                size: 40,
            }
        );
    }

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
