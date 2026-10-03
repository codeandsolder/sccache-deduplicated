// Copyright 2026 Mozilla Foundation
//
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

#![expect(
    clippy::too_many_lines,
    reason = "legacy implementation retained during strict-gate rollout to avoid unrelated semantic/API churn"
)]

use bytes::Bytes;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;

#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
use crate::cache::build_single_cache;
use crate::cache::disk::DiskCache;
use crate::cache::{Cache, CacheMode, CacheWrite, Storage};
use crate::compiler::PreprocessorCacheEntry;
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
use crate::config::CacheType;
use crate::config::{Config, PreprocessorCacheModeConfig, WriteErrorPolicy};
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
use crate::errors::Context;
use crate::errors::{Result, anyhow};
use crate::util::average_duration;

/// Increment an atomic stats counter, handling the Option check.
/// Usage: `inc_stat!(optional_stats, field_name, value)`
macro_rules! inc_stat {
    ($stats:expr, $field:ident, $value:expr) => {
        if let Some(s) = $stats {
            s.$field.fetch_add($value, Ordering::Relaxed);
        }
    };
}

/// Lock-free atomic counters for multi-level cache statistics.
/// Stored directly in `MultiLevelStorage` to avoid mutex contention.
struct AtomicLevelStats {
    name: String,
    location: String,
    hits: AtomicU64,
    misses: AtomicU64,
    writes: AtomicU64,
    write_failures: AtomicU64,
    backfills_from: AtomicU64,
    backfills_to: AtomicU64,
    hit_duration_nanos: AtomicU64,
    write_duration_nanos: AtomicU64,
}

impl AtomicLevelStats {
    fn new(name: String, location: String) -> Self {
        Self {
            name,
            location,
            hits: AtomicU64::default(),
            misses: AtomicU64::default(),
            writes: AtomicU64::default(),
            write_failures: AtomicU64::default(),
            backfills_from: AtomicU64::default(),
            backfills_to: AtomicU64::default(),
            hit_duration_nanos: AtomicU64::default(),
            write_duration_nanos: AtomicU64::default(),
        }
    }

    /// Create atomic stats for a specific cache level with formatted name
    fn for_level(idx: usize, storage: &Arc<dyn Storage>) -> Self {
        Self::new(
            format!("L{idx} ({})", storage.cache_type_name()),
            storage.location(),
        )
    }

    /// Create a Vec of atomic stats from a slice of storage backends
    fn from_levels(levels: &[Arc<dyn Storage>]) -> Vec<Arc<Self>> {
        levels
            .iter()
            .enumerate()
            .map(|(idx, level)| Arc::new(Self::for_level(idx, level)))
            .collect()
    }

    /// Take a consistent snapshot of all stats
    fn snapshot(&self) -> LevelStats {
        LevelStats {
            name: self.name.clone(),
            location: self.location.clone(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            write_failures: self.write_failures.load(Ordering::Relaxed),
            backfills_from: self.backfills_from.load(Ordering::Relaxed),
            backfills_to: self.backfills_to.load(Ordering::Relaxed),
            hit_duration: Duration::from_nanos(self.hit_duration_nanos.load(Ordering::Relaxed)),
            write_duration: Duration::from_nanos(self.write_duration_nanos.load(Ordering::Relaxed)),
        }
    }
}

/// Statistics for a single cache level (snapshot for display/serialization).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LevelStats {
    /// Human-readable name of this level (e.g., "L0 (disk)")
    pub name: String,
    /// Detailed location string (e.g., "Local disk: \"/path\"" or "s3, name: bucket, prefix: /p/")
    pub location: String,
    /// Number of cache hits at this level
    pub hits: u64,
    /// Number of cache misses (checked but not found) at this level
    pub misses: u64,
    /// Number of successful writes to this level
    pub writes: u64,
    /// Number of failed writes to this level
    pub write_failures: u64,
    /// Number of times data from this level was backfilled to faster levels
    pub backfills_from: u64,
    /// Number of times data from slower levels was backfilled to this level
    pub backfills_to: u64,
    /// Total time spent reading hits from this level
    pub hit_duration: Duration,
    /// Total time spent writing to this level
    pub write_duration: Duration,
}

/// Per-level statistics for multi-level cache operation.
///
/// Serializes as a flat JSON array of level stats (no wrapper object).
#[derive(Debug, Clone, Default)]
pub struct MultiLevelStats(pub Vec<LevelStats>);

impl Serialize for MultiLevelStats {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MultiLevelStats {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Vec::<LevelStats>::deserialize(deserializer).map(MultiLevelStats)
    }
}

impl std::ops::AddAssign for LevelStats {
    fn add_assign(&mut self, rhs: Self) {
        // name and location identify the level — keep lhs values
        self.hits += rhs.hits;
        self.misses += rhs.misses;
        self.writes += rhs.writes;
        self.write_failures += rhs.write_failures;
        self.backfills_from += rhs.backfills_from;
        self.backfills_to += rhs.backfills_to;
        self.hit_duration += rhs.hit_duration;
        self.write_duration += rhs.write_duration;
    }
}

impl std::ops::AddAssign for MultiLevelStats {
    fn add_assign(&mut self, rhs: Self) {
        let mut rhs_iter = rhs.0.into_iter();
        for lhs_level in &mut self.0 {
            if let Some(rhs_level) = rhs_iter.next() {
                *lhs_level += rhs_level;
            }
        }
        // Append any extra levels present only in rhs
        self.0.extend(rhs_iter);
    }
}

fn duration_nanos_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

impl LevelStats {
    /// Calculate hit rate as a percentage
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        const SCALE: u128 = 100_000_000;

        let total = self.hits.saturating_add(self.misses);
        if total == 0 {
            return 0.0;
        }
        let scaled = u128::from(self.hits) * SCALE / u128::from(total);
        let scaled = u32::try_from(scaled).unwrap_or(100_000_000);
        f64::from(scaled) / 1_000_000.0
    }

    /// Calculate average hit latency in milliseconds
    #[must_use]
    pub fn avg_hit_latency_ms(&self) -> f64 {
        average_duration(self.hit_duration, self.hits).as_secs_f64() * 1000.0
    }

    /// Calculate average write latency in milliseconds
    #[must_use]
    pub fn avg_write_latency_ms(&self) -> f64 {
        average_duration(self.write_duration, self.writes).as_secs_f64() * 1000.0
    }

    /// Format stats for human-readable display
    /// Returns a vector of (label, `value_with_suffix`, `suffix_length`) tuples
    /// `suffix_length` is used for width calculations in formatting
    /// Order: hits, misses, rate, writes, failures, backfills, write timing, read timing
    #[must_use]
    pub fn format_stats(&self) -> Vec<(String, String, usize)> {
        let mut stats = vec![];

        // 1. Hits/Misses/Rate
        stats.push((format!("  {} hits", self.name), self.hits.to_string(), 0));
        stats.push((
            format!("  {} misses", self.name),
            self.misses.to_string(),
            0,
        ));

        let total_checks = self.hits + self.misses;
        if total_checks > 0 {
            stats.push((
                format!("  {} hit rate", self.name),
                format!("{:.2} %", self.hit_rate()),
                2, // " %" is 2 chars
            ));
        } else {
            stats.push((format!("  {} hit rate", self.name), "-".to_string(), 0));
        }

        // 2. Writes and failures
        stats.push((
            format!("  {} writes", self.name),
            self.writes.to_string(),
            0,
        ));
        stats.push((
            format!("  {} write failures", self.name),
            self.write_failures.to_string(),
            0,
        ));

        // 3. Backfills
        stats.push((
            format!("  {} backfills from", self.name),
            self.backfills_from.to_string(),
            0,
        ));
        stats.push((
            format!("  {} backfills to", self.name),
            self.backfills_to.to_string(),
            0,
        ));

        // 4. Timing stats
        let avg_write_duration = average_duration(self.write_duration, self.writes);
        stats.push((
            format!("  {} avg cache write", self.name),
            crate::util::fmt_duration_as_secs(&avg_write_duration),
            2, // " s" is 2 chars
        ));

        let avg_read_duration = average_duration(self.hit_duration, self.hits);
        stats.push((
            format!("  {} avg cache read hit", self.name),
            crate::util::fmt_duration_as_secs(&avg_read_duration),
            2, // " s" is 2 chars
        ));

        stats
    }
}

impl MultiLevelStats {
    /// Format all stats for human-readable display.
    /// Returns a vector of (label, value, `suffix_type`) tuples.
    #[must_use]
    pub fn format_stats(&self) -> Vec<(String, String, usize)> {
        let mut result = vec![];

        if self.0.is_empty() {
            return result;
        }

        // Global stats
        result.push((
            "Multi-level cache levels".to_string(),
            self.0.len().to_string(),
            0,
        ));

        // Per-level stats
        for level_stats in &self.0 {
            result.extend(level_stats.format_stats());
        }

        result
    }
}

const DEFAULT_SLOW_LEVEL_WRITE_CONCURRENCY: usize = 4;

#[derive(Default)]
struct BackgroundTasks {
    tracker: TaskTracker,
}

impl BackgroundTasks {
    /// Register detached cache work before it can begin executing.
    fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        // TaskTracker creates its tracking token before tokio::spawn, so drain()
        // cannot observe an empty tracker while this task has already started.
        drop(self.tracker.spawn(future));
    }

    /// Wait for all detached work belonging to this barrier.
    ///
    /// Closing does not reject later spawns: `TaskTracker` keeps tracking them. If a
    /// task is registered while this wait is still non-empty it is included; a task
    /// registered after the tracker reaches empty belongs to the next drain.
    async fn drain(&self) {
        self.tracker.close();
        self.tracker.wait().await;
    }
}

/// A multi-level cache storage that checks multiple storage backends in order.
///
/// This enables hierarchical caching similar to CPU L1/L2/L3 caches:
/// - Fast, small caches (e.g., disk) are checked first (L0)
/// - Slower, larger caches (e.g., S3) are checked on miss
/// - Cache hits trigger automatic async backfill to faster levels
/// - Writes go to all levels in parallel
///
/// Configure via `SCCACHE_MULTILEVEL_CHAIN="disk,redis,s3`" environment variable.
/// See docs/MultiLevel.md for details.
pub struct MultiLevelStorage {
    levels: Vec<Arc<dyn Storage>>,
    write_error_policy: WriteErrorPolicy,
    /// Lock-free atomic statistics per level
    atomic_stats: Vec<Arc<AtomicLevelStats>>,
    /// Base directories for path normalization, propagated to compiler pipeline
    basedirs: Vec<Vec<u8>>,
    /// Bounds asynchronous traffic to slower cache levels.
    slow_level_semaphore: Arc<Semaphore>,
    /// Tracks detached work so graceful shutdown can drain it deterministically.
    background_tasks: Arc<BackgroundTasks>,
}

impl MultiLevelStorage {
    /// Collect and deduplicate basedirs from all cache levels.
    fn collect_basedirs(levels: &[Arc<dyn Storage>]) -> Vec<Vec<u8>> {
        let mut seen = Vec::new();
        for level in levels {
            for basedir in level.basedirs() {
                if !seen.contains(basedir) {
                    seen.push(basedir.clone());
                }
            }
        }
        seen
    }

    /// Create a new multi-level storage from a list of storage backends.
    ///
    /// Levels are checked in order (L0, L1, L2, ...) during reads.
    /// All levels receive writes in parallel.
    #[must_use]
    pub fn new(levels: Vec<Arc<dyn Storage>>) -> Self {
        Self::with_write_error_policy(levels, WriteErrorPolicy::default())
    }

    /// Create a new multi-level storage with explicit write error policy.
    #[must_use]
    pub fn with_write_error_policy(
        levels: Vec<Arc<dyn Storage>>,
        write_error_policy: WriteErrorPolicy,
    ) -> Self {
        Self::with_write_error_policy_and_concurrency(
            levels,
            write_error_policy,
            DEFAULT_SLOW_LEVEL_WRITE_CONCURRENCY,
        )
    }

    fn with_write_error_policy_and_concurrency(
        levels: Vec<Arc<dyn Storage>>,
        write_error_policy: WriteErrorPolicy,
        slow_write_concurrency: usize,
    ) -> Self {
        let atomic_stats = AtomicLevelStats::from_levels(&levels);
        let basedirs = Self::collect_basedirs(&levels);

        Self {
            levels,
            write_error_policy,
            atomic_stats,
            basedirs,
            slow_level_semaphore: Arc::new(Semaphore::new(slow_write_concurrency.max(1))),
            background_tasks: Arc::new(BackgroundTasks::default()),
        }
    }

    /// Get a snapshot of current multi-level cache statistics.
    #[must_use]
    pub fn stats(&self) -> MultiLevelStats {
        MultiLevelStats(self.atomic_stats.iter().map(|s| s.snapshot()).collect())
    }

    fn build_disk_level(
        config: &Config,
        pool: &tokio::runtime::Handle,
    ) -> Result<Arc<dyn Storage>> {
        let disk_config = config.cache_configs.disk.as_ref().ok_or_else(|| {
            anyhow!("Disk cache specified in levels but not configured (set SCCACHE_DIR)")
        })?;
        debug!(
            "Adding disk cache level with dir {}, size {}",
            disk_config.dir.display(),
            disk_config.size
        );
        Ok(Arc::new(DiskCache::new(
            &disk_config.dir,
            disk_config.size,
            pool,
            disk_config.preprocessor_cache_mode,
            disk_config.rw_mode.into(),
            config.basedirs.clone(),
        )))
    }

    #[cfg(any(
        feature = "azure",
        feature = "gcs",
        feature = "gha",
        feature = "memcached",
        feature = "redis",
        feature = "s3",
        feature = "webdav",
        feature = "oss",
        feature = "cos"
    ))]
    fn configured_remote_cache_type(
        level_name: &str,
        config: &Config,
    ) -> Result<Option<CacheType>> {
        match level_name.to_ascii_lowercase().as_str() {
            #[cfg(feature = "s3")]
            "s3" => Ok(config.cache_configs.s3.clone().map(CacheType::S3)),
            #[cfg(not(feature = "s3"))]
            "s3" => Err(anyhow!("Cache level 's3' requires the 's3' feature")),
            #[cfg(feature = "redis")]
            "redis" => Ok(config.cache_configs.redis.clone().map(CacheType::Redis)),
            #[cfg(not(feature = "redis"))]
            "redis" => Err(anyhow!("Cache level 'redis' requires the 'redis' feature")),
            #[cfg(feature = "memcached")]
            "memcached" => Ok(config
                .cache_configs
                .memcached
                .clone()
                .map(CacheType::Memcached)),
            #[cfg(not(feature = "memcached"))]
            "memcached" => Err(anyhow!(
                "Cache level 'memcached' requires the 'memcached' feature"
            )),
            #[cfg(feature = "gcs")]
            "gcs" => Ok(config.cache_configs.gcs.clone().map(CacheType::GCS)),
            #[cfg(not(feature = "gcs"))]
            "gcs" => Err(anyhow!("Cache level 'gcs' requires the 'gcs' feature")),
            #[cfg(feature = "gha")]
            "gha" => Ok(config.cache_configs.gha.clone().map(CacheType::GHA)),
            #[cfg(not(feature = "gha"))]
            "gha" => Err(anyhow!("Cache level 'gha' requires the 'gha' feature")),
            #[cfg(feature = "azure")]
            "azure" => Ok(config.cache_configs.azure.clone().map(CacheType::Azure)),
            #[cfg(not(feature = "azure"))]
            "azure" => Err(anyhow!("Cache level 'azure' requires the 'azure' feature")),
            #[cfg(feature = "webdav")]
            "webdav" => Ok(config.cache_configs.webdav.clone().map(CacheType::Webdav)),
            #[cfg(not(feature = "webdav"))]
            "webdav" => Err(anyhow!(
                "Cache level 'webdav' requires the 'webdav' feature"
            )),
            #[cfg(feature = "oss")]
            "oss" => Ok(config.cache_configs.oss.clone().map(CacheType::OSS)),
            #[cfg(not(feature = "oss"))]
            "oss" => Err(anyhow!("Cache level 'oss' requires the 'oss' feature")),
            #[cfg(feature = "cos")]
            "cos" => Ok(config.cache_configs.cos.clone().map(CacheType::COS)),
            #[cfg(not(feature = "cos"))]
            "cos" => Err(anyhow!("Cache level 'cos' requires the 'cos' feature")),
            _ => Err(anyhow!("Unknown cache level: '{level_name}'")),
        }
    }

    #[cfg(any(
        feature = "azure",
        feature = "gcs",
        feature = "gha",
        feature = "memcached",
        feature = "redis",
        feature = "s3",
        feature = "webdav",
        feature = "oss",
        feature = "cos"
    ))]
    fn build_remote_level(
        level_name: &str,
        config: &Config,
        pool: &tokio::runtime::Handle,
    ) -> Result<Arc<dyn Storage>> {
        let cache_type = Self::configured_remote_cache_type(level_name, config)?.ok_or_else(|| {
            anyhow!(
                "Cache level '{level_name}' specified in SCCACHE_MULTILEVEL_CHAIN but not configured (missing environment variables)"
            )
        })?;
        let storage =
            build_single_cache(&cache_type, &config.basedirs, pool, config.skip_cache_check)
                .with_context(|| format!("Failed to build cache for level '{level_name}'"))?;
        trace!("Added cache level: {level_name}");
        Ok(storage)
    }

    #[cfg(not(any(
        feature = "azure",
        feature = "gcs",
        feature = "gha",
        feature = "memcached",
        feature = "redis",
        feature = "s3",
        feature = "webdav",
        feature = "oss",
        feature = "cos"
    )))]
    fn build_remote_level(
        level_name: &str,
        _config: &Config,
        _pool: &tokio::runtime::Handle,
    ) -> Result<Arc<dyn Storage>> {
        Err(anyhow!(
            "Cache level '{level_name}' requires a backend feature to be enabled (e.g., --features redis,s3)"
        ))
    }

    fn build_level(
        level_name: &str,
        config: &Config,
        pool: &tokio::runtime::Handle,
    ) -> Result<Arc<dyn Storage>> {
        if level_name.eq_ignore_ascii_case("disk") {
            Self::build_disk_level(config, pool)
        } else {
            Self::build_remote_level(level_name, config, pool)
        }
    }

    /// Create a multi-level storage from configuration.
    ///
    /// Returns `None` if no levels are configured (`SCCACHE_MULTILEVEL_CHAIN` is not set).
    ///
    /// # Errors
    ///
    /// Returns an error if a configured level is unknown, disabled at compile time,
    /// missing its backend configuration, or cannot be initialized.
    pub fn from_config(config: &Config, pool: &tokio::runtime::Handle) -> Result<Option<Self>> {
        let ml_config = match config.cache_configs.multilevel.as_ref() {
            Some(cfg) if !cfg.chain.is_empty() => cfg,
            _ => return Ok(None),
        };

        debug!(
            "Configuring multi-level cache with {} levels",
            ml_config.chain.len()
        );

        let storages = ml_config
            .chain
            .iter()
            .map(|level_name| Self::build_level(level_name.trim(), config, pool))
            .collect::<Result<Vec<_>>>()?;

        debug!(
            "Initialized multi-level storage with {} total levels",
            storages.len()
        );

        Ok(Some(Self::with_write_error_policy_and_concurrency(
            storages,
            ml_config.write_error_policy,
            ml_config.slow_write_concurrency,
        )))
    }

    fn record_hit_and_schedule_backfills(
        &self,
        key: &str,
        idx: usize,
        duration: Duration,
        raw_bytes_for_backfill: Option<Bytes>,
    ) {
        debug!("Cache hit at level {idx} in {duration:?}");

        inc_stat!(self.atomic_stats.get(idx), hits, 1);
        inc_stat!(
            self.atomic_stats.get(idx),
            hit_duration_nanos,
            duration_nanos_u64(duration)
        );
        for miss_idx in 0..idx {
            inc_stat!(self.atomic_stats.get(miss_idx), misses, 1);
        }

        self.repair_slower_levels_from_hit(key, idx);
        self.backfill_faster_levels(key, idx, raw_bytes_for_backfill);
    }

    async fn read_level_with_raw(&self, idx: usize, key: &str) -> (Result<Cache>, Option<Bytes>) {
        let level = &self.levels[idx];
        if idx == 0 {
            return (level.get(key).await, None);
        }

        match level.get_with_raw(key).await {
            Ok((cache, raw_bytes)) => (Ok(cache), raw_bytes),
            Err(error) => (Err(error), None),
        }
    }

    fn backfill_faster_levels(&self, key: &str, hit_level: usize, raw_bytes: Option<Bytes>) {
        if hit_level == 0 {
            return;
        }

        let Some(raw_bytes) = raw_bytes else {
            debug!(
                "Cache backend at level {hit_level} does not support get_raw(), skipping backfill"
            );
            return;
        };

        inc_stat!(
            self.atomic_stats.get(hit_level),
            backfills_from,
            u64::try_from(hit_level).unwrap_or(u64::MAX)
        );

        for backfill_idx in 0..hit_level {
            let key = key.to_string();
            let bytes = raw_bytes.clone();
            let level = Arc::clone(&self.levels[backfill_idx]);
            let stats = self.atomic_stats.get(backfill_idx).map(Arc::clone);
            let background_tasks = Arc::clone(&self.background_tasks);

            background_tasks.spawn(async move {
                match Self::write_entry_from_bytes(&level, &key, &bytes).await {
                    Ok(()) => {
                        trace!(
                            "Backfilled cache level {backfill_idx} from level {hit_level}"
                        );
                        inc_stat!(stats.as_deref(), backfills_to, 1);
                    }
                    Err(error) => {
                        debug!(
                            "Background backfill from level {hit_level} to level {backfill_idx} failed: {error}"
                        );
                    }
                }
            });
        }
    }

    /// Ensure slower cache levels contain an entry already served by a faster level.
    ///
    /// This path is deliberately detached from the cache hit: the caller gets the
    /// faster-level hit immediately. Slower levels are probed only when they expose
    /// a cheap existence check, and the source object is read only if at least one
    /// slower level is actually missing the key.
    fn repair_slower_levels_from_hit(&self, key: &str, hit_idx: usize) {
        if hit_idx + 1 >= self.levels.len() {
            return;
        }

        let source = Arc::clone(&self.levels[hit_idx]);
        let source_stats = Arc::clone(&self.atomic_stats[hit_idx]);
        let targets = self
            .levels
            .iter()
            .enumerate()
            .skip(hit_idx + 1)
            .map(|(idx, level)| (idx, Arc::clone(level), Arc::clone(&self.atomic_stats[idx])))
            .collect::<Vec<_>>();
        let key = key.to_owned();
        let semaphore = Arc::clone(&self.slow_level_semaphore);
        let background_tasks = Arc::clone(&self.background_tasks);

        background_tasks.spawn(async move {
            let Ok(_permit) = semaphore.acquire_owned().await else {
                return;
            };

            let mut missing = Vec::new();
            for (idx, level, stats) in targets {
                match level.entry_exists(&key).await {
                    Ok(Some(true)) => {
                        trace!("Cache level {idx} already contains {key}, no repair needed");
                    }
                    Ok(Some(false)) => missing.push((idx, level, stats)),
                    Ok(None) => {
                        trace!(
                            "Cache level {idx} has no cheap existence probe; skipping repair check"
                        );
                    }
                    Err(error) => {
                        debug!("Failed to probe cache level {idx} while repairing {key}: {error}");
                    }
                }
            }

            if missing.is_empty() {
                return;
            }

            let raw = match source.get_raw(&key).await {
                Ok(Some(raw)) => raw,
                Ok(None) => {
                    debug!(
                        "Faster cache level {hit_idx} could not provide raw bytes for repair of {key}"
                    );
                    return;
                }
                Err(error) => {
                    debug!(
                        "Failed reading raw bytes from cache level {hit_idx} for repair of {key}: {error}"
                    );
                    return;
                }
            };

            for (idx, level, stats) in missing {
                let start = Instant::now();
                match Self::write_entry_from_bytes(&level, &key, &raw).await {
                    Ok(()) => {
                        let duration = start.elapsed();
                        inc_stat!(Some(source_stats.as_ref()), backfills_from, 1);
                        inc_stat!(Some(stats.as_ref()), backfills_to, 1);
                        inc_stat!(Some(stats.as_ref()), writes, 1);
                        inc_stat!(
                            Some(stats.as_ref()),
                            write_duration_nanos,
                            duration_nanos_u64(duration)
                        );
                        trace!(
                            "Repaired slower cache level {idx} from faster level {hit_idx} in {duration:?}"
                        );
                    }
                    Err(error) => {
                        inc_stat!(Some(stats.as_ref()), write_failures, 1);
                        debug!(
                            "Failed repairing cache level {idx} from level {hit_idx} for {key}: {error}"
                        );
                    }
                }
            }
        });
    }

    /// Helper to write cache entry from raw bytes.
    ///
    /// Used during backfill operations to efficiently copy data between levels.
    async fn write_entry_from_bytes(
        level: &Arc<dyn Storage>,
        key: &str,
        data: &Bytes,
    ) -> Result<()> {
        // Bytes::clone() is a cheap ref-count bump, no data copy
        level.put_raw(key, data.clone()).await?;
        Ok(())
    }

    /// Write to levels starting from `start_idx` asynchronously.
    async fn write_remaining_levels_async(&self, key: &str, data: &Bytes, start_idx: usize) {
        for (idx, level) in self.levels.iter().enumerate().skip(start_idx) {
            // Check if level is read-only before spawning task
            if matches!(level.check().await, Ok(CacheMode::ReadOnly)) {
                debug!("Level {idx} is read-only, skipping write");
                continue;
            }

            let data = data.clone();
            let key = key.to_string();
            let level = Arc::clone(level);
            let stats_arc = self.atomic_stats.get(idx).map(Arc::clone);
            let semaphore = (idx > 0).then(|| Arc::clone(&self.slow_level_semaphore));
            let background_tasks = Arc::clone(&self.background_tasks);

            background_tasks.spawn(async move {
                let _permit = if let Some(semaphore) = semaphore {
                    match semaphore.acquire_owned().await {
                        Ok(permit) => Some(permit),
                        Err(_) => return,
                    }
                } else {
                    None
                };

                let start = Instant::now();
                match Self::write_entry_from_bytes(&level, &key, &data).await {
                    Ok(()) => {
                        let duration = start.elapsed();
                        trace!("Stored in cache level {idx} asynchronously in {duration:?}");
                        inc_stat!(stats_arc.as_deref(), writes, 1);
                        inc_stat!(
                            stats_arc.as_deref(),
                            write_duration_nanos,
                            duration_nanos_u64(duration)
                        );
                    }
                    Err(e) => {
                        debug!("Background write to level {idx} failed: {e}");
                        inc_stat!(stats_arc.as_deref(), write_failures, 1);
                    }
                }
            });
        }
    }
}

#[async_trait]
impl Storage for MultiLevelStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        for idx in 0..self.levels.len() {
            let start = Instant::now();
            let (cache_result, raw_bytes_for_backfill) = self.read_level_with_raw(idx, key).await;

            match cache_result {
                Ok(Cache::Hit(entry)) => {
                    self.record_hit_and_schedule_backfills(
                        key,
                        idx,
                        start.elapsed(),
                        raw_bytes_for_backfill,
                    );
                    return Ok(Cache::Hit(entry));
                }
                Ok(Cache::Miss) => {
                    trace!("Cache miss at level {idx}, trying next level");
                }
                Ok(other) => {
                    return Ok(other);
                }
                Err(e) => {
                    warn!("Error checking cache level {idx}: {e}, trying next level");
                }
            }
        }
        debug!("Cache miss at all levels");

        // Mark final miss for all checked levels
        for idx in 0..self.levels.len() {
            inc_stat!(self.atomic_stats.get(idx), misses, 1);
        }

        Ok(Cache::Miss)
    }

    async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
        for level in &self.levels {
            if let Some(bytes) = level.get_raw(key).await? {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        let data: Bytes = entry.finish()?.into();
        self.put_raw(key, data).await
    }

    async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
        if self.levels.is_empty() {
            return Err(anyhow!("No cache levels configured"));
        }

        let key_str = key.to_string();

        match self.write_error_policy {
            WriteErrorPolicy::Ignore => {
                // Never fail, log warnings only
                self.write_remaining_levels_async(&key_str, &data, 0).await;
                Ok(Duration::ZERO)
            }

            WriteErrorPolicy::L0 => {
                // Fail only if L0 write fails (unless L0 is read-only)
                if let Some(l0) = self.levels.first() {
                    // Check if L0 is read-only before attempting write
                    if matches!(l0.check().await, Ok(CacheMode::ReadOnly)) {
                        debug!("Level 0 is read-only, skipping L0 write");
                    } else {
                        // Attempt write and propagate errors
                        let start = Instant::now();
                        match Self::write_entry_from_bytes(l0, &key_str, &data).await {
                            Ok(()) => {
                                let duration = start.elapsed();
                                trace!("Stored in cache level 0 in {duration:?}");
                                inc_stat!(self.atomic_stats.first(), writes, 1);
                                inc_stat!(
                                    self.atomic_stats.first(),
                                    write_duration_nanos,
                                    duration_nanos_u64(duration)
                                );
                            }
                            Err(e) => {
                                inc_stat!(self.atomic_stats.first(), write_failures, 1);
                                return Err(e);
                            }
                        }
                    }

                    // Background writes for L1+ (best-effort)
                    self.write_remaining_levels_async(&key_str, &data, 1).await;
                }
                Ok(Duration::ZERO)
            }

            WriteErrorPolicy::All => {
                // Fail if any RW level fails
                use tokio::sync::mpsc;
                let (tx, mut rx) = mpsc::channel(self.levels.len());

                for (idx, level) in self.levels.iter().enumerate() {
                    let data = data.clone();
                    let key_str = key_str.clone();
                    let level = Arc::clone(level);
                    let tx = tx.clone();
                    let stats_arc = self.atomic_stats.get(idx).map(Arc::clone);
                    let semaphore = (idx > 0).then(|| Arc::clone(&self.slow_level_semaphore));

                    let write_task = async move {
                        let _permit = if let Some(semaphore) = semaphore {
                            Some(
                                semaphore
                                    .acquire_owned()
                                    .await
                                    .map_err(|_| anyhow!("slow-level write semaphore closed"))?,
                            )
                        } else {
                            None
                        };
                        let start = Instant::now();
                        let result = Self::write_entry_from_bytes(&level, &key_str, &data).await;
                        let duration = start.elapsed();
                        Ok::<_, anyhow::Error>((idx, result, level, duration, stats_arc))
                    };

                    if idx == 0 {
                        // L0 synchronous
                        let (idx, result, level, duration, stats_arc) = write_task.await?;
                        if let Err(e) = result {
                            // Check if read-only before failing
                            if !matches!(level.check().await, Ok(CacheMode::ReadOnly)) {
                                inc_stat!(stats_arc.as_deref(), write_failures, 1);
                                return Err(anyhow!("Failed to write to cache level {idx}: {e}"));
                            }
                        } else {
                            inc_stat!(stats_arc.as_deref(), writes, 1);
                            inc_stat!(
                                stats_arc.as_deref(),
                                write_duration_nanos,
                                duration_nanos_u64(duration)
                            );
                        }
                    } else {
                        // L1+ async
                        tokio::spawn(async move {
                            match write_task.await {
                                Ok(result) => {
                                    let _ = tx.send(result).await;
                                }
                                Err(error) => debug!("Slow-level write setup failed: {error}"),
                            }
                        });
                    }
                }
                drop(tx);

                // Check async results
                while let Some((idx, result, level, duration, stats_arc)) = rx.recv().await {
                    if let Err(e) = result {
                        // Check if read-only before failing
                        if !matches!(level.check().await, Ok(CacheMode::ReadOnly)) {
                            inc_stat!(stats_arc.as_deref(), write_failures, 1);
                            return Err(anyhow!("Failed to write to cache level {idx}: {e}"));
                        }
                    } else {
                        inc_stat!(stats_arc.as_deref(), writes, 1);
                        inc_stat!(
                            stats_arc.as_deref(),
                            write_duration_nanos,
                            duration_nanos_u64(duration)
                        );
                    }
                }

                Ok(Duration::ZERO)
            }
        }
    }

    async fn drain_background(&self) {
        self.background_tasks.drain().await;
    }

    async fn check(&self) -> Result<CacheMode> {
        // The composite is writable when any level is writable: put()
        // already skips read-only levels on writes, so a read-only level
        // must not demote the whole chain (e.g. a writable local disk in
        // front of a read-only shared remote). Only a chain in which
        // every level is read-only is itself read-only.
        let mut result = CacheMode::ReadOnly;
        if self.levels.is_empty() {
            return Ok(CacheMode::ReadWrite);
        }
        for (idx, level) in self.levels.iter().enumerate() {
            match level.check().await {
                Ok(CacheMode::ReadOnly) => {
                    debug!("Cache level {idx} is read-only");
                }
                Ok(CacheMode::ReadWrite) => {
                    result = CacheMode::ReadWrite;
                    trace!("Cache level {idx} is read-write");
                }
                Err(error) if idx == 0 => {
                    warn!("Error checking required cache level 0: {error}");
                    return Err(error);
                }
                Err(error) => {
                    warn!(
                        "Cache level {idx} is unavailable during startup check: {error}; continuing with faster levels"
                    );
                }
            }
        }
        debug!("Multi-level cache mode: {result:?}");
        Ok(result)
    }

    fn location(&self) -> String {
        format!("Multi-level ({} levels)", self.levels.len())
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        let mut total = 0u64;
        for level in &self.levels {
            if let Some(size) = level.current_size().await? {
                total = total.saturating_add(size);
            }
        }
        if total > 0 { Ok(Some(total)) } else { Ok(None) }
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        let mut total = 0u64;
        for level in &self.levels {
            if let Some(size) = level.max_size().await? {
                total = total.saturating_add(size);
            }
        }
        if total > 0 { Ok(Some(total)) } else { Ok(None) }
    }

    fn multilevel_stats(&self) -> Option<crate::cache::multilevel::MultiLevelStats> {
        Some(self.stats())
    }

    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        self.levels
            .first()
            .map(|level| level.preprocessor_cache_mode_config())
            .unwrap_or_default()
    }

    fn basedirs(&self) -> &[Vec<u8>] {
        &self.basedirs
    }

    async fn get_preprocessor_cache_entry(
        &self,
        key: &str,
    ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
        for level in &self.levels {
            if let Some(entry) = level.get_preprocessor_cache_entry(key).await? {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    async fn put_preprocessor_cache_entry(
        &self,
        key: &str,
        preprocessor_cache_entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        // Write preprocessor cache to all levels in parallel (best-effort)
        // Unlike regular cache entries, preprocessor cache writes are not critical
        // and shouldn't fail the compilation
        let futures: Vec<_> = self
            .levels
            .iter()
            .enumerate()
            .map(|(idx, level)| {
                let key = key.to_string();
                let entry = preprocessor_cache_entry.clone();
                let level = Arc::clone(level);
                let semaphore = (idx > 0).then(|| Arc::clone(&self.slow_level_semaphore));

                tokio::spawn(async move {
                    let _permit = if let Some(semaphore) = semaphore {
                        match semaphore.acquire_owned().await {
                            Ok(permit) => Some(permit),
                            Err(_) => return,
                        }
                    } else {
                        None
                    };
                    if let Err(e) = level.put_preprocessor_cache_entry(&key, entry).await {
                        warn!("Failed to write preprocessor cache entry to level {idx}: {e}");
                    }
                })
            })
            .collect();

        // Wait for all writes to complete (errors are logged, not propagated)
        futures::future::join_all(futures).await;

        Ok(())
    }
}

#[cfg(test)]
#[path = "multilevel_test.rs"]
mod test;
