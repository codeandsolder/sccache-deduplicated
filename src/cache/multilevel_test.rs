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

use super::*;
use crate::cache::CacheRead;
use crate::cache::disk::DiskCache;
use crate::cache::readonly::ReadOnlyStorage;
use crate::config::Config;
use crate::config::PreprocessorCacheModeConfig;
use bytes::Bytes;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use tempfile::Builder as TempBuilder;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::Mutex;
use tokio::time::sleep;

#[test]
fn average_duration_handles_more_than_u32_samples() {
    let samples = u64::from(u32::MAX) + 1;
    let total = Duration::from_secs(samples);
    assert_eq!(average_duration(total, samples), Duration::from_secs(1));
}

#[test]
fn duration_nanos_saturates_instead_of_truncating() {
    assert_eq!(duration_nanos_u64(Duration::from_secs(u64::MAX)), u64::MAX);
}

#[test]
fn test_multi_level_storage_get() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let tempdir1 = TempBuilder::new().prefix("sccache_test_l1_").tempdir()?;
    let cache_dir1 = tempdir1.path().join("cache");
    fs::create_dir(&cache_dir1)?;

    let tempdir2 = TempBuilder::new().prefix("sccache_test_l2_").tempdir()?;
    let cache_dir2 = tempdir2.path().join("cache");
    fs::create_dir(&cache_dir2)?;

    let cache1 = DiskCache::new(
        &cache_dir1,
        1024 * 1024 * 100,
        runtime.handle(),
        PreprocessorCacheModeConfig::default(),
        CacheMode::ReadWrite,
        vec![],
    );
    let cache2 = DiskCache::new(
        &cache_dir2,
        1024 * 1024 * 100,
        runtime.handle(),
        PreprocessorCacheModeConfig::default(),
        CacheMode::ReadWrite,
        vec![],
    );

    let cache1_storage: Arc<dyn Storage> = Arc::new(cache1);
    let cache2_storage: Arc<dyn Storage> = Arc::new(cache2);

    let storage = MultiLevelStorage::new(vec![
        Arc::clone(&cache1_storage),
        Arc::clone(&cache2_storage),
    ]);

    runtime.block_on(async {
        // Write directly to level 2 (level 1 is empty)
        {
            let entry = CacheWrite::default();
            cache2_storage.put("test_key", entry).await?;
        }

        // Now try to read through multi-level storage
        assert!(
            matches!(storage.get("test_key").await?, Cache::Hit(_)),
            "Expected cache hit at level 2"
        );

        // Try non-existent key
        assert!(
            matches!(storage.get("nonexistent").await?, Cache::Miss),
            "Expected cache miss"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_multi_level_storage_backfill_on_hit() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let tempdir1 = TempBuilder::new().prefix("sccache_test_bf_l1_").tempdir()?;
    let cache_dir1 = tempdir1.path().join("cache");
    fs::create_dir(&cache_dir1)?;

    let tempdir2 = TempBuilder::new().prefix("sccache_test_bf_l2_").tempdir()?;
    let cache_dir2 = tempdir2.path().join("cache");
    fs::create_dir(&cache_dir2)?;

    let cache1 = DiskCache::new(
        &cache_dir1,
        1024 * 1024 * 100,
        runtime.handle(),
        PreprocessorCacheModeConfig::default(),
        CacheMode::ReadWrite,
        vec![],
    );
    let cache2 = DiskCache::new(
        &cache_dir2,
        1024 * 1024 * 100,
        runtime.handle(),
        PreprocessorCacheModeConfig::default(),
        CacheMode::ReadWrite,
        vec![],
    );

    let cache1_storage: Arc<dyn Storage> = Arc::new(cache1);
    let cache2_storage: Arc<dyn Storage> = Arc::new(cache2);

    let storage = MultiLevelStorage::new(vec![
        Arc::clone(&cache1_storage),
        Arc::clone(&cache2_storage),
    ]);

    runtime.block_on(async {
        // Write directly to level 2 (level 1 is empty)
        {
            let entry = CacheWrite::default();
            cache2_storage.put("backfill_key", entry).await?;
        }

        // Verify level 1 doesn't have it yet
        assert!(
            matches!(cache1_storage.get("backfill_key").await?, Cache::Miss),
            "Level 1 should be empty"
        );

        // Now read through multi-level storage - should hit level 2 and backfill to level 1
        assert!(
            matches!(storage.get("backfill_key").await?, Cache::Hit(_)),
            "Expected cache hit at level 2"
        );

        // Give background backfill task time to complete
        sleep(Duration::from_millis(200)).await;

        // Now level 1 should have the data (backfilled)
        assert!(
            matches!(cache1_storage.get("backfill_key").await?, Cache::Hit(_)),
            "Level 1 should now have the data (backfilled)"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

/// In-memory storage mock for testing multi-level backfill with remote-like backends.
///
/// This is used to test multi-level cache backfill logic without requiring:
/// - Network access to real remote services (S3, Redis, etc.)
/// - Complex mock infrastructure (channels, queues, etc.)
/// - Disk I/O operations
///
/// The mock implements both Storage trait and `get_raw()` to simulate real backend
/// behavior where remote caches support raw byte retrieval for efficient backfilling.
struct InMemoryStorage {
    data: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    access_log: Arc<Mutex<Vec<String>>>,
    raw_access_log: Arc<Mutex<Vec<String>>>,
    existence_log: Arc<Mutex<Vec<String>>>,
}

impl InMemoryStorage {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
            access_log: Arc::new(Mutex::new(Vec::new())),
            raw_access_log: Arc::new(Mutex::new(Vec::new())),
            existence_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn get_access_log(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.access_log)
    }

    fn get_raw_access_log(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.raw_access_log)
    }

    fn get_existence_log(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.existence_log)
    }
}

#[async_trait]
impl Storage for InMemoryStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        self.access_log.lock().await.push(format!("get:{key}"));

        let data = self.data.lock().await;
        Ok(data.get(key).map_or_else(
            || Cache::Miss,
            |bytes| {
                CacheRead::from(Cursor::new(bytes.clone())).map_or_else(|_| Cache::Miss, Cache::Hit)
            },
        ))
    }

    async fn get_with_raw(&self, key: &str) -> Result<(Cache, Option<Bytes>)> {
        let Some(bytes) = self.get_raw(key).await? else {
            return Ok((Cache::Miss, None));
        };
        let raw_bytes = bytes.clone();
        match CacheRead::from(Cursor::new(bytes)) {
            Ok(entry) => Ok((Cache::Hit(entry), Some(raw_bytes))),
            Err(error) => Err(error),
        }
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        self.access_log.lock().await.push(format!("put:{key}"));

        let data = entry.finish()?;
        self.data.lock().await.insert(key.to_string(), data);
        Ok(Duration::ZERO)
    }

    async fn check(&self) -> Result<CacheMode> {
        Ok(CacheMode::ReadWrite)
    }

    fn location(&self) -> String {
        "InMemory".to_string()
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn entry_exists(&self, key: &str) -> Result<Option<bool>> {
        self.existence_log
            .lock()
            .await
            .push(format!("entry_exists:{key}"));
        Ok(Some(self.data.lock().await.contains_key(key)))
    }

    /// Implement `get_raw()` to enable backfill testing with remote-like backends.
    /// This simulates the behavior of real remote backends (S3, Redis, etc.) that
    /// can efficiently return raw serialized cache entries for backfilling.
    async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
        self.raw_access_log
            .lock()
            .await
            .push(format!("get_raw:{key}"));
        Ok(self.data.lock().await.get(key).cloned().map(Bytes::from))
    }

    /// Implement `put_raw()` to enable backfill writes during testing.
    async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
        self.data
            .lock()
            .await
            .insert(key.to_string(), data.to_vec());
        Ok(Duration::ZERO)
    }
}

#[test]
fn test_l0_hit_repairs_missing_l1_without_blocking_hit() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let l0 = Arc::new(InMemoryStorage::new());
    let l1 = Arc::new(InMemoryStorage::new());
    let storage = MultiLevelStorage::new(vec![
        l0.clone() as Arc<dyn Storage>,
        l1.clone() as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        l0.put("repair_key", CacheWrite::default()).await?;
        l0.get_raw_access_log().lock().await.clear();

        assert!(matches!(storage.get("repair_key").await?, Cache::Hit(_)));

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if l1.data.lock().await.contains_key("repair_key") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;

        assert_eq!(
            l1.get_existence_log().lock().await.as_slice(),
            &["entry_exists:repair_key"]
        );
        assert_eq!(
            l0.get_raw_access_log().lock().await.as_slice(),
            &["get_raw:repair_key"]
        );

        let stats = storage.stats();
        assert_eq!(stats.0[0].backfills_from, 1);
        assert_eq!(stats.0[1].backfills_to, 1);
        assert_eq!(stats.0[1].writes, 1);
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_l0_hit_does_not_read_source_when_l1_already_has_key() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let l0 = Arc::new(InMemoryStorage::new());
    let l1 = Arc::new(InMemoryStorage::new());
    let storage = MultiLevelStorage::new(vec![
        l0.clone() as Arc<dyn Storage>,
        l1.clone() as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        l0.put("present_key", CacheWrite::default()).await?;
        l1.put("present_key", CacheWrite::default()).await?;
        l0.get_raw_access_log().lock().await.clear();
        l1.get_existence_log().lock().await.clear();

        assert!(matches!(storage.get("present_key").await?, Cache::Hit(_)));

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !l1.get_existence_log().lock().await.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;

        assert_eq!(
            l1.get_existence_log().lock().await.as_slice(),
            &["entry_exists:present_key"]
        );
        assert!(l0.get_raw_access_log().lock().await.is_empty());

        let stats = storage.stats();
        assert_eq!(stats.0[0].backfills_from, 0);
        assert_eq!(stats.0[1].backfills_to, 0);
        assert_eq!(stats.0[1].writes, 0);
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_multilevel_raw_hit_reads_backend_once() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let l0 = Arc::new(InMemoryStorage::new());
    let l1 = Arc::new(InMemoryStorage::new());
    let storage = MultiLevelStorage::new(vec![
        l0.clone() as Arc<dyn Storage>,
        l1.clone() as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        let entry = CacheWrite::default();
        l1.put("single_read_key", entry).await?;

        // Ignore setup writes and assert the lookup path itself.  A raw-capable
        // level should be read once, then the same bytes should feed both
        // parsing and the asynchronous backfill.
        l0.get_access_log().lock().await.clear();
        l1.get_access_log().lock().await.clear();
        l1.get_raw_access_log().lock().await.clear();

        assert!(matches!(
            storage.get("single_read_key").await?,
            Cache::Hit(_)
        ));

        assert_eq!(
            l1.get_raw_access_log().lock().await.as_slice(),
            &["get_raw:single_read_key"]
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_disk_plus_remote_to_remote_backfill() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // Create multi-level cache: Disk (L0) + Memcached (L1) + Redis (L2) + S3 (L3)
    // This simulates a real-world setup with local disk cache and multiple remote caches
    let tempdir = TempBuilder::new()
        .prefix("sccache_test_multilevel_")
        .tempdir()?;
    let cache_dir = tempdir.path().join("cache");
    fs::create_dir(&cache_dir)?;

    let disk_cache = Arc::new(DiskCache::new(
        &cache_dir,
        1024 * 1024 * 100,
        runtime.handle(),
        PreprocessorCacheModeConfig::default(),
        CacheMode::ReadWrite,
        vec![],
    ));

    let remote_l1 = Arc::new(InMemoryStorage::new()); // Memcached-like
    let remote_l2 = Arc::new(InMemoryStorage::new()); // Redis-like
    let remote_l3 = Arc::new(InMemoryStorage::new()); // S3-like

    let storage = MultiLevelStorage::new(vec![
        disk_cache.clone() as Arc<dyn Storage>,
        remote_l1.clone() as Arc<dyn Storage>,
        remote_l2.clone() as Arc<dyn Storage>,
        remote_l3.clone() as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        // Scenario: Data only in S3 (L3), need to backfill all the way to local disk (L0)
        {
            let entry = CacheWrite::default();
            remote_l3.put("global_key", entry).await?;
        }

        // Verify only L3 has it
        assert!(matches!(disk_cache.get("global_key").await?, Cache::Miss));
        assert!(matches!(remote_l1.get("global_key").await?, Cache::Miss));
        assert!(matches!(remote_l2.get("global_key").await?, Cache::Miss));

        // Read through multi-level storage - should hit L3 and backfill everywhere
        assert!(
            matches!(storage.get("global_key").await?, Cache::Hit(_)),
            "Expected cache hit at L3"
        );

        // Give all background backfill tasks time to complete
        // We have 3 backfill tasks (L3 -> L2, L3 -> L1, L3 -> L0)
        sleep(Duration::from_millis(400)).await;

        // Verify local disk was backfilled (closest to CPU)
        assert!(
            matches!(disk_cache.get("global_key").await?, Cache::Hit(_)),
            "Disk cache should be backfilled from L3"
        );

        // Verify remote L1 was backfilled
        assert!(
            matches!(remote_l1.get("global_key").await?, Cache::Hit(_)),
            "Remote L1 should be backfilled from L3"
        );

        // Verify remote L2 was backfilled
        assert!(
            matches!(remote_l2.get("global_key").await?, Cache::Hit(_)),
            "Remote L2 should be backfilled from L3"
        );

        // Now reading should hit at L0 (disk) - fastest
        assert!(
            matches!(storage.get("global_key").await?, Cache::Hit(_)),
            "Should hit at disk cache (L0)"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_disk_plus_remotes_write_to_all() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // Test write path: ensure data is written to all levels
    let tempdir = TempBuilder::new()
        .prefix("sccache_test_write_all_")
        .tempdir()?;
    let cache_dir = tempdir.path().join("cache");
    fs::create_dir(&cache_dir)?;

    let disk_cache = Arc::new(DiskCache::new(
        &cache_dir,
        1024 * 1024 * 100,
        runtime.handle(),
        PreprocessorCacheModeConfig::default(),
        CacheMode::ReadWrite,
        vec![],
    ));

    let remote_l1 = Arc::new(InMemoryStorage::new());
    let remote_l2 = Arc::new(InMemoryStorage::new());

    let storage = MultiLevelStorage::new(vec![
        disk_cache.clone() as Arc<dyn Storage>,
        remote_l1.clone() as Arc<dyn Storage>,
        remote_l2.clone() as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        // Write through multi-level should go to all levels
        {
            let entry = CacheWrite::default();
            storage.put("write_test_key", entry).await?;
        }

        // Give async writes time to complete
        sleep(Duration::from_millis(200)).await;

        // Verify disk cache has it
        assert!(
            matches!(disk_cache.get("write_test_key").await?, Cache::Hit(_)),
            "Disk cache should have data after put"
        );

        // Verify both remote caches have it
        assert!(
            matches!(remote_l1.get("write_test_key").await?, Cache::Hit(_)),
            "Remote L1 should have data after put"
        );

        assert!(
            matches!(remote_l2.get("write_test_key").await?, Cache::Hit(_)),
            "Remote L2 should have data after put"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_remote_to_remote_backfill() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // Create three in-memory "remote" caches to simulate:
    // L0: Memcached (fast, small)
    // L1: Redis (medium, medium)
    // L2: S3 (slow, large)
    let cache_l0 = Arc::new(InMemoryStorage::new());
    let cache_l1 = Arc::new(InMemoryStorage::new());
    let cache_l2 = Arc::new(InMemoryStorage::new());

    let storage = MultiLevelStorage::new(vec![
        cache_l0.clone() as Arc<dyn Storage>,
        cache_l1.clone() as Arc<dyn Storage>,
        cache_l2.clone() as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        // Simulate cache miss at L0 and L1, hit at L2 (typical scenario)
        {
            let entry = CacheWrite::default();
            cache_l2.put("remote_key", entry).await?;
        }

        // Verify L0 and L1 are empty (cache misses at those levels)
        assert!(
            matches!(cache_l0.get("remote_key").await?, Cache::Miss),
            "L0 should be empty initially"
        );
        assert!(
            matches!(cache_l1.get("remote_key").await?, Cache::Miss),
            "L1 should be empty initially"
        );

        // Read through multi-level storage - should hit L2 and backfill to L0 and L1
        assert!(
            matches!(storage.get("remote_key").await?, Cache::Hit(_)),
            "Expected cache hit at L2"
        );

        // Give background backfill tasks time to complete
        // Multiple levels means multiple concurrent spawn tasks
        sleep(Duration::from_millis(300)).await;

        // Verify L0 was backfilled from L2 (through L1)
        assert!(
            matches!(cache_l0.get("remote_key").await?, Cache::Hit(_)),
            "L0 should be backfilled from L2"
        );

        // Verify L1 was backfilled from L2
        assert!(
            matches!(cache_l1.get("remote_key").await?, Cache::Hit(_)),
            "L1 should be backfilled from L2"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
#[serial_test::serial(multilevel_env)]
fn test_config_validation_invalid_level_name() -> Result<()> {
    // Test that invalid level names are rejected
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // Set invalid level name
    // SAFETY: this test is serialized on multilevel_env, so these process-wide env changes cannot race peer tests.
    unsafe {
        env::set_var("SCCACHE_MULTILEVEL_CHAIN", "disk,invalid_backend,s3");
        env::set_var("SCCACHE_DIR", "/tmp/test-cache");
    }

    let config = Config::load()?;
    let result = MultiLevelStorage::from_config(&config, runtime.handle());

    // Should error with unknown cache level
    assert!(result.is_err());
    if let Err(e) = result {
        let err_msg = format!("{e}");
        assert!(err_msg.contains("Unknown cache level") || err_msg.contains("invalid_backend"));
    }

    // SAFETY: this test is serialized on multilevel_env; restore the process-wide variables before releasing the lock.
    unsafe {
        env::remove_var("SCCACHE_MULTILEVEL_CHAIN");
        env::remove_var("SCCACHE_DIR");
    }
    Ok(())
}

#[test]
fn test_config_validation_empty_levels() -> Result<()> {
    // Test that empty levels list is handled
    let storage = MultiLevelStorage::new(vec![]);

    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    runtime.block_on(async {
        // Get should return miss (no levels to check)
        assert!(
            matches!(storage.get("test_key").await?, Cache::Miss),
            "Empty levels should always miss"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_config_validation_single_level() -> Result<()> {
    // Test that single level works (passthrough mode)
    let cache = Arc::new(InMemoryStorage::new());
    let storage = MultiLevelStorage::new(vec![cache.clone() as Arc<dyn Storage>]);

    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    runtime.block_on(async {
        let entry = CacheWrite::default();
        storage.put("single_key", entry).await?;

        assert!(
            matches!(storage.get("single_key").await?, Cache::Hit(_)),
            "Single level should work as passthrough"
        );

        // Should not backfill since only one level
        assert!(
            matches!(cache.get("single_key").await?, Cache::Hit(_)),
            "Data should be in the single level"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
#[serial_test::serial(multilevel_env)]
fn test_config_level_not_configured() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // Set level without configuration
    // SAFETY: this test is serialized on multilevel_env, so these process-wide env changes cannot race peer tests.
    unsafe {
        env::set_var("SCCACHE_MULTILEVEL_CHAIN", "redis");
        // Don't set SCCACHE_REDIS_ENDPOINT
        env::remove_var("SCCACHE_REDIS");
        env::remove_var("SCCACHE_REDIS_ENDPOINT");
    }

    let config = Config::load()?;
    let result = MultiLevelStorage::from_config(&config, runtime.handle());

    // Should error with "not configured" or "requires" (when feature disabled)
    assert!(result.is_err());
    if let Err(e) = result {
        let err_msg = format!("{e}");
        assert!(
            err_msg.contains("not configured")
                || err_msg.contains("missing")
                || err_msg.contains("requires"),
            "Expected error about missing config or feature, got: {err_msg}"
        );
    }

    // SAFETY: this test is serialized on multilevel_env; restore the process-wide variable before releasing the lock.
    unsafe {
        env::remove_var("SCCACHE_MULTILEVEL_CHAIN");
    }
    Ok(())
}

#[test]
fn test_concurrent_reads() -> Result<()> {
    // Test multiple simultaneous reads to different levels
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()?;

    let cache_l0 = Arc::new(InMemoryStorage::new());
    let cache_l1 = Arc::new(InMemoryStorage::new());
    let cache_l2 = Arc::new(InMemoryStorage::new());

    let storage = Arc::new(MultiLevelStorage::new(vec![
        cache_l0.clone() as Arc<dyn Storage>,
        cache_l1.clone() as Arc<dyn Storage>,
        cache_l2.clone() as Arc<dyn Storage>,
    ]));

    runtime.block_on(async {
        // Populate different keys at different levels
        cache_l0.put("key_l0", CacheWrite::default()).await?;
        cache_l1.put("key_l1", CacheWrite::default()).await?;
        cache_l2.put("key_l2", CacheWrite::default()).await?;

        // Concurrent reads
        let storage1 = Arc::clone(&storage);
        let storage2 = Arc::clone(&storage);
        let storage3 = Arc::clone(&storage);

        let (r1, r2, r3) = tokio::join!(
            async move { storage1.get("key_l0").await },
            async move { storage2.get("key_l1").await },
            async move { storage3.get("key_l2").await },
        );

        // All should hit
        assert!(matches!(r1?, Cache::Hit(_)));
        assert!(matches!(r2?, Cache::Hit(_)));
        assert!(matches!(r3?, Cache::Hit(_)));
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_concurrent_write_and_read() -> Result<()> {
    // Test concurrent writes and reads to same key
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()?;

    let cache_l0 = Arc::new(InMemoryStorage::new());
    let cache_l1 = Arc::new(InMemoryStorage::new());

    let storage = Arc::new(MultiLevelStorage::new(vec![
        cache_l0 as Arc<dyn Storage>,
        cache_l1 as Arc<dyn Storage>,
    ]));

    runtime.block_on(async {
        let storage_write = Arc::clone(&storage);
        let storage_read = Arc::clone(&storage);

        // Concurrent write and read
        let write_task = tokio::spawn(async move {
            storage_write
                .put("concurrent_key", CacheWrite::default())
                .await
        });

        let read_task = tokio::spawn(async move {
            sleep(Duration::from_millis(10)).await;
            storage_read.get("concurrent_key").await
        });

        let (write_result, read_result) = tokio::join!(write_task, read_task);

        // Write should succeed
        write_result??;

        // Read might miss or hit depending on timing (both are valid)
        assert!(
            matches!(read_result??, Cache::Hit(_) | Cache::Miss),
            "Unexpected cache result"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_large_data_handling() -> Result<()> {
    // Test with large cache entries
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let cache_l0 = Arc::new(InMemoryStorage::new());
    let cache_l1 = Arc::new(InMemoryStorage::new());

    let storage = MultiLevelStorage::new(vec![
        cache_l0.clone() as Arc<dyn Storage>,
        cache_l1.clone() as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        // Create large entry (1MB of data)
        let mut entry = CacheWrite::new();
        let large_data = vec![0xAB; 1024 * 1024]; // 1MB of data
        entry.put_stdout(&large_data)?;
        cache_l1.put("large_key", entry).await?;

        // Read through multi-level - should hit at L1
        assert!(
            matches!(storage.get("large_key").await?, Cache::Hit(_)),
            "Should hit at L1"
        );

        // Wait for backfill
        sleep(Duration::from_millis(200)).await;

        // Verify L0 was backfilled
        assert!(
            matches!(cache_l0.get("large_key").await?, Cache::Hit(_)),
            "L0 should have backfilled data from L1"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_storage_trait_methods() -> Result<()> {
    // Test Storage trait methods: check(), location(), current_size(), max_size()
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let cache_l0 = Arc::new(InMemoryStorage::new());
    let cache_l1 = Arc::new(InMemoryStorage::new());

    let storage = MultiLevelStorage::new(vec![
        cache_l0 as Arc<dyn Storage>,
        cache_l1 as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        // Test check() - should return ReadWrite
        assert!(
            matches!(storage.check().await?, CacheMode::ReadWrite),
            "Expected ReadWrite mode"
        );

        // Test location() - should return multi-level description
        let location = storage.location();
        assert!(
            location.contains("Multi-level"),
            "Location should mention Multi-level: {location}"
        );

        // Test current_size() - should return None or Some
        let _ = storage.current_size().await?;

        // Test max_size() - should return None or Some
        let _ = storage.max_size().await?;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_all_levels_fail_on_put() -> Result<()> {
    // Test behavior when all storage levels fail on write
    // In multi-level design, put() succeeds if ANY level succeeds
    // Even if all fail, it should not panic
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // Create ReadOnly storages that will reject writes
    let cache_l0 = Arc::new(ReadOnlyStorage(Arc::new(InMemoryStorage::new())));
    let cache_l1 = Arc::new(ReadOnlyStorage(Arc::new(InMemoryStorage::new())));

    let storage = MultiLevelStorage::new(vec![
        cache_l0 as Arc<dyn Storage>,
        cache_l1 as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        let entry = CacheWrite::new();

        // put() should complete without panic even when all levels fail
        // (writes to L0 are synchronous, L1+ are async background)
        let result = storage.put("fail_key", entry).await;

        assert!(result.is_ok(), "Put should succeed with read-only levels");
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_preprocessor_cache_mode() -> Result<()> {
    // Test preprocessor_cache_mode_config() returns first level's config
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let tempdir = TempBuilder::new()
        .prefix("sccache_test_preprocessor_")
        .tempdir()?;
    let cache_dir = tempdir.path().join("cache");
    fs::create_dir(&cache_dir)?;

    let preprocessor_config = PreprocessorCacheModeConfig {
        use_preprocessor_cache_mode: true,
        ..Default::default()
    };

    let disk_cache = Arc::new(DiskCache::new(
        &cache_dir,
        1024 * 1024 * 100,
        runtime.handle(),
        preprocessor_config,
        CacheMode::ReadWrite,
        vec![],
    ));

    let cache_l1 = Arc::new(InMemoryStorage::new());

    let storage = MultiLevelStorage::new(vec![
        disk_cache as Arc<dyn Storage>,
        cache_l1 as Arc<dyn Storage>,
    ]);

    // Should return first level's config
    let config = storage.preprocessor_cache_mode_config();
    assert!(config.use_preprocessor_cache_mode);
    Ok(())
}

#[test]
fn test_empty_levels_new() {
    // Edge case: creating MultiLevelStorage with empty vec
    // This is allowed but from_config prevents it
    let storage = MultiLevelStorage::new(vec![]);

    // Should have zero levels
    assert_eq!(storage.levels.len(), 0);

    // location() should still work
    let location = storage.location();
    assert!(location.contains('0'));
}

#[test]
fn test_preprocessor_cache_methods() -> Result<()> {
    // Test get_preprocessor_cache_entry and put_preprocessor_cache_entry
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let tempdir = TempBuilder::new().prefix("sccache_test_prep_").tempdir()?;
    let cache_dir = tempdir.path().join("cache");
    fs::create_dir(&cache_dir)?;

    let disk_cache = Arc::new(DiskCache::new(
        &cache_dir,
        1024 * 1024 * 100,
        runtime.handle(),
        PreprocessorCacheModeConfig::default(),
        CacheMode::ReadWrite,
        vec![],
    ));

    let storage = MultiLevelStorage::new(vec![disk_cache as Arc<dyn Storage>]);

    runtime.block_on(async {
        // Test get_preprocessor_cache_entry - should return None for non-existent key
        let result = storage.get_preprocessor_cache_entry("test_key").await;
        assert!(result.is_ok());
        assert!(result?.is_none());

        // Test put_preprocessor_cache_entry
        let entry = PreprocessorCacheEntry::default();
        let result = storage
            .put_preprocessor_cache_entry("test_key", entry)
            .await;
        assert!(result.is_ok());
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_readonly_level_in_check() -> Result<()> {
    // Test that check() properly detects read-only levels
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let tempdir = TempBuilder::new().prefix("sccache_test_ro_").tempdir()?;
    let cache_dir = tempdir.path().join("cache");
    fs::create_dir(&cache_dir)?;

    let disk_cache = DiskCache::new(
        &cache_dir,
        1024 * 1024 * 100,
        runtime.handle(),
        PreprocessorCacheModeConfig::default(),
        CacheMode::ReadWrite,
        vec![],
    );

    // Wrap in ReadOnly
    let ro_cache = Arc::new(ReadOnlyStorage(Arc::new(disk_cache)));

    let storage = MultiLevelStorage::new(vec![ro_cache as Arc<dyn Storage>]);

    runtime.block_on(async {
        // check() should detect read-only mode
        assert!(
            matches!(storage.check().await?, CacheMode::ReadOnly),
            "Should detect read-only mode"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_mixed_readonly_chain_is_readwrite_in_check() -> Result<()> {
    // A chain that contains a writable level must report ReadWrite even
    // when other levels are read-only: put() skips read-only levels, so a
    // read-only remote behind a writable local disk (the documented
    // "read-only fallback" topology) must not demote the whole cache to
    // read-only. Regression test for #2773.
    let runtime = RuntimeBuilder::new_current_thread().enable_all().build()?;

    // Writable L0, read-only L1
    let writable_l0 = Arc::new(InMemoryStorage::new());
    let read_only_l1 = Arc::new(ReadOnlyStorage(Arc::new(InMemoryStorage::new())));
    let storage = MultiLevelStorage::new(vec![
        writable_l0 as Arc<dyn Storage>,
        read_only_l1 as Arc<dyn Storage>,
    ]);
    runtime.block_on(async {
        assert!(
            matches!(storage.check().await?, CacheMode::ReadWrite),
            "Writable L0 + read-only L1 should be ReadWrite"
        );
        Ok::<(), anyhow::Error>(())
    })?;

    // Read-only L0, writable L1: still writable (put() skips L0)
    let read_only_l0 = Arc::new(ReadOnlyStorage(Arc::new(InMemoryStorage::new())));
    let writable_l1 = Arc::new(InMemoryStorage::new());
    let storage = MultiLevelStorage::new(vec![
        read_only_l0 as Arc<dyn Storage>,
        writable_l1 as Arc<dyn Storage>,
    ]);
    runtime.block_on(async {
        assert!(
            matches!(storage.check().await?, CacheMode::ReadWrite),
            "Read-only L0 + writable L1 should be ReadWrite"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

struct CheckFailingStorage;

#[async_trait]
impl Storage for CheckFailingStorage {
    async fn get(&self, _key: &str) -> Result<Cache> {
        Err(anyhow!("intentional check failure"))
    }

    async fn put(&self, _key: &str, _entry: CacheWrite) -> Result<Duration> {
        Err(anyhow!("intentional check failure"))
    }

    async fn check(&self) -> Result<CacheMode> {
        Err(anyhow!("intentional check failure"))
    }

    fn location(&self) -> String {
        "CheckFailingStorage".to_owned()
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}

#[test]
fn test_unavailable_l1_does_not_block_healthy_l0() -> Result<()> {
    let runtime = RuntimeBuilder::new_current_thread().enable_all().build()?;

    let l0 = Arc::new(InMemoryStorage::new());
    let l1 = Arc::new(CheckFailingStorage);
    let storage = MultiLevelStorage::new(vec![l0 as Arc<dyn Storage>, l1 as Arc<dyn Storage>]);

    runtime.block_on(async {
        assert!(matches!(storage.check().await?, CacheMode::ReadWrite));
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_unavailable_l0_remains_fatal() -> Result<()> {
    let runtime = RuntimeBuilder::new_current_thread().enable_all().build()?;

    let l0 = Arc::new(CheckFailingStorage);
    let l1 = Arc::new(InMemoryStorage::new());
    let storage = MultiLevelStorage::new(vec![l0 as Arc<dyn Storage>, l1 as Arc<dyn Storage>]);

    runtime.block_on(async {
        assert!(storage.check().await.is_err());
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_all_readonly_chain_is_readonly_in_check() -> Result<()> {
    // Only a chain in which EVERY level is read-only is itself read-only.
    let runtime = RuntimeBuilder::new_current_thread().enable_all().build()?;

    let read_only_l0 = Arc::new(ReadOnlyStorage(Arc::new(InMemoryStorage::new())));
    let read_only_l1 = Arc::new(ReadOnlyStorage(Arc::new(InMemoryStorage::new())));
    let storage = MultiLevelStorage::new(vec![
        read_only_l0 as Arc<dyn Storage>,
        read_only_l1 as Arc<dyn Storage>,
    ]);
    runtime.block_on(async {
        assert!(
            matches!(storage.check().await?, CacheMode::ReadOnly),
            "All read-only levels should be ReadOnly"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_sequential_read_order() -> Result<()> {
    // Test that reads happen sequentially (L0, L1, L2, ...), not in parallel
    // This verifies the documented behavior: "check multiple storage backends in sequence"
    let runtime = RuntimeBuilder::new_current_thread().enable_all().build()?;

    // Create three storage levels with access tracking
    let l0 = Arc::new(InMemoryStorage::new());
    let l1 = Arc::new(InMemoryStorage::new());
    let l2 = Arc::new(InMemoryStorage::new());

    let l0_log = l0.get_access_log();
    let l1_log = l1.get_access_log();
    let l2_log = l2.get_access_log();
    let l1_raw_log = l1.get_raw_access_log();
    let l2_raw_log = l2.get_raw_access_log();

    // Put data only in L2 (slowest level)
    let key = "test_key_12345678901234567890";
    runtime.block_on(async {
        let mut entry = CacheWrite::default();
        entry.put_stdout(b"test data")?;
        l2.put(key, entry).await?;
        Ok::<(), anyhow::Error>(())
    })?;

    let storage = MultiLevelStorage::new(vec![
        l0 as Arc<dyn Storage>,
        l1 as Arc<dyn Storage>,
        l2 as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        let result = storage.get(key).await?;

        assert!(matches!(result, Cache::Hit(_)));

        // Check that all three levels were accessed in order
        let l0_accesses = l0_log.lock().await;
        let l1_accesses = l1_log.lock().await;
        let l2_accesses = l2_log.lock().await;

        // L0 still uses get(); raw-capable lower levels use one get_raw() to
        // both parse and backfill the hit.
        assert_eq!(l0_accesses.len(), 1, "L0 should be checked first");
        assert_eq!(l1_accesses.len(), 0, "L1 should use raw lookup");
        assert_eq!(l2_accesses.len(), 1, "L2 should contain setup put only");
        assert_eq!(
            l1_raw_log.lock().await.as_slice(),
            &[format!("get_raw:{key}")]
        );
        assert_eq!(
            l2_raw_log.lock().await.as_slice(),
            &[format!("get_raw:{key}")]
        );

        assert_eq!(l0_accesses[0], format!("get:{key}"));
        assert_eq!(l2_accesses[0], format!("put:{key}")); // from setup
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_read_stops_at_first_hit_not_parallel() -> Result<()> {
    // Test that when L1 has data, L2 is NEVER accessed (proving sequential not parallel)
    let runtime = RuntimeBuilder::new_current_thread().enable_all().build()?;

    let l0 = Arc::new(InMemoryStorage::new());
    let l1 = Arc::new(InMemoryStorage::new());
    let l2 = Arc::new(InMemoryStorage::new());

    let l0_log = l0.get_access_log();
    let l1_log = l1.get_access_log();
    let l2_log = l2.get_access_log();
    let l1_raw_log = l1.get_raw_access_log();

    let key = "test_key_early_hit_1234567890ab";

    // Put data in L1
    runtime.block_on(async {
        let mut entry = CacheWrite::default();
        entry.put_stdout(b"L1 data")?;
        l1.put(key, entry).await?;
        Ok::<(), anyhow::Error>(())
    })?;

    let storage = MultiLevelStorage::new(vec![
        l0 as Arc<dyn Storage>,
        l1 as Arc<dyn Storage>,
        l2 as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        let result = storage.get(key).await?;

        assert!(matches!(result, Cache::Hit(_)));

        // Verify L0 and L1 were accessed, but L2 was NOT
        let l0_accesses = l0_log.lock().await;
        let l1_accesses = l1_log.lock().await;
        let l2_accesses = l2_log.lock().await;

        assert_eq!(l0_accesses.len(), 1, "L0 should be checked first");
        assert_eq!(
            l1_accesses.len(),
            1,
            "L1: put (setup); lookup uses raw access"
        );
        assert_eq!(
            l1_raw_log.lock().await.as_slice(),
            &[format!("get_raw:{key}")]
        );
        assert_eq!(
            l2_accesses.len(),
            0,
            "L2 should NOT be checked (sequential read stops at first hit)"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

/// Storage mock that always fails on write (for testing error handling).
///
/// Unlike `ReadOnlyStorage` (which is a valid mode), this returns actual errors
/// to simulate real failure scenarios like disk full, network errors, etc.
struct FailingStorage;

#[async_trait]
impl Storage for FailingStorage {
    async fn get(&self, _key: &str) -> Result<Cache> {
        Ok(Cache::Miss)
    }

    async fn put(&self, _key: &str, _entry: CacheWrite) -> Result<Duration> {
        Err(anyhow!("Intentional failure for testing"))
    }

    async fn put_raw(&self, _key: &str, _entry: Bytes) -> Result<Duration> {
        Err(anyhow!("Intentional failure for testing"))
    }

    async fn check(&self) -> Result<CacheMode> {
        Ok(CacheMode::ReadWrite) // It's RW but fails on put
    }

    fn location(&self) -> String {
        "FailingStorage".to_string()
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        PreprocessorCacheModeConfig::default()
    }

    async fn get_preprocessor_cache_entry(
        &self,
        _key: &str,
    ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
        Err(anyhow!("Intentional failure for testing"))
    }

    async fn put_preprocessor_cache_entry(
        &self,
        _key: &str,
        _entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        Err(anyhow!("Intentional failure for testing"))
    }
}

#[test]
fn test_put_mode_ignore() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // All levels fail with actual errors
    let cache_l0 = Arc::new(FailingStorage);
    let cache_l1 = Arc::new(FailingStorage);

    let storage = MultiLevelStorage::with_write_error_policy(
        vec![cache_l0 as Arc<dyn Storage>, cache_l1 as Arc<dyn Storage>],
        WriteErrorPolicy::Ignore,
    );

    runtime.block_on(async {
        let entry = CacheWrite::new();
        let result = storage.put("test_key", entry).await;

        assert!(
            result.is_ok(),
            "WriteErrorPolicy::Ignore should never fail, even when all levels error"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_put_mode_l0_fails_on_error() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // L0 fails with actual error, L1 succeeds
    let cache_l0 = Arc::new(FailingStorage);
    let cache_l1 = Arc::new(InMemoryStorage::new());

    let storage = MultiLevelStorage::with_write_error_policy(
        vec![cache_l0 as Arc<dyn Storage>, cache_l1 as Arc<dyn Storage>],
        WriteErrorPolicy::L0,
    );

    runtime.block_on(async {
        let entry = CacheWrite::new();
        let result = storage.put("test_key", entry).await;

        let err_msg = match result {
            Ok(_) => {
                return Err(anyhow!(
                    "WriteErrorPolicy::L0 unexpectedly succeeded when L0 write failed"
                ));
            }
            Err(error) => error.to_string(),
        };
        assert!(
            err_msg.contains("Intentional") || err_msg.contains("put_raw not implemented"),
            "Expected failure message, got: {err_msg}"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_put_mode_l0_succeeds_if_l0_ok() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // L0 succeeds, L1 fails (shouldn't matter in L0 mode)
    let cache_l0 = Arc::new(InMemoryStorage::new());
    let cache_l1 = Arc::new(FailingStorage);

    let storage = MultiLevelStorage::with_write_error_policy(
        vec![cache_l0 as Arc<dyn Storage>, cache_l1 as Arc<dyn Storage>],
        WriteErrorPolicy::L0,
    );

    runtime.block_on(async {
        let entry = CacheWrite::new();
        let result = storage.put("test_key", entry).await;

        assert!(
            result.is_ok(),
            "WriteErrorPolicy::L0 should succeed when L0 succeeds, even if L1+ fails"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_put_mode_all_fails_on_any_error() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // L0 succeeds, L1 fails
    let cache_l0 = Arc::new(InMemoryStorage::new());
    let cache_l1 = Arc::new(FailingStorage);

    let storage = MultiLevelStorage::with_write_error_policy(
        vec![cache_l0 as Arc<dyn Storage>, cache_l1 as Arc<dyn Storage>],
        WriteErrorPolicy::All,
    );

    runtime.block_on(async {
        let entry = CacheWrite::new();
        let result = storage.put("test_key", entry).await;

        // Give background L1 task time to complete and report failure
        sleep(Duration::from_millis(100)).await;

        assert!(
            result.is_err(),
            "WriteErrorPolicy::All should fail when any RW level fails"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_put_mode_all_succeeds_when_all_ok() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // Both levels succeed
    let cache_l0 = Arc::new(InMemoryStorage::new());
    let cache_l1 = Arc::new(InMemoryStorage::new());

    let storage = MultiLevelStorage::with_write_error_policy(
        vec![
            cache_l0.clone() as Arc<dyn Storage>,
            cache_l1.clone() as Arc<dyn Storage>,
        ],
        WriteErrorPolicy::All,
    );

    runtime.block_on(async {
        let entry = CacheWrite::new();
        let result = storage.put("test_key", entry).await;

        // Give background tasks time to complete
        sleep(Duration::from_millis(100)).await;

        assert!(
            result.is_ok(),
            "WriteErrorPolicy::All should succeed when all levels succeed"
        );

        // Verify both levels have the data
        assert!(matches!(cache_l0.get("test_key").await?, Cache::Hit(_)));
        assert!(matches!(cache_l1.get("test_key").await?, Cache::Hit(_)));
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_put_mode_all_skips_readonly() -> Result<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // L0 writable, L1 read-only (should be skipped), L2 writable
    let cache_l0 = Arc::new(InMemoryStorage::new());
    let cache_l1 = Arc::new(ReadOnlyStorage(Arc::new(InMemoryStorage::new())));
    let cache_l2 = Arc::new(InMemoryStorage::new());

    let storage = MultiLevelStorage::with_write_error_policy(
        vec![
            cache_l0.clone() as Arc<dyn Storage>,
            cache_l1 as Arc<dyn Storage>,
            cache_l2.clone() as Arc<dyn Storage>,
        ],
        WriteErrorPolicy::All,
    );

    runtime.block_on(async {
        let entry = CacheWrite::new();
        let result = storage.put("test_key", entry).await;

        // Give background tasks time to complete
        sleep(Duration::from_millis(100)).await;

        assert!(
            result.is_ok(),
            "WriteErrorPolicy::All should succeed when read-only levels are skipped"
        );

        // Verify writable levels have the data
        assert!(matches!(cache_l0.get("test_key").await?, Cache::Hit(_)));
        assert!(matches!(cache_l2.get("test_key").await?, Cache::Hit(_)));
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

// A Storage that does NOT override get_raw/put_raw, so it inherits the
// default no-op implementations.  Used to verify that MultiLevelStorage
// correctly skips levels that don't support raw access.
struct NoRawStorage {
    inner: InMemoryStorage,
}

impl NoRawStorage {
    fn new() -> Self {
        Self {
            inner: InMemoryStorage::new(),
        }
    }
}

#[async_trait]
impl Storage for NoRawStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        self.inner.get(key).await
    }
    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        self.inner.put(key, entry).await
    }
    fn location(&self) -> String {
        "NoRaw".to_string()
    }
    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
    // get_raw and put_raw are NOT overridden — they inherit the default
    // no-op implementations from the Storage trait.
}

#[test]
fn test_multilevel_get_raw_finds_first_hit() -> Result<()> {
    // Verifies that MultiLevelStorage::get_raw iterates levels in order
    // and returns the bytes from the first level that has them.
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let l0 = Arc::new(InMemoryStorage::new()); // empty
    let l1 = Arc::new(InMemoryStorage::new()); // will hold the entry

    let storage = MultiLevelStorage::new(vec![
        l0.clone() as Arc<dyn Storage>,
        l1.clone() as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        l1.put("key", CacheWrite::default()).await?;

        // L0 has nothing — get_raw on L0 directly returns None.
        assert!(l0.get_raw("key").await?.is_none());

        // MultiLevelStorage::get_raw should skip L0 and find the entry at L1.
        let raw = storage.get_raw("key").await?;
        assert!(
            raw.is_some(),
            "expected a hit via MultiLevelStorage::get_raw"
        );

        // The bytes should be parseable as a valid cache entry.
        let bytes = raw.ok_or_else(|| anyhow::anyhow!("expected raw cache bytes"))?;
        assert!(
            CacheRead::from(std::io::Cursor::new(bytes.to_vec())).is_ok(),
            "get_raw bytes should be a valid zip archive"
        );

        // A key that exists in neither level should return None.
        assert!(storage.get_raw("missing").await?.is_none());
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_multilevel_get_raw_skips_levels_without_raw_support() -> Result<()> {
    // Verifies that MultiLevelStorage::get_raw gracefully skips a level
    // that inherits the default no-op get_raw (returns Ok(None)) and
    // continues to the next level.  This is the exact scenario that
    // motivated adding get_raw to MultiLevelStorage: without an explicit
    // implementation, calling get_raw on the MultiLevelStorage itself
    // would always return None even when data is present.
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let l0 = Arc::new(NoRawStorage::new()); // no get_raw support
    let l1 = Arc::new(InMemoryStorage::new()); // has get_raw support

    let storage = MultiLevelStorage::new(vec![
        l0.clone() as Arc<dyn Storage>,
        l1.clone() as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        // Put data at L1 (also via L0 which stores via its inner InMemoryStorage,
        // but L0::get_raw returns None so the multilevel must reach L1).
        l1.put("key", CacheWrite::default()).await?;

        // Confirm L0::get_raw truly returns None (the default).
        assert!(l0.get_raw("key").await?.is_none());

        // MultiLevelStorage::get_raw should fall through L0 and find the entry at L1.
        let raw = storage.get_raw("key").await?;
        assert!(
            raw.is_some(),
            "expected hit at L1 after skipping L0 (no raw support)"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn test_multilevel_put_raw_writes_to_all_levels() -> Result<()> {
    // Verifies that MultiLevelStorage::put_raw propagates the raw bytes
    // to every level, so a subsequent get_raw on any individual level
    // returns the same bytes.
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let l0 = Arc::new(InMemoryStorage::new());
    let l1 = Arc::new(InMemoryStorage::new());

    let storage = MultiLevelStorage::new(vec![
        l0.clone() as Arc<dyn Storage>,
        l1.clone() as Arc<dyn Storage>,
    ]);

    runtime.block_on(async {
        // Build raw bytes for a valid (empty) cache entry.
        let raw_bytes: Bytes = CacheWrite::default().finish()?.into();

        storage.put_raw("key", raw_bytes.clone()).await?;

        // Give background writes time to complete.
        sleep(Duration::from_millis(50)).await;

        // Both levels should now hold identical bytes.
        let from_l0 = l0.get_raw("key").await?;
        let from_l1 = l1.get_raw("key").await?;
        assert_eq!(
            from_l0.as_deref(),
            Some(raw_bytes.as_ref()),
            "L0 should have the raw bytes"
        );
        assert_eq!(
            from_l1.as_deref(),
            Some(raw_bytes.as_ref()),
            "L1 should have the raw bytes"
        );
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}
