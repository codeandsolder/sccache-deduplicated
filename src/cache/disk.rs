// Copyright 2016 Mozilla Foundation
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

use crate::cache::{Cache, CacheMode, CacheRead, CacheWrite, Storage};
use crate::compiler::PreprocessorCacheEntry;
use crate::lru_disk_cache::ReadSeek;
use async_trait::async_trait;
use bytes::Bytes;
use std::ffi::OsStr;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::errors::{Result, anyhow};

use super::lazy_disk_cache::LazyDiskCache;
use super::utils::normalize_key;
use crate::config::PreprocessorCacheModeConfig;

/// A cache that stores entries at local disk paths.
pub struct DiskCache {
    /// `LruDiskCache` does all the real work here.
    lru: Arc<Mutex<LazyDiskCache>>,
    /// Thread pool to execute disk I/O
    pool: tokio::runtime::Handle,
    preprocessor_cache_mode_config: PreprocessorCacheModeConfig,
    preprocessor_cache: Arc<Mutex<LazyDiskCache>>,
    rw_mode: CacheMode,
    basedirs: Vec<Vec<u8>>,
}

impl DiskCache {
    /// Create a new `DiskCache` rooted at `root`, with `max_size` as the maximum cache size on-disk, in bytes.
    pub fn new<T: AsRef<OsStr>>(
        root: T,
        max_size: u64,
        pool: &tokio::runtime::Handle,
        preprocessor_cache_mode_config: PreprocessorCacheModeConfig,
        rw_mode: CacheMode,
        basedirs: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            lru: Arc::new(Mutex::new(LazyDiskCache::Uninit {
                root: root.as_ref().to_os_string(),
                max_size,
            })),
            pool: pool.clone(),
            preprocessor_cache_mode_config,
            preprocessor_cache: Arc::new(Mutex::new(LazyDiskCache::Uninit {
                root: Path::new(root.as_ref())
                    .join("preprocessor")
                    .into_os_string(),
                max_size,
            })),
            rw_mode,
            basedirs,
        }
    }
}

/// Make a path to the cache entry with key `key`.
fn make_key_path(key: &str) -> PathBuf {
    Path::new(&key[0..1]).join(&key[1..2]).join(key)
}

/// Preserve the remote preprocessor key layout, using native separators on disk.
fn preprocessor_key_path(key: &str) -> PathBuf {
    normalize_key(key).split('/').collect()
}

#[async_trait]
impl Storage for DiskCache {
    async fn get(&self, key: &str) -> Result<Cache> {
        trace!("DiskCache::get({key})");
        let path = make_key_path(key);
        let lru = self.lru.clone();
        let mode = self.rw_mode;

        self.pool
            .spawn_blocking(move || {
                let file = lru
                    .lock()
                    .map_err(|_| anyhow!("disk cache mutex poisoned"))?
                    .open(&path, mode)?;
                file.map_or(Ok(Cache::Miss), |file| {
                    CacheRead::from(file).map(Cache::Hit)
                })
            })
            .await?
    }

    async fn get_with_raw(&self, key: &str) -> Result<(Cache, Option<Bytes>)> {
        match self.get_raw(key).await? {
            Some(data) => {
                let hit = CacheRead::from(std::io::Cursor::new(data.clone()))?;
                Ok((Cache::Hit(hit), Some(data)))
            }
            None => Ok((Cache::Miss, None)),
        }
    }

    async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
        trace!("DiskCache::get_raw({key})");
        let path = make_key_path(key);
        let lru = self.lru.clone();
        let mode = self.rw_mode;

        self.pool
            .spawn_blocking(move || {
                let file = lru
                    .lock()
                    .map_err(|_| anyhow!("disk cache mutex poisoned"))?
                    .open(&path, mode)?;
                let Some(mut file) = file else {
                    return Ok(None);
                };
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                Ok(Some(data.into()))
            })
            .await?
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        trace!("DiskCache::put({key})");
        // Delegate to put_raw after serializing the entry
        let data = entry.finish()?;
        self.put_raw(key, data.into()).await
    }

    async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
        trace!("DiskCache::put_raw({key}, {} bytes)", data.len());

        if self.rw_mode == CacheMode::ReadOnly {
            return Err(anyhow!("Cannot write to a read-only cache"));
        }

        let lru = self.lru.clone();
        let key = make_key_path(key);

        self.pool
            .spawn_blocking(move || {
                let start = Instant::now();
                let mut f = {
                    let mut guard = lru
                        .lock()
                        .map_err(|_| anyhow!("disk cache mutex poisoned"))?;
                    guard.get_or_init()?.prepare_add(key, data.len() as u64)?
                };
                f.as_file_mut().write_all(&data)?;
                {
                    let mut guard = lru
                        .lock()
                        .map_err(|_| anyhow!("disk cache mutex poisoned"))?;
                    guard.get_or_init()?.commit(f)?;
                }
                Ok(start.elapsed())
            })
            .await?
    }

    async fn check(&self) -> Result<CacheMode> {
        Ok(self.rw_mode)
    }

    fn location(&self) -> String {
        let path = {
            let guard = self
                .lru
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.path().to_owned()
        };
        format!("Local disk: {}", path.display())
    }

    fn cache_type_name(&self) -> &'static str {
        "disk"
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        let mut guard = self
            .lru
            .lock()
            .map_err(|_| anyhow!("disk cache mutex poisoned"))?;
        Ok(guard.get().map(|cache| cache.size()))
    }
    async fn max_size(&self) -> Result<Option<u64>> {
        let guard = self
            .lru
            .lock()
            .map_err(|_| anyhow!("disk cache mutex poisoned"))?;
        Ok(Some(guard.capacity()))
    }
    async fn tier_observations(
        &self,
        _allow_refresh: bool,
    ) -> Vec<crate::cache::CacheTierObservation> {
        use crate::build_runtime::analytics::TierCacheReport;
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut observation = crate::cache::CacheTierObservation::observe(self).await;
        let lru = self.lru.clone();
        let report = self
            .pool
            .spawn_blocking(move || {
                let entries = lru.lock().ok()?.get()?.analytics_entries();
                let now = SystemTime::now();
                let mut report = TierCacheReport {
                    sampled_at: now.duration_since(UNIX_EPOCH).ok()?.as_secs(),
                    ..Default::default()
                };
                for (path, size) in entries {
                    let age = std::fs::metadata(path)
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .map(|time| now.duration_since(time).unwrap_or_default().as_secs());
                    report.distribution.record(size, None, 1, None, age);
                }
                Some(report)
            })
            .await;
        observation.report = report.ok().flatten();
        vec![observation]
    }

    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        self.preprocessor_cache_mode_config
    }
    fn basedirs(&self) -> &[Vec<u8>] {
        &self.basedirs
    }
    async fn get_preprocessor_cache_entry(&self, key: &str) -> Result<Option<Box<dyn ReadSeek>>> {
        let key = preprocessor_key_path(key);
        let cache = self.preprocessor_cache.clone();
        let mode = self.rw_mode;
        self.pool
            .spawn_blocking(move || {
                cache
                    .lock()
                    .map_err(|_| anyhow!("preprocessor cache mutex poisoned"))?
                    .open(&key, mode)
            })
            .await?
    }
    async fn put_preprocessor_cache_entry(
        &self,
        key: &str,
        preprocessor_cache_entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        if self.rw_mode == CacheMode::ReadOnly {
            return Err(anyhow!("Cannot write to a read-only cache"));
        }

        let key = preprocessor_key_path(key);
        let mut f = {
            let mut guard = self
                .preprocessor_cache
                .lock()
                .map_err(|_| anyhow!("preprocessor cache mutex poisoned"))?;
            guard.get_or_init()?.prepare_add(key, 0)?
        };
        preprocessor_cache_entry.serialize_to(BufWriter::new(f.as_file_mut()))?;
        {
            let mut guard = self
                .preprocessor_cache
                .lock()
                .map_err(|_| anyhow!("preprocessor cache mutex poisoned"))?;
            guard.get_or_init()?.commit(f)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0123456789abcdef";

    fn disk_cache(
        root: &Path,
        runtime: &tokio::runtime::Runtime,
        mode: CacheMode,
        size: u64,
    ) -> DiskCache {
        DiskCache::new(
            root,
            size,
            runtime.handle(),
            PreprocessorCacheModeConfig::activated(),
            mode,
            vec![],
        )
    }

    #[test]
    fn read_only_disk_does_not_initialize_or_prune_the_cache() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("cache");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let reader = disk_cache(&root, &runtime, CacheMode::ReadOnly, 1);
            assert!(matches!(reader.get(KEY).await?, Cache::Miss));
            assert!(reader.get_raw(KEY).await?.is_none());
            assert!(reader.get_preprocessor_cache_entry(KEY).await?.is_none());
            assert!(!root.exists());

            let writer = disk_cache(&root, &runtime, CacheMode::ReadWrite, 1024 * 1024);
            writer.put(KEY, CacheWrite::new()).await?;
            writer
                .put_preprocessor_cache_entry(KEY, PreprocessorCacheEntry::new())
                .await?;
            drop(writer);
            let artifact = root.join(make_key_path(KEY));
            let preprocessor = root.join("preprocessor").join(preprocessor_key_path(KEY));
            let temporary = root.join(".sccachetmp_test");
            std::fs::write(&temporary, b"other process temporary file")?;
            let old = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
            for path in [&artifact, &preprocessor] {
                std::fs::File::options()
                    .write(true)
                    .open(path)?
                    .set_times(std::fs::FileTimes::new().set_modified(old))?;
            }
            assert!(matches!(reader.get(KEY).await?, Cache::Hit(_)));
            assert_eq!(
                reader.get_raw(KEY).await?.as_deref(),
                Some(std::fs::read(&artifact)?.as_slice())
            );
            let (hit, raw) = reader.get_with_raw(KEY).await?;
            assert!(matches!(hit, Cache::Hit(_)));
            assert!(raw.is_some());
            assert!(reader.get_preprocessor_cache_entry(KEY).await?.is_some());
            assert!(reader.put(KEY, CacheWrite::new()).await.is_err());
            assert!(
                reader
                    .put_preprocessor_cache_entry(KEY, PreprocessorCacheEntry::new())
                    .await
                    .is_err()
            );
            assert!(reader.current_size().await?.is_none());
            assert!(temporary.exists());
            for path in [&artifact, &preprocessor] {
                assert_eq!(std::fs::metadata(path)?.modified()?, old);
            }
            Ok(())
        })
    }

    #[test]
    fn preprocessor_entry_survives_reopening_disk_cache() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let writer = disk_cache(dir.path(), &runtime, CacheMode::ReadWrite, 1024 * 1024);
            writer
                .put_preprocessor_cache_entry(KEY, PreprocessorCacheEntry::new())
                .await?;
            drop(writer);
            let reader = disk_cache(dir.path(), &runtime, CacheMode::ReadWrite, 1024 * 1024);
            assert!(reader.get_preprocessor_cache_entry(KEY).await?.is_some());
            Ok(())
        })
    }

    #[test]
    fn test_disk_cache_type_name() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;

        let disk = DiskCache::new(
            tempdir.path(),
            1024 * 1024,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        );

        assert_eq!(disk.cache_type_name(), "disk");
        Ok(())
    }
}
