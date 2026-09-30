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

use super::cache_io::{Cache, CacheMode, CacheRead, CacheWrite, ReadSeek};
#[cfg(feature = "azure")]
use crate::cache::azure::AzureBlobCache;
#[cfg(feature = "cos")]
use crate::cache::cos::COSCache;
use crate::cache::disk::DiskCache;
#[cfg(feature = "gcs")]
use crate::cache::gcs::GCSCache;
#[cfg(feature = "gha")]
use crate::cache::gha::GHACache;
#[cfg(feature = "memcached")]
use crate::cache::memcached::MemcachedCache;
use crate::cache::multilevel::{MultiLevelStats, MultiLevelStorage};
#[cfg(feature = "oss")]
use crate::cache::oss::OSSCache;
#[cfg(feature = "redis")]
use crate::cache::redis::RedisCache;
#[cfg(feature = "s3")]
use crate::cache::s3::S3Cache;
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
use crate::cache::utils::normalize_key;
#[cfg(feature = "webdav")]
use crate::cache::webdav::WebdavCache;
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
use crate::config::{self, CacheType};
use crate::config::{Config, PreprocessorCacheModeConfig};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

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
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::errors::{Result, anyhow, bail};

/// Result of [`Storage::get_path`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GetPathResult {
    /// Cache hit: the entry lives at this filesystem path.
    Found(PathBuf),
    /// Cache miss: the key is not in the cache.
    Miss,
    /// This backend does not support direct file access; use `get`/`get_raw` instead.
    Unsupported,
}

/// An interface to cache storage.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Get a cache entry by `key`.
    ///
    /// If an error occurs, this method should return a `Cache::Error`.
    /// If nothing fails but the entry is not found in the cache,
    /// it should return a `Cache::Miss`.
    /// If the entry is successfully found in the cache, it should
    /// return a `Cache::Hit`.
    async fn get(&self, key: &str) -> Result<Cache>;

    /// Get a parsed cache entry and, when supported, the same entry's raw bytes.
    ///
    /// Multi-level caches use the raw bytes to backfill faster levels. The
    /// default preserves compatibility with existing backends by retaining
    /// the historical second `get_raw()` call; raw-capable backends can
    /// override this to avoid reading a hit twice.
    async fn get_with_raw(&self, key: &str) -> Result<(Cache, Option<Bytes>)> {
        let cache = self.get(key).await?;
        let raw = if matches!(&cache, Cache::Hit(_)) {
            match self.get_raw(key).await {
                Ok(raw) => raw,
                Err(error) => {
                    debug!("Failed to get raw bytes for cache backfill: {error}");
                    None
                }
            }
        } else {
            None
        };
        Ok((cache, raw))
    }

    /// Put `entry` in the cache under `key`.
    ///
    /// Returns a `Future` that will provide the result or error when the put is
    /// finished.
    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration>;

    /// Get raw serialized cache entry bytes by `key` (for multi-level backfill).
    /// Returns `None` if the entry is not found, or if the implementation doesn't support raw access.
    /// This is used by multi-level caches to backfill faster levels.
    async fn get_raw(&self, _key: &str) -> Result<Option<Bytes>> {
        Ok(None)
    }

    /// Check whether a cache entry exists without fetching its object bytes.
    ///
    /// Returns Ok(None) when the backend has no cheap existence probe. Multi-level
    /// caches use this to repair slower levels from a faster-level hit without
    /// turning the repair check into a full remote cache read.
    async fn entry_exists(&self, _key: &str) -> Result<Option<bool>> {
        Ok(None)
    }

    /// Put raw serialized cache entry bytes under `key` (for multi-level backfill).
    /// Returns an error if the implementation doesn't support raw access.
    /// This is used by multi-level caches to backfill faster levels.
    async fn put_raw(&self, _key: &str, _data: Bytes) -> Result<Duration> {
        Err(anyhow!("put_raw not implemented for this storage backend"))
    }

    /// Check the cache capability.
    ///
    /// - `Ok(CacheMode::ReadOnly)` means cache can only be used to `get`
    ///   cache.
    /// - `Ok(CacheMode::ReadWrite)` means cache can do both `get` and `put`.
    /// - `Err(err)` means cache is not setup correctly or not match with
    ///   users input (for example, user try to use `ReadWrite` but cache
    ///   is `ReadOnly`).
    ///
    /// We will provide a default implementation which returns
    /// `Ok(CacheMode::ReadWrite)` for service that doesn't
    /// support check yet.
    async fn check(&self) -> Result<CacheMode> {
        Ok(CacheMode::ReadWrite)
    }

    /// Get the storage location.
    fn location(&self) -> String;

    /// Get the cache backend type name (e.g., "disk", "redis", "s3").
    /// Used for statistics and display purposes.
    fn cache_type_name(&self) -> &'static str {
        "unknown"
    }

    /// Get the current storage usage, if applicable.
    async fn current_size(&self) -> Result<Option<u64>>;

    /// Get the maximum storage size, if applicable.
    async fn max_size(&self) -> Result<Option<u64>>;

    /// Get multi-level cache statistics, if this is a multi-level storage.
    fn multilevel_stats(&self) -> Option<MultiLevelStats> {
        None
    }

    /// Return the config for preprocessor cache mode if applicable
    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        // Enable by default, only in local mode
        PreprocessorCacheModeConfig::default()
    }
    /// Return the base directories for path normalization if configured
    fn basedirs(&self) -> &[Vec<u8>] {
        &[]
    }
    /// Return the filesystem path of the cached entry for `key`.
    /// Default impl returns [`GetPathResult::Unsupported`].
    async fn get_path(&self, _key: &str) -> GetPathResult {
        GetPathResult::Unsupported
    }

    /// Return the preprocessor cache entry for a given preprocessor key,
    /// if it exists.
    /// Only applicable when using preprocessor cache mode.
    async fn get_preprocessor_cache_entry(
        &self,
        _key: &str,
    ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
        Ok(None)
    }
    /// Insert a preprocessor cache entry at the given preprocessor key,
    /// overwriting the entry if it exists.
    /// Only applicable when using preprocessor cache mode.
    async fn put_preprocessor_cache_entry(
        &self,
        _key: &str,
        _preprocessor_cache_entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        Ok(())
    }
}

/// Wrapper for `opendal::Operator` that adds basedirs support
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
pub struct RemoteStorage {
    operator: opendal::Operator,
    basedirs: Vec<Vec<u8>>,
    rw_mode: CacheMode,
    skip_cache_check: bool,
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
impl RemoteStorage {
    #[must_use]
    pub const fn new(
        operator: opendal::Operator,
        basedirs: Vec<Vec<u8>>,
        rw_mode: CacheMode,
    ) -> Self {
        Self {
            operator,
            basedirs,
            rw_mode,
            skip_cache_check: false,
        }
    }

    #[must_use]
    pub const fn with_skip_cache_check(mut self, skip_cache_check: bool) -> Self {
        self.skip_cache_check = skip_cache_check;
        self
    }
}

/// Implement storage for operator.
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
#[async_trait]
impl Storage for RemoteStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        Ok(self.get_with_raw(key).await?.0)
    }

    async fn get_with_raw(&self, key: &str) -> Result<(Cache, Option<Bytes>)> {
        match self.operator.read(&normalize_key(key)).await {
            Ok(res) => {
                let data = res.to_bytes();
                let hit = CacheRead::from(io::Cursor::new(data.clone()))?;
                Ok((Cache::Hit(hit), Some(data)))
            }
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok((Cache::Miss, None)),
            Err(e) => {
                warn!("Got unexpected error: {e:?}");
                Ok((Cache::Miss, None))
            }
        }
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        trace!("RemoteStorage::put({key})");
        // Delegate to put_raw after serializing the entry
        let data = entry.finish()?;
        self.put_raw(key, data.into()).await
    }

    async fn check(&self) -> Result<CacheMode> {
        use opendal::ErrorKind;

        if self.skip_cache_check {
            debug!(
                "storage check skipped; using configured cache mode: {:?}",
                self.rw_mode
            );
            return Ok(self.rw_mode);
        }

        let path = ".sccache_check";

        // Read is required, return error directly if we can't read .
        match self.operator.read(path).await {
            Ok(_) => (),
            // Read not exist file with not found is ok.
            Err(err) if err.kind() == ErrorKind::NotFound => (),
            // Tricky Part.
            //
            // We tolerate rate limited here to make sccache keep running.
            // For the worse case, we will miss all the cache.
            //
            // In some super rare cases, user could configure storage in wrong
            // and hitting other services rate limit. There are few things we
            // can do, so we will print our the error here to make users know
            // about it.
            Err(err) if err.kind() == ErrorKind::RateLimited => {
                eprintln!("cache storage read check: {err:?}, but we decide to keep running");
            }
            Err(err) => bail!("cache storage failed to read: {err:?}"),
        }

        // No need to check write if we are in manually-set read-only mode
        if self.rw_mode == CacheMode::ReadOnly {
            let mode = CacheMode::ReadOnly;
            debug!("storage check result: {mode:?} (manually set)");
            return Ok(mode);
        }

        let can_write = match self.operator.write(path, "Hello, World!").await {
            Ok(_) => true,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => true,
            // Tolerate all other write errors because we can do read at least.
            Err(err) => {
                eprintln!("storage write check failed: {err:?}");
                false
            }
        };

        let mode = if can_write {
            CacheMode::ReadWrite
        } else {
            CacheMode::ReadOnly
        };

        debug!("storage check result: {mode:?}");

        Ok(mode)
    }

    fn location(&self) -> String {
        let meta = self.operator.info();
        format!(
            "{}, name: {}, prefix: {}",
            meta.scheme(),
            meta.name(),
            meta.root()
        )
    }

    fn cache_type_name(&self) -> &'static str {
        // Use opendal's scheme as the cache type name
        // This returns "s3", "redis", "azure", "gcs", etc.
        self.operator.info().scheme()
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    fn basedirs(&self) -> &[Vec<u8>] {
        &self.basedirs
    }

    /// Get raw bytes from remote storage for multi-level backfill.
    ///
    /// Unlike `get()` which parses bytes into `CacheRead` (a `ZipArchive<Box<dyn ReadSeek>>`),
    /// this returns the raw bytes without parsing. `CacheRead` is a one-way transformation —
    /// there is no way to extract the original bytes back from the parsed ZIP archive.
    /// For backfill we need the raw bytes to write directly to another cache level.
    async fn entry_exists(&self, key: &str) -> Result<Option<bool>> {
        trace!("opendal::Operator::entry_exists({key})");
        match self.operator.stat(&normalize_key(key)).await {
            Ok(_) => Ok(Some(true)),
            Err(error) if error.kind() == opendal::ErrorKind::NotFound => Ok(Some(false)),
            Err(error) => Err(anyhow!("Failed to stat cache entry {key}: {error:?}")),
        }
    }

    async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
        trace!("opendal::Operator::get_raw({key})");
        match self.operator.read(&normalize_key(key)).await {
            Ok(res) => {
                let data = res.to_bytes();
                trace!(
                    "opendal::Operator::get_raw({key}): Found {} bytes",
                    data.len()
                );
                Ok(Some(data))
            }
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => {
                trace!("opendal::Operator::get_raw({key}): NotFound");
                Ok(None)
            }
            Err(e) => {
                warn!("opendal::Operator::get_raw({key}): Error: {e:?}");
                // Return error instead of silently returning None
                Err(anyhow!("Failed to read raw bytes: {e:?}"))
            }
        }
    }

    /// Write raw bytes to remote storage for multi-level backfill.
    ///
    /// Unlike `put()` which takes a `CacheWrite` and serializes it, this writes
    /// pre-serialized bytes directly. Paired with `get_raw()` for efficient
    /// level-to-level data transfer without a deserialize/reserialize round-trip.
    async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
        trace!("opendal::Operator::put_raw({key}, {} bytes)", data.len());
        let start = std::time::Instant::now();

        if self.rw_mode == CacheMode::ReadOnly {
            bail!("storage is read-only");
        }

        self.operator.write(&normalize_key(key), data).await?;

        Ok(start.elapsed())
    }
}

#[cfg(feature = "azure")]
fn build_azure_operator(c: &config::AzureCacheConfig) -> Result<opendal::Operator> {
    AzureBlobCache::build(
        c.connection_string.as_deref(),
        &c.container,
        &c.key_prefix,
        c.storage_account.as_deref(),
        c.endpoint.as_deref(),
    )
    .map_err(|err| anyhow!("create azure cache failed: {err:?}"))
}

#[cfg(feature = "gcs")]
fn build_gcs_operator(c: &config::GCSCacheConfig) -> Result<opendal::Operator> {
    GCSCache::build(
        &c.bucket,
        &c.key_prefix,
        c.cred_path.as_deref(),
        c.service_account.as_deref(),
        c.rw_mode.into(),
        c.credential_url.as_deref(),
    )
    .map_err(|err| anyhow!("create gcs cache failed: {err:?}"))
}

#[cfg(feature = "gha")]
fn build_gha_operator(c: &config::GHACacheConfig) -> Result<opendal::Operator> {
    GHACache::build(&c.version).map_err(|err| anyhow!("create gha cache failed: {err:?}"))
}

#[cfg(feature = "memcached")]
fn build_memcached_operator(c: &config::MemcachedCacheConfig) -> Result<opendal::Operator> {
    MemcachedCache::build(
        &c.url,
        c.username.as_deref(),
        c.password.as_deref(),
        &c.key_prefix,
        c.expiration,
    )
    .map_err(|err| anyhow!("create memcached cache failed: {err:?}"))
}

#[cfg(feature = "redis")]
fn build_redis_operator(c: &config::RedisCacheConfig) -> Result<opendal::Operator> {
    let operator = match (&c.endpoint, &c.cluster_endpoints, &c.url) {
        (Some(url), None, None) => {
            debug!("Init redis single-node cache with url {url}");
            RedisCache::build_single(
                url,
                c.username.as_deref(),
                c.password.as_deref(),
                c.db,
                &c.key_prefix,
                c.ttl,
            )
        }
        (None, Some(urls), None) => {
            debug!("Init redis cluster cache with urls {urls}");
            RedisCache::build_cluster(
                urls,
                c.username.as_deref(),
                c.password.as_deref(),
                c.db,
                &c.key_prefix,
                c.ttl,
            )
        }
        (None, None, Some(url)) => {
            warn!("Init redis single-node cache from deprecated API with url {url}");
            if c.username.is_some()
                || c.password.is_some()
                || c.db != crate::config::DEFAULT_REDIS_DB
            {
                bail!(
                    "username, password and db have no effect when url is set; use endpoint or cluster_endpoints"
                );
            }
            RedisCache::build_from_url(url, &c.key_prefix, c.ttl)
        }
        _ => bail!("exactly one of endpoint, cluster_endpoints, or url must be set"),
    };
    operator.map_err(|err| anyhow!("create redis cache failed: {err:?}"))
}

#[cfg(feature = "s3")]
fn build_s3_operator(c: &config::S3CacheConfig) -> Result<opendal::Operator> {
    S3Cache::new(c.bucket.clone(), c.key_prefix.clone(), c.no_credentials)
        .with_region(c.region.clone())
        .with_endpoint(c.endpoint.clone())
        .with_use_ssl(c.use_ssl)
        .with_server_side_encryption(c.server_side_encryption)
        .with_server_side_encryption_aws_kms(c.server_side_encryption_aws_kms)
        .with_server_side_encryption_kms_key_id(c.server_side_encryption_kms_key_id.clone())
        .with_enable_virtual_host_style(c.enable_virtual_host_style)
        .build()
        .map_err(|err| anyhow!("create s3 cache failed: {err:?}"))
}

#[cfg(feature = "webdav")]
fn build_webdav_operator(c: &config::WebdavCacheConfig) -> Result<opendal::Operator> {
    WebdavCache::build(
        &c.endpoint,
        &c.key_prefix,
        c.username.as_deref(),
        c.password.as_deref(),
        c.token.as_deref(),
        c.disable_create_dir,
    )
    .map_err(|err| anyhow!("create webdav cache failed: {err:?}"))
}

#[cfg(feature = "oss")]
fn build_oss_operator(c: &config::OSSCacheConfig) -> Result<opendal::Operator> {
    OSSCache::build(
        &c.bucket,
        &c.key_prefix,
        c.endpoint.as_deref(),
        c.no_credentials,
    )
    .map_err(|err| anyhow!("create oss cache failed: {err:?}"))
}

#[cfg(feature = "cos")]
fn build_cos_operator(c: &config::COSCacheConfig) -> Result<opendal::Operator> {
    COSCache::build(&c.bucket, &c.key_prefix, c.endpoint.as_deref())
        .map_err(|err| anyhow!("create cos cache failed: {err:?}"))
}

/// Build a single cache storage from CacheType.
///
/// # Errors
///
/// Returns an error if the selected backend is unavailable in this build, is
/// misconfigured, or cannot initialize its storage operator.
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
pub fn build_single_cache(
    cache_type: &CacheType,
    basedirs: &[Vec<u8>],
    _pool: &tokio::runtime::Handle,
    skip_cache_check: bool,
) -> Result<Arc<dyn Storage>> {
    let (operator, rw_mode) = match cache_type {
        #[cfg(feature = "azure")]
        CacheType::Azure(c) => {
            debug!(
                "Init azure cache with container {}, key_prefix {}",
                c.container, c.key_prefix
            );
            (build_azure_operator(c)?, c.rw_mode.into())
        }
        #[cfg(not(feature = "azure"))]
        CacheType::Azure(_) => bail!("Azure cache support is not enabled"),
        #[cfg(feature = "gcs")]
        CacheType::GCS(c) => {
            debug!(
                "Init gcs cache with bucket {}, key_prefix {}",
                c.bucket, c.key_prefix
            );
            (build_gcs_operator(c)?, c.rw_mode.into())
        }
        #[cfg(not(feature = "gcs"))]
        CacheType::GCS(_) => bail!("GCS cache support is not enabled"),
        #[cfg(feature = "gha")]
        CacheType::GHA(c) => {
            debug!("Init gha cache with version {}", c.version);
            (build_gha_operator(c)?, c.rw_mode.into())
        }
        #[cfg(not(feature = "gha"))]
        CacheType::GHA(_) => bail!("GitHub Actions cache support is not enabled"),
        #[cfg(feature = "memcached")]
        CacheType::Memcached(c) => {
            debug!("Init memcached cache with url {}", c.url);
            (build_memcached_operator(c)?, c.rw_mode.into())
        }
        #[cfg(not(feature = "memcached"))]
        CacheType::Memcached(_) => bail!("Memcached cache support is not enabled"),
        #[cfg(feature = "redis")]
        CacheType::Redis(c) => (build_redis_operator(c)?, c.rw_mode.into()),
        #[cfg(not(feature = "redis"))]
        CacheType::Redis(_) => bail!("Redis cache support is not enabled"),
        #[cfg(feature = "s3")]
        CacheType::S3(c) => {
            debug!(
                "Init s3 cache with bucket {}, endpoint {}",
                c.bucket,
                c.endpoint.as_deref().unwrap_or("<default>")
            );
            (build_s3_operator(c)?, c.rw_mode.into())
        }
        #[cfg(not(feature = "s3"))]
        CacheType::S3(_) => bail!("S3 cache support is not enabled"),
        #[cfg(feature = "webdav")]
        CacheType::Webdav(c) => {
            debug!("Init webdav cache with endpoint {}", c.endpoint);
            (build_webdav_operator(c)?, c.rw_mode.into())
        }
        #[cfg(not(feature = "webdav"))]
        CacheType::Webdav(_) => bail!("WebDAV cache support is not enabled"),
        #[cfg(feature = "oss")]
        CacheType::OSS(c) => {
            debug!(
                "Init oss cache with bucket {}, endpoint {}",
                c.bucket,
                c.endpoint.as_deref().unwrap_or("<default>")
            );
            (build_oss_operator(c)?, c.rw_mode.into())
        }
        #[cfg(not(feature = "oss"))]
        CacheType::OSS(_) => bail!("OSS cache support is not enabled"),
        #[cfg(feature = "cos")]
        CacheType::COS(c) => {
            debug!(
                "Init cos cache with bucket {}, endpoint {}",
                c.bucket,
                c.endpoint.as_deref().unwrap_or("<default>")
            );
            (build_cos_operator(c)?, c.rw_mode.into())
        }
        #[cfg(not(feature = "cos"))]
        CacheType::COS(_) => bail!("COS cache support is not enabled"),
    };

    let storage = RemoteStorage::new(operator, basedirs.to_vec(), rw_mode)
        .with_skip_cache_check(skip_cache_check);
    Ok(Arc::new(storage))
}

/// Get a suitable `Storage` implementation from configuration.
/// Supports both single-cache (backward compatible) and multi-level cache configurations.
///
/// # Errors
///
/// Returns an error if a configured cache backend is invalid or cannot be initialized.
pub fn storage_from_config(
    config: &Config,
    pool: &tokio::runtime::Handle,
) -> Result<Arc<dyn Storage>> {
    // Check for multi-level cache configuration
    if let Some(multilevel) = MultiLevelStorage::from_config(config, pool)? {
        return Ok(Arc::new(multilevel));
    }

    // Single cache or fallback to disk (backward compatible path)
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
    if let Some(cache_type) = &config.cache {
        debug!("Configuring single cache from CacheType");
        return build_single_cache(cache_type, &config.basedirs, pool, config.skip_cache_check);
    }

    // No remote cache configured - use disk cache only
    let (dir, size) = (&config.fallback_cache.dir, config.fallback_cache.size);
    let preprocessor_cache_mode_config = config.fallback_cache.preprocessor_cache_mode;
    let rw_mode = config.fallback_cache.rw_mode.into();
    debug!("Init disk cache with dir {}, size {size}", dir.display());
    Ok(Arc::new(DiskCache::new(
        dir,
        size,
        pool,
        preprocessor_cache_mode_config,
        rw_mode,
        config.basedirs.clone(),
    )))
}

#[cfg(test)]
mod test {
    use super::{CacheMode, CacheWrite, RemoteStorage, storage_from_config};
    use crate::compiler::PreprocessorCacheEntry;
    use crate::config::{self, CacheModeConfig, CacheType, Config};
    use crate::errors::{Result, anyhow};
    use fs_err as fs;

    #[test]
    fn test_read_write_mode_local() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()?;

        let mut config = Config {
            cache: None,
            ..Default::default()
        };

        let tempdir = tempfile::Builder::new()
            .prefix("sccache_test_rust_cargo")
            .tempdir()?;
        let cache_dir = tempdir.path().join("cache");
        fs::create_dir(&cache_dir)?;

        config.fallback_cache.dir = cache_dir;
        config.fallback_cache.rw_mode = CacheModeConfig::ReadWrite;

        {
            let cache = storage_from_config(&config, runtime.handle())?;
            runtime.block_on(async move {
                cache.put("test1", CacheWrite::default()).await?;
                cache
                    .put_preprocessor_cache_entry("test1", PreprocessorCacheEntry::default())
                    .await?;
                Ok::<(), anyhow::Error>(())
            })?;
        }

        config.fallback_cache.rw_mode = CacheModeConfig::ReadOnly;

        {
            let cache = storage_from_config(&config, runtime.handle())?;
            runtime.block_on(async move {
                match cache.put("test1", CacheWrite::default()).await {
                    Ok(_) => {
                        return Err(anyhow!("read-only cache unexpectedly accepted a cache put"));
                    }
                    Err(error) => {
                        assert_eq!(error.to_string(), "Cannot write to a read-only cache");
                    }
                }
                match cache
                    .put_preprocessor_cache_entry("test1", PreprocessorCacheEntry::default())
                    .await
                {
                    Ok(()) => {
                        return Err(anyhow!(
                            "read-only cache unexpectedly accepted a preprocessor-cache put"
                        ));
                    }
                    Err(error) => {
                        assert_eq!(error.to_string(), "Cannot write to a read-only cache");
                    }
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }

        Ok(())
    }

    #[test]
    #[cfg(feature = "s3")]
    fn test_operator_storage_s3_with_basedirs() -> Result<()> {
        let operator = crate::cache::s3::S3Cache::new(
            "test-bucket".to_string(),
            "test-prefix".to_string(),
            true,
        )
        .with_region(Some("us-east-1".to_string()))
        .build()?;

        let basedirs = vec![b"/home/user/project".to_vec(), b"/opt/build".to_vec()];
        let storage = RemoteStorage::new(operator, basedirs.clone(), CacheMode::ReadWrite);

        assert_eq!(storage.basedirs(), basedirs.as_slice());
        assert_eq!(storage.basedirs().len(), 2);
        assert_eq!(storage.basedirs()[0], b"/home/user/project".to_vec());
        assert_eq!(storage.basedirs()[1], b"/opt/build".to_vec());
        Ok(())
    }

    #[test]
    #[cfg(feature = "s3")]
    fn test_skip_remote_cache_check_uses_configured_mode() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        for (configured_mode, expected_mode) in [
            (CacheModeConfig::ReadOnly, CacheMode::ReadOnly),
            (CacheModeConfig::ReadWrite, CacheMode::ReadWrite),
        ] {
            let cache_config = config::S3CacheConfig {
                bucket: "test-bucket".to_owned(),
                region: Some("us-east-1".to_owned()),
                key_prefix: String::new(),
                no_credentials: true,
                endpoint: Some("http://127.0.0.1:1".to_owned()),
                use_ssl: Some(false),
                server_side_encryption: None,
                server_side_encryption_aws_kms: None,
                server_side_encryption_kms_key_id: None,
                enable_virtual_host_style: None,
                rw_mode: configured_mode,
            };
            let single_cache_config = Config {
                cache: Some(CacheType::S3(cache_config.clone())),
                skip_cache_check: true,
                ..Default::default()
            };

            let storage = storage_from_config(&single_cache_config, runtime.handle())?;
            assert_eq!(runtime.block_on(storage.check())?, expected_mode);

            let multilevel_config = Config {
                cache_configs: config::CacheConfigs {
                    s3: Some(cache_config),
                    multilevel: Some(config::MultiLevelConfig {
                        chain: vec!["s3".to_owned()],
                        write_error_policy: config::WriteErrorPolicy::default(),
                    }),
                    ..Default::default()
                },
                skip_cache_check: true,
                ..Default::default()
            };

            let storage = storage_from_config(&multilevel_config, runtime.handle())?;
            assert_eq!(runtime.block_on(storage.check())?, expected_mode);
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "redis")]
    fn test_operator_storage_redis_with_basedirs() -> Result<()> {
        let operator = crate::cache::redis::RedisCache::build_single(
            "redis://localhost:6379",
            None,
            None,
            0,
            "test-prefix",
            0,
        )?;

        let basedirs = vec![b"/workspace".to_vec()];
        let storage = RemoteStorage::new(operator, basedirs.clone(), CacheMode::ReadWrite);

        assert_eq!(storage.basedirs(), basedirs.as_slice());
        assert_eq!(storage.basedirs().len(), 1);
        Ok(())
    }

    #[test]
    #[cfg(feature = "redis")]
    fn test_operator_storage_redis_with_read_only() -> Result<()> {
        use crate::test::utils::Waiter;

        let operator = crate::cache::redis::RedisCache::build_single(
            "redis://localhost:6379",
            None,
            None,
            0,
            "test-prefix",
            0,
        )?;

        let storage = RemoteStorage::new(operator, vec![], CacheMode::ReadOnly);
        match storage.put("test", CacheWrite::default()).wait() {
            Ok(_) => Err(anyhow!(
                "read-only Redis cache unexpectedly accepted a cache put"
            )),
            Err(error) => {
                assert_eq!(error.to_string(), "storage is read-only");
                Ok(())
            }
        }
    }
}
