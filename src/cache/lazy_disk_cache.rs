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

use crate::cache::CacheMode;
use crate::errors::Result;
use crate::lru_disk_cache::{Error as LruError, LruDiskCache, ReadSeek};
use std::ffi::OsString;
use std::path::Path;

pub enum LazyDiskCache {
    Uninit { root: OsString, max_size: u64 },
    Init(LruDiskCache),
}

impl LazyDiskCache {
    /// Return the initialized disk cache, creating it on first use.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying disk cache cannot be initialized.
    pub fn get_or_init(&mut self) -> Result<&mut LruDiskCache> {
        match self {
            Self::Uninit { root, max_size } => {
                *self = Self::Init(LruDiskCache::new(&root, *max_size)?);
                self.get_or_init()
            }
            Self::Init(d) => Ok(d),
        }
    }

    /// Read-only storage is a direct filesystem reader. Do not initialize the
    /// writable LRU (which scans, deletes and may create directories), or impose
    /// its eviction limit on an immutable cache maintained by another process.
    pub fn open(&mut self, key: &Path, mode: CacheMode) -> Result<Option<Box<dyn ReadSeek>>> {
        LruDiskCache::validate_key(key.as_os_str())?;
        if mode == CacheMode::ReadOnly {
            let path = self.path().join(key);
            return match fs_err::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() => match fs_err::File::open(&path) {
                    Ok(file) => Ok(Some(Box::new(file))),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(error) => Err(error.into()),
                },
                Ok(_) => Ok(None),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            };
        }
        match self.get_or_init()?.get(key) {
            Ok(file) => Ok(Some(file)),
            Err(LruError::FileNotInCache) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub const fn get(&mut self) -> Option<&mut LruDiskCache> {
        match self {
            Self::Uninit { .. } => None,
            Self::Init(d) => Some(d),
        }
    }

    #[must_use = "the configured byte limit is returned without changing it"]
    pub const fn capacity(&self) -> u64 {
        match self {
            Self::Uninit { max_size, .. } => *max_size,
            Self::Init(d) => d.capacity(),
        }
    }

    #[must_use = "the returned path identifies the cache storage location"]
    pub fn path(&self) -> &Path {
        match self {
            Self::Uninit { root, .. } => root.as_ref(),
            Self::Init(d) => d.path(),
        }
    }
}
