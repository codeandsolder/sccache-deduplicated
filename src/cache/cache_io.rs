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

use super::utils::{get_file_mode, set_file_mode};
use crate::errors::{Context, Result, bail};
use fs_err as fs;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{Cursor, Read, Seek, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

/// Cache object sourced by a file.
#[derive(Clone)]
pub struct FileObjectSource {
    /// Identifier for this object. Should be unique within a compilation unit.
    /// Note that a compilation unit is a single source file in C/C++ and a crate in Rust.
    pub key: String,
    /// Absolute path to the file.
    pub path: PathBuf,
    /// Whether the file must be present on disk and is essential for the compilation.
    pub optional: bool,
}

/// Result of a cache lookup.
pub enum Cache {
    /// Result was found in cache.
    Hit(CacheRead),
    /// Result was not found in cache.
    Miss,
    /// Do not cache the results of the compilation.
    None,
    /// Cache entry should be ignored, force compilation.
    Recache,
}

impl fmt::Debug for Cache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Hit(_) => write!(f, "Cache::Hit(...)"),
            Self::Miss => write!(f, "Cache::Miss"),
            Self::None => write!(f, "Cache::None"),
            Self::Recache => write!(f, "Cache::Recache"),
        }
    }
}

/// `CacheMode` is used to represent which mode we are using.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheMode {
    /// Only read cache from storage.
    ReadOnly,
    /// Full support of cache storage: read and write.
    ReadWrite,
}

/// Trait objects can't be bounded by more than one non-builtin trait.
pub trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

/// Data stored in the compiler cache.
pub struct CacheRead {
    zip: ZipArchive<Box<dyn ReadSeek>>,
}

/// Represents a failure to decompress stored object data.
#[derive(Debug)]
pub struct DecompressionFailure;

impl std::fmt::Display for DecompressionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to decompress content")
    }
}

impl std::error::Error for DecompressionFailure {}

impl CacheRead {
    /// Create a cache entry from `reader`.
    ///
    /// # Errors
    ///
    /// Returns an error if `reader` does not contain a valid cache archive.
    pub fn from<R>(reader: R) -> Result<Self>
    where
        R: ReadSeek + 'static,
    {
        let z = ZipArchive::new(Box::new(reader) as Box<dyn ReadSeek>)
            .context("Failed to parse cache entry")?;
        Ok(Self { zip: z })
    }

    /// Get an object from this cache entry at `name` and write it to `to`.
    /// If the file has stored permissions, return them.
    ///
    /// # Errors
    ///
    /// Returns an error if the object is missing, malformed, or cannot be decompressed.
    pub fn get_object<T>(&mut self, name: &str, to: &mut T) -> Result<Option<u32>>
    where
        T: Write,
    {
        let file = self.zip.by_name(name).or(Err(DecompressionFailure))?;
        if file.compression() != CompressionMethod::Stored {
            bail!(DecompressionFailure);
        }
        let mode = file.unix_mode();
        zstd::stream::copy_decode(file, to).or(Err(DecompressionFailure))?;
        Ok(mode)
    }

    /// Get the stdout from this cache entry, if it exists.
    pub fn get_stdout(&mut self) -> Vec<u8> {
        self.get_bytes("stdout")
    }

    /// Get the stderr from this cache entry, if it exists.
    pub fn get_stderr(&mut self) -> Vec<u8> {
        self.get_bytes("stderr")
    }

    fn get_bytes(&mut self, name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        drop(self.get_object(name, &mut bytes));
        bytes
    }

    /// Extract cached objects atomically to their requested output paths.
    ///
    /// # Errors
    ///
    /// Returns an error if a required object is missing or an output cannot be created,
    /// persisted, or restored.
    pub async fn extract_objects<T>(
        mut self,
        objects: T,
        pool: &tokio::runtime::Handle,
    ) -> Result<()>
    where
        T: IntoIterator<Item = FileObjectSource> + Send + Sync + 'static,
    {
        pool.spawn_blocking(move || {
            for FileObjectSource {
                key,
                path,
                optional,
            } in objects
            {
                if is_path_null(&path) {
                    // For unix, this is just a fast path to discard such outputs,
                    // so it is not an issue if `is_path_null` has false-negatives.
                    // But for Windows, since `NUL` looks like a relative path, the
                    // temporary file creation logic would happily succeed, creating
                    // a temp file in the CWD, but then the subsequent `persist`
                    // would fail with `ERROR_ALREADY_EXISTS`, since `NUL` always
                    // exists and cannot be `replaced`, so we really need to
                    // short-circuit more of such cases on Windows.
                    debug!("Skipping output to {}", path.display());
                    continue;
                }
                let Some(dir) = path.parent() else {
                    bail!("Output file without a parent directory!");
                };
                // Write the cache entry to a tempfile and then atomically
                // move it to its final location so that other rustc invocations
                // happening in parallel don't see a partially-written file.
                match (NamedTempFile::new_in(dir), optional) {
                    (Ok(mut tmp), _) => {
                        match (self.get_object(&key, &mut tmp), optional) {
                            (Ok(mode), _) => {
                                tmp.persist(&path)?;
                                if let Some(mode) = mode {
                                    set_file_mode(path.as_path(), mode)?;
                                }
                            }
                            (Err(e), false) => return Err(e),
                            // Skip if no object was found and it is optional.
                            (Err(_), true) => {}
                        }
                    }
                    (Err(e), false) => {
                        // Fall back to writing directly to the final location
                        warn!("Failed to create temp file on the same file system: {e}");
                        let mut f = std::fs::File::create(&path)?;
                        // `optional` is false in this branch, so do not ignore errors
                        let mode = self.get_object(&key, &mut f)?;
                        if let Some(mode) = mode
                            && let Err(e) = set_file_mode(path.as_path(), mode)
                        {
                            // Here we ignore errors from setting file mode because
                            // if we could not create a temp file in the same directory,
                            // we probably can't set the mode either (e.g. /dev/stuff)
                            warn!("Failed to reset file mode: {e}");
                        }
                    }
                    // Skip if no object was found and it is optional.
                    (Err(_), true) => {}
                }
            }
            Ok(())
        })
        .await?
    }
}

#[cfg(unix)]
fn is_path_null(path: &Path) -> bool {
    path == Path::new("/dev/null")
}

#[cfg(windows)]
fn is_path_null(path: &Path) -> bool {
    // For Windows, it appears that `NUL` with whatever extension is also a blackhole
    // (at least for `CreateFileX`), so it does not suffice to check for an exact match
    // Also note that gcc, cl.exe, et al. append a correct extension automatically even
    // if the user asks for output to `NUL`.
    let Some(stem) = path.file_stem() else {
        return false;
    };
    stem.eq_ignore_ascii_case("NUL")
}

/// Data to be stored in the compiler cache.
pub struct CacheWrite {
    zip: ZipWriter<Cursor<Vec<u8>>>,
}

impl CacheWrite {
    /// Create a new, empty cache entry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            zip: ZipWriter::new(Cursor::new(vec![])),
        }
    }

    /// Create a new cache entry populated with the contents of `objects`.
    ///
    /// # Errors
    ///
    /// Returns an error if a required input cannot be opened, read, or added to the archive.
    pub async fn from_objects<T>(objects: T, pool: &tokio::runtime::Handle) -> Result<Self>
    where
        T: IntoIterator<Item = FileObjectSource> + Send + Sync + 'static,
    {
        pool.spawn_blocking(move || {
            let mut entry = Self::new();
            for FileObjectSource {
                key,
                path,
                optional,
            } in objects
            {
                let f = fs::File::open(&path)
                    .with_context(|| format!("failed to open file `{}`", path.display()));
                match (f, optional) {
                    (Ok(mut f), _) => {
                        let mode = get_file_mode(&f)?;
                        entry.put_object(&key, &mut f, mode).with_context(|| {
                            format!("failed to put object `{}` in cache entry", path.display())
                        })?;
                    }
                    (Err(e), false) => return Err(e),
                    (Err(_), true) => {}
                }
            }
            Ok(entry)
        })
        .await?
    }

    /// Add an object containing the contents of `from` to this cache entry at `name`.
    /// If `mode` is `Some`, store the file entry with that mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive entry cannot be created, read, or compressed.
    pub fn put_object<T>(&mut self, name: &str, from: &mut T, mode: Option<u32>) -> Result<()>
    where
        T: Read,
    {
        // We're going to declare the compression method as "stored",
        // but we're actually going to store zstd-compressed blobs.
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        let opts = mode.map_or(opts, |mode| opts.unix_permissions(mode));
        self.zip
            .start_file(name, opts)
            .context("Failed to start cache entry object")?;

        let compression_level = std::env::var("SCCACHE_CACHE_ZSTD_LEVEL")
            .ok()
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(3);
        zstd::stream::copy_encode(from, &mut self.zip, compression_level)?;
        Ok(())
    }

    /// Store compiler stdout in this cache entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the data cannot be written to the archive.
    pub fn put_stdout(&mut self, bytes: &[u8]) -> Result<()> {
        self.put_bytes("stdout", bytes)
    }

    /// Store compiler stderr in this cache entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the data cannot be written to the archive.
    pub fn put_stderr(&mut self, bytes: &[u8]) -> Result<()> {
        self.put_bytes("stderr", bytes)
    }

    fn put_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        if !bytes.is_empty() {
            let mut cursor = Cursor::new(bytes);
            return self.put_object(name, &mut cursor, None);
        }
        Ok(())
    }

    /// Finish writing data to the cache entry writer, and return the data.
    ///
    /// # Errors
    ///
    /// Returns an error if finalizing the cache archive fails.
    pub fn finish(self) -> Result<Vec<u8>> {
        let Self { zip } = self;
        let cur = zip.finish().context("Failed to finish cache entry zip")?;
        Ok(cur.into_inner())
    }
}

impl Default for CacheWrite {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn test_extract_object_to_devnull_works() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()?;

        let pool = runtime.handle();

        let cache_data = CacheWrite::new();
        let cache_read = CacheRead::from(std::io::Cursor::new(cache_data.finish()?))?;

        let objects = vec![FileObjectSource {
            key: "test_key".to_string(),
            path: PathBuf::from("/dev/null"),
            optional: false,
        }];

        runtime.block_on(cache_read.extract_objects(objects, pool))?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_extract_object_to_dev_fd_something() -> Result<()> {
        // Open a pipe, write to `/dev/fd/{fd}` and check the other end that the correct data was written.
        use std::os::fd::AsRawFd;
        use tokio::io::AsyncReadExt;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()?;
        let pool = runtime.handle();
        let mut cache_data = CacheWrite::new();
        let data = b"test data";
        cache_data.put_bytes("test_key", data)?;
        let cache_read = CacheRead::from(std::io::Cursor::new(cache_data.finish()?))?;
        runtime.block_on(async {
            let (sender, mut receiver) = tokio::net::unix::pipe::pipe()?;
            let sender_fd = sender.into_blocking_fd()?;
            let raw_fd = sender_fd.as_raw_fd();
            let fd_path = PathBuf::from(format!("/dev/fd/{raw_fd}"));
            let objects = vec![FileObjectSource {
                key: "test_key".to_string(),
                path: fd_path.clone(),
                optional: false,
            }];
            // On FreeBSD, `/dev/fd/{fd}` does not always exist (i.e. without mounting `fdescfs`), so we skip this test if we get `ENOENT`.
            if !fd_path.exists() {
                info!("Skipping test_extract_object_to_dev_fd_something because /dev/fd/{raw_fd} does not exist");
                return Ok(());
            }
            cache_read.extract_objects(objects, pool).await?;
            let mut buf = vec![0; data.len()];
            let n = receiver.read_exact(&mut buf).await?;
            assert_eq!(n, data.len(), "Read the correct number of bytes");
            assert_eq!(buf, data, "Read the correct data from /dev/fd/{raw_fd}");
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn test_extract_object_to_non_writable_path() -> Result<()> {
        // See `test_extract_object_to_dev_fd_something`: we still cannot cover all platforms by the other tests. Here we test a more portable case of creating a file and making its parent directory non-writable, in which case we should still be able to extract the object successfully.

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()?;

        let pool = runtime.handle();

        let mut cache_data = CacheWrite::new();
        cache_data.put_bytes("test_key", b"real_test_data")?;
        let cache_read = CacheRead::from(std::io::Cursor::new(cache_data.finish()?))?;

        let tmpdir = tempfile::tempdir()?;
        let target_path = tmpdir.path().join("test_file");
        std::fs::write(&target_path, b"test")?;
        // The current Rust fs permissions API is kind of awkward...
        let mut perm = tmpdir.path().metadata()?.permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(tmpdir.path(), perm.clone())?;
        // Note that this doesn't guarantee that a new file cannot be created anymore.
        // For example, as documented in `std::fs::Permissions::set_readonly`, the
        // `FILE_ATTRIBUTE_READONLY` attribute on Windows is entirely ignored for directories.

        let objects = vec![FileObjectSource {
            key: "test_key".to_string(),
            path: target_path.clone(),
            optional: false,
        }];
        let result = runtime.block_on(cache_read.extract_objects(objects, pool));
        assert!(
            result.is_ok(),
            "Extracting to the target path should succeed"
        );
        // Test the content; make sure the old content is overwritten
        let content = std::fs::read(&target_path)?;
        assert_eq!(
            content, b"real_test_data",
            "Extracted content should be correct"
        );

        // `tempfile` needs us to restore owner write permission for cleanup.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perm.set_mode(perm.mode() | 0o200);
        }
        #[cfg(not(unix))]
        perm.set_readonly(false);
        std::fs::set_permissions(tmpdir.path(), perm)?;
        tmpdir.close()?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn test_extract_object_to_nul_works() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()?;

        let pool = runtime.handle();

        let cache_data = CacheWrite::new();
        let cache_read = CacheRead::from(std::io::Cursor::new(cache_data.finish()?))?;

        let objects = vec![FileObjectSource {
            key: "test_key".to_string(),
            path: PathBuf::from("NUL"),
            optional: false,
        }];

        runtime.block_on(cache_read.extract_objects(objects, pool))?;
        Ok(())
    }
}
