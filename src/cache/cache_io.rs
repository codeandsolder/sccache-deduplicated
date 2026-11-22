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
use crate::compression::{VerifiedZstdFrame, cache_level, encode};
use crate::errors::{Context, Result, bail};
use crate::util::MetadataCtimeExt;
use fs_err as fs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

/// A validated worker frame corresponding to a materialized local output file.
/// Preserve the final file's semantics if another output aliases or replaces it
/// before the cache archive is assembled.
pub struct MaterializedOutput {
    frame: VerifiedZstdFrame,
    metadata: std::fs::Metadata,
}

impl MaterializedOutput {
    /// Associate the validated frame with the file it was materialized into.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file's metadata cannot be read.
    pub fn new(frame: VerifiedZstdFrame, file: &fs::File) -> std::io::Result<Self> {
        Ok(Self {
            frame,
            metadata: file.metadata()?,
        })
    }

    fn frame_for(&self, metadata: &std::fs::Metadata) -> Option<&VerifiedZstdFrame> {
        same_output_metadata(&self.metadata, metadata).then_some(&self.frame)
    }
}

/// Compare the identity and timestamps rather than assuming an existing output
/// was produced by the last successful invocation.
fn same_output_metadata(old: &std::fs::Metadata, new: &std::fs::Metadata) -> bool {
    old.is_file()
        && new.is_file()
        && old.len() == new.len()
        && old
            .modified()
            .ok()
            .zip(new.modified().ok())
            .is_some_and(|(a, b)| a == b)
        && old
            .ctime_or_creation()
            .ok()
            .zip(new.ctime_or_creation().ok())
            .is_some_and(|(a, b)| a == b)
        && same_file_identity(old, new)
}

fn output_provably_changed(old: &std::fs::Metadata, new: &std::fs::Metadata) -> bool {
    !old.is_file()
        || !new.is_file()
        || old.len() != new.len()
        || !same_file_identity(old, new)
        || old
            .modified()
            .ok()
            .zip(new.modified().ok())
            .is_some_and(|(a, b)| a != b)
        || old
            .ctime_or_creation()
            .ok()
            .zip(new.ctime_or_creation().ok())
            .is_some_and(|(a, b)| a != b)
}

/// Files present before the actual compiler runs. A locally generated depfile
/// is already an output of this invocation, so exclude it from the snapshot.
pub(crate) fn snapshot_existing_outputs(
    objects: &[FileObjectSource],
    locally_preprocessed: bool,
) -> HashMap<PathBuf, std::fs::Metadata> {
    objects
        .iter()
        .filter(|object| !(locally_preprocessed && object.key == "d"))
        .filter_map(|object| {
            fs::metadata(&object.path)
                .ok()
                .map(|metadata| (object.path.clone(), metadata))
        })
        .collect()
}

#[cfg(unix)]
fn same_file_identity(old: &std::fs::Metadata, new: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    old.dev() == new.dev() && old.ino() == new.ino()
}

#[cfg(windows)]
fn same_file_identity(_old: &std::fs::Metadata, _new: &std::fs::Metadata) -> bool {
    // Windows' stable Rust metadata exposes creation/modification times rather
    // than file IDs; those timestamps are checked above.
    true
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
    #[must_use = "the returned archive writer must receive the compilation outputs"]
    pub fn new() -> Self {
        Self {
            zip: ZipWriter::new(Cursor::new(vec![])),
        }
    }

    /// Create a new cache entry populated with the contents of `objects`.
    ///
    /// # Errors
    ///
    /// Returns `None` when a successful compiler invocation omitted a required
    /// output or left an old output untouched. Such invocations must not be
    /// cached as full compilations. Other archive I/O errors are reported.
    pub async fn from_objects<T>(
        objects: T,
        remote_outputs: HashMap<PathBuf, MaterializedOutput>,
        existing_outputs: HashMap<PathBuf, std::fs::Metadata>,
        pool: &tokio::runtime::Handle,
    ) -> Result<Option<Self>>
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
                match fs::File::open(&path) {
                    Ok(mut f) => {
                        let metadata = f.metadata()?;
                        if existing_outputs
                            .get(&path)
                            .is_some_and(|old| !output_provably_changed(old, &metadata))
                        {
                            debug!(
                                "Compiler left an existing output unchanged: {}",
                                path.display()
                            );
                            return Ok(None);
                        }
                        let mode = get_file_mode(&metadata);
                        let stored = if let Some(frame) = remote_outputs
                            .get(&path)
                            .and_then(|output| output.frame_for(&metadata))
                        {
                            entry.put_compressed_object(&key, frame, mode)
                        } else {
                            entry.put_object(&key, &mut f, mode)
                        };
                        stored.with_context(|| {
                            format!("failed to put object `{}` in cache entry", path.display())
                        })?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if !optional {
                            debug!(
                                "Successful compiler omitted required output: {}",
                                path.display()
                            );
                            return Ok(None);
                        }
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to open output `{}`", path.display())
                        });
                    }
                }
            }
            Ok(Some(entry))
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
        self.start_object(name, mode)?;
        encode(from, &mut self.zip, cache_level())?;
        Ok(())
    }

    /// The worker's frame was validated while materializing the compiler output.
    /// Copy it verbatim into the cache, without reading or recompressing the file.
    fn put_compressed_object(
        &mut self,
        name: &str,
        output: &VerifiedZstdFrame,
        mode: Option<u32>,
    ) -> Result<()> {
        self.start_object(name, mode)?;
        self.zip.write_all(output.compressed_bytes())?;
        Ok(())
    }

    fn start_object(&mut self, name: &str, mode: Option<u32>) -> Result<()> {
        // The entry stores a Zstandard frame, not a ZIP-compressed payload.
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        let opts = mode.map_or(opts, |mode| opts.unix_permissions(mode));
        self.zip
            .start_file(name, opts)
            .context("Failed to start cache entry object")
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

    #[test]
    fn stores_verified_worker_frame_verbatim_and_compresses_local_outputs() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let temp = tempfile::tempdir()?;
        let remote_path = temp.path().join("remote.o");
        let local_path = temp.path().join("local.d");
        let optional_path = temp.path().join("missing");
        let remote = b"large remote artifact".repeat(1024);
        let local = b"preprocessed dependency file";
        let frame = crate::compression::ZstdFrame::try_from_reader(remote.as_slice(), 10)?;
        let mut output = fs::File::create(&remote_path)?;
        let verified = frame.materialize(&mut output)?;
        let expected_frame = verified.compressed_bytes().to_vec();
        let materialized = MaterializedOutput::new(verified, &output)?;
        drop(output);
        fs::write(&local_path, local)?;

        let objects = vec![
            FileObjectSource {
                key: "remote".into(),
                path: remote_path.clone(),
                optional: false,
            },
            FileObjectSource {
                key: "local".into(),
                path: local_path,
                optional: false,
            },
            FileObjectSource {
                key: "optional".into(),
                path: optional_path,
                optional: true,
            },
        ];
        let entry = runtime
            .block_on(CacheWrite::from_objects(
                objects,
                HashMap::from([(remote_path, materialized)]),
                HashMap::new(),
                runtime.handle(),
            ))?
            .context("expected complete compiler outputs")?;
        let encoded = entry.finish()?;
        let mut zip = ZipArchive::new(Cursor::new(&encoded))?;
        let mut zip_file = zip.by_name("remote")?;
        let mut frame_bytes = Vec::new();
        zip_file.read_to_end(&mut frame_bytes)?;
        assert_eq!(zip_file.compression(), CompressionMethod::Stored);
        assert_eq!(frame_bytes, expected_frame);
        drop(zip_file);
        assert!(zip.by_name("optional").is_err());
        let mut read = CacheRead::from(Cursor::new(encoded))?;
        let mut result = Vec::new();
        read.get_object("remote", &mut result)?;
        assert_eq!(result, remote);
        result.clear();
        read.get_object("local", &mut result)?;
        assert_eq!(result, local);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn materialized_worker_output_is_recompressed_if_replaced() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("out.o");
        let frame = crate::compression::ZstdFrame::try_from_reader(&b"first"[..], 3)?;
        let mut output = fs::File::create(&path)?;
        let frame = MaterializedOutput::new(frame.materialize(&mut output)?, &output)?;
        drop(output);

        let replacement = temp.path().join("replacement");
        fs::write(&replacement, b"other")?;
        fs::rename(replacement, &path)?;
        let objects = vec![FileObjectSource {
            key: "obj".into(),
            path: path.clone(),
            optional: false,
        }];
        let entry = runtime
            .block_on(CacheWrite::from_objects(
                objects,
                HashMap::from([(path, frame)]),
                HashMap::new(),
                runtime.handle(),
            ))?
            .context("expected complete compiler outputs")?;
        let mut read = CacheRead::from(Cursor::new(entry.finish()?))?;
        let mut bytes = Vec::new();
        read.get_object("obj", &mut bytes)?;
        assert_eq!(bytes, b"other");
        Ok(())
    }

    #[test]
    fn missing_or_unchanged_compiler_outputs_are_not_cacheable() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("output.o");
        let depfile = temp.path().join("output.d");
        fs::write(&depfile, b"locally generated dependencies")?;
        let objects = vec![
            FileObjectSource {
                key: "obj".into(),
                path: path.clone(),
                optional: false,
            },
            FileObjectSource {
                key: "d".into(),
                path: depfile,
                optional: false,
            },
        ];
        let package = |snapshot| {
            runtime.block_on(CacheWrite::from_objects(
                objects.clone(),
                HashMap::new(),
                snapshot,
                runtime.handle(),
            ))
        };
        assert!(package(snapshot_existing_outputs(&objects, true))?.is_none());

        fs::write(&path, b"old output")?;
        let snapshot = snapshot_existing_outputs(&objects, true);
        assert!(package(snapshot)?.is_none());
        assert_eq!(fs::read(&path)?, b"old output");

        let snapshot = snapshot_existing_outputs(&objects, true);
        fs::write(&path, b"new artifact with different length")?;
        let entry = package(snapshot)?.context("expected complete compiler outputs")?;
        let mut cache = CacheRead::from(Cursor::new(entry.finish()?))?;
        let mut contents = Vec::new();
        cache.get_object("obj", &mut contents)?;
        assert_eq!(contents, b"new artifact with different length");
        contents.clear();
        cache.get_object("d", &mut contents)?;
        assert_eq!(contents, b"locally generated dependencies");
        Ok(())
    }

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
