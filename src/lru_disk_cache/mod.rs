pub mod lru_cache;

use fs::File;
use fs_err as fs;
use std::borrow::Borrow;
use std::boxed::Box;
use std::collections::hash_map::RandomState;
use std::error::Error as StdError;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::hash::BuildHasher;
use std::io;
use std::io::prelude::*;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use filetime::{FileTime, set_file_times};
pub use lru_cache::{LruCache, Meter};
use tempfile::NamedTempFile;
use walkdir::WalkDir;

use crate::util::OsStrExt;

const TEMPFILE_PREFIX: &str = ".sccachetmp";

struct FileSize;

/// Given a tuple of (path, filesize), use the filesize for measurement.
impl<K> Meter<K, u64> for FileSize {
    type Measure = u64;

    fn measure<Q: ?Sized>(&self, _: &Q, v: &u64) -> u64
    where
        K: Borrow<Q>,
    {
        *v
    }
}

/// Return an iterator of `(path, size)` of files under `path` sorted by ascending last-modified
/// time, such that the oldest modified file is returned first.
fn get_all_files<P: AsRef<Path>>(path: P) -> Box<dyn Iterator<Item = (PathBuf, u64)>> {
    let mut files: Vec<_> = WalkDir::new(path.as_ref())
        .into_iter()
        .filter_map(|e| {
            e.ok().and_then(|f| {
                // Only look at files
                if f.file_type().is_file() {
                    // Get the last-modified time, size, and the full path.
                    f.metadata().ok().and_then(|m| {
                        m.modified()
                            .ok()
                            .map(|mtime| (mtime, f.path().to_owned(), m.len()))
                    })
                } else {
                    None
                }
            })
        })
        .collect();
    // Sort by last-modified-time, so oldest file first.
    files.sort_by_key(|k| k.0);
    Box::new(files.into_iter().map(|(_mtime, path, size)| (path, size)))
}

/// An LRU cache of files on disk.
pub struct LruDiskCache<S: BuildHasher = RandomState> {
    lru: LruCache<OsString, u64, S, FileSize>,
    root: PathBuf,
    pending_size: Arc<AtomicU64>,
}

/// Errors returned by this crate.
#[derive(Debug)]
pub enum Error {
    /// The file was too large to fit in the cache.
    FileTooLarge,
    /// The file was not in the cache.
    FileNotInCache,
    /// An IO Error occurred.
    Io(io::Error),
    /// A prepared entry was committed to a different cache.
    InvalidPendingEntry,
    /// A cache key was not a safe relative path.
    InvalidCacheKey(PathBuf),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileTooLarge => write!(f, "File too large"),
            Self::FileNotInCache => write!(f, "File not in cache"),
            Self::Io(e) => write!(f, "{e}"),
            Self::InvalidPendingEntry => write!(f, "prepared entry belongs to a different cache"),
            Self::InvalidCacheKey(path) => write!(f, "invalid cache key: {}", path.display()),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// A convenience `Result` type
pub type Result<T> = std::result::Result<T, Error>;

/// Trait objects can't be bounded by more than one non-builtin trait.
pub trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

enum AddFile<'a> {
    AbsPath(PathBuf),
    RelPath(&'a OsStr),
}

struct PendingReservation {
    pending_size: Arc<AtomicU64>,
    size: u64,
}

impl PendingReservation {
    fn new(pending_size: Arc<AtomicU64>, size: u64) -> Result<Self> {
        let mut current = pending_size.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(size).ok_or(Error::FileTooLarge)?;
            match pending_size.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        Ok(Self { pending_size, size })
    }
}

impl Drop for PendingReservation {
    fn drop(&mut self) {
        let mut current = self.pending_size.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(self.size);
            match self.pending_size.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }
}

pub struct LruDiskCacheAddEntry {
    file: NamedTempFile,
    key: OsString,
    reservation: PendingReservation,
}

impl LruDiskCacheAddEntry {
    pub fn as_file_mut(&mut self) -> &mut std::fs::File {
        self.file.as_file_mut()
    }
}

impl LruDiskCache {
    /// Create an `LruDiskCache` that stores files in `path`, limited to `size` bytes.
    ///
    /// Existing files in `path` will be stored with their last-modified time from the filesystem
    /// used as the order for the recency of their use. Any files that are individually larger
    /// than `size` bytes will be removed.
    ///
    /// The cache is not observant of changes to files under `path` from external sources, it
    /// expects to have sole maintence of the contents.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache directory cannot be created or initialized.
    pub fn new<T>(path: T, size: u64) -> Result<Self>
    where
        PathBuf: From<T>,
    {
        Self {
            lru: LruCache::with_meter(size, FileSize),
            root: PathBuf::from(path),
            pending_size: Arc::new(AtomicU64::new(0)),
        }
        .init()
    }

    /// Return the current size of all the files in the cache.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.lru
            .size()
            .saturating_add(self.pending_size.load(Ordering::Relaxed))
    }

    /// Return the count of entries in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lru.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lru.len() == 0
    }

    /// Return the maximum size of the cache.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        self.lru.capacity()
    }

    /// Return the path in which the cache is stored.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.root.as_path()
    }

    fn validate_key(key: &OsStr) -> Result<()> {
        let path = Path::new(key);
        let mut has_component = false;
        for component in path.components() {
            has_component = true;
            if !matches!(component, Component::Normal(_)) {
                return Err(Error::InvalidCacheKey(path.to_owned()));
            }
        }
        if !has_component {
            return Err(Error::InvalidCacheKey(path.to_owned()));
        }
        Ok(())
    }

    /// Return the path that `key` would be stored at.
    fn rel_to_abs_path<K: AsRef<Path>>(&self, rel_path: K) -> PathBuf {
        self.root.join(rel_path)
    }

    /// Scan `self.root` for existing files and store them.
    fn init(mut self) -> Result<Self> {
        fs::create_dir_all(&self.root)?;
        for (file, size) in get_all_files(&self.root) {
            if file
                .file_name()
                .is_some_and(|name| name.starts_with(TEMPFILE_PREFIX))
            {
                if let Err(error) = fs::remove_file(&file) {
                    error!(
                        "Error removing temporary file `{}`: {error}",
                        file.display()
                    );
                }
            } else if !self.can_store(size) {
                if let Err(error) = fs::remove_file(&file) {
                    error!(
                        "Error removing oversized cache file `{}` ({size} bytes): {error}",
                        file.display()
                    );
                }
            } else {
                let add_file = AddFile::AbsPath(file);
                self.add_file(&add_file, size)
                    .unwrap_or_else(|e| error!("Error adding file: {e}"));
            }
        }
        Ok(self)
    }

    /// Returns `true` if the disk cache can store a file of `size` bytes.
    #[must_use]
    pub const fn can_store(&self, size: u64) -> bool {
        size <= self.lru.capacity()
    }

    fn make_space(&mut self, size: u64) -> Result<()> {
        if !self.can_store(size) {
            return Err(Error::FileTooLarge);
        }

        while self.size().saturating_add(size) > self.capacity() {
            let Some((rel_path, file_size)) = self.lru.remove_lru() else {
                // Outstanding prepared entries can reserve all remaining capacity.
                return Err(Error::FileTooLarge);
            };
            let remove_path = self.rel_to_abs_path(&rel_path);
            if let Err(error) = fs::remove_file(&remove_path) {
                if error.kind() == std::io::ErrorKind::NotFound {
                    debug!(
                        "Cache entry disappeared before eviction: `{}`",
                        remove_path.display()
                    );
                } else {
                    // Restore accounting if eviction could not be completed.
                    self.lru.insert(rel_path, file_size);
                    return Err(Error::Io(error));
                }
            }
        }
        Ok(())
    }

    /// Add the file at `path` of size `size` to the cache.
    fn add_file(&mut self, addfile_path: &AddFile<'_>, size: u64) -> Result<()> {
        let rel_path = match addfile_path {
            AddFile::AbsPath(path) => path
                .strip_prefix(&self.root)
                .map_err(|_| Error::InvalidCacheKey(path.clone()))?
                .as_os_str(),
            AddFile::RelPath(path) => *path,
        };
        Self::validate_key(rel_path)?;
        self.make_space(size)?;
        self.lru.insert(rel_path.to_owned(), size);
        Ok(())
    }

    fn insert_by<K: AsRef<OsStr>, F: FnOnce(&Path) -> io::Result<()>>(
        &mut self,
        key: K,
        size: Option<u64>,
        by: F,
    ) -> Result<()> {
        if let Some(size) = size
            && !self.can_store(size)
        {
            return Err(Error::FileTooLarge);
        }
        let rel_path = key.as_ref();
        Self::validate_key(rel_path)?;
        let path = self.rel_to_abs_path(rel_path);
        let parent = path
            .parent()
            .ok_or_else(|| Error::InvalidCacheKey(PathBuf::from(rel_path)))?;
        fs::create_dir_all(parent)?;
        by(&path)?;
        let size = match size {
            Some(size) => size,
            None => fs::metadata(path)?.len(),
        };
        self.add_file(&AddFile::RelPath(rel_path), size)
            .map_err(|e| {
                error!(
                    "Failed to insert file `{}`: {e}",
                    rel_path.to_string_lossy()
                );
                let cleanup_path = self.rel_to_abs_path(rel_path);
                if let Err(cleanup_error) = fs::remove_file(&cleanup_path) {
                    warn!(
                        "Failed to remove rejected cache file {}: {cleanup_error}",
                        cleanup_path.display()
                    );
                }
                e
            })
    }

    /// Add a file by calling `with` with the open `File` corresponding to the cache at path `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid, writing fails, or the cache cannot make space.
    pub fn insert_with<K: AsRef<OsStr>, F: FnOnce(File) -> io::Result<()>>(
        &mut self,
        key: K,
        with: F,
    ) -> Result<()> {
        self.insert_by(key, None, |path| with(File::create(path)?))
    }

    /// Add a file with `bytes` as its contents to the cache at path `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid, writing fails, or the cache cannot make space.
    pub fn insert_bytes<K: AsRef<OsStr>>(&mut self, key: K, bytes: &[u8]) -> Result<()> {
        self.insert_by(key, Some(bytes.len() as u64), |path| {
            let mut f = File::create(path)?;
            f.write_all(bytes)?;
            Ok(())
        })
    }

    /// Add an existing file at `path` to the cache at path `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if the source cannot be read/moved, the key is invalid, or the cache cannot make space.
    pub fn insert_file<K: AsRef<OsStr>, P: AsRef<OsStr>>(&mut self, key: K, path: P) -> Result<()> {
        let size = fs::metadata(path.as_ref())?.len();
        self.insert_by(key, Some(size), |new_path| {
            fs::rename(path.as_ref(), new_path).or_else(|_| {
                warn!("fs::rename failed, falling back to copy!");
                fs::copy(path.as_ref(), new_path)?;
                fs::remove_file(path.as_ref()).unwrap_or_else(|e| {
                    error!("Failed to remove original file in insert_file: {e}");
                });
                Ok(())
            })
        })
    }

    /// Prepare the insertion of a file at path `key`. The resulting entry must be
    /// committed with `LruDiskCache::commit`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid, the reservation is too large, or the temporary file cannot be created.
    pub fn prepare_add<'a, K: AsRef<OsStr> + 'a>(
        &mut self,
        key: K,
        size: u64,
    ) -> Result<LruDiskCacheAddEntry> {
        Self::validate_key(key.as_ref())?;
        self.make_space(size)?;
        let reservation = PendingReservation::new(Arc::clone(&self.pending_size), size)?;
        let file = tempfile::Builder::new()
            .prefix(TEMPFILE_PREFIX)
            .tempfile_in(&self.root)?;
        Ok(LruDiskCacheAddEntry {
            file,
            key: key.as_ref().to_owned(),
            reservation,
        })
    }

    /// Commit an entry coming from `LruDiskCache::prepare_add`.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry belongs to another cache, persistence fails, or capacity cannot be made available.
    pub fn commit(&mut self, entry: LruDiskCacheAddEntry) -> Result<()> {
        if !Arc::ptr_eq(&entry.reservation.pending_size, &self.pending_size) {
            return Err(Error::InvalidPendingEntry);
        }

        let LruDiskCacheAddEntry {
            mut file,
            key,
            reservation,
        } = entry;

        // The prepared entry is no longer outstanding. From here on, account
        // for its actual on-disk size rather than the advertised reservation.
        drop(reservation);

        file.flush()?;
        let real_size = file.as_file().metadata()?.len();
        self.make_space(real_size)?;

        let path = self.rel_to_abs_path(&key);
        let parent = path.parent().ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache entry path has no parent directory",
            ))
        })?;
        fs::create_dir_all(parent)?;
        file.persist(path).map_err(|error| error.error)?;
        self.lru.insert(key, real_size);
        Ok(())
    }

    /// Return `true` if a file with path `key` is in the cache. Entries created
    /// by `LruDiskCache::prepare_add` but not yet committed return `false`.
    pub fn contains_key<K: AsRef<OsStr>>(&self, key: K) -> bool {
        self.lru.contains_key(key.as_ref())
    }

    /// Get an opened `File` for `key`, if one exists and can be opened. Updates the LRU state
    /// of the file if present. Avoid using this method if at all possible, prefer `.get`.
    /// Entries created by `LruDiskCache::prepare_add` but not yet committed return
    /// `Err(Error::FileNotInCache)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is absent or the cached file cannot be touched/opened.
    pub fn get_file<K: AsRef<OsStr>>(&mut self, key: K) -> Result<File> {
        let rel_path = key.as_ref();
        let path = self.rel_to_abs_path(rel_path);
        self.lru
            .get(rel_path)
            .ok_or(Error::FileNotInCache)
            .and_then(|_| {
                let t = FileTime::now();
                set_file_times(&path, t, t)?;
                File::open(path).map_err(Into::into)
            })
    }

    /// Get an opened readable and seekable handle to the file at `key`, if one exists and can
    /// be opened. Updates the LRU state of the file if present.
    /// Entries created by `LruDiskCache::prepare_add` but not yet committed return
    /// `Err(Error::FileNotInCache)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is absent or the cached file cannot be opened.
    pub fn get<K: AsRef<OsStr>>(&mut self, key: K) -> Result<Box<dyn ReadSeek>> {
        self.get_file(key).map(|f| Box::new(f) as Box<dyn ReadSeek>)
    }

    /// Return the absolute path for `key` if it is present in the cache, without opening the
    /// file. Updates the LRU eviction order. Returns `None` if the key is absent.
    pub fn get_abs_path<K: AsRef<OsStr>>(&mut self, key: K) -> Option<PathBuf> {
        let rel_path = key.as_ref();
        let path = self.rel_to_abs_path(rel_path);
        self.lru.get(rel_path).map(|_| path)
    }

    /// Remove the given key from the cache.
    ///
    /// # Errors
    ///
    /// Returns an error if an existing cached file cannot be removed.
    pub fn remove<K: AsRef<OsStr>>(&mut self, key: K) -> Result<()> {
        match self.lru.remove(key.as_ref()) {
            Some(_) => {
                let path = self.rel_to_abs_path(key.as_ref());
                fs::remove_file(&path).map_err(|e| {
                    error!("Error removing file from cache: `{}`: {e}", path.display());
                    Into::into(e)
                })
            }
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fs::{self, File};
    use super::{Error, LruDiskCache, LruDiskCacheAddEntry, Result, get_all_files};

    use filetime::{FileTime, set_file_times};
    use std::io::{self, Read, Write};
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    struct TestFixture {
        /// Temp directory.
        pub tempdir: TempDir,
    }

    fn create_file<T: AsRef<Path>, F: FnOnce(File) -> io::Result<()>>(
        dir: &Path,
        path: T,
        fill_contents: F,
    ) -> io::Result<PathBuf> {
        let b = dir.join(path);
        let parent = b.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "test file path has no parent")
        })?;
        fs::create_dir_all(parent)?;
        let f = fs::File::create(&b)?;
        fill_contents(f)?;
        b.canonicalize()
    }

    /// Set the last modified time of `path` backwards by `seconds` seconds.
    fn set_mtime_back<T: AsRef<Path>>(path: T, seconds: usize) -> io::Result<()> {
        let metadata = fs::metadata(path.as_ref())?;
        let modified = FileTime::from_last_modification_time(&metadata);
        let seconds = i64::try_from(seconds).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "mtime offset is too large")
        })?;
        let modified = FileTime::from_unix_time(
            modified.unix_seconds().saturating_sub(seconds),
            modified.nanoseconds(),
        );
        set_file_times(path, modified, modified)?;
        Ok(())
    }

    fn read_all<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
        let mut v = vec![];
        r.read_to_end(&mut v)?;
        Ok(v)
    }

    impl TestFixture {
        pub fn new() -> io::Result<Self> {
            Ok(Self {
                tempdir: tempfile::Builder::new()
                    .prefix("lru-disk-cache-test")
                    .tempdir()?,
            })
        }

        pub fn tmp(&self) -> &Path {
            self.tempdir.path()
        }

        pub fn create_file<T: AsRef<Path>>(&self, path: T, size: usize) -> io::Result<PathBuf> {
            create_file(self.tempdir.path(), path, |mut file| {
                file.write_all(&vec![0; size])
            })
        }
    }

    #[test]
    fn test_rejects_unsafe_cache_keys() -> Result<()> {
        let f = TestFixture::new()?;
        let mut cache = LruDiskCache::new(f.tmp(), 25)?;
        let absolute = f.tmp().join("absolute-key");

        for key in [
            Path::new(""),
            Path::new("../escape"),
            Path::new("nested/../../escape"),
            absolute.as_path(),
        ] {
            assert!(matches!(
                cache.insert_bytes(key.as_os_str(), b"x"),
                Err(Error::InvalidCacheKey(_))
            ));
            assert!(matches!(
                cache.prepare_add(key.as_os_str(), 1),
                Err(Error::InvalidCacheKey(_))
            ));
        }

        Ok(())
    }

    #[test]
    fn test_dropped_prepared_entry_releases_reservation() -> Result<()> {
        let f = TestFixture::new()?;
        let mut cache = LruDiskCache::new(f.tmp(), 10)?;
        let entry = cache.prepare_add("pending", 10)?;

        assert_eq!(cache.size(), 10);
        drop(entry);
        assert_eq!(cache.size(), 0);

        Ok(())
    }

    #[test]
    fn test_cross_cache_commit_releases_origin_reservation() -> Result<()> {
        let first = TestFixture::new()?;
        let second = TestFixture::new()?;
        let mut origin = LruDiskCache::new(first.tmp(), 10)?;
        let mut other = LruDiskCache::new(second.tmp(), 10)?;
        let entry = origin.prepare_add("pending", 10)?;

        assert!(matches!(
            other.commit(entry),
            Err(Error::InvalidPendingEntry)
        ));
        assert_eq!(origin.size(), 0);

        Ok(())
    }

    #[test]
    fn test_commit_larger_than_reservation_releases_reservation_on_error() -> Result<()> {
        let f = TestFixture::new()?;
        let mut cache = LruDiskCache::new(f.tmp(), 10)?;
        let mut entry = cache.prepare_add("pending", 5)?;
        entry.as_file_mut().write_all(&[0; 11])?;

        assert!(matches!(cache.commit(entry), Err(Error::FileTooLarge)));
        assert_eq!(cache.size(), 0);

        Ok(())
    }

    #[test]
    fn test_empty_dir() -> Result<()> {
        let f = TestFixture::new()?;
        LruDiskCache::new(f.tmp(), 1024)?;

        Ok(())
    }

    #[test]
    fn test_missing_root() -> Result<()> {
        let f = TestFixture::new()?;
        LruDiskCache::new(f.tmp().join("not-here"), 1024)?;

        Ok(())
    }

    #[test]
    fn test_some_existing_files() -> Result<()> {
        let f = TestFixture::new()?;
        f.create_file("file1", 10)?;
        f.create_file("file2", 10)?;
        let c = LruDiskCache::new(f.tmp(), 20)?;
        assert_eq!(c.size(), 20);
        assert_eq!(c.len(), 2);

        Ok(())
    }

    #[test]
    fn test_existing_file_too_large() -> Result<()> {
        let f = TestFixture::new()?;
        // Create files explicitly in the past.
        set_mtime_back(f.create_file("file1", 10)?, 10)?;
        set_mtime_back(f.create_file("file2", 10)?, 5)?;
        let c = LruDiskCache::new(f.tmp(), 15)?;
        assert_eq!(c.size(), 10);
        assert_eq!(c.len(), 1);
        assert!(!c.contains_key("file1"));
        assert!(c.contains_key("file2"));

        Ok(())
    }

    #[test]
    fn test_existing_files_lru_mtime() -> Result<()> {
        let f = TestFixture::new()?;
        // Create files explicitly in the past.
        set_mtime_back(f.create_file("file1", 10)?, 5)?;
        set_mtime_back(f.create_file("file2", 10)?, 10)?;
        let mut c = LruDiskCache::new(f.tmp(), 25)?;
        assert_eq!(c.size(), 20);
        c.insert_bytes("file3", &[0; 10])?;
        assert_eq!(c.size(), 20);
        // The oldest file on disk should have been removed.
        assert!(!c.contains_key("file2"));
        assert!(c.contains_key("file1"));

        Ok(())
    }

    #[test]
    fn test_insert_bytes() -> Result<()> {
        let f = TestFixture::new()?;
        let mut c = LruDiskCache::new(f.tmp(), 25)?;
        c.insert_bytes("a/b/c", &[0; 10])?;
        assert!(c.contains_key("a/b/c"));
        c.insert_bytes("a/b/d", &[0; 10])?;
        assert_eq!(c.size(), 20);
        // Adding this third file should put the cache above the limit.
        c.insert_bytes("x/y/z", &[0; 10])?;
        assert_eq!(c.size(), 20);
        // The least-recently-used file should have been removed.
        assert!(!c.contains_key("a/b/c"));
        assert!(!f.tmp().join("a/b/c").exists());

        Ok(())
    }

    #[test]
    fn test_insert_bytes_exact() -> Result<()> {
        // Test that files adding up to exactly the size limit works.
        let f = TestFixture::new()?;
        let mut c = LruDiskCache::new(f.tmp(), 20)?;
        c.insert_bytes("file1", &[1; 10])?;
        c.insert_bytes("file2", &[2; 10])?;
        assert_eq!(c.size(), 20);
        c.insert_bytes("file3", &[3; 10])?;
        assert_eq!(c.size(), 20);
        assert!(!c.contains_key("file1"));

        Ok(())
    }

    #[test]
    fn test_add_get_lru() -> Result<()> {
        let f = TestFixture::new()?;
        {
            let mut c = LruDiskCache::new(f.tmp(), 25)?;
            c.insert_bytes("file1", &[1; 10])?;
            c.insert_bytes("file2", &[2; 10])?;
            // Get the file to bump its LRU status.
            assert_eq!(read_all(&mut c.get("file1")?)?, vec![1u8; 10]);
            // Adding this third file should put the cache above the limit.
            c.insert_bytes("file3", &[3; 10])?;
            assert_eq!(c.size(), 20);
            // The least-recently-used file should have been removed.
            assert!(!c.contains_key("file2"));
        }
        // Get rid of the cache, to test that the LRU persists on-disk as mtimes.
        // This is hacky, but mtime resolution on my mac with HFS+ is only 1 second, so we either
        // need to have a 1 second sleep in the test (boo) or adjust the mtimes back a bit so
        // that updating one file to the current time actually works to make it newer.
        set_mtime_back(f.tmp().join("file1"), 5)?;
        set_mtime_back(f.tmp().join("file3"), 5)?;
        {
            let mut c = LruDiskCache::new(f.tmp(), 25)?;
            // Bump file1 again.
            c.get("file1")?;
        }
        // Now check that the on-disk mtimes were updated and used.
        {
            let mut c = LruDiskCache::new(f.tmp(), 25)?;
            assert!(c.contains_key("file1"));
            assert!(c.contains_key("file3"));
            assert_eq!(c.size(), 20);
            // Add another file to bump out the least-recently-used.
            c.insert_bytes("file4", &[4; 10])?;
            assert_eq!(c.size(), 20);
            assert!(!c.contains_key("file3"));
            assert!(c.contains_key("file1"));
        }

        Ok(())
    }

    #[test]
    fn test_insert_bytes_too_large() -> Result<()> {
        let f = TestFixture::new()?;
        let mut c = LruDiskCache::new(f.tmp(), 1)?;
        assert!(matches!(
            c.insert_bytes("a/b/c", &[0; 2]),
            Err(Error::FileTooLarge)
        ));

        Ok(())
    }

    #[test]
    fn test_insert_file() -> Result<()> {
        let f = TestFixture::new()?;
        let p1 = f.create_file("file1", 10)?;
        let p2 = f.create_file("file2", 10)?;
        let p3 = f.create_file("file3", 10)?;
        let mut c = LruDiskCache::new(f.tmp().join("cache"), 25)?;
        c.insert_file("file1", &p1)?;
        assert_eq!(c.len(), 1);
        c.insert_file("file2", &p2)?;
        assert_eq!(c.len(), 2);
        // Get the file to bump its LRU status.
        assert_eq!(read_all(&mut c.get("file1")?)?, vec![0u8; 10]);
        // Adding this third file should put the cache above the limit.
        c.insert_file("file3", &p3)?;
        assert_eq!(c.len(), 2);
        assert_eq!(c.size(), 20);
        // The least-recently-used file should have been removed.
        assert!(!c.contains_key("file2"));
        assert!(!p1.exists());
        assert!(!p2.exists());
        assert!(!p3.exists());

        Ok(())
    }

    #[test]
    fn test_prepare_and_commit() -> Result<()> {
        let f = TestFixture::new()?;
        let cache_dir = f.tmp();
        let mut c = LruDiskCache::new(cache_dir, 25)?;
        let mut tmp = c.prepare_add("a/b/c", 10)?;
        // An entry added but not committed doesn't count, except for the
        // (reserved) size of the disk cache.
        assert!(!c.contains_key("a/b/c"));
        assert_eq!(c.size(), 10);
        assert_eq!(c.lru.size(), 0);
        tmp.as_file_mut().write_all(&[0; 10])?;
        c.commit(tmp)?;
        // Once committed, the file appears.
        assert!(c.contains_key("a/b/c"));
        assert_eq!(c.size(), 10);
        assert_eq!(c.lru.size(), 10);

        let mut tmp = c.prepare_add("a/b/d", 10)?;
        assert_eq!(c.size(), 20);
        assert_eq!(c.lru.size(), 10);
        // Even though we haven't committed the second file, preparing for
        // the addition of the third one should put the cache above the
        // limit and trigger cleanup.
        let mut tmp2 = c.prepare_add("x/y/z", 10)?;
        assert_eq!(c.size(), 20);
        assert_eq!(c.lru.size(), 0);
        // At this point, we expect the first entry to have been removed entirely.
        assert!(!c.contains_key("a/b/c"));
        assert!(!f.tmp().join("a/b/c").exists());
        tmp.as_file_mut().write_all(&[0; 10])?;
        tmp2.as_file_mut().write_all(&[0; 10])?;
        c.commit(tmp)?;
        assert_eq!(c.size(), 20);
        assert_eq!(c.lru.size(), 10);
        c.commit(tmp2)?;
        assert_eq!(c.size(), 20);
        assert_eq!(c.lru.size(), 20);

        let mut tmp = c.prepare_add("a/b/c", 5)?;
        assert_eq!(c.size(), 25);
        assert_eq!(c.lru.size(), 20);
        // Committing a file bigger than the promised size should properly
        // handle the case where the real size makes the cache go over the limit.
        tmp.as_file_mut().write_all(&[0; 10])?;
        c.commit(tmp)?;
        assert_eq!(c.size(), 20);
        assert_eq!(c.lru.size(), 20);
        assert!(!c.contains_key("a/b/d"));
        assert!(!f.tmp().join("a/b/d").exists());

        // If for some reason, the cache still contains a temporary file on
        // initialization, the temporary file is removed.
        let LruDiskCacheAddEntry { file, .. } = c.prepare_add("a/b/d", 5)?;
        let (_, path) = file.keep().map_err(|error| Error::Io(error.error))?;
        std::mem::drop(c);
        // Ensure that the temporary file is indeed there.
        assert!(get_all_files(cache_dir).any(|(file, _)| file == path));
        LruDiskCache::new(cache_dir, 25)?;
        // The temporary file should not be there anymore.
        assert!(get_all_files(cache_dir).all(|(file, _)| file != path));

        Ok(())
    }

    #[test]
    fn test_remove() -> Result<()> {
        let f = TestFixture::new()?;
        let p1 = f.create_file("file1", 10)?;
        let p2 = f.create_file("file2", 10)?;
        let p3 = f.create_file("file3", 10)?;
        let mut c = LruDiskCache::new(f.tmp().join("cache"), 25)?;
        c.insert_file("file1", &p1)?;
        c.insert_file("file2", &p2)?;
        c.remove("file1")?;
        c.insert_file("file3", &p3)?;
        assert_eq!(c.len(), 2);
        assert_eq!(c.size(), 20);

        // file1 should have been removed.
        assert!(!c.contains_key("file1"));
        assert!(!f.tmp().join("cache").join("file1").exists());
        assert!(f.tmp().join("cache").join("file2").exists());
        assert!(f.tmp().join("cache").join("file3").exists());
        assert!(!p1.exists());
        assert!(!p2.exists());
        assert!(!p3.exists());

        let p4 = f.create_file("file1", 10)?;
        c.insert_file("file1", &p4)?;
        assert_eq!(c.len(), 2);
        // file2 should have been removed.
        assert!(c.contains_key("file1"));
        assert!(!c.contains_key("file2"));
        assert!(!f.tmp().join("cache").join("file2").exists());
        assert!(!p4.exists());

        Ok(())
    }
}
