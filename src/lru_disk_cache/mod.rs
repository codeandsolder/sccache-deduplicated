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

pub use lru_cache::{LruCache, Meter};
use std::fs::FileTimes;
use std::time::SystemTime;
use tempfile::NamedTempFile;
use walkdir::WalkDir;

use crate::util::OsStrExt;

const TEMPFILE_PREFIX: &str = ".sccachetmp";

/// Name of the cache-directory tag file (<https://bford.info/cachedir/>).
pub const CACHEDIR_TAG_FILE_NAME: &str = "CACHEDIR.TAG";

/// The canonical tag file content from the Cache Directory Tagging
/// Specification, with sccache named as the creating application. Backup
/// tools only match the first line; the comments document the file for
/// humans.
const CACHEDIR_TAG_CONTENTS: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55
#
# This file is a cache directory tag created by sccache.
# For information about cache directory tags, see:
#\thttps://bford.info/cachedir/
";

/// Write (or refresh) the cache-directory tag file in `root`.
///
/// Best-effort by design: a read-only or unwritable cache directory must not
/// fail cache creation, and concurrent sccache processes writing identical
/// bytes are harmless.
fn write_cache_dir_tag(root: &Path) {
    let tag = root.join(CACHEDIR_TAG_FILE_NAME);
    // An existing valid tag is sufficient. Do not rewrite or follow an
    // arbitrary existing symlink or special file.
    if let Ok(metadata) = fs::symlink_metadata(&tag) {
        if !metadata.is_file() {
            warn!("Not a regular cache directory tag: {}", tag.display());
            return;
        }
        if fs::read(&tag)
            .is_ok_and(|buf| buf.starts_with(b"Signature: 8a477f597d28d172789f06886806bc55"))
        {
            return;
        }
    }
    let write = || -> io::Result<()> {
        let mut temp = tempfile::Builder::new()
            .prefix(TEMPFILE_PREFIX)
            .tempfile_in(root)?;
        temp.write_all(CACHEDIR_TAG_CONTENTS)?;
        temp.persist(&tag).map_err(|error| error.error)?;
        Ok(())
    };
    if let Err(error) = write() {
        warn!(
            "Error writing cache directory tag {}: {error}",
            tag.display()
        );
    }
}

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
                if f.file_type().is_file() && f.file_name() != CACHEDIR_TAG_FILE_NAME {
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
    #[must_use = "the returned size is needed for cache capacity accounting"]
    pub fn size(&self) -> u64 {
        self.lru
            .size()
            .saturating_add(self.pending_size.load(Ordering::Relaxed))
    }

    /// Return the count of entries in the cache.
    #[must_use = "the entry count is returned without modifying the cache"]
    pub fn len(&self) -> usize {
        self.lru.len()
    }

    #[must_use = "the result describes whether the cache contains any entries"]
    pub fn is_empty(&self) -> bool {
        self.lru.len() == 0
    }

    /// Return the maximum size of the cache.
    #[must_use = "the configured byte limit is returned without changing it"]
    pub const fn capacity(&self) -> u64 {
        self.lru.capacity()
    }

    /// Return the path in which the cache is stored.
    #[must_use = "the returned path identifies the cache storage location"]
    pub fn path(&self) -> &Path {
        self.root.as_path()
    }

    pub(crate) fn validate_key(key: &OsStr) -> Result<()> {
        let path = Path::new(key);
        let mut has_component = false;
        for component in path.components() {
            has_component = true;
            if !matches!(component, Component::Normal(name) if name != CACHEDIR_TAG_FILE_NAME) {
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
        write_cache_dir_tag(&self.root);
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
                self.add_file(&file, size)
                    .unwrap_or_else(|e| error!("Error adding file: {e}"));
            }
        }
        Ok(self)
    }

    /// Returns `true` if the disk cache can store a file of `size` bytes.
    #[must_use = "the result determines whether the entry fits within the cache capacity"]
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

    /// Index an existing file while scanning the cache at startup.
    fn add_file(&mut self, path: &Path, size: u64) -> Result<()> {
        let rel_path = path
            .strip_prefix(&self.root)
            .map_err(|_| Error::InvalidCacheKey(path.to_owned()))?
            .as_os_str();
        Self::validate_key(rel_path)?;
        self.make_space(size)?;
        self.lru.insert(rel_path.to_owned(), size);
        Ok(())
    }

    // Retain the previous on-disk value and restore its LRU accounting if
    // admission or atomic publication fails.
    fn commit_replacement<F: FnOnce(&Path) -> io::Result<()>>(
        &mut self,
        key: &OsStr,
        size: u64,
        publish: F,
    ) -> Result<()> {
        Self::validate_key(key)?;
        if !self.can_store(size) {
            return Err(Error::FileTooLarge);
        }
        let destination = self.rel_to_abs_path(key);
        let parent = destination
            .parent()
            .ok_or_else(|| Error::InvalidCacheKey(PathBuf::from(key)))?;
        fs::create_dir_all(parent)?;

        let previous = self.lru.remove(key);
        let published = self
            .make_space(size)
            .and_then(|()| publish(&destination).map_err(Error::Io));
        if let Err(error) = published {
            if let Some(previous_size) = previous {
                self.lru.insert(key.to_owned(), previous_size);
            }
            return Err(error);
        }
        self.lru.insert(key.to_owned(), size);
        Ok(())
    }

    fn insert_by<K: AsRef<OsStr>, F: FnOnce(&Path) -> io::Result<()>>(
        &mut self,
        key: K,
        size: Option<u64>,
        by: F,
    ) -> Result<()> {
        let key = key.as_ref();
        Self::validate_key(key)?;
        if size.is_some_and(|size| !self.can_store(size)) {
            return Err(Error::FileTooLarge);
        }
        // The callback must never write the existing live entry. Staged names
        // are also discarded if a process restarts before publication.
        let staged = tempfile::Builder::new()
            .prefix(TEMPFILE_PREFIX)
            .tempfile_in(&self.root)?;
        by(staged.path())?;
        let actual_size = staged.as_file().metadata()?.len();
        self.commit_replacement(key, actual_size, |destination| {
            staged
                .persist(destination)
                .map_err(|error| error.error)
                .map(|_| ())
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
        let source = Path::new(path.as_ref());
        let metadata = fs::symlink_metadata(source)?;
        if !metadata.file_type().is_file() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache source must be a regular file",
            )));
        }
        // A renamed hard link would keep the cache sharing an inode with a
        // mutable external path. Only the unique-link fast path may rename.
        #[cfg(unix)]
        let has_external_links = {
            use std::os::unix::fs::MetadataExt;
            metadata.nlink() > 1
        };
        #[cfg(windows)]
        let has_external_links = {
            use std::os::windows::fs::MetadataExt;
            metadata.number_of_links().is_none_or(|count| count > 1)
        };
        #[cfg(not(any(unix, windows)))]
        let has_external_links = true;

        let size = metadata.len();
        let root = self.root.clone();
        self.commit_replacement(key.as_ref(), size, |destination| {
            if !has_external_links
                && (source == destination || fs::rename(source, destination).is_ok())
            {
                return Ok(());
            }
            // Shared inodes and cross-device imports need their own contents;
            // stage the copy so a failure cannot truncate a live cache entry.
            let staged = tempfile::Builder::new()
                .prefix(TEMPFILE_PREFIX)
                .tempfile_in(root)?;
            fs::copy(source, staged.path())?;
            staged.persist(destination).map_err(|error| error.error)?;
            if source != destination
                && let Err(error) = fs::remove_file(source)
            {
                error!("Failed to remove original file in insert_file: {error}");
            }
            Ok(())
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
        self.commit_replacement(&key, real_size, |destination| {
            file.persist(destination)
                .map_err(|error| error.error)
                .map(|_| ())
        })?;
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
        if self.lru.get(rel_path).is_none() {
            return Err(Error::FileNotInCache);
        }
        let mut options = File::options();
        options.read(true);
        // Windows requires FILE_WRITE_ATTRIBUTES to set timestamps on
        // an otherwise read-only handle; do not request write-data access.
        #[cfg(windows)]
        {
            use fs_err::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Foundation::GENERIC_READ;
            use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES;
            options.access_mode(GENERIC_READ | FILE_WRITE_ATTRIBUTES);
        }
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // An externally removed cache file is a miss, not an I/O failure.
                // Forget its size now instead of retaining a phantom LRU entry.
                self.lru.remove(rel_path);
                return Err(Error::FileNotInCache);
            }
            Err(error) => return Err(Error::Io(error)),
        };
        let now = SystemTime::now();
        file.set_times(FileTimes::new().set_accessed(now).set_modified(now))?;
        Ok(file)
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

    /// Remove the given key from the cache.
    ///
    /// # Errors
    ///
    /// Returns an error if an existing cached file cannot be removed.
    pub fn remove<K: AsRef<OsStr>>(&mut self, key: K) -> Result<()> {
        let key = key.as_ref();
        if !self.lru.contains_key(key) {
            return Ok(());
        }
        let path = self.rel_to_abs_path(key);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                error!(
                    "Error removing file from cache: `{}`: {error}",
                    path.display()
                );
                return Err(Error::Io(error));
            }
        }
        self.lru.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::fs::{self, File};
    use super::{
        CACHEDIR_TAG_CONTENTS, CACHEDIR_TAG_FILE_NAME, Error, LruDiskCache, LruDiskCacheAddEntry,
        Result, get_all_files,
    };

    use std::fs::FileTimes;
    use std::io::{self, Read, Write};
    use std::path::{Path, PathBuf};
    use std::time::Duration;
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
        let file = File::options().write(true).open(path.as_ref())?;
        let modified = file.metadata()?.modified()?;
        let seconds = u64::try_from(seconds).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "mtime offset is too large")
        })?;
        let modified = modified
            .checked_sub(Duration::from_secs(seconds))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "mtime offset is out of range")
            })?;
        file.set_times(
            FileTimes::new()
                .set_accessed(modified)
                .set_modified(modified),
        )
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
    fn failed_streaming_replacement_preserves_live_entry_and_restart_state() -> Result<()> {
        let fixture = TestFixture::new()?;
        let root = fixture.tmp().join("cache");
        let mut cache = LruDiskCache::new(&root, 8)?;
        cache.insert_bytes("key", b"original")?;

        let failure = cache.insert_with("key", |mut file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("stream interrupted"))
        });
        assert!(failure.is_err());
        assert_eq!(read_all(&mut cache.get("key")?)?, b"original");
        assert_eq!(cache.size(), 8);
        assert!(matches!(
            cache.insert_with("key", |mut file| file.write_all(b"oversized")),
            Err(Error::FileTooLarge)
        ));
        assert_eq!(read_all(&mut cache.get("key")?)?, b"original");

        cache.insert_bytes("key", b"updated!")?;
        assert_eq!(cache.size(), 8);
        assert_eq!(read_all(&mut cache.get("key")?)?, b"updated!");
        drop(cache);
        let mut cache = LruDiskCache::new(&root, 8)?;
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.size(), 8);
        assert_eq!(read_all(&mut cache.get("key")?)?, b"updated!");
        Ok(())
    }

    #[test]
    fn file_replacement_preserves_source_and_cached_entry_on_admission_failure() -> Result<()> {
        let fixture = TestFixture::new()?;
        let root = fixture.tmp().join("cache");
        let mut cache = LruDiskCache::new(&root, 8)?;
        cache.insert_bytes("key", b"original")?;

        let too_large = fixture.tmp().join("large-source");
        fs::write(&too_large, b"ninebytes")?;
        assert!(matches!(
            cache.insert_file("key", &too_large),
            Err(Error::FileTooLarge)
        ));
        assert_eq!(fs::read(&too_large)?, b"ninebytes");
        assert_eq!(read_all(&mut cache.get("key")?)?, b"original");

        let replacement = fixture.tmp().join("new-source");
        fs::write(&replacement, b"replaced")?;
        cache.insert_file("key", &replacement)?;
        assert!(!replacement.exists());
        assert_eq!(cache.size(), 8);
        assert_eq!(read_all(&mut cache.get("key")?)?, b"replaced");
        Ok(())
    }

    #[test]
    fn non_file_sources_do_not_replace_cached_content() -> Result<()> {
        let fixture = TestFixture::new()?;
        let mut cache = LruDiskCache::new(fixture.tmp().join("cache"), 32)?;
        cache.insert_bytes("entry", b"original")?;

        let directory = fixture.tmp().join("source-directory");
        fs::create_dir(&directory)?;
        assert!(matches!(
            cache.insert_file("entry", &directory),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));

        #[cfg(unix)]
        {
            let source = fixture.tmp().join("external-source");
            fs::write(&source, b"other")?;
            let symlink = fixture.tmp().join("source-symlink");
            std::os::unix::fs::symlink(&source, &symlink)?;
            assert!(matches!(
                cache.insert_file("entry", &symlink),
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidInput
            ));
            assert!(fs::symlink_metadata(&symlink)?.file_type().is_symlink());
            assert_eq!(fs::read(&source)?, b"other");
        }

        assert_eq!(read_all(&mut cache.get("entry")?)?, b"original");
        assert_eq!(cache.size(), 8);
        Ok(())
    }

    #[test]
    fn importing_hardlinks_detaches_external_mutable_inodes() -> Result<()> {
        let fixture = TestFixture::new()?;
        let root = fixture.tmp().join("cache");
        let mut cache = LruDiskCache::new(&root, 32)?;
        let source = fixture.tmp().join("source");
        let alias = fixture.tmp().join("external-alias");
        fs::write(&source, b"original")?;
        fs::hard_link(&source, &alias)?;

        cache.insert_file("entry", &source)?;
        assert!(!source.exists());
        assert_eq!(fs::read(&alias)?, b"original");
        fs::write(&alias, b"changed!")?;
        assert_eq!(read_all(&mut cache.get("entry")?)?, b"original");

        // Reimporting the cache's own pathname must also detach any newly
        // created outside hard link, without deleting the destination.
        let external = fixture.tmp().join("second-alias");
        fs::hard_link(root.join("entry"), &external)?;
        cache.insert_file("entry", root.join("entry"))?;
        fs::write(&external, b"mutated!")?;
        assert_eq!(read_all(&mut cache.get("entry")?)?, b"original");
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.size(), 8);
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
    fn failed_removal_preserves_lru_accounting() -> Result<()> {
        let fixture = TestFixture::new()?;
        let root = fixture.tmp().join("cache");
        let mut cache = LruDiskCache::new(&root, 32)?;
        cache.insert_bytes("entry", b"payload")?;
        let path = root.join("entry");

        fs::remove_file(&path)?;
        fs::create_dir(&path)?;
        assert!(matches!(cache.remove("entry"), Err(Error::Io(_))));
        assert!(cache.contains_key("entry"));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.size(), 7);

        fs::remove_dir(&path)?;
        cache.remove("entry")?;
        assert!(!cache.contains_key("entry"));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.size(), 0);
        Ok(())
    }

    #[test]
    fn vanished_cache_file_becomes_a_miss_and_releases_accounting() -> Result<()> {
        let fixture = TestFixture::new()?;
        let root = fixture.tmp().join("cache");
        let mut cache = LruDiskCache::new(&root, 32)?;
        cache.insert_bytes("entry", b"original")?;
        let path = root.join("entry");
        fs::remove_file(&path)?;

        #[cfg(unix)]
        {
            // A broken path which is not simply missing must keep its
            // accounting until the filesystem error is resolved.
            std::os::unix::fs::symlink("entry", &path)?;
            assert!(matches!(cache.get_file("entry"), Err(Error::Io(_))));
            assert!(cache.contains_key("entry"));
            assert_eq!(cache.size(), 8);
            fs::remove_file(&path)?;
        }

        assert!(matches!(
            cache.get_file("entry"),
            Err(Error::FileNotInCache)
        ));
        assert!(!cache.contains_key("entry"));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.size(), 0);

        cache.insert_bytes("entry", b"replacement")?;
        assert_eq!(read_all(&mut cache.get("entry")?)?, b"replacement");
        assert_eq!(cache.size(), 11);
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

    #[test]
    fn test_writes_cachedir_tag() -> Result<()> {
        let f = TestFixture::new()?;
        LruDiskCache::new(f.tmp(), 1024)?;
        let tag = f.tmp().join(CACHEDIR_TAG_FILE_NAME);
        assert_eq!(fs::read(&tag)?, CACHEDIR_TAG_CONTENTS);
        Ok(())
    }

    #[test]
    fn test_cachedir_tag_not_a_cache_entry() -> Result<()> {
        let f = TestFixture::new()?;
        let c = LruDiskCache::new(f.tmp(), 50)?;
        assert_eq!(c.size(), 0);
        assert_eq!(c.len(), 0);
        // A second open over the same root must not count or evict the tag,
        // and the tag must survive.
        drop(c);
        let mut c = LruDiskCache::new(f.tmp(), 50)?;
        assert_eq!(c.size(), 0);
        assert_eq!(c.len(), 0);
        assert!(f.tmp().join(CACHEDIR_TAG_FILE_NAME).exists());
        // Filling the cache forces eviction; the tag must still survive.
        c.insert_bytes("a", &[0u8; 30])?;
        c.insert_bytes("b", &[0u8; 30])?;
        assert!(f.tmp().join(CACHEDIR_TAG_FILE_NAME).exists());
        assert!(!c.contains_key("a"));
        Ok(())
    }

    #[test]
    fn test_nested_cache_tag_survives() -> Result<()> {
        let f = TestFixture::new()?;
        let c = LruDiskCache::new(f.tmp(), 50)?;
        // A nested cache (the preprocessor cache is <root>/preprocessor)
        // writes its own tag; the recursive scan must leave it alone.
        let nested = f.tmp().join("preprocessor");
        LruDiskCache::new(&nested, 50)?;
        drop(c);
        let mut c = LruDiskCache::new(f.tmp(), 50)?;
        assert_eq!(c.size(), 0);
        c.insert_bytes("a", &[0u8; 30])?;
        c.insert_bytes("b", &[0u8; 30])?;
        assert!(nested.join(CACHEDIR_TAG_FILE_NAME).exists());
        assert!(f.tmp().join(CACHEDIR_TAG_FILE_NAME).exists());
        Ok(())
    }
}
