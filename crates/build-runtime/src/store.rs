use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Instant,
};

#[cfg(target_os = "linux")]
use std::collections::VecDeque;

use anyhow::{Context, Result, anyhow, ensure};
use bincode::Options;
use redb::{
    Database, MultimapTableDefinition, ReadableDatabase, ReadableMultimapTable, ReadableTable,
    ReadableTableMetadata, TableDefinition, WriteTransaction,
};
use serde::{Deserialize, Serialize};
use tempfile::{NamedTempFile, TempPath};

use super::{
    ActionFingerprint, ActionKey, ActionMode, BlobEncoding, BlobReader, BlobRef, ContentId,
    ResultId, ResultManifest, blob_codec, identity::encoding,
};

const ACTIONS: TableDefinition<'static, &[u8; 32], &[u8]> = TableDefinition::new("actions_v1");
const RESULTS: TableDefinition<'static, &[u8; 32], &[u8]> = TableDefinition::new("results_v1");
const PACKAGES: TableDefinition<'static, &[u8; 32], &[u8]> = TableDefinition::new("packages_v1");
const BLOB_PACKAGES: MultimapTableDefinition<'static, &[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("blob_packages_v1");
const TREE_PACKAGES: MultimapTableDefinition<'static, &[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("tree_packages_v1");
const TREES: TableDefinition<'static, &[u8; 32], &[u8]> = TableDefinition::new("trees_v1");
const BLOBS: TableDefinition<'static, &[u8; 32], u64> = TableDefinition::new("blobs_v1");
const BLOB_LAYOUTS: TableDefinition<'static, &[u8; 32], u8> =
    TableDefinition::new("blob_layouts_v1");
// ZFS ARC manages compression transparently; adding Zstd frames on top
// prevents ARC from seeing and sharing the native file's uncompressed bytes.
#[cfg(target_os = "linux")]
const ZFS_SUPER_MAGIC: rustix::fs::FsWord = 0x2fc1_2fc1;

#[cfg(target_os = "linux")]
fn is_native_zfs(path: &Path) -> Result<bool> {
    Ok(rustix::fs::statfs(path)?.f_type == ZFS_SUPER_MAGIC)
}

#[cfg(not(target_os = "linux"))]
fn is_native_zfs(_path: &Path) -> Result<bool> {
    Ok(false)
}

// Linux mountinfo encodes spaces, tabs, newlines, and backslashes with octal
// escapes. Parse as bytes so non-UTF-8 mountpoint names remain representable.
#[cfg(target_os = "linux")]
fn mountinfo_path(raw: &[u8]) -> Result<PathBuf> {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    let mut decoded = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\\' {
            ensure!(
                i + 3 < raw.len()
                    && raw[i + 1..i + 4]
                        .iter()
                        .all(|digit| (b'0'..=b'7').contains(digit)),
                "invalid octal escape in Linux mountinfo path"
            );
            let octet = u16::from(raw[i + 1] - b'0') * 64
                + u16::from(raw[i + 2] - b'0') * 8
                + u16::from(raw[i + 3] - b'0');
            decoded.push(u8::try_from(octet).context("mountinfo escape exceeds one byte")?);
            i += 4;
        } else {
            decoded.push(raw[i]);
            i += 1;
        }
    }
    Ok(PathBuf::from(OsStr::from_bytes(&decoded)))
}

/// Detach abandoned FUSE mounts before deleting their directories.
///
/// An abrupt worker exit can leave its kernel FUSE mounts in the caller's
/// mount namespace. chmod(2) on the FUSE root then returns EROFS (even after
/// the daemon has exited), preventing store reopening and garbage recovery.
/// Only the store's own build-fuse-*/root mountpoints are considered. The
/// exclusive Redb lock is held by the caller before this function runs.
#[cfg(target_os = "linux")]
fn detach_orphan_fuse_mounts(directory: &Path) -> Result<()> {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt, process::Command};

    let mountinfo = fs::read("/proc/self/mountinfo")?;
    let mut stale = Vec::new();
    for line in mountinfo.split(|&byte| byte == b'\n') {
        let Some(split) = line.windows(3).position(|window| window == b" - ") else {
            continue;
        };
        let kind = line[split + 3..]
            .split(|&byte| byte == b' ')
            .next()
            .unwrap_or_default();
        if kind != b"fuse" && !kind.starts_with(b"fuse.") {
            continue;
        }
        let Some(point) = line[..split].split(|&byte| byte == b' ').nth(4) else {
            continue;
        };
        let mounted = mountinfo_path(point)?;
        let Ok(relative) = mounted.strip_prefix(directory) else {
            continue;
        };
        let Some(name) = relative.parent().and_then(Path::file_name) else {
            continue;
        };
        if relative.file_name() != Some(OsStr::new("root"))
            || !name.as_bytes().starts_with(b"build-fuse-")
            || relative.components().count() != 2
        {
            continue;
        }
        stale.push(mounted);
    }
    stale.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for mountpoint in stale {
        let output = Command::new("fusermount3")
            .args(["-u", "-z"])
            .arg(&mountpoint)
            .output()
            .with_context(|| {
                format!(
                    "invoke fusermount3 to release orphaned native CAS mount {}",
                    mountpoint.display()
                )
            })?;
        ensure!(
            output.status.success(),
            "could not unmount abandoned native CAS FUSE view {}: {}",
            mountpoint.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn detach_orphan_fuse_mounts(_directory: &Path) -> Result<()> {
    Ok(())
}

// An unexpected process exit can leave native CoW tree hierarchies behind.
// The Redb lock is already held by the caller, so no live store can own the
// transient mounts being reclaimed. Never follow symlinks during cleanup.
fn clean_orphan_mounts(directory: &Path) -> Result<()> {
    fn remove(path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.is_dir() {
            // Tree manifests can contain directories with restrictive modes.
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            for child in fs::read_dir(path)? {
                remove(&child?.path())?;
            }
            fs::remove_dir(path)?;
        } else {
            fs::remove_file(path)?;
        }
        Ok(())
    }
    detach_orphan_fuse_mounts(directory)?;
    for entry in fs::read_dir(directory)? {
        remove(&entry?.path())?;
    }
    Ok(())
}

const RESULT_ACTIONS: MultimapTableDefinition<'static, &[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("result_actions_v1");
const ACCOUNTING: TableDefinition<'static, u8, u64> = TableDefinition::new("accounting_v1");
const LIVE_BYTES: u8 = 0;
const PENDING_BYTES: u8 = 1;
const PENDING_DELETIONS: TableDefinition<'static, &[u8; 32], u64> =
    TableDefinition::new("pending_deletions_v1");
const BLOB_ROOTS: MultimapTableDefinition<'static, &[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("blob_roots_v1");

#[derive(Serialize, Deserialize)]
struct ActionRecord {
    fingerprint: ActionFingerprint,
    result: ResultId,
}

/// A verified immutable blob staged for publication.
///
/// Dropping it before publication discards the temporary file. Closed, owner-private paths
/// keep descriptor use proportional to active transfers, not manifest size.
pub struct StagedBlob {
    path: TempPath,
    metadata: fs::Metadata,
    reference: BlobRef,
    encoding: BlobEncoding,
    owner: Arc<Inner>,
}

impl StagedBlob {
    #[must_use = "the reference identifies the staged content"]
    pub const fn reference(&self) -> BlobRef {
        self.reference
    }

    fn validate_metadata(&self, actual: &fs::Metadata) -> Result<()> {
        let expected = &self.metadata;
        ensure!(
            actual.is_file()
                && actual.dev() == expected.dev()
                && actual.ino() == expected.ino()
                && actual.len() == expected.len()
                && actual.mode() == expected.mode()
                && actual.mtime() == expected.mtime()
                && actual.mtime_nsec() == expected.mtime_nsec()
                && actual.ctime() == expected.ctime()
                && actual.ctime_nsec() == expected.ctime_nsec(),
            "native staged content changed before publication"
        );
        Ok(())
    }

    fn open_file(&self) -> Result<File> {
        use rustix::fs::{Mode, OFlags, open};
        let file = File::from(open(
            &*self.path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        self.validate_metadata(&file.metadata()?)?;
        Ok(file)
    }
}

/// Result of committing an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Published {
    pub action: ActionKey,
    pub result: ResultId,
    pub new_action: bool,
}

/// Result of an explicit action eviction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eviction {
    Missing,
    Pinned,
    Removed { unreferenced_logical_bytes: u64 },
}

/// Counts logical content, not compressed device usage. On ZFS the dataset
/// quota and referenced/exclusive byte counters govern physical capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub actions: u64,
    pub results: u64,
    pub trees: u64,
    pub blobs: u64,
    pub logical_bytes: u64,
    pub pending_gc_blobs: u64,
    pub pending_gc_bytes: u64,
}

/// Work completed by a bounded garbage collection pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarbageCollected {
    pub blobs: u64,
    pub logical_bytes: u64,
    pub failed: Vec<ContentId>,
}

#[derive(Default)]
struct Pins {
    actions: BTreeMap<ActionKey, usize>,
    trees: BTreeMap<crate::TreeId, usize>,
    blobs: BTreeMap<ContentId, usize>,
    last_used: BTreeMap<space::Root, Instant>,
}

impl Pins {
    fn reserve_content<'a>(
        &mut self,
        ids: impl Iterator<Item = &'a ContentId> + Clone,
    ) -> Result<()> {
        for id in ids.clone() {
            ensure!(
                self.blobs.get(id).copied().unwrap_or(0) < usize::MAX,
                "content pin count overflow"
            );
        }
        for &id in ids {
            *self.blobs.entry(id).or_default() += 1;
        }
        Ok(())
    }
}

// All lease categories use the same pin reference-counting invariant.
fn release_pin<K: Ord + std::fmt::Debug>(pins: &mut BTreeMap<K, usize>, key: &K) {
    match pins.get_mut(key) {
        Some(count) if *count > 1 => *count -= 1,
        Some(_) => {
            pins.remove(key);
        }
        None => log::error!("native store lease lost its pin: {key:?}"),
    }
}

struct Inner {
    root: PathBuf,
    db: Database,
    // Mutations serialize filesystem changes with durable metadata commits.
    // Readers only acquire the separate pin lock, not the publication lock.
    mutations: Mutex<()>,
    pins: Mutex<Pins>,
    package_imports: Mutex<BTreeSet<crate::PackageIdentity>>,
    space_policy: Option<SpacePolicy>,
    space: Mutex<space::SpaceState>,
}

impl Inner {
    fn lock_pins(&self) -> Result<MutexGuard<'_, Pins>> {
        self.pins
            .lock()
            .map_err(|_| anyhow!("native store pin lock poisoned"))
    }

    fn lock_mutations(&self) -> Result<MutexGuard<'_, ()>> {
        self.mutations
            .lock()
            .map_err(|_| anyhow!("native store mutation lock poisoned"))
    }

    fn blob_path(&self, id: ContentId) -> PathBuf {
        let hex = blake3::Hash::from_bytes(id.0).to_hex();
        let hex = hex.as_str();
        // A BLAKE3 hex string is always exactly 64 ASCII characters.
        self.root.join("blobs").join(&hex[..2]).join(&hex[2..])
    }

    fn blob_encoding(&self, id: ContentId) -> Result<BlobEncoding> {
        let read = self.db.begin_read()?;
        let layouts = read.open_table(BLOB_LAYOUTS)?;
        let value = layouts
            .get(&id.0)?
            .with_context(|| format!("missing indexed physical encoding for {id:?}"))?
            .value();
        BlobEncoding::try_from(value)
    }

    fn check_blob(&self, id: ContentId, size: u64) -> Result<()> {
        let path = self.blob_path(id);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("missing native store content {id:?}"))?;
        ensure!(metadata.is_file(), "invalid native store content {id:?}");
        ensure!(
            BlobReader::open(File::open(&path)?, self.blob_encoding(id)?)?.len() == size,
            "invalid native store content {id:?}"
        );
        Ok(())
    }

    fn open_declared(&self, blobs: &BTreeMap<ContentId, u64>, id: ContentId) -> Result<File> {
        ensure!(
            blobs.contains_key(&id),
            "content {id:?} is not part of the leased manifest"
        );
        Ok(File::open(self.blob_path(id))?)
    }

    fn install_blob(&self, blob: StagedBlob, directories: &mut BTreeSet<PathBuf>) -> Result<()> {
        let path = self.blob_path(blob.reference.id);
        let parent = path.parent().context("invalid blob storage path")?;
        if directories.insert(parent.to_owned()) {
            match fs::create_dir(parent) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            directories.insert(self.root.join("blobs"));
        }
        // An unindexed file can remain after a failed transaction; replace it
        // with verified bytes rather than trusting its name or its length.
        blob.validate_metadata(&fs::symlink_metadata(&blob.path)?)?;
        blob.path.persist(&path)?;
        Ok(())
    }

    fn remove_blob(&self, id: ContentId) -> Result<()> {
        let path = self.blob_path(id);
        match fs::remove_file(&path) {
            Ok(()) => {
                File::open(path.parent().context("invalid blob storage path")?)?.sync_all()?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn recover_orphans(&self) -> Result<()> {
        // Only run at open, while the exclusive database lock prevents a
        // second live store from staging or publishing files.
        for entry in fs::read_dir(self.root.join("staging"))? {
            fs::remove_file(entry?.path())?;
        }
        let read = self.db.begin_read()?;
        let blobs = read.open_table(BLOBS)?;
        let layouts = read.open_table(BLOB_LAYOUTS)?;
        let mut stale_layouts = Vec::new();
        for entry in layouts.iter()? {
            let (id, _) = entry?;
            if blobs.get(id.value())?.is_none() {
                stale_layouts.push(*id.value());
            }
        }
        for shard in fs::read_dir(self.root.join("blobs"))? {
            let shard = shard?;
            ensure!(shard.file_type()?.is_dir(), "invalid blob shard");
            let prefix = shard.file_name();
            let prefix = prefix.to_str().context("invalid blob shard name")?;
            ensure!(prefix.len() == 2, "invalid blob shard name");
            for entry in fs::read_dir(shard.path())? {
                let entry = entry?;
                let suffix = entry.file_name();
                let suffix = suffix.to_str().context("invalid blob file name")?;
                let id =
                    ContentId(*blake3::Hash::from_hex(format!("{prefix}{suffix}"))?.as_bytes());
                ensure!(
                    entry.file_type()?.is_file() && entry.path() == self.blob_path(id),
                    "invalid blob file"
                );
                if blobs.get(&id.0)?.is_none() {
                    self.remove_blob(id)?;
                } else {
                    ensure!(
                        layouts.get(&id.0)?.is_some(),
                        "indexed CAS entry missing physical encoding"
                    );
                }
            }
        }
        // Pending deletions are all unreferenced, and no readers or uploads
        // can survive a process restart. The scan above removed their files.
        drop(layouts);
        drop(blobs);
        drop(read);
        let write = self.db.begin_write()?;
        {
            let mut layouts = write.open_table(BLOB_LAYOUTS)?;
            for id in stale_layouts {
                layouts.remove(&id)?;
            }
            let mut pending = write.open_table(PENDING_DELETIONS)?;
            pending.retain(|_, _| false)?;
            let mut accounting = write.open_table(ACCOUNTING)?;
            accounting.insert(PENDING_BYTES, 0)?;
        }
        write.commit()?;
        Ok(())
    }
}

struct ReservingReader<'a, 's, R> {
    source: R,
    budget: &'a mut space::StageBudget<'s>,
    seen: u64,
    bounded: bool,
}
impl<R: Read> Read for ReservingReader<'_, '_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.source.read(buffer)?;
        let next = self
            .seen
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("native stage size overflow"))?;
        if !self.bounded {
            self.budget.grow_to(next).map_err(io::Error::other)?;
        }
        self.seen = next;
        Ok(count)
    }
}

/// Single-owner, durable action index and content-addressed file storage.
///
/// Blocking storage operations belong on an I/O executor rather than the
/// scheduler's asynchronous control loop. Provision the directory on a
/// dedicated compressed filesystem/dataset; this type does not create pools,
/// change filesystem properties or start other cache services.
#[cfg(target_os = "linux")]
const MAX_CACHED_TREE_MOUNTS: usize = 16;

/// A bounded set of persistent immutable views, independent of each action's
/// private writable scratch. Reusing a view preserves kernel page-cache pages.
#[cfg(target_os = "linux")]
#[derive(Default)]
struct MountCache {
    entries: BTreeMap<crate::TreeId, Arc<trees::ReadOnlyView>>,
    order: VecDeque<crate::TreeId>,
}

#[cfg(target_os = "linux")]
impl MountCache {
    fn mount(
        &mut self,
        lease: trees::TreeLease,
        persistent: &Path,
        scratch: &Path,
        native_zfs: bool,
        protected: &[PathBuf],
    ) -> Result<trees::MountedTree> {
        let key = lease.id();
        if let Some(view) = self.entries.get(&key) {
            let mounted = trees::MountedTree::from_view(Arc::clone(view), scratch)?;
            self.order.retain(|other| other != &key);
            self.order.push_back(key);
            return Ok(mounted);
        }
        // A new action identity need not imply a new physical view. Reuse
        // unchanged directories, symlinks and hardlink groups from a cached
        // root; only differing regular files are cloned/decoded into private
        // files and read-only bound into the sandbox. Never reuse changed
        // files beneath writable or already-mounted paths.
        let best = self
            .entries
            .iter()
            .filter_map(|(&id, view)| {
                let changed = trees::compatible_regular_file_overlays(
                    view.manifest(),
                    lease.manifest(),
                    protected,
                )?;
                // Per-file bind mounts and private clones have a cost too:
                // only use the fast path when more entries are preserved
                // than replaced. This is a performance choice, not a
                // correctness constraint.
                (changed.len() < lease.manifest().entries.len() - changed.len())
                    .then_some((id, changed))
            })
            .min_by_key(|(id, changed)| (changed.len(), *id));
        if let Some((base_id, changed)) = best {
            let view = Arc::clone(&self.entries[&base_id]);
            let mut mounted = trees::MountedTree::from_view(view, scratch)?;
            let overlay = lease.materialize_overlays(&changed, scratch)?;
            let stats = overlay.stats;
            mounted.attach_overlays(overlay);
            log::debug!(
                "native CAS reused immutable tree {base_id:?} with {} file overlays, {} block clones, {} copied bytes",
                changed.len(),
                stats.cloned_files,
                stats.copied_bytes,
            );
            self.order.retain(|other| other != &base_id);
            self.order.push_back(base_id);
            return Ok(mounted);
        }
        let view = Arc::new(if native_zfs {
            trees::ReadOnlyView::materialize_zfs(lease, persistent)?
        } else {
            trees::ReadOnlyView::mount_fuse(lease, persistent)?
        });
        let mounted = trees::MountedTree::from_view(Arc::clone(&view), scratch)?;
        self.entries.insert(key, view);
        self.order.push_back(key);
        while self.entries.len() > MAX_CACHED_TREE_MOUNTS {
            if let Some(least_recent) = self.order.pop_front() {
                self.entries.remove(&least_recent);
            }
        }
        Ok(mounted)
    }

    /// Drop inactive cached views before evicting durable CAS content.
    /// A view held by an executing build retains its lease and is not evicted.
    fn drop_idle(&mut self, only: Option<crate::TreeId>) {
        let unused: Vec<_> = self
            .entries
            .iter()
            .filter(|(id, view)| {
                only.is_none_or(|target| **id == target) && Arc::strong_count(view) == 1
            })
            .map(|(&id, _)| id)
            .collect();
        for key in &unused {
            self.entries.remove(key);
        }
        self.order.retain(|key| !unused.contains(key));
    }
}

pub struct NativeStore {
    inner: Arc<Inner>,
    physical_encoding: BlobEncoding,
    #[cfg(target_os = "linux")]
    mounts: Mutex<MountCache>,
}

impl NativeStore {
    #[cfg(target_os = "linux")]
    pub(crate) fn mount_tree_protected(
        &self,
        lease: trees::TreeLease,
        parent: &Path,
        protected: &[PathBuf],
    ) -> Result<trees::MountedTree> {
        let native_zfs = self.can_clone_into(parent)?;
        self.mounts
            .lock()
            .map_err(|_| anyhow!("native CAS mount cache lock poisoned"))?
            .mount(
                lease,
                &self.inner.root.join("mounts"),
                parent,
                native_zfs,
                protected,
            )
    }

    #[cfg(target_os = "linux")]
    fn drop_idle_views(&self, only: Option<crate::TreeId>) -> Result<()> {
        self.mounts
            .lock()
            .map_err(|_| anyhow!("native CAS mount cache lock poisoned"))?
            .drop_idle(only);
        Ok(())
    }

    /// Open or initialize an exclusive store and recover unreferenced files.
    ///
    /// # Errors
    /// Returns an error for filesystem, database or recovery failures, including
    /// when another live process owns this directory.
    pub fn open(root: &Path) -> Result<Self> {
        Self::open_inner(root, None)
    }

    fn open_inner(root: &Path, space_policy: Option<SpacePolicy>) -> Result<Self> {
        fs::create_dir_all(root)?;
        let root = fs::canonicalize(root)?;
        let metadata = fs::metadata(&root)?;
        ensure!(
            metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o022 == 0,
            "native store root must be owned by the service and not writable by others"
        );
        let index = root.join("index.redb");
        match fs::symlink_metadata(&index) {
            Ok(metadata) => ensure!(metadata.is_file(), "native index is not a regular file"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                ensure!(
                    fs::read_dir(&root)?.next().is_none(),
                    "native store must start in an empty directory"
                );
            }
            Err(error) => return Err(error.into()),
        }
        let db = Database::create(index)?;
        for name in ["staging", "blobs", "mounts"] {
            let path = root.join(name);
            fs::create_dir_all(&path)?;
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_dir()
                    && metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.mode() & 0o022 == 0,
                "native store directory is not owner-controlled: {}",
                path.display()
            );
            if name == "staging" || name == "mounts" {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            }
        }
        clean_orphan_mounts(&root.join("mounts"))?;
        File::open(&root)?.sync_all()?;
        let write = db.begin_write()?;
        write.open_table(ACTIONS)?;
        write.open_table(RESULTS)?;
        write.open_table(TREES)?;
        write.open_table(PACKAGES)?;
        write.open_multimap_table(TREE_PACKAGES)?;
        write.open_multimap_table(BLOB_PACKAGES)?;
        write.open_table(BLOBS)?;
        write.open_table(BLOB_LAYOUTS)?;
        write.open_multimap_table(RESULT_ACTIONS)?;
        write.open_multimap_table(BLOB_ROOTS)?;
        write.open_table(PENDING_DELETIONS)?;
        {
            let mut accounting = write.open_table(ACCOUNTING)?;
            if accounting.get(LIVE_BYTES)?.is_none() {
                accounting.insert(LIVE_BYTES, 0)?;
            }
            if accounting.get(PENDING_BYTES)?.is_none() {
                accounting.insert(PENDING_BYTES, 0)?;
            }
        }
        write.commit()?;
        let physical_encoding = if is_native_zfs(&root.join("staging"))? {
            BlobEncoding::Raw
        } else {
            BlobEncoding::ZstdChunks
        };
        let inner = Arc::new(Inner {
            root,
            db,
            mutations: Mutex::new(()),
            pins: Mutex::new(Pins::default()),
            package_imports: Mutex::new(BTreeSet::new()),
            space_policy,
            space: Mutex::default(),
        });
        inner.recover_orphans()?;
        Ok(Self {
            inner,
            physical_encoding,
            #[cfg(target_os = "linux")]
            mounts: Mutex::new(MountCache::default()),
        })
    }

    /// The storage format selected for this store's backing filesystem.
    /// ZFS retains ordinary files; other filesystems retain indexed Zstd frames.
    #[must_use = "blob storage and transfer must use the backing filesystem's physical encoding"]
    pub const fn physical_encoding(&self) -> BlobEncoding {
        self.physical_encoding
    }

    /// True when the backing store is on ZFS and can share native ARC buffers.
    #[must_use = "native block cloning is only valid on a compatible ZFS dataset"]
    pub const fn uses_native_zfs(&self) -> bool {
        matches!(self.physical_encoding, BlobEncoding::Raw)
    }

    #[cfg(target_os = "linux")]
    /// Check whether a build can use native block cloning on this store.
    ///
    /// # Errors
    /// Returns an error when native ZFS and scratch are on different datasets.
    pub fn can_clone_into(&self, scratch: &Path) -> Result<bool> {
        if !self.uses_native_zfs() {
            return Ok(false);
        }
        ensure!(
            is_native_zfs(scratch)?
                && fs::metadata(scratch)?.dev() == fs::metadata(&self.inner.root)?.dev(),
            "native ZFS CAS and sandbox scratch must be on the same ZFS dataset for block cloning"
        );
        Ok(true)
    }

    /// Stage generated content in the backing filesystem's preferred format.
    ///
    /// # Errors
    /// Returns an error if the stream or filesystem fails.
    pub fn stage(&self, reader: impl Read) -> Result<StagedBlob> {
        self.stage_local_inner(reader, None)
    }

    fn stage_local_inner(&self, reader: impl Read, bound: Option<u64>) -> Result<StagedBlob> {
        match self.physical_encoding {
            BlobEncoding::Raw => self.stage_inner(reader, bound),
            BlobEncoding::ZstdChunks => self.stage_compressed_inner(reader, bound),
        }
    }

    // Original upstream package archives retain their exact bytes.
    // Size is an upper bound, not a substitute for digest/length validation.
    fn stage_inner(&self, mut reader: impl Read, bound: Option<u64>) -> Result<StagedBlob> {
        let mut budget = space::StageBudget::new(self);
        if let Some(bound) = bound {
            budget.grow_to(bound)?;
        }

        let mut file = NamedTempFile::new_in(self.inner.root.join("staging"))?;
        let mut hash = blake3::Hasher::new();
        let mut buffer = vec![0; 64 * 1024];
        let mut size = 0_u64;
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    let bytes = &buffer[..count];
                    size = size
                        .checked_add(u64::try_from(count)?)
                        .context("blob length overflow")?;
                    if let Some(bound) = bound {
                        ensure!(size <= bound, "native staged stream exceeds upper bound");
                    } else {
                        // Grow unknown-length streams in 4 MiB increments.
                        const CHUNK: u64 = 4 * 1024 * 1024;
                        budget.grow_to(
                            size.div_ceil(CHUNK)
                                .checked_mul(CHUNK)
                                .context("staging budget overflow")?,
                        )?;
                    }
                    file.write_all(bytes)?;
                    hash.update(bytes);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        // The inode metadata is not part of the blob identity; callers
        // apply the manifest's mode to copies/materialized outputs.
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        file.as_file().sync_all()?;
        let metadata = file.as_file().metadata()?;
        Ok(StagedBlob {
            path: file.into_temp_path(),
            metadata,
            reference: BlobRef {
                id: ContentId(*hash.finalize().as_bytes()),
                size,
            },
            encoding: BlobEncoding::Raw,
            owner: Arc::clone(&self.inner),
        })
    }

    // Reserve the raw upper bound even though actual physical storage is compressed.
    // This preserves the managed store's conservative allocation policy.
    pub(crate) fn stage_compressed_inner(
        &self,
        reader: impl Read,
        bound: Option<u64>,
    ) -> Result<StagedBlob> {
        let mut budget = space::StageBudget::new(self);
        if let Some(bound) = bound {
            budget.grow_to(bound)?;
        }
        let mut staged = NamedTempFile::new_in(self.inner.root.join("staging"))?;
        let reference = blob_codec::encode(
            ReservingReader {
                source: reader,
                budget: &mut budget,
                seen: 0,
                bounded: bound.is_some(),
            },
            staged.as_file_mut(),
            bound,
        )?;
        staged
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        staged.as_file().sync_all()?;
        let metadata = staged.as_file().metadata()?;
        Ok(StagedBlob {
            path: staged.into_temp_path(),
            metadata,
            reference,
            encoding: BlobEncoding::ZstdChunks,
            owner: Arc::clone(&self.inner),
        })
    }

    /// Verify incoming physical content and retain it in the local backend's
    /// format. ZFS stores plaintext; non-ZFS stores independently compressed
    /// chunks. Logical IDs are always checked against decoded bytes.
    ///
    /// # Errors
    /// Returns an error for corruption, truncation or unexpected content.
    pub fn stage_expected_physical(
        &self,
        expected: BlobRef,
        encoding: BlobEncoding,
        reader: impl Read,
    ) -> Result<StagedBlob> {
        // Convert physical storage at ingress, instead of persisting the
        // sender's encoding on an incompatible backing filesystem.
        if self.physical_encoding == BlobEncoding::ZstdChunks && encoding == BlobEncoding::Raw {
            let mut original = tempfile::tempfile_in(self.inner.root.join("staging"))?;
            blob_codec::transfer(reader, io::sink(), &mut original, expected, encoding)?;
            original.rewind()?;
            let staged = self.stage_compressed_inner(original, Some(expected.size))?;
            ensure!(
                staged.reference == expected,
                "CAS re-encoding digest mismatch"
            );
            return Ok(staged);
        }
        let mut budget = space::StageBudget::new(self);
        budget.grow_to(expected.size)?;
        let mut staged = NamedTempFile::new_in(self.inner.root.join("staging"))?;
        if self.physical_encoding == encoding {
            blob_codec::transfer(reader, staged.as_file_mut(), io::sink(), expected, encoding)?;
        } else {
            // ZFS receives compressed content, but stores decoded ordinary files.
            blob_codec::transfer(reader, io::sink(), staged.as_file_mut(), expected, encoding)?;
        }
        staged
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        staged.as_file().sync_all()?;
        let metadata = staged.as_file().metadata()?;
        Ok(StagedBlob {
            path: staged.into_temp_path(),
            metadata,
            reference: expected,
            encoding: self.physical_encoding,
            owner: Arc::clone(&self.inner),
        })
    }

    /// Stage an advertised blob, rejecting short, long or wrong-content streams.
    /// The length bounds the amount read even if the sender never ends input.
    ///
    /// # Errors
    /// Returns an error for an invalid stream, digest/length mismatch or I/O failure.
    pub fn stage_expected(&self, expected: BlobRef, reader: impl Read) -> Result<StagedBlob> {
        let limit = expected
            .size
            .checked_add(1)
            .context("blob length overflow")?;
        let staged = self.stage_local_inner(reader.take(limit), Some(limit))?;
        ensure!(
            staged.reference() == expected,
            "uploaded content does not match its declared digest and length"
        );
        Ok(staged)
    }

    /// Reserve already present content during missing-blob negotiation.
    /// Uploads can wait outside the mutation lock while eviction defers
    /// deletion of their reserved content.
    ///
    /// # Errors
    /// Returns an error for malformed manifests, inconsistent metadata or I/O.
    pub fn reserve_upload(&self, manifest: &ResultManifest) -> Result<UploadReservation> {
        self.reserve_blobs(manifest.blobs()?)
    }

    fn reserve_blobs(&self, blobs: BTreeMap<ContentId, u64>) -> Result<UploadReservation> {
        let _mutation = self.inner.lock_mutations()?;
        let read = self.inner.db.begin_read()?;
        let live = read.open_table(BLOBS)?;
        let pending = read.open_table(PENDING_DELETIONS)?;
        let mut missing = Vec::new();
        let mut reserved = Vec::new();
        for (id, size) in blobs {
            let live_size = live.get(&id.0)?.map(|entry| entry.value());
            let pending_size = pending.get(&id.0)?.map(|entry| entry.value());
            if let Some(indexed_size) = live_size.or(pending_size) {
                ensure!(indexed_size == size, "inconsistent indexed content length");
                if live_size.is_some() {
                    self.inner.check_blob(id, size)?;
                    reserved.push(id);
                } else if self.inner.check_blob(id, size).is_ok() {
                    reserved.push(id);
                } else {
                    missing.push(BlobRef { id, size });
                }
            } else {
                missing.push(BlobRef { id, size });
            }
        }
        let mut pins = self.inner.lock_pins()?;
        // Validate every count before changing any pin.
        pins.reserve_content(reserved.iter())?;
        drop(pins);
        Ok(UploadReservation {
            inner: Arc::clone(&self.inner),
            reserved,
            missing,
        })
    }

    /// Atomically publish a successful result. All newly referenced blobs must
    /// be staged; blobs already in the store can be referenced without upload.
    ///
    /// The same action and result is idempotent. A different result requires
    /// explicit refresh mode; a failed refresh leaves the prior action intact.
    ///
    /// # Errors
    /// Returns an error for conflicting actions, missing or inconsistent content,
    /// filesystem or transactional metadata failures.
    pub fn publish(
        &self,
        fingerprint: &ActionFingerprint,
        manifest: &ResultManifest,
        staged: Vec<StagedBlob>,
        mode: ActionMode,
    ) -> Result<Published> {
        let _mutation = self.inner.lock_mutations()?;
        self.publish_locked(fingerprint, manifest, staged, mode)
    }

    /// Publish and pin the resulting action before eviction can remove it.
    ///
    /// # Errors
    /// Returns an error for invalid results, missing content or storage failure.
    pub fn publish_pinned(
        &self,
        fingerprint: &ActionFingerprint,
        manifest: &ResultManifest,
        staged: Vec<StagedBlob>,
        mode: ActionMode,
    ) -> Result<ResultLease> {
        let _mutation = self.inner.lock_mutations()?;
        let published = self.publish_locked(fingerprint, manifest, staged, mode)?;
        self.lookup(published.action)?
            .context("committed result missing")
    }

    fn publish_locked(
        &self,
        fingerprint: &ActionFingerprint,
        manifest: &ResultManifest,
        staged: Vec<StagedBlob>,
        mode: ActionMode,
    ) -> Result<Published> {
        let action = fingerprint.key()?;
        let result = manifest.id()?;
        let blobs = manifest.blobs()?;
        let staged = self.prepare_staging(&blobs, staged)?;
        let write = self.inner.db.begin_write()?;
        let new_action;
        {
            let mut actions = write.open_table(ACTIONS)?;
            let mut results = write.open_table(RESULTS)?;
            let mut result_actions = write.open_multimap_table(RESULT_ACTIONS)?;
            let previous = actions
                .get(&action.0)?
                .map(|value| encoding().deserialize::<ActionRecord>(value.value()))
                .transpose()?;
            new_action = previous.is_none();
            if let Some(stored) = &previous {
                ensure!(
                    stored.fingerprint == *fingerprint,
                    "conflicting native action fingerprint"
                );
                if stored.result == result {
                    for (&id, &size) in &blobs {
                        self.inner.check_blob(id, size)?;
                    }
                    self.inner.lock_pins()?.touch(space::Root::Action(action));
                    return Ok(Published {
                        action,
                        result,
                        new_action: false,
                    });
                }
                ensure!(
                    mode == ActionMode::Refresh,
                    "conflicting result for action {action:?}"
                );
            }
            let existing_result = if let Some(stored) = results.get(&result.0)? {
                let stored: ResultManifest = encoding().deserialize(stored.value())?;
                ensure!(stored == *manifest, "conflicting native result manifest");
                true
            } else {
                false
            };
            self.attach_blobs(&write, &result.0, &blobs, staged, existing_result)?;
            if !existing_result {
                let bytes = encoding().serialize(manifest)?;
                results.insert(&result.0, bytes.as_slice())?;
            }
            let record = ActionRecord {
                fingerprint: fingerprint.clone(),
                result,
            };
            let bytes = encoding().serialize(&record)?;
            actions.insert(&action.0, bytes.as_slice())?;
            result_actions.insert(&result.0, &action.0)?;
            if let Some(previous) = previous {
                Self::release_result_reference(
                    &write,
                    &mut results,
                    &mut result_actions,
                    action,
                    previous.result,
                )?;
            }
        }
        // Files and their directory entries are durable before the index
        // exposes them. Orphans from an interrupted write are harmless.
        write.commit()?;
        self.inner.lock_pins()?.touch(space::Root::Action(action));
        Ok(Published {
            action,
            result,
            new_action,
        })
    }

    fn prepare_staging(
        &self,
        blobs: &BTreeMap<ContentId, u64>,
        staged: Vec<StagedBlob>,
    ) -> Result<BTreeMap<ContentId, StagedBlob>> {
        ensure!(
            staged
                .iter()
                .all(|blob| Arc::ptr_eq(&blob.owner, &self.inner)),
            "staged content belongs to a different store"
        );
        let staged: BTreeMap<_, _> = staged
            .into_iter()
            .map(|blob| (blob.reference.id, blob))
            .collect();
        ensure!(
            staged.keys().all(|id| blobs.contains_key(id)),
            "unreferenced staged content"
        );
        Ok(staged)
    }

    fn attach_blobs(
        &self,
        write: &WriteTransaction,
        root: &[u8; 32],
        blobs: &BTreeMap<ContentId, u64>,
        mut staged: BTreeMap<ContentId, StagedBlob>,
        existing_result: bool,
    ) -> Result<()> {
        let mut blob_table = write.open_table(BLOBS)?;
        let mut layouts = write.open_table(BLOB_LAYOUTS)?;
        let mut blob_roots = write.open_multimap_table(BLOB_ROOTS)?;
        let mut pending = write.open_table(PENDING_DELETIONS)?;
        let mut accounting = write.open_table(ACCOUNTING)?;
        let mut resurrected = Vec::new();
        for (&id, &size) in blobs {
            if let Some(existing_size) = blob_table.get(&id.0)?.map(|entry| entry.value()) {
                ensure!(existing_size == size, "content length mismatch for {id:?}");
                self.inner.check_blob(id, size)?;
            } else {
                ensure!(!existing_result, "indexed result is missing content {id:?}");
                if let Some(old_size) = pending.get(&id.0)?.map(|entry| entry.value()) {
                    ensure!(
                        old_size == size,
                        "pending content length mismatch for {id:?}"
                    );
                    if self.inner.check_blob(id, size).is_ok() {
                        resurrected.push(id);
                        continue;
                    }
                }
                let blob = staged
                    .get(&id)
                    .with_context(|| format!("missing staged content {id:?}"))?;
                ensure!(
                    blob.reference.size == size,
                    "staged length mismatch for {id:?}"
                );
            }
        }
        let mut added = 0_u64;
        let mut pending_removed = 0_u64;
        let mut directories = BTreeSet::new();
        for (&id, &size) in blobs {
            if blob_table.get(&id.0)?.is_none() {
                if resurrected.binary_search(&id).is_err() {
                    let blob = staged
                        .remove(&id)
                        .context("validated staged content disappeared")?;
                    let encoding = blob.encoding;
                    self.inner.install_blob(blob, &mut directories)?;
                    ensure!(
                        layouts.insert(&id.0, encoding as u8)?.is_none(),
                        "physical encoding already indexed for new CAS content"
                    );
                }
                blob_table.insert(&id.0, size)?;
                added = added.checked_add(size).context("store size overflow")?;
                if let Some(old) = pending.remove(&id.0)? {
                    pending_removed = pending_removed
                        .checked_add(old.value())
                        .context("pending GC size overflow")?;
                }
            }
            if !existing_result {
                blob_roots.insert(&id.0, root)?;
            }
        }
        if added != 0 {
            let previous = accounting
                .get(LIVE_BYTES)?
                .context("missing live accounting")?
                .value();
            accounting.insert(
                LIVE_BYTES,
                previous.checked_add(added).context("store size overflow")?,
            )?;
        }
        if pending_removed != 0 {
            let previous = accounting
                .get(PENDING_BYTES)?
                .context("missing pending accounting")?
                .value();
            accounting.insert(
                PENDING_BYTES,
                previous
                    .checked_sub(pending_removed)
                    .context("pending GC size underflow")?,
            )?;
        }
        // Every staged inode was synced before admission. Sync each affected
        // shard once, before the transaction exposes any of its content.
        for directory in directories.iter().rev() {
            File::open(directory)?.sync_all()?;
        }
        Ok(())
    }

    /// Acquire a result lease, pinning its action and all referenced content.
    ///
    /// # Errors
    /// Returns an error for corrupt metadata, missing blobs or I/O failure.
    pub fn lookup(&self, action: ActionKey) -> Result<Option<ResultLease>> {
        let mut pins = self.inner.lock_pins()?;
        let read = self.inner.db.begin_read()?;
        let actions = read.open_table(ACTIONS)?;
        let Some(record) = actions.get(&action.0)? else {
            return Ok(None);
        };
        let record: ActionRecord = encoding().deserialize(record.value())?;
        ensure!(
            record.fingerprint.key()? == action,
            "invalid indexed action fingerprint"
        );
        let results = read.open_table(RESULTS)?;
        let manifest = results
            .get(&record.result.0)?
            .context("missing indexed result")?;
        let manifest: ResultManifest = encoding().deserialize(manifest.value())?;
        ensure!(
            manifest.id()? == record.result,
            "invalid indexed result manifest"
        );
        let blobs = manifest.blobs()?;
        for (&id, &size) in &blobs {
            self.inner.check_blob(id, size)?;
        }
        let count = pins
            .actions
            .get(&action)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .context("action pin count overflow")?;
        // A refresh can retire the old result while its delivery lease
        // survives. Pin its content independently of the action mapping.
        pins.reserve_content(blobs.keys())?;
        pins.actions.insert(action, count);
        pins.touch(space::Root::Action(action));
        drop(pins);
        Ok(Some(ResultLease {
            inner: Arc::clone(&self.inner),
            action,
            manifest,
            blobs,
        }))
    }

    /// Find all actions that yielded the same complete result, retaining their
    /// semantic input fingerprints for differential cache-key analysis.
    ///
    /// # Errors
    /// Returns an error for unreadable or inconsistent metadata.
    pub fn equivalent_actions(
        &self,
        result: ResultId,
    ) -> Result<Vec<(ActionKey, ActionFingerprint)>> {
        let read = self.inner.db.begin_read()?;
        let aliases = read.open_multimap_table(RESULT_ACTIONS)?;
        let actions = read.open_table(ACTIONS)?;
        aliases
            .get(&result.0)?
            .map(|entry| {
                let key = ActionKey(*entry?.value());
                let record = actions.get(&key.0)?.context("missing indexed action")?;
                let record: ActionRecord = encoding().deserialize(record.value())?;
                ensure!(record.result == result, "inconsistent result reverse index");
                Ok((key, record.fingerprint))
            })
            .collect()
    }

    /// Remove one action, then reclaim only results and blobs whose last
    /// reference disappeared. Active leases prevent eviction of their action.
    ///
    /// # Errors
    /// Returns an error for inconsistent metadata or storage failures.
    pub fn evict(&self, action: ActionKey) -> Result<Eviction> {
        let _mutation = self.inner.lock_mutations()?;
        let mut pins = self.inner.lock_pins()?;
        if pins.actions.contains_key(&action) {
            return Ok(Eviction::Pinned);
        }
        let write = self.inner.db.begin_write()?;
        let unreferenced_logical_bytes;
        {
            let mut actions = write.open_table(ACTIONS)?;
            let mut results = write.open_table(RESULTS)?;
            let mut result_actions = write.open_multimap_table(RESULT_ACTIONS)?;
            let Some(record) = actions.remove(&action.0)? else {
                return Ok(Eviction::Missing);
            };
            let record: ActionRecord = encoding().deserialize(record.value())?;
            unreferenced_logical_bytes = Self::release_result_reference(
                &write,
                &mut results,
                &mut result_actions,
                action,
                record.result,
            )?;
        }
        // Durable deletion intent precedes physical deletion. The collector
        // can batch work and retry failures without scanning the live store.
        write.commit()?;
        // Lookup and eviction must serialize until removal is committed.
        pins.last_used.remove(&space::Root::Action(action));
        drop(pins);
        Ok(Eviction::Removed {
            unreferenced_logical_bytes,
        })
    }

    fn release_result_reference(
        write: &WriteTransaction,
        results: &mut redb::Table<'_, &[u8; 32], &[u8]>,
        aliases: &mut redb::MultimapTable<'_, &[u8; 32], &[u8; 32]>,
        action: ActionKey,
        result: ResultId,
    ) -> Result<u64> {
        ensure!(
            aliases.remove(&result.0, &action.0)?,
            "missing result reverse reference"
        );
        if aliases.get(&result.0)?.next().transpose()?.is_some() {
            return Ok(0);
        }
        let manifest = results
            .remove(&result.0)?
            .context("missing indexed result")?;
        let manifest: ResultManifest = encoding().deserialize(manifest.value())?;
        Self::detach_blobs(write, &result.0, manifest.blobs()?)
    }

    fn detach_blobs(
        write: &WriteTransaction,
        root: &[u8; 32],
        blobs: BTreeMap<ContentId, u64>,
    ) -> Result<u64> {
        let mut blob_table = write.open_table(BLOBS)?;
        let mut blob_roots = write.open_multimap_table(BLOB_ROOTS)?;
        let mut pending = write.open_table(PENDING_DELETIONS)?;
        let mut accounting = write.open_table(ACCOUNTING)?;
        let mut unreferenced_logical_bytes = 0_u64;
        for (id, size) in blobs {
            ensure!(
                blob_roots.remove(&id.0, root)?,
                "missing blob reverse reference"
            );
            if blob_roots.get(&id.0)?.next().transpose()?.is_none() {
                let indexed_size = blob_table.remove(&id.0)?.context("missing indexed blob")?;
                ensure!(
                    indexed_size.value() == size,
                    "inconsistent indexed blob length"
                );
                ensure!(
                    pending.insert(&id.0, size)?.is_none(),
                    "live blob already pending deletion"
                );
                unreferenced_logical_bytes = unreferenced_logical_bytes
                    .checked_add(size)
                    .context("unreferenced size overflow")?;
            }
        }
        if unreferenced_logical_bytes != 0 {
            let live = accounting
                .get(LIVE_BYTES)?
                .context("missing live accounting")?
                .value();
            let queued = accounting
                .get(PENDING_BYTES)?
                .context("missing pending accounting")?
                .value();
            accounting.insert(
                LIVE_BYTES,
                live.checked_sub(unreferenced_logical_bytes)
                    .context("store size underflow")?,
            )?;
            accounting.insert(
                PENDING_BYTES,
                queued
                    .checked_add(unreferenced_logical_bytes)
                    .context("pending GC size overflow")?,
            )?;
        }
        Ok(unreferenced_logical_bytes)
    }

    /// Reclaim up to `limit` unreferenced content files. Active upload and
    /// result-delivery reservations protect their content from deletion.
    ///
    /// # Errors
    /// Returns an error for database failures; per-file failures remain queued
    /// and are reported in the collection result.
    pub fn collect_garbage(&self, limit: usize) -> Result<GarbageCollected> {
        let _mutation = self.inner.lock_mutations()?;
        let pins = self.inner.lock_pins()?;
        let read = self.inner.db.begin_read()?;
        let pending = read.open_table(PENDING_DELETIONS)?;
        let mut candidates = Vec::new();
        for entry in pending.iter()? {
            if candidates.len() >= limit {
                break;
            }
            let (id, size) = entry?;
            let id = ContentId(*id.value());
            if !pins.blobs.contains_key(&id) {
                candidates.push((id, size.value()));
            }
        }
        drop(pending);
        drop(read);
        // A new upload reservation requires the mutation lock. Committed
        // result readers cannot acquire new pins on pending-only content.
        drop(pins);
        let mut completed = Vec::new();
        let mut failed = Vec::new();
        let mut logical_bytes = 0_u64;
        for (id, size) in candidates {
            match self.inner.remove_blob(id) {
                Ok(()) => {
                    completed.push(id);
                    logical_bytes = logical_bytes
                        .checked_add(size)
                        .context("GC size overflow")?;
                }
                Err(error) => {
                    log::warn!("could not reclaim native content {id:?}: {error:#}");
                    failed.push(id);
                }
            }
        }
        if !completed.is_empty() {
            let write = self.inner.db.begin_write()?;
            {
                let mut pending = write.open_table(PENDING_DELETIONS)?;
                let mut layouts = write.open_table(BLOB_LAYOUTS)?;
                let mut accounting = write.open_table(ACCOUNTING)?;
                for id in &completed {
                    ensure!(pending.remove(&id.0)?.is_some(), "missing pending deletion");
                    ensure!(
                        layouts.remove(&id.0)?.is_some(),
                        "missing physical encoding for removed blob"
                    );
                }
                let queued = accounting
                    .get(PENDING_BYTES)?
                    .context("missing pending accounting")?
                    .value();
                accounting.insert(
                    PENDING_BYTES,
                    queued
                        .checked_sub(logical_bytes)
                        .context("pending GC size underflow")?,
                )?;
            }
            write.commit()?;
        }
        Ok(GarbageCollected {
            blobs: u64::try_from(completed.len())?,
            logical_bytes,
            failed,
        })
    }

    /// Return logical accounting from a consistent index snapshot.
    ///
    /// # Errors
    /// Returns an error for metadata failures or a size overflow.
    pub fn stats(&self) -> Result<CacheStats> {
        let read = self.inner.db.begin_read()?;
        let actions = read.open_table(ACTIONS)?;
        let results = read.open_table(RESULTS)?;
        let blobs = read.open_table(BLOBS)?;
        let pending = read.open_table(PENDING_DELETIONS)?;
        let accounting = read.open_table(ACCOUNTING)?;
        Ok(CacheStats {
            actions: actions.len()?,
            results: results.len()?,
            trees: read.open_table(TREES)?.len()?,
            blobs: blobs.len()?,
            logical_bytes: accounting
                .get(LIVE_BYTES)?
                .context("missing live accounting")?
                .value(),
            pending_gc_blobs: pending.len()?,
            pending_gc_bytes: accounting
                .get(PENDING_BYTES)?
                .context("missing pending accounting")?
                .value(),
        })
    }
}

/// Missing-blob negotiation lease. Keep it alive until publication or
/// cancellation; dropping it releases the content reservations.
pub struct UploadReservation {
    inner: Arc<Inner>,
    reserved: Vec<ContentId>,
    missing: Vec<BlobRef>,
}

impl UploadReservation {
    #[must_use = "missing blobs must be uploaded before publication"]
    pub fn missing(&self) -> &[BlobRef] {
        &self.missing
    }
}

impl Drop for UploadReservation {
    fn drop(&mut self) {
        match self.inner.lock_pins() {
            Ok(mut pins) => {
                for id in &self.reserved {
                    release_pin(&mut pins.blobs, id);
                }
            }
            Err(error) => {
                log::error!("could not release native store upload reservation: {error:#}");
            }
        }
    }
}

/// A snapshot of a result whose content cannot be evicted during consumption.
pub struct ResultLease {
    inner: Arc<Inner>,
    action: ActionKey,
    manifest: ResultManifest,
    blobs: BTreeMap<ContentId, u64>,
}

impl ResultLease {
    #[must_use = "the manifest identifies the leased result"]
    pub const fn manifest(&self) -> &ResultManifest {
        &self.manifest
    }

    /// Open a file for transport. Its inode remains valid after unlinking,
    /// so a response can own it independently of this lease.
    ///
    /// # Errors
    /// Returns an error for undeclared content or filesystem failure.
    pub fn open_file(&self, id: ContentId) -> Result<File> {
        self.inner.open_declared(&self.blobs, id)
    }

    /// The immutable physical CAS encoding of a declared result blob.
    ///
    /// # Errors
    /// Returns an error for undeclared content or missing index metadata.
    pub fn physical_encoding(&self, id: ContentId) -> Result<BlobEncoding> {
        ensure!(self.blobs.contains_key(&id), "undeclared result content");
        self.inner.blob_encoding(id)
    }

    /// Open a blob belonging to this result. The reader borrows the lease and
    /// cannot outlive the corresponding eviction pin.
    ///
    /// # Errors
    /// Returns an error for an undeclared blob or filesystem failure.
    pub fn open_blob(&self, id: ContentId) -> Result<impl Read + Seek + '_> {
        Ok(LeasedReader {
            file: BlobReader::open(self.open_file(id)?, self.inner.blob_encoding(id)?)?,
            _lease: self,
        })
    }
}

impl Drop for ResultLease {
    fn drop(&mut self) {
        match self.inner.lock_pins() {
            Ok(mut pins) => {
                release_pin(&mut pins.actions, &self.action);
                for id in self.blobs.keys() {
                    release_pin(&mut pins.blobs, id);
                }
            }
            Err(error) => log::error!("could not release native store result lease: {error:#}"),
        }
    }
}

struct LeasedReader<'a, L> {
    file: BlobReader,
    _lease: &'a L,
}

impl<L> Read for LeasedReader<'_, L> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl<L> Seek for LeasedReader<'_, L> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

mod space;
use crate::SpacePolicy;
pub use space::SpaceReport;
mod audit;
pub use audit::{ComponentAudit, NativeIndexAudit, SchemaInventory};
mod packages;
pub use packages::{
    PackageArchiveLease, PackageDecoder, PackageImportLimits, PackagePolicy, PackageSlot,
    VerifiedPackage, decode_package_process,
};
mod trees;
pub use trees::TreeLease;
#[cfg(target_os = "linux")]
pub use trees::{MaterializationStats, MaterializedTree, MountedTree};

#[cfg(test)]
mod tests;
