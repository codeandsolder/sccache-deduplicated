//! Read-only virtual trees backed directly by independently compressed CAS objects.
//! A Bubblewrap worker receives a normal filesystem without persistent expanded copies.
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};
use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    LockOwner, MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, Request, Session, SessionUnmounter,
};
use rustix::fs::{AtFlags, CWD, Timestamps, ioctl_ficlone, utimensat};
use rustix::time::Timespec;
use tempfile::TempDir;

use super::{TreeLease, materialize::OverlayFiles};
use crate::{BlobReader, BlobRef, TreeEntry, TreeManifest, TreeMetadata, TreePath, TreeTimestamp};
use crate::{MaterializationStats, MaterializedTree};

const TTL: Duration = Duration::from_secs(3600);

enum Kind {
    Directory(BTreeMap<OsString, INodeNo>),
    File(BlobRef),
    Symlink(Vec<u8>),
}

struct Node {
    kind: Kind,
    metadata: TreeMetadata,
    parent: INodeNo,
    nlink: u32,
}

struct OpenHandles {
    next: u64,
    readers: BTreeMap<FileHandle, Arc<Mutex<BlobReader>>>,
}

struct VirtualFs {
    lease: TreeLease,
    nodes: Vec<Node>,
    handles: Mutex<OpenHandles>,
    uid: u32,
    gid: u32,
}

impl VirtualFs {
    fn new(lease: TreeLease) -> Result<Self> {
        let root = lease.manifest().root;
        let mut nodes = vec![Node {
            kind: Kind::Directory(BTreeMap::new()),
            metadata: root,
            parent: INodeNo::ROOT,
            nlink: 2,
        }];
        let mut paths = BTreeMap::from([(Vec::new(), INodeNo::ROOT)]);
        for (path, entry) in &lease.manifest().entries {
            if matches!(entry, TreeEntry::Hardlink(_)) {
                continue;
            }
            let bytes = path.as_bytes();
            let cut = bytes.iter().rposition(|&b| b == b'/');
            let (parent_path, name) =
                cut.map_or_else(|| (&b""[..], bytes), |n| (&bytes[..n], &bytes[n + 1..]));
            let parent = *paths
                .get(parent_path)
                .context("missing FUSE parent directory")?;
            let (kind, metadata) = match entry {
                TreeEntry::Directory(meta) => (Kind::Directory(BTreeMap::new()), *meta),
                TreeEntry::File { blob, metadata } => (Kind::File(*blob), *metadata),
                TreeEntry::Symlink { target, modified } => (
                    Kind::Symlink(target.clone()),
                    TreeMetadata {
                        mode: 0o777,
                        modified: *modified,
                    },
                ),
                TreeEntry::Hardlink(_) => unreachable!("hardlinks handled in second pass"),
            };
            let ino = INodeNo(u64::try_from(nodes.len())? + 1);
            let is_dir = matches!(&kind, Kind::Directory(_));
            nodes.push(Node {
                kind,
                metadata,
                parent,
                nlink: if is_dir { 2 } else { 1 },
            });
            let parent_node = &mut nodes[usize::try_from(parent.0 - 1)?];
            let Kind::Directory(children) = &mut parent_node.kind else {
                anyhow::bail!("FUSE parent is not a directory");
            };
            ensure!(
                children
                    .insert(OsStr::from_bytes(name).to_owned(), ino)
                    .is_none(),
                "duplicate FUSE child"
            );
            if is_dir {
                parent_node.nlink = parent_node
                    .nlink
                    .checked_add(1)
                    .context("FUSE directory link count overflow")?;
            }
            paths.insert(bytes.to_vec(), ino);
        }
        for (path, entry) in &lease.manifest().entries {
            let TreeEntry::Hardlink(target) = entry else {
                continue;
            };
            let bytes = path.as_bytes();
            let cut = bytes.iter().rposition(|&b| b == b'/');
            let (parent_path, name) =
                cut.map_or_else(|| (&b""[..], bytes), |n| (&bytes[..n], &bytes[n + 1..]));
            let parent = *paths
                .get(parent_path)
                .context("missing FUSE hardlink parent")?;
            let ino = *paths
                .get(target.as_bytes())
                .context("missing FUSE hardlink target")?;
            let Kind::File(_) = nodes[usize::try_from(ino.0 - 1)?].kind else {
                anyhow::bail!("hardlink targets must be regular files");
            };
            let target = &mut nodes[usize::try_from(ino.0 - 1)?];
            target.nlink = target
                .nlink
                .checked_add(1)
                .context("FUSE file link count overflow")?;
            let Kind::Directory(children) = &mut nodes[usize::try_from(parent.0 - 1)?].kind else {
                anyhow::bail!("FUSE hardlink parent is not a directory");
            };
            ensure!(
                children
                    .insert(OsStr::from_bytes(name).to_owned(), ino)
                    .is_none(),
                "duplicate FUSE hardlink"
            );
        }
        Ok(Self {
            lease,
            nodes,
            handles: Mutex::new(OpenHandles {
                next: 1,
                readers: BTreeMap::new(),
            }),
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
        })
    }

    fn node(&self, ino: INodeNo) -> Option<&Node> {
        self.nodes.get(usize::try_from(ino.0.checked_sub(1)?).ok()?)
    }

    fn attr(&self, ino: INodeNo) -> Result<FileAttr> {
        let node = self.node(ino).context("missing virtual inode")?;
        let (kind, size) = match &node.kind {
            Kind::Directory(_) => (FileType::Directory, 0),
            Kind::File(blob) => (FileType::RegularFile, blob.size),
            Kind::Symlink(target) => (FileType::Symlink, target.len() as u64),
        };
        let time = timestamp(node.metadata.modified)?;
        Ok(FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind,
            perm: u16::try_from(node.metadata.mode & 0o777)?,
            nlink: node.nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        })
    }
}

fn timestamp(ts: TreeTimestamp) -> Result<SystemTime> {
    let sec = Duration::from_secs(ts.seconds.unsigned_abs());
    let nanos = Duration::from_nanos(u64::from(ts.nanoseconds));
    let t = if ts.seconds < 0 {
        SystemTime::UNIX_EPOCH
            .checked_sub(sec)
            .and_then(|time| time.checked_add(nanos))
    } else {
        SystemTime::UNIX_EPOCH
            .checked_add(sec)
            .and_then(|time| time.checked_add(nanos))
    };
    t.context("FUSE timestamp overflow")
}

impl Filesystem for VirtualFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let found = self.node(parent).and_then(|node| match &node.kind {
            Kind::Directory(children) => children.get(name).copied(),
            _ => None,
        });
        match found.and_then(|ino| self.attr(ino).ok()) {
            Some(attr) => reply.entry(&TTL, &attr, Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.attr(ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(_) => reply.error(Errno::ENOENT),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match self.node(ino).map(|node| &node.kind) {
            Some(Kind::Symlink(target)) => reply.data(target),
            _ => reply.error(Errno::EINVAL),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(node) = self.node(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Kind::Directory(children) = &node.kind else {
            reply.error(Errno::ENOTDIR);
            return;
        };
        // Avoid cloning every filename on each directory page.
        let Ok(offset) = usize::try_from(offset) else {
            reply.error(Errno::EOVERFLOW);
            return;
        };
        if offset == 0 && reply.add(ino, 1, FileType::Directory, OsStr::new(".")) {
            reply.ok();
            return;
        }
        if offset <= 1 && reply.add(node.parent, 2, FileType::Directory, OsStr::new("..")) {
            reply.ok();
            return;
        }
        for (idx, (name, &child)) in children.iter().enumerate().skip(offset.saturating_sub(2)) {
            let kind = match self.node(child).map(|node| &node.kind) {
                Some(Kind::Directory(_)) => FileType::Directory,
                Some(Kind::File(_)) => FileType::RegularFile,
                Some(Kind::Symlink(_)) => FileType::Symlink,
                None => {
                    reply.error(Errno::EIO);
                    return;
                }
            };
            let Some(cookie) = idx.checked_add(3).and_then(|i| u64::try_from(i).ok()) else {
                reply.error(Errno::EOVERFLOW);
                return;
            };
            if reply.add(child, cookie, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(
        &self,
        _req: &Request,
        ino: INodeNo,
        flags: OpenFlags,
        kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        if flags.0 & (libc::O_ACCMODE | libc::O_TRUNC) != libc::O_RDONLY || kill_suid_gid {
            reply.error(Errno::EROFS);
            return;
        }
        let Some(Kind::File(blob)) = self.node(ino).map(|node| &node.kind) else {
            reply.error(Errno::EISDIR);
            return;
        };
        let path = self.lease.inner.blob_path(blob.id);
        let opened = self
            .lease
            .inner
            .blob_encoding(blob.id)
            .and_then(|encoding| BlobReader::open(File::open(path)?, encoding));
        match opened {
            Ok(reader) => {
                let Ok(mut handles) = self.handles.lock() else {
                    reply.error(Errno::EIO);
                    return;
                };
                let handle = FileHandle(handles.next);
                let Some(next) = handles.next.checked_add(1) else {
                    reply.error(Errno::EMFILE);
                    return;
                };
                handles.next = next;
                handles.readers.insert(handle, Arc::new(Mutex::new(reader)));
                reply.opened(handle, FopenFlags::FOPEN_KEEP_CACHE);
            }
            Err(error) => {
                log::error!("failed to open virtual CAS file: {error:#}");
                reply.error(Errno::EIO);
            }
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        // Only hold the table lock while obtaining the reader. A seek/read
        // pair is atomic per handle; unrelated files can decode independently.
        let reader = match self.handles.lock() {
            Ok(handles) => handles.readers.get(&fh).cloned(),
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        let Some(reader) = reader else {
            reply.error(Errno::EBADF);
            return;
        };
        let Ok(mut reader) = reader.lock() else {
            reply.error(Errno::EIO);
            return;
        };
        let mut out = vec![0; size as usize];
        let result = reader
            .seek(SeekFrom::Start(offset))
            .and_then(|_| reader.read(&mut out));
        match result {
            Ok(n) => reply.data(&out[..n]),
            Err(error) => {
                log::error!("virtual CAS decode failed: {error}");
                reply.error(Errno::EIO);
            }
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let Ok(mut handles) = self.handles.lock() else {
            reply.error(Errno::EIO);
            return;
        };
        handles.readers.remove(&fh);
        reply.ok();
    }
}

/// A pinned immutable tree view. Native ZFS files use ARC directly; other
/// filesystems expose indexed compressed objects through a read-only FUSE mount.
pub enum ReadOnlyView {
    Fuse {
        manifest: TreeManifest,
        unmount: SessionUnmounter,
        thread: Option<JoinHandle<io::Result<()>>>,
        _directory: TempDir,
        mountpoint: PathBuf,
    },
    Zfs {
        lease: TreeLease,
        materialized: MaterializedTree,
    },
}

impl ReadOnlyView {
    pub(crate) fn mount_fuse(lease: TreeLease, parent: &Path) -> Result<Self> {
        let manifest = lease.manifest().clone();
        let filesystem = VirtualFs::new(lease)?;
        let directory = tempfile::Builder::new()
            .prefix("build-fuse-")
            .tempdir_in(parent)?;
        let mountpoint = directory.path().join("root");
        fs::create_dir(&mountpoint)?;
        let mut config = Config::default();
        config.mount_options = vec![
            MountOption::RO,
            MountOption::DefaultPermissions,
            MountOption::FSName("sccache-native-cas".into()),
        ];
        let mut session = Session::new(filesystem, &mountpoint, &config)?;
        let unmount = session.unmount_callable();
        let thread = thread::spawn(move || session.run());
        Ok(Self::Fuse {
            manifest,
            unmount,
            thread: Some(thread),
            _directory: directory,
            mountpoint,
        })
    }

    pub(crate) fn materialize_zfs(lease: TreeLease, parent: &Path) -> Result<Self> {
        // Clone each immutable CAS tree only on its first use. Subsequent
        // actions share this view and expose it only through read-only binds.
        let materialized = lease.materialize(parent)?;
        Ok(Self::Zfs {
            lease,
            materialized,
        })
    }

    pub(crate) const fn manifest(&self) -> &TreeManifest {
        match self {
            Self::Fuse { manifest, .. } => manifest,
            Self::Zfs { lease, .. } => lease.manifest(),
        }
    }

    fn root(&self) -> &Path {
        match self {
            Self::Fuse { mountpoint, .. } => mountpoint,
            Self::Zfs { materialized, .. } => materialized.root(),
        }
    }

    const fn is_zfs(&self) -> bool {
        matches!(self, Self::Zfs { .. })
    }

    fn private_zfs_view(&self, parent: &Path) -> Result<MaterializedTree> {
        let Self::Zfs { lease, .. } = self else {
            anyhow::bail!("private native ZFS materialization requires a ZFS input");
        };
        lease.materialize(parent)
    }

    /// An output region that contains one hardlink but not its other link
    /// cannot be cloned independently without changing POSIX inode identity.
    /// Fall back to one per-action private ZFS tree for that entire layout.
    fn crosses_hardlink_boundary(&self, regions: &[PathBuf]) -> bool {
        let Self::Zfs { lease, .. } = self else {
            return false;
        };
        let region_for = |bytes: &[u8]| {
            let path = Path::new(OsStr::from_bytes(bytes));
            regions
                .iter()
                .position(|region| region.as_os_str().is_empty() || path.starts_with(region))
        };
        lease.manifest().entries.iter().any(|(path, entry)| {
            let TreeEntry::Hardlink(target) = entry else {
                return false;
            };
            region_for(path.as_bytes()) != region_for(target.as_bytes())
        })
    }
}

impl Drop for ReadOnlyView {
    fn drop(&mut self) {
        if let Self::Fuse {
            unmount, thread, ..
        } = self
        {
            if let Err(error) = unmount.unmount() {
                log::warn!("cannot unmount compressed CAS tree: {error}");
            }
            if let Some(thread) = thread.take() {
                match thread.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => log::warn!("compressed CAS FUSE worker failed: {error}"),
                    Err(_) => log::error!("compressed CAS FUSE worker panicked"),
                }
            }
        }
    }
}

/// One immutable view per tree identity, with private `CoW` scratch for each
/// action. Native ZFS shares ARC-backed cloned inodes; non-ZFS shares FUSE.
pub struct MountedTree {
    view: Arc<ReadOnlyView>,
    private_zfs: Option<MaterializedTree>,
    directory: TempDir,
    writable: BTreeMap<PathBuf, PathBuf>,
    scratch_directories: Vec<PathBuf>,
    overlays: Option<OverlayFiles>,
}

impl MountedTree {
    pub(crate) fn from_view(view: Arc<ReadOnlyView>, parent: &Path) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("build-mutable-")
            .tempdir_in(parent)?;
        Ok(Self {
            view,
            private_zfs: None,
            directory,
            writable: BTreeMap::new(),
            scratch_directories: Vec::new(),
            overlays: None,
        })
    }

    #[must_use = "the sandbox must bind the root of the pinned immutable view"]
    pub fn root(&self) -> &Path {
        self.private_zfs
            .as_ref()
            .map_or_else(|| self.view.root(), MaterializedTree::root)
    }

    pub(crate) fn manifest(&self) -> &TreeManifest {
        self.overlays
            .as_ref()
            .map_or_else(|| self.view.manifest(), OverlayFiles::manifest)
    }

    pub(crate) fn attach_overlays(&mut self, overlays: OverlayFiles) {
        self.overlays = Some(overlays);
    }

    pub(crate) fn overlay_bindings(&self) -> impl Iterator<Item = (&TreePath, &Path)> {
        self.overlays.iter().flat_map(|overlay| {
            overlay
                .replacements
                .iter()
                .map(|(path, file)| (path, file.as_path()))
        })
    }

    pub(crate) fn overlay_stats(&self) -> Option<MaterializationStats> {
        self.overlays.as_ref().map(|overlay| overlay.stats)
    }

    /// Build a private output-directory view. ZFS block-clones only the
    /// writable subtree, while non-ZFS copies decoded FUSE content. Hardlink
    /// groups crossing an output binding receive one complete private ZFS view
    /// to preserve POSIX inode identity and write propagation.
    ///
    /// # Errors
    /// Returns an error for invalid directories, clone failure or I/O failure.
    pub fn mark_writable(&mut self, relative: &Path) -> Result<()> {
        if self.writable.contains_key(relative) {
            return Ok(());
        }
        let source = self.root().join(relative);
        ensure!(source.is_dir(), "writable mount source is not a directory");

        let regions = self
            .writable
            .keys()
            .cloned()
            .chain(std::iter::once(relative.to_owned()))
            .collect::<Vec<_>>();
        if self.private_zfs.is_none() && self.view.crosses_hardlink_boundary(&regions) {
            let mut private = self.view.private_zfs_view(self.directory.path())?;
            for existing in self.writable.keys() {
                private.mark_writable(existing);
            }
            private.mark_writable(relative);
            for (existing, value) in &mut self.writable {
                *value = private.root().join(existing);
            }
            self.writable
                .insert(relative.to_owned(), private.root().join(relative));
            self.private_zfs = Some(private);
            return Ok(());
        }

        if let Some(private) = self.private_zfs.as_mut() {
            private.mark_writable(relative);
            self.writable
                .insert(relative.to_owned(), private.root().join(relative));
            return Ok(());
        }

        let scratch = self
            .directory
            .path()
            .join(format!("mutable-{}", self.writable.len()));
        // Track partial scratch trees too, so failures cannot leave mode-000
        // directories behind after cleanup.
        self.scratch_directories.push(scratch.clone());
        let mut links = BTreeMap::new();
        copy_directory(&source, &scratch, &mut links, self.view.is_zfs())?;
        self.writable.insert(relative.to_owned(), scratch);
        Ok(())
    }

    /// Resolve a previously prepared writable mount source.
    ///
    /// # Errors
    /// Returns an error when the writable mount was not declared.
    pub fn writable_path(&self, relative: &Path) -> Result<&Path> {
        self.writable
            .get(relative)
            .map(PathBuf::as_path)
            .context("writable directory not prepared")
    }
}

impl Drop for MountedTree {
    fn drop(&mut self) {
        // Make the private scratch tree traversable before TempDir recursively
        // removes it. Original manifest directories may be mode 000 or 0555.
        for path in &self.scratch_directories {
            crate::tree_fs::restore_mutable_directories(path);
        }
    }
}

fn copy_directory(
    src: &Path,
    dst: &Path,
    links: &mut BTreeMap<(u64, u64), PathBuf>,
    clone_zfs: bool,
) -> Result<()> {
    fs::create_dir(dst)?;
    let src_meta = fs::symlink_metadata(src)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let meta = fs::symlink_metadata(&src_path)?;
        if meta.is_dir() {
            copy_directory(&src_path, &dst_path, links, clone_zfs)?;
        } else if meta.is_symlink() {
            symlink(fs::read_link(&src_path)?, &dst_path)?;
            copy_time(&dst_path, &meta)?;
        } else if meta.is_file() {
            let identity = (meta.dev(), meta.ino());
            if let Some(previous) = links.get(&identity) {
                fs::hard_link(previous, &dst_path)?;
            } else {
                let mut source = File::open(&src_path)?;
                let mut target = File::create(&dst_path)?;
                if clone_zfs {
                    ioctl_ficlone(&target, &source)
                        .context("native ZFS CoW clone failed for writable subtree")?;
                } else {
                    io::copy(&mut source, &mut target)?;
                }
                links.insert(identity, dst_path.clone());
                fs::set_permissions(&dst_path, fs::Permissions::from_mode(meta.mode() & 0o777))?;
                copy_time(&dst_path, &meta)?;
            }
        } else {
            anyhow::bail!("unsupported entry in writable overlay");
        }
    }
    fs::set_permissions(dst, fs::Permissions::from_mode(src_meta.mode() & 0o777))?;
    copy_time(dst, &src_meta)?;
    Ok(())
}

fn copy_time(path: &Path, meta: &fs::Metadata) -> Result<()> {
    let time = Timespec {
        tv_sec: meta.mtime(),
        tv_nsec: meta.mtime_nsec(),
    };
    utimensat(
        CWD,
        path,
        &Timestamps {
            last_access: time,
            last_modification: time,
        },
        AtFlags::SYMLINK_NOFOLLOW,
    )?;
    Ok(())
}

impl TreeLease {
    /// Mount a read-only virtual tree directly over the immutable CAS.
    /// The FUSE filesystem owns this lease, preventing eviction while mounted.
    ///
    /// # Errors
    /// Returns an error when the mount, manifest or filesystem is unavailable.
    pub fn mount_readonly(self, parent: &Path) -> Result<MountedTree> {
        MountedTree::from_view(Arc::new(ReadOnlyView::mount_fuse(self, parent)?), parent)
    }
}

#[cfg(test)]
mod tests {
    use super::super::overlay::compatible_regular_file_overlays;
    use super::*;
    use crate::{Eviction, NativeStore};

    #[test]
    fn file_overlay_compatibility_checks_complete_namespace_topology() -> Result<()> {
        use crate::{BlobRef, ContentId};

        let meta = TreeMetadata {
            mode: 0o755,
            modified: TreeTimestamp {
                seconds: 1,
                nanoseconds: 0,
            },
        };
        let path = |bytes: &[u8]| TreePath::new(bytes.to_vec());
        let file = |bytes: &[u8], metadata| TreeEntry::File {
            blob: BlobRef {
                id: ContentId::of(bytes),
                size: u64::try_from(bytes.len()).expect("test size"),
            },
            metadata,
        };
        let original = TreeManifest {
            root: meta,
            entries: BTreeMap::from([
                (path(b"bin")?, TreeEntry::Directory(meta)),
                (path(b"bin/tool")?, file(b"tool", meta)),
                (
                    path(b"bin/tool-hardlink")?,
                    TreeEntry::Hardlink(path(b"bin/tool")?),
                ),
                (path(b"src")?, TreeEntry::Directory(meta)),
                (path(b"src/header")?, file(b"header", meta)),
                (
                    path(b"src/link")?,
                    TreeEntry::Symlink {
                        target: b"../bin/tool".to_vec(),
                        modified: meta.modified,
                    },
                ),
                (path(b"src/variable")?, file(b"original", meta)),
            ]),
        };
        original.validate()?;
        let mut changed = original.clone();
        changed
            .entries
            .insert(path(b"src/variable")?, file(b"changed", meta));
        assert_eq!(
            compatible_regular_file_overlays(&original, &changed, &[]),
            Some(vec![path(b"src/variable")?])
        );
        // Changing only a regular-file mode or mtime is also safe: its
        // private overlay inode receives those exact target attributes.
        let mut mode_changed = meta;
        mode_changed.mode = 0o700;
        changed
            .entries
            .insert(path(b"src/variable")?, file(b"changed", mode_changed));
        assert_eq!(
            compatible_regular_file_overlays(&original, &changed, &[]),
            Some(vec![path(b"src/variable")?])
        );
        assert!(
            compatible_regular_file_overlays(&original, &changed, &[PathBuf::from("src")])
                .is_none()
        );
        assert!(
            compatible_regular_file_overlays(&original, &changed, &[PathBuf::from("bin")])
                .is_some()
        );

        let mut directory = changed.clone();
        directory
            .entries
            .insert(path(b"src")?, TreeEntry::Directory(mode_changed));
        assert!(compatible_regular_file_overlays(&original, &directory, &[]).is_none());

        let mut symlink = changed.clone();
        symlink.entries.insert(
            path(b"src/link")?,
            TreeEntry::Symlink {
                target: b"../bin/other".to_vec(),
                modified: meta.modified,
            },
        );
        assert!(compatible_regular_file_overlays(&original, &symlink, &[]).is_none());

        let mut removed = changed.clone();
        removed.entries.remove(&path(b"src/header")?);
        assert!(compatible_regular_file_overlays(&original, &removed, &[]).is_none());

        Ok(())
    }

    #[test]
    fn changed_hardlink_targets_require_the_original_inode_group() -> Result<()> {
        use crate::{BlobRef, ContentId};

        let meta = TreeMetadata {
            mode: 0o755,
            modified: TreeTimestamp {
                seconds: 1,
                nanoseconds: 0,
            },
        };
        let path = |bytes: &[u8]| TreePath::new(bytes.to_vec());
        let file = |bytes: &[u8]| TreeEntry::File {
            blob: BlobRef {
                id: ContentId::of(bytes),
                size: bytes.len() as u64,
            },
            metadata: meta,
        };
        let original = TreeManifest {
            root: meta,
            entries: BTreeMap::from([
                (path(b"bin")?, TreeEntry::Directory(meta)),
                (path(b"bin/tool")?, file(b"tool")),
                (path(b"bin/alias")?, TreeEntry::Hardlink(path(b"bin/tool")?)),
            ]),
        };
        original.validate()?;
        let mut changed = original.clone();
        changed
            .entries
            .insert(path(b"bin/tool")?, file(b"new tool"));
        changed.validate()?;
        assert!(
            compatible_regular_file_overlays(&original, &changed, &[]).is_none(),
            "changing the referent of an unchanged hardlink must not split the inode group"
        );
        Ok(())
    }

    #[test]
    fn distinct_regular_file_versions_reuse_pinned_tree_and_isolate_writable_outputs() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let input = temp.path().join("input");
        fs::create_dir_all(input.join("src"))?;
        fs::create_dir_all(input.join("out"))?;
        fs::create_dir_all(input.join("bin"))?;
        fs::write(input.join("src/variable"), b"first version")?;
        fs::write(input.join("bin/tool"), b"immutable tool")?;
        fs::hard_link(input.join("bin/tool"), input.join("bin/alias"))?;
        symlink("../bin/tool", input.join("src/link"))?;
        for index in 0..96 {
            fs::write(
                input.join("src").join(format!("header-{index:03}")),
                b"unchanged header",
            )?;
        }
        let store = NativeStore::open(&temp.path().join("store"))?;
        let first = store.capture_tree(&input)?;
        let first_id = first.id();
        let first_view = store.mount_tree_protected(first, temp.path(), &[])?;
        let cached_root = first_view.root().to_owned();
        fs::write(input.join("src/variable"), b"second version")?;
        fs::set_permissions(
            input.join("src/variable"),
            fs::Permissions::from_mode(0o600),
        )?;
        let source_metadata = fs::metadata(input.join("src/variable"))?;
        let next = store.capture_tree(&input)?;
        assert_ne!(next.id(), first_id);
        let target_id = next.id();
        let mut next_view =
            store.mount_tree_protected(next, temp.path(), &[PathBuf::from("out")])?;
        assert_eq!(next_view.root(), cached_root);
        let replaced = next_view.overlay_bindings().collect::<Vec<_>>();
        assert_eq!(replaced.len(), 1);
        assert_eq!(replaced[0].0, &TreePath::new(b"src/variable".to_vec())?);
        assert_eq!(fs::read(replaced[0].1)?, b"second version");
        let bound_metadata = fs::metadata(replaced[0].1)?;
        assert_eq!(
            bound_metadata.mode() & 0o777,
            source_metadata.mode() & 0o777
        );
        assert_eq!(bound_metadata.mtime(), source_metadata.mtime());
        assert_eq!(bound_metadata.mtime_nsec(), source_metadata.mtime_nsec());
        assert_eq!(
            fs::read(cached_root.join("src/variable"))?,
            b"first version"
        );
        assert_eq!(store.evict_tree(first_id)?, Eviction::Pinned);
        assert_eq!(store.evict_tree(target_id)?, Eviction::Pinned);
        next_view.mark_writable(Path::new("out"))?;
        fs::write(
            next_view.writable_path(Path::new("out"))?.join("result"),
            b"private output",
        )?;
        assert!(!cached_root.join("out/result").exists());
        let target_lease = store.lookup_tree(target_id)?.context("missing target")?;
        let fallback =
            store.mount_tree_protected(target_lease, temp.path(), &[PathBuf::from("src")])?;
        assert_eq!(fallback.overlay_bindings().count(), 0);
        assert_ne!(fallback.root(), cached_root);
        drop(fallback);
        drop(next_view);
        drop(first_view);
        assert!(matches!(
            store.evict_tree(first_id)?,
            Eviction::Removed { .. }
        ));
        Ok(())
    }

    #[test]
    fn mounted_tree_exposes_decoded_data_hardlinks_symlinks_and_writable_scratch() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let input = temp.path().join("input");
        fs::create_dir_all(input.join("bin"))?;
        fs::create_dir_all(input.join("out"))?;
        let bytes = b"content-addressed-virtual-file
"
        .repeat(20_000);
        fs::write(input.join("bin/compiler"), &bytes)?;
        fs::set_permissions(
            input.join("bin/compiler"),
            fs::Permissions::from_mode(0o755),
        )?;
        fs::hard_link(input.join("bin/compiler"), input.join("bin/alias"))?;
        symlink("compiler", input.join("bin/link"))?;
        fs::write(input.join("out/original"), b"untouched")?;
        let store = NativeStore::open(&temp.path().join("store"))?;
        let lease = store.capture_tree(&input)?;
        let mut mounted = lease.mount_readonly(temp.path())?;
        let root = mounted.root().to_owned();
        assert_eq!(fs::read(root.join("bin/compiler"))?, bytes);
        assert_eq!(fs::read(root.join("bin/link"))?, bytes);
        assert_eq!(
            fs::metadata(root.join("bin/alias"))?.ino(),
            fs::metadata(root.join("bin/compiler"))?.ino()
        );
        assert_eq!(fs::read_link(root.join("bin/link"))?, Path::new("compiler"));
        assert_eq!(
            fs::metadata(root.join("bin/compiler"))?.mode() & 0o777,
            0o755
        );
        assert!(fs::write(root.join("bin/compiler"), b"bad").is_err());
        mounted.mark_writable(Path::new("out"))?;
        let writable = mounted.writable_path(Path::new("out"))?.to_owned();
        assert_eq!(fs::read(writable.join("original"))?, b"untouched");
        fs::write(writable.join("new"), b"build-output")?;
        assert_eq!(fs::read(writable.join("new"))?, b"build-output");
        assert!(!root.join("out/new").exists());
        assert_eq!(fs::read(root.join("out/original"))?, b"untouched");
        drop(mounted);
        assert!(!root.exists());
        Ok(())
    }

    #[test]
    fn concurrent_source_versions_bind_independent_immutable_files() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let input = temporary.path().join("input");
        fs::create_dir_all(input.join("src"))?;
        fs::write(input.join("src/source"), b"original")?;
        for index in 0..64 {
            fs::write(
                input.join("src").join(format!("header-{index:03}")),
                b"fixed",
            )?;
        }
        let store = NativeStore::open(&temporary.path().join("store"))?;
        let original = store.capture_tree(&input)?;
        let mut manifest = original.manifest().clone();
        let base_view = store.mount_tree_protected(original, temporary.path(), &[])?;
        let shared_root = base_view.root().to_owned();
        let name = TreePath::new(b"src/source".to_vec())?;
        let mut variants = Vec::new();
        for index in 0..8 {
            let bytes = format!("independent version {index}").into_bytes();
            let staged = store.stage(bytes.as_slice())?;
            let metadata = match manifest.entries.get(&name) {
                Some(TreeEntry::File { metadata, .. }) => *metadata,
                _ => anyhow::bail!("missing source file"),
            };
            manifest.entries.insert(
                name.clone(),
                TreeEntry::File {
                    blob: staged.reference(),
                    metadata,
                },
            );
            let id = store.publish_tree(&manifest, vec![staged])?;
            variants.push((id, bytes));
        }
        let scratch = temporary.path();
        std::thread::scope(|scope| -> Result<()> {
            let handles = variants
                .iter()
                .map(|(id, bytes)| {
                    let store = &store;
                    let shared_root = &shared_root;
                    scope.spawn(move || -> Result<()> {
                        let lease = store.lookup_tree(*id)?.context("variant missing")?;
                        let mounted = store.mount_tree_protected(lease, scratch, &[])?;
                        assert_eq!(mounted.root(), shared_root);
                        let changed = mounted.overlay_bindings().collect::<Vec<_>>();
                        assert_eq!(changed.len(), 1);
                        assert_eq!(fs::read(changed[0].1)?, *bytes);
                        assert_eq!(fs::read(shared_root.join("src/source"))?, b"original");
                        Ok(())
                    })
                })
                .collect::<Vec<_>>();
            for handle in handles {
                handle.join().expect("overlay thread panicked")?;
            }
            Ok(())
        })?;
        drop(base_view);
        Ok(())
    }

    /// Verify both the indexed-Zstd/FUSE implementation and, when available,
    /// native ZFS block-cloned subtree construction.
    #[test]
    fn changing_directory_members_reuses_unaffected_tree_and_preserves_inodes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        verify_directory_view(temp.path())?;
        let current = std::env::current_dir()?;
        if crate::store::is_native_zfs(&current)? {
            let zfs = tempfile::tempdir_in(current)?;
            verify_directory_view(zfs.path())?;
        }
        Ok(())
    }

    fn verify_directory_view(parent: &Path) -> Result<()> {
        let input = parent.join("input");
        let work = input.join("src/work");
        fs::create_dir_all(&work)?;
        fs::create_dir_all(input.join("out"))?;
        fs::create_dir_all(input.join("stable"))?;
        fs::write(work.join("source"), b"first")?;
        fs::hard_link(work.join("source"), work.join("alias"))?;
        fs::write(work.join("removed"), b"old")?;
        symlink("source", work.join("sym"))?;
        for index in 0..96 {
            fs::write(
                input.join("stable").join(format!("header-{index:03}")),
                b"header",
            )?;
        }
        let store = NativeStore::open(&parent.join("store"))?;
        let original = store.capture_tree(&input)?;
        let old_id = original.id();
        let base = store.mount_tree_protected(original, parent, &[])?;
        let base_root = base.root().to_owned();

        fs::write(work.join("source"), b"second")?;
        fs::remove_file(work.join("removed"))?;
        fs::write(work.join("added"), b"new")?;
        fs::remove_file(work.join("sym"))?;
        symlink("added", work.join("sym"))?;
        let newer = store.capture_tree(&input)?;
        let newer_id = newer.id();
        assert_ne!(old_id, newer_id);
        let mut view = store.mount_tree_protected(newer, parent, &[PathBuf::from("out")])?;
        assert_eq!(view.root(), base_root);
        let bindings = view.overlay_bindings().collect::<Vec<_>>();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].0, &TreePath::new(b"src/work".to_vec())?);
        let replacement = bindings[0].1;
        assert!(replacement.is_dir());
        assert_eq!(fs::read(replacement.join("source"))?, b"second");
        assert_eq!(fs::read(replacement.join("alias"))?, b"second");
        assert_eq!(fs::read_link(replacement.join("sym"))?, Path::new("added"));
        assert_eq!(fs::read(replacement.join("added"))?, b"new");
        assert!(!replacement.join("removed").exists());
        assert_eq!(
            fs::metadata(replacement.join("source"))?.ino(),
            fs::metadata(replacement.join("alias"))?.ino()
        );
        assert_eq!(fs::metadata(replacement.join("source"))?.nlink(), 2);
        assert_eq!(fs::read(base_root.join("src/work/source"))?, b"first");
        assert!(base_root.join("src/work/removed").exists());
        assert!(!base_root.join("src/work/added").exists());
        assert_eq!(store.evict_tree(old_id)?, Eviction::Pinned);
        assert_eq!(store.evict_tree(newer_id)?, Eviction::Pinned);
        let stats = view
            .overlay_stats()
            .context("missing materialization counters")?;
        println!(
            "DIRECTORY_OVERLAY backend={} cloned_files={} copied_files={} copied_bytes={} unchanged_headers=96",
            if store.uses_native_zfs() {
                "zfs"
            } else {
                "fuse"
            },
            stats.cloned_files,
            stats.copied_files,
            stats.copied_bytes,
        );
        if store.uses_native_zfs() {
            assert_eq!(stats.cloned_files, 2);
            assert_eq!(stats.copied_files, 0);
        } else {
            assert_eq!(stats.copied_files, 2);
        }
        view.mark_writable(Path::new("out"))?;
        fs::write(
            view.writable_path(Path::new("out"))?.join("private"),
            b"private",
        )?;
        assert!(!base_root.join("out/private").exists());
        drop(view);
        drop(base);
        assert!(matches!(
            store.evict_tree(old_id)?,
            Eviction::Removed { .. }
        ));
        Ok(())
    }

    #[test]
    fn concurrent_directory_topology_variants_keep_private_inode_groups() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let input = temp.path().join("input");
        let work = input.join("src/work");
        fs::create_dir_all(&work)?;
        fs::create_dir_all(input.join("headers"))?;
        fs::write(work.join("source"), b"unchanged")?;
        fs::hard_link(work.join("source"), work.join("alias"))?;
        fs::write(work.join("removed"), b"obsolete")?;
        symlink("source", work.join("selected"))?;
        for index in 0..64 {
            fs::write(input.join("headers").join(format!("{index:03}")), b"header")?;
        }
        let store = NativeStore::open(&temp.path().join("store"))?;
        let base = store.capture_tree(&input)?;
        let cached = store.mount_tree_protected(base, temp.path(), &[])?;
        let cached_root = cached.root().to_owned();
        let mut variants = Vec::new();
        let source = store.capture_tree(&input)?;
        let source_name = TreePath::new(b"src/work/source".to_vec())?;
        let referent = match source.manifest().entries.get(&source_name) {
            Some(TreeEntry::File { .. }) => &source_name,
            Some(TreeEntry::Hardlink(target)) => target,
            _ => anyhow::bail!("captured source must be a regular file or hardlink"),
        };
        let metadata = match source.manifest().entries.get(referent) {
            Some(TreeEntry::File { metadata, .. }) => *metadata,
            _ => anyhow::bail!("captured hardlink referent missing"),
        };
        for index in 0..8 {
            let mut manifest = source.manifest().clone();
            let content = format!("generated variant {index}").into_bytes();
            let blob = store.stage(content.as_slice())?;
            let name = format!("variant-{index}");
            manifest
                .entries
                .remove(&TreePath::new(b"src/work/removed".to_vec())?);
            manifest.entries.insert(
                TreePath::new(format!("src/work/{name}").into_bytes())?,
                TreeEntry::File {
                    blob: blob.reference(),
                    metadata,
                },
            );
            manifest.entries.insert(
                TreePath::new(b"src/work/selected".to_vec())?,
                TreeEntry::Symlink {
                    target: name.as_bytes().to_vec(),
                    modified: TreeTimestamp {
                        seconds: 123,
                        nanoseconds: 0,
                    },
                },
            );
            let id = store.publish_tree(&manifest, vec![blob])?;
            variants.push((id, name, content));
        }
        let scratch = temp.path();
        std::thread::scope(|scope| -> Result<()> {
            let handles = variants
                .iter()
                .map(|(id, name, content)| {
                    let store = &store;
                    let cached_root = &cached_root;
                    scope.spawn(move || -> Result<()> {
                        let target = store.lookup_tree(*id)?.context("missing variant")?;
                        let view = store.mount_tree_protected(target, scratch, &[])?;
                        assert_eq!(view.root(), cached_root);
                        let bindings = view.overlay_bindings().collect::<Vec<_>>();
                        assert_eq!(bindings.len(), 1);
                        let dir = bindings[0].1;
                        assert_eq!(fs::read(dir.join(name))?, *content);
                        assert_eq!(fs::read_link(dir.join("selected"))?, Path::new(name));
                        assert!(!dir.join("removed").exists());
                        assert_eq!(
                            fs::metadata(dir.join("source"))?.ino(),
                            fs::metadata(dir.join("alias"))?.ino()
                        );
                        assert_eq!(fs::metadata(dir.join("source"))?.nlink(), 2);
                        assert!(matches!(store.evict_tree(*id)?, Eviction::Pinned));
                        Ok(())
                    })
                })
                .collect::<Vec<_>>();
            for task in handles {
                task.join().expect("directory overlay thread panicked")?;
            }
            Ok(())
        })?;
        assert_eq!(
            fs::read_link(cached_root.join("src/work/selected"))?,
            Path::new("source")
        );
        drop(source);
        drop(cached);
        Ok(())
    }

    #[test]
    fn cached_zfs_view_clones_only_writable_subtree_and_isolates_builds() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let input = temp.path().join("input");
        fs::create_dir_all(input.join("out"))?;
        fs::create_dir_all(input.join("bin"))?;
        fs::write(input.join("bin/tool"), b"immutable compiler binary")?;
        fs::write(input.join("out/source"), b"unmodified")?;
        fs::hard_link(input.join("out/source"), input.join("out/alias"))?;
        symlink("../bin/tool", input.join("out/tool-link"))?;
        let store = NativeStore::open(&temp.path().join("store"))?;
        if !store.uses_native_zfs() {
            return Ok(());
        }
        let lease = store.capture_tree(&input)?;
        let id = lease.id();
        let scratch_one = temp.path().join("action-one");
        let scratch_two = temp.path().join("action-two");
        fs::create_dir(&scratch_one)?;
        fs::create_dir(&scratch_two)?;
        let mut first = store.mount_tree_protected(lease, &scratch_one, &[])?;
        let root = first.root().to_owned();
        let cached_tool_inode = fs::metadata(root.join("bin/tool"))?.ino();
        let lease = store.lookup_tree(id)?.context("missing native ZFS tree")?;
        let mut second = store.mount_tree_protected(lease, &scratch_two, &[])?;
        assert_eq!(root, second.root(), "immutable ZFS tree should be shared");
        assert_eq!(
            fs::metadata(second.root().join("bin/tool"))?.ino(),
            cached_tool_inode
        );

        first.mark_writable(Path::new("out"))?;
        second.mark_writable(Path::new("out"))?;
        assert!(first.private_zfs.is_none());
        assert!(second.private_zfs.is_none());
        let first_out = first.writable_path(Path::new("out"))?.to_owned();
        let second_out = second.writable_path(Path::new("out"))?.to_owned();
        assert_ne!(first_out, second_out);
        assert_ne!(
            fs::metadata(root.join("out/source"))?.ino(),
            fs::metadata(first_out.join("source"))?.ino()
        );
        assert_eq!(
            fs::metadata(first_out.join("source"))?.ino(),
            fs::metadata(first_out.join("alias"))?.ino()
        );
        assert_eq!(
            fs::read_link(first_out.join("tool-link"))?,
            Path::new("../bin/tool")
        );
        fs::write(first_out.join("source"), b"first action")?;
        fs::write(second_out.join("source"), b"second action")?;
        assert_eq!(fs::read(root.join("out/source"))?, b"unmodified");
        assert_eq!(fs::read(first_out.join("alias"))?, b"first action");
        assert_eq!(fs::read(second_out.join("source"))?, b"second action");
        assert_eq!(
            fs::read(root.join("bin/tool"))?,
            b"immutable compiler binary"
        );
        drop(first);
        drop(second);
        assert!(matches!(store.evict_tree(id)?, Eviction::Removed { .. }));
        assert!(!root.exists(), "eviction drops the cached ZFS tree");
        Ok(())
    }

    #[test]
    fn hardlinks_crossing_output_mounts_keep_one_private_zfs_inode_group() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let input = temp.path().join("input");
        fs::create_dir_all(input.join("out"))?;
        fs::create_dir_all(input.join("lib"))?;
        fs::write(input.join("lib/shared"), b"before")?;
        fs::hard_link(input.join("lib/shared"), input.join("out/alias"))?;
        let store = NativeStore::open(&temp.path().join("store"))?;
        if !store.uses_native_zfs() {
            return Ok(());
        }
        let lease = store.capture_tree(&input)?;
        let mut mounted = store.mount_tree_protected(lease, temp.path(), &[])?;
        let immutable_root = mounted.root().to_owned();
        mounted.mark_writable(Path::new("out"))?;
        assert!(
            mounted.private_zfs.is_some(),
            "cross-mount hardlinks need one private CoW tree"
        );
        let private_root = mounted.root().to_owned();
        assert_ne!(private_root, immutable_root);
        let output = mounted.writable_path(Path::new("out"))?.to_owned();
        assert_eq!(
            fs::metadata(private_root.join("lib/shared"))?.ino(),
            fs::metadata(output.join("alias"))?.ino()
        );
        fs::write(output.join("alias"), b"modified")?;
        assert_eq!(fs::read(private_root.join("lib/shared"))?, b"modified");
        assert_eq!(fs::read(immutable_root.join("lib/shared"))?, b"before");
        drop(mounted);
        assert!(!private_root.exists());
        Ok(())
    }

    #[test]
    fn cached_readonly_mount_keeps_inode_and_releases_pins_on_eviction() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let input = temp.path().join("input");
        fs::create_dir_all(&input)?;
        fs::write(input.join("artifact"), b"generated compiler output")?;
        let store = NativeStore::open(&temp.path().join("store"))?;
        let first_lease = store.capture_tree(&input)?;
        let id = first_lease.id();

        let scratch_one = temp.path().join("build-one");
        let scratch_two = temp.path().join("build-two");
        fs::create_dir(&scratch_one)?;
        fs::create_dir(&scratch_two)?;
        let first = store.mount_tree_protected(first_lease, &scratch_one, &[])?;
        let root = first.root().to_owned();
        let ino = fs::metadata(root.join("artifact"))?.ino();
        assert_eq!(
            fs::read(root.join("artifact"))?,
            b"generated compiler output"
        );
        let second_lease = store.lookup_tree(id)?.context("tree not indexed")?;
        let second = store.mount_tree_protected(second_lease, &scratch_two, &[])?;
        assert_eq!(root, second.root());
        assert_eq!(fs::metadata(second.root().join("artifact"))?.ino(), ino);
        assert_eq!(store.evict_tree(id)?, Eviction::Pinned);

        drop(first);
        drop(second);
        assert!(root.exists(), "cache should retain the warm read-only view");
        assert!(matches!(store.evict_tree(id)?, Eviction::Removed { .. }));
        assert!(!root.exists(), "eviction must unmount the inactive view");
        Ok(())
    }
}
