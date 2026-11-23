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
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};
use fuser::{
    BackgroundSession, FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, Request,
};
use rustix::fs::{AtFlags, CWD, Timestamps, utimensat};
use rustix::time::Timespec;
use tempfile::TempDir;

use super::TreeLease;
use crate::{BlobReader, BlobRef, TreeEntry, TreeMetadata, TreeTimestamp};

const TTL: Duration = Duration::from_secs(3600);
const KEEP_CACHE: u32 = 1 << 1;

enum Kind {
    Directory(BTreeMap<OsString, u64>),
    File(BlobRef),
    Symlink(Vec<u8>),
}

struct Node {
    kind: Kind,
    metadata: TreeMetadata,
    parent: u64,
    nlink: u32,
}

struct VirtualFs {
    _lease: TreeLease,
    nodes: Vec<Node>,
    handles: BTreeMap<u64, BlobReader>,
    next_handle: u64,
    uid: u32,
    gid: u32,
}

impl VirtualFs {
    fn new(lease: TreeLease) -> Result<Self> {
        let root = lease.manifest().root;
        let mut nodes = vec![Node {
            kind: Kind::Directory(BTreeMap::new()),
            metadata: root,
            parent: 1,
            nlink: 2,
        }];
        let mut paths = BTreeMap::from([(Vec::new(), 1_u64)]);
        for (path, entry) in &lease.manifest().entries {
            if matches!(entry, TreeEntry::Hardlink(_)) {
                continue;
            }
            let bytes = path.as_bytes();
            let cut = bytes.iter().rposition(|&b| b == b'/');
            let (parent_path, name) = match cut {
                Some(n) => (&bytes[..n], &bytes[n + 1..]),
                None => (&b""[..], bytes),
            };
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
            let ino = u64::try_from(nodes.len())? + 1;
            nodes.push(Node {
                kind,
                metadata,
                parent,
                nlink: 1,
            });
            let Kind::Directory(children) = &mut nodes[usize::try_from(parent - 1)?].kind else {
                anyhow::bail!("FUSE parent is not a directory");
            };
            ensure!(
                children
                    .insert(OsStr::from_bytes(name).to_owned(), ino)
                    .is_none(),
                "duplicate FUSE child"
            );
            paths.insert(bytes.to_vec(), ino);
        }
        for (path, entry) in &lease.manifest().entries {
            let TreeEntry::Hardlink(target) = entry else {
                continue;
            };
            let bytes = path.as_bytes();
            let cut = bytes.iter().rposition(|&b| b == b'/');
            let (parent_path, name) = match cut {
                Some(n) => (&bytes[..n], &bytes[n + 1..]),
                None => (&b""[..], bytes),
            };
            let parent = *paths
                .get(parent_path)
                .context("missing FUSE hardlink parent")?;
            let ino = *paths
                .get(target.as_bytes())
                .context("missing FUSE hardlink target")?;
            let Kind::File(_) = nodes[usize::try_from(ino - 1)?].kind else {
                anyhow::bail!("hardlink targets must be regular files");
            };
            nodes[usize::try_from(ino - 1)?].nlink += 1;
            let Kind::Directory(children) = &mut nodes[usize::try_from(parent - 1)?].kind else {
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
            _lease: lease,
            nodes,
            handles: BTreeMap::new(),
            next_handle: 1,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        })
    }

    fn node(&self, ino: u64) -> Option<&Node> {
        self.nodes.get(usize::try_from(ino.checked_sub(1)?).ok()?)
    }

    fn attr(&self, ino: u64) -> Result<FileAttr> {
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
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let found = self.node(parent).and_then(|node| match &node.kind {
            Kind::Directory(children) => children.get(name).copied(),
            _ => None,
        });
        match found.and_then(|ino| self.attr(ino).ok()) {
            Some(attr) => reply.entry(&TTL, &attr, 0),
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.attr(ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(_) => reply.error(libc::ENOENT),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        match self.node(ino).map(|node| &node.kind) {
            Some(Kind::Symlink(target)) => reply.data(target),
            _ => reply.error(libc::EINVAL),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(node) = self.node(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Kind::Directory(children) = &node.kind else {
            reply.error(libc::ENOTDIR);
            return;
        };
        let mut entries = vec![
            (ino, FileType::Directory, OsString::from(".")),
            (node.parent, FileType::Directory, OsString::from("..")),
        ];
        for (name, &child) in children {
            let kind = match self.node(child).map(|node| &node.kind) {
                Some(Kind::Directory(_)) => FileType::Directory,
                Some(Kind::File(_)) => FileType::RegularFile,
                Some(Kind::Symlink(_)) => FileType::Symlink,
                None => {
                    reply.error(libc::EIO);
                    return;
                }
            };
            entries.push((child, kind, name.clone()));
        }
        for (index, (child, kind, name)) in
            entries.into_iter().enumerate().skip(offset.max(0) as usize)
        {
            if reply.add(child, (index + 1) as i64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        if flags & libc::O_ACCMODE != libc::O_RDONLY {
            reply.error(libc::EROFS);
            return;
        }
        let Some(Kind::File(blob)) = self.node(ino).map(|node| &node.kind) else {
            reply.error(libc::EISDIR);
            return;
        };
        let path = self._lease.inner.blob_path(blob.id);
        match File::open(path)
            .map_err(anyhow::Error::from)
            .and_then(BlobReader::open)
        {
            Ok(reader) => {
                let handle = self.next_handle;
                self.next_handle = self.next_handle.wrapping_add(1);
                self.handles.insert(handle, reader);
                reply.opened(handle, KEEP_CACHE);
            }
            Err(error) => {
                log::error!("failed to open virtual CAS file: {error:#}");
                reply.error(libc::EIO);
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Some(reader) = self.handles.get_mut(&fh) else {
            reply.error(libc::EBADF);
            return;
        };
        let mut out = vec![0; size as usize];
        let result = u64::try_from(offset)
            .map_err(io::Error::other)
            .and_then(|at| reader.seek(SeekFrom::Start(at)))
            .and_then(|_| reader.read(&mut out));
        match result {
            Ok(n) => reply.data(&out[..n]),
            Err(error) => {
                log::error!("virtual CAS decode failed: {error}");
                reply.error(libc::EIO);
            }
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.handles.remove(&fh);
        reply.ok();
    }
}

/// A mounted immutable tree plus the minimal private writable directories
/// needed for a build's output mounts. Immutable inputs stay compressed.
pub struct MountedTree {
    _session: BackgroundSession,
    directory: TempDir,
    mountpoint: PathBuf,
    writable: BTreeMap<PathBuf, PathBuf>,
}

impl MountedTree {
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.mountpoint
    }

    /// Copy the contents of one directory into private writable scratch.
    /// This is necessary only for paths that the build may modify.
    ///
    /// # Errors
    /// Returns an error for invalid backing directories, file types or I/O failures.
    pub fn mark_writable(&mut self, relative: &Path) -> Result<()> {
        let source = self.mountpoint.join(relative);
        ensure!(source.is_dir(), "writable mount source is not a directory");
        let scratch = self
            .directory
            .path()
            .join(format!("mutable-{}", self.writable.len()));
        let mut links = BTreeMap::new();
        copy_directory(&source, &scratch, &mut links)?;
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

fn copy_directory(src: &Path, dst: &Path, links: &mut BTreeMap<(u64, u64), PathBuf>) -> Result<()> {
    fs::create_dir(dst)?;
    let src_meta = fs::symlink_metadata(src)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let meta = fs::symlink_metadata(&src_path)?;
        if meta.is_dir() {
            copy_directory(&src_path, &dst_path, links)?;
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
                io::copy(&mut source, &mut target)?;
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
        let filesystem = VirtualFs::new(self)?;
        let directory = tempfile::Builder::new()
            .prefix("build-fuse-")
            .tempdir_in(parent)?;
        let mountpoint = directory.path().join("root");
        fs::create_dir(&mountpoint)?;
        let session = fuser::spawn_mount2(
            filesystem,
            &mountpoint,
            &[
                MountOption::RO,
                MountOption::DefaultPermissions,
                MountOption::FSName("sccache-native-cas".into()),
            ],
        )?;
        Ok(MountedTree {
            _session: session,
            directory,
            mountpoint,
            writable: BTreeMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NativeStore;

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
}
