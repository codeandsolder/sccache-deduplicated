use super::*;
use fuser::{
    BsdFileFlags, Filesystem, FopenFlags, LockOwner, OpenFlags, Owner, RenameFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
    ReplyWrite, ReplyXattr, Request, TimeOrNow, WriteFlags,
};
use rustix::time::Timespec;
use std::os::unix::fs::DirEntryExt;

fn reply_empty(reply: ReplyEmpty, result: Result<()>) {
    match result {
        Ok(()) => reply.ok(),
        Err(error) => reply.error(fs_error(error)),
    }
}
fn reply_entry(reply: ReplyEntry, result: Result<FileAttr>) {
    match result {
        Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
        Err(error) => reply.error(fs_error(error)),
    }
}
fn xattr_reply(reply: ReplyXattr, size: u32, result: Result<Vec<u8>>) {
    match result {
        Ok(bytes) if size == 0 => match u32::try_from(bytes.len()) {
            Ok(n) => reply.size(n),
            Err(_) => reply.error(Errno::EOVERFLOW),
        },
        Ok(bytes) if bytes.len() <= size as usize => reply.data(&bytes),
        Ok(_) => reply.error(Errno::ERANGE),
        Err(error) => reply.error(fs_error(error)),
    }
}
fn attr_time(time: Option<TimeOrNow>) -> Result<Timespec> {
    let Some(time) = time else {
        return Ok(Timespec {
            tv_sec: 0,
            tv_nsec: rfs::UTIME_OMIT,
        });
    };
    let TimeOrNow::SpecificTime(time) = time else {
        return Ok(Timespec {
            tv_sec: 0,
            tv_nsec: rfs::UTIME_NOW,
        });
    };
    let (sec, nano) = match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => (i64::try_from(d.as_secs())?, i64::from(d.subsec_nanos())),
        Err(e) => {
            let d = e.duration();
            let sec = -i64::try_from(d.as_secs())?;
            let nano = i64::from(d.subsec_nanos());
            if nano == 0 {
                (sec, 0)
            } else {
                (sec - 1, 1_000_000_000 - nano)
            }
        }
    };
    Ok(Timespec {
        tv_sec: sec,
        tv_nsec: nano,
    })
}
impl IntermediateFs {
    fn lookup_attr(&self, parent: INodeNo, name: &OsStr) -> Result<FileAttr> {
        let (ino, node) = self.child(parent, name)?;
        match node.attr(ino) {
            Ok(attr) => Ok(attr),
            Err(error) => {
                lock(&self.namespace)?.forget(ino, 1);
                Err(error)
            }
        }
    }
    fn unlink_entry(&self, parent: INodeNo, name: &OsStr, flags: AtFlags) -> Result<()> {
        rfs::unlinkat(&self.node(parent)?.fd, name, flags)?;
        Ok(())
    }
    fn read_file(&self, ino: INodeNo, fh: FileHandle, offset: u64, size: u32) -> Result<Vec<u8>> {
        let node = self.node(ino)?;
        let guard = lock(&node.mutation)?;
        let file = match node.reference()? {
            Some(reference) => self.spool(reference)?,
            None => self.file(fh)?,
        };
        let mut bytes = vec![0; size as usize];
        let n = file.read_at(&mut bytes, offset)?;
        bytes.truncate(n);
        drop(guard);
        Ok(bytes)
    }
    fn write_file(&self, ino: INodeNo, fh: FileHandle, offset: u64, bytes: &[u8]) -> Result<u32> {
        let node = self.node(ino)?;
        let _guard = lock(&node.mutation)?;
        self.detach(&node, false)?;
        let file = self.file(fh)?;
        Ok(u32::try_from(file.write_at(bytes, offset)?)?)
    }
    fn read_xattr(&self, ino: INodeNo, name: &OsStr) -> Result<Vec<u8>> {
        let node = self.node(ino)?;
        let _guard = lock(&node.mutation)?;
        if name == SESSION_XATTR && node.fd.metadata()?.is_dir() {
            return Ok(self.session.0.to_vec());
        }
        if name == REFERENCE_XATTR {
            return node
                .reference()?
                .map(|r| r.encode().to_vec())
                .ok_or_else(|| rustix::io::Errno::NODATA.into());
        }
        if name == INTERNAL || node.fd.metadata()?.file_type().is_symlink() {
            return Err(rustix::io::Errno::NODATA.into());
        }
        let size = rfs::getxattr_query(node.path(), name)?;
        let mut bytes = vec![0; size];
        let size = rfs::getxattr(node.path(), name, &mut bytes[..])?;
        bytes.truncate(size);
        Ok(bytes)
    }
}
impl Filesystem for IntermediateFs {
    fn init(&mut self, _: &Request, config: &mut fuser::KernelConfig) -> io::Result<()> {
        // Without atomic truncation the kernel opens a file for writing
        // before truncating it, forcing unnecessary copy-on-write reads.
        config
            .add_capabilities(fuser::InitFlags::FUSE_ATOMIC_O_TRUNC)
            .map_err(|_| io::Error::other("kernel lacks atomic truncating open"))?;
        Ok(())
    }

    fn lookup(&self, _: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        reply_entry(reply, self.lookup_attr(parent, name));
    }
    fn forget(&self, _: &Request, ino: INodeNo, count: u64) {
        if let Ok(mut ns) = self.namespace.lock() {
            ns.forget(ino, count);
        }
    }
    fn getattr(&self, _: &Request, ino: INodeNo, _: Option<FileHandle>, reply: ReplyAttr) {
        match self.node(ino).and_then(|node| node.attr(ino)) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(error) => reply.error(fs_error(error)),
        }
    }
    fn setattr(
        &self,
        _: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _: Option<SystemTime>,
        _: Option<FileHandle>,
        _: Option<SystemTime>,
        _: Option<SystemTime>,
        _: Option<SystemTime>,
        _: Option<BsdFileFlags>,
        kill: bool,
        reply: ReplyAttr,
    ) {
        let result = (|| {
            let node = self.node(ino)?;
            let _guard = lock(&node.mutation)?;
            if let Some(size) = size {
                self.detach(&node, size == 0)?;
                node.open(OFlags::WRONLY)?.set_len(size)?;
            }
            if let Some(mode) = mode.or_else(|| {
                kill.then(|| node.fd.metadata().map(|m| m.mode() & !0o6000).unwrap_or(0))
            }) {
                ensure!(
                    !node.fd.metadata()?.file_type().is_symlink(),
                    "cannot chmod a symlink"
                );
                fs::set_permissions(node.path(), fs::Permissions::from_mode(mode & 0o7777))?;
            }
            if uid.is_some() || gid.is_some() {
                rfs::chownat(
                    &node.fd,
                    "",
                    uid.map(rfs::Uid::from_raw),
                    gid.map(rfs::Gid::from_raw),
                    AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
                )?;
            }
            if atime.is_some() || mtime.is_some() {
                let times = rfs::Timestamps {
                    last_access: attr_time(atime)?,
                    last_modification: attr_time(mtime)?,
                };
                rfs::utimensat(
                    &node.fd,
                    "",
                    &times,
                    AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
                )?;
            }
            node.attr(ino)
        })();
        match result {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(error) => reply.error(fs_error(error)),
        }
    }
    fn readlink(&self, _: &Request, ino: INodeNo, reply: ReplyData) {
        match self
            .node(ino)
            .and_then(|node| Ok(rfs::readlinkat(&node.fd, "", Vec::new())?))
        {
            Ok(link) => reply.data(link.as_bytes()),
            Err(error) => reply.error(fs_error(error)),
        }
    }
    fn mkdir(
        &self,
        _: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _: Owner,
        reply: ReplyEntry,
    ) {
        reply_entry(
            reply,
            (|| {
                rfs::mkdirat(
                    &self.node(parent)?.fd,
                    name,
                    Mode::from_bits_truncate(mode & !umask),
                )?;
                self.lookup_attr(parent, name)
            })(),
        );
    }
    fn mknod(
        &self,
        _: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _: u32,
        _: Owner,
        reply: ReplyEntry,
    ) {
        if mode & libc::S_IFMT != libc::S_IFREG {
            reply.error(Errno::EPERM);
            return;
        }
        reply_entry(
            reply,
            (|| {
                rfs::openat(
                    &self.node(parent)?.fd,
                    name,
                    OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(mode & !umask),
                )?;
                self.lookup_attr(parent, name)
            })(),
        );
    }
    fn unlink(&self, _: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        reply_empty(reply, self.unlink_entry(parent, name, AtFlags::empty()));
    }
    fn rmdir(&self, _: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        reply_empty(reply, self.unlink_entry(parent, name, AtFlags::REMOVEDIR));
    }
    fn symlink(
        &self,
        _: &Request,
        parent: INodeNo,
        name: &OsStr,
        target: &Path,
        _: Owner,
        reply: ReplyEntry,
    ) {
        reply_entry(
            reply,
            (|| {
                rfs::symlinkat(target, &self.node(parent)?.fd, name)?;
                self.lookup_attr(parent, name)
            })(),
        );
    }
    fn rename(
        &self,
        _: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        _: Option<Owner>,
        reply: ReplyEmpty,
    ) {
        reply_empty(
            reply,
            (|| {
                let flags = rfs::RenameFlags::from_bits(flags.bits())
                    .context("unsupported rename flags")?;
                rfs::renameat_with(
                    &self.node(parent)?.fd,
                    name,
                    &self.node(newparent)?.fd,
                    newname,
                    flags,
                )?;
                Ok(())
            })(),
        );
    }
    fn link(&self, _: &Request, ino: INodeNo, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        reply_entry(
            reply,
            (|| {
                let node = self.node(ino)?;
                // For ordinary inodes, /proc/self/fd follows the descriptor to
                // the actual inode even after rename. Symlinks use AT_EMPTY_PATH.
                if node.fd.metadata()?.file_type().is_symlink() {
                    rfs::linkat(
                        &node.fd,
                        "",
                        &self.node(parent)?.fd,
                        name,
                        AtFlags::EMPTY_PATH,
                    )?;
                } else {
                    rfs::linkat(
                        rfs::CWD,
                        node.path(),
                        &self.node(parent)?.fd,
                        name,
                        AtFlags::SYMLINK_FOLLOW,
                    )?;
                }
                self.lookup_attr(parent, name)
            })(),
        );
    }
    fn open(&self, _: &Request, ino: INodeNo, flags: OpenFlags, _: bool, reply: ReplyOpen) {
        match self.open_file(ino, flags.0) {
            Ok(fh) => reply.opened(fh, FopenFlags::empty()),
            Err(error) => reply.error(fs_error(error)),
        }
    }
    fn create(
        &self,
        _: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        _: bool,
        _: Owner,
        reply: ReplyCreate,
    ) {
        let result = (|| {
            let file = rfs::openat(
                &self.node(parent)?.fd,
                name,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC,
                Mode::from_bits_truncate(mode & !umask),
            )?;
            drop(file);
            let (ino, node) = self.child(parent, name)?;
            let attr = node.attr(ino)?;
            let fh = self.open_file(ino, flags)?;
            Ok((attr, fh))
        })();
        match result {
            Ok((attr, fh)) => reply.created(&TTL, &attr, Generation(0), fh, FopenFlags::empty()),
            Err(error) => reply.error(fs_error(error)),
        }
    }
    fn read(
        &self,
        _: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _: OpenFlags,
        _: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.read_file(ino, fh, offset, size) {
            Ok(bytes) => reply.data(&bytes),
            Err(error) => reply.error(fs_error(error)),
        }
    }
    fn write(
        &self,
        _: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        bytes: &[u8],
        _: WriteFlags,
        _: OpenFlags,
        _: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.write_file(ino, fh, offset, bytes) {
            Ok(n) => reply.written(n),
            Err(error) => reply.error(fs_error(error)),
        }
    }
    fn release(
        &self,
        _: &Request,
        _: INodeNo,
        fh: FileHandle,
        _: OpenFlags,
        _: Option<LockOwner>,
        _: bool,
        reply: ReplyEmpty,
    ) {
        reply_empty(
            reply,
            (|| {
                lock(&self.namespace)?.release(fh);
                Ok(())
            })(),
        );
    }
    fn flush(&self, _: &Request, _: INodeNo, _: FileHandle, _: LockOwner, reply: ReplyEmpty) {
        reply.ok();
    }
    fn fsync(&self, _: &Request, _: INodeNo, fh: FileHandle, datasync: bool, reply: ReplyEmpty) {
        reply_empty(
            reply,
            (|| {
                let file = self.file(fh)?;
                if datasync {
                    file.sync_data()?;
                } else {
                    file.sync_all()?;
                }
                Ok(())
            })(),
        );
    }
    fn opendir(&self, _: &Request, ino: INodeNo, _: OpenFlags, reply: ReplyOpen) {
        let result = (|| {
            let node = self.node(ino)?;
            let parent: File = rfs::openat(
                &node.fd,
                "..",
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
            )?
            .into();
            let mut ns = lock(&self.namespace)?;
            let parent = if ino == INodeNo::ROOT {
                ino
            } else {
                ns.inode(&parent.metadata()?)?
            };
            let mut entries = vec![
                (ino, FileType::Directory, ".".into()),
                (parent, FileType::Directory, "..".into()),
            ];
            for entry in fs::read_dir(node.path())? {
                let entry = entry?;
                let child = if entry.ino() == ns.root_inode {
                    INodeNo::ROOT
                } else {
                    INodeNo(entry.ino().checked_add(2).context("inode overflow")?)
                };
                entries.push((
                    child,
                    FileType::from_std(entry.file_type()?)
                        .context("unknown directory entry type")?,
                    entry.file_name(),
                ));
            }
            ns.handle(
                ino,
                Handle::Directory {
                    ino,
                    entries: Arc::new(entries),
                },
            )
        })();
        match result {
            Ok(fh) => reply.opened(fh, FopenFlags::empty()),
            Err(error) => reply.error(fs_error(error)),
        }
    }
    fn readdir(
        &self,
        _: &Request,
        _: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let entries = match lock(&self.namespace).and_then(|ns| match ns.handles.get(&fh) {
            Some(Handle::Directory { entries, .. }) => Ok(Arc::clone(entries)),
            _ => Err(missing()),
        }) {
            Ok(entries) => entries,
            Err(error) => {
                reply.error(fs_error(error));
                return;
            }
        };
        for (index, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, index as u64 + 1, *kind, name) {
                break;
            }
        }
        reply.ok();
    }
    fn releasedir(&self, _: &Request, _: INodeNo, fh: FileHandle, _: OpenFlags, reply: ReplyEmpty) {
        reply_empty(
            reply,
            (|| {
                lock(&self.namespace)?.release(fh);
                Ok(())
            })(),
        );
    }
    fn fsyncdir(&self, _: &Request, ino: INodeNo, _: FileHandle, _: bool, reply: ReplyEmpty) {
        reply_empty(
            reply,
            (|| {
                self.node(ino)?
                    .open(OFlags::RDONLY | OFlags::DIRECTORY)?
                    .sync_all()?;
                Ok(())
            })(),
        );
    }
    fn statfs(&self, _: &Request, _: INodeNo, reply: ReplyStatfs) {
        match rfs::statvfs(&self.scratch) {
            Ok(s) => reply.statfs(
                s.f_blocks,
                s.f_bfree,
                s.f_bavail,
                s.f_files,
                s.f_ffree,
                s.f_bsize as u32,
                s.f_namemax as u32,
                s.f_frsize as u32,
            ),
            Err(error) => reply.error(Errno::from_i32(error.raw_os_error())),
        }
    }
    fn getxattr(&self, _: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        xattr_reply(reply, size, self.read_xattr(ino, name));
    }
    fn setxattr(
        &self,
        _: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        reply_empty(
            reply,
            (|| {
                ensure!(position == 0, "unsupported xattr position");
                let node = self.node(ino)?;
                if name == REFERENCE_XATTR {
                    return self.attach(&node, IntermediateReference::decode(value)?);
                }
                ensure!(
                    name != INTERNAL
                        && name != SESSION_XATTR
                        && !node.fd.metadata()?.file_type().is_symlink(),
                    "reserved or unsupported xattr"
                );
                let _guard = lock(&node.mutation)?;
                rfs::setxattr(
                    node.path(),
                    name,
                    value,
                    rfs::XattrFlags::from_bits_truncate(flags as u32),
                )?;
                Ok(())
            })(),
        );
    }
    fn listxattr(&self, _: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        xattr_reply(
            reply,
            size,
            (|| {
                let node = self.node(ino)?;
                if node.fd.metadata()?.file_type().is_symlink() {
                    return Ok(Vec::new());
                }
                let mut bytes = vec![0; rfs::listxattr_query(node.path())?];
                let n = rfs::listxattr(node.path(), &mut bytes[..])?;
                let mut result = Vec::new();
                for name in bytes[..n]
                    .split(|&c| c == 0)
                    .filter(|name| !name.is_empty() && *name != INTERNAL.as_bytes())
                {
                    result.extend_from_slice(name);
                    result.push(0);
                }
                Ok(result)
            })(),
        );
    }
    fn removexattr(&self, _: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        reply_empty(
            reply,
            (|| {
                let node = self.node(ino)?;
                ensure!(
                    name != INTERNAL
                        && name != SESSION_XATTR
                        && name != REFERENCE_XATTR
                        && !node.fd.metadata()?.file_type().is_symlink(),
                    "reserved or unsupported xattr"
                );
                let _guard = lock(&node.mutation)?;
                rfs::removexattr(node.path(), name)?;
                Ok(())
            })(),
        );
    }
    fn fallocate(
        &self,
        _: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        reply_empty(
            reply,
            (|| {
                let node = self.node(ino)?;
                let _guard = lock(&node.mutation)?;
                self.detach(&node, false)?;
                rfs::fallocate(
                    &*self.file(fh)?,
                    rfs::FallocateFlags::from_bits_truncate(mode as u32),
                    offset,
                    length,
                )?;
                Ok(())
            })(),
        );
    }
}
