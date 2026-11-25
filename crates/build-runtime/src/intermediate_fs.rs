//! Writable, private Cargo build-directory mount. The backing namespace has
//! ordinary Unix inode semantics; immutable content is a separate lease, not
//! a sparse file that can accidentally be read as zeroes.
use crate::{BlobRef, ContentId, wire::Ticket};
use anyhow::{Context, Result, ensure};
use fuser::{
    BackgroundSession, Config, Errno, FileAttr, FileHandle, FileType, Generation, INodeNo,
    MountOption,
};
use rustix::fs::{self as rfs, AtFlags, Mode, OFlags};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime},
};

mod operations;

const TTL: Duration = Duration::ZERO;
const INTERNAL: &str = "user.sccache.internal-reference";
/// The synthetic session attribute on directories of a Cargo mount.
pub const SESSION_XATTR: &str = "user.sccache.session";
/// A synthetic immutable reference, readable without fetching its data.
pub const REFERENCE_XATTR: &str = "user.sccache.reference";

/// Exact session and content identity, independently of inode metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntermediateReference {
    pub session: Ticket,
    pub blob: BlobRef,
}
impl IntermediateReference {
    pub fn encode(self) -> [u8; 72] {
        let mut bytes = [0; 72];
        bytes[..32].copy_from_slice(&self.session.0);
        bytes[32..64].copy_from_slice(&self.blob.id.0);
        bytes[64..].copy_from_slice(&self.blob.size.to_le_bytes());
        bytes
    }
    /// Decode the complete, fixed-size reference; reject truncated attributes.
    /// # Errors
    /// Invalid attribute length.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == 72, "invalid intermediate reference length");
        Ok(Self {
            session: Ticket(bytes[..32].try_into()?),
            blob: BlobRef {
                id: ContentId(bytes[32..64].try_into()?),
                size: u64::from_le_bytes(bytes[64..].try_into()?),
            },
        })
    }
}

/// The caller supplies an authenticated authorization and a verified content
/// reader. The mount owns no remote credentials.
pub trait IntermediateContent: Send + Sync + 'static {
    fn authorize(&self, reference: IntermediateReference) -> Result<()>;
    fn fetch(&self, reference: IntermediateReference, destination: &mut File) -> Result<()>;
}

fn fs_error(error: anyhow::Error) -> Errno {
    log::debug!("intermediate filesystem: {error:#}");
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<io::Error>() {
            return Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO));
        }
        if let Some(error) = cause.downcast_ref::<rustix::io::Errno>() {
            return Errno::from_i32(error.raw_os_error());
        }
    }
    Errno::EIO
}
fn missing() -> anyhow::Error {
    io::Error::from_raw_os_error(libc::ENOENT).into()
}
fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| anyhow::anyhow!("intermediate filesystem lock poisoned"))
}

struct Node {
    fd: File,
    mutation: Mutex<()>,
}
impl Node {
    fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))
    }
    fn open(&self, flags: OFlags) -> Result<File> {
        Ok(rfs::open(self.path(), flags | OFlags::CLOEXEC, Mode::empty())?.into())
    }
    fn reference(&self) -> Result<Option<IntermediateReference>> {
        if !self.fd.metadata()?.is_file() {
            return Ok(None);
        }
        let mut bytes = [0; 72];
        match rfs::getxattr(self.path(), INTERNAL, &mut bytes[..]) {
            Ok(n) => Ok(Some(IntermediateReference::decode(&bytes[..n])?)),
            Err(rustix::io::Errno::NODATA) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    fn attr(&self, ino: INodeNo) -> Result<FileAttr> {
        let metadata = self.fd.metadata()?;
        Ok(FileAttr {
            ino,
            size: metadata.len(),
            blocks: metadata.blocks(),
            atime: metadata.accessed()?,
            mtime: metadata.modified()?,
            ctime: unix_time(metadata.ctime(), metadata.ctime_nsec())?,
            crtime: metadata.created().unwrap_or(SystemTime::UNIX_EPOCH),
            kind: FileType::from_std(metadata.file_type()).context("unsupported inode type")?,
            perm: (metadata.mode() & 0o7777) as u16,
            nlink: u32::try_from(metadata.nlink())?,
            uid: metadata.uid(),
            gid: metadata.gid(),
            rdev: u32::try_from(metadata.rdev())?,
            flags: 0,
            blksize: u32::try_from(metadata.blksize())?,
        })
    }
}
fn unix_time(seconds: i64, nanos: i64) -> Result<SystemTime> {
    let base = if seconds < 0 {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
    } else {
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds.unsigned_abs()))
    };
    base.and_then(|t| t.checked_add(Duration::from_nanos(nanos as u64)))
        .context("inode time overflow")
}
struct Entry {
    node: Arc<Node>,
    lookups: u64,
    opens: usize,
}
enum Handle {
    File {
        ino: INodeNo,
        file: Arc<File>,
    },
    Directory {
        ino: INodeNo,
        entries: Arc<Vec<(INodeNo, FileType, OsString)>>,
    },
}
struct Namespace {
    root_inode: u64,
    nodes: BTreeMap<INodeNo, Entry>,
    handles: BTreeMap<FileHandle, Handle>,
    next: u64,
}
impl Namespace {
    fn inode(&self, metadata: &fs::Metadata) -> Result<INodeNo> {
        if metadata.ino() == self.root_inode {
            Ok(INodeNo::ROOT)
        } else {
            Ok(INodeNo(
                metadata.ino().checked_add(2).context("inode overflow")?,
            ))
        }
    }
    fn register(&mut self, fd: File) -> Result<(INodeNo, Arc<Node>)> {
        let ino = self.inode(&fd.metadata()?)?;
        let entry = self.nodes.entry(ino).or_insert_with(|| Entry {
            node: Arc::new(Node {
                fd,
                mutation: Mutex::new(()),
            }),
            lookups: 0,
            opens: 0,
        });
        entry.lookups = entry
            .lookups
            .checked_add(1)
            .context("lookup count overflow")?;
        Ok((ino, Arc::clone(&entry.node)))
    }
    fn forget(&mut self, ino: INodeNo, count: u64) {
        if let Some(entry) = self.nodes.get_mut(&ino) {
            entry.lookups = entry.lookups.saturating_sub(count);
        }
        self.prune(ino);
    }
    fn prune(&mut self, ino: INodeNo) {
        if ino != INodeNo::ROOT
            && self
                .nodes
                .get(&ino)
                .is_some_and(|e| e.lookups == 0 && e.opens == 0)
        {
            self.nodes.remove(&ino);
        }
    }
    fn handle(&mut self, ino: INodeNo, handle: Handle) -> Result<FileHandle> {
        let id = FileHandle(self.next);
        self.next = self.next.checked_add(1).context("handle overflow")?;
        self.nodes.get_mut(&ino).context("unknown inode")?.opens += 1;
        self.handles.insert(id, handle);
        Ok(id)
    }
    fn release(&mut self, handle: FileHandle) {
        if let Some(handle) = self.handles.remove(&handle) {
            let ino = match handle {
                Handle::File { ino, .. } | Handle::Directory { ino, .. } => ino,
            };
            if let Some(entry) = self.nodes.get_mut(&ino) {
                entry.opens -= 1;
            }
            self.prune(ino);
        }
    }
}
type Spool = Arc<Mutex<Option<tempfile::TempPath>>>;
struct IntermediateFs {
    session: Ticket,
    content: Arc<dyn IntermediateContent>,
    namespace: Mutex<Namespace>,
    // No global lock is held during a network read. One verified file per
    // content identity is shared by all aliases in this mount.
    spools: Mutex<BTreeMap<(ContentId, u64), Spool>>,
    scratch: PathBuf,
}
impl IntermediateFs {
    fn node(&self, ino: INodeNo) -> Result<Arc<Node>> {
        lock(&self.namespace)?
            .nodes
            .get(&ino)
            .map(|e| Arc::clone(&e.node))
            .ok_or_else(missing)
    }
    fn child(&self, parent: INodeNo, name: &OsStr) -> Result<(INodeNo, Arc<Node>)> {
        let parent = self.node(parent)?;
        let file: File = rfs::openat(
            &parent.fd,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
        lock(&self.namespace)?.register(file)
    }
    fn file(&self, fh: FileHandle) -> Result<Arc<File>> {
        match lock(&self.namespace)?.handles.get(&fh) {
            Some(Handle::File { file, .. }) => Ok(Arc::clone(file)),
            _ => Err(io::Error::from_raw_os_error(libc::EBADF).into()),
        }
    }
    fn spool(&self, reference: IntermediateReference) -> Result<Arc<File>> {
        ensure!(
            reference.session == self.session,
            "foreign intermediate reference"
        );
        let slot = {
            let mut spools = lock(&self.spools)?;
            Arc::clone(
                spools
                    .entry((reference.blob.id, reference.blob.size))
                    .or_default(),
            )
        };
        let mut file = lock(&slot)?;
        if let Some(file) = file.as_ref() {
            return Ok(Arc::new(File::open(file)?));
        }
        let mut staged = tempfile::NamedTempFile::new_in(&self.scratch)?;
        self.content.fetch(reference, staged.as_file_mut())?;
        ensure!(
            staged.metadata()?.len() == reference.blob.size,
            "intermediate length mismatch"
        );
        staged.seek(SeekFrom::Start(0))?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0; 128 * 1024];
        loop {
            let count = staged.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        ensure!(
            hasher.finalize().as_bytes() == &reference.blob.id.0,
            "intermediate digest mismatch"
        );
        let reader = Arc::new(staged.reopen()?);
        *file = Some(staged.into_temp_path());
        Ok(reader)
    }
    // Caller holds the inode mutation lock. A write-open detaches before
    // returning to the kernel, so pending mmap writes cannot advertise a
    // stale immutable reference.
    fn detach(&self, node: &Node, discard: bool) -> Result<()> {
        let Some(reference) = node.reference()? else {
            return Ok(());
        };
        let destination = node.open(OFlags::WRONLY)?;
        if discard {
            destination.set_len(0)?;
        } else {
            let source = self.spool(reference)?;
            let previous = node.fd.metadata()?;
            let mut offset = 0;
            let mut bytes = vec![0; 128 * 1024];
            while offset < reference.blob.size {
                let n = source.read_at(&mut bytes, offset)?;
                ensure!(n != 0, "truncated intermediate spool");
                destination.write_all_at(&bytes[..n], offset)?;
                offset += n as u64;
            }
            destination.set_times(
                fs::FileTimes::new()
                    .set_accessed(previous.accessed()?)
                    .set_modified(previous.modified()?),
            )?;
        }
        // If copying fails, the reference remains authoritative even if its
        // private backing inode was partially filled.
        rfs::removexattr(node.path(), INTERNAL)?;
        Ok(())
    }
    fn open_file(&self, ino: INodeNo, flags: i32) -> Result<FileHandle> {
        let node = self.node(ino)?;
        let guard = lock(&node.mutation)?;
        if flags & (libc::O_ACCMODE | libc::O_TRUNC) != libc::O_RDONLY {
            self.detach(&node, flags & libc::O_TRUNC != 0)?;
        }
        // The FUSE kernel owns the logical file offset. Do not pass append
        // through to pwrite, which ignores its offset on Linux O_APPEND FDs.
        let flags = flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_APPEND | libc::O_NOFOLLOW);
        let file = Arc::new(node.open(OFlags::from_bits_truncate(flags as u32))?);
        drop(guard);
        lock(&self.namespace)?.handle(ino, Handle::File { ino, file })
    }
    fn attach(&self, node: &Node, reference: IntermediateReference) -> Result<()> {
        ensure!(
            reference.session == self.session,
            "foreign intermediate session"
        );
        self.content.authorize(reference)?;
        let _guard = lock(&node.mutation)?;
        let metadata = node.fd.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.len() == 0
                && metadata.nlink() == 1
                && node.reference()?.is_none(),
            "reference publication requires a fresh empty file"
        );
        let destination = node.open(OFlags::WRONLY)?;
        // Marker first. A failed length update cannot expose zero-filled
        // bytes, and the staging inode is never published on failure.
        rfs::setxattr(
            node.path(),
            INTERNAL,
            &reference.encode(),
            rfs::XattrFlags::CREATE,
        )?;
        if let Err(error) = destination.set_len(reference.blob.size) {
            let _ = rfs::removexattr(node.path(), INTERNAL);
            return Err(error.into());
        }
        Ok(())
    }
}

/// Mount a build-scoped intermediate filesystem over a private empty directory.
/// The returned session must outlive Cargo and its child processes.
/// # Errors
/// Returns an error when the backing directory or FUSE mount cannot be opened.
pub fn mount_intermediates(
    mount: &Path,
    backing: &Path,
    scratch: &Path,
    session: Ticket,
    content: Arc<dyn IntermediateContent>,
) -> Result<BackgroundSession> {
    let fd: File = rfs::open(
        backing,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into();
    let root_inode = fd.metadata()?.ino();
    let fs = IntermediateFs {
        session,
        content,
        scratch: scratch.to_owned(),
        spools: Mutex::default(),
        namespace: Mutex::new(Namespace {
            root_inode,
            nodes: BTreeMap::from([(
                INodeNo::ROOT,
                Entry {
                    node: Arc::new(Node {
                        fd,
                        mutation: Mutex::new(()),
                    }),
                    lookups: 1,
                    opens: 0,
                },
            )]),
            handles: BTreeMap::new(),
            next: 1,
        }),
    };
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::FSName("sccache-intermediates".into()),
        MountOption::DefaultPermissions,
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::Exec,
        MountOption::NoAtime,
    ];
    config.n_threads = Some(4);
    Ok(fuser::spawn_mount(fs, mount, &config)?)
}

fn is_fuse(file: &File) -> Result<bool> {
    Ok(rfs::fstatfs(file)?.f_type == 0x6573_5546)
}

/// Read the filesystem-provided session token without reading file data.
/// # Errors
/// Returns an error on malformed attributes or failed filesystem access.
pub fn intermediate_session(directory: &Path) -> Result<Option<Ticket>> {
    let file = File::open(directory)?;
    if !is_fuse(&file)? {
        return Ok(None);
    }
    let mut bytes = [0; 32];
    match rfs::fgetxattr(&file, SESSION_XATTR, &mut bytes[..]) {
        Ok(32) => Ok(Some(Ticket(bytes))),
        Ok(_) => anyhow::bail!("malformed intermediate session token"),
        Err(rustix::io::Errno::NODATA | rustix::io::Errno::NOTSUP | rustix::io::Errno::NOSYS) => {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

/// Obtain the exact reference from an already-open inode. The caller still
/// authenticates the token with its daemon before using the content identity.
/// # Errors
/// Returns an error on malformed attributes or failed filesystem access.
pub fn intermediate_reference(file: &File) -> Result<Option<IntermediateReference>> {
    if !file.metadata()?.is_file() || !is_fuse(file)? {
        return Ok(None);
    }
    let mut bytes = [0; 72];
    match rfs::fgetxattr(file, REFERENCE_XATTR, &mut bytes[..]) {
        Ok(n) => {
            let reference = IntermediateReference::decode(&bytes[..n])?;
            ensure!(
                reference.blob.size == file.metadata()?.len(),
                "intermediate inode length changed"
            );
            Ok(Some(reference))
        }
        Err(rustix::io::Errno::NODATA | rustix::io::Errno::NOTSUP | rustix::io::Errno::NOSYS) => {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

/// Install a reference on a fresh staging file. The FUSE server authenticates
/// it and supplies its exact size without downloading content.
/// # Errors
/// Returns an error for unknown leases, existing data or non-intermediate files.
pub fn attach_intermediate(file: &File, reference: IntermediateReference) -> Result<()> {
    ensure!(is_fuse(file)?, "intermediate output is not on a FUSE mount");
    rfs::fsetxattr(
        file,
        REFERENCE_XATTR,
        &reference.encode(),
        rfs::XattrFlags::CREATE,
    )?;
    ensure!(
        file.metadata()?.len() == reference.blob.size,
        "intermediate publication length mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
