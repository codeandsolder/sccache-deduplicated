//! Worker-side, read-only demand filesystem. The compiler runs in its
//! ordinary Bubblewrap namespace; it never receives origin credentials or
//! physical origin paths. Every content read is authorized by an observation
//! and admitted to the ordinary verified CAS before exposing any bytes.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};
use fuser::{
    BackgroundSession, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, LockOwner, MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, Request, Session,
};

use super::{
    DiscoveryBundle, DiscoveryInode, DiscoveryKind, DiscoveryMetadata, DiscoveryOrigin,
    DiscoveryQuery, DiscoveryReplay, DiscoveryReply, DiscoveryTranscript,
};
use crate::{BlobReader, BlobRef, BuildPath, ContentId, NativeStore, TreeLease, TreeTimestamp};

/// Session-scoped data transport. Implementations must authorize each blob
/// against this session's observation set. The worker independently verifies
/// transferred bytes via the ordinary CAS, including size and digest.
pub trait DiscoveryTransport: Send {
    /// # Errors
    /// Returns an error when the origin cannot complete the observation.
    fn query(&mut self, query: &DiscoveryQuery) -> Result<DiscoveryReply>;

    /// Confirm the complete observation set at the origin before it may be
    /// used as a dependency key. The origin rechecks its own observations,
    /// including negative results, rather than trusting the worker.
    /// # Errors
    /// Returns an error for origin mutation or transcript mismatch.
    fn seal(&mut self, transcript: &DiscoveryTranscript) -> Result<()>;

    /// # Errors
    /// Returns an error for unavailable or unauthorized content.
    fn open_blob(&mut self, blob: BlobRef) -> Result<Box<dyn Read + Send>>;
}

impl DiscoveryTransport for DiscoveryOrigin {
    fn query(&mut self, query: &DiscoveryQuery) -> Result<DiscoveryReply> {
        Self::query(self, query.clone())
    }

    fn seal(&mut self, transcript: &DiscoveryTranscript) -> Result<()> {
        ensure!(
            Self::seal(self)?.canonical()? == *transcript,
            "origin and worker discovery transcripts differ"
        );
        Ok(())
    }

    fn open_blob(&mut self, blob: BlobRef) -> Result<Box<dyn Read + Send>> {
        Ok(Box::new(Self::open_blob(self, blob)?))
    }
}

/// Final replay has all bytes in its admitted immutable input tree. It
/// cannot request origin metadata or additional content.
struct SealedTransport;

impl DiscoveryTransport for SealedTransport {
    fn query(&mut self, _: &DiscoveryQuery) -> Result<DiscoveryReply> {
        anyhow::bail!("sealed discovery replay cannot query the origin")
    }
    fn seal(&mut self, _: &DiscoveryTranscript) -> Result<()> {
        anyhow::bail!("sealed discovery replay cannot seal live observations")
    }
    fn open_blob(&mut self, _: BlobRef) -> Result<Box<dyn Read + Send>> {
        anyhow::bail!("sealed discovery replay input blob missing from CAS")
    }
}

enum Mode {
    Record(DiscoveryTranscript),
    Replay(DiscoveryReplay),
}

struct State {
    transport: Box<dyn DiscoveryTransport>,
    mode: Mode,
    store: NativeStore,
    content: BTreeMap<ContentId, TreeLease>,
    failure: Option<String>,
    roots: BTreeSet<BuildPath>,
    expected_roots: Option<BTreeSet<BuildPath>>,
}

impl State {
    fn observe(&mut self, query: DiscoveryQuery) -> Result<DiscoveryReply> {
        match &mut self.mode {
            Mode::Record(transcript) => {
                if let Some(reply) = transcript.get(&query) {
                    return Ok(reply.clone());
                }
                let reply = self.transport.query(&query)?;
                transcript.record(query, reply.clone())?;
                Ok(reply)
            }
            Mode::Replay(replay) => Ok(replay.query(&query)?.clone()),
        }
    }

    fn content(
        &mut self,
        path: &BuildPath,
        expected: DiscoveryMetadata,
        size: u64,
        scope: &BuildPath,
    ) -> Result<BlobReader> {
        // The kernel opens an inode, not a dentry. If lookup order changes
        // between live discovery and replay, the representative path of a
        // hardlink group may differ. Use the actual recorded content read
        // for this inode within this mount, never a different inode's bytes.
        let query = DiscoveryQuery::ReadFile(path.clone());
        let query = if let Mode::Replay(replay) = &self.mode {
            replay.file_query(query, expected.inode, scope)?
        } else {
            query
        };
        let DiscoveryReply::File { metadata, blob } = self.observe(query)? else {
            anyhow::bail!("discovered regular file disappeared before content read");
        };
        ensure!(
            metadata == expected && blob.size == size,
            "discovered file metadata changed before read"
        );
        if let Some(lease) = self.content.get(&blob.id) {
            ensure!(
                lease.blobs().get(&blob.id) == Some(&blob.size),
                "inconsistent discovery blob length"
            );
            return lease.open_decoded(blob.id);
        }
        let manifest = NativeStore::blob_retention_manifest(blob)?;
        let lease = if let Some(lease) = self.store.lookup_tree(manifest.id()?)? {
            lease
        } else {
            let reservation = self
                .store
                .reserve_blobs(&BTreeMap::from([(blob.id, blob.size)]))?;
            let staged = if reservation.missing().is_empty() {
                Vec::new()
            } else {
                vec![
                    self.store
                        .stage_expected(blob, self.transport.open_blob(blob)?)?,
                ]
            };
            let lease = self.store.publish_tree_pinned(&manifest, staged)?;
            drop(reservation);
            lease
        };
        let reader = lease.open_decoded(blob.id)?;
        self.content.insert(blob.id, lease);
        Ok(reader)
    }

    fn fail(&mut self, error: &anyhow::Error) {
        if self.failure.is_none() {
            self.failure = Some(format!("{error:#}"));
        }
    }
}

/// One discovery or exact replay session. Multiple disjoint logical roots
/// may be mounted using the same session and ordinary content store. A
/// result is usable only after all mounts have joined successfully and the
/// complete observation set has been validated.
pub struct DiscoverySession(Arc<Mutex<State>>);

impl DiscoverySession {
    /// # Errors
    /// Returns an error for a malformed replay transcript.
    pub fn new(
        store: NativeStore,
        transport: impl DiscoveryTransport + 'static,
        replay: Option<DiscoveryBundle>,
    ) -> Result<Self> {
        let (mode, expected_roots) = match replay {
            Some(bundle) => (
                Mode::Replay(DiscoveryReplay::new(bundle.transcript().clone())?),
                Some(bundle.roots().clone()),
            ),
            None => (Mode::Record(DiscoveryTranscript::default()), None),
        };
        Ok(Self(Arc::new(Mutex::new(State {
            transport: Box::new(transport),
            mode,
            store,
            content: BTreeMap::new(),
            failure: None,
            roots: BTreeSet::new(),
            expected_roots,
        }))))
    }

    /// Construct a replay that can only access the admitted CAS contents.
    /// # Errors
    /// Returns an error for an invalid discovery package.
    pub fn replay(store: NativeStore, bundle: DiscoveryBundle) -> Result<Self> {
        Self::new(store, SealedTransport, Some(bundle))
    }

    /// Mount a logical directory under a private worker scratch directory.
    /// No origin filesystem path is mounted on the worker.
    /// # Errors
    /// Returns an error for invalid roots, observations or FUSE initialization.
    pub fn mount(&self, logical: BuildPath, scratch: &Path) -> Result<DiscoveryMount> {
        let result = self.mount_inner(logical, scratch);
        if let Err(error) = &result
            && let Ok(mut state) = self.0.lock()
        {
            state.fail(error);
        }
        result
    }

    fn mount_inner(&self, logical: BuildPath, scratch: &Path) -> Result<DiscoveryMount> {
        let fs = DiscoveryFs::new(Arc::clone(&self.0), logical)?;
        let directory = tempfile::Builder::new()
            .prefix("discovery-fuse-")
            .tempdir_in(scratch)?;
        let root = directory.path().join("root");
        fs::create_dir(&root)?;
        let mut config = Config::default();
        config.mount_options = vec![
            MountOption::RO,
            MountOption::DefaultPermissions,
            MountOption::NoDev,
            MountOption::NoSuid,
            MountOption::FSName("sccache-discovery".into()),
        ];
        let session = Session::new(fs, &root, &config)?.spawn()?;
        Ok(DiscoveryMount {
            session: Some(session),
            state: Arc::clone(&self.0),
            root,
            _directory: directory,
        })
    }

    /// Finish after every mount has been explicitly unmounted and joined.
    /// A backend I/O error invalidates the action even if the compiler
    /// ignored its resulting errno and exited successfully.
    /// # Errors
    /// Returns an error for active mounts, observation failures or replay drift.
    pub fn finish(self) -> Result<DiscoveredInputs> {
        let mut state = Arc::try_unwrap(self.0)
            .map_err(|_| anyhow::anyhow!("discovery mounts are still active"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("discovery session poisoned"))?;
        ensure!(
            state.failure.is_none(),
            "discovery filesystem failed: {}",
            state.failure.as_deref().unwrap_or_default()
        );
        ensure!(
            state
                .expected_roots
                .as_ref()
                .is_none_or(|roots| roots == &state.roots),
            "replay did not mount the complete observed namespace"
        );
        let transcript = match state.mode {
            Mode::Record(transcript) => {
                let transcript = transcript.canonical()?;
                state.transport.seal(&transcript)?;
                transcript
            }
            Mode::Replay(replay) => replay.finish()?,
        };
        Ok(DiscoveredInputs {
            bundle: DiscoveryBundle::new(state.roots, transcript)?,
            content: state.content,
        })
    }
}

/// A sealed dependency transcript and its verified, pinned CAS content.
pub struct DiscoveredInputs {
    bundle: DiscoveryBundle,
    content: BTreeMap<ContentId, TreeLease>,
}

impl DiscoveredInputs {
    #[must_use]
    pub const fn transcript(&self) -> &DiscoveryTranscript {
        self.bundle.transcript()
    }

    #[must_use]
    pub const fn bundle(&self) -> &DiscoveryBundle {
        &self.bundle
    }

    /// Publish the observation record and its existing content references
    /// through the ordinary CAS tree transaction. No blob is copied.
    /// # Errors
    /// Returns an error for foreign content leases or failed publication.
    pub fn publish(&self, store: &NativeStore) -> Result<TreeLease> {
        ensure!(
            self.content.values().all(|lease| lease.belongs_to(store)),
            "discovered content belongs to a different store"
        );
        let (encoded, manifest) = self.bundle.encode()?;
        let record = store.stage(encoded.as_slice())?;
        store.publish_tree_pinned(&manifest, vec![record])
    }

    /// # Errors
    /// Returns an error for an undeclared or unavailable content blob.
    pub fn open_blob(&self, blob: BlobRef) -> Result<BlobReader> {
        let lease = self
            .content
            .get(&blob.id)
            .context("content was not discovered")?;
        ensure!(
            lease.blobs().get(&blob.id) == Some(&blob.size),
            "discovered blob length mismatch"
        );
        lease.open_decoded(blob.id)
    }
}

/// Owned FUSE mount. The worker binds root() read-only into Bubblewrap.
/// Explicit unmount is required before publishing an action.
pub struct DiscoveryMount {
    session: Option<BackgroundSession>,
    state: Arc<Mutex<State>>,
    root: PathBuf,
    _directory: tempfile::TempDir,
}

impl DiscoveryMount {
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// # Errors
    /// Returns an error if unmount or the FUSE session fails.
    pub fn unmount(mut self) -> Result<()> {
        let result = self
            .session
            .take()
            .context("discovery mount already closed")?
            .umount_and_join();
        if let Err(error) = result {
            let error = anyhow::Error::from(error).context("unmount discovery filesystem");
            if let Ok(mut state) = self.state.lock() {
                state.fail(&error);
            }
            return Err(error);
        }
        Ok(())
    }
}

impl Drop for DiscoveryMount {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            let result = session.umount_and_join();
            if let Ok(mut state) = self.state.lock() {
                let error = match result {
                    Ok(()) => {
                        anyhow::anyhow!("discovery mount dropped without explicit completion")
                    }
                    Err(error) => anyhow::Error::from(error).context("drop discovery mount"),
                };
                state.fail(&error);
            }
        }
    }
}

const TTL: Duration = Duration::from_secs(3600);

#[derive(Clone, PartialEq, Eq)]
enum NodeKind {
    Directory(DiscoveryMetadata),
    Regular(DiscoveryMetadata, u64),
    Symlink {
        inode: DiscoveryInode,
        links: u32,
        target: Vec<u8>,
        modified: TreeTimestamp,
    },
}

impl NodeKind {
    fn from_reply(reply: DiscoveryReply) -> FsResult<Self> {
        match reply {
            DiscoveryReply::Directory(meta) => Ok(Self::Directory(meta)),
            DiscoveryReply::Regular { metadata, size } => Ok(Self::Regular(metadata, size)),
            DiscoveryReply::Symlink {
                inode,
                links,
                target,
                modified,
            } => Ok(Self::Symlink {
                inode,
                links,
                target,
                modified,
            }),
            DiscoveryReply::Missing => Err(FsError::Expected(Errno::ENOENT)),
            DiscoveryReply::NotDirectory => Err(FsError::Expected(Errno::ENOTDIR)),
            _ => Err(anyhow::anyhow!("invalid discovery lookup reply").into()),
        }
    }

    const fn identity(&self) -> DiscoveryInode {
        match self {
            Self::Directory(meta) | Self::Regular(meta, _) => meta.inode,
            Self::Symlink { inode, .. } => *inode,
        }
    }

    fn attr(&self, ino: INodeNo) -> Result<FileAttr> {
        let (kind, mode, size, modified, nlink) = match self {
            Self::Directory(meta) => (
                FileType::Directory,
                meta.metadata.mode,
                0,
                meta.metadata.modified,
                meta.links,
            ),
            Self::Regular(meta, size) => (
                FileType::RegularFile,
                meta.metadata.mode,
                *size,
                meta.metadata.modified,
                meta.links,
            ),
            Self::Symlink {
                links,
                target,
                modified,
                ..
            } => (
                FileType::Symlink,
                0o777,
                u64::try_from(target.len())?,
                *modified,
                *links,
            ),
        };
        let secs = Duration::from_secs(modified.seconds.unsigned_abs());
        let nanos = Duration::from_nanos(u64::from(modified.nanoseconds));
        let base = if modified.seconds < 0 {
            SystemTime::UNIX_EPOCH.checked_sub(secs)
        } else {
            SystemTime::UNIX_EPOCH.checked_add(secs)
        };
        let time = base
            .and_then(|t| t.checked_add(nanos))
            .context("discovery timestamp overflow")?;
        Ok(FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind,
            perm: u16::try_from(mode & 0o1777)?,
            nlink,
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
            rdev: 0,
            flags: 0,
            blksize: 4096,
        })
    }
}

struct Node {
    path: BuildPath,
    parent: INodeNo,
    kind: NodeKind,
}

struct Handle {
    inode: INodeNo,
    reader: Option<BlobReader>,
}

struct Namespace {
    inodes: BTreeMap<DiscoveryInode, INodeNo>,
    nodes: BTreeMap<INodeNo, Node>,
    handles: BTreeMap<FileHandle, Handle>,
    next_handle: u64,
    replay: bool,
}

impl Namespace {
    fn intern(&mut self, identity: DiscoveryInode) -> Result<INodeNo> {
        if let Some(&ino) = self.inodes.get(&identity) {
            return Ok(ino);
        }
        // Live discovery's output is never published. Exact replay uses
        // canonical transcript inode identities, independent of lookup order.
        let ino = if self.replay {
            identity
                .replay_inode()?
                .checked_add(1)
                .context("discovery inode overflow")?
        } else {
            u64::try_from(self.inodes.len())?
                .checked_add(1)
                .context("discovery inode overflow")?
        };
        let ino = INodeNo(ino);
        self.inodes.insert(identity, ino);
        Ok(ino)
    }

    fn node(&self, ino: INodeNo) -> Result<&Node> {
        self.nodes.get(&ino).context("unknown discovery inode")
    }

    fn lookup(&mut self, state: &mut State, parent: INodeNo, name: &OsStr) -> FsResult<FileAttr> {
        let node = self.node(parent)?;
        if !matches!(node.kind, NodeKind::Directory(_)) {
            return Err(FsError::Expected(Errno::ENOTDIR));
        }
        let path = child_path(&node.path, name)?;
        let kind = NodeKind::from_reply(state.observe(DiscoveryQuery::Lookup(path.clone()))?)?;
        let ino = self.intern(kind.identity())?;
        if let Some(previous) = self.nodes.get(&ino) {
            ensure_node(previous, &path, &kind)?;
        } else {
            self.nodes.insert(ino, Node { path, parent, kind });
        }
        Ok(self.node(ino)?.kind.attr(ino)?)
    }

    fn directory(
        &mut self,
        state: &mut State,
        ino: INodeNo,
    ) -> FsResult<Vec<(INodeNo, FileType, OsString)>> {
        let node = self.node(ino)?;
        if !matches!(node.kind, NodeKind::Directory(_)) {
            return Err(FsError::Expected(Errno::ENOTDIR));
        }
        let parent = node.parent;
        let DiscoveryReply::DirectoryEntries(entries) =
            state.observe(DiscoveryQuery::ReadDirectory(node.path.clone()))?
        else {
            return Err(anyhow::anyhow!("discovery directory changed before enumeration").into());
        };
        let mut directory = vec![
            (ino, FileType::Directory, ".".into()),
            (parent, FileType::Directory, "..".into()),
        ];
        for entry in entries {
            let child = self.intern(entry.inode)?;
            let kind = match entry.kind {
                DiscoveryKind::Directory => FileType::Directory,
                DiscoveryKind::Regular => FileType::RegularFile,
                DiscoveryKind::Symlink => FileType::Symlink,
                DiscoveryKind::Fifo => FileType::NamedPipe,
                DiscoveryKind::Socket => FileType::Socket,
                DiscoveryKind::CharacterDevice => FileType::CharDevice,
                DiscoveryKind::BlockDevice => FileType::BlockDevice,
                DiscoveryKind::Unknown => {
                    return Err(anyhow::anyhow!("unresolved discovery directory entry type").into());
                }
            };
            directory.push((child, kind, OsStr::from_bytes(&entry.name).to_owned()));
        }
        Ok(directory)
    }

    fn open(
        &mut self,
        ino: INodeNo,
        flags: OpenFlags,
        kill_suid_gid: bool,
    ) -> FsResult<FileHandle> {
        if flags.0 & (libc::O_ACCMODE | libc::O_TRUNC) != libc::O_RDONLY || kill_suid_gid {
            return Err(FsError::Expected(Errno::EROFS));
        }
        if !matches!(self.node(ino)?.kind, NodeKind::Regular(..)) {
            return Err(FsError::Expected(Errno::EISDIR));
        }
        let handle = FileHandle(self.next_handle);
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .context("discovery file handle overflow")?;
        self.handles.insert(
            handle,
            Handle {
                inode: ino,
                reader: None,
            },
        );
        Ok(handle)
    }

    fn read(
        &mut self,
        state: &mut State,
        scope: &BuildPath,
        ino: INodeNo,
        handle: FileHandle,
        offset: u64,
        size: u32,
    ) -> FsResult<Vec<u8>> {
        let node = self.nodes.get(&ino).context("unknown discovery inode")?;
        let NodeKind::Regular(meta, length) = node.kind else {
            return Err(FsError::Expected(Errno::EISDIR));
        };
        let file = self
            .handles
            .get_mut(&handle)
            .filter(|file| file.inode == ino)
            .context("unknown discovery file handle")?;
        let count = u64::from(size).min(length.saturating_sub(offset));
        if count == 0 {
            return Ok(Vec::new());
        }
        if file.reader.is_none() {
            file.reader = Some(state.content(&node.path, meta, length, scope)?);
        }
        let reader = file
            .reader
            .as_mut()
            .context("discovery content reader missing")?;
        reader
            .seek(SeekFrom::Start(offset))
            .context("seek discovered CAS file")?;
        let mut bytes = vec![0; usize::try_from(count).context("discovery read size overflow")?];
        reader
            .read_exact(&mut bytes)
            .context("read discovered CAS file")?;
        Ok(bytes)
    }
}

fn child_path(parent: &BuildPath, name: &OsStr) -> Result<BuildPath> {
    let mut path = parent.as_bytes().to_vec();
    if path != b"/" {
        path.push(b'/');
    }
    path.extend_from_slice(name.as_bytes());
    BuildPath::new(path)
}

fn ensure_node(previous: &Node, path: &BuildPath, kind: &NodeKind) -> Result<()> {
    ensure!(
        &previous.kind == kind,
        "inconsistent metadata for discovered inode aliases"
    );
    // Linux permits directory aliases through distinct mounts, not
    // directory hardlinks inside one FUSE namespace. Separate mount roots
    // preserve that distinction instead of choosing an arbitrary parent.
    ensure!(
        !matches!(kind, NodeKind::Directory(_)) || &previous.path == path,
        "directory aliases require distinct discovery mounts"
    );
    Ok(())
}

enum FsError {
    Expected(Errno),
    Infrastructure(anyhow::Error),
}

impl From<anyhow::Error> for FsError {
    fn from(error: anyhow::Error) -> Self {
        Self::Infrastructure(error)
    }
}
type FsResult<T> = std::result::Result<T, FsError>;

struct DiscoveryFs {
    scope: BuildPath,
    state: Arc<Mutex<State>>,
    namespace: Mutex<Namespace>,
}

impl DiscoveryFs {
    fn new(state: Arc<Mutex<State>>, scope: BuildPath) -> Result<Self> {
        let mut locked = state
            .lock()
            .map_err(|_| anyhow::anyhow!("discovery session poisoned"))?;
        ensure!(
            locked
                .expected_roots
                .as_ref()
                .is_none_or(|roots| roots.contains(&scope)),
            "unobserved discovery mount"
        );
        ensure!(
            locked.roots.insert(scope.clone()),
            "duplicate discovery mount"
        );
        let reply = locked.observe(DiscoveryQuery::Lookup(scope.clone()))?;
        let DiscoveryReply::Directory(metadata) = reply else {
            anyhow::bail!("discovery mount root is not a directory");
        };
        let replay = matches!(locked.mode, Mode::Replay(_));
        drop(locked);
        let kind = NodeKind::Directory(metadata);
        let namespace = Namespace {
            inodes: BTreeMap::from([(kind.identity(), INodeNo::ROOT)]),
            nodes: BTreeMap::from([(
                INodeNo::ROOT,
                Node {
                    path: scope.clone(),
                    parent: INodeNo::ROOT,
                    kind,
                },
            )]),
            handles: BTreeMap::new(),
            next_handle: 1,
            replay,
        };
        Ok(Self {
            scope,
            state,
            namespace: Mutex::new(namespace),
        })
    }

    fn call<T>(
        &self,
        f: impl FnOnce(&mut Namespace, &mut State) -> FsResult<T>,
    ) -> std::result::Result<T, Errno> {
        let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
        if state.failure.is_some() {
            return Err(Errno::EIO);
        }
        let Ok(mut namespace) = self.namespace.lock() else {
            state.fail(&anyhow::anyhow!("discovery inode table poisoned"));
            return Err(Errno::EIO);
        };
        match f(&mut namespace, &mut state) {
            Ok(value) => Ok(value),
            Err(FsError::Expected(errno)) => Err(errno),
            Err(FsError::Infrastructure(error)) => {
                state.fail(&error);
                Err(Errno::EIO)
            }
        }
    }
}

impl Filesystem for DiscoveryFs {
    fn lookup(&self, _: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.call(|ns, state| ns.lookup(state, parent, name)) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(errno) => reply.error(errno),
        }
    }

    fn getattr(&self, _: &Request, ino: INodeNo, _: Option<FileHandle>, reply: ReplyAttr) {
        match self.call(|ns, _| Ok(ns.node(ino)?.kind.attr(ino)?)) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(errno) => reply.error(errno),
        }
    }

    fn readlink(&self, _: &Request, ino: INodeNo, reply: ReplyData) {
        match self.call(|ns, _| match &ns.node(ino)?.kind {
            NodeKind::Symlink { target, .. } => Ok(target.clone()),
            _ => Err(FsError::Expected(Errno::EINVAL)),
        }) {
            Ok(target) => reply.data(&target),
            Err(errno) => reply.error(errno),
        }
    }

    fn readdir(
        &self,
        _: &Request,
        ino: INodeNo,
        _: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        match self.call(|ns, state| ns.directory(state, ino)) {
            Ok(entries) => {
                let Ok(offset) = usize::try_from(offset) else {
                    reply.error(Errno::EOVERFLOW);
                    return;
                };
                for (index, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset) {
                    let Some(cookie) = index.checked_add(1).and_then(|i| u64::try_from(i).ok())
                    else {
                        reply.error(Errno::EOVERFLOW);
                        return;
                    };
                    if reply.add(ino, cookie, kind, name) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(errno) => reply.error(errno),
        }
    }

    fn open(
        &self,
        _: &Request,
        ino: INodeNo,
        flags: OpenFlags,
        kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        match self.call(|ns, _| ns.open(ino, flags, kill_suid_gid)) {
            Ok(handle) => reply.opened(handle, FopenFlags::FOPEN_KEEP_CACHE),
            Err(errno) => reply.error(errno),
        }
    }

    fn read(
        &self,
        _: &Request,
        ino: INodeNo,
        handle: FileHandle,
        offset: u64,
        size: u32,
        _: OpenFlags,
        _: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.call(|ns, state| ns.read(state, &self.scope, ino, handle, offset, size)) {
            Ok(bytes) => reply.data(&bytes),
            Err(errno) => reply.error(errno),
        }
    }

    fn release(
        &self,
        _: &Request,
        _: INodeNo,
        handle: FileHandle,
        _: OpenFlags,
        _: Option<LockOwner>,
        _: bool,
        reply: ReplyEmpty,
    ) {
        match self.call(|ns, _| {
            ns.handles
                .remove(&handle)
                .context("unknown released discovery handle")?;
            Ok(())
        }) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }
}

#[cfg(test)]
mod tests;
