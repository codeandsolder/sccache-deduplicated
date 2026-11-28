//! Path-oriented input discovery. Only explicitly observed file contents are
//! hashed. Directory enumeration and metadata queries have separate results:
//! enumerating a directory does not turn every member into a content input.
//!
//! The origin owns a bounded set of directory capabilities. The worker must
//! resolve symlinks in its logical namespace and request the resulting paths;
//! the origin never follows a worker-supplied symlink through an authority
//! boundary. This module does not run a compiler or grant execution authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::File,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use rustix::{
    fs::{
        CWD, Dir, FileType, Mode, OFlags, ResolveFlags, Stat, fstat, openat, openat2, readlinkat,
    },
    io::Errno,
};
use serde::{Deserialize, Serialize};

use crate::{
    BlobRef, BuildPath, ContentId, TreeMetadata, TreeTimestamp, hash_descriptor,
    identity::typed_digest,
    source::{metadata, timestamp, unchanged},
};

#[cfg(feature = "store")]
mod filesystem;
#[cfg(feature = "store")]
pub use filesystem::{DiscoveredInputs, DiscoveryMount, DiscoverySession, DiscoveryTransport};

/// A logical operation, not a physical origin path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DiscoveryQuery {
    Lookup(BuildPath),
    ReadDirectory(BuildPath),
    ReadFile(BuildPath),
}

impl DiscoveryQuery {
    fn path(&self) -> &BuildPath {
        match self {
            Self::Lookup(path) | Self::ReadDirectory(path) | Self::ReadFile(path) => path,
        }
    }

    fn validate(&self) -> Result<()> {
        BuildPath::new(self.path().as_bytes().to_vec())?;
        Ok(())
    }
}

/// The type exposed by directory enumeration. Unknown is a real getdents
/// result; asking for metadata is a distinct operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryKind {
    Directory,
    Regular,
    Symlink,
    Fifo,
    Socket,
    CharacterDevice,
    BlockDevice,
    Unknown,
}

impl From<FileType> for DiscoveryKind {
    fn from(kind: FileType) -> Self {
        match kind {
            FileType::Directory => Self::Directory,
            FileType::RegularFile => Self::Regular,
            FileType::Symlink => Self::Symlink,
            FileType::Fifo => Self::Fifo,
            FileType::Socket => Self::Socket,
            FileType::CharacterDevice => Self::CharacterDevice,
            FileType::BlockDevice => Self::BlockDevice,
            FileType::Unknown => Self::Unknown,
        }
    }
}

/// Origin-local inode identity. The transcript canonicalizes equivalence
/// classes before hashing: device and inode numbers are never cache keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DiscoveryInode {
    device: u64,
    inode: u64,
}

impl DiscoveryInode {
    #[cfg(feature = "store")]
    fn replay_inode(self) -> Result<u64> {
        ensure!(
            self.device == 0 && self.inode != 0,
            "noncanonical replay inode"
        );
        Ok(self.inode)
    }

    fn from_stat(stat: &Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryMetadata {
    pub inode: DiscoveryInode,
    pub metadata: TreeMetadata,
    pub links: u32,
}

impl DiscoveryMetadata {
    fn from_stat(stat: &Stat) -> Result<Self> {
        Ok(Self {
            inode: DiscoveryInode::from_stat(stat),
            metadata: metadata(stat)?,
            links: u32::try_from(stat.st_nlink)?,
        })
    }

    fn validate(self) -> Result<()> {
        self.metadata.validate()?;
        ensure!(self.links > 0, "discovery inode has no links");
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDirent {
    pub name: Vec<u8>,
    pub kind: DiscoveryKind,
    pub inode: DiscoveryInode,
}

/// Lookup and read results share the same normalized metadata contract as
/// immutable native trees. Raw host device/inode numbers and ctime do not
/// become cross-worker action keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryReply {
    Missing,
    NotDirectory,
    IsDirectory,
    Directory(DiscoveryMetadata),
    Regular {
        metadata: DiscoveryMetadata,
        size: u64,
    },
    Symlink {
        inode: DiscoveryInode,
        links: u32,
        target: Vec<u8>,
        modified: TreeTimestamp,
    },
    DirectoryEntries(Vec<DiscoveryDirent>),
    File {
        metadata: DiscoveryMetadata,
        blob: BlobRef,
    },
}

impl DiscoveryReply {
    fn normalize_inodes(
        &mut self,
        aliases: &mut BTreeMap<DiscoveryInode, DiscoveryInode>,
    ) -> Result<()> {
        let mut normalize = |inode: &mut DiscoveryInode| -> Result<()> {
            let next = u64::try_from(aliases.len())?
                .checked_add(1)
                .context("discovery inode count overflow")?;
            *inode = *aliases.entry(*inode).or_insert(DiscoveryInode {
                device: 0,
                inode: next,
            });
            Ok(())
        };
        match self {
            Self::Directory(meta)
            | Self::Regular { metadata: meta, .. }
            | Self::File { metadata: meta, .. } => normalize(&mut meta.inode)?,
            Self::Symlink { inode, .. } => normalize(inode)?,
            Self::DirectoryEntries(entries) => {
                for entry in entries {
                    normalize(&mut entry.inode)?;
                }
            }
            Self::Missing | Self::NotDirectory | Self::IsDirectory => {}
        }
        Ok(())
    }

    fn validate(&self, query: &DiscoveryQuery) -> Result<()> {
        use DiscoveryQuery as Q;
        use DiscoveryReply as R;
        match (query, self) {
            (_, R::Missing | R::NotDirectory) | (Q::ReadFile(_), R::IsDirectory) => Ok(()),
            (Q::Lookup(_), R::Directory(meta) | R::Regular { metadata: meta, .. })
            | (Q::ReadFile(_), R::File { metadata: meta, .. }) => meta.validate(),
            (
                Q::Lookup(_),
                R::Symlink {
                    target,
                    modified,
                    links,
                    ..
                },
            ) => {
                ensure!(
                    !target.is_empty() && !target.contains(&0) && *links > 0,
                    "invalid discovery symlink"
                );
                ensure!(
                    modified.nanoseconds < 1_000_000_000,
                    "invalid discovery timestamp"
                );
                Ok(())
            }
            (Q::ReadDirectory(_), R::DirectoryEntries(entries)) => {
                let mut previous: Option<&[u8]> = None;
                for entry in entries {
                    let name = entry.name.as_slice();
                    ensure!(
                        !name.is_empty()
                            && name != b"."
                            && name != b".."
                            && !name.contains(&b'/')
                            && !name.contains(&0),
                        "invalid discovery directory entry"
                    );
                    ensure!(
                        previous.is_none_or(|old| old < name),
                        "unordered or duplicate discovery directory entry"
                    );
                    previous = Some(name);
                }
                Ok(())
            }
            _ => anyhow::bail!("discovery reply does not match query"),
        }
    }
}

/// A deterministic transcript is the dependency evidence, not an execution
/// authorization. An exact replay must honor every recorded operation and
/// reject accesses outside it. A directory listing contains names and kinds
/// only; content enters the transcript exclusively via ReadFile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DiscoveryTranscript(BTreeMap<DiscoveryQuery, DiscoveryReply>);

impl DiscoveryTranscript {
    /// Record a complete, validated observation. Repeated observations of
    /// the same operation must be identical.
    /// # Errors
    /// Returns an error for malformed or inconsistent observations.
    pub fn record(&mut self, query: DiscoveryQuery, reply: DiscoveryReply) -> Result<()> {
        query.validate()?;
        reply.validate(&query)?;
        match self.0.entry(query) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(reply);
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                ensure!(
                    entry.get() == &reply,
                    "discovery input changed during observation: {:?}",
                    entry.key()
                );
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn get(&self, query: &DiscoveryQuery) -> Option<&DiscoveryReply> {
        self.0.get(query)
    }

    /// Canonicalize the observed inode equivalence relation, in query/path
    /// order, independent of host inode numbers or discovery concurrency.
    /// The replay uses these same normalized identities.
    /// # Errors
    /// Returns an error for invalid observations, including deserialized data.
    pub fn canonical(&self) -> Result<Self> {
        let mut canonical = self.clone();
        let mut aliases = BTreeMap::new();
        for (query, reply) in &mut canonical.0 {
            query.validate()?;
            reply.validate(query)?;
            reply.normalize_inodes(&mut aliases)?;
        }
        Ok(canonical)
    }

    /// # Errors
    /// Returns an error for invalid observations, including deserialized data.
    pub fn fingerprint(&self) -> Result<ContentId> {
        Ok(ContentId(typed_digest(
            b"sccache-input-discovery-v2\0",
            &self.canonical()?.0,
        )?))
    }

    #[must_use]
    pub fn observations(&self) -> &BTreeMap<DiscoveryQuery, DiscoveryReply> {
        &self.0
    }
}

/// Enforce the sealed filesystem observations during replay. Missing
/// observations are infrastructure errors, not an ENOENT response. A
/// compiler cannot accidentally succeed after seeing an incomplete view.
pub struct DiscoveryReplay {
    transcript: DiscoveryTranscript,
    seen: BTreeSet<DiscoveryQuery>,
    failed: bool,
}

impl DiscoveryReplay {
    /// # Errors
    /// Returns an error for a malformed transcript.
    pub fn new(transcript: DiscoveryTranscript) -> Result<Self> {
        let transcript = transcript.canonical()?;
        Ok(Self {
            transcript,
            seen: BTreeSet::new(),
            failed: false,
        })
    }

    /// # Errors
    /// Returns an error for an operation not authorized by discovery.
    pub fn query(&mut self, query: &DiscoveryQuery) -> Result<&DiscoveryReply> {
        let Some(reply) = self.transcript.get(query) else {
            self.failed = true;
            anyhow::bail!("unobserved filesystem operation during replay: {query:?}");
        };
        self.seen.insert(query.clone());
        Ok(reply)
    }

    #[cfg(feature = "store")]
    fn file_query(
        &self,
        query: DiscoveryQuery,
        inode: DiscoveryInode,
        scope: &BuildPath,
    ) -> Result<DiscoveryQuery> {
        if self.transcript.get(&query).is_some() {
            return Ok(query);
        }
        self.transcript
            .0
            .iter()
            .find_map(|(candidate, reply)| {
                if let (DiscoveryQuery::ReadFile(path), DiscoveryReply::File { metadata, .. }) =
                    (candidate, reply)
                    && path.within(scope.as_bytes())
                    && metadata.inode == inode
                {
                    return Some(candidate.clone());
                }
                None
            })
            .context("unobserved file content during replay")
    }

    /// A replay with a different observation set must not be published under
    /// the discovered action identity. This also prevents accumulating stale
    /// dependencies merely because a previous run happened to observe them.
    /// # Errors
    /// Returns an error if replay did not use all observations.
    pub fn finish(self) -> Result<DiscoveryTranscript> {
        ensure!(
            !self.failed && self.seen.len() == self.transcript.0.len(),
            "replay did not consume the complete discovery transcript"
        );
        Ok(self.transcript)
    }
}

/// Caller-selected total resource budgets. Limits are admission policy, not
/// part of the dependency fingerprint of a successfully observed input.
#[derive(Debug, Clone, Copy)]
pub struct DiscoveryLimits {
    pub max_queries: usize,
    pub max_dirents: usize,
    pub max_content_bytes: u64,
}

/// Descriptor-scoped origin service. Construct it from caller-authorized
/// roots, never from paths supplied by the executing worker. The longest
/// matching logical root selects a pinned origin directory. File bytes
/// remain in pinned descriptors until the discovery session is released.
pub struct DiscoveryOrigin {
    roots: BTreeMap<BuildPath, File>,
    files: BTreeMap<ContentId, File>,
    transcript: DiscoveryTranscript,
    limits: DiscoveryLimits,
    dirents: usize,
    content_bytes: u64,
}

impl DiscoveryOrigin {
    /// # Errors
    /// Returns an error for a zero resource limit.
    pub fn new(limits: DiscoveryLimits) -> Result<Self> {
        ensure!(
            limits.max_queries > 0 && limits.max_dirents > 0 && limits.max_content_bytes > 0,
            "invalid discovery limits"
        );
        Ok(Self {
            roots: BTreeMap::new(),
            files: BTreeMap::new(),
            transcript: DiscoveryTranscript::default(),
            limits,
            dirents: 0,
            content_bytes: 0,
        })
    }

    /// Add a caller-selected directory authority before any observation.
    /// # Errors
    /// Returns an error for invalid, duplicate, or inaccessible roots.
    pub fn add_root(&mut self, logical: BuildPath, physical: &Path) -> Result<()> {
        ensure!(
            self.transcript.0.is_empty(),
            "cannot change active discovery roots"
        );
        BuildPath::new(logical.as_bytes().to_vec())?;
        ensure!(
            physical.is_absolute(),
            "discovery origin root must be absolute"
        );
        let file = File::from(openat(
            CWD,
            physical,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        ensure!(
            !self.roots.contains_key(&logical),
            "duplicate discovery root"
        );
        for (existing, descriptor) in &self.roots {
            let nested = if existing.within(logical.as_bytes()) {
                Some((&file, &existing.as_bytes()[logical.as_bytes().len()..]))
            } else if logical.within(existing.as_bytes()) {
                Some((descriptor, &logical.as_bytes()[existing.as_bytes().len()..]))
            } else {
                None
            };
            if let Some((parent, suffix)) = nested {
                let relative = suffix.strip_prefix(b"/").unwrap_or(suffix);
                openat2(
                    parent,
                    OsStr::from_bytes(relative),
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .context("nested discovery root has no directory mountpoint in its parent")?;
            }
        }
        self.roots.insert(logical, file);
        Ok(())
    }

    fn open(&self, path: &BuildPath) -> Result<std::result::Result<File, DiscoveryReply>> {
        let (root, directory) = self
            .roots
            .iter()
            .filter(|(root, _)| path.within(root.as_bytes()))
            .max_by_key(|(root, _)| root.as_bytes().len())
            .context("path outside authorized discovery roots")?;
        let relative = &path.as_bytes()[root.as_bytes().len()..];
        let relative = relative.strip_prefix(b"/").unwrap_or(relative);
        let relative = if relative.is_empty() {
            b".".as_slice()
        } else {
            relative
        };
        match openat2(
            directory,
            OsStr::from_bytes(relative),
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(fd) => Ok(Ok(File::from(fd))),
            Err(Errno::NOENT) => Ok(Err(DiscoveryReply::Missing)),
            Err(Errno::NOTDIR) => Ok(Err(DiscoveryReply::NotDirectory)),
            Err(error) => Err(error).context("open scoped discovery path"),
        }
    }

    fn inspect(
        &self,
        query: &DiscoveryQuery,
        max_dirents: usize,
        max_content_bytes: u64,
    ) -> Result<(DiscoveryReply, Option<File>)> {
        // Inspect through O_PATH before opening a readable descriptor.
        // Looking up a special inode never opens a device or blocks on a FIFO.
        let file = match self.open(query.path())? {
            Ok(file) => file,
            Err(reply) => return Ok((reply, None)),
        };
        let stat = fstat(&file)?;
        let kind = FileType::from_raw_mode(stat.st_mode);
        let reply = match query {
            DiscoveryQuery::Lookup(_) => match kind {
                FileType::Directory => {
                    DiscoveryReply::Directory(DiscoveryMetadata::from_stat(&stat)?)
                }
                FileType::RegularFile => DiscoveryReply::Regular {
                    metadata: DiscoveryMetadata::from_stat(&stat)?,
                    size: u64::try_from(stat.st_size)?,
                },
                FileType::Symlink => DiscoveryReply::Symlink {
                    inode: DiscoveryInode::from_stat(&stat),
                    links: u32::try_from(stat.st_nlink)?,
                    target: readlinkat(&file, "", Vec::new())?.into_bytes(),
                    modified: timestamp(&stat)?,
                },
                _ => anyhow::bail!("unsupported discovery inode type"),
            },
            DiscoveryQuery::ReadDirectory(_) => {
                if kind != FileType::Directory {
                    return Ok((DiscoveryReply::NotDirectory, None));
                }
                let reader = File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
                unchanged(&stat, &fstat(&reader)?)?;
                let mut entries = Vec::new();
                for entry in Dir::read_from(&reader)? {
                    let entry = entry?;
                    let name = entry.file_name().to_bytes();
                    if name == b"." || name == b".." {
                        continue;
                    }
                    ensure!(
                        entries.len() < max_dirents,
                        "discovery directory entry limit exceeded"
                    );
                    let kind = if entry.file_type() == FileType::Unknown {
                        FileType::from_raw_mode(
                            rustix::fs::statat(
                                &reader,
                                OsStr::from_bytes(name),
                                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                            )?
                            .st_mode,
                        )
                    } else {
                        entry.file_type()
                    };
                    ensure!(
                        kind != FileType::Unknown,
                        "unknown discovery directory entry"
                    );
                    entries.push(DiscoveryDirent {
                        name: name.to_vec(),
                        kind: kind.into(),
                        inode: DiscoveryInode {
                            device: stat.st_dev,
                            inode: entry.ino(),
                        },
                    });
                }
                entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
                DiscoveryReply::DirectoryEntries(entries)
            }
            DiscoveryQuery::ReadFile(_) => {
                if kind == FileType::Directory {
                    return Ok((DiscoveryReply::IsDirectory, None));
                }
                ensure!(
                    kind == FileType::RegularFile,
                    "discovery read requires a regular file"
                );
                ensure!(
                    u64::try_from(stat.st_size)? <= max_content_bytes,
                    "discovery file exceeds content budget"
                );
                let reader = File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
                unchanged(&stat, &fstat(&reader)?)?;
                let blob = hash_descriptor(&reader)?;
                unchanged(&stat, &fstat(&reader)?)?;
                return Ok((
                    DiscoveryReply::File {
                        metadata: DiscoveryMetadata::from_stat(&stat)?,
                        blob,
                    },
                    Some(reader),
                ));
            }
        };
        unchanged(&stat, &fstat(&file)?)?;
        Ok((reply, None))
    }

    /// Return the actual observation, recording a stable result for each
    /// logical operation. No directory walk or unrelated file hashing.
    /// # Errors
    /// Returns an error for inaccessible paths, unsupported inodes, limits,
    /// or a source mutation.
    pub fn query(&mut self, query: DiscoveryQuery) -> Result<DiscoveryReply> {
        query.validate()?;
        if let Some(reply) = self.transcript.get(&query) {
            return Ok(reply.clone());
        }
        ensure!(
            self.transcript.0.len() < self.limits.max_queries,
            "discovery query limit exceeded"
        );
        let (reply, file) = self.inspect(
            &query,
            self.limits.max_dirents - self.dirents,
            self.limits.max_content_bytes - self.content_bytes,
        )?;
        let added_dirents = if let DiscoveryReply::DirectoryEntries(entries) = &reply {
            entries.len()
        } else {
            0
        };
        // Account for bytes actually hashed, even when two observed
        // paths contain equal bytes and ultimately share one CAS blob.
        let added_bytes = if let DiscoveryReply::File { blob, .. } = &reply {
            blob.size
        } else {
            0
        };
        let dirents = self
            .dirents
            .checked_add(added_dirents)
            .context("discovery dirent count overflow")?;
        let bytes = self
            .content_bytes
            .checked_add(added_bytes)
            .context("discovery content size overflow")?;
        ensure!(
            dirents <= self.limits.max_dirents,
            "discovery directory entry budget exceeded"
        );
        ensure!(
            bytes <= self.limits.max_content_bytes,
            "discovery content budget exceeded"
        );
        if let (DiscoveryReply::File { blob, .. }, Some(file)) = (&reply, file) {
            self.files.entry(blob.id).or_insert(file);
        }
        self.dirents = dirents;
        self.content_bytes = bytes;
        self.transcript.record(query, reply.clone())?;
        Ok(reply)
    }

    /// Re-observe a prior discovery without executing the compiler. A
    /// changed observation requires a new discovery action; no broad
    /// inventory or caller-side compiler execution is necessary.
    ///
    /// A mismatch consumes this session; the partial access set cannot be
    /// mistaken for a newly completed discovery.
    /// # Errors
    /// Returns an error for inaccessible or invalid observations.
    pub fn refresh(mut self, previous: &DiscoveryTranscript) -> Result<Option<Self>> {
        ensure!(
            self.transcript.0.is_empty(),
            "refresh requires a fresh discovery session"
        );
        previous.fingerprint()?;
        for (query, expected) in &previous.0 {
            let mut actual = self.query(query.clone())?;
            let mut expected = expected.clone();
            actual.normalize_inodes(&mut BTreeMap::new())?;
            expected.normalize_inodes(&mut BTreeMap::new())?;
            if actual != expected {
                return Ok(None);
            }
        }
        if self.seal()?.canonical()? != previous.canonical()? {
            return Ok(None);
        }
        Ok(Some(self))
    }

    /// Re-evaluate the exact observed operations before sealing. Negative
    /// lookups and enumeration changes are checked just like content changes.
    /// # Errors
    /// Returns an error if any observation has changed.
    pub fn seal(&self) -> Result<&DiscoveryTranscript> {
        for (query, expected) in &self.transcript.0 {
            let (actual, _) = self.inspect(
                query,
                self.limits.max_dirents,
                self.limits.max_content_bytes,
            )?;
            ensure!(
                &actual == expected,
                "discovery input changed before sealing: {query:?}"
            );
        }
        self.transcript.fingerprint()?;
        Ok(&self.transcript)
    }

    /// Open an independent reader for previously observed content. The
    /// receiver must still verify the content ID and size while consuming
    /// it; pinning does not make an origin inode immutable against writers.
    /// # Errors
    /// Returns an error if the content was not observed or cannot be reopened.
    pub fn open_blob(&self, blob: BlobRef) -> Result<File> {
        let file = self
            .files
            .get(&blob.id)
            .context("content was not discovered")?;
        let stat: Stat = fstat(file)?;
        ensure!(
            u64::try_from(stat.st_size)? == blob.size,
            "discovered content length changed"
        );
        Ok(File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Read, os::unix::fs::symlink};

    fn path(bytes: &[u8]) -> Result<BuildPath> {
        BuildPath::new(bytes.to_vec())
    }

    #[test]
    fn only_observed_file_contents_enter_the_transcript() -> Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("selected.a"), b"chosen")?;
        fs::write(temp.path().join("unrelated.a"), b"unrelated")?;
        let mut origin = DiscoveryOrigin::new(DiscoveryLimits {
            max_queries: 16,
            max_dirents: 16,
            max_content_bytes: 1024,
        })?;
        origin.add_root(path(b"/libraries")?, temp.path())?;
        origin.query(DiscoveryQuery::ReadDirectory(path(b"/libraries")?))?;
        let DiscoveryReply::File { blob, .. } =
            origin.query(DiscoveryQuery::ReadFile(path(b"/libraries/selected.a")?))?
        else {
            anyhow::bail!("missing selected archive")
        };
        let initial = origin.seal()?.fingerprint()?;
        fs::write(
            temp.path().join("unrelated.a"),
            b"different bytes and length",
        )?;
        assert_eq!(initial, origin.seal()?.fingerprint()?);
        let mut first = origin.open_blob(blob)?;
        let mut second = origin.open_blob(blob)?;
        let mut a = [0; 2];
        first.read_exact(&mut a)?;
        assert_eq!(&a, b"ch");
        let mut b = Vec::new();
        second.read_to_end(&mut b)?;
        assert_eq!(&b, b"chosen");
        fs::write(temp.path().join("selected.a"), b"changed")?;
        assert!(origin.seal().is_err());
        Ok(())
    }

    #[test]
    fn negative_lookups_and_directory_names_are_observed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut origin = DiscoveryOrigin::new(DiscoveryLimits {
            max_queries: 16,
            max_dirents: 16,
            max_content_bytes: 1024,
        })?;
        origin.add_root(path(b"/libs")?, temp.path())?;
        let missing = DiscoveryQuery::Lookup(path(b"/libs/first.a")?);
        assert_eq!(origin.query(missing)?, DiscoveryReply::Missing);
        origin.query(DiscoveryQuery::ReadDirectory(path(b"/libs")?))?;
        origin.seal()?;
        fs::write(temp.path().join("first.a"), b"new candidate")?;
        assert!(origin.seal().is_err());
        Ok(())
    }

    #[test]
    fn origin_does_not_follow_symlinks_across_authority_boundaries() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("hidden"), b"outside")?;
        symlink(outside.path(), temp.path().join("alias"))?;
        let mut origin = DiscoveryOrigin::new(DiscoveryLimits {
            max_queries: 16,
            max_dirents: 16,
            max_content_bytes: 1024,
        })?;
        origin.add_root(path(b"/libs")?, temp.path())?;
        assert!(matches!(
            origin.query(DiscoveryQuery::Lookup(path(b"/libs/alias")?))?,
            DiscoveryReply::Symlink { .. }
        ));
        assert!(
            origin
                .query(DiscoveryQuery::ReadFile(path(b"/libs/alias/hidden")?))
                .is_err()
        );
        assert!(
            origin
                .query(DiscoveryQuery::ReadFile(path(b"/outside/hidden")?))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn distinguishes_missing_paths_from_wrong_inode_types() -> Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("file"), b"file")?;
        let mut origin = DiscoveryOrigin::new(DiscoveryLimits {
            max_queries: 16,
            max_dirents: 16,
            max_content_bytes: 1024,
        })?;
        origin.add_root(path(b"/root")?, temp.path())?;
        assert_eq!(
            origin.query(DiscoveryQuery::Lookup(path(b"/root/file/child")?))?,
            DiscoveryReply::NotDirectory
        );
        assert_eq!(
            origin.query(DiscoveryQuery::ReadDirectory(path(b"/root/file")?))?,
            DiscoveryReply::NotDirectory
        );
        assert_eq!(
            origin.query(DiscoveryQuery::ReadFile(path(b"/root")?))?,
            DiscoveryReply::IsDirectory
        );
        assert_eq!(
            origin.query(DiscoveryQuery::Lookup(path(b"/root/missing")?))?,
            DiscoveryReply::Missing
        );
        origin.seal()?;
        Ok(())
    }

    #[test]
    fn replay_never_treats_an_unobserved_path_as_absent() -> Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("chosen"), b"chosen")?;
        let limits = DiscoveryLimits {
            max_queries: 8,
            max_dirents: 8,
            max_content_bytes: 1024,
        };
        let mut origin = DiscoveryOrigin::new(limits)?;
        origin.add_root(path(b"/input")?, temp.path())?;
        let miss = DiscoveryQuery::Lookup(path(b"/input/absent")?);
        let read = DiscoveryQuery::ReadFile(path(b"/input/chosen")?);
        origin.query(miss.clone())?;
        origin.query(read.clone())?;
        let original = origin.seal()?.clone();
        let mut replay = DiscoveryReplay::new(original.clone())?;
        assert_eq!(replay.query(&miss)?, &DiscoveryReply::Missing);
        assert!(
            replay
                .query(&DiscoveryQuery::Lookup(path(b"/input/unobserved")?))
                .is_err()
        );
        replay.query(&read)?;
        assert!(replay.finish().is_err());
        let mut refreshed = DiscoveryOrigin::new(limits)?;
        refreshed.add_root(path(b"/input")?, temp.path())?;
        let refreshed = refreshed
            .refresh(&original)?
            .context("unchanged transcript did not refresh")?;
        let mut replay = DiscoveryReplay::new(refreshed.seal()?.clone())?;
        replay.query(&read)?;
        replay.query(&miss)?;
        assert_eq!(replay.finish()?.fingerprint()?, original.fingerprint()?);
        fs::write(temp.path().join("absent"), b"higher-priority input")?;
        let mut changed = DiscoveryOrigin::new(limits)?;
        changed.add_root(path(b"/input")?, temp.path())?;
        assert!(changed.refresh(&original)?.is_none());
        Ok(())
    }

    #[test]
    fn nested_roots_require_real_mountpoints_and_total_budget_is_bounded() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let nested = tempfile::tempdir()?;
        fs::write(temp.path().join("a"), b"a")?;
        fs::write(nested.path().join("b"), b"b")?;
        let mut origin = DiscoveryOrigin::new(DiscoveryLimits {
            max_queries: 8,
            max_dirents: 2,
            max_content_bytes: 1,
        })?;
        origin.add_root(path(b"/input")?, temp.path())?;
        assert!(
            origin
                .add_root(path(b"/input/absent")?, nested.path())
                .is_err()
        );
        fs::create_dir(temp.path().join("nested"))?;
        origin.add_root(path(b"/input/nested")?, nested.path())?;
        origin.query(DiscoveryQuery::ReadDirectory(path(b"/input")?))?;
        assert!(
            origin
                .query(DiscoveryQuery::ReadDirectory(path(b"/input/nested")?))
                .is_err()
        );
        origin.query(DiscoveryQuery::ReadFile(path(b"/input/a")?))?;
        assert!(
            origin
                .query(DiscoveryQuery::ReadFile(path(b"/input/nested/b")?))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn inode_equivalence_not_host_inode_number_participates_in_identity() -> Result<()> {
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        let distinct = tempfile::tempdir()?;
        for dir in [first.path(), second.path(), distinct.path()] {
            fs::write(dir.join("a"), b"bytes")?;
            fs::hard_link(dir.join("a"), dir.join("b"))?;
        }
        // Replace b with an independent inode of identical contents.
        fs::remove_file(distinct.path().join("b"))?;
        fs::write(distinct.path().join("b"), b"bytes")?;
        let observe = |dir: &Path| -> Result<DiscoveryTranscript> {
            let mut origin = DiscoveryOrigin::new(DiscoveryLimits {
                max_queries: 8,
                max_dirents: 8,
                max_content_bytes: 1024,
            })?;
            origin.add_root(path(b"/input")?, dir)?;
            // Directory enumeration observes inode equivalence, not file bytes
            // or the unrelated timestamps of these independently created files.
            origin.query(DiscoveryQuery::ReadDirectory(path(b"/input")?))?;
            Ok(origin.seal()?.clone())
        };
        assert_eq!(
            observe(first.path())?.fingerprint()?,
            observe(second.path())?.fingerprint()?
        );
        assert_ne!(
            observe(first.path())?.fingerprint()?,
            observe(distinct.path())?.fingerprint()?
        );
        Ok(())
    }

    #[test]
    fn longest_root_wins_and_limits_are_explicit() -> Result<()> {
        let outer = tempfile::tempdir()?;
        let nested = tempfile::tempdir()?;
        fs::create_dir(outer.path().join("nested"))?;
        fs::write(nested.path().join("only"), b"nested root")?;
        let mut origin = DiscoveryOrigin::new(DiscoveryLimits {
            max_queries: 1,
            max_dirents: 1,
            max_content_bytes: 1024,
        })?;
        origin.add_root(path(b"/input")?, outer.path())?;
        origin.add_root(path(b"/input/nested")?, nested.path())?;
        let query = DiscoveryQuery::Lookup(path(b"/input/nested/only")?);
        assert!(matches!(
            origin.query(query.clone())?,
            DiscoveryReply::Regular { .. }
        ));
        assert!(origin.query(query).is_ok());
        assert!(
            origin
                .query(DiscoveryQuery::Lookup(path(b"/input")?))
                .is_err()
        );
        assert!(origin.add_root(path(b"/later")?, outer.path()).is_err());
        Ok(())
    }
}
