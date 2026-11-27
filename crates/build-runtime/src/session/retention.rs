//! Build-scoped retention. Result leases are shared with the original action
//! before its delivery ticket is released, so GC never observes a pin gap.
use super::{
    Arc, BTreeMap, BlobRef, ContentId, Context, HashMap, Instant, Mutex, MutexGuard,
    NativeDownload, NativeSessions, Phase, Publisher, Ready, Result, ResultLease, Ticket, anyhow,
    bail, ensure,
};
use crate::{
    ResultId, RetainedPackage, TreeId, TreeLease, VerifiedPackage,
    wire::{ImpactHead, ImpactUpdate},
};

#[derive(Default)]
pub(super) struct RetentionGroups {
    groups: Mutex<HashMap<Ticket, Group>>,
}

struct Group {
    owner: crate::PeerId,
    expires: Instant,
    metadata_bytes: u64,
    roots: BTreeMap<RootId, RetainedLease>,
    blobs: BTreeMap<ContentId, (u64, RootId)>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RootId {
    Result(ResultId),
    Package(TreeId),
    Impact(TreeId),
}

#[derive(Clone)]
enum RetainedLease {
    Result(Arc<ResultLease>),
    Package(Arc<VerifiedPackage>),
    Impact(Arc<TreeLease>),
}

impl RetainedLease {
    fn bytes(&self) -> Result<u64> {
        Ok(match self {
            Self::Result(lease) => bincode::serialized_size(lease.manifest())?,
            Self::Package(package) => bincode::serialized_size(package.tree().manifest())?,
            Self::Impact(tree) => bincode::serialized_size(tree.manifest())?,
        })
    }

    fn download(&self, blob: BlobRef) -> Result<NativeDownload> {
        let (file, encoding) = match self {
            Self::Result(lease) => (lease.open_file(blob.id)?, lease.physical_encoding(blob.id)?),
            Self::Impact(tree) => (tree.open_file(blob.id)?, tree.physical_encoding(blob.id)?),
            Self::Package(package) => (
                package.tree().open_file(blob.id)?,
                package.tree().physical_encoding(blob.id)?,
            ),
        };
        Ok(NativeDownload::blob((file, encoding), blob.size))
    }
}

impl RetentionGroups {
    fn lock(&self) -> Result<MutexGuard<'_, HashMap<Ticket, Group>>> {
        self.groups
            .lock()
            .map_err(|_| anyhow!("native retention map poisoned"))
    }

    pub(super) fn reap(&self, now: Instant) -> Result<usize> {
        let expired = {
            let mut groups = self.lock()?;
            let expired = groups
                .extract_if(|_, group| group.expires <= now)
                .map(|(_, group)| group)
                .collect::<Vec<_>>();
            drop(groups);
            expired
        };
        Ok(expired.len())
    }
}

impl Group {
    fn touch(&mut self, peer: crate::PeerId, deadline: Instant) -> Result<()> {
        ensure!(
            self.owner == peer && self.expires > Instant::now(),
            "unknown or expired native retention group"
        );
        self.expires = deadline;
        Ok(())
    }

    fn insert(
        &mut self,
        lease: RetainedLease,
        id: RootId,
        blobs: BTreeMap<ContentId, u64>,
        max_metadata: u64,
    ) -> Result<()> {
        if self.roots.contains_key(&id) {
            return Ok(());
        }
        // Bound both the retained manifests and their unique content lookup
        // entries. The physical store's existing quota bounds pinned bytes.
        let bytes = lease
            .bytes()?
            .checked_add(u64::try_from(blobs.len())?.saturating_mul(128))
            .and_then(|bytes| bytes.checked_add(256))
            .context("native retention metadata size overflow")?;
        let next = self
            .metadata_bytes
            .checked_add(bytes)
            .context("native retention metadata size overflow")?;
        ensure!(
            next <= max_metadata,
            "native retention metadata capacity exceeded"
        );
        for (&blob, &size) in &blobs {
            ensure!(
                self.blobs
                    .get(&blob)
                    .is_none_or(|(previous, _)| *previous == size),
                "conflicting retained content length"
            );
        }
        for (blob, size) in blobs {
            self.blobs.entry(blob).or_insert((size, id));
        }
        self.roots.insert(id, lease);
        self.metadata_bytes = next;
        Ok(())
    }

    fn source(&self, blob: BlobRef) -> Result<RetainedLease> {
        let (size, id) = self
            .blobs
            .get(&blob.id)
            .context("undeclared retained blob")?;
        ensure!(*size == blob.size, "incorrect retained blob length");
        self.roots.get(id).cloned().context("retained root missing")
    }
}

impl NativeSessions {
    /// Start a bounded, peer-owned retention group independent of compile
    /// admission slots. One group can pin thousands of successful actions.
    /// # Errors
    /// Returns an error if the retention group limit is exhausted.
    pub fn open_retention(&self, owner: crate::PeerId) -> Result<Ticket> {
        let mut groups = self.retained.lock()?;
        ensure!(
            groups.len() < self.limits.max_sessions,
            "native retention group capacity exceeded"
        );
        let ticket = loop {
            let ticket = Ticket(rand::random());
            if !groups.contains_key(&ticket) {
                break ticket;
            }
        };
        groups.insert(
            ticket,
            Group {
                owner,
                expires: self.deadline(),
                metadata_bytes: 0,
                roots: BTreeMap::new(),
                blobs: BTreeMap::new(),
            },
        );
        drop(groups);
        Ok(ticket)
    }

    /// Retain a committed result before closing the original action ticket.
    /// Idempotent for an identical result; a refresh cannot substitute another
    /// result for the one actually observed by this caller.
    /// # Errors
    /// Returns an error for an unauthorized, uncommitted or inconsistent result.
    pub fn retain_result(
        &self,
        group: Ticket,
        action: Ticket,
        expected: ResultId,
        owner: crate::PeerId,
    ) -> Result<()> {
        let session = self.get(action)?;
        let lease = {
            let mut state = Self::lock(&session)?;
            self.authorize_reader(&mut state, Publisher::Client)?;
            ensure!(
                state
                    .allocation
                    .as_ref()
                    .is_none_or(|allocation| allocation.requester == owner),
                "native retention requester differs from action owner"
            );
            let Phase::Ready(Ready::Result(lease)) = &state.phase else {
                bail!("only committed results can be retained");
            };
            let lease = Arc::clone(lease);
            drop(state);
            lease
        };
        ensure!(
            lease.manifest().id()? == expected,
            "native retained result differs from observed result"
        );
        let blobs = lease.manifest().blobs()?;
        let mut groups = self.retained.lock()?;
        let group = groups
            .get_mut(&group)
            .context("unknown or expired native retention group")?;
        group.touch(owner, self.deadline())?;
        let result = group.insert(
            RetainedLease::Result(lease),
            RootId::Result(expected),
            blobs,
            u64::try_from(self.limits.max_manifest_cache_bytes)?,
        );
        drop(groups);
        result
    }

    /// Transfer the verified package pin into an authenticated build lease.
    /// The caller must pass the package obtained from the verified archive
    /// index/acquisition operation, never an arbitrary client-supplied tree.
    /// # Errors
    /// Invalid group, quota, or package from another store.
    pub fn retain_package(
        &self,
        group: Ticket,
        owner: crate::PeerId,
        package: VerifiedPackage,
    ) -> Result<RetainedPackage> {
        ensure!(
            package.tree().belongs_to(self.store()),
            "package belongs to a different store"
        );
        let receipt = package.receipt();
        let manifest = package.tree().manifest().clone();
        let blobs = package.tree().blobs().clone();
        let mut groups = self.retained.lock()?;
        let group = groups
            .get_mut(&group)
            .context("unknown or expired native retention group")?;
        group.touch(owner, self.deadline())?;
        group.insert(
            RetainedLease::Package(Arc::new(package)),
            RootId::Package(receipt.tree),
            blobs,
            u64::try_from(self.limits.max_manifest_cache_bytes)?,
        )?;
        drop(groups);
        Ok(RetainedPackage { receipt, manifest })
    }

    /// Look up an impact head and transfer the record pin to the peer's
    /// build-scoped retention group. Existing retained-blob transport then
    /// delivers the record with exact length and digest verification.
    pub fn retain_impact_head(
        &self,
        group: Ticket,
        owner: crate::PeerId,
        scope: ContentId,
    ) -> Result<Option<ImpactHead>> {
        self.renew_retention(group, owner)?;
        let Some((tree, blob)) = self.store().lookup_impact_head(scope)? else {
            return Ok(None);
        };
        let id = tree.id();
        let mut groups = self.retained.lock()?;
        let group = groups
            .get_mut(&group)
            .context("unknown or expired native retention group")?;
        group.touch(owner, self.deadline())?;
        group.insert(
            RetainedLease::Impact(Arc::new(tree)),
            RootId::Impact(id),
            BTreeMap::from([(blob.id, blob.size)]),
            u64::try_from(self.limits.max_manifest_cache_bytes)?,
        )?;
        Ok(Some(ImpactHead { tree: id, blob }))
    }

    /// Publish only a fully uploaded, committed record tree. The upload
    /// ticket is an existing scheduler capability, and the retention group
    /// belongs to the authenticated caller.
    pub fn publish_impact_head(
        &self,
        group: Ticket,
        owner: crate::PeerId,
        scope: ContentId,
        expected: Option<TreeId>,
        upload: Ticket,
    ) -> Result<ImpactUpdate> {
        self.renew_retention(group, owner)?;
        let session = self.get(upload)?;
        let tree = {
            let mut state = Self::lock(&session)?;
            self.authorize_reader(&mut state, Publisher::Client)?;
            let Phase::Ready(Ready::Tree(delivery)) = &state.phase else {
                bail!("impact record upload not committed");
            };
            let super::TreeSource::Stored(tree) = &delivery.source else {
                bail!("impact record must be a committed upload");
            };
            self.store()
                .lookup_tree(tree.id())?
                .context("impact record lost its upload pin")?
        };
        self.store()
            .compare_exchange_impact_head(scope, expected, &tree)
    }

    /// Renew a build-wide lease, independent of the number of retained results.
    /// # Errors
    /// Returns an error for an expired or unauthorized group.
    pub fn renew_retention(&self, group: Ticket, owner: crate::PeerId) -> Result<()> {
        self.retained
            .lock()?
            .get_mut(&group)
            .context("unknown or expired native retention group")?
            .touch(owner, self.deadline())
    }

    /// Authorize exact retained content for direct worker delivery.
    /// # Errors
    /// Returns an error for an expired group or undeclared content.
    pub fn retained_sources(
        &self,
        group: Ticket,
        owner: crate::PeerId,
        blobs: &[BlobRef],
    ) -> Result<()> {
        ensure!(
            !blobs.is_empty() && blobs.len() <= crate::wire::MAX_SOURCE_BATCH,
            "invalid retained source batch"
        );
        let mut groups = self.retained.lock()?;
        let group = groups
            .get_mut(&group)
            .context("unknown or expired native retention group")?;
        group.touch(owner, self.deadline())?;
        for &blob in blobs {
            group.source(blob)?;
        }
        drop(groups);
        Ok(())
    }

    /// Open the exact retained content for verified transfer. The open
    /// descriptor survives concurrent group release, without holding a lock.
    /// # Errors
    /// Returns an error for an invalid group, blob, or failed storage access.
    pub fn download_retained(
        &self,
        group: Ticket,
        owner: crate::PeerId,
        blob: BlobRef,
    ) -> Result<NativeDownload> {
        let lease = {
            let mut groups = self.retained.lock()?;
            let group = groups
                .get_mut(&group)
                .context("unknown or expired native retention group")?;
            group.touch(owner, self.deadline())?;
            let lease = group.source(blob)?;
            drop(groups);
            lease
        };
        lease.download(blob)
    }

    /// Close a group, releasing all its content pins outside the registry lock.
    /// # Errors
    /// Returns an error for an unauthorized group or invalid registry.
    pub fn close_retention(&self, group: Ticket, owner: crate::PeerId) -> Result<()> {
        let removed = {
            let mut groups = self.retained.lock()?;
            let current = groups
                .get(&group)
                .context("unknown native retention group")?;
            ensure!(
                current.owner == owner,
                "native retention group belongs to another peer"
            );
            groups.remove(&group)
        };
        drop(removed);
        Ok(())
    }
}
