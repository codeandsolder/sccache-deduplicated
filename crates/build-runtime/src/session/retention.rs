//! Build-scoped retention. Result leases are shared with the original action
//! before its delivery ticket is released, so GC never observes a pin gap.
use super::*;
use crate::ResultId;

#[derive(Default)]
pub(super) struct RetentionGroups {
    groups: Mutex<HashMap<Ticket, Group>>,
}

struct Group {
    owner: crate::PeerId,
    expires: Instant,
    metadata_bytes: u64,
    results: BTreeMap<ResultId, Arc<ResultLease>>,
    blobs: BTreeMap<ContentId, (u64, ResultId)>,
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
            let keys = groups
                .iter()
                .filter_map(|(id, group)| (group.expires <= now).then_some(*id))
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|id| groups.remove(&id))
                .collect::<Vec<_>>()
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
        lease: Arc<ResultLease>,
        id: ResultId,
        blobs: BTreeMap<ContentId, u64>,
        max_metadata: u64,
    ) -> Result<()> {
        if self.results.contains_key(&id) {
            return Ok(());
        }
        // Bound both the retained manifests and their unique content lookup
        // entries. The physical store's existing quota bounds pinned bytes.
        let bytes = bincode::serialized_size(lease.manifest())?
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
        self.results.insert(id, lease);
        self.metadata_bytes = next;
        Ok(())
    }

    fn source(&self, blob: BlobRef) -> Result<Arc<ResultLease>> {
        let (size, id) = self
            .blobs
            .get(&blob.id)
            .context("undeclared retained blob")?;
        ensure!(*size == blob.size, "incorrect retained blob length");
        self.results
            .get(id)
            .cloned()
            .context("retained result missing")
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
                results: BTreeMap::new(),
                blobs: BTreeMap::new(),
            },
        );
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
            Arc::clone(lease)
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
        group.insert(
            lease,
            expected,
            blobs,
            u64::try_from(self.limits.max_manifest_cache_bytes)?,
        )
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
    ) -> Result<(File, BlobEncoding)> {
        let lease = {
            let mut groups = self.retained.lock()?;
            let group = groups
                .get_mut(&group)
                .context("unknown or expired native retention group")?;
            group.touch(owner, self.deadline())?;
            group.source(blob)?
        };
        encode_delivery(
            (lease.open_file(blob.id)?, lease.physical_encoding(blob.id)?),
            false,
        )
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
