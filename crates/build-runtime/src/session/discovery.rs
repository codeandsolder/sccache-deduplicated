//! Scheduler-owned mailbox for the live observation phase of a delegated
//! action. Exactly one request is outstanding; duplicate HTTP requests
//! replay the same answer without granting new input authority.

use super::*;
use crate::{
    Artifact, DISCOVERY_RESULT, DiscoverySource, DiscoverySpec, PeerId,
    discovery::{DiscoveryBundle, DiscoveryReply, DiscoveryTranscript},
    wire::{DiscoveryAnswer, DiscoveryOperation, DiscoveryPoll, DiscoveryRequest},
};

pub(super) struct Mailbox {
    roots: BTreeSet<crate::BuildPath>,
    observations: DiscoveryTranscript,
    observed_files: BTreeMap<ContentId, u64>,
    operation: Option<DiscoveryRequest>,
    answer: Option<DiscoveryAnswer>,
    retained: BTreeMap<ContentId, Arc<TreeLease>>,
    bytes: u64,
    metadata: usize,
    sealed: bool,
    failed: bool,
}

impl Mailbox {
    pub(super) fn new(spec: &DiscoverySpec) -> Result<Self> {
        ensure!(
            matches!(spec.source, DiscoverySource::Live { .. }),
            "expected live discovery declaration"
        );
        Ok(Self {
            roots: spec.mounts.clone(),
            observations: DiscoveryTranscript::default(),
            observed_files: BTreeMap::new(),
            operation: None,
            answer: None,
            retained: BTreeMap::new(),
            bytes: 0,
            metadata: 0,
            sealed: false,
            failed: false,
        })
    }

    fn request(&mut self, request: DiscoveryRequest) -> Result<Option<DiscoveryAnswer>> {
        if self.operation.as_ref() == Some(&request) {
            return Ok(self.answer.clone());
        }
        ensure!(
            !self.failed && !self.sealed,
            "discovery session already terminal"
        );
        let next = match &self.operation {
            None => 0,
            Some(previous) => {
                ensure!(
                    self.answer.is_some(),
                    "discovery request already outstanding"
                );
                previous
                    .sequence
                    .checked_add(1)
                    .context("discovery sequence overflow")?
            }
        };
        ensure!(
            request.sequence == next,
            "invalid discovery request sequence"
        );
        match &request.operation {
            DiscoveryOperation::Observe(query) => {
                query.validate()?;
                ensure!(
                    self.roots
                        .iter()
                        .any(|root| query.path().within(root.as_bytes())),
                    "discovery query outside declared roots"
                );
                ensure!(
                    self.observations.get(query).is_none(),
                    "duplicate observation requires original sequence"
                );
            }
            DiscoveryOperation::Fetch(blob) => {
                ensure!(
                    !self.retained.contains_key(&blob.id),
                    "discovery blob already fetched"
                );
                ensure!(
                    self.observed_files.get(&blob.id) == Some(&blob.size),
                    "unobserved discovery blob"
                );
            }
            DiscoveryOperation::Seal(digest) => {
                ensure!(
                    self.observations.fingerprint()? == *digest,
                    "discovery seal differs from scheduler observations"
                );
                DiscoveryBundle::new(self.roots.clone(), self.observations.clone())?;
            }
        }
        self.operation = Some(request);
        self.answer = None;
        Ok(None)
    }

    fn poll(&self) -> DiscoveryPoll {
        match (&self.operation, &self.answer) {
            (Some(request), None) => DiscoveryPoll::Demand(request.clone()),
            (_, _) if self.sealed || self.failed => DiscoveryPoll::Complete,
            _ => DiscoveryPoll::Waiting,
        }
    }

    fn check_answer(&self, sequence: u64, answer: &DiscoveryAnswer) -> Result<Option<BlobRef>> {
        let request = self
            .operation
            .as_ref()
            .context("unsolicited discovery answer")?;
        ensure!(
            request.sequence == sequence,
            "discovery answer sequence mismatch"
        );
        if let Some(previous) = &self.answer {
            ensure!(
                previous == answer,
                "discovery answer changed after acceptance"
            );
            return Ok(None);
        }
        match (&request.operation, answer) {
            (_, DiscoveryAnswer::Rejected(message)) => {
                ensure!(
                    !message.is_empty() && message.len() <= 4096,
                    "invalid discovery rejection"
                );
                Ok(None)
            }
            (DiscoveryOperation::Observe(query), DiscoveryAnswer::Observed(reply)) => {
                reply.validate(query)?;
                Ok(None)
            }
            (DiscoveryOperation::Fetch(blob), DiscoveryAnswer::Available) => Ok(Some(*blob)),
            (DiscoveryOperation::Seal(_), DiscoveryAnswer::Sealed) => Ok(None),
            _ => bail!("discovery answer differs from requested operation"),
        }
    }

    fn answer(
        &mut self,
        sequence: u64,
        answer: DiscoveryAnswer,
        retained: Option<TreeLease>,
        limits: SessionLimits,
    ) -> Result<()> {
        self.check_answer(sequence, &answer)?;
        if self.answer.is_some() {
            return Ok(());
        }
        let request = self
            .operation
            .as_ref()
            .context("discovery operation missing")?;
        match &answer {
            DiscoveryAnswer::Observed(reply) => {
                let DiscoveryOperation::Observe(query) = &request.operation else {
                    bail!("expected observation request");
                };
                let metadata = self
                    .metadata
                    .checked_add(usize::try_from(
                        crate::identity::encoding().serialized_size(&(query, reply))?,
                    )?)
                    .context("discovery metadata overflow")?;
                let added = if let DiscoveryReply::File { blob, .. } = reply {
                    blob.size
                } else {
                    0
                };
                let bytes = self
                    .bytes
                    .checked_add(added)
                    .context("discovery content budget overflow")?;
                ensure!(
                    metadata <= limits.max_manifest_cache_bytes && bytes <= limits.max_tree_bytes,
                    "discovery session exceeds metadata or content limit"
                );
                if let DiscoveryReply::File { blob, .. } = reply {
                    if let Some(size) = self.observed_files.get(&blob.id) {
                        ensure!(*size == blob.size, "inconsistent discovery blob lengths");
                    } else {
                        ensure!(
                            self.observed_files.len() < limits.max_tree_blobs,
                            "discovery blob count limit exceeded"
                        );
                        self.observed_files.insert(blob.id, blob.size);
                    }
                }
                self.observations.record(query.clone(), reply.clone())?;
                self.metadata = metadata;
                self.bytes = bytes;
            }
            DiscoveryAnswer::Available => {
                let DiscoveryOperation::Fetch(blob) = request.operation else {
                    bail!("expected content request");
                };
                let lease = retained.context("missing verified discovery blob lease")?;
                ensure!(
                    lease.blobs().get(&blob.id) == Some(&blob.size),
                    "discovery blob lease differs from request"
                );
                self.retained.insert(blob.id, Arc::new(lease));
            }
            DiscoveryAnswer::Sealed => self.sealed = true,
            DiscoveryAnswer::Rejected(_) => self.failed = true,
        }
        self.answer = Some(answer);
        Ok(())
    }

    pub(super) fn verify_result(&self, manifest: &ResultManifest) -> Result<()> {
        ensure!(
            self.sealed && !self.failed,
            "unsealed live discovery cannot publish"
        );
        let (_, expected) =
            DiscoveryBundle::new(self.roots.clone(), self.observations.clone())?.encode()?;
        ensure!(
            manifest.outputs.get(DISCOVERY_RESULT) == Some(&Artifact::Tree(expected)),
            "discovery result differs from sealed scheduler observations"
        );
        Ok(())
    }
}

fn action(state: &mut Session) -> Result<&mut PendingAction> {
    let Phase::Pending(pending) = &mut state.phase else {
        bail!("discovery action no longer pending");
    };
    let Pending::Action(action) = &mut **pending else {
        bail!("discovery requires an action");
    };
    ensure!(
        action.inputs_staged,
        "discovery requires admitted static inputs"
    );
    Ok(action)
}

fn mailbox(state: &mut Session) -> Result<&mut Mailbox> {
    action(state)?
        .discovery
        .as_mut()
        .context("action did not declare live discovery")
}

impl NativeSessions {
    fn discovery_origin(&self, state: &mut Session, origin: PeerId) -> Result<()> {
        ensure!(
            state
                .allocation
                .as_ref()
                .is_some_and(|allocation| allocation.requester == origin),
            "discovery origin does not own delegated action"
        );
        self.authorize_reader(state, Publisher::Client)
    }

    /// Submit or poll a single worker request under its delegated ticket.
    /// # Errors
    /// Invalid authority, declaration, request or sequence.
    pub fn discovery_request(
        &self,
        ticket: Ticket,
        publisher: Publisher,
        request: DiscoveryRequest,
    ) -> Result<Option<DiscoveryAnswer>> {
        ensure!(
            matches!(publisher, Publisher::Worker { .. }),
            "live discovery requires assigned worker"
        );
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize(&mut state, publisher)?;
        mailbox(&mut state)?.request(request)
    }

    /// Poll the delegated action's live origin. Ordinary input staging
    /// completes before this mailbox becomes visible.
    /// # Errors
    /// Invalid origin or ticket.
    pub fn discovery_poll(&self, ticket: Ticket, origin: PeerId) -> Result<DiscoveryPoll> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.discovery_origin(&mut state, origin)?;
        if !matches!(state.phase, Phase::Pending(_)) {
            return Ok(DiscoveryPoll::Complete);
        }
        Ok(mailbox(&mut state)?.poll())
    }

    /// Complete a request using metadata or a verified ordinary CAS upload.
    /// A Fetch answer only succeeds after the exact blob retention tree exists.
    /// # Errors
    /// Invalid origin, sequence, observation or unavailable verified content.
    pub fn discovery_answer(
        &self,
        ticket: Ticket,
        origin: PeerId,
        sequence: u64,
        answer: DiscoveryAnswer,
    ) -> Result<()> {
        let session = self.get(ticket)?;
        let blob = {
            let mut state = Self::lock(&session)?;
            self.discovery_origin(&mut state, origin)?;
            mailbox(&mut state)?.check_answer(sequence, &answer)?
        };
        let retained = blob
            .map(|blob| -> Result<_> {
                let manifest = NativeStore::blob_retention_manifest(blob)?;
                self.store()
                    .lookup_tree(manifest.id()?)?
                    .context("discovery content not committed")
            })
            .transpose()?;
        let mut state = Self::lock(&session)?;
        self.discovery_origin(&mut state, origin)?;
        mailbox(&mut state)?.answer(sequence, answer, retained, self.limits)
    }

    /// Deliver only content already authorized by an observation and a
    /// completed fetch request. This is not a general CAS read endpoint.
    /// # Errors
    /// Invalid worker authority or undeclared content.
    pub fn discovery_download(
        &self,
        ticket: Ticket,
        publisher: Publisher,
        blob: BlobRef,
    ) -> Result<NativeDownload> {
        ensure!(
            matches!(publisher, Publisher::Worker { .. }),
            "live discovery requires assigned worker"
        );
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize(&mut state, publisher)?;
        let mailbox = mailbox(&mut state)?;
        let lease = Arc::clone(
            mailbox
                .retained
                .get(&blob.id)
                .context("undelivered discovery blob")?,
        );
        drop(state);
        ensure!(
            lease.blobs().get(&blob.id) == Some(&blob.size),
            "discovery download length mismatch"
        );
        Ok(NativeDownload::blob(
            (lease.open_file(blob.id)?, lease.physical_encoding(blob.id)?),
            blob.size,
        ))
    }
}
