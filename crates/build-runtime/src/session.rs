//! Expiring native cache sessions, independent of transport and worker selection.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    io::Read,
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};

use crate::{
    Admission, ArchiveLength, BlobRef, BuildCoordinator, CompilePermit, ContentId,
    InstallationManifest, NativeStore, PackageArchive, PackageArchiveLease, PackageIdentity,
    PackageImportLimits, ResultLease, ResultManifest, StagedBlob, TreeId, TreeLease, TreeManifest,
    UploadReservation,
    wire::{
        ActionRequest, BeginResult, NativeAdmission, NativeStatus, Publisher, ScheduleReply,
        Ticket, TreeOffer, TreeRead, WorkerAllocation,
    },
};

/// Explicit admission and resource bounds for the native protocol.
#[derive(Debug, Clone, Copy)]
pub struct SessionLimits {
    pub idle_timeout: Duration,
    pub max_sessions: usize,
    pub max_result_bytes: u64,
    pub max_result_blobs: usize,
    pub max_tree_bytes: u64,
    pub max_tree_blobs: usize,
    pub max_concurrent_uploads: usize,
    pub max_total_uploads: usize,
}

impl SessionLimits {
    /// Validate limits before starting the service.
    ///
    /// # Errors
    /// Returns an error for zero or unusable limits.
    pub fn validate(self) -> Result<()> {
        ensure!(
            !self.idle_timeout.is_zero() && Instant::now().checked_add(self.idle_timeout).is_some(),
            "invalid session timeout"
        );
        ensure!(
            self.max_sessions > 0
                && self.max_result_blobs > 0
                && self.max_result_bytes > 0
                && self.max_tree_blobs > 0
                && self.max_tree_bytes > 0
                && self.max_concurrent_uploads > 0
                && self.max_total_uploads > 0,
            "native limits must be nonzero"
        );
        Ok(())
    }

    fn check_blobs(self, kind: Kind, blobs: &BTreeMap<ContentId, u64>) -> Result<()> {
        let (max_bytes, max_blobs) = match kind {
            Kind::Action => (self.max_result_bytes, self.max_result_blobs),
            Kind::Tree => (self.max_tree_bytes, self.max_tree_blobs),
        };
        ensure!(
            blobs.len() <= max_blobs,
            "native manifest blob limit exceeded"
        );
        let bytes = blobs.values().try_fold(0_u64, |sum, &size| {
            sum.checked_add(size)
                .context("native manifest size overflow")
        })?;
        ensure!(bytes <= max_bytes, "native manifest byte limit exceeded");
        Ok(())
    }
}

/// One shared verified transfer state for result and input-tree publication.
struct Transfer {
    reservation: UploadReservation,
    missing: BTreeMap<ContentId, BlobRef>,
    staged: BTreeMap<ContentId, StagedBlob>,
    active: BTreeSet<ContentId>,
}

impl Transfer {
    fn new(reservation: UploadReservation) -> Self {
        Self {
            missing: reservation
                .missing()
                .iter()
                .map(|blob| (blob.id, *blob))
                .collect(),
            reservation,
            staged: BTreeMap::new(),
            active: BTreeSet::new(),
        }
    }

    fn missing(&self) -> Vec<BlobRef> {
        self.missing
            .values()
            .filter(|blob| !self.staged.contains_key(&blob.id))
            .copied()
            .collect()
    }

    fn start(&mut self, blob: BlobRef, limit: usize) -> Result<()> {
        ensure!(
            self.missing.get(&blob.id) == Some(&blob),
            "unexpected content upload"
        );
        ensure!(
            !self.staged.contains_key(&blob.id),
            "content already staged"
        );
        ensure!(
            self.active.len() < limit,
            "concurrent upload limit exceeded"
        );
        ensure!(
            self.active.insert(blob.id),
            "content upload already in flight"
        );
        Ok(())
    }

    fn complete(&self) -> bool {
        self.active.is_empty() && self.staged.len() == self.missing.len()
    }

    fn publish<T>(self, commit: impl FnOnce(Vec<StagedBlob>) -> Result<T>) -> Result<T> {
        let result = commit(self.staged.into_values().collect());
        // Keep previously present blobs reserved through the durable commit.
        drop(self.reservation);
        result
    }
}

struct PendingAction {
    request: ActionRequest,
    permit: CompilePermit,
    inputs: Vec<TreeLease>,
    upload: Option<(ResultManifest, Transfer)>,
    allocation: Option<WorkerAllocation>,
}

enum Pending {
    Action(Box<PendingAction>),
    Tree {
        manifest: TreeManifest,
        transfer: Transfer,
    },
}

impl Pending {
    fn transfer_mut(&mut self) -> Option<&mut Transfer> {
        match self {
            Self::Action(action) => action.upload.as_mut().map(|(_, transfer)| transfer),
            Self::Tree { transfer, .. } => Some(transfer),
        }
    }

    fn check_complete(&self) -> Result<()> {
        let transfer = match self {
            Self::Action(action) => action.upload.as_ref().map(|(_, transfer)| transfer),
            Self::Tree { transfer, .. } => Some(transfer),
        };
        ensure!(
            transfer.is_some_and(Transfer::complete),
            "native upload incomplete"
        );
        Ok(())
    }

    fn publish(self, store: &NativeStore) -> Result<Ready> {
        match self {
            Self::Action(action) => {
                let PendingAction {
                    permit,
                    inputs,
                    upload,
                    ..
                } = *action;
                let (manifest, transfer) = upload.context("missing result negotiation")?;
                let result = transfer.publish(|staged| permit.publish_pinned(&manifest, staged));
                drop(inputs);
                Ok(Ready::Result(result?))
            }
            Self::Tree { manifest, transfer } => Ok(Ready::Tree(TreeDelivery::new(
                transfer.publish(|staged| store.publish_tree_pinned(&manifest, staged))?,
            ))),
        }
    }
}

struct TreeDelivery {
    tree: TreeLease,
    packages: BTreeMap<ContentId, PackageArchiveLease>,
}

impl TreeDelivery {
    const fn new(tree: TreeLease) -> Self {
        Self {
            tree,
            packages: BTreeMap::new(),
        }
    }

    fn open_file(&self, id: ContentId) -> Result<File> {
        if let Some(package) = self.packages.get(&id) {
            return package.open_file();
        }
        self.tree.open_file(id)
    }
}

enum Ready {
    Result(ResultLease),
    Tree(TreeDelivery),
}

impl Ready {
    fn open_file(&self, id: ContentId) -> Result<File> {
        match self {
            Self::Result(lease) => lease.open_file(id),
            Self::Tree(lease) => lease.open_file(id),
        }
    }

    fn committed(&self) -> Committed {
        match self {
            Self::Result(lease) => Committed::Result(lease.manifest().clone()),
            Self::Tree(lease) => Committed::Tree(lease.tree.id()),
        }
    }
}

enum Committed {
    Result(ResultManifest),
    Tree(TreeId),
}

enum Phase {
    Pending(Box<Pending>),
    Publishing,
    Ready(Ready),
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Action,
    Tree,
}

struct Session {
    expires: Instant,
    publisher: Publisher,
    kind: Kind,
    phase: Phase,
}

type SharedSession = Arc<Mutex<Session>>;

/// Owns short-lived compile, upload and download capabilities.
///
/// Filesystem and database operations happen outside the session map lock.
/// Independent uploads stream without holding their session lock.
pub struct NativeSessions {
    coordinator: BuildCoordinator,
    limits: SessionLimits,
    sessions: Mutex<HashMap<Ticket, SharedSession>>,
    active_uploads: AtomicUsize,
}

/// A bounded service slot is occupied. Clients can retry without changing
/// identities or starting additional downloads.
#[derive(Debug)]
pub struct NativeServiceBusy;

impl std::fmt::Display for NativeServiceBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native service capacity exceeded")
    }
}

impl std::error::Error for NativeServiceBusy {}

impl NativeSessions {
    /// Initialize a scheduler-owned native service.
    ///
    /// # Errors
    /// Returns an error for invalid limits.
    pub fn new(store: NativeStore, limits: SessionLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            coordinator: BuildCoordinator::new(store),
            limits,
            sessions: Mutex::new(HashMap::new()),
            active_uploads: AtomicUsize::new(0),
        })
    }

    #[must_use = "the store contains the native content and action index"]
    pub fn store(&self) -> &NativeStore {
        self.coordinator.store()
    }

    /// Resolve an original Rust installer without fetching or decoding its archive.
    /// Warm lookups do not wait for unrelated cold downloads.
    /// # Errors
    /// Returns an error for invalid metadata or storage failure.
    pub fn lookup_rust_package(
        &self,
        identity: PackageIdentity,
        limits: PackageImportLimits,
    ) -> Result<Option<InstallationManifest>> {
        let policy = limits.policy()?;
        let Some(package) = self.store().lookup_package(identity, policy)? else {
            return Ok(None);
        };
        self.store()
            .publish_rust_installer(&package, policy.directory)
            .map(Some)
    }

    /// Import or acquire an original package. The input factory is invoked
    /// only after reserving that original identity and rechecking availability.
    /// Different packages may be acquired together within service limits.
    /// # Errors
    /// Returns an error for busy service, invalid archive or storage failures.
    pub fn provision_rust_package<R: Read>(
        &self,
        identity: PackageIdentity,
        length: ArchiveLength,
        limits: PackageImportLimits,
        executable: &Path,
        acquire: impl FnOnce() -> Result<R>,
    ) -> Result<(InstallationManifest, bool)> {
        let store = self.store();
        let mut upload = None;
        let (package, reused) =
            store.acquire_package(identity, length, limits, executable, || {
                upload = Some(self.upload_slot()?);
                acquire()
            })?;
        drop(upload);
        Ok((
            store.publish_rust_installer(&package, limits.policy()?.directory)?,
            reused,
        ))
    }

    fn sessions(&self) -> Result<MutexGuard<'_, HashMap<Ticket, SharedSession>>> {
        self.sessions
            .lock()
            .map_err(|_| anyhow!("native session map poisoned"))
    }

    fn lock(session: &SharedSession) -> Result<MutexGuard<'_, Session>> {
        session
            .lock()
            .map_err(|_| anyhow!("native session poisoned"))
    }

    fn deadline(&self) -> Instant {
        Instant::now() + self.limits.idle_timeout
    }

    fn get(&self, ticket: Ticket) -> Result<SharedSession> {
        self.sessions()?
            .get(&ticket)
            .cloned()
            .context("unknown or expired native ticket")
    }

    fn register(&self, kind: Kind, publisher: Publisher, phase: Phase) -> Result<Ticket> {
        let mut sessions = self.sessions()?;
        ensure!(
            sessions.len() < self.limits.max_sessions,
            "native session capacity exceeded"
        );
        let ticket = loop {
            let candidate = Ticket(rand::random());
            if !sessions.contains_key(&candidate) {
                break candidate;
            }
        };
        sessions.insert(
            ticket,
            Arc::new(Mutex::new(Session {
                expires: self.deadline(),
                publisher,
                kind,
                phase,
            })),
        );
        drop(sessions);
        Ok(ticket)
    }

    fn touch(&self, session: &mut Session) -> Result<()> {
        ensure!(session.expires > Instant::now(), "native ticket expired");
        session.expires = self.deadline();
        Ok(())
    }

    fn authorize(&self, session: &mut Session, publisher: Publisher) -> Result<()> {
        ensure!(
            session.publisher == publisher,
            "native publisher does not own ticket"
        );
        self.touch(session)
    }

    fn authorize_reader(&self, session: &mut Session, reader: Publisher) -> Result<()> {
        let expected = match session.kind {
            Kind::Action => Publisher::Client,
            Kind::Tree => session.publisher,
        };
        ensure!(reader == expected, "native reader does not own ticket");
        self.touch(session)
    }

    /// Reap expired sessions and release their pins and compile permits.
    ///
    /// # Errors
    /// Returns an error if the session map is poisoned.
    pub fn reap(&self) -> Result<usize> {
        let now = Instant::now();
        let (count, expired) = {
            let mut map = self.sessions()?;
            let before = map.len();
            let mut expired = Vec::new();
            // Never wait on another session's I/O while holding the global map.
            map.retain(|_, shared| match shared.try_lock() {
                Ok(mut state) => {
                    if state.expires <= now && !matches!(state.phase, Phase::Publishing) {
                        expired.push(std::mem::replace(&mut state.phase, Phase::Failed));
                        false
                    } else {
                        true
                    }
                }
                Err(std::sync::TryLockError::WouldBlock) => true,
                Err(std::sync::TryLockError::Poisoned(error)) => {
                    expired.push(std::mem::replace(
                        &mut error.into_inner().phase,
                        Phase::Failed,
                    ));
                    false
                }
            });
            (before - map.len(), expired)
        };
        // Release permits even if an expired upload still owns a session Arc.
        drop(expired);
        Ok(count)
    }

    /// Admit a complete action, pinning its input closure on a miss.
    ///
    /// # Errors
    /// Returns an error for invalid inputs, missing trees, capacity exhaustion
    /// or storage failure.
    pub fn admit(&self, request: ActionRequest, publisher: Publisher) -> Result<NativeAdmission> {
        self.reap()?;
        let fingerprint = request.action_fingerprint()?;
        match self.coordinator.admit(fingerprint)? {
            Admission::InFlight => Ok(NativeAdmission::InFlight),
            Admission::Cached(lease) => {
                request.validate_result(lease.manifest())?;
                let manifest = lease.manifest().clone();
                let ticket =
                    self.register(Kind::Action, publisher, Phase::Ready(Ready::Result(lease)))?;
                Ok(NativeAdmission::Hit { ticket, manifest })
            }
            Admission::Compile(permit) => {
                let mut inputs = Vec::new();
                let mut missing = BTreeSet::new();
                for &id in &request.input_trees {
                    match self.store().lookup_tree(id)? {
                        Some(lease) => inputs.push(lease),
                        None => {
                            missing.insert(id);
                        }
                    }
                }
                if !missing.is_empty() {
                    // Drop the compile permit rather than reserve capacity
                    // while the client supplies its input closure.
                    return Ok(NativeAdmission::MissingInputs { trees: missing });
                }
                let packages = inputs
                    .iter()
                    .map(|lease| (lease.id(), lease.manifest()))
                    .collect();
                let composed = request.root.recipe.compose(&packages)?;
                request.root.verify(composed.id()?)?;
                self.limits.check_blobs(Kind::Tree, &composed.blobs()?)?;
                let pending = Pending::Action(Box::new(PendingAction {
                    request,
                    permit,
                    inputs,
                    upload: None,
                    allocation: None,
                }));
                let ticket =
                    self.register(Kind::Action, publisher, Phase::Pending(Box::new(pending)))?;
                Ok(NativeAdmission::Compile { ticket })
            }
        }
    }

    /// Allocate one scheduler job for a pending action, or replay the
    /// original allocation after a lost response. The per-action lock
    /// serializes allocation without blocking unrelated actions.
    ///
    /// # Errors
    /// Returns an error if the declaration differs, the ticket is not pending,
    /// or allocation fails.
    pub fn schedule(
        &self,
        ticket: Ticket,
        request: &ActionRequest,
        allocate: impl FnOnce() -> Result<ScheduleReply>,
    ) -> Result<ScheduleReply> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.touch(&mut state)?;
        let publisher = state.publisher;
        let Phase::Pending(pending) = &mut state.phase else {
            bail!("native ticket is no longer pending");
        };
        let Pending::Action(action) = &mut **pending else {
            bail!("native ticket is not an action");
        };
        ensure!(
            &action.request == request,
            "allocation declaration differs from admission"
        );
        if let Some(allocation) = &action.allocation {
            return Ok(ScheduleReply::Assigned(allocation.clone()));
        }
        ensure!(
            publisher == Publisher::Client && action.upload.is_none(),
            "native action already has a publisher"
        );
        let reply = allocate()?;
        if let ScheduleReply::Assigned(allocation) = &reply {
            action.allocation = Some(allocation.clone());
            state.publisher = Publisher::Worker {
                address: allocation.address,
                job: allocation.job,
            };
        }
        state.expires = self.deadline();
        drop(state);
        Ok(reply)
    }

    /// Verify that the executing worker received the admitted declaration.
    ///
    /// # Errors
    /// Returns an error for unauthorized, expired or mismatched actions.
    pub fn verify_execution(
        &self,
        ticket: Ticket,
        publisher: Publisher,
        request: &ActionRequest,
    ) -> Result<()> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize(&mut state, publisher)?;
        let Phase::Pending(pending) = &state.phase else {
            bail!("native action no longer pending");
        };
        let Pending::Action(action) = &**pending else {
            bail!("native ticket is not an action");
        };
        ensure!(
            &action.request == request,
            "execution declaration differs from admission"
        );
        drop(state);
        Ok(())
    }

    /// Renew a live compilation lease from its authenticated publisher.
    ///
    /// # Errors
    /// Returns an error if the ticket expired or belongs to another publisher.
    pub fn renew(&self, ticket: Ticket, publisher: Publisher) -> Result<()> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        if matches!(state.phase, Phase::Ready(_)) && publisher == Publisher::Client {
            self.authorize_reader(&mut state, publisher)
        } else {
            self.authorize(&mut state, publisher)
        }
    }

    fn upload_slot(&self) -> Result<UploadSlot<'_>> {
        let mut active = self.active_uploads.load(Ordering::Acquire);
        loop {
            if active >= self.limits.max_total_uploads {
                return Err(NativeServiceBusy.into());
            }
            match self.active_uploads.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(UploadSlot(&self.active_uploads)),
                Err(observed) => active = observed,
            }
        }
    }

    /// Negotiate missing output content. Identical repeated requests are safe.
    ///
    /// # Errors
    /// Returns an error for unauthorized or expired tickets, invalid results,
    /// exceeded limits or storage failure.
    pub fn begin(
        &self,
        ticket: Ticket,
        publisher: Publisher,
        manifest: ResultManifest,
    ) -> Result<BeginResult> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize(&mut state, publisher)?;
        self.limits.check_blobs(Kind::Action, &manifest.blobs()?)?;
        match &mut state.phase {
            Phase::Pending(pending) => {
                let Pending::Action(action) = &mut **pending else {
                    bail!("ticket does not accept a result");
                };
                action.request.validate_result(&manifest)?;
                if let Some((previous, transfer)) = &action.upload {
                    ensure!(
                        previous == &manifest,
                        "result manifest changed after negotiation"
                    );
                    return Ok(BeginResult {
                        missing: transfer.missing(),
                    });
                }
                let transfer = Transfer::new(self.store().reserve_upload(&manifest)?);
                let missing = transfer.missing();
                action.upload = Some((manifest, transfer));
                drop(state);
                Ok(BeginResult { missing })
            }
            Phase::Ready(Ready::Result(lease)) => {
                ensure!(
                    lease.manifest() == &manifest,
                    "result already committed with different manifest"
                );
                Ok(BeginResult {
                    missing: Vec::new(),
                })
            }
            _ => bail!("native session is not accepting a result"),
        }
    }

    /// Negotiate a tree upload. A previously committed tree needs no data.
    ///
    /// # Errors
    /// Returns an error for invalid manifests, limits or storage failure.
    pub fn offer_tree(&self, manifest: TreeManifest) -> Result<TreeOffer> {
        self.reap()?;
        let id = manifest.id()?;
        self.limits.check_blobs(Kind::Tree, &manifest.blobs()?)?;
        let (phase, missing) = if let Some(lease) = self.store().lookup_tree(id)? {
            (
                Phase::Ready(Ready::Tree(TreeDelivery::new(lease))),
                Vec::new(),
            )
        } else {
            let transfer = Transfer::new(self.store().reserve_tree_upload(&manifest)?);
            let missing = transfer.missing();
            (
                Phase::Pending(Box::new(Pending::Tree { manifest, transfer })),
                missing,
            )
        };
        let ticket = self.register(Kind::Tree, Publisher::Client, phase)?;
        Ok(TreeOffer {
            ticket,
            id,
            missing,
        })
    }

    /// Open a tree delivery lease. Workers can only fetch a declared input of
    /// their currently delegated action.
    ///
    /// # Errors
    /// Returns an error for unauthorized, missing or invalid trees.
    pub fn open_tree(
        &self,
        id: TreeId,
        reader: Publisher,
        action_ticket: Option<Ticket>,
    ) -> Result<TreeRead> {
        self.reap()?;
        let action = if reader == Publisher::Client {
            None
        } else {
            Some(self.get(action_ticket.context("worker tree request needs its action ticket")?)?)
        };
        let state = if let Some(action) = &action {
            let mut state = Self::lock(action)?;
            self.authorize(&mut state, reader)?;
            let Phase::Pending(pending) = &state.phase else {
                bail!("worker action no longer pending");
            };
            let Pending::Action(action) = &**pending else {
                bail!("worker ticket is not an action");
            };
            ensure!(
                action.request.input_trees.contains(&id),
                "tree is not an input of this action"
            );
            Some(state)
        } else {
            None
        };
        // The action pins this tree until the delivery lease is acquired.
        let lease = self
            .store()
            .lookup_tree(id)?
            .context("native input tree unavailable")?;
        drop(state);
        let manifest = lease.manifest().clone();
        let ticket = self.register(
            Kind::Tree,
            reader,
            Phase::Ready(Ready::Tree(TreeDelivery::new(lease))),
        )?;
        Ok(TreeRead { ticket, manifest })
    }

    /// Negotiate compressed originals for an already authorized worker tree
    /// delivery. Requests cannot name blobs outside that tree.
    /// # Errors
    /// Returns an error for unauthorized or invalid delivery requests.
    pub fn plan_packages(
        &self,
        ticket: Ticket,
        reader: Publisher,
        missing: &[BlobRef],
        max_archive_bytes: u64,
    ) -> Result<Vec<PackageArchive>> {
        ensure!(
            matches!(reader, Publisher::Worker { .. }),
            "package delivery requires a worker"
        );
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize_reader(&mut state, reader)?;
        let Phase::Ready(Ready::Tree(delivery)) = &mut state.phase else {
            bail!("package delivery requires a tree ticket");
        };
        let blobs = delivery.tree.manifest().blobs()?;
        ensure!(
            missing.len() <= blobs.len()
                && missing
                    .iter()
                    .all(|blob| blobs.get(&blob.id) == Some(&blob.size)),
            "package request contains undeclared content"
        );
        // Bounded archive count per request. Remaining content is fetched by
        // the ordinary exact-blob protocol.
        let packages = self
            .store()
            .plan_package_downloads(missing, 8, max_archive_bytes)?;
        let offers = packages.iter().map(PackageArchiveLease::archive).collect();
        delivery.packages = packages
            .into_iter()
            .map(|lease| (lease.archive().blob.id, lease))
            .collect();
        drop(state);
        Ok(offers)
    }

    /// Stream one negotiated missing blob, verifying digest and size.
    ///
    /// # Errors
    /// Returns an error for unauthorized, unexpected or invalid uploads.
    pub fn upload(
        &self,
        ticket: Ticket,
        publisher: Publisher,
        blob: BlobRef,
        reader: impl Read,
    ) -> Result<()> {
        let _slot = self.upload_slot()?;
        let session = self.get(ticket)?;
        {
            let mut state = Self::lock(&session)?;
            self.authorize(&mut state, publisher)?;
            let Phase::Pending(pending) = &mut state.phase else {
                bail!("no active native upload");
            };
            pending
                .transfer_mut()
                .context("no negotiated native upload")?
                .start(blob, self.limits.max_concurrent_uploads)?;
            drop(state);
        }
        let result = self.store().stage_expected(blob, reader);
        let mut state = Self::lock(&session)?;
        // Clear the active marker even if this upload exceeded its lease.
        if let Phase::Pending(pending) = &mut state.phase
            && let Some(transfer) = pending.transfer_mut()
        {
            transfer.active.remove(&blob.id);
        }
        self.authorize(&mut state, publisher)?;
        let Phase::Pending(pending) = &mut state.phase else {
            bail!("native upload cancelled");
        };
        let transfer = pending.transfer_mut().context("native upload cancelled")?;
        transfer.staged.insert(blob.id, result?);
        drop(state);
        Ok(())
    }

    fn commit_pending(
        &self,
        ticket: Ticket,
        publisher: Publisher,
        kind: Kind,
    ) -> Result<Committed> {
        let session = self.get(ticket)?;
        let pending = {
            let mut state = Self::lock(&session)?;
            self.authorize(&mut state, publisher)?;
            ensure!(
                state.kind == kind,
                "native ticket has wrong publication kind"
            );
            match &state.phase {
                Phase::Ready(lease) => return Ok(lease.committed()),
                Phase::Pending(pending) => pending.check_complete()?,
                _ => bail!("native session cannot commit"),
            }
            let Phase::Pending(pending) = std::mem::replace(&mut state.phase, Phase::Publishing)
            else {
                bail!("native phase changed");
            };
            drop(state);
            pending
        };
        let result = pending.publish(self.store());
        let mut state = Self::lock(&session)?;
        state.expires = self.deadline();
        let reply = match result {
            Ok(lease) => {
                let reply = lease.committed();
                state.phase = Phase::Ready(lease);
                Ok(reply)
            }
            Err(error) => {
                state.phase = Phase::Failed;
                Err(error)
            }
        };
        drop(state);
        reply
    }

    /// Commit a negotiated successful result and retain its delivery lease.
    ///
    /// # Errors
    /// Returns an error for invalid tickets, incomplete uploads or storage failure.
    pub fn commit(&self, ticket: Ticket, publisher: Publisher) -> Result<ResultManifest> {
        match self.commit_pending(ticket, publisher, Kind::Action)? {
            Committed::Result(manifest) => Ok(manifest),
            Committed::Tree(_) => bail!("native result publication returned a tree"),
        }
    }

    /// Commit one negotiated input tree and retain its publication lease.
    ///
    /// # Errors
    /// Returns an error for invalid tickets, incomplete uploads or storage failure.
    pub fn commit_tree(&self, ticket: Ticket) -> Result<TreeId> {
        match self.commit_pending(ticket, Publisher::Client, Kind::Tree)? {
            Committed::Tree(id) => Ok(id),
            Committed::Result(_) => bail!("native tree publication returned a result"),
        }
    }

    /// Observe the result of a client-owned action ticket.
    ///
    /// # Errors
    /// Returns an error for unknown or expired tickets.
    pub fn status(&self, ticket: Ticket) -> Result<NativeStatus> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        ensure!(state.kind == Kind::Action, "native ticket is not an action");
        if matches!(state.phase, Phase::Ready(_) | Phase::Failed) {
            self.touch(&mut state)?;
        } else if !matches!(state.phase, Phase::Publishing) {
            ensure!(state.expires > Instant::now(), "native ticket expired");
        }
        Ok(match &state.phase {
            Phase::Pending(_) | Phase::Publishing => NativeStatus::Compiling,
            Phase::Ready(Ready::Result(lease)) => NativeStatus::Ready(lease.manifest().clone()),
            Phase::Ready(Ready::Tree(_)) => bail!("native action has a tree result"),
            Phase::Failed => NativeStatus::Failed,
        })
    }

    /// Open only declared content with an owned file descriptor.
    ///
    /// # Errors
    /// Returns an error for unknown tickets, unavailable or undeclared content.
    pub fn download(&self, ticket: Ticket, reader: Publisher, id: ContentId) -> Result<File> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize_reader(&mut state, reader)?;
        let Phase::Ready(lease) = &state.phase else {
            bail!("native content not available");
        };
        let file = lease.open_file(id);
        drop(state);
        file
    }

    /// Release a delivery ticket, or cancel an unfinished action.
    ///
    /// # Errors
    /// Returns an error for unauthorized tickets or publication already in progress.
    pub fn close(&self, ticket: Ticket, reader: Publisher) -> Result<()> {
        let session = self.get(ticket)?;
        let previous = {
            let mut state = Self::lock(&session)?;
            self.authorize_reader(&mut state, reader)?;
            ensure!(
                !matches!(state.phase, Phase::Publishing),
                "native publication in progress"
            );
            state.expires = Instant::now();
            std::mem::replace(&mut state.phase, Phase::Failed)
        };
        let removed = self.sessions()?.remove(&ticket);
        drop(removed);
        drop(previous);
        Ok(())
    }

    /// Fail an action from its authenticated publisher, releasing its permit.
    ///
    /// # Errors
    /// Returns an error for unauthorized tickets or completed publication.
    pub fn fail(&self, ticket: Ticket, publisher: Publisher) -> Result<()> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize(&mut state, publisher)?;
        ensure!(
            matches!(state.phase, Phase::Pending(_) | Phase::Failed),
            "native action already publishing or committed"
        );
        let previous = std::mem::replace(&mut state.phase, Phase::Failed);
        drop(state);
        drop(previous);
        Ok(())
    }
}

struct UploadSlot<'a>(&'a AtomicUsize);

impl Drop for UploadSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests;
