//! Expiring native cache sessions, independent of transport and worker selection.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    future::Future,
    io::Read,
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use crate::store::PackagePreparation;
use anyhow::{Context, Result, anyhow, bail, ensure};
use bincode::Options;

use crate::{
    ActionMode, Admission, ArchiveLength, BlobEncoding, BlobRef, BuildCoordinator, CompilePermit,
    ContentId, NativeStore, PackageArchive, PackageArchiveLease, PackageIdentity,
    PackageImportLimits, PackageTransferCost, ResultLease, ResultManifest, StagedBlob, TreeId,
    TreeLease, TreeManifest, UploadReservation, VerifiedPackage,
    wire::{
        ActionRequest, BeginResult, ClientDeliveryObservation, DeliverySelection, InputDemand,
        InputPoll, NativeAdmission, NativeStatus, Publisher, ScheduleReply, Ticket, TreeOffer,
        TreeRead, WorkerAllocation,
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
    pub max_manifest_cache_bytes: usize,
    pub peer_discovery_timeout: Duration,
}

impl SessionLimits {
    /// Validate limits before starting the service.
    ///
    /// # Errors
    /// Returns an error for zero or unusable limits.
    pub fn validate(self) -> Result<()> {
        ensure!(
            !self.idle_timeout.is_zero()
                && Instant::now().checked_add(self.idle_timeout).is_some()
                && self.peer_discovery_timeout <= self.idle_timeout,
            "invalid session timeout"
        );
        ensure!(
            self.max_sessions > 0
                && self.max_result_blobs > 0
                && self.max_result_bytes > 0
                && self.max_tree_blobs > 0
                && self.max_tree_bytes > 0
                && self.max_concurrent_uploads > 0
                && self.max_total_uploads > 0
                && self.max_manifest_cache_bytes > 0,
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
    budget: crate::store::StagingReservation,
    missing: BTreeMap<ContentId, BlobRef>,
    staged: BTreeMap<ContentId, StagedBlob>,
    active: BTreeSet<ContentId>,
}

impl Transfer {
    fn new(
        store: &NativeStore,
        reservation: UploadReservation,
        closure: &BTreeMap<ContentId, u64>,
    ) -> Result<Self> {
        // Admit the actual missing closure atomically, before accepting any
        // bytes. Partial uploads must not deadlock competing publications.
        let bytes = reservation.missing().iter().try_fold(0_u64, |sum, blob| {
            sum.checked_add(blob.size).context("transfer size overflow")
        })?;
        if bytes != 0 {
            let total = closure.values().try_fold(0_u64, |sum, &size| {
                sum.checked_add(size)
                    .context("transfer closure size overflow")
            })?;
            store.check_transfer_capacity(total)?;
        }
        let budget = store.reserve_transfer(bytes)?;
        Ok(Self {
            budget,
            missing: reservation
                .missing()
                .iter()
                .map(|blob| (blob.id, *blob))
                .collect(),
            reservation,
            staged: BTreeMap::new(),
            active: BTreeSet::new(),
        })
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
        if self.active.len() >= limit {
            return Err(NativeServiceBusy.into());
        }
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

struct InputManifest {
    manifest: TreeManifest,
    blobs: BTreeMap<ContentId, u64>,
}

struct CachedManifest {
    input: Arc<InputManifest>,
    bytes: usize,
    used: Instant,
}

#[derive(Default)]
struct ManifestCatalog {
    entries: HashMap<TreeId, CachedManifest>,
    bytes: usize,
}

impl ManifestCatalog {
    fn get(&mut self, id: TreeId) -> Option<Arc<InputManifest>> {
        self.entries.get_mut(&id).map(|entry| {
            entry.used = Instant::now();
            Arc::clone(&entry.input)
        })
    }

    fn remember(&mut self, id: TreeId, input: Arc<InputManifest>, bytes: usize, limit: usize) {
        if bytes > limit {
            return;
        }
        if let Some(previous) = self.entries.remove(&id) {
            self.bytes -= previous.bytes;
        }
        while self.bytes > limit - bytes {
            let Some((&oldest, _)) = self.entries.iter().min_by_key(|(_, entry)| entry.used) else {
                break;
            };
            if let Some(removed) = self.entries.remove(&oldest) {
                self.bytes -= removed.bytes;
            }
        }
        self.entries.insert(
            id,
            CachedManifest {
                input,
                bytes,
                used: Instant::now(),
            },
        );
        self.bytes += bytes;
    }
}

struct PendingAction {
    request: ActionRequest,
    permit: CompilePermit,
    inputs: BTreeMap<TreeId, Arc<InputManifest>>,
    inputs_staged: bool,
    demands: BTreeMap<ContentId, (TreeId, Arc<Backfill>)>,
    unavailable: BTreeSet<(TreeId, ContentId)>,
    origin: Arc<()>,
    upload: Option<(ResultManifest, Transfer)>,
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
                let PendingAction { permit, upload, .. } = *action;
                let (manifest, transfer) = upload.context("missing result negotiation")?;
                let result = transfer.publish(|staged| permit.publish_pinned(&manifest, staged));
                Ok(Ready::Result(Arc::new(result?)))
            }
            Self::Tree { manifest, transfer } => Ok(Ready::Tree(Box::new(TreeDelivery::new(
                transfer.publish(|staged| store.publish_tree_pinned(&manifest, staged))?,
            )))),
        }
    }

    async fn publish_async(self, store: &NativeStore) -> Result<Ready> {
        match self {
            Self::Action(action) => {
                let PendingAction { permit, upload, .. } = *action;
                let (manifest, transfer) = upload.context("missing result negotiation")?;
                let Transfer {
                    reservation,
                    staged,
                    ..
                } = transfer;
                let result = permit
                    .publish_pinned_async(manifest, staged.into_values().collect(), reservation)
                    .await?;
                Ok(Ready::Result(Arc::new(result)))
            }
            Self::Tree { manifest, transfer } => {
                let Transfer {
                    reservation,
                    staged,
                    ..
                } = transfer;
                let tree = store
                    .publish_tree_pinned_async(
                        manifest,
                        staged.into_values().collect(),
                        reservation,
                    )
                    .await?;
                Ok(Ready::Tree(Box::new(TreeDelivery::new(tree))))
            }
        }
    }
}

enum TreeSource {
    Stored(TreeLease),
    Action {
        ticket: Ticket,
        id: TreeId,
        input: Arc<InputManifest>,
    },
}

struct TreeDelivery {
    source: TreeSource,
    packages: BTreeMap<ContentId, PackageArchiveLease>,
    requested: BTreeSet<ContentId>,
    reservation: Option<UploadReservation>,
}

impl TreeDelivery {
    const fn new(tree: TreeLease) -> Self {
        Self {
            source: TreeSource::Stored(tree),
            packages: BTreeMap::new(),
            requested: BTreeSet::new(),
            reservation: None,
        }
    }

    fn manifest(&self) -> &TreeManifest {
        match &self.source {
            TreeSource::Stored(tree) => tree.manifest(),
            TreeSource::Action { input, .. } => &input.manifest,
        }
    }
}

/// A missing file may be shared by several independently admitted actions.
/// Only the claimed origin uploads; the verified retention lease is shared.
struct Backfill {
    blob: BlobRef,
    requester: crate::PeerId,
    state: Mutex<BackfillState>,
}

#[derive(Default)]
struct BackfillState {
    // Give a bounded peer discovery window before requesting the origin.
    peer_until: Option<Instant>,
    // Retry only after an origin has explicitly exhausted its sources.
    // Between probes any other live origin can claim the input.
    peer_retry_at: Option<Instant>,
    claim: Option<BackfillClaim>,
    uploading: bool,
    ready: Option<Arc<TreeLease>>,
}

struct BackfillClaim {
    ticket: Ticket,
    expires: Instant,
    origin: Weak<()>,
}

impl BackfillClaim {
    fn live(&self, now: Instant) -> bool {
        self.expires > now && self.origin.strong_count() > 0
    }
}

impl Backfill {
    fn lock(&self) -> Result<MutexGuard<'_, BackfillState>> {
        self.state
            .lock()
            .map_err(|_| anyhow!("native backfill lock poisoned"))
    }
}

struct BackfillUpload {
    flight: Arc<Backfill>,
    _slot: Option<UploadSlot>,
}

impl BackfillUpload {
    fn complete(self, lease: Arc<TreeLease>) -> Result<()> {
        let mut pending = self.flight.lock()?;
        pending.ready = Some(lease);
        pending.peer_until = None;
        pending.peer_retry_at = None;
        drop(pending);
        Ok(())
    }
}

impl Drop for BackfillUpload {
    fn drop(&mut self) {
        if let Ok(mut state) = self.flight.lock() {
            state.uploading = false;
        }
    }
}

/// Exclusive opportunity to recover one missing input from a peer cache.
/// Dropping the claim allows the originating client to supply the same blob.
pub struct PeerInputClaim(BackfillUpload);

impl PeerInputClaim {
    #[must_use = "identifies the content claimed for recovery"]
    pub fn blob(&self) -> BlobRef {
        self.0.flight.blob
    }

    #[must_use = "identifies the worker awaiting recovered content"]
    pub fn requester(&self) -> crate::PeerId {
        self.0.flight.requester
    }
}

enum Ready {
    Result(Arc<ResultLease>),
    Tree(Box<TreeDelivery>),
}

impl Ready {
    fn committed(&self) -> Result<Committed> {
        match self {
            Self::Result(lease) => Ok(Committed::Result(lease.manifest().clone())),
            Self::Tree(lease) => match &lease.source {
                TreeSource::Stored(tree) => Ok(Committed::Tree(tree.id())),
                TreeSource::Action { .. } => bail!("delivery tickets cannot be committed"),
            },
        }
    }
}

enum Committed {
    Result(ResultManifest),
    Tree(TreeId),
}

enum Phase {
    Pending(Box<Pending>),
    Publishing(Option<ResultManifest>),
    Ready(Ready),
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Action,
    Tree,
}

struct AllocationIntent {
    declaration: [u8; 32],
    requester: crate::PeerId,
    selection: DeliverySelection,
}

impl AllocationIntent {
    fn matches(
        &self,
        declaration: [u8; 32],
        requester: crate::PeerId,
        selection: &DeliverySelection,
    ) -> bool {
        self.declaration == declaration
            && self.requester == requester
            && &self.selection == selection
    }
}

struct DelegatedAllocation {
    declaration: [u8; 32],
    worker: WorkerAllocation,
    requester: crate::PeerId,
    selection: DeliverySelection,
    allocation_started: Instant,
    delivery_reported: bool,
}

/// An authenticated receipt for a committed remote action. The scheduler
/// owns the elapsed clock; client timing and byte counts are advisory.
#[derive(Debug, Clone, Copy)]
pub struct DeliveryReceipt {
    pub worker: crate::PeerId,
    pub job: u64,
    pub requester: crate::PeerId,
    pub profile: ContentId,
    pub result_bytes: u64,
    pub elapsed: Duration,
    pub observation: ClientDeliveryObservation,
}

struct Session {
    allocating: Option<Arc<AllocationIntent>>,
    allocation: Option<DelegatedAllocation>,
    expires: Instant,
    publisher: Publisher,
    kind: Kind,
    phase: Phase,
}

impl Session {
    fn result_negotiation(&mut self, manifest: &ResultManifest) -> Result<ResultNegotiation<'_>> {
        match &mut self.phase {
            Phase::Pending(pending) => {
                let Pending::Action(action) = &mut **pending else {
                    bail!("ticket does not accept a result");
                };
                if let Some((previous, transfer)) = &action.upload {
                    ensure!(
                        previous == manifest,
                        "result manifest changed after negotiation"
                    );
                    Ok(ResultNegotiation::Existing(BeginResult {
                        missing: transfer.missing(),
                    }))
                } else {
                    action.request.validate_output_contract(manifest)?;
                    Ok(ResultNegotiation::Unnegotiated(action))
                }
            }
            Phase::Ready(Ready::Result(lease)) => {
                ensure!(
                    lease.manifest() == manifest,
                    "result already committed with different manifest"
                );
                Ok(ResultNegotiation::Existing(BeginResult {
                    missing: Vec::new(),
                }))
            }
            _ => bail!("native session is not accepting a result"),
        }
    }

    fn negotiated_result(&self) -> Option<&ResultManifest> {
        // Local execution and trees keep their existing publication semantics.
        self.allocation.as_ref()?;
        match &self.phase {
            Phase::Pending(pending) => match &**pending {
                Pending::Action(action) => action.upload.as_ref().map(|(manifest, _)| manifest),
                Pending::Tree { .. } => None,
            },
            Phase::Publishing(manifest) => manifest.as_ref(),
            _ => None,
        }
    }
}

enum ResultNegotiation<'a> {
    Existing(BeginResult),
    Unnegotiated(&'a mut PendingAction),
}

type SharedSession = Arc<Mutex<Session>>;

enum CommitStart {
    Ready(Committed),
    Pending {
        session: SharedSession,
        pending: Box<Pending>,
    },
}

// The allocation claim owns no mutex guard. Failure or unwinding releases
// only its own intent, never a later retry.
struct AllocationClaim {
    session: SharedSession,
    intent: Arc<AllocationIntent>,
}

impl Drop for AllocationClaim {
    fn drop(&mut self) {
        if let Ok(mut state) = self.session.lock()
            && state
                .allocating
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.intent))
        {
            state.allocating = None;
        }
    }
}

/// Keeps one negotiated upload and its space reservation alive across
/// incremental I/O. Cancellation clears the active marker and discards
/// the incomplete staging file, rather than stranding the transfer.
pub struct NativeUpload {
    stager: crate::store::PhysicalStager,
    publication: UploadPublication,
}

enum UploadPublication {
    Direct(UploadGuard),
    Backfill {
        manifest: TreeManifest,
        reserved: UploadReservation,
        guard: BackfillUpload,
    },
}

fn backfill_error(error: anyhow::Error) -> anyhow::Error {
    use crate::store::BlobIntegrityError;
    match error.downcast_ref::<BlobIntegrityError>() {
        Some(BlobIntegrityError::Digest) => error.context(NativeInputRejected),
        Some(BlobIntegrityError::Length { expected, actual }) if actual > expected => {
            error.context(NativeInputRejected)
        }
        // Short/truncated bodies and local storage failures leave the
        // claim retryable; another source may still satisfy it.
        _ => {
            log::debug!("native backfill publication interrupted: {error:#}");
            error.context(NativeServiceBusy)
        }
    }
}

impl NativeUpload {
    /// Accept the next bounded physical bytes.
    ///
    /// # Errors
    /// Returns an error for malformed input or storage failure.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        let result = self.stager.feed(bytes);
        self.classify(result)
    }

    /// Whether incremental encoding may require compression or decompression.
    #[must_use = "determines whether processing requires the codec executor"]
    pub fn requires_codec_pool(&self) -> bool {
        self.stager.requires_codec_pool()
    }

    /// Verify and encode a bounded batch without filesystem I/O.
    ///
    /// # Errors
    /// Returns an error for malformed input or an unflushed previous batch.
    pub fn encode_pending(&mut self, bytes: &[u8]) -> Result<()> {
        let result = self.stager.encode_pending(bytes);
        self.classify(result)
    }

    /// Write the verified physical batch, without codec work.
    ///
    /// # Errors
    /// Returns an error for storage failure or a failed codec.
    pub fn flush_pending(&mut self) -> Result<()> {
        let result = self.stager.flush_pending();
        self.classify(result)
    }

    /// Submit a verified physical batch to the completion driver.
    ///
    /// # Errors
    /// Returns an error for storage failure or a failed codec.
    #[cfg(feature = "async-io")]
    pub async fn flush_pending_async(self) -> Result<Self> {
        crate::disk::run(move || async move {
            let mut upload = self;
            let result = upload.stager.flush_pending_io().await;
            upload.classify(result)?;
            Ok(upload)
        })
        .await
    }

    /// Flush and synchronize a completely verified staging file.
    ///
    /// # Errors
    /// Returns an error for storage failure or an unfinished codec.
    #[cfg(feature = "async-io")]
    pub async fn finish_file_async(self) -> Result<Self> {
        crate::disk::run(move || async move {
            let mut upload = self;
            let result = upload.stager.finalize_io().await;
            upload.classify(result)?;
            Ok(upload)
        })
        .await
    }

    /// Complete codec validation and produce any final physical bytes.
    ///
    /// # Errors
    /// Returns an error for invalid or incomplete content.
    pub fn finish_encoding(&mut self) -> Result<()> {
        let result = self.stager.finish_encoding();
        self.classify(result)
    }

    fn classify<T>(&self, result: Result<T>) -> Result<T> {
        match &self.publication {
            UploadPublication::Direct(_) => result,
            UploadPublication::Backfill { .. } => result.map_err(backfill_error),
        }
    }
}

struct UploadGuard {
    session: SharedSession,
    publisher: Publisher,
    blob: BlobRef,
    active: bool,
    _slot: UploadSlot,
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        if self.active
            && let Ok(mut state) = self.session.lock()
            && let Phase::Pending(pending) = &mut state.phase
            && let Some(transfer) = pending.transfer_mut()
        {
            transfer.active.remove(&self.blob.id);
        }
    }
}

/// A replayed allocation or the exclusive right to dispatch a new action.
pub enum SchedulePreparation {
    Replay(ScheduleReply),
    Dispatch(ScheduleReservation),
}

/// Owns a scheduling intent across asynchronous remote assignment.
/// Dropping the reservation releases the intent without changing publisher.
pub struct ScheduleReservation {
    claim: AllocationClaim,
    blobs: BTreeMap<ContentId, u64>,
    trees: Vec<Arc<InputManifest>>,
    allocation_started: Instant,
    idle_timeout: Duration,
}

impl ScheduleReservation {
    /// Move the deduplicated input closure into placement, and borrow the
    /// immutable per-tree closures for the package catalog.
    #[must_use = "placement must use the admitted input closure"]
    pub fn placement_inputs(
        &mut self,
    ) -> (BTreeMap<ContentId, u64>, Vec<&BTreeMap<ContentId, u64>>) {
        (
            std::mem::take(&mut self.blobs),
            self.trees.iter().map(|tree| &tree.blobs).collect(),
        )
    }

    /// Install the delegated publisher after the worker acknowledges.
    ///
    /// # Errors
    /// Returns an error if the client cancelled the allocation or state is poisoned.
    pub fn finish(self, reply: ScheduleReply) -> Result<ScheduleReply> {
        let mut state = NativeSessions::lock(&self.claim.session)?;
        ensure!(
            state
                .allocating
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.claim.intent))
                && matches!(state.phase, Phase::Pending(_)),
            "native allocation cancelled before acknowledgement"
        );
        state.allocating = None;
        if let ScheduleReply::Assigned(allocation) = &reply {
            state.allocation = Some(DelegatedAllocation {
                declaration: self.claim.intent.declaration,
                worker: allocation.clone(),
                requester: self.claim.intent.requester,
                selection: self.claim.intent.selection.clone(),
                allocation_started: self.allocation_started,
                delivery_reported: false,
            });
            state.publisher = Publisher::Worker {
                peer: allocation.peer,
                job: allocation.job,
            };
        }
        state.expires = Instant::now() + self.idle_timeout;
        drop(state);
        Ok(reply)
    }
}

/// Owns short-lived compile, upload and download capabilities.
///
/// Filesystem and database operations happen outside the session map lock.
/// Independent uploads stream without holding their session lock.
pub struct NativeSessions {
    coordinator: BuildCoordinator,
    admission_counters: telemetry::AdmissionCounters,
    limits: SessionLimits,
    sessions: Mutex<HashMap<Ticket, SharedSession>>,
    retained: retention::RetentionGroups,
    active_uploads: Arc<AtomicUsize>,
    backfills: Mutex<HashMap<ContentId, Weak<Backfill>>>,
    peer_wake: Arc<tokio::sync::Notify>,
    manifests: Mutex<ManifestCatalog>,
    recovery: recovery::RecoveryQueue,
    live_traces: live::LiveTraces,
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

/// The origin supplied complete bytes that do not match the requested content.
/// This source locator should be declined rather than retried.
#[derive(Debug)]
pub struct NativeInputRejected;

impl std::fmt::Display for NativeInputRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native input bytes rejected")
    }
}

impl std::error::Error for NativeInputRejected {}

/// An authorized input is being requested from its submitting client.
#[derive(Debug)]
pub struct NativeContentPending;

impl std::fmt::Display for NativeContentPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native input content pending")
    }
}

impl std::error::Error for NativeContentPending {}

impl NativeSessions {
    /// Initialize a scheduler-owned native service.
    ///
    /// # Errors
    /// Returns an error for invalid limits.
    pub fn new(store: NativeStore, limits: SessionLimits) -> Result<Self> {
        limits.validate()?;
        store.enable_result_history(u64::try_from(limits.max_manifest_cache_bytes)?)?;
        Ok(Self {
            coordinator: BuildCoordinator::new(store),
            admission_counters: telemetry::AdmissionCounters::default(),
            limits,
            sessions: Mutex::new(HashMap::new()),
            retained: retention::RetentionGroups::default(),
            active_uploads: Arc::new(AtomicUsize::new(0)),
            backfills: Mutex::new(HashMap::new()),
            peer_wake: Arc::new(tokio::sync::Notify::new()),
            manifests: Mutex::new(ManifestCatalog::default()),
            recovery: recovery::RecoveryQueue::default(),
            live_traces: live::LiveTraces::default(),
        })
    }

    /// Record a complete bounded client snapshot, replacing its previous report.
    /// # Errors
    /// Invalid observation or exceeded reporter capacity.
    pub fn report_live_traces(
        &self,
        peer: crate::PeerId,
        report: crate::wire::LiveTraceBatch,
    ) -> Result<()> {
        self.live_traces.report(peer, report, Instant::now())
    }

    /// Observe current, unexpired request reports.
    /// # Errors
    /// The live observation registry is poisoned.
    pub fn live_traces(&self) -> Result<crate::wire::LiveTraceSnapshot> {
        self.live_traces.snapshot(Instant::now())
    }

    #[must_use = "the store contains the native content and action index"]
    pub fn store(&self) -> &NativeStore {
        self.coordinator.store()
    }

    /// Resolve an original archive without fetching or decoding it again.
    /// Warm lookups do not wait for unrelated cold downloads.
    /// # Errors
    /// Returns an error for invalid metadata or storage failure.
    pub fn lookup_package(
        &self,
        identity: PackageIdentity,
        limits: PackageImportLimits,
    ) -> Result<Option<VerifiedPackage>> {
        self.store().lookup_package(identity, limits.policy()?)
    }

    /// Claim an original package and its shared upload capacity before
    /// receiving bytes. A cache hit needs neither an upload nor a decoder.
    ///
    /// # Errors
    /// Returns an error for a busy service, invalid metadata or storage failure.
    pub fn prepare_package(
        &self,
        identity: PackageIdentity,
        length: ArchiveLength,
        limits: PackageImportLimits,
    ) -> Result<PackagePreparation<impl Send + 'static + use<>>> {
        self.store().prepare_package(identity, length, limits, || {
            self.upload_slot(UploadSource::Direct)
        })
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
                allocating: None,
                allocation: None,
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
        ensure!(
            session.allocating.is_some() || session.expires > Instant::now(),
            "native ticket expired"
        );
        session.expires = self.deadline();
        Ok(())
    }

    fn authorize(&self, session: &mut Session, publisher: Publisher) -> Result<()> {
        if session.allocating.is_some() {
            return Err(NativeServiceBusy.into());
        }
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
                    if state.expires <= now
                        && state.allocating.is_none()
                        && !matches!(state.phase, Phase::Publishing(_))
                    {
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
        self.reap_backfills(now)?;
        self.recovery.reap()?;
        Ok(count + self.retained.reap(now)?)
    }

    // A canceled origin can leave an upload claim alive in a flight shared
    // by other actions. Reclaim those slots even if none of the remaining
    // origins polls that particular blob again.
    fn reap_backfills(&self, now: Instant) -> Result<()> {
        let flights = {
            let mut map = self
                .backfills
                .lock()
                .map_err(|_| anyhow!("native backfill map poisoned"))?;
            let mut live = Vec::new();
            map.retain(|_, flight| {
                flight.upgrade().is_some_and(|flight| {
                    live.push(flight);
                    true
                })
            });
            live
        };
        for flight in flights {
            let mut pending = flight.lock()?;
            if pending.claim.as_ref().is_some_and(|claim| !claim.live(now)) {
                pending.claim = None;
            }
        }
        Ok(())
    }

    fn input_manifest(
        &self,
        id: TreeId,
        declared: Option<TreeManifest>,
    ) -> Result<Option<Arc<InputManifest>>> {
        let cached = self
            .manifests
            .lock()
            .map_err(|_| anyhow!("native manifest catalog poisoned"))?
            .get(id);
        if let Some(input) = cached {
            ensure!(
                declared
                    .as_ref()
                    .is_none_or(|manifest| manifest == &input.manifest),
                "input manifest differs from validated declaration"
            );
            return Ok(Some(input));
        }
        let manifest = if let Some(manifest) = declared {
            ensure!(manifest.id()? == id, "input manifest identity mismatch");
            manifest
        } else if let Some(manifest) = self.store().lookup_tree_manifest(id)? {
            manifest
        } else {
            return Ok(None);
        };
        let blobs = manifest.blobs()?;
        self.limits.check_blobs(Kind::Tree, &blobs)?;
        let bytes = usize::try_from(bincode::DefaultOptions::new().serialized_size(&manifest)?)?;
        let input = Arc::new(InputManifest { manifest, blobs });
        self.manifests
            .lock()
            .map_err(|_| anyhow!("native manifest catalog poisoned"))?
            .remember(
                id,
                Arc::clone(&input),
                bytes,
                self.limits.max_manifest_cache_bytes,
            );
        Ok(Some(input))
    }

    /// Admit an action from verified manifest identities, without requiring
    /// its entire content closure in the scheduler CAS.
    ///
    /// # Errors
    /// Returns an error for invalid inputs, missing trees, capacity exhaustion
    /// or storage failure.
    pub fn admit(
        &self,
        trace: Option<crate::wire::TraceContext>,
        request: ActionRequest,
        publisher: Publisher,
        mode: ActionMode,
        declared: BTreeMap<TreeId, TreeManifest>,
    ) -> Result<NativeAdmission> {
        let result = self.admit_inner(trace, request, publisher, mode, declared);
        self.admission_counters.record(mode, &result);
        result
    }

    fn admit_inner(
        &self,
        trace: Option<crate::wire::TraceContext>,
        request: ActionRequest,
        publisher: Publisher,
        mode: ActionMode,
        mut declared: BTreeMap<TreeId, TreeManifest>,
    ) -> Result<NativeAdmission> {
        self.reap()?;
        let fingerprint = request.action_fingerprint()?;
        match self.coordinator.admit(trace, fingerprint, mode)? {
            Admission::InFlight(producer) => Ok(NativeAdmission::InFlight { producer }),
            Admission::Cached(lease) => {
                self.recovery
                    .release_ready(request.action_fingerprint()?.key()?)?;
                request.validate_result(lease.manifest())?;
                let manifest = lease.manifest().clone();
                let ticket = self.register(
                    Kind::Action,
                    publisher,
                    Phase::Ready(Ready::Result(Arc::new(lease))),
                )?;
                Ok(NativeAdmission::Hit { ticket, manifest })
            }
            Admission::Compile(permit) => {
                let permit = if mode == ActionMode::Reuse
                    && !self.limits.peer_discovery_timeout.is_zero()
                    && let Some(manifest) = self.store().result_receipt(permit.key())?
                {
                    request.validate_result(&manifest)?;
                    self.limits.check_blobs(Kind::Action, &manifest.blobs()?)?;
                    let Some(permit) = self.recovery.offer(
                        permit,
                        manifest,
                        self.limits.max_sessions,
                        self.limits.max_manifest_cache_bytes,
                        self.limits.idle_timeout,
                    )?
                    else {
                        return Ok(NativeAdmission::InFlight { producer: None });
                    };
                    permit
                } else {
                    permit
                };
                ensure!(
                    declared.keys().all(|id| request.input_trees.contains(id)),
                    "undeclared input manifest"
                );
                let mut inputs = BTreeMap::new();
                let mut missing = BTreeSet::new();
                for &id in &request.input_trees {
                    if let Some(input) = self.input_manifest(id, declared.remove(&id))? {
                        inputs.insert(id, input);
                    } else {
                        missing.insert(id);
                    }
                }
                if !missing.is_empty() {
                    return Ok(NativeAdmission::MissingInputs { trees: missing });
                }
                let packages = inputs
                    .iter()
                    .map(|(&id, input)| (id, &input.manifest))
                    .collect();
                let composed = request.root.recipe.compose(&packages)?;
                request.root.verify(composed.id()?)?;
                self.limits.check_blobs(Kind::Tree, &composed.blobs()?)?;
                let pending = Pending::Action(Box::new(PendingAction {
                    request,
                    permit,
                    inputs,
                    inputs_staged: false,
                    demands: BTreeMap::new(),
                    unavailable: BTreeSet::new(),
                    origin: Arc::new(()),
                    upload: None,
                }));
                let ticket =
                    self.register(Kind::Action, publisher, Phase::Pending(Box::new(pending)))?;
                Ok(NativeAdmission::Compile { ticket })
            }
        }
    }

    /// Allocate one scheduler job for a pending action, or replay the
    /// original allocation after a lost response. A short-lived intent
    /// serializes assignment without holding the session lock across I/O.
    /// Duplicate requests and early worker verification receive a retryable
    /// busy result until the publisher has been installed.
    ///
    /// # Errors
    /// Returns an error if the declaration differs, the ticket is not pending,
    /// or allocation fails.
    pub fn prepare_schedule(
        &self,
        ticket: Ticket,
        request: &ActionRequest,
        requester: crate::PeerId,
        selection: DeliverySelection,
    ) -> Result<SchedulePreparation> {
        let declaration =
            crate::identity::typed_digest(b"sccache-native-allocation-declaration-v1\0", request)?;
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        if !matches!(state.phase, Phase::Publishing(_)) {
            self.touch(&mut state)?;
        }
        // Assignment starts independently of the response reaching the
        // origin. Replay survives execution, publication and failure.
        if let Some(allocation) = &state.allocation {
            ensure!(
                allocation.declaration == declaration
                    && allocation.requester == requester
                    && allocation.selection == selection,
                "allocation declaration differs from admission"
            );
            return Ok(SchedulePreparation::Replay(ScheduleReply::Assigned(
                allocation.worker.clone(),
            )));
        }
        if let Some(intent) = &state.allocating {
            ensure!(
                intent.matches(declaration, requester, &selection),
                "allocation declaration differs from admission"
            );
            return Err(NativeServiceBusy.into());
        }
        let publisher = state.publisher;
        let Phase::Pending(pending) = &state.phase else {
            bail!("native ticket is no longer pending");
        };
        let Pending::Action(action) = &**pending else {
            bail!("native ticket is not an action");
        };
        ensure!(
            &action.request == request,
            "allocation declaration differs from admission"
        );
        ensure!(
            publisher == Publisher::Client && action.upload.is_none(),
            "native action already has a publisher"
        );
        ensure!(
            selection
                .outputs
                .iter()
                .all(|name| request.required_outputs.contains_key(name)
                    || request.optional_outputs.contains_key(name)),
            "undeclared selected output"
        );
        let inputs = action.inputs.clone();
        let trees = action
            .request
            .input_trees
            .iter()
            .map(|id| {
                inputs
                    .get(id)
                    .cloned()
                    .context("missing admitted input manifest")
            })
            .collect::<Result<Vec<_>>>()?;
        let intent = Arc::new(AllocationIntent {
            declaration,
            requester,
            selection,
        });
        state.allocating = Some(Arc::clone(&intent));
        drop(state);
        let claim = AllocationClaim {
            session: Arc::clone(&session),
            intent,
        };
        let mut blobs = BTreeMap::new();
        for tree in inputs.values() {
            for (&id, &size) in &tree.blobs {
                ensure!(
                    blobs
                        .insert(id, size)
                        .is_none_or(|previous| previous == size),
                    "inconsistent input blob length"
                );
            }
        }
        Ok(SchedulePreparation::Dispatch(ScheduleReservation {
            claim,
            blobs,
            trees,
            allocation_started: Instant::now(),
            idle_timeout: self.limits.idle_timeout,
        }))
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
        if publisher == Publisher::Client && state.allocating.is_some() {
            self.touch(&mut state)
        } else if publisher == Publisher::Client
            && (matches!(state.phase, Phase::Ready(_)) || state.negotiated_result().is_some())
        {
            self.authorize_reader(&mut state, publisher)
        } else {
            self.authorize(&mut state, publisher)
        }
    }

    fn upload_slot(&self, source: UploadSource) -> Result<UploadSlot> {
        let limit = match source {
            UploadSource::Direct => self.limits.max_total_uploads,
            UploadSource::Peer => self.limits.max_total_uploads.saturating_sub(1).max(1),
        };
        let mut active = self.active_uploads.load(Ordering::Acquire);
        loop {
            if active >= limit {
                return Err(NativeServiceBusy.into());
            }
            match self.active_uploads.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(UploadSlot(
                        Arc::clone(&self.active_uploads),
                        Arc::clone(&self.peer_wake),
                    ));
                }
                Err(observed) => active = observed,
            }
        }
    }

    /// Maximum useful concurrency for independent uploads on a single
    /// session. The global admission check still applies to every upload.
    #[must_use = "use the negotiated limit to avoid excess upload requests"]
    pub const fn upload_parallelism(&self) -> usize {
        if self.limits.max_concurrent_uploads < self.limits.max_total_uploads {
            self.limits.max_concurrent_uploads
        } else {
            self.limits.max_total_uploads
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
        {
            let mut state = Self::lock(&session)?;
            self.authorize(&mut state, publisher)?;
            if let ResultNegotiation::Existing(reply) = state.result_negotiation(&manifest)? {
                return Ok(reply);
            }
            drop(state);
        }
        // Validate and reserve the closure outside the session lock. A
        // collector or filesystem lookup must never block ticket renewal.
        let blobs = manifest.blobs()?;
        self.limits.check_blobs(Kind::Action, &blobs)?;
        ensure!(
            manifest.logical_bytes()? <= self.limits.max_result_bytes,
            "native result logical byte limit exceeded"
        );
        let transfer = Transfer::new(self.store(), self.store().reserve_blobs(&blobs)?, &blobs)?;
        let mut state = Self::lock(&session)?;
        self.authorize(&mut state, publisher)?;
        // Another identical begin may already have won, or the ticket may
        // have closed while its content was being pinned.
        let reply = match state.result_negotiation(&manifest)? {
            ResultNegotiation::Existing(reply) => reply,
            ResultNegotiation::Unnegotiated(action) => {
                let missing = transfer.missing();
                action.upload = Some((manifest, transfer));
                BeginResult { missing }
            }
        };
        drop(state);
        Ok(reply)
    }

    /// Negotiate a tree upload. A previously committed tree needs no data.
    ///
    /// # Errors
    /// Returns an error for invalid manifests, limits or storage failure.
    pub fn offer_tree(&self, manifest: TreeManifest) -> Result<TreeOffer> {
        self.reap()?;
        let id = manifest.id()?;
        let blobs = manifest.blobs()?;
        self.limits.check_blobs(Kind::Tree, &blobs)?;
        let (phase, missing) = if let Some(lease) = self.store().lookup_tree(id)? {
            (
                Phase::Ready(Ready::Tree(Box::new(TreeDelivery::new(lease)))),
                Vec::new(),
            )
        } else {
            let transfer = Transfer::new(
                self.store(),
                self.store().reserve_tree_upload(&manifest)?,
                &blobs,
            )?;
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

    /// Open a tree delivery lease. Executors can only fetch a declared input of
    /// their currently delegated action.
    ///
    /// # Errors
    /// Returns an error for unauthorized, missing or invalid trees.
    pub fn open_tree(
        &self,
        id: TreeId,
        reader: Publisher,
        action_ticket: Ticket,
    ) -> Result<TreeRead> {
        self.reap()?;
        let action = self.get(action_ticket)?;
        let mut state = Self::lock(&action)?;
        self.authorize(&mut state, reader)?;
        let Phase::Pending(pending) = &state.phase else {
            bail!("native executor action no longer pending");
        };
        let Pending::Action(action) = &**pending else {
            bail!("native executor ticket is not an action");
        };
        ensure!(
            !action.inputs_staged && action.request.input_trees.contains(&id),
            "tree is not an available input of this action"
        );
        let input = Arc::clone(
            action
                .inputs
                .get(&id)
                .context("missing admitted input manifest")?,
        );
        let manifest = input.manifest.clone();
        drop(state);
        let ticket = self.register(
            Kind::Tree,
            reader,
            Phase::Ready(Ready::Tree(Box::new(TreeDelivery {
                source: TreeSource::Action {
                    ticket: action_ticket,
                    id,
                    input,
                },
                packages: BTreeMap::new(),
                requested: BTreeSet::new(),
                reservation: None,
            }))),
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
        cost: PackageTransferCost,
    ) -> Result<Vec<PackageArchive>> {
        cost.validate()?;
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
        let blobs = delivery.manifest().blobs()?;
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
            .plan_package_downloads(missing, 8, max_archive_bytes, cost)?;
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
        encoding: BlobEncoding,
        reader: impl Read,
    ) -> Result<()> {
        let mut upload = self.prepare_upload(ticket, publisher, blob, encoding)?;
        upload.stager.read_from(reader)?;
        self.finish_upload(upload)
    }

    /// Reserve a negotiated upload before reading any untrusted payload.
    ///
    /// # Errors
    /// Returns an error for unauthorized, unexpected, busy or unavailable uploads.
    pub fn prepare_upload(
        &self,
        ticket: Ticket,
        publisher: Publisher,
        blob: BlobRef,
        encoding: BlobEncoding,
    ) -> Result<NativeUpload> {
        let slot = self.upload_slot(UploadSource::Direct)?;
        let session = self.get(ticket)?;
        let budget = {
            let mut state = Self::lock(&session)?;
            self.authorize(&mut state, publisher)?;
            let Phase::Pending(pending) = &mut state.phase else {
                bail!("no active native upload");
            };
            let transfer = pending
                .transfer_mut()
                .context("no negotiated native upload")?;
            transfer.start(blob, self.limits.max_concurrent_uploads)?;
            transfer.budget.clone()
        };
        let guard = UploadGuard {
            session,
            publisher,
            blob,
            active: true,
            _slot: slot,
        };
        let stager = self
            .store()
            .prepare_physical_reserved(blob, encoding, budget)?;
        Ok(NativeUpload {
            stager,
            publication: UploadPublication::Direct(guard),
        })
    }

    /// Finish verification and attach the immutable staged file to the
    /// still-authorized transfer.
    ///
    /// # Errors
    /// Returns an error if the bytes are invalid or the lease ended.
    pub fn finish_upload(&self, upload: NativeUpload) -> Result<()> {
        let NativeUpload {
            stager,
            publication,
        } = upload;
        let guard = match publication {
            UploadPublication::Direct(guard) => guard,
            UploadPublication::Backfill {
                manifest,
                reserved: _reserved,
                guard,
            } => {
                return (|| {
                    let lease = self
                        .store()
                        .publish_tree_pinned(&manifest, vec![stager.finish()?])?;
                    guard.complete(Arc::new(lease))
                })()
                .map_err(backfill_error);
            }
        };
        self.attach_direct_upload(guard, stager.finish()?)
    }

    /// Complete a received upload without parking a blocking worker behind
    /// the CAS publication queue. The owned task holds the upload claim
    /// through the committed backfill receipt even if its caller disconnects.
    ///
    /// # Errors
    /// Returns an error for invalid content, expired transfers or storage failure.
    pub async fn finish_upload_async(self: &Arc<Self>, upload: NativeUpload) -> Result<()> {
        let sessions = Arc::clone(self);
        tokio::spawn(async move {
            let NativeUpload {
                stager,
                publication,
            } = upload;
            match publication {
                UploadPublication::Direct(guard) => {
                    tokio::task::spawn_blocking(move || {
                        sessions.attach_direct_upload(guard, stager.finish()?)
                    })
                    .await?
                }
                UploadPublication::Backfill {
                    manifest,
                    reserved,
                    guard,
                } => {
                    let result = async {
                        let staged = tokio::task::spawn_blocking(move || stager.finish()).await??;
                        let lease = sessions
                            .store()
                            .publish_tree_pinned_async(manifest, vec![staged], reserved)
                            .await?;
                        guard.complete(Arc::new(lease))
                    }
                    .await;
                    result.map_err(backfill_error)
                }
            }
        })
        .await?
    }

    fn attach_direct_upload(&self, mut guard: UploadGuard, staged: StagedBlob) -> Result<()> {
        let mut state = Self::lock(&guard.session)?;
        self.authorize(&mut state, guard.publisher)?;
        let Phase::Pending(pending) = &mut state.phase else {
            bail!("native upload cancelled");
        };
        let transfer = pending.transfer_mut().context("native upload cancelled")?;
        transfer.staged.insert(guard.blob.id, staged);
        transfer.active.remove(&guard.blob.id);
        // Disarm under the same lock; a later transfer must not lose its marker.
        guard.active = false;
        drop(state);
        drop(guard);
        Ok(())
    }

    fn begin_commit(
        &self,
        ticket: Ticket,
        publisher: Publisher,
        kind: Kind,
    ) -> Result<CommitStart> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize(&mut state, publisher)?;
        ensure!(
            state.kind == kind,
            "native ticket has wrong publication kind"
        );
        match &state.phase {
            Phase::Ready(lease) => return Ok(CommitStart::Ready(lease.committed()?)),
            Phase::Pending(pending) => pending.check_complete()?,
            _ => bail!("native session cannot commit"),
        }
        let preview = state.negotiated_result().cloned();
        let Phase::Pending(pending) =
            std::mem::replace(&mut state.phase, Phase::Publishing(preview))
        else {
            bail!("native phase changed");
        };
        drop(state);
        Ok(CommitStart::Pending { session, pending })
    }

    fn finish_commit(&self, session: &SharedSession, result: Result<Ready>) -> Result<Committed> {
        let mut state = Self::lock(session)?;
        state.expires = self.deadline();
        let reply = match result {
            Ok(lease) => {
                let reply = lease.committed();
                state.phase = Phase::Ready(lease);
                reply
            }
            Err(error) => {
                state.phase = Phase::Failed;
                Err(error)
            }
        };
        drop(state);
        reply
    }

    fn commit_pending(
        &self,
        ticket: Ticket,
        publisher: Publisher,
        kind: Kind,
    ) -> Result<Committed> {
        match self.begin_commit(ticket, publisher, kind)? {
            CommitStart::Ready(reply) => Ok(reply),
            CommitStart::Pending { session, pending } => {
                let result = pending.publish(self.store());
                self.finish_commit(&session, result)
            }
        }
    }

    async fn commit_pending_async(
        self: &Arc<Self>,
        ticket: Ticket,
        publisher: Publisher,
        kind: Kind,
    ) -> Result<Committed> {
        let sessions = Arc::clone(self);
        // Keep the session transition alive independently of a disconnected
        // response waiter. A queued publication must never strand Publishing.
        tokio::spawn(async move {
            match sessions.begin_commit(ticket, publisher, kind)? {
                CommitStart::Ready(reply) => Ok(reply),
                CommitStart::Pending { session, pending } => {
                    let result = pending.publish_async(sessions.store()).await;
                    sessions.finish_commit(&session, result)
                }
            }
        })
        .await?
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

    /// Commit a negotiated result through the asynchronous CAS queue.
    ///
    /// # Errors
    /// Returns an error for invalid tickets, incomplete uploads or storage failure.
    pub async fn commit_async(
        self: &Arc<Self>,
        ticket: Ticket,
        publisher: Publisher,
    ) -> Result<ResultManifest> {
        match self
            .commit_pending_async(ticket, publisher, Kind::Action)
            .await?
        {
            Committed::Result(manifest) => Ok(manifest),
            Committed::Tree(_) => bail!("native result publication returned a tree"),
        }
    }

    /// Commit a negotiated tree through the asynchronous CAS queue.
    ///
    /// # Errors
    /// Returns an error for invalid tickets, incomplete uploads or storage failure.
    pub async fn commit_tree_async(self: &Arc<Self>, ticket: Ticket) -> Result<TreeId> {
        match self
            .commit_pending_async(ticket, Publisher::Client, Kind::Tree)
            .await?
        {
            Committed::Tree(id) => Ok(id),
            Committed::Result(_) => bail!("native tree publication returned a result"),
        }
    }

    /// Observe the result of a client-owned action ticket.
    ///
    /// # Errors
    /// Returns an error for unknown or expired tickets.
    pub fn status(&self, ticket: Ticket) -> Result<NativeStatus> {
        self.status_with_preview(ticket, false)
    }

    /// Request a provisional result manifest once the producing worker has
    /// negotiated it. Ordinary status polling does not resend this metadata.
    ///
    /// # Errors
    /// Returns an error for unknown or expired tickets.
    pub fn status_with_preview(&self, ticket: Ticket, preview: bool) -> Result<NativeStatus> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        ensure!(state.kind == Kind::Action, "native ticket is not an action");
        if matches!(state.phase, Phase::Ready(_) | Phase::Failed) {
            self.touch(&mut state)?;
        } else if !matches!(state.phase, Phase::Publishing(_)) {
            ensure!(
                state.allocating.is_some() || state.expires > Instant::now(),
                "native ticket expired"
            );
        }
        Ok(match &state.phase {
            Phase::Pending(_) | Phase::Publishing(_) if preview => state
                .negotiated_result()
                .map_or(NativeStatus::Compiling, |manifest| {
                    NativeStatus::Negotiated(manifest.clone())
                }),
            Phase::Pending(_) | Phase::Publishing(_) => NativeStatus::Compiling,
            Phase::Ready(Ready::Result(lease)) => NativeStatus::Ready(lease.manifest().clone()),
            Phase::Ready(Ready::Tree(_)) => bail!("native action has a tree result"),
            Phase::Failed => NativeStatus::Failed,
        })
    }

    /// Authorize exact content delivery under a live result or input-tree
    /// lease. Return the known producer and current scheduler residency.
    ///
    /// # Errors
    /// Returns an error for expired tickets, invalid leases or undeclared content.
    pub fn authorize_blob_sources(
        &self,
        ticket: Ticket,
        reader: Publisher,
        blobs: &[BlobRef],
    ) -> Result<(Option<crate::PeerId>, Vec<bool>)> {
        ensure!(
            !blobs.is_empty() && blobs.len() <= crate::wire::MAX_SOURCE_BATCH,
            "invalid content source batch"
        );
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize_reader(&mut state, reader)?;
        let declared = |manifest: &BTreeMap<ContentId, u64>| {
            blobs
                .iter()
                .all(|blob| manifest.get(&blob.id) == Some(&blob.size))
        };
        let producer = state
            .allocation
            .as_ref()
            .map(|allocation| allocation.worker.peer);
        let (producer, pinned) = match &state.phase {
            Phase::Ready(Ready::Result(lease)) => {
                ensure!(declared(lease.blobs()), "undeclared result source");
                (producer, true)
            }
            Phase::Ready(Ready::Tree(delivery)) => match &delivery.source {
                TreeSource::Stored(tree) => {
                    ensure!(declared(tree.blobs()), "undeclared tree source");
                    (None, true)
                }
                TreeSource::Action { input, .. } => {
                    ensure!(declared(&input.blobs), "undeclared input source");
                    (None, false)
                }
            },
            _ => {
                let preview = state
                    .negotiated_result()
                    .context("native delivery not ready")?;
                ensure!(
                    declared(&preview.blobs()?),
                    "undeclared negotiated result source"
                );
                (producer, false)
            }
        };
        drop(state);
        let availability = if pinned {
            vec![true; blobs.len()]
        } else {
            self.store().available_blobs(blobs)?
        };
        Ok((producer, availability))
    }

    /// Open declared content for transport. Generated raw ZFS files are
    /// temporarily encoded for efficient wire transfer; original package
    /// archives are returned byte-for-byte.
    ///
    /// # Errors
    /// Returns an error for unknown tickets, unavailable or undeclared content.
    pub fn download(
        &self,
        ticket: Ticket,
        reader: Publisher,
        id: ContentId,
    ) -> Result<NativeDownload> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize_reader(&mut state, reader)?;
        // A negotiated result may already share content with the durable CAS.
        if let Some(manifest) = state.negotiated_result() {
            let size = *manifest
                .blobs()?
                .get(&id)
                .context("undeclared negotiated result blob")?;
            drop(state);
            let physical = self
                .store()
                .open_available_physical(BlobRef { id, size })?
                .ok_or(NativeContentPending)?;
            return Ok(NativeDownload::blob(physical, size));
        }
        let Phase::Ready(lease) = &mut state.phase else {
            bail!("native content not available");
        };
        let download = match lease {
            Ready::Result(lease) => NativeDownload::blob(
                (lease.open_file(id)?, lease.physical_encoding(id)?),
                lease.blob_size(id)?,
            ),
            Ready::Tree(delivery) => {
                if let Some(package) = delivery.packages.get(&id) {
                    return Ok(NativeDownload {
                        file: package.open_file()?,
                        encoding: BlobEncoding::Raw,
                        logical_size: package.archive().blob.size,
                        original_archive: true,
                    });
                }
                match &delivery.source {
                    TreeSource::Stored(tree) => NativeDownload::blob(
                        (tree.open_file(id)?, tree.physical_encoding(id)?),
                        *tree.blobs().get(&id).context("undeclared tree content")?,
                    ),
                    TreeSource::Action {
                        ticket,
                        id: tree,
                        input,
                    } => {
                        let size = *input.blobs.get(&id).context("undeclared input blob")?;
                        let tree = *tree;
                        let action = *ticket;
                        let blob = BlobRef { id, size };
                        if let Some(file) = self.store().open_available_physical(blob)? {
                            let requested = delivery.requested.remove(&id);
                            drop(state);
                            if requested {
                                self.finish_backfills(action, reader, [id])?;
                            }
                            return Ok(NativeDownload::blob(file, size));
                        }
                        delivery.requested.insert(id);
                        drop(state);
                        self.request_backfills(action, reader, tree, &[blob])?;
                        return Err(NativeContentPending.into());
                    }
                }
            }
        };
        drop(state);
        Ok(download)
    }

    /// Prefetch only the blobs the worker actually lacks. Protect those
    /// already present on the scheduler and request the rest from the origin.
    ///
    /// # Errors
    /// Returns an error for unauthorized or undeclared inputs or storage failure.
    pub fn request_inputs(
        &self,
        ticket: Ticket,
        reader: Publisher,
        missing: Vec<BlobRef>,
    ) -> Result<()> {
        let session = self.get(ticket)?;
        let (action, tree, input) = {
            let mut state = Self::lock(&session)?;
            self.authorize_reader(&mut state, reader)?;
            let Phase::Ready(Ready::Tree(delivery)) = &state.phase else {
                bail!("input prefetch requires a tree delivery");
            };
            let TreeSource::Action {
                ticket: action,
                id: tree,
                input,
            } = &delivery.source
            else {
                bail!("input prefetch requires an assigned action");
            };
            let target = (*action, *tree, Arc::clone(input));
            drop(state);
            target
        };
        let mut blobs = BTreeMap::new();
        for blob in missing {
            ensure!(
                input.blobs.get(&blob.id) == Some(&blob.size)
                    && blobs.insert(blob.id, blob.size).is_none(),
                "undeclared or duplicate input prefetch"
            );
        }
        // Physical validation and pending-content reservation may wait for
        // storage/GC. Lease renewal and close must not wait behind either.
        let reservation = self.store().reserve_blobs(&blobs)?;
        let absent = reservation.missing().to_vec();
        {
            let mut state = Self::lock(&session)?;
            self.authorize_reader(&mut state, reader)?;
            let Phase::Ready(Ready::Tree(delivery)) = &mut state.phase else {
                bail!("input delivery closed during prefetch");
            };
            ensure!(
                matches!(&delivery.source, TreeSource::Action { ticket, id, .. } if *ticket == action && *id == tree),
                "input delivery changed during prefetch"
            );
            delivery.requested.extend(absent.iter().map(|blob| blob.id));
            if let Some(existing) = &mut delivery.reservation {
                existing.merge_pins(reservation)?;
            } else {
                delivery.reservation = Some(reservation);
            }
            drop(state);
        }
        self.request_backfills(action, reader, tree, &absent)
    }

    fn request_backfills(
        &self,
        ticket: Ticket,
        reader: Publisher,
        tree: TreeId,
        blobs: &[BlobRef],
    ) -> Result<()> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize(&mut state, reader)?;
        let Phase::Pending(pending) = &mut state.phase else {
            bail!("native action no longer pending");
        };
        let Pending::Action(action) = &mut **pending else {
            bail!("native action required");
        };
        ensure!(
            !action.inputs_staged,
            "native input staging already finished"
        );
        let input = action.inputs.get(&tree).context("undeclared input tree")?;
        let Publisher::Worker {
            peer: requester, ..
        } = reader
        else {
            bail!("backfill requires a worker");
        };
        let mut flights = self
            .backfills
            .lock()
            .map_err(|_| anyhow!("native backfill map poisoned"))?;
        for &blob in blobs {
            ensure!(
                input.blobs.get(&blob.id) == Some(&blob.size),
                "undeclared input blob"
            );
            let flight = if let Some(flight) = flights.get(&blob.id).and_then(Weak::upgrade) {
                ensure!(flight.blob == blob, "conflicting requested blob length");
                flight
            } else {
                let flight = Arc::new(Backfill {
                    blob,
                    requester,
                    state: Mutex::new(BackfillState {
                        peer_until: (!self.limits.peer_discovery_timeout.is_zero())
                            .then(|| Instant::now() + self.limits.peer_discovery_timeout),
                        ..BackfillState::default()
                    }),
                });
                flights.insert(blob.id, Arc::downgrade(&flight));
                flight
            };
            {
                let mut pending = flight.lock()?;
                if pending.ready.is_some() && self.store().open_available_blob(blob)?.is_none() {
                    pending.ready = None;
                    if !self.limits.peer_discovery_timeout.is_zero() {
                        pending.peer_until =
                            Some(Instant::now() + self.limits.peer_discovery_timeout);
                    }
                }
            }
            action.demands.entry(blob.id).or_insert((tree, flight));
        }
        drop(flights);
        drop(state);
        self.peer_wake.notify_waiters();
        Ok(())
    }

    /// Claim one missing blob for a peer-source lookup. A short discovery window
    /// prevents a busy peer service from delaying the original submitter.
    ///
    /// # Errors
    /// Returns an error for poisoned state or a resource accounting failure.
    pub async fn claim_peer_input(&self, wait: Duration) -> Result<Option<PeerInputClaim>> {
        let deadline = Instant::now() + wait;
        loop {
            let mut notified = std::pin::pin!(self.peer_wake.notified());
            notified.as_mut().enable();
            if let Some(claim) = self.try_claim_peer_input()? {
                return Ok(Some(claim));
            }
            if Instant::now() >= deadline
                || tokio::time::timeout_at(deadline.into(), notified)
                    .await
                    .is_err()
            {
                return Ok(None);
            }
        }
    }

    fn try_claim_peer_input(&self) -> Result<Option<PeerInputClaim>> {
        let flights = self
            .backfills
            .lock()
            .map_err(|_| anyhow!("native backfill map poisoned"))?;
        let now = Instant::now();
        for flight in flights.values().filter_map(Weak::upgrade) {
            let Ok(mut pending) = flight.state.try_lock() else {
                continue;
            };
            if pending.uploading || pending.ready.is_some() || pending.claim.is_some() {
                continue;
            }
            if pending.peer_retry_at.is_some_and(|at| at <= now) {
                pending.peer_until = Some(now + self.limits.peer_discovery_timeout);
                pending.peer_retry_at = Some(now + Duration::from_secs(1));
            }
            let Some(until) = pending.peer_until else {
                continue;
            };
            if until <= now {
                pending.peer_until = None;
                continue;
            }
            pending.peer_until = None;
            pending.uploading = true;
            drop(pending);
            return Ok(Some(PeerInputClaim(BackfillUpload {
                flight,
                _slot: None,
            })));
        }
        drop(flights);
        Ok(None)
    }

    /// Recover verified peer content using the same durable blob acquisition
    /// flight as result recovery. The owned task holds the input and upload
    /// claims through publication even if its caller stops awaiting it.
    ///
    /// # Errors
    /// Returns an error for unavailable or invalid content or storage failure.
    pub async fn recover_peer_input<F, Fut>(
        self: &Arc<Self>,
        claim: PeerInputClaim,
        deadline: Instant,
        fetch: F,
    ) -> Result<()>
    where
        F: Fn(BlobRef, NativeStore, Instant) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<StagedBlob>>> + Send + 'static,
    {
        let sessions = Arc::clone(self);
        tokio::spawn(async move {
            let lease = sessions
                .acquire_peer_blob(claim.blob(), deadline, false, &fetch)
                .await?;
            claim.0.complete(lease)
        })
        .await?
    }

    fn finish_backfills(
        &self,
        ticket: Ticket,
        reader: Publisher,
        ids: impl IntoIterator<Item = ContentId>,
    ) -> Result<()> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize(&mut state, reader)?;
        let Phase::Pending(pending) = &mut state.phase else {
            bail!("native action no longer pending");
        };
        let Pending::Action(action) = &mut **pending else {
            bail!("native action required");
        };
        // An origin may already have received a claim while another
        // publication makes this blob available. Let the claimed stream
        // finish rather than rejecting valid bytes mid-transfer.
        for id in ids {
            if let Some((_, flight)) = action.demands.get(&id) {
                let pending = flight.lock()?;
                let finished = pending.claim.is_none() && !pending.uploading;
                drop(pending);
                if finished {
                    action.demands.remove(&id);
                }
            }
        }
        drop(state);
        Ok(())
    }

    /// The executor has pinned all input trees and no longer needs origin
    /// transfers. Release unconsumed claims before entering the CPU queue.
    ///
    /// # Errors
    /// Returns an error for an invalid or unauthorized action ticket.
    pub fn inputs_staged(&self, ticket: Ticket, publisher: Publisher) -> Result<()> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize(&mut state, publisher)?;
        let Phase::Pending(pending) = &mut state.phase else {
            bail!("native action no longer pending");
        };
        let Pending::Action(action) = &mut **pending else {
            bail!("native action required");
        };
        if !action.inputs_staged {
            // A flight can remain live through another action even when
            // this action no longer needs it. Release only our own claim.
            for (_, flight) in action.demands.values() {
                let mut pending = flight.lock()?;
                if pending
                    .claim
                    .as_ref()
                    .is_some_and(|claim| claim.ticket == ticket)
                {
                    pending.claim = None;
                }
            }
            action.demands.clear();
            action.unavailable.clear();
            action.inputs_staged = true;
        }
        drop(state);
        Ok(())
    }

    /// Poll missing inputs requested by the assigned worker. Claims are shared
    /// by content identity across actions and expire if their source disappears.
    ///
    /// # Errors
    /// Returns an error for an invalid or expired action ticket.
    pub fn poll_input(&self, ticket: Ticket) -> Result<InputPoll> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize_reader(&mut state, Publisher::Client)?;
        let Phase::Pending(pending) = &state.phase else {
            return Ok(InputPoll::Complete);
        };
        let Pending::Action(action) = &**pending else {
            bail!("native action required");
        };
        if action.inputs_staged {
            return Ok(InputPoll::Complete);
        }
        let now = Instant::now();
        // A lost poll reply is replayable. Each origin has one demand at a
        // time, but the claim itself does not reserve a transfer slot.
        let mut candidate = None;
        for (tree, flight) in action.demands.values() {
            if action.unavailable.contains(&(*tree, flight.blob.id)) {
                continue;
            }
            let mut pending = flight.lock()?;
            if pending.claim.as_ref().is_some_and(|claim| !claim.live(now)) {
                pending.claim = None;
            }
            if pending.uploading
                || pending.ready.is_some()
                || pending.peer_until.is_some_and(|until| until > now)
            {
                continue;
            }
            pending.peer_until = None;
            if let Some(claim) = &mut pending.claim {
                if claim.ticket == ticket {
                    claim.expires = self.deadline();
                    return Ok(InputPoll::Demand(InputDemand {
                        tree: *tree,
                        blob: flight.blob,
                    }));
                }
            } else if candidate.is_none() {
                candidate = Some((*tree, flight));
            }
        }
        if let Some((tree, flight)) = candidate {
            let mut pending = flight.lock()?;
            if !pending.uploading
                && pending.ready.is_none()
                && pending.claim.is_none()
                && pending.peer_until.is_none_or(|until| until <= now)
            {
                pending.claim = Some(BackfillClaim {
                    ticket,
                    expires: self.deadline(),
                    origin: Arc::downgrade(&action.origin),
                });
                return Ok(InputPoll::Demand(InputDemand {
                    tree,
                    blob: flight.blob,
                }));
            }
            drop(pending);
        }
        drop(state);
        Ok(InputPoll::Waiting)
    }

    /// Release a claim when the original file cannot be reopened. Other
    /// declared source trees, live origins and peers may still satisfy it.
    ///
    /// # Errors
    /// Returns an error for an invalid ticket or unclaimed input.
    pub fn input_unavailable(&self, ticket: Ticket, demand: InputDemand) -> Result<()> {
        let InputDemand {
            tree: declined,
            blob,
        } = demand;
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize_reader(&mut state, Publisher::Client)?;
        let Phase::Pending(pending) = &mut state.phase else {
            return Ok(());
        };
        let Pending::Action(action) = &mut **pending else {
            bail!("native action required");
        };
        ensure!(
            action
                .inputs
                .get(&declined)
                .is_some_and(|input| input.blobs.get(&blob.id) == Some(&blob.size)),
            "undeclared unavailable input"
        );
        // Replayed declines must not consume the claim for an alternate
        // source tree or a different origin.
        if action.unavailable.contains(&(declined, blob.id)) {
            return Ok(());
        }
        let Some((tree, flight)) = action.demands.get_mut(&blob.id) else {
            // The worker can finish a download before the decline arrives.
            return Ok(());
        };
        ensure!(
            *tree == declined && flight.blob == blob,
            "unavailable input differs from demand"
        );
        let mut pending = flight.lock()?;
        // An expired claim may already belong to another origin. Do not
        // disturb it; this notification applies only to our source.
        if pending
            .claim
            .as_ref()
            .is_some_and(|claim| claim.ticket == ticket)
        {
            pending.claim = None;
        }
        action.unavailable.insert((declined, blob.id));
        if let Some((&alternate, _)) = action.inputs.iter().find(|(id, input)| {
            input.blobs.get(&blob.id) == Some(&blob.size)
                && !action.unavailable.contains(&(**id, blob.id))
        }) {
            *tree = alternate;
        } else if !self.limits.peer_discovery_timeout.is_zero() && pending.ready.is_none() {
            let now = Instant::now();
            pending.peer_until = Some(now + self.limits.peer_discovery_timeout);
            pending.peer_retry_at = Some(now + Duration::from_secs(1));
        }
        drop(pending);
        drop(state);
        self.peer_wake.notify_waiters();
        Ok(())
    }

    /// Backfill exactly one demanded input from its claimed origin.
    ///
    /// # Errors
    /// Returns an error for an unauthorized, unrequested or invalid stream.
    pub fn backfill_input(&self, ticket: Ticket, blob: BlobRef, reader: impl Read) -> Result<()> {
        let mut upload = self.prepare_backfill(ticket, blob)?;
        let result = upload.stager.read_from(reader);
        upload.classify(result)?;
        self.finish_upload(upload)
    }

    /// Claim one requested input and reserve its in-place verification state.
    ///
    /// # Errors
    /// Returns an error for an unauthorized, unrequested or busy transfer.
    pub fn prepare_backfill(&self, ticket: Ticket, blob: BlobRef) -> Result<NativeUpload> {
        let session = self.get(ticket)?;
        let guard = {
            let mut state = Self::lock(&session)?;
            self.authorize_reader(&mut state, Publisher::Client)?;
            let Phase::Pending(pending) = &state.phase else {
                bail!("native action no longer pending");
            };
            let Pending::Action(action) = &**pending else {
                bail!("native action required");
            };
            let (_, flight) = action
                .demands
                .get(&blob.id)
                .context("unrequested input upload")?;
            ensure!(flight.blob == blob, "input upload length mismatch");
            let mut pending = flight.lock()?;
            ensure!(
                !pending.uploading
                    && pending.ready.is_none()
                    && pending
                        .claim
                        .as_ref()
                        .is_some_and(|claim| claim.ticket == ticket && claim.live(Instant::now())),
                "input upload not claimed"
            );
            // Admission begins when a body is actually about to be received.
            // A busy receiver leaves the claim intact for a retry.
            let slot = self.upload_slot(UploadSource::Direct)?;
            pending.claim = None;
            pending.uploading = true;
            let upload = BackfillUpload {
                flight: Arc::clone(flight),
                _slot: Some(slot),
            };
            drop(pending);
            drop(state);
            upload
        };
        (|| {
            let manifest = NativeStore::blob_retention_manifest(blob)?;
            let reserved = self.store().reserve_tree_upload(&manifest)?;
            // Still verify the stream if concurrent publication supplied it.
            let stager = self.store().prepare_physical(blob, BlobEncoding::Raw)?;
            Ok(NativeUpload {
                stager,
                publication: UploadPublication::Backfill {
                    manifest,
                    reserved,
                    guard,
                },
            })
        })()
        .map_err(backfill_error)
    }

    /// Record the receiver's successful staging receipt once, while the
    /// result lease still proves both publication and allocation ownership.
    ///
    /// # Errors
    /// Returns an error for an expired/uncommitted ticket, another requester,
    /// or counts exceeding the verified manifest.
    pub fn record_client_delivery(
        &self,
        ticket: Ticket,
        requester: crate::PeerId,
        observation: ClientDeliveryObservation,
    ) -> Result<Option<DeliveryReceipt>> {
        let session = self.get(ticket)?;
        let mut state = Self::lock(&session)?;
        self.authorize_reader(&mut state, Publisher::Client)?;
        let Phase::Ready(Ready::Result(lease)) = &state.phase else {
            bail!("native delivery is not committed");
        };
        let Some(allocation) = state.allocation.as_ref() else {
            return Ok(None);
        };
        ensure!(
            requester == allocation.requester,
            "native delivery requester differs from allocation"
        );
        let selected = lease
            .manifest()
            .selected_blobs(&allocation.selection.outputs)?;
        let selected_size = selected
            .values()
            .copied()
            .try_fold(0_u64, u64::checked_add)
            .context("selected size overflow")?;
        let declared = lease.manifest().blobs()?;
        let size = declared
            .values()
            .copied()
            .try_fold(0_u64, u64::checked_add)
            .context("result size overflow")?;
        let bytes = observation
            .direct_bytes
            .checked_add(observation.scheduler_bytes)
            .context("delivery size overflow")?;
        ensure!(
            bytes <= observation.selected_bytes
                && observation.selected_bytes == selected_size
                && observation.unique_blobs <= u64::try_from(selected.len())?
                && (observation.unique_blobs != 0 || bytes == 0),
            "delivery exceeds result manifest"
        );
        let Some(allocation) = state.allocation.as_mut() else {
            return Ok(None);
        };
        if allocation.delivery_reported {
            return Ok(None);
        }
        let elapsed = allocation.allocation_started.elapsed();
        ensure!(
            Duration::from_nanos(observation.staging_nanoseconds)
                <= elapsed.saturating_add(Duration::from_secs(1)),
            "invalid delivery duration"
        );
        allocation.delivery_reported = true;
        let receipt = DeliveryReceipt {
            worker: allocation.worker.peer,
            job: allocation.worker.job,
            requester,
            profile: allocation.selection.profile,
            result_bytes: size,
            elapsed,
            observation,
        };
        drop(state);
        Ok(Some(receipt))
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
                !matches!(state.phase, Phase::Publishing(_)),
                "native publication in progress"
            );
            state.expires = Instant::now();
            state.allocating = None;
            std::mem::replace(&mut state.phase, Phase::Failed)
        };
        let removed = self.sessions()?.remove(&ticket);
        drop(removed);
        if let Phase::Ready(Ready::Tree(delivery)) = &previous
            && let TreeSource::Action { ticket: action, .. } = &delivery.source
            && !delivery.requested.is_empty()
        {
            // A different local tree acquisition may have supplied some
            // prefetched bytes. Stop requesting unclaimed leftovers.
            let _ = self.finish_backfills(*action, reader, delivery.requested.iter().copied());
        }
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

#[derive(Clone, Copy)]
enum UploadSource {
    Direct,
    Peer,
}

struct UploadSlot(Arc<AtomicUsize>, Arc<tokio::sync::Notify>);

impl Drop for UploadSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
        self.1.notify_waiters();
    }
}

mod live;
mod recovery;
mod retention;
mod telemetry;
pub use telemetry::{AdmissionStats, ManifestStatus, RecoveryStatus, SessionStatus, TicketStatus};

#[cfg(test)]
mod tests;

/// Open, authorized physical content. Transport chooses wire encoding without
/// rewriting the complete object or scanning its compressed frame index.
#[derive(Debug)]
pub struct NativeDownload {
    pub file: File,
    pub encoding: BlobEncoding,
    pub logical_size: u64,
    pub original_archive: bool,
}

impl NativeDownload {
    fn blob((file, encoding): (File, BlobEncoding), logical_size: u64) -> Self {
        Self {
            file,
            encoding,
            logical_size,
            original_archive: false,
        }
    }
}
