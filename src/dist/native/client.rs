//! Native action admission, missing-input negotiation and verified delivery.
//! The compiler frontend owns discovery; this layer needs no client cache.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Seek, Take, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::{ExitStatus, Output},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use tempfile::NamedTempFile;

use super::{NativeCacheClient, copy_verified, retryable_transport_error};
use crate::build_runtime::{
    ActionMode, Artifact, BlobRef, ContentId, ExecutionSpec, MaterializedTree, PreparedTree,
    ResultManifest, TreeId, TreeManifest, materialize_tree,
    wire::{
        ClientDeliveryObservation, InputDemand, InputPoll, NativeAdmission, NativeRunResult,
        NativeStatus, ScheduleReply, Ticket, WorkerAllocation,
    },
};

/// Explicit client admission and delivery bounds.
pub struct NativeBuildPolicy {
    pub mode: ActionMode,
    pub timeout: Duration,
    pub renewal_interval: Duration,
    pub max_result_bytes: u64,
}

use crate::server::activity::{self, Phase};
use crate::{latency_trace::TraceContext, protocol::NativeBuildSource};

/// Native compiler response after all declared results have been delivered.
pub struct NativeBuildResult {
    pub source: NativeBuildSource,
    pub output: Output,
    pub manifest: Option<ResultManifest>,
}

/// An input reader that can be abandoned on a direct upload, or drained
/// exactly to its frame boundary when the caller supplied it over IPC.
#[derive(Clone)]
pub(super) struct InputBlob {
    reader: Arc<Mutex<Take<Box<dyn Read + Send>>>>,
    framed: bool,
}

impl InputBlob {
    pub(super) fn new(reader: Box<dyn Read + Send>, size: u64, framed: bool) -> Self {
        Self {
            reader: Arc::new(Mutex::new(reader.take(size))),
            framed,
        }
    }

    fn discard_unread(&self) -> Result<()> {
        if self.framed {
            let mut reader = self
                .reader
                .lock()
                .map_err(|_| anyhow::anyhow!("native input reader poisoned"))?;
            io::copy(&mut *reader, &mut io::sink())?;
            ensure!(reader.limit() == 0, "truncated native IPC input frame");
            drop(reader);
        }
        Ok(())
    }
}

impl Read for InputBlob {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader
            .lock()
            .map_err(|_| io::Error::other("native input reader poisoned"))?
            .read(buffer)
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub(super) enum NativeProgress {
    Phase(Phase),
    WaitForProducer(Option<TraceContext>),
    Assigned {
        job: u64,
        worker: crate::build_runtime::PeerId,
    },
}

impl NativeProgress {
    pub(super) fn apply(self) {
        match self {
            Self::Phase(phase) => activity::phase(phase),
            Self::WaitForProducer(producer) => activity::wait_for_producer(producer),
            Self::Assigned { job, worker } => {
                activity::job(job, worker.to_string());
                activity::phase(Phase::StageInputs);
            }
        }
    }
}

pub(super) trait InputProvider {
    fn trace_context(&self) -> Option<TraceContext> {
        activity::trace_context()
    }

    fn progress(&mut self, progress: NativeProgress) -> Result<()> {
        progress.apply();
        Ok(())
    }
    fn manifest(&mut self, tree: TreeId) -> Result<TreeManifest>;
    fn open_blob(&mut self, tree: TreeId, blob: BlobRef) -> Result<Option<InputBlob>>;
}

pub(super) struct LocalInputs<'a>(BTreeMap<TreeId, &'a PreparedTree>);

impl<'a> LocalInputs<'a> {
    pub(super) fn new(spec: &ExecutionSpec, inputs: &'a [PreparedTree]) -> Result<Self> {
        let inputs = inputs
            .iter()
            .map(|tree| (tree.id(), tree))
            .collect::<BTreeMap<_, _>>();
        ensure!(
            inputs.keys().copied().collect::<BTreeSet<_>>() == spec.action_request()?.input_trees,
            "prepared native inputs differ from the action declaration"
        );
        Ok(Self(inputs))
    }

    fn matching_sources(&self, id: ContentId) -> impl Iterator<Item = Box<dyn Read + Send>> + '_ {
        self.0
            .values()
            .filter_map(move |tree| tree.open_local_blob(id).ok())
    }

    pub(super) fn tree(&self, id: TreeId) -> Result<&PreparedTree> {
        self.0
            .get(&id)
            .copied()
            .context("scheduler requested undeclared input tree")
    }

    pub(super) fn open_source(
        &self,
        tree: TreeId,
        blob: BlobRef,
    ) -> Result<Option<Box<dyn Read + Send>>> {
        match self.tree(tree)?.open_blob(blob.id) {
            Ok(reader) => Ok(Some(reader)),
            Err(error) => {
                debug!("native origin cannot supply {blob:?}: {error:#}");
                Ok(None)
            }
        }
    }
}

impl InputProvider for LocalInputs<'_> {
    fn manifest(&mut self, tree: TreeId) -> Result<TreeManifest> {
        Ok(self.tree(tree)?.manifest().clone())
    }

    fn open_blob(&mut self, tree: TreeId, blob: BlobRef) -> Result<Option<InputBlob>> {
        Ok(self
            .open_source(tree, blob)?
            .map(|reader| InputBlob::new(reader, blob.size, false)))
    }
}

enum StagedOutput {
    File(NamedTempFile),
    Tree(MaterializedTree),
}

impl StagedOutput {
    fn publish(self, path: &Path) -> Result<()> {
        match self {
            Self::File(file) => {
                file.persist(path)?;
            }
            Self::Tree(tree) => tree.publish(path)?,
        }
        Ok(())
    }
}

pub(super) struct Pin<'a> {
    client: &'a NativeCacheClient,
    pub(super) ticket: Ticket,
    trace: Option<TraceContext>,
    assigned: bool,
    selected: BTreeSet<String>,
    delivery: Option<ClientDeliveryObservation>,
}

impl Drop for Pin<'_> {
    fn drop(&mut self) {
        let result = self.delivery.map_or_else(
            || self.client.close(self.ticket),
            |observation| self.client.close_delivered(self.ticket, observation),
        );
        if let Err(error) = result {
            debug!("native session could not be closed: {error:#}");
        }
    }
}

/// An action is either ready for verified delivery under a live result
/// lease, or returned compiler failure diagnostics without a cache entry.
pub(super) enum Outcome<'a> {
    Ready {
        delivery: Box<Delivery<'a>>,
        source: NativeBuildSource,
        manifest: ResultManifest,
    },
    Failed {
        source: NativeBuildSource,
        failure: NativeRunResult,
    },
}

/// A destination that is either private staging (safe to reset after a
/// failed verification) or an irreversible framed IPC stream.
pub(super) enum BlobSink<'a> {
    File(&'a mut fs::File),
    Memory(&'a mut Vec<u8>),
    Stream(&'a mut dyn Write),
}

impl BlobSink<'_> {
    pub(super) fn reborrow(&mut self) -> BlobSink<'_> {
        match self {
            Self::File(file) => BlobSink::File(file),
            Self::Memory(bytes) => BlobSink::Memory(bytes),
            Self::Stream(stream) => BlobSink::Stream(&mut **stream),
        }
    }

    pub(super) fn reset(&mut self) -> Result<()> {
        match self {
            Self::File(file) => {
                file.set_len(0)?;
                file.rewind()?;
            }
            Self::Memory(bytes) => bytes.clear(),
            Self::Stream(_) => bail!("cannot rewind a result stream"),
        }
        Ok(())
    }
}

impl Write for BlobSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.write(bytes),
            Self::Memory(buffer) => buffer.write(bytes),
            Self::Stream(stream) => stream.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::File(file) => file.flush(),
            Self::Memory(buffer) => buffer.flush(),
            Self::Stream(stream) => stream.flush(),
        }
    }
}

type BlobDownload<'a> = dyn FnMut(BlobRef, &mut BlobSink<'_>) -> Result<()> + 'a;

pub(super) struct Delivery<'a> {
    pin: Pin<'a>,
    publication: Option<Box<Publication>>,
}

pub(super) struct Publication {
    allocation: WorkerAllocation,
    manifest: ResultManifest,
    deadline: Instant,
    max_result_bytes: u64,
}

impl Publication {
    fn confirm(&self, pin: &Pin<'_>) -> Result<()> {
        let manifest = pin.client.await_result_commit(pin.ticket, self.deadline)?;
        ensure!(
            manifest == self.manifest,
            "native committed result differs from negotiation"
        );
        // Durable publication is authoritative. Acknowledge promptly to
        // release the worker reservation, but do not wait for a lost RPC.
        let remaining = self
            .deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(250));
        if !remaining.is_zero() {
            let _ = pin
                .client
                .run_worker(&self.allocation, remaining, self.max_result_bytes);
        }
        Ok(())
    }
}

impl Delivery<'_> {
    pub(super) fn retain(
        &mut self,
        session: &super::result_session::NativeResultSession,
        manifest: &ResultManifest,
        interval: Duration,
    ) -> Result<()> {
        let Self { pin, publication } = self;
        pin.client.with_renewal(pin.ticket, interval, |check| {
            check()?;
            if let Some(pending) = publication.take() {
                pending.confirm(pin)?;
            }
            session.retain(pin.ticket, manifest)
        })
    }

    pub(super) fn with_download<T>(
        &mut self,
        renewal_interval: Duration,
        declared: &BTreeMap<crate::build_runtime::ContentId, u64>,
        operation: impl FnOnce(&mut BlobDownload<'_>) -> Result<T>,
    ) -> Result<T> {
        let Self { pin, publication } = self;
        let started = Instant::now();
        let (value, observation) =
            pin.client
                .with_renewal(pin.ticket, renewal_interval, |check| {
                    let mut delivery = super::peer_delivery::ResultDelivery::new(
                        pin.client,
                        pin.ticket,
                        declared,
                        publication.as_ref().map(|pending| pending.deadline),
                    );
                    let result = operation(&mut |blob, output| {
                        check()?;
                        delivery.download(blob, output)
                    })?;
                    check()?;
                    if let Some(publication) = publication {
                        publication.confirm(pin)?;
                    }
                    Ok((result, delivery.observation(started.elapsed())))
                })?;
        *publication = None;
        if pin.assigned {
            pin.delivery = Some(observation);
        }
        Ok(value)
    }
}

impl NativeCacheClient {
    /// Admit an exact native action, supply only absent inputs, and execute
    /// on a scheduler-assigned worker when needed. Results use the fastest
    /// authorized verified source.
    /// The caller may select any subset of declared outputs (including none).
    /// All outputs are still captured and validated under the same action key.
    /// No result is repackaged into the legacy cache.
    ///
    /// # Errors
    /// Returns an error for incomplete inputs, invalid destinations, admission,
    /// scheduling, transfer or output installation failures.
    pub fn run_action(
        &self,
        spec: &ExecutionSpec,
        inputs: &[PreparedTree],
        destinations: &BTreeMap<String, PathBuf>,
        policy: &NativeBuildPolicy,
    ) -> Result<NativeBuildResult> {
        self.run_action_inner(spec, inputs, destinations, policy, None, BTreeSet::new())
    }

    pub(crate) fn run_action_retained(
        &self,
        spec: &ExecutionSpec,
        inputs: &[PreparedTree],
        destinations: &BTreeMap<String, PathBuf>,
        policy: &NativeBuildPolicy,
        retention: (&super::result_session::Registry, u32),
        retained: BTreeSet<Ticket>,
    ) -> Result<NativeBuildResult> {
        self.run_action_inner(
            spec,
            inputs,
            destinations,
            policy,
            Some(retention),
            retained,
        )
    }

    fn run_action_inner(
        &self,
        spec: &ExecutionSpec,
        inputs: &[PreparedTree],
        destinations: &BTreeMap<String, PathBuf>,
        policy: &NativeBuildPolicy,
        retention: Option<(&super::result_session::Registry, u32)>,
        mut retained: BTreeSet<Ticket>,
    ) -> Result<NativeBuildResult> {
        let mut inputs = LocalInputs::new(spec, inputs)?;
        let destinations = verify_destinations(spec, destinations)?;
        let destinations = super::intermediate::Destinations::new(destinations)?;
        retained.extend(destinations.sessions());
        let groups = retained
            .into_iter()
            .map(|token| {
                let (registry, uid) = retention.context("retention registry unavailable")?;
                registry.get(uid, token)
            })
            .collect::<Result<Vec<_>>>()?;
        let selected = destinations.eager.keys().cloned().collect();
        match self.acquire_action(spec, &mut inputs, policy, &selected)? {
            Outcome::Ready {
                mut delivery,
                source,
                manifest,
            } => {
                inputs.progress(NativeProgress::Phase(Phase::RestoreOutputs))?;
                validate_manifest(spec, &manifest, policy.max_result_bytes)?;
                let declared = manifest.selected_blobs(&selected)?;
                let staged =
                    delivery.with_download(policy.renewal_interval, &declared, |download| {
                        fetch_result(
                            spec,
                            &manifest,
                            &destinations.eager,
                            &inputs,
                            policy.max_result_bytes,
                            download,
                        )
                    })?;
                for group in groups {
                    delivery.retain(&group, &manifest, policy.renewal_interval)?;
                }
                let references = destinations.stage(&manifest)?;
                let output = staged.install()?;
                references.install()?;
                Ok(NativeBuildResult {
                    source,
                    output,
                    manifest: Some(manifest),
                })
            }
            Outcome::Failed { source, failure } => Ok(NativeBuildResult {
                source,
                output: failed_output(failure)?,
                manifest: None,
            }),
        }
    }

    pub(super) fn acquire_action(
        &self,
        spec: &ExecutionSpec,
        inputs: &mut impl InputProvider,
        policy: &NativeBuildPolicy,
        selected: &BTreeSet<String>,
    ) -> Result<Outcome<'_>> {
        validate_policy(policy)?;
        let request = spec.action_request()?;
        inputs.progress(NativeProgress::Phase(Phase::CacheLookup))?;
        let start = Instant::now();
        let mut declared = BTreeMap::new();
        let trace = inputs.trace_context();
        let mut waiting = None;

        loop {
            ensure!(
                start.elapsed() < policy.timeout,
                "native admission timed out"
            );
            let admission = self.admit(trace, spec, policy.mode, &declared)?;
            if !matches!(admission, NativeAdmission::InFlight { .. }) && waiting.take().is_some() {
                inputs.progress(NativeProgress::Phase(Phase::CacheLookup))?;
            }
            match admission {
                NativeAdmission::Hit { ticket, manifest } => {
                    let pin = Pin {
                        client: self,
                        ticket,
                        trace,
                        assigned: false,
                        selected: selected.clone(),
                        delivery: None,
                    };
                    return Ok(Outcome::Ready {
                        delivery: Box::new(Delivery {
                            pin,
                            publication: None,
                        }),
                        source: NativeBuildSource::Hit,
                        manifest,
                    });
                }
                NativeAdmission::InFlight { producer } => {
                    let producer = producer.filter(|producer| {
                        trace.is_none_or(|own| own.trace_id != producer.trace_id)
                    });
                    if waiting != Some(producer) {
                        inputs.progress(NativeProgress::WaitForProducer(producer))?;
                        waiting = Some(producer);
                    }
                    // No speculative duplicate compilation.
                    thread::sleep(
                        Duration::from_millis(50)
                            .min(policy.timeout.saturating_sub(start.elapsed())),
                    );
                }
                NativeAdmission::MissingInputs { trees } => {
                    ensure!(!trees.is_empty(), "empty native missing-input response");
                    for id in trees {
                        ensure!(
                            start.elapsed() < policy.timeout,
                            "native input preparation timed out"
                        );
                        ensure!(
                            request.input_trees.contains(&id),
                            "scheduler requested undeclared input tree"
                        );
                        let manifest = inputs.manifest(id)?;
                        ensure!(manifest.id()? == id, "input provider supplied wrong tree");
                        ensure!(
                            declared.insert(id, manifest).is_none(),
                            "scheduler did not accept declared input"
                        );
                    }
                }
                NativeAdmission::Compile { ticket } => {
                    let pin = Pin {
                        client: self,
                        ticket,
                        trace,
                        assigned: false,
                        selected: selected.clone(),
                        delivery: None,
                    };
                    return self.run_admitted(pin, spec, inputs, policy, start);
                }
            }
        }
    }

    fn schedule_with_retry(
        &self,
        pin: &Pin<'_>,
        spec: &ExecutionSpec,
        start: Instant,
        timeout: Duration,
    ) -> Result<ScheduleReply> {
        let mut delay = Duration::from_millis(10);
        loop {
            let remaining = timeout.saturating_sub(start.elapsed());
            ensure!(!remaining.is_zero(), "native allocation deadline exceeded");
            match self.schedule_selected(pin.trace, pin.ticket, spec.clone(), pin.selected.clone())
            {
                Ok(reply) => return Ok(reply),
                Err(error) if retryable_transport_error(&error) => {
                    debug!("retrying native allocation: {error:#}");
                    thread::sleep(delay.min(remaining));
                    delay = (delay * 2).min(Duration::from_millis(200));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn run_admitted<'a>(
        &self,
        mut pin: Pin<'a>,
        spec: &ExecutionSpec,
        inputs: &mut impl InputProvider,
        policy: &NativeBuildPolicy,
        start: Instant,
    ) -> Result<Outcome<'a>> {
        inputs.progress(NativeProgress::Phase(Phase::AllocateWorker))?;
        let reply = self.schedule_with_retry(&pin, spec, start, policy.timeout)?;
        let allocation = match reply {
            ScheduleReply::Assigned(allocation) => allocation,
            ScheduleReply::Unavailable { message } => {
                bail!("native worker unavailable: {message}");
            }
        };
        pin.assigned = true;
        inputs.progress(NativeProgress::Assigned {
            job: allocation.job,
            worker: allocation.peer,
        })?;
        let source = NativeBuildSource::Worker(allocation.peer);
        let request = spec.action_request()?;
        let remaining = policy.timeout.saturating_sub(start.elapsed());
        // Keep the origin connection live while the worker acquires inputs.
        // Only the worker RPC needs a separate thread; the original provider
        // (including the namespace stream) remains owned by this thread.
        let result = thread::scope(|scope| {
            let worker = scope.spawn(|| {
                self.observe_worker(&allocation, remaining, policy.max_result_bytes, |phase| {
                    if phase == crate::build_runtime::wire::NativeJobPhase::Publishing
                        && let Ok(NativeStatus::Negotiated(manifest)) =
                            self.preview_status(pin.ticket)
                    {
                        return Some(manifest);
                    }
                    None
                })
            });
            let supply = self.supply_until_ready(
                pin.ticket,
                &request.input_trees,
                inputs,
                start,
                policy,
                || worker.is_finished(),
            );
            // A worker may become ready through a concurrent provider while
            // its previous origin request is still in transit. Preserve an
            // already terminal result instead of cancelling it.
            let terminal = supply.is_err()
                && (worker.is_finished()
                    || matches!(
                        self.preview_status(pin.ticket),
                        Ok(NativeStatus::Negotiated(_)
                            | NativeStatus::Ready(_)
                            | NativeStatus::Failed)
                    ));
            if supply.is_err() && !terminal {
                let _ = self.close(pin.ticket);
            }
            let result = worker
                .join()
                .map_err(|_| anyhow::anyhow!("native worker request panicked"))?;
            if !terminal {
                supply?;
            }
            result
        });
        let result = match result {
            Ok(std::ops::ControlFlow::Break(manifest)) => {
                validate_manifest(spec, &manifest, policy.max_result_bytes)?;
                let publication = Publication {
                    allocation,
                    manifest: manifest.clone(),
                    deadline: start
                        .checked_add(policy.timeout)
                        .context("native publication deadline overflow")?,
                    max_result_bytes: policy.max_result_bytes,
                };
                return Ok(Outcome::Ready {
                    delivery: Box::new(Delivery {
                        pin,
                        publication: Some(Box::new(publication)),
                    }),
                    source,
                    manifest,
                });
            }
            Ok(std::ops::ControlFlow::Continue(result)) => Ok(result),
            Err(error) => Err(error),
        };
        self.finish_remote(pin, source, result)
    }

    fn finish_remote<'a>(
        &self,
        pin: Pin<'a>,
        source: NativeBuildSource,
        result: Result<NativeRunResult>,
    ) -> Result<Outcome<'a>> {
        let error = match result {
            Ok(NativeRunResult::Stored) => None,
            Ok(failure @ NativeRunResult::Failed { .. }) => {
                return Ok(Outcome::Failed { source, failure });
            }
            Ok(NativeRunResult::JobNotFound) => {
                Some(anyhow::anyhow!("native worker lost its assigned job"))
            }
            Ok(NativeRunResult::Unavailable) => Some(anyhow::anyhow!(
                "native worker could not execute its assigned job"
            )),
            Ok(NativeRunResult::Pending(_) | NativeRunResult::Acknowledged) => {
                Some(anyhow::anyhow!("unexpected nonterminal worker result"))
            }
            Err(error) => Some(error),
        };
        // Successful publication is authoritative even if the worker's
        // terminal response was lost, expired, or the worker restarted.
        match (self.status(pin.ticket), error) {
            (Ok(NativeStatus::Ready(manifest)), _) => Ok(Outcome::Ready {
                delivery: Box::new(Delivery {
                    pin,
                    publication: None,
                }),
                source,
                manifest,
            }),
            (_, Some(error)) | (Err(error), None) => Err(error),
            (Ok(_), None) => bail!("native worker did not publish its result"),
        }
    }
    fn supply_until_ready(
        &self,
        ticket: Ticket,
        input_trees: &BTreeSet<TreeId>,
        inputs: &mut impl InputProvider,
        start: Instant,
        policy: &NativeBuildPolicy,
        worker_finished: impl Fn() -> bool,
    ) -> Result<()> {
        let mut idle = Duration::from_millis(10);
        while !worker_finished() {
            ensure!(
                start.elapsed() < policy.timeout,
                "native worker deadline exceeded"
            );
            let poll = match self.poll_input(ticket) {
                Ok(poll) => poll,
                Err(error) if retryable_transport_error(&error) => {
                    debug!("retrying native input demand poll: {error:#}");
                    thread::sleep(idle);
                    idle = (idle * 2).min(Duration::from_millis(200));
                    continue;
                }
                Err(error) => return Err(error),
            };
            match poll {
                InputPoll::Complete => {
                    inputs.progress(NativeProgress::Phase(Phase::RunDistributed))?;
                    break;
                }
                InputPoll::Waiting => {
                    thread::sleep(idle);
                    idle = (idle * 2).min(Duration::from_millis(200));
                }
                InputPoll::Demand(demand) => {
                    idle = Duration::from_millis(10);
                    ensure!(
                        input_trees.contains(&demand.tree),
                        "scheduler requested undeclared tree"
                    );
                    self.supply_demand(ticket, demand, inputs, start, policy)?;
                }
            }
        }
        Ok(())
    }

    fn supply_demand(
        &self,
        ticket: Ticket,
        demand: InputDemand,
        inputs: &mut impl InputProvider,
        start: Instant,
        policy: &NativeBuildPolicy,
    ) -> Result<()> {
        if let Some(reader) = inputs.open_blob(demand.tree, demand.blob)? {
            match self.backfill_input(ticket, demand.blob, reader.clone()) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    // An interrupted HTTP request may have consumed only a
                    // prefix of the IPC frame. Realign before another demand.
                    reader.discard_unread()?;
                    let status = error
                        .downcast_ref::<wreq::Error>()
                        .and_then(wreq::Error::status);
                    if retryable_transport_error(&error)
                        || status == Some(http::StatusCode::CONFLICT)
                    {
                        debug!("retrying native input upload after polling: {error:#}");
                        thread::sleep(Duration::from_millis(50));
                        return Ok(());
                    }
                    if status != Some(http::StatusCode::UNPROCESSABLE_ENTITY) {
                        return Err(error);
                    }
                    // Only a verified content mismatch makes this locator
                    // unsuitable; ordinary I/O and claim failures are retried.
                    debug!("native input upload rejected: {error:#}");
                }
            }
        }
        loop {
            ensure!(
                start.elapsed() < policy.timeout,
                "native source decline deadline exceeded"
            );
            match self.input_unavailable(ticket, demand) {
                Ok(()) => return Ok(()),
                Err(error) if retryable_transport_error(&error) => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

pub(super) fn validate_policy(policy: &NativeBuildPolicy) -> Result<()> {
    ensure!(
        !policy.timeout.is_zero()
            && !policy.renewal_interval.is_zero()
            && policy.max_result_bytes > 0
            && policy.max_result_bytes < u64::MAX,
        "invalid native client bounds"
    );
    Ok(())
}

pub(super) fn failed_output(failure: NativeRunResult) -> Result<Output> {
    let NativeRunResult::Failed {
        code,
        signal,
        stdout,
        stderr,
    } = failure
    else {
        bail!("expected native compiler failure");
    };
    let status = match (code, signal) {
        (Some(code @ 1..=255), None) => crate::util::exit_status_from_code(code),
        (None, Some(signal @ 1..=64)) => ExitStatus::from_raw(signal),
        _ => bail!("invalid native compiler exit status"),
    };
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

pub(super) fn validate_manifest(
    spec: &ExecutionSpec,
    manifest: &ResultManifest,
    max_result_bytes: u64,
) -> Result<()> {
    spec.action_request()?.validate_result(manifest)?;
    ensure!(
        manifest.logical_bytes()? <= max_result_bytes,
        "native result exceeds client limits"
    );
    Ok(())
}

/// The result manifest is independent of delivery selection. Reuse verified
/// bytes already available to this caller, and download each repeated blob
/// at most once. Anonymous staging files cannot become a second persistent
/// cache or be modified through an output pathname.
struct ResultBlobs<'a, D> {
    inputs: &'a LocalInputs<'a>,
    repeated: BTreeSet<ContentId>,
    verified: BTreeMap<ContentId, tempfile::TempPath>,
    spool: Option<tempfile::TempDir>,
    download: D,
}

impl<D: FnMut(BlobRef, &mut BlobSink<'_>) -> Result<()>> ResultBlobs<'_, D> {
    fn spool_file(&mut self) -> Result<NamedTempFile> {
        if self.spool.is_none() {
            self.spool = Some(tempfile::tempdir()?);
        }
        Ok(NamedTempFile::new_in(
            self.spool.as_ref().context("missing result spool")?.path(),
        )?)
    }

    fn write(
        &mut self,
        blob: BlobRef,
        existing: Option<&Path>,
        output: &mut BlobSink<'_>,
    ) -> Result<()> {
        if let Some(path) = self.verified.get(&blob.id) {
            io::copy(&mut fs::File::open(path)?, output)?;
            return Ok(());
        }

        // Never consume a local candidate directly into the destination: it
        // may have changed since discovery. Verify into private staging first.
        let existing = existing.and_then(|path| {
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)
                .ok()?;
            let metadata = file.metadata().ok()?;
            if crate::build_runtime::intermediate_fs::intermediate_reference(&file)
                .ok()
                .flatten()
                .is_some()
            {
                return None;
            }
            (metadata.is_file() && metadata.len() == blob.size)
                .then(|| Box::new(file) as Box<dyn Read + Send>)
        });
        let inputs = self.inputs;
        let repeated = self.repeated.contains(&blob.id);
        // Repeated content gets one shared spool. A unique blob can be
        // verified directly in its private destination and reset on failure.
        let mut spool = if repeated {
            Some(self.spool_file()?)
        } else {
            None
        };
        {
            let mut target = spool.as_mut().map_or_else(
                || output.reborrow(),
                |file| BlobSink::File(file.as_file_mut()),
            );
            let mut reused = false;
            for candidate in existing.into_iter().chain(inputs.matching_sources(blob.id)) {
                target.reset()?;
                if copy_verified(candidate, blob, &mut target).is_ok() {
                    reused = true;
                    break;
                }
            }
            if !reused {
                target.reset()?;
                (self.download)(blob, &mut target)?;
            }
        }
        if let Some(mut file) = spool {
            file.rewind()?;
            io::copy(&mut file, output)?;
            self.verified.insert(blob.id, file.into_temp_path());
        }
        Ok(())
    }
}

fn repeated_result_blobs(
    manifest: &ResultManifest,
    destinations: &BTreeMap<String, PathBuf>,
) -> BTreeSet<ContentId> {
    let mut seen = BTreeSet::new();
    let mut repeated = BTreeSet::new();
    let mut count = |blob: BlobRef| {
        if !seen.insert(blob.id) {
            repeated.insert(blob.id);
        }
    };
    for blob in manifest.stdout.into_iter().chain(manifest.stderr) {
        count(blob);
    }
    for (name, artifact) in &manifest.outputs {
        if !destinations.contains_key(name) {
            continue;
        }
        match artifact {
            Artifact::File { blob, .. } => count(*blob),
            Artifact::Tree(tree) | Artifact::GeneratedTree(tree) => {
                for entry in tree.entries.values() {
                    if let crate::build_runtime::TreeEntry::File { blob, .. } = entry {
                        count(*blob);
                    }
                }
            }
        }
    }
    repeated
}

/// Result installation is shared by direct HTTP and namespace callers.
/// All content is verified before any destination is exposed.
pub(super) fn fetch_result(
    spec: &ExecutionSpec,
    manifest: &ResultManifest,
    destinations: &BTreeMap<String, PathBuf>,
    inputs: &LocalInputs<'_>,
    max_result_bytes: u64,
    download: impl FnMut(BlobRef, &mut BlobSink<'_>) -> Result<()>,
) -> Result<StagedResult> {
    validate_manifest(spec, manifest, max_result_bytes)?;
    let mut blobs = ResultBlobs {
        inputs,
        repeated: repeated_result_blobs(manifest, destinations),
        verified: BTreeMap::new(),
        spool: None,
        download,
    };
    let mut diagnostic = |blob: Option<BlobRef>| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        if let Some(blob) = blob {
            blobs.write(blob, None, &mut BlobSink::Memory(&mut bytes))?;
        }
        Ok(bytes)
    };
    let stdout = diagnostic(manifest.stdout)?;
    let stderr = diagnostic(manifest.stderr)?;
    let mut staged = Vec::new();
    for (name, artifact) in &manifest.outputs {
        let Some(path) = destinations.get(name) else {
            continue;
        };
        let parent = path.parent().context("native output has no parent")?;
        let temp = match artifact {
            Artifact::File { blob, mode } => {
                let mut temp = NamedTempFile::new_in(parent)?;
                blobs.write(*blob, Some(path), &mut BlobSink::File(temp.as_file_mut()))?;
                if let Some(mode) = mode {
                    temp.as_file()
                        .set_permissions(fs::Permissions::from_mode(*mode))?;
                }
                StagedOutput::File(temp)
            }
            Artifact::Tree(manifest) | Artifact::GeneratedTree(manifest) => {
                StagedOutput::Tree(materialize_tree(manifest, parent, |blob, path| {
                    blobs.write(
                        blob,
                        None,
                        &mut BlobSink::File(
                            &mut fs::OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(path)?,
                        ),
                    )
                })?)
            }
        };
        staged.push((temp, path.clone()));
    }
    Ok(StagedResult {
        stdout,
        stderr,
        files: staged,
    })
}

#[derive(Default)]
pub(super) struct StagedIntermediates(Vec<(StagedOutput, PathBuf)>);

impl StagedIntermediates {
    pub(super) fn file(&mut self, file: NamedTempFile, destination: PathBuf) {
        self.0.push((StagedOutput::File(file), destination));
    }
    pub(super) fn tree(&mut self, tree: MaterializedTree, destination: PathBuf) {
        self.0.push((StagedOutput::Tree(tree), destination));
    }
    pub(super) fn install(self) -> Result<()> {
        for (file, path) in self.0 {
            file.publish(&path)?;
        }
        Ok(())
    }
}

pub(super) struct StagedResult {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    files: Vec<(StagedOutput, PathBuf)>,
}

impl StagedResult {
    pub(super) fn install(self) -> Result<Output> {
        // File-wise atomic publication, not an atomic multi-file rename.
        for (temp, path) in self.files {
            temp.publish(&path)?;
        }
        Ok(Output {
            status: crate::util::exit_status_from_code(0),
            stdout: self.stdout,
            stderr: self.stderr,
        })
    }
}

pub(super) fn verify_destinations(
    spec: &ExecutionSpec,
    destinations: &BTreeMap<String, PathBuf>,
) -> Result<BTreeMap<String, PathBuf>> {
    ensure!(
        destinations
            .keys()
            .all(|name| spec.outputs.contains_key(name)),
        "native output destination is not declared"
    );
    let mut seen = BTreeSet::new();
    let mut verified = BTreeMap::new();
    for (name, path) in destinations {
        ensure!(
            path.is_absolute() && path != Path::new("/dev/null"),
            "invalid native output destination"
        );
        let parent = path
            .parent()
            .context("output parent missing")?
            .canonicalize()?;
        let filename = path.file_name().context("output file name missing")?;
        let path = parent.join(filename);
        ensure!(
            seen.iter()
                .all(|other: &PathBuf| !path.starts_with(other) && !other.starts_with(&path)),
            "native output destination paths overlap"
        );
        if spec.outputs[name].kind.is_tree() {
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => bail!("native tree output destination must not exist"),
                Err(error) => return Err(error.into()),
            }
        }
        seen.insert(path.clone());
        verified.insert(name.clone(), path);
    }
    Ok(verified)
}

#[cfg(test)]
mod input_blob_tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn aborted_framed_input_drains_exactly_the_remaining_payload() -> Result<()> {
        let source = InputBlob::new(Box::new(Cursor::new(b"firstnext")), 5, true);
        let mut uploader = source.clone();
        let mut prefix = [0; 2];
        uploader.read_exact(&mut prefix)?;
        assert_eq!(&prefix, b"fi");
        source.discard_unread()?;
        assert_eq!(uploader.read(&mut prefix)?, 0);
        let mut reader = source.reader.lock().unwrap();
        let mut next = Vec::new();
        reader.get_mut().read_to_end(&mut next)?;
        assert_eq!(next, b"next");
        Ok(())
    }
}

#[cfg(test)]
mod result_tests {
    use super::*;
    use crate::build_runtime::{
        BuildPath, CommandSpec, ExecutionRoot, MappedTree, OutputKind, OutputSpec, TreeMetadata,
        TreePath, TreeRecipe, TreeTimestamp,
    };

    fn metadata(mode: u32) -> TreeMetadata {
        TreeMetadata {
            mode,
            modified: TreeTimestamp {
                seconds: 1,
                nanoseconds: 0,
            },
        }
    }

    fn blob(data: &[u8]) -> BlobRef {
        BlobRef {
            id: ContentId::of(data),
            size: data.len() as u64,
        }
    }

    fn fixture() -> Result<(ExecutionSpec, PreparedTree, ResultManifest)> {
        let mut input = MappedTree::new(metadata(0o755));
        input.add_bytes(
            TreePath::new(b"input".to_vec())?,
            b"input".to_vec(),
            metadata(0o644),
        )?;
        let input = input.prepare()?;
        let mut intermediate = MappedTree::new(metadata(0o755));
        for (name, data) in [
            ("input-copy", b"input".as_slice()),
            ("duplicate-a", b"codegen"),
            ("duplicate-b", b"codegen"),
        ] {
            intermediate.add_bytes(
                TreePath::new(name.as_bytes().to_vec())?,
                data.to_vec(),
                metadata(0o644),
            )?;
        }
        let intermediate = intermediate.prepare()?;
        let spec = ExecutionSpec {
            compiler_result: None,
            working_inputs: Default::default(),
            platform: ContentId::of(b"platform"),
            root: ExecutionRoot::resolve(
                TreeRecipe::union(metadata(0o755), [input.id()]),
                &BTreeMap::from([(input.id(), input.manifest())]),
            )?,
            mounts: BTreeMap::new(),
            command: CommandSpec {
                umask: 0o022,
                executable: BuildPath::new(b"/tool".to_vec())?,
                arguments: Vec::new(),
                cwd: BuildPath::new(b"/".to_vec())?,
                environment: BTreeMap::new(),
            },
            outputs: BTreeMap::from([
                (
                    "final".into(),
                    OutputSpec {
                        path: BuildPath::new(b"/final".to_vec())?,
                        required: true,
                        kind: OutputKind::File,
                    },
                ),
                (
                    "intermediate".into(),
                    OutputSpec {
                        path: BuildPath::new(b"/intermediate".to_vec())?,
                        required: true,
                        kind: OutputKind::Tree,
                    },
                ),
            ]),
        };
        let manifest = ResultManifest {
            outputs: BTreeMap::from([
                (
                    "final".into(),
                    Artifact::File {
                        blob: blob(b"final"),
                        mode: Some(0o755),
                    },
                ),
                (
                    "intermediate".into(),
                    Artifact::Tree(intermediate.manifest().clone()),
                ),
            ]),
            stdout: None,
            stderr: None,
        };
        Ok((spec, input, manifest))
    }

    #[test]
    fn private_blob_staging_can_retry_after_partial_or_corrupt_delivery() -> Result<()> {
        let expected = blob(b"correct");
        let mut file = tempfile::tempfile()?;
        let mut bytes = Vec::new();
        for mut sink in [BlobSink::File(&mut file), BlobSink::Memory(&mut bytes)] {
            assert!(copy_verified(b"corrupt".as_slice(), expected, &mut sink).is_err());
            sink.reset()?;
            assert!(copy_verified(b"short".as_slice(), expected, &mut sink).is_err());
            sink.reset()?;
            copy_verified(b"correct".as_slice(), expected, &mut sink)?;
        }
        file.rewind()?;
        let mut actual = Vec::new();
        file.read_to_end(&mut actual)?;
        assert_eq!(actual, b"correct");
        assert_eq!(bytes, b"correct");
        assert!(BlobSink::Stream(&mut io::sink()).reset().is_err());
        Ok(())
    }

    #[test]
    fn selected_results_reuse_verified_inputs_and_duplicate_content() -> Result<()> {
        let (spec, input, manifest) = fixture()?;
        let inputs = [input];
        let inputs = LocalInputs::new(&spec, &inputs)?;
        let root = tempfile::tempdir()?;
        let final_path = root.path().join("final");
        let intermediate_path = root.path().join("intermediate");
        let final_only = verify_destinations(
            &spec,
            &BTreeMap::from([("final".into(), final_path.clone())]),
        )?;
        let mut requested = Vec::new();
        fetch_result(
            &spec,
            &manifest,
            &final_only,
            &inputs,
            1024,
            |content, out| {
                requested.push(content);
                copy_verified(b"final".as_slice(), content, out)
            },
        )?
        .install()?;
        assert_eq!(requested, [blob(b"final")]);
        assert_eq!(fs::read(&final_path)?, b"final");
        assert!(!intermediate_path.exists());

        let all = verify_destinations(
            &spec,
            &BTreeMap::from([
                ("final".into(), final_path.clone()),
                ("intermediate".into(), intermediate_path.clone()),
            ]),
        )?;
        requested.clear();
        fetch_result(&spec, &manifest, &all, &inputs, 1024, |content, out| {
            requested.push(content);
            copy_verified(b"codegen".as_slice(), content, out)
        })?
        .install()?;
        assert_eq!(requested, [blob(b"codegen")]);
        assert_eq!(fs::read(intermediate_path.join("input-copy"))?, b"input");
        assert_eq!(fs::read(intermediate_path.join("duplicate-a"))?, b"codegen");
        assert_eq!(fs::read(intermediate_path.join("duplicate-b"))?, b"codegen");
        assert_eq!(fs::read(&final_path)?, b"final");
        Ok(())
    }

    #[test]
    fn corrupt_existing_output_is_replaced_and_unselected_outputs_still_validated() -> Result<()> {
        let (spec, input, mut manifest) = fixture()?;
        let inputs = [input];
        let inputs = LocalInputs::new(&spec, &inputs)?;
        let root = tempfile::tempdir()?;
        let output = root.path().join("final");
        fs::write(&output, b"wrong")?;
        let selected =
            verify_destinations(&spec, &BTreeMap::from([("final".into(), output.clone())]))?;
        assert!(
            verify_destinations(&spec, &BTreeMap::from([("unknown".into(), output.clone())]),)
                .is_err()
        );
        let mut downloads = 0;
        fetch_result(
            &spec,
            &manifest,
            &selected,
            &inputs,
            1024,
            |content, out| {
                downloads += 1;
                copy_verified(b"final".as_slice(), content, out)
            },
        )?
        .install()?;
        assert_eq!(downloads, 1);
        assert_eq!(fs::read(&output)?, b"final");
        // An unselected tree can be internally valid while contradicting
        // the length of a digest in a selected file.
        let mut inconsistent = manifest.clone();
        let Some(Artifact::Tree(tree)) = inconsistent.outputs.get_mut("intermediate") else {
            anyhow::bail!("missing intermediate tree");
        };
        tree.entries.insert(
            TreePath::new(b"conflict".to_vec())?,
            crate::build_runtime::TreeEntry::File {
                blob: BlobRef {
                    id: ContentId::of(b"final"),
                    size: 6,
                },
                metadata: metadata(0o644),
            },
        );
        assert!(
            inconsistent
                .selected_blobs(&BTreeSet::from(["final".to_owned()]))
                .is_ok()
        );
        assert!(validate_manifest(&spec, &inconsistent, 1024).is_err());
        manifest.outputs.remove("intermediate");
        assert!(
            fetch_result(&spec, &manifest, &selected, &inputs, 1024, |_, _| {
                anyhow::bail!("invalid complete manifest must not transfer content")
            })
            .is_err()
        );
        Ok(())
    }
}
