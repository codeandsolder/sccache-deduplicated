//! Bounded worker pipeline. A job occupies exactly one reservation across all
//! stages; ready jobs retain their inputs without owning a compiler thread.

use std::{
    collections::{BTreeMap, HashMap, HashSet, hash_map::Entry},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use sccache::{
    build_runtime::{
        CapturedExecution, TreeLease,
        wire::{NativeJobPhase, NativeRunRequest, NativeRunResult},
    },
    dist::{
        JobId, JobState, NativeAssignment, NativeJobProgress, NativePlacement, NativeQueueSnapshot,
        ServerOutgoing, UpdateJobStateResult,
        execution_queue::ExecutionQueue,
        native::{CompletedWorker, PreparedWorker, WorkerPreparation},
    },
    latency_trace::{PhaseTrace, enabled},
};

use super::{NativeInputPins, NativeWorker};

const RESULT_RETENTION: Duration = Duration::from_mins(5);

struct Assignment {
    spec: NativeAssignment,
    pins: NativeInputPins,
}

enum Terminal {
    Stored,
    Failed(CapturedExecution),
    Unavailable,
}

impl Terminal {
    fn response(&self) -> Result<NativeRunResult> {
        match self {
            Self::Stored => Ok(NativeRunResult::Stored),
            Self::Failed(captured) => captured.failure_result(),
            Self::Unavailable => Ok(NativeRunResult::Unavailable),
        }
    }

    fn from_result(result: Result<CapturedExecution>) -> Self {
        match result {
            Ok(captured) if captured.successful_result().is_some() => Self::Stored,
            Ok(captured) => Self::Failed(captured),
            Err(error) => {
                warn!("Native worker action failed: {error:#}");
                Self::Unavailable
            }
        }
    }
}

enum State {
    Active(NativeJobPhase),
    Terminal {
        result: Arc<Terminal>,
        completed_at: Instant,
    },
}

struct Reservation {
    accepted_at: Instant,
    phase_since: Instant,
    remaining: RemainingInputs,
    cancelled: Arc<AtomicBool>,
    state: State,
    trace: Option<PhaseTrace>,
}

#[derive(Clone, Copy, Default)]
struct RemainingInputs {
    bytes: u64,
    blobs: u64,
}

impl RemainingInputs {
    fn from_missing(missing: &[sccache::build_runtime::BlobRef]) -> Self {
        Self {
            bytes: missing
                .iter()
                .map(|blob| blob.size)
                .fold(0, u64::saturating_add),
            blobs: u64::try_from(missing.len()).unwrap_or(u64::MAX),
        }
    }
}

fn trace_phase(phase: NativeJobPhase) -> &'static str {
    match phase {
        NativeJobPhase::Assigned => "assigned",
        NativeJobPhase::Queued => "staging_queue",
        NativeJobPhase::Staging => "stage_inputs",
        NativeJobPhase::Ready => "compiler_queue",
        NativeJobPhase::Executing => "execute",
        NativeJobPhase::AwaitingPublication => "publication_queue",
        NativeJobPhase::Publishing => "publish_outputs",
        NativeJobPhase::Terminal => "terminal",
    }
}

impl Reservation {
    fn progress(&self, now: Instant) -> NativeJobProgress {
        let phase = match self.state {
            State::Active(phase) => phase,
            State::Terminal { .. } => NativeJobPhase::Terminal,
        };
        NativeJobProgress {
            phase,
            phase_nanoseconds: u64::try_from(
                now.saturating_duration_since(self.phase_since).as_nanos(),
            )
            .unwrap_or(u64::MAX),
            remaining_input_bytes: self.remaining.bytes,
            remaining_input_blobs: self.remaining.blobs,
        }
    }
}

struct Job {
    id: JobId,
    requester: Arc<dyn ServerOutgoing>,
    cancelled: Arc<AtomicBool>,
}

struct Staging {
    job: Job,
    assignment: Box<Assignment>,
}

struct Ready {
    job: Job,
    prepared: PreparedWorker,
}

struct Publishing {
    job: Job,
    completed: CompletedWorker,
}

struct Shared {
    worker: NativeWorker,
    queue: Arc<ExecutionQueue>,
    reservations: Mutex<HashMap<JobId, Reservation>>,
    capacity: usize,
    io_width: usize,
}

impl Shared {
    fn reap(reservations: &mut HashMap<JobId, Reservation>) {
        reservations.retain(|_, entry| {
            !matches!(&entry.state, State::Terminal { completed_at, .. } if completed_at.elapsed() >= RESULT_RETENTION)
        });
    }

    fn phase(&self, job: JobId, phase: NativeJobPhase) {
        let mut reservations = self
            .reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = reservations.get_mut(&job) {
            entry.state = State::Active(phase);
            entry.phase_since = Instant::now();
            if let Some(trace) = &mut entry.trace {
                trace.phase(trace_phase(phase));
            }
            if phase.inputs_ready() {
                entry.remaining = RemainingInputs::default();
            }
        }
    }

    fn remaining(&self, job: JobId, remaining: RemainingInputs) {
        let mut reservations = self
            .reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = reservations.get_mut(&job) {
            entry.remaining = remaining;
        }
    }

    fn terminal(&self, job: JobId, result: Terminal) {
        let mut reservations = self
            .reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let failed = !matches!(&result, Terminal::Stored);
        let trace = if let Some(entry) = reservations.get_mut(&job) {
            let now = Instant::now();
            entry.state = State::Terminal {
                result: Arc::new(result),
                completed_at: now,
            };
            entry.phase_since = now;
            entry.remaining = RemainingInputs::default();
            entry.trace.take()
        } else {
            None
        };
        drop(reservations);
        if let Some(trace) = trace {
            trace.finish(failed);
        }
    }

    async fn finish(&self, job: &Job, result: Result<CapturedExecution>) {
        // A lost completion acknowledgement must not discard successfully
        // published outputs or the original compiler diagnostics.
        match job
            .requester
            .do_update_job_state(job.id, JobState::Complete)
            .await
        {
            Ok(UpdateJobStateResult::Success) => (),
            Ok(UpdateJobStateResult::Fail { msg }) => {
                warn!("Native job {} completion rejected: {msg}", job.id);
            }
            Err(error) => warn!(
                "Native job {} completion acknowledgement failed: {error:#}",
                job.id
            ),
        }
        self.terminal(job.id, Terminal::from_result(result));
    }

    fn finish_blocking(&self, job: &Job, result: Result<CapturedExecution>) {
        match sccache::http_client::io_runtime() {
            Ok(runtime) => runtime.block_on(self.finish(job, result)),
            Err(error) => {
                warn!("Native completion runtime unavailable: {error:#}");
                self.terminal(job.id, Terminal::from_result(result));
            }
        }
    }

    async fn stage(&self, staging: Staging, ready: &SyncSender<Ready>) {
        let Staging { job, assignment } = staging;
        let missing = assignment.pins.blobs.missing();
        let mut remaining = RemainingInputs::from_missing(missing);
        let mut missing: BTreeMap<_, _> = missing.iter().map(|blob| (blob.id, blob.size)).collect();
        let mut on_tree = |tree: &TreeLease| {
            for id in tree.blobs().keys() {
                if let Some(bytes) = missing.remove(id) {
                    remaining.bytes = remaining.bytes.saturating_sub(bytes);
                    remaining.blobs = remaining.blobs.saturating_sub(1);
                }
            }
            self.remaining(job.id, remaining);
        };
        let result = self
            .worker
            .prepare(
                job.id,
                &assignment.spec,
                &self.queue,
                WorkerPreparation {
                    estimated_result_bytes: assignment.spec.estimated_result_bytes,
                    cancelled: Arc::clone(&job.cancelled),
                    on_tree: &mut on_tree,
                    on_authorized: || async {
                        match job
                            .requester
                            .do_update_job_state(job.id, JobState::Started)
                            .await?
                        {
                            UpdateJobStateResult::Success => {
                                self.phase(job.id, NativeJobPhase::Staging);
                                Ok(())
                            }
                            UpdateJobStateResult::Fail { msg } => {
                                anyhow::bail!("scheduler rejected native job start: {msg}")
                            }
                        }
                    },
                },
            )
            .await;
        match result {
            Ok(prepared) => {
                // PreparedWorker owns every complete input tree. Drop the
                // assignment's partial pins only after this handoff.
                drop(assignment);
                self.phase(job.id, NativeJobPhase::Ready);
                if let Err(error) = ready.try_send(Ready { job, prepared }) {
                    let Ready { job, prepared } = match error {
                        mpsc::TrySendError::Full(task) | mpsc::TrySendError::Disconnected(task) => {
                            task
                        }
                    };
                    drop(prepared);
                    self.finish(&job, Err(anyhow::anyhow!("native compiler pool stopped")))
                        .await;
                }
            }
            Err(error) => {
                drop(assignment);
                self.finish(&job, Err(error)).await;
            }
        }
    }

    fn compile(&self, ready: Ready, publishing: &tokio::sync::mpsc::Sender<Publishing>) {
        let Ready { job, prepared } = ready;
        let completed = self.worker.execute(prepared, &self.queue, || {
            self.phase(job.id, NativeJobPhase::Executing);
        });
        self.phase(job.id, NativeJobPhase::AwaitingPublication);
        if let Err(error) = publishing.try_send(Publishing { job, completed }) {
            let Publishing { job, completed } = error.into_inner();
            drop(completed);
            self.finish_blocking(
                &job,
                Err(anyhow::anyhow!("native publication pool stopped")),
            );
        }
    }

    async fn publish(&self, publishing: Publishing) {
        let Publishing { job, completed } = publishing;
        self.phase(job.id, NativeJobPhase::Publishing);
        let result = self.worker.publish(completed).await;
        self.finish(&job, result).await;
    }
}

/// The receiver lock is held only while waiting for a task, never during
/// transfers, compilation, publication or scheduler calls.
fn spawn_pool<T: Send + 'static>(
    name: &str,
    width: usize,
    receiver: Receiver<T>,
    operation: impl Fn(T) + Send + Sync + 'static,
) -> Result<Vec<JoinHandle<()>>> {
    ensure!(width > 0, "native dispatcher pool must be nonempty");
    let receiver = Arc::new(Mutex::new(receiver));
    let operation = Arc::new(operation);
    let mut threads = Vec::with_capacity(width);
    for index in 0..width {
        let receiver = Arc::clone(&receiver);
        let operation = Arc::clone(&operation);
        threads.push(
            thread::Builder::new()
                .name(format!("{name}-{index}"))
                .spawn(move || {
                    loop {
                        let next = receiver
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .recv();
                        let Ok(task) = next else {
                            break;
                        };
                        operation(task);
                    }
                })?,
        );
    }
    Ok(threads)
}

// Own each admitted operation until it completes, including when its
// scheduler/client stops polling. The queue capacity and width are independent.
fn spawn_async_pool<T, F, Fut>(
    runtime: &tokio::runtime::Runtime,
    width: usize,
    mut receiver: tokio::sync::mpsc::Receiver<T>,
    operation: F,
) -> tokio::task::JoinHandle<()>
where
    T: Send + 'static,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    runtime.spawn(async move {
        let mut active = tokio::task::JoinSet::new();
        let mut closed = false;
        loop {
            if closed && active.is_empty() {
                break;
            }
            tokio::select! {
                task = receiver.recv(), if !closed && active.len() < width => {
                    match task {
                        Some(task) => { active.spawn(operation(task)); }
                        None => closed = true,
                    }
                }
                result = active.join_next(), if !active.is_empty() => {
                    if let Some(Err(error)) = result {
                        error!("Native dispatcher stage operation failed: {error:#}");
                    }
                }
            }
        }
    })
}

pub struct NativeDispatcher {
    shared: Arc<Shared>,
    staging: Option<tokio::sync::mpsc::Sender<Staging>>,
    staging_task: Option<tokio::task::JoinHandle<()>>,
    publication_task: Option<tokio::task::JoinHandle<()>>,
    threads: Vec<JoinHandle<()>>,
}

impl NativeDispatcher {
    pub(super) fn new(worker: NativeWorker, queue: Arc<ExecutionQueue>) -> Result<Self> {
        let width = queue.width().get();
        let io_width = worker.transfer_parallelism().min(width);
        // The reservation bound includes assigned, staging, ready, running,
        // publishing and unacknowledged terminal jobs. Each queue can hold
        // that entire bound, so a stage never deadlocks on downstream capacity.
        let capacity = worker
            .max_inflight_jobs
            .unwrap_or_else(|| width.saturating_mul(4));
        ensure!(
            (1..=NativeQueueSnapshot::MAX_CAPACITY as usize).contains(&capacity)
                && width <= NativeQueueSnapshot::MAX_CAPACITY as usize,
            "native dispatcher reservation or compiler limit out of range"
        );
        let shared = Arc::new(Shared {
            worker,
            queue,
            reservations: Mutex::new(HashMap::new()),
            capacity,
            io_width,
        });
        let (staging, staging_rx) = tokio::sync::mpsc::channel(capacity);
        let runtime = sccache::http_client::io_runtime()?;
        let (ready, ready_rx) = mpsc::sync_channel(capacity);
        let (publishing, publishing_rx) = tokio::sync::mpsc::channel(capacity);
        let threads = {
            let shared = Arc::clone(&shared);
            spawn_pool("native-compile", width, ready_rx, move |task| {
                shared.compile(task, &publishing);
            })?
        };
        let publication_task = {
            let shared = Arc::clone(&shared);
            spawn_async_pool(runtime, io_width, publishing_rx, move |task| {
                let shared = Arc::clone(&shared);
                async move { shared.publish(task).await }
            })
        };
        let staging_task = {
            let shared = Arc::clone(&shared);
            spawn_async_pool(runtime, io_width, staging_rx, move |task| {
                let shared = Arc::clone(&shared);
                let ready = ready.clone();
                async move { shared.stage(task, &ready).await }
            })
        };
        Ok(Self {
            shared,
            staging: Some(staging),
            staging_task: Some(staging_task),
            publication_task: Some(publication_task),
            threads,
        })
    }

    pub(super) fn worker(&self) -> &NativeWorker {
        &self.shared.worker
    }

    pub(super) fn assign(
        &self,
        id: JobId,
        spec: NativeAssignment,
        requester: Arc<dyn ServerOutgoing>,
    ) -> Result<()> {
        ensure!(
            spec.trace
                .is_none_or(sccache::latency_trace::TraceContext::valid),
            "invalid worker trace context"
        );
        let mut trace = spec.trace.filter(|_| enabled()).map(|parent| {
            PhaseTrace::new(
                parent,
                "sccache-worker",
                "worker_job",
                "assignment",
                vec![("sccache.job_id", id.0.to_string())],
            )
        });
        spec.spec.validate()?;
        let pins = self.shared.worker.pin_resident_inputs(&spec)?;
        let remaining = RemainingInputs::from_missing(pins.blobs.missing());
        let mut reservations = self
            .shared
            .reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Shared::reap(&mut reservations);
        ensure!(
            reservations.len() < self.shared.capacity,
            "native dispatcher reservation limit reached"
        );
        let sender = self.staging.as_ref().context("native dispatcher stopped")?;
        let Entry::Vacant(entry) = reservations.entry(id) else {
            anyhow::bail!("duplicate native assignment for job {id}");
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let now = Instant::now();
        if let Some(trace) = &mut trace {
            trace.phase("staging_queue");
        }
        entry.insert(Reservation {
            accepted_at: now,
            phase_since: now,
            remaining,
            cancelled: Arc::clone(&cancelled),
            state: State::Active(NativeJobPhase::Queued),
            trace,
        });
        let task = Staging {
            job: Job {
                id,
                requester,
                cancelled,
            },
            assignment: Box::new(Assignment { spec, pins }),
        };
        // No authorization RPC on this request thread: the scheduler has not
        // yet installed the delegated publisher while awaiting our acknowledgement.
        if let Err(error) = sender.try_send(task) {
            reservations.remove(&id);
            drop(reservations);
            drop(error);
            anyhow::bail!("native staging dispatcher unavailable");
        }
        drop(reservations);
        Ok(())
    }

    pub(super) fn snapshot(&self) -> NativeQueueSnapshot {
        let mut reservations = self
            .shared
            .reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Shared::reap(&mut reservations);
        let now = Instant::now();
        NativeQueueSnapshot {
            capacity: u32::try_from(self.shared.capacity)
                .unwrap_or(NativeQueueSnapshot::MAX_CAPACITY),
            compiler_slots: u32::try_from(self.shared.queue.width().get())
                .unwrap_or(NativeQueueSnapshot::MAX_CAPACITY),
            compiler_active: u32::try_from(self.shared.queue.active())
                .unwrap_or(NativeQueueSnapshot::MAX_CAPACITY),
            staging_slots: u32::try_from(self.shared.io_width)
                .unwrap_or(NativeQueueSnapshot::MAX_CAPACITY),
            publication_slots: u32::try_from(self.shared.io_width)
                .unwrap_or(NativeQueueSnapshot::MAX_CAPACITY),
            jobs: reservations
                .iter()
                .map(|(&id, entry)| (id, entry.progress(now)))
                .collect(),
        }
    }

    pub(super) fn placement(&self) -> NativePlacement {
        self.shared.worker.placement(self.snapshot())
    }

    pub(super) fn reconcile(&self, known: &HashSet<JobId>, cutoff: Instant) -> usize {
        let reservations = self
            .shared
            .reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Retain active reservations until their owning stage drains. A
        // terminal result is independent of the scheduler job's lifetime.
        let removed = reservations
            .iter()
            .filter(|(id, entry)| {
                entry.accepted_at < cutoff
                    && !known.contains(id)
                    && matches!(entry.state, State::Active(_))
                    && !entry.cancelled.swap(true, Ordering::AcqRel)
            })
            .count();
        drop(reservations);
        removed
    }

    /// Polls only observe state; assignment already initiated execution.
    /// Terminal data survives lost responses until explicit acknowledgement.
    pub(super) fn poll(&self, id: JobId, request: NativeRunRequest) -> Result<NativeRunResult> {
        let mut reservations = self
            .shared
            .reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Shared::reap(&mut reservations);
        if request == NativeRunRequest::Acknowledge {
            if reservations
                .get(&id)
                .is_none_or(|entry| matches!(entry.state, State::Terminal { .. }))
            {
                reservations.remove(&id);
                return Ok(NativeRunResult::Acknowledged);
            }
            anyhow::bail!("cannot acknowledge an active native job");
        }
        let Some(entry) = reservations.get(&id) else {
            return Ok(NativeRunResult::JobNotFound);
        };
        match &entry.state {
            State::Terminal { result, .. } => {
                let result = Arc::clone(result);
                drop(reservations);
                result.response()
            }
            State::Active(phase) => Ok(NativeRunResult::Pending(*phase)),
        }
    }
}

#[cfg(test)]
mod tests;

impl Drop for NativeDispatcher {
    fn drop(&mut self) {
        {
            let reservations = self
                .shared
                .reservations
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for entry in reservations.values() {
                entry.cancelled.store(true, Ordering::Release);
            }
        }
        drop(self.staging.take());
        // Drain staging, then compilation, then publication. Each stage
        // owns the downstream sender, so joining in this order closes it.
        join_async_stage(self.staging_task.take());
        for thread in self.threads.drain(..) {
            if thread.join().is_err() {
                error!("Native dispatcher compiler thread panicked");
            }
        }
        join_async_stage(self.publication_task.take());
    }
}

fn join_async_stage(task: Option<tokio::task::JoinHandle<()>>) {
    if let Some(task) = task {
        match sccache::http_client::io_runtime() {
            Ok(runtime) => {
                if let Err(error) = runtime.block_on(task) {
                    error!("Native dispatcher stage failed: {error:#}");
                }
            }
            Err(error) => error!("Native dispatcher runtime unavailable: {error:#}"),
        }
    }
}
