//! Bounded worker pipeline. A job occupies exactly one reservation across all
//! stages; ready jobs retain their inputs without owning a compiler thread.

use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
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
        CapturedExecution,
        wire::{NativeJobPhase, NativeRunRequest, NativeRunResult},
    },
    dist::{
        JobId, JobState, NativeAssignment, ServerOutgoing, UpdateJobStateResult,
        execution_queue::ExecutionQueue,
        native::{CompletedWorker, PreparedWorker},
    },
};

use super::{NativeInputPins, NativeWorker};

const RESULT_RETENTION: Duration = Duration::from_mins(5);

struct Assignment {
    spec: NativeAssignment,
    _pins: NativeInputPins,
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
    Assigned(Box<Assignment>),
    Active(NativeJobPhase),
    Terminal {
        result: Arc<Terminal>,
        completed_at: Instant,
    },
}

struct Reservation {
    accepted_at: Instant,
    cancelled: Arc<AtomicBool>,
    state: State,
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
        }
    }

    fn terminal(&self, job: JobId, result: Terminal) {
        let mut reservations = self
            .reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = reservations.get_mut(&job) {
            entry.state = State::Terminal {
                result: Arc::new(result),
                completed_at: Instant::now(),
            };
        }
    }

    fn finish(&self, job: Job, result: Result<CapturedExecution>) {
        // A lost completion acknowledgement must not discard successfully
        // published outputs or the original compiler diagnostics.
        match job
            .requester
            .do_update_job_state(job.id, JobState::Complete)
        {
            Ok(UpdateJobStateResult::Success) => (),
            Ok(UpdateJobStateResult::Fail { msg }) => {
                warn!("Native job {} completion rejected: {msg}", job.id)
            }
            Err(error) => warn!(
                "Native job {} completion acknowledgement failed: {error:#}",
                job.id
            ),
        }
        self.terminal(job.id, Terminal::from_result(result));
    }

    fn stage(&self, staging: Staging, ready: &SyncSender<Ready>) {
        let Staging { job, assignment } = staging;
        self.phase(job.id, NativeJobPhase::Staging);
        let result = (|| {
            match job
                .requester
                .do_update_job_state(job.id, JobState::Started)?
            {
                UpdateJobStateResult::Success => (),
                UpdateJobStateResult::Fail { msg } => {
                    anyhow::bail!("scheduler rejected native job start: {msg}")
                }
            }
            ensure!(
                !job.cancelled.load(Ordering::Acquire),
                "native job cancelled before staging"
            );
            Ok(())
        })();
        let result = match result {
            Ok(()) => self.worker.prepare(
                job.id,
                &assignment.spec,
                &self.queue,
                Arc::clone(&job.cancelled),
            ),
            Err(error) => {
                self.worker.fail(job.id, assignment.spec.ticket);
                Err(error)
            }
        };
        match result {
            Ok(prepared) => {
                // PreparedWorker owns every complete input tree. Drop the
                // assignment's partial pins only after this handoff.
                drop(assignment);
                self.phase(job.id, NativeJobPhase::Ready);
                if let Err(error) = ready.send(Ready { job, prepared }) {
                    let Ready { job, prepared } = error.0;
                    drop(prepared);
                    self.finish(job, Err(anyhow::anyhow!("native compiler pool stopped")));
                }
            }
            Err(error) => {
                drop(assignment);
                self.finish(job, Err(error));
            }
        }
    }

    fn compile(&self, ready: Ready, publishing: &SyncSender<Publishing>) {
        let Ready { job, prepared } = ready;
        let completed = self.worker.execute(prepared, &self.queue, || {
            self.phase(job.id, NativeJobPhase::Executing)
        });
        self.phase(job.id, NativeJobPhase::Publishing);
        if let Err(error) = publishing.send(Publishing { job, completed }) {
            let Publishing { job, completed } = error.0;
            drop(completed);
            self.finish(job, Err(anyhow::anyhow!("native publication pool stopped")));
        }
    }

    fn publish(&self, publishing: Publishing) {
        let Publishing { job, completed } = publishing;
        let result = self.worker.publish(completed);
        self.finish(job, result);
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

pub(super) struct NativeDispatcher {
    shared: Arc<Shared>,
    staging: Option<SyncSender<Staging>>,
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
            capacity > 0,
            "native dispatcher reservation limit must be nonzero"
        );
        let shared = Arc::new(Shared {
            worker,
            queue,
            reservations: Mutex::new(HashMap::new()),
            capacity,
        });
        let (staging, staging_rx) = mpsc::sync_channel(capacity);
        let (ready, ready_rx) = mpsc::sync_channel(capacity);
        let (publishing, publishing_rx) = mpsc::sync_channel(capacity);
        let mut threads = {
            let shared = Arc::clone(&shared);
            spawn_pool("native-publish", io_width, publishing_rx, move |task| {
                shared.publish(task)
            })?
        };
        {
            let shared = Arc::clone(&shared);
            threads.extend(spawn_pool(
                "native-compile",
                width,
                ready_rx,
                move |task| shared.compile(task, &publishing),
            )?);
        }
        {
            let shared = Arc::clone(&shared);
            threads.extend(spawn_pool(
                "native-stage",
                io_width,
                staging_rx,
                move |task| shared.stage(task, &ready),
            )?);
        }
        Ok(Self {
            shared,
            staging: Some(staging),
            threads,
        })
    }

    pub(super) fn worker(&self) -> &NativeWorker {
        &self.shared.worker
    }

    pub(super) fn assign(&self, id: JobId, spec: NativeAssignment) -> Result<()> {
        spec.spec.validate()?;
        let pins = self.shared.worker.pin_resident_inputs(&spec)?;
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
        match reservations.entry(id) {
            Entry::Occupied(_) => anyhow::bail!("duplicate native assignment for job {id}"),
            Entry::Vacant(entry) => {
                entry.insert(Reservation {
                    accepted_at: Instant::now(),
                    cancelled: Arc::new(AtomicBool::new(false)),
                    state: State::Assigned(Box::new(Assignment { spec, _pins: pins })),
                });
            }
        }
        drop(reservations);
        Ok(())
    }

    pub(super) fn active_jobs(&self) -> Vec<JobId> {
        let mut reservations = self
            .shared
            .reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Shared::reap(&mut reservations);
        reservations
            .iter()
            .filter_map(|(&id, entry)| matches!(entry.state, State::Active(_)).then_some(id))
            .collect()
    }

    pub(super) fn reconcile(&self, known: &HashSet<JobId>, cutoff: Instant) -> usize {
        let mut reservations = self
            .shared
            .reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let before = reservations.len();
        reservations.retain(|id, entry| {
            if entry.accepted_at >= cutoff || known.contains(id) {
                return true;
            }
            match &entry.state {
                State::Assigned(_) => false,
                State::Active(_) => {
                    entry.cancelled.store(true, Ordering::Release);
                    true
                }
                // A completion acknowledgement removes the scheduler entry
                // before the client has fetched its terminal result.
                State::Terminal { .. } => true,
            }
        });
        let removed = before - reservations.len();
        drop(reservations);
        removed
    }

    /// The first poll claims the assignment; retries only observe its state.
    /// Terminal data survives lost responses until explicit acknowledgement.
    pub(super) fn poll(
        &self,
        id: JobId,
        requester: Arc<dyn ServerOutgoing>,
        request: NativeRunRequest,
    ) -> Result<NativeRunResult> {
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
        let Some(entry) = reservations.get_mut(&id) else {
            return Ok(NativeRunResult::JobNotFound);
        };
        match &entry.state {
            State::Terminal { result, .. } => {
                let result = Arc::clone(result);
                drop(reservations);
                result.response()
            }
            State::Active(phase) => Ok(NativeRunResult::Pending(*phase)),
            State::Assigned(_) => {
                let State::Assigned(assignment) =
                    std::mem::replace(&mut entry.state, State::Active(NativeJobPhase::Queued))
                else {
                    anyhow::bail!("native assignment changed while locked");
                };
                let job = Job {
                    id,
                    requester,
                    cancelled: Arc::clone(&entry.cancelled),
                };
                let task = Staging { job, assignment };
                // At most capacity reservations exist across all stages. A
                // full channel cannot occur for a newly claimed reservation.
                if let Err(error) = self
                    .staging
                    .as_ref()
                    .context("native dispatcher stopped")?
                    .try_send(task)
                {
                    let task = match error {
                        mpsc::TrySendError::Full(task) | mpsc::TrySendError::Disconnected(task) => {
                            task
                        }
                    };
                    let Staging { assignment, .. } = task;
                    entry.state = State::Assigned(assignment);
                    return Err(anyhow::anyhow!("native staging dispatcher unavailable"));
                }
                drop(reservations);
                Ok(NativeRunResult::Pending(NativeJobPhase::Queued))
            }
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
        // Closing each upstream channel releases the downstream senders.
        for thread in self.threads.drain(..) {
            if thread.join().is_err() {
                error!("Native dispatcher thread panicked");
            }
        }
    }
}
