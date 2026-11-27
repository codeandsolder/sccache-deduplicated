//! Observable compile-request lifetimes. Heartbeats prove transport liveness;
//! only actual phase transitions reset the phase deadline.

use crate::{
    latency_trace::{LatencySpan, TraceContext, nanos, unix_nanos},
    protocol::{Compile, CompileFinished, CompileIdentity, NativeBuildSource},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    future::Future,
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
pub const IPC_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(90);

/// Separate budgets for preparation/publication and potentially long execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CompileLimits {
    pub phase_timeout_secs: u64,
    pub execution_timeout_secs: u64,
}

impl Default for CompileLimits {
    fn default() -> Self {
        Self {
            phase_timeout_secs: 1800,
            execution_timeout_secs: 7200,
        }
    }
}

impl CompileLimits {
    /// # Errors
    /// Returns an error for a zero phase deadline.
    pub fn validate(self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.phase_timeout_secs > 0 && self.execution_timeout_secs > 0,
            "compile request deadlines must be positive"
        );
        Ok(())
    }

    pub(super) const fn budget(self, phase: Phase) -> Duration {
        Duration::from_secs(match phase {
            Phase::HashInputs | Phase::RunDistributed | Phase::LocalCompile => {
                self.execution_timeout_secs
            }
            _ => self.phase_timeout_secs,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    DetectCompiler,
    ParseArguments,
    ResolveDistribution,
    HashInputs,
    CacheLookup,
    RestoreOutputs,
    PlanCompile,
    IdentifyToolchain,
    AllocateWorker,
    UploadToolchain,
    StageInputs,
    RunDistributed,
    LocalCompile,
    PublishOutputs,
    PackResult,
    RecordResult,
    WriteCache,
    SendReply,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompileOwner {
    Daemon,
    Namespace,
}

const MAX_TRACE_INTERVALS: usize = 128;

impl Phase {
    const fn trace_name(self) -> &'static str {
        match self {
            Self::DetectCompiler => "detect_compiler",
            Self::ParseArguments => "parse_arguments",
            Self::ResolveDistribution => "resolve_distribution",
            Self::HashInputs => "hash_inputs",
            Self::CacheLookup => "cache_lookup",
            Self::RestoreOutputs => "restore_outputs",
            Self::PlanCompile => "plan_compile",
            Self::IdentifyToolchain => "identify_toolchain",
            Self::AllocateWorker => "allocate_worker",
            Self::UploadToolchain => "upload_toolchain",
            Self::StageInputs => "stage_inputs",
            Self::RunDistributed => "run_distributed",
            Self::LocalCompile => "local_compile",
            Self::PublishOutputs => "publish_outputs",
            Self::PackResult => "pack_result",
            Self::RecordResult => "record_result",
            Self::WriteCache => "write_cache",
            Self::SendReply => "send_reply",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceOutcome {
    Hit,
    Miss,
    Local,
    Worker,
    Uncacheable,
    Success,
    Failed,
    Cancelled,
    Abandoned,
}

impl TraceOutcome {
    const fn name(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Local => "local",
            Self::Worker => "worker",
            Self::Uncacheable => "uncacheable",
            Self::Success => "success",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Abandoned => "abandoned",
        }
    }

    const fn error(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled | Self::Abandoned)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Transition {
    phase: Phase,
    offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum IntervalKind {
    JobserverWait,
    CompilerChild,
}

impl IntervalKind {
    const fn name(self) -> &'static str {
        match self {
            Self::JobserverWait => "jobserver_wait",
            Self::CompilerChild => "compiler_child",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Interval {
    kind: IntervalKind,
    start: u64,
    end: u64,
}

/// Complete, bounded history from the process that owns the compilation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceHistory {
    start: u64,
    elapsed: u64,
    transitions: Vec<Transition>,
    intervals: Vec<Interval>,
    omitted_transitions: u64,
    omitted_intervals: u64,
    outcome: Option<TraceOutcome>,
    action: Option<crate::build_runtime::ActionKey>,
}

impl TraceHistory {
    pub(crate) fn new() -> Self {
        Self {
            start: unix_nanos(),
            elapsed: 0,
            transitions: vec![Transition {
                phase: Phase::DetectCompiler,
                offset: 0,
            }],
            intervals: Vec::new(),
            omitted_transitions: 0,
            omitted_intervals: 0,
            outcome: None,
            action: None,
        }
    }

    fn transition(&mut self, phase: Phase, offset: u64) {
        if self.transitions.len() < MAX_TRACE_INTERVALS {
            self.transitions.push(Transition { phase, offset });
        } else {
            self.omitted_transitions = self.omitted_transitions.saturating_add(1);
        }
    }

    fn interval(&mut self, kind: IntervalKind, start: u64, end: u64) {
        if self.intervals.len() < MAX_TRACE_INTERVALS {
            self.intervals.push(Interval { kind, start, end });
        } else {
            self.omitted_intervals = self.omitted_intervals.saturating_add(1);
        }
    }

    fn valid(&self) -> bool {
        self.transitions.len() <= MAX_TRACE_INTERVALS
            && self.intervals.len() <= MAX_TRACE_INTERVALS
            && self
                .transitions
                .first()
                .is_some_and(|first| first.offset == 0)
            && self
                .transitions
                .windows(2)
                .all(|pair| pair[0].offset <= pair[1].offset)
            && self
                .transitions
                .last()
                .is_some_and(|last| last.offset <= self.elapsed)
            && self
                .intervals
                .iter()
                .all(|interval| interval.start <= interval.end && interval.end <= self.elapsed)
    }

    fn append_spans(
        &self,
        parent: TraceContext,
        start: u64,
        end: u64,
        spans: &mut Vec<LatencySpan>,
    ) {
        let boundary = self.start.saturating_add(self.elapsed).min(end);
        for (index, transition) in self.transitions.iter().enumerate() {
            let from = self
                .start
                .saturating_add(transition.offset)
                .clamp(start, end);
            let until = self
                .transitions
                .get(index + 1)
                .map_or(boundary, |next| self.start.saturating_add(next.offset))
                .clamp(from, end);
            // Once the history is truncated the final transition has an
            // unknown end; never attribute the omitted tail to that phase.
            if index + 1 == self.transitions.len() && self.omitted_transitions != 0 {
                break;
            }
            spans.push(LatencySpan::child(
                parent,
                "sccache-client",
                transition.phase.trace_name(),
                from,
                until,
            ));
        }
        for interval in &self.intervals {
            let from = self.start.saturating_add(interval.start).clamp(start, end);
            let until = self.start.saturating_add(interval.end).clamp(from, end);
            spans.push(LatencySpan::child(
                parent,
                "sccache-client",
                interval.kind.name(),
                from,
                until,
            ));
        }
    }
}

/// Snapshot of one request, using monotonic elapsed time instead of wall time.
/// No command arguments or environment variables are exposed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileActivity {
    pub id: String,
    pub client_pid: u32,
    pub owner: CompileOwner,
    pub output: Option<String>,
    pub compiler: String,
    pub cwd: String,
    pub phase: Phase,
    pub phase_sequence: u64,
    /// Age of last caller observation (namespace requests only).
    pub observation_age_ms: Option<u64>,
    pub cancellation_requested: bool,
    pub elapsed_ms: u64,
    pub phase_age_ms: u64,
    pub waiting_for_jobserver: usize,
    pub compiler_children: usize,
    pub distributed_job: Option<u64>,
    pub worker: Option<String>,
    pub trace: TraceHistory,
}

struct State {
    sequence: u64,
    observed: Option<Instant>,
    output: Option<String>,
    phase: Phase,
    changed: Instant,
    waiting_for_jobserver: usize,
    compiler_children: usize,
    distributed_job: Option<u64>,
    worker: Option<String>,
    history: TraceHistory,
    remote_history: Option<TraceHistory>,
}

pub(crate) struct Activity {
    id: String,
    client_pid: u32,
    owner: CompileOwner,
    compiler: String,
    cwd: String,
    started: Instant,
    pub(super) cancellation: CancellationToken,
    state: Mutex<State>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl Activity {
    pub(crate) fn new(id: String, identity: &CompileIdentity, owner: CompileOwner) -> Self {
        let now = Instant::now();
        Self {
            id,
            client_pid: identity.client_pid,
            owner,
            compiler: Path::new(&identity.exe)
                .file_name()
                .unwrap_or(identity.exe.as_os_str())
                .to_string_lossy()
                .into_owned(),
            cwd: identity.cwd.to_string_lossy().into_owned(),
            started: now,
            cancellation: CancellationToken::new(),
            state: Mutex::new(State {
                sequence: 0,
                observed: None,
                output: None,
                phase: Phase::DetectCompiler,
                changed: now,
                waiting_for_jobserver: 0,
                compiler_children: 0,
                distributed_job: None,
                worker: None,
                history: TraceHistory::new(),
                remote_history: None,
            }),
        }
    }

    pub(super) fn phase(&self, phase: Phase) {
        let mut state = lock(&self.state);
        if state.phase != phase {
            state.phase = phase;
            state.sequence = state.sequence.saturating_add(1);
            state.changed = Instant::now();
            let offset = nanos(state.changed.duration_since(self.started));
            state.history.transition(phase, offset);
        }
    }

    pub(crate) fn snapshot(&self) -> CompileActivity {
        let state = lock(&self.state);
        let now = Instant::now();
        let mut history = state
            .remote_history
            .clone()
            .unwrap_or_else(|| state.history.clone());
        if state.remote_history.is_none() {
            history.elapsed = nanos(now.duration_since(self.started));
        }
        CompileActivity {
            id: self.id.clone(),
            client_pid: self.client_pid,
            owner: self.owner,
            output: state.output.clone(),
            compiler: self.compiler.clone(),
            cwd: self.cwd.clone(),
            phase: state.phase,
            phase_sequence: state.sequence,
            observation_age_ms: state
                .observed
                .map(|received| millis(now.duration_since(received))),
            cancellation_requested: self.cancellation.is_cancelled(),
            elapsed_ms: millis(now.duration_since(self.started)),
            phase_age_ms: millis(now.duration_since(state.changed)),
            waiting_for_jobserver: state.waiting_for_jobserver,
            compiler_children: state.compiler_children,
            distributed_job: state.distributed_job,
            worker: state.worker.clone(),
            trace: history,
        }
    }

    // The caller supplies monotonic elapsed phase time, not an absolute
    // clock value. Repeated observations of a phase can never renew it.
    pub(super) fn observe(&self, sample: CompileActivity) -> Result<()> {
        ensure!(
            self.owner == CompileOwner::Namespace,
            "not a namespace activity"
        );
        self.apply_observation(sample)
    }

    // Only the private, daemon-spawned executor pipe calls this. The public
    // observation RPC remains restricted to namespace-owned compilation.
    #[cfg(target_os = "linux")]
    pub(super) fn observe_executor(&self, sample: CompileActivity) -> Result<()> {
        ensure!(self.owner == CompileOwner::Daemon, "not a daemon activity");
        self.apply_observation(sample)
    }

    fn apply_observation(&self, sample: CompileActivity) -> Result<()> {
        ensure!(
            sample.owner == self.owner
                && sample.id == self.id
                && sample.client_pid == self.client_pid
                && sample.compiler == self.compiler
                && sample.cwd == self.cwd,
            "compile observation identity mismatch"
        );
        ensure!(sample.trace.valid(), "invalid compile trace history");
        let now = Instant::now();
        let age = Duration::from_millis(sample.phase_age_ms).min(now.duration_since(self.started));
        let changed = now - age;
        let mut state = lock(&self.state);
        match sample.phase_sequence.cmp(&state.sequence) {
            std::cmp::Ordering::Less => anyhow::bail!("out-of-order namespace compile observation"),
            std::cmp::Ordering::Equal => {
                ensure!(
                    sample.phase == state.phase,
                    "inconsistent namespace phase sequence"
                );
                state.changed = state.changed.min(changed);
            }
            std::cmp::Ordering::Greater => {
                state.sequence = sample.phase_sequence;
                state.phase = sample.phase;
                state.changed = changed;
            }
        }
        if let Some(previous) = &state.remote_history {
            ensure!(
                sample.trace.start == previous.start
                    && sample.trace.elapsed >= previous.elapsed
                    && sample.trace.transitions.starts_with(&previous.transitions)
                    && sample.trace.intervals.starts_with(&previous.intervals),
                "inconsistent remote trace history"
            );
        }
        state.observed = Some(now);
        state.output = sample.output;
        state.waiting_for_jobserver = sample.waiting_for_jobserver;
        state.compiler_children = sample.compiler_children;
        state.distributed_job = sample.distributed_job;
        state.worker = sample.worker;
        state.remote_history = Some(sample.trace);
        drop(state);
        Ok(())
    }

    pub(crate) fn outcome(&self, outcome: TraceOutcome) {
        lock(&self.state).history.outcome = Some(outcome);
    }

    pub(super) fn finished(&self, result: &CompileFinished) {
        let mut state = lock(&self.state);
        if let Some(report) = result.native {
            state.history.action = Some(report.key);
            state.history.outcome = Some(match report.source {
                NativeBuildSource::Hit => TraceOutcome::Hit,
                NativeBuildSource::Local => TraceOutcome::Local,
                NativeBuildSource::Worker(_) => TraceOutcome::Worker,
            });
        }
        if result.retcode != Some(0) || result.signal.is_some() {
            state.history.outcome = Some(TraceOutcome::Failed);
        } else if state.history.outcome.is_none()
            && state
                .remote_history
                .as_ref()
                .and_then(|history| history.outcome)
                .is_none()
        {
            state.history.outcome = Some(TraceOutcome::Success);
        }
    }

    fn export(&self) {
        if !crate::latency_trace::enabled() {
            return;
        }
        let state = lock(&self.state);
        let mut history = state.history.clone();
        history.elapsed = nanos(self.started.elapsed());
        let context = TraceContext::request(&self.id);
        let start = history.start;
        let end = start.saturating_add(history.elapsed);
        let remote = state.remote_history.clone();
        let outcome = if self.cancellation.is_cancelled() {
            TraceOutcome::Cancelled
        } else {
            history
                .outcome
                .or_else(|| remote.as_ref().and_then(|history| history.outcome))
                .unwrap_or(TraceOutcome::Abandoned)
        };
        let mut attributes = vec![
            ("sccache.request_id", self.id.clone()),
            ("sccache.compiler", self.compiler.clone()),
            ("sccache.outcome", outcome.name().into()),
        ];
        if let Some(output) = &state.output {
            attributes.push(("sccache.output", output.clone()));
        }
        if let Some(worker) = &state.worker {
            attributes.push(("sccache.worker", worker.clone()));
        }
        if let Some(job) = state.distributed_job {
            attributes.push(("sccache.job_id", job.to_string()));
        }
        if let Some(action) = history
            .action
            .or_else(|| remote.as_ref().and_then(|history| history.action))
        {
            attributes.push((
                "sccache.action_key",
                blake3::Hash::from_bytes(action.0).to_hex().to_string(),
            ));
        }
        drop(state);
        let omitted = history
            .omitted_transitions
            .saturating_add(history.omitted_intervals)
            .saturating_add(remote.as_ref().map_or(0, |history| {
                history
                    .omitted_transitions
                    .saturating_add(history.omitted_intervals)
            }));
        if omitted != 0 {
            attributes.push(("sccache.omitted_intervals", omitted.to_string()));
        }
        let mut spans = vec![LatencySpan {
            context,
            parent: None,
            service: "sccache-client",
            name: "compile",
            start,
            end,
            attributes,
            error: outcome.error(),
        }];
        if let Some(remote) = remote {
            let child_start = remote.start.clamp(start, end);
            let child_end = remote
                .start
                .saturating_add(remote.elapsed)
                .clamp(child_start, end);
            if child_start > start {
                spans.push(LatencySpan::child(
                    context,
                    "sccache-client",
                    "executor_startup",
                    start,
                    child_start,
                ));
            }
            remote.append_spans(context, child_start, child_end, &mut spans);
            // Only local transitions after the child returns are real local
            // work. The initial local DetectCompiler phase is an observer.
            if let Some(transition) = history
                .transitions
                .iter()
                .find(|transition| start.saturating_add(transition.offset) >= child_end)
            {
                let after = start.saturating_add(transition.offset).min(end);
                if after > child_end {
                    spans.push(LatencySpan::child(
                        context,
                        "sccache-client",
                        "executor_return",
                        child_end,
                        after,
                    ));
                }
                history.append_spans(context, after, end, &mut spans);
                spans.retain(|span| span.parent.is_none() || span.end > span.start);
            } else if end > child_end {
                spans.push(LatencySpan::child(
                    context,
                    "sccache-client",
                    "executor_return",
                    child_end,
                    end,
                ));
            }
        } else {
            history.append_spans(context, start, end, &mut spans);
        }
        crate::latency_trace::submit(spans);
    }
}

impl CompileActivity {
    pub(super) fn deadline_error(&self, limits: CompileLimits) -> Option<String> {
        let snapshot = self;
        if snapshot.cancellation_requested {
            Some(format!(
                "compile request {} cancellation requested during {:?}; outcome unknown",
                snapshot.id, snapshot.phase
            ))
        } else if Duration::from_millis(snapshot.phase_age_ms) >= limits.budget(snapshot.phase) {
            Some(format!(
                "compile request {} exceeded its {:?} phase deadline after {} ms; outcome unknown",
                snapshot.id, snapshot.phase, snapshot.phase_age_ms
            ))
        } else {
            None
        }
    }
}

pub(super) struct Registry {
    generation: u64,
    next: AtomicU64,
    active: Mutex<BTreeMap<String, Arc<Activity>>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            generation: rand::random(),
            next: AtomicU64::default(),
            active: Mutex::default(),
        }
    }
}

impl Registry {
    pub(super) fn begin(&self, compile: &Compile) -> Registration<'_> {
        self.register(&CompileIdentity::from(compile), CompileOwner::Daemon)
    }

    pub(super) fn register(
        &self,
        identity: &CompileIdentity,
        owner: CompileOwner,
    ) -> Registration<'_> {
        let sequence = self.next.fetch_add(1, Ordering::Relaxed);
        let id = format!("{:016x}-{sequence:x}", self.generation);
        let activity = Arc::new(Activity::new(id.clone(), identity, owner));
        lock(&self.active).insert(id, Arc::clone(&activity));
        Registration {
            registry: self,
            activity,
        }
    }

    pub(super) fn cancel(&self, id: &str) -> bool {
        let activity = lock(&self.active).get(id).cloned();
        activity.is_some_and(|activity| {
            activity.cancellation.cancel();
            true
        })
    }

    pub(super) fn snapshots(&self) -> Vec<CompileActivity> {
        lock(&self.active)
            .values()
            .map(|activity| activity.snapshot())
            .collect()
    }
}

pub(super) struct Registration<'a> {
    registry: &'a Registry,
    pub(super) activity: Arc<Activity>,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        lock(&self.registry.active).remove(&self.activity.id);
        self.activity.export();
    }
}

tokio::task_local! {
    static CURRENT: Option<Arc<Activity>>;
}

/// Explicitly propagate telemetry context into spawned compiler tasks.
/// It affects observation only, never the compiler arguments or cache key.
pub(super) fn inherit<F: Future>(future: F) -> impl Future<Output = F::Output> {
    CURRENT.scope(CURRENT.try_with(Clone::clone).ok().flatten(), future)
}

pub(crate) fn scope<F: Future>(
    activity: &Arc<Activity>,
    future: F,
) -> impl Future<Output = F::Output> {
    CURRENT.scope(Some(Arc::clone(activity)), future)
}

#[cfg(target_os = "linux")]
pub(crate) fn current() -> Option<Arc<Activity>> {
    CURRENT.try_with(Clone::clone).ok().flatten()
}

#[cfg(all(target_os = "linux", feature = "dist-client"))]
pub(crate) fn inherit_blocking<F: FnOnce() -> R, R>(work: F) -> impl FnOnce() -> R {
    let activity = current();
    move || CURRENT.sync_scope(activity, work)
}

#[cfg(all(target_os = "linux", feature = "dist-client"))]
pub(crate) fn sync_scope<F: FnOnce() -> R, R>(activity: Option<Arc<Activity>>, work: F) -> R {
    CURRENT.sync_scope(activity, work)
}

#[must_use = "downstream spans require the active request context"]
pub fn trace_context() -> Option<TraceContext> {
    CURRENT
        .try_with(|current| {
            current
                .as_ref()
                .map(|activity| TraceContext::request(&activity.id))
        })
        .ok()
        .flatten()
}

pub(super) fn outcome(outcome: TraceOutcome) {
    let _ = CURRENT.try_with(|current| {
        if let Some(activity) = current {
            activity.outcome(outcome);
        }
    });
}

pub(super) fn finished(result: &CompileFinished) {
    let _ = CURRENT.try_with(|current| {
        if let Some(activity) = current {
            activity.finished(result);
        }
    });
}

pub fn phase(phase: Phase) {
    let _ = CURRENT.try_with(|current| {
        if let Some(activity) = current {
            activity.phase(phase);
        }
    });
}

pub(super) fn output(name: String) {
    let _ = CURRENT.try_with(|current| {
        if let Some(activity) = current {
            lock(&activity.state).output = Some(name);
        }
    });
}

/// An actual child lifecycle; it can overlap other children during hashing.
pub struct ChildActivity {
    activity: Option<Arc<Activity>>,
    running: bool,
    since: Instant,
}

impl ChildActivity {
    pub fn waiting() -> Self {
        let activity = CURRENT.try_with(Clone::clone).ok().flatten();
        if let Some(activity) = &activity {
            lock(&activity.state).waiting_for_jobserver += 1;
        }
        Self {
            activity,
            running: false,
            since: Instant::now(),
        }
    }

    pub fn started(&mut self) {
        if !self.running {
            if let Some(activity) = &self.activity {
                let mut state = lock(&activity.state);
                state.waiting_for_jobserver -= 1;
                state.compiler_children += 1;
                let now = Instant::now();
                state.history.interval(
                    IntervalKind::JobserverWait,
                    nanos(self.since.duration_since(activity.started)),
                    nanos(now.duration_since(activity.started)),
                );
                self.since = now;
            }
            self.running = true;
        }
    }
}

impl Drop for ChildActivity {
    fn drop(&mut self) {
        if let Some(activity) = &self.activity {
            let mut state = lock(&activity.state);
            let kind = if self.running {
                IntervalKind::CompilerChild
            } else {
                IntervalKind::JobserverWait
            };
            state.history.interval(
                kind,
                nanos(self.since.duration_since(activity.started)),
                nanos(activity.started.elapsed()),
            );
            if self.running {
                state.compiler_children -= 1;
            } else {
                state.waiting_for_jobserver -= 1;
            }
        }
    }
}

#[cfg(feature = "dist-client")]
pub fn job(id: u64, worker: String) {
    let _ = CURRENT.try_with(|current| {
        if let Some(activity) = current {
            let mut state = lock(&activity.state);
            state.distributed_job = Some(id);
            state.worker = Some(worker);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn executor_observations_preserve_daemon_deadlines() -> Result<()> {
        let identity = CompileIdentity {
            client_pid: 42,
            exe: "/usr/bin/rustc".into(),
            cwd: "/build".into(),
        };
        let registry = Registry::default();
        let registration = registry.register(&identity, CompileOwner::Daemon);
        let parent = &registration.activity;
        let child = Activity::new(parent.snapshot().id, &identity, CompileOwner::Daemon);
        let limits = CompileLimits {
            phase_timeout_secs: 10,
            execution_timeout_secs: 30,
        };
        child.phase(Phase::PlanCompile);
        tokio::time::advance(Duration::from_secs(6)).await;
        parent.observe_executor(child.snapshot())?;
        assert_eq!(parent.snapshot().phase_age_ms, 6000);
        assert!(parent.observe(child.snapshot()).is_err());
        let mut invalid = child.snapshot();
        invalid.client_pid += 1;
        assert!(parent.observe_executor(invalid).is_err());
        tokio::time::advance(Duration::from_secs(5)).await;
        let mut stale = child.snapshot();
        stale.phase_age_ms = 0;
        parent.observe_executor(stale)?;
        assert!(parent.snapshot().deadline_error(limits).is_some());
        child.phase(Phase::RunDistributed);
        parent.observe_executor(child.snapshot())?;
        assert!(parent.snapshot().deadline_error(limits).is_none());
        assert_eq!(parent.snapshot().owner, CompileOwner::Daemon);
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "dist-client"))]
    #[tokio::test]
    async fn native_blocking_assignment_reaches_parent_observer() -> Result<()> {
        let identity = CompileIdentity {
            client_pid: 42,
            exe: "/usr/bin/rustc".into(),
            cwd: "/build".into(),
        };
        let parent = Activity::new("native".into(), &identity, CompileOwner::Daemon);
        let child = Arc::new(Activity::new(
            parent.snapshot().id,
            &identity,
            CompileOwner::Daemon,
        ));
        scope(&child, async {
            tokio::task::spawn_blocking(inherit_blocking(|| {
                phase(Phase::AllocateWorker);
                job(123, "worker-a".into());
                phase(Phase::StageInputs);
            }))
            .await
        })
        .await?;
        parent.observe_executor(child.snapshot())?;
        let snapshot = parent.snapshot();
        assert_eq!(snapshot.phase, Phase::StageInputs);
        assert_eq!(snapshot.distributed_job, Some(123));
        assert_eq!(snapshot.worker.as_deref(), Some("worker-a"));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn caller_observation_cannot_renew_same_phase_and_preserves_transition_age() -> Result<()>
    {
        let identity = CompileIdentity {
            client_pid: 17,
            exe: "/usr/bin/rustc".into(),
            cwd: "/build".into(),
        };
        let registry = Registry::default();
        let registration = registry.register(&identity, CompileOwner::Namespace);
        let daemon = &registration.activity;
        let caller = Activity::new(daemon.snapshot().id, &identity, CompileOwner::Namespace);
        let limits = CompileLimits {
            phase_timeout_secs: 10,
            execution_timeout_secs: 30,
        };
        tokio::time::advance(Duration::from_secs(5)).await;
        daemon.observe(caller.snapshot())?;
        assert_eq!(daemon.snapshot().phase_age_ms, 5000);
        tokio::time::advance(Duration::from_secs(6)).await;
        let mut stale = caller.snapshot();
        stale.phase_age_ms = 0;
        daemon.observe(stale)?;
        assert_eq!(daemon.snapshot().phase_age_ms, 11000);
        assert!(daemon.snapshot().deadline_error(limits).is_some());

        // A caller may leave and reenter the same named phase between
        // observations. Its real sequence/age, not the receipt time, wins.
        caller.phase(Phase::HashInputs);
        caller.phase(Phase::DetectCompiler);
        tokio::time::advance(Duration::from_secs(3)).await;
        daemon.observe(caller.snapshot())?;
        let snapshot = daemon.snapshot();
        assert_eq!(snapshot.phase_sequence, 2);
        assert_eq!(
            snapshot
                .trace
                .transitions
                .iter()
                .map(|transition| transition.phase)
                .collect::<Vec<_>>(),
            vec![
                Phase::DetectCompiler,
                Phase::HashInputs,
                Phase::DetectCompiler
            ]
        );
        assert_eq!(snapshot.trace.transitions[1].offset, 11_000_000_000);
        assert_eq!(snapshot.phase_age_ms, 3000);
        assert_eq!(snapshot.observation_age_ms, Some(0));
        assert!(snapshot.deadline_error(limits).is_none());
        let mut invalid = caller.snapshot();
        invalid.phase_sequence = 1;
        assert!(daemon.observe(invalid).is_err());
        assert!(registry.cancel(&snapshot.id));
        assert!(daemon.snapshot().deadline_error(limits).is_some());
        Ok(())
    }

    #[tokio::test]
    async fn phase_context_survives_spawn_and_registration_cancels() -> anyhow::Result<()> {
        let registry = Registry::default();
        let request = Compile {
            client_pid: std::process::id(),
            exe: "/usr/bin/rustc".into(),
            cwd: "/build".into(),
            args: vec!["private argument".into()],
            env_vars: vec![("PRIVATE".into(), "secret".into())],
        };
        let first = registry.begin(&request);
        let second = registry.begin(&request);
        assert_ne!(first.activity.id, second.activity.id);
        scope(&first.activity, async {
            phase(Phase::HashInputs);
            tokio::spawn(inherit(async { phase(Phase::CacheLookup) })).await
        })
        .await?;
        assert_eq!(first.activity.snapshot().phase, Phase::CacheLookup);
        assert_eq!(second.activity.snapshot().phase, Phase::DetectCompiler);
        scope(&first.activity, async {
            let mut child = ChildActivity::waiting();
            assert_eq!(first.activity.snapshot().waiting_for_jobserver, 1);
            child.started();
            assert_eq!(first.activity.snapshot().waiting_for_jobserver, 0);
            assert_eq!(first.activity.snapshot().compiler_children, 1);
            drop(child);
            assert_eq!(first.activity.snapshot().compiler_children, 0);
        })
        .await;
        let changed = lock(&first.activity.state).changed;
        scope(&first.activity, async { phase(Phase::CacheLookup) }).await;
        assert_eq!(lock(&first.activity.state).changed, changed);
        let json = serde_json::to_string(&registry.snapshots())?;
        assert!(!json.contains("private argument") && !json.contains("secret"));
        drop(first);
        assert_eq!(registry.snapshots().len(), 1);
        drop(second);
        assert!(registry.snapshots().is_empty());
        Ok(())
    }
}
