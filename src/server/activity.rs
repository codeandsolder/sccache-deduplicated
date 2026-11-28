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
            Phase::HashInputs
            | Phase::RunDistributed
            | Phase::CompilerQuery
            | Phase::WaitForProducer => self.execution_timeout_secs,
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
    WaitForProducer,
    RestoreOutputs,
    PlanCompile,
    IdentifyToolchain,
    AllocateWorker,
    UploadToolchain,
    StageInputs,
    RunDistributed,
    CompilerQuery,
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
            Self::WaitForProducer => "wait_for_producer",
            Self::RestoreOutputs => "restore_outputs",
            Self::PlanCompile => "plan_compile",
            Self::IdentifyToolchain => "identify_toolchain",
            Self::AllocateWorker => "allocate_worker",
            Self::UploadToolchain => "upload_toolchain",
            Self::StageInputs => "stage_inputs",
            Self::RunDistributed => "run_distributed",
            Self::CompilerQuery => "compiler_query",
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
    producer: Option<TraceContext>,
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

/// Independent digests of the exact bytes fed to each key field. Retained
/// in executor observations because namespace children do not export OTLP.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct KeyEvidence {
    kind: String,
    digest: String,
    fields: Vec<(String, String)>,
    offset: u64,
}

impl KeyEvidence {
    fn valid(&self, elapsed: u64) -> bool {
        let digest =
            |value: &str| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit());
        self.kind.len() <= 64
            && self.kind.is_ascii()
            && digest(&self.digest)
            && self.offset <= elapsed
            && self.fields.len() <= 512
            && self
                .fields
                .iter()
                .all(|(name, value)| name.len() <= 256 && name.is_ascii() && digest(value))
    }
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
    key_evidence: Vec<KeyEvidence>,
}

impl TraceHistory {
    pub(crate) fn new() -> Self {
        Self {
            start: unix_nanos(),
            elapsed: 0,
            transitions: vec![Transition {
                phase: Phase::DetectCompiler,
                producer: None,
                offset: 0,
            }],
            intervals: Vec::new(),
            omitted_transitions: 0,
            omitted_intervals: 0,
            outcome: None,
            action: None,
            key_evidence: Vec::new(),
        }
    }

    fn transition(&mut self, phase: Phase, producer: Option<TraceContext>, offset: u64) {
        if self.transitions.len() < MAX_TRACE_INTERVALS {
            self.transitions.push(Transition {
                phase,
                producer,
                offset,
            });
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
            && self.key_evidence.len() <= 8
            && self
                .key_evidence
                .iter()
                .all(|evidence| evidence.valid(self.elapsed))
            && self
                .transitions
                .first()
                .is_some_and(|first| first.offset == 0)
            && self.transitions.iter().all(|transition| {
                transition.producer.is_none_or(|producer| {
                    transition.phase == Phase::WaitForProducer && producer.valid()
                })
            })
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
                .all(|interval| (interval.start..=self.elapsed).contains(&interval.end))
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
            let mut span = LatencySpan::phase(
                parent,
                "sccache-client",
                transition.phase.trace_name(),
                from,
                until,
            );
            if let Some(producer) = transition.producer {
                span.links.push(producer);
                span.attributes
                    .push(("sccache.producer_trace_id", producer.hex_id()));
            }
            spans.push(span);
        }
        for interval in &self.intervals {
            let from = self.start.saturating_add(interval.start).clamp(start, end);
            let until = self.start.saturating_add(interval.end).clamp(from, end);
            let mut span =
                LatencySpan::child(parent, "sccache-client", interval.kind.name(), from, until);
            span.attributes
                .push(("sccache.span_kind", "interval".into()));
            spans.push(span);
        }
        for evidence in &self.key_evidence {
            let at = self.start.saturating_add(evidence.offset).clamp(start, end);
            let mut span = LatencySpan::child(
                parent,
                "sccache-client",
                "cache_key_components",
                at.saturating_sub(1).max(start),
                at,
            );
            span.attributes
                .push(("sccache.key.kind", evidence.kind.clone()));
            span.attributes
                .push(("sccache.key.digest", evidence.digest.clone()));
            if let Ok(fields) = serde_json::to_string(&evidence.fields) {
                span.attributes.push(("sccache.key.components", fields));
            }
            spans.push(span);
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
    producer: Option<TraceContext>,
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
                producer: None,
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
        self.phase_with_producer(phase, None);
    }

    fn phase_with_producer(&self, phase: Phase, producer: Option<TraceContext>) {
        let mut state = lock(&self.state);
        if state.phase != phase || state.producer != producer {
            state.phase = phase;
            state.producer = producer;
            state.sequence = state.sequence.saturating_add(1);
            state.changed = Instant::now();
            let offset = nanos(state.changed.duration_since(self.started));
            state.history.transition(phase, producer, offset);
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
        if let Some(previous) = &state.remote_history {
            ensure!(
                sample.trace.start == previous.start
                    && sample.trace.elapsed >= previous.elapsed
                    && sample.trace.transitions.starts_with(&previous.transitions)
                    && sample.trace.intervals.starts_with(&previous.intervals)
                    && sample
                        .trace
                        .key_evidence
                        .starts_with(&previous.key_evidence),
                "inconsistent remote trace history"
            );
        }
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
        if let Some(report) = result.native.last() {
            state.history.action = Some(report.key);
            state.history.outcome = Some(
                if result
                    .native
                    .iter()
                    .any(|report| matches!(report.source, NativeBuildSource::Worker(_)))
                {
                    TraceOutcome::Worker
                } else {
                    TraceOutcome::Hit
                },
            );
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
            links: Vec::new(),
            service: "sccache-client",
            name: "compile",
            start,
            end,
            attributes,
            error: outcome.error(),
        }];
        append_request_spans(&history, remote.as_ref(), context, start, end, &mut spans);
        crate::latency_trace::submit(spans);
    }
}

fn append_request_spans(
    history: &TraceHistory,
    remote: Option<&TraceHistory>,
    context: TraceContext,
    start: u64,
    end: u64,
    spans: &mut Vec<LatencySpan>,
) {
    if let Some(remote) = remote {
        let child_start = remote.start.clamp(start, end);
        let child_end = remote
            .start
            .saturating_add(remote.elapsed)
            .clamp(child_start, end);
        let mut cursor = start;
        // The parent's only pre-child wait is executor admission, not
        // process startup or a physical compiler permit. Keep them separate.
        for interval in history
            .intervals
            .iter()
            .filter(|i| i.kind == IntervalKind::JobserverWait)
        {
            let from = history
                .start
                .saturating_add(interval.start)
                .clamp(cursor, child_start);
            let until = history
                .start
                .saturating_add(interval.end)
                .clamp(from, child_start);
            for (name, left, right) in [
                ("executor_startup", cursor, from),
                ("executor_admission", from, until),
            ] {
                if right > left {
                    spans.push(LatencySpan::phase(
                        context,
                        "sccache-client",
                        name,
                        left,
                        right,
                    ));
                }
            }
            cursor = until;
        }
        if child_start > cursor {
            spans.push(LatencySpan::phase(
                context,
                "sccache-client",
                "executor_startup",
                cursor,
                child_start,
            ));
        }
        remote.append_spans(context, child_start, child_end, spans);
        // Only local transitions after the child returns are real local
        // work. The initial local DetectCompiler phase is an observer.
        if let Some(transition) = history
            .transitions
            .iter()
            .find(|transition| start.saturating_add(transition.offset) >= child_end)
        {
            let after = start.saturating_add(transition.offset).min(end);
            if after > child_end {
                spans.push(LatencySpan::phase(
                    context,
                    "sccache-client",
                    "executor_return",
                    child_end,
                    after,
                ));
            }
            history.append_spans(context, after, end, spans);
            spans.retain(|span| span.parent.is_none() || span.end > span.start);
        } else if end > child_end {
            spans.push(LatencySpan::phase(
                context,
                "sccache-client",
                "executor_return",
                child_end,
                end,
            ));
        }
    } else {
        history.append_spans(context, start, end, spans);
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

    #[cfg(all(target_os = "linux", feature = "dist-client"))]
    fn live_snapshot(&self, instance: &str) -> crate::build_runtime::wire::LiveTraceBatch {
        use crate::build_runtime::wire::{LiveTraceBatch, LiveTraceRequest, MAX_LIVE_TRACE_ROWS};
        fn bounded_label(value: &str) -> String {
            value
                .chars()
                .filter(|ch| !ch.is_control())
                .scan(0, |bytes, ch| {
                    *bytes += ch.len_utf8();
                    (*bytes <= 256).then_some(ch)
                })
                .collect()
        }
        let mut selected = lock(&self.active).values().cloned().collect::<Vec<_>>();
        let active = u64::try_from(selected.len()).unwrap_or(u64::MAX);
        selected.sort_unstable_by_key(|activity| activity.started);
        selected.truncate(MAX_LIVE_TRACE_ROWS);
        let requests = selected
            .iter()
            .map(|activity| {
                let state = lock(&activity.state);
                let now = Instant::now();
                let producer = state
                    .remote_history
                    .as_ref()
                    .and_then(|history| history.transitions.last())
                    .filter(|transition| transition.phase == state.phase)
                    .and_then(|transition| transition.producer)
                    .or(state.producer);
                LiveTraceRequest {
                    trace: TraceContext::request(&activity.id),
                    compiler: bounded_label(&activity.compiler),
                    output: bounded_label(state.output.as_deref().unwrap_or_default()),
                    phase: state.phase.trace_name().into(),
                    elapsed_ms: millis(now.duration_since(activity.started)),
                    phase_age_ms: millis(now.duration_since(state.changed)),
                    worker: bounded_label(state.worker.as_deref().unwrap_or_default()),
                    job: state.distributed_job,
                    producer,
                }
            })
            .collect();
        LiveTraceBatch {
            generation: self.generation,
            instance: instance.to_owned(),
            active,
            requests,
        }
    }

    #[cfg(all(target_os = "linux", feature = "dist-client"))]
    pub(super) async fn report_live(
        self: Arc<Self>,
        client: Arc<crate::compiler::NativeCompilerClient>,
        instance: &'static str,
    ) {
        let mut ticker = tokio::time::interval(Duration::from_secs(2));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut active = false;
        loop {
            ticker.tick().await;
            let report = self.live_snapshot(instance);
            if active || report.active != 0 {
                active = report.active != 0;
                if let Err(error) = client.report_live_traces(&report).await {
                    // Retry empty reports too, so completed work is removed promptly.
                    active = true;
                    log::debug!("live trace observation unavailable: {error:#}");
                }
            }
        }
    }

    pub(super) fn snapshots(&self) -> Vec<CompileActivity> {
        let active = lock(&self.active).values().cloned().collect::<Vec<_>>();
        active.iter().map(|activity| activity.snapshot()).collect()
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

#[cfg(feature = "dist-client")]
pub fn wait_for_producer(producer: Option<TraceContext>) {
    let _ = CURRENT.try_with(|current| {
        if let Some(activity) = current {
            activity.phase_with_producer(Phase::WaitForProducer, producer);
        }
    });
}

/// Record independently comparable input digests, not the original values.
/// The bounded observation travels back to the daemon with the request trace.
pub(crate) fn key_evidence(kind: &str, digest: &str, fields: Vec<(&str, String)>) {
    let _ = CURRENT.try_with(|current| {
        if let Some(activity) = current {
            let mut state = lock(&activity.state);
            let offset = nanos(activity.started.elapsed());
            if state.history.key_evidence.len() < 8 {
                let evidence = KeyEvidence {
                    kind: kind.into(),
                    digest: digest.into(),
                    fields: fields
                        .into_iter()
                        .map(|(name, value)| (name.into(), value))
                        .collect(),
                    offset,
                };
                if evidence.valid(offset) {
                    state.history.key_evidence.push(evidence);
                }
            }
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
                drop(state);
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

    #[tokio::test(start_paused = true)]
    async fn waiting_spans_link_the_actual_producer_across_retries() {
        let identity = CompileIdentity {
            client_pid: 7,
            exe: "rustc".into(),
            cwd: "/build".into(),
        };
        let activity = Activity::new("waiting".into(), &identity, CompileOwner::Namespace);
        let first = TraceContext::request("producer-1");
        let second = TraceContext::request("producer-2");
        activity.phase(Phase::CacheLookup);
        activity.phase_with_producer(Phase::WaitForProducer, Some(first));
        tokio::time::advance(Duration::from_secs(2)).await;
        activity.phase_with_producer(Phase::WaitForProducer, Some(first));
        tokio::time::advance(Duration::from_secs(3)).await;
        activity.phase_with_producer(Phase::WaitForProducer, Some(second));
        tokio::time::advance(Duration::from_secs(7)).await;
        activity.phase(Phase::RestoreOutputs);
        let history = activity.snapshot().trace;
        let mut spans = Vec::new();
        let start = history.start;
        history.append_spans(
            TraceContext::request("waiting"),
            start,
            start + history.elapsed,
            &mut spans,
        );
        let waiting = spans
            .iter()
            .filter(|span| span.name == "wait_for_producer")
            .collect::<Vec<_>>();
        assert_eq!(waiting.len(), 2);
        assert_eq!(waiting[0].links, vec![first]);
        assert_eq!(waiting[0].end - waiting[0].start, 5_000_000_000);
        assert_eq!(waiting[1].links, vec![second]);
        assert_eq!(waiting[1].end - waiting[1].start, 7_000_000_000);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn key_audit_preserves_digest_and_reaches_daemon() -> Result<()> {
        let identity = CompileIdentity {
            client_pid: 42,
            exe: "/usr/bin/cc".into(),
            cwd: "/build".into(),
        };
        let parent = Activity::new("key-audit".into(), &identity, CompileOwner::Daemon);
        let child = Arc::new(Activity::new(
            parent.snapshot().id,
            &identity,
            CompileOwner::Daemon,
        ));
        let hash = |bytes: &[u8]| {
            let mut digest = crate::util::Digest::new();
            digest.update(bytes);
            digest.finish()
        };
        let key = scope(&child, async {
            let mut digest = crate::util::Digest::audited("test-key");
            digest.audit_field("first");
            digest.update(b"one");
            digest.audit_field("second");
            digest.update(b"two");
            digest.finish()
        })
        .await;
        assert_eq!(key, hash(b"onetwo"));
        parent.observe_executor(child.snapshot())?;
        let history = parent.snapshot().trace;
        let evidence = &history.key_evidence[0];
        assert_eq!(evidence.digest, key);
        assert_eq!(
            evidence.fields,
            vec![
                ("first".into(), hash(b"one")),
                ("second".into(), hash(b"two"))
            ]
        );
        let mut spans = Vec::new();
        history.append_spans(
            TraceContext::request("key-audit"),
            history.start,
            history.start + history.elapsed,
            &mut spans,
        );
        assert!(spans.iter().any(|span| span.name == "cache_key_components"));
        Ok(())
    }

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
