//! Observable compile-request lifetimes. Heartbeats prove transport liveness;
//! only actual phase transitions reset the phase deadline.

use crate::protocol::{Compile, CompileIdentity};
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
            }),
        }
    }

    pub(super) fn phase(&self, phase: Phase) {
        let mut state = lock(&self.state);
        if state.phase != phase {
            state.phase = phase;
            state.sequence = state.sequence.saturating_add(1);
            state.changed = Instant::now();
        }
    }

    pub(crate) fn snapshot(&self) -> CompileActivity {
        let state = lock(&self.state);
        let now = Instant::now();
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
        }
    }

    // The caller supplies monotonic elapsed phase time, not an absolute
    // clock value. Repeated observations of a phase can never renew it.
    pub(super) fn observe(&self, sample: CompileActivity) -> Result<()> {
        ensure!(
            self.owner == CompileOwner::Namespace
                && sample.owner == self.owner
                && sample.id == self.id
                && sample.client_pid == self.client_pid
                && sample.compiler == self.compiler
                && sample.cwd == self.cwd,
            "namespace compile observation identity mismatch"
        );
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
        state.observed = Some(now);
        state.output = sample.output;
        state.waiting_for_jobserver = sample.waiting_for_jobserver;
        state.compiler_children = sample.compiler_children;
        state.distributed_job = sample.distributed_job;
        state.worker = sample.worker;
        drop(state);
        Ok(())
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
        }
    }

    pub fn started(&mut self) {
        if !self.running {
            if let Some(activity) = &self.activity {
                let mut state = lock(&activity.state);
                state.waiting_for_jobserver -= 1;
                state.compiler_children += 1;
            }
            self.running = true;
        }
    }
}

impl Drop for ChildActivity {
    fn drop(&mut self) {
        if let Some(activity) = &self.activity {
            let mut state = lock(&activity.state);
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
