//! Observable compile-request lifetimes. Heartbeats prove transport liveness;
//! only actual phase transitions reset the phase deadline.

use crate::protocol::Compile;
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

/// Snapshot of one request, using monotonic elapsed time instead of wall time.
/// No command arguments or environment variables are exposed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileActivity {
    pub id: String,
    pub client_pid: u32,
    pub output: Option<String>,
    pub compiler: String,
    pub cwd: String,
    pub phase: Phase,
    pub cancellation_requested: bool,
    pub elapsed_ms: u64,
    pub phase_age_ms: u64,
    pub waiting_for_jobserver: usize,
    pub compiler_children: usize,
    pub distributed_job: Option<u64>,
    pub worker: Option<String>,
}

struct State {
    output: Option<String>,
    phase: Phase,
    changed: Instant,
    waiting_for_jobserver: usize,
    compiler_children: usize,
    distributed_job: Option<u64>,
    worker: Option<String>,
}

pub(super) struct Activity {
    id: String,
    client_pid: u32,
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
    pub(super) fn phase(&self, phase: Phase) {
        let mut state = lock(&self.state);
        if state.phase != phase {
            state.phase = phase;
            state.changed = Instant::now();
        }
    }

    pub(super) fn snapshot(&self) -> CompileActivity {
        let state = lock(&self.state);
        let now = Instant::now();
        CompileActivity {
            id: self.id.clone(),
            client_pid: self.client_pid,
            output: state.output.clone(),
            compiler: self.compiler.clone(),
            cwd: self.cwd.clone(),
            phase: state.phase,
            cancellation_requested: self.cancellation.is_cancelled(),
            elapsed_ms: millis(now.duration_since(self.started)),
            phase_age_ms: millis(now.duration_since(state.changed)),
            waiting_for_jobserver: state.waiting_for_jobserver,
            compiler_children: state.compiler_children,
            distributed_job: state.distributed_job,
            worker: state.worker.clone(),
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
        let sequence = self.next.fetch_add(1, Ordering::Relaxed);
        let id = format!("{:016x}-{sequence:x}", self.generation);
        let now = Instant::now();
        let activity = Arc::new(Activity {
            id: id.clone(),
            client_pid: compile.client_pid,
            compiler: Path::new(&compile.exe)
                .file_name()
                .unwrap_or(compile.exe.as_os_str())
                .to_string_lossy()
                .into_owned(),
            cwd: compile.cwd.to_string_lossy().into_owned(),
            started: now,
            cancellation: CancellationToken::new(),
            state: Mutex::new(State {
                output: None,
                phase: Phase::DetectCompiler,
                changed: now,
                waiting_for_jobserver: 0,
                compiler_children: 0,
                distributed_job: None,
                worker: None,
            }),
        });
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

pub(super) fn scope<F: Future>(
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
