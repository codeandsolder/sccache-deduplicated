//! Execute a frontend-supplied DAG through the existing managed compiler client.
//! The plan controls readiness; the daemon still owns worker admission and
//! content-addressed artifacts. No compiler wrapper process is spawned per node.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    io::{self, BufReader},
    num::NonZeroUsize,
    os::unix::ffi::OsStrExt as _,
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Mutex, mpsc},
    thread,
};

use anyhow::{Context, Result, ensure};
use sccache_build::{
    BuildGraph, BuildPlan, PlanAction, PlanCommand, PlanConnection, PlanNode, PlannerReply,
    PlannerRequest,
};

use crate::{
    commands::{CompileInvocation, CompileSession},
    config::Config,
};

fn environment(command: &PlanCommand) -> Vec<(OsString, OsString)> {
    let mut env: BTreeMap<_, _> = if command.inherit_environment {
        std::env::vars_os().collect()
    } else {
        BTreeMap::new()
    };
    for change in &command.environment {
        let name = OsStr::from_bytes(&change.name);
        match &change.value {
            Some(value) => {
                env.insert(name.to_owned(), OsStr::from_bytes(value).to_owned());
            }
            None => {
                env.remove(name);
            }
        }
    }
    // Never inherit a stale external Cargo/make jobserver. Local actions use
    // the session's jobserver instead; remote jobs use worker admission.
    for name in ["CARGO_MAKEFLAGS", "MAKEFLAGS", "MFLAGS"] {
        env.remove(OsStr::new(name));
    }
    env.into_iter().collect()
}

fn invocation(command: &PlanCommand) -> CompileInvocation<'_> {
    CompileInvocation {
        exe: BuildPlan::path(&command.executable),
        cwd: BuildPlan::path(&command.cwd),
        cmdline: command
            .arguments
            .iter()
            .map(|arg| OsStr::from_bytes(arg).to_owned())
            .collect(),
        env_vars: environment(command),
    }
}

fn publish(source: &Path, destination: &Path) -> Result<()> {
    // Use a sibling temporary file and atomic rename, so consumers never
    // observe partially installed final artifacts.
    let parent = destination.parent().context("publication has no parent")?;
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    fs::copy(source, temporary.path())?;
    temporary.persist(destination)?;
    Ok(())
}

fn execute_node(session: &CompileSession<'_>, node: &PlanNode, action: &PlanAction) -> Result<()> {
    node.validate_action(action)?;
    for directory in &node.directories {
        fs::create_dir_all(BuildPlan::path(directory))?;
    }
    match action {
        PlanAction::Deferred => anyhow::bail!("unresolved build action"),
        PlanAction::Noop => {}
        PlanAction::Compile { command } => {
            let code =
                session.execute(invocation(command), &mut io::stdout(), &mut io::stderr())?;
            ensure!(code == 0, "compiler exited with status {code}");
        }
        PlanAction::Process {
            command,
            stdout,
            stderr,
        } => {
            let invocation = invocation(command);
            let mut process = Command::new(invocation.exe);
            process
                .args(invocation.cmdline)
                .current_dir(invocation.cwd)
                .env_clear()
                .envs(invocation.env_vars)
                .stdin(Stdio::null());
            if let Some(output) = stdout {
                process.stdout(fs::File::create(BuildPlan::path(output))?);
            }
            if let Some(output) = stderr {
                process.stderr(fs::File::create(BuildPlan::path(output))?);
            }
            let status = session.execute_process(&mut process)?;
            ensure!(status.success(), "process exited with {status}");
        }
        PlanAction::Publish {
            source,
            destination,
        } => {
            publish(BuildPlan::path(source), BuildPlan::path(destination))?;
        }
    }
    for output in &node.required_outputs {
        ensure!(
            BuildPlan::path(output).try_exists()?,
            "successful action did not produce {:?}",
            BuildPlan::path(output)
        );
    }
    Ok(())
}

/// Dispatch the ready frontier with a bound on outstanding requests, not a
/// CPU quota. Do not send dependent actions until their artifacts are ready.
/// After a failure, drain already submitted requests before returning.
fn dispatch(
    mut graph: BuildGraph,
    max_in_flight: NonZeroUsize,
    execute: impl Fn(usize) -> Result<()> + Sync,
) -> Result<()> {
    thread::scope(|scope| {
        let (sender, receiver) = mpsc::channel();
        let mut active = 0;
        let mut failure = None;
        while !graph.is_complete() {
            while failure.is_none() && active < max_in_flight.get() {
                let Some(index) = graph.take_ready() else {
                    break;
                };
                let send = sender.clone();
                let execute = &execute;
                thread::Builder::new().spawn_scoped(scope, move || {
                    // A worker panic must not leave the dispatcher blocked on
                    // a completion message that can never be sent.
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| execute(index)))
                            .unwrap_or_else(|_| {
                                Err(anyhow::anyhow!("build node {index} panicked"))
                            });
                    let _ = send.send((index, result));
                })?;
                active += 1;
            }
            if active == 0 {
                break;
            }
            let (index, result) = receiver.recv()?;
            active -= 1;
            match result {
                Ok(()) => graph.complete(index)?,
                Err(error) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        ensure!(graph.is_complete(), "build graph stalled");
        Ok(())
    })
}

pub(crate) fn execute(path: &Path, max_in_flight: NonZeroUsize, config: &Config) -> Result<()> {
    let file =
        fs::File::open(path).with_context(|| format!("open build plan {}", path.display()))?;
    let plan: BuildPlan = serde_json::from_reader(io::BufReader::new(file))?;
    let graph = plan.graph()?;
    ensure!(
        plan.nodes
            .iter()
            .all(|node| !matches!(node.action, PlanAction::Deferred)),
        "offline build plan contains deferred actions"
    );
    let session = CompileSession::new(config, true)?;
    dispatch(graph, max_in_flight, |index| {
        let node = &plan.nodes[index];
        execute_node(&session, node, &node.action)
            .with_context(|| format!("build node {index}: {}", node.label))
    })
}

/// A live planner is a command materializer, not a second job scheduler.
/// Requests are serialized because Cargo's workspace model is single-threaded;
/// execution and dependency admission remain concurrent.
struct PlannerClient {
    connection: PlanConnection<BufReader<ChildStdout>, ChildStdin>,
    child: Child,
}

impl PlannerClient {
    fn start(executable: &Path, args: &[OsString]) -> Result<(Self, BuildPlan)> {
        let mut child = Command::new(executable)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .context("start build planner")?;
        let stdin = child.stdin.take().context("missing planner stdin")?;
        let stdout = child.stdout.take().context("missing planner stdout")?;
        let mut client = Self {
            connection: PlanConnection::new(BufReader::new(stdout), stdin),
            child,
        };
        let PlannerReply::Plan { plan } = client.reply()? else {
            anyhow::bail!("planner did not send a build graph");
        };
        Ok((client, plan))
    }

    fn reply(&mut self) -> Result<PlannerReply> {
        match self.connection.receive()? {
            PlannerReply::Error { message } => anyhow::bail!("planner: {message}"),
            reply => Ok(reply),
        }
    }

    fn request(&mut self, request: &PlannerRequest) -> Result<PlannerReply> {
        self.connection.send(request)?;
        self.reply()
    }

    fn prepare(&mut self, index: usize) -> Result<PlanAction> {
        let PlannerReply::Action {
            index: returned,
            action,
        } = self.request(&PlannerRequest::Prepare { index })?
        else {
            anyhow::bail!("expected prepared action");
        };
        ensure!(returned == index, "planner returned the wrong node");
        ensure!(
            !matches!(action, PlanAction::Deferred),
            "planner returned an unresolved action"
        );
        Ok(action)
    }

    fn complete(&mut self, index: usize) -> Result<()> {
        let PlannerReply::Completed { index: returned } =
            self.request(&PlannerRequest::Complete { index })?
        else {
            anyhow::bail!("expected completed action");
        };
        ensure!(returned == index, "planner completed the wrong node");
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        ensure!(
            matches!(
                self.request(&PlannerRequest::Finish)?,
                PlannerReply::Finished
            ),
            "planner did not finish"
        );
        ensure!(
            self.child.wait()?.success(),
            "planner exited unsuccessfully"
        );
        Ok(())
    }
}

impl Drop for PlannerClient {
    fn drop(&mut self) {
        // Dispatch has drained all accepted actions before this runs. Reap
        // the planner so it cannot retain source-cache or layout locks.
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub(crate) fn execute_planner(
    executable: &Path,
    args: &[OsString],
    max_in_flight: NonZeroUsize,
    config: &Config,
) -> Result<()> {
    let (client, plan) = PlannerClient::start(executable, args)?;
    let graph = plan.graph()?;
    let client = Mutex::new(client);
    let session = CompileSession::new(config, true)?;
    let planner = || {
        client
            .lock()
            .map_err(|_| anyhow::anyhow!("planner lock poisoned"))
    };
    dispatch(graph, max_in_flight, |index| {
        let node = &plan.nodes[index];
        (|| {
            let action = if matches!(node.action, PlanAction::Deferred) {
                Some(planner()?.prepare(index)?)
            } else {
                None
            };
            execute_node(&session, node, action.as_ref().unwrap_or(&node.action))?;
            if action.is_some() {
                planner()?.complete(index)?;
            }
            Ok(())
        })()
        .with_context(|| format!("build node {index}: {}", node.label))
    })?;
    planner()?.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Barrier, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn independent_nodes_run_concurrently_and_join_observes_completion() -> Result<()> {
        let graph = BuildGraph::new(&[vec![], vec![], vec![0, 1]], &[1, 1, 1])?;
        let barrier = Barrier::new(2);
        let completed = Mutex::new(Vec::new());
        dispatch(
            graph,
            NonZeroUsize::new(2).context("invalid width")?,
            |index| {
                if index < 2 {
                    barrier.wait();
                } else {
                    assert_eq!(completed.lock().unwrap().len(), 2);
                }
                completed.lock().unwrap().push(index);
                Ok(())
            },
        )?;
        assert_eq!(completed.into_inner().unwrap().last(), Some(&2));
        Ok(())
    }

    #[test]
    fn failed_node_never_releases_dependents() -> Result<()> {
        let graph = BuildGraph::new(&[vec![], vec![0]], &[1, 1])?;
        let attempted = AtomicBool::new(false);
        let result = dispatch(graph, NonZeroUsize::MIN, |index| {
            if index == 0 {
                anyhow::bail!("failure");
            }
            attempted.store(true, Ordering::Relaxed);
            Ok(())
        });
        assert!(result.is_err());
        assert!(!attempted.load(Ordering::Relaxed));
        Ok(())
    }

    #[test]
    fn panic_is_reported_instead_of_waiting_for_a_lost_message() -> Result<()> {
        let graph = BuildGraph::new(&[vec![]], &[1])?;
        let result = dispatch(graph, NonZeroUsize::MIN, |_| panic!("injected panic"));
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn publication_replaces_final_file_atomically() -> Result<()> {
        let root = tempfile::tempdir()?;
        let input = root.path().join("input");
        let output = root.path().join("output");
        fs::write(&input, b"new result")?;
        fs::write(&output, b"old result")?;
        publish(&input, &output)?;
        assert_eq!(fs::read(output)?, b"new result");
        Ok(())
    }
}
