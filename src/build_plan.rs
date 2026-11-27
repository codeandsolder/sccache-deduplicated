//! Execute a frontend-supplied DAG through the existing managed compiler client.
//! The plan controls readiness; the daemon still owns worker admission and
//! content-addressed artifacts. No compiler wrapper process is spawned per node.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    io::{self, IsTerminal, Write},
    num::NonZeroUsize,
    os::unix::ffi::OsStrExt as _,
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
};

use anyhow::{Context, Result, ensure};
use sccache_build::{BuildGraph, BuildPlan, PlanAction, PlanCommand, PlanNode};

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

/// Cargo's compiler templates use structured rustc diagnostics. Render the
/// diagnostic payload, not the surrounding artifact/unused-extern events.
fn render_diagnostics(bytes: &[u8]) -> Result<()> {
    let mut stderr = io::stderr().lock();
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) {
            match value
                .get("$message_type")
                .and_then(serde_json::Value::as_str)
            {
                Some("diagnostic") => {
                    if let Some(rendered) =
                        value.get("rendered").and_then(serde_json::Value::as_str)
                    {
                        if stderr.is_terminal() {
                            stderr.write_all(rendered.as_bytes())?;
                        } else {
                            strip_ansi_escapes::Writer::new(&mut stderr)
                                .write_all(rendered.as_bytes())?;
                        }
                        continue;
                    }
                }
                Some("artifact" | "unused-externs" | "future-incompat") => continue,
                _ => {}
            }
        }
        stderr.write_all(line)?;
    }
    Ok(())
}

pub(crate) fn execute_node(
    session: &CompileSession<'_>,
    node: &PlanNode,
    action: &PlanAction,
) -> Result<()> {
    node.validate_action(action)?;
    for directory in &node.directories {
        fs::create_dir_all(BuildPlan::path(directory))?;
    }
    match action {
        PlanAction::Noop => {}
        PlanAction::Compile { command } => {
            let mut invocation = invocation(command);
            // The site wrapper opts Cargo invocations into canonical path
            // identity. Preserve that policy when it is no longer a subprocess.
            let cargo = invocation
                .env_vars
                .iter()
                .any(|(key, _)| key == "CARGO_MANIFEST_DIR");
            if cargo {
                invocation
                    .env_vars
                    .retain(|(key, _)| key != "SCCACHE_EXPERIMENTAL_CANONICAL_RUST");
                invocation
                    .env_vars
                    .push(("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()));
            }
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = session.execute(invocation, &mut stdout, &mut stderr)?;
            io::stdout().lock().write_all(&stdout)?;
            if cargo {
                render_diagnostics(&stderr)?;
            } else {
                io::stderr().lock().write_all(&stderr)?;
            }
            ensure!(code == 0, "compiler exited with status {code}");
        }
        PlanAction::Process {
            command,
            stdout,
            stderr,
            inherit_stdin,
        } => {
            let invocation = invocation(command);
            let mut process = Command::new(invocation.exe);
            process
                .args(invocation.cmdline)
                .current_dir(invocation.cwd)
                .env_clear()
                .envs(invocation.env_vars)
                .stdin(if *inherit_stdin {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                });
            if let Some(output) = stdout {
                process.stdout(fs::File::create(BuildPlan::path(output))?);
            }
            if let Some(output) = stderr {
                process.stderr(fs::File::create(BuildPlan::path(output))?);
            }
            let status = session.execute_process(&mut process)?;
            if !status.success() {
                let mut diagnostics = io::stderr().lock();
                for path in [stdout, stderr].into_iter().flatten() {
                    let mut file = fs::File::open(BuildPlan::path(path))?;
                    io::copy(&mut file, &mut diagnostics)?;
                }
                anyhow::bail!("process exited with {status}");
            }
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
pub(crate) fn dispatch(
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
    let session = CompileSession::new(config, true)?;
    dispatch(graph, max_in_flight, |index| {
        let node = &plan.nodes[index];
        execute_node(&session, node, &node.action)
            .with_context(|| format!("build node {index}: {}", node.label))
    })
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
