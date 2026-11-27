//! Exercise the real CLI without starting a daemon.
//! Compiler actions are covered by native_plan_e2e.sh on a managed endpoint.
#![cfg(unix)]

use anyhow::{Result, ensure};
use sccache_build::{BUILD_PLAN_VERSION, BuildPath, BuildPlan, PlanAction, PlanCommand, PlanNode};
use std::{fs, os::unix::ffi::OsStrExt, path::Path, process::Command};

fn path(path: &Path) -> Result<BuildPath> {
    BuildPath::new(path.as_os_str().as_bytes().to_vec())
}

fn plan(root: &Path) -> Result<BuildPlan> {
    let source = path(&root.join("source"))?;
    let result = path(&root.join("result"))?;
    Ok(BuildPlan {
        version: BUILD_PLAN_VERSION,
        nodes: vec![
            PlanNode {
                label: "produce".into(),
                dependencies: vec![],
                estimated_cost: 1,
                directories: vec![],
                required_outputs: vec![source.clone()],
                action: PlanAction::Process {
                    command: PlanCommand {
                        executable: path(Path::new("/bin/sh"))?,
                        cwd: path(root)?,
                        arguments: vec![b"-c".to_vec(), b"printf native-plan".to_vec()],
                        inherit_environment: false,
                        environment: vec![],
                    },
                    stdout: Some(source.clone()),
                    stderr: None,
                    inherit_stdin: false,
                },
            },
            PlanNode {
                label: "publish".into(),
                dependencies: vec![0],
                estimated_cost: 1,
                directories: vec![],
                required_outputs: vec![result.clone()],
                action: PlanAction::Publish {
                    source,
                    destination: result,
                },
            },
        ],
    })
}

fn executor() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sccache"))
}

#[test]
fn explicit_plan_publishes_required_artifact() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let file = root.join("plan.json");
    fs::write(&file, serde_json::to_vec(&plan(root)?)?)?;
    let run = executor().arg("--execute-plan").arg(file).output()?;
    ensure!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(fs::read(root.join("result"))?, b"native-plan");
    Ok(())
}
