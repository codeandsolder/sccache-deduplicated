//! Exercise the real CLI and live planner handshake without starting a daemon.
//! Compiler actions are covered by native_plan_e2e.sh on a managed endpoint.
#![cfg(unix)]

use anyhow::{Result, ensure};
use sccache_build::{
    BUILD_PLAN_VERSION, BuildPath, BuildPlan, PlanAction, PlanCommand, PlanNode, PlannerReply,
};
use std::{
    fs,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::Path,
    process::Command,
};

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

#[test]
fn live_planner_observes_completed_prerequisites() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut plan = plan(root)?;
    let actions: Vec<_> = plan
        .nodes
        .iter_mut()
        .map(|node| std::mem::replace(&mut node.action, PlanAction::Deferred))
        .collect();
    // Generated replies contain path bytes rather than shell expressions.
    // Escape single quotes so arbitrary JSON strings stay literal.
    let reply = |value: &PlannerReply| -> Result<String> {
        Ok(format!(
            "printf '%s\\n' '{}'\n",
            serde_json::to_string(value)?.replace('\'', "'\\''")
        ))
    };
    let mut script = String::from("#!/bin/sh\nset -eu\ncd \"$(dirname \"$0\")\"\n");
    script.push_str(&reply(&PlannerReply::Plan { plan })?);
    for (index, action) in actions.into_iter().enumerate() {
        script.push_str(&format!(
            "IFS= read -r request\n[ \"$request\" = '{{\"kind\":\"prepare\",\"index\":{index}}}' ]\n"
        ));
        if index == 1 {
            script.push_str("[ \"$(cat source)\" = native-plan ]\n");
        }
        script.push_str(&reply(&PlannerReply::Action { index, action })?);
        script.push_str(&format!(
            "IFS= read -r request\n[ \"$request\" = '{{\"kind\":\"complete\",\"index\":{index}}}' ]\n"
        ));
        script.push_str(&reply(&PlannerReply::Completed { index })?);
    }
    script.push_str("IFS= read -r request\n[ \"$request\" = '{\"kind\":\"finish\"}' ]\n");
    script.push_str(&reply(&PlannerReply::Finished)?);
    let planner = root.join("planner");
    fs::write(&planner, script)?;
    fs::set_permissions(&planner, fs::Permissions::from_mode(0o700))?;
    let run = executor().arg("--execute-planner").arg(planner).output()?;
    ensure!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(fs::read(root.join("result"))?, b"native-plan");
    Ok(())
}
