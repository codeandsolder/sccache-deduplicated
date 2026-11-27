//! Package-manager-independent workspace inspection and source formatting.
use super::RustBuildArgs;
use anyhow::{Result, ensure};
use sccache_rust_build::Workspace;
use sccache_rust_build::settings;
use serde_json::Value;
use std::{collections::BTreeSet, io, path::PathBuf, process::Command};

pub(super) fn write(value: &Value) -> Result<i32> {
    serde_json::to_writer(io::stdout().lock(), value)?;
    println!();
    Ok(0)
}

pub(super) fn format_sources(
    workspace: &Workspace,
    selected: &[PathBuf],
    args: &RustBuildArgs,
) -> Result<i32> {
    let executable = settings::tool("rustfmt", None, args.toolchain.as_deref(), &workspace.root)?;
    let mut formatted = BTreeSet::new();
    for root in selected {
        let manifest = workspace.package(root)?;
        let paths = manifest
            .targets
            .iter()
            .filter_map(|target| {
                formatted
                    .insert(target.source.clone())
                    .then_some(&target.source)
            })
            .collect::<Vec<_>>();
        if paths.is_empty() {
            continue;
        }
        let status = Command::new(&executable)
            .current_dir(&manifest.root)
            .arg("--edition")
            .arg(&manifest.package.edition)
            .args(&args.trailing)
            .args(paths)
            .status()?;
        ensure!(status.success(), "rustfmt exited with {status}");
    }
    Ok(0)
}
