//! Offline planner smoke test for a corpus of real locked workspaces.
//! No compiler actions are executed and no workspace files are modified.
use anyhow::{Context, Result, ensure};
use sccache_rust_build::{
    BuildMode, Graph, Lockfile, PlanOptions, Planner, Registries, ResolveOptions, Settings,
    Sources, Toolchain, Workspace,
};
use std::{collections::BTreeSet, num::NonZeroUsize, path::PathBuf, time::Instant};

fn inspect(manifest: PathBuf, import: &PathBuf) -> Result<()> {
    let start = Instant::now();
    let workspace = Workspace::discover(&manifest)?;
    let settings = Settings::load(&workspace.root, Some(import))?;
    let toolchain = Toolchain::discover(&workspace.root, None, None, None, false, false)?;
    let scratch = tempfile::tempdir()?;
    let lock = Lockfile::load(&workspace.root.join("Cargo.lock"))?;
    ensure!(lock.version.is_some(), "workspace has no lockfile");
    let mut sources = Sources::new(
        &workspace,
        lock,
        Some(import.clone()),
        scratch.path().join("sources"),
    );
    sources.registries = Registries::from_settings(&settings.document)?;
    let graph = Graph::resolve(
        &mut sources,
        ResolveOptions {
            selected: workspace.members.clone(),
            features: BTreeSet::new(),
            default_features: true,
            all_features: false,
            dev_dependencies: true,
            host: toolchain.host.clone(),
            target: toolchain.target.clone(),
            source_jobs: NonZeroUsize::MIN.saturating_add(15),
        },
    )?;
    let resolve_time = start.elapsed();
    let options = PlanOptions {
        mode: BuildMode::Check,
        all_targets: true,
        ..PlanOptions::default()
    };
    let plan = Planner::new(
        &graph,
        &workspace,
        &settings,
        &toolchain,
        &options,
        scratch.path().join("intermediate"),
        scratch.path().join("final"),
    )?;
    let mut dag = plan.graph()?;
    let mut ready = 0;
    while let Some(node) = dag.take_ready() {
        dag.complete(node)?;
        ready += 1;
    }
    ensure!(dag.is_complete(), "incomplete action graph");
    println!(
        "{}\t{} packages\t{} units\t{} actions\tresolve={}ms\ttotal={}ms",
        manifest.display(),
        graph.packages.len(),
        graph.units.len(),
        ready,
        resolve_time.as_millis(),
        start.elapsed().as_millis()
    );
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let import = PathBuf::from(
        args.next()
            .context("usage: inspect <read-only package cache root> <manifest>...")?,
    );
    let mut failed = 0;
    let mut count = 0;
    for arg in args {
        let manifest = PathBuf::from(arg);
        count += 1;
        if let Err(error) = inspect(manifest.clone(), &import) {
            eprintln!("{}: {error:#}", manifest.display());
            failed += 1;
        }
    }
    ensure!(count > 0, "no manifests supplied");
    ensure!(
        failed == 0,
        "{failed} of {count} workspaces failed planning"
    );
    Ok(())
}
