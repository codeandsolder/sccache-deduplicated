//! The native Rust build frontend is linked into sccache itself. It resolves
//! the workspace, holds one artifact lease and submits actual rustc requests.
//! No external Cargo process, Cargo job queue or Cargo fingerprint database.
mod planner;
mod settings;

use self::{
    planner::Planner,
    settings::{Settings, Toolchain},
};
use crate::{build_plan, commands::CompileSession, config::Config};
use anyhow::{Context, Result, ensure};
use clap::{Parser, ValueEnum};
use sccache_rust_build::{Graph, Lockfile, ResolveOptions, Sources, Target, TargetKind, Workspace};
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs, io,
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    Build,
    Check,
    Test,
    Clippy,
    Run,
}

#[derive(Debug, Parser)]
#[command(
    name = "sccache",
    about = "Native Rust workspace build using the managed content-addressed executor"
)]
pub struct RustBuildArgs {
    #[arg(value_enum)]
    pub mode: Mode,
    #[arg(long, default_value = "Cargo.toml")]
    manifest_path: PathBuf,
    #[arg(short = 'p', long = "package")]
    packages: Vec<String>,
    #[arg(long)]
    workspace: bool,
    #[arg(long)]
    release: bool,
    #[arg(long, conflicts_with = "release")]
    profile: Option<String>,
    #[arg(long, value_delimiter = ',')]
    features: Vec<String>,
    #[arg(long)]
    no_default_features: bool,
    #[arg(long)]
    all_features: bool,
    #[arg(long)]
    lib: bool,
    #[arg(long)]
    bin: Vec<String>,
    #[arg(long)]
    bins: bool,
    #[arg(long)]
    all_targets: bool,
    #[arg(long)]
    pub no_run: bool,
    #[arg(long)]
    target: Option<OsString>,
    #[arg(long)]
    target_dir: Option<PathBuf>,
    #[arg(long)]
    rustc: Option<PathBuf>,
    #[arg(long)]
    import_root: Option<PathBuf>,
    #[arg(long)]
    offline: bool,
    #[arg(long)]
    locked: bool,
    #[arg(short = 'j', long = "jobs", default_value = "64")]
    max_in_flight: NonZeroUsize,
    #[arg(last = true)]
    pub trailing: Vec<OsString>,
}

impl RustBuildArgs {
    pub fn profile_name(&self) -> &str {
        self.profile.as_deref().unwrap_or(if self.release {
            "release"
        } else if self.mode == Mode::Test {
            "test"
        } else {
            "dev"
        })
    }

    pub fn selects(&self, target: &Target) -> bool {
        if self.lib || self.bins || !self.bin.is_empty() {
            return (self.lib && target.kind == TargetKind::Library)
                || (target.kind == TargetKind::Binary
                    && (self.bins || self.bin.contains(&target.name)));
        }
        if self.mode == Mode::Run {
            return target.kind == TargetKind::Binary;
        }
        if self.all_targets {
            return target.kind != TargetKind::BuildScript;
        }
        if self.mode == Mode::Test {
            return matches!(
                target.kind,
                TargetKind::Library | TargetKind::Binary | TargetKind::Test
            );
        }
        matches!(target.kind, TargetKind::Library | TargetKind::Binary)
    }

    fn selected(&self, workspace: &Workspace) -> Result<Vec<PathBuf>> {
        let mut selected = BTreeSet::new();
        if self.workspace {
            selected.extend(workspace.members.iter().cloned());
        }
        if self.packages.is_empty() && !self.workspace {
            selected.extend(workspace.defaults.iter().cloned());
        }
        for name in &self.packages {
            let mut found = Vec::new();
            for member in &workspace.members {
                let manifest = workspace.package(member)?;
                if manifest.package.name == *name {
                    found.push(member.clone());
                }
            }
            ensure!(
                found.len() == 1,
                "package selection {name:?} is missing or ambiguous"
            );
            selected.extend(found);
        }
        Ok(selected.into_iter().collect())
    }
}

fn download(url: &str, file: &mut fs::File) -> Result<()> {
    let response = crate::http_client::io_runtime()?.block_on(async {
        crate::http_client::new_http_client_builder()
            .build()?
            .get(url)
            .send()
            .await?
            .error_for_status()
    })?;
    let mut reader = crate::http_client::ResponseReader::new(response)?;
    io::copy(&mut reader, file)?;
    Ok(())
}

fn absolute(path: &Path, cwd: &Path) -> Result<PathBuf> {
    // Canonicalize the parent when the output directory does not yet exist.
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    fs::create_dir_all(&path)?;
    Ok(path.canonicalize()?)
}

fn execute(args: RustBuildArgs) -> Result<i32> {
    let cwd = std::env::current_dir()?;
    let workspace = Workspace::discover(&args.manifest_path)?;
    let import = args
        .import_root
        .clone()
        .or_else(|| std::env::var_os("CARGO_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".cargo")));
    let settings = Settings::load(&cwd, import.as_deref())?;
    let target = args
        .target
        .as_deref()
        .or_else(|| settings.target().map(OsStr::new));
    let toolchain = Toolchain::discover(
        &cwd,
        args.rustc.as_deref(),
        target,
        args.mode == Mode::Clippy,
        false,
    )?;
    let selected = args.selected(&workspace)?;
    let target_root = absolute(
        args.target_dir
            .as_deref()
            .unwrap_or(&workspace.root.join("target")),
        &cwd,
    )?;
    let mut final_root = target_root;
    if target.is_some() {
        final_root.push(&toolchain.target.triple);
    }
    final_root.push(match args.profile_name() {
        "dev" | "test" => "debug",
        "bench" => "release",
        name => name,
    });
    let lock = Lockfile::load(&workspace.root.join("Cargo.lock"))?;
    ensure!(
        !args.locked || lock.version.is_some(),
        "--locked requires an existing lockfile"
    );
    let config = Config::load()?;
    crate::cargo_launcher::with_build_intermediates(|lease, intermediate| {
        let sources_root = lease.root().join("sources");
        fs::create_dir_all(&sources_root)?;
        let mut sources = Sources::new(&workspace, lock, import, sources_root);
        if !args.offline {
            sources.download = Some(&download);
        }
        let options = ResolveOptions {
            selected,
            features: args
                .features
                .iter()
                .flat_map(|f| f.split_whitespace())
                .map(str::to_owned)
                .collect(),
            default_features: !args.no_default_features,
            all_features: args.all_features,
            dev_dependencies: args.mode == Mode::Test || args.all_targets,
            host: toolchain.host.clone(),
            target: toolchain.target.clone(),
        };
        let mut changed = sources.lock.version.is_none();
        if changed {
            sources.lock = sources.resolve_lock(&toolchain.version)?;
        }
        let graph = match Graph::resolve(&mut sources, options.clone()) {
            Ok(graph) => graph,
            Err(error)
                if !args.locked
                    && error
                        .downcast_ref::<sccache_rust_build::LockMismatch>()
                        .is_some() =>
            {
                sources.lock = sources.resolve_lock(&toolchain.version)?;
                changed = true;
                Graph::resolve(&mut sources, options)?
            }
            Err(error) => return Err(error),
        };
        if changed {
            sources.lock.write(&workspace.root.join("Cargo.lock"))?;
        }
        let planner = Planner::new(
            &graph,
            &workspace,
            &settings,
            &toolchain,
            &args,
            intermediate.to_path_buf(),
            final_root,
        )?;
        let session = CompileSession::new(&config, true)?.with_lease(lease);
        eprintln!(
            "native build: {} packages, {} actions",
            graph.packages.len(),
            planner.len()
        );
        build_plan::dispatch(planner.graph()?, args.max_in_flight, |index| {
            let node = planner
                .prepare(index)
                .with_context(|| format!("prepare build node {index}"))?;
            build_plan::execute_node(&session, &node, &node.action)
                .with_context(|| node.label.clone())?;
            planner.complete(index)
        })?;
        Ok(0)
    })
}

pub(crate) fn run_if_requested() -> Option<Result<i32>> {
    let args: Vec<_> = std::env::args_os().collect();
    let mode = args.get(1)?.to_str()?;
    if !matches!(mode, "build" | "check" | "test" | "clippy" | "run") {
        return None;
    }
    Some(match RustBuildArgs::try_parse_from(args) {
        Ok(args) => execute(args),
        Err(error) => {
            error.exit();
        }
    })
}
