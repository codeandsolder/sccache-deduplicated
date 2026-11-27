//! The native Rust build frontend is linked into sccache itself. It resolves
//! the workspace, holds one artifact lease and submits actual rustc requests.
//! No external Cargo process, Cargo job queue or Cargo fingerprint database.
mod coverage;
mod metadata;

use crate::{build_plan, commands::CompileSession, config::Config};
use anyhow::{Context, Result, ensure};
use clap::{Parser, ValueEnum};
use sccache_rust_build::{
    BuildMode, Graph, Lockfile, PlanOptions, Planner, ResolveOptions, Settings, Sources,
    TargetKind, Toolchain, Workspace,
};
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
    Doc,
    Metadata,
    GenerateLockfile,
    Update,
    Fmt,
    Clean,
}

#[derive(Debug, Parser)]
#[command(
    name = "sccache",
    about = "Native Rust workspace build using the managed content-addressed executor"
)]
pub struct RustBuildArgs {
    #[arg(value_enum)]
    pub mode: Mode,
    #[arg(long)]
    toolchain: Option<String>,
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
    #[arg(long)]
    manifest_path: Option<PathBuf>,
    #[arg(long)]
    no_deps: bool,
    #[arg(long, default_value = "1")]
    format_version: u32,
    #[arg(long)]
    frozen: bool,
    #[arg(long)]
    exclude: Vec<String>,
    #[arg(long)]
    doc: bool,
    #[arg(long)]
    no_doc: bool,
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
    example: Vec<String>,
    #[arg(long)]
    examples: bool,
    #[arg(long = "test")]
    test_targets: Vec<String>,
    #[arg(long)]
    tests: bool,
    #[arg(long)]
    bench: Vec<String>,
    #[arg(long)]
    benches: bool,
    #[arg(long)]
    pub no_run: bool,
    /// Execute instrumented tests and write native coverage evidence.
    #[arg(long, value_name = "REPORT", conflicts_with = "no_run")]
    collect_coverage: Option<PathBuf>,
    #[arg(long, requires = "collect_coverage")]
    aggregate_profile: Option<PathBuf>,
    #[arg(long, requires = "collect_coverage")]
    continuous_coverage: bool,
    #[arg(long, requires = "collect_coverage")]
    llvm_tools_dir: Option<PathBuf>,
    #[arg(long, requires = "collect_coverage")]
    test_jobs: Option<NonZeroUsize>,
    #[arg(long)]
    target: Option<OsString>,
    #[arg(long)]
    target_dir: Option<PathBuf>,
    #[arg(long)]
    rustc: Option<PathBuf>,
    #[arg(long, conflicts_with_all = ["rustc", "toolchain"])]
    toolchain_root: Option<PathBuf>,
    #[arg(long)]
    import_root: Option<PathBuf>,
    #[arg(long)]
    offline: bool,
    #[arg(long)]
    locked: bool,
    #[arg(short = 'j', long = "jobs", default_value = "64")]
    max_in_flight: NonZeroUsize,
    #[arg(long, default_value = "16")]
    source_jobs: NonZeroUsize,
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

    fn plan_options(&self) -> Result<PlanOptions> {
        let mode = match self.mode {
            Mode::Build => BuildMode::Build,
            Mode::Check => BuildMode::Check,
            Mode::Test => BuildMode::Test,
            Mode::Clippy => BuildMode::Clippy,
            Mode::Run => BuildMode::Run,
            Mode::Doc => BuildMode::Doc,
            _ => anyhow::bail!("command does not produce a build graph"),
        };
        Ok(PlanOptions {
            mode,
            release: self.release,
            profile: self.profile.clone(),
            lib: self.lib,
            bin: self.bin.clone(),
            bins: self.bins,
            all_targets: self.all_targets,
            example: self.example.clone(),
            examples: self.examples,
            test_targets: self.test_targets.clone(),
            tests: self.tests,
            bench: self.bench.clone(),
            benches: self.benches,
            no_run: self.no_run,
            coverage: self.collect_coverage.as_ref().map(|_| {
                if self.continuous_coverage {
                    sccache_rust_build::impact::CoverageMode::Continuous
                } else {
                    sccache_rust_build::impact::CoverageMode::Exit
                }
            }),
            doc: self.doc,
            no_doc: self.no_doc,
            no_deps: self.no_deps,
            trailing: self.trailing.clone(),
        })
    }

    fn dev_dependencies(&self) -> bool {
        self.mode == Mode::Test
            || self.all_targets
            || self.examples
            || !self.example.is_empty()
            || self.tests
            || !self.test_targets.is_empty()
            || self.benches
            || !self.bench.is_empty()
    }

    pub fn validate_targets(&self, graph: &Graph) -> Result<()> {
        for (kind, names) in [
            (TargetKind::Binary, &self.bin),
            (TargetKind::Example, &self.example),
            (TargetKind::Test, &self.test_targets),
            (TargetKind::Bench, &self.bench),
        ] {
            for name in names {
                ensure!(
                    graph.roots.iter().any(|unit| graph
                        .manifest(*unit)
                        .targets
                        .iter()
                        .any(|target| target.kind == kind && &target.name == name)),
                    "unknown selected target {name:?}"
                );
            }
        }
        Ok(())
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
        for name in &self.exclude {
            ensure!(self.workspace, "--exclude requires --workspace");
            let mut found = false;
            for member in &workspace.members {
                if workspace.package(member)?.package.name == *name {
                    selected.remove(member);
                    found = true;
                }
            }
            ensure!(found, "unknown excluded package {name:?}");
        }
        Ok(selected.into_iter().collect())
    }
}

fn download(url: &str, file: &mut fs::File) -> Result<()> {
    let response = crate::http_client::io_runtime()?.block_on(async {
        Ok::<_, anyhow::Error>(
            crate::http_client::new_http_client_builder()
                .build()?
                .get(url)
                .send()
                .await?,
        )
    })?;
    if response.status() == http::StatusCode::NOT_FOUND {
        return Err(sccache_rust_build::IndexNotFound.into());
    }
    let response = response.error_for_status()?;
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

fn execute(mut args: RustBuildArgs) -> Result<i32> {
    let cwd = std::env::current_dir()?;
    ensure!(
        args.collect_coverage.is_none() || args.mode == Mode::Test,
        "--collect-coverage requires test mode"
    );
    if let (Some(report), Some(profile)) = (&args.collect_coverage, &args.aggregate_profile) {
        ensure!(
            cwd.join(report) != cwd.join(profile),
            "coverage report and aggregate profile must be different files"
        );
    }
    if args.frozen {
        args.locked = true;
        args.offline = true;
    }
    let manifest = args.manifest_path.clone().map_or_else(
        || {
            cwd.ancestors()
                .map(|directory| directory.join("Cargo.toml"))
                .find(|path| path.is_file())
                .context("no Rust manifest found")
        },
        Ok,
    )?;
    let workspace = Workspace::discover(&manifest)?;
    let import = args
        .import_root
        .clone()
        .or_else(|| std::env::var_os("CARGO_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".cargo")));
    let settings = Settings::load(&cwd, import.as_deref())?;
    let registries = sccache_rust_build::Registries::from_settings(&settings.document)?;
    let selected =
        if args.mode == Mode::Metadata && args.packages.is_empty() && args.exclude.is_empty() {
            workspace.members.clone()
        } else {
            args.selected(&workspace)?
        };
    let default_target = workspace.root.join("target");
    let target_root = args
        .target_dir
        .as_deref()
        .or_else(|| settings.target_dir())
        .unwrap_or(&default_target);
    if args.mode == Mode::Metadata {
        ensure!(
            args.format_version == 1,
            "unsupported metadata format version"
        );
        if args.no_deps {
            return metadata::write(&sccache_rust_build::workspace_metadata(
                &workspace,
                &cwd.join(target_root),
                &registries,
                None,
            )?);
        }
    }
    if args.mode == Mode::Clean {
        let path = if target_root.is_absolute() {
            target_root.to_path_buf()
        } else {
            cwd.join(target_root)
        };
        if path.exists() {
            ensure!(
                path.canonicalize()? != workspace.root,
                "refusing to clean the workspace root"
            );
            ensure!(
                path.join("CACHEDIR.TAG").is_file(),
                "not a marked build output directory"
            );
            let directory = fs::File::open(&path)?;
            directory.lock()?;
            fs::remove_dir_all(&path)?;
        }
        return Ok(0);
    }
    if args.mode == Mode::Fmt {
        return metadata::format_sources(&workspace, &selected, &args);
    }
    let target = args
        .target
        .as_deref()
        .or_else(|| settings.target().map(OsStr::new));
    let needs_docs =
        args.mode == Mode::Doc || (args.mode == Mode::Test && !args.no_run && !args.no_doc);
    let installation = args.toolchain_root.as_deref().or_else(|| {
        if args.rustc.is_none() && args.toolchain.is_none() {
            settings.toolchain_root()
        } else {
            None
        }
    });
    let toolchain = if let Some(root) = installation {
        Toolchain::from_root(&cwd, root, target, args.mode == Mode::Clippy, needs_docs)?
    } else {
        Toolchain::discover(
            &cwd,
            args.rustc.as_deref(),
            args.toolchain.as_deref(),
            target,
            args.mode == Mode::Clippy,
            needs_docs,
        )?
    };
    if matches!(args.mode, Mode::GenerateLockfile | Mode::Update) {
        ensure!(
            !args.locked,
            "lockfile generation requires permission to change the lock"
        );
        let scratch = tempfile::Builder::new()
            .prefix("native-resolution-")
            .tempdir()?;
        let lock = if args.mode == Mode::Update {
            Lockfile::default()
        } else {
            Lockfile::load(&workspace.root.join("Cargo.lock"))?
        };
        let mut sources = Sources::new(&workspace, lock, import, scratch.path().to_path_buf());
        sources.registries = registries;
        if !args.offline {
            sources.download = Some(&download);
        }
        let lock = sources.resolve_lock(&toolchain.version)?;
        lock.write(&workspace.root.join("Cargo.lock"))?;
        return Ok(0);
    }
    // Metadata does not publish artifacts or create an output directory.
    let (target_lock, target_root) = if args.mode == Mode::Metadata {
        (None, cwd.join(target_root))
    } else {
        let target_root = absolute(target_root, &cwd)?;
        let lock = fs::File::open(&target_root)?;
        lock.lock()?;
        let marker = target_root.join("CACHEDIR.TAG");
        if !marker.exists() {
            fs::write(
                &marker,
                b"Signature: 8a477f597d28d172789f06886806bc55\n# Managed Rust build outputs.\n",
            )?;
        }
        (Some(lock), target_root)
    };
    let mut final_root = target_root.clone();
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
    crate::build_lease::with_build_intermediates(|lease, intermediate, content| {
        let sources_root = lease.root().join("sources");
        fs::create_dir_all(&sources_root)?;
        let package_tree = |package: &sccache_rust_build::LockedPackage,
                            registry: &sccache_rust_build::Registry,
                            key: &str,
                            stem: &str| {
            let checksum = package
                .checksum
                .as_deref()
                .context("missing package checksum")?;
            let identity = crate::build_runtime::PackageIdentity::from_sha256_hex(
                checksum,
                crate::build_runtime::PackageCompression::Gzip,
            )?;
            let path =
                registry.archive_path(&package.name, &package.version.to_string(), checksum)?;
            let destination = intermediate
                .join("package-sources")
                .join(blake3::hash(key.as_bytes()).to_hex().as_str());
            if crate::dist::native::intermediate::package(
                content,
                identity,
                &registry.upstream,
                &path,
                args.offline,
                &destination,
                stem,
            )? {
                Ok(Some(destination.join(stem)))
            } else {
                Ok(None)
            }
        };
        let mut sources = Sources::new(&workspace, lock, import, sources_root);
        sources.registries = registries;
        sources.package_tree = Some(&package_tree);
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
            dev_dependencies: args.dev_dependencies() || args.mode == Mode::Metadata,
            host: toolchain.host.clone(),
            target: toolchain.target.clone(),
            source_jobs: args.source_jobs,
        };
        let mut changed = sources.lock().version.is_none();
        if changed {
            let lock = sources.resolve_lock(&toolchain.version)?;
            sources.replace_lock(lock);
        }
        let graph = match Graph::resolve(&mut sources, options.clone()) {
            Ok(graph) => graph,
            Err(error)
                if !args.locked
                    && error
                        .downcast_ref::<sccache_rust_build::LockMismatch>()
                        .is_some() =>
            {
                let lock = sources.resolve_lock(&toolchain.version)?;
                sources.replace_lock(lock);
                changed = true;
                Graph::resolve(&mut sources, options)?
            }
            Err(error) => return Err(error),
        };
        if changed {
            sources.lock().write(&workspace.root.join("Cargo.lock"))?;
        }
        if args.mode == Mode::Metadata {
            return metadata::write(&sccache_rust_build::workspace_metadata(
                &workspace,
                &target_root,
                &sources.registries,
                Some((&graph, &sources)),
            )?);
        }
        // Keep the output lock alive across dispatch.
        let _target_lock = target_lock;
        args.validate_targets(&graph)?;
        let plan_options = args.plan_options()?;
        // Never replace ordinary build products with instrumented binaries.
        let final_root = if plan_options.coverage.is_some() {
            lease.root().join("coverage-target")
        } else {
            final_root
        };
        let planner = Planner::new(
            &graph,
            &workspace,
            &settings,
            &toolchain,
            &plan_options,
            intermediate.to_path_buf(),
            final_root,
        )?;
        let session = CompileSession::new(&config, true)?.with_lease(lease);
        eprintln!(
            "native build: {} packages, {} actions",
            graph.packages.len(),
            planner.len()
        );
        if let Some(report) = args.collect_coverage.as_deref() {
            return coverage::execute(
                &session,
                content,
                &planner,
                &toolchain,
                &workspace,
                lease.root(),
                args.max_in_flight,
                coverage::Options {
                    report,
                    aggregate: args.aggregate_profile.as_deref(),
                    mode: plan_options.coverage.context("missing coverage mode")?,
                    tools_dir: args.llvm_tools_dir.as_deref(),
                    jobs: args
                        .test_jobs
                        .unwrap_or(std::thread::available_parallelism()?),
                    trailing: &args.trailing,
                    verbose: args.verbose > 0,
                },
            );
        }
        build_plan::dispatch(planner.graph()?, args.max_in_flight, |index| {
            let node = planner
                .prepare(index)
                .with_context(|| format!("prepare build node {index}"))?;
            if args.verbose > 0 {
                eprintln!("{}", node.label);
            }
            build_plan::execute_node(&session, &node, &node.action)
                .with_context(|| node.label.clone())?;
            planner.complete(index)
        })?;
        Ok(0)
    })
}

pub(crate) fn run_if_requested() -> Option<Result<i32>> {
    let mut args: Vec<_> = std::env::args_os().collect();
    let explicit = args.get(1)?.to_str()?.strip_prefix('+').map(str::to_owned);
    let mode = args.get(if explicit.is_some() { 2 } else { 1 })?.to_str()?;
    if !matches!(
        mode,
        "build"
            | "check"
            | "test"
            | "clippy"
            | "run"
            | "doc"
            | "metadata"
            | "generate-lockfile"
            | "update"
            | "fmt"
            | "clean"
    ) {
        return None;
    }
    if let Some(toolchain) = explicit {
        args.remove(1);
        args.splice(
            2..2,
            [OsString::from("--toolchain"), OsString::from(toolchain)],
        );
    }
    Some(match RustBuildArgs::try_parse_from(args) {
        Ok(args) => execute(args),
        Err(error) => {
            error.exit();
        }
    })
}
