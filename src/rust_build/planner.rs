//! Translate the resolved unit graph into compiler, build-script and final
//! publication actions. The common runtime owns readiness and cache admission.
use super::{
    Mode, RustBuildArgs,
    settings::{Settings, Toolchain},
};
use anyhow::{Context, Result, bail, ensure};
use sccache_build::{BuildGraph, BuildPath, EnvironmentChange, PlanAction, PlanCommand, PlanNode};
use sccache_rust_build::{
    BuildDomain, DependencyKind, Graph, LinkDirective, LinkScope, Manifest, Profile, ScriptOutput,
    Target, TargetKind, Workspace,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
enum Action {
    Compile {
        unit: usize,
        target: usize,
        test: bool,
        metadata: bool,
        script: bool,
        tag: String,
        profile: Profile,
    },
    Script {
        unit: usize,
        compiler: usize,
        stdout: PathBuf,
        stderr: PathBuf,
        out: PathBuf,
    },
    Publish {
        source: PathBuf,
        destination: PathBuf,
    },
    Run {
        unit: usize,
        compiler: usize,
    },
    Rustdoc {
        unit: usize,
        target: usize,
        test: bool,
    },
}

#[derive(Debug)]
struct Node {
    action: Action,
    deps: BTreeSet<usize>,
    outputs: Vec<PathBuf>,
    label: String,
}

pub struct Planner<'a> {
    graph: &'a Graph,
    workspace: &'a Workspace,
    settings: &'a Settings,
    toolchain: &'a Toolchain,
    options: &'a RustBuildArgs,
    intermediate: PathBuf,
    final_root: PathBuf,
    nodes: Vec<Node>,
    libraries: Vec<Option<usize>>,
    scripts: Vec<Option<usize>>,
    binaries: Vec<BTreeMap<String, (usize, PathBuf)>>,
    binary_publications: Vec<Vec<usize>>,
    file_names: BTreeMap<(bool, bool, Vec<String>), Vec<String>>,
}

fn bytes(value: &OsStr) -> Vec<u8> {
    value.as_encoded_bytes().to_vec()
}
fn path(value: &Path) -> Result<BuildPath> {
    BuildPath::new(bytes(value.as_os_str()))
}
fn crate_name(name: &str) -> String {
    name.replace('-', "_")
}
fn published_filename(filename: &str, target: &Target, tag: &str) -> String {
    let name = filename.replace(&format!("-{tag}"), "");
    if matches!(target.kind, TargetKind::Binary | TargetKind::Example) {
        let crate_name = crate_name(&target.name);
        if let Some(suffix) = name.strip_prefix(&crate_name) {
            return format!("{}{suffix}", target.name);
        }
    }
    name
}

fn envify(value: &str) -> String {
    value.replace('-', "_").to_uppercase()
}

fn command(
    exe: &Path,
    cwd: &Path,
    args: Vec<OsString>,
    env: BTreeMap<OsString, OsString>,
) -> Result<PlanCommand> {
    Ok(PlanCommand {
        executable: path(exe)?,
        cwd: path(cwd)?,
        arguments: args.iter().map(|arg| bytes(arg)).collect(),
        inherit_environment: false,
        environment: env
            .into_iter()
            .map(|(name, value)| EnvironmentChange {
                name: bytes(&name),
                value: Some(bytes(&value)),
            })
            .collect(),
    })
}

impl<'a> Planner<'a> {
    pub fn new(
        graph: &'a Graph,
        workspace: &'a Workspace,
        settings: &'a Settings,
        toolchain: &'a Toolchain,
        options: &'a RustBuildArgs,
        intermediate: PathBuf,
        final_root: PathBuf,
    ) -> Result<Self> {
        let mut planner = Self {
            graph,
            workspace,
            settings,
            toolchain,
            options,
            intermediate,
            final_root,
            nodes: Vec::new(),
            libraries: vec![None; graph.units.len()],
            scripts: vec![None; graph.units.len()],
            binaries: vec![BTreeMap::new(); graph.units.len()],
            binary_publications: vec![Vec::new(); graph.units.len()],
            file_names: BTreeMap::new(),
        };
        planner.allocate()?;
        planner.dependencies()?;
        Ok(planner)
    }

    fn unit_manifest(&self, unit: usize) -> &Manifest {
        self.graph.manifest(unit)
    }

    fn target(&self, unit: usize, index: usize) -> &Target {
        &self.unit_manifest(unit).targets[index]
    }

    fn host(&self, unit: usize, script: bool) -> bool {
        script || self.graph.units[unit].domain == BuildDomain::Host
    }

    fn output_dir(&self, host: bool) -> PathBuf {
        self.intermediate
            .join(if host { "host" } else { "target" })
            .join("deps")
    }

    fn profile(&self, unit: usize, script: bool) -> Result<Profile> {
        let manifest = self.unit_manifest(unit);
        Profile::load(
            &self.workspace.document,
            self.options.profile_name(),
            &manifest.package.name,
            self.host(unit, script),
            self.graph.sources[self.graph.units[unit].package].is_some(),
        )
    }

    fn compile(&mut self, unit: usize, target: usize, test: bool, script: bool) -> Result<usize> {
        let manifest = self.unit_manifest(unit);
        let target_spec = manifest.targets[target].clone();
        let host = self.host(unit, script);
        let metadata = !host && matches!(self.options.mode, Mode::Check | Mode::Clippy);
        let profile = self.profile(unit, script)?;
        let package = self.graph.units[unit].package;
        let identity = match &self.graph.sources[package] {
            Some(source) => source.clone(),
            None => manifest
                .root
                .strip_prefix(&self.workspace.root)
                .unwrap_or(&manifest.root)
                .to_string_lossy()
                .into_owned(),
        };
        // This is a namespace for rustc's crate disambiguator, not a result
        // fingerprint. The actual compiler cache hashes inputs and arguments.
        let key = serde_json::to_vec(&(
            &manifest.package.name,
            manifest.package.version.to_string(),
            identity,
            &target_spec.name,
            &target_spec.crate_types,
            &self.graph.units[unit].features,
            host,
            format!("{:?}", self.graph.units[unit].domain),
            test,
            metadata,
            &profile.options,
            if host {
                &self.toolchain.host.triple
            } else {
                &self.toolchain.target.triple
            },
            &self.toolchain.version,
        ))?;
        let tag = blake3::hash(&key).to_hex()[..24].to_owned();
        let name = crate_name(&target_spec.name);
        let types = if test {
            vec!["bin".to_owned()]
        } else {
            target_spec.crate_types.clone()
        };
        let label = format!(
            "{} {} ({})",
            manifest.package.name,
            target_spec.name,
            if script {
                "build script"
            } else if test {
                "test"
            } else if metadata {
                "check"
            } else {
                "compile"
            }
        );
        let output_dir = self.output_dir(host);
        let outputs = if metadata {
            vec![output_dir.join(format!("lib{name}-{tag}.rmeta"))]
        } else {
            let cache_key = (host, test && target_spec.harness, types.clone());
            if !self.file_names.contains_key(&cache_key) {
                let names = self
                    .toolchain
                    .filenames(&types, host, test && target_spec.harness)?;
                self.file_names.insert(cache_key.clone(), names);
            }
            self.file_names[&cache_key]
                .iter()
                .map(|filename| {
                    output_dir.join(
                        filename
                            .replace("sccache_probe", &name)
                            .replace("sccache_tag", &tag),
                    )
                })
                .collect()
        };
        let index = self.nodes.len();
        self.nodes.push(Node {
            action: Action::Compile {
                unit,
                target,
                test,
                metadata,
                script,
                tag,
                profile,
            },
            deps: BTreeSet::new(),
            outputs,
            label,
        });
        Ok(index)
    }

    fn allocate(&mut self) -> Result<()> {
        for unit in 0..self.graph.units.len() {
            let manifest = self.unit_manifest(unit);
            let library = manifest
                .targets
                .iter()
                .position(|t| t.kind == TargetKind::Library);
            let script = manifest
                .targets
                .iter()
                .position(|t| t.kind == TargetKind::BuildScript);
            if let Some(target) = library {
                self.libraries[unit] = Some(self.compile(unit, target, false, false)?);
            }
            if let Some(target) = script {
                let compiler = self.compile(unit, target, false, true)?;
                let Action::Compile { tag, .. } = &self.nodes[compiler].action else {
                    bail!("invalid build script compile action")
                };
                let directory = self.intermediate.join("scripts").join(tag);
                let stdout = directory.join("stdout");
                let stderr = directory.join("stderr");
                let out = directory.join("out");
                let index = self.nodes.len();
                let label = format!("{} build script run", self.unit_manifest(unit).package.name);
                self.nodes.push(Node {
                    action: Action::Script {
                        unit,
                        compiler,
                        stdout: stdout.clone(),
                        stderr: stderr.clone(),
                        out,
                    },
                    deps: BTreeSet::from([compiler]),
                    outputs: vec![stdout, stderr],
                    label,
                });
                self.scripts[unit] = Some(index);
            }
        }
        if self.options.mode == Mode::Doc {
            return self.allocate_docs();
        }
        let mut roots = Vec::new();
        for &unit in &self.graph.roots {
            let targets = self.unit_manifest(unit).targets.clone();
            let features = self.graph.units[unit].features.clone();
            let available = |target: &Target| target.required_features.is_subset(&features);
            let needs_integration_binaries = targets.iter().any(|target| {
                target.kind == TargetKind::Test && self.options.selects(target) && available(target)
            });
            // Build actual binaries for integration tests, not the unit-test
            // harnesses. The executable paths must remain usable at test time.
            for (index, target) in targets.iter().enumerate() {
                if target.kind != TargetKind::Binary || !available(target) {
                    continue;
                }
                let selected = self.options.selects(target);
                if (selected && self.options.mode != Mode::Test) || needs_integration_binaries {
                    let compiled = self.compile(unit, index, false, false)?;
                    let Action::Compile { tag, metadata, .. } = &self.nodes[compiled].action else {
                        bail!("invalid binary compile action")
                    };
                    let destination = if *metadata {
                        self.final_root.join(&target.name)
                    } else {
                        let source = self.nodes[compiled]
                            .outputs
                            .first()
                            .context("missing binary output")?;
                        self.final_root.join(published_filename(
                            source
                                .file_name()
                                .and_then(OsStr::to_str)
                                .context("invalid binary filename")?,
                            target,
                            tag,
                        ))
                    };
                    self.binaries[unit].insert(target.name.clone(), (compiled, destination));
                    if needs_integration_binaries
                        && !(selected && self.options.mode != Mode::Test)
                        && !*metadata
                    {
                        roots.push((unit, index, compiled, false));
                    }
                }
            }
            for (index, target) in targets.iter().enumerate() {
                if target.kind == TargetKind::BuildScript
                    || !target
                        .required_features
                        .is_subset(&self.graph.units[unit].features)
                    || !self.options.selects(target)
                {
                    continue;
                }
                if self.options.mode == Mode::Test && self.options.doc {
                    continue;
                }
                let harness_target = matches!(target.kind, TargetKind::Test | TargetKind::Bench);
                let test_mode = self.options.mode == Mode::Test || harness_target;
                if self.options.mode != Mode::Test || target.test || harness_target {
                    let compiled = if target.kind == TargetKind::Library && !test_mode {
                        self.libraries[unit].context("missing library node")?
                    } else if target.kind == TargetKind::Binary && !test_mode {
                        self.binaries[unit][&target.name].0
                    } else {
                        self.compile(unit, index, test_mode, false)?
                    };
                    roots.push((unit, index, compiled, test_mode));
                }
                if self.options.all_targets
                    && self.options.mode != Mode::Test
                    && target.test
                    && !harness_target
                    && matches!(target.kind, TargetKind::Library | TargetKind::Binary)
                {
                    let compiled = self.compile(unit, index, true, false)?;
                    roots.push((unit, index, compiled, true));
                }
            }
        }
        let doctests =
            self.options.mode == Mode::Test && !self.options.no_run && !self.options.no_doc;
        ensure!(
            !roots.is_empty() || (doctests && self.options.doc),
            "no selected targets have their required features"
        );
        ensure!(
            self.options.mode != Mode::Run || roots.len() == 1,
            "run requires exactly one binary"
        );
        for (unit, target, compiled, test) in roots {
            let spec = self.target(unit, target).clone();
            let Action::Compile { tag, metadata, .. } = self.nodes[compiled].action.clone() else {
                bail!("invalid root action")
            };
            if metadata {
                continue;
            }
            if self.options.mode == Mode::Test && test && !self.options.no_run {
                self.nodes.push(Node {
                    action: Action::Run {
                        unit,
                        compiler: compiled,
                    },
                    deps: BTreeSet::from([compiled]),
                    outputs: vec![],
                    label: format!("run {}", spec.name),
                });
                continue;
            }
            let directory = if test {
                self.final_root.join("tests")
            } else if spec.kind == TargetKind::Example {
                self.final_root.join("examples")
            } else {
                self.final_root.clone()
            };
            let outputs = self.nodes[compiled].outputs.clone();
            for source in outputs {
                let filename = source
                    .file_name()
                    .and_then(OsStr::to_str)
                    .context("non-UTF8 output name")?;
                let final_name = if test {
                    filename.to_owned()
                } else {
                    published_filename(filename, &spec, &tag)
                };
                let destination = directory.join(final_name);
                let publication = self.nodes.len();
                self.nodes.push(Node {
                    action: Action::Publish {
                        source,
                        destination: destination.clone(),
                    },
                    deps: BTreeSet::from([compiled]),
                    outputs: vec![destination],
                    label: format!("publish {}", spec.name),
                });
                if spec.kind == TargetKind::Binary && !test {
                    self.binary_publications[unit].push(publication);
                }
                if self.options.mode == Mode::Run {
                    self.nodes.push(Node {
                        action: Action::Run {
                            unit,
                            compiler: compiled,
                        },
                        deps: BTreeSet::from([publication]),
                        outputs: vec![],
                        label: format!("run {}", spec.name),
                    });
                }
            }
        }
        if doctests {
            let mut docs = 0;
            for &unit in &self.graph.roots {
                let targets = self.unit_manifest(unit).targets.clone();
                for (target, spec) in targets.iter().enumerate() {
                    if spec.kind == TargetKind::Library
                        && spec.doctest
                        && self.options.selects(spec)
                        && spec
                            .required_features
                            .is_subset(&self.graph.units[unit].features)
                    {
                        self.nodes.push(Node {
                            action: Action::Rustdoc {
                                unit,
                                target,
                                test: true,
                            },
                            deps: BTreeSet::new(),
                            outputs: Vec::new(),
                            label: format!("doctest {}", spec.name),
                        });
                        docs += 1;
                    }
                }
            }
            ensure!(
                !self.options.doc || docs > 0,
                "no selected documentation tests"
            );
        }
        Ok(())
    }

    fn docs_directory(&self) -> PathBuf {
        self.final_root
            .parent()
            .unwrap_or(&self.final_root)
            .join("doc")
    }

    fn allocate_docs(&mut self) -> Result<()> {
        // rustdoc writes a shared search index and static resources. Serialize
        // writers while still compiling every prerequisite concurrently.
        let mut previous = None;
        for unit in 0..self.graph.units.len() {
            let root = self.graph.units[unit].root;
            if !root && self.options.no_deps {
                continue;
            }
            let targets = self.unit_manifest(unit).targets.clone();
            for (target, spec) in targets.iter().enumerate() {
                if !spec.doc
                    || !spec
                        .required_features
                        .is_subset(&self.graph.units[unit].features)
                    || if root {
                        !self.options.selects(spec)
                    } else {
                        spec.kind != TargetKind::Library
                    }
                {
                    continue;
                }
                let mut deps = BTreeSet::new();
                if let Some(previous) = previous {
                    deps.insert(previous);
                }
                previous = Some(self.nodes.len());
                self.nodes.push(Node {
                    action: Action::Rustdoc {
                        unit,
                        target,
                        test: false,
                    },
                    deps,
                    outputs: vec![
                        self.docs_directory()
                            .join(crate_name(&spec.name))
                            .join("index.html"),
                    ],
                    label: format!("document {}", spec.name),
                });
            }
        }
        ensure!(previous.is_some(), "no documentation targets selected");
        Ok(())
    }

    fn dependencies(&mut self) -> Result<()> {
        for index in 0..self.nodes.len() {
            let mut deps = self.nodes[index].deps.clone();
            match self.nodes[index].action {
                Action::Compile {
                    unit,
                    target,
                    script,
                    test,
                    ..
                } => {
                    for edge in &self.graph.units[unit].edges {
                        let required = if script {
                            edge.kind == DependencyKind::Build
                        } else {
                            edge.kind == DependencyKind::Normal
                                || (edge.kind == DependencyKind::Dev
                                    && (test
                                        || matches!(
                                            self.target(unit, target).kind,
                                            TargetKind::Example
                                                | TargetKind::Test
                                                | TargetKind::Bench
                                        )))
                        };
                        if required {
                            deps.insert(
                                self.libraries[edge.unit].context("dependency has no library")?,
                            );
                        }
                    }
                    if !script {
                        if self.target(unit, target).kind == TargetKind::Test {
                            deps.extend(self.binary_publications[unit].iter().copied());
                        }
                        if let Some(script) = self.scripts[unit] {
                            deps.insert(script);
                        }
                        if self.target(unit, target).kind != TargetKind::Library
                            && let Some(lib) = self.libraries[unit]
                        {
                            deps.insert(lib);
                        }
                    }
                }
                Action::Script { unit, .. } => {
                    for edge in &self.graph.units[unit].edges {
                        if edge.kind != DependencyKind::Dev
                            && let Some(script) = self.scripts[edge.unit]
                        {
                            deps.insert(script);
                        }
                    }
                }
                Action::Rustdoc { unit, target, test } => {
                    for edge in &self.graph.units[unit].edges {
                        if edge.kind == DependencyKind::Normal
                            || (test && edge.kind == DependencyKind::Dev)
                        {
                            deps.insert(
                                self.libraries[edge.unit].context("missing rustdoc dependency")?,
                            );
                        }
                    }
                    if let Some(script) = self.scripts[unit] {
                        deps.insert(script);
                    }
                    if (test || self.target(unit, target).kind != TargetKind::Library)
                        && let Some(lib) = self.libraries[unit]
                    {
                        deps.insert(lib);
                    }
                }
                Action::Publish { .. } | Action::Run { .. } => {}
            }
            self.nodes[index].deps = deps;
        }
        // Validate every materialized destination up front, including root
        // names that collide across selected packages.
        let mut paths = BTreeSet::new();
        for node in &self.nodes {
            for path in &node.outputs {
                ensure!(
                    paths.insert(path),
                    "multiple build actions produce {}",
                    path.display()
                );
            }
        }
        self.graph()?;
        Ok(())
    }

    pub fn graph(&self) -> Result<BuildGraph> {
        let deps = self
            .nodes
            .iter()
            .map(|node| node.deps.iter().copied().collect())
            .collect::<Vec<_>>();
        let costs = self
            .nodes
            .iter()
            .map(|node| match node.action {
                Action::Compile { .. } => 10,
                Action::Script { .. } => 5,
                _ => 1,
            })
            .collect::<Vec<_>>();
        BuildGraph::new(&deps, &costs)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    fn script_out(&self, unit: usize) -> Option<&Path> {
        let node = self.scripts[unit]?;
        match &self.nodes[node].action {
            Action::Script { out, .. } => Some(out),
            _ => None,
        }
    }

    fn read_script(&self, unit: usize) -> Result<Option<ScriptOutput>> {
        let Some(node) = self.scripts[unit] else {
            return Ok(None);
        };
        let Action::Script { stdout, .. } = &self.nodes[node].action else {
            bail!("invalid script action")
        };
        Ok(Some(ScriptOutput::read(stdout)?))
    }

    fn env(&self, unit: usize, target: &Target) -> BTreeMap<OsString, OsString> {
        let manifest = self.unit_manifest(unit);
        let mut env = self.settings.environment.clone();
        env.retain(|name, _| {
            let name = name.as_encoded_bytes();
            ![
                b"CARGO_PKG_".as_slice(),
                b"CARGO_CFG_",
                b"CARGO_FEATURE_",
                b"CARGO_BIN_EXE_",
                b"DEP_",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix))
                && ![
                    b"CARGO_PRIMARY_PACKAGE".as_slice(),
                    b"CARGO_BIN_NAME",
                    b"CARGO_CRATE_NAME",
                    b"OUT_DIR",
                    b"HOST",
                    b"TARGET",
                    b"PROFILE",
                    b"OPT_LEVEL",
                    b"DEBUG",
                    b"NUM_JOBS",
                ]
                .contains(&name)
        });
        let package = &manifest.package;
        let mut set = |key: &str, value: OsString| {
            env.insert(key.into(), value);
        };
        set("CARGO_MANIFEST_DIR", manifest.root.clone().into_os_string());
        set(
            "CARGO_MANIFEST_PATH",
            manifest.root.join("Cargo.toml").into_os_string(),
        );
        set("CARGO_PKG_NAME", package.name.clone().into());
        set("CARGO_PKG_VERSION", package.version.to_string().into());
        for (name, value) in [
            ("MAJOR", package.version.major),
            ("MINOR", package.version.minor),
            ("PATCH", package.version.patch),
        ] {
            set(
                &format!("CARGO_PKG_VERSION_{name}"),
                value.to_string().into(),
            );
        }
        set(
            "CARGO_PKG_VERSION_PRE",
            package.version.pre.to_string().into(),
        );
        for name in [
            "description",
            "homepage",
            "repository",
            "license",
            "license-file",
            "rust-version",
            "readme",
            "authors",
        ] {
            set(
                &format!("CARGO_PKG_{}", envify(name)),
                package
                    .metadata
                    .get(name)
                    .cloned()
                    .unwrap_or_default()
                    .into(),
            );
        }
        set("CARGO_CRATE_NAME", crate_name(&target.name).into());
        if target.kind == TargetKind::Binary {
            set("CARGO_BIN_NAME", target.name.clone().into());
        }
        if self.graph.units[unit].root {
            set("CARGO_PRIMARY_PACKAGE", "1".into());
        }
        if let Some(out) = self.script_out(unit) {
            set("OUT_DIR", out.as_os_str().to_owned());
        }
        // All compiler intermediates share one stable canonical namespace.
        let build_root = if manifest.root.starts_with(&self.workspace.root) {
            &self.workspace.root
        } else {
            &manifest.root
        };
        set(
            "SCCACHE_CANONICAL_BUILD_ROOT",
            build_root.as_os_str().to_owned(),
        );
        set(
            "SCCACHE_CANONICAL_TARGET_ROOT",
            self.intermediate.as_os_str().to_owned(),
        );
        set("CARGO_TARGET_DIR", self.intermediate.as_os_str().to_owned());
        set("RUSTC", self.toolchain.rustc.as_os_str().to_owned());
        if let Some(rustdoc) = &self.toolchain.rustdoc {
            set("RUSTDOC", rustdoc.as_os_str().to_owned());
        }
        env
    }

    fn extern_path(&self, index: usize) -> Result<&Path> {
        let paths = &self.nodes[index].outputs;
        paths
            .iter()
            .find(|p| {
                p.extension()
                    .and_then(OsStr::to_str)
                    .is_some_and(|ext| matches!(ext, "rlib" | "rmeta" | "so" | "dll" | "dylib"))
            })
            .map(PathBuf::as_path)
            .context("dependency has no Rust-linkable artifact")
    }

    fn extern_arg(&self, args: &mut Vec<OsString>, alias: &str, index: usize) -> Result<()> {
        let mut extern_arg = OsString::from(format!("{}=", crate_name(alias)));
        extern_arg.push(self.extern_path(index)?);
        args.extend(["--extern".into(), extern_arg]);
        Ok(())
    }

    fn native_search(&self, unit: usize, kind: DependencyKind) -> Result<Vec<String>> {
        let mut seen = BTreeSet::new();
        let mut stack = self.graph.units[unit]
            .edges
            .iter()
            .filter(|e| e.kind == kind)
            .map(|e| e.unit)
            .collect::<Vec<_>>();
        let mut result = Vec::new();
        while let Some(dep) = stack.pop() {
            if !seen.insert(dep) {
                continue;
            }
            if let Some(script) = self.read_script(dep)? {
                for directive in script.links {
                    if let LinkDirective::Search(value) = directive {
                        result.push(value);
                    }
                }
            }
            stack.extend(
                self.graph.units[dep]
                    .edges
                    .iter()
                    .filter(|e| e.kind == DependencyKind::Normal)
                    .map(|e| e.unit),
            );
        }
        Ok(result)
    }

    fn compile_action(
        &self,
        unit: usize,
        target_index: usize,
        test: bool,
        metadata: bool,
        script: bool,
        tag: &str,
        profile: &Profile,
    ) -> Result<PlanAction> {
        let manifest = self.unit_manifest(unit);
        let target = self.target(unit, target_index);
        let host = self.host(unit, script);
        let platform = if host {
            &self.toolchain.host
        } else {
            &self.toolchain.target
        };
        let mut env = self.env(unit, target);
        let mut args = vec![
            "--crate-name".into(),
            crate_name(&target.name).into(),
            "--edition".into(),
            manifest.package.edition.clone().into(),
            target.source.clone().into_os_string(),
            "--crate-type".into(),
            if test {
                "bin".into()
            } else {
                target.crate_types.join(",").into()
            },
        ];
        if test && target.harness {
            args.push("--test".into());
        }
        if target.kind == TargetKind::Test {
            for (name, (_, executable)) in &self.binaries[unit] {
                env.insert(
                    format!("CARGO_BIN_EXE_{name}").into(),
                    executable.as_os_str().to_owned(),
                );
            }
        }
        args.extend([
            "--emit".into(),
            if metadata {
                "dep-info,metadata".into()
            } else {
                "dep-info,link".into()
            },
            "--error-format=json".into(),
            "--json=diagnostic-rendered-ansi,artifacts".into(),
            "-C".into(),
            format!("metadata={tag}").into(),
            "-C".into(),
            format!("extra-filename=-{tag}").into(),
            "--out-dir".into(),
            self.output_dir(host).into_os_string(),
        ]);
        if !host && let Some(target) = &self.toolchain.explicit_target {
            args.extend(["--target".into(), target.clone()]);
        }
        args.extend(profile.arguments(test).into_iter().map(OsString::from));
        if let Some(linker) = self.settings.linker(platform)? {
            let mut arg = OsString::from("linker=");
            arg.push(linker);
            args.extend(["-C".into(), arg]);
        }
        self.dependency_arguments(unit, target, host, script, test, &mut args, &mut env)?;
        args.extend(self.settings.rustflags(
            platform,
            host,
            self.toolchain.explicit_target.is_some(),
        )?);
        if self.options.mode == Mode::Clippy && self.graph.units[unit].root && !script {
            args.extend(self.options.trailing.iter().cloned());
        }
        if !self.graph.units[unit].root {
            args.extend(["--cap-lints".into(), "allow".into()]);
        }
        let exe = if self.options.mode == Mode::Clippy && self.graph.units[unit].root && !script {
            self.toolchain
                .clippy
                .as_deref()
                .context("clippy driver unavailable")?
        } else {
            &self.toolchain.rustc
        };
        Ok(PlanAction::Compile {
            command: command(exe, &manifest.root, args, env)?,
        })
    }

    fn dependency_arguments(
        &self,
        unit: usize,
        target: &Target,
        host: bool,
        script: bool,
        test: bool,
        args: &mut Vec<OsString>,
        env: &mut BTreeMap<OsString, OsString>,
    ) -> Result<()> {
        let manifest = self.unit_manifest(unit);
        for feature in &self.graph.units[unit].features {
            args.extend(["--cfg".into(), format!("feature={feature:?}").into()]);
        }
        let mut cfg_features = manifest
            .features
            .keys()
            .map(|f| format!("{f:?}"))
            .collect::<Vec<_>>();
        cfg_features.extend(
            manifest
                .dependencies
                .iter()
                .filter(|d| d.optional)
                .map(|d| format!("{:?}", d.alias)),
        );
        cfg_features.sort();
        cfg_features.dedup();
        args.extend([
            "--check-cfg".into(),
            format!("cfg(feature, values({}))", cfg_features.join(",")).into(),
        ]);
        let mut dependency_dir = OsString::from("dependency=");
        dependency_dir.push(self.output_dir(host));
        args.extend(["-L".into(), dependency_dir]);
        if !host {
            let mut dir = OsString::from("dependency=");
            dir.push(self.output_dir(true));
            args.extend(["-L".into(), dir]);
        }
        for edge in &self.graph.units[unit].edges {
            if if script {
                edge.kind == DependencyKind::Build
            } else {
                edge.kind == DependencyKind::Normal
                    || (edge.kind == DependencyKind::Dev
                        && (test
                            || matches!(
                                target.kind,
                                TargetKind::Example | TargetKind::Test | TargetKind::Bench
                            )))
            } {
                self.extern_arg(
                    args,
                    &edge.alias,
                    self.libraries[edge.unit].context("missing extern library")?,
                )?;
            }
        }
        if !script
            && target.kind != TargetKind::Library
            && let Some(lib) = self.libraries[unit]
        {
            self.extern_arg(args, &self.graph.library(unit)?.name, lib)?;
        }
        for value in self.native_search(
            unit,
            if script {
                DependencyKind::Build
            } else {
                DependencyKind::Normal
            },
        )? {
            args.extend(["-L".into(), value.into()]);
        }
        if !script && let Some(output) = self.read_script(unit)? {
            env.extend(output.env.into_iter().map(|(k, v)| (k.into(), v.into())));
            for cfg in output.cfg {
                args.extend(["--cfg".into(), cfg.into()]);
            }
            for cfg in output.check_cfg {
                args.extend(["--check-cfg".into(), cfg.into()]);
            }
            let has_lib = self.libraries[unit].is_some();
            for directive in output.links {
                match directive {
                    LinkDirective::Search(value) => args.extend(["-L".into(), value.into()]),
                    LinkDirective::Library(value)
                        if !has_lib || target.kind == TargetKind::Library =>
                    {
                        args.extend(["-l".into(), value.into()])
                    }
                    LinkDirective::Argument(scope, value) if applies(&scope, target, test) => {
                        args.extend(["-C".into(), format!("link-arg={value}").into()])
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn rustdoc_action(&self, unit: usize, target_index: usize, test: bool) -> Result<PlanAction> {
        let manifest = self.unit_manifest(unit);
        let target = self.target(unit, target_index);
        let host = self.host(unit, false);
        let mut env = self.env(unit, target);
        let mut args = vec![
            "--crate-name".into(),
            crate_name(&target.name).into(),
            "--edition".into(),
            manifest.package.edition.clone().into(),
            target.source.clone().into_os_string(),
            "--crate-type".into(),
            target.crate_types.join(",").into(),
        ];
        if !host && let Some(target) = &self.toolchain.explicit_target {
            args.extend(["--target".into(), target.clone()]);
        }
        self.dependency_arguments(unit, target, host, false, test, &mut args, &mut env)?;
        let platform = if host {
            &self.toolchain.host
        } else {
            &self.toolchain.target
        };
        if let Some(linker) = self.settings.linker(platform)? {
            let mut flag = OsString::from("linker=");
            flag.push(linker);
            args.extend(["-C".into(), flag]);
        }
        if test {
            // Doctest rustc invocations enter the same managed compiler path.
            args.extend([
                "--test".into(),
                "-Z".into(),
                "unstable-options".into(),
                "--test-builder".into(),
                self.toolchain.rustc.clone().into_os_string(),
                "--test-builder-wrapper".into(),
                std::env::current_exe()?.into_os_string(),
                "--test-run-directory".into(),
                manifest.root.clone().into_os_string(),
            ]);
            if let Some(lib) = self.libraries[unit] {
                self.extern_arg(&mut args, &target.name, lib)?;
            }
            for argument in &self.options.trailing {
                args.extend(["--test-args".into(), argument.clone()]);
            }
        } else {
            args.extend(["--out-dir".into(), self.docs_directory().into_os_string()]);
            args.extend(self.options.trailing.iter().cloned());
        }
        if let Some(flags) = self.settings.environment.get(OsStr::new("RUSTDOCFLAGS")) {
            args.extend(
                flags
                    .to_string_lossy()
                    .split_whitespace()
                    .map(OsString::from),
            );
        }
        Ok(PlanAction::Process {
            command: command(
                self.toolchain
                    .rustdoc
                    .as_deref()
                    .context("missing rustdoc")?,
                &manifest.root,
                args,
                env,
            )?,
            stdout: None,
            stderr: None,
            inherit_stdin: false,
        })
    }

    fn script_action(
        &self,
        unit: usize,
        compiler: usize,
        stdout: &Path,
        stderr: &Path,
        out: &Path,
    ) -> Result<PlanAction> {
        let manifest = self.unit_manifest(unit);
        let target = manifest
            .targets
            .iter()
            .find(|t| t.kind == TargetKind::BuildScript)
            .context("missing script target")?;
        let mut env = self.env(unit, target);
        env.remove(OsStr::new("RUSTFLAGS"));
        let platform = if self.graph.units[unit].domain == BuildDomain::Host {
            &self.toolchain.host
        } else {
            &self.toolchain.target
        };
        env.extend(
            platform
                .environment()
                .into_iter()
                .map(|(k, v)| (k.into(), v.into())),
        );
        for feature in &self.graph.units[unit].features {
            env.insert(
                format!("CARGO_FEATURE_{}", envify(feature)).into(),
                "1".into(),
            );
        }
        let profile = self.profile(unit, false)?;
        for (name, value) in [
            ("HOST", self.toolchain.host.triple.clone()),
            ("TARGET", platform.triple.clone()),
            (
                "PROFILE",
                if self.options.profile_name() == "release" {
                    "release".into()
                } else {
                    "debug".into()
                },
            ),
            (
                "OPT_LEVEL",
                profile
                    .options
                    .get("opt-level")
                    .cloned()
                    .unwrap_or_else(|| "0".into()),
            ),
            (
                "DEBUG",
                (profile
                    .options
                    .get("debug")
                    .is_some_and(|v| !matches!(v.as_str(), "0" | "false" | "none")))
                .to_string(),
            ),
            ("NUM_JOBS", crate::util::num_cpus().to_string()),
        ] {
            env.insert(name.into(), value.into());
        }
        env.insert("OUT_DIR".into(), out.as_os_str().to_owned());
        let flags = self.settings.rustflags(
            platform,
            self.graph.units[unit].domain == BuildDomain::Host,
            self.toolchain.explicit_target.is_some(),
        )?;
        env.insert(
            "CARGO_ENCODED_RUSTFLAGS".into(),
            flags
                .iter()
                .map(|v| v.to_string_lossy())
                .collect::<Vec<_>>()
                .join("\u{1f}")
                .into(),
        );
        for edge in &self.graph.units[unit].edges {
            if edge.kind == DependencyKind::Dev {
                continue;
            }
            let dependency = self.unit_manifest(edge.unit);
            if let Some(links) = &dependency.package.links
                && let Some(output) = self.read_script(edge.unit)?
            {
                for (name, value) in output.metadata {
                    env.insert(
                        format!("DEP_{}_{}", envify(links), envify(&name)).into(),
                        value.into(),
                    );
                }
            }
        }
        let executable = self.nodes[compiler]
            .outputs
            .first()
            .context("build script has no executable")?;
        Ok(PlanAction::Process {
            command: command(executable, &manifest.root, vec![], env)?,
            stdout: Some(path(stdout)?),
            stderr: Some(path(stderr)?),
            inherit_stdin: false,
        })
    }

    pub fn prepare(&self, index: usize) -> Result<PlanNode> {
        let node = &self.nodes[index];
        let action = match &node.action {
            Action::Compile {
                unit,
                target,
                test,
                metadata,
                script,
                tag,
                profile,
            } => self.compile_action(*unit, *target, *test, *metadata, *script, tag, profile)?,
            Action::Script {
                unit,
                compiler,
                stdout,
                stderr,
                out,
            } => self.script_action(*unit, *compiler, stdout, stderr, out)?,
            Action::Publish {
                source,
                destination,
            } => PlanAction::Publish {
                source: path(source)?,
                destination: path(destination)?,
            },
            Action::Rustdoc { unit, target, test } => self.rustdoc_action(*unit, *target, *test)?,
            Action::Run { unit, compiler } => {
                let executable = self.nodes[*compiler]
                    .outputs
                    .first()
                    .context("missing test executable")?;
                let Action::Compile { target, .. } = self.nodes[*compiler].action else {
                    bail!("invalid test compiler")
                };
                let target = self.target(*unit, target);
                let executable =
                    if self.options.mode == Mode::Run && target.kind == TargetKind::Binary {
                        &self.binaries[*unit][&target.name].1
                    } else {
                        executable
                    };
                let mut env = self.env(*unit, target);
                if let Some(output) = self.read_script(*unit)? {
                    env.extend(output.env.into_iter().map(|(k, v)| (k.into(), v.into())));
                }
                PlanAction::Process {
                    command: command(
                        executable,
                        &self.unit_manifest(*unit).root,
                        self.options.trailing.clone(),
                        env,
                    )?,
                    stdout: None,
                    stderr: None,
                    inherit_stdin: self.options.mode == Mode::Run,
                }
            }
        };
        let mut directories = node
            .outputs
            .iter()
            .filter_map(|path| path.parent())
            .map(path)
            .collect::<Result<Vec<_>>>()?;
        if let Action::Script { out, .. } = &node.action {
            directories.push(path(out)?);
        }
        Ok(PlanNode {
            label: node.label.clone(),
            dependencies: node.deps.iter().copied().collect(),
            estimated_cost: 1,
            directories,
            required_outputs: node
                .outputs
                .iter()
                .map(|p| path(p))
                .collect::<Result<_>>()?,
            action,
        })
    }

    pub fn complete(&self, index: usize) -> Result<()> {
        if let Action::Script { stdout, .. } = &self.nodes[index].action {
            let output = ScriptOutput::read(stdout)?;
            for warning in output.warnings {
                eprintln!("warning: {}: {warning}", self.nodes[index].label);
            }
        }
        Ok(())
    }
}

fn applies(scope: &LinkScope, target: &Target, test: bool) -> bool {
    match scope {
        LinkScope::All => {
            test || target.kind != TargetKind::Library
                || target.crate_types.iter().any(|t| t == "cdylib")
        }
        LinkScope::Binary(name) => target.kind == TargetKind::Binary && &target.name == name,
        LinkScope::Kind(kind) => target.kind == *kind,
        LinkScope::Cdylib => target.crate_types.iter().any(|t| t == "cdylib"),
    }
}
