use anyhow::{Context, Result, bail, ensure};
use semver::{Version, VersionReq};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use toml::{Table, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyKind {
    Normal,
    Build,
    Dev,
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub alias: String,
    pub name: String,
    pub requirement: VersionReq,
    pub path: Option<PathBuf>,
    pub git: Option<String>,
    pub git_reference: Option<(String, String)>,
    pub registry: Option<String>,
    pub optional: bool,
    pub default_features: bool,
    pub features: BTreeSet<String>,
    pub kind: DependencyKind,
    pub platform: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TargetKind {
    Library,
    Binary,
    BuildScript,
    Example,
    Test,
    Bench,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub name: String,
    pub source: PathBuf,
    pub kind: TargetKind,
    pub crate_types: Vec<String>,
    pub required_features: BTreeSet<String>,
    pub test: bool,
    pub harness: bool,
    pub doctest: bool,
    pub doc: bool,
    pub edition: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: Version,
    pub edition: String,
    pub links: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub root: PathBuf,
    pub package: Package,
    pub dependencies: Vec<Dependency>,
    pub features: BTreeMap<String, Vec<String>>,
    pub targets: Vec<Target>,
    pub lint_arguments: Vec<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug)]
pub struct Workspace {
    pub root: PathBuf,
    pub members: Vec<PathBuf>,
    pub defaults: Vec<PathBuf>,
    pub document: Table,
}

pub(crate) fn read(path: &Path) -> Result<Table> {
    let source = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&source).with_context(|| format!("parse {}", path.display()))
}

fn strings(value: Option<&Value>) -> Result<Vec<String>> {
    value.map_or_else(
        || Ok(Vec::new()),
        |value| {
            value
                .as_array()
                .context("expected string array")?
                .iter()
                .map(|v| Ok(v.as_str().context("expected string")?.to_owned()))
                .collect()
        },
    )
}

fn text<'a>(table: &'a Table, key: &str) -> Result<Option<&'a str>> {
    table
        .get(key)
        .map(|v| {
            v.as_str()
                .with_context(|| format!("{key} must be a string"))
        })
        .transpose()
}

fn boolean(table: &Table, key: &str, default: bool) -> Result<bool> {
    table.get(key).map_or(Ok(default), |v| {
        v.as_bool()
            .with_context(|| format!("{key} must be boolean"))
    })
}

fn table<'a>(document: &'a Table, key: &str) -> Result<Option<&'a Table>> {
    document
        .get(key)
        .map(|value| {
            value
                .as_table()
                .with_context(|| format!("{key} must be a table"))
        })
        .transpose()
}

// Use the ecosystem's regular glob grammar, including character classes,
// rather than an incomplete independent wildcard implementation.
fn expand(root: &Path, pattern: &str, output: &mut BTreeSet<PathBuf>) -> Result<()> {
    let root = root.to_str().context("workspace root is not UTF-8")?;
    let pattern = format!("{}/{}", glob::Pattern::escape(root), pattern);
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: true,
    };
    for entry in glob::glob_with(&pattern, options)? {
        let path = entry?;
        if path.join("Cargo.toml").is_file() {
            output.insert(path.canonicalize()?);
        }
    }
    Ok(())
}

impl Workspace {
    fn standalone(root: PathBuf, document: Table) -> Result<Self> {
        ensure!(
            document.contains_key("package"),
            "manifest has no package or workspace"
        );
        Ok(Self {
            root: root.clone(),
            members: vec![root.clone()],
            defaults: vec![root],
            document,
        })
    }

    fn from_root(root: PathBuf, document: Table) -> Result<(Self, BTreeSet<PathBuf>)> {
        let ws = table(&document, "workspace")?.context("missing [workspace]")?;
        let mut members = BTreeSet::new();
        let mut excluded = BTreeSet::new();
        let mut defaults = BTreeSet::new();
        if document.contains_key("package") {
            members.insert(root.clone());
        }
        for pattern in strings(ws.get("exclude"))? {
            expand(&root, &pattern, &mut excluded)?;
        }
        for pattern in strings(ws.get("members"))? {
            let mut matching = BTreeSet::new();
            expand(&root, &pattern, &mut matching)?;
            ensure!(
                !matching.is_empty(),
                "workspace member pattern {pattern:?} matched no manifests"
            );
            members.extend(matching);
        }
        members.retain(|p| !excluded.contains(p));
        for pattern in strings(ws.get("default-members"))? {
            expand(&root, &pattern, &mut defaults)?;
        }
        let mut workspace = Self {
            root: root.clone(),
            members: Vec::new(),
            defaults: Vec::new(),
            document,
        };
        // Path dependencies underneath the workspace root are implicit
        // members. Traverse all declarations, including inactive platforms
        // and optional features. Never absorb excluded/independent workspaces.
        let mut pending = members.clone();
        while let Some(member) = pending.pop_first() {
            let manifest = Manifest::load(&member, Some(&workspace))?;
            for dependency in &manifest.dependencies {
                let Some(path) = dependency.path.as_ref() else {
                    continue;
                };
                let path = path.canonicalize().with_context(|| {
                    format!(
                        "resolve path dependency {} of {}",
                        dependency.alias, manifest.package.name
                    )
                })?;
                if !path.starts_with(&root) || excluded.contains(&path) || members.contains(&path) {
                    continue;
                }
                let candidate = read(&path.join("Cargo.toml"))?;
                if candidate.contains_key("workspace") {
                    continue;
                }
                let explicit = table(&candidate, "package")?
                    .and_then(|p| p.get("workspace"))
                    .and_then(Value::as_str);
                if let Some(explicit) = explicit
                    && path.join(explicit).canonicalize()? != root
                {
                    continue;
                }
                members.insert(path.clone());
                pending.insert(path);
            }
        }
        ensure!(!members.is_empty(), "workspace has no packages");
        if defaults.is_empty() {
            if workspace.document.contains_key("package") {
                defaults.insert(root);
            } else {
                defaults.clone_from(&members);
            }
        }
        ensure!(
            defaults.is_subset(&members),
            "default member is not a workspace member"
        );
        workspace.members = members.into_iter().collect();
        workspace.defaults = defaults.into_iter().collect();
        Ok((workspace, excluded))
    }

    pub fn discover(manifest: &Path) -> Result<Self> {
        let manifest = manifest.canonicalize()?;
        let local = read(&manifest)?;
        let member = manifest
            .parent()
            .context("manifest has no parent")?
            .to_path_buf();
        if local.contains_key("workspace") {
            return Ok(Self::from_root(member, local)?.0);
        }
        let explicit = table(&local, "package")?
            .and_then(|p| p.get("workspace"))
            .and_then(Value::as_str);
        let root = if let Some(path) = explicit {
            Some(member.join(path).canonicalize()?)
        } else {
            let mut root = None;
            for parent in member.ancestors().skip(1) {
                let candidate = parent.join("Cargo.toml");
                if candidate.is_file() && read(&candidate)?.contains_key("workspace") {
                    root = Some(parent.to_path_buf());
                    break;
                }
            }
            root
        };
        let Some(root) = root else {
            return Self::standalone(member, local);
        };
        let document = read(&root.join("Cargo.toml"))?;
        let (mut workspace, excluded) = Self::from_root(root, document)?;
        if workspace.members.contains(&member) {
            // A manifest selected from a member is not a request to build
            // the workspace's root default-members as well.
            workspace.defaults = vec![member];
            return Ok(workspace);
        }
        ensure!(
            explicit.is_none(),
            "package.workspace does not include the package"
        );
        if excluded.contains(&member) {
            return Self::standalone(member, local);
        }
        bail!(
            "package {} is inside but not a member of workspace {}",
            member.display(),
            workspace.root.display()
        )
    }

    pub fn package(&self, root: &Path) -> Result<Manifest> {
        let root = root.canonicalize()?;
        if self.members.contains(&root) {
            Manifest::load(&root, Some(self))
        } else {
            let workspace = Self::discover(&root.join("Cargo.toml"))?;
            Manifest::load(&root, Some(&workspace))
        }
    }
}

pub(crate) fn dependency(
    alias: &str,
    value: &Value,
    kind: DependencyKind,
    platform: Option<&str>,
    root: &Path,
    workspace: Option<&Workspace>,
) -> Result<Dependency> {
    let mut spec = match value {
        Value::String(version) => {
            Table::from_iter([("version".into(), Value::String(version.clone()))])
        }
        Value::Table(spec) => spec.clone(),
        _ => bail!("invalid dependency {alias}"),
    };
    let mut base = root;
    if boolean(&spec, "workspace", false)? {
        let ws = workspace.context("workspace dependency without workspace")?;
        let shared = ws
            .document
            .get("workspace")
            .and_then(Value::as_table)
            .and_then(|t| t.get("dependencies"))
            .and_then(Value::as_table)
            .and_then(|t| t.get(alias))
            .with_context(|| format!("missing workspace dependency {alias}"))?;
        let mut inherited = match shared {
            Value::String(v) => Table::from_iter([("version".into(), Value::String(v.clone()))]),
            Value::Table(t) => t.clone(),
            _ => bail!("invalid inherited dependency {alias}"),
        };
        let mut features = strings(inherited.get("features"))?;
        features.extend(strings(spec.get("features"))?);
        for (key, value) in spec {
            match key.as_str() {
                "workspace" | "features" => {}
                "optional" | "default-features" => {
                    inherited.insert(key, value);
                }
                _ => bail!("unsupported override of workspace dependency {alias}: {key}"),
            }
        }
        inherited.insert(
            "features".into(),
            Value::Array(features.into_iter().map(Value::String).collect()),
        );
        spec = inherited;
        base = &ws.root;
    }
    ensure!(
        !spec.contains_key("artifact"),
        "artifact dependency {alias} requires explicit target planning"
    );
    let name = text(&spec, "package")?.unwrap_or(alias).to_owned();
    let mut git_reference = None;
    for key in ["rev", "tag", "branch"] {
        if let Some(value) = text(&spec, key)? {
            ensure!(
                git_reference.is_none(),
                "multiple git references on {alias}"
            );
            ensure!(spec.contains_key("git"), "{key} requires a git source");
            git_reference = Some((key.to_owned(), value.to_owned()));
        }
    }
    let path = text(&spec, "path")?.map(|p| base.join(p));
    let git = text(&spec, "git")?.map(str::to_owned);
    let registry = text(&spec, "registry")?
        .or(text(&spec, "registry-index")?)
        .map(str::to_owned);
    ensure!(
        path.is_none() || git.is_none(),
        "dependency {alias} has both path and git"
    );
    ensure!(
        git.is_none() || registry.is_none(),
        "dependency {alias} has both git and registry"
    );
    Ok(Dependency {
        alias: alias.to_owned(),
        name,
        requirement: VersionReq::parse(text(&spec, "version")?.unwrap_or("*"))?,
        path,
        git,
        git_reference,
        registry,
        optional: boolean(&spec, "optional", false)?,
        default_features: boolean(&spec, "default-features", true)?,
        features: strings(spec.get("features"))?.into_iter().collect(),
        kind,
        platform: platform.map(str::to_owned),
    })
}

fn dependencies(
    document: &Table,
    platform: Option<&str>,
    root: &Path,
    workspace: Option<&Workspace>,
    out: &mut Vec<Dependency>,
) -> Result<()> {
    for (key, kind) in [
        ("dependencies", DependencyKind::Normal),
        ("build-dependencies", DependencyKind::Build),
        ("dev-dependencies", DependencyKind::Dev),
    ] {
        if let Some(deps) = table(document, key)? {
            for (alias, value) in deps {
                out.push(dependency(alias, value, kind, platform, root, workspace)?);
            }
        }
    }
    Ok(())
}

fn target(
    root: &Path,
    spec: &Table,
    name: &str,
    path: PathBuf,
    kind: TargetKind,
) -> Result<Target> {
    let name = text(spec, "name")?.unwrap_or(name).to_owned();
    let source = text(spec, "path")?.map_or(path, |path| root.join(path));
    // Published dependencies may omit auxiliary test/example sources.
    // Validate source existence when an action is actually requested.
    let mut crate_types = strings(spec.get("crate-type"))?;
    if boolean(spec, "proc-macro", false)? {
        crate_types = vec!["proc-macro".into()];
    }
    if crate_types.is_empty() {
        crate_types.push(
            if kind == TargetKind::Library {
                "lib"
            } else {
                "bin"
            }
            .into(),
        );
    }
    Ok(Target {
        name,
        source,
        kind,
        crate_types,
        required_features: strings(spec.get("required-features"))?
            .into_iter()
            .collect(),
        test: boolean(
            spec,
            "test",
            kind != TargetKind::Example && kind != TargetKind::Bench,
        )?,
        harness: boolean(spec, "harness", true)?,
        doctest: boolean(spec, "doctest", kind == TargetKind::Library)?,
        doc: boolean(
            spec,
            "doc",
            matches!(kind, TargetKind::Library | TargetKind::Binary),
        )?,
        edition: text(spec, "edition")?.map(str::to_owned),
    })
}

fn lint_arguments(document: &Table, workspace: Option<&Workspace>) -> Result<Vec<String>> {
    let Some(local) = table(document, "lints")? else {
        return Ok(Vec::new());
    };
    let lints = if boolean(local, "workspace", false)? {
        ensure!(
            local.len() == 1,
            "cannot override inherited workspace lints"
        );
        workspace
            .context("workspace lints requested without workspace")?
            .document
            .get("workspace")
            .and_then(Value::as_table)
            .and_then(|t| t.get("lints"))
            .and_then(Value::as_table)
            .context("missing workspace.lints")?
    } else {
        local
    };
    let mut entries = Vec::new();
    for (tool, values) in lints {
        if tool == "workspace" {
            continue;
        }
        let values = values
            .as_table()
            .context("lint namespace must be a table")?;
        for (name, value) in values {
            let (level, priority, check_cfg) = match value {
                Value::String(level) => (level.as_str(), 0, Vec::new()),
                Value::Table(spec) => (
                    text(spec, "level")?.context("lint level missing")?,
                    spec.get("priority").map_or(Ok(0), |value| {
                        value.as_integer().context("invalid lint priority")
                    })?,
                    strings(spec.get("check-cfg"))?,
                ),
                _ => bail!("invalid lint setting {name}"),
            };
            let flag = match level {
                "allow" => "-A",
                "warn" => "-W",
                "deny" => "-D",
                "forbid" => "-F",
                "expect" => "--expect",
                _ => bail!("invalid lint level {level}"),
            };
            let name = if tool == "rust" {
                name.clone()
            } else {
                format!("{tool}::{name}")
            };
            entries.push((priority, name, flag, check_cfg));
        }
    }
    // Lower priority first: specific lint overrides must follow groups.
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut args = Vec::new();
    for (_, name, flag, check_cfg) in entries {
        args.extend([flag.to_owned(), name]);
        for cfg in check_cfg {
            args.extend(["--check-cfg".to_owned(), cfg]);
        }
    }
    Ok(args)
}

impl Manifest {
    pub fn load(root: &Path, workspace: Option<&Workspace>) -> Result<Self> {
        let root = root.canonicalize()?;
        let document = read(&root.join("Cargo.toml"))?;
        let mut package = table(&document, "package")?
            .context("missing [package]")?
            .clone();
        for (key, value) in &mut package {
            if value
                .as_table()
                .and_then(|t| t.get("workspace"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                *value = workspace
                    .and_then(|ws| ws.document.get("workspace"))
                    .and_then(Value::as_table)
                    .and_then(|t| t.get("package"))
                    .and_then(Value::as_table)
                    .and_then(|t| t.get(key))
                    .with_context(|| format!("missing workspace package field {key}"))?
                    .clone();
            }
        }
        let name = text(&package, "name")?
            .context("missing package name")?
            .to_owned();
        let version = Version::parse(text(&package, "version")?.unwrap_or("0.0.0"))?;
        let edition = text(&package, "edition")?.unwrap_or("2015").to_owned();
        let links = text(&package, "links")?.map(str::to_owned);
        let mut metadata = BTreeMap::new();
        for key in [
            "description",
            "homepage",
            "repository",
            "license",
            "license-file",
            "rust-version",
            "readme",
        ] {
            if let Some(value) = package.get(key).and_then(Value::as_str) {
                metadata.insert(key.to_owned(), value.to_owned());
            }
        }
        metadata.insert("authors".into(), strings(package.get("authors"))?.join(":"));
        let mut deps = Vec::new();
        dependencies(&document, None, &root, workspace, &mut deps)?;
        if let Some(platforms) = table(&document, "target")? {
            for (platform, value) in platforms {
                dependencies(
                    value
                        .as_table()
                        .context("invalid target dependency table")?,
                    Some(platform),
                    &root,
                    workspace,
                    &mut deps,
                )?;
            }
        }
        let mut features = BTreeMap::new();
        if let Some(values) = table(&document, "features")? {
            for (name, value) in values {
                features.insert(name.clone(), strings(Some(value))?);
            }
        }
        let mut targets = Vec::new();
        let empty = Table::new();
        if document.contains_key("lib")
            || (boolean(&package, "autolib", true)? && root.join("src/lib.rs").is_file())
        {
            targets.push(target(
                &root,
                table(&document, "lib")?.unwrap_or(&empty),
                &name.replace('-', "_"),
                root.join("src/lib.rs"),
                TargetKind::Library,
            )?);
        }
        for (key, dir, auto, kind) in [
            ("bin", "src/bin", "autobins", TargetKind::Binary),
            ("example", "examples", "autoexamples", TargetKind::Example),
            ("test", "tests", "autotests", TargetKind::Test),
            ("bench", "benches", "autobenches", TargetKind::Bench),
        ] {
            let mut seen = BTreeSet::new();
            if let Some(value) = document.get(key) {
                for spec in value.as_array().context("invalid target array")? {
                    let spec = spec.as_table().context("invalid target")?;
                    let target_name =
                        text(spec, "name")?.context("explicit target requires a name")?;
                    let mut candidate = root.join(dir).join(format!("{target_name}.rs"));
                    if !candidate.is_file() {
                        candidate = root.join(dir).join(target_name).join("main.rs");
                    }
                    if kind == TargetKind::Binary
                        && target_name == name
                        && root.join("src/main.rs").is_file()
                    {
                        candidate = root.join("src/main.rs");
                    }
                    targets.push(target(&root, spec, target_name, candidate, kind)?);
                    seen.insert(target_name.to_owned());
                }
            }
            if boolean(&package, auto, true)? {
                if kind == TargetKind::Binary
                    && !seen.contains(&name)
                    && root.join("src/main.rs").is_file()
                {
                    targets.push(target(
                        &root,
                        &empty,
                        &name,
                        root.join("src/main.rs"),
                        kind,
                    )?);
                    seen.insert(name.clone());
                }
                let directory = root.join(dir);
                if directory.is_dir() {
                    for entry in fs::read_dir(directory)? {
                        let entry = entry?;
                        let path = entry.path();
                        let (name, source) =
                            if path.is_file() && path.extension().is_some_and(|s| s == "rs") {
                                (path.file_stem(), path.clone())
                            } else if path.is_dir() && path.join("main.rs").is_file() {
                                (path.file_name(), path.join("main.rs"))
                            } else {
                                continue;
                            };
                        let name = name
                            .and_then(|s| s.to_str())
                            .context("target name is not UTF-8")?;
                        if seen.insert(name.to_owned()) {
                            targets.push(target(&root, &empty, name, source, kind)?);
                        }
                    }
                }
            }
        }
        let build = match package.get("build") {
            Some(Value::Boolean(false)) => None,
            Some(Value::String(path)) => Some(root.join(path)),
            Some(Value::Boolean(true)) => Some(root.join("build.rs")),
            None => root
                .join("build.rs")
                .is_file()
                .then(|| root.join("build.rs")),
            _ => bail!("invalid package.build"),
        };
        if let Some(build) = build {
            targets.push(target(
                &root,
                &empty,
                "build_script_build",
                build,
                TargetKind::BuildScript,
            )?);
        }
        targets.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));
        ensure!(!targets.is_empty(), "package {name} has no targets");
        Ok(Self {
            root,
            package: Package {
                name,
                version,
                edition,
                links,
                metadata,
            },
            dependencies: deps,
            features,
            targets,
            lint_arguments: lint_arguments(&document, workspace)?,
            metadata: package.get("metadata").cloned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_package(root: &Path, name: &str, extra: &str) -> Result<()> {
        fs::create_dir_all(root.join("src"))?;
        fs::write(root.join("src/lib.rs"), "")?;
        fs::write(
            root.join("Cargo.toml"),
            format!("[package]\nname={name:?}\nversion=\"1.0.0\"\nedition=\"2024\"\n{extra}"),
        )?;
        Ok(())
    }

    #[test]
    fn implicit_members_exclusions_and_member_default_selection() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        fs::write(
            root.join("Cargo.toml"),
            r#"
[workspace]
members = ["crates/[ab]"]
default-members = ["crates/a"]
exclude = ["excluded"]
[workspace.dependencies]
implicit = { path = "implicit" }
[workspace.lints.rust]
warnings = { level = "deny", priority = -1 }
dead_code = "allow"
unexpected_cfgs = { level = "warn", check-cfg = ["cfg(native_build)"] }
[workspace.lints.clippy]
all = { level = "warn", priority = -2 }
"#,
        )?;
        write_package(
            &root.join("crates/a"),
            "a",
            r#"
[dependencies]
implicit = { workspace = true }
excluded = { path = "../../excluded" }
[lints]
workspace = true
[lib]
edition = "2021"
"#,
        )?;
        write_package(&root.join("crates/b"), "b", "")?;
        write_package(
            &root.join("implicit"),
            "implicit",
            "[dependencies]\nleaf={path=\"../leaf\"}\n",
        )?;
        write_package(&root.join("leaf"), "leaf", "")?;
        write_package(&root.join("excluded"), "excluded", "")?;
        let ws = Workspace::discover(&root.join("Cargo.toml"))?;
        assert_eq!(ws.members.len(), 4);
        assert!(ws.members.contains(&root.join("implicit")));
        assert!(ws.members.contains(&root.join("leaf")));
        assert!(!ws.members.contains(&root.join("excluded")));
        assert_eq!(ws.defaults, vec![root.join("crates/a")]);
        let member = Workspace::discover(&root.join("crates/b/Cargo.toml"))?;
        assert_eq!(member.defaults, vec![root.join("crates/b")]);
        let excluded = Workspace::discover(&root.join("excluded/Cargo.toml"))?;
        assert_eq!(excluded.root, root.join("excluded"));
        let a = ws.package(&root.join("crates/a"))?;
        assert_eq!(a.targets[0].edition.as_deref(), Some("2021"));
        assert_eq!(
            a.lint_arguments,
            [
                "-W",
                "clippy::all",
                "-D",
                "warnings",
                "-A",
                "dead_code",
                "-W",
                "unexpected_cfgs",
                "--check-cfg",
                "cfg(native_build)"
            ]
        );
        Ok(())
    }
}
