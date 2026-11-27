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

// Workspace globs cover path components (including **). Do not recurse into
// symlink directories: explicit members may still refer to external paths.
fn glob(pattern: &[u8], name: &[u8]) -> bool {
    let mut row = vec![false; name.len() + 1];
    row[0] = true;
    for &byte in pattern {
        let mut next = vec![false; row.len()];
        if byte == b'*' {
            next[0] = row[0];
            for j in 1..next.len() {
                next[j] = row[j] || next[j - 1];
            }
        } else {
            for j in 1..next.len() {
                next[j] = row[j - 1] && (byte == b'?' || byte == name[j - 1]);
            }
        }
        row = next;
    }
    row[name.len()]
}

fn expand(root: &Path, pattern: &str, output: &mut BTreeSet<PathBuf>) -> Result<()> {
    fn walk(root: &Path, parts: &[&str], out: &mut BTreeSet<PathBuf>) -> Result<()> {
        let Some((head, tail)) = parts.split_first() else {
            if root.join("Cargo.toml").is_file() {
                out.insert(root.canonicalize()?);
            }
            return Ok(());
        };
        if *head == "**" {
            walk(root, tail, out)?;
            for entry in fs::read_dir(root)? {
                let entry = entry?;
                if entry.file_type()?.is_dir()
                    && !entry.file_name().to_string_lossy().starts_with('.')
                {
                    walk(&entry.path(), parts, out)?;
                }
            }
        } else if head.contains(['*', '?']) {
            for entry in fs::read_dir(root)? {
                let entry = entry?;
                if entry.file_type()?.is_dir()
                    && glob(head.as_bytes(), entry.file_name().as_encoded_bytes())
                {
                    walk(&entry.path(), tail, out)?;
                }
            }
        } else {
            walk(&root.join(head), tail, out)?;
        }
        Ok(())
    }
    walk(
        root,
        &pattern
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect::<Vec<_>>(),
        output,
    )
}

impl Workspace {
    pub fn discover(manifest: &Path) -> Result<Self> {
        let manifest = manifest.canonicalize()?;
        let local = read(&manifest)?;
        let member = manifest
            .parent()
            .context("manifest has no parent")?
            .to_path_buf();
        let explicit = table(&local, "package")?
            .and_then(|p| p.get("workspace"))
            .and_then(Value::as_str);
        let root = if let Some(path) = explicit {
            member.join(path).canonicalize()?
        } else if local.contains_key("workspace") {
            member.clone()
        } else {
            let mut found = member.clone();
            for parent in member.ancestors().skip(1) {
                let candidate = parent.join("Cargo.toml");
                if candidate.is_file() && read(&candidate)?.contains_key("workspace") {
                    found = parent.to_path_buf();
                    break;
                }
            }
            found
        };
        let document = read(&root.join("Cargo.toml"))?;
        let mut members = BTreeSet::new();
        let mut defaults = BTreeSet::new();
        if document.contains_key("package") {
            members.insert(root.clone());
        }
        if let Some(ws) = table(&document, "workspace")? {
            for pattern in strings(ws.get("members"))? {
                expand(&root, &pattern, &mut members)?;
            }
            let mut excluded = BTreeSet::new();
            for pattern in strings(ws.get("exclude"))? {
                expand(&root, &pattern, &mut excluded)?;
            }
            members.retain(|p| !excluded.contains(p));
            for pattern in strings(ws.get("default-members"))? {
                expand(&root, &pattern, &mut defaults)?;
            }
        }
        if members.is_empty() && local.contains_key("package") {
            members.insert(member.clone());
        }
        ensure!(!members.is_empty(), "workspace has no packages");
        if member != root && local.contains_key("package") {
            defaults.insert(member.clone());
            members.insert(member);
        }
        if defaults.is_empty() {
            if document.contains_key("package") {
                defaults.insert(root.clone());
            } else {
                defaults.clone_from(&members);
            }
        }
        ensure!(
            defaults.is_subset(&members),
            "default member is not a workspace member"
        );
        Ok(Self {
            root,
            members: members.into_iter().collect(),
            defaults: defaults.into_iter().collect(),
            document,
        })
    }

    pub fn package(&self, root: &Path) -> Result<Manifest> {
        Manifest::load(root, Some(self))
    }
}

fn dependency(
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
    Ok(Dependency {
        alias: alias.to_owned(),
        name,
        requirement: VersionReq::parse(text(&spec, "version")?.unwrap_or("*"))?,
        path: text(&spec, "path")?.map(|p| base.join(p)),
        git: text(&spec, "git")?.map(str::to_owned),
        git_reference,
        registry: text(&spec, "registry")?.map(str::to_owned),
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
    ensure!(
        source.is_file(),
        "missing target source {}",
        source.display()
    );
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
        test: boolean(spec, "test", true)?,
    })
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
        })
    }
}
