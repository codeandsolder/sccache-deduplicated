//! Registry resolution is independent of build execution. Search decisions are
//! reversible: later constraints can change earlier choices rather than silently
//! selecting incompatible duplicate versions in one semver compatibility class.
use crate::{
    Dependency, DependencyKind, LockedPackage, Lockfile, Manifest, Package, Sources,
    resolve::{all_features, default_feature, feature_request},
    source::{identity, load_discovered, validate_dependency},
};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Duration, Utc};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
};

const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[derive(Clone, Debug)]
struct Candidate {
    manifest: Manifest,
    lock: LockedPackage,
}

#[derive(Deserialize)]
struct IndexDependency {
    name: String,
    package: Option<String>,
    req: VersionReq,
    #[serde(default)]
    features: BTreeSet<String>,
    #[serde(default)]
    optional: bool,
    #[serde(default = "yes")]
    default_features: bool,
    target: Option<String>,
    kind: Option<String>,
    registry: Option<String>,
}

const fn yes() -> bool {
    true
}

#[derive(Deserialize)]
struct IndexRecord {
    name: String,
    vers: Version,
    cksum: String,
    #[serde(default)]
    deps: Vec<IndexDependency>,
    #[serde(default)]
    features: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    features2: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    yanked: bool,
    links: Option<String>,
    rust_version: Option<String>,
    pubtime: Option<String>,
    #[serde(default)]
    v: u32,
}

impl IndexRecord {
    fn candidate(self) -> Result<Candidate> {
        let mut features = self.features;
        for (name, more) in self.features2 {
            features.entry(name).or_default().extend(more);
        }
        let dependencies = self
            .deps
            .into_iter()
            .map(|d| {
                let kind = match d.kind.as_deref() {
                    None | Some("normal") => DependencyKind::Normal,
                    Some("build") => DependencyKind::Build,
                    Some("dev") => DependencyKind::Dev,
                    Some(kind) => bail!("unknown registry dependency kind {kind}"),
                };
                Ok(Dependency {
                    alias: d.name.clone(),
                    name: d.package.unwrap_or(d.name),
                    requirement: d.req,
                    path: None,
                    git: None,
                    registry: d.registry,
                    optional: d.optional,
                    default_features: d.default_features,
                    features: d.features,
                    kind,
                    platform: d.target,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let lock = LockedPackage {
            name: self.name.clone(),
            version: self.vers.clone(),
            source: Some(REGISTRY.to_owned()),
            checksum: Some(self.cksum),
            dependencies: Vec::new(),
        };
        Ok(Candidate {
            manifest: Manifest {
                root: PathBuf::new(),
                package: Package {
                    name: self.name,
                    version: self.vers,
                    edition: String::new(),
                    links: self.links,
                    metadata: BTreeMap::new(),
                },
                dependencies,
                features,
                targets: Vec::new(),
            },
            lock,
        })
    }
}

fn index_path(name: &str) -> Result<String> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid registry package name {name}"
    );
    let name = name.to_ascii_lowercase();
    Ok(match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    })
}

fn records(bytes: &[u8]) -> Result<Vec<IndexRecord>> {
    // The local sparse cache contains NUL-delimited JSON entries, whereas
    // the network index contains newline-delimited JSON. Neither needs a
    // Cargo process or a Cargo library.
    let segments: Vec<_> = if bytes.first() == Some(&3) {
        bytes
            .split(|&b| b == 0)
            .filter(|s| s.first() == Some(&b'{'))
            .collect()
    } else {
        bytes
            .split(|&b| b == b'\n')
            .filter(|s| !s.is_empty())
            .collect()
    };
    segments
        .into_iter()
        .map(|s| Ok(serde_json::from_slice(s)?))
        .collect()
}

fn rust_version(value: &str) -> Option<Version> {
    Version::parse(value)
        .or_else(|_| Version::parse(&format!("{value}.0")))
        .ok()
}

fn same_class(a: &Version, b: &Version) -> bool {
    a.major == b.major
        && (a.major != 0 || (a.minor == b.minor && (a.minor != 0 || a.patch == b.patch)))
}

#[derive(Clone)]
struct Chosen {
    candidate: Arc<Candidate>,
    requested: BTreeSet<String>,
    root: bool,
    edges: BTreeMap<usize, String>,
}

#[derive(Clone)]
struct Need {
    parent: String,
    index: usize,
    features: BTreeSet<String>,
}

#[derive(Clone, Default)]
struct State {
    chosen: BTreeMap<String, Chosen>,
    needs: VecDeque<Need>,
}

impl State {
    fn activate(
        &mut self,
        candidate: Arc<Candidate>,
        requested: BTreeSet<String>,
        root: bool,
    ) -> Result<String> {
        let id = identity(&candidate.lock);
        let fresh = !self.chosen.contains_key(&id);
        let chosen = self.chosen.entry(id.clone()).or_insert_with(|| Chosen {
            candidate,
            requested: BTreeSet::new(),
            root,
            edges: BTreeMap::new(),
        });
        let old_len = chosen.requested.len();
        let was_root = chosen.root;
        chosen.root |= root;
        chosen.requested.extend(requested);
        if fresh || old_len != chosen.requested.len() || was_root != chosen.root {
            let manifest = &chosen.candidate.manifest;
            let features = feature_request(manifest, &chosen.requested)?;
            for (index, dep) in manifest.dependencies.iter().enumerate() {
                if dep.kind == DependencyKind::Dev && !chosen.root {
                    continue;
                }
                if dep.optional && !features.optional.contains(&dep.alias) {
                    continue;
                }
                let mut requested = dep.features.clone();
                if let Some(forwards) = features.forwards.get(&dep.alias) {
                    requested.extend(forwards.iter().cloned());
                }
                self.needs.push_back(Need {
                    parent: id.clone(),
                    index,
                    features: requested,
                });
            }
        }
        Ok(id)
    }

    fn choose(&mut self, need: &Need, candidate: Arc<Candidate>) -> Result<()> {
        let id = identity(&candidate.lock);
        let parent = &self.chosen[&need.parent];
        let dep = &parent.candidate.manifest.dependencies[need.index];
        if let Some(existing) = parent.edges.get(&need.index) {
            ensure!(existing == &id, "dependency edge already selected");
        }
        for (other_id, other) in &self.chosen {
            if other_id == &id {
                continue;
            }
            let a = &candidate.lock;
            let b = &other.candidate.lock;
            ensure!(
                a.name != b.name || a.source != b.source || !same_class(&a.version, &b.version),
                "semver-compatible versions {} {} and {} conflict",
                a.name,
                a.version,
                b.version
            );
            if let Some(links) = &candidate.manifest.package.links {
                ensure!(
                    other.candidate.manifest.package.links.as_ref() != Some(links),
                    "native links conflict: {links}"
                );
            }
        }
        let mut requested = need.features.clone();
        default_feature(&candidate.manifest, dep.default_features, &mut requested);
        let id = self.activate(candidate, requested, false)?;
        self.chosen
            .get_mut(&need.parent)
            .context("missing parent")?
            .edges
            .insert(need.index, id);
        Ok(())
    }

    fn lock(self) -> Lockfile {
        let packages = self
            .chosen
            .values()
            .map(|chosen| {
                let mut lock = chosen.candidate.lock.clone();
                lock.dependencies = chosen
                    .edges
                    .values()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .map(|id| {
                        let child = &self.chosen[&id].candidate.lock;
                        match &child.source {
                            Some(source) => format!("{} {} ({source})", child.name, child.version),
                            None => format!("{} {}", child.name, child.version),
                        }
                    })
                    .collect();
                lock
            })
            .collect();
        Lockfile {
            version: Some(4),
            packages,
        }
    }
}

struct Search<'a, 'b> {
    sources: &'a Sources<'b>,
    cutoff: DateTime<Utc>,
    rustc: Version,
    registry: BTreeMap<String, Vec<Arc<Candidate>>>,
    paths: BTreeMap<PathBuf, Arc<Candidate>>,
}

impl Search<'_, '_> {
    fn path(&mut self, root: &Path) -> Result<Arc<Candidate>> {
        let root = root.canonicalize()?;
        if let Some(candidate) = self.paths.get(&root) {
            return Ok(Arc::clone(candidate));
        }
        let manifest = if root.starts_with(&self.sources.workspace.root) {
            Manifest::load(&root, Some(self.sources.workspace))?
        } else {
            load_discovered(&root)?
        };
        let lock = LockedPackage {
            name: manifest.package.name.clone(),
            version: manifest.package.version.clone(),
            source: None,
            checksum: None,
            dependencies: Vec::new(),
        };
        let candidate = Arc::new(Candidate { manifest, lock });
        self.paths.insert(root, Arc::clone(&candidate));
        Ok(candidate)
    }

    fn index(&mut self, name: &str) -> Result<Vec<Arc<Candidate>>> {
        if let Some(candidates) = self.registry.get(name) {
            return Ok(candidates.clone());
        }
        let relative = index_path(name)?;
        let bytes = if let Some(download) = self.sources.download {
            let mut file = tempfile::tempfile_in(&self.sources.scratch)?;
            download(&format!("https://index.crates.io/{relative}"), &mut file)?;
            file.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            bytes
        } else {
            let import = self
                .sources
                .import_root
                .as_ref()
                .context("no offline index configured")?;
            // Only import the crates.io index, never a similarly named crate
            // from an arbitrary alternative registry.
            let index = import.join("registry/index");
            let mut candidates = Vec::new();
            for entry in fs::read_dir(index)? {
                let entry = entry?;
                if !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("index.crates.io-")
                {
                    continue;
                }
                let path = entry.path().join(".cache").join(&relative);
                if path.is_file() {
                    candidates.push(path);
                }
            }
            ensure!(
                candidates.len() == 1,
                "missing or ambiguous offline crates.io index entry for {name}"
            );
            fs::read(&candidates[0])?
        };
        let mut result = Vec::new();
        for record in records(&bytes)? {
            if record.name != name || record.v > 2 || record.yanked {
                continue;
            }
            // Release policy is based on registry-published time, not file
            // timestamps. Existing locked versions are not re-selected here.
            if !record
                .pubtime
                .as_deref()
                .and_then(|v| v.parse::<DateTime<Utc>>().ok())
                .is_some_and(|time| time <= self.cutoff)
            {
                continue;
            }
            if record
                .rust_version
                .as_deref()
                .and_then(rust_version)
                .is_some_and(|v| v > self.rustc)
            {
                continue;
            }
            result.push(Arc::new(record.candidate()?));
        }
        result.sort_by(|a, b| b.lock.version.cmp(&a.lock.version));
        self.registry.insert(name.to_owned(), result.clone());
        Ok(result)
    }

    fn candidates(&mut self, state: &State, need: &Need) -> Result<Vec<Arc<Candidate>>> {
        let parent = &state.chosen[&need.parent];
        let dep = &parent.candidate.manifest.dependencies[need.index];
        if let Some(id) = parent.edges.get(&need.index) {
            return Ok(vec![Arc::clone(&state.chosen[id].candidate)]);
        }
        if let Some(path) = &dep.path {
            let candidate = self.path(path)?;
            validate_dependency(&candidate.manifest, dep)?;
            return Ok(vec![candidate]);
        }
        ensure!(
            dep.git.is_none(),
            "unlocked git dependencies require an exact source lock: {}",
            dep.alias
        );
        ensure!(
            dep.registry.as_deref().is_none_or(|v| matches!(
                v,
                "crates-io" | "https://github.com/rust-lang/crates.io-index"
            )),
            "unsupported unlocked registry for {}",
            dep.alias
        );
        let mut candidates = self.index(&dep.name)?;
        if let Some(patches) = self
            .sources
            .workspace
            .document
            .get("patch")
            .and_then(toml::Value::as_table)
            .and_then(|t| t.get("crates-io"))
            .and_then(toml::Value::as_table)
        {
            for (name, patch) in patches {
                let Some(spec) = patch.as_table() else {
                    continue;
                };
                if spec
                    .get("package")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(name)
                    != dep.name
                {
                    continue;
                }
                let path = spec
                    .get("path")
                    .and_then(toml::Value::as_str)
                    .context("unlocked non-path patch requires exact source lock")?;
                let candidate = self.path(&self.sources.workspace.root.join(path))?;
                candidates.retain(|other| other.lock.version != candidate.lock.version);
                candidates.push(candidate);
            }
        }
        candidates.retain(|c| dep.requirement.matches(&c.lock.version));
        // Prefer reusing an existing choice, then locked versions from the
        // previous lockfile, then the newest eligible version.
        candidates.sort_by_cached_key(|c| {
            let reused = state.chosen.contains_key(&identity(&c.lock));
            let locked = self
                .sources
                .lock
                .packages
                .iter()
                .any(|p| identity(p) == identity(&c.lock));
            (
                std::cmp::Reverse(reused),
                std::cmp::Reverse(locked),
                std::cmp::Reverse(c.lock.version.clone()),
            )
        });
        Ok(candidates)
    }

    fn solve(&mut self) -> Result<Lockfile> {
        let mut state = State::default();
        for member in &self.sources.workspace.members {
            let candidate = self.path(member)?;
            let mut requested = BTreeSet::new();
            all_features(&candidate.manifest, &mut requested);
            state.activate(candidate, requested, true)?;
        }
        // Keep alternatives only at genuine decision points. Failed feature
        // constraints, native links conflicts and semver conflicts all unwind
        // to an earlier choice; no recursion proportional to graph depth.
        let mut alternatives = Vec::<(State, Need, std::vec::IntoIter<Arc<Candidate>>)>::new();
        let mut failure;
        loop {
            let Some(need) = state.needs.pop_front() else {
                return Ok(state.lock());
            };
            let candidates = self.candidates(&state, &need)?;
            let mut valid = candidates.into_iter().filter_map(|candidate| {
                let mut next = state.clone();
                next.choose(&need, Arc::clone(&candidate))
                    .ok()
                    .map(|()| candidate)
            });
            if let Some(first) = valid.next() {
                let rest = valid.collect::<Vec<_>>();
                if !rest.is_empty() {
                    alternatives.push((state.clone(), need.clone(), rest.into_iter()));
                }
                state.choose(&need, first)?;
                continue;
            }
            let dep = &state.chosen[&need.parent].candidate.manifest.dependencies[need.index];
            failure = format!(
                "{} requires {} {} with features {:?}",
                need.parent, dep.name, dep.requirement, need.features
            );
            loop {
                let Some((mut previous, need, mut rest)) = alternatives.pop() else {
                    bail!("no version solution: {failure}");
                };
                if let Some(next) = rest.next() {
                    if rest.len() > 0 {
                        alternatives.push((previous.clone(), need.clone(), rest));
                    }
                    previous.choose(&need, next)?;
                    state = previous;
                    break;
                }
            }
        }
    }
}

impl Sources<'_> {
    pub fn resolve_lock(&self, rustc: &str) -> Result<Lockfile> {
        let version = rustc
            .lines()
            .find_map(|line| line.strip_prefix("release: "))
            .context("rustc release is missing")?;
        let mut version = Version::parse(version)?;
        // Nightly is allowed to build packages requiring the corresponding
        // stable language version.
        version.pre = semver::Prerelease::EMPTY;
        Search {
            sources: self,
            cutoff: Utc::now() - Duration::hours(72),
            rustc: version,
            registry: BTreeMap::new(),
            paths: BTreeMap::new(),
        }
        .solve()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Workspace;
    use serde_json::json;

    fn package(root: &Path, name: &str, body: &str) -> Result<()> {
        fs::create_dir_all(root.join("src"))?;
        fs::write(root.join("src/lib.rs"), "")?;
        fs::write(
            root.join("Cargo.toml"),
            format!("[package]\nname={name:?}\nversion=\"0.1.0\"\nedition=\"2024\"\n{body}"),
        )?;
        Ok(())
    }

    fn index(root: &Path, name: &str, entries: &[serde_json::Value]) -> Result<()> {
        let path = root
            .join("registry/index/index.crates.io-fixture/.cache")
            .join(index_path(name)?);
        fs::create_dir_all(path.parent().context("missing index parent")?)?;
        let mut bytes = vec![3, 2, 0, 0, 0];
        bytes.extend_from_slice(b"etag: fixture\0");
        for entry in entries {
            bytes.extend_from_slice(
                entry["vers"]
                    .as_str()
                    .context("version missing")?
                    .as_bytes(),
            );
            bytes.push(0);
            bytes.extend_from_slice(&serde_json::to_vec(entry)?);
            bytes.push(0);
        }
        fs::write(path, bytes)?;
        Ok(())
    }

    fn release(
        name: &str,
        version: &str,
        deps: serde_json::Value,
        features: serde_json::Value,
    ) -> serde_json::Value {
        json!({"name": name, "vers": version, "deps": deps, "cksum": "0".repeat(64), "features": features, "pubtime": "2020-01-01T00:00:00Z"})
    }

    #[test]
    fn backtracks_and_preserves_feature_and_version_constraints() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("workspace");
        package(&root, "app", "[dependencies]\na = \"1\"\nb = \"1\"\n")?;
        let import = temp.path().join("import");
        index(
            &import,
            "a",
            &[
                release("a", "1.0.0", json!([]), json!({"needed": []})),
                release("a", "1.1.0", json!([]), json!({})),
            ],
        )?;
        index(
            &import,
            "b",
            &[release(
                "b",
                "1.0.0",
                json!([{"name":"a", "req":"=1.0.0", "features":["needed"], "default_features":true}]),
                json!({}),
            )],
        )?;
        let workspace = Workspace::discover(&root.join("Cargo.toml"))?;
        let scratch = temp.path().join("scratch");
        fs::create_dir_all(&scratch)?;
        let sources = Sources::new(&workspace, Lockfile::default(), Some(import), scratch);
        let lock = sources.resolve_lock("release: 1.100.0-nightly")?;
        assert_eq!(lock.packages.len(), 3);
        assert!(
            lock.packages
                .iter()
                .any(|p| p.name == "a" && p.version == Version::new(1, 0, 0))
        );
        assert!(
            !lock
                .packages
                .iter()
                .any(|p| p.name == "a" && p.version == Version::new(1, 1, 0))
        );
        let file = root.join("Cargo.lock");
        lock.write(&file)?;
        let loaded = Lockfile::load(&file)?;
        assert_eq!(toml::to_string(&loaded)?, toml::to_string(&lock)?);
        Ok(())
    }

    #[test]
    fn selects_two_incompatible_major_versions_and_rejects_new_release() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("workspace");
        package(
            &root,
            "app",
            "[dependencies]\nold = { package = \"a\", version = \"1\" }\nnew = { package = \"a\", version = \"2\" }\n",
        )?;
        let import = temp.path().join("import");
        let mut future = release("a", "2.1.0", json!([]), json!({}));
        future["pubtime"] = json!("2100-01-01T00:00:00Z");
        index(
            &import,
            "a",
            &[
                release("a", "1.0.0", json!([]), json!({})),
                release("a", "2.0.0", json!([]), json!({})),
                future,
            ],
        )?;
        let workspace = Workspace::discover(&root.join("Cargo.toml"))?;
        let scratch = temp.path().join("scratch");
        fs::create_dir_all(&scratch)?;
        let sources = Sources::new(&workspace, Lockfile::default(), Some(import), scratch);
        let lock = sources.resolve_lock("release: 1.100.0-nightly")?;
        assert_eq!(
            lock.packages
                .iter()
                .filter(|p| p.name == "a")
                .map(|p| p.version.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([Version::new(1, 0, 0), Version::new(2, 0, 0)])
        );
        Ok(())
    }
}
