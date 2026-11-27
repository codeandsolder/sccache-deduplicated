use crate::{Dependency, DependencyKind, Manifest, Platform, Sources, TargetKind};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::{
    num::NonZeroUsize,
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
};

/// Features for host dependencies and target dependencies are unified
/// separately, as required by the modern Rust workspace resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BuildDomain {
    Host,
    Target,
}

#[derive(Debug, Clone)]
pub struct Edge {
    pub alias: String,
    pub unit: usize,
    pub kind: DependencyKind,
}

#[derive(Debug)]
pub struct Unit {
    pub package: usize,
    pub domain: BuildDomain,
    pub features: BTreeSet<String>,
    pub edges: Vec<Edge>,
    pub root: bool,
}

#[derive(Debug)]
pub struct Graph {
    pub packages: Vec<Manifest>,
    pub sources: Vec<Option<String>>,
    pub units: Vec<Unit>,
    pub roots: Vec<usize>,
}

#[derive(Clone)]
pub struct ResolveOptions {
    pub selected: Vec<PathBuf>,
    pub features: BTreeSet<String>,
    pub default_features: bool,
    pub all_features: bool,
    pub dev_dependencies: bool,
    pub host: Platform,
    pub target: Platform,
    pub source_jobs: NonZeroUsize,
}

#[derive(Default)]
pub(crate) struct FeatureRequest {
    pub(crate) names: BTreeSet<String>,
    pub(crate) optional: BTreeSet<String>,
    pub(crate) forwards: BTreeMap<String, BTreeSet<String>>,
}

pub(crate) fn feature_request(
    package: &Manifest,
    requested: &BTreeSet<String>,
) -> Result<FeatureRequest> {
    let optional: BTreeSet<_> = package
        .dependencies
        .iter()
        .filter(|d| d.optional)
        .map(|d| d.alias.as_str())
        .collect();
    let aliases: BTreeSet<_> = package
        .dependencies
        .iter()
        .map(|d| d.alias.as_str())
        .collect();
    let hidden: BTreeSet<_> = package
        .features
        .values()
        .flatten()
        .filter_map(|s| s.strip_prefix("dep:"))
        .collect();
    let mut pending = requested.iter().cloned().collect::<VecDeque<_>>();
    let mut state = FeatureRequest::default();
    let mut weak = Vec::new();
    while let Some(name) = pending.pop_front() {
        if let Some(alias) = name.strip_prefix("dep:") {
            ensure!(
                optional.contains(alias),
                "unknown optional dependency {alias} in {}",
                package.package.name
            );
            state.optional.insert(alias.to_owned());
        } else if let Some((alias, feature)) = name.split_once('/') {
            let weak_alias = alias.strip_suffix('?');
            let alias = weak_alias.unwrap_or(alias);
            ensure!(
                aliases.contains(alias) && !feature.is_empty(),
                "invalid dependency feature {name}"
            );
            if weak_alias.is_some() {
                ensure!(
                    optional.contains(alias),
                    "weak feature requires optional dependency {alias}"
                );
                weak.push((alias.to_owned(), feature.to_owned()));
            } else {
                if optional.contains(alias) {
                    state.optional.insert(alias.to_owned());
                    if !hidden.contains(alias) {
                        pending.push_back(alias.to_owned());
                    }
                }
                state
                    .forwards
                    .entry(alias.to_owned())
                    .or_default()
                    .insert(feature.to_owned());
            }
        } else if state.names.insert(name.clone()) {
            if let Some(entries) = package.features.get(&name) {
                pending.extend(entries.iter().cloned());
            } else if optional.contains(name.as_str()) && !hidden.contains(name.as_str()) {
                state.optional.insert(name);
            } else {
                anyhow::bail!("unknown feature {name} in {}", package.package.name);
            }
        }
    }
    for (alias, feature) in weak {
        if state.optional.contains(&alias) {
            state.forwards.entry(alias).or_default().insert(feature);
        }
    }
    Ok(state)
}

pub(crate) fn default_feature(manifest: &Manifest, enabled: bool, names: &mut BTreeSet<String>) {
    if enabled && manifest.features.contains_key("default") {
        names.insert("default".to_owned());
    }
}

pub(crate) fn all_features(manifest: &Manifest, names: &mut BTreeSet<String>) {
    names.extend(manifest.features.keys().cloned());
    let hidden: BTreeSet<_> = manifest
        .features
        .values()
        .flatten()
        .filter_map(|v| v.strip_prefix("dep:"))
        .collect();
    names.extend(
        manifest
            .dependencies
            .iter()
            .filter(|d| d.optional && !hidden.contains(d.alias.as_str()))
            .map(|d| d.alias.clone()),
    );
}

fn is_proc_macro(manifest: &Manifest) -> bool {
    manifest.targets.iter().any(|target| {
        target.kind == TargetKind::Library
            && target.crate_types.iter().any(|kind| kind == "proc-macro")
    })
}

struct Resolver<'a, 'b> {
    sources: &'a Sources<'b>,
    options: ResolveOptions,
    graph: Graph,
    packages: BTreeMap<(PathBuf, Option<String>), usize>,
    units: BTreeMap<(usize, BuildDomain), usize>,
    requests: Vec<BTreeSet<String>>,
    work: BTreeSet<usize>,
    resolved_edges: BTreeMap<(usize, usize), usize>,
    waiting: BTreeMap<(usize, usize), BTreeSet<usize>>,
}

struct Acquisition {
    parent: Manifest,
    source: Option<String>,
    key: (usize, usize),
}

struct Acquired {
    key: (usize, usize),
    result: Result<(Manifest, Option<String>)>,
}

impl Resolver<'_, '_> {
    fn package(&mut self, manifest: Manifest, source: Option<String>) -> usize {
        let key = (manifest.root.clone(), source.clone());
        if let Some(index) = self.packages.get(&key) {
            return *index;
        }
        let index = self.graph.packages.len();
        self.graph.packages.push(manifest);
        self.graph.sources.push(source);
        self.packages.insert(key, index);
        index
    }

    fn unit(
        &mut self,
        package: usize,
        domain: BuildDomain,
        requested: BTreeSet<String>,
        root: bool,
    ) -> usize {
        if let Some(&index) = self.units.get(&(package, domain)) {
            let previous = self.requests[index].len();
            self.requests[index].extend(requested);
            if previous != self.requests[index].len() || (root && !self.graph.units[index].root) {
                self.work.insert(index);
            }
            self.graph.units[index].root |= root;
            return index;
        }
        let index = self.graph.units.len();
        self.units.insert((package, domain), index);
        self.graph.units.push(Unit {
            package,
            domain,
            features: BTreeSet::new(),
            edges: Vec::new(),
            root,
        });
        self.requests.push(requested);
        self.work.insert(index);
        index
    }

    fn dependency(
        &mut self,
        unit: usize,
        package: usize,
        dep_index: usize,
        sender: &mpsc::Sender<Acquisition>,
    ) -> Result<Option<usize>> {
        let key = (package, dep_index);
        if let Some(&result) = self.resolved_edges.get(&key) {
            return Ok(Some(result));
        }
        let waiters = self.waiting.entry(key).or_default();
        if waiters.is_empty() {
            sender
                .send(Acquisition {
                    parent: self.graph.packages[package].clone(),
                    source: self.graph.sources[package].clone(),
                    key,
                })
                .context("source acquisition pool stopped")?;
        }
        waiters.insert(unit);
        Ok(None)
    }

    fn acquired(&mut self, message: Acquired) -> Result<()> {
        let (manifest, source) = message.result?;
        let package = self.package(manifest, source);
        self.resolved_edges.insert(message.key, package);
        self.work.extend(
            self.waiting
                .remove(&message.key)
                .context("unexpected acquisition reply")?,
        );
        Ok(())
    }

    fn expand(&mut self, index: usize, sender: &mpsc::Sender<Acquisition>) -> Result<()> {
        let unit = &self.graph.units[index];
        let package = unit.package;
        let domain = unit.domain;
        let root = unit.root;
        let manifest = &self.graph.packages[package];
        let features = feature_request(manifest, &self.requests[index])?;
        let deps = manifest.dependencies.clone();
        let mut edges = Vec::new();
        let mut aliases = BTreeMap::new();
        for (dep_index, dep) in deps.iter().enumerate() {
            if dep.optional && !features.optional.contains(&dep.alias) {
                continue;
            }
            if dep.kind == DependencyKind::Dev && !(root && self.options.dev_dependencies) {
                continue;
            }
            if dep.kind == DependencyKind::Build
                && !self.graph.packages[package]
                    .targets
                    .iter()
                    .any(|t| t.kind == TargetKind::BuildScript)
            {
                continue;
            }
            let platform = if domain == BuildDomain::Host || dep.kind == DependencyKind::Build {
                &self.options.host
            } else {
                &self.options.target
            };
            if let Some(selector) = &dep.platform {
                if !platform.matches(selector)? {
                    continue;
                }
            }
            let Some(child) = self.dependency(index, package, dep_index, sender)? else {
                continue;
            };
            let child_manifest = &self.graph.packages[child];
            let child_domain = if domain == BuildDomain::Host
                || dep.kind == DependencyKind::Build
                || is_proc_macro(child_manifest)
            {
                BuildDomain::Host
            } else {
                BuildDomain::Target
            };
            let mut requested = dep.features.clone();
            default_feature(child_manifest, dep.default_features, &mut requested);
            if let Some(forwards) = features.forwards.get(&dep.alias) {
                requested.extend(forwards.iter().cloned());
            }
            let child = self.unit(child, child_domain, requested, false);
            let key = (dep.kind, dep.alias.clone());
            if let Some(previous) = aliases.insert(key, child) {
                ensure!(
                    previous == child,
                    "conflicting active dependency alias {}",
                    dep.alias
                );
            } else {
                edges.push(Edge {
                    alias: dep.alias.clone(),
                    unit: child,
                    kind: dep.kind,
                });
            }
        }
        self.graph.units[index].features = features.names;
        self.graph.units[index].edges = edges;
        Ok(())
    }
    fn resolve_all(&mut self) -> Result<()> {
        let (requests, receive) = mpsc::channel::<Acquisition>();
        let (replies, results) = mpsc::channel::<Acquired>();
        let receive = Mutex::new(receive);
        let cancelled = AtomicBool::new(false);
        let sources = self.sources;
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..self.options.source_jobs.get() {
                let replies = replies.clone();
                let receive = &receive;
                let cancelled = &cancelled;
                let worker =
                    std::thread::Builder::new().spawn_scoped(scope, move || -> Result<()> {
                        loop {
                            let request = receive
                                .lock()
                                .map_err(|_| anyhow::anyhow!("source queue poisoned"))?
                                .recv();
                            let Ok(request) = request else {
                                break;
                            };
                            if cancelled.load(Ordering::Acquire) {
                                break;
                            }
                            let dependency = &request.parent.dependencies[request.key.1];
                            let result = sources
                                .dependency(&request.parent, request.source.as_deref(), dependency)
                                .with_context(|| {
                                    format!(
                                        "resolve {} dependency {}",
                                        request.parent.package.name, dependency.alias
                                    )
                                });
                            if replies
                                .send(Acquired {
                                    key: request.key,
                                    result,
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(())
                    });
                match worker {
                    Ok(worker) => workers.push(worker),
                    Err(error) => {
                        cancelled.store(true, Ordering::Release);
                        drop(requests);
                        for worker in workers {
                            let _ = worker.join();
                        }
                        return Err(error.into());
                    }
                }
            }
            drop(replies);
            let resolution = (|| {
                loop {
                    // Drain already completed acquisitions first, coalescing
                    // feature invalidations. No breadth-level barrier.
                    while let Ok(message) = results.try_recv() {
                        self.acquired(message)?;
                    }
                    while let Some(index) = self.work.pop_first() {
                        self.expand(index, &requests)?;
                    }
                    if self.waiting.is_empty() {
                        break;
                    }
                    self.acquired(
                        results
                            .recv()
                            .context("source acquisition pool ended prematurely")?,
                    )?;
                }
                Ok(())
            })();
            cancelled.store(true, Ordering::Release);
            drop(requests);
            drop(results);
            let mut failure = resolution;
            for worker in workers {
                match worker.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) if failure.is_ok() => failure = Err(error),
                    Err(_) if failure.is_ok() => {
                        failure = Err(anyhow::anyhow!("source worker panicked"))
                    }
                    _ => {}
                }
            }
            failure
        })
    }
}

impl Graph {
    pub fn resolve(sources: &mut Sources<'_>, options: ResolveOptions) -> Result<Self> {
        ensure!(!options.selected.is_empty(), "no selected packages");
        let mut resolver = Resolver {
            sources,
            options,
            graph: Self {
                packages: Vec::new(),
                sources: Vec::new(),
                units: Vec::new(),
                roots: Vec::new(),
            },
            packages: BTreeMap::new(),
            units: BTreeMap::new(),
            requests: Vec::new(),
            work: BTreeSet::new(),
            resolved_edges: BTreeMap::new(),
            waiting: BTreeMap::new(),
        };
        let mut roots = Vec::new();
        for root in resolver.options.selected.clone() {
            let manifest = resolver.sources.manifest(&root)?;
            if resolver.sources.lock().version.is_some()
                && resolver.sources.locked_parent(&manifest, None)?.is_none()
            {
                return Err(crate::LockMismatch(format!(
                    "root {} {} is absent",
                    manifest.package.name, manifest.package.version
                ))
                .into());
            }
            let mut features = BTreeSet::new();
            for requested in &resolver.options.features {
                if let Some((package, feature)) = requested.split_once('/') {
                    // A qualified workspace feature addresses the selected package.
                    // Otherwise retain dependency feature forwarding for a single root.
                    if package == manifest.package.name {
                        features.insert(feature.to_owned());
                    } else if resolver.options.selected.len() == 1 {
                        features.insert(requested.clone());
                    }
                } else if resolver.options.selected.len() == 1
                    || manifest.features.contains_key(requested)
                    || manifest
                        .dependencies
                        .iter()
                        .any(|d| d.optional && d.alias == *requested)
                {
                    features.insert(requested.clone());
                }
            }
            default_feature(&manifest, resolver.options.default_features, &mut features);
            if resolver.options.all_features {
                all_features(&manifest, &mut features);
            }
            let domain = if is_proc_macro(&manifest) {
                BuildDomain::Host
            } else {
                BuildDomain::Target
            };
            let package = resolver.package(manifest, None);
            roots.push(resolver.unit(package, domain, features, true));
        }
        resolver.graph.roots = roots;
        resolver.resolve_all()?;
        resolver.graph.canonicalize();
        let mut links = BTreeMap::new();
        for unit in &resolver.graph.units {
            let manifest = &resolver.graph.packages[unit.package];
            if let Some(name) = &manifest.package.links {
                let key = (unit.domain, name);
                if let Some(previous) = links.insert(key, unit.package) {
                    ensure!(
                        previous == unit.package,
                        "multiple packages link native library {name}"
                    );
                }
            }
            for edge in &unit.edges {
                let dep = &resolver.graph.packages[resolver.graph.units[edge.unit].package];
                ensure!(
                    dep.targets.iter().any(|t| t.kind == TargetKind::Library),
                    "dependency {} has no library target",
                    edge.alias
                );
            }
        }
        Ok(resolver.graph)
    }

    fn canonicalize(&mut self) {
        let mut package_order: Vec<_> = (0..self.packages.len()).collect();
        package_order.sort_by(|&a, &b| {
            let a = (
                &self.packages[a].package.name,
                &self.packages[a].package.version,
                &self.sources[a],
                &self.packages[a].root,
            );
            let b = (
                &self.packages[b].package.name,
                &self.packages[b].package.version,
                &self.sources[b],
                &self.packages[b].root,
            );
            a.cmp(&b)
        });
        let mut packages: Vec<_> = std::mem::take(&mut self.packages)
            .into_iter()
            .map(Some)
            .collect();
        let mut sources: Vec<_> = std::mem::take(&mut self.sources)
            .into_iter()
            .map(Some)
            .collect();
        let mut package_map = vec![0; packages.len()];
        for (new, old) in package_order.into_iter().enumerate() {
            package_map[old] = new;
            if let Some(package) = packages[old].take() {
                self.packages.push(package);
            }
            if let Some(source) = sources[old].take() {
                self.sources.push(source);
            }
        }
        let mut order: Vec<_> = (0..self.units.len()).collect();
        order.sort_by_key(|&index| {
            (
                package_map[self.units[index].package],
                self.units[index].domain,
            )
        });
        let mut units: Vec<_> = std::mem::take(&mut self.units)
            .into_iter()
            .map(Some)
            .collect();
        let mut map = vec![0; units.len()];
        for (new, old) in order.into_iter().enumerate() {
            map[old] = new;
            if let Some(mut unit) = units[old].take() {
                unit.package = package_map[unit.package];
                self.units.push(unit);
            }
        }
        for unit in &mut self.units {
            for edge in &mut unit.edges {
                edge.unit = map[edge.unit];
            }
        }
        for root in &mut self.roots {
            *root = map[*root];
        }
    }

    pub fn manifest(&self, unit: usize) -> &Manifest {
        &self.packages[self.units[unit].package]
    }

    pub fn library(&self, unit: usize) -> Result<&crate::Target> {
        self.manifest(unit)
            .targets
            .iter()
            .find(|t| t.kind == TargetKind::Library)
            .context("package has no library")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Lockfile, Workspace};
    use std::fs;
    #[test]
    fn feature_union_reaches_fixed_point_with_optional_and_weak_edges() -> Result<()> {
        let root = tempfile::tempdir()?;
        let write = |name: &str, body: &str| -> Result<()> {
            let path = root.path().join(name);
            fs::create_dir_all(path.join("src"))?;
            fs::write(path.join("src/lib.rs"), "")?;
            fs::write(
                path.join("Cargo.toml"),
                format!("[package]\nname={name:?}\nversion=\"1.0.0\"\nedition=\"2024\"\n{body}"),
            )?;
            Ok(())
        };
        write(
            "a",
            "[dependencies]\nb={path=\"../b\",features=[\"enable\"]}\nc={path=\"../c\"}\n",
        )?;
        write(
            "b",
            "[dependencies]\nd={path=\"../d\",optional=true}\n[features]\nenable=[\"dep:d\",\"d?/extra\"]\nother=[\"d/other\"]\n",
        )?;
        write(
            "c",
            "[dependencies]\nb={path=\"../b\",features=[\"other\"]}\n",
        )?;
        write("d", "[features]\nextra=[]\nother=[]\n")?;
        fs::write(
            root.path().join("Cargo.toml"),
            "[workspace]\nmembers=[\"a\",\"b\",\"c\",\"d\"]\n",
        )?;
        let ws = Workspace::discover(&root.path().join("Cargo.toml"))?;
        let mut sources = Sources::new(&ws, Lockfile::default(), None, root.path().join("scratch"));
        let platform = Platform::parse("host".into(), "unix")?;
        let graph = Graph::resolve(
            &mut sources,
            ResolveOptions {
                selected: vec![root.path().join("a")],
                features: BTreeSet::new(),
                default_features: true,
                all_features: false,
                dev_dependencies: false,
                host: platform.clone(),
                target: platform,
                source_jobs: std::num::NonZeroUsize::MIN.saturating_add(3),
            },
        )?;
        let unit = graph
            .units
            .iter()
            .find(|u| graph.packages[u.package].package.name == "d")
            .context("missing optional dependency")?;
        assert_eq!(
            unit.features,
            BTreeSet::from(["extra".into(), "other".into()])
        );
        Ok(())
    }
    #[test]
    fn acquisitions_follow_ready_edges_without_a_level_barrier() -> Result<()> {
        use sha2::{Digest, Sha256};
        use std::{io::Write, sync::Condvar, time::Duration};
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("src"))?;
        fs::write(root.path().join("src/lib.rs"), "")?;
        fs::write(
            root.path().join("Cargo.toml"),
            "[package]\nname=\"root\"\nversion=\"1.0.0\"\n[dependencies]\na=\"1\"\nb=\"1\"\n",
        )?;
        let ws = Workspace::discover(&root.path().join("Cargo.toml"))?;
        let mut archives = BTreeMap::new();
        let mut packages = vec![crate::LockedPackage {
            name: "root".into(),
            version: "1.0.0".parse()?,
            source: None,
            checksum: None,
            dependencies: vec!["a".into(), "b".into()],
        }];
        for (name, body, deps) in [
            ("a", "", vec![]),
            ("b", "[dependencies]\nc=\"1\"\n", vec!["c".into()]),
            ("c", "", vec![]),
        ] {
            let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::fast(),
            ));
            let manifest =
                format!("[package]\nname={name:?}\nversion=\"1.0.0\"\nedition=\"2024\"\n{body}");
            for (file, contents) in [
                ("Cargo.toml", manifest.as_bytes()),
                ("src/lib.rs", &b""[..]),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_mode(0o644);
                header.set_size(contents.len() as u64);
                header.set_cksum();
                builder.append_data(&mut header, format!("{name}-1.0.0/{file}"), contents)?;
            }
            let bytes = builder.into_inner()?.finish()?;
            let checksum = Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            archives.insert(name.to_owned(), bytes);
            packages.push(crate::LockedPackage {
                name: name.into(),
                version: "1.0.0".parse()?,
                source: Some(crate::registry::CRATES_IO.into()),
                checksum: Some(checksum),
                dependencies: deps,
            });
        }
        let signal = (Mutex::new(false), Condvar::new());
        let archive = |pkg: &crate::LockedPackage,
                       _: &crate::Registry,
                       output: &mut fs::File|
         -> Result<bool> {
            if pkg.name == "a" {
                let (ready, _) = signal
                    .1
                    .wait_timeout_while(signal.0.lock().unwrap(), Duration::from_secs(5), |ready| {
                        !*ready
                    })
                    .unwrap();
                ensure!(*ready, "acquisition of c was blocked behind unrelated a");
            } else if pkg.name == "c" {
                *signal.0.lock().unwrap() = true;
                signal.1.notify_all();
            }
            output.write_all(&archives[&pkg.name])?;
            Ok(true)
        };
        let mut sources = Sources::new(
            &ws,
            Lockfile {
                version: Some(4),
                packages,
            },
            None,
            root.path().join("scratch"),
        );
        sources.archive = Some(&archive);
        let platform = Platform::parse("host".into(), "unix")?;
        let graph = Graph::resolve(
            &mut sources,
            ResolveOptions {
                selected: vec![root.path().to_owned()],
                features: BTreeSet::new(),
                default_features: true,
                all_features: false,
                dev_dependencies: false,
                host: platform.clone(),
                target: platform,
                source_jobs: NonZeroUsize::new(2).unwrap(),
            },
        )?;
        assert_eq!(
            graph
                .packages
                .iter()
                .map(|p| p.package.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b", "c", "root"]
        );
        Ok(())
    }
}
