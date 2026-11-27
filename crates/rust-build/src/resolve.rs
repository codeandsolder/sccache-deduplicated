use crate::{Dependency, DependencyKind, Manifest, Platform, Sources, TargetKind};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;

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

pub struct ResolveOptions {
    pub selected: Vec<PathBuf>,
    pub features: BTreeSet<String>,
    pub default_features: bool,
    pub all_features: bool,
    pub dev_dependencies: bool,
    pub host: Platform,
    pub target: Platform,
}

#[derive(Default)]
struct FeatureRequest {
    names: BTreeSet<String>,
    optional: BTreeSet<String>,
    forwards: BTreeMap<String, BTreeSet<String>>,
}

fn feature_request(package: &Manifest, requested: &BTreeSet<String>) -> Result<FeatureRequest> {
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

fn default_feature(manifest: &Manifest, enabled: bool, names: &mut BTreeSet<String>) {
    if enabled && manifest.features.contains_key("default") {
        names.insert("default".to_owned());
    }
}

fn all_features(manifest: &Manifest, names: &mut BTreeSet<String>) {
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
    sources: &'a mut Sources<'b>,
    options: ResolveOptions,
    graph: Graph,
    packages: BTreeMap<(PathBuf, Option<String>), usize>,
    units: BTreeMap<(usize, BuildDomain), usize>,
    requests: Vec<BTreeSet<String>>,
    work: BTreeSet<usize>,
    resolved_edges: BTreeMap<(usize, usize), usize>,
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

    fn dependency(&mut self, package: usize, index: usize, dep: &Dependency) -> Result<usize> {
        if let Some(&result) = self.resolved_edges.get(&(package, index)) {
            return Ok(result);
        }
        let (manifest, source) = self.sources.dependency(
            &self.graph.packages[package],
            self.graph.sources[package].as_deref(),
            dep,
        )?;
        let result = self.package(manifest, source);
        self.resolved_edges.insert((package, index), result);
        Ok(result)
    }

    fn expand(&mut self, index: usize) -> Result<()> {
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
            let child = self.dependency(package, dep_index, dep)?;
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
        };
        let mut roots = Vec::new();
        for root in resolver.options.selected.clone() {
            let manifest = resolver.sources.workspace.package(&root)?;
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
        while let Some(index) = resolver.work.pop_first() {
            resolver.expand(index)?;
        }
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
}
