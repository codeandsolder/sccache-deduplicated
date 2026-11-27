//! Stable package and unit graph inspection. External sources are leased, so
//! exported paths describe source-relative locations, never expired scratch.
use crate::{
    BuildDomain, DependencyKind, Graph, Manifest, Registries, Sources, TargetKind, Workspace,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

fn path_text(path: &Path) -> Result<&str> {
    path.to_str().context("metadata paths must be UTF-8")
}

fn package_id(manifest: &Manifest, source: Option<&str>) -> Result<String> {
    let source = if let Some(source) = source {
        source.to_owned()
    } else {
        let url = url::Url::from_directory_path(&manifest.root)
            .map_err(|()| anyhow::anyhow!("invalid local package root"))?;
        format!("path+{url}")
    };
    Ok(format!(
        "{source}#{}@{}",
        manifest.package.name, manifest.package.version
    ))
}

fn kind(kind: DependencyKind) -> &'static str {
    match kind {
        DependencyKind::Normal => "normal",
        DependencyKind::Build => "build",
        DependencyKind::Dev => "dev",
    }
}

fn package(
    manifest: &Manifest,
    source: Option<&str>,
    source_root: &Path,
    checksum: Option<&str>,
    registries: &Registries,
) -> Result<Value> {
    let pkg = &manifest.package;
    let external = source.is_some();
    let paths = |path: &Path| -> Result<(Option<String>, String)> {
        if external {
            let canonical = path.canonicalize()?;
            let relative = canonical
                .strip_prefix(source_root)
                .context("external package path escapes its source root")?;
            Ok((None, path_text(relative)?.to_owned()))
        } else {
            Ok((
                Some(path_text(path)?.to_owned()),
                path_text(path.strip_prefix(source_root).unwrap_or(path))?.to_owned(),
            ))
        }
    };
    let targets = manifest.targets.iter().map(|target| {
        let kinds = match target.kind {
            TargetKind::Library => target.crate_types.clone(),
            TargetKind::Binary => vec!["bin".into()],
            TargetKind::Example => vec!["example".into()],
            TargetKind::Test => vec!["test".into()],
            TargetKind::Bench => vec!["bench".into()],
            TargetKind::BuildScript => vec!["custom-build".into()],
        };
        let (src_path, source_path) = paths(&target.source)?;
        Ok(json!({"name":target.name,"kind":kinds,"crate_types":target.crate_types,"src_path":src_path,"source_path":source_path,
            "edition":target.edition.as_deref().unwrap_or(&pkg.edition),"required-features":target.required_features,
            "test":target.test,"doctest":target.doctest,"doc":target.doc,"harness":target.harness}))
    }).collect::<Result<Vec<_>>>()?;
    let dependencies = manifest.dependencies.iter().map(|dep| {
        let (path, source_path) = if let Some(path) = &dep.path {
            let (path, relative) = paths(path)?; (path, Some(relative))
        } else { (None, None) };
        let source = if let Some(git) = &dep.git { Some(format!("git+{git}")) }
            else if dep.path.is_none() { Some(registries.get(dep.registry.as_deref())?.source.clone()) }
            else { None };
        Ok(json!({"name":dep.name,"source":source,"git_reference":dep.git_reference,"req":dep.requirement.to_string(),
            "kind":(dep.kind != DependencyKind::Normal).then(|| kind(dep.kind)),"rename":(dep.alias!=dep.name).then_some(&dep.alias),
            "optional":dep.optional,"uses_default_features":dep.default_features,"features":dep.features,"target":dep.platform,"registry":dep.registry,"path":path,"source_path":source_path}))
    }).collect::<Result<Vec<_>>>()?;
    let (manifest_path, source_path) = paths(&manifest.root.join("Cargo.toml"))?;
    Ok(
        json!({"name":pkg.name,"version":pkg.version.to_string(),"id":package_id(manifest,source)?,"source":source,"checksum":checksum,
        "license":pkg.metadata.get("license"),"license_file":pkg.metadata.get("license-file"),"description":pkg.metadata.get("description"),
        "dependencies":dependencies,"targets":targets,"features":manifest.features,"manifest_path":manifest_path,"source_path":source_path,
        "edition":pkg.edition,"links":pkg.links,"repository":pkg.metadata.get("repository"),"homepage":pkg.metadata.get("homepage"),
        "rust_version":pkg.metadata.get("rust-version"),"readme":pkg.metadata.get("readme"),"metadata":manifest.metadata}),
    )
}

/// The graph is the actual selected host/target resolution, not a fictional
/// flattened package graph that loses domain-specific feature sets.
pub fn workspace_metadata(
    workspace: &Workspace,
    target: &Path,
    registries: &Registries,
    resolved: Option<(&Graph, &Sources<'_>)>,
) -> Result<Value> {
    let mut packages = BTreeMap::<String, Value>::new();
    let mut members = BTreeMap::<PathBuf, String>::new();
    for path in &workspace.members {
        let manifest = workspace.package(path)?;
        let id = package_id(&manifest, None)?;
        packages.insert(
            id.clone(),
            package(&manifest, None, &manifest.root, None, registries)?,
        );
        members.insert(path.clone(), id);
    }
    let defaults = workspace
        .defaults
        .iter()
        .map(|p| members.get(p).context("workspace default member missing"))
        .collect::<Result<Vec<_>>>()?;
    let resolution = if let Some((graph, sources)) = resolved {
        let mut ids = Vec::new();
        for (index, manifest) in graph.packages.iter().enumerate() {
            let source = graph.sources[index].as_deref();
            let id = package_id(manifest, source)?;
            let root = sources.source_root(manifest, source)?;
            let locked = sources.locked_parent(manifest, source)?;
            let checksum = locked.and_then(|p| p.checksum.as_deref());
            packages.insert(
                id.clone(),
                package(manifest, source, &root, checksum, registries)?,
            );
            ids.push(id);
        }
        let nodes = graph.units.iter().enumerate().map(|(index,unit)| json!({
            "id":index,"package":ids[unit.package],"domain":match unit.domain {BuildDomain::Host=>"host",BuildDomain::Target=>"target"},
            "root":unit.root,"features":unit.features,"dependencies":unit.edges.iter().map(|edge| json!({"alias":edge.alias,"unit":edge.unit,"kind":kind(edge.kind)})).collect::<Vec<_>>()
        })).collect::<Vec<_>>();
        json!({"roots":graph.roots,"units":nodes})
    } else {
        Value::Null
    };
    ensure!(
        target.is_absolute(),
        "metadata target directory must be absolute"
    );
    Ok(
        json!({"packages":packages.into_values().collect::<Vec<_>>(),"workspace_members":members.values().collect::<Vec<_>>(),
        "workspace_default_members":defaults,"resolve":resolution,"target_directory":path_text(target)?,"workspace_root":path_text(&workspace.root)?,"version":1,
        "metadata":workspace.document.get("workspace").and_then(toml::Value::as_table).and_then(|table|table.get("metadata"))}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BuildDomain, LockedPackage, Lockfile, Unit};
    use std::{collections::BTreeSet, fs};
    #[test]
    fn metadata_does_not_export_expired_external_source_paths() -> Result<()> {
        let root = tempfile::tempdir()?;
        let local = root.path().join("local");
        let external = root.path().join("scratch/private/dep");
        for (path, name) in [(&local, "local"), (&external, "dep")] {
            fs::create_dir_all(path.join("src"))?;
            fs::write(path.join("src/lib.rs"), "")?;
            fs::write(
                path.join("Cargo.toml"),
                format!(
                    "[package]\nname={name:?}\nversion=\"1.0.0\"\nedition=\"2024\"\n[package.metadata]\ncustom=1\n"
                ),
            )?;
        }
        let workspace = Workspace::discover(&local.join("Cargo.toml"))?;
        let registries = Registries::default();
        let source = crate::registry::CRATES_IO.to_owned();
        let lock = Lockfile {
            version: Some(4),
            packages: vec![LockedPackage {
                name: "dep".into(),
                version: "1.0.0".parse()?,
                source: Some(source.clone()),
                checksum: Some("ab".repeat(32)),
                dependencies: vec![],
            }],
        };
        let sources = Sources::new(&workspace, lock, None, root.path().join("scratch"));
        let graph = Graph {
            packages: vec![workspace.package(&local)?, Manifest::load(&external, None)?],
            sources: vec![None, Some(source)],
            units: vec![
                Unit {
                    package: 0,
                    domain: BuildDomain::Target,
                    features: BTreeSet::new(),
                    edges: vec![crate::Edge {
                        alias: "renamed".into(),
                        unit: 1,
                        kind: DependencyKind::Normal,
                    }],
                    root: true,
                },
                Unit {
                    package: 1,
                    domain: BuildDomain::Host,
                    features: BTreeSet::from(["feature".into()]),
                    edges: vec![],
                    root: false,
                },
            ],
            roots: vec![0],
        };
        let output = workspace_metadata(
            &workspace,
            &local.join("target"),
            &registries,
            Some((&graph, &sources)),
        )?;
        assert!(!output.to_string().contains("scratch/private"));
        let package = output["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "dep")
            .unwrap();
        assert!(package["manifest_path"].is_null());
        assert_eq!(package["targets"][0]["source_path"], "src/lib.rs");
        assert_eq!(package["metadata"]["custom"], 1);
        assert_eq!(
            output["resolve"]["units"][0]["dependencies"][0]["alias"],
            "renamed"
        );
        assert_eq!(output["resolve"]["units"][1]["domain"], "host");
        Ok(())
    }
}
