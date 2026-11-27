//! Package-manager-independent workspace inspection and source formatting.
use super::RustBuildArgs;
use anyhow::{Result, ensure};
use sccache_rust_build::settings;
use sccache_rust_build::{DependencyKind, Manifest, TargetKind, Workspace};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io,
    path::{Path, PathBuf},
    process::Command,
};

fn package_id(manifest: &Manifest) -> String {
    format!(
        "path+file://{}#{}@{}",
        manifest.root.display(),
        manifest.package.name,
        manifest.package.version
    )
}

fn package(manifest: &Manifest) -> Value {
    let package = &manifest.package;
    let targets = manifest
        .targets
        .iter()
        .map(|target| {
            let kind = match target.kind {
                TargetKind::Library => target.crate_types.clone(),
                TargetKind::Binary => vec!["bin".into()],
                TargetKind::Example => vec!["example".into()],
                TargetKind::Test => vec!["test".into()],
                TargetKind::Bench => vec!["bench".into()],
                TargetKind::BuildScript => vec!["custom-build".into()],
            };
            json!({
                "name": target.name,
                "kind": kind,
                "crate_types": target.crate_types,
                "src_path": target.source,
                "edition": package.edition,
                "required-features": target.required_features,
                "test": target.test,
                "doctest": target.doctest,
                "doc": target.doc,
            })
        })
        .collect::<Vec<_>>();
    let dependencies = manifest.dependencies.iter().map(|dep| {
        json!({
            "name": dep.name,
            "source": dep.git.as_ref().map(|url| format!("git+{url}")),
            "req": dep.requirement.to_string(),
            "kind": match dep.kind { DependencyKind::Normal => None, DependencyKind::Build => Some("build"), DependencyKind::Dev => Some("dev") },
            "rename": (dep.alias != dep.name).then_some(&dep.alias),
            "optional": dep.optional,
            "uses_default_features": dep.default_features,
            "features": dep.features,
            "target": dep.platform,
            "registry": dep.registry,
            "path": dep.path,
        })
    }).collect::<Vec<_>>();
    json!({
        "name": package.name,
        "version": package.version.to_string(),
        "id": package_id(manifest),
        "license": package.metadata.get("license"),
        "license_file": package.metadata.get("license-file"),
        "description": package.metadata.get("description"),
        "source": null,
        "dependencies": dependencies,
        "targets": targets,
        "features": manifest.features,
        "manifest_path": manifest.root.join("Cargo.toml"),
        "edition": package.edition,
        "links": package.links,
        "repository": package.metadata.get("repository"),
        "homepage": package.metadata.get("homepage"),
        "rust_version": package.metadata.get("rust-version"),
        "readme": package.metadata.get("readme"),
        "metadata": null,
    })
}

pub(super) fn workspace(
    workspace: &Workspace,
    target: &Path,
    cwd: &Path,
    args: &RustBuildArgs,
) -> Result<i32> {
    ensure!(args.format_version == 1, "unsupported metadata version");
    // Full resolved metadata includes external source paths. Do not claim
    // these paths remain accessible after their build-wide leases expire.
    ensure!(
        args.no_deps,
        "workspace metadata requires --no-deps; external sources are build-leased"
    );
    let manifests = workspace
        .members
        .iter()
        .map(|path| workspace.package(path))
        .collect::<Result<Vec<_>>>()?;
    let members = manifests.iter().map(package_id).collect::<Vec<_>>();
    let defaults = manifests
        .iter()
        .filter(|manifest| workspace.defaults.contains(&manifest.root))
        .map(package_id)
        .collect::<Vec<_>>();
    let target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        cwd.join(target)
    };
    serde_json::to_writer(
        io::stdout().lock(),
        &json!({
            "packages": manifests.iter().map(package).collect::<Vec<_>>(),
            "workspace_members": members,
            "workspace_default_members": defaults,
            "resolve": null,
            "target_directory": target,
            "workspace_root": workspace.root,
            "version": 1,
            "metadata": workspace.document.get("workspace").and_then(toml::Value::as_table).and_then(|table| table.get("metadata")),
        }),
    )?;
    println!();
    Ok(0)
}

pub(super) fn format_sources(
    workspace: &Workspace,
    selected: &[PathBuf],
    args: &RustBuildArgs,
) -> Result<i32> {
    let executable = settings::tool("rustfmt", None, args.toolchain.as_deref(), &workspace.root)?;
    let mut formatted = BTreeSet::new();
    for root in selected {
        let manifest = workspace.package(root)?;
        let paths = manifest
            .targets
            .iter()
            .filter_map(|target| {
                formatted
                    .insert(target.source.clone())
                    .then_some(&target.source)
            })
            .collect::<Vec<_>>();
        if paths.is_empty() {
            continue;
        }
        let status = Command::new(&executable)
            .current_dir(&manifest.root)
            .arg("--edition")
            .arg(&manifest.package.edition)
            .args(&args.trailing)
            .args(paths)
            .status()?;
        ensure!(status.success(), "rustfmt exited with {status}");
    }
    Ok(0)
}
