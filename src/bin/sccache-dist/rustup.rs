//! Resolve the installed Rustup component inventory against its recorded
//! release manifest. This is a provisioning operation, never compiler hot-path
//! network discovery.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    num::NonZeroUsize,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use sccache::{
    build_runtime::{
        InstallationCatalog, InstallationManifest, InstallationRecipe, InstalledComponent,
        PackageCompression, PackageIdentity, TreePath,
    },
    dist::native::{NativeCacheClient, PackageAcquisition, PackageLocator, map_packages},
};
use serde::Deserialize;

const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct RustupConfig {
    config_version: String,
    components: Vec<Component>,
}

#[derive(Debug, Deserialize)]
struct Component {
    pkg: String,
    target: String,
}

impl Component {
    fn installed_name(&self) -> Result<String> {
        validate_name(&self.pkg)?;
        if self.target == "*" {
            Ok(self.pkg.clone())
        } else {
            validate_name(&self.target)?;
            Ok(format!("{}-{}", self.pkg, self.target))
        }
    }
}

#[derive(Deserialize)]
struct Channel {
    #[serde(rename = "manifest-version")]
    version: String,
    date: String,
    pkg: BTreeMap<String, DistributionPackage>,
    #[serde(default)]
    renames: BTreeMap<String, Rename>,
}

#[derive(Deserialize)]
struct Rename {
    to: String,
}

#[derive(Deserialize)]
struct DistributionPackage {
    target: BTreeMap<String, DistributionTarget>,
}

#[derive(Deserialize)]
struct DistributionTarget {
    available: bool,
    url: Option<String>,
    hash: Option<String>,
    xz_url: Option<String>,
    xz_hash: Option<String>,
}

impl DistributionTarget {
    fn locator(&self) -> Result<PackageLocator> {
        ensure!(
            self.available,
            "installed component not available in release metadata"
        );
        let (url, hash, compression) = match (&self.xz_url, &self.xz_hash) {
            (Some(url), Some(hash)) => (url, hash, PackageCompression::Xz),
            (None, None) => (
                self.url.as_ref().context("missing original package URL")?,
                self.hash
                    .as_ref()
                    .context("missing original package checksum")?,
                PackageCompression::Gzip,
            ),
            _ => anyhow::bail!("incomplete XZ package metadata"),
        };
        PackageLocator::from_rust_url(PackageIdentity::from_sha256_hex(hash, compression)?, url)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SelectedComponent {
    locator: PackageLocator,
    names: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct Inventory {
    release: String,
    selected: BTreeMap<String, SelectedComponent>,
    skipped: BTreeSet<String>,
}

fn read_metadata(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("read Rustup metadata {}", path.display()))?
        .take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= MAX_METADATA_BYTES,
        "Rustup metadata exceeds limit"
    );
    Ok(String::from_utf8(bytes)?)
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && name != "."
            && name != "..",
        "invalid Rustup component or target name"
    );
    Ok(())
}

/// Mirror the current compiler toolchain discovery's bin/lib closure.
/// Documentation-only, shell-completion-only and other irrelevant
/// components are not downloaded for a build unless full scope is selected.
fn contains_build_payload(manifest: &str) -> Result<bool> {
    let mut relevant = false;
    for line in manifest.lines().filter(|line| !line.is_empty()) {
        let (kind, path) = line
            .split_once(':')
            .context("invalid installed component manifest")?;
        ensure!(
            matches!(kind, "file" | "dir"),
            "unsupported installer manifest directive"
        );
        let path = TreePath::new(path.as_bytes().to_vec())?;
        relevant |= matches!(
            path.as_bytes().split(|&byte| byte == b'/').next(),
            Some(b"bin" | b"lib")
        );
    }
    Ok(relevant)
}

impl Inventory {
    fn read(root: &Path, full: bool) -> Result<Self> {
        let rustlib = root.join("lib/rustlib");
        let config: RustupConfig =
            toml::from_str(&read_metadata(&rustlib.join("multirust-config.toml"))?)?;
        let channel: Channel = toml::from_str(&read_metadata(
            &rustlib.join("multirust-channel-manifest.toml"),
        )?)?;
        ensure!(
            config.config_version == "1" && channel.version == "2",
            "unsupported Rustup metadata version"
        );
        let names = read_metadata(&rustlib.join("components"))?;
        let mut installed = BTreeSet::new();
        for name in names.lines().filter(|line| !line.is_empty()) {
            validate_name(name)?;
            ensure!(
                installed.insert(name.to_owned()),
                "duplicate installed Rustup component"
            );
        }
        let mut inventory = Self {
            release: channel.date.clone(),
            selected: BTreeMap::new(),
            skipped: BTreeSet::new(),
        };
        for component in config.components {
            let name = component.installed_name()?;
            ensure!(
                installed.remove(&name),
                "Rustup configuration and installed component list differ: {name}"
            );
            let manifest = read_metadata(&rustlib.join(format!("manifest-{name}")))?;
            if !contains_build_payload(&manifest)? && !full {
                inventory.skipped.insert(name);
                continue;
            }
            let package = if channel.pkg.contains_key(&component.pkg) {
                component.pkg.as_str()
            } else {
                channel
                    .renames
                    .get(&component.pkg)
                    .context("installed package missing from channel manifest")?
                    .to
                    .as_str()
            };
            validate_name(package)?;
            let target = channel
                .pkg
                .get(package)
                .and_then(|pkg| pkg.target.get(&component.target))
                .with_context(|| {
                    format!("installed component {name} missing release package target")
                })?;
            let qualified = if component.target == "*" {
                package.to_owned()
            } else {
                format!("{package}-{}", component.target)
            };
            let mut names = vec![name.clone(), qualified, package.to_owned(), component.pkg];
            // Preserve priority: exact targeted component before unqualified names.
            let mut seen = BTreeSet::new();
            names.retain(|name| seen.insert(name.clone()));
            inventory.selected.insert(
                name,
                SelectedComponent {
                    locator: target.locator()?,
                    names,
                },
            );
        }
        ensure!(
            installed.is_empty(),
            "Rustup configuration omits installed components: {installed:?}"
        );
        ensure!(
            !inventory.selected.is_empty(),
            "no installed Rust build components selected"
        );
        Ok(inventory)
    }

    fn resolve(
        &self,
        client: &NativeCacheClient,
        jobs: NonZeroUsize,
    ) -> Result<(InstallationRecipe, ProvisioningReport)> {
        let unique = self
            .selected
            .values()
            .map(|component| (component.locator.identity, &component.locator))
            .collect::<BTreeMap<_, _>>();
        let requests = unique.into_values().collect::<Vec<_>>();
        let acquired = acquire_packages(client, &requests, jobs)?;
        let mut recipe = InstallationRecipe {
            release: self.release.clone(),
            packages: BTreeMap::new(),
            components: BTreeMap::new(),
        };
        let mut report = ProvisioningReport::default();
        for package in acquired {
            if package.reused {
                report.reused_packages += 1;
            } else {
                report.acquired_packages += 1;
                report.downloaded_archive_bytes = report
                    .downloaded_archive_bytes
                    .checked_add(package.package.source.size)
                    .context("original Rust download byte count overflow")?;
            }
            let identity = package.package.source.identity;
            ensure!(
                recipe.packages.insert(identity, package.package).is_none(),
                "duplicate acquired package"
            );
        }
        for (name, selected) in &self.selected {
            let identity = selected.locator.identity;
            let manifest = recipe
                .packages
                .get(&identity)
                .context("missing acquired package")?;
            let component = selected
                .names
                .iter()
                .find(|candidate| manifest.components.contains_key(*candidate))
                .with_context(|| {
                    format!("original package does not contain installed component {name}")
                })?;
            recipe.components.insert(
                name.clone(),
                InstalledComponent {
                    package: identity,
                    component: component.clone(),
                },
            );
        }
        Ok((recipe, report))
    }
}

fn acquire_packages(
    client: &NativeCacheClient,
    requests: &[&PackageLocator],
    jobs: NonZeroUsize,
) -> Result<Vec<PackageAcquisition<InstallationManifest>>> {
    map_packages(requests, jobs, |locator| {
        let package = client
            .acquire_rust_package(locator)
            .with_context(|| format!("provision Rust archive {}", locator.path))?;
        info!(
            "Resolved Rust archive {}, reused: {}",
            locator.path, package.reused
        );
        Ok(package)
    })
}

#[derive(Default, serde::Serialize)]
struct ProvisioningReport {
    acquired_packages: u64,
    reused_packages: u64,
    downloaded_archive_bytes: u64,
}

pub(super) fn sync(
    root: &Path,
    config: &Path,
    catalog_path: &Path,
    recipe_path: &Path,
    full: bool,
    jobs: NonZeroUsize,
) -> Result<()> {
    ensure!(
        catalog_path != recipe_path,
        "installation catalog and recipe outputs must differ"
    );
    let root = root.canonicalize()?;
    let inventory = Inventory::read(&root, full)?;
    let client = super::package_client(config)?;
    let (recipe, packages) = inventory.resolve(&client, jobs)?;
    let tree_recipe = recipe.tree_recipe()?;
    let selected = recipe.selected_manifests()?;
    let (catalog, attestation) = InstallationCatalog::attest(&root, &selected, Some(catalog_path))?;
    ensure!(
        Inventory::read(&root, full)? == inventory,
        "Rustup installation changed during provisioning"
    );
    super::write_installation_metadata(recipe_path, |file| recipe.write(file))?;
    super::write_installation_metadata(catalog_path, |file| catalog.write(file))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "release": recipe.release,
            "components": recipe.components.keys().collect::<Vec<_>>(),
            "skipped_components": inventory.skipped,
            "packages": packages,
            "recipe_fingerprint": tree_recipe.fingerprint()?,
            "recipe_layers": tree_recipe.layers.len(),
            "attestation": attestation,
        }))?
    );
    Ok(())
}

#[cfg(test)]
mod tests;
