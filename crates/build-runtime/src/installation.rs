//! Portable original-package installation metadata.

use crate::{
    BlobRef, PackageIdentity, PackageSource, TreeEntry, TreeId, TreeManifest, TreePath, TreeRecipe,
    identity::encoding,
};
use anyhow::{Context, Result, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

const MANIFEST_MAGIC: &[u8] = b"sccache-installation-manifest-v2\0";
const RECIPE_MAGIC: &[u8] = b"sccache-installation-recipe-v1\0";
const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;

/// A portable manifest derived from an original verified package. It contains
/// metadata and content identities only; no host-local file versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationManifest {
    pub source: PackageSource,
    pub package: TreeId,
    pub components: BTreeMap<String, TreeManifest>,
}

pub fn read_document<T: serde::de::DeserializeOwned>(
    mut reader: impl Read,
    magic: &[u8],
) -> Result<T> {
    let mut header = vec![0; magic.len()];
    reader.read_exact(&mut header)?;
    ensure!(header == magic, "unsupported installation metadata format");
    let mut bytes = Vec::new();
    reader
        .take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= MAX_METADATA_BYTES,
        "installation metadata exceeds limit"
    );
    Ok(encoding()
        .with_limit(MAX_METADATA_BYTES)
        .deserialize(&bytes)?)
}

pub fn write_document<T: Serialize>(
    mut writer: impl Write,
    magic: &[u8],
    document: &T,
) -> Result<()> {
    let encoded = encoding()
        .with_limit(MAX_METADATA_BYTES)
        .serialize(document)?;
    ensure!(
        u64::try_from(encoded.len())? <= MAX_METADATA_BYTES,
        "installation metadata exceeds limit"
    );
    writer.write_all(magic)?;
    writer.write_all(&encoded)?;
    Ok(())
}

impl InstallationManifest {
    /// Encode portable package metadata.
    /// # Errors
    /// Returns an error for invalid component manifests or encoding failures.
    pub fn write(&self, writer: impl Write) -> Result<()> {
        self.validate()?;
        write_document(writer, MANIFEST_MAGIC, self)
    }

    /// Decode portable package metadata.
    /// # Errors
    /// Returns an error for invalid data or I/O failure.
    pub fn read(reader: impl Read) -> Result<Self> {
        let manifest: Self = read_document(reader, MANIFEST_MAGIC)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Verify the component metadata and paths.
    /// # Errors
    /// Returns an error for invalid component manifests.
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.components.is_empty(), "empty installation manifest");
        for (name, component) in &self.components {
            ensure!(!name.is_empty(), "empty installation component name");
            component.validate()?;
        }
        Ok(())
    }

    /// The expected regular file contents, including hardlinks.
    /// # Errors
    /// Returns an error for conflicting component files.
    pub fn files(&self) -> Result<BTreeMap<TreePath, BlobRef>> {
        let mut files = BTreeMap::new();
        for component in self.components.values() {
            for (path, entry) in &component.entries {
                let entry = if let TreeEntry::Hardlink(target) = entry {
                    component
                        .entries
                        .get(target)
                        .context("installation hardlink target missing")?
                } else {
                    entry
                };
                if let TreeEntry::File { blob, .. } = entry
                    && let Some(previous) = files.insert(path.clone(), *blob)
                {
                    ensure!(
                        previous == *blob,
                        "conflicting installation component files"
                    );
                }
            }
        }
        Ok(files)
    }
}

/// One installed component selected from a verified archive. The installed
/// name can include its target triple even when the archive's component
/// directory uses an unqualified package name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledComponent {
    pub package: PackageIdentity,
    pub component: String,
}

/// Portable release selection, independent of the installing host and its
/// inode versions. Each original package appears once and its selected
/// component trees can be composed without reading file bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationRecipe {
    pub release: String,
    pub packages: BTreeMap<PackageIdentity, InstallationManifest>,
    pub components: BTreeMap<String, InstalledComponent>,
}

impl InstallationRecipe {
    /// Select only installed components and retain their exact upstream
    /// provenance. Unselected payload in a multi-component archive is not
    /// used for local attestation or tree assembly.
    /// # Errors
    /// Returns an error for missing or conflicting package metadata.
    pub fn selected_manifests(&self) -> Result<Vec<InstallationManifest>> {
        ensure!(
            !self.release.is_empty() && !self.components.is_empty(),
            "empty installation recipe"
        );
        let mut selected = BTreeMap::<PackageIdentity, InstallationManifest>::new();
        for (name, component) in &self.components {
            ensure!(!name.is_empty(), "empty installed component name");
            let manifest = self
                .packages
                .get(&component.package)
                .context("installation package missing")?;
            ensure!(
                manifest.source.identity == component.package,
                "installation package identity mismatch"
            );
            let tree = manifest
                .components
                .get(&component.component)
                .context("installation component missing")?;
            let selection =
                selected
                    .entry(component.package)
                    .or_insert_with(|| InstallationManifest {
                        source: manifest.source,
                        package: manifest.package,
                        components: BTreeMap::new(),
                    });
            selection
                .components
                .insert(component.component.clone(), tree.clone());
        }
        ensure!(
            selected.len() == self.packages.len(),
            "unreferenced installation package"
        );
        let manifests = selected.into_values().collect::<Vec<_>>();
        for manifest in &manifests {
            manifest.validate()?;
        }
        Ok(manifests)
    }

    /// Derive the normalized immutable installed tree recipe. Validate
    /// overlapping paths and content now rather than on a remote worker.
    /// # Errors
    /// Returns an error for incomplete or conflicting component trees.
    pub fn tree_recipe(&self) -> Result<TreeRecipe> {
        let manifests = self.selected_manifests()?;
        let mut trees = BTreeMap::new();
        let mut directories = None;
        for tree in manifests
            .iter()
            .flat_map(|manifest| manifest.components.values())
        {
            if let Some(previous) = directories {
                ensure!(
                    previous == tree.root,
                    "inconsistent installation directory normalization"
                );
            } else {
                directories = Some(tree.root);
            }
            let id = tree.id()?;
            if let Some(previous) = trees.insert(id, tree) {
                ensure!(
                    previous == tree,
                    "conflicting identical component identifiers"
                );
            }
        }
        let recipe = TreeRecipe::union(
            directories.context("empty installation tree")?,
            trees.keys().copied(),
        );
        recipe.compose(&trees)?;
        Ok(recipe)
    }

    /// Encode the portable release selection and its component manifests.
    /// # Errors
    /// Returns an error for invalid recipe metadata or serialization failure.
    pub fn write(&self, writer: impl Write) -> Result<()> {
        self.tree_recipe()?;
        write_document(writer, RECIPE_MAGIC, self)
    }

    /// Decode and validate an installation recipe from a trusted source.
    /// # Errors
    /// Returns an error for malformed, incomplete or conflicting metadata.
    pub fn read(reader: impl Read) -> Result<Self> {
        let recipe: Self = read_document(reader, RECIPE_MAGIC)?;
        recipe.tree_recipe()?;
        Ok(recipe)
    }
}
