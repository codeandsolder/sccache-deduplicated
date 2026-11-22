//! Portable original-package installation metadata.

use crate::{BlobRef, TreeEntry, TreeId, TreeManifest, TreePath, identity::encoding};
use anyhow::{Context, Result, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

const MANIFEST_MAGIC: &[u8] = b"sccache-installation-manifest-v1\0";
const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;

/// A portable manifest derived from an original verified package. It contains
/// metadata and content identities only; no host-local file versions.
#[derive(Debug, Serialize, Deserialize)]
pub struct InstallationManifest {
    pub source_sha256: [u8; 32],
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
