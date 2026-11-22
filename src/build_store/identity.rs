use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize};

/// BLAKE3 digest of the exact uncompressed bytes of a file or input component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    #[must_use]
    pub fn of(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }
}

/// Identifies an action's semantic inputs, not its resulting bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionKey(pub [u8; 32]);

/// Identifies the complete successful result, including diagnostics and metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResultId(pub [u8; 32]);

/// A versioned set of input-component digests suitable for cache-key auditing.
///
/// Callers must account for all observable inputs. The schema identifies the
/// compiler's normalization and hashing policy, not its physical host. Only
/// component digests, not the original environment or source contents, belong
/// here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionFingerprint {
    pub schema: String,
    pub components: BTreeMap<String, ContentId>,
}

impl ActionFingerprint {
    /// Hash the complete, deterministically ordered fingerprint.
    ///
    /// # Errors
    /// Returns an error if the fingerprint cannot be encoded.
    pub fn key(&self) -> Result<ActionKey> {
        Ok(ActionKey(typed_digest(b"sccache-action-v1\0", self)?))
    }

    /// Report added, removed or changed input components. A schema change must
    /// be compared separately because it may change their interpretation.
    #[must_use]
    pub fn differing_components<'a>(&'a self, other: &'a Self) -> BTreeSet<&'a str> {
        self.components
            .keys()
            .chain(other.components.keys())
            .filter(|key| self.components.get(*key) != other.components.get(*key))
            .map(String::as_str)
            .collect()
    }
}

/// Content identity and expected logical length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    pub id: ContentId,
    pub size: u64,
}

/// One materialized compiler output. File metadata belongs to the manifest so
/// different modes can share the same underlying content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub blob: BlobRef,
    pub mode: Option<u32>,
}

/// Result of a successful cacheable compilation.
///
/// Output names are opaque compiler artifact keys, not filesystem paths. A
/// consumer must map them to its own validated output declarations. Failed or
/// non-cacheable actions must not be published as successful results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultManifest {
    pub outputs: BTreeMap<String, Artifact>,
    pub stdout: Option<BlobRef>,
    pub stderr: Option<BlobRef>,
}

impl ResultManifest {
    /// Hash the complete result independently of action identity.
    ///
    /// # Errors
    /// Returns an error if the manifest cannot be encoded.
    pub fn id(&self) -> Result<ResultId> {
        Ok(ResultId(typed_digest(b"sccache-result-v1\0", self)?))
    }

    /// Iterate over each unique content reference, checking that repeated
    /// content IDs agree about their lengths.
    ///
    /// # Errors
    /// Returns an error if the same digest has conflicting declared lengths.
    pub fn blobs(&self) -> Result<BTreeMap<ContentId, u64>> {
        let mut blobs = BTreeMap::new();
        for blob in self
            .outputs
            .values()
            .map(|artifact| artifact.blob)
            .chain(self.stdout)
            .chain(self.stderr)
        {
            if let Some(previous) = blobs.insert(blob.id, blob.size) {
                ensure!(
                    previous == blob.size,
                    "inconsistent lengths for content {:?}",
                    blob.id
                );
            }
        }
        Ok(blobs)
    }
}

fn typed_digest(domain: &[u8], value: &impl Serialize) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    encoding()
        .serialize_into(&mut hasher, value)
        .context("encoding native build identity")?;
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn encoding() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_identity_is_order_independent_and_schema_sensitive() -> Result<()> {
        let a = ContentId::of(b"a");
        let b = ContentId::of(b"b");
        let first = ActionFingerprint {
            schema: "rust-v1".into(),
            components: BTreeMap::from([("args".into(), a), ("env".into(), b)]),
        };
        let mut second = ActionFingerprint {
            schema: first.schema.clone(),
            components: BTreeMap::from([("env".into(), b), ("args".into(), a)]),
        };
        assert_eq!(first.key()?, second.key()?);
        second.schema = "rust-v2".into();
        assert_ne!(first.key()?, second.key()?);
        second.components.remove("env");
        second.components.insert("toolchain".into(), b);
        assert_eq!(
            first.differing_components(&second),
            BTreeSet::from(["env", "toolchain"])
        );
        Ok(())
    }

    #[test]
    fn result_identity_includes_diagnostics_and_modes() -> Result<()> {
        let blob = BlobRef {
            id: ContentId::of(b"file"),
            size: 4,
        };
        let mut result = ResultManifest {
            outputs: BTreeMap::from([(
                "obj".into(),
                Artifact {
                    blob,
                    mode: Some(0o644),
                },
            )]),
            stdout: None,
            stderr: None,
        };
        let first = result.id()?;
        result.stderr = Some(blob);
        assert_ne!(first, result.id()?);
        assert_eq!(result.blobs()?.len(), 1);
        result.stderr = None;
        if let Some(artifact) = result.outputs.get_mut("obj") {
            artifact.mode = Some(0o755);
        }
        assert_ne!(first, result.id()?);
        result.stdout = Some(BlobRef { size: 5, ..blob });
        assert!(result.blobs().is_err());
        Ok(())
    }
}
