//! A sealed discovery transcript is ordinary CAS input, not a second cache
//! or an opaque origin path. Its manifest contains only the canonical
//! observation record and the unique content blobs actually read.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize};

use super::{DiscoveryQuery, DiscoveryReply, DiscoveryTranscript};
use crate::{
    BlobRef, BuildPath, ContentId, TreeEntry, TreeLease, TreeManifest, TreeMetadata, TreePath,
    TreeTimestamp, identity::encoding,
};

const TRANSCRIPT: &[u8] = b"observations-v2";
const DIRECTORY: TreeMetadata = TreeMetadata {
    mode: 0o755,
    modified: TreeTimestamp {
        seconds: 0,
        nanoseconds: 0,
    },
};
const FILE: TreeMetadata = TreeMetadata {
    mode: 0o444,
    ..DIRECTORY
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryBundle {
    roots: BTreeSet<BuildPath>,
    transcript: DiscoveryTranscript,
}

impl DiscoveryBundle {
    /// # Errors
    /// Returns an error for an invalid or incomplete observation namespace.
    pub fn new(roots: BTreeSet<BuildPath>, transcript: DiscoveryTranscript) -> Result<Self> {
        let bundle = Self {
            roots,
            transcript: transcript.canonical()?,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    fn validate(&self) -> Result<()> {
        ensure!(!self.roots.is_empty(), "empty discovery mount set");
        ensure!(
            self.transcript.canonical()? == self.transcript,
            "noncanonical discovery transcript"
        );
        for root in &self.roots {
            BuildPath::new(root.as_bytes().to_vec())?;
            ensure!(
                matches!(
                    self.transcript.get(&DiscoveryQuery::Lookup(root.clone())),
                    Some(DiscoveryReply::Directory(_))
                ),
                "discovery root has no directory observation"
            );
        }
        for query in self.transcript.observations().keys() {
            ensure!(
                self.roots
                    .iter()
                    .any(|root| query.path().within(root.as_bytes())),
                "discovery observation outside mounted roots"
            );
        }
        Ok(())
    }

    #[must_use]
    pub const fn roots(&self) -> &BTreeSet<BuildPath> {
        &self.roots
    }

    #[must_use]
    pub const fn transcript(&self) -> &DiscoveryTranscript {
        &self.transcript
    }

    fn manifest(&self, encoded: &[u8]) -> Result<TreeManifest> {
        let mut blobs = BTreeMap::new();
        for reply in self.transcript.observations().values() {
            if let DiscoveryReply::File { blob, .. } = reply
                && let Some(previous) = blobs.insert(blob.id, blob.size)
            {
                ensure!(
                    previous == blob.size,
                    "inconsistent discovered content lengths"
                );
            }
        }
        let mut entries = BTreeMap::from([
            (
                TreePath::new(TRANSCRIPT.to_vec())?,
                TreeEntry::File {
                    blob: BlobRef {
                        id: ContentId::of(encoded),
                        size: u64::try_from(encoded.len())?,
                    },
                    metadata: FILE,
                },
            ),
            (
                TreePath::new(b"blobs".to_vec())?,
                TreeEntry::Directory(DIRECTORY),
            ),
        ]);
        for (index, (id, size)) in blobs.into_iter().enumerate() {
            entries.insert(
                TreePath::new(format!("blobs/{index}").into_bytes())?,
                TreeEntry::File {
                    blob: BlobRef { id, size },
                    metadata: FILE,
                },
            );
        }
        Ok(TreeManifest {
            root: DIRECTORY,
            entries,
        })
    }

    pub(super) fn encode(&self) -> Result<(Vec<u8>, TreeManifest)> {
        self.validate()?;
        let encoded = encoding().serialize(self)?;
        let manifest = self.manifest(&encoded)?;
        Ok((encoded, manifest))
    }

    /// Read and validate a sealed package from a previously admitted tree.
    /// No origin lookup or filesystem access is authorized by the package.
    /// # Errors
    /// Returns an error for malformed, oversized, or noncanonical content.
    pub fn load(lease: &TreeLease, max_metadata_bytes: u64) -> Result<Self> {
        let Some(TreeEntry::File { blob, .. }) = lease.manifest().entries.get(TRANSCRIPT) else {
            anyhow::bail!("missing discovery transcript blob");
        };
        ensure!(
            blob.size <= max_metadata_bytes,
            "discovery transcript exceeds worker metadata limit"
        );
        let mut encoded = Vec::new();
        lease
            .open_decoded(blob.id)?
            .take(
                blob.size
                    .checked_add(1)
                    .context("discovery transcript length overflow")?,
            )
            .read_to_end(&mut encoded)?;
        ensure!(
            u64::try_from(encoded.len())? == blob.size && ContentId::of(&encoded) == blob.id,
            "discovery transcript digest mismatch"
        );
        let bundle: Self = encoding()
            .with_limit(max_metadata_bytes)
            .deserialize(&encoded)?;
        bundle.validate()?;
        ensure!(
            bundle.manifest(&encoded)? == *lease.manifest(),
            "discovery package does not match exact observed content"
        );
        Ok(bundle)
    }
}
