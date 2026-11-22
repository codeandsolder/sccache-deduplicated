//! Portable manifests for normalized Unix build trees. Each file references
//! the very same content store used by compiler results. No archive encoding
//! or host storage path participates in tree identity.

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{BlobRef, ContentId, identity::typed_digest};

/// Identity of a complete tree, including its directory and inode metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TreeId(pub [u8; 32]);

/// An exact relative POSIX path encoded as bytes, without traversal or
/// ambiguous spellings. Non-UTF-8 filenames are supported.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TreePath(Vec<u8>);

impl TreePath {
    /// Create a relative path.
    ///
    /// # Errors
    /// Returns an error for invalid path components.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let path = Self(bytes);
        path.validate()?;
        Ok(path)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.0.contains(&0)
                && self
                    .0
                    .split(|&byte| byte == b'/')
                    .all(|part| { !part.is_empty() && part != b"." && part != b".." }),
            "invalid relative tree path"
        );
        Ok(())
    }

    #[must_use = "these bytes identify the exact relative path"]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn parent(&self) -> Option<Self> {
        self.0
            .iter()
            .rposition(|&byte| byte == b'/')
            .map(|index| Self(self.0[..index].to_vec()))
    }
}

/// Explicit Unix modification timestamp. Access time is normalized to this
/// timestamp when materializing; creation and change times are not portable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeTimestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

impl TreeTimestamp {
    fn validate(self) -> Result<()> {
        ensure!(self.nanoseconds < 1_000_000_000, "invalid tree timestamp");
        Ok(())
    }
}

/// Permissions and modification time of a regular file or directory.
///
/// The sandbox establishes ownership. Set-ID files are forbidden; this is
/// a build-tree representation, not a general privileged filesystem backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeMetadata {
    pub mode: u32,
    pub modified: TreeTimestamp,
}

impl TreeMetadata {
    pub(crate) fn validate(self) -> Result<()> {
        ensure!(self.mode & !0o1777 == 0, "unsupported build tree mode");
        self.modified.validate()
    }
}

/// Every parent directory must be declared explicitly. A hardlink names an
/// actual regular-file entry, not another hardlink or a symlink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TreeEntry {
    Directory(TreeMetadata),
    File {
        blob: BlobRef,
        metadata: TreeMetadata,
    },
    Symlink {
        target: Vec<u8>,
        modified: TreeTimestamp,
    },
    Hardlink(TreePath),
}

/// A normalized Unix tree.
///
/// All paths, metadata and symlink bytes are inputs to its identity. Ownership, ACLs and extended attributes are intentionally
/// outside this contract and must be controlled by the environment recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeManifest {
    pub root: TreeMetadata,
    pub entries: BTreeMap<TreePath, TreeEntry>,
}

impl TreeManifest {
    /// Check topology and metadata, including all deserialized paths.
    ///
    /// # Errors
    /// Returns an error for invalid paths, missing parents, unsupported
    /// permissions, invalid hardlinks or inconsistent content lengths.
    pub fn validate(&self) -> Result<()> {
        self.root.validate()?;
        for (path, entry) in &self.entries {
            path.validate()?;
            if let Some(parent) = path.parent() {
                ensure!(
                    matches!(self.entries.get(&parent), Some(TreeEntry::Directory(_))),
                    "tree entry does not have a declared directory parent"
                );
            }
            match entry {
                TreeEntry::Directory(metadata) | TreeEntry::File { metadata, .. } => {
                    metadata.validate()?;
                }
                TreeEntry::Symlink { target, modified } => {
                    ensure!(
                        !target.is_empty() && !target.contains(&0),
                        "invalid symbolic link target"
                    );
                    modified.validate()?;
                }
                TreeEntry::Hardlink(target) => {
                    target.validate()?;
                    ensure!(
                        matches!(self.entries.get(target), Some(TreeEntry::File { .. })),
                        "hardlink must refer directly to a regular-file entry"
                    );
                }
            }
        }
        self.blobs()?;
        Ok(())
    }

    /// Derive a stable identity for a valid normalized tree.
    ///
    /// # Errors
    /// Returns an error for an invalid tree or serialization failure.
    pub fn id(&self) -> Result<TreeId> {
        self.validate()?;
        Ok(TreeId(typed_digest(b"sccache-tree-v1\0", self)?))
    }

    /// Unique file contents required by this tree.
    ///
    /// # Errors
    /// Returns an error for conflicting lengths for the same content.
    pub fn blobs(&self) -> Result<BTreeMap<ContentId, u64>> {
        let mut blobs = BTreeMap::new();
        for entry in self.entries.values() {
            if let TreeEntry::File { blob, .. } = entry
                && let Some(previous) = blobs.insert(blob.id, blob.size)
            {
                ensure!(previous == blob.size, "inconsistent tree content length");
            }
        }
        Ok(blobs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> TreeMetadata {
        TreeMetadata {
            mode: 0o755,
            modified: TreeTimestamp {
                seconds: 1,
                nanoseconds: 0,
            },
        }
    }

    #[test]
    fn validates_paths_even_after_deserialization() -> Result<()> {
        for invalid in [
            b"".as_slice(),
            b"/a",
            b"a/../b",
            b"a//b",
            b"a/.",
            b"a/",
            b"a\0b",
        ] {
            assert!(TreePath::new(invalid.to_vec()).is_err());
            let tree = TreeManifest {
                root: metadata(),
                entries: BTreeMap::from([(
                    TreePath(invalid.to_vec()),
                    TreeEntry::Directory(metadata()),
                )]),
            };
            assert!(tree.id().is_err());
        }
        assert!(TreePath::new(vec![0xff]).is_ok());
        Ok(())
    }

    #[test]
    fn rejects_non_directory_parents_and_non_file_hardlink_targets() -> Result<()> {
        let a = TreePath::new(b"a".to_vec())?;
        let child = TreePath::new(b"a/b".to_vec())?;
        let mut tree = TreeManifest {
            root: metadata(),
            entries: BTreeMap::from([
                (
                    a.clone(),
                    TreeEntry::Symlink {
                        target: b"/etc".to_vec(),
                        modified: metadata().modified,
                    },
                ),
                (child.clone(), TreeEntry::Directory(metadata())),
            ]),
        };
        assert!(tree.id().is_err());
        tree.entries.remove(&child);
        tree.entries
            .insert(TreePath::new(b"alias".to_vec())?, TreeEntry::Hardlink(a));
        assert!(tree.id().is_err());
        Ok(())
    }
}
