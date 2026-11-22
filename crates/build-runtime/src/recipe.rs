//! Compose already imported package trees by metadata, without reading,
//! copying, extracting or repacking their file contents.

use std::collections::{BTreeMap, btree_map::Entry};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    ContentId, TreeEntry, TreeId, TreeManifest, TreeMetadata, TreePath, identity::typed_digest,
};

/// Mount a source package (or its selected directory) into the result tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeLayer {
    pub tree: TreeId,
    /// None selects the entire tree.
    pub source: Option<TreePath>,
    /// None places the selected directory at the root.
    pub destination: Option<TreePath>,
}

/// Explicit toolchain or dependency-tree composition.
///
/// Directory metadata is normalized by the recipe; file and symlink metadata
/// remain intact. Overlapping entries must agree exactly. No implicit
/// last-writer precedence can hide a conflicting package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeRecipe {
    pub directories: TreeMetadata,
    pub layers: Vec<TreeLayer>,
}

impl TreeRecipe {
    /// Stable fingerprint of the package selection and placement instructions.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn fingerprint(&self) -> Result<ContentId> {
        Ok(ContentId(typed_digest(b"sccache-tree-recipe-v1\0", self)?))
    }

    /// Compose verified trees without reading any of their underlying files.
    ///
    /// # Errors
    /// Returns an error for unavailable packages, invalid paths or conflicting
    /// entries, including incompatible hardlink topology.
    pub fn compose(&self, packages: &BTreeMap<TreeId, &TreeManifest>) -> Result<TreeManifest> {
        let mut manifest = TreeManifest {
            root: self.directories,
            entries: BTreeMap::new(),
        };
        for layer in &self.layers {
            let package = packages
                .get(&layer.tree)
                .context("recipe package unavailable")?;
            ensure!(
                package.id()? == layer.tree,
                "recipe package digest mismatch"
            );
            self.compose_layer(layer, package, &mut manifest)?;
        }
        manifest.validate()?;
        Ok(manifest)
    }

    fn compose_layer(
        &self,
        layer: &TreeLayer,
        package: &TreeManifest,
        output: &mut TreeManifest,
    ) -> Result<()> {
        if let Some(source) = &layer.source {
            ensure!(
                matches!(package.entries.get(source), Some(TreeEntry::Directory(_))),
                "recipe source is not a declared directory"
            );
        }
        if let Some(destination) = &layer.destination {
            self.add_directories(&mut output.entries, destination)?;
        }
        // Select path mappings first, so forward hardlinks are handled just
        // like backward ones. A selected subtree can reference an inode whose
        // original regular-file entry is outside that subtree.
        let mut selected = BTreeMap::new();
        for path in package.entries.keys() {
            if let Some(mapped) = map_path(path, layer)? {
                selected.insert(path, mapped);
            }
        }
        let mut external_hardlinks = BTreeMap::<&TreePath, TreePath>::new();
        for (&path, mapped) in &selected {
            let entry = package.entries.get(path).context("recipe entry missing")?;
            let entry = match entry {
                TreeEntry::Directory(_) => TreeEntry::Directory(self.directories),
                TreeEntry::Hardlink(target) => {
                    if let Some(target) = selected.get(target) {
                        TreeEntry::Hardlink(target.clone())
                    } else {
                        match external_hardlinks.entry(target) {
                            Entry::Occupied(previous) => {
                                TreeEntry::Hardlink(previous.get().clone())
                            }
                            Entry::Vacant(first) => {
                                first.insert(mapped.clone());
                                package
                                    .entries
                                    .get(target)
                                    .context("recipe external hardlink missing")?
                                    .clone()
                            }
                        }
                    }
                }
                other => other.clone(),
            };
            insert(&mut output.entries, mapped.clone(), entry)?;
        }
        Ok(())
    }

    fn add_directories(
        &self,
        entries: &mut BTreeMap<TreePath, TreeEntry>,
        destination: &TreePath,
    ) -> Result<()> {
        let mut prefix = Vec::new();
        for part in destination.as_bytes().split(|&byte| byte == b'/') {
            if !prefix.is_empty() {
                prefix.push(b'/');
            }
            prefix.extend_from_slice(part);
            insert(
                entries,
                TreePath::new(prefix.clone())?,
                TreeEntry::Directory(self.directories),
            )?;
        }
        Ok(())
    }
}

fn map_path(path: &TreePath, layer: &TreeLayer) -> Result<Option<TreePath>> {
    let relative = if let Some(source) = &layer.source {
        let Some(rest) = path
            .as_bytes()
            .strip_prefix(source.as_bytes())
            .and_then(|rest| rest.strip_prefix(b"/"))
        else {
            return Ok(None);
        };
        rest
    } else {
        path.as_bytes()
    };
    let mut mapped = layer.destination.as_ref().map_or_else(Vec::new, |dest| {
        let mut bytes = dest.as_bytes().to_vec();
        bytes.push(b'/');
        bytes
    });
    mapped.extend_from_slice(relative);
    Ok(Some(TreePath::new(mapped)?))
}

fn insert(
    entries: &mut BTreeMap<TreePath, TreeEntry>,
    path: TreePath,
    value: TreeEntry,
) -> Result<()> {
    match entries.entry(path) {
        Entry::Vacant(entry) => {
            entry.insert(value);
        }
        Entry::Occupied(entry) => ensure!(
            *entry.get() == value,
            "recipe package entries conflict at {:?}",
            entry.key()
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlobRef, TreeTimestamp};

    fn path(bytes: &[u8]) -> Result<TreePath> {
        TreePath::new(bytes.to_vec())
    }

    fn sample() -> Result<TreeManifest> {
        let metadata = TreeMetadata {
            mode: 0o755,
            modified: TreeTimestamp {
                seconds: 42,
                nanoseconds: 0,
            },
        };
        let blob = BlobRef {
            id: ContentId::of(b"compiler"),
            size: 8,
        };
        let external = path(b"original")?;
        Ok(TreeManifest {
            root: metadata,
            entries: BTreeMap::from([
                (external.clone(), TreeEntry::File { blob, metadata }),
                (path(b"component")?, TreeEntry::Directory(metadata)),
                (path(b"component/a")?, TreeEntry::Hardlink(external.clone())),
                (path(b"component/b")?, TreeEntry::Hardlink(external)),
                (path(b"component/file")?, TreeEntry::File { blob, metadata }),
            ]),
        })
    }

    #[test]
    fn subtree_rebasing_preserves_selected_hardlink_groups() -> Result<()> {
        let package = sample()?;
        let id = package.id()?;
        let recipe = TreeRecipe {
            directories: TreeMetadata {
                mode: 0o555,
                ..package.root
            },
            layers: vec![TreeLayer {
                tree: id,
                source: Some(path(b"component")?),
                destination: Some(path(b"toolchain/bin")?),
            }],
        };
        let tree = recipe.compose(&BTreeMap::from([(id, &package)]))?;
        assert_eq!(tree.root.mode, 0o555);
        assert!(matches!(
            tree.entries.get(&path(b"toolchain/bin/a")?),
            Some(TreeEntry::File { .. })
        ));
        assert_eq!(
            tree.entries.get(&path(b"toolchain/bin/b")?),
            Some(&TreeEntry::Hardlink(path(b"toolchain/bin/a")?))
        );
        assert_eq!(tree.blobs()?.len(), 1);
        Ok(())
    }

    #[test]
    fn incompatible_package_entries_are_not_silently_overwritten() -> Result<()> {
        let first = sample()?;
        let mut second = first.clone();
        second
            .entries
            .insert(path(b"component/file")?, TreeEntry::Directory(first.root));
        let first_id = first.id()?;
        let second_id = second.id()?;
        let recipe = TreeRecipe {
            directories: first.root,
            layers: vec![
                TreeLayer {
                    tree: first_id,
                    source: None,
                    destination: None,
                },
                TreeLayer {
                    tree: second_id,
                    source: None,
                    destination: None,
                },
            ],
        };
        assert!(
            recipe
                .compose(&BTreeMap::from([(first_id, &first), (second_id, &second)]))
                .is_err()
        );
        Ok(())
    }
}
