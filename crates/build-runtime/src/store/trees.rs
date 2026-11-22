use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use redb::{ReadableDatabase, ReadableTable};

use super::{
    Eviction, Inner, LeasedReader, NativeStore, PACKAGES, StagedBlob, TREE_PACKAGES, TREES,
    UploadReservation, encoding, release_pin,
};
use crate::{ContentId, TreeId, TreeManifest, TreeRecipe};

impl NativeStore {
    /// Reserve any already available files before negotiating a tree upload.
    ///
    /// # Errors
    /// Returns an error for an invalid manifest or storage failure.
    pub fn reserve_tree_upload(&self, manifest: &TreeManifest) -> Result<UploadReservation> {
        manifest.validate()?;
        self.reserve_blobs(manifest.blobs()?)
    }

    /// Retain one immutable tree root using the shared file-content index.
    /// Publishing the same tree repeatedly is idempotent.
    ///
    /// # Errors
    /// Returns an error for an invalid manifest, missing content or storage failure.
    pub fn publish_tree(&self, manifest: &TreeManifest, staged: Vec<StagedBlob>) -> Result<TreeId> {
        self.publish_tree_indexed(manifest, staged, None)
    }

    pub(super) fn publish_tree_indexed(
        &self,
        manifest: &TreeManifest,
        staged: Vec<StagedBlob>,
        package: Option<ContentId>,
    ) -> Result<TreeId> {
        let _mutation = self.inner.lock_mutations()?;
        self.publish_tree_locked(manifest, staged, package)
    }

    /// Publish a tree and acquire its delivery lease atomically with respect
    /// to eviction.
    ///
    /// # Errors
    /// Returns an error for invalid manifests, missing blobs or storage failure.
    pub fn publish_tree_pinned(
        &self,
        manifest: &TreeManifest,
        staged: Vec<StagedBlob>,
    ) -> Result<TreeLease> {
        let _mutation = self.inner.lock_mutations()?;
        let id = self.publish_tree_locked(manifest, staged, None)?;
        self.lookup_tree(id)?.context("committed tree missing")
    }

    fn publish_tree_locked(
        &self,
        manifest: &TreeManifest,
        staged: Vec<StagedBlob>,
        package: Option<ContentId>,
    ) -> Result<TreeId> {
        let id = manifest.id()?;
        let blobs = manifest.blobs()?;
        let staged = self.prepare_staging(&blobs, staged)?;
        let write = self.inner.db.begin_write()?;
        {
            let mut trees = write.open_table(TREES)?;
            let exists = if let Some(stored) = trees.get(&id.0)? {
                let stored: TreeManifest = encoding().deserialize(stored.value())?;
                ensure!(stored == *manifest, "conflicting native tree");
                true
            } else {
                false
            };
            self.attach_blobs(&write, &id.0, &blobs, staged, exists)?;
            if !exists {
                trees.insert(&id.0, encoding().serialize(manifest)?.as_slice())?;
            }
            if let Some(package) = package {
                let mut packages = write.open_table(PACKAGES)?;
                if let Some(previous) = packages.insert(&package.0, &id.0)? {
                    ensure!(
                        *previous.value() == id.0,
                        "conflicting upstream package tree"
                    );
                }
                write
                    .open_multimap_table(TREE_PACKAGES)?
                    .insert(&id.0, &package.0)?;
            }
        }
        write.commit()?;
        Ok(id)
    }

    /// Publish a composed recipe, while pinning all of its input package
    /// trees. The output references the same existing file content.
    ///
    /// # Errors
    /// Returns an error if any package is missing or the recipe conflicts.
    pub fn publish_recipe(&self, recipe: &TreeRecipe) -> Result<TreeId> {
        let mut leases = BTreeMap::new();
        for layer in &recipe.layers {
            if let std::collections::btree_map::Entry::Vacant(entry) = leases.entry(layer.tree) {
                let lease = self
                    .lookup_tree(layer.tree)?
                    .context("recipe package missing")?;
                entry.insert(lease);
            }
        }
        let packages = leases
            .iter()
            .map(|(&id, lease)| (id, lease.manifest()))
            .collect();
        let manifest = recipe.compose(&packages)?;
        self.publish_tree(&manifest, Vec::new())
    }

    /// Pin a tree while its files are consumed.
    ///
    /// # Errors
    /// Returns an error for invalid metadata, missing content or storage failure.
    pub fn lookup_tree(&self, id: TreeId) -> Result<Option<TreeLease>> {
        let mut pins = self.inner.lock_pins()?;
        let read = self.inner.db.begin_read()?;
        let trees = read.open_table(TREES)?;
        let Some(record) = trees.get(&id.0)? else {
            return Ok(None);
        };
        let manifest: TreeManifest = encoding().deserialize(record.value())?;
        ensure!(manifest.id()? == id, "invalid indexed tree");
        let blobs = manifest.blobs()?;
        for (&content, &size) in &blobs {
            self.inner.check_blob(content, size)?;
        }
        let count = pins.trees.entry(id).or_default();
        *count = count.checked_add(1).context("tree pin count overflow")?;
        drop(pins);
        Ok(Some(TreeLease {
            inner: Arc::clone(&self.inner),
            id,
            manifest,
            blobs,
        }))
    }

    /// Remove a tree root, preserving content shared with other trees or actions.
    ///
    /// # Errors
    /// Returns an error for inconsistent metadata or storage failure.
    pub fn evict_tree(&self, id: TreeId) -> Result<Eviction> {
        let _mutation = self.inner.lock_mutations()?;
        let pins = self.inner.lock_pins()?;
        if pins.trees.contains_key(&id) {
            return Ok(Eviction::Pinned);
        }
        let write = self.inner.db.begin_write()?;
        let bytes = {
            let mut trees = write.open_table(TREES)?;
            let Some(record) = trees.remove(&id.0)? else {
                return Ok(Eviction::Missing);
            };
            let manifest: TreeManifest = encoding().deserialize(record.value())?;
            ensure!(manifest.id()? == id, "invalid indexed tree");
            let mut packages = write.open_table(PACKAGES)?;
            let mut reverse = write.open_multimap_table(TREE_PACKAGES)?;
            for key in reverse.remove_all(&id.0)? {
                let package = *key?.value();
                let previous = packages
                    .remove(&package)?
                    .context("missing reverse package reference")?;
                ensure!(*previous.value() == id.0, "inconsistent package index");
            }
            Self::detach_blobs(&write, &id.0, manifest.blobs()?)?
        };
        write.commit()?;
        drop(pins);
        Ok(Eviction::Removed {
            unreferenced_logical_bytes: bytes,
        })
    }
}

/// A pinned tree manifest and its unique file content.
pub struct TreeLease {
    inner: Arc<Inner>,
    id: TreeId,
    manifest: TreeManifest,
    blobs: BTreeMap<ContentId, u64>,
}

impl TreeLease {
    #[must_use = "the identifier names the leased tree"]
    pub const fn id(&self) -> TreeId {
        self.id
    }

    #[must_use = "the manifest describes the leased tree"]
    pub const fn manifest(&self) -> &TreeManifest {
        &self.manifest
    }

    /// Open declared content for streaming independently of the tree lease.
    ///
    /// # Errors
    /// Returns an error for undeclared content or storage failure.
    pub fn open_file(&self, id: ContentId) -> Result<File> {
        self.inner.open_declared(&self.blobs, id)
    }

    /// Open an independent reader for content declared by this tree.
    ///
    /// # Errors
    /// Returns an error for undeclared content or filesystem failure.
    pub fn open_blob(&self, id: ContentId) -> Result<impl Read + Seek + '_> {
        Ok(LeasedReader {
            file: self.open_file(id)?,
            _lease: self,
        })
    }
}

impl Drop for TreeLease {
    fn drop(&mut self) {
        match self.inner.lock_pins() {
            Ok(mut pins) => release_pin(&mut pins.trees, &self.id),
            Err(error) => log::error!("could not release native store tree lease: {error:#}"),
        }
    }
}

#[cfg(target_os = "linux")]
mod capture;
#[cfg(target_os = "linux")]
mod materialize;
#[cfg(target_os = "linux")]
pub use materialize::{MaterializationStats, MaterializedTree};
#[cfg(test)]
mod tests;
