use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use redb::{ReadableDatabase, ReadableTable};

use super::packages::PackageRecord;
use super::{
    BLOB_PACKAGES, Eviction, Inner, LeasedReader, NativeStore, PACKAGES, StagedBlob, TREE_PACKAGES,
    TREES, USAGE, UploadReservation, encoding, release_pin, space::Root,
};
use crate::{BlobRef, ContentId, PackageSource, TreeId, TreeManifest, TreeRecipe};

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
        let _mutation = self.inner.lock_mutations()?;
        self.publish_tree_locked(manifest, staged, None)
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
        self.publish_tree_indexed_pinned(manifest, staged, None)
    }

    pub(super) fn publish_tree_indexed_pinned(
        &self,
        manifest: &TreeManifest,
        staged: Vec<StagedBlob>,
        package: Option<(ContentId, PackageSource, Option<StagedBlob>)>,
    ) -> Result<TreeLease> {
        let _mutation = self.inner.lock_mutations()?;
        let id = self.publish_tree_locked(manifest, staged, package)?;
        self.lookup_tree(id)?.context("committed tree missing")
    }

    fn publish_tree_locked(
        &self,
        manifest: &TreeManifest,
        staged: Vec<StagedBlob>,
        package: Option<(ContentId, PackageSource, Option<StagedBlob>)>,
    ) -> Result<TreeId> {
        let id = manifest.id()?;
        let blobs = manifest.blobs()?;
        let staged = self.prepare_staging(&blobs, staged)?;
        let write = self.inner.db.begin_write()?;
        let mut staged_reservations = Vec::new();
        {
            let mut trees = write.open_table(TREES)?;
            let exists = if let Some(stored) = trees.get(&id.0)? {
                let stored: TreeManifest = encoding().deserialize(stored.value())?;
                ensure!(stored == *manifest, "conflicting native tree");
                true
            } else {
                false
            };
            self.attach_blobs(
                &write,
                &id.0,
                &blobs,
                staged,
                exists,
                &mut staged_reservations,
            )?;
            if !exists {
                trees.insert(&id.0, encoding().serialize(manifest)?.as_slice())?;
            }
            if let Some((package, source, original)) = package {
                let mut packages = write.open_table(PACKAGES)?;
                let previous = packages
                    .get(&package.0)?
                    .map(|entry| encoding().deserialize::<PackageRecord>(entry.value()))
                    .transpose()?;
                let expanded_bytes =
                    manifest.entries.values().try_fold(0_u64, |total, entry| {
                        let bytes = match entry {
                            crate::TreeEntry::File { blob, .. } => blob.size,
                            _ => 0,
                        };
                        total
                            .checked_add(bytes)
                            .context("original package expanded size overflow")
                    })?;
                let mut record = PackageRecord {
                    source,
                    tree: id,
                    archive: original.as_ref().map(StagedBlob::reference),
                    expanded_bytes,
                    entry_count: u64::try_from(manifest.entries.len())?,
                };
                if let Some(previous) = previous {
                    ensure!(
                        previous.source == source
                            && previous.tree == id
                            && previous.expanded_bytes == record.expanded_bytes
                            && previous.entry_count == record.entry_count,
                        "conflicting upstream package tree"
                    );
                    if let Some(archive) = previous.archive {
                        ensure!(
                            record.archive.is_none_or(|new| new == archive),
                            "conflicting upstream package archive"
                        );
                        record.archive = Some(archive);
                        self.inner.check_blob(archive.id, archive.size)?;
                    } else if let Some(original) = original {
                        self.attach_package_archive(
                            &write,
                            package,
                            original,
                            &blobs,
                            &mut staged_reservations,
                        )?;
                    }
                } else if let Some(original) = original {
                    self.attach_package_archive(
                        &write,
                        package,
                        original,
                        &blobs,
                        &mut staged_reservations,
                    )?;
                }
                packages.insert(&package.0, encoding().serialize(&record)?.as_slice())?;
                write
                    .open_multimap_table(TREE_PACKAGES)?
                    .insert(&id.0, &package.0)?;
            }
        }
        write.commit()?;
        drop(staged_reservations);
        self.inner.lock_pins()?.touch(Root::Tree(id));
        Ok(id)
    }

    fn attach_package_archive(
        &self,
        write: &redb::WriteTransaction,
        package: ContentId,
        original: StagedBlob,
        contents: &BTreeMap<ContentId, u64>,
        reservations: &mut Vec<super::space::StagingReservation>,
    ) -> Result<()> {
        let BlobRef { id, size } = original.reference();
        let blobs = BTreeMap::from([(id, size)]);
        let staged = self.prepare_staging(&blobs, vec![original])?;
        self.attach_blobs(write, &package.0, &blobs, staged, false, reservations)?;
        let mut reverse = write.open_multimap_table(BLOB_PACKAGES)?;
        for id in contents.keys() {
            reverse.insert(&id.0, &package.0)?;
        }
        Ok(())
    }

    /// Publish a composed recipe, while pinning all of its input package
    /// trees. The output references the same existing file content.
    ///
    /// # Errors
    /// Returns an error if any package is missing or the recipe conflicts.
    pub fn publish_recipe(&self, recipe: &TreeRecipe) -> Result<TreeId> {
        let lease = self.lease_recipe(recipe)?;
        self.publish_tree(lease.manifest(), Vec::new())
    }

    /// Compose and lease a recipe in memory, without publishing a new CAS
    /// root or copying any content. The source package pins keep every
    /// referenced file live until the composed lease is released.
    ///
    /// # Errors
    /// Returns an error for missing trees, conflicting entries or invalid metadata.
    pub fn lease_recipe(&self, recipe: &TreeRecipe) -> Result<TreeLease> {
        recipe.validate()?;
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
        let id = manifest.id()?;
        let blobs = manifest.blobs()?;
        Ok(TreeLease {
            inner: Arc::clone(&self.inner),
            id,
            manifest,
            blobs,
            pins: leases.into_values().flat_map(|lease| lease.pins).collect(),
        })
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
        pins.touch(Root::Tree(id));
        let count = pins.trees.entry(id).or_default();
        *count = count.checked_add(1).context("tree pin count overflow")?;
        drop(pins);
        Ok(Some(TreeLease {
            inner: Arc::clone(&self.inner),
            id,
            manifest,
            blobs,
            pins: vec![TreePin {
                inner: Arc::clone(&self.inner),
                id,
            }],
        }))
    }

    /// Remove a tree root, preserving content shared with other trees or actions.
    ///
    /// # Errors
    /// Returns an error for inconsistent metadata or storage failure.
    pub fn evict_tree(&self, id: TreeId) -> Result<Eviction> {
        let _mutation = self.inner.lock_mutations()?;
        let mut pins = self.inner.lock_pins()?;
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
            let contents = manifest.blobs()?;
            let mut archive_bytes = 0_u64;
            for key in reverse.remove_all(&id.0)? {
                let package = *key?.value();
                let previous = packages
                    .remove(&package)?
                    .context("missing reverse package reference")?;
                let record: PackageRecord = encoding().deserialize(previous.value())?;
                ensure!(record.tree == id, "inconsistent package index");
                if let Some(blob) = record.archive {
                    let mut by_blob = write.open_multimap_table(BLOB_PACKAGES)?;
                    for id in contents.keys() {
                        ensure!(
                            by_blob.remove(&id.0, &package)?,
                            "missing original package content reference"
                        );
                    }
                    drop(by_blob);
                    archive_bytes = archive_bytes
                        .checked_add(Self::detach_blobs(
                            &write,
                            &package,
                            BTreeMap::from([(blob.id, blob.size)]),
                        )?)
                        .context("archive eviction size overflow")?;
                }
            }
            archive_bytes
                .checked_add(Self::detach_blobs(&write, &id.0, contents)?)
                .context("tree eviction size overflow")?
        };
        write.open_table(USAGE)?.remove(&Root::Tree(id).key())?;
        write.commit()?;
        pins.usage.remove(&Root::Tree(id));
        pins.dirty_usage.remove(&Root::Tree(id));
        drop(pins);
        Ok(Eviction::Removed {
            unreferenced_logical_bytes: bytes,
        })
    }
}

/// A tree manifest with indexed root or constituent-package pins.
pub struct TreeLease {
    pub(super) inner: Arc<Inner>,
    id: TreeId,
    manifest: TreeManifest,
    blobs: BTreeMap<ContentId, u64>,
    pins: Vec<TreePin>,
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

struct TreePin {
    inner: Arc<Inner>,
    id: TreeId,
}

impl Drop for TreePin {
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
