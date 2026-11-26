use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek},
    sync::{Arc, Condvar, Mutex, PoisonError, Weak},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use redb::{ReadableDatabase, ReadableTable};

use super::packages::PackageRecord;
use super::{
    BLOB_PACKAGES, Eviction, Inner, LeasedReader, NativeStore, PACKAGES, Publication, StagedBlob,
    TREE_PACKAGES, TREES, USAGE, UploadReservation, encoding, release_pin, space::Root,
};
use crate::{BlobRef, ContentId, PackageSource, TreeId, TreeManifest, TreeRecipe};

#[derive(Default)]
pub(super) struct TreeFlights(Mutex<BTreeMap<TreeId, Weak<TreeFlight>>>);

#[derive(Default)]
struct TreeFlight {
    state: Mutex<FlightState>,
    wake: Condvar,
    async_wake: tokio::sync::Notify,
}

#[derive(Default)]
enum FlightState {
    #[default]
    Idle,
    Fetching,
    Ready(Arc<TreeLease>),
}

struct FlightOwner(Arc<TreeFlight>);

impl Drop for FlightOwner {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        if matches!(*state, FlightState::Fetching) {
            *state = FlightState::Idle;
        }
        drop(state);
        self.0.wake.notify_all();
        self.0.async_wake.notify_waiters();
    }
}

impl NativeStore {
    /// Open indexed content without requiring a complete tree. The open descriptor
    /// remains valid across eviction. The caller must authorize the blob separately.
    ///
    /// # Errors
    /// Returns an error for inconsistent indexed lengths or storage failures.
    pub fn open_available_blob(&self, blob: BlobRef) -> Result<Option<crate::BlobReader>> {
        self.open_available_physical(blob)?
            .map(|(file, encoding)| crate::BlobReader::open(file, encoding))
            .transpose()
    }

    /// Open the indexed physical representation for exact CAS transport.
    /// # Errors
    /// Returns an error for inconsistent storage metadata or I/O.
    pub fn open_available_physical(
        &self,
        blob: BlobRef,
    ) -> Result<Option<(File, crate::BlobEncoding)>> {
        let read = self.inner.db.begin_read()?;
        let live = read.open_table(super::BLOBS)?;
        let pending = read.open_table(super::PENDING_DELETIONS)?;
        let size = match live.get(&blob.id.0)? {
            Some(size) => size.value(),
            None => match pending.get(&blob.id.0)? {
                Some(size) => size.value(),
                None => return Ok(None),
            },
        };
        ensure!(size == blob.size, "inconsistent indexed blob length");
        let layouts = read.open_table(super::BLOB_LAYOUTS)?;
        self.inner.open_checked_blob(&layouts, blob.id, blob.size)
    }

    /// A canonical single-blob retention root. Uses the ordinary CAS and eviction
    /// policy so incomplete tree acquisitions can share verified bytes without
    /// making a second copy or leaving unaccounted files.
    ///
    /// # Errors
    /// Returns an error for invalid tree metadata.
    pub fn blob_retention_manifest(blob: BlobRef) -> Result<TreeManifest> {
        let modified = crate::TreeTimestamp {
            seconds: 0,
            nanoseconds: 0,
        };
        Ok(TreeManifest {
            root: crate::TreeMetadata {
                mode: 0o755,
                modified,
            },
            entries: BTreeMap::from([(
                crate::TreePath::new(b"blob".to_vec())?,
                crate::TreeEntry::File {
                    blob,
                    metadata: crate::TreeMetadata {
                        mode: 0o444,
                        modified,
                    },
                },
            )]),
        })
    }

    /// Resolve a tree with one in-flight acquisition per immutable identity.
    /// Waiting consumers share the published lease; failed producers release
    /// ownership so another authorized consumer can retry.
    /// # Errors
    /// Returns an error for cancellation, invalid acquisition or storage failure.
    pub fn acquire_tree(
        &self,
        id: TreeId,
        check: impl Fn() -> Result<()>,
        fetch: impl FnOnce() -> Result<TreeLease>,
    ) -> Result<(Arc<TreeLease>, bool)> {
        check()?;
        if let Some(tree) = self.lookup_tree(id)? {
            return Ok((Arc::new(tree), true));
        }
        let flight = self.tree_flight(id);
        loop {
            check()?;
            let mut state = flight.state.lock().unwrap_or_else(PoisonError::into_inner);
            match &*state {
                FlightState::Ready(lease) => return Ok((Arc::clone(lease), true)),
                FlightState::Idle => {
                    *state = FlightState::Fetching;
                    drop(state);
                    let _owner = FlightOwner(Arc::clone(&flight));
                    let (lease, reused) = match self.lookup_tree(id)? {
                        Some(lease) => (lease, true),
                        None => (fetch()?, false),
                    };
                    let lease = self.complete_flight(id, &flight, lease)?;
                    return Ok((lease, reused));
                }
                FlightState::Fetching => {
                    drop(
                        flight
                            .wake
                            .wait_timeout(state, Duration::from_millis(100))
                            .unwrap_or_else(PoisonError::into_inner),
                    );
                }
            }
        }
    }

    fn tree_flight(&self, id: TreeId) -> Arc<TreeFlight> {
        let mut flights = self
            .inner
            .tree_flights
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        flights.retain(|_, flight| flight.strong_count() > 0);
        flights.get(&id).and_then(Weak::upgrade).unwrap_or_else(|| {
            let flight = Arc::new(TreeFlight::default());
            flights.insert(id, Arc::downgrade(&flight));
            flight
        })
    }

    fn complete_flight(
        &self,
        id: TreeId,
        flight: &TreeFlight,
        lease: TreeLease,
    ) -> Result<Arc<TreeLease>> {
        ensure!(
            lease.id() == id && Arc::ptr_eq(&lease.inner, &self.inner),
            "tree acquisition returned unrelated content"
        );
        let lease = Arc::new(lease);
        *flight.state.lock().unwrap_or_else(PoisonError::into_inner) =
            FlightState::Ready(Arc::clone(&lease));
        Ok(lease)
    }

    async fn lookup_tree_async(&self, id: TreeId) -> Result<Option<TreeLease>> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.lookup_tree(id)).await?
    }

    /// Share a tree flight with synchronous or asynchronous producers.
    /// A follower waits for notification, deadline or cancellation, without
    /// occupying a condition-variable thread. A producer owns the flight
    /// until its fetch future completes or is dropped.
    ///
    /// # Errors
    /// Returns an error for cancellation, timeout, invalid content or failed acquisition.
    pub async fn acquire_tree_async<Fut, Cancel>(
        &self,
        id: TreeId,
        deadline: Instant,
        cancelled: Cancel,
        fetch: impl FnOnce() -> Fut + Send,
    ) -> Result<(Arc<TreeLease>, bool)>
    where
        Fut: std::future::Future<Output = Result<TreeLease>> + Send,
        Cancel: std::future::Future<Output = Result<()>> + Send,
    {
        ensure!(
            Instant::now() < deadline,
            "native tree acquisition deadline exceeded"
        );
        if let Some(tree) = self.lookup_tree_async(id).await? {
            return Ok((Arc::new(tree), true));
        }
        let flight = self.tree_flight(id);
        let mut cancelled = std::pin::pin!(cancelled);
        loop {
            ensure!(
                Instant::now() < deadline,
                "native tree acquisition deadline exceeded"
            );
            let mut notified = std::pin::pin!(flight.async_wake.notified());
            notified.as_mut().enable();
            let owner = {
                let mut state = flight.state.lock().unwrap_or_else(PoisonError::into_inner);
                match &*state {
                    FlightState::Ready(lease) => return Ok((Arc::clone(lease), true)),
                    FlightState::Idle => {
                        *state = FlightState::Fetching;
                        drop(state);
                        Some(FlightOwner(Arc::clone(&flight)))
                    }
                    FlightState::Fetching => None,
                }
            };
            if let Some(_owner) = owner {
                let (lease, reused) = match self.lookup_tree_async(id).await? {
                    Some(lease) => (lease, true),
                    None => (fetch().await?, false),
                };
                return Ok((self.complete_flight(id, &flight, lease)?, reused));
            }
            tokio::select! {
                result = tokio::time::timeout_at(deadline.into(), notified) => {
                    result.context("native tree acquisition deadline exceeded")?;
                }
                result = &mut cancelled => {
                    result?;
                    anyhow::bail!("native tree acquisition cancelled");
                }
            }
        }
    }

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
        if package.is_none() {
            let read = self.inner.db.begin_read()?;
            let trees = read.open_table(TREES)?;
            if let Some(stored) = trees.get(&id.0)? {
                let stored: TreeManifest = encoding().deserialize(stored.value())?;
                ensure!(stored == *manifest, "conflicting native tree");
                if self.blobs_present(&blobs)? {
                    self.inner.lock_pins()?.touch(Root::Tree(id));
                    return Ok(id);
                }
            }
        }
        let write = self.inner.db.begin_write()?;
        let mut publication = Publication::default();
        {
            let mut trees = write.open_table(TREES)?;
            let exists = if let Some(stored) = trees.get(&id.0)? {
                let stored: TreeManifest = encoding().deserialize(stored.value())?;
                ensure!(stored == *manifest, "conflicting native tree");
                true
            } else {
                false
            };
            self.attach_blobs(&write, &id.0, &blobs, staged, exists, &mut publication)?;
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
                            &mut publication,
                        )?;
                    }
                } else if let Some(original) = original {
                    self.attach_package_archive(
                        &write,
                        package,
                        original,
                        &blobs,
                        &mut publication,
                    )?;
                }
                packages.insert(&package.0, encoding().serialize(&record)?.as_slice())?;
                write
                    .open_multimap_table(TREE_PACKAGES)?
                    .insert(&id.0, &package.0)?;
            }
        }
        publication.commit(&self.inner, write)?;
        self.inner.lock_pins()?.touch(Root::Tree(id));
        Ok(id)
    }

    fn attach_package_archive(
        &self,
        write: &redb::WriteTransaction,
        package: ContentId,
        original: StagedBlob,
        contents: &BTreeMap<ContentId, u64>,
        publication: &mut Publication,
    ) -> Result<()> {
        let BlobRef { id, size } = original.reference();
        let blobs = BTreeMap::from([(id, size)]);
        let staged = self.prepare_staging(&blobs, vec![original])?;
        self.attach_blobs(write, &package.0, &blobs, staged, false, publication)?;
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

    /// Read immutable tree metadata independently of local blob residency.
    ///
    /// # Errors
    /// Returns an error for invalid metadata or storage failure.
    pub(crate) fn lookup_tree_manifest(&self, id: TreeId) -> Result<Option<TreeManifest>> {
        let read = self.inner.db.begin_read()?;
        let trees = read.open_table(TREES)?;
        let Some(record) = trees.get(&id.0)? else {
            return Ok(None);
        };
        let manifest: TreeManifest = encoding().deserialize(record.value())?;
        ensure!(manifest.id()? == id, "invalid indexed tree");
        Ok(Some(manifest))
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
        // A tree's identity is immutable. Pin the root before validating
        // its manifest and files, without retaining the shared pin mutex.
        let count = pins.trees.entry(id).or_default();
        *count = count.checked_add(1).context("tree pin count overflow")?;
        drop(pins);
        let pin = TreePin {
            inner: Arc::clone(&self.inner),
            id,
        };
        let manifest: TreeManifest = encoding().deserialize(record.value())?;
        ensure!(manifest.id()? == id, "invalid indexed tree");
        let blobs = manifest.blobs()?;
        if !self.blobs_present(&blobs)? {
            return Ok(None);
        }
        self.inner.lock_pins()?.touch(Root::Tree(id));
        Ok(Some(TreeLease {
            inner: Arc::clone(&self.inner),
            id,
            manifest,
            blobs,
            pins: vec![pin],
        }))
    }

    /// Remove a tree root, preserving content shared with other trees or actions.
    ///
    /// # Errors
    /// Returns an error for inconsistent metadata or storage failure.
    pub fn evict_tree(&self, id: TreeId) -> Result<Eviction> {
        #[cfg(target_os = "linux")]
        self.drop_idle_views(Some(id))?;
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

    /// Unique content lengths in this verified tree closure.
    #[must_use = "the returned map describes the pinned content"]
    pub const fn blobs(&self) -> &BTreeMap<ContentId, u64> {
        &self.blobs
    }

    /// Open declared content for streaming independently of the tree lease.
    ///
    /// # Errors
    /// Returns an error for undeclared content or storage failure.
    pub fn open_file(&self, id: ContentId) -> Result<File> {
        self.inner.open_declared(&self.blobs, id)
    }

    /// The immutable physical CAS encoding of a declared tree blob.
    ///
    /// # Errors
    /// Returns an error for undeclared content or missing index metadata.
    pub fn physical_encoding(&self, id: ContentId) -> Result<crate::BlobEncoding> {
        ensure!(self.blobs.contains_key(&id), "undeclared tree content");
        self.inner.blob_encoding(id)
    }

    /// Open decoded content as an owned reader. The file descriptor remains
    /// valid independently of the tree lease, including during a network upload.
    ///
    /// # Errors
    /// Returns an error for missing content or an invalid physical payload.
    pub fn open_decoded(&self, id: ContentId) -> Result<crate::BlobReader> {
        crate::BlobReader::open(self.open_file(id)?, self.inner.blob_encoding(id)?)
    }

    /// Open an independent reader for content declared by this tree.
    ///
    /// # Errors
    /// Returns an error for undeclared content or filesystem failure.
    pub fn open_blob(&self, id: ContentId) -> Result<impl Read + Seek + '_> {
        Ok(LeasedReader {
            file: crate::BlobReader::open(self.open_file(id)?, self.inner.blob_encoding(id)?)?,
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
mod mount;
#[cfg(target_os = "linux")]
pub use mount::MountedTree;
#[cfg(target_os = "linux")]
pub use mount::ReadOnlyView;
#[cfg(target_os = "linux")]
mod overlay;
#[cfg(target_os = "linux")]
pub(super) use overlay::plan_overlays;
#[cfg(target_os = "linux")]
mod materialize;
#[cfg(test)]
mod tests;
