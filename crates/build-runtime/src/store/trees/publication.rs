//! Opportunistic group commit for asynchronous immutable-tree publication.
//! The queue owns every admitted request, its staging files, and its input
//! pins until the durable transaction finishes, even if a waiter disappears.
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, PoisonError},
};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use redb::{ReadTransaction, ReadableDatabase, ReadableTable};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

use super::{
    super::{BLOB_LAYOUTS, BLOBS, PENDING_DELETIONS},
    ContentId, NativeStore, Publication, Root, StagedBlob, TREES, TreeId, TreeLease, TreeManifest,
    TreePin, encoding,
};

// Bound prepared work independently from network and compiler admission.
// Limit a transaction by both request count and manifest size. A single
// large tree remains admissible; subsequent small trees cannot enlarge it.
const QUEUE_CAPACITY: usize = 256;
const MAX_BATCH_REQUESTS: usize = 64;
const MAX_BATCH_ENTRIES: usize = 16_384;

pub(in crate::store) struct TreePublicationQueue {
    slots: Arc<Semaphore>,
    state: Mutex<QueueState>,
    #[cfg(test)]
    pub(super) committed_batches: std::sync::atomic::AtomicU64,
}

impl Default for TreePublicationQueue {
    fn default() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(QUEUE_CAPACITY)),
            state: Mutex::default(),
            #[cfg(test)]
            committed_batches: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

#[derive(Default)]
struct QueueState {
    pending: VecDeque<Request>,
    running: bool,
}

struct Request {
    manifest: TreeManifest,
    staged: Vec<StagedBlob>,
    completion: Completion,
}

struct Completion {
    reply: oneshot::Sender<Result<TreeLease>>,
    _retained: Box<dyn Send>,
    _permit: OwnedSemaphorePermit,
}

impl Completion {
    fn send(self, result: Result<TreeLease>) {
        let _ = self.reply.send(result);
    }
}

impl NativeStore {
    /// Queue a verified immutable-tree publication and receive its pinned
    /// lease after the durable index commit. Independent ready requests can
    /// share a transaction and directory synchronization. The retained state
    /// (e.g. acquisition pins) is owned until publication completes.
    ///
    /// # Errors
    /// Returns an error for invalid tree contents, failed storage, or shutdown.
    pub async fn publish_tree_pinned_async<R: Send + 'static>(
        &self,
        manifest: TreeManifest,
        staged: Vec<StagedBlob>,
        retained: R,
    ) -> Result<TreeLease> {
        let queue = &self.inner.tree_publications;
        let permit = Arc::clone(&queue.slots).acquire_owned().await?;
        let (reply, receive) = oneshot::channel();
        let start = {
            let mut state = queue.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.pending.push_back(Request {
                manifest,
                staged,
                completion: Completion {
                    reply,
                    _retained: Box::new(retained),
                    _permit: permit,
                },
            });
            let start = !state.running;
            state.running = true;
            start
        };
        if start {
            let drain = Drain {
                store: self.clone(),
                armed: true,
            };
            tokio::spawn(drain.run());
        }
        receive
            .await
            .context("native tree publication task stopped")?
    }

    fn process_tree_batch(&self, requests: Vec<Request>) {
        let mut prepared = Vec::with_capacity(requests.len());
        for Request {
            manifest,
            staged,
            completion,
        } in requests
        {
            match PreparedTree::new(self, manifest, staged) {
                Ok(tree) => prepared.push((tree, completion)),
                Err(error) => completion.send(Err(error)),
            }
        }
        if let Err(error) = self.publish_tree_batch(&mut prepared) {
            // A real transaction/storage failure invalidates the entire
            // atomic batch. Individual invalid requests were rejected
            // before mutation; never acknowledge an uncommitted root.
            for (_, completion) in prepared {
                completion.send(Err(anyhow::anyhow!(
                    "native tree publication transaction failed: {error:#}"
                )));
            }
        }
    }

    fn publish_tree_batch(&self, prepared: &mut Vec<(PreparedTree, Completion)>) -> Result<()> {
        if prepared.is_empty() {
            return Ok(());
        }
        let _mutation = self.inner.lock_mutations()?;
        let read = self.inner.db.begin_read()?;
        let mut pending = Vec::with_capacity(prepared.len());
        for (tree, completion) in prepared.drain(..) {
            match tree.preflight(self, &read) {
                Ok(true) => completion.send(tree.lease(self)),
                Ok(false) => pending.push((tree, completion)),
                Err(error) => completion.send(Err(error)),
            }
        }
        drop(read);
        *prepared = pending;
        if prepared.is_empty() {
            return Ok(());
        }
        let write = self.inner.db.begin_write()?;
        let mut publication = Publication::default();
        for (tree, _) in prepared.iter_mut() {
            self.attach_tree(
                &write,
                tree.id,
                &tree.manifest,
                &tree.blobs,
                std::mem::take(&mut tree.staged),
                &mut publication,
            )?;
        }
        publication.commit(&self.inner, write)?;
        log::trace!(target: "native_cas_publication", "committed tree batch with {} requests", prepared.len());
        #[cfg(test)]
        self.inner
            .tree_publications
            .committed_batches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        for (tree, completion) in prepared.drain(..) {
            completion.send(tree.lease(self));
        }
        Ok(())
    }
}

struct Drain {
    store: NativeStore,
    armed: bool,
}

impl Drain {
    async fn run(mut self) {
        // Collect immediately runnable submissions without a fixed batching
        // timer, and never occupy a blocking thread while the queue is empty.
        tokio::task::yield_now().await;
        loop {
            let batch = {
                let queue = &self.store.inner.tree_publications;
                let mut state = queue.state.lock().unwrap_or_else(PoisonError::into_inner);
                if state.pending.is_empty() {
                    state.running = false;
                    self.armed = false;
                    return;
                }
                let mut batch = Vec::new();
                let mut entries = 0_usize;
                while let Some(next) = state.pending.front() {
                    let cost = next.manifest.entries.len().max(1);
                    if !batch.is_empty()
                        && (batch.len() >= MAX_BATCH_REQUESTS
                            || entries.saturating_add(cost) > MAX_BATCH_ENTRIES)
                    {
                        break;
                    }
                    if let Some(request) = state.pending.pop_front() {
                        batch.push(request);
                        entries = entries.saturating_add(cost);
                    }
                }
                batch
            };
            let store = self.store.clone();
            if let Err(error) =
                tokio::task::spawn_blocking(move || store.process_tree_batch(batch)).await
            {
                log::error!("native tree publication batch failed: {error:#}");
            }
        }
    }
}

impl Drop for Drain {
    fn drop(&mut self) {
        if self.armed {
            // A stopped runtime must not strand the queue or prevent another
            // runtime from starting its next drain. Active blocking batches
            // retain ownership of their own requests until completion.
            let pending = {
                let mut state = self
                    .store
                    .inner
                    .tree_publications
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                state.running = false;
                std::mem::take(&mut state.pending)
            };
            for request in pending {
                request.completion.send(Err(anyhow::anyhow!(
                    "native tree publication drain stopped"
                )));
            }
        }
    }
}

struct PreparedTree {
    id: TreeId,
    manifest: TreeManifest,
    blobs: BTreeMap<ContentId, u64>,
    staged: BTreeMap<ContentId, StagedBlob>,
}

impl PreparedTree {
    fn new(store: &NativeStore, manifest: TreeManifest, staged: Vec<StagedBlob>) -> Result<Self> {
        let id = manifest.id()?;
        let blobs = manifest.blobs()?;
        let staged = store.prepare_staging(&blobs, staged)?;
        for (&id, blob) in &staged {
            ensure!(
                blobs.get(&id) == Some(&blob.reference().size),
                "staged content length mismatch"
            );
            blob.validate_metadata(&std::fs::symlink_metadata(&blob.path)?)?;
        }
        Ok(Self {
            id,
            manifest,
            blobs,
            staged,
        })
    }

    // Reject malformed/incomplete requests before mutating the shared
    // transaction. A valid request must independently supply missing bytes;
    // another queued request is not its implicit source of content.
    fn preflight(&self, store: &NativeStore, read: &ReadTransaction) -> Result<bool> {
        let trees = read.open_table(TREES)?;
        let exists = if let Some(record) = trees.get(&self.id.0)? {
            let stored: TreeManifest = encoding().deserialize(record.value())?;
            ensure!(stored == self.manifest, "conflicting native tree");
            true
        } else {
            false
        };
        let live = read.open_table(BLOBS)?;
        let pending = read.open_table(PENDING_DELETIONS)?;
        let layouts = read.open_table(BLOB_LAYOUTS)?;
        let mut complete = true;
        for (&id, &size) in &self.blobs {
            let present = if let Some(indexed) = live.get(&id.0)? {
                ensure!(indexed.value() == size, "indexed content length mismatch");
                store.inner.blob_present(&layouts, id, size)?
            } else {
                ensure!(!exists, "indexed tree is missing content");
                if let Some(indexed) = pending.get(&id.0)? {
                    ensure!(indexed.value() == size, "pending content length mismatch");
                    store
                        .inner
                        .blob_present(&layouts, id, size)
                        .unwrap_or(false)
                } else {
                    false
                }
            };
            if !present {
                ensure!(
                    self.staged.contains_key(&id),
                    "missing staged tree content {id:?}"
                );
                complete = false;
            }
        }
        Ok(exists && complete)
    }

    fn lease(self, store: &NativeStore) -> Result<TreeLease> {
        let mut pins = store.inner.lock_pins()?;
        let count = pins.trees.entry(self.id).or_default();
        *count = count.checked_add(1).context("tree pin count overflow")?;
        pins.touch(Root::Tree(self.id));
        drop(pins);
        Ok(TreeLease {
            inner: Arc::clone(&store.inner),
            id: self.id,
            manifest: self.manifest,
            blobs: self.blobs,
            pins: vec![TreePin {
                inner: Arc::clone(&store.inner),
                id: self.id,
            }],
        })
    }
}
