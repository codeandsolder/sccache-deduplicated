//! Opportunistic group commit for asynchronous immutable CAS publication.
//! Every admitted request owns its staging files, pins and completion until
//! the shared durable transaction finishes, even if a waiter disappears.
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex, PoisonError},
};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use redb::{ReadTransaction, ReadableDatabase, ReadableTable, WriteTransaction};
use tokio::sync::{Semaphore, oneshot};

use super::{
    Attachment, BLOB_LAYOUTS, BLOBS, BlobIndex, NativeStore, PENDING_DELETIONS, Publication,
    ResultLease, StagedBlob, TREES, encoding,
    results::{PreparedResult, ResultPlan},
};
use crate::{
    ActionFingerprint, ActionKey, ActionMode, Artifact, ContentId, ResultManifest, TreeId,
    TreeLease, TreeManifest,
};

const QUEUE_CAPACITY: usize = 256;
const MAX_BATCH_REQUESTS: usize = 64;
const MAX_BATCH_ENTRIES: usize = 16_384;

pub(super) struct PublicationQueue {
    slots: Arc<Semaphore>,
    state: Mutex<QueueState>,
    #[cfg(test)]
    pub(super) committed_batches: std::sync::atomic::AtomicU64,
}

impl Default for PublicationQueue {
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

enum Request {
    Tree {
        manifest: TreeManifest,
        staged: Vec<StagedBlob>,
        completion: Completion<TreeLease>,
    },
    Result {
        action: ActionKey,
        fingerprint: ActionFingerprint,
        manifest: ResultManifest,
        staged: Vec<StagedBlob>,
        mode: ActionMode,
        completion: Completion<ResultLease>,
    },
}

struct Completion<T> {
    reply: oneshot::Sender<Result<T>>,
    // The request owns its admission and caller-supplied resources as one
    // lifetime. Neither is a mutex guard or can be released before commit.
    _resources: Box<dyn Send>,
}

impl<T> Completion<T> {
    fn send(self, result: Result<T>) {
        let _ = self.reply.send(result);
    }
}

impl Request {
    fn cost(&self) -> usize {
        match self {
            Self::Tree { manifest, .. } => manifest.entries.len().max(1),
            Self::Result { manifest, .. } => {
                manifest.outputs.values().fold(2_usize, |count, artifact| {
                    let entries = match artifact {
                        Artifact::File { .. } => 1,
                        Artifact::Tree(tree) | Artifact::GeneratedTree(tree) => {
                            tree.entries.len().max(1)
                        }
                    };
                    count.saturating_add(entries)
                })
            }
        }
    }

    const fn action(&self) -> Option<ActionKey> {
        match self {
            Self::Tree { .. } => None,
            Self::Result { action, .. } => Some(*action),
        }
    }

    fn prepare(self, store: &NativeStore) -> Option<Prepared> {
        match self {
            Self::Tree {
                manifest,
                staged,
                completion,
            } => match PreparedTree::new(store, manifest, staged) {
                Ok(tree) => Some(Prepared::Tree(tree, completion)),
                Err(error) => {
                    completion.send(Err(error));
                    None
                }
            },
            Self::Result {
                fingerprint,
                manifest,
                staged,
                mode,
                completion,
                ..
            } => {
                match PreparedResult::new(
                    store,
                    Cow::Owned(fingerprint),
                    Cow::Owned(manifest),
                    staged,
                    mode,
                ) {
                    Ok(result) => Some(Prepared::Result(result, completion)),
                    Err(error) => {
                        completion.send(Err(error));
                        None
                    }
                }
            }
        }
    }

    fn fail(self, error: anyhow::Error) {
        match self {
            Self::Tree { completion, .. } => completion.send(Err(error)),
            Self::Result { completion, .. } => completion.send(Err(error)),
        }
    }
}

enum Prepared {
    Tree(PreparedTree, Completion<TreeLease>),
    Result(PreparedResult<'static>, Completion<ResultLease>),
}

impl Prepared {
    fn preflight(self, store: &NativeStore, read: &ReadTransaction) -> Option<Validated> {
        match self {
            Self::Tree(tree, completion) => match tree.preflight(store, read) {
                Ok(true) => {
                    completion.send(tree.lease(store));
                    None
                }
                Ok(false) => Some(Validated::Tree(tree, completion)),
                Err(error) => {
                    completion.send(Err(error));
                    None
                }
            },
            Self::Result(result, completion) => match result.preflight(store, read) {
                Ok(plan) if plan.unchanged => {
                    completion.send(result.lease(store));
                    None
                }
                Ok(plan) => Some(Validated::Result(result, plan, completion)),
                Err(error) => {
                    completion.send(Err(error));
                    None
                }
            },
        }
    }

    fn fail(self, error: anyhow::Error) {
        match self {
            Self::Tree(_, completion) => completion.send(Err(error)),
            Self::Result(_, completion) => completion.send(Err(error)),
        }
    }
}

enum Validated {
    Tree(PreparedTree, Completion<TreeLease>),
    Result(PreparedResult<'static>, ResultPlan, Completion<ResultLease>),
}

impl Validated {
    fn revalidate(&self, store: &NativeStore, write: &WriteTransaction) -> Result<()> {
        match self {
            Self::Tree(..) => Ok(()),
            Self::Result(result, plan, _) => result.revalidate_replacement(store, write, plan),
        }
    }

    fn attach(
        &mut self,
        store: &NativeStore,
        write: &WriteTransaction,
        publication: &mut Publication,
    ) -> Result<()> {
        match self {
            Self::Tree(tree, _) => store.attach_tree(
                write,
                tree.id,
                &tree.manifest,
                &tree.blobs,
                std::mem::take(&mut tree.staged),
                publication,
            ),
            Self::Result(result, plan, _) => result.attach(store, write, publication, plan),
        }
    }

    fn complete(self, store: &NativeStore) {
        match self {
            Self::Tree(tree, completion) => completion.send(tree.lease(store)),
            Self::Result(result, _, completion) => completion.send(result.lease(store)),
        }
    }

    fn fail(self, error: anyhow::Error) {
        match self {
            Self::Tree(_, completion) => completion.send(Err(error)),
            Self::Result(_, _, completion) => completion.send(Err(error)),
        }
    }
}

impl NativeStore {
    /// Queue a verified immutable-tree publication and receive its pinned
    /// lease after the durable index commit.
    ///
    /// # Errors
    /// Returns an error for invalid tree contents, failed storage, or shutdown.
    pub async fn publish_tree_pinned_async<R: Send + 'static>(
        &self,
        manifest: TreeManifest,
        staged: Vec<StagedBlob>,
        retained: R,
    ) -> Result<TreeLease> {
        let (completion, receive) = self.publication_completion(retained).await?;
        self.enqueue_publication(Request::Tree {
            manifest,
            staged,
            completion,
        });
        receive
            .await
            .context("native tree publication task stopped")?
    }

    /// Queue a verified compiler result for shared durable publication.
    /// The caller's resources are retained through the result commit.
    ///
    /// # Errors
    /// Returns an error for invalid results, conflicts, failed storage, or shutdown.
    pub async fn publish_pinned_async<R: Send + 'static>(
        &self,
        fingerprint: ActionFingerprint,
        manifest: ResultManifest,
        staged: Vec<StagedBlob>,
        mode: ActionMode,
        retained: R,
    ) -> Result<ResultLease> {
        let action = fingerprint.key()?;
        let (completion, receive) = self.publication_completion(retained).await?;
        self.enqueue_publication(Request::Result {
            action,
            fingerprint,
            manifest,
            staged,
            mode,
            completion,
        });
        receive
            .await
            .context("native result publication task stopped")?
    }

    async fn publication_completion<T, R: Send + 'static>(
        &self,
        retained: R,
    ) -> Result<(Completion<T>, oneshot::Receiver<Result<T>>)> {
        let resources: Box<dyn Send> = Box::new((
            retained,
            Arc::clone(&self.inner.publication_queue.slots)
                .acquire_owned()
                .await?,
        ));
        let (reply, receive) = oneshot::channel();
        Ok((
            Completion {
                reply,
                _resources: resources,
            },
            receive,
        ))
    }

    fn enqueue_publication(&self, request: Request) {
        let start = {
            let mut state = self
                .inner
                .publication_queue
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.pending.push_back(request);
            let start = !state.running;
            state.running = true;
            start
        };
        if start {
            tokio::spawn(
                Drain {
                    store: self.clone(),
                    armed: true,
                }
                .run(),
            );
        }
    }

    fn process_publication_batch(&self, requests: Vec<Request>) {
        let mut prepared: Vec<_> = requests
            .into_iter()
            .filter_map(|request| request.prepare(self))
            .collect();
        let mut validated = Vec::with_capacity(prepared.len());
        if let Err(error) = self.publish_batch(&mut prepared, &mut validated) {
            for request in prepared {
                request.fail(anyhow::anyhow!(
                    "native publication transaction failed: {error:#}"
                ));
            }
            for request in validated {
                request.fail(anyhow::anyhow!(
                    "native publication transaction failed: {error:#}"
                ));
            }
        }
    }

    fn publish_batch(
        &self,
        prepared: &mut Vec<Prepared>,
        validated: &mut Vec<Validated>,
    ) -> Result<()> {
        if prepared.is_empty() {
            return Ok(());
        }
        let _mutation = self.inner.lock_mutations()?;
        let read = self.inner.db.begin_read()?;
        validated.extend(
            prepared
                .drain(..)
                .filter_map(|request| request.preflight(self, &read)),
        );
        drop(read);
        if validated.is_empty() {
            return Ok(());
        }
        let write = self.inner.db.begin_write()?;
        let mut publication = Publication::default();
        let mut index = 0;
        while index < validated.len() {
            if let Err(error) = validated[index].revalidate(self, &write) {
                validated.remove(index).fail(error);
            } else {
                validated[index].attach(self, &write, &mut publication)?;
                index += 1;
            }
        }
        if validated.is_empty() {
            return Ok(());
        }
        publication.commit(&self.inner, write)?;
        log::trace!(target: "native_cas_publication", "committed CAS batch with {} requests", validated.len());
        #[cfg(test)]
        self.inner
            .publication_queue
            .committed_batches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        for request in validated.drain(..) {
            request.complete(self);
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
                let queue = &self.store.inner.publication_queue;
                let mut state = queue.state.lock().unwrap_or_else(PoisonError::into_inner);
                if state.pending.is_empty() {
                    state.running = false;
                    drop(state);
                    self.armed = false;
                    return;
                }
                let mut batch = Vec::new();
                let mut entries = 0_usize;
                let mut actions = BTreeSet::new();
                while let Some(next) = state.pending.front() {
                    let cost = next.cost();
                    // A second publication of the same action must observe
                    // the first's committed state, including Reuse conflicts.
                    if !batch.is_empty()
                        && (batch.len() >= MAX_BATCH_REQUESTS
                            || entries.saturating_add(cost) > MAX_BATCH_ENTRIES
                            || next
                                .action()
                                .is_some_and(|action| actions.contains(&action)))
                    {
                        break;
                    }
                    if let Some(request) = state.pending.pop_front() {
                        if let Some(action) = request.action() {
                            actions.insert(action);
                        }
                        batch.push(request);
                        entries = entries.saturating_add(cost);
                    }
                }
                batch
            };
            let store = self.store.clone();
            if let Err(error) =
                tokio::task::spawn_blocking(move || store.process_publication_batch(batch)).await
            {
                log::error!("native CAS publication batch failed: {error:#}");
            }
        }
    }
}

impl Drop for Drain {
    fn drop(&mut self) {
        if self.armed {
            let pending = {
                let mut state = self
                    .store
                    .inner
                    .publication_queue
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                state.running = false;
                let pending = std::mem::take(&mut state.pending);
                drop(state);
                pending
            };
            for request in pending {
                request.fail(anyhow::anyhow!("native CAS publication drain stopped"));
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
        let index = BlobIndex {
            live: &live,
            pending: &pending,
            layouts: &layouts,
        };
        let mut complete = true;
        for (&id, &size) in &self.blobs {
            complete &= index.inspect(
                &store.inner,
                crate::BlobRef { id, size },
                exists,
                self.staged.get(&id),
            )? == Attachment::Live;
        }
        Ok(exists && complete)
    }

    fn lease(self, store: &NativeStore) -> Result<TreeLease> {
        store.lease_prepared_tree(self.id, self.manifest, self.blobs)
    }
}
