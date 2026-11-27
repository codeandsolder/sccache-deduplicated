//! Worker-resident immutable execution state. The durable CAS remains the
//! authority; memo entries are weak references to already pinned content,
//! and only the bounded read-only view cache owns idle leases.

use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, Weak},
};

use anyhow::{Context, Result, anyhow, ensure};

use super::{
    NativeStore, UploadReservation,
    space::Root,
    trees::{MountedTree, ReadOnlyView, TreeLease, plan_overlays},
};
use crate::{BlobRef, ContentId, ExecutionRoot, TreeId};

/// The complete resident portion of an admitted input closure. Complete
/// trees protect all their blobs; the remaining partial closure has its
/// own reservation until the worker has acquired the missing trees.
pub struct ResidentInputs {
    _trees: Vec<Arc<TreeLease>>,
    blobs: UploadReservation,
}

impl ResidentInputs {
    #[must_use = "missing inputs must be acquired before execution"]
    pub fn missing(&self) -> &[BlobRef] {
        self.blobs.missing()
    }
}

impl NativeStore {
    /// Pin complete resident trees and reserve only the input blobs not
    /// already covered by those leases. No redundant disk probe or
    /// per-blob pin is needed for a verified immutable tree.
    /// # Errors
    /// Returns an error for inconsistent lengths or store failure.
    pub fn reserve_resident_inputs(
        &self,
        trees: impl IntoIterator<Item = TreeId>,
        mut uncovered: BTreeMap<ContentId, u64>,
    ) -> Result<ResidentInputs> {
        let mut leases = Vec::new();
        for id in trees {
            if let Some(tree) = self.lookup_resident_tree(id)? {
                for (id, &size) in tree.blobs() {
                    if let Some(expected) = uncovered.remove(id) {
                        ensure!(size == expected, "inconsistent admitted content length");
                    }
                }
                leases.push(tree);
            }
        }
        let blobs = self.reserve_blobs(&uncovered)?;
        Ok(ResidentInputs {
            _trees: leases,
            blobs,
        })
    }
}

const MAX_CACHED_TREE_MOUNTS: usize = 16;
const MEMO_SWEEP_THRESHOLD: usize = 64;

type MemoSlot<V> = Arc<Mutex<Weak<V>>>;

/// Per-identity coordination without serializing unrelated builds. The map
/// retains neither content nor filesystem views after their final owner drops.
struct WeakMemo<K, V> {
    slots: Mutex<MemoIndex<K, V>>,
}

struct MemoIndex<K, V> {
    slots: BTreeMap<K, MemoSlot<V>>,
    sweep_at: usize,
}

impl<K, V> Default for WeakMemo<K, V> {
    fn default() -> Self {
        Self {
            slots: Mutex::new(MemoIndex {
                slots: BTreeMap::new(),
                sweep_at: MEMO_SWEEP_THRESHOLD,
            }),
        }
    }
}

impl<K: Ord + Copy, V> WeakMemo<K, V> {
    fn slot(&self, key: K) -> Result<MemoSlot<V>> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| anyhow!("resident memo lock poisoned"))?;
        if let Some(slot) = slots.slots.get(&key) {
            return Ok(Arc::clone(slot));
        }
        if slots.slots.len() >= slots.sweep_at {
            // Never remove a slot that another caller owns, even if its
            // producer has not yet finished constructing the value.
            slots.slots.retain(|_, slot| {
                Arc::strong_count(slot) > 1
                    || slot
                        .try_lock()
                        .map_or(true, |value| value.strong_count() > 0)
            });
            // Avoid repeatedly scanning a large set of live in-flight jobs.
            slots.sweep_at = MEMO_SWEEP_THRESHOLD.max(slots.slots.len().saturating_mul(2));
        }
        Ok(Arc::clone(slots.slots.entry(key).or_default()))
    }
}

#[derive(Default)]
struct ViewCache {
    entries: BTreeMap<TreeId, Arc<ReadOnlyView>>,
    order: VecDeque<TreeId>,
}

impl ViewCache {
    fn touch(&mut self, key: TreeId) {
        if self.entries.contains_key(&key) {
            self.order.retain(|other| *other != key);
            self.order.push_back(key);
        }
    }

    fn retain(&mut self, key: TreeId, view: Arc<ReadOnlyView>) -> Option<Arc<ReadOnlyView>> {
        // A per-identity flight guarantees that an existing value is the
        // same view. Dropping the redundant Arc cannot destroy the view.
        self.entries.entry(key).or_insert(view);
        self.touch(key);
        if self.entries.len() > MAX_CACHED_TREE_MOUNTS {
            self.order
                .pop_front()
                .and_then(|id| self.entries.remove(&id))
        } else {
            None
        }
    }

    fn retire_idle(&mut self, only: Option<TreeId>) -> Vec<Arc<ReadOnlyView>> {
        let unused: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(&id, view)| {
                (Arc::strong_count(view) == 1
                    && only.is_none_or(|target| id == target || view.lease().holds_tree(target)))
                .then_some(id)
            })
            .collect();
        let retired = unused
            .iter()
            .filter_map(|id| self.entries.remove(id))
            .collect();
        self.order.retain(|key| !unused.contains(key));
        retired
    }
}

#[derive(Default)]
pub(super) struct ResidentRuntime {
    trees: WeakMemo<TreeId, TreeLease>,
    recipes: WeakMemo<ContentId, TreeLease>,
    views: WeakMemo<TreeId, ReadOnlyView>,
    retained: Mutex<ViewCache>,
}

impl ResidentRuntime {
    pub(super) fn lookup_tree(
        &self,
        store: &NativeStore,
        id: TreeId,
    ) -> Result<Option<Arc<TreeLease>>> {
        let slot = self.trees.slot(id)?;
        let mut memo = slot
            .lock()
            .map_err(|_| anyhow!("resident tree lock poisoned"))?;
        if let Some(lease) = memo.upgrade() {
            store.inner.lock_pins()?.touch(Root::Tree(id));
            return Ok(Some(lease));
        }
        let lease = store.lookup_tree(id)?.map(Arc::new);
        if let Some(lease) = &lease {
            *memo = Arc::downgrade(lease);
        }
        Ok(lease)
    }

    pub(super) fn remember_tree(
        &self,
        store: &NativeStore,
        lease: Arc<TreeLease>,
    ) -> Result<Arc<TreeLease>> {
        ensure!(
            lease.belongs_to(store) && lease.is_indexed(),
            "resident input must be an indexed lease from this store"
        );
        let slot = self.trees.slot(lease.id())?;
        let mut memo = slot
            .lock()
            .map_err(|_| anyhow!("resident tree lock poisoned"))?;
        if let Some(existing) = memo.upgrade() {
            return Ok(existing);
        }
        *memo = Arc::downgrade(&lease);
        Ok(lease)
    }

    pub(super) fn recipe(
        &self,
        store: &NativeStore,
        root: &ExecutionRoot,
        inputs: &BTreeMap<TreeId, Arc<TreeLease>>,
    ) -> Result<Arc<TreeLease>> {
        // Even a memo hit must be backed by this action's authorized
        // constituent leases, and the declared composed digest must match.
        for layer in &root.recipe.layers {
            let lease = inputs
                .get(&layer.tree)
                .context("resident recipe input missing")?;
            ensure!(
                lease.belongs_to(store) && lease.id() == layer.tree,
                "resident recipe input mismatch"
            );
        }
        let slot = self.recipes.slot(root.recipe.fingerprint()?)?;
        let mut memo = slot
            .lock()
            .map_err(|_| anyhow!("resident recipe lock poisoned"))?;
        if let Some(lease) = memo.upgrade() {
            root.verify(lease.id())?;
            return Ok(lease);
        }
        let lease = Arc::new(store.compose_leased_recipe(&root.recipe, inputs)?);
        root.verify(lease.id())?;
        *memo = Arc::downgrade(&lease);
        Ok(lease)
    }

    fn retain(&self, key: TreeId, view: Arc<ReadOnlyView>) -> Result<()> {
        let retired = self
            .retained
            .lock()
            .map_err(|_| anyhow!("resident view cache lock poisoned"))?
            .retain(key, view);
        // FUSE unmount/join and ZFS tree cleanup can be slow.
        drop(retired);
        Ok(())
    }

    pub(super) fn mount(
        &self,
        lease: Arc<TreeLease>,
        persistent: &Path,
        scratch: &Path,
        native_zfs: bool,
        protected: &[PathBuf],
    ) -> Result<MountedTree> {
        let key = lease.id();
        let slot = self.views.slot(key)?;
        let mut memo = slot
            .lock()
            .map_err(|_| anyhow!("resident view lock poisoned"))?;
        if let Some(view) = memo.upgrade() {
            self.retain(key, Arc::clone(&view))?;
            return Ok(MountedTree::from_view(view, scratch));
        }

        // Snapshot only the immutable references under the cache lock.
        // Diffing large manifests and all disk/FUSE work happen outside it.
        let candidates = self
            .retained
            .lock()
            .map_err(|_| anyhow!("resident view cache lock poisoned"))?
            .entries
            .iter()
            .map(|(&id, view)| (id, Arc::downgrade(view)))
            .collect::<Vec<_>>();
        let mut best: Option<(TreeId, Arc<ReadOnlyView>, super::trees::OverlayPlan)> = None;
        for (id, candidate) in candidates {
            let Some(view) = candidate.upgrade() else {
                continue;
            };
            let Some(plan) = plan_overlays(view.manifest(), lease.manifest(), protected) else {
                continue;
            };
            if plan.materialized_entries >= lease.manifest().entries.len().div_ceil(2) {
                continue;
            }
            if best.as_ref().is_none_or(|(_, _, previous)| {
                plan.materialized_entries < previous.materialized_entries
            }) {
                // A nonempty overlay has at least one target entry. Since
                // identities are sorted, this also preserves the tie break.
                let optimal = plan.materialized_entries == 1;
                best = Some((id, view, plan));
                if optimal {
                    break;
                }
            }
        }
        if let Some((base_id, view, plan)) = best {
            // Overlays are private per action, not published as resident
            // views. There is no shared construction left to serialize.
            drop(memo);
            self.retained
                .lock()
                .map_err(|_| anyhow!("resident view cache lock poisoned"))?
                .touch(base_id);
            let mut mounted = MountedTree::from_view(view, scratch);
            let overlay = lease.materialize_overlays(&plan, scratch)?;
            let stats = overlay.stats;
            mounted.attach_overlays(overlay);
            log::debug!(
                "native CAS reused immutable tree {base_id:?} with {} changed files, {} changed subtrees, {} block clones, {} copied bytes",
                plan.files.len(),
                plan.directories.len(),
                stats.cloned_files,
                stats.copied_bytes,
            );
            return Ok(mounted);
        }

        let view = Arc::new(if native_zfs {
            ReadOnlyView::materialize_zfs(lease, persistent)?
        } else {
            ReadOnlyView::mount_fuse(lease, persistent)?
        });
        *memo = Arc::downgrade(&view);
        self.retain(key, Arc::clone(&view))?;
        Ok(MountedTree::from_view(view, scratch))
    }

    pub(super) fn drop_idle(&self, only: Option<TreeId>) -> Result<()> {
        let retired = self
            .retained
            .lock()
            .map_err(|_| anyhow!("resident view cache lock poisoned"))?
            .retire_idle(only);
        drop(retired);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Eviction, TreeMetadata, TreeRecipe, TreeTimestamp};
    use std::{fs, sync::Barrier, time::Duration};

    #[test]
    fn unrelated_identities_do_not_share_a_preparation_lock() -> Result<()> {
        let memo = WeakMemo::<u64, u64>::default();
        let first = memo.slot(1)?;
        let _held = first.lock().expect("lock first identity");
        std::thread::scope(|scope| {
            let (send, receive) = std::sync::mpsc::channel();
            let memo = &memo;
            scope.spawn(move || {
                let second = memo.slot(2).expect("second identity");
                let _guard = second.lock().expect("lock second identity");
                send.send(()).expect("receiver");
            });
            receive
                .recv_timeout(Duration::from_secs(5))
                .expect("independent preparation");
        });
        Ok(())
    }

    #[test]
    fn memo_sweep_preserves_active_flights_and_discards_dead_slots() -> Result<()> {
        let memo = WeakMemo::<usize, usize>::default();
        let held = memo.slot(0)?;
        let value = Arc::new(1);
        *memo.slot(1)?.lock().expect("value slot") = Arc::downgrade(&value);
        for id in 2..MEMO_SWEEP_THRESHOLD * 4 {
            drop(memo.slot(id)?);
        }
        assert!(Arc::ptr_eq(&held, &memo.slot(0)?));
        assert!(Arc::ptr_eq(
            &value,
            &memo
                .slot(1)?
                .lock()
                .expect("value slot")
                .upgrade()
                .context("live value")?
        ));
        assert!(memo.slots.lock().expect("memo index").slots.len() <= MEMO_SWEEP_THRESHOLD);
        Ok(())
    }

    #[test]
    fn resident_tree_leases_are_shared_but_do_not_prevent_eviction() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("input"), b"resident input")?;
        let store = NativeStore::open(&directory.path().join("store"))?;
        let original = store.capture_tree(&source)?;
        let id = original.id();
        let first = store.remember_resident_tree(Arc::new(original))?;
        let second = store.lookup_resident_tree(id)?.context("resident tree")?;
        assert!(Arc::ptr_eq(&first, &second));
        let other = NativeStore::open(&directory.path().join("other"))?;
        assert!(other.remember_resident_tree(Arc::clone(&first)).is_err());
        assert_eq!(store.evict_tree(id)?, Eviction::Pinned);
        drop(first);
        drop(second);
        assert!(matches!(store.evict_tree(id)?, Eviction::Removed { .. }));
        assert!(store.lookup_resident_tree(id)?.is_none());
        Ok(())
    }

    #[test]
    fn assignment_reserves_only_blobs_not_covered_by_complete_trees() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        fs::create_dir(&source)?;
        let bytes = b"resident input";
        fs::write(source.join("input"), bytes)?;
        let store = NativeStore::open(&directory.path().join("store"))?;
        let lease = store.capture_tree(&source)?;
        let id = lease.id();
        let blob = ContentId::of(bytes);
        let missing = ContentId::of(b"missing");
        let length = u64::try_from(bytes.len())?;
        let inputs = BTreeMap::from([(blob, length), (missing, 7)]);
        let pins = store.reserve_resident_inputs([id], inputs)?;
        assert_eq!(
            pins.missing(),
            &[BlobRef {
                id: missing,
                size: 7
            }]
        );
        assert!(
            store
                .reserve_resident_inputs([id], BTreeMap::from([(blob, length + 1)]))
                .is_err()
        );
        drop(lease);
        assert_eq!(store.evict_tree(id)?, Eviction::Pinned);
        drop(pins);
        assert!(matches!(store.evict_tree(id)?, Eviction::Removed { .. }));
        Ok(())
    }

    #[test]
    fn composed_view_singleflight_and_constituent_eviction() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("compiler"), b"toolchain")?;
        let store = NativeStore::open(&directory.path().join("store"))?;
        let input = store.remember_resident_tree(Arc::new(store.capture_tree(&source)?))?;
        let id = input.id();
        let recipe = TreeRecipe::union(
            TreeMetadata {
                mode: 0o755,
                modified: TreeTimestamp {
                    seconds: 1,
                    nanoseconds: 0,
                },
            },
            [id],
        );
        let root = ExecutionRoot {
            id: recipe
                .compose(&BTreeMap::from([(id, input.manifest())]))?
                .id()?,
            recipe,
        };
        let inputs = BTreeMap::from([(id, input)]);
        let first = store.resident_recipe(&root, &inputs)?;
        let second = store.resident_recipe(&root, &inputs)?;
        assert!(Arc::ptr_eq(&first, &second));
        let mut forged = root.clone();
        forged.id = TreeId([0; 32]);
        assert!(store.resident_recipe(&forged, &inputs).is_err());
        assert!(store.resident_recipe(&root, &BTreeMap::new()).is_err());
        let barrier = Barrier::new(4);
        let views = std::thread::scope(|scope| {
            let handles = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        store.mount_tree_protected(Arc::clone(&first), directory.path(), &[])
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("mount worker"))
                .collect::<Result<Vec<_>>>()
        })?;
        let path = views[0].root().to_owned();
        assert!(views.iter().all(|view| view.root() == path));
        assert_eq!(fs::read(path.join("compiler"))?, b"toolchain");
        assert_eq!(store.evict_tree(id)?, Eviction::Pinned);
        drop(views);
        drop(first);
        drop(second);
        drop(inputs);
        assert!(matches!(store.evict_tree(id)?, Eviction::Removed { .. }));
        assert!(!path.exists());
        Ok(())
    }
}
