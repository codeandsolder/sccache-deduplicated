use std::{collections::BTreeMap, io::Cursor};

use super::*;
use crate::{
    ActionFingerprint, Artifact, BlobRef, ContentId, ResultManifest, TreeEntry, TreeManifest,
    TreeMetadata, TreePath, TreeTimestamp,
};

fn policy() -> SpacePolicy {
    SpacePolicy {
        min_available_bytes: 100,
        target_available_bytes: 200,
        max_resident_bytes: Some(u64::MAX),
        target_resident_bytes: Some(u64::MAX),
        max_evictions_per_pass: 4,
        gc_batch: 16,
    }
}

fn publish(store: &NativeStore, name: &str) -> Result<ActionKey> {
    let stage = store.stage(Cursor::new(name.as_bytes()))?;
    let blob: BlobRef = stage.reference();
    let manifest = ResultManifest {
        outputs: BTreeMap::from([("obj".into(), Artifact::File { blob, mode: None })]),
        stdout: None,
        stderr: None,
    };
    let fingerprint = ActionFingerprint {
        schema: "test".into(),
        components: BTreeMap::from([("source".into(), ContentId::of(name.as_bytes()))]),
    };
    Ok(store
        .publish(
            &fingerprint,
            &manifest,
            vec![stage],
            crate::ActionMode::Reuse,
        )?
        .action)
}

fn eviction_roots(store: &NativeStore, count: usize) -> Result<Vec<Root>> {
    Ok(store
        .eviction_candidates(count, false)?
        .into_iter()
        .map(EvictionTarget::root)
        .collect())
}

#[test]
fn physical_pressure_evicts_oldest_root_but_never_active_leases() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    let old = publish(&store, "old")?;
    let newer = publish(&store, "newer")?;
    let pin = store.lookup(old)?.context("missing old result")?;
    let root = store.publish_tree(
        &TreeManifest {
            root: TreeMetadata {
                mode: 0o755,
                modified: TreeTimestamp {
                    seconds: 0,
                    nanoseconds: 0,
                },
            },
            entries: BTreeMap::new(),
        },
        vec![],
    )?;
    // Simulate physical pressure which is relieved by reclaiming the newer
    // action, not by assuming its logical length equals reclaimed disk space.
    let report = store.reclaim(
        policy(),
        || Ok(10),
        20,
        || {
            Ok(if store.stats()?.actions == 2 {
                100
            } else {
                250
            })
        },
    )?;
    assert_eq!(report.evicted_roots, 1);
    assert!(report.minimum_satisfied);
    assert!(store.lookup(newer)?.is_none());
    assert!(store.lookup(old)?.is_some());
    assert!(store.lookup_tree(root)?.is_some());
    drop(pin);
    Ok(())
}

#[test]
fn unreclaimable_space_rejects_admission_and_work_is_bounded() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    let old = publish(&store, "old")?;
    let new = publish(&store, "new")?;
    let mut p = policy();
    p.max_evictions_per_pass = 1;
    let report = store.reclaim(p, || Ok(50), 50, || Ok(10))?;
    assert_eq!(report.evicted_roots, 1);
    assert!(!report.minimum_satisfied);
    assert!(store.lookup(old)?.is_none());
    assert!(store.lookup(new)?.is_some());
    Ok(())
}

#[test]
fn managed_staging_reservations_are_released_and_oversize_rejected() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open_managed(temp.path(), policy())?;
    let mut budget = super::StageBudget::new(&store);
    budget.grow_to(4096)?;
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        4096
    );
    assert!(budget.grow_to(u64::MAX).is_err());
    drop(budget);
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        0
    );
    let blob = store.stage_expected(
        BlobRef {
            id: ContentId::of(b"abc"),
            size: 3,
        },
        &b"abc"[..],
    )?;
    assert_eq!(blob.reference().size, 3);
    Ok(())
}

#[test]
fn reuse_favors_a_hot_root_over_a_newer_cold_root() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    let hot = publish(&store, "hot")?;
    for _ in 0..32 {
        drop(store.lookup(hot)?.context("missing hot action")?);
    }
    let cold = publish(&store, "cold")?;
    let mut limit = policy();
    limit.max_evictions_per_pass = 1;
    let report = store.reclaim(
        limit,
        || Ok(0),
        0,
        || Ok(if store.stats()?.actions == 2 { 0 } else { 300 }),
    )?;
    assert_eq!(report.evicted_roots, 1);
    assert!(store.lookup(hot)?.is_some());
    assert!(store.lookup(cold)?.is_none());
    Ok(())
}

#[test]
fn empty_gc_and_healthy_space_maintenance_do_not_wait_for_publication() -> Result<()> {
    use std::{sync::mpsc, thread};
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open_managed(temp.path(), policy())?;
    let key = publish(&store, "data")?;
    let mutation = store.inner.lock_mutations()?;
    let report = thread::scope(|scope| -> Result<_> {
        let (send, receive) = mpsc::channel();
        let store = &store;
        let worker = scope.spawn(move || send.send(store.maintain_space()));
        let observed = receive.recv_timeout(Duration::from_secs(2));
        drop(mutation);
        worker
            .join()
            .map_err(|_| anyhow!("maintenance worker panicked"))??;
        observed?
    })?
    .context("missing space policy")?;
    assert!(report.minimum_satisfied);
    assert_eq!(report.resident_bytes, 4);
    // A due checkpoint was postponed, not dropped, while publication owned
    // the mutation mutex.
    assert!(
        store
            .inner
            .lock_pins()?
            .dirty_usage
            .contains(&Root::Action(key))
    );
    store.maintain_space()?;
    assert!(store.inner.lock_pins()?.dirty_usage.is_empty());
    assert!(matches!(store.evict(key)?, Eviction::Removed { .. }));
    assert_eq!(
        store
            .maintain_space()?
            .context("missing space policy")?
            .resident_bytes,
        0
    );
    Ok(())
}

#[test]
fn usage_checkpoint_preserves_touches_after_its_snapshot() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    let key = publish(&store, "data")?;
    let root = Root::Action(key);
    let unchanged = Root::Action(publish(&store, "unchanged")?);
    let snapshot = store.inner.lock_pins()?.usage_snapshot();
    let before = store.inner.lock_pins()?.usage[&root];
    drop(store.lookup(key)?.context("missing result")?);
    persist_usage(&store.inner.db, &snapshot)?;
    {
        let mut pins = store.inner.lock_pins()?;
        pins.finish_usage_checkpoint(&snapshot);
        assert!(pins.dirty_usage.contains(&root));
        assert!(!pins.dirty_usage.contains(&unchanged));
        assert_eq!(pins.usage[&root].hits, before.hits + 1);
    }
    store.checkpoint_usage()?;
    assert!(store.inner.lock_pins()?.dirty_usage.is_empty());
    let read = store.inner.db.begin_read()?;
    let usage = read.open_table(super::super::USAGE)?;
    let saved: UsageRecord = encoding().deserialize(
        usage
            .get(&root.key())?
            .context("missing checkpoint")?
            .value(),
    )?;
    assert_eq!(saved.hits, before.hits + 1);
    Ok(())
}

#[test]
fn usage_survives_restart_and_is_removed_with_evicted_roots() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (hot, cold) = {
        let store = NativeStore::open(temp.path())?;
        let hot = publish(&store, "hot")?;
        for _ in 0..32 {
            drop(store.lookup(hot)?.context("missing hot action")?);
        }
        let cold = publish(&store, "cold")?;
        store.checkpoint_usage()?;
        (hot, cold)
    };
    let store = NativeStore::open(temp.path())?;
    let usage = store.inner.lock_pins()?;
    assert!(
        usage
            .usage
            .get(&Root::Action(hot))
            .context("usage lost")?
            .hits
            > 32
    );
    drop(usage);
    let mut limit = policy();
    limit.max_evictions_per_pass = 1;
    let report = store.reclaim(
        limit,
        || Ok(0),
        0,
        || Ok(if store.stats()?.actions == 2 { 0 } else { 300 }),
    )?;
    assert_eq!(report.evicted_roots, 1);
    assert!(store.lookup(hot)?.is_some());
    assert!(store.lookup(cold)?.is_none());
    drop(store);
    let restored = NativeStore::open(temp.path())?;
    assert!(
        !restored
            .inner
            .lock_pins()?
            .usage
            .contains_key(&Root::Action(cold))
    );
    Ok(())
}

#[test]
fn resident_limit_evicts_even_when_filesystem_has_plenty_of_space() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    let first = publish(&store, "aaa")?;
    let second = publish(&store, "bbb")?;
    let newest = publish(&store, "ccccc")?;
    for _ in 0..16 {
        drop(store.lookup(newest)?.context("missing hot new root")?);
    }
    let mut limit = policy();
    limit.max_resident_bytes = Some(8);
    limit.target_resident_bytes = Some(6);
    let report = store.reclaim(limit, || Ok(0), 0, || Ok(100_000))?;
    assert!(report.minimum_satisfied);
    assert_eq!(report.evicted_roots, 2);
    assert!(report.resident_bytes <= 6);
    assert!(store.lookup(first)?.is_none());
    assert!(store.lookup(second)?.is_none());
    assert!(store.lookup(newest)?.is_some());
    Ok(())
}

#[test]
fn active_content_is_never_evicted_to_meet_a_worker_budget() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    let keep = publish(&store, "keep")?;
    let pin = store.lookup(keep)?.context("missing pinned action")?;
    let mut limit = policy();
    limit.max_resident_bytes = Some(1);
    limit.target_resident_bytes = Some(1);
    let report = store.reclaim(limit, || Ok(0), 0, || Ok(100_000))?;
    assert_eq!(report.evicted_roots, 0);
    assert!(!report.minimum_satisfied);
    drop(pin);
    let report = store.reclaim(limit, || Ok(0), 0, || Ok(100_000))?;
    assert!(report.minimum_satisfied);
    assert_eq!(report.resident_bytes, 0);
    Ok(())
}

#[test]
fn clean_shutdown_checkpoints_unflushed_accesses() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let hot = {
        let store = NativeStore::open(temp.path())?;
        let key = publish(&store, "restart")?;
        for _ in 0..6 {
            drop(store.lookup(key)?.context("missing action")?);
        }
        // No explicit checkpoint or maintenance call.
        key
    };
    let reopened = NativeStore::open(temp.path())?;
    let pins = reopened.inner.lock_pins()?;
    assert!(
        pins.usage
            .get(&Root::Action(hot))
            .context("orderly shutdown lost usage")?
            .hits
            >= 7
    );
    drop(pins);
    Ok(())
}

#[test]
fn staged_files_keep_exact_reservations_until_commit_or_drop() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut limit = policy();
    limit.max_resident_bytes = Some(10);
    limit.target_resident_bytes = Some(8);
    let store = NativeStore::open_managed(temp.path(), limit)?;
    let first = store.stage(&b"12345"[..])?;
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        5
    );
    // A second concurrent upload cannot overcommit the worker budget.
    assert!(store.stage(&b"abcdef"[..]).is_err());
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        5
    );
    drop(first);
    let second = store.stage(&b"abcdef"[..])?;
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        6
    );
    drop(second);
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        0
    );
    Ok(())
}

#[test]
fn exact_budget_allows_exact_verified_blob_but_rejects_oversize() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut limit = policy();
    limit.max_resident_bytes = Some(3);
    limit.target_resident_bytes = Some(3);
    let store = NativeStore::open_managed(temp.path(), limit)?;
    let expected = BlobRef {
        id: ContentId::of(b"abc"),
        size: 3,
    };
    let exact = store.stage_expected(expected, &b"abc"[..])?;
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        3
    );
    drop(exact);
    assert!(store.stage_expected(expected, &b"abcd"[..]).is_err());
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        0
    );
    Ok(())
}

#[test]
fn staged_release_never_waits_for_space_admission_lock() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open_managed(temp.path(), policy())?;
    let staged = store.stage(&b"reservation"[..])?;
    let held = store
        .inner
        .space
        .lock()
        .map_err(|_| anyhow!("poisoned admission lock"))?;
    // Streaming already deferred its unused round-up. Publication can
    // hold the mutation lock; a staged-file drop must not take the
    // admission lock as that would admit an ABBA deadlock.
    let already_released = store.inner.space_released.load(Ordering::Acquire);
    drop(staged);
    assert_eq!(
        store.inner.space_released.load(Ordering::Acquire),
        already_released + u64::try_from(b"reservation".len())?
    );
    drop(held);
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        0
    );
    Ok(())
}

#[test]
fn eviction_ranking_does_not_block_publication_and_revalidates_action_generation() -> Result<()> {
    use std::{sync::mpsc, thread};
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    let name = "old";
    let key = publish(&store, name)?;
    let mutation = store.inner.lock_mutations()?;
    let candidates = thread::scope(|scope| -> Result<_> {
        let (send, receive) = mpsc::channel();
        let store = &store;
        let worker = scope.spawn(move || send.send(store.eviction_candidates(1, true)));
        let observed = receive.recv_timeout(Duration::from_secs(2));
        drop(mutation);
        worker
            .join()
            .map_err(|_| anyhow!("ranking worker panicked"))??;
        observed?
    })?;
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].root(), Root::Action(key));
    let staged = store.stage(&b"new"[..])?;
    let manifest = ResultManifest {
        outputs: BTreeMap::from([(
            "obj".into(),
            Artifact::File {
                blob: staged.reference(),
                mode: None,
            },
        )]),
        stdout: None,
        stderr: None,
    };
    let fingerprint = ActionFingerprint {
        schema: "test".into(),
        components: BTreeMap::from([("source".into(), ContentId::of(name.as_bytes()))]),
    };
    store.publish(
        &fingerprint,
        &manifest,
        vec![staged],
        crate::ActionMode::Refresh,
    )?;
    assert_eq!(candidates[0].evict(&store)?, Eviction::Missing);
    assert_eq!(
        store
            .lookup(key)?
            .context("refreshed action missing")?
            .manifest(),
        &manifest
    );
    assert_eq!(store.collect_garbage(8)?.blobs, 1);
    Ok(())
}

#[test]
fn bounded_eviction_selection_keeps_only_lowest_utility_roots() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    let hot = publish(&store, "hot")?;
    let cold = publish(&store, "cold")?;
    let warm = publish(&store, "warm")?;
    for _ in 0..32 {
        drop(store.lookup(hot)?.context("missing hot root")?);
    }
    for _ in 0..8 {
        drop(store.lookup(warm)?.context("missing warm root")?);
    }
    assert_eq!(eviction_roots(&store, 1)?, vec![Root::Action(cold)]);
    assert_eq!(
        eviction_roots(&store, 2)?,
        vec![Root::Action(cold), Root::Action(warm)]
    );
    assert_eq!(
        eviction_roots(&store, 3)?,
        vec![Root::Action(cold), Root::Action(warm), Root::Action(hot)]
    );
    Ok(())
}

#[test]
fn committed_action_releases_staging_reservations_into_resident_accounting() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut limit = policy();
    limit.max_resident_bytes = Some(6);
    limit.target_resident_bytes = Some(5);
    let store = NativeStore::open_managed(temp.path(), limit)?;
    let key = publish(&store, "12345")?;
    let report = store.maintain_space()?.context("missing policy")?;
    assert_eq!(report.reserved_bytes, 0);
    assert_eq!(report.resident_bytes, 5);
    assert!(report.minimum_satisfied);
    assert!(store.lookup(key)?.is_some());
    Ok(())
}

#[test]
fn committed_tree_releases_staging_reservations_into_resident_accounting() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut limit = policy();
    limit.max_resident_bytes = Some(6);
    limit.target_resident_bytes = Some(5);
    let store = NativeStore::open_managed(temp.path(), limit)?;
    let staged = store.stage(&b"12345"[..])?;
    let metadata = TreeMetadata {
        mode: 0o755,
        modified: TreeTimestamp {
            seconds: 0,
            nanoseconds: 0,
        },
    };
    let tree = TreeManifest {
        root: metadata,
        entries: BTreeMap::from([(
            TreePath::new(b"file".to_vec())?,
            TreeEntry::File {
                blob: staged.reference(),
                metadata,
            },
        )]),
    };
    let tree_id = store.publish_tree(&tree, vec![staged])?;
    let report = store.maintain_space()?.context("missing policy")?;
    assert_eq!(report.reserved_bytes, 0);
    assert_eq!(report.resident_bytes, 5);
    assert!(report.minimum_satisfied);
    assert!(store.lookup_tree(tree_id)?.is_some());
    Ok(())
}

#[test]
fn eviction_prefers_exclusive_blobs_over_shared_result_aliases() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    let first = publish(&store, "aliased-payload")?;
    let fingerprint = ActionFingerprint {
        schema: "test".into(),
        components: BTreeMap::from([("source".into(), ContentId::of(b"different-input"))]),
    };
    let shared_blob = BlobRef {
        id: ContentId::of(b"aliased-payload"),
        size: u64::try_from(b"aliased-payload".len())?,
    };
    let manifest = ResultManifest {
        outputs: BTreeMap::from([(
            "obj".into(),
            Artifact::File {
                blob: shared_blob,
                mode: None,
            },
        )]),
        stdout: None,
        stderr: None,
    };
    let alias = store
        .publish(&fingerprint, &manifest, vec![], crate::ActionMode::Reuse)?
        .action;
    let exclusive = publish(&store, "exclusive")?;
    // This action has more accesses but frees content; neither alias frees
    // its own shared result until the final action reference disappears.
    for _ in 0..32 {
        drop(
            store
                .lookup(exclusive)?
                .context("missing exclusive result")?,
        );
    }
    assert_eq!(eviction_roots(&store, 1)?, vec![Root::Action(exclusive)]);
    assert!(matches!(
        store.evict(first)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 0
        }
    ));
    assert_eq!(eviction_roots(&store, 1)?, vec![Root::Action(alias)]);
    assert!(matches!(
        store.evict(alias)?,
        Eviction::Removed {
            unreferenced_logical_bytes
        } if unreferenced_logical_bytes == shared_blob.size
    ));
    Ok(())
}

#[test]
fn eviction_prefers_exclusive_tree_content_over_shared_tree_blobs() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    let metadata = TreeMetadata {
        mode: 0o755,
        modified: TreeTimestamp {
            seconds: 0,
            nanoseconds: 0,
        },
    };
    let staged = store.stage(&b"shared-tree-content"[..])?;
    let shared = staged.reference();
    let mut manifest = TreeManifest {
        root: metadata,
        entries: BTreeMap::from([(
            TreePath::new(b"file".to_vec())?,
            TreeEntry::File {
                blob: shared,
                metadata,
            },
        )]),
    };
    let first = store.publish_tree(&manifest, vec![staged])?;
    manifest.root.mode = 0o700;
    let second = store.publish_tree(&manifest, vec![])?;
    let staged = store.stage(&b"exclusive-content"[..])?;
    let unique = staged.reference();
    manifest.root.mode = 0o750;
    manifest.entries.insert(
        TreePath::new(b"file".to_vec())?,
        TreeEntry::File {
            blob: unique,
            metadata,
        },
    );
    let exclusive = store.publish_tree(&manifest, vec![staged])?;
    for _ in 0..32 {
        drop(
            store
                .lookup_tree(exclusive)?
                .context("missing exclusive tree")?,
        );
    }
    assert_eq!(eviction_roots(&store, 1)?, vec![Root::Tree(exclusive)]);
    assert!(matches!(
        store.evict_tree(first)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 0
        }
    ));
    assert_eq!(eviction_roots(&store, 1)?, vec![Root::Tree(second)]);
    Ok(())
}

#[test]
fn physical_reclaim_estimate_uses_file_allocation_not_logical_size() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    let name = "compressible-allocation-".repeat(4096);
    let action = publish(&store, &name)?;
    let lease = store.lookup(action)?.context("missing action")?;
    let result = lease.manifest().id()?;
    let id = ContentId::of(name.as_bytes());
    let size = u64::try_from(name.len())?;
    let blobs = BTreeMap::from([(id, size)]);
    let disappearing = BTreeSet::from([result.0]);
    let read = store.inner.db.begin_read()?;
    let owners = read.open_multimap_table(BLOB_ROOTS)?;
    let actual_blocks = std::fs::metadata(store.inner.blob_path(id))?
        .blocks()
        .checked_mul(512)
        .context("allocation block overflow")?;
    assert_eq!(
        store.reclaimable_potential(&blobs, &disappearing, &BTreeSet::new(), &owners, true)?,
        actual_blocks
    );
    assert_eq!(
        store.reclaimable_potential(&blobs, &disappearing, &BTreeSet::new(), &owners, false)?,
        size
    );
    let pinned = store
        .inner
        .lock_pins()?
        .blobs
        .keys()
        .copied()
        .collect::<BTreeSet<_>>();
    assert!(pinned.contains(&id));
    assert_eq!(
        store.reclaimable_potential(&blobs, &disappearing, &pinned, &owners, true)?,
        0
    );
    drop(lease);
    Ok(())
}

#[test]
fn eviction_counts_retained_package_archive_even_when_tree_files_are_shared() -> Result<()> {
    use crate::{
        ArchiveLength, PackageCompression, PackageDecoder, PackageIdentity, PackagePolicy,
    };
    use sha2::{Digest as _, Sha256};

    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(4);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "pkg/file", &b"DATA"[..])?;
    let compressed = zstd::stream::encode_all(&tar.into_inner()?[..], 1)?;

    let mut limits = PackagePolicy::normalized_archive(20, 16_384, 65_536, 16_384)?;
    limits.retain_original = true;
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    let original = store.import_package(
        PackageIdentity {
            sha256: Sha256::digest(&compressed).into(),
            compression: PackageCompression::Zstd,
        },
        ArchiveLength::Exact(u64::try_from(compressed.len())?),
        limits,
        &compressed[..],
        PackageDecoder::InProcess,
    )?;
    let original_id = original.tree().id();
    let mut sibling_manifest = original.tree().manifest().clone();
    sibling_manifest.root.mode = 0o700;
    let sibling = store.publish_tree(&sibling_manifest, vec![])?;
    drop(original);

    // The expanded file remains shared with sibling, but the original
    // compressed archive belongs exclusively to the package tree.
    assert_eq!(eviction_roots(&store, 1)?, vec![Root::Tree(original_id)]);
    assert!(matches!(
        store.evict_tree(original_id)?,
        Eviction::Removed {
            unreferenced_logical_bytes
        } if unreferenced_logical_bytes == u64::try_from(compressed.len())?
    ));
    assert_eq!(store.stats()?.blobs, 1);
    assert!(store.lookup_tree(sibling)?.is_some());
    Ok(())
}

#[test]
fn output_headroom_survives_other_staging_and_converts_without_double_charge() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut limit = policy();
    limit.max_resident_bytes = Some(10);
    limit.target_resident_bytes = Some(10);
    let store = NativeStore::open_managed(temp.path(), limit)?;
    let mut output = store.reserve_staging(7)?;
    let input = store.stage_expected(
        BlobRef {
            id: ContentId::of(b"abc"),
            size: 3,
        },
        &b"abc"[..],
    )?;
    assert!(store.reserve_staging(1).is_err());
    let blob = BlobRef {
        id: ContentId::of(b"result!"),
        size: 7,
    };
    let staged = output.stage_expected(blob, &b"result!"[..])?;
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        10
    );
    assert!(
        output
            .stage_expected(
                BlobRef {
                    id: ContentId::of(b"x"),
                    size: 1
                },
                &b"x"[..]
            )
            .is_err()
    );
    let manifest = ResultManifest {
        outputs: BTreeMap::from([("obj".into(), Artifact::File { blob, mode: None })]),
        stdout: None,
        stderr: None,
    };
    let fingerprint = ActionFingerprint {
        schema: "reserved-output".into(),
        components: BTreeMap::new(),
    };
    let lease = store.publish_pinned(
        &fingerprint,
        &manifest,
        vec![staged],
        crate::ActionMode::Reuse,
    )?;
    drop(output);
    let report = store.maintain_space()?.context("missing policy")?;
    assert_eq!(report.reserved_bytes, 3);
    assert_eq!(report.resident_bytes, 10);
    assert!(store.reserve_staging(1).is_err());
    drop(input);
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        0
    );
    assert_eq!(store.stats()?.logical_bytes, 7);
    drop(lease);
    Ok(())
}

#[test]
fn rejected_reserved_upload_releases_its_charge() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut limit = policy();
    limit.max_resident_bytes = Some(10);
    limit.target_resident_bytes = Some(10);
    let store = NativeStore::open_managed(temp.path(), limit)?;
    let mut budget = store.reserve_staging(10)?;
    assert!(
        budget
            .stage_expected(
                BlobRef {
                    id: ContentId::of(b"abc"),
                    size: 3
                },
                &b"bad"[..]
            )
            .is_err()
    );
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        7
    );
    drop(budget);
    assert_eq!(
        store
            .maintain_space()?
            .context("missing policy")?
            .reserved_bytes,
        0
    );
    Ok(())
}

#[test]
fn residency_snapshot_tracks_live_outputs_across_eviction_and_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let retained = ContentId::of(b"retained");
    let removed = ContentId::of(b"removed");
    {
        let store = NativeStore::open(dir.path())?;
        let keep = publish(&store, "retained")?;
        let drop_key = publish(&store, "removed")?;
        let before = store.blob_residency()?.context("missing inventory")?;
        assert!(before.may_contain(retained));
        assert!(before.may_contain(removed));
        assert!(matches!(store.evict(drop_key)?, Eviction::Removed { .. }));
        let after = store.blob_residency()?.context("missing inventory")?;
        assert!(after.may_contain(retained));
        assert!(!after.may_contain(removed));
        assert!(store.lookup(keep)?.is_some());
    }
    let store = NativeStore::open(dir.path())?;
    let restored = store.blob_residency()?.context("missing inventory")?;
    assert!(restored.may_contain(retained));
    assert!(!restored.may_contain(removed));
    Ok(())
}

#[test]
fn observation_does_not_reclaim_or_wait_for_admission() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = NativeStore::open_managed(temp.path(), policy())?;
    let mut budget = StageBudget::new(&store);
    budget.grow_to(4096)?;
    let before = store.stats()?;
    let observation = store.space_status()?;
    assert_eq!(observation.reserved_bytes, Some(4096));
    assert_eq!(observation.policy, Some(policy()));
    {
        let _admission = store
            .inner
            .space
            .lock()
            .map_err(|_| anyhow!("space poisoned"))?;
        assert_eq!(store.space_status()?.reserved_bytes, None);
    }
    drop(budget);
    assert_eq!(store.space_status()?.reserved_bytes, Some(0));
    assert_eq!(store.stats()?, before);
    Ok(())
}

#[test]
fn maintenance_replenishes_headroom_before_admission_pressure() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    for name in ["aaa", "bbb", "ccc"] {
        publish(&store, name)?;
    }
    let mut limit = policy();
    limit.max_resident_bytes = Some(9);
    limit.target_resident_bytes = Some(3);
    let report = store.reclaim(limit, || Ok(0), 1, || Ok(100_000))?;
    assert!(report.minimum_satisfied);
    assert_eq!(report.evicted_roots, 2);
    assert_eq!(store.stats()?.actions, 1);
    Ok(())
}

#[test]
fn reservations_that_cannot_fit_do_not_evict_resident_content() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut limit = policy();
    limit.max_resident_bytes = Some(20);
    limit.target_resident_bytes = Some(10);
    let store = NativeStore::open_managed(dir.path(), limit)?;
    let hot = publish(&store, "hot")?;
    let _reservation = store.reserve_staging(16)?;
    let refused = store.reserve_staging(5);
    assert!(matches!(refused, Err(error) if error.is::<StageSpaceExhausted>()));
    assert!(store.lookup(hot)?.is_some());
    let refused = store.reserve_staging(21);
    assert!(matches!(refused, Err(error) if error.is::<StageSpaceTooLarge>()));
    assert!(store.lookup(hot)?.is_some());
    Ok(())
}

#[test]
fn full_admission_does_not_evict_until_maintenance_replenishes_headroom() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut limit = policy();
    limit.max_resident_bytes = Some(12);
    limit.target_resident_bytes = Some(8);
    let store = NativeStore::open_managed(dir.path(), limit)?;
    for name in ["aaaa", "bbbb", "cccc"] {
        publish(&store, name)?;
    }
    assert!(matches!(store.reserve_staging(4), Err(error) if error.is::<StageSpaceExhausted>()));
    assert_eq!(store.stats()?.actions, 3);
    let report = store.maintain_space()?.context("missing policy")?;
    assert_eq!(report.evicted_roots, 1);
    let _admitted = store.reserve_staging(4)?;
    assert_eq!(store.stats()?.actions, 2);
    Ok(())
}

#[test]
fn maintenance_exclusion_does_not_block_headroom_admission() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open_managed(dir.path(), policy())?;
    let _maintenance = store
        .inner
        .space_maintenance
        .lock()
        .map_err(|_| anyhow!("maintenance poisoned"))?;
    let _reservation = store.reserve_staging(4096)?;
    assert!(store.maintain_space()?.is_none());
    Ok(())
}

#[test]
fn quota_only_policy_retains_logical_content_until_physical_pressure() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    for name in ["aaaa", "bbbb", "cccc"] {
        publish(&store, name)?;
    }
    let mut limit = policy();
    limit.max_resident_bytes = None;
    limit.target_resident_bytes = None;
    limit.min_available_bytes = 1;
    limit.target_available_bytes = 4;
    limit.validate()?;
    let report = store.reclaim(limit, || Ok(0), 0, || Ok(100_000))?;
    assert_eq!(report.evicted_roots, 0);
    assert_eq!(store.stats()?.actions, 3);
    assert!(report.minimum_satisfied);
    Ok(())
}
