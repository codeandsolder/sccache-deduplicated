use std::{collections::BTreeMap, io::Cursor};

use super::*;
use crate::{
    ActionFingerprint, Artifact, BlobRef, ContentId, ResultManifest, TreeManifest, TreeMetadata,
    TreeTimestamp,
};

fn policy() -> SpacePolicy {
    SpacePolicy {
        min_available_bytes: 100,
        target_available_bytes: 200,
        max_resident_bytes: u64::MAX,
        target_resident_bytes: u64::MAX,
        max_evictions_per_pass: 4,
        gc_batch: 16,
    }
}

fn publish(store: &NativeStore, name: &str) -> Result<ActionKey> {
    let stage = store.stage(Cursor::new(name.as_bytes()))?;
    let blob: BlobRef = stage.reference();
    let manifest = ResultManifest {
        outputs: BTreeMap::from([("obj".into(), Artifact { blob, mode: None })]),
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
    let report = store.reclaim(policy(), 10, 20, || {
        Ok(if store.stats()?.actions == 2 {
            100
        } else {
            250
        })
    })?;
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
    let report = store.reclaim(p, 50, 50, || Ok(10))?;
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
    let report = store.reclaim(limit, 0, 0, || {
        Ok(if store.stats()?.actions == 2 { 0 } else { 300 })
    })?;
    assert_eq!(report.evicted_roots, 1);
    assert!(store.lookup(hot)?.is_some());
    assert!(store.lookup(cold)?.is_none());
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
    let report = store.reclaim(limit, 0, 0, || {
        Ok(if store.stats()?.actions == 2 { 0 } else { 300 })
    })?;
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
    limit.max_resident_bytes = 8;
    limit.target_resident_bytes = 6;
    let report = store.reclaim(limit, 0, 0, || Ok(100_000))?;
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
    limit.max_resident_bytes = 1;
    limit.target_resident_bytes = 1;
    let report = store.reclaim(limit, 0, 0, || Ok(100_000))?;
    assert_eq!(report.evicted_roots, 0);
    assert!(!report.minimum_satisfied);
    drop(pin);
    let report = store.reclaim(limit, 0, 0, || Ok(100_000))?;
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
    limit.max_resident_bytes = 10;
    limit.target_resident_bytes = 8;
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
    limit.max_resident_bytes = 3;
    limit.target_resident_bytes = 3;
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
    // Publication can hold a separate mutation lock. A staged-file drop
    // cannot need the space mutex or we would admit an ABBA deadlock.
    drop(staged);
    assert_eq!(
        store.inner.space_released.load(Ordering::Acquire),
        u64::try_from(b"reservation".len())?
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
