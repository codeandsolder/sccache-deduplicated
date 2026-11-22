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
    Ok(store.publish(&fingerprint, &manifest, vec![stage])?.action)
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
