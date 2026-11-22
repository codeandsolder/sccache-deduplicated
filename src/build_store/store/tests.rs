use std::{collections::BTreeMap, io::Read, sync::Barrier, thread};

use anyhow::{Context, Result};

use super::*;
use crate::build_store::Artifact;

fn action(name: &str) -> ActionFingerprint {
    ActionFingerprint {
        schema: "test".into(),
        components: BTreeMap::from([("source".into(), ContentId::of(name.as_bytes()))]),
    }
}

fn result(blob: BlobRef) -> ResultManifest {
    ResultManifest {
        outputs: BTreeMap::from([(
            "obj".into(),
            Artifact {
                blob,
                mode: Some(0o644),
            },
        )]),
        stdout: None,
        stderr: None,
    }
}

#[test]
fn aliases_and_shared_artifacts_reclaim_only_last_reference() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let stage = store.stage(&b"object"[..])?;
    let object = stage.reference();
    let first = result(object);
    let a = store.publish(&action("a"), &first, vec![stage])?;
    let b = store.publish(&action("b"), &first, vec![])?;
    assert_eq!(a.result, b.result);
    assert_ne!(a.action, b.action);
    assert_eq!(store.equivalent_actions(a.result)?.len(), 2);
    assert_eq!(
        store.stats()?,
        CacheStats {
            actions: 2,
            results: 1,
            blobs: 1,
            logical_bytes: 6
        }
    );

    let diagnostics = store.stage(&b"warning"[..])?;
    let mut second = first.clone();
    second.stderr = Some(diagnostics.reference());
    let c = store.publish(&action("c"), &second, vec![diagnostics])?;
    assert_ne!(c.result, a.result);
    assert_eq!(
        store.stats()?,
        CacheStats {
            actions: 3,
            results: 2,
            blobs: 2,
            logical_bytes: 13
        }
    );

    let lease = store.lookup(b.action)?.context("missing pinned result")?;
    let another_lease = store.lookup(b.action)?.context("missing second pin")?;
    drop(lease);
    assert_eq!(store.evict(b.action)?, Eviction::Pinned);
    assert_eq!(
        store.evict(a.action)?,
        Eviction::Removed {
            reclaimed_logical_bytes: 0
        }
    );
    assert_eq!(
        store.evict(c.action)?,
        Eviction::Removed {
            reclaimed_logical_bytes: 7
        }
    );
    let mut bytes = Vec::new();
    another_lease
        .open_blob(object.id)?
        .read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"object");
    assert!(another_lease.open_blob(ContentId::of(b"warning")).is_err());
    drop(another_lease);
    assert_eq!(
        store.evict(b.action)?,
        Eviction::Removed {
            reclaimed_logical_bytes: 6
        }
    );
    assert_eq!(store.evict(b.action)?, Eviction::Missing);
    assert_eq!(
        store.stats()?,
        CacheStats {
            actions: 0,
            results: 0,
            blobs: 0,
            logical_bytes: 0
        }
    );
    assert!(!store.inner.blob_path(object.id).exists());
    Ok(())
}

#[test]
fn publication_is_idempotent_and_conflicts_are_rejected() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let stage = store.stage(&b"first"[..])?;
    let manifest = result(stage.reference());
    let fingerprint = action("same");
    let first = store.publish(&fingerprint, &manifest, vec![stage])?;
    let duplicate = store.publish(&fingerprint, &manifest, vec![])?;
    assert!(first.new_action);
    assert!(!duplicate.new_action);
    assert_eq!(first.result, duplicate.result);
    let other = store.stage(&b"other"[..])?;
    assert!(
        store
            .publish(&fingerprint, &result(other.reference()), vec![other])
            .is_err()
    );
    assert_eq!(store.stats()?.actions, 1);
    assert_eq!(
        store
            .lookup(first.action)?
            .context("missing result")?
            .manifest(),
        &manifest
    );
    Ok(())
}

#[test]
fn incomplete_publication_never_installs_or_exposes_partial_results() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let staged = store.stage(&b"available"[..])?;
    let reference = staged.reference();
    let mut manifest = result(reference);
    manifest.stdout = Some(BlobRef {
        id: ContentId::of(b"missing"),
        size: 7,
    });
    let fingerprint = action("incomplete");
    assert!(
        store
            .publish(&fingerprint, &manifest, vec![staged])
            .is_err()
    );
    assert!(!store.inner.blob_path(reference.id).exists());
    assert!(store.lookup(fingerprint.key()?)?.is_none());
    assert_eq!(store.stats()?.blobs, 0);
    Ok(())
}

#[test]
fn reopen_recovers_unindexed_content_and_keeps_committed_results() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let stage = store.stage(&b"committed"[..])?;
    let manifest = result(stage.reference());
    let published = store.publish(&action("persisted"), &manifest, vec![stage])?;
    let orphan = ContentId::of(b"unindexed");
    let orphan_path = store.inner.blob_path(orphan);
    fs::create_dir_all(orphan_path.parent().context("missing parent")?)?;
    fs::write(&orphan_path, b"unindexed")?;
    fs::write(dir.path().join("staging").join("interrupted"), b"partial")?;
    drop(store);

    let reopened = NativeStore::open(dir.path())?;
    assert!(!orphan_path.exists());
    assert_eq!(fs::read_dir(dir.path().join("staging"))?.count(), 0);
    let lease = reopened
        .lookup(published.action)?
        .context("missing persisted result")?;
    assert_eq!(lease.manifest(), &manifest);
    let mut bytes = Vec::new();
    lease
        .open_blob(manifest.outputs["obj"].blob.id)?
        .read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"committed");
    Ok(())
}

#[test]
fn missing_content_is_not_returned_as_a_hit() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let stage = store.stage(&b"object"[..])?;
    let object = stage.reference();
    let published = store.publish(&action("invalid"), &result(object), vec![stage])?;
    fs::remove_file(store.inner.blob_path(object.id))?;
    assert!(store.lookup(published.action).is_err());
    Ok(())
}

#[test]
fn foreign_staged_content_is_rejected_and_keeps_owner_alive() -> Result<()> {
    let first_dir = tempfile::tempdir()?;
    let second_dir = tempfile::tempdir()?;
    let first = NativeStore::open(first_dir.path())?;
    let second = NativeStore::open(second_dir.path())?;
    let staged = first.stage(&b"contents"[..])?;
    let manifest = result(staged.reference());
    drop(first);
    assert!(NativeStore::open(first_dir.path()).is_err());
    assert!(
        second
            .publish(&action("foreign"), &manifest, vec![staged])
            .is_err()
    );
    assert!(NativeStore::open(first_dir.path()).is_ok());
    Ok(())
}

#[test]
fn concurrent_publishers_share_content_and_result() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let barrier = Barrier::new(4);
    thread::scope(|scope| -> Result<()> {
        let handles: Vec<_> = (0..4)
            .map(|index| {
                let store = &store;
                let barrier = &barrier;
                scope.spawn(move || -> Result<Published> {
                    let staged = store.stage(&b"identical"[..])?;
                    let manifest = result(staged.reference());
                    barrier.wait();
                    store.publish(&action(&index.to_string()), &manifest, vec![staged])
                })
            })
            .collect();
        for handle in handles {
            handle.join().map_err(|_| anyhow!("publisher panicked"))??;
        }
        Ok(())
    })?;
    assert_eq!(
        store.stats()?,
        CacheStats {
            actions: 4,
            results: 1,
            blobs: 1,
            logical_bytes: 9
        }
    );
    Ok(())
}
