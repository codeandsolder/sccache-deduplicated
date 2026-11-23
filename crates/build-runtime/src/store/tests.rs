use std::{collections::BTreeMap, io::Read, sync::Barrier, thread};

use anyhow::{Context, Result};

use super::*;
use crate::Artifact;

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
fn literal_magic_prefix_in_raw_cas_blob_survives_restart() -> Result<()> {
    use crate::{TreeEntry, TreeManifest, TreeMetadata, TreePath, TreeTimestamp};
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path())?;
    let content = b"SC-CAS-ZSTD-0002arbitrary-original-bytes";
    let staged = store.stage_inner(content.as_slice(), Some(content.len() as u64))?;
    let reference = staged.reference();
    let metadata = TreeMetadata {
        mode: 0o755,
        modified: TreeTimestamp {
            seconds: 10,
            nanoseconds: 0,
        },
    };
    let tree = TreeManifest {
        root: metadata,
        entries: BTreeMap::from([(
            TreePath::new(b"source".to_vec())?,
            TreeEntry::File {
                blob: reference,
                metadata,
            },
        )]),
    };
    let id = store.publish_tree(&tree, vec![staged])?;
    let lease = store
        .lookup_tree(id)?
        .context("missing raw archive-like content")?;
    let mut decoded = Vec::new();
    lease.open_blob(reference.id)?.read_to_end(&mut decoded)?;
    assert_eq!(decoded, content);
    let mut physical = Vec::new();
    lease.open_file(reference.id)?.read_to_end(&mut physical)?;
    assert_eq!(physical, content);
    drop(lease);
    drop(store);

    let reopened = NativeStore::open(directory.path())?;
    let lease = reopened
        .lookup_tree(id)?
        .context("raw physical kind lost across restart")?;
    decoded.clear();
    lease.open_blob(reference.id)?.read_to_end(&mut decoded)?;
    assert_eq!(decoded, content);
    Ok(())
}

#[test]
fn aliases_and_shared_artifacts_reclaim_only_last_reference() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let stage = store.stage(&b"object"[..])?;
    let object = stage.reference();
    let first = result(object);
    let a = store.publish(&action("a"), &first, vec![stage], crate::ActionMode::Reuse)?;
    let b = store.publish(&action("b"), &first, vec![], crate::ActionMode::Reuse)?;
    assert_eq!(a.result, b.result);
    assert_ne!(a.action, b.action);
    assert_eq!(store.equivalent_actions(a.result)?.len(), 2);
    assert_eq!(
        store.stats()?,
        CacheStats {
            actions: 2,
            results: 1,
            trees: 0,
            blobs: 1,
            logical_bytes: 6,
            pending_gc_blobs: 0,
            pending_gc_bytes: 0
        }
    );

    let diagnostics = store.stage(&b"warning"[..])?;
    let mut second = first;
    second.stderr = Some(diagnostics.reference());
    let c = store.publish(
        &action("c"),
        &second,
        vec![diagnostics],
        crate::ActionMode::Reuse,
    )?;
    assert_ne!(c.result, a.result);
    assert_eq!(
        store.stats()?,
        CacheStats {
            actions: 3,
            results: 2,
            trees: 0,
            blobs: 2,
            logical_bytes: 13,
            pending_gc_blobs: 0,
            pending_gc_bytes: 0
        }
    );

    let lease = store.lookup(b.action)?.context("missing pinned result")?;
    let another_lease = store.lookup(b.action)?.context("missing second pin")?;
    drop(lease);
    assert_eq!(store.evict(b.action)?, Eviction::Pinned);
    assert_eq!(
        store.evict(a.action)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 0
        }
    );
    assert_eq!(
        store.evict(c.action)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 7
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
            unreferenced_logical_bytes: 6
        }
    );
    assert_eq!(store.evict(b.action)?, Eviction::Missing);
    assert_eq!(
        store.stats()?,
        CacheStats {
            actions: 0,
            results: 0,
            trees: 0,
            blobs: 0,
            logical_bytes: 0,
            pending_gc_blobs: 2,
            pending_gc_bytes: 13
        }
    );
    assert!(store.inner.blob_path(object.id).exists());
    let gc = store.collect_garbage(1)?;
    assert_eq!(gc.blobs, 1);
    assert_eq!(gc.failed, []);
    let gc = store.collect_garbage(1)?;
    assert_eq!(gc.blobs, 1);
    assert_eq!(gc.failed, []);
    assert_eq!(store.stats()?.pending_gc_bytes, 0);
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
    let first = store.publish(
        &fingerprint,
        &manifest,
        vec![stage],
        crate::ActionMode::Reuse,
    )?;
    let duplicate = store.publish(&fingerprint, &manifest, vec![], crate::ActionMode::Reuse)?;
    assert!(first.new_action);
    assert!(!duplicate.new_action);
    assert_eq!(first.result, duplicate.result);
    let other = store.stage(&b"other"[..])?;
    assert!(
        store
            .publish(
                &fingerprint,
                &result(other.reference()),
                vec![other],
                crate::ActionMode::Reuse
            )
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
            .publish(
                &fingerprint,
                &manifest,
                vec![staged],
                crate::ActionMode::Reuse
            )
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
    let published = store.publish(
        &action("persisted"),
        &manifest,
        vec![stage],
        crate::ActionMode::Reuse,
    )?;
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
    let published = store.publish(
        &action("invalid"),
        &result(object),
        vec![stage],
        crate::ActionMode::Reuse,
    )?;
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
            .publish(
                &action("foreign"),
                &manifest,
                vec![staged],
                crate::ActionMode::Reuse
            )
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
                    store.publish(
                        &action(&index.to_string()),
                        &manifest,
                        vec![staged],
                        crate::ActionMode::Reuse,
                    )
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
            trees: 0,
            blobs: 1,
            logical_bytes: 9,
            pending_gc_blobs: 0,
            pending_gc_bytes: 0
        }
    );
    Ok(())
}

#[test]
fn negotiated_content_survives_eviction_and_is_reused_without_upload() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let stage = store.stage(&b"shared"[..])?;
    let manifest = result(stage.reference());
    let before = store.reserve_upload(&manifest)?;
    assert_eq!(before.missing(), &[stage.reference()]);
    drop(before);
    let first = store.publish(
        &action("first"),
        &manifest,
        vec![stage],
        crate::ActionMode::Reuse,
    )?;

    let reserved = store.reserve_upload(&manifest)?;
    assert_eq!(reserved.missing(), []);
    assert_eq!(
        store.evict(first.action)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 6
        }
    );
    assert_eq!(store.stats()?.pending_gc_bytes, 6);
    assert_eq!(store.collect_garbage(32)?.blobs, 0);
    let second = store.publish(
        &action("second"),
        &manifest,
        vec![],
        crate::ActionMode::Reuse,
    )?;
    assert_eq!(first.result, second.result);
    assert_eq!(store.stats()?.pending_gc_bytes, 0);
    assert_eq!(store.stats()?.logical_bytes, 6);
    drop(reserved);
    assert_eq!(
        store.evict(second.action)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 6
        }
    );
    assert_eq!(store.collect_garbage(32)?.logical_bytes, 6);
    Ok(())
}

#[test]
fn expected_upload_validates_digest_and_bounds_input() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let expected = BlobRef {
        id: ContentId::of(b"abc"),
        size: 3,
    };
    assert!(store.stage_expected(expected, &b"ab"[..]).is_err());
    assert!(store.stage_expected(expected, &b"xyz"[..]).is_err());
    assert!(store.stage_expected(expected, io::repeat(b'a')).is_err());
    let staged = store.stage_expected(expected, &b"abc"[..])?;
    assert_eq!(staged.reference(), expected);
    Ok(())
}

#[test]
fn restart_reclaims_pending_garbage_including_empty_files() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let stage = store.stage(&b""[..])?;
    let content = stage.reference();
    let published = store.publish(
        &action("empty"),
        &result(content),
        vec![stage],
        crate::ActionMode::Reuse,
    )?;
    assert_eq!(
        store.evict(published.action)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 0
        }
    );
    assert_eq!(store.stats()?.pending_gc_blobs, 1);
    let path = store.inner.blob_path(content.id);
    assert!(path.exists());
    drop(store);
    let store = NativeStore::open(dir.path())?;
    assert_eq!(store.stats()?.pending_gc_blobs, 0);
    assert!(!path.exists());
    Ok(())
}

#[test]
fn garbage_collection_failures_remain_queued() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let stage = store.stage(&b"data"[..])?;
    let content = stage.reference();
    let published = store.publish(
        &action("remove"),
        &result(content),
        vec![stage],
        crate::ActionMode::Reuse,
    )?;
    store.evict(published.action)?;
    let path = store.inner.blob_path(content.id);
    fs::remove_file(&path)?;
    fs::create_dir(&path)?;
    let failed = store.collect_garbage(1)?;
    assert_eq!(failed.failed, vec![content.id]);
    assert_eq!(store.stats()?.pending_gc_bytes, 4);
    fs::remove_dir(&path)?;
    assert_eq!(store.collect_garbage(1)?.logical_bytes, 4);
    assert_eq!(store.stats()?.pending_gc_bytes, 0);
    Ok(())
}

#[test]
fn opening_a_nonempty_unowned_directory_is_rejected() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("unrelated");
    fs::write(&path, b"keep me")?;
    assert!(NativeStore::open(dir.path()).is_err());
    assert_eq!(fs::read(&path)?, b"keep me");
    Ok(())
}

#[test]
fn lookups_do_not_wait_on_publication_lock() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let stage = store.stage(&b"data"[..])?;
    let published = store.publish(
        &action("lookup"),
        &result(stage.reference()),
        vec![stage],
        crate::ActionMode::Reuse,
    )?;
    let mutation = store.inner.lock_mutations()?;
    thread::scope(|scope| -> Result<()> {
        let (send, receive) = std::sync::mpsc::channel();
        let store = &store;
        let handle = scope
            .spawn(move || send.send(store.lookup(published.action).map(|lease| lease.is_some())));
        let observed = receive.recv_timeout(std::time::Duration::from_secs(2));
        drop(mutation);
        handle.join().map_err(|_| anyhow!("reader panicked"))??;
        assert!(observed??);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn refresh_retains_shared_aliases_and_old_result_leases() -> Result<()> {
    use crate::ActionMode;
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let old = store.stage(&b"first"[..])?;
    let old_blob = old.reference();
    let first = result(old_blob);
    let a = store.publish(&action("a"), &first, vec![old], ActionMode::Reuse)?;
    let b = store.publish(&action("b"), &first, vec![], ActionMode::Reuse)?;
    let reader = store.lookup(a.action)?.context("old result missing")?;
    let new = store.stage(&b"second"[..])?;
    let second = result(new.reference());
    let refreshed = store.publish(&action("a"), &second, vec![new], ActionMode::Refresh)?;
    assert_eq!(refreshed.action, a.action);
    assert!(!refreshed.new_action);
    assert_eq!(store.equivalent_actions(a.result)?.len(), 1);
    assert_eq!(
        store.lookup(b.action)?.context("alias lost")?.manifest(),
        &first
    );
    assert_eq!(store.stats()?.results, 2);
    assert_eq!(store.stats()?.pending_gc_blobs, 0);
    store.publish(&action("b"), &second, vec![], ActionMode::Refresh)?;
    assert_eq!(store.equivalent_actions(a.result)?.len(), 0);
    assert_eq!(store.stats()?.results, 1);
    assert_eq!(store.stats()?.pending_gc_blobs, 1);
    assert_eq!(store.collect_garbage(8)?.blobs, 0);
    let mut bytes = Vec::new();
    reader.open_blob(old_blob.id)?.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"first");
    drop(reader);
    assert_eq!(store.collect_garbage(8)?.blobs, 1);
    assert_eq!(
        store
            .lookup(a.action)?
            .context("refreshed result missing")?
            .manifest(),
        &second
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn staging_many_blobs_does_not_hold_file_descriptors() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path())?;
    let staging = directory.path().canonicalize()?.join("staging");
    let mut staged = Vec::new();
    for index in 0_u32..256 {
        staged.push(store.stage(index.to_le_bytes().as_slice())?);
    }
    let open = fs::read_dir("/proc/self/fd")?
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        .filter(|path| path.starts_with(&staging))
        .count();
    assert_eq!(
        open, 0,
        "staging leaked descriptors for completed transfers"
    );
    assert_eq!(fs::read_dir(&staging)?.count(), staged.len());
    for (index, blob) in staged.iter().enumerate() {
        let mut bytes = Vec::new();
        crate::BlobReader::open(blob.open_file()?, crate::BlobEncoding::ZstdChunks)?
            .read_to_end(&mut bytes)?;
        assert_eq!(bytes, u32::try_from(index)?.to_le_bytes());
    }
    drop(staged);
    assert_eq!(fs::read_dir(&staging)?.count(), 0);
    Ok(())
}

#[test]
fn replaced_or_modified_staging_file_cannot_be_published() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path())?;
    let first = store.stage(b"abc".as_slice())?;
    let path = first.path.to_path_buf();
    fs::remove_file(&path)?;
    fs::write(&path, b"xyz")?;
    assert!(first.open_file().is_err());
    assert!(
        store
            .inner
            .install_blob(first, &mut BTreeSet::new())
            .is_err()
    );

    let second = store.stage(b"abc".as_slice())?;
    fs::set_permissions(&second.path, fs::Permissions::from_mode(0o600))?;
    fs::write(&second.path, b"xyz")?;
    assert!(second.open_file().is_err());
    assert!(
        store
            .inner
            .install_blob(second, &mut BTreeSet::new())
            .is_err()
    );
    assert_eq!(store.stats()?.blobs, 0);
    Ok(())
}
