use std::{
    collections::BTreeMap,
    io::{self, Read},
    sync::Barrier,
    thread,
};

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
            Artifact::File {
                blob,
                mode: Some(0o644),
            },
        )]),
        stdout: None,
        stderr: None,
    }
}

#[test]
fn local_filesystem_policy_and_cross_format_ingest_preserve_logical_content() -> Result<()> {
    use std::{
        io::{Seek, SeekFrom},
        path::Path,
    };
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let expected_encoding = if is_native_zfs(dir.path())? {
        BlobEncoding::Raw
    } else {
        BlobEncoding::ZstdChunks
    };
    assert_eq!(store.physical_encoding(), expected_encoding);
    let original = b"native-artifact-over-zfs-arc".repeat(32_000);
    let staged = store.stage(original.as_slice())?;
    let reference = staged.reference();
    assert_eq!(reference.id, ContentId::of(&original));
    assert_eq!(staged.encoding, expected_encoding);
    let mut staged_bytes = Vec::new();
    staged.open_file()?.read_to_end(&mut staged_bytes)?;
    if expected_encoding == BlobEncoding::Raw {
        assert_eq!(staged_bytes, original);
    } else {
        assert_ne!(staged_bytes, original);
    }

    // Both physical wire representations must be converted to the locally
    // chosen format, with no change to the original content identity.
    let mut compressed = tempfile::tempfile()?;
    assert_eq!(
        blob_codec::encode(original.as_slice(), &mut compressed, None)?,
        reference
    );
    compressed.seek(SeekFrom::Start(0))?;
    for (encoding, reader) in [
        (
            BlobEncoding::Raw,
            Box::new(original.as_slice()) as Box<dyn Read>,
        ),
        (
            BlobEncoding::ZstdChunks,
            Box::new(compressed) as Box<dyn Read>,
        ),
    ] {
        let received = store.stage_expected_physical(reference, encoding, reader)?;
        assert_eq!(received.reference(), reference);
        assert_eq!(received.encoding, expected_encoding);
        let mut reader = BlobReader::open(received.open_file()?, received.encoding)?;
        let mut roundtrip = Vec::new();
        reader.read_to_end(&mut roundtrip)?;
        assert_eq!(roundtrip, original);
    }
    // A different filesystem must not inadvertently adopt ZFS's raw policy.
    if Path::new("/dev/shm").is_dir() && !is_native_zfs(Path::new("/dev/shm"))? {
        let tmp = tempfile::tempdir_in("/dev/shm")?;
        let other = NativeStore::open(tmp.path())?;
        assert_eq!(other.physical_encoding(), BlobEncoding::ZstdChunks);
        let encoded = other.stage(original.as_slice())?;
        assert_eq!(encoded.encoding, BlobEncoding::ZstdChunks);
        assert_eq!(encoded.reference(), reference);
        assert!(encoded.open_file()?.metadata()?.len() < original.len() as u64);
    }
    Ok(())
}

#[test]
fn heterogeneous_zfs_and_non_zfs_stores_exchange_all_physical_encodings() -> Result<()> {
    use crate::{TreeEntry, TreeManifest, TreeMetadata, TreePath, TreeTimestamp};
    use std::path::Path;

    // The default tempfile root may be tmpfs even when the checkout is on
    // ZFS. Build the ZFS half on a verified, writable ZFS path rather than
    // testing /home and then accidentally creating the store in /tmp.
    let zfs_parent = std::env::current_dir()?;
    if !is_native_zfs(&zfs_parent)?
        || !Path::new("/dev/shm").is_dir()
        || is_native_zfs(Path::new("/dev/shm"))?
    {
        return Ok(());
    }

    let zfs_dir = tempfile::tempdir_in(&zfs_parent)?;
    let memory_dir = tempfile::tempdir_in("/dev/shm")?;
    let zfs = NativeStore::open(zfs_dir.path())?;
    let non_zfs = NativeStore::open(memory_dir.path())?;
    assert_eq!(zfs.physical_encoding(), BlobEncoding::Raw);
    assert_eq!(non_zfs.physical_encoding(), BlobEncoding::ZstdChunks);
    let metadata = TreeMetadata {
        mode: 0o555,
        modified: TreeTimestamp {
            seconds: 1234,
            nanoseconds: 0,
        },
    };
    let mut incompressible = vec![0_u8; 525_011];
    blake3::Hasher::new()
        .finalize_xof()
        .fill(&mut incompressible);
    let corpus = [
        b"compiler-output-with-structure".repeat(28_000),
        incompressible,
        b"SC-CAS-ZSTD-0002".repeat(41),
        Vec::new(),
    ];

    // Every source-to-destination pairing, including identical backends,
    // must produce the exact same logical content with the receiver's local
    // physical representation. This exercises both source file descriptors
    // and destination CAS index lookup after publication.
    for (direction, (source, destination)) in [
        (&zfs, &zfs),
        (&zfs, &non_zfs),
        (&non_zfs, &zfs),
        (&non_zfs, &non_zfs),
    ]
    .into_iter()
    .enumerate()
    {
        for (sample, original) in corpus.iter().enumerate() {
            let source_staged = source.stage(original.as_slice())?;
            let expected = source_staged.reference();
            assert_eq!(expected.id, ContentId::of(original));
            let staged = destination.stage_expected_physical(
                expected,
                source_staged.encoding,
                source_staged.open_file()?,
            )?;
            assert_eq!(staged.reference(), expected);
            assert_eq!(staged.encoding, destination.physical_encoding());
            let path = TreePath::new(format!("artifact-{direction}-{sample}").into_bytes())?;
            let manifest = TreeManifest {
                root: metadata,
                entries: BTreeMap::from([(
                    path,
                    TreeEntry::File {
                        blob: expected,
                        metadata,
                    },
                )]),
            };
            let id = destination.publish_tree(&manifest, vec![staged])?;
            let lease = destination
                .lookup_tree(id)?
                .context("transferred CAS tree missing")?;
            assert_eq!(
                lease.physical_encoding(expected.id)?,
                destination.physical_encoding()
            );
            let mut recovered = Vec::new();
            lease.open_blob(expected.id)?.read_to_end(&mut recovered)?;
            assert_eq!(&recovered, original);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn mountinfo_path_preserves_all_linux_escape_sequences() -> Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let original = b"/tmp/space here\ttab\nline\\slash\xff";
    let parsed = mountinfo_path(b"/tmp/space\\040here\\011tab\\012line\\134slash\xff")?;
    assert_eq!(parsed.as_os_str().as_bytes(), original);
    assert!(mountinfo_path(b"/tmp/\\777").is_err());
    assert!(mountinfo_path(b"/tmp/\\09").is_err());
    assert!(mountinfo_path(b"/tmp/\\").is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn reopening_store_detaches_owned_readonly_fuse_mounts() -> Result<()> {
    use fuser::{Config, Filesystem, MountOption, Session};

    struct EmptyFilesystem;
    impl Filesystem for EmptyFilesystem {}

    let tmp = tempfile::tempdir()?;
    let store = NativeStore::open(tmp.path())?;
    drop(store);
    let parent = tmp.path().join("mounts").join("build-fuse-abandoned-test");
    let mountpoint = parent.join("root");
    fs::create_dir_all(&mountpoint)?;
    let mut config = Config::default();
    config.mount_options = vec![MountOption::RO, MountOption::DefaultPermissions];
    let session = Session::new(EmptyFilesystem, &mountpoint, &config)?;
    let service = thread::spawn(move || session.run());
    // The FUSE mount is intentionally still live while reopening the store.
    // It simulates the same persisted mountpoint as a killed worker; the Redb
    // store lock is free, so the recovery path must reclaim the mount first.
    let reopened = NativeStore::open(tmp.path())?;
    assert!(!parent.exists(), "stale FUSE view was not removed");
    drop(reopened);
    let _ = service.join();
    Ok(())
}

#[test]
fn orphaned_native_views_are_reclaimed_without_following_links() -> Result<()> {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    let temp = tempfile::tempdir()?;
    let store = NativeStore::open(temp.path())?;
    drop(store);
    let mount_root = temp.path().join("mounts");
    let orphan = mount_root.join("old-cached-zfs-tree");
    let restricted = orphan.join("readonly");
    fs::create_dir_all(restricted.join("nested"))?;
    fs::write(restricted.join("nested/stale"), b"old build data")?;
    let outside = temp.path().join("outside");
    fs::write(&outside, b"keep")?;
    symlink(&outside, orphan.join("redirect"))?;
    fs::set_permissions(&restricted, fs::Permissions::from_mode(0o000))?;
    let reopened = NativeStore::open(temp.path())?;
    assert!(!orphan.exists(), "stale tree should be reclaimed");
    assert_eq!(fs::read(&outside)?, b"keep");
    drop(reopened);
    Ok(())
}

#[test]
fn literal_magic_prefix_in_raw_cas_blob_survives_restart() -> Result<()> {
    use crate::{TreeEntry, TreeManifest, TreeMetadata, TreePath, TreeTimestamp};
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path())?;
    let content = b"SC-CAS-ZSTD-0002arbitrary-original-bytes";
    let staged = store.stage_inner(
        content.as_slice(),
        Some(content.len() as u64),
        space::StageBudget::new(&store),
    )?;
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
fn blob_identity_is_exact_content_and_independent_of_read_chunking() -> Result<()> {
    struct Chunked<'a> {
        data: &'a [u8],
        maximum: usize,
    }

    impl Read for Chunked<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let count = output.len().min(self.maximum).min(self.data.len());
            output[..count].copy_from_slice(&self.data[..count]);
            self.data = &self.data[count..];
            Ok(count)
        }
    }

    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let data: Vec<u8> = (0_u8..=250).cycle().take(131_071).collect();
    let expected = BlobRef {
        id: ContentId(*blake3::hash(&data).as_bytes()),
        size: data.len().try_into()?,
    };

    for maximum in [1, 31, 4096, 65_536, data.len()] {
        let staged = store.stage(Chunked {
            data: &data,
            maximum,
        })?;
        assert_eq!(staged.reference(), expected);
    }

    let empty = store.stage(io::empty())?;
    assert_eq!(empty.reference().id, ContentId::of(b""));
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

#[tokio::test]
async fn mixed_result_and_tree_publications_share_one_durable_transaction() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let first = store.stage(&b"shared result"[..])?;
    let duplicate = store.stage(&b"shared result"[..])?;
    let tree_blob = store.stage(&b"shared result"[..])?;
    let other = store.stage(&b"conflicting result"[..])?;
    let blob = first.reference();
    let manifest = result(blob);
    let tree = NativeStore::blob_retention_manifest(blob)?;
    let bad = result(BlobRef {
        id: ContentId::of(b"missing"),
        size: 7,
    });
    let (a, tree_lease, invalid, alias, conflict) = tokio::join!(
        store.publish_pinned_async(
            action("a"),
            manifest.clone(),
            vec![first],
            ActionMode::Reuse,
            ()
        ),
        store.publish_tree_pinned_async(tree.clone(), vec![tree_blob], ()),
        store.publish_pinned_async(action("invalid"), bad, Vec::new(), ActionMode::Reuse, ()),
        store.publish_pinned_async(
            action("alias"),
            manifest.clone(),
            vec![duplicate],
            ActionMode::Reuse,
            ()
        ),
        store.publish_pinned_async(
            action("a"),
            result(other.reference()),
            vec![other],
            ActionMode::Reuse,
            ()
        ),
    );
    let (a, tree_lease, alias) = (a?, tree_lease?, alias?);
    assert!(invalid.is_err());
    assert!(conflict.is_err());
    assert_eq!(a.manifest(), &manifest);
    assert_eq!(alias.manifest(), &manifest);
    assert_eq!(tree_lease.manifest(), &tree);
    assert_eq!(
        store
            .inner
            .publication_queue
            .committed_batches
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(store.stats()?.blobs, 1);
    assert_eq!(store.stats()?.actions, 2);
    assert_eq!(store.stats()?.results, 1);
    assert_eq!(store.evict(action("a").key()?)?, Eviction::Pinned);
    Ok(())
}

#[tokio::test]
async fn result_batch_resurrects_alias_retired_by_earlier_refresh() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let original = store.stage(&b"original result"[..])?;
    let old_blob = original.reference();
    let old = result(old_blob);
    let original_lease =
        store.publish_pinned(&action("old"), &old, vec![original], ActionMode::Reuse)?;
    let replacement = store.stage(&b"replacement result"[..])?;
    let replacement_manifest = result(replacement.reference());
    let (refreshed, new_alias) = tokio::join!(
        store.publish_pinned_async(
            action("old"),
            replacement_manifest.clone(),
            vec![replacement],
            ActionMode::Refresh,
            ()
        ),
        store.publish_pinned_async(
            action("new"),
            old.clone(),
            Vec::new(),
            ActionMode::Reuse,
            ()
        ),
    );
    let (refreshed, new_alias) = (refreshed?, new_alias?);
    assert_eq!(refreshed.manifest(), &replacement_manifest);
    assert_eq!(new_alias.manifest(), &old);
    assert_eq!(original_lease.manifest(), &old);
    assert_eq!(store.stats()?.pending_gc_blobs, 0);
    assert_eq!(
        store
            .inner
            .publication_queue
            .committed_batches
            .load(Ordering::Relaxed),
        1
    );
    let mut bytes = Vec::new();
    original_lease
        .open_blob(old_blob.id)?
        .read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"original result");
    Ok(())
}

#[tokio::test]
async fn repaired_result_prevents_conditional_replacement_in_same_batch() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let original = store.stage(&b"original result"[..])?;
    let old_blob = original.reference();
    let old = result(old_blob);
    store.publish_pinned(&action("old"), &old, vec![original], ActionMode::Reuse)?;
    std::fs::remove_file(store.inner.blob_path(old_blob.id))?;
    let repair = store.stage(&b"original result"[..])?;
    let replacement = store.stage(&b"replacement result"[..])?;
    let replacement_manifest = result(replacement.reference());
    let (repaired, replaced) = tokio::join!(
        store.publish_pinned_async(
            action("alias"),
            old.clone(),
            vec![repair],
            ActionMode::Reuse,
            ()
        ),
        store.publish_pinned_async(
            action("old"),
            replacement_manifest,
            vec![replacement],
            ActionMode::Reuse,
            ()
        ),
    );
    assert_eq!(repaired?.manifest(), &old);
    assert!(replaced.is_err());
    assert_eq!(
        store
            .lookup(action("old").key()?)?
            .context("missing repaired result")?
            .manifest(),
        &old
    );
    assert_eq!(store.stats()?.results, 1);
    Ok(())
}

#[tokio::test]
async fn cancelled_result_publication_still_commits_and_releases_admission() -> Result<()> {
    use std::{
        future::{Future, poll_fn},
        task::Poll,
        time::Duration,
    };
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let staged = store.stage(&b"cancelled waiter result"[..])?;
    let blob = staged.reference();
    let fingerprint = action("cancelled");
    let key = fingerprint.key()?;
    let published = store.inner.publications.register([blob.id])?;
    let mut future = Box::pin(store.publish_pinned_async(
        fingerprint,
        result(blob),
        vec![staged],
        ActionMode::Reuse,
        (),
    ));
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(future);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), published.next()).await?,
        BTreeSet::from([blob.id])
    );
    assert_eq!(
        store
            .lookup(key)?
            .context("cancelled publication lost result")?
            .manifest(),
        &result(blob)
    );
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
        .open_blob(manifest.outputs["obj"].test_file_blob().id)?
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
    assert!(store.lookup(published.action)?.is_none());
    {
        let pins = store.inner.lock_pins()?;
        assert!(!pins.actions.contains_key(&published.action));
        assert!(!pins.blobs.contains_key(&object.id));
    }
    assert_eq!(
        store.result_receipt(published.action)?,
        Some(result(object))
    );
    let staged = store.stage_expected(object, &b"object"[..])?;
    let repaired = store.publish_pinned(
        &action("invalid"),
        &result(object),
        vec![staged],
        ActionMode::Reuse,
    )?;
    assert_eq!(repaired.manifest(), &result(object));
    assert_eq!(store.stats()?.logical_bytes, 6);
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
fn physically_missing_pending_blob_can_be_repaired_before_gc() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let staged = store.stage(&b"pending repair"[..])?;
    let blob = staged.reference();
    let published = store.publish(
        &action("old"),
        &result(blob),
        vec![staged],
        ActionMode::Reuse,
    )?;
    store.evict(published.action)?;
    fs::remove_file(store.inner.blob_path(blob.id))?;
    let staged = store.stage_expected(blob, &b"pending repair"[..])?;
    let new = store.publish_pinned(
        &action("new"),
        &result(blob),
        vec![staged],
        ActionMode::Reuse,
    )?;
    assert_eq!(new.manifest(), &result(blob));
    assert_eq!(store.stats()?.pending_gc_blobs, 0);
    assert_eq!(store.stats()?.logical_bytes, blob.size);
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
fn batched_availability_preserves_order_and_pending_content() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let live = store.stage(&b"live"[..])?;
    let pending = store.stage(&b"pending"[..])?;
    let live_ref = live.reference();
    let pending_ref = pending.reference();
    store.publish(
        &action("live"),
        &result(live_ref),
        vec![live],
        ActionMode::Reuse,
    )?;
    let retired = store.publish(
        &action("pending"),
        &result(pending_ref),
        vec![pending],
        ActionMode::Reuse,
    )?;
    store.evict(retired.action)?;
    let missing = BlobRef {
        id: ContentId::of(b"missing"),
        size: 7,
    };
    assert_eq!(
        store.available_blobs(&[missing, pending_ref, live_ref, pending_ref])?,
        vec![false, true, true, true]
    );
    assert!(
        store
            .available_blobs(&[BlobRef {
                id: live_ref.id,
                size: live_ref.size + 1
            }])
            .is_err()
    );
    store.collect_garbage(8)?;
    assert_eq!(
        store.available_blobs(&[pending_ref, live_ref])?,
        vec![false, true]
    );
    Ok(())
}

#[test]
fn live_reservations_do_not_wait_for_publication_but_pending_content_is_protected() -> Result<()> {
    use std::{sync::mpsc, time::Duration};
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let stage = store.stage(&b"live and pending"[..])?;
    let blob = stage.reference();
    let published = store.publish(
        &action("live-reserve"),
        &result(blob),
        vec![stage],
        ActionMode::Reuse,
    )?;
    let references = BTreeMap::from([(blob.id, blob.size)]);
    let mutation = store.inner.lock_mutations()?;
    let reservation = thread::scope(|scope| -> Result<_> {
        let (send, receive) = mpsc::channel();
        let store = &store;
        let references = references.clone();
        let worker = scope.spawn(move || send.send(store.reserve_blobs(&references)));
        let observed = receive.recv_timeout(Duration::from_secs(2));
        drop(mutation);
        worker
            .join()
            .map_err(|_| anyhow!("reservation worker panicked"))??;
        observed?
    })?;
    assert!(reservation.missing().is_empty());
    assert!(matches!(
        store.evict(published.action)?,
        Eviction::Removed { .. }
    ));
    let mutation = store.inner.lock_mutations()?;
    let pending = thread::scope(|scope| -> Result<_> {
        let (send, receive) = mpsc::channel();
        let store = &store;
        let worker = scope.spawn(move || send.send(store.reserve_blobs(&references)));
        assert!(matches!(
            receive.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(mutation);
        let pending = receive.recv_timeout(Duration::from_secs(2))??;
        worker
            .join()
            .map_err(|_| anyhow!("reservation worker panicked"))??;
        Ok(pending)
    })?;
    drop(reservation);
    assert!(pending.missing().is_empty());
    assert_eq!(store.collect_garbage(8)?.blobs, 0);
    drop(pending);
    assert_eq!(store.collect_garbage(8)?.blobs, 1);
    Ok(())
}

#[test]
fn publication_tracks_unsynced_shards_across_aborted_transactions() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let first = store.stage(&b"aborted staging"[..])?;
    let blob = first.reference();
    let mut directories = BTreeSet::new();
    {
        let _mutation = store.inner.lock_mutations()?;
        let _reservation = store.inner.install_blob(first, &mut directories)?;
        assert!(store.inner.dirty_blob_directory.load(Ordering::Relaxed));
    }
    assert!(store.inner.dirty_blob_directory.load(Ordering::Relaxed));
    assert!(store.open_available_physical(blob)?.is_none());
    let replacement = store.stage_expected(blob, &b"aborted staging"[..])?;
    store.publish(
        &action("recovered"),
        &result(blob),
        vec![replacement],
        ActionMode::Reuse,
    )?;
    assert!(!store.inner.dirty_blob_directory.load(Ordering::Relaxed));
    assert!(store.open_available_physical(blob)?.is_some());
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
        crate::BlobReader::open(blob.open_file()?, blob.encoding)?.read_to_end(&mut bytes)?;
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

#[test]
fn evicted_result_receipts_survive_restart_and_remain_bounded() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let a = action("a");
    let b = action("b");
    let manifest;
    {
        let store = NativeStore::open(dir.path())?;
        store.enable_result_history(1024)?;
        let blob = store.stage(&b"object"[..])?;
        manifest = result(blob.reference());
        store.publish(&a, &manifest, vec![blob], ActionMode::Reuse)?;
        store.publish(&b, &manifest, vec![], ActionMode::Reuse)?;
        store.evict(a.key()?)?;
        store.evict(b.key()?)?;
        store.collect_garbage(32)?;
        assert_eq!(store.stats()?.blobs, 0);
    }
    let store = NativeStore::open(dir.path())?;
    // Offline eviction also honors the previously configured limit.
    assert_eq!(store.result_receipt(a.key()?)?, Some(manifest.clone()));
    assert_eq!(store.result_receipt(b.key()?)?, Some(manifest.clone()));
    let blob = store.stage(&b"new object"[..])?;
    let replacement = result(blob.reference());
    store.publish(&b, &replacement, vec![blob], ActionMode::Refresh)?;
    assert_eq!(store.result_receipt(b.key()?)?, Some(replacement.clone()));
    store.evict(b.key()?)?;
    assert_eq!(store.result_receipt(b.key()?)?, Some(replacement));
    store.enable_result_history(0)?;
    assert!(store.result_receipt(a.key()?)?.is_none());
    assert!(store.result_receipt(b.key()?)?.is_none());
    Ok(())
}

#[test]
fn result_receipt_budget_evicts_oldest_metadata_only() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    store.enable_result_history(200)?;
    let staged = store.stage(&b"object"[..])?;
    let manifest = result(staged.reference());
    let first = store.publish(&action("first"), &manifest, vec![staged], ActionMode::Reuse)?;
    let second = store.publish(&action("second"), &manifest, vec![], ActionMode::Reuse)?;
    store.evict(first.action)?;
    assert_eq!(store.result_receipt(first.action)?, Some(manifest.clone()));
    store.evict(second.action)?;
    assert!(store.result_receipt(first.action)?.is_none());
    assert_eq!(store.result_receipt(second.action)?, Some(manifest));
    store.collect_garbage(32)?;
    assert_eq!(store.stats()?.blobs, 0);
    Ok(())
}
