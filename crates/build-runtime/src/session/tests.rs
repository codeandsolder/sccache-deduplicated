use super::*;
use crate::{
    ActionFingerprint, Artifact, ContentId, Eviction, ExecutionRoot, TreeMetadata, TreeRecipe,
    TreeTimestamp,
};
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom},
};

fn service(dir: &std::path::Path) -> Result<NativeSessions> {
    let store = NativeStore::open(dir)?;
    store.publish_tree(&empty_root(), vec![])?;
    NativeSessions::new(
        store,
        SessionLimits {
            idle_timeout: Duration::from_secs(10),
            max_sessions: 8,
            max_result_bytes: 1024,
            max_result_blobs: 8,
            max_tree_bytes: 1024 * 1024,
            max_tree_blobs: 100,
            max_concurrent_uploads: 2,
            max_total_uploads: 4,
        },
    )
}

fn upload_encoded(
    service: &NativeSessions,
    ticket: Ticket,
    publisher: Publisher,
    declared: BlobRef,
    contents: &[u8],
) -> Result<()> {
    let mut encoded = tempfile::tempfile()?;
    crate::encode_native_blob(contents, &mut encoded, None)?;
    encoded.seek(SeekFrom::Start(0))?;
    service.upload(
        ticket,
        publisher,
        declared,
        crate::BlobEncoding::ZstdChunks,
        encoded,
    )
}

fn decoded_download(
    service: &NativeSessions,
    ticket: Ticket,
    publisher: Publisher,
    id: ContentId,
) -> Result<crate::BlobReader> {
    {
        let (file, encoding) = service.download(ticket, publisher, id)?;
        crate::BlobReader::open(file, encoding)
    }
}

fn empty_root() -> TreeManifest {
    TreeManifest {
        root: TreeMetadata {
            mode: 0o755,
            modified: TreeTimestamp {
                seconds: 1,
                nanoseconds: 0,
            },
        },
        entries: BTreeMap::new(),
    }
}

fn request() -> Result<ActionRequest> {
    let root = empty_root();
    let id = root.id()?;
    Ok(ActionRequest {
        fingerprint: ActionFingerprint {
            schema: "test-native-v1".into(),
            components: BTreeMap::from([("source".into(), ContentId::of(b"input"))]),
        },
        root: ExecutionRoot {
            id,
            recipe: TreeRecipe::union(root.root, [id]),
        },
        input_trees: BTreeSet::from([id]),
        required_outputs: BTreeSet::from(["obj".into()]),
        optional_outputs: BTreeSet::new(),
    })
}

fn manifest(bytes: &[u8]) -> ResultManifest {
    ResultManifest {
        outputs: BTreeMap::from([(
            "obj".into(),
            Artifact {
                blob: BlobRef {
                    id: ContentId::of(bytes),
                    size: bytes.len() as u64,
                },
                mode: Some(0o644),
            },
        )]),
        stdout: None,
        stderr: None,
    }
}

#[test]
fn worker_publication_and_client_download_are_bound_to_ticket() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let worker = Publisher::Worker {
        address: "127.0.0.1:10501".parse()?,
        job: 42,
    };
    let other_worker = Publisher::Worker {
        address: "127.0.0.1:10502".parse()?,
        job: 42,
    };
    let NativeAdmission::Compile { ticket } =
        service.admit(request()?, worker, ActionMode::Reuse)?
    else {
        bail!("expected compilation");
    };
    assert_eq!(
        service.admit(request()?, Publisher::Client, ActionMode::Reuse)?,
        NativeAdmission::InFlight
    );
    let output = manifest(b"object");
    let blob = output.outputs["obj"].blob;
    assert!(service.begin(ticket, other_worker, output.clone()).is_err());
    assert!(
        service
            .begin(ticket, Publisher::Client, output.clone())
            .is_err()
    );
    assert_eq!(
        service.begin(ticket, worker, output.clone())?.missing,
        vec![blob]
    );
    assert!(service.commit(ticket, worker).is_err());
    assert!(upload_encoded(&service, ticket, worker, blob, b"wrong!").is_err());
    upload_encoded(&service, ticket, worker, blob, b"object")?;
    assert_eq!(service.begin(ticket, worker, output.clone())?.missing, []);
    assert_eq!(service.commit(ticket, worker)?, output);
    assert_eq!(service.commit(ticket, worker)?, output);
    assert_eq!(service.status(ticket)?, NativeStatus::Ready(output.clone()));
    let mut file = decoded_download(&service, ticket, Publisher::Client, blob.id)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"object");
    let key = request()?.action_fingerprint()?.key()?;
    assert_eq!(service.store().evict(key)?, Eviction::Pinned);
    let NativeAdmission::Hit {
        ticket: second,
        manifest,
    } = service.admit(request()?, Publisher::Client, ActionMode::Reuse)?
    else {
        bail!("expected hit");
    };
    assert_eq!(manifest, output);
    service.close(ticket, Publisher::Client)?;
    assert_eq!(service.store().evict(key)?, Eviction::Pinned);
    service.close(second, Publisher::Client)?;
    assert_eq!(
        service.store().evict(key)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 6
        }
    );
    assert_eq!(service.store().collect_garbage(1)?.blobs, 1);
    assert!(service.status(second).is_err());
    Ok(())
}

#[test]
fn abandoned_and_failed_sessions_release_exclusive_compilation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let NativeAdmission::Compile { ticket } =
        service.admit(request()?, Publisher::Client, ActionMode::Reuse)?
    else {
        bail!("expected compilation");
    };
    {
        let session = service.get(ticket)?;
        NativeSessions::lock(&session)?.expires = Instant::now();
    }
    assert_eq!(service.reap()?, 1);
    assert!(service.status(ticket).is_err());
    let NativeAdmission::Compile { ticket } =
        service.admit(request()?, Publisher::Client, ActionMode::Reuse)?
    else {
        bail!("expected compilation after expiration");
    };
    service.fail(ticket, Publisher::Client)?;
    assert_eq!(service.status(ticket)?, NativeStatus::Failed);
    assert!(matches!(
        service.admit(request()?, Publisher::Client, ActionMode::Reuse)?,
        NativeAdmission::Compile { .. }
    ));
    Ok(())
}

#[test]
fn result_contract_and_limits_control_publication() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let NativeAdmission::Compile { ticket } =
        service.admit(request()?, Publisher::Client, ActionMode::Reuse)?
    else {
        bail!("expected compilation");
    };
    let mut invalid = manifest(b"data");
    invalid.outputs.clear();
    assert!(service.begin(ticket, Publisher::Client, invalid).is_err());
    let too_large = manifest(&[0; 1025]);
    assert!(service.begin(ticket, Publisher::Client, too_large).is_err());
    let first = manifest(b"first");
    service.begin(ticket, Publisher::Client, first)?;
    assert!(
        service
            .begin(ticket, Publisher::Client, manifest(b"second"))
            .is_err()
    );
    service.close(ticket, Publisher::Client)?;
    assert!(matches!(
        service.admit(request()?, Publisher::Client, ActionMode::Reuse)?,
        NativeAdmission::Compile { .. }
    ));
    Ok(())
}

#[test]
fn delegation_and_publisher_renewal_are_exclusive() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let NativeAdmission::Compile { ticket } =
        service.admit(request()?, Publisher::Client, ActionMode::Reuse)?
    else {
        bail!("expected compilation");
    };
    let worker = "127.0.0.1:10501".parse()?;
    let allocation = WorkerAllocation {
        address: worker,
        job: 42,
        auth: "proof".into(),
        certificate: vec![1],
    };
    let expected = ScheduleReply::Assigned(allocation);
    assert_eq!(
        service.schedule(ticket, &request()?, || Ok(expected.clone()))?,
        expected
    );
    assert_eq!(
        service.schedule(ticket, &request()?, || bail!("duplicate allocation"))?,
        expected
    );
    assert!(service.renew(ticket, Publisher::Client).is_err());
    let mut changed = request()?;
    changed.required_outputs.insert("other".into());
    assert!(
        service
            .schedule(ticket, &changed, || bail!("wrong declaration"))
            .is_err()
    );
    service.renew(
        ticket,
        Publisher::Worker {
            address: worker,
            job: 42,
        },
    )?;
    let session = service.get(ticket)?;
    let expiry = NativeSessions::lock(&session)?.expires;
    assert_eq!(service.status(ticket)?, NativeStatus::Compiling);
    assert_eq!(NativeSessions::lock(&session)?.expires, expiry);
    service.begin(
        ticket,
        Publisher::Worker {
            address: worker,
            job: 42,
        },
        manifest(b"object"),
    )?;
    assert_eq!(
        service.schedule(ticket, &request()?, || bail!("duplicate assignment"))?,
        expected
    );
    Ok(())
}

fn verify_package_plan_authorization(
    service: &NativeSessions,
    ticket: Ticket,
    worker: Publisher,
    blob: BlobRef,
) -> Result<()> {
    assert!(
        service
            .plan_packages(
                ticket,
                Publisher::Client,
                &[blob],
                u64::MAX,
                crate::PackageTransferCost::default()
            )
            .is_err()
    );
    assert!(
        service
            .plan_packages(
                ticket,
                worker,
                &[BlobRef {
                    id: ContentId::of(b"unrelated"),
                    size: 9
                }],
                u64::MAX,
                crate::PackageTransferCost::default()
            )
            .is_err()
    );
    assert!(
        service
            .plan_packages(
                ticket,
                worker,
                &[blob, blob],
                u64::MAX,
                crate::PackageTransferCost::default()
            )
            .is_err()
    );
    assert_eq!(
        service.plan_packages(
            ticket,
            worker,
            &[blob],
            u64::MAX,
            crate::PackageTransferCost::default()
        )?,
        []
    );
    Ok(())
}

#[test]
fn shared_input_tree_is_pinned_and_worker_can_fetch_only_declared_inputs() -> Result<()> {
    use crate::{TreeEntry, TreePath};
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let blob = BlobRef {
        id: ContentId::of(b"tree data"),
        size: 9,
    };
    let metadata = TreeMetadata {
        mode: 0o755,
        modified: TreeTimestamp {
            seconds: 1,
            nanoseconds: 0,
        },
    };
    let manifest = TreeManifest {
        root: metadata,
        entries: BTreeMap::from([(
            TreePath::new(b"input".to_vec())?,
            TreeEntry::File { blob, metadata },
        )]),
    };
    let offer = service.offer_tree(manifest.clone())?;
    assert_eq!(offer.missing, vec![blob]);
    assert!(service.commit_tree(offer.ticket).is_err());
    upload_encoded(
        &service,
        offer.ticket,
        Publisher::Client,
        blob,
        b"tree data",
    )?;
    let id = service.commit_tree(offer.ticket)?;
    assert_eq!(id, manifest.id()?);
    let again = service.offer_tree(manifest)?;
    assert_eq!(again.missing, []);
    assert_eq!(service.commit_tree(again.ticket)?, id);

    let mut request = request()?;
    request.root = ExecutionRoot {
        id,
        recipe: TreeRecipe::union(metadata, [id]),
    };
    request.input_trees = BTreeSet::from([id]);
    let worker = Publisher::Worker {
        address: "127.0.0.1:10501".parse()?,
        job: 42,
    };
    let NativeAdmission::Compile { ticket } =
        service.admit(request.clone(), worker, ActionMode::Reuse)?
    else {
        bail!("expected native action");
    };
    service.close(offer.ticket, Publisher::Client)?;
    service.close(again.ticket, Publisher::Client)?;
    assert_eq!(service.store().evict_tree(id)?, Eviction::Pinned);
    assert!(service.open_tree(id, worker, Ticket([0; 32])).is_err());
    let unrelated = service.store().publish_tree(
        &TreeManifest {
            root: metadata,
            entries: BTreeMap::new(),
        },
        vec![],
    )?;
    assert!(service.open_tree(unrelated, worker, ticket).is_err());
    assert!(service.open_tree(id, Publisher::Client, ticket).is_err());
    let read = service.open_tree(id, worker, ticket)?;
    verify_package_plan_authorization(&service, read.ticket, worker, blob)?;
    assert!(
        service
            .download(read.ticket, Publisher::Client, blob.id)
            .is_err()
    );
    let mut contents = Vec::new();
    decoded_download(&service, read.ticket, worker, blob.id)?.read_to_end(&mut contents)?;
    assert_eq!(contents, b"tree data");
    service.close(read.ticket, worker)?;
    service.fail(ticket, worker)?;
    assert_eq!(
        service.store().evict_tree(id)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 9
        }
    );
    assert_eq!(
        service.admit(request, Publisher::Client, ActionMode::Reuse)?,
        NativeAdmission::MissingInputs {
            trees: BTreeSet::from([id])
        }
    );
    Ok(())
}

#[test]
fn expiry_releases_action_even_when_a_transfer_retains_the_session() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let NativeAdmission::Compile { ticket } =
        service.admit(request()?, Publisher::Client, ActionMode::Reuse)?
    else {
        bail!("expected compilation");
    };
    let held = service.get(ticket)?;
    NativeSessions::lock(&held)?.expires = Instant::now();
    assert_eq!(service.reap()?, 1);
    assert!(matches!(NativeSessions::lock(&held)?.phase, Phase::Failed));
    assert!(matches!(
        service.admit(request()?, Publisher::Client, ActionMode::Reuse)?,
        NativeAdmission::Compile { .. }
    ));
    Ok(())
}

#[test]
fn original_package_slots_deduplicate_identities_and_bound_parallel_imports() -> Result<()> {
    use crate::PackageCompression;
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let identity = |byte| PackageIdentity {
        sha256: [byte; 32],
        compression: PackageCompression::Xz,
    };
    let first = service.store().package_slot(identity(1), 2)?;
    assert!(service.store().package_slot(identity(1), 2).is_err());
    let second = service.store().package_slot(identity(2), 2)?;
    assert!(service.store().package_slot(identity(3), 2).is_err());
    drop(first);
    let third = service.store().package_slot(identity(3), 2)?;
    assert!(service.store().package_slot(identity(1), 2).is_err());
    drop((second, third));
    assert!(service.store().package_slot(identity(1), 2).is_ok());
    Ok(())
}

#[test]
fn refresh_keeps_previous_result_until_success_and_preserves_readers() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let client = Publisher::Client;
    let NativeAdmission::Compile { ticket: first } =
        service.admit(request()?, client, ActionMode::Reuse)?
    else {
        bail!("expected initial compilation");
    };
    let old = manifest(b"old");
    let old_blob = old.outputs["obj"].blob;
    service.begin(first, client, old.clone())?;
    upload_encoded(&service, first, client, old_blob, b"old")?;
    service.commit(first, client)?;

    let NativeAdmission::Compile { ticket: failed } =
        service.admit(request()?, client, ActionMode::Refresh)?
    else {
        bail!("expected refresh");
    };
    assert_eq!(
        service.admit(request()?, client, ActionMode::Refresh)?,
        NativeAdmission::InFlight
    );
    let NativeAdmission::Hit {
        ticket: reader,
        manifest: current,
    } = service.admit(request()?, client, ActionMode::Reuse)?
    else {
        bail!("expected old hit during refresh");
    };
    assert_eq!(current, old);
    service.fail(failed, client)?;
    service.close(failed, client)?;

    let NativeAdmission::Compile { ticket: next } =
        service.admit(request()?, client, ActionMode::Refresh)?
    else {
        bail!("expected another refresh");
    };
    let new = manifest(b"new");
    let new_blob = new.outputs["obj"].blob;
    service.begin(next, client, new.clone())?;
    assert!(service.commit(next, client).is_err());
    assert_eq!(service.status(reader)?, NativeStatus::Ready(old));
    upload_encoded(&service, next, client, new_blob, b"new")?;
    assert_eq!(service.commit(next, client)?, new);
    let NativeAdmission::Hit {
        ticket: latest,
        manifest: current,
    } = service.admit(request()?, client, ActionMode::Reuse)?
    else {
        bail!("expected refreshed hit");
    };
    assert_eq!(current, new);
    assert_eq!(service.store().stats()?.actions, 1);
    assert_eq!(service.store().stats()?.results, 1);
    assert_eq!(service.store().collect_garbage(8)?.blobs, 0);
    let mut bytes = Vec::new();
    decoded_download(&service, reader, client, old_blob.id)?.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"old");
    service.close(first, client)?;
    service.close(reader, client)?;
    assert_eq!(service.store().collect_garbage(8)?.blobs, 1);
    service.close(next, client)?;
    service.close(latest, client)?;
    Ok(())
}
