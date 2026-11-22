use super::*;
use crate::{ActionFingerprint, Artifact, ContentId, Eviction};
use std::{collections::BTreeMap, io::Read};

fn service(dir: &std::path::Path) -> Result<NativeSessions> {
    NativeSessions::new(
        NativeStore::open(dir)?,
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

fn request() -> ActionRequest {
    ActionRequest {
        fingerprint: ActionFingerprint {
            schema: "test-native-v1".into(),
            components: BTreeMap::from([("source".into(), ContentId::of(b"input"))]),
        },
        input_trees: BTreeSet::new(),
        required_outputs: BTreeMap::from([("obj".into(), crate::OutputKind::File)]),
        optional_outputs: BTreeMap::new(),
    }
}

fn manifest(bytes: &[u8]) -> ResultManifest {
    ResultManifest {
        outputs: BTreeMap::from([(
            "obj".into(),
            Artifact::File {
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
    let NativeAdmission::Compile { ticket } = service.admit(request(), worker)? else {
        bail!("expected compilation");
    };
    assert_eq!(
        service.admit(request(), Publisher::Client)?,
        NativeAdmission::InFlight
    );
    let output = manifest(b"object");
    let blob = output.outputs["obj"].test_file_blob();
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
    assert!(
        service
            .upload(ticket, worker, blob, &b"wrong!"[..])
            .is_err()
    );
    service.upload(ticket, worker, blob, &b"object"[..])?;
    assert!(
        service
            .begin(ticket, worker, output.clone())?
            .missing
            .is_empty()
    );
    assert_eq!(service.commit(ticket, worker)?, output);
    assert_eq!(service.commit(ticket, worker)?, output);
    assert_eq!(service.status(ticket)?, NativeStatus::Ready(output.clone()));
    let mut file = service.download(ticket, Publisher::Client, blob.id)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"object");
    let key = request().action_fingerprint()?.key()?;
    assert_eq!(service.store().evict(key)?, Eviction::Pinned);
    let NativeAdmission::Hit {
        ticket: second,
        manifest,
    } = service.admit(request(), Publisher::Client)?
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
    let NativeAdmission::Compile { ticket } = service.admit(request(), Publisher::Client)? else {
        bail!("expected compilation");
    };
    {
        let session = service.get(ticket)?;
        NativeSessions::lock(&session)?.expires = Instant::now();
    }
    assert_eq!(service.reap()?, 1);
    assert!(service.status(ticket).is_err());
    let NativeAdmission::Compile { ticket } = service.admit(request(), Publisher::Client)? else {
        bail!("expected compilation after expiration");
    };
    service.fail(ticket, Publisher::Client)?;
    assert_eq!(service.status(ticket)?, NativeStatus::Failed);
    assert!(matches!(
        service.admit(request(), Publisher::Client)?,
        NativeAdmission::Compile { .. }
    ));
    Ok(())
}

#[test]
fn result_contract_and_limits_control_publication() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let NativeAdmission::Compile { ticket } = service.admit(request(), Publisher::Client)? else {
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
        service.admit(request(), Publisher::Client)?,
        NativeAdmission::Compile { .. }
    ));
    Ok(())
}

#[test]
fn delegation_and_publisher_renewal_are_exclusive() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let NativeAdmission::Compile { ticket } = service.admit(request(), Publisher::Client)? else {
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
        service.schedule(ticket, &request(), || Ok(expected.clone()))?,
        expected
    );
    assert_eq!(
        service.schedule(ticket, &request(), || bail!("duplicate allocation"))?,
        expected
    );
    assert!(service.renew(ticket, Publisher::Client).is_err());
    let mut changed = request();
    changed
        .required_outputs
        .insert("other".into(), crate::OutputKind::File);
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
        service.schedule(ticket, &request(), || bail!("duplicate assignment"))?,
        expected
    );
    Ok(())
}

#[test]
fn shared_input_tree_is_pinned_and_worker_can_fetch_only_declared_inputs() -> Result<()> {
    use crate::{TreeEntry, TreeMetadata, TreePath, TreeTimestamp};
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
    service.upload(offer.ticket, Publisher::Client, blob, &b"tree data"[..])?;
    let id = service.commit_tree(offer.ticket)?;
    assert_eq!(id, manifest.id()?);
    let again = service.offer_tree(manifest)?;
    assert!(again.missing.is_empty());
    assert_eq!(service.commit_tree(again.ticket)?, id);

    let mut request = request();
    request.input_trees.insert(id);
    let worker = Publisher::Worker {
        address: "127.0.0.1:10501".parse()?,
        job: 42,
    };
    let NativeAdmission::Compile { ticket } = service.admit(request.clone(), worker)? else {
        bail!("expected native action");
    };
    service.close(offer.ticket, Publisher::Client)?;
    service.close(again.ticket, Publisher::Client)?;
    assert_eq!(service.store().evict_tree(id)?, Eviction::Pinned);
    assert!(service.open_tree(id, worker, None).is_err());
    let unrelated = service.store().publish_tree(
        &TreeManifest {
            root: metadata,
            entries: BTreeMap::new(),
        },
        vec![],
    )?;
    assert!(service.open_tree(unrelated, worker, Some(ticket)).is_err());
    let read = service.open_tree(id, worker, Some(ticket))?;
    assert!(
        service
            .download(read.ticket, Publisher::Client, blob.id)
            .is_err()
    );
    let mut contents = Vec::new();
    service
        .download(read.ticket, worker, blob.id)?
        .read_to_end(&mut contents)?;
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
        service.admit(request, Publisher::Client)?,
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
    let NativeAdmission::Compile { ticket } = service.admit(request(), Publisher::Client)? else {
        bail!("expected compilation");
    };
    let held = service.get(ticket)?;
    NativeSessions::lock(&held)?.expires = Instant::now();
    assert_eq!(service.reap()?, 1);
    assert!(matches!(NativeSessions::lock(&held)?.phase, Phase::Failed));
    assert!(matches!(
        service.admit(request(), Publisher::Client)?,
        NativeAdmission::Compile { .. }
    ));
    Ok(())
}

#[test]
fn tree_result_contract_rejects_wrong_kinds_and_duplicate_logical_overflow() -> Result<()> {
    use crate::{OutputKind, TreeEntry, TreeManifest, TreeMetadata, TreePath, TreeTimestamp};
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let mut request = request();
    request
        .required_outputs
        .insert("obj".into(), OutputKind::Tree);
    let NativeAdmission::Compile { ticket } = service.admit(request.clone(), Publisher::Client)?
    else {
        bail!("expected tree miss");
    };
    assert!(
        service
            .begin(ticket, Publisher::Client, manifest(b"wrong kind"))
            .is_err()
    );
    let metadata = TreeMetadata {
        mode: 0o755,
        modified: TreeTimestamp {
            seconds: 0,
            nanoseconds: 0,
        },
    };
    let data = vec![42_u8; 600];
    let blob = BlobRef {
        id: ContentId::of(&data),
        size: data.len() as u64,
    };
    let tree = TreeManifest {
        root: metadata,
        entries: BTreeMap::from([
            (
                TreePath::new(b"one".to_vec())?,
                TreeEntry::File { blob, metadata },
            ),
            (
                TreePath::new(b"two".to_vec())?,
                TreeEntry::File { blob, metadata },
            ),
        ]),
    };
    let mut result = ResultManifest {
        outputs: BTreeMap::from([("obj".into(), Artifact::Tree(tree))]),
        stdout: None,
        stderr: None,
    };
    assert_eq!(result.blobs()?.len(), 1);
    assert_eq!(result.logical_bytes()?, 1200);
    assert!(
        service
            .begin(ticket, Publisher::Client, result.clone())
            .is_err()
    );
    let Artifact::Tree(tree) = result.outputs.get_mut("obj").context("missing tree")? else {
        bail!("expected tree");
    };
    tree.entries.remove(&TreePath::new(b"two".to_vec())?);
    assert_eq!(
        service
            .begin(ticket, Publisher::Client, result.clone())?
            .missing,
        vec![blob]
    );
    service.upload(ticket, Publisher::Client, blob, data.as_slice())?;
    assert_eq!(service.commit(ticket, Publisher::Client)?, result);
    service.close(ticket, Publisher::Client)?;
    let NativeAdmission::Hit { ticket, manifest } = service.admit(request, Publisher::Client)?
    else {
        bail!("expected tree hit");
    };
    assert_eq!(manifest, result);
    let mut restored = Vec::new();
    service
        .download(ticket, Publisher::Client, blob.id)?
        .read_to_end(&mut restored)?;
    assert_eq!(restored, data);
    Ok(())
}
