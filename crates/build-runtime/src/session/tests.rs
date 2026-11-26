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
            max_manifest_cache_bytes: 1024 * 1024,
            peer_discovery_timeout: Duration::ZERO,
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

fn selection() -> DeliverySelection {
    DeliverySelection {
        profile: ContentId::of(b"test command family"),
        outputs: BTreeSet::from(["obj".into()]),
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
        required_outputs: BTreeMap::from([("obj".into(), crate::OutputKind::File)]),
        optional_outputs: BTreeMap::new(),
    })
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
        peer: test_peer(1),
        job: 42,
    };
    let other_worker = Publisher::Worker {
        peer: test_peer(2),
        job: 42,
    };
    let NativeAdmission::Compile { ticket } = service.admit(
        request()?,
        worker,
        ActionMode::Reuse,
        std::collections::BTreeMap::new(),
    )?
    else {
        bail!("expected compilation");
    };
    assert_eq!(
        service.admit(
            request()?,
            Publisher::Client,
            ActionMode::Reuse,
            std::collections::BTreeMap::new()
        )?,
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
    } = service.admit(
        request()?,
        Publisher::Client,
        ActionMode::Reuse,
        std::collections::BTreeMap::new(),
    )?
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
    let NativeAdmission::Compile { ticket } = service.admit(
        request()?,
        Publisher::Client,
        ActionMode::Reuse,
        std::collections::BTreeMap::new(),
    )?
    else {
        bail!("expected compilation");
    };
    {
        let session = service.get(ticket)?;
        NativeSessions::lock(&session)?.expires = Instant::now();
    }
    assert_eq!(service.reap()?, 1);
    assert!(service.status(ticket).is_err());
    let NativeAdmission::Compile { ticket } = service.admit(
        request()?,
        Publisher::Client,
        ActionMode::Reuse,
        std::collections::BTreeMap::new(),
    )?
    else {
        bail!("expected compilation after expiration");
    };
    service.fail(ticket, Publisher::Client)?;
    assert_eq!(service.status(ticket)?, NativeStatus::Failed);
    assert!(matches!(
        service.admit(
            request()?,
            Publisher::Client,
            ActionMode::Reuse,
            std::collections::BTreeMap::new()
        )?,
        NativeAdmission::Compile { .. }
    ));
    Ok(())
}

#[test]
fn result_contract_and_limits_control_publication() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let NativeAdmission::Compile { ticket } = service.admit(
        request()?,
        Publisher::Client,
        ActionMode::Reuse,
        std::collections::BTreeMap::new(),
    )?
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
        service.admit(
            request()?,
            Publisher::Client,
            ActionMode::Reuse,
            std::collections::BTreeMap::new()
        )?,
        NativeAdmission::Compile { .. }
    ));
    Ok(())
}

impl NativeSessions {
    fn schedule(
        &self,
        ticket: Ticket,
        request: &ActionRequest,
        requester: crate::PeerId,
        selection: DeliverySelection,
        allocate: impl FnOnce(
            BTreeMap<ContentId, u64>,
            Vec<&BTreeMap<ContentId, u64>>,
        ) -> Result<ScheduleReply>,
    ) -> Result<ScheduleReply> {
        match self.prepare_schedule(ticket, request, requester, selection)? {
            SchedulePreparation::Replay(reply) => Ok(reply),
            SchedulePreparation::Dispatch(mut reservation) => {
                let (blobs, trees) = reservation.placement_inputs();
                let reply = allocate(blobs, trees)?;
                reservation.finish(reply)
            }
        }
    }
}

#[test]
fn delegation_and_publisher_renewal_are_exclusive() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let NativeAdmission::Compile { ticket } = service.admit(
        request()?,
        Publisher::Client,
        ActionMode::Reuse,
        std::collections::BTreeMap::new(),
    )?
    else {
        bail!("expected compilation");
    };
    let worker = test_peer(1);
    let allocation = WorkerAllocation {
        peer: worker,
        routes: sccache_peer_identity::RouteSet::new("127.0.0.1:10501".parse()?, []),
        job: 42,
        auth: "proof".into(),
    };
    let expected = ScheduleReply::Assigned(allocation);
    assert_eq!(
        service.schedule(ticket, &request()?, test_peer(9), selection(), |_, _| Ok(
            expected.clone()
        ))?,
        expected
    );
    assert_eq!(
        service.schedule(
            ticket,
            &request()?,
            test_peer(9),
            selection(),
            |_, _| bail!("duplicate allocation")
        )?,
        expected
    );
    assert!(service.renew(ticket, Publisher::Client).is_err());
    assert!(
        service
            .schedule(
                ticket,
                &request()?,
                test_peer(9),
                DeliverySelection {
                    outputs: BTreeSet::new(),
                    ..selection()
                },
                |_, _| bail!("selection changed")
            )
            .is_err()
    );
    assert!(
        service
            .schedule(
                ticket,
                &request()?,
                test_peer(8),
                selection(),
                |_, _| bail!("wrong requester")
            )
            .is_err()
    );
    assert!(
        service
            .record_client_delivery(ticket, test_peer(9), ClientDeliveryObservation::default())
            .is_err()
    );
    let mut changed = request()?;
    changed
        .required_outputs
        .insert("other".into(), crate::OutputKind::File);
    assert!(
        service
            .schedule(ticket, &changed, test_peer(9), selection(), |_, _| bail!(
                "wrong declaration"
            ))
            .is_err()
    );
    service.renew(
        ticket,
        Publisher::Worker {
            peer: worker,
            job: 42,
        },
    )?;
    let session = service.get(ticket)?;
    let expiry = NativeSessions::lock(&session)?.expires;
    assert_eq!(service.status(ticket)?, NativeStatus::Compiling);
    assert_eq!(NativeSessions::lock(&session)?.expires, expiry);
    let publisher = Publisher::Worker {
        peer: worker,
        job: 42,
    };
    let result = manifest(b"object");
    let missing = service.begin(ticket, publisher, result.clone())?.missing;
    assert_eq!(
        service.status_with_preview(ticket, true)?,
        NativeStatus::Negotiated(result.clone())
    );
    assert_eq!(
        service.authorize_blob_sources(ticket, Publisher::Client, &missing)?,
        (Some(worker), vec![false])
    );
    assert!(
        service
            .download(ticket, Publisher::Client, missing[0].id)
            .unwrap_err()
            .is::<NativeContentPending>()
    );
    service.renew(ticket, Publisher::Client)?;

    assert_eq!(
        service.schedule(
            ticket,
            &request()?,
            test_peer(9),
            selection(),
            |_, _| bail!("duplicate assignment")
        )?,
        expected
    );
    assert_eq!(missing.len(), 1);
    service.upload(
        ticket,
        publisher,
        missing[0],
        crate::BlobEncoding::Raw,
        &b"object"[..],
    )?;
    assert_eq!(service.commit(ticket, publisher)?, result);
    let delivered = ClientDeliveryObservation {
        selected_bytes: 6,
        direct_bytes: 6,
        scheduler_bytes: 0,
        unique_blobs: 1,
        staging_nanoseconds: 0,
    };
    assert!(
        service
            .record_client_delivery(ticket, test_peer(8), delivered)
            .is_err()
    );
    assert!(
        service
            .record_client_delivery(
                ticket,
                test_peer(9),
                ClientDeliveryObservation {
                    direct_bytes: 7,
                    ..delivered
                }
            )
            .is_err()
    );
    assert!(
        service
            .record_client_delivery(
                ticket,
                test_peer(9),
                ClientDeliveryObservation {
                    selected_bytes: 5,
                    direct_bytes: 5,
                    ..delivered
                }
            )
            .is_err()
    );
    let receipt = service
        .record_client_delivery(ticket, test_peer(9), delivered)?
        .context("missing receipt")?;
    assert_eq!(
        (
            receipt.worker,
            receipt.job,
            receipt.requester,
            receipt.observation
        ),
        (worker, 42, test_peer(9), delivered)
    );
    assert!(
        service
            .record_client_delivery(ticket, test_peer(9), delivered)?
            .is_none()
    );

    // A worker can finish while the original schedule response is lost.
    assert_eq!(
        service.schedule(
            ticket,
            &request()?,
            test_peer(9),
            selection(),
            |_, _| bail!("duplicate assignment after commit")
        )?,
        expected
    );
    assert!(
        service
            .schedule(ticket, &changed, test_peer(9), selection(), |_, _| bail!(
                "wrong declaration after commit"
            ))
            .is_err()
    );

    let mut failed = request()?;
    failed
        .fingerprint
        .components
        .insert("failed".into(), ContentId::of(b"failed"));
    let NativeAdmission::Compile { ticket } = service.admit(
        failed.clone(),
        Publisher::Client,
        ActionMode::Reuse,
        BTreeMap::new(),
    )?
    else {
        bail!("expected second compilation");
    };
    assert_eq!(
        service.schedule(ticket, &failed, test_peer(9), selection(), |_, _| Ok(
            expected.clone()
        ))?,
        expected
    );
    // The same bytes are already durable from the previous action. A
    // negotiated result can read those bytes before commit, but a subsequent
    // failed publication must never be observable as a ready result.
    assert!(
        service
            .begin(ticket, publisher, result.clone())?
            .missing
            .is_empty()
    );
    assert_eq!(service.status(ticket)?, NativeStatus::Compiling);
    assert_eq!(
        service.status_with_preview(ticket, true)?,
        NativeStatus::Negotiated(result)
    );
    assert_eq!(
        service.authorize_blob_sources(ticket, Publisher::Client, &missing)?,
        (Some(worker), vec![true])
    );
    let mut bytes = Vec::new();
    decoded_download(&service, ticket, Publisher::Client, missing[0].id)?
        .read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"object");
    service.fail(ticket, publisher)?;
    assert_eq!(
        service.schedule(ticket, &failed, test_peer(9), selection(), |_, _| bail!(
            "duplicate assignment after failure"
        ))?,
        expected
    );
    assert_eq!(service.status(ticket)?, NativeStatus::Failed);
    Ok(())
}

#[test]
fn delegation_is_nonblocking_and_retries_early_worker_verification() -> Result<()> {
    use std::{sync::mpsc, thread};
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    for accepted in [false, true] {
        let mut action = request()?;
        action.fingerprint.components.insert(
            "allocation-attempt".into(),
            ContentId::of(&[u8::from(accepted)]),
        );
        let NativeAdmission::Compile { ticket } = service.admit(
            action.clone(),
            Publisher::Client,
            ActionMode::Reuse,
            BTreeMap::new(),
        )?
        else {
            bail!("expected compilation");
        };
        let worker = WorkerAllocation {
            peer: test_peer(1),
            routes: sccache_peer_identity::RouteSet::new("127.0.0.1:10501".parse()?, []),
            job: u64::from(accepted),
            auth: "proof".into(),
        };
        let publisher = Publisher::Worker {
            peer: worker.peer,
            job: worker.job,
        };
        let expected = if accepted {
            ScheduleReply::Assigned(worker)
        } else {
            ScheduleReply::Unavailable {
                message: "assignment rejected".into(),
            }
        };
        thread::scope(|scope| -> Result<()> {
            let (start, start_rx) = mpsc::channel();
            let (done, done_rx) = mpsc::channel();
            let service = &service;
            let action = &action;
            let verifier = scope.spawn(move || -> Result<()> {
                start_rx.recv_timeout(Duration::from_secs(5))?;
                assert_eq!(service.status(ticket)?, NativeStatus::Compiling);
                service.renew(ticket, Publisher::Client)?;
                assert!(
                    service
                        .verify_execution(ticket, publisher, action)
                        .unwrap_err()
                        .is::<NativeServiceBusy>()
                );
                assert!(
                    service
                        .schedule(ticket, action, test_peer(9), selection(), |_, _| bail!(
                            "duplicate allocation"
                        ))
                        .unwrap_err()
                        .is::<NativeServiceBusy>()
                );
                assert!(
                    !service
                        .schedule(ticket, action, test_peer(8), selection(), |_, _| bail!(
                            "wrong requester"
                        ))
                        .unwrap_err()
                        .is::<NativeServiceBusy>()
                );
                done.send(())?;
                Ok(())
            });
            let reply = service.schedule(ticket, action, test_peer(9), selection(), |_, _| {
                start.send(())?;
                done_rx.recv_timeout(Duration::from_secs(5))?;
                Ok(expected.clone())
            })?;
            assert_eq!(reply, expected);
            assert_eq!(
                service.verify_execution(ticket, publisher, action).is_ok(),
                accepted
            );
            verifier
                .join()
                .map_err(|_| anyhow!("verification thread panicked"))??;
            Ok(())
        })?;
        service.close(ticket, Publisher::Client)?;
    }
    Ok(())
}

#[test]
fn closing_during_assignment_cannot_resurrect_the_ticket() -> Result<()> {
    use std::{sync::mpsc, thread};
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let action = request()?;
    let NativeAdmission::Compile { ticket } = service.admit(
        action.clone(),
        Publisher::Client,
        ActionMode::Reuse,
        BTreeMap::new(),
    )?
    else {
        bail!("expected compilation");
    };
    let worker = WorkerAllocation {
        peer: test_peer(1),
        routes: sccache_peer_identity::RouteSet::new("127.0.0.1:10501".parse()?, []),
        job: 42,
        auth: "proof".into(),
    };
    let publisher = Publisher::Worker {
        peer: worker.peer,
        job: worker.job,
    };
    thread::scope(|scope| -> Result<()> {
        let (start, started) = mpsc::channel();
        let (done, closed) = mpsc::channel();
        let service = &service;
        let closer = scope.spawn(move || -> Result<()> {
            started.recv_timeout(Duration::from_secs(5))?;
            service.close(ticket, Publisher::Client)?;
            done.send(())?;
            Ok(())
        });
        let result = service.schedule(ticket, &action, test_peer(9), selection(), |_, _| {
            start.send(())?;
            closed.recv_timeout(Duration::from_secs(5))?;
            Ok(ScheduleReply::Assigned(worker))
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("cancelled before acknowledgement")
        );
        closer.join().map_err(|_| anyhow!("closer panicked"))??;
        Ok(())
    })?;
    assert!(
        service
            .verify_execution(ticket, publisher, &action)
            .is_err()
    );
    assert!(service.status(ticket).is_err());
    assert!(matches!(
        service.admit(
            action,
            Publisher::Client,
            ActionMode::Reuse,
            BTreeMap::new()
        )?,
        NativeAdmission::Compile { .. }
    ));
    Ok(())
}

#[test]
fn failed_assignment_releases_intent_for_retry() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let action = request()?;
    let NativeAdmission::Compile { ticket } = service.admit(
        action.clone(),
        Publisher::Client,
        ActionMode::Reuse,
        BTreeMap::new(),
    )?
    else {
        bail!("expected compilation");
    };
    assert!(
        service
            .schedule(ticket, &action, test_peer(9), selection(), |_, _| bail!(
                "transport failed"
            ))
            .is_err()
    );
    let expected = ScheduleReply::Unavailable {
        message: "no capacity".into(),
    };
    assert_eq!(
        service.schedule(ticket, &action, test_peer(9), selection(), |_, _| Ok(
            expected.clone()
        ))?,
        expected
    );
    service.renew(ticket, Publisher::Client)?;
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
fn input_manifest_survives_scheduler_eviction_and_worker_fetch_is_scoped() -> Result<()> {
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
        peer: test_peer(1),
        job: 42,
    };
    let NativeAdmission::Compile { ticket } = service.admit(
        request.clone(),
        worker,
        ActionMode::Reuse,
        std::collections::BTreeMap::new(),
    )?
    else {
        bail!("expected native action");
    };
    service.close(offer.ticket, Publisher::Client)?;
    service.close(again.ticket, Publisher::Client)?;
    assert_eq!(
        service.store().evict_tree(id)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 9,
        }
    );
    // Tree eviction queues physical deletion; force actual reclamation so
    // this case tests a scheduler payload miss, not pending-GC reuse.
    service.store().collect_garbage(16)?;
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
    assert_eq!(
        service.authorize_blob_sources(read.ticket, worker, &[blob])?,
        (None, vec![false])
    );
    assert!(
        service
            .authorize_blob_sources(read.ticket, Publisher::Client, &[blob])
            .is_err()
    );
    assert!(
        service
            .authorize_blob_sources(
                read.ticket,
                worker,
                &[BlobRef {
                    size: blob.size + 1,
                    ..blob
                }]
            )
            .is_err()
    );
    // Merely discovering a direct source must not trigger origin backfill.
    assert_eq!(service.poll_input(ticket)?, InputPoll::Waiting);
    assert!(
        service
            .download(read.ticket, Publisher::Client, blob.id)
            .is_err()
    );
    assert!(
        service
            .download(read.ticket, worker, blob.id)
            .unwrap_err()
            .is::<NativeContentPending>()
    );
    assert_eq!(
        service.poll_input(ticket)?,
        InputPoll::Demand(InputDemand { tree: id, blob })
    );
    service.backfill_input(ticket, blob, &b"tree data"[..])?;
    assert_eq!(
        service.authorize_blob_sources(read.ticket, worker, &[blob])?,
        (None, vec![true])
    );
    let mut contents = Vec::new();
    decoded_download(&service, read.ticket, worker, blob.id)?.read_to_end(&mut contents)?;
    assert_eq!(contents, b"tree data");
    service.close(read.ticket, worker)?;
    service.fail(ticket, worker)?;
    let retention = NativeStore::blob_retention_manifest(blob)?.id()?;
    assert_eq!(
        service.store().evict_tree(retention)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 9,
        }
    );
    assert!(matches!(
        service.admit(
            request,
            Publisher::Client,
            ActionMode::Reuse,
            BTreeMap::new()
        )?,
        NativeAdmission::Compile { .. }
    ));
    Ok(())
}

#[test]
fn expiry_releases_action_even_when_a_transfer_retains_the_session() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let NativeAdmission::Compile { ticket } = service.admit(
        request()?,
        Publisher::Client,
        ActionMode::Reuse,
        std::collections::BTreeMap::new(),
    )?
    else {
        bail!("expected compilation");
    };
    let held = service.get(ticket)?;
    NativeSessions::lock(&held)?.expires = Instant::now();
    assert_eq!(service.reap()?, 1);
    assert!(matches!(NativeSessions::lock(&held)?.phase, Phase::Failed));
    assert!(matches!(
        service.admit(
            request()?,
            Publisher::Client,
            ActionMode::Reuse,
            std::collections::BTreeMap::new()
        )?,
        NativeAdmission::Compile { .. }
    ));
    Ok(())
}

#[test]
fn tree_result_contract_rejects_wrong_kinds_and_duplicate_logical_overflow() -> Result<()> {
    use crate::{OutputKind, TreeEntry, TreeManifest, TreeMetadata, TreePath, TreeTimestamp};
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let mut request = request()?;
    request
        .required_outputs
        .insert("obj".into(), OutputKind::Tree);
    let NativeAdmission::Compile { ticket } = service.admit(
        request.clone(),
        Publisher::Client,
        ActionMode::Reuse,
        BTreeMap::new(),
    )?
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
    upload_encoded(&service, ticket, Publisher::Client, blob, data.as_slice())?;
    assert_eq!(service.commit(ticket, Publisher::Client)?, result);
    service.close(ticket, Publisher::Client)?;
    let NativeAdmission::Hit { ticket, manifest } = service.admit(
        request,
        Publisher::Client,
        ActionMode::Reuse,
        BTreeMap::new(),
    )?
    else {
        bail!("expected tree hit");
    };
    assert_eq!(manifest, result);
    let mut restored = Vec::new();
    decoded_download(&service, ticket, Publisher::Client, blob.id)?.read_to_end(&mut restored)?;
    assert_eq!(restored, data);
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
    let NativeAdmission::Compile { ticket: first } = service.admit(
        request()?,
        client,
        ActionMode::Reuse,
        std::collections::BTreeMap::new(),
    )?
    else {
        bail!("expected initial compilation");
    };
    let old = manifest(b"old");
    let old_blob = old.outputs["obj"].test_file_blob();
    service.begin(first, client, old.clone())?;
    upload_encoded(&service, first, client, old_blob, b"old")?;
    service.commit(first, client)?;

    let NativeAdmission::Compile { ticket: failed } = service.admit(
        request()?,
        client,
        ActionMode::Refresh,
        std::collections::BTreeMap::new(),
    )?
    else {
        bail!("expected refresh");
    };
    assert_eq!(
        service.admit(
            request()?,
            client,
            ActionMode::Refresh,
            std::collections::BTreeMap::new()
        )?,
        NativeAdmission::InFlight
    );
    let NativeAdmission::Hit {
        ticket: reader,
        manifest: current,
    } = service.admit(
        request()?,
        client,
        ActionMode::Reuse,
        std::collections::BTreeMap::new(),
    )?
    else {
        bail!("expected old hit during refresh");
    };
    assert_eq!(current, old);
    service.fail(failed, client)?;
    service.close(failed, client)?;

    let NativeAdmission::Compile { ticket: next } = service.admit(
        request()?,
        client,
        ActionMode::Refresh,
        std::collections::BTreeMap::new(),
    )?
    else {
        bail!("expected another refresh");
    };
    let new = manifest(b"new");
    let new_blob = new.outputs["obj"].test_file_blob();
    service.begin(next, client, new.clone())?;
    assert!(service.commit(next, client).is_err());
    assert_eq!(service.status(reader)?, NativeStatus::Ready(old));
    upload_encoded(&service, next, client, new_blob, b"new")?;
    assert_eq!(service.commit(next, client)?, new);
    let NativeAdmission::Hit {
        ticket: latest,
        manifest: current,
    } = service.admit(
        request()?,
        client,
        ActionMode::Reuse,
        std::collections::BTreeMap::new(),
    )?
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

#[test]
fn lazy_manifest_admission_and_cross_action_backfill_are_single_flight() -> Result<()> {
    use crate::{TreeEntry, TreePath};
    let directory = tempfile::tempdir()?;
    let service = service(directory.path())?;
    let root = empty_root().root;
    let bytes = b"shared content";
    let blob = BlobRef {
        id: ContentId::of(bytes),
        size: bytes.len() as u64,
    };
    let other = BlobRef {
        id: ContentId::of(b"unused"),
        size: 6,
    };
    let tree = TreeManifest {
        root,
        entries: BTreeMap::from([
            (
                TreePath::new(b"used".to_vec())?,
                TreeEntry::File {
                    blob,
                    metadata: root,
                },
            ),
            (
                TreePath::new(b"worker-already-has".to_vec())?,
                TreeEntry::File {
                    blob: other,
                    metadata: root,
                },
            ),
        ]),
    };
    let id = tree.id()?;
    let mut first = request()?;
    first.root = ExecutionRoot {
        id,
        recipe: TreeRecipe::union(root, [id]),
    };
    first.input_trees = BTreeSet::from([id]);
    let mut second = first.clone();
    second
        .fingerprint
        .components
        .insert("second".into(), ContentId::of(b"second"));
    let worker1 = Publisher::Worker {
        peer: test_peer(1),
        job: 1,
    };
    let worker2 = Publisher::Worker {
        peer: test_peer(2),
        job: 2,
    };
    assert_eq!(
        service.admit(first.clone(), worker1, ActionMode::Reuse, BTreeMap::new())?,
        NativeAdmission::MissingInputs {
            trees: BTreeSet::from([id])
        }
    );
    let NativeAdmission::Compile { ticket: a } = service.admit(
        first,
        worker1,
        ActionMode::Reuse,
        BTreeMap::from([(id, tree)]),
    )?
    else {
        bail!("metadata-only admission failed");
    };
    let NativeAdmission::Compile { ticket: b } =
        service.admit(second, worker2, ActionMode::Reuse, BTreeMap::new())?
    else {
        bail!("cached manifest admission failed");
    };
    assert_eq!(service.store().stats()?.blobs, 0);
    let ta = service.open_tree(id, worker1, a)?.ticket;
    let tb = service.open_tree(id, worker2, b)?.ticket;
    assert!(service.request_inputs(ta, worker2, vec![blob]).is_err());
    assert!(
        service
            .request_inputs(
                ta,
                worker1,
                vec![BlobRef {
                    id: blob.id,
                    size: blob.size + 1
                }]
            )
            .is_err()
    );
    service.request_inputs(ta, worker1, vec![blob])?;
    service.request_inputs(tb, worker2, vec![blob])?;
    assert_eq!(
        service.poll_input(a)?,
        InputPoll::Demand(InputDemand { tree: id, blob })
    );
    assert_eq!(
        service.poll_input(a)?,
        InputPoll::Demand(InputDemand { tree: id, blob })
    );
    assert_eq!(service.poll_input(b)?, InputPoll::Waiting);
    assert!(service.backfill_input(b, blob, &bytes[..]).is_err());
    assert!(service.backfill_input(a, other, &b"unused"[..]).is_err());
    assert!(
        service
            .download(ta, worker1, blob.id)
            .unwrap_err()
            .is::<NativeContentPending>()
    );
    // A rejected source stream releases its reservation so a different origin can supply it.
    assert!(
        service
            .backfill_input(a, blob, &b"short"[..])
            .unwrap_err()
            .is::<NativeServiceBusy>()
    );
    assert_eq!(
        service.poll_input(a)?,
        InputPoll::Demand(InputDemand { tree: id, blob })
    );
    assert!(
        service
            .backfill_input(a, blob, &b"wrong content!"[..])
            .unwrap_err()
            .is::<NativeInputRejected>()
    );
    assert_eq!(
        service.poll_input(b)?,
        InputPoll::Demand(InputDemand { tree: id, blob })
    );
    service.backfill_input(b, blob, &bytes[..])?;
    assert_eq!(service.poll_input(a)?, InputPoll::Waiting);
    assert_eq!(service.poll_input(b)?, InputPoll::Waiting);
    for (ticket, worker) in [(ta, worker1), (tb, worker2)] {
        let mut actual = Vec::new();
        decoded_download(&service, ticket, worker, blob.id)?.read_to_end(&mut actual)?;
        assert_eq!(actual, bytes);
        service.close(ticket, worker)?;
    }
    assert_eq!(service.store().stats()?.blobs, 1);
    assert!(service.store().open_available_blob(other)?.is_none());
    assert_eq!(service.active_uploads.load(Ordering::Acquire), 0);
    service.fail(a, worker1)?;
    service.fail(b, worker2)?;
    Ok(())
}

#[test]
fn cancelled_or_staged_source_releases_claim_to_another_live_origin() -> Result<()> {
    for staged in [false, true] {
        exercise_source_release(staged)?;
    }
    Ok(())
}

fn exercise_source_release(staged: bool) -> Result<()> {
    use crate::{TreeEntry, TreePath};
    let directory = tempfile::tempdir()?;
    let service = service(directory.path())?;
    let bytes = b"content";
    let blob = BlobRef {
        id: ContentId::of(bytes),
        size: bytes.len() as u64,
    };
    let root = empty_root().root;
    let tree = TreeManifest {
        root,
        entries: BTreeMap::from([(
            TreePath::new(b"file".to_vec())?,
            TreeEntry::File {
                blob,
                metadata: root,
            },
        )]),
    };
    let id = tree.id()?;
    let mut spec = request()?;
    spec.root = ExecutionRoot {
        id,
        recipe: TreeRecipe::union(root, [id]),
    };
    spec.input_trees = BTreeSet::from([id]);
    let worker = Publisher::Worker {
        peer: test_peer(1),
        job: 1,
    };
    let NativeAdmission::Compile { ticket: a } = service.admit(
        spec.clone(),
        worker,
        ActionMode::Reuse,
        BTreeMap::from([(id, tree)]),
    )?
    else {
        bail!("first admission failed")
    };
    spec.fingerprint
        .components
        .insert("other".into(), ContentId::of(b"other"));
    let NativeAdmission::Compile { ticket: b } =
        service.admit(spec, worker, ActionMode::Reuse, BTreeMap::new())?
    else {
        bail!("second admission failed")
    };
    let ta = service.open_tree(id, worker, a)?.ticket;
    let tb = service.open_tree(id, worker, b)?.ticket;
    service.request_inputs(ta, worker, vec![blob])?;
    service.request_inputs(tb, worker, vec![blob])?;
    assert_eq!(
        service.poll_input(a)?,
        InputPoll::Demand(InputDemand { tree: id, blob })
    );
    assert_eq!(service.poll_input(b)?, InputPoll::Waiting);
    if staged {
        // A worker independently acquired the blob. Mark staging complete
        // even though the origin had already claimed an unnecessary upload.
        assert!(service.inputs_staged(a, Publisher::Client).is_err());
        service.inputs_staged(a, worker)?;
        service.inputs_staged(a, worker)?;
        assert_eq!(service.poll_input(a)?, InputPoll::Complete);
        assert!(service.open_tree(id, worker, a).is_err());
        assert_eq!(service.active_uploads.load(Ordering::Acquire), 0);
    } else {
        service.close(a, Publisher::Client)?;
    }
    // The shared flight survives A, but its dead claim must not retain
    // the global upload slot until B happens to poll it.
    service.reap()?;
    assert_eq!(service.active_uploads.load(Ordering::Acquire), 0);
    assert_eq!(
        service.poll_input(b)?,
        InputPoll::Demand(InputDemand { tree: id, blob })
    );
    service.backfill_input(b, blob, &bytes[..])?;
    assert_eq!(service.active_uploads.load(Ordering::Acquire), 0);
    let mut actual = Vec::new();
    decoded_download(&service, tb, worker, blob.id)?.read_to_end(&mut actual)?;
    assert_eq!(actual, bytes);
    Ok(())
}

#[test]
fn peer_backfill_uses_same_flight_and_falls_back_to_origin() -> Result<()> {
    use crate::{TreeEntry, TreePath};
    let directory = tempfile::tempdir()?;
    let mut service = service(directory.path())?;
    service.limits.peer_discovery_timeout = Duration::from_secs(1);
    let root = empty_root().root;
    let first = BlobRef {
        id: ContentId::of(b"peer bytes"),
        size: 10,
    };
    let second = BlobRef {
        id: ContentId::of(b"origin bytes"),
        size: 12,
    };
    let third = BlobRef {
        id: ContentId::of(b"late peer"),
        size: 9,
    };
    let tree = TreeManifest {
        root,
        entries: BTreeMap::from([
            (
                TreePath::new(b"first".to_vec())?,
                TreeEntry::File {
                    blob: first,
                    metadata: root,
                },
            ),
            (
                TreePath::new(b"second".to_vec())?,
                TreeEntry::File {
                    blob: second,
                    metadata: root,
                },
            ),
            (
                TreePath::new(b"third".to_vec())?,
                TreeEntry::File {
                    blob: third,
                    metadata: root,
                },
            ),
        ]),
    };
    let id = tree.id()?;
    let mut spec = request()?;
    spec.root = ExecutionRoot {
        id,
        recipe: TreeRecipe::union(root, [id]),
    };
    spec.input_trees = BTreeSet::from([id]);
    let peer = test_peer(1);
    let worker = Publisher::Worker { peer, job: 1 };
    let NativeAdmission::Compile { ticket } = service.admit(
        spec,
        worker,
        ActionMode::Reuse,
        BTreeMap::from([(id, tree)]),
    )?
    else {
        bail!("metadata-only admission failed");
    };
    let delivery = service.open_tree(id, worker, ticket)?.ticket;
    service.request_inputs(delivery, worker, vec![first])?;
    assert_eq!(service.poll_input(ticket)?, InputPoll::Waiting);
    let claim = service
        .claim_peer_input(Duration::ZERO)?
        .context("peer claim missing")?;
    assert_eq!(claim.blob(), first);
    assert_eq!(claim.requester(), peer);
    assert_eq!(service.poll_input(ticket)?, InputPoll::Waiting);
    assert!(service.claim_peer_input(Duration::ZERO)?.is_none());
    service.recover_peer_input(
        claim,
        Instant::now() + Duration::from_secs(1),
        |blob, store, _| Ok(Some(store.stage_expected(blob, &b"peer bytes"[..])?)),
    )?;
    let mut bytes = Vec::new();
    decoded_download(&service, delivery, worker, first.id)?.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"peer bytes");
    assert_eq!(service.poll_input(ticket)?, InputPoll::Waiting);

    service.request_inputs(delivery, worker, vec![second])?;
    let claim = service
        .claim_peer_input(Duration::ZERO)?
        .context("peer claim missing")?;
    assert_eq!(claim.blob(), second);
    // A wrong peer payload must not become visible; the failed claim
    // releases the same single flight to the origin.
    assert!(
        service
            .recover_peer_input(
                claim,
                Instant::now() + Duration::from_secs(1),
                |_, store, _| { Ok(Some(store.stage(&b"wrong bytes!"[..])?)) }
            )
            .is_err()
    );
    assert!(service.store().open_available_blob(second)?.is_none());
    assert_eq!(
        service.poll_input(ticket)?,
        InputPoll::Demand(InputDemand {
            tree: id,
            blob: second
        })
    );
    service.backfill_input(ticket, second, &b"origin bytes"[..])?;
    bytes.clear();
    decoded_download(&service, delivery, worker, second.id)?.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"origin bytes");

    service.request_inputs(delivery, worker, vec![third])?;
    drop(
        service
            .claim_peer_input(Duration::ZERO)?
            .context("initial peer claim missing")?,
    );
    assert_eq!(
        service.poll_input(ticket)?,
        InputPoll::Demand(InputDemand {
            tree: id,
            blob: third
        })
    );
    let decline = InputDemand {
        tree: id,
        blob: third,
    };
    service.input_unavailable(ticket, decline)?;
    service.input_unavailable(ticket, decline)?; // lost acknowledgement

    assert_eq!(service.poll_input(ticket)?, InputPoll::Waiting);
    let claim = service
        .claim_peer_input(Duration::ZERO)?
        .context("renewed peer claim missing")?;
    drop(claim);
    let flight = service
        .backfills
        .lock()
        .unwrap()
        .get(&third.id)
        .and_then(Weak::upgrade)
        .context("missing flight")?;
    flight.lock()?.peer_retry_at = Some(Instant::now());
    let claim = service
        .claim_peer_input(Duration::ZERO)?
        .context("periodic peer retry missing")?;
    service.recover_peer_input(
        claim,
        Instant::now() + Duration::from_secs(1),
        |blob, store, _| Ok(Some(store.stage_expected(blob, &b"late peer"[..])?)),
    )?;
    bytes.clear();
    decoded_download(&service, delivery, worker, third.id)?.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"late peer");
    assert_eq!(service.active_uploads.load(Ordering::Acquire), 0);
    service.close(delivery, worker)?;
    service.fail(ticket, worker)?;
    Ok(())
}

#[test]
fn evicted_result_is_restored_once_from_only_missing_peer_blobs() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let req = request()?;
    let fingerprint = req.action_fingerprint()?;
    let key = fingerprint.key()?;
    let mut output = manifest(b"peer object");
    let local = BlobRef {
        id: ContentId::of(b"local stderr"),
        size: 12,
    };
    output.stderr = Some(local);
    {
        let service = service(dir.path())?;
        let store = service.store();
        let staged = store.stage_expected(local, &b"local stderr"[..])?;
        store.publish_tree(&NativeStore::blob_retention_manifest(local)?, vec![staged])?;
        let staged =
            store.stage_expected(output.outputs["obj"].test_file_blob(), &b"peer object"[..])?;
        store.publish(&fingerprint, &output, vec![staged], ActionMode::Reuse)?;
        store.evict(key)?;
        store.collect_garbage(32)?;
        assert!(store.lookup(key)?.is_none());
    }
    let mut service = service(dir.path())?;
    service.limits.peer_discovery_timeout = Duration::from_millis(25);
    for _ in 0..2 {
        assert_eq!(
            service.admit(
                req.clone(),
                Publisher::Client,
                ActionMode::Reuse,
                BTreeMap::new()
            )?,
            NativeAdmission::InFlight
        );
    }
    let calls = std::cell::Cell::new(0);
    assert!(
        service.recover_next_result(Duration::ZERO, |blob, store, _| {
            calls.set(calls.get() + 1);
            assert_eq!(blob, output.outputs["obj"].test_file_blob());
            Ok(Some(store.stage_expected(blob, &b"peer object"[..])?))
        })?
    );
    assert_eq!(calls.get(), 1);
    assert!(!service.recover_next_result(Duration::ZERO, |_, _, _| unreachable!())?);
    let NativeAdmission::Hit { ticket, manifest } =
        service.admit(req, Publisher::Client, ActionMode::Reuse, BTreeMap::new())?
    else {
        bail!("recovered result should be a hit");
    };
    assert_eq!(manifest, output);
    let mut data = Vec::new();
    decoded_download(
        &service,
        ticket,
        Publisher::Client,
        output.outputs["obj"].test_file_blob().id,
    )?
    .read_to_end(&mut data)?;
    assert_eq!(data, b"peer object");
    service.close(ticket, Publisher::Client)?;
    assert_eq!(service.active_uploads.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn failed_result_recovery_preserves_partial_content_and_allows_compilation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut service = service(dir.path())?;
    service.limits.peer_discovery_timeout = Duration::from_millis(25);
    let req = request()?;
    let fingerprint = req.action_fingerprint()?;
    let key = fingerprint.key()?;
    let mut output = manifest(b"larger object");
    let missing = BlobRef {
        id: ContentId::of(b"err"),
        size: 3,
    };
    output.stderr = Some(missing);
    let store = service.store();
    let object = output.outputs["obj"].test_file_blob();
    store.publish(
        &fingerprint,
        &output,
        vec![
            store.stage_expected(object, &b"larger object"[..])?,
            store.stage_expected(missing, &b"err"[..])?,
        ],
        ActionMode::Reuse,
    )?;
    store.evict(key)?;
    store.collect_garbage(32)?;
    assert_eq!(
        service.admit(
            req.clone(),
            Publisher::Client,
            ActionMode::Reuse,
            BTreeMap::new()
        )?,
        NativeAdmission::InFlight
    );
    assert!(
        service.recover_next_result(Duration::ZERO, |blob, store, _| {
            if blob == object {
                Ok(Some(store.stage_expected(blob, &b"larger object"[..])?))
            } else {
                assert_eq!(blob, missing);
                Ok(None)
            }
        })?
    );
    assert!(store.open_available_blob(object)?.is_some());
    assert!(store.open_available_blob(missing)?.is_none());
    assert!(store.lookup(key)?.is_none());
    let NativeAdmission::Compile { ticket } = service.admit(
        req.clone(),
        Publisher::Client,
        ActionMode::Reuse,
        BTreeMap::new(),
    )?
    else {
        bail!("failed recovery must permit a fresh build");
    };
    service.close(ticket, Publisher::Client)?;
    let NativeAdmission::Compile { ticket } =
        service.admit(req, Publisher::Client, ActionMode::Refresh, BTreeMap::new())?
    else {
        bail!("explicit refresh must never use recovery");
    };
    service.close(ticket, Publisher::Client)?;
    assert_eq!(service.active_uploads.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn peer_recovery_cannot_consume_last_direct_upload_slot() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut service = service(directory.path())?;
    let mut peers = Vec::new();
    for _ in 0..3 {
        peers.push(service.upload_slot(UploadSource::Peer)?);
    }
    assert!(
        matches!(service.upload_slot(UploadSource::Peer), Err(error) if error.is::<NativeServiceBusy>())
    );
    let direct = service.upload_slot(UploadSource::Direct)?;
    assert!(service.upload_slot(UploadSource::Direct).is_err());
    drop(direct);
    assert!(service.upload_slot(UploadSource::Peer).is_err());
    drop(peers);
    service.limits.max_total_uploads = 1;
    let peer = service.upload_slot(UploadSource::Peer)?;
    assert!(service.upload_slot(UploadSource::Direct).is_err());
    drop(peer);
    assert_eq!(service.active_uploads.load(Ordering::Acquire), 0);
    Ok(())
}

fn test_peer(value: u8) -> crate::PeerId {
    crate::PeerId::from_digest([value; 32])
}

#[test]
fn session_telemetry_reports_contended_tickets_without_waiting() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let service = service(temp.path())?;
    let ticket = service.register(Kind::Action, Publisher::Client, Phase::Failed)?;
    let shared = service.get(ticket)?;
    let state = NativeSessions::lock(&shared)?;
    let original_expiry = state.expires;
    let busy = service
        .telemetry()?
        .tickets
        .context("tickets unavailable")?;
    assert_eq!((busy.registered, busy.busy, busy.failed), (1, 1, 0));
    drop(state);
    let status = service.telemetry()?;
    assert_eq!(status.max_sessions, 8);
    assert_eq!(status.max_uploads, 4);
    let tickets = status.tickets.context("tickets unavailable")?;
    assert_eq!(
        (
            tickets.registered,
            tickets.action,
            tickets.failed,
            tickets.busy
        ),
        (1, 1, 1, 0)
    );
    assert_eq!(NativeSessions::lock(&shared)?.expires, original_expiry);
    let _map = service.sessions()?;
    assert!(service.telemetry()?.tickets.is_none());
    Ok(())
}

#[test]
fn retention_group_survives_action_close_refresh_and_exceeds_action_slots() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let service = service(dir.path())?;
    let owner = test_peer(1);
    let other = test_peer(2);
    let group = service.open_retention(owner)?;
    let expiring = service.open_retention(owner)?;
    let mut retained = Vec::new();
    let key = request()?.action_fingerprint()?.key()?;
    // More results than the entire action ticket capacity. Repeated refresh
    // of one action must not replace already-retained immutable output bytes.
    for value in 0_u8..24 {
        let bytes = [value; 8];
        let result = manifest(&bytes);
        let blob = result.outputs["obj"].test_file_blob();
        let NativeAdmission::Compile { ticket } = service.admit(
            request()?,
            Publisher::Client,
            ActionMode::Refresh,
            BTreeMap::new(),
        )?
        else {
            bail!("expected fresh action");
        };
        assert!(
            service
                .retain_result(group, ticket, result.id()?, owner)
                .is_err()
        );
        service.begin(ticket, Publisher::Client, result.clone())?;
        upload_encoded(&service, ticket, Publisher::Client, blob, &bytes)?;
        service.commit(ticket, Publisher::Client)?;
        assert!(
            service
                .retain_result(group, ticket, result.id()?, other)
                .is_err()
        );
        service.retain_result(group, ticket, result.id()?, owner)?;
        service.retain_result(group, ticket, result.id()?, owner)?;
        if value == 23 {
            service.retain_result(expiring, ticket, result.id()?, owner)?;
        }
        service.close(ticket, Publisher::Client)?;
        retained.push((blob, bytes));
    }
    assert_eq!(service.store().evict(key)?, Eviction::Pinned);
    for (blob, bytes) in retained {
        assert!(service.download_retained(group, other, blob).is_err());
        let (file, encoding) = service.download_retained(group, owner, blob)?;
        let mut reader = crate::BlobReader::open(file, encoding)?;
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual)?;
        assert_eq!(actual, bytes);
    }
    assert!(service.renew_retention(group, other).is_err());
    assert!(service.close_retention(group, other).is_err());
    service.close_retention(group, owner)?;
    assert_eq!(service.store().evict(key)?, Eviction::Pinned);
    // Reaping the remaining group releases its pin without an explicit close.
    assert_eq!(
        service
            .retained
            .reap(Instant::now() + Duration::from_secs(11))?,
        1
    );
    assert!(service.renew_retention(expiring, owner).is_err());
    assert!(!matches!(service.store().evict(key)?, Eviction::Pinned));
    Ok(())
}
