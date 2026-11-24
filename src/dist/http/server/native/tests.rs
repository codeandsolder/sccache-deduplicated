use std::{collections::BTreeMap, io::Cursor};

use super::*;
use crate::{
    build_runtime::{
        Artifact, BlobRef, BuildPath, CommandSpec, ContentId, ExecutionRoot, ExecutionSpec,
        OutputSpec, ResultManifest, SessionLimits, TreeManifest, TreeMetadata, TreeRecipe,
        TreeTimestamp,
        wire::{NativeAdmission, NativeStatus, ScheduleReply, WorkerAllocation},
    },
    dist::{JobId, ServerId, native::NativeCacheClient},
};

struct ClientCheck;

impl ClientAuthCheck for ClientCheck {
    fn check(&self, token: &str) -> std::result::Result<(), super::super::ClientVisibleMsg> {
        if token == "client-token" {
            Ok(())
        } else {
            Err(super::super::ClientVisibleMsg::from_nonsensitive(
                "invalid client".into(),
            ))
        }
    }
}

fn action(root: &TreeManifest) -> Result<ExecutionSpec> {
    let id = root.id()?;
    Ok(ExecutionSpec {
        platform: ContentId::of(b"test-platform"),
        root: ExecutionRoot::resolve(
            TreeRecipe::union(
                TreeMetadata {
                    mode: 0o755,
                    modified: TreeTimestamp {
                        seconds: 1,
                        nanoseconds: 0,
                    },
                },
                [id],
            ),
            &BTreeMap::from([(id, root)]),
        )?,
        mounts: BTreeMap::new(),
        command: CommandSpec {
            executable: BuildPath::new(b"/bin/tool".to_vec())?,
            arguments: Vec::new(),
            cwd: BuildPath::new(b"/".to_vec())?,
            environment: BTreeMap::new(),
        },
        outputs: BTreeMap::from([(
            "obj".into(),
            OutputSpec {
                path: BuildPath::new(b"/out/obj".to_vec())?,
                required: true,
                kind: sccache_build::OutputKind::File,
            },
        )]),
    })
}

fn limits() -> SessionLimits {
    SessionLimits {
        idle_timeout: Duration::from_secs(30),
        max_sessions: 16,
        max_result_bytes: 32 * 1024 * 1024,
        max_result_blobs: 8,
        max_tree_bytes: 64 * 1024 * 1024,
        max_tree_blobs: 100,
        max_concurrent_uploads: 2,
        max_total_uploads: 4,
        max_manifest_cache_bytes: 1024 * 1024,
        peer_discovery_timeout: Duration::ZERO,
    }
}

fn make_client(url: &reqwest::Url, token: &str) -> Result<NativeCacheClient> {
    NativeCacheClient::new(
        url.clone(),
        token.into(),
        Duration::from_secs(10),
        1024 * 1024,
    )
}

#[derive(Debug, PartialEq, Eq)]
enum Observation {
    Staged,
    Negotiated,
    Committed(ResultManifest, Duration),
}

type Observations = Mutex<Vec<(ServerId, JobId, Observation)>>;

fn with_native_service(
    operation: impl FnOnce(&reqwest::Url, &NativeSessions, &NetworkMeter, &Observations) -> Result<()>,
) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let sessions = Arc::new(NativeSessions::new(
        NativeStore::open(directory.path())?,
        limits(),
    )?);
    let worker: ServerId = "127.0.0.1:10501".parse()?;
    let network = Arc::new(NetworkMeter::default());
    let observations = Arc::new(Observations::default());
    let server = rouille::Server::new("127.0.0.1:0", {
        let sessions = Arc::clone(&sessions);
        let network = Arc::clone(&network);
        let observations = Arc::clone(&observations);
        move |request| {
            respond(
                request,
                NativeServices {
                    sessions: &sessions,
                    packages: None,
                    network: &network,
                    observe_result: &|server, job, event| {
                        let result = match event {
                            crate::dist::NativeLifecycleEvent::InputsStaged => Observation::Staged,
                            crate::dist::NativeLifecycleEvent::Negotiated => {
                                Observation::Negotiated
                            }
                            crate::dist::NativeLifecycleEvent::Committed {
                                manifest,
                                retained_after_begin,
                                ..
                            } => Observation::Committed(manifest.clone(), retained_after_begin),
                        };
                        observations.lock().unwrap().push((server, job, result));
                    },
                },
                &move |_, _, _| {
                    Ok(ScheduleReply::Assigned(WorkerAllocation {
                        address: worker.addr(),
                        job: 42,
                        auth: "allocation-proof".into(),
                        certificate: vec![1],
                    }))
                },
                &ClientCheck,
                &move |token| (token == "worker-token").then_some(worker),
                1024 * 1024,
            )
        }
    })
    .map_err(|error| anyhow!("{error}"))?
    .pool_size(4);
    let url = reqwest::Url::parse(&format!("http://{}/", server.server_addr()))?;
    let (handle, stop) = server.stoppable();
    let outcome = operation(&url, &sessions, &network, &observations);
    stop.send(()).map_err(|error| anyhow!("{error}"))?;
    handle
        .join()
        .map_err(|_| anyhow!("native HTTP test server panicked"))?;
    outcome
}

fn verify_compressed_download(
    url: &reqwest::Url,
    ticket: crate::build_runtime::wire::Ticket,
    blob: BlobRef,
    bytes: &[u8],
) -> Result<()> {
    // Negotiation preserves the authenticated verified-bytes contract.
    let compressed = reqwest::blocking::Client::new()
        .post(url.join("/api/v5/native/client/download")?)
        .bearer_auth("client-token")
        .header("Content-Type", "application/octet-stream")
        .body(codec().serialize(&DownloadRequest {
            ticket,
            id: blob.id,
        })?)
        .send()?
        .error_for_status()?;
    assert_eq!(
        compressed
            .headers()
            .get("X-Sccache-CAS-Encoding")
            .context("server skipped native zstd transfer")?
            .as_bytes(),
        b"zstd-chunks"
    );
    let mut decoded = Vec::new();
    crate::build_runtime::transfer_native_blob(
        compressed,
        std::io::sink(),
        &mut decoded,
        blob,
        BlobEncoding::ZstdChunks,
    )?;
    assert_eq!(decoded, bytes);
    Ok(())
}

#[test]
fn direct_worker_upload_and_verified_client_hit_over_http() -> Result<()> {
    with_native_service(|url, sessions, network, observations| {
        let client = make_client(url, "client-token")?;
        let worker_client = make_client(url, "worker-token")?.for_worker(JobId(42));
        let wrong_job = worker_client.clone().for_worker(JobId(43));
        let unauthorized = make_client(url, "bad-token")?;
        let root = TreeManifest {
            root: TreeMetadata {
                mode: 0o755,
                modified: TreeTimestamp {
                    seconds: 1,
                    nanoseconds: 0,
                },
            },
            entries: BTreeMap::new(),
        };
        let offer = client.offer_tree(&root)?;
        assert!(offer.missing.is_empty());
        assert_eq!(client.commit_tree(offer.ticket)?, root.id()?);
        let spec = action(&root)?;

        assert!(
            unauthorized
                .admit(
                    &spec,
                    crate::build_runtime::ActionMode::Reuse,
                    &BTreeMap::new()
                )
                .is_err()
        );

        let NativeAdmission::Compile { ticket } = client.admit(
            &spec,
            crate::build_runtime::ActionMode::Reuse,
            &BTreeMap::new(),
        )?
        else {
            anyhow::bail!("expected compilation");
        };
        assert_eq!(
            client.admit(
                &spec,
                crate::build_runtime::ActionMode::Reuse,
                &BTreeMap::new()
            )?,
            NativeAdmission::InFlight
        );
        let mut wrong_spec = spec.clone();
        wrong_spec.command.arguments.push(b"changed".to_vec());
        assert!(client.schedule(ticket, wrong_spec).is_err());
        let allocation = client.schedule(ticket, spec.clone())?;
        assert!(matches!(allocation, ScheduleReply::Assigned(_)));
        assert_eq!(client.schedule(ticket, spec.clone())?, allocation);
        worker_client.renew(ticket)?;
        worker_client.verify_execution(ticket, spec.clone())?;
        let mut wrong = spec.clone();
        wrong.command.arguments.push(b"changed".to_vec());
        assert!(worker_client.verify_execution(ticket, wrong).is_err());
        assert!(wrong_job.verify_execution(ticket, spec.clone()).is_err());
        client.close(offer.ticket)?;
        assert!(client.renew(ticket).is_err());
        assert!(wrong_job.renew(ticket).is_err());

        let bytes = vec![0x5a; 2 * 1024 * 1024];
        let blob = BlobRef {
            id: ContentId::of(&bytes),
            size: u64::try_from(bytes.len())?,
        };
        let output = ResultManifest {
            outputs: BTreeMap::from([(
                "obj".into(),
                Artifact::File {
                    blob,
                    mode: Some(0o644),
                },
            )]),
            stdout: None,
            stderr: None,
        };
        assert_eq!(
            worker_client.begin(ticket, output.clone())?.missing,
            vec![blob]
        );
        assert!(
            worker_client
                .commit(ticket, Duration::from_secs(300), None)
                .is_err()
        );
        assert!(
            wrong_job
                .commit(ticket, Duration::from_secs(300), None)
                .is_err()
        );
        let owner: ServerId = "127.0.0.1:10501".parse()?;
        assert_eq!(
            *observations.lock().unwrap(),
            vec![(owner, JobId(42), Observation::Negotiated)]
        );
        assert!(
            wrong_job
                .upload(ticket, blob, Cursor::new(bytes.clone()))
                .is_err()
        );
        assert!(
            worker_client
                .upload(ticket, blob, Cursor::new(vec![0; bytes.len()]))
                .is_err()
        );
        worker_client.upload(ticket, blob, Cursor::new(bytes.clone()))?;
        let retention = Duration::from_millis(299_123);
        assert_eq!(worker_client.commit(ticket, retention, None)?, output);
        assert_eq!(
            *observations.lock().unwrap(),
            vec![
                (owner, JobId(42), Observation::Negotiated),
                (
                    owner,
                    JobId(42),
                    Observation::Committed(output.clone(), retention)
                )
            ]
        );
        assert_eq!(client.status(ticket)?, NativeStatus::Ready(output.clone()));
        let mut downloaded = Vec::new();
        client.download(ticket, blob, &mut downloaded)?;
        assert_eq!(downloaded, bytes);
        verify_compressed_download(url, ticket, blob, &bytes)?;
        let measured = network.snapshot();
        let worker = Peer::Worker("127.0.0.1:10501".parse()?);
        let client_peer = Peer::Client("127.0.0.1".parse()?);
        assert!(measured.receive.peers[&worker].body_bytes > 0);
        assert_eq!(measured.receive.peers[&worker].active_remaining_bytes, 0);
        assert!(measured.send.peers[&client_peer].body_bytes > 0);
        assert!(measured.send.peers[&client_peer].body_bytes < blob.size);
        assert!(
            client
                .download(
                    ticket,
                    BlobRef {
                        id: ContentId::of(b"other"),
                        size: 5
                    },
                    Vec::new()
                )
                .is_err()
        );
        assert!(worker_client.status(ticket).is_err());
        let NativeAdmission::Hit {
            ticket: hit,
            manifest,
        } = client.admit(
            &spec,
            crate::build_runtime::ActionMode::Reuse,
            &BTreeMap::new(),
        )?
        else {
            anyhow::bail!("expected stored hit");
        };
        assert_eq!(manifest, output);
        client.close(ticket)?;
        client.close(hit)?;
        assert_eq!(sessions.store().stats()?.blobs, 1);
        Ok(())
    })
}

#[test]
fn raw_physical_transport_preserves_original_magic_prefixed_bytes() -> Result<()> {
    use std::io::{Seek, Write};

    with_native_service(|url, _sessions, _, _| {
        let client = make_client(url, "client-token")?;
        let worker = make_client(url, "worker-token")?.for_worker(JobId(42));
        let root = TreeManifest {
            root: TreeMetadata {
                mode: 0o755,
                modified: TreeTimestamp {
                    seconds: 1,
                    nanoseconds: 0,
                },
            },
            entries: BTreeMap::new(),
        };
        let offered = client.offer_tree(&root)?;
        client.commit_tree(offered.ticket)?;
        let spec = action(&root)?;
        let NativeAdmission::Compile { ticket } = client.admit(
            &spec,
            crate::build_runtime::ActionMode::Reuse,
            &BTreeMap::new(),
        )?
        else {
            anyhow::bail!("expected native compile");
        };
        assert!(matches!(
            client.schedule(ticket, spec)?,
            ScheduleReply::Assigned(_)
        ));
        let original = b"SC-CAS-ZSTD-0002an-original-uncompressed-package-blob";
        let blob = BlobRef {
            id: ContentId::of(original),
            size: u64::try_from(original.len())?,
        };
        let manifest = ResultManifest {
            outputs: BTreeMap::from([(
                "obj".into(),
                Artifact::File {
                    blob,
                    mode: Some(0o644),
                },
            )]),
            stdout: None,
            stderr: None,
        };
        assert_eq!(worker.begin(ticket, manifest.clone())?.missing, vec![blob]);
        let mut raw = tempfile::tempfile()?;
        raw.write_all(original)?;
        raw.rewind()?;
        worker.upload_stored_file(ticket, blob, crate::build_runtime::BlobEncoding::Raw, raw)?;
        assert_eq!(worker.commit(ticket, Duration::ZERO, None)?, manifest);
        let mut received = Vec::new();
        client.download(ticket, blob, &mut received)?;
        assert_eq!(received, original);
        client.close(ticket)?;
        client.close(offered.ticket)?;
        Ok(())
    })
}

#[test]
fn metadata_is_bounded_and_rejects_trailing_bytes() -> Result<()> {
    let request = Request::fake_http(
        "POST",
        "/api/v5/native/client/status",
        Vec::new(),
        vec![0; 33],
    );
    assert!(metadata::<crate::build_runtime::wire::Ticket>(&request, 32).is_err());
    let request = Request::fake_http(
        "POST",
        "/api/v5/native/client/status",
        Vec::new(),
        vec![0; 33],
    );
    assert!(metadata::<crate::build_runtime::wire::Ticket>(&request, 64).is_err());
    let header = UploadHeader {
        ticket: crate::build_runtime::wire::Ticket([7; 32]),
        blob: BlobRef {
            id: ContentId::of(b"abc"),
            size: 3,
        },
        encoding: crate::build_runtime::BlobEncoding::ZstdChunks as u8,
    };
    let encoded = codec().serialize(&header)?;
    assert_eq!(encoded.len(), 73);
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires Linux Bubblewrap and ldd"]
fn native_action_transfers_inputs_executes_and_retains_worker_result() -> Result<()> {
    use crate::build_runtime::ExecutionPolicy;
    use std::{fs, process::Command};
    with_native_service(|url, sessions, _network, _observations| {
        let directory = tempfile::tempdir()?;
        let sender = NativeStore::open(&directory.path().join("sender"))?;
        let worker_store = NativeStore::open(&directory.path().join("worker"))?;
        let root = directory.path().join("root");
        for name in ["bin", "out", "tmp", "proc", "dev", "src"] {
            fs::create_dir_all(root.join(name))?;
        }
        fs::copy("/bin/sh", root.join("bin/tool"))?;
        let dependencies = Command::new("ldd").arg("/bin/sh").output()?;
        ensure!(
            dependencies.status.success(),
            "cannot determine shell dependencies"
        );
        for line in std::str::from_utf8(&dependencies.stdout)?.lines() {
            if let Some(path) = line.split_whitespace().find(|part| part.starts_with('/')) {
                let destination = root.join(path.strip_prefix('/').context("library path")?);
                fs::create_dir_all(destination.parent().context("library parent")?)?;
                fs::copy(path, destination)?;
            }
        }
        let root = sender.capture_tree(&root)?;
        let source = directory.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("input"), b"hello native\n")?;
        let source = sender.capture_tree(&source)?;
        let client = make_client(url, "client-token")?;
        let worker = make_client(url, "worker-token")?.for_worker(JobId(42));
        let root_pin = client.push_tree(
            root.manifest(),
            |id| root.open_decoded(id),
            Duration::from_secs(1),
        )?;
        let source_pin = client.push_tree(
            source.manifest(),
            |id| source.open_decoded(id),
            Duration::from_secs(1),
        )?;
        let mut spec = action(root.manifest())?;
        spec.mounts
            .insert(BuildPath::new(b"/src".to_vec())?, source.id());
        spec.command.arguments = vec![b"-c".to_vec(), b"IFS= read -r data < /src/input; printf '%s' \"$data\" > /out/obj; printf diagnostic >&2".to_vec()];
        let NativeAdmission::Compile { ticket } = client.admit(
            &spec,
            crate::build_runtime::ActionMode::Reuse,
            &BTreeMap::new(),
        )?
        else {
            anyhow::bail!("expected native compilation");
        };
        assert!(matches!(
            client.schedule(ticket, spec.clone())?,
            ScheduleReply::Assigned(_)
        ));
        client.close(root_pin)?;
        client.close(source_pin)?;
        let policy = ExecutionPolicy {
            platform: spec.platform,
            bubblewrap: "/usr/bin/bwrap".into(),
            scratch: directory.path().into(),
            timeout: Duration::from_secs(10),
            max_result_bytes: 1024,
        };
        let transport = crate::dist::native::PackageTransportTracker::new(
            crate::build_runtime::wire::WorkerTiming::default(),
        )?;
        let execution_queue =
            crate::dist::execution_queue::ExecutionQueue::new(std::num::NonZeroUsize::MIN);
        let artifact_grace =
            crate::dist::native::ArtifactGrace::new(Duration::from_secs(300), 1024)?;
        let delivery = crate::dist::native::WorkerDelivery {
            renewal_interval: Duration::from_secs(1),
            package_import: None,
            transport: &transport,
            execution_queue: &execution_queue,
            artifact_grace: &artifact_grace,
        };
        let busy = execution_queue.acquire(|| Ok(()))?;
        let prepared = worker.prepare_on_worker(
            ticket,
            &spec,
            &worker_store,
            &policy,
            delivery,
            crate::dist::native::WorkerPreparation {
                estimated_result_bytes: None,
                cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                on_tree: &mut |_| {},
                on_authorized: &|| Ok(()),
            },
        )?;
        assert_eq!(execution_queue.active(), 1);
        drop(busy);
        let completed = prepared.execute(&worker_store, &policy, delivery, || {
            assert_eq!(execution_queue.active(), 1)
        });
        assert_eq!(execution_queue.active(), 0);
        let result = completed.publish(&worker_store, &policy, &transport)?;
        let manifest = result
            .successful_result()
            .context("native execution failed")?;
        assert_eq!(
            client.status(ticket)?,
            NativeStatus::Ready(manifest.clone())
        );
        let mut bytes = Vec::new();
        let Artifact::File { blob, .. } = &manifest.outputs["obj"] else {
            anyhow::bail!("expected file output");
        };
        client.download(ticket, *blob, &mut bytes)?;
        assert_eq!(bytes, b"hello native");
        bytes.clear();
        client.download(
            ticket,
            manifest.stderr.context("missing diagnostics")?,
            &mut bytes,
        )?;
        assert_eq!(bytes, b"diagnostic");
        assert_eq!(worker_store.stats()?.actions, 1);
        let key = spec.action_request()?.action_fingerprint()?.key()?;
        assert_eq!(
            worker_store.evict(key)?,
            crate::build_runtime::Eviction::Pinned
        );
        assert_eq!(
            worker_store
                .lookup(key)?
                .context("worker output missing")?
                .manifest(),
            manifest
        );
        assert_eq!(sessions.store().stats()?.actions, 1);
        let NativeAdmission::Hit {
            ticket: hit,
            manifest: cached,
        } = client.admit(
            &spec,
            crate::build_runtime::ActionMode::Reuse,
            &BTreeMap::new(),
        )?
        else {
            anyhow::bail!("expected cache hit");
        };
        assert_eq!(&cached, manifest);
        client.close(ticket)?;
        client.close(hit)?;
        Ok(())
    })
}

#[test]
fn physical_blob_response_preserves_content_and_reuses_encoded_files() -> Result<()> {
    use std::io::{Seek as _, Write as _};
    let compressible = vec![b'Z'; 256 * 1024];
    let noise: Vec<u8> = (0..8192_u64)
        .flat_map(|i| *blake3::hash(&i.to_le_bytes()).as_bytes())
        .collect();
    for original in [compressible, noise] {
        let blob = BlobRef {
            id: ContentId::of(&original),
            size: u64::try_from(original.len())?,
        };
        let mut raw = tempfile::tempfile()?;
        raw.write_all(&original)?;
        raw.rewind()?;
        let response = physical_blob_response(raw, BlobEncoding::Raw)?;
        assert!(
            response
                .headers
                .iter()
                .any(|(name, value)| name == "X-Sccache-CAS-Encoding" && value == "zstd-chunks")
        );
        let (stream, size) = response.data.into_reader_and_size();
        let mut encoded = tempfile::tempfile()?;
        let mut decoded = Vec::new();
        crate::build_runtime::transfer_native_blob(
            stream,
            &mut encoded,
            &mut decoded,
            blob,
            BlobEncoding::ZstdChunks,
        )?;
        assert_eq!(decoded, original);
        encoded.rewind()?;
        let (stream, reused_size) = physical_blob_response(encoded, BlobEncoding::ZstdChunks)?
            .data
            .into_reader_and_size();
        assert_eq!(size, reused_size);
        let mut decoded = Vec::new();
        crate::build_runtime::transfer_native_blob(
            stream,
            std::io::sink(),
            &mut decoded,
            blob,
            BlobEncoding::ZstdChunks,
        )?;
        assert_eq!(decoded, original);
    }
    Ok(())
}

#[test]
fn lazy_admission_prefetch_and_origin_backfill_over_http() -> Result<()> {
    use crate::build_runtime::{
        TreeEntry, TreePath,
        wire::{InputDemand, InputPoll},
    };
    with_native_service(|url, sessions, _network, observations| {
        let client = make_client(url, "client-token")?;
        let worker = make_client(url, "worker-token")?.for_worker(JobId(42));
        let metadata = TreeMetadata {
            mode: 0o755,
            modified: TreeTimestamp {
                seconds: 1,
                nanoseconds: 0,
            },
        };
        let bytes = b"missing from scheduler";
        let missing = BlobRef {
            id: ContentId::of(bytes),
            size: u64::try_from(bytes.len())?,
        };
        let unused = BlobRef {
            id: ContentId::of(b"already on worker"),
            size: 17,
        };
        let root = TreeManifest {
            root: metadata,
            entries: BTreeMap::from([
                (
                    TreePath::new(b"missing".to_vec())?,
                    TreeEntry::File {
                        blob: missing,
                        metadata,
                    },
                ),
                (
                    TreePath::new(b"unused".to_vec())?,
                    TreeEntry::File {
                        blob: unused,
                        metadata,
                    },
                ),
            ]),
        };
        let id = root.id()?;
        let spec = action(&root)?;
        let NativeAdmission::Compile { ticket } =
            client.admit(&spec, ActionMode::Reuse, &BTreeMap::from([(id, root)]))?
        else {
            anyhow::bail!("metadata-only admission failed");
        };
        assert_eq!(sessions.store().stats()?.blobs, 0);
        assert!(matches!(
            client.schedule(ticket, spec)?,
            ScheduleReply::Assigned(_)
        ));
        let read = worker.open_tree(ticket, id)?;
        let request = reqwest::blocking::Client::new();
        let prefetch = InputPrefetchRequest {
            ticket: read.ticket,
            missing: vec![missing],
        };
        request
            .post(url.join("/api/v5/native/worker/input_prefetch")?)
            .bearer_auth("worker-token")
            .header("Content-Type", "application/octet-stream")
            .header("X-Sccache-Native-Job", "42")
            .body(codec().serialize(&prefetch)?)
            .send()?
            .error_for_status()?;
        let pending = request
            .post(url.join("/api/v5/native/worker/download")?)
            .bearer_auth("worker-token")
            .header("Content-Type", "application/octet-stream")
            .header("X-Sccache-Native-Job", "42")
            .body(codec().serialize(&DownloadRequest {
                ticket: read.ticket,
                id: missing.id,
            })?)
            .send()?;
        assert_eq!(pending.status(), reqwest::StatusCode::ACCEPTED);
        assert_eq!(
            client.poll_input(ticket)?,
            InputPoll::Demand(InputDemand {
                tree: id,
                blob: missing
            })
        );
        client.backfill_input(ticket, missing, Cursor::new(bytes))?;
        let mut actual = Vec::new();
        worker.download(read.ticket, missing, &mut actual)?;
        assert_eq!(actual, bytes);
        assert_eq!(client.poll_input(ticket)?, InputPoll::Waiting);
        assert_eq!(sessions.store().stats()?.blobs, 1);
        assert!(sessions.store().open_available_blob(unused)?.is_none());
        worker.close(read.ticket)?;
        assert!(client.inputs_staged(ticket).is_err());
        assert!(
            make_client(url, "worker-token")?
                .for_worker(JobId(43))
                .inputs_staged(ticket)
                .is_err()
        );
        assert!(observations.lock().unwrap().is_empty());
        worker.inputs_staged(ticket)?;
        worker.inputs_staged(ticket)?;
        let owner: ServerId = "127.0.0.1:10501".parse()?;
        assert_eq!(
            *observations.lock().unwrap(),
            vec![
                (owner, JobId(42), Observation::Staged),
                (owner, JobId(42), Observation::Staged),
            ]
        );
        assert_eq!(client.poll_input(ticket)?, InputPoll::Complete);
        worker.fail(ticket)?;
        client.close(ticket)?;
        Ok(())
    })
}
