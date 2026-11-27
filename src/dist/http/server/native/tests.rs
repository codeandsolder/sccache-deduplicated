use sccache_cluster_identity::{
    ClusterCa, EnrollmentAuthority, Identity, PeerConfig, PeerCredentials, Registry, Role,
    TlsCredentials,
};
use std::{
    collections::BTreeMap,
    io::{Cursor, Seek},
    sync::Mutex,
};

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

fn action(root: &TreeManifest) -> Result<ExecutionSpec> {
    let id = root.id()?;
    Ok(ExecutionSpec {
        compiler_result: None,
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
            umask: 0o022,
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

struct TestEndpoint {
    url: url::Url,
    scheduler: ServerId,
    client: Arc<PeerCredentials>,
    rejected_config: PeerConfig,
    worker: Arc<PeerCredentials>,
    sources: Arc<Mutex<BTreeMap<ContentId, Vec<BlobSource>>>>,
}
fn make_client(endpoint: &TestEndpoint, token: &str) -> Result<NativeCacheClient> {
    let peer = match token {
        "client-token" => &endpoint.client,
        "worker-token" => &endpoint.worker,
        _ => {
            let token = token.to_owned();
            return NativeCacheClient::new(
                &endpoint.url,
                crate::dist::cluster::open_peer(
                    endpoint.rejected_config.clone(),
                    &endpoint.url,
                    Role::Client,
                    move || Ok(token.clone()),
                )?,
                Duration::from_secs(10),
                1024 * 1024,
            );
        }
    };
    NativeCacheClient::new(
        &endpoint.url,
        Arc::clone(peer),
        Duration::from_secs(10),
        1024 * 1024,
    )
}
impl TestEndpoint {
    fn raw(&self, peer: &PeerCredentials) -> Result<(wreq::Client, url::Url)> {
        let credential = peer.current()?;
        let transport = sccache_cluster_identity::ClusterHttpClient::new(
            &credential,
            self.scheduler,
            Role::Scheduler,
            sccache_cluster_identity::endpoint(&self.url)?,
        )?;
        Ok((transport.client(), transport.base().clone()))
    }
}
#[derive(Debug, PartialEq, Eq)]
enum Observation {
    Staged,
    Negotiated,
    Committed(ResultManifest, Duration),
}

type Observations = Mutex<Vec<(ServerId, JobId, Observation)>>;

fn with_native_service(
    operation: impl FnOnce(&TestEndpoint, &NativeSessions, &NetworkMeter, &Observations) -> Result<()>,
) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let sessions = Arc::new(NativeSessions::new(
        NativeStore::open(directory.path())?,
        limits(),
    )?);
    let cluster = directory.path().join("cluster");
    std::fs::create_dir_all(&cluster)?;
    let authority = EnrollmentAuthority::new(
        ClusterCa::open(&cluster.join("ca-key.pem"))?,
        Registry::initialize(&cluster.join("registry.bin"))?,
        7,
    )?;
    let identity = Identity::open(&cluster.join("key.pem"))?;
    let scheduler = identity.id()?;
    let leaf = authority.scheduler_certificate(&identity)?;
    let ca_certificate = cluster.join("ca.pem");
    sccache_cluster_identity::publish_trust_anchor(authority.certificate(), &ca_certificate)?;
    let credential = TlsCredentials::new(
        identity,
        leaf,
        authority.certificate().clone(),
        Role::Scheduler,
    )?;
    let tls = Arc::new(ClusterListener::new(&credential)?);
    let client_config = PeerConfig {
        directory: cluster.join("client"),
        ca_certificate,
        scheduler_id: scheduler,
    };
    let worker_config = PeerConfig {
        directory: cluster.join("worker"),
        ..client_config.clone()
    };
    let worker = sccache_cluster_identity::open_identity(&worker_config)?.id()?;
    let enrollment = Arc::new(SchedulerEnrollment::new(
        authority,
        move |role, id, _, token| match role {
            Role::Client => token == "client-token",
            Role::Worker => id == worker && token == "worker-token",
            Role::Scheduler => false,
        },
    ));
    let network = Arc::new(NetworkMeter::default());
    let observations = Arc::new(Observations::default());
    let sources = Arc::new(Mutex::new(BTreeMap::<ContentId, Vec<BlobSource>>::new()));
    let server = Listener::bind(
        "127.0.0.1:0".parse()?,
        tls,
        ListenerRole::Scheduler(enrollment),
        4,
        {
            let sessions = Arc::clone(&sessions);
            let network = Arc::clone(&network);
            let observations = Arc::clone(&observations);
            let sources = Arc::clone(&sources);
            let schedule_sessions = Arc::clone(&sessions);
            let schedule_network = Arc::clone(&network);
            let upload_sessions = Arc::clone(&sessions);
            let upload_network = Arc::clone(&network);
            let observe_result: Arc<ResultObserver<'static>> =
                Arc::new(move |server, job, event| {
                    let result = match event {
                        crate::dist::NativeLifecycleEvent::Delivered(_) => return,
                        crate::dist::NativeLifecycleEvent::InputsStaged => Observation::Staged,
                        crate::dist::NativeLifecycleEvent::Negotiated => Observation::Negotiated,
                        crate::dist::NativeLifecycleEvent::Committed {
                            manifest,
                            retained_after_begin,
                            ..
                        } => Observation::Committed(manifest.clone(), retained_after_begin),
                    };
                    observations.lock().unwrap().push((server, job, result));
                });
            let commit_routes = CommitRoutes {
                sessions: Arc::clone(&sessions),
                observe_result: Arc::clone(&observe_result),
            };
            native_router(
                move |request, role, operation| {
                    respond(
                        request,
                        role,
                        operation,
                        NativeServices {
                            sessions: &sessions,
                            packages: None,
                            network: &network,
                            source_plan: &|blob, _, _| {
                                Ok(sources
                                    .lock()
                                    .unwrap()
                                    .get(&blob.id)
                                    .cloned()
                                    .unwrap_or_default())
                            },
                            observe_result: observe_result.as_ref(),
                        },
                        1024 * 1024,
                    )
                },
                move |request| {
                    schedule_response(
                        request,
                        Arc::clone(&schedule_sessions),
                        Arc::clone(&schedule_network),
                        Arc::new(move |_, _, _| async move {
                            Ok(ScheduleReply::Assigned(WorkerAllocation {
                                peer: worker,
                                routes: sccache_peer_identity::RouteSet::new(
                                    "127.0.0.1:10501".parse().unwrap(),
                                    [],
                                ),
                                job: 42,
                                auth: "allocation-proof".into(),
                            }))
                        }),
                        1024 * 1024,
                    )
                },
                move |request, role, operation| {
                    upload_response(
                        request,
                        role,
                        operation,
                        Arc::clone(&upload_sessions),
                        Arc::clone(&upload_network),
                        1024 * 1024,
                    )
                },
                &commit_routes,
                None,
                1024 * 1024,
            )
        },
    )?;
    let url = url::Url::parse(&format!("https://{}/", server.local_addr()?))?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let handle = thread::spawn(move || server.run_until(stopped));
    let outcome = (|| {
        let rejected_config = PeerConfig {
            directory: cluster.join("rejected"),
            ..client_config.clone()
        };
        let client = crate::dist::cluster::open_peer(client_config, &url, Role::Client, || {
            Ok("client-token".into())
        })?;
        let worker = crate::dist::cluster::open_peer(worker_config, &url, Role::Worker, || {
            Ok("worker-token".into())
        })?;
        let endpoint = TestEndpoint {
            url,
            scheduler,
            client,
            rejected_config,
            worker,
            sources,
        };
        operation(&endpoint, &sessions, &network, &observations)
    })();
    let _ = stop.send(());
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("native HTTPS test server panicked"))??;
    outcome
}

fn verify_compressed_download(
    endpoint: &TestEndpoint,
    ticket: crate::build_runtime::wire::Ticket,
    blob: BlobRef,
    bytes: &[u8],
) -> Result<()> {
    // Negotiation preserves the authenticated verified-bytes contract.
    let (http, url) = endpoint.raw(&endpoint.client)?;
    let compressed = crate::http_client::io_runtime()?
        .block_on(
            http.post(url.join("/api/v5/native/client/download")?.as_str())
                .bearer_auth("client-token")
                .header("Content-Type", "application/octet-stream")
                .body(codec().serialize(&DownloadRequest {
                    ticket,
                    id: blob.id,
                })?)
                .timeout(Duration::from_secs(10))
                .send(),
        )?
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
        crate::http_client::ResponseReader::new(compressed)?,
        std::io::sink(),
        &mut decoded,
        blob,
        BlobEncoding::ZstdChunks,
    )?;
    assert_eq!(decoded, bytes);
    Ok(())
}

fn verify_peer_delivery(
    endpoint: &TestEndpoint,
    client: &NativeCacheClient,
    ticket: crate::build_runtime::wire::Ticket,
    blob: BlobRef,
    bytes: &[u8],
    network: &NetworkMeter,
    committed: bool,
) -> Result<()> {
    use crate::dist::JobAuthorizer;
    use std::{
        io::Write,
        sync::atomic::{AtomicBool, Ordering},
    };
    let worker = endpoint.worker.current()?;
    let worker_id = worker.id()?;
    let authorizer = super::super::JWTJobAuthorizer::boxed(&[7; super::super::JWT_KEY_LENGTH])?;
    let recipient = BlobRecipient::Client(endpoint.client.current()?.id()?);
    let token = authorizer.generate_blob_token(blob, recipient)?;
    let revocations = Arc::new(super::super::cluster_http::Revocations::default());
    revocations.update(Vec::new());
    let bad = Arc::new(AtomicBool::new(false));
    let server = Listener::bind(
        "127.0.0.1:0".parse()?,
        Arc::new(ClusterListener::new(&worker)?),
        ListenerRole::Worker {
            scheduler: endpoint.scheduler,
            revocations,
        },
        2,
        {
            let bytes = bytes.to_vec();
            let bad = Arc::clone(&bad);
            routes(
                Router::new().route(
                    "/api/v3/distserver/native_blob",
                    super::super::cluster_http::route(
                        MethodFilter::POST,
                        AdmissionClass::Bulk,
                        |_| Some(40),
                        move |_: &(), request| {
                            serve_peer_blob(request, &*authorizer, |requested| {
                                if requested != blob {
                                    return Ok(None);
                                }
                                let mut file = tempfile::tempfile()?;
                                if bad.load(Ordering::Relaxed) {
                                    file.write_all(b"corrupt")?;
                                } else {
                                    file.write_all(&bytes)?;
                                }
                                file.rewind()?;
                                Ok(Some((file, BlobEncoding::Raw)))
                            })
                            .unwrap_or_else(|_| {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "test peer response failed",
                                )
                                    .into_response()
                            })
                        },
                    ),
                ),
                (),
            )
        },
    )?;
    let address = server.local_addr()?;
    endpoint.sources.lock().unwrap().insert(
        blob.id,
        vec![BlobSource {
            peer: worker_id,
            routes: sccache_peer_identity::RouteSet::new(address, []),
            token,
        }],
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let handle = thread::spawn(move || server.run_until(stopped));
    let outcome = (|| {
        let plans = client.source_plans(ticket, &[blob]);
        let plan = plans
            .get(&blob.id)
            .context("missing authorized result source")?;
        assert_eq!(plan.scheduler_present, committed);
        assert_eq!(plan.sources.len(), 1);
        // The source grant comes from the live scheduler, but the configured
        // data fallback is deliberately unavailable. The worker must supply
        // the bytes directly without contacting that data listener.
        let unavailable = std::net::TcpListener::bind("127.0.0.1:0")?;
        let base = url::Url::parse(&format!("https://{}/", unavailable.local_addr()?))?;
        let direct = NativeCacheClient::new(
            &base,
            Arc::clone(&endpoint.client),
            Duration::from_secs(10),
            1024 * 1024,
        )?;
        let before = network
            .snapshot()
            .send
            .peers
            .values()
            .map(|peer| peer.body_bytes)
            .sum::<u64>();
        let receive = |reader, encoding| {
            let mut output = Vec::new();
            crate::build_runtime::transfer_native_blob(
                reader,
                std::io::sink(),
                &mut output,
                blob,
                encoding,
            )?;
            Ok(output)
        };
        assert_eq!(
            direct
                .try_peer_blob(plan, receive)
                .context("direct worker delivery failed")?,
            bytes
        );
        let after = network
            .snapshot()
            .send
            .peers
            .values()
            .map(|peer| peer.body_bytes)
            .sum::<u64>();
        assert_eq!(before, after);
        bad.store(true, Ordering::Relaxed);
        assert!(direct.try_peer_blob(plan, receive).is_none());
        // The durable scheduler copy still restores the result, without a rerun.
        if committed {
            let mut fallback = Vec::new();
            client.download(ticket, blob, &mut fallback)?;
            assert_eq!(fallback, bytes);
        } else {
            assert!(client.download(ticket, blob, Vec::new()).is_err());
        }
        Ok(())
    })();
    let _ = stop.send(());
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("peer delivery test listener panicked"))??;
    endpoint.sources.lock().unwrap().remove(&blob.id);
    outcome
}

#[test]
fn stalled_bulk_uploads_leave_lease_and_dispatch_lanes_available() -> Result<()> {
    use crate::build_runtime::{TreeEntry, TreePath};
    use bytes::Bytes;
    use futures::{StreamExt, stream};

    with_native_service(|endpoint, _, network, _| {
        let client = make_client(endpoint, "client-token")?;
        let worker = make_client(endpoint, "worker-token")?.for_worker(JobId(42));
        let metadata = TreeMetadata {
            mode: 0o755,
            modified: TreeTimestamp {
                seconds: 1,
                nanoseconds: 0,
            },
        };
        let root = TreeManifest {
            root: metadata,
            entries: BTreeMap::new(),
        };
        let offer = client.offer_tree(&root)?;
        client.commit_tree(offer.ticket)?;
        let spec = action(&root)?;
        let NativeAdmission::Compile { ticket } = client.admit(
            &spec,
            crate::build_runtime::ActionMode::Reuse,
            &BTreeMap::new(),
        )?
        else {
            anyhow::bail!("expected compilation");
        };

        let (http, base) = endpoint.raw(&endpoint.client)?;
        let upload_url = base.join("/api/v5/native/client/upload")?;
        let runtime = crate::http_client::io_runtime()?;
        let mut uploads = Vec::new();
        const PAYLOAD: usize = 256 * 1024;
        for byte in 0_u8..4 {
            let bytes = vec![byte; PAYLOAD];
            let blob = BlobRef {
                id: ContentId::of(&bytes),
                size: PAYLOAD as u64,
            };
            let tree = TreeManifest {
                root: metadata,
                entries: BTreeMap::from([(
                    TreePath::new(b"input".to_vec())?,
                    TreeEntry::File { blob, metadata },
                )]),
            };
            let offer = client.offer_tree(&tree)?;
            assert_eq!(offer.missing, vec![blob]);
            let header = codec().serialize(&UploadHeader {
                ticket: offer.ticket,
                blob,
                encoding: BlobEncoding::Raw as u8,
            })?;
            let (resume, paused) = tokio::sync::oneshot::channel::<()>();
            let stream = stream::once(async move { Ok::<_, std::io::Error>(Bytes::from(header)) })
                .chain(stream::once(async move {
                    paused.await.map_err(std::io::Error::other)?;
                    Ok(Bytes::from(bytes))
                }));
            let request = http
                .post(upload_url.as_str())
                .header("Content-Type", "application/octet-stream")
                .body(wreq::Body::wrap_stream(stream))
                .timeout(Duration::from_secs(20));
            uploads.push((
                resume,
                runtime.spawn(async move { request.send().await }),
                offer.ticket,
                tree.id()?,
            ));
        }

        // The transfer meters are installed only after the authenticated
        // upload header has been parsed and its staging reservation acquired.
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let remaining: u64 = network
                        .snapshot()
                        .receive
                        .peers
                        .values()
                        .map(|peer| peer.active_remaining_bytes)
                        .sum();
                    if remaining >= 4 * PAYLOAD as u64 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
        })?;

        let rejected = runtime.block_on(
            http.post(upload_url.as_str())
                .header("Content-Type", "application/octet-stream")
                .body(Vec::new())
                .timeout(Duration::from_secs(3))
                .send(),
        )?;
        assert_eq!(rejected.status(), http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(client.status(ticket)?, NativeStatus::Compiling);
        client.renew(ticket)?;
        assert!(matches!(
            client.schedule(ticket, spec)?,
            ScheduleReply::Assigned(_)
        ));
        worker.renew(ticket)?;

        // Resume each valid upload, and verify all four reservations can publish.
        let tasks = uploads
            .into_iter()
            .map(|(resume, task, ticket, id)| {
                resume
                    .send(())
                    .map_err(|()| anyhow::anyhow!("upload stopped before resume"))?;
                Ok((task, ticket, id))
            })
            .collect::<Result<Vec<_>>>()?;
        for (task, ticket, id) in tasks {
            runtime.block_on(task)??.error_for_status()?;
            assert_eq!(client.commit_tree(ticket)?, id);
        }
        Ok(())
    })
}

#[test]
fn direct_worker_upload_and_verified_client_hit_over_http() -> Result<()> {
    with_native_service(|url, sessions, network, observations| {
        let client = make_client(url, "client-token")?;
        let worker_client = make_client(url, "worker-token")?.for_worker(JobId(42));
        let wrong_job = worker_client.clone().for_worker(JobId(43));
        let unauthorized = make_client(url, "bad-token");
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

        assert!(unauthorized.is_err());

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
        let (begin, width) = crate::http_client::io_runtime()?
            .block_on(worker_client.begin_result_upload(ticket, output.clone()))?;
        assert_eq!(begin.missing, vec![blob]);
        assert_eq!(
            width.map(std::num::NonZeroUsize::get),
            Some(limits().max_concurrent_uploads)
        );
        assert_eq!(client.status(ticket)?, NativeStatus::Compiling);
        assert_eq!(
            sessions.status_with_preview(ticket, true)?,
            NativeStatus::Negotiated(output.clone())
        );
        assert_eq!(
            sessions.authorize_blob_sources(ticket, Publisher::Client, &[blob])?,
            (Some(url.worker.current()?.id()?), vec![false])
        );
        assert!(
            sessions
                .download(ticket, Publisher::Client, blob.id)
                .unwrap_err()
                .is::<NativeContentPending>()
        );
        assert!(
            sessions
                .authorize_blob_sources(
                    ticket,
                    Publisher::Client,
                    &[BlobRef {
                        size: blob.size + 1,
                        ..blob
                    }]
                )
                .is_err()
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
        let owner = url.worker.current()?.id()?;
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
        verify_peer_delivery(url, &client, ticket, blob, &bytes, network, false)?;
        worker_client.upload(ticket, blob, Cursor::new(bytes.clone()))?;
        let retention = Duration::from_millis(299_123);
        assert_eq!(worker_client.commit(ticket, retention, None)?, output);
        assert_eq!(
            sessions.authorize_blob_sources(ticket, Publisher::Client, &[blob])?,
            (Some(owner), vec![true])
        );
        assert!(
            sessions
                .authorize_blob_sources(
                    ticket,
                    Publisher::Client,
                    &[BlobRef {
                        size: blob.size + 1,
                        ..blob
                    }]
                )
                .is_err()
        );
        assert!(
            sessions
                .authorize_blob_sources(ticket, Publisher::Client, &[])
                .is_err()
        );
        let (http, base) = url.raw(&url.client)?;
        let source_request = |blobs: Vec<BlobRef>| -> Result<wreq::Response> {
            Ok(crate::http_client::io_runtime()?.block_on(
                http.post(base.join("/api/v5/native/client/blob_sources")?.as_str())
                    .header("Content-Type", "application/octet-stream")
                    .body(codec().serialize(&BlobSourceRequest { ticket, blobs })?)
                    .timeout(Duration::from_secs(10))
                    .send(),
            )?)
        };
        assert_eq!(source_request(vec![blob])?.status(), http::StatusCode::OK);
        assert!(
            !source_request(vec![BlobRef {
                size: blob.size + 1,
                ..blob
            }])?
            .status()
            .is_success()
        );
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
        verify_peer_delivery(url, &client, ticket, blob, &bytes, network, true)?;
        let mut downloaded = Vec::new();
        client.download(ticket, blob, &mut downloaded)?;
        assert_eq!(downloaded, bytes);
        verify_compressed_download(url, ticket, blob, &bytes)?;
        let measured = network.snapshot();
        let ip = std::net::Ipv4Addr::LOCALHOST.into();
        let path = crate::build_runtime::NetworkPath::new(ip, ip);
        let worker = Peer::Worker(url.worker.current()?.id()?).on_path(path);
        let client_peer = Peer::Client(url.client.current()?.id()?).on_path(path);
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

fn admit_empty_action(
    client: &NativeCacheClient,
) -> Result<(
    crate::build_runtime::wire::Ticket,
    crate::build_runtime::wire::Ticket,
)> {
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
    Ok((ticket, offered.ticket))
}

#[test]
fn result_upload_backpressure_preserves_negotiated_transfer() -> Result<()> {
    with_native_service(|endpoint, sessions, _, _| {
        let client = make_client(endpoint, "client-token")?;
        let worker = make_client(endpoint, "worker-token")?.for_worker(JobId(42));
        let (ticket, offered) = admit_empty_action(&client)?;
        let blob = |bytes: &[u8]| BlobRef {
            id: ContentId::of(bytes),
            size: bytes.len() as u64,
        };
        let (object, stdout, stderr) = (blob(b"object"), blob(b"stdout"), blob(b"stderr"));
        let manifest = ResultManifest {
            outputs: BTreeMap::from([(
                "obj".into(),
                Artifact::File {
                    blob: object,
                    mode: Some(0o644),
                },
            )]),
            stdout: Some(stdout),
            stderr: Some(stderr),
        };
        let (reply, width) = crate::http_client::io_runtime()?
            .block_on(worker.begin_result_upload(ticket, manifest.clone()))?;
        assert_eq!(width.map(std::num::NonZeroUsize::get), Some(2));
        assert_eq!(reply.missing.len(), 3);
        let publisher = Publisher::Worker {
            peer: endpoint.worker.current()?.id()?,
            job: 42,
        };
        let first = sessions.prepare_upload(ticket, publisher, object, BlobEncoding::Raw)?;
        let second = sessions.prepare_upload(ticket, publisher, stdout, BlobEncoding::Raw)?;
        let refusal = worker.upload(ticket, stderr, Cursor::new(b"stderr".to_vec()));
        assert!(
            matches!(refusal, Err(error) if error.downcast_ref::<wreq::Error>().and_then(wreq::Error::status) == Some(StatusCode::SERVICE_UNAVAILABLE))
        );
        worker.renew(ticket)?;
        drop(first);
        worker.upload(ticket, stderr, Cursor::new(b"stderr".to_vec()))?;
        drop(second);
        worker.upload(ticket, stdout, Cursor::new(b"stdout".to_vec()))?;
        worker.upload(ticket, object, Cursor::new(b"object".to_vec()))?;
        assert_eq!(worker.commit(ticket, Duration::ZERO, None)?, manifest);
        for (reference, expected) in [
            (object, b"object"),
            (stdout, b"stdout"),
            (stderr, b"stderr"),
        ] {
            let mut actual = Vec::new();
            client.download(ticket, reference, &mut actual)?;
            assert_eq!(&actual, expected);
        }
        client.close(ticket)?;
        client.close(offered)?;
        Ok(())
    })
}

#[test]
fn raw_physical_transport_preserves_original_magic_prefixed_bytes() -> Result<()> {
    use std::io::{Seek, Write};

    with_native_service(|url, _sessions, _, _| {
        let client = make_client(url, "client-token")?;
        let worker = make_client(url, "worker-token")?.for_worker(JobId(42));
        let (ticket, offered) = admit_empty_action(&client)?;
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
        client.close(offered)?;
        Ok(())
    })
}

#[test]
fn metadata_is_bounded_and_rejects_trailing_bytes() -> Result<()> {
    let request = Request::fake_http_from(
        "127.0.0.1:0".parse()?,
        "POST",
        "/api/v5/native/client/status",
        Vec::new(),
        vec![0; 34],
    );
    assert!(metadata::<StatusRequest>(&request, 33).is_err());
    let request = Request::fake_http_from(
        "127.0.0.1:0".parse()?,
        "POST",
        "/api/v5/native/client/status",
        Vec::new(),
        vec![0; 34],
    );
    assert!(metadata::<StatusRequest>(&request, 64).is_err());
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
        spec.command.arguments = vec![b"-c".to_vec(), b"IFS= read -r data < /src/input; printf '%s' \"$data\" > /out/obj; printf diagnostic >&2; printf stdout".to_vec()];
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
            artifact_grace: Some(&artifact_grace),
        };
        let busy = execution_queue.acquire(|| Ok(()))?;
        let prepared = crate::http_client::io_runtime()?.block_on(worker.prepare_on_worker(
            ticket,
            &spec,
            &worker_store,
            &policy,
            delivery,
            crate::dist::native::WorkerPreparation {
                estimated_result_bytes: None,
                cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                on_tree: &mut |_| {},
                on_authorized: || std::future::ready(Ok(())),
            },
        ))?;
        assert_eq!(execution_queue.active(), 1);
        drop(busy);
        let completed = prepared.execute(&worker_store, &policy, delivery, || {
            assert_eq!(execution_queue.active(), 1)
        });
        assert_eq!(execution_queue.active(), 0);
        let result = crate::http_client::io_runtime()?.block_on(completed.publish(
            &worker_store,
            &policy,
            &transport,
        ))?;
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
        bytes.clear();
        client.download(
            ticket,
            manifest.stdout.context("missing stdout")?,
            &mut bytes,
        )?;
        assert_eq!(bytes, b"stdout");
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

#[tokio::test]
async fn physical_blob_response_preserves_content_and_reuses_encoded_files() -> Result<()> {
    use std::io::{Seek as _, Write as _};
    let request = Request::fake_http_from(
        "127.0.0.1:1".parse()?,
        "POST",
        "/test",
        Vec::new(),
        Vec::new(),
    );
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
        let response = physical_blob_response(&request, raw, BlobEncoding::Raw)?;
        assert_eq!(response.headers()["X-Sccache-CAS-Encoding"], "zstd-chunks");
        assert!(
            !response
                .headers()
                .contains_key(http::header::CONTENT_LENGTH)
        );
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024).await?;
        let size = u64::try_from(bytes.len())?;
        let stream = std::io::Cursor::new(bytes);
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
        let response = physical_blob_response(&request, encoded, BlobEncoding::ZstdChunks)?;
        let reused_size = response.headers()[http::header::CONTENT_LENGTH]
            .to_str()?
            .parse::<u64>()?;
        assert_eq!(size, reused_size);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024).await?;
        assert_eq!(u64::try_from(bytes.len())?, reused_size);
        let stream = std::io::Cursor::new(bytes);
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
        let (request, base) = url.raw(&url.worker)?;
        let prefetch = InputPrefetchRequest {
            ticket: read.ticket,
            missing: vec![missing],
        };
        crate::http_client::io_runtime()?
            .block_on(
                request
                    .post(base.join("/api/v5/native/worker/input_prefetch")?.as_str())
                    .bearer_auth("worker-token")
                    .header("Content-Type", "application/octet-stream")
                    .header("X-Sccache-Native-Job", "42")
                    .body(codec().serialize(&prefetch)?)
                    .timeout(Duration::from_secs(10))
                    .send(),
            )?
            .error_for_status()?;
        let pending = crate::http_client::io_runtime()?.block_on(
            request
                .post(base.join("/api/v5/native/worker/download")?.as_str())
                .bearer_auth("worker-token")
                .header("Content-Type", "application/octet-stream")
                .header("X-Sccache-Native-Job", "42")
                .body(codec().serialize(&DownloadRequest {
                    ticket: read.ticket,
                    id: missing.id,
                })?)
                .timeout(Duration::from_secs(10))
                .send(),
        )?;
        assert_eq!(pending.status(), http::StatusCode::ACCEPTED);
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
        let owner = url.worker.current()?.id()?;
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
