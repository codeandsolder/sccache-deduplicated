//! Dedicated native cache listener. Reuse scheduler authentication and job
//! ownership without running filesystem I/O on the scheduling request pool.

use std::{
    collections::BTreeMap,
    fs::File,
    future::Future,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use super::cluster_http::{
    AdmissionClass, Listener, ListenerRole, Request, async_route, binary, path_route, routes,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    response::{IntoResponse, Response},
    routing::MethodFilter,
};
use bincode::Options;
use futures::TryStreamExt;
use http::StatusCode;
use sccache_cluster_identity::{ClusterListener, Role, SchedulerEnrollment};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::AsyncReadExt;
use tokio_util::io::StreamReader;

use super::{SchedulerRequester, role_error};
use crate::{
    build_runtime::{
        ActionMode, ArchiveLength, BlobEncoding, BlobRef, Direction, ExecutionSpec,
        NativeContentPending, NativeInputRejected, NativeLeaseRejected, NativeServiceBusy,
        NativeSessions, NativeStore, NetworkMeter, NetworkSnapshot, PackageCatalog,
        PackageIdentity, PackageImportLimits, PackagePreparation, PackageSource, Peer,
        SchedulePreparation, ScheduleReservation, StagedBlob, TreeId, TreeManifest,
        VerifiedPackage,
        wire::{BlobRecipient, BlobSource, BlobSourcePlan, Publisher, ScheduleReply, UploadHeader},
    },
    config::scheduler::NativeCacheConfig,
    dist::native::{
        BlobSourceRequest, CloseRequest, CommitRequest, DownloadRequest, ExecutionRequest,
        InputPrefetchRequest, ManifestRequest, OpenTreeRequest, PackageAcquisition, PackageLocator,
        PackagePlanRequest, RetainRequest, RetainedDownloadRequest, ScheduleRequest, StatusRequest,
        codec,
        ingress::{receive_blob, receive_package, stage_blob},
    },
};

mod network;

pub(super) type SourcePlanner<'a> = dyn Fn(BlobRef, BlobRecipient, Option<crate::dist::ServerId>) -> Result<Vec<BlobSource>>
    + Send
    + Sync
    + 'a;

pub(super) type ResultObserver<'a> = dyn Fn(crate::dist::ServerId, crate::dist::JobId, crate::dist::NativeLifecycleEvent<'_>)
    + Send
    + Sync
    + 'a;

struct PackageService {
    limits: PackageImportLimits,
    upstreams: BTreeMap<String, (url::Url, wreq::Client)>,
}

impl PackageService {
    fn new(config: &NativeCacheConfig) -> Result<Option<Self>> {
        let Some(limits) = config.package_import else {
            return Ok(None);
        };
        let mut upstreams = BTreeMap::new();
        for (name, upstream) in &config.package_upstreams {
            let client = crate::http_client::new_http_client_builder()
                .timeout(Duration::from_secs(upstream.timeout_secs))
                .connect_timeout(Duration::from_secs(10))
                .redirect(wreq::redirect::Policy::none())
                .pool_max_idle_per_host(0)
                .no_proxy()
                .build()?;
            upstreams.insert(name.clone(), (upstream.origin.clone(), client));
        }
        Ok(Some(Self { limits, upstreams }))
    }

    async fn acquire(
        &self,
        sessions: Arc<NativeSessions>,
        locator: PackageLocator,
        network: &NetworkMeter,
    ) -> Result<(VerifiedPackage, bool)> {
        locator.validate()?;
        let (base, client) = self
            .upstreams
            .get(&locator.upstream)
            .context("package upstream not configured")?;
        let url = locator.resolve(base)?;
        let length = locator.expected_size.map_or(
            ArchiveLength::AtMost(self.limits.max_archive_bytes),
            ArchiveLength::Exact,
        );
        ensure!(
            length.maximum() <= self.limits.max_archive_bytes,
            "upstream package exceeds archive size limit"
        );
        let limits = self.limits;
        let identity = locator.identity;
        let prepared =
            tokio::task::spawn_blocking(move || sessions.prepare_package(identity, length, limits))
                .await??;
        let upload = match prepared {
            PackagePreparation::Cached(package) => return Ok((package, true)),
            PackagePreparation::Import(upload) => upload,
        };
        let response = client.get(url.as_str()).send().await?.error_for_status()?;
        ensure!(
            response
                .content_length()
                .is_none_or(|size| length.accepts(size)),
            "upstream package length violates expectation"
        );
        let size = response.content_length().or(locator.expected_size);
        let peer = observed_response_peer(&response, Peer::Upstream);
        let meter = network.transfer(Direction::Receive, peer, size.unwrap_or(0), size);
        let mut input = StreamReader::new(Box::pin(
            response.bytes_stream().map_err(std::io::Error::other),
        ));
        Ok((
            receive_package(upload, &mut input, Some(meter), length)
                .await?
                .0,
            false,
        ))
    }
}

#[derive(Clone)]
struct CommitRoutes {
    sessions: Arc<NativeSessions>,
    observe_result: Arc<ResultObserver<'static>>,
}

async fn commit_response(
    mut request: Request,
    role: &'static str,
    operation: &'static str,
    routes: CommitRoutes,
    limit: usize,
) -> Response {
    let publisher = match request_publisher(&request, role) {
        Ok(publisher) => publisher,
        Err(response) => return *response,
    };
    let result = async {
        let data = request
            .read_bounded(limit)
            .await
            .map_err(|error| anyhow::anyhow!("native metadata body: {error:?}"))?;
        if operation == "tree_commit" {
            return encode(
                &routes
                    .sessions
                    .commit_tree_async(decode_metadata(&data, limit)?)
                    .await?,
                limit,
            );
        }
        let CommitRequest {
            ticket,
            retained_after_begin_millis,
            observation,
        } = decode_metadata(&data, limit)?;
        let manifest = routes.sessions.commit_async(ticket, publisher).await?;
        if let Publisher::Worker { peer, job } = publisher {
            (routes.observe_result)(
                peer,
                crate::dist::JobId(job),
                crate::dist::NativeLifecycleEvent::Committed {
                    manifest: &manifest,
                    retained_after_begin: Duration::from_millis(retained_after_begin_millis),
                    observation,
                },
            );
        }
        encode(&manifest, limit)
    }
    .await;
    native_response(operation, result)
}

#[derive(Clone)]
struct PackageRoutes {
    service: Arc<PackageService>,
    sessions: Arc<NativeSessions>,
    network: Arc<NetworkMeter>,
}

async fn package_response(
    mut request: Request,
    operation: &'static str,
    routes: PackageRoutes,
    limit: usize,
) -> Response {
    if let Err(response) = request_publisher(&request, "client") {
        return *response;
    }
    let result = async {
        let rust = operation.starts_with("rust_");
        let acquire = operation.ends_with("_acquire");
        let (package, reused) = if acquire {
            let bytes = request
                .read_bounded(limit)
                .await
                .map_err(|error| anyhow::anyhow!("package locator body: {error:?}"))?;
            let locator = codec()
                .with_limit(u64::try_from(limit)?)
                .deserialize(&bytes)?;
            routes
                .service
                .acquire(Arc::clone(&routes.sessions), locator, &routes.network)
                .await?
        } else {
            let peer = Peer::Client(request.id()).on_path(request.path());
            let stream = request
                .body_stream()
                .context("missing original package body")?;
            let mut input = StreamReader::new(Box::pin(stream));
            let mut header = [0; 44];
            input.read_exact(&mut header).await?;
            let source: PackageSource = codec().with_limit(44).deserialize(&header)?;
            let length = ArchiveLength::Exact(source.size);
            let sessions = Arc::clone(&routes.sessions);
            let limits = routes.service.limits;
            match tokio::task::spawn_blocking(move || {
                sessions.prepare_package(source.identity, length, limits)
            })
            .await??
            {
                PackagePreparation::Cached(package) => (package, true),
                PackagePreparation::Import(upload) => {
                    let meter = routes.network.transfer(
                        Direction::Receive,
                        peer,
                        source.size,
                        Some(source.size),
                    );
                    (
                        receive_package(upload, &mut input, Some(meter), length)
                            .await?
                            .0,
                        false,
                    )
                }
            }
        };
        // Installer recipe publication reads the verified tree and updates the
        // index; only that local work runs on the blocking pool.
        if rust {
            tokio::task::spawn_blocking(move || {
                let package = routes
                    .sessions
                    .store()
                    .publish_rust_installer(&package, routes.service.limits.policy()?.directory)?;
                if acquire {
                    encode(&PackageAcquisition { package, reused }, limit)
                } else {
                    encode(&package, limit)
                }
            })
            .await?
        } else if acquire {
            encode(
                &PackageAcquisition {
                    package: package.receipt(),
                    reused,
                },
                limit,
            )
        } else {
            encode(&package.receipt(), limit)
        }
    }
    .await;
    native_response(operation, result)
}

pub(super) struct PublicationCallbacks<S, O> {
    pub source_plan: S,
    pub observe_result: O,
}

#[expect(
    clippy::too_many_lines,
    reason = "native listener startup owns the shared session lifetime and starts its coordinated acquisition and maintenance workers"
)]
pub(super) fn spawn<Fut, PeerFut>(
    cache: (&NativeCacheConfig, NativeStore),
    allocate: impl Fn(crate::dist::NativeAssignment, NetworkSnapshot, Arc<PackageCatalog>) -> Fut
    + Send
    + Sync
    + 'static,
    fetch_peer: impl Fn(BlobRef, Option<crate::dist::ServerId>, NativeStore, Instant) -> PeerFut
    + Send
    + Sync
    + 'static,
    publication: PublicationCallbacks<
        impl Fn(BlobRef, BlobRecipient, Option<crate::dist::ServerId>) -> Result<Vec<BlobSource>>
        + Send
        + Sync
        + 'static,
        impl Fn(crate::dist::ServerId, crate::dist::JobId, crate::dist::NativeLifecycleEvent<'_>)
        + Send
        + Sync
        + 'static,
    >,
    tls: Arc<ClusterListener>,
    enrollment: Arc<SchedulerEnrollment>,
    network: Arc<NetworkMeter>,
) -> Result<(std::net::SocketAddr, Arc<NativeSessions>)>
where
    Fut: Future<Output = Result<ScheduleReply>> + Send + 'static,
    PeerFut: Future<Output = Result<Option<StagedBlob>>> + Send + 'static,
{
    let (config, store) = cache;
    let PublicationCallbacks {
        source_plan,
        observe_result,
    } = publication;
    let socket = super::cluster_http::bind_data_socket(config.public_addr, config.bind_address)?;
    let bound = socket.local_addr()?;
    let limits = config.session_limits()?;
    let sessions = Arc::new(NativeSessions::new(store, limits)?);
    let observe_result: Arc<ResultObserver<'static>> = Arc::new(observe_result);
    let commit_routes = CommitRoutes {
        sessions: Arc::clone(&sessions),
        observe_result: Arc::clone(&observe_result),
    };
    let maintenance = Arc::downgrade(&sessions);
    let fetch_peer = Arc::new(fetch_peer);
    // One dispatcher scans the pending demands. Logical acquisition
    // ownership is separate from the actual shared transfer admission.
    let runtime = crate::http_client::io_runtime()?;
    {
        let sessions = Arc::downgrade(&sessions);
        let fetch_peer = Arc::clone(&fetch_peer);
        runtime.spawn(async move {
            let mut active = tokio::task::JoinSet::new();
            while let Some(sessions) = sessions.upgrade() {
                tokio::select! {
                    result = active.join_next(), if !active.is_empty() => {
                        if let Some(Err(error)) = result {
                            warn!("native peer recovery task failed: {error:#}");
                        }
                    }
                    claim = sessions.claim_peer_input(Duration::from_millis(100)),
                        if active.len() < limits.max_sessions => {
                        match claim {
                            Ok(Some(claim)) => {
                                let requester = claim.requester();
                                let deadline = Instant::now() + limits.idle_timeout;
                                let fetch = Arc::clone(&fetch_peer);
                                active.spawn(async move {
                                    if let Err(error) = sessions.recover_peer_input(
                                        claim, deadline, move |blob, store, deadline| {
                                            fetch(blob, Some(requester), store, deadline)
                                        }
                                    ).await {
                                        debug!("native peer backfill unavailable: {error:#}");
                                    }
                                });
                            }
                            Ok(None) => {}
                            Err(error) => {
                                warn!("native peer claim failed: {error:#}");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }
        });
    }
    // Independent result recoveries share the same real transfer budget.
    // The recovery queue accounts for their manifests until they complete.
    {
        let sessions = Arc::downgrade(&sessions);
        let fetch_peer = Arc::clone(&fetch_peer);
        runtime.spawn(async move {
            use futures::stream::{FuturesUnordered, StreamExt};
            let mut active = FuturesUnordered::new();
            while let Some(sessions) = sessions.upgrade() {
                let fetch = Arc::clone(&fetch_peer);
                tokio::select! {
                    result = active.next(), if !active.is_empty() => {
                        match result {
                            Some(Ok(Err(error))) => warn!("native result recovery failed: {error:#}"),
                            Some(Err(error)) => warn!("native result recovery task failed: {error:#}"),
                            _ => {}
                        }
                    }
                    claimed = sessions.start_result_recovery(
                        Duration::from_millis(100),
                        move |blob, store, deadline| fetch(blob, None, store, deadline),
                    ), if active.len() < limits.max_sessions => {
                        match claimed {
                            Ok(Some(task)) => active.push(task),
                            Ok(None) => {}
                            Err(error) => {
                                warn!("native result recovery claim failed: {error:#}");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }
        });
    }
    let metadata_limit = config.max_metadata_bytes;
    let packages = PackageService::new(config)?.map(Arc::new);
    let package_routes = packages.as_ref().map(|service| PackageRoutes {
        service: Arc::clone(service),
        sessions: Arc::clone(&sessions),
        network: Arc::clone(&network),
    });
    network::start(
        &network,
        config.directory.join("network-path-timing.json"),
        config.public_addr,
    )?;
    let retained_sessions = Arc::clone(&sessions);
    let schedule_sessions = Arc::clone(&sessions);
    let schedule_network = Arc::clone(&network);
    let upload_sessions = Arc::clone(&sessions);
    let upload_network = Arc::clone(&network);
    let allocate = Arc::new(allocate);
    let server = Listener::from_socket(
        socket,
        tls,
        ListenerRole::Scheduler(enrollment),
        config.http_threads,
        native_router(
            move |request, role, operation| {
                respond(
                    request,
                    role,
                    operation,
                    NativeServices {
                        sessions: &sessions,
                        packages: packages.as_deref(),
                        network: &network,
                        source_plan: &source_plan,
                        observe_result: observe_result.as_ref(),
                    },
                    metadata_limit,
                )
            },
            move |request| {
                schedule_response(
                    request,
                    Arc::clone(&schedule_sessions),
                    Arc::clone(&schedule_network),
                    Arc::clone(&allocate),
                    metadata_limit,
                )
            },
            move |request, role, operation| {
                upload_response(
                    request,
                    role,
                    operation,
                    Arc::clone(&upload_sessions),
                    Arc::clone(&upload_network),
                    metadata_limit,
                )
            },
            &commit_routes,
            package_routes,
            metadata_limit,
        ),
    )?;
    info!("Native cache listening on {bound}");
    thread::Builder::new()
        .name("native-cache-maintenance".into())
        .spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(1));
                let Some(maintenance) = maintenance.upgrade() else {
                    break;
                };
                if let Err(error) = maintenance.reap() {
                    error!("native cache session reap failed: {error:#}");
                }
                match maintenance.store().maintain_space() {
                    Ok(Some(report)) if !report.minimum_satisfied => {
                        warn!("native cache space pressure: {report:?}");
                    }
                    Ok(_) => {}
                    Err(error) => {
                        if maintenance.store().index_requires_restart() {
                            error!("native cache index requires reopening; terminating for supervised recovery: {error:#}");
                            std::process::exit(1);
                        }
                        error!("native cache space maintenance failed: {error:#}");
                    }
                }
            }
        })?;
    thread::Builder::new()
        .name("native-cache-http".into())
        .spawn(move || {
            if let Err(error) = server.run() {
                error!("native cache HTTPS listener terminated: {error:#}");
            }
        })?;
    Ok((bound, retained_sessions))
}

/// Unknown operations stay in the bulk lane; only the enumerated protocol
/// operations get access to reserved metadata, dispatch or control capacity.
fn native_admission_class((_, operation): &(String, String)) -> AdmissionClass {
    match operation.as_str() {
        "renew" | "fail" | "retain_renew" | "retain_close" | "close" | "inputs_staged"
        | "input_unavailable" => AdmissionClass::Control,
        "admit"
        | "status"
        | "poll_input"
        | "verify"
        | "input_prefetch"
        | "retain_open"
        | "retain_add"
        | "blob_sources"
        | "retain_sources"
        | "tree_offer"
        | "tree_open"
        | "package_plan"
        | "package_lookup"
        | "rust_package_lookup"
        | "trace_live"
        | "begin" => AdmissionClass::Metadata,
        _ => AdmissionClass::Bulk,
    }
}

#[expect(
    clippy::literal_string_with_formatting_args,
    reason = "Axum route parameters use literal braces"
)]
fn native_router<F, A, Fut, U, UFut>(
    handler: F,
    schedule: A,
    upload: U,
    commits: &CommitRoutes,
    packages: Option<PackageRoutes>,
    metadata_limit: usize,
) -> Router
where
    F: Fn(&Request, &str, &str) -> Response + Send + Sync + 'static,
    A: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
    U: Fn(Request, &'static str, &'static str) -> UFut + Send + Sync + 'static,
    UFut: Future<Output = Response> + Send + 'static,
{
    let upload = Arc::new(upload);
    let client_upload = Arc::clone(&upload);
    let client_backfill = Arc::clone(&upload);
    let mut router = Router::new()
        .route(
            "/api/v5/native/client/schedule",
            async_route(
                MethodFilter::POST,
                AdmissionClass::Dispatch,
                move |_: Arc<F>, request| schedule(request),
            ),
        )
        .route(
            "/api/v5/native/client/upload",
            async_route(
                MethodFilter::POST,
                AdmissionClass::Bulk,
                move |_: Arc<F>, request| client_upload(request, "client", "upload"),
            ),
        )
        .route(
            "/api/v5/native/worker/upload",
            async_route(
                MethodFilter::POST,
                AdmissionClass::Bulk,
                move |_: Arc<F>, request| upload(request, "worker", "upload"),
            ),
        )
        .route(
            "/api/v5/native/client/backfill_input",
            async_route(
                MethodFilter::POST,
                AdmissionClass::Bulk,
                move |_: Arc<F>, request| client_backfill(request, "client", "backfill_input"),
            ),
        )
        .route(
            "/api/v5/native/{role}/{operation}",
            path_route(
                MethodFilter::POST,
                native_admission_class,
                move |_, _: &(String, String)| Some(metadata_limit),
                |handler: &F, request, (role, operation): (String, String)| {
                    handler(request, &role, &operation)
                },
            ),
        );
    for (path, role, operation) in [
        ("/api/v5/native/worker/commit", "worker", "commit"),
        ("/api/v5/native/client/tree_commit", "client", "tree_commit"),
    ] {
        let commits = commits.clone();
        router = router.route(
            path,
            async_route(
                MethodFilter::POST,
                AdmissionClass::Metadata,
                move |_: Arc<F>, request| {
                    commit_response(request, role, operation, commits.clone(), metadata_limit)
                },
            ),
        );
    }
    if let Some(packages) = packages {
        for (path, operation) in [
            ("/api/v5/native/client/package_import", "package_import"),
            (
                "/api/v5/native/client/rust_package_import",
                "rust_package_import",
            ),
            ("/api/v5/native/client/package_acquire", "package_acquire"),
            (
                "/api/v5/native/client/rust_package_acquire",
                "rust_package_acquire",
            ),
        ] {
            let packages = packages.clone();
            router = router.route(
                path,
                async_route(
                    MethodFilter::POST,
                    AdmissionClass::Bulk,
                    move |_: Arc<F>, request| {
                        package_response(request, operation, packages.clone(), metadata_limit)
                    },
                ),
            );
        }
    }
    routes(router, handler)
}

/// The single peer-content endpoint serves scheduler recovery, worker inputs,
/// and client results. Only an exact, recipient-bound capability grants access.
pub(super) fn serve_peer_blob(
    request: &Request,
    authorizer: &dyn crate::dist::JobAuthorizer,
    open: impl FnOnce(BlobRef) -> Result<Option<(File, BlobEncoding)>>,
) -> Result<Response> {
    use sccache_cluster_identity::Role;
    let recipient = match request.role() {
        Role::Scheduler => BlobRecipient::Scheduler,
        Role::Client => BlobRecipient::Client(request.id()),
        Role::Worker => BlobRecipient::Worker(request.id()),
    };
    let Ok(blob) = metadata::<BlobRef>(request, 40) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    let permitted = super::bearer_http_auth(request)
        .is_some_and(|token| authorizer.verify_blob_token(blob, recipient, token).is_ok());
    if !permitted {
        return Ok((StatusCode::UNAUTHORIZED, "invalid peer capability").into_response());
    }
    match open(blob)? {
        Some((file, encoding)) => physical_blob_response(request, file, encoding),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

pub(super) fn physical_blob_response(
    request: &Request,
    file: File,
    encoding: BlobEncoding,
) -> Result<Response> {
    let length = file.metadata()?.len();
    let mut response = if encoding == BlobEncoding::Raw {
        // A raw ZFS replica is compressed on demand for the wire, without
        // pre-reading or spooling the complete physical blob.
        request.compressed_file_body(file, length, None)?
    } else {
        request.file_body(file, length, None)
    };
    let encoding = BlobEncoding::ZstdChunks;
    response.headers_mut().insert(
        "x-sccache-cas-encoding",
        http::HeaderValue::from_static(encoding.http_value()),
    );
    Ok(response)
}

fn observed_response_peer(response: &wreq::Response, peer: Peer) -> Peer {
    response
        .local_addr()
        .zip(response.remote_addr())
        .map_or(peer, |(local, remote)| {
            peer.on_path(crate::build_runtime::NetworkPath::new(
                local.ip(),
                remote.ip(),
            ))
        })
}

/// Retrieve a blob from a specific authenticated worker using its exact-content capability.
pub(super) async fn fetch_peer(
    routes: &SchedulerRequester,
    source: &crate::dist::NativeBlobSource,
    blob: BlobRef,
    store: NativeStore,
    network: &NetworkMeter,
    deadline: Instant,
) -> Result<Option<StagedBlob>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    ensure!(!remaining.is_zero(), "native peer deadline expired");
    let timeout = Duration::from_secs((5 + blob.size.div_ceil(1024 * 1024)).min(60)).min(remaining);
    let mut selected = None;
    for address in routes.download_endpoints(source.server, blob.size)? {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let (client, base) = routes.endpoint(source.server, address)?;
        let response = client
            .post(super::super::urls::server_native_blob(&base)?.as_str())
            .timeout(timeout.min(remaining))
            .bearer_auth(&source.token)
            .header("Content-Type", "application/octet-stream")
            .body(codec().serialize(&blob)?)
            .send()
            .await;
        match response {
            Err(error) if error.is_connect() => routes.failed(source.server, address),
            result => {
                selected = Some((result?, address));
                break;
            }
        }
    }
    let Some((response, address)) = selected else {
        return Ok(None);
    };
    if response.status() == http::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let response = response.error_for_status()?;
    let encoding = BlobEncoding::from_http_value(
        response
            .headers()
            .get("x-sccache-cas-encoding")
            .context("missing peer encoding")?
            .to_str()?,
    )?;
    let size = response.content_length();
    let peer = observed_response_peer(&response, Peer::Worker(source.server));
    let mut input =
        routes
            .routes
            .measure_response_async(source.server, Role::Worker, address, response);
    let meter = network.transfer(Direction::Receive, peer, blob.size, size);
    Ok(Some(
        stage_blob(store, blob, encoding, &mut input, Some(meter)).await?,
    ))
}

#[derive(Clone, Copy)]
struct NativeServices<'a> {
    sessions: &'a NativeSessions,
    packages: Option<&'a PackageService>,
    network: &'a NetworkMeter,
    source_plan: &'a SourcePlanner<'a>,
    observe_result: &'a ResultObserver<'a>,
}

fn respond(
    request: &Request,
    role: &str,
    operation: &str,
    services: NativeServices<'_>,
    limit: usize,
) -> Response {
    let publisher = match request_publisher(request, role) {
        Ok(publisher) => publisher,
        Err(response) => return *response,
    };
    native_response(
        operation,
        dispatch(request, services, publisher, operation, limit),
    )
}

fn request_publisher(
    request: &Request,
    role: &str,
) -> std::result::Result<Publisher, Box<Response>> {
    if request.header("Content-Type") != Some("application/octet-stream") {
        return Err(Box::new(StatusCode::BAD_REQUEST.into_response()));
    }
    Ok(match role {
        "client" => {
            if let Some(response) = role_error(request, Role::Client) {
                return Err(Box::new(response));
            }
            Publisher::Client
        }
        "worker" => {
            if let Some(response) = role_error(request, Role::Worker) {
                return Err(Box::new(response));
            }
            let server = request.id();
            let Some(job) = request
                .header("X-Sccache-Native-Job")
                .and_then(|job| job.parse::<u64>().ok())
            else {
                return Err(Box::new(StatusCode::BAD_REQUEST.into_response()));
            };
            Publisher::Worker { peer: server, job }
        }
        _ => return Err(Box::new(StatusCode::NOT_FOUND.into_response())),
    })
}

async fn upload_response(
    mut request: Request,
    role: &str,
    operation: &str,
    sessions: Arc<NativeSessions>,
    network: Arc<NetworkMeter>,
    limit: usize,
) -> Response {
    let publisher = match request_publisher(&request, role) {
        Ok(publisher) => publisher,
        Err(response) => return *response,
    };
    let peer = match publisher {
        Publisher::Client => Peer::Client(request.id()),
        Publisher::Worker { peer, .. } => Peer::Worker(peer),
    }
    .on_path(request.path());
    let backfill = operation == "backfill_input";
    let result = async {
        let stream = request
            .body_stream()
            .context("missing native upload body")?;
        let mut input = StreamReader::new(Box::pin(stream));
        let mut header = [0; 73];
        input.read_exact(&mut header).await?;
        let header: UploadHeader = codec().with_limit(73).deserialize(&header)?;
        let encoding = BlobEncoding::try_from(header.encoding)?;
        let upload = {
            let sessions = Arc::clone(&sessions);
            tokio::task::spawn_blocking(move || {
                if backfill {
                    ensure!(
                        encoding == BlobEncoding::Raw,
                        "backfill input requires logical bytes"
                    );
                    sessions.prepare_backfill(header.ticket, header.blob)
                } else {
                    sessions.prepare_upload(header.ticket, publisher, header.blob, encoding)
                }
            })
            .await??
        };
        let meter = network.transfer(Direction::Receive, peer, header.blob.size, None);
        let upload = receive_blob(upload, &mut input, Some(meter), |error| {
            let error = anyhow::Error::from(error);
            if backfill {
                error.context(NativeServiceBusy)
            } else {
                error
            }
        })
        .await?;
        sessions.finish_upload_async(upload).await?;
        encode(&(), limit)
    }
    .await;
    native_response(operation, result)
}

// Prepare immutable placement inputs on the blocking pool; the worker RPC
// itself is a future and holds neither a session lock nor a blocking thread.
async fn schedule_response<A, Fut>(
    mut request: Request,
    sessions: Arc<NativeSessions>,
    network: Arc<NetworkMeter>,
    allocate: Arc<A>,
    limit: usize,
) -> Response
where
    A: Fn(crate::dist::NativeAssignment, NetworkSnapshot, Arc<PackageCatalog>) -> Fut
        + Send
        + Sync
        + 'static,
    Fut: Future<Output = Result<ScheduleReply>> + Send,
{
    if request.header("Content-Type") != Some("application/octet-stream") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Some(response) = role_error(&request, Role::Client) {
        return response;
    }
    let requester = request.id();
    let result = async {
        let bytes = request
            .read_bounded(limit)
            .await
            .map_err(|error| anyhow::anyhow!("native schedule body: {error:?}"))?;
        let schedule: ScheduleRequest = codec().with_limit(limit as u64).deserialize(&bytes)?;
        ensure!(
            schedule
                .trace
                .is_none_or(crate::latency_trace::TraceContext::valid),
            "invalid schedule trace context"
        );
        let mut trace = schedule
            .trace
            .filter(|_| crate::latency_trace::enabled())
            .map(|parent| {
                crate::latency_trace::SpanGuard::new(parent, "sccache-scheduler", "allocate_worker")
            });
        let result = async {
            let prepared = tokio::task::spawn_blocking(move || {
                prepare_schedule(&sessions, &network, requester, schedule)
            })
            .await??;
            match prepared {
                Ok((reservation, assignment, snapshot, packages)) => {
                    let reply = allocate(assignment, snapshot, packages).await?;
                    reservation.finish(reply)
                }
                Err(replay) => Ok(replay),
            }
        }
        .await;
        if let Some(trace) = &mut trace
            && result.is_ok()
            && !matches!(&result, Ok(ScheduleReply::Unavailable { .. }))
        {
            trace.succeed();
        }
        let reply = result?;
        encode(&reply, limit)
    }
    .await;
    native_response("schedule", result)
}

type PreparedSchedule = (
    ScheduleReservation,
    crate::dist::NativeAssignment,
    NetworkSnapshot,
    Arc<PackageCatalog>,
);

fn prepare_schedule(
    sessions: &NativeSessions,
    network: &NetworkMeter,
    requester: crate::dist::ServerId,
    schedule: ScheduleRequest,
) -> Result<std::result::Result<PreparedSchedule, ScheduleReply>> {
    let ScheduleRequest {
        ticket,
        trace,
        spec,
        receiver,
        selected,
    } = schedule;
    ensure!(receiver.valid(), "invalid client delivery telemetry");
    let request = spec.action_request()?;
    let selection = crate::build_runtime::wire::DeliverySelection::new(&spec, selected)?;
    let profile = selection.profile;
    let mut reservation = match sessions.prepare_schedule(ticket, &request, requester, selection)? {
        SchedulePreparation::Replay(reply) => return Ok(Err(reply)),
        SchedulePreparation::Dispatch(reservation) => reservation,
    };
    let (inputs, trees) = reservation.placement_inputs();
    let blobs = inputs
        .iter()
        .map(|(&id, &size)| BlobRef { id, size })
        .collect::<Vec<_>>();
    let mut packages = sessions
        .store()
        .package_catalog(&blobs)
        .unwrap_or_else(|error| {
            warn!("Native package placement catalog unavailable: {error:#}");
            PackageCatalog::default()
        });
    packages.restrict_to_trees(trees);
    let mut snapshot = network.snapshot();
    snapshot.interfaces = crate::dist::cluster::interface_report();
    Ok(Ok((
        reservation,
        crate::dist::NativeAssignment {
            trace,
            ticket,
            spec,
            input_blobs: inputs,
            estimated_result_bytes: None,
            receiver: Some((requester, receiver)),
            delivery_profile: Some(profile),
        },
        snapshot,
        Arc::new(packages),
    )))
}

fn native_response(operation: &str, result: Result<Response>) -> Response {
    match result {
        Ok(response) => response,
        Err(error) if error.is::<NativeContentPending>() => {
            (StatusCode::ACCEPTED, "native input pending").into_response()
        }
        Err(error) if error.is::<NativeInputRejected>() => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "native input bytes rejected",
        )
            .into_response(),
        Err(error) if error.is::<crate::build_runtime::StageSpaceExhausted>() => {
            debug!("Native cache {operation} waiting for storage: {error:#}");
            (StatusCode::SERVICE_UNAVAILABLE, "native cache storage busy").into_response()
        }
        Err(error) if error.is::<NativeServiceBusy>() => {
            (StatusCode::SERVICE_UNAVAILABLE, "native service busy").into_response()
        }
        Err(error) if matches!(operation, "renew" | "retain_renew") => {
            match error.downcast_ref::<NativeLeaseRejected>() {
                Some(NativeLeaseRejected::Expired) => {
                    (StatusCode::GONE, "native lease lost").into_response()
                }
                Some(NativeLeaseRejected::Unauthorized) => {
                    (StatusCode::FORBIDDEN, "native lease owner mismatch").into_response()
                }
                None => {
                    error!("Native cache {operation} failed: {error:#}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "native renewal service failed",
                    )
                        .into_response()
                }
            }
        }
        Err(error) => {
            // Do not return host paths, auth tokens or raw internal metadata
            // to callers. The service log carries diagnostic context.
            warn!("Native cache {operation} rejected: {error:#}");
            (StatusCode::CONFLICT, "native cache operation rejected").into_response()
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "single exhaustive protocol dispatch preserves the operation-level authorization checks alongside each wire decoder"
)]
fn dispatch(
    request: &Request,
    services: NativeServices<'_>,
    publisher: Publisher,
    operation: &str,
    limit: usize,
) -> Result<Response> {
    let NativeServices {
        sessions,
        packages,
        network,
        observe_result,
        source_plan,
    } = services;
    let peer = match publisher {
        Publisher::Client => Peer::Client(request.id()),
        Publisher::Worker { peer, .. } => Peer::Worker(peer),
    }
    .on_path(request.path());
    match operation {
        "package_lookup" | "rust_package_lookup"
            if publisher == Publisher::Client && packages.is_some() =>
        {
            let identity: PackageIdentity = metadata(request, limit)?;
            let service = packages.context("native original-package provisioning disabled")?;
            let package = sessions.lookup_package(identity, service.limits)?;
            if operation == "rust_package_lookup" {
                let manifest = package
                    .as_ref()
                    .map(|package| {
                        sessions
                            .store()
                            .publish_rust_installer(package, service.limits.policy()?.directory)
                    })
                    .transpose()?;
                encode(&manifest, limit)
            } else {
                encode(
                    &package
                        .as_ref()
                        .map(crate::build_runtime::VerifiedPackage::receipt),
                    limit,
                )
            }
        }
        "trace_live" if publisher == Publisher::Client => {
            sessions.report_live_traces(request.id(), metadata(request, limit.min(512 * 1024))?)?;
            encode(&(), limit)
        }
        "admit" if publisher == Publisher::Client => {
            let (trace, input, mode, declared): (
                Option<crate::latency_trace::TraceContext>,
                ExecutionSpec,
                ActionMode,
                BTreeMap<TreeId, TreeManifest>,
            ) = metadata(request, limit)?;
            ensure!(
                trace.is_none_or(crate::latency_trace::TraceContext::valid),
                "invalid admission trace context"
            );
            encode(
                &sessions.admit(trace, input.action_request()?, publisher, mode, declared)?,
                limit,
            )
        }
        "input_prefetch" if matches!(publisher, Publisher::Worker { .. }) => {
            let InputPrefetchRequest { ticket, missing } = metadata(request, limit)?;
            sessions.request_inputs(ticket, publisher, missing)?;
            encode(&(), limit)
        }
        "poll_input" if publisher == Publisher::Client => {
            encode(&sessions.poll_input(metadata(request, limit)?)?, limit)
        }
        "inputs_staged" if matches!(publisher, Publisher::Worker { .. }) => {
            sessions.inputs_staged(metadata(request, limit)?, publisher)?;
            if let Publisher::Worker { peer, job } = publisher {
                observe_result(
                    peer,
                    crate::dist::JobId(job),
                    crate::dist::NativeLifecycleEvent::InputsStaged,
                );
            }
            encode(&(), limit)
        }
        "input_unavailable" if publisher == Publisher::Client => {
            let (ticket, demand) = metadata(request, limit)?;
            sessions.input_unavailable(ticket, demand)?;
            encode(&(), limit)
        }
        "status" if publisher == Publisher::Client => {
            let StatusRequest { ticket, preview } = metadata(request, limit)?;
            encode(&sessions.status_with_preview(ticket, preview)?, limit)
        }
        "close" => {
            let CloseRequest { ticket, delivery } = metadata(request, limit)?;
            if publisher == Publisher::Client
                && let Some(delivery) = delivery
            {
                match sessions.record_client_delivery(ticket, request.id(), delivery) {
                    Ok(Some(receipt)) => {
                        observe_result(
                            receipt.worker,
                            crate::dist::JobId(receipt.job),
                            crate::dist::NativeLifecycleEvent::Delivered(receipt),
                        );
                        trace!(target: "native_placement_replay", "{}", serde_json::json!({
                            "kind": "delivered", "job": receipt.job, "worker": receipt.worker,
                            "requester": receipt.requester,
                            "actual_client_completion_seconds": receipt.elapsed.as_secs_f64(),
                            "staging_nanoseconds": receipt.observation.staging_nanoseconds,
                            "selected_bytes": receipt.observation.selected_bytes,
                            "direct_bytes": receipt.observation.direct_bytes,
                            "scheduler_bytes": receipt.observation.scheduler_bytes,
                            "unique_blobs": receipt.observation.unique_blobs,
                        }));
                    }
                    Ok(None) => {}
                    Err(error) => debug!("native delivery observation rejected: {error:#}"),
                }
            }
            sessions.close(ticket, publisher)?;
            encode(&(), limit)
        }
        "retain_open" if publisher == Publisher::Client => {
            let (): () = metadata(request, limit)?;
            encode(&sessions.open_retention(request.id())?, limit)
        }
        "retain_add" if publisher == Publisher::Client => {
            let RetainRequest {
                group,
                action,
                result,
            } = metadata(request, limit)?;
            sessions.retain_result(group, action, result, request.id())?;
            encode(&(), limit)
        }
        "retain_renew" if publisher == Publisher::Client => encode(
            &sessions.renew_retention(metadata(request, limit)?, request.id())?,
            limit,
        ),
        "retain_close" if publisher == Publisher::Client => {
            sessions.close_retention(metadata(request, limit)?, request.id())?;
            encode(&(), limit)
        }
        "blob_sources" | "retain_sources" => {
            let BlobSourceRequest { ticket, blobs } = metadata(request, limit)?;
            let (producer, availability) = if operation == "retain_sources" {
                ensure!(publisher == Publisher::Client, "retention is client-owned");
                sessions.retained_sources(ticket, request.id(), &blobs)?;
                (None, vec![true; blobs.len()])
            } else {
                sessions.authorize_blob_sources(ticket, publisher, &blobs)?
            };
            let recipient = match publisher {
                Publisher::Client => BlobRecipient::Client(request.id()),
                Publisher::Worker { peer, .. } => BlobRecipient::Worker(peer),
            };
            let plans = blobs
                .into_iter()
                .zip(availability)
                .map(|(blob, scheduler_present)| {
                    Ok(BlobSourcePlan {
                        blob,
                        scheduler_present,
                        sources: source_plan(blob, recipient, producer)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            encode(&plans, limit)
        }
        "download" | "retain_download" => {
            let download = if operation == "retain_download" {
                ensure!(publisher == Publisher::Client, "retention is client-owned");
                let RetainedDownloadRequest { group, blob } = metadata(request, limit)?;
                sessions.download_retained(group, request.id(), blob)?
            } else {
                let DownloadRequest { ticket, id } = metadata(request, limit)?;
                sessions.download(ticket, publisher, id)?
            };
            let size = download.file.metadata()?.len();
            let (mut response, encoding) = if download.encoding == BlobEncoding::Raw
                && !download.original_archive
            {
                ensure!(
                    size == download.logical_size,
                    "raw CAS length differs from declared size"
                );
                let meter = network.transfer(Direction::Send, peer, download.logical_size, None);
                (
                    request.compressed_file_body(
                        download.file,
                        download.logical_size,
                        Some(meter),
                    )?,
                    BlobEncoding::ZstdChunks,
                )
            } else {
                let meter =
                    network.transfer(Direction::Send, peer, download.logical_size, Some(size));
                (
                    request.file_body(download.file, size, Some(meter)),
                    download.encoding,
                )
            };
            response.headers_mut().insert(
                "x-sccache-cas-encoding",
                http::HeaderValue::from_static(encoding.http_value()),
            );
            Ok(response)
        }
        "tree_offer" if publisher == Publisher::Client => {
            encode(&sessions.offer_tree(metadata(request, limit)?)?, limit)
        }
        "tree_open" if matches!(publisher, Publisher::Worker { .. }) => {
            let OpenTreeRequest { action, tree } = metadata(request, limit)?;
            encode(&sessions.open_tree(tree, publisher, action)?, limit)
        }
        "package_plan" if matches!(publisher, Publisher::Worker { .. }) => {
            let PackagePlanRequest {
                ticket,
                missing,
                max_archive_bytes,
                cost,
            } = metadata(request, limit)?;
            encode(
                &sessions.plan_packages(ticket, publisher, &missing, max_archive_bytes, cost)?,
                limit,
            )
        }
        "verify" if matches!(publisher, Publisher::Worker { .. }) => {
            let ExecutionRequest { ticket, spec } = metadata(request, limit)?;
            sessions.verify_execution(ticket, publisher, &spec.action_request()?)?;
            encode(&(), limit)
        }
        "begin" if matches!(publisher, Publisher::Worker { .. }) => {
            let ManifestRequest { ticket, manifest } = metadata(request, limit)?;
            let reply = sessions.begin(ticket, publisher, manifest)?;
            if let Publisher::Worker { peer, job } = publisher {
                observe_result(
                    peer,
                    crate::dist::JobId(job),
                    crate::dist::NativeLifecycleEvent::Negotiated,
                );
            }
            let mut response = encode(&reply, limit)?;
            response.headers_mut().insert(
                crate::dist::native::UPLOAD_PARALLELISM_HEADER,
                http::HeaderValue::from_str(&sessions.upload_parallelism().to_string())?,
            );
            Ok(response)
        }
        "renew" => encode(
            &sessions.renew(metadata(request, limit)?, publisher)?,
            limit,
        ),
        "fail" => {
            sessions.fail(metadata(request, limit)?, publisher)?;
            encode(&(), limit)
        }
        _ => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

pub(super) fn metadata<T: DeserializeOwned>(request: &Request, limit: usize) -> Result<T> {
    let data = request
        .read_buffered(limit)
        .map_err(|error| anyhow::anyhow!("native metadata body: {error:?}"))?;
    decode_metadata(&data, limit)
}

fn decode_metadata<T: DeserializeOwned>(data: &[u8], limit: usize) -> Result<T> {
    Ok(codec()
        .with_limit(u64::try_from(limit)?)
        .deserialize(data)?)
}

fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Response> {
    let data = codec().with_limit(u64::try_from(limit)?).serialize(value)?;
    Ok(binary(data))
}

#[cfg(test)]
mod tests;
