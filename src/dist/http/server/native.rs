//! Dedicated native cache listener. Reuse scheduler authentication and job
//! ownership without running filesystem I/O on the scheduling request pool.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use super::cluster_http::{Listener, ListenerRole, Request, binary, file_body, path_route, routes};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    response::{IntoResponse, Response},
    routing::MethodFilter,
};
use bincode::Options;
use http::StatusCode;
use sccache_cluster_identity::{ClusterListener, Role, SchedulerEnrollment};
use serde::{Serialize, de::DeserializeOwned};

use super::{SchedulerRequester, role_error};
use crate::{
    build_runtime::{
        ActionMode, ArchiveLength, BlobEncoding, BlobRef, Direction, ExecutionSpec,
        NativeContentPending, NativeInputRejected, NativeServiceBusy, NativeSessions, NativeStore,
        NetworkMeter, PackageIdentity, PackageImportLimits, PackageSource, Peer, StagedBlob,
        TreeId, TreeManifest, VerifiedPackage,
        wire::{BlobRecipient, BlobSource, BlobSourcePlan, Publisher, ScheduleReply, UploadHeader},
    },
    config::scheduler::NativeCacheConfig,
    dist::native::{
        BlobSourceRequest, CloseRequest, CommitRequest, DownloadRequest, ExecutionRequest,
        InputPrefetchRequest, ManifestRequest, OpenTreeRequest, PackageAcquisition, PackageLocator,
        PackagePlanRequest, RetainRequest, RetainedDownloadRequest, ScheduleRequest, StatusRequest,
        codec,
    },
};

mod network;

pub(super) type Allocator = dyn Fn(
        crate::dist::NativeAssignment,
        &crate::build_runtime::NetworkSnapshot,
        std::sync::Arc<crate::build_runtime::PackageCatalog>,
    ) -> Result<ScheduleReply>
    + Send
    + Sync;

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

    fn acquire(
        &self,
        sessions: &NativeSessions,
        locator: &PackageLocator,
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
        sessions.provision_package(
            locator.identity,
            length,
            self.limits,
            &std::env::current_exe()?,
            || {
                let response = crate::http_client::io_runtime()?
                    .block_on(client.get(url.as_str()).send())?
                    .error_for_status()?;
                ensure!(
                    response
                        .content_length()
                        .is_none_or(|size| length.accepts(size)),
                    "upstream package length violates expectation"
                );
                let size = response.content_length().or(locator.expected_size);
                let peer = observed_response_peer(&response, Peer::Upstream);
                Ok(network.meter(
                    Direction::Receive,
                    peer,
                    crate::http_client::ResponseReader::new(response)?,
                    size.unwrap_or(0),
                    size,
                ))
            },
        )
    }
}

pub(super) struct PublicationCallbacks<S, O> {
    pub source_plan: S,
    pub observe_result: O,
}

#[expect(
    clippy::too_many_lines,
    reason = "native listener startup owns the shared session lifetime and starts its coordinated acquisition and maintenance workers"
)]
pub(super) fn spawn(
    cache: (&NativeCacheConfig, NativeStore),
    allocate: impl Fn(
        crate::dist::NativeAssignment,
        &crate::build_runtime::NetworkSnapshot,
        std::sync::Arc<crate::build_runtime::PackageCatalog>,
    ) -> Result<ScheduleReply>
    + Send
    + Sync
    + 'static,
    fetch_peer: impl Fn(
        BlobRef,
        Option<crate::dist::ServerId>,
        &NativeStore,
        Instant,
    ) -> Result<Option<StagedBlob>>
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
) -> Result<(std::net::SocketAddr, Arc<NativeSessions>)> {
    let (config, store) = cache;
    let PublicationCallbacks {
        source_plan,
        observe_result,
    } = publication;
    let socket = super::cluster_http::bind_data_socket(config.public_addr, config.bind_address)?;
    let bound = socket.local_addr()?;
    let limits = config.session_limits()?;
    let sessions = Arc::new(NativeSessions::new(store, limits)?);
    let maintenance = Arc::downgrade(&sessions);
    let fetch_peer = Arc::new(fetch_peer);
    // Keep source acquisition bounded separately from compiler execution
    // and leave capacity for originating-client uploads.
    let peer_threads = config.max_total_uploads.saturating_sub(1).clamp(1, 4);
    for index in 0..peer_threads {
        let sessions = Arc::downgrade(&sessions);
        let fetch_peer = Arc::clone(&fetch_peer);
        thread::Builder::new()
            .name(format!("native-peer-backfill-{index}"))
            .spawn(move || {
                while let Some(sessions) = sessions.upgrade() {
                    match sessions.claim_peer_input(Duration::from_millis(100)) {
                        Ok(Some(claim)) => {
                            let requester = claim.requester();
                            let deadline = Instant::now() + limits.idle_timeout;
                            if let Err(error) = sessions.recover_peer_input(
                                claim,
                                deadline,
                                |blob, store, deadline| {
                                    fetch_peer(blob, Some(requester), store, deadline)
                                },
                            ) {
                                debug!("native peer backfill unavailable: {error:#}");
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            warn!("native peer claim failed: {error:#}");
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
            })?;
    }
    // Result recovery holds the action permit but no compiler slot. It
    // runs outside HTTP and uses the same bounded upload budget as inputs.
    {
        let sessions = Arc::downgrade(&sessions);
        thread::Builder::new()
            .name("native-result-recovery".into())
            .spawn(move || {
                while let Some(sessions) = sessions.upgrade() {
                    if let Err(error) = sessions
                        .recover_next_result(Duration::from_millis(100), |blob, store, deadline| {
                            fetch_peer(blob, None, store, deadline)
                        })
                    {
                        warn!("native result recovery failed: {error:#}");
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            })?;
    }
    let metadata_limit = config.max_metadata_bytes;
    let packages = PackageService::new(config)?;
    network::start(
        &network,
        config.directory.join("network-path-timing.json"),
        config.public_addr,
    )?;
    let retained_sessions = Arc::clone(&sessions);
    let server = Listener::from_socket(
        socket,
        tls,
        ListenerRole::Scheduler(enrollment),
        config.http_threads,
        native_router(move |request, role, operation| {
            respond(
                request,
                role,
                operation,
                NativeServices {
                    sessions: &sessions,
                    packages: packages.as_ref(),
                    network: &network,
                    source_plan: &source_plan,
                    observe_result: &observe_result,
                },
                &allocate,
                metadata_limit,
            )
        }),
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
                    Err(error) => error!("native cache space maintenance failed: {error:#}"),
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

fn native_router<F>(handler: F) -> Router
where
    F: Fn(&Request, &str, &str) -> Response + Send + Sync + 'static,
{
    routes(
        Router::new().route(
            "/api/v5/native/{role}/{operation}",
            path_route(
                MethodFilter::POST,
                |handler: &F, request, (role, operation): (String, String)| {
                    handler(request, &role, &operation)
                },
            ),
        ),
        handler,
    )
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
        Some((file, encoding)) => physical_blob_response(file, encoding),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

pub(super) fn physical_blob_response(mut file: File, encoding: BlobEncoding) -> Result<Response> {
    let (file, encoding) = if encoding == BlobEncoding::Raw {
        let mut encoded = tempfile::tempfile()?;
        crate::build_runtime::encode_native_blob(&mut file, &mut encoded, None)?;
        encoded.rewind()?;
        (encoded, BlobEncoding::ZstdChunks)
    } else {
        (file, encoding)
    };
    let length = file.metadata()?.len();
    let mut response = file_body(file, length);
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
pub(super) fn fetch_peer(
    routes: &SchedulerRequester,
    source: &crate::dist::NativeBlobSource,
    blob: BlobRef,
    network: &NetworkMeter,
    deadline: Instant,
) -> Result<Option<(impl Read + Send + use<>, BlobEncoding)>> {
    // Bounded source probe: allow roughly 4 MiB/s plus setup time,
    // with an absolute ceiling; a slow peer falls back to the origin.
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
        let response = crate::http_client::io_runtime()?.block_on(
            client
                .post(super::super::urls::server_native_blob(&base)?.as_str())
                .timeout(timeout.min(remaining))
                .bearer_auth(&source.token)
                .header("Content-Type", "application/octet-stream")
                .body(codec().serialize(&blob)?)
                .send(),
        );
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
    let response = routes.routes.measure_response(
        source.server,
        sccache_cluster_identity::Role::Worker,
        address,
        response,
    )?;
    let response = network.meter(Direction::Receive, peer, response, blob.size, size);
    Ok(Some((response, encoding)))
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
    allocate: &Allocator,
    limit: usize,
) -> Response {
    if request.header("Content-Type") != Some("application/octet-stream") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let publisher = match role {
        "client" => {
            if let Some(response) = role_error(request, Role::Client) {
                return response;
            }
            Publisher::Client
        }
        "worker" => {
            if let Some(response) = role_error(request, Role::Worker) {
                return response;
            }
            let server = request.id();
            let Some(job) = request
                .header("X-Sccache-Native-Job")
                .and_then(|job| job.parse::<u64>().ok())
            else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            Publisher::Worker { peer: server, job }
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    match dispatch(request, services, allocate, publisher, operation, limit) {
        Ok(response) => response,
        Err(error) if error.is::<NativeContentPending>() => {
            (StatusCode::ACCEPTED, "native input pending").into_response()
        }
        Err(error) if error.is::<NativeInputRejected>() => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "native input bytes rejected",
        )
            .into_response(),
        Err(error) if error.is::<NativeServiceBusy>() => {
            (StatusCode::SERVICE_UNAVAILABLE, "native service busy").into_response()
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
    allocate: &Allocator,
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
        "package_acquire" | "rust_package_acquire"
            if publisher == Publisher::Client && packages.is_some() =>
        {
            let locator: PackageLocator = metadata(request, limit)?;
            let service = packages.context("native original-package provisioning disabled")?;
            let (package, reused) = service.acquire(sessions, &locator, network)?;
            if operation == "rust_package_acquire" {
                let manifest = sessions
                    .store()
                    .publish_rust_installer(&package, service.limits.policy()?.directory)?;
                encode(
                    &PackageAcquisition {
                        package: manifest,
                        reused,
                    },
                    limit,
                )
            } else {
                encode(
                    &PackageAcquisition {
                        package: package.receipt(),
                        reused,
                    },
                    limit,
                )
            }
        }
        "package_import" | "rust_package_import"
            if publisher == Publisher::Client && packages.is_some() =>
        {
            let service = packages.context("native original-package provisioning disabled")?;
            let mut body = request.data().context("missing original package body")?;
            // Fixed width: SHA-256, u32 codec, u64 length. The remaining
            // bytes stream directly into verified archive staging.
            let source: PackageSource = codec().with_limit(44).deserialize_from(&mut body)?;
            let (package, _) = sessions.provision_package(
                source.identity,
                ArchiveLength::Exact(source.size),
                service.limits,
                &std::env::current_exe()?,
                || {
                    Ok(network.meter(
                        Direction::Receive,
                        peer,
                        body,
                        source.size,
                        Some(source.size),
                    ))
                },
            )?;
            if operation == "rust_package_import" {
                encode(
                    &sessions
                        .store()
                        .publish_rust_installer(&package, service.limits.policy()?.directory)?,
                    limit,
                )
            } else {
                encode(&package.receipt(), limit)
            }
        }
        "admit" if publisher == Publisher::Client => {
            let (input, mode, declared): (
                ExecutionSpec,
                ActionMode,
                BTreeMap<TreeId, TreeManifest>,
            ) = metadata(request, limit)?;
            encode(
                &sessions.admit(input.action_request()?, publisher, mode, declared)?,
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
        "inputs_staged" => {
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
        "backfill_input" if publisher == Publisher::Client => {
            let mut body = request.data().context("missing native backfill body")?;
            let header: UploadHeader = codec().with_limit(73).deserialize_from(&mut body)?;
            ensure!(
                header.encoding == BlobEncoding::Raw as u8,
                "backfill input requires logical bytes"
            );
            let reader = network.meter(Direction::Receive, peer, body, header.blob.size, None);
            sessions.backfill_input(header.ticket, header.blob, reader)?;
            encode(&(), limit)
        }
        "schedule" if publisher == Publisher::Client => {
            let ScheduleRequest {
                ticket,
                spec,
                receiver,
                selected,
            } = metadata(request, limit)?;
            ensure!(receiver.valid(), "invalid client delivery telemetry");
            let requester_id = request.id();
            let request = spec.action_request()?;
            let selection = crate::build_runtime::wire::DeliverySelection::new(&spec, selected)?;
            let profile = selection.profile;
            encode(
                &sessions.schedule(
                    ticket,
                    &request,
                    requester_id,
                    selection,
                    |inputs, trees| {
                        let blobs = inputs
                            .iter()
                            .map(|(&id, &size)| BlobRef { id, size })
                            .collect::<Vec<_>>();
                        let mut packages =
                            sessions
                                .store()
                                .package_catalog(&blobs)
                                .unwrap_or_else(|error| {
                                    warn!(
                                        "Native package placement catalog unavailable: {error:#}"
                                    );
                                    crate::build_runtime::PackageCatalog::default()
                                });
                        packages.restrict_to_trees(trees);
                        let mut snapshot = network.snapshot();
                        snapshot.interfaces = crate::dist::cluster::interface_report();
                        allocate(
                            crate::dist::NativeAssignment {
                                ticket,
                                spec,
                                input_blobs: inputs,
                                estimated_result_bytes: None,
                                receiver: Some((requester_id, receiver)),
                                delivery_profile: Some(profile),
                            },
                            &snapshot,
                            std::sync::Arc::new(packages),
                        )
                    },
                )?,
                limit,
            )
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
        "retain_renew" if publisher == Publisher::Client => {
            sessions.renew_retention(metadata(request, limit)?, request.id())?;
            encode(&(), limit)
        }
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
            let (file, encoding) = if operation == "retain_download" {
                ensure!(publisher == Publisher::Client, "retention is client-owned");
                let RetainedDownloadRequest { group, blob } = metadata(request, limit)?;
                sessions.download_retained(group, request.id(), blob)?
            } else {
                let DownloadRequest { ticket, id } = metadata(request, limit)?;
                sessions.download(ticket, publisher, id)?
            };
            let logical =
                crate::build_runtime::BlobReader::open(file.try_clone()?, encoding)?.len();
            let size = file.metadata()?.len();
            let reader = network.meter(Direction::Send, peer, file, logical, Some(size));
            let mut response = file_body(reader, size);
            response.headers_mut().insert(
                "x-sccache-cas-encoding",
                http::HeaderValue::from_static(encoding.http_value()),
            );
            Ok(response)
        }
        "tree_offer" if publisher == Publisher::Client => {
            encode(&sessions.offer_tree(metadata(request, limit)?)?, limit)
        }
        "tree_commit" if publisher == Publisher::Client => {
            encode(&sessions.commit_tree(metadata(request, limit)?)?, limit)
        }
        "tree_open" => {
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
        "verify" => {
            let ExecutionRequest { ticket, spec } = metadata(request, limit)?;
            sessions.verify_execution(ticket, publisher, &spec.action_request()?)?;
            encode(&(), limit)
        }
        "begin" => {
            let ManifestRequest { ticket, manifest } = metadata(request, limit)?;
            let reply = sessions.begin(ticket, publisher, manifest)?;
            if let Publisher::Worker { peer, job } = publisher {
                observe_result(
                    peer,
                    crate::dist::JobId(job),
                    crate::dist::NativeLifecycleEvent::Negotiated,
                );
            }
            encode(&reply, limit)
        }
        "upload" => {
            let mut body = request.data().context("missing native upload body")?;
            // Fixed-width header, never deserialize or buffer the actual blob.
            let header: UploadHeader = codec().with_limit(73).deserialize_from(&mut body)?;
            let reader = network.meter(Direction::Receive, peer, body, header.blob.size, None);
            sessions.upload(
                header.ticket,
                publisher,
                header.blob,
                BlobEncoding::try_from(header.encoding)?,
                reader,
            )?;
            encode(&(), limit)
        }
        "commit" => {
            let CommitRequest {
                ticket,
                retained_after_begin_millis,
                observation,
            } = metadata(request, limit)?;
            let manifest = sessions.commit(ticket, publisher)?;
            if let Publisher::Worker { peer, job } = publisher {
                observe_result(
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
        "renew" => {
            sessions.renew(metadata(request, limit)?, publisher)?;
            encode(&(), limit)
        }
        "fail" => {
            sessions.fail(metadata(request, limit)?, publisher)?;
            encode(&(), limit)
        }
        _ => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

pub(super) fn metadata<T: DeserializeOwned>(request: &Request, limit: usize) -> Result<T> {
    let limit = u64::try_from(limit)?;
    let max_read = limit
        .checked_add(1)
        .context("native metadata limit overflow")?;
    let mut data = Vec::new();
    request
        .data()
        .context("missing native metadata body")?
        .take(max_read)
        .read_to_end(&mut data)?;
    ensure!(
        u64::try_from(data.len())? <= limit,
        "native metadata exceeds configured limit"
    );
    Ok(codec().with_limit(limit).deserialize(&data)?)
}

fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Response> {
    let data = codec().with_limit(u64::try_from(limit)?).serialize(value)?;
    Ok(binary(data))
}

#[cfg(test)]
mod tests;
