//! Dedicated native cache listener. Reuse scheduler authentication and job
//! ownership without running filesystem I/O on the scheduling request pool.

use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, ensure};
use bincode::Options;
use rouille::{Request, Response, ResponseBody};
use serde::{Serialize, de::DeserializeOwned};

use super::{ClientAuthCheck, ServerAuthenticator, authenticate_client, authenticate_server};
use crate::{
    build_runtime::{
        ActionMode, ArchiveLength, BlobRef, ContentId, Direction, ExecutionSpec,
        NativeContentPending, NativeInputRejected, NativeServiceBusy, NativeSessions, NativeStore,
        NetworkMeter, PackageIdentity, PackageImportLimits, PackageSource, Peer, StagedBlob,
        TreeId, TreeManifest, VerifiedPackage,
        wire::{Publisher, ScheduleReply, UploadHeader},
    },
    config::scheduler::NativeCacheConfig,
    dist::native::{
        DownloadRequest, ExecutionRequest, InputPrefetchRequest, ManifestRequest, OpenTreeRequest,
        PackageAcquisition, PackageLocator, PackagePlanRequest, codec,
    },
};

mod network;

pub(super) type Allocator = dyn Fn(
        crate::dist::NativeAssignment,
        &crate::build_runtime::NetworkSnapshot,
    ) -> Result<ScheduleReply>
    + Send
    + Sync;

struct PackageService {
    limits: PackageImportLimits,
    upstreams: BTreeMap<String, (reqwest::Url, reqwest::blocking::Client)>,
}

impl PackageService {
    fn new(config: &NativeCacheConfig) -> Result<Option<Self>> {
        let Some(limits) = config.package_import else {
            return Ok(None);
        };
        let mut upstreams = BTreeMap::new();
        for (name, upstream) in &config.package_upstreams {
            let client = crate::util::new_reqwest_blocking_builder()?
                .timeout(Duration::from_secs(upstream.timeout_secs))
                .connect_timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
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
                let response = client.get(url).send()?.error_for_status()?;
                ensure!(
                    response
                        .content_length()
                        .is_none_or(|size| length.accepts(size)),
                    "upstream package length violates expectation"
                );
                let size = response.content_length().or(locator.expected_size);
                Ok(network.meter(
                    Direction::Receive,
                    Peer::Upstream,
                    response,
                    size.unwrap_or(0),
                    size,
                ))
            },
        )
    }
}

pub(super) fn spawn(
    config: &NativeCacheConfig,
    allocate: impl Fn(
        crate::dist::NativeAssignment,
        &crate::build_runtime::NetworkSnapshot,
    ) -> Result<ScheduleReply>
    + Send
    + Sync
    + 'static,
    fetch_peer: impl Fn(
        BlobRef,
        Option<std::net::SocketAddr>,
        &NativeStore,
        Instant,
    ) -> Result<Option<StagedBlob>>
    + Send
    + Sync
    + 'static,
    client_auth: Arc<dyn ClientAuthCheck>,
    server_auth: Arc<ServerAuthenticator>,
    network: Arc<NetworkMeter>,
) -> Result<()> {
    let limits = config.session_limits()?;
    let sessions = Arc::new(NativeSessions::new(
        NativeStore::open_managed(&config.directory, config.space)?,
        limits,
    )?);
    let maintenance = Arc::downgrade(&sessions);
    let fetch_peer = Arc::new(fetch_peer);
    // Keep source acquisition bounded separately from compiler execution
    // and leave capacity for originating-client uploads.
    let peer_threads = config.max_total_uploads.saturating_sub(1).min(4).max(1);
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
        config.directory.join("network-timing.json"),
        config.public_addr,
    )?;
    let server = rouille::Server::new(config.public_addr, move |request| {
        respond(
            request,
            NativeServices {
                sessions: &sessions,
                packages: packages.as_ref(),
                network: &network,
            },
            &allocate,
            &*client_auth,
            &*server_auth,
            metadata_limit,
        )
    })
    .map_err(|error| anyhow!("could not bind native cache listener: {error}"))?
    .pool_size(config.http_threads);
    info!("Native cache listening on {}", config.public_addr);
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
            server.run();
            error!("native cache HTTP listener terminated");
        })?;
    Ok(())
}

const PREFIX: &str = "/api/v2/native/";

/// Compress only when a representative prefix wins comfortably. We keep the
/// immutable digest-named files raw for mmap/materialization; this codec is
/// solely a negotiated transfer representation.
pub(super) fn blob_response(mut file: File, accept_zstd: bool) -> Result<Response> {
    const SAMPLE_SIZE: u64 = 128 * 1024;
    const MIN_COMPRESS_BYTES: u64 = 32 * 1024;
    if !accept_zstd || file.metadata()?.len() < MIN_COMPRESS_BYTES {
        return Ok(Response::from_file("application/octet-stream", file));
    }

    let sampled = usize::try_from(file.metadata()?.len().min(SAMPLE_SIZE))?;
    let mut prefix = vec![0; sampled];
    file.read_exact(&mut prefix)?;
    let packed = zstd::bulk::compress(&prefix, 1)?;
    file.seek(SeekFrom::Start(0))?;

    // A meaningful margin amortizes encoding CPU under heavy load and avoids
    // paying to recompress already packed/upstream-compressed binaries.
    if packed.len().saturating_add(64) * 100 > sampled * 85 {
        return Ok(Response::from_file("application/octet-stream", file));
    }

    let encoded = zstd::stream::read::Encoder::new(file, 1)?;
    Ok(Response {
        status_code: 200,
        headers: vec![
            ("Content-Type".into(), "application/octet-stream".into()),
            ("X-Sccache-Blob-Codec".into(), "zstd".into()),
        ],
        data: ResponseBody::from_reader(encoded),
        upgrade: None,
    })
}

/// Reuse TLS connections without broadening each peer's pinned trust root.
#[derive(Default)]
pub(super) struct PeerHttp {
    clients: Mutex<HashMap<crate::dist::ServerId, (ContentId, reqwest::blocking::Client)>>,
}

impl PeerHttp {
    fn client(
        &self,
        server: crate::dist::ServerId,
        certificate: &[u8],
    ) -> Result<reqwest::blocking::Client> {
        let digest = ContentId::of(certificate);
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| anyhow!("native peer HTTP cache poisoned"))?;
        if let Some((saved, client)) = clients.get(&server)
            && *saved == digest
        {
            return Ok(client.clone());
        }
        let certificate = reqwest::Certificate::from_pem(certificate)?;
        let client = reqwest::blocking::Client::builder()
            .tls_certs_only([certificate])
            .connect_timeout(Duration::from_secs(1))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(2)
            .no_proxy()
            .build()?;
        // Bound stale worker connections across fleet churn. Current requests
        // retain their own cloned clients and are unaffected.
        if clients.len() >= 64 {
            clients.clear();
        }
        clients.insert(server, (digest, client.clone()));
        Ok(client)
    }

    /// Retrieve a blob from a specific worker using its exact-content
    /// capability. A stale inventory hint is an ordinary miss.
    pub(super) fn fetch(
        &self,
        source: crate::dist::NativeBlobSource,
        blob: BlobRef,
        certificate: &[u8],
        network: &NetworkMeter,
        deadline: Instant,
    ) -> Result<Option<Box<dyn Read + Send>>> {
        // Bounded source probe: allow roughly 4 MiB/s plus setup time,
        // with an absolute ceiling; a slow peer falls back to the origin.
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "native peer deadline expired");
        let timeout =
            Duration::from_secs((5 + blob.size.div_ceil(1024 * 1024)).min(60)).min(remaining);
        let response = self
            .client(source.server, certificate)?
            .post(super::super::urls::server_native_blob(source.server)?)
            .timeout(timeout)
            .bearer_auth(source.token)
            .header("Content-Type", "application/octet-stream")
            .header("X-Sccache-Accept-Blob-Codec", "zstd")
            .body(codec().serialize(&blob)?)
            .send()?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response = response.error_for_status()?;
        let encoding = response.headers().get("X-Sccache-Blob-Codec").cloned();
        let size = response.content_length();
        let response = network.meter(
            Direction::Receive,
            Peer::Worker(source.server.addr()),
            response,
            blob.size,
            size,
        );
        match encoding.as_ref() {
            None => Ok(Some(Box::new(response))),
            Some(codec) if codec.as_bytes() == b"zstd" => {
                Ok(Some(Box::new(zstd::stream::read::Decoder::new(response)?)))
            }
            Some(other) => anyhow::bail!("unsupported peer blob codec: {other:?}"),
        }
    }
}

#[derive(Clone, Copy)]
struct NativeServices<'a> {
    sessions: &'a NativeSessions,
    packages: Option<&'a PackageService>,
    network: &'a NetworkMeter,
}

fn respond(
    request: &Request,
    services: NativeServices<'_>,
    allocate: &Allocator,
    client_auth: &dyn ClientAuthCheck,
    server_auth: &ServerAuthenticator,
    limit: usize,
) -> Response {
    if request.method() != "POST" {
        return Response::empty_404();
    }
    let url = request.url();
    let Some(path) = url.strip_prefix(PREFIX) else {
        return Response::empty_404();
    };
    let Some((role, operation)) = path.split_once('/') else {
        return Response::empty_404();
    };
    if request.header("Content-Type") != Some("application/octet-stream") {
        return Response::empty_400();
    }
    let publisher = match role {
        "client" => {
            if let Err(response) = authenticate_client(request, client_auth) {
                return response;
            }
            Publisher::Client
        }
        "worker" => {
            let server = match authenticate_server(request, server_auth) {
                Ok(server) => server,
                Err(response) => return response,
            };
            let Some(job) = request
                .header("X-Sccache-Native-Job")
                .and_then(|job| job.parse::<u64>().ok())
            else {
                return Response::empty_400();
            };
            Publisher::Worker {
                address: server.addr(),
                job,
            }
        }
        _ => return Response::empty_404(),
    };
    match dispatch(request, services, allocate, publisher, operation, limit) {
        Ok(response) => response,
        Err(error) if error.is::<NativeContentPending>() => {
            Response::text("native input pending").with_status_code(202)
        }
        Err(error) if error.is::<NativeInputRejected>() => {
            Response::text("native input bytes rejected").with_status_code(422)
        }
        Err(error) if error.is::<NativeServiceBusy>() => {
            Response::text("native service busy").with_status_code(503)
        }
        Err(error) => {
            // Do not return host paths, auth tokens or raw internal metadata
            // to callers. The service log carries diagnostic context.
            warn!("Native cache {operation} rejected: {error:#}");
            Response::text("native cache operation rejected").with_status_code(409)
        }
    }
}

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
    } = services;
    let peer = match publisher {
        Publisher::Client => Peer::Client(request.remote_addr().ip()),
        Publisher::Worker { address, .. } => Peer::Worker(address),
    };
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
        "input_demands" if publisher == Publisher::Client => {
            encode(&sessions.input_demands(metadata(request, limit)?)?, limit)
        }
        "input_unavailable" if publisher == Publisher::Client => {
            let (ticket, demand) = metadata(request, limit)?;
            sessions.input_unavailable(ticket, demand)?;
            encode(&(), limit)
        }
        "backfill_input" if publisher == Publisher::Client => {
            let mut body = request.data().context("missing native backfill body")?;
            let header: UploadHeader = codec().with_limit(72).deserialize_from(&mut body)?;
            let reader = network.meter(
                Direction::Receive,
                peer,
                body,
                header.blob.size,
                Some(header.blob.size),
            );
            sessions.backfill_input(header.ticket, header.blob, reader)?;
            encode(&(), limit)
        }
        "schedule" if publisher == Publisher::Client => {
            let ExecutionRequest { ticket, spec } = metadata(request, limit)?;
            let request = spec.action_request()?;
            encode(
                &sessions.schedule(ticket, &request, |inputs| {
                    let snapshot = network.snapshot();
                    allocate(
                        crate::dist::NativeAssignment {
                            ticket,
                            spec,
                            input_blobs: inputs,
                        },
                        &snapshot,
                    )
                })?,
                limit,
            )
        }
        "status" if publisher == Publisher::Client => {
            encode(&sessions.status(metadata(request, limit)?)?, limit)
        }
        "close" => {
            sessions.close(metadata(request, limit)?, publisher)?;
            encode(&(), limit)
        }
        "download" => {
            let DownloadRequest { ticket, id } = metadata(request, limit)?;
            let file = sessions.download(ticket, publisher, id)?;
            let logical = file.metadata()?.len();
            let mut response = blob_response(
                file,
                request.header("X-Sccache-Accept-Blob-Codec") == Some("zstd"),
            )?;
            let (reader, size) = response.data.into_reader_and_size();
            let reader = network.meter(
                Direction::Send,
                peer,
                reader,
                logical,
                size.map(|size| size as u64),
            );
            response.data = match size {
                Some(size) => ResponseBody::from_reader_and_size(reader, size),
                None => ResponseBody::from_reader(reader),
            };
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
            encode(&sessions.begin(ticket, publisher, manifest)?, limit)
        }
        "upload" => {
            let mut body = request.data().context("missing native upload body")?;
            // Fixed-width header, never deserialize or buffer the actual blob.
            let header: UploadHeader = codec().with_limit(72).deserialize_from(&mut body)?;
            let reader = network.meter(
                Direction::Receive,
                peer,
                body,
                header.blob.size,
                Some(header.blob.size),
            );
            sessions.upload(header.ticket, publisher, header.blob, reader)?;
            encode(&(), limit)
        }
        "commit" => encode(
            &sessions.commit(metadata(request, limit)?, publisher)?,
            limit,
        ),
        "renew" => {
            sessions.renew(metadata(request, limit)?, publisher)?;
            encode(&(), limit)
        }
        "fail" => {
            sessions.fail(metadata(request, limit)?, publisher)?;
            encode(&(), limit)
        }
        _ => Ok(Response::empty_404()),
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
    Ok(Response::from_data("application/octet-stream", data))
}

#[cfg(test)]
mod tests;
