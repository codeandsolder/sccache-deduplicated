//! Client and worker adapters for the scheduler's native cache protocol.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Cursor, Read, Seek, Write},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::build_runtime::{
    ActionMode, BlobEncoding, BlobRef, ContentId, ExecutionSpec, InstallationManifest,
    PackageIdentity, PackageReceipt, PackageSource, PackageTransferCost, ResultManifest, TreeId,
    TreeManifest,
    wire::{
        BeginResult, InputDemand, InputPoll, NativeAdmission, NativeRunRequest, NativeRunResult,
        NativeStatus, ScheduleReply, Ticket, TreeOffer, TreeRead, UploadHeader, WorkerAllocation,
    },
};
use crate::dist::{
    JobId,
    cluster_routes::{MeasuredReader, Transfer},
};

#[cfg(any(
    feature = "dist-server",
    all(target_os = "linux", feature = "native-store")
))]
pub(in crate::dist) mod ingress;
mod package;
#[cfg(all(target_os = "linux", feature = "native-store"))]
mod peer_delivery;
mod upload;
pub use package::{
    PackageAcquisition, PackageLocator, map_packages, validate_upstream_base,
    validate_upstream_name,
};

type LeaseCheck<'a> = dyn Fn() -> Result<()> + Sync + 'a;

#[derive(Serialize, Deserialize)]
pub(super) struct ExecutionRequest {
    pub ticket: Ticket,
    pub spec: ExecutionSpec,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ScheduleRequest {
    pub ticket: Ticket,
    pub spec: ExecutionSpec,
    pub receiver: crate::build_runtime::wire::ClientDeliveryRates,
    pub selected: std::collections::BTreeSet<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ManifestRequest {
    pub ticket: Ticket,
    pub manifest: ResultManifest,
}

#[derive(Serialize, Deserialize)]
pub(super) struct CommitRequest {
    pub ticket: Ticket,
    // Duration from receipt of the begin response until local grace expiry.
    pub retained_after_begin_millis: u64,
    pub observation: Option<crate::build_runtime::wire::ActionObservation>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct DownloadRequest {
    pub ticket: Ticket,
    pub id: ContentId,
}

#[derive(Serialize, Deserialize)]
pub(super) struct RetainRequest {
    pub group: Ticket,
    pub action: Ticket,
    pub result: crate::build_runtime::ResultId,
}

#[derive(Serialize, Deserialize)]
pub(super) struct RetainedDownloadRequest {
    pub group: Ticket,
    pub blob: BlobRef,
}

#[derive(Serialize, Deserialize)]
pub(super) struct CloseRequest {
    pub ticket: Ticket,
    pub delivery: Option<crate::build_runtime::wire::ClientDeliveryObservation>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct StatusRequest {
    pub ticket: Ticket,
    pub preview: bool,
}

#[derive(Serialize, Deserialize)]
pub(super) struct BlobSourceRequest {
    pub ticket: Ticket,
    pub blobs: Vec<BlobRef>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct OpenTreeRequest {
    pub action: Ticket,
    pub tree: TreeId,
}

#[derive(Serialize, Deserialize)]
pub(super) struct InputPrefetchRequest {
    pub ticket: Ticket,
    pub missing: Vec<BlobRef>,
}

#[cfg(all(target_os = "linux", feature = "native-store"))]
#[derive(Serialize, Deserialize)]
pub(super) struct PackagePlanRequest {
    pub ticket: Ticket,
    pub missing: Vec<BlobRef>,
    pub max_archive_bytes: u64,
    pub cost: PackageTransferCost,
}

#[derive(Clone, Copy)]
enum Role {
    Client,
    Worker(JobId),
}

/// Bounded streaming HTTP client for native result publication and retrieval.
///
/// The worker uses the same authenticated listener as clients, but is scoped
/// to its scheduler-assigned job and the delegated ticket.
#[derive(Clone)]
pub struct NativeCacheClient {
    routes: std::sync::Arc<crate::dist::cluster::ClusterRoutes>,
    peer: std::sync::Arc<sccache_cluster_identity::PeerCredentials>,
    address: std::net::SocketAddr,
    candidates: std::sync::Arc<
        std::sync::Mutex<Option<(sccache_peer_identity::RouteSet, Instant, Instant)>>,
    >,
    discovery: std::sync::Arc<tokio::sync::Mutex<()>>,
    role: Role,
    metadata_limit: u64,
    timeout: Duration,
}

struct UploadObservation {
    address: crate::dist::cluster_routes::Route,
    length: u64,
    header_length: usize,
    started: Instant,
    local: Option<std::net::IpAddr>,
    evidence: Option<crate::dist::cluster_routes::interface::Evidence>,
}

impl NativeCacheClient {
    /// Create an authenticated native client with explicit request bounds.
    ///
    /// # Errors
    /// Returns an error for invalid endpoint configuration or HTTP setup.
    pub fn new(
        base: &url::Url,
        peer: std::sync::Arc<sccache_cluster_identity::PeerCredentials>,
        timeout: Duration,
        metadata_limit: u64,
    ) -> Result<Self> {
        let address = sccache_cluster_identity::endpoint(base)?;
        ensure!(
            metadata_limit > 0 && metadata_limit < u64::MAX && !timeout.is_zero(),
            "invalid native client bounds"
        );
        Ok(Self {
            routes: std::sync::Arc::new(crate::dist::cluster::ClusterRoutes::for_peer(
                std::sync::Arc::clone(&peer),
            )),
            peer,
            address,
            candidates: std::sync::Arc::default(),
            discovery: std::sync::Arc::default(),
            role: Role::Client,
            metadata_limit,
            timeout,
        })
    }

    /// Reuse a configured HTTP client for one authenticated worker job.
    #[must_use = "the returned client is scoped to this worker job"]
    pub const fn for_worker(mut self, job: JobId) -> Self {
        self.role = Role::Worker(job);
        self
    }

    /// Refresh the shared member credential without discarding its route measurements.
    pub fn refresh_credentials(&self) {
        if let Err(error) = crate::dist::cluster::refresh_blocking(&self.peer) {
            warn!("Native client certificate renewal will be retried: {error:#}");
        }
    }

    /// Query scheduler status using the same pinned cluster identity as builds.
    #[cfg(all(target_os = "linux", feature = "dist-client"))]
    pub(crate) async fn scheduler_status(&self) -> Result<super::SchedulerStatusResult> {
        let (client, base) = self.routes.endpoint(
            self.peer.scheduler_id(),
            sccache_cluster_identity::Role::Scheduler,
            crate::dist::cluster_routes::Route::unbound(self.peer.scheduler_address()),
        )?;
        let url = super::http::urls::scheduler_status(&base)?;
        super::http::transport::send_async(
            client.get(url.as_str()),
            super::http::transport::RequestClass::Control,
        )
        .await
    }

    fn cache_routes(&self) -> sccache_peer_identity::RouteSet {
        crate::http_client::io_runtime().map_or_else(
            |_| sccache_peer_identity::RouteSet::new(self.address, []),
            |runtime| runtime.block_on(self.cache_routes_async()),
        )
    }

    async fn cache_routes_async(&self) -> sccache_peer_identity::RouteSet {
        use sccache_peer_identity::{Role, RouteSet};
        #[derive(serde::Deserialize)]
        struct Reply {
            routes: RouteSet,
        }
        let fallback = || RouteSet::new(self.address, []);
        // No synchronous lock spans a network operation. Concurrent requests
        // use the last usable advertisement (or the configured endpoint)
        // instead of queueing behind one slow discovery RPC.
        let Ok(cached) = self.candidates.lock().map(|cached| cached.clone()) else {
            return fallback();
        };
        if let Some((routes, _, attempted)) = cached.as_ref()
            && attempted.elapsed() < Duration::from_secs(30)
        {
            return routes.clone();
        }
        let previous = || {
            cached
                .as_ref()
                .filter(|(_, updated, _)| updated.elapsed() < Duration::from_secs(90))
                .map_or_else(
                    || (fallback(), Instant::now()),
                    |(routes, updated, _)| (routes.clone(), *updated),
                )
        };
        let Ok(_discovery) = self.discovery.try_lock() else {
            return previous().0;
        };
        // Recheck after taking ownership in case another request completed
        // discovery between our snapshot and acquisition of the guard.
        if let Ok(cached) = self.candidates.lock()
            && let Some((routes, _, attempted)) = cached.as_ref()
            && attempted.elapsed() < Duration::from_secs(30)
        {
            return routes.clone();
        }
        let fetched = async {
            let (client, base) = self.routes.endpoint(
                self.peer.scheduler_id(),
                Role::Scheduler,
                crate::dist::cluster_routes::Route::unbound(self.peer.scheduler_address()),
            )?;
            let response = client
                .get(base.join("/api/v1/scheduler/native_routes")?.as_str())
                .header(http::header::ACCEPT, "application/octet-stream")
                .timeout(Duration::from_millis(500))
                .send()
                .await?
                .error_for_status()?;
            let reply: Reply = decode_response_async(response, 4096).await?;
            ensure!(reply.routes.valid(), "invalid scheduler routes");
            Ok::<_, anyhow::Error>(RouteSet::new(self.address, reply.routes.iter()))
        }
        .await;
        let (routes, updated) = match fetched {
            Ok(routes) => (routes, Instant::now()),
            Err(error) => {
                debug!("Native cache path discovery unavailable: {error:#}");
                previous()
            }
        };
        self.routes
            .prime(self.peer.scheduler_id(), Role::Scheduler, &routes);
        if let Ok(mut cached) = self.candidates.lock() {
            *cached = Some((routes.clone(), updated, Instant::now()));
        }
        routes
    }

    /// Report only fresh path measurements; heartbeat generation never
    /// performs network I/O or waits for route discovery.
    #[must_use = "the snapshot supplies current route costs"]
    pub fn path_rates(&self) -> crate::build_runtime::wire::CachePathRates {
        use sccache_peer_identity::{Role, RouteSet};
        let cached = self.candidates.try_lock().ok();
        let fallback = RouteSet::new(self.address, []);
        let routes = cached
            .as_deref()
            .and_then(Option::as_ref)
            .filter(|(_, updated, _)| updated.elapsed() < Duration::from_secs(90))
            .map_or(&fallback, |(routes, _, _)| routes);
        let peer = self.peer.scheduler_id();
        let rates = crate::build_runtime::wire::CachePathRates {
            download: self
                .routes
                .best_rate(peer, Role::Scheduler, routes, Transfer::Download(0)),
            upload: self
                .routes
                .best_rate(peer, Role::Scheduler, routes, Transfer::Upload(0)),
        };
        drop(cached);
        rates
    }

    /// Fresh verified worker-to-receiver logical delivery rates, bounded
    /// for heartbeat transport. Never initiates network I/O.
    #[cfg(all(target_os = "linux", feature = "native-store"))]
    #[must_use = "the snapshot supplies peer delivery forecasts"]
    pub fn peer_download_rates(&self) -> Vec<crate::build_runtime::wire::PeerDownloadRate> {
        self.routes.peer_download_rates()
    }

    fn operation_path(&self, operation: &str) -> (String, Option<JobId>) {
        let (role, job) = match self.role {
            Role::Client => ("client", None),
            Role::Worker(job) => ("worker", Some(job)),
        };
        (format!("/api/v5/native/{role}/{operation}"), job)
    }

    fn request_at(
        &self,
        operation: &str,
        address: crate::dist::cluster_routes::Route,
    ) -> Result<wreq::RequestBuilder> {
        let (path, job) = self.operation_path(operation);
        let (http, base) = self.routes.endpoint(
            self.peer.scheduler_id(),
            sccache_cluster_identity::Role::Scheduler,
            address,
        )?;
        let url = base.join(&path)?;
        let mut request = http
            .post(url.as_str())
            .timeout(self.timeout)
            .header(http::header::CONTENT_TYPE, "application/octet-stream");
        if let Some(job) = job {
            request = request.header("X-Sccache-Native-Job", job.to_string());
        }
        Ok(request)
    }

    fn cache_endpoints(
        &self,
        transfer: Option<Transfer>,
    ) -> Vec<crate::dist::cluster_routes::Route> {
        self.order_cache_endpoints(&self.cache_routes(), transfer)
    }

    fn order_cache_endpoints(
        &self,
        routes: &sccache_peer_identity::RouteSet,
        transfer: Option<Transfer>,
    ) -> Vec<crate::dist::cluster_routes::Route> {
        let peer = self.peer.scheduler_id();
        let role = sccache_cluster_identity::Role::Scheduler;
        self.routes.prime(peer, role, routes);
        transfer.map_or_else(
            || self.routes.ordered(peer, role, routes),
            |transfer| self.routes.ordered_transfer(peer, role, routes, transfer),
        )
    }

    fn send_to_cache(
        &self,
        operation: &str,
        body: Vec<u8>,
        timeout: Duration,
        transfer: Option<Transfer>,
    ) -> Result<(wreq::Response, crate::dist::cluster_routes::Route)> {
        crate::http_client::io_runtime()?
            .block_on(self.send_to_cache_async(operation, body, timeout, transfer))
    }

    async fn send_to_cache_async(
        &self,
        operation: &str,
        body: Vec<u8>,
        timeout: Duration,
        transfer: Option<Transfer>,
    ) -> Result<(wreq::Response, crate::dist::cluster_routes::Route)> {
        let start = Instant::now();
        let mut last_error = None;
        let body = bytes::Bytes::from(body);
        let routes = self.cache_routes_async().await;
        for address in self.order_cache_endpoints(&routes, transfer) {
            let remaining = timeout.checked_sub(start.elapsed()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "native request deadline expired")
            })?;
            let response = self
                .request_at(operation, address)?
                .timeout(remaining)
                .body(body.clone())
                .send()
                .await;
            match response {
                Err(error) if error.is_connect() => {
                    self.routes.failed(
                        self.peer.scheduler_id(),
                        sccache_cluster_identity::Role::Scheduler,
                        address,
                    );
                    last_error = Some(error);
                }
                result => return Ok((result?, address)),
            }
        }
        Err(last_error.context("native cache route unavailable")?.into())
    }

    fn send_replayable(
        &self,
        operation: &str,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<wreq::Response> {
        self.send_to_cache(operation, body, timeout, None)
            .map(|(response, _)| response)
    }

    fn control<T: Serialize + Sync, R: DeserializeOwned>(
        &self,
        operation: &str,
        value: &T,
    ) -> Result<R> {
        self.control_with_timeout(operation, value, self.timeout)
    }

    fn control_with_timeout<T: Serialize + Sync, R: DeserializeOwned>(
        &self,
        operation: &str,
        value: &T,
        timeout: Duration,
    ) -> Result<R> {
        crate::http_client::io_runtime()?
            .block_on(self.control_with_timeout_async(operation, value, timeout))
    }

    async fn control_with_timeout_async<T: Serialize + Sync, R: DeserializeOwned>(
        &self,
        operation: &str,
        value: &T,
        timeout: Duration,
    ) -> Result<R> {
        ensure!(
            !timeout.is_zero(),
            "native control request deadline expired"
        );
        let data = codec().with_limit(self.metadata_limit).serialize(value)?;
        let timeout = timeout.min(self.timeout);
        tokio::time::timeout(timeout, async {
            let (response, _) = self
                .send_to_cache_async(operation, data, timeout, None)
                .await?;
            decode_response_async(response.error_for_status()?, self.metadata_limit).await
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "native control request deadline expired",
            )
        })?
    }

    // Retrying is deliberately limited to package resolution: a busy reply
    // does not mutate anything, and even a repeated acquisition is idempotent.
    fn package_control<T: Serialize + Sync, R: DeserializeOwned>(
        &self,
        operation: &str,
        value: &T,
    ) -> Result<R> {
        let data = codec().with_limit(self.metadata_limit).serialize(value)?;
        let start = Instant::now();
        loop {
            let remaining = self
                .timeout
                .checked_sub(start.elapsed())
                .context("package provisioning deadline expired")?;
            let response = self.send_replayable(operation, data.clone(), remaining)?;
            if response.status() != http::StatusCode::SERVICE_UNAVAILABLE {
                return decode_response(response.error_for_status()?, self.metadata_limit);
            }
            drop(response);
            let delay = Duration::from_millis(250);
            ensure!(
                remaining > delay,
                "native package provisioning busy until deadline"
            );
            std::thread::sleep(delay);
        }
    }

    /// Resolve a verified package or let the scheduler download its original
    /// bytes from the configured Rust distribution origin.
    /// # Errors
    /// Returns an error for unavailable provisioning, invalid provenance or transport failure.
    pub fn acquire_rust_package(
        &self,
        locator: &PackageLocator,
    ) -> Result<PackageAcquisition<InstallationManifest>> {
        locator.validate()?;
        let result: PackageAcquisition<InstallationManifest> =
            self.package_control("rust_package_acquire", locator)?;
        validate_installation_manifest(locator.identity, &result.package)?;
        ensure!(
            locator
                .expected_size
                .is_none_or(|size| size == result.package.source.size),
            "incorrect original package length"
        );
        Ok(result)
    }

    /// Acquire a generic original archive from a configured repository.
    /// # Errors
    /// Returns an error for invalid provenance, unavailable package or transport failure.
    pub fn acquire_package(
        &self,
        locator: &PackageLocator,
    ) -> Result<PackageAcquisition<PackageReceipt>> {
        locator.validate()?;
        let result: PackageAcquisition<PackageReceipt> =
            self.package_control("package_acquire", locator)?;
        ensure!(
            result.package.source.identity == locator.identity
                && locator
                    .expected_size
                    .is_none_or(|size| size == result.package.source.size),
            "incorrect original package provenance"
        );
        Ok(result)
    }

    /// Resolve portable installation metadata from an already verified
    /// original package. No archive or installed files are uploaded.
    /// # Errors
    /// Returns an error for unavailable provisioning or invalid metadata.
    pub fn lookup_rust_package(
        &self,
        identity: PackageIdentity,
    ) -> Result<Option<InstallationManifest>> {
        let manifest: Option<InstallationManifest> =
            self.package_control("rust_package_lookup", &identity)?;
        if let Some(manifest) = &manifest {
            validate_installation_manifest(identity, manifest)?;
        }
        Ok(manifest)
    }

    /// Resolve an already indexed original archive, without re-uploading it.
    /// # Errors
    /// Returns an error for invalid provenance or transport failure.
    pub fn lookup_package(&self, identity: PackageIdentity) -> Result<Option<PackageReceipt>> {
        let receipt: Option<PackageReceipt> = self.package_control("package_lookup", &identity)?;
        if let Some(receipt) = receipt {
            ensure!(
                receipt.source.identity == identity,
                "incorrect original package provenance"
            );
        }
        Ok(receipt)
    }

    /// Upload the exact original archive for generic compressed transport.
    /// # Errors
    /// Returns an error on checksum, size, decoder or transport failure.
    pub fn import_package(&self, source: PackageSource, archive: File) -> Result<PackageReceipt> {
        let receipt: PackageReceipt = self.import_original("package_import", source, archive)?;
        ensure!(
            receipt.source == source,
            "incorrect original package provenance"
        );
        Ok(receipt)
    }

    /// Upload a Rust installer and resolve its component installation metadata.
    /// # Errors
    /// Returns an error on checksum, size, decoder or transport failure.
    pub fn import_rust_package(
        &self,
        source: PackageSource,
        archive: File,
    ) -> Result<InstallationManifest> {
        let manifest: InstallationManifest =
            self.import_original("rust_package_import", source, archive)?;
        validate_installation_manifest(source.identity, &manifest)?;
        ensure!(
            manifest.source == source,
            "incorrect original package length"
        );
        Ok(manifest)
    }

    fn import_original<R: DeserializeOwned>(
        &self,
        operation: &str,
        source: PackageSource,
        archive: File,
    ) -> Result<R> {
        ensure!(
            archive.metadata()?.len() == source.size,
            "original package file length mismatch"
        );
        let response = self.send_stream(operation, &source, source.size, archive)?;
        Ok(codec()
            .with_limit(self.metadata_limit)
            .deserialize(&response)?)
    }

    /// Admit a complete native action.
    ///
    /// # Errors
    /// Returns an error on invalid metadata, authentication or transport failure.
    pub fn admit(
        &self,
        spec: &ExecutionSpec,
        mode: ActionMode,
        declared: &BTreeMap<TreeId, TreeManifest>,
    ) -> Result<NativeAdmission> {
        self.control("admit", &(spec, mode, declared))
    }

    pub(super) fn poll_input(&self, ticket: Ticket) -> Result<InputPoll> {
        self.control("poll_input", &ticket)
    }

    #[cfg(any(feature = "dist-client", test))]
    pub(super) fn inputs_staged(&self, ticket: Ticket) -> Result<()> {
        self.control("inputs_staged", &ticket)
    }

    fn input_unavailable(&self, ticket: Ticket, demand: InputDemand) -> Result<()> {
        self.control("input_unavailable", &(ticket, demand))
    }

    pub(super) fn backfill_input(
        &self,
        ticket: Ticket,
        blob: BlobRef,
        reader: impl Read + Send + 'static,
    ) -> Result<()> {
        self.send_stream(
            "backfill_input",
            &UploadHeader {
                ticket,
                blob,
                encoding: BlobEncoding::Raw as u8,
            },
            blob.size,
            reader,
        )?;
        Ok(())
    }

    /// Verify that a publisher is executing exactly the admitted specification.
    ///
    /// # Errors
    /// Returns an error if the ticket, publisher or specification differs.
    pub fn verify_execution(&self, ticket: Ticket, spec: ExecutionSpec) -> Result<()> {
        self.control("verify", &ExecutionRequest { ticket, spec })
    }

    /// Allocate a compatible worker, replaying the same reservation on retry.
    ///
    /// # Errors
    /// Returns an error for an invalid or expired action.
    pub fn schedule(&self, ticket: Ticket, spec: ExecutionSpec) -> Result<ScheduleReply> {
        let selected = spec.outputs.keys().cloned().collect();
        self.schedule_selected(ticket, spec, selected)
    }

    fn schedule_selected(
        &self,
        ticket: Ticket,
        spec: ExecutionSpec,
        selected: std::collections::BTreeSet<String>,
    ) -> Result<ScheduleReply> {
        let receiver = crate::build_runtime::wire::ClientDeliveryRates {
            scheduler: self.path_rates().download,
            interfaces: crate::dist::cluster::interface_report(),
            #[cfg(all(target_os = "linux", feature = "native-store"))]
            peers: self.peer_download_rates(),
            #[cfg(not(all(target_os = "linux", feature = "native-store")))]
            peers: Vec::new(),
        };
        self.control(
            "schedule",
            &ScheduleRequest {
                ticket,
                spec,
                receiver,
                selected,
            },
        )
    }

    /// Observe a scheduler-dispatched worker job over its authenticated HTTPS
    /// endpoint. Successful outputs are delivered separately.
    ///
    /// # Errors
    /// Returns an error for a rejected job, invalid certificate or transport
    /// failure, or an oversized failure response.
    pub fn run_worker(
        &self,
        allocation: &WorkerAllocation,
        timeout: Duration,
        max_response_bytes: u64,
    ) -> Result<NativeRunResult> {
        match self.observe_worker(allocation, timeout, max_response_bytes, |_| {
            None::<std::convert::Infallible>
        })? {
            std::ops::ControlFlow::Continue(result) => Ok(result),
            std::ops::ControlFlow::Break(never) => match never {},
        }
    }

    fn observe_worker<T>(
        &self,
        allocation: &WorkerAllocation,
        timeout: Duration,
        max_response_bytes: u64,
        mut early: impl FnMut(crate::build_runtime::wire::NativeJobPhase) -> Option<T>,
    ) -> Result<std::ops::ControlFlow<T, NativeRunResult>> {
        ensure!(
            !timeout.is_zero() && max_response_bytes > 0 && max_response_bytes < u64::MAX,
            "invalid native run limits"
        );
        ensure!(
            allocation.routes.valid(),
            "invalid worker route advertisement"
        );
        let role = sccache_cluster_identity::Role::Worker;
        let _ = self
            .routes
            .select(allocation.peer, role, &allocation.routes);
        let max_response_bytes = max_response_bytes
            .checked_add(64)
            .context("native response limit overflow")?;
        let started = Instant::now();
        let mut idle = Duration::from_millis(5);
        let rpc = |operation, remaining: Duration| -> Result<NativeRunResult> {
            let started = Instant::now();
            let mut last_error = None;
            for address in self
                .routes
                .ordered(allocation.peer, role, &allocation.routes)
            {
                let (http, base) = self.routes.endpoint(allocation.peer, role, address)?;
                let url =
                    crate::dist::http::urls::server_run_native_job(&base, JobId(allocation.job))?;
                let response = crate::http_client::io_runtime()?.block_on(
                    http.post(url.as_str())
                        .bearer_auth(&allocation.auth)
                        .header(http::header::CONTENT_TYPE, "application/octet-stream")
                        .timeout(
                            remaining
                                .saturating_sub(started.elapsed())
                                .min(Duration::from_secs(5)),
                        )
                        .body(codec().serialize(&operation)?)
                        .send(),
                );
                match response {
                    Err(error) if error.is_connect() => {
                        self.routes.failed(allocation.peer, role, address);
                        last_error = Some(error);
                    }
                    result => {
                        return decode_response(result?.error_for_status()?, max_response_bytes);
                    }
                }
            }
            Err(last_error.context("no worker route available")?.into())
        };
        loop {
            let remaining = timeout.saturating_sub(started.elapsed());
            ensure!(!remaining.is_zero(), "native worker deadline exceeded");
            match rpc(NativeRunRequest::Poll, remaining) {
                Ok(NativeRunResult::Pending(phase)) => {
                    if let Some(value) = early(phase) {
                        return Ok(std::ops::ControlFlow::Break(value));
                    }
                }
                Ok(NativeRunResult::Acknowledged) => {
                    anyhow::bail!("unexpected native worker acknowledgement")
                }
                Ok(result) => {
                    if !matches!(result, NativeRunResult::JobNotFound) {
                        let remaining = timeout.saturating_sub(started.elapsed());
                        if !remaining.is_zero() {
                            let _ = rpc(
                                NativeRunRequest::Acknowledge,
                                remaining.min(Duration::from_millis(250)),
                            );
                        }
                    }
                    return Ok(std::ops::ControlFlow::Continue(result));
                }
                Err(error) if retryable_transport_error(&error) => {
                    debug!("retrying native worker status: {error:#}");
                }
                Err(error) => return Err(error),
            }
            std::thread::sleep(idle.min(remaining));
            idle = (idle * 2).min(Duration::from_millis(100));
        }
    }

    /// Negotiate and upload a tree using the sender's immutable content.
    ///
    /// # Errors
    /// Returns an error for a rejected tree or transfer failure.
    pub fn offer_tree(&self, manifest: &TreeManifest) -> Result<TreeOffer> {
        self.control("tree_offer", manifest)
    }

    /// Publish the offered tree, retaining the ticket's delivery pin.
    ///
    /// # Errors
    /// Returns an error if content is missing or the offer expired.
    pub fn commit_tree(&self, ticket: Ticket) -> Result<TreeId> {
        self.control("tree_commit", &ticket)
    }

    /// Obtain a tree's manifest and delivery pin for an authorized job.
    ///
    /// # Errors
    /// Returns an error if this action cannot access the tree.
    pub fn open_tree(&self, action: Ticket, tree: TreeId) -> Result<TreeRead> {
        self.control("tree_open", &OpenTreeRequest { action, tree })
    }

    /// Publish a tree directly from its declared sources, transferring only
    /// absent blobs. Readers are opened lazily; no client CAS is needed.
    /// # Errors
    /// Returns an error on negotiation, verification or transport failure.
    pub fn push_tree<R: Read + Send + 'static>(
        &self,
        manifest: &TreeManifest,
        mut open: impl FnMut(ContentId) -> Result<R>,
        renewal_interval: Duration,
    ) -> Result<Ticket> {
        self.push_tree_with(manifest, renewal_interval, |ticket, blob| {
            self.upload(ticket, blob, open(blob.id)?)
        })
    }

    /// Publish a tree from its local physical CAS representation.
    /// Already encoded data travels unchanged, while native ZFS raw content
    /// is compressed temporarily for transfer without changing its disk format.
    ///
    /// # Errors
    /// Returns an error if a reserved blob is absent or fails remote validation.
    pub fn push_tree_stored(
        &self,
        manifest: &TreeManifest,
        mut open: impl FnMut(ContentId) -> Result<(File, BlobEncoding)>,
        renewal_interval: Duration,
    ) -> Result<Ticket> {
        self.push_tree_with(manifest, renewal_interval, |ticket, blob| {
            let (file, encoding) = open(blob.id)?;
            match encoding {
                // Preserve network compression even though ZFS stores the
                // plain bytes and lets ARC compress them natively.
                BlobEncoding::Raw => self.upload(ticket, blob, file),
                BlobEncoding::ZstdChunks => self.upload_stored_file(ticket, blob, encoding, file),
            }
        })
    }

    fn push_tree_with(
        &self,
        manifest: &TreeManifest,
        renewal_interval: Duration,
        mut upload: impl FnMut(Ticket, BlobRef) -> Result<()>,
    ) -> Result<Ticket> {
        let id = manifest.id()?;
        let blobs = manifest.blobs()?;
        let offer = self.offer_tree(manifest)?;
        debug!(
            "native tree {id:?}: upload {}/{} blobs, {}/{} logical bytes",
            offer.missing.len(),
            blobs.len(),
            offer
                .missing
                .iter()
                .map(|blob| u128::from(blob.size))
                .sum::<u128>(),
            blobs.values().copied().map(u128::from).sum::<u128>()
        );
        let result = self.with_renewal(offer.ticket, renewal_interval, |check| {
            ensure!(offer.id == id, "native tree offer identity mismatch");
            let mut seen = std::collections::BTreeSet::new();
            for blob in offer.missing {
                check()?;
                ensure!(
                    blobs.get(&blob.id) == Some(&blob.size) && seen.insert(blob.id),
                    "scheduler requested undeclared or duplicate input content"
                );
                upload(offer.ticket, blob)?;
            }
            ensure!(
                self.commit_tree(offer.ticket)? == id,
                "native tree commit identity mismatch"
            );
            Ok(offer.ticket)
        });
        if result.is_err() {
            let _ = self.close(offer.ticket);
        }
        result
    }

    /// Fetch a declared input tree into the worker store.
    ///
    /// # Errors
    /// Returns an error for an invalid manifest or failed transfer.
    #[cfg(all(target_os = "linux", feature = "native-store"))]
    async fn fetch_tree(
        &self,
        action: Ticket,
        id: TreeId,
        store: &crate::build_runtime::NativeStore,
        delivery: worker::WorkerDelivery<'_>,
        action_check: &LeaseCheck<'_>,
        on_tree: &mut (dyn FnMut(&crate::build_runtime::TreeLease) + Send),
    ) -> Result<crate::build_runtime::TreeLease> {
        action_check()?;
        let transport = delivery.transport;
        let read: crate::build_runtime::wire::TreeRead = self
            .control_with_timeout_async(
                "tree_open",
                &OpenTreeRequest { action, tree: id },
                self.timeout,
            )
            .await?;
        let ticket = read.ticket;
        let result = async {
            self.control_with_timeout_async::<_, ()>("renew", &ticket, self.timeout).await?;
            let renewals = renewal::Renewals::start(self.clone(), delivery.renewal_interval)?;
            renewals.add(ticket)?;
            let check = &|| { action_check()?; renewals.check() };
            check()?;
            ensure!(read.manifest.id()? == id, "native tree download identity mismatch");
            let manifest = read.manifest;
            let reserved = {
                let store = store.clone();
                let manifest = manifest.clone();
                tokio::task::spawn_blocking(move || store.reserve_tree_upload(&manifest)).await??
            };
            if delivery.artifact_grace.is_none() {
                let tree = self.fetch_shared_tree(ticket, store, manifest, reserved, check).await?;
                renewals.finish_async().await?;
                return Ok(tree);
            }
            let packages = match delivery.package_import {
                Some(limits) if !reserved.missing().is_empty() => self.reconstruct_packages(
                    ticket, reserved.missing(), store, limits, transport, check
                ).await?,
                _ => Vec::new(),
            };
            let updated = {
                let store = store.clone();
                let manifest = manifest.clone();
                tokio::task::spawn_blocking(move || store.reserve_tree_upload(&manifest)).await??
            };
            drop(reserved);
            let mut raw_missing = updated.missing().to_vec();
            raw_missing.sort_unstable_by_key(|blob| std::cmp::Reverse(blob.size));
            let mut acquired = Vec::new();
            let lookahead = transport.parallelism().get().saturating_mul(8).min(256);
            for chunk in raw_missing.chunks(lookahead) {
                let plans = self.source_plans_async("blob_sources", ticket, chunk).await;
                let prefetch = self.plan_prefetch(&plans, chunk).await;
                if !prefetch.is_empty() {
                    self.control_with_timeout_async::<_, ()>("input_prefetch", &InputPrefetchRequest {
                        ticket, missing: prefetch,
                    }, self.timeout).await?;
                }
                let leases = ingress::map_bounded(
                    chunk.iter().copied(), transport.parallelism(), |blob| {
                        self.fetch_input_blob(ticket, blob, plans.get(&blob.id), store, transport, check)
                    },
                ).await?;
                for lease in &leases { on_tree(lease); }
                acquired.extend(leases);
            }
            let store = store.clone();
            let tree = tokio::task::spawn_blocking(move || {
                let tree = store.publish_tree_pinned(&manifest, Vec::new())?;
                drop((acquired, packages, updated));
                Ok::<_, anyhow::Error>(tree)
            }).await??;
            if log::log_enabled!(target: "native_cas_replay", log::Level::Trace) {
                log::trace!(target: "native_cas_replay", "{}", serde_json::json!({
                    "kind": "tree_transfer", "tree": id, "raw_missing_blobs": raw_missing.len(),
                    "raw_missing_bytes": raw_missing.iter().map(|blob| u128::from(blob.size)).sum::<u128>(),
                }));
            }
            renewals.finish_async().await?;
            Ok(tree)
        }.await;
        let _ = self
            .control_with_timeout_async::<_, ()>(
                "close",
                &CloseRequest {
                    ticket,
                    delivery: None,
                },
                self.timeout,
            )
            .await;
        result
    }

    /// The scheduler is the acquisition producer for a colocated worker.
    /// Never own a retention-tree flight while waiting for that producer, and
    /// never stream bytes from the same CAS back into itself.
    #[cfg(all(target_os = "linux", feature = "native-store"))]
    async fn fetch_shared_tree(
        &self,
        ticket: Ticket,
        store: &crate::build_runtime::NativeStore,
        manifest: TreeManifest,
        reserved: crate::build_runtime::UploadReservation,
        check: &LeaseCheck<'_>,
    ) -> Result<crate::build_runtime::TreeLease> {
        let mut missing = reserved.missing().to_vec();
        missing.sort_unstable_by_key(|blob| std::cmp::Reverse(blob.size));
        let mut pins = vec![reserved];
        for chunk in missing.chunks(256) {
            check()?;
            self.control_with_timeout_async::<_, ()>(
                "input_prefetch",
                &InputPrefetchRequest {
                    ticket,
                    missing: chunk.to_vec(),
                },
                self.timeout,
            )
            .await?;
            let deadline = Instant::now()
                .checked_add(self.timeout)
                .context("shared native input deadline overflow")?;
            let cancelled = async {
                loop {
                    check()?;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            };
            let blobs = chunk.iter().map(|blob| (blob.id, blob.size)).collect();
            pins.extend(store.await_blobs(blobs, deadline, cancelled).await?);
        }
        check()?;
        let owned = store.clone();
        tokio::task::spawn_blocking(move || {
            let tree = owned.publish_tree_pinned(&manifest, Vec::new())?;
            drop(pins);
            Ok(tree)
        })
        .await?
    }

    #[cfg(all(target_os = "linux", feature = "native-store"))]
    async fn fetch_input_blob(
        &self,
        ticket: Ticket,
        blob: BlobRef,
        plan: Option<&crate::build_runtime::wire::BlobSourcePlan>,
        store: &crate::build_runtime::NativeStore,
        transport: &worker::PackageTransportTracker,
        check: &LeaseCheck<'_>,
    ) -> Result<std::sync::Arc<crate::build_runtime::TreeLease>> {
        check()?;
        let manifest = crate::build_runtime::NativeStore::blob_retention_manifest(blob)?;
        let id = manifest.id()?;
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .context("native input deadline overflow")?;
        let cancelled = async {
            loop {
                check()?;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        Box::pin(store.acquire_tree_async(id, deadline, cancelled, || async {
            check()?;
            let (manifest, reservation) = {
                let store = store.clone();
                tokio::task::spawn_blocking(move || {
                    let reservation = store.reserve_tree_upload(&manifest)?;
                    Ok::<_, anyhow::Error>((manifest, reservation))
                }).await??
            };
            let staged = if reservation.missing().is_empty() {
                Vec::new()
            } else {
                let mut direct = None;
                if let Some(plan) = plan.filter(|plan| !plan.sources.is_empty()) {
                    let slot = transport.raw_slot(check).await?;
                    let started = Instant::now();
                    direct = self.try_peer_blob_async(plan, |mut reader, encoding| async move {
                        ingress::stage_blob(store.clone(), blob, encoding, &mut reader, None).await
                    }).await;
                    drop(slot);
                    if direct.is_some() {
                        transport.observe_raw(blob.size, started.elapsed());
                    }
                }
                if let Some(staged) = direct {
                    vec![staged]
                } else {
                    let start = Instant::now();
                    let mut delay = Duration::from_millis(10);
                    loop {
                        check()?;
                        let slot = transport.raw_slot(check).await?;
                        let remaining = self.timeout.checked_sub(start.elapsed())
                            .filter(|remaining| !remaining.is_zero())
                            .context("native input backfill timed out")?;
                        let transfer = Instant::now();
                        match self.try_download_response_async(ticket, blob, remaining).await {
                            Ok(Some((response, encoding))) => {
                                let length = response.content_length().unwrap_or(0);
                                let mut stream = InputDownload { reader: response, remaining: length, interrupted: false };
                                match ingress::stage_blob(store.clone(), blob, encoding, &mut stream, None).await {
                                    Ok(staged) => {
                                        transport.observe_raw(blob.size, transfer.elapsed());
                                        break vec![staged];
                                    }
                                    Err(error) if stream.interrupted => {
                                        debug!("retrying interrupted native blob transfer {blob:?}: {error:#}");
                                    }
                                    Err(error) => return Err(error),
                                }
                            }
                            Ok(None) => {}
                            Err(error) if retryable_transport_error(&error) => {
                                debug!("retrying native blob request {blob:?}: {error:#}");
                            }
                            Err(error) => return Err(error),
                        }
                        drop(slot);
                        let remaining = self.timeout.saturating_sub(start.elapsed());
                        ensure!(!remaining.is_zero(), "native input backfill timed out");
                        tokio::time::sleep(delay.min(remaining)).await;
                        delay = (delay * 2).min(Duration::from_millis(200));
                    }
                }
            };
            let store = store.clone();
            tokio::task::spawn_blocking(move || {
                let tree = store.publish_tree_pinned(&manifest, staged)?;
                drop(reservation);
                Ok(tree)
            }).await?
        })).await.map(|(lease, _)| lease)
    }

    /// Negotiate missing content for a successful result.
    ///
    /// # Errors
    /// Returns an error if the output contract or session is invalid.
    pub fn begin(&self, ticket: Ticket, manifest: ResultManifest) -> Result<BeginResult> {
        self.control("begin", &ManifestRequest { ticket, manifest })
    }

    /// Compress a new blob once and upload the encoded representation.
    /// The scheduler verifies the original digest while retaining the exact
    /// compressed bytes; no transfer-side recompression is necessary.
    ///
    /// # Errors
    /// Returns an error on transport or verification failure.
    pub fn upload(
        &self,
        ticket: Ticket,
        blob: BlobRef,
        reader: impl Read + Send + 'static,
    ) -> Result<()> {
        let mut encoded = tempfile::tempfile()?;
        let reference =
            crate::build_runtime::encode_native_blob(reader, &mut encoded, Some(blob.size))?;
        ensure!(
            reference == blob,
            "native upload content digest or length mismatch"
        );
        encoded.rewind()?;
        self.upload_stored_file(ticket, blob, BlobEncoding::ZstdChunks, encoded)
    }

    /// Transfer an immutable physical CAS payload as supplied, including its
    /// explicit raw or Zstd encoding. The receiver verifies decoded identity.
    ///
    /// # Errors
    /// Returns an error for a missing physical file or rejected transfer.
    pub fn upload_stored_file(
        &self,
        ticket: Ticket,
        blob: BlobRef,
        encoding: BlobEncoding,
        file: File,
    ) -> Result<()> {
        #[cfg(all(unix, feature = "native-store"))]
        {
            crate::http_client::io_runtime()?
                .block_on(self.upload_stored_file_async(ticket, blob, encoding, file))
        }
        #[cfg(not(all(unix, feature = "native-store")))]
        {
            let size = file.metadata()?.len();
            if encoding == BlobEncoding::Raw {
                ensure!(size == blob.size, "native raw upload size mismatch");
            }
            self.send_stream(
                "upload",
                &UploadHeader {
                    ticket,
                    blob,
                    encoding: encoding as u8,
                },
                size,
                file,
            )?;
            Ok(())
        }
    }

    fn send_stream(
        &self,
        operation: &str,
        metadata: &impl Serialize,
        size: u64,
        mut reader: impl Read,
    ) -> Result<Vec<u8>> {
        let header = codec()
            .with_limit(self.metadata_limit)
            .serialize(metadata)?;
        let length = size
            .checked_add(u64::try_from(header.len())?)
            .context("native upload length overflow")?;
        let (path, job) = self.operation_path(operation);
        let peer = self.peer.scheduler_id();
        let role = sccache_cluster_identity::Role::Scheduler;
        let start = Instant::now();
        let mut last_error = None;
        for address in self.cache_endpoints(Some(Transfer::Upload(length))) {
            let remaining = self
                .timeout
                .checked_sub(start.elapsed())
                .context("native upload deadline expired")?;
            let client = self.routes.streaming_endpoint(peer, role, address)?;
            let mut request = client
                .request(http::Method::POST, &path)?
                .timeout(remaining)
                .header(http::header::CONTENT_TYPE, "application/octet-stream");
            if let Some(job) = job {
                request = request.header("X-Sccache-Native-Job", job.to_string());
            }
            let started = Instant::now();
            let local = self.routes.local_source(peer, role, address);
            let tracked = crate::dist::cluster_routes::interface::TrackedReader::new(
                Cursor::new(&header).chain(&mut reader),
                local,
                Transfer::Upload(length),
                address.source.map(|local| {
                    sccache_peer_identity::NetworkPath::new(local, address.address.ip())
                }),
            );
            let evidence = tracked.evidence();
            let attempt = upload::send(request, length, self.metadata_limit, tracked)?;
            match self.record_upload_attempt(
                UploadObservation {
                    address,
                    length,
                    header_length: header.len(),
                    started,
                    local,
                    evidence,
                },
                attempt,
            )? {
                std::ops::ControlFlow::Break(bytes) => return Ok(bytes),
                std::ops::ControlFlow::Continue(error) => last_error = Some(error),
            }
        }
        Err(last_error.context("native upload route unavailable")?)
    }

    fn record_upload_attempt(
        &self,
        observation: UploadObservation,
        attempt: upload::Attempt,
    ) -> Result<std::ops::ControlFlow<Vec<u8>, anyhow::Error>> {
        let UploadObservation {
            address,
            length,
            header_length,
            started,
            local,
            evidence,
        } = observation;
        let peer = self.peer.scheduler_id();
        let role = sccache_cluster_identity::Role::Scheduler;
        match attempt.result {
            Ok(mut response) => {
                if response.path.local == local {
                    response.path.quality =
                        evidence.map_or(response.path.quality, |sample| sample.quality());
                }
                // An already-provisioned package can return before reading
                // the entire archive; it supplies no full-body rate sample.
                if attempt.consumed == length {
                    self.routes.transferred(
                        peer,
                        role,
                        address,
                        Transfer::Upload(length),
                        started.elapsed(),
                        response.path,
                    );
                }
                Ok(std::ops::ControlFlow::Break(response.bytes))
            }
            Err(error) => {
                let transport = error.downcast_ref::<wreq::Error>();
                let connect = transport.is_some_and(wreq::Error::is_connect);
                let interrupted = transport.is_some_and(|error| {
                    error.is_connect()
                        || error.is_timeout()
                        || error.is_body()
                        || error.is_request()
                });
                if interrupted {
                    self.routes.failed(peer, role, address);
                }
                // Before any request body is polled, the server cannot
                // consume a ticket/claim. A proven connect failure may
                // also replay metadata, but never a consumed source byte.
                if interrupted
                    && (attempt.consumed == 0
                        || (connect && attempt.consumed <= header_length as u64))
                {
                    Ok(std::ops::ControlFlow::Continue(error))
                } else {
                    Err(error)
                }
            }
        }
    }

    #[cfg(all(unix, feature = "native-store"))]
    async fn upload_stored_file_async(
        &self,
        ticket: Ticket,
        blob: BlobRef,
        encoding: BlobEncoding,
        file: File,
    ) -> Result<()> {
        let (file, size) = tokio::task::spawn_blocking(move || {
            let size = file.metadata()?.len();
            Ok::<_, io::Error>((std::sync::Arc::new(file), size))
        })
        .await??;
        if encoding == BlobEncoding::Raw {
            ensure!(size == blob.size, "native raw upload size mismatch");
        }
        let header = bytes::Bytes::from(codec().with_limit(self.metadata_limit).serialize(
            &UploadHeader {
                ticket,
                blob,
                encoding: encoding as u8,
            },
        )?);
        let length = size
            .checked_add(header.len() as u64)
            .context("native upload length overflow")?;
        let peer = self.peer.scheduler_id();
        let role = sccache_cluster_identity::Role::Scheduler;
        let start = Instant::now();
        let routes = self.cache_routes_async().await;
        let mut last_error = None;
        for address in self.order_cache_endpoints(&routes, Some(Transfer::Upload(length))) {
            let remaining = self
                .timeout
                .checked_sub(start.elapsed())
                .context("native upload deadline expired")?;
            let request = self.request_at("upload", address)?.timeout(remaining);
            let started = Instant::now();
            let local = self.routes.local_source(peer, role, address);
            let activity = crate::dist::cluster_routes::interface::activity(
                local,
                Transfer::Upload(length),
                address.source.map(|local| {
                    sccache_peer_identity::NetworkPath::new(local, address.address.ip())
                }),
            );
            let evidence = activity
                .as_ref()
                .map(crate::dist::cluster_routes::interface::Activity::evidence);
            let attempt = upload::send_file(
                request,
                header.clone(),
                std::sync::Arc::clone(&file),
                size,
                self.metadata_limit,
                activity,
            )
            .await?;
            match self.record_upload_attempt(
                UploadObservation {
                    address,
                    length,
                    header_length: header.len(),
                    started,
                    local,
                    evidence,
                },
                attempt,
            )? {
                std::ops::ControlFlow::Break(_) => return Ok(()),
                std::ops::ControlFlow::Continue(error) => last_error = Some(error),
            }
        }
        Err(last_error.context("native upload route unavailable")?)
    }

    /// Commit the negotiated result.
    ///
    /// # Errors
    /// Returns an error if uploads are unfinished or publication failed.
    pub fn commit(
        &self,
        ticket: Ticket,
        retained_after_begin: Duration,
        observation: Option<crate::build_runtime::wire::ActionObservation>,
    ) -> Result<ResultManifest> {
        self.control(
            "commit",
            &CommitRequest {
                ticket,
                retained_after_begin_millis: u64::try_from(retained_after_begin.as_millis())
                    .unwrap_or(u64::MAX),
                observation,
            },
        )
    }

    /// Renew the publishing lease during a long-running compilation.
    ///
    /// # Errors
    /// Returns an error for expired or unauthorized tickets.
    pub fn renew(&self, ticket: Ticket) -> Result<()> {
        self.control("renew", &ticket)
    }

    /// Open a build-scoped immutable result retention lease.
    /// # Errors
    /// Returns an error when the scheduler cannot admit the lease.
    pub fn open_retention(&self) -> Result<Ticket> {
        self.control("retain_open", &())
    }

    /// Pin the exact committed result under the build lease.
    /// # Errors
    /// Returns an error for an expired, unauthorized, or changed result.
    pub fn retain_result(
        &self,
        group: Ticket,
        action: Ticket,
        result: crate::build_runtime::ResultId,
    ) -> Result<()> {
        self.control(
            "retain_add",
            &RetainRequest {
                group,
                action,
                result,
            },
        )
    }

    /// Renew a build lease in one RPC regardless of its artifact count.
    /// # Errors
    /// Returns an error for an expired or unauthorized lease.
    pub fn renew_retention(&self, group: Ticket) -> Result<()> {
        self.control("retain_renew", &group)
    }

    /// Release the build lease and its retained content.
    /// # Errors
    /// Returns an error if the scheduler rejects the release.
    pub fn close_retention(&self, group: Ticket) -> Result<()> {
        self.control("retain_close", &group)
    }

    /// Download retained content with the ordinary authenticated, measured
    /// direct-peer transport and a verified scheduler fallback. Return the
    /// verified staging descriptor at offset zero, without copying its bytes.
    /// # Errors
    /// Returns an error for an unavailable or corrupt retained blob.
    #[cfg(all(target_os = "linux", feature = "native-store"))]
    pub fn download_retained(&self, group: Ticket, blob: BlobRef) -> Result<File> {
        fn stage(reader: impl Read, blob: BlobRef, encoding: BlobEncoding) -> Result<File> {
            let mut file = tempfile::tempfile()?;
            crate::build_runtime::transfer_native_blob(
                reader,
                io::sink(),
                &mut file,
                blob,
                encoding,
            )?;
            file.rewind()?;
            Ok(file)
        }
        let plans = self.retained_source_plans(group, &[blob]);
        if let Some(plan) = plans.get(&blob.id)
            && let Some(file) =
                self.try_peer_blob(plan, |reader, encoding| stage(reader, blob, encoding))
        {
            return Ok(file);
        }
        let request = codec().serialize(&RetainedDownloadRequest { group, blob })?;
        let (reader, encoding) = self
            .receive_blob("retain_download", request, blob, self.timeout)?
            .context("native retained content unavailable")?;
        stage(reader, blob, encoding)
    }

    /// Report a failed compilation without publishing any shared result.
    ///
    /// # Errors
    /// Returns an error for expired or unauthorized tickets.
    pub fn fail(&self, ticket: Ticket) -> Result<()> {
        self.control("fail", &ticket)
    }

    fn with_renewal<T>(
        &self,
        ticket: Ticket,
        interval: Duration,
        operation: impl FnOnce(&LeaseCheck<'_>) -> Result<T>,
    ) -> Result<T> {
        self.renew(ticket)?;
        let renewals = renewal::Renewals::start(self.clone(), interval)?;
        renewals.add(ticket)?;
        let result = operation(&|| renewals.check());
        let renewed = renewals.finish();
        result.and_then(|value| renewed.map(|()| value))
    }
    /// Observe the client's result ticket.
    ///
    /// # Errors
    /// Returns an error on an unavailable ticket or transport failure.
    pub fn status(&self, ticket: Ticket) -> Result<NativeStatus> {
        self.control(
            "status",
            &StatusRequest {
                ticket,
                preview: false,
            },
        )
    }

    #[cfg(all(target_os = "linux", feature = "dist-client"))]
    fn preview_status(&self, ticket: Ticket) -> Result<NativeStatus> {
        self.control(
            "status",
            &StatusRequest {
                ticket,
                preview: true,
            },
        )
    }

    /// Release a result ticket or cancel an unfinished action.
    ///
    /// # Errors
    /// Returns an error if the ticket cannot be closed.
    pub fn close(&self, ticket: Ticket) -> Result<()> {
        self.control(
            "close",
            &CloseRequest {
                ticket,
                delivery: None,
            },
        )
    }

    #[cfg(all(target_os = "linux", feature = "dist-client"))]
    fn close_delivered(
        &self,
        ticket: Ticket,
        delivery: crate::build_runtime::wire::ClientDeliveryObservation,
    ) -> Result<()> {
        self.control(
            "close",
            &CloseRequest {
                ticket,
                delivery: Some(delivery),
            },
        )
    }

    /// Stream a result blob into caller-owned staging storage and verify it.
    ///
    /// Do not expose the destination to consumers until this method succeeds.
    ///
    /// # Errors
    /// Returns an error for a rejected transfer, wrong length/digest or I/O.
    pub fn download(
        &self,
        ticket: Ticket,
        blob: BlobRef,
        mut destination: impl Write,
    ) -> Result<()> {
        let (response, encoding) = self.download_response(ticket, blob)?;
        crate::build_runtime::transfer_native_blob(
            response,
            io::sink(),
            &mut destination,
            blob,
            encoding,
        )
    }

    fn download_response(
        &self,
        ticket: Ticket,
        blob: BlobRef,
    ) -> Result<(
        MeasuredReader<crate::http_client::ResponseReader>,
        BlobEncoding,
    )> {
        self.try_download_response(ticket, blob, self.timeout)?
            .context("native content not yet available")
    }

    fn try_download_response(
        &self,
        ticket: Ticket,
        blob: BlobRef,
        timeout: Duration,
    ) -> Result<
        Option<(
            MeasuredReader<crate::http_client::ResponseReader>,
            BlobEncoding,
        )>,
    > {
        let request = codec().serialize(&DownloadRequest {
            ticket,
            id: blob.id,
        })?;
        self.receive_blob("download", request, blob, timeout)
    }

    fn receive_blob(
        &self,
        operation: &str,
        request: Vec<u8>,
        blob: BlobRef,
        timeout: Duration,
    ) -> Result<
        Option<(
            MeasuredReader<crate::http_client::ResponseReader>,
            BlobEncoding,
        )>,
    > {
        let response = crate::http_client::io_runtime()?
            .block_on(self.receive_blob_response(operation, request, blob, timeout))?;
        response
            .map(|(response, address, encoding)| {
                Ok((
                    self.routes.measure_response(
                        self.peer.scheduler_id(),
                        sccache_cluster_identity::Role::Scheduler,
                        address,
                        response,
                    )?,
                    encoding,
                ))
            })
            .transpose()
    }

    #[cfg(all(target_os = "linux", feature = "native-store"))]
    async fn try_download_response_async(
        &self,
        ticket: Ticket,
        blob: BlobRef,
        timeout: Duration,
    ) -> Result<
        Option<(
            MeasuredReader<crate::dist::cluster::AsyncResponseReader>,
            BlobEncoding,
        )>,
    > {
        let request = codec().serialize(&DownloadRequest {
            ticket,
            id: blob.id,
        })?;
        let response = self
            .receive_blob_response("download", request, blob, timeout)
            .await?;
        Ok(response.map(|(response, address, encoding)| {
            (
                self.routes.measure_response_async(
                    self.peer.scheduler_id(),
                    sccache_cluster_identity::Role::Scheduler,
                    address,
                    response,
                ),
                encoding,
            )
        }))
    }

    async fn receive_blob_response(
        &self,
        operation: &str,
        request: Vec<u8>,
        blob: BlobRef,
        timeout: Duration,
    ) -> Result<
        Option<(
            wreq::Response,
            crate::dist::cluster_routes::Route,
            BlobEncoding,
        )>,
    > {
        let (response, address) = self
            .send_to_cache_async(
                operation,
                request,
                timeout,
                Some(Transfer::Download(blob.size)),
            )
            .await?;
        if response.status() == http::StatusCode::ACCEPTED {
            return Ok(None);
        }
        let response = response.error_for_status()?;
        let encoding = BlobEncoding::from_http_value(
            response
                .headers()
                .get("x-sccache-cas-encoding")
                .context("native response missing encoding")?
                .to_str()?,
        )?;
        Ok(Some((response, address, encoding)))
    }
}

// Only remote transport interruptions are retried. Local CAS errors and
// complete streams with the wrong digest are not silently treated as misses.
#[cfg(all(target_os = "linux", feature = "native-store"))]
struct InputDownload<R> {
    reader: R,
    remaining: u64,
    interrupted: bool,
}

#[cfg(all(target_os = "linux", feature = "native-store"))]
impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for InputDownload<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::{pin::Pin, task::Poll};
        let this = self.get_mut();
        let before = buffer.filled().len();
        let nonempty = buffer.remaining() > 0;
        match Pin::new(&mut this.reader).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                let count = buffer.filled().len() - before;
                if count == 0 && nonempty && this.remaining != 0 {
                    this.interrupted = true;
                }
                this.remaining = this.remaining.saturating_sub(count as u64);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                if error.kind() != io::ErrorKind::Interrupted {
                    this.interrupted = true;
                }
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn retryable_transport_error(error: &anyhow::Error) -> bool {
    if let Some(error) = error.downcast_ref::<wreq::Error>() {
        return error.is_timeout()
            || error.is_connect()
            || error.is_body()
            || error.is_request()
            || error.status().is_some_and(|status| {
                status.is_server_error() || status == http::StatusCode::TOO_MANY_REQUESTS
            });
    }
    error.downcast_ref::<io::Error>().is_some_and(|error| {
        matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::TimedOut
                | io::ErrorKind::BrokenPipe
        )
    })
}

#[cfg(all(test, target_os = "linux", feature = "native-store"))]
#[tokio::test]
async fn native_input_stream_distinguishes_truncation_from_complete_transfer() -> Result<()> {
    use tokio::io::AsyncReadExt;
    let mut short = InputDownload {
        reader: Cursor::new(b"short"),
        remaining: 8,
        interrupted: false,
    };
    let mut bytes = Vec::new();
    short.read_to_end(&mut bytes).await?;
    assert!(short.interrupted);
    assert_eq!(short.remaining, 3);
    let mut complete = InputDownload {
        reader: Cursor::new(b"complete"),
        remaining: 8,
        interrupted: false,
    };
    bytes.clear();
    complete.read_to_end(&mut bytes).await?;
    assert!(!complete.interrupted);
    assert_eq!(complete.remaining, 0);
    Ok(())
}

fn copy_verified(reader: impl Read, blob: BlobRef, mut destination: impl Write) -> Result<()> {
    let limit = blob
        .size
        .checked_add(1)
        .context("native download size overflow")?;
    let mut reader = reader.take(limit);
    let mut hash = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut received = 0_u64;
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        received = received
            .checked_add(u64::try_from(count)?)
            .context("native download length overflow")?;
        ensure!(
            received <= blob.size,
            "native download exceeds declared length"
        );
        hash.update(&buffer[..count]);
        destination.write_all(&buffer[..count])?;
    }
    ensure!(
        received == blob.size && ContentId(*hash.finalize().as_bytes()) == blob.id,
        "native download digest or length mismatch"
    );
    Ok(())
}

fn decode_response<T: DeserializeOwned>(response: wreq::Response, limit: u64) -> Result<T> {
    crate::http_client::io_runtime()?.block_on(decode_response_async(response, limit))
}

async fn decode_response_async<T: DeserializeOwned>(
    response: wreq::Response,
    limit: u64,
) -> Result<T> {
    let bytes =
        crate::http_client::read_bounded_bytes_async(response, usize::try_from(limit)?).await?;
    ensure!(
        u64::try_from(bytes.len())? <= limit,
        "native response exceeds configured limit"
    );
    Ok(codec().with_limit(limit).deserialize(&bytes)?)
}

fn validate_installation_manifest(
    identity: PackageIdentity,
    manifest: &InstallationManifest,
) -> Result<()> {
    ensure!(
        manifest.source.identity == identity,
        "incorrect original package provenance"
    );
    manifest.validate()
}

pub(super) fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
}

#[cfg(all(target_os = "linux", feature = "native-store"))]
mod grace;
mod renewal;
#[cfg(all(target_os = "linux", feature = "native-store"))]
mod worker;
#[cfg(all(target_os = "linux", feature = "native-store"))]
pub use grace::ArtifactGrace;
#[cfg(all(target_os = "linux", feature = "native-store"))]
pub use worker::{
    CompletedWorker, PackageTransportTracker, PreparedWorker, WorkerDelivery, WorkerPreparation,
};

#[cfg(all(target_os = "linux", feature = "dist-client"))]
mod client;
#[cfg(all(target_os = "linux", feature = "dist-client"))]
mod local;
#[cfg(all(target_os = "linux", feature = "dist-client"))]
pub use crate::protocol::NativeBuildSource;
#[cfg(all(target_os = "linux", feature = "dist-client"))]
pub use client::{NativeBuildPolicy, NativeBuildResult};
#[cfg(all(target_os = "linux", feature = "dist-client"))]
pub use local::LocalExecutor;

#[cfg(all(target_os = "linux", feature = "dist-client"))]
pub(crate) mod broker;

#[cfg(all(target_os = "linux", feature = "dist-client"))]
pub(crate) mod result_session;

#[cfg(all(target_os = "linux", feature = "dist-client"))]
pub(crate) mod intermediate;
