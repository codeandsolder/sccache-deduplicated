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
    routes: std::sync::Arc<crate::dist::cluster::BlockingRoutes>,
    peer: std::sync::Arc<sccache_cluster_identity::PeerCredentials>,
    address: std::net::SocketAddr,
    candidates: std::sync::Arc<
        std::sync::Mutex<Option<(sccache_peer_identity::RouteSet, Instant, Instant)>>,
    >,
    role: Role,
    metadata_limit: u64,
    timeout: Duration,
}

impl NativeCacheClient {
    /// Create an authenticated native client with explicit request bounds.
    ///
    /// # Errors
    /// Returns an error for invalid endpoint configuration or HTTP setup.
    pub fn new(
        base: &reqwest::Url,
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
            routes: std::sync::Arc::new(crate::dist::cluster::BlockingRoutes::for_peer(
                std::sync::Arc::clone(&peer),
            )),
            peer,
            address,
            candidates: std::sync::Arc::default(),
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

    fn cache_routes(&self) -> sccache_peer_identity::RouteSet {
        use sccache_peer_identity::{Role, RouteSet};
        #[derive(serde::Deserialize)]
        struct Reply {
            routes: RouteSet,
        }
        let fallback = || RouteSet::new(self.address, []);
        let Ok(mut cached) = self.candidates.lock() else {
            return fallback();
        };
        if let Some((routes, _, attempted)) = cached.as_ref()
            && attempted.elapsed() < Duration::from_secs(30)
        {
            return routes.clone();
        }
        let fetched = (|| -> Result<RouteSet> {
            let (client, base) = self.routes.endpoint(
                self.peer.scheduler_id(),
                Role::Scheduler,
                crate::dist::cluster_routes::Route::unbound(self.peer.scheduler_address()),
            )?;
            let response = client
                .get(base.join("/api/v1/scheduler/native_routes")?)
                .header(reqwest::header::ACCEPT, "application/octet-stream")
                .timeout(Duration::from_millis(500))
                .send()?
                .error_for_status()?;
            let reply: Reply = decode_response(response, 4096)?;
            ensure!(reply.routes.valid(), "invalid scheduler routes");
            // The local configured endpoint is always the fallback even if the
            // scheduler advertises a different reachable interface.
            Ok(RouteSet::new(self.address, reply.routes.iter()))
        })();
        let (routes, updated) = match fetched {
            Ok(routes) => (routes, Instant::now()),
            Err(error) => {
                debug!("Native cache path discovery unavailable: {error:#}");
                cached
                    .as_ref()
                    .filter(|(_, updated, _)| updated.elapsed() < Duration::from_secs(90))
                    .map_or_else(
                        || (fallback(), Instant::now()),
                        |(routes, updated, _)| (routes.clone(), *updated),
                    )
            }
        };
        self.routes
            .prime(self.peer.scheduler_id(), Role::Scheduler, &routes);
        *cached = Some((routes.clone(), updated, Instant::now()));
        drop(cached);
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
    ) -> Result<reqwest::blocking::RequestBuilder> {
        let (path, job) = self.operation_path(operation);
        let (http, base) = self.routes.endpoint(
            self.peer.scheduler_id(),
            sccache_cluster_identity::Role::Scheduler,
            address,
        )?;
        let url = base.join(&path)?;
        let mut request = http
            .post(url)
            .timeout(self.timeout)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream");
        if let Some(job) = job {
            request = request.header("X-Sccache-Native-Job", job.to_string());
        }
        Ok(request)
    }

    fn cache_endpoints(
        &self,
        transfer: Option<Transfer>,
    ) -> Vec<crate::dist::cluster_routes::Route> {
        let routes = self.cache_routes();
        let peer = self.peer.scheduler_id();
        let role = sccache_cluster_identity::Role::Scheduler;
        self.routes.prime(peer, role, &routes);
        transfer.map_or_else(
            || self.routes.ordered(peer, role, &routes),
            |transfer| self.routes.ordered_transfer(peer, role, &routes, transfer),
        )
    }

    fn send_to_cache(
        &self,
        operation: &str,
        body: Vec<u8>,
        timeout: Duration,
        transfer: Option<Transfer>,
    ) -> Result<(
        reqwest::blocking::Response,
        crate::dist::cluster_routes::Route,
    )> {
        let start = Instant::now();
        let mut last_error = None;
        let body = bytes::Bytes::from(body);
        for address in self.cache_endpoints(transfer) {
            let remaining = timeout
                .checked_sub(start.elapsed())
                .context("native request deadline expired")?;
            let response = self
                .request_at(operation, address)?
                .timeout(remaining)
                .body(body.clone())
                .send();
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
    ) -> Result<reqwest::blocking::Response> {
        self.send_to_cache(operation, body, timeout, None)
            .map(|(response, _)| response)
    }

    fn control<T: Serialize, R: DeserializeOwned>(&self, operation: &str, value: &T) -> Result<R> {
        let data = codec().with_limit(self.metadata_limit).serialize(value)?;
        let response = self
            .send_replayable(operation, data, self.timeout)?
            .error_for_status()?;
        decode_response(response, self.metadata_limit)
    }

    // Retrying is deliberately limited to package resolution: a busy reply
    // does not mutate anything, and even a repeated acquisition is idempotent.
    fn package_control<T: Serialize, R: DeserializeOwned>(
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
            if response.status() != reqwest::StatusCode::SERVICE_UNAVAILABLE {
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
                let response = http
                    .post(url)
                    .bearer_auth(&allocation.auth)
                    .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                    .timeout(
                        remaining
                            .saturating_sub(started.elapsed())
                            .min(Duration::from_secs(5)),
                    )
                    .body(codec().serialize(&operation)?)
                    .send();
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
    fn fetch_tree(
        &self,
        action: Ticket,
        id: TreeId,
        store: &crate::build_runtime::NativeStore,
        delivery: worker::WorkerDelivery<'_>,
        action_check: &LeaseCheck<'_>,
        on_tree: &mut dyn FnMut(&crate::build_runtime::TreeLease),
    ) -> Result<crate::build_runtime::TreeLease> {
        action_check()?;
        let transport = delivery.transport;
        let read = self.open_tree(action, id)?;
        let result = self.with_renewal(read.ticket, delivery.renewal_interval, |tree_check| {
            let check = &|| {
                action_check()?;
                tree_check()
            };
            check()?;
            ensure!(
                read.manifest.id()? == id,
                "native tree download identity mismatch"
            );
            let reserved = store.reserve_tree_upload(&read.manifest)?;
            #[cfg(target_os = "linux")]
            let packages = match delivery.package_import {
                Some(limits) if !reserved.missing().is_empty() => self.reconstruct_packages(
                    read.ticket,
                    reserved.missing(),
                    store,
                    limits,
                    transport,
                    check,
                )?,
                _ => Vec::new(),
            };
            let updated = store.reserve_tree_upload(&read.manifest)?;
            drop(reserved);
            debug!(
                "native tree {id:?}: downloading {} raw bytes in at most {} concurrent requests after package reconstruction",
                updated
                    .missing()
                    .iter()
                    .map(|blob| u128::from(blob.size))
                    .sum::<u128>(),
                transport.parallelism()
            );
            let mut raw_missing = updated.missing().to_vec();
            raw_missing.sort_unstable_by_key(|blob| std::cmp::Reverse(blob.size));
            let mut acquired = Vec::new();
            // Register a bounded lookahead before download slots start waiting.
            // The origin can stream subsequent misses while these are consumed.
            let lookahead = transport.parallelism().get().saturating_mul(8).min(256);
            for chunk in raw_missing.chunks(lookahead) {
                let plans = self.source_plans(read.ticket, chunk);
                self.probe_sources(plans.values());
                let prefetch = chunk.iter().copied().filter(|blob| {
                    plans.get(&blob.id).is_none_or(|plan| !self.has_direct_source(plan))
                }).collect::<Vec<_>>();
                if !prefetch.is_empty() {
                    self.control::<_, ()>("input_prefetch", &InputPrefetchRequest {
                        ticket: read.ticket,
                        missing: prefetch,
                    })?;
                }
                let leases = map_packages(chunk, transport.parallelism(), |blob| {
                    self.fetch_input_blob(read.ticket, *blob, plans.get(&blob.id), store, transport, check)
                })?;
                for lease in &leases {
                    on_tree(lease);
                }
                acquired.extend(leases);
            }
            let tree = store.publish_tree_pinned(&read.manifest, Vec::new())?;
            drop(acquired);
            if log::log_enabled!(target: "native_cas_replay", log::Level::Trace) {
                log::trace!(
                    target: "native_cas_replay",
                    "{}",
                    serde_json::json!({
                        "kind": "tree_transfer",
                        "tree": id,
                        "raw_missing_blobs": raw_missing.len(),
                        "raw_missing_bytes": raw_missing
                            .iter()
                            .map(|blob| u128::from(blob.size))
                            .sum::<u128>(),
                    })
                );
            }
            #[cfg(target_os = "linux")]
            drop(packages);
            Ok(tree)
        });
        // Best effort: the remote pin also expires automatically.
        let _ = self.close(read.ticket);
        result
    }

    #[cfg(all(target_os = "linux", feature = "native-store"))]
    fn fetch_input_blob(
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
        let (lease, _) = store.acquire_tree(manifest.id()?, check, || {
            let reservation = store.reserve_tree_upload(&manifest)?;
            let staged = if reservation.missing().is_empty() {
                Vec::new()
            } else {
                if let Some(plan) = plan.filter(|plan| self.has_direct_source(plan)) {
                    let slot = transport.raw_slot(check)?;
                    let started = Instant::now();
                    let staged = self.try_peer_blob(plan, |reader, encoding| store.stage_expected_physical(blob, encoding, reader));
                    drop(slot);
                    if let Some(staged) = staged {
                        transport.observe_raw(blob.size, started.elapsed());
                        return store.publish_tree_pinned(&manifest, vec![staged]);
                    }
                }
                let start = Instant::now();
                let mut delay = Duration::from_millis(10);
                loop {
                    check()?;
                    let slot = transport.raw_slot(check)?;
                    let remaining = self.timeout.checked_sub(start.elapsed())
                        .filter(|remaining| !remaining.is_zero())
                        .context("native input backfill timed out")?;
                    let transfer = Instant::now();
                    match self.try_download_response(ticket, blob, remaining) {
                        Ok(Some((response, encoding))) => {
                            let length = response.content_length().unwrap_or(0);
                            let mut stream = InputDownload {
                                reader: response,
                                remaining: length,
                                interrupted: false,
                            };
                            match store.stage_expected_physical(blob, encoding, &mut stream) {
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
                    std::thread::sleep(delay.min(remaining));
                    delay = (delay * 2).min(Duration::from_millis(200));
                }
            };
            store.publish_tree_pinned(&manifest, staged)
        })?;
        Ok(lease)
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
                .request(reqwest::Method::POST, &path)?
                .timeout(remaining)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream");
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
                    return Ok(response.bytes);
                }
                Err(error) => {
                    let transport = error.downcast_ref::<reqwest::Error>();
                    let connect = transport.is_some_and(reqwest::Error::is_connect);
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
                            || (connect && attempt.consumed <= header.len() as u64))
                    {
                        last_error = Some(error);
                    } else {
                        return Err(error);
                    }
                }
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
    /// direct-peer transport and a verified scheduler fallback.
    /// # Errors
    /// Returns an error for an unavailable or corrupt retained blob.
    #[cfg(all(target_os = "linux", feature = "native-store"))]
    pub fn download_retained(
        &self,
        group: Ticket,
        blob: BlobRef,
        mut destination: impl Write,
    ) -> Result<()> {
        let plans = self.retained_source_plans(group, &[blob]);
        if let Some(plan) = plans.get(&blob.id)
            && let Some(mut file) = self.try_peer_blob(plan, |reader, encoding| {
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
            })
        {
            io::copy(&mut file, &mut destination)?;
            return Ok(());
        }
        let request = codec().serialize(&RetainedDownloadRequest { group, blob })?;
        let (reader, encoding) = self
            .receive_blob("retain_download", request, blob, self.timeout)?
            .context("native retained content unavailable")?;
        crate::build_runtime::transfer_native_blob(
            reader,
            io::sink(),
            &mut destination,
            blob,
            encoding,
        )
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
    ) -> Result<(MeasuredReader<reqwest::blocking::Response>, BlobEncoding)> {
        self.try_download_response(ticket, blob, self.timeout)?
            .context("native content not yet available")
    }

    fn try_download_response(
        &self,
        ticket: Ticket,
        blob: BlobRef,
        timeout: Duration,
    ) -> Result<Option<(MeasuredReader<reqwest::blocking::Response>, BlobEncoding)>> {
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
    ) -> Result<Option<(MeasuredReader<reqwest::blocking::Response>, BlobEncoding)>> {
        let (response, address) = self.send_to_cache(
            operation,
            request,
            timeout,
            Some(Transfer::Download(blob.size)),
        )?;
        if response.status() == reqwest::StatusCode::ACCEPTED {
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
        let response = self.routes.measure_response(
            self.peer.scheduler_id(),
            sccache_cluster_identity::Role::Scheduler,
            address,
            response,
        );
        Ok(Some((response, encoding)))
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
impl<R: Read> Read for InputDownload<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.reader.read(buffer) {
            Ok(count) => {
                if count == 0 && !buffer.is_empty() && self.remaining != 0 {
                    self.interrupted = true;
                }
                self.remaining = self.remaining.saturating_sub(count as u64);
                Ok(count)
            }
            Err(error) => {
                if error.kind() != io::ErrorKind::Interrupted {
                    self.interrupted = true;
                }
                Err(error)
            }
        }
    }
}

fn retryable_transport_error(error: &anyhow::Error) -> bool {
    if let Some(error) = error.downcast_ref::<reqwest::Error>() {
        return error.is_timeout()
            || error.is_connect()
            || error.is_body()
            || error.is_request()
            || error.status().is_some_and(|status| {
                status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
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
#[test]
fn native_input_stream_distinguishes_truncation_from_complete_transfer() -> Result<()> {
    let mut short = InputDownload {
        reader: Cursor::new(b"short"),
        remaining: 8,
        interrupted: false,
    };
    let mut bytes = Vec::new();
    short.read_to_end(&mut bytes)?;
    assert!(short.interrupted);
    assert_eq!(short.remaining, 3);
    let mut complete = InputDownload {
        reader: Cursor::new(b"complete"),
        remaining: 8,
        interrupted: false,
    };
    bytes.clear();
    complete.read_to_end(&mut bytes)?;
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

fn decode_response<T: DeserializeOwned>(
    response: reqwest::blocking::Response,
    limit: u64,
) -> Result<T> {
    let mut bytes = Vec::new();
    response.take(limit + 1).read_to_end(&mut bytes)?;
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
