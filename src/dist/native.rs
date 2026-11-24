//! Client and worker adapters for the scheduler's native cache protocol.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Cursor, Read, Write},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::build_runtime::{
    ActionMode, BlobRef, ContentId, ExecutionSpec, InstallationManifest, PackageIdentity,
    PackageReceipt, PackageSource, PackageTransferCost, ResultManifest, TreeId, TreeManifest,
    wire::{
        BeginResult, InputDemand, InputPoll, NativeAdmission, NativeRunRequest, NativeRunResult,
        NativeStatus, ScheduleReply, Ticket, TreeOffer, TreeRead, UploadHeader, WorkerAllocation,
    },
};
use crate::dist::JobId;

mod package;
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
pub(super) struct ManifestRequest {
    pub ticket: Ticket,
    pub manifest: ResultManifest,
}

#[derive(Serialize, Deserialize)]
pub(super) struct CommitRequest {
    pub ticket: Ticket,
    // Duration from receipt of the begin response until local grace expiry.
    pub retained_after_begin_millis: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct DownloadRequest {
    pub ticket: Ticket,
    pub id: ContentId,
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
    http: reqwest::blocking::Client,
    base: reqwest::Url,
    auth: String,
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
        base: reqwest::Url,
        auth: String,
        timeout: Duration,
        metadata_limit: u64,
    ) -> Result<Self> {
        ensure!(
            matches!(base.scheme(), "http" | "https")
                && base.query().is_none()
                && base.fragment().is_none()
                && base.username().is_empty()
                && base.password().is_none(),
            "invalid native cache endpoint"
        );
        ensure!(
            metadata_limit > 0 && metadata_limit < u64::MAX && !timeout.is_zero(),
            "invalid native client bounds"
        );
        let http = crate::http_client::new_reqwest_blocking_builder()?
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .build()?;
        Ok(Self {
            http,
            base,
            auth,
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

    fn request(&self, operation: &str) -> Result<reqwest::blocking::RequestBuilder> {
        let (role, job) = match self.role {
            Role::Client => ("client", None),
            Role::Worker(job) => ("worker", Some(job)),
        };
        let url = self
            .base
            .join(&format!("/api/v3/native/{role}/{operation}"))?;
        let mut request = self
            .http
            .post(url)
            .bearer_auth(&self.auth)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CONNECTION, "close");
        if let Some(job) = job {
            request = request.header("X-Sccache-Native-Job", job.to_string());
        }
        Ok(request)
    }

    fn control<T: Serialize, R: DeserializeOwned>(&self, operation: &str, value: &T) -> Result<R> {
        let data = codec().with_limit(self.metadata_limit).serialize(value)?;
        let response = self
            .request(operation)?
            .body(data)
            .send()?
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
            let response = self
                .request(operation)?
                .timeout(remaining)
                .body(data.clone())
                .send()?;
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
        decode_response(response, self.metadata_limit)
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
            &UploadHeader { ticket, blob },
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
        self.control("schedule", &ExecutionRequest { ticket, spec })
    }

    /// Claim a scheduler-assigned worker job over its authenticated HTTPS
    /// endpoint. Successful outputs are read separately from the scheduler.
    ///
    /// # Errors
    /// Returns an error for a rejected job, invalid certificate or transport
    /// failure, or an oversized failure response.
    pub fn run_worker(
        allocation: &WorkerAllocation,
        timeout: Duration,
        max_response_bytes: u64,
    ) -> Result<NativeRunResult> {
        ensure!(
            !timeout.is_zero() && max_response_bytes > 0 && max_response_bytes < u64::MAX,
            "invalid native run limits"
        );
        let certificate = reqwest::Certificate::from_pem(&allocation.certificate)?;
        let http = reqwest::blocking::Client::builder()
            .tls_certs_only([certificate])
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let url = crate::dist::http::urls::server_run_native_job(
            crate::dist::ServerId::new(allocation.address),
            JobId(allocation.job),
        )?;
        let max_response_bytes = max_response_bytes
            .checked_add(64)
            .context("native response limit overflow")?;
        let started = Instant::now();
        let mut idle = Duration::from_millis(5);
        let rpc = |operation, remaining: Duration| -> Result<NativeRunResult> {
            let response = http
                .post(url.clone())
                .bearer_auth(&allocation.auth)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .timeout(remaining.min(Duration::from_secs(5)))
                .body(codec().serialize(&operation)?)
                .send()?
                .error_for_status()?;
            decode_response(response, max_response_bytes)
        };
        loop {
            let remaining = timeout.saturating_sub(started.elapsed());
            ensure!(!remaining.is_zero(), "native worker deadline exceeded");
            match rpc(NativeRunRequest::Poll, remaining) {
                Ok(NativeRunResult::Pending(_)) => {}
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
                    return Ok(result);
                }
                Err(error) if retryable_transport_error(&error) => {
                    debug!("retrying native worker status: {error:#}")
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
        let id = manifest.id()?;
        let blobs = manifest.blobs()?;
        let offer = self.offer_tree(manifest)?;
        debug!(
            "native tree {id:?}: upload {}/{} blobs, {}/{} content bytes",
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
                self.upload(offer.ticket, blob, open(blob.id)?)?;
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
                self.control::<_, ()>("input_prefetch", &InputPrefetchRequest {
                    ticket: read.ticket,
                    missing: chunk.to_vec(),
                })?;
                let leases = map_packages(chunk, transport.parallelism(), |blob| {
                    self.fetch_input_blob(read.ticket, *blob, store, transport, check)
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
                let start = Instant::now();
                let mut delay = Duration::from_millis(10);
                loop {
                    check()?;
                    let slot = transport.raw_slot(check)?;
                    let remaining = self.timeout.checked_sub(start.elapsed())
                        .filter(|remaining| !remaining.is_zero())
                        .context("native input backfill timed out")?;
                    let transfer = Instant::now();
                    match self.try_download_response(ticket, blob.id, remaining) {
                        Ok(Some(response)) => {
                            let mut stream = InputDownload {
                                reader: response,
                                remaining: blob.size,
                                interrupted: false,
                            };
                            match store.stage_expected(blob, &mut stream) {
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

    /// Upload one missing blob directly from an open file descriptor.
    ///
    /// # Errors
    /// Returns an error for an invalid length or rejected transfer.
    pub fn upload_file(&self, ticket: Ticket, blob: BlobRef, file: File) -> Result<()> {
        ensure!(
            file.metadata()?.len() == blob.size,
            "native upload file length mismatch"
        );
        self.upload(ticket, blob, file)
    }

    /// Send raw content without buffering it in memory. The scheduler verifies
    /// the full digest and declared length before admitting it.
    ///
    /// # Errors
    /// Returns an error on transport or verification failure.
    pub fn upload(
        &self,
        ticket: Ticket,
        blob: BlobRef,
        reader: impl Read + Send + 'static,
    ) -> Result<()> {
        self.send_stream("upload", &UploadHeader { ticket, blob }, blob.size, reader)?;
        Ok(())
    }

    fn send_stream(
        &self,
        operation: &str,
        metadata: &impl Serialize,
        size: u64,
        reader: impl Read + Send + 'static,
    ) -> Result<reqwest::blocking::Response> {
        let header = codec()
            .with_limit(self.metadata_limit)
            .serialize(metadata)?;
        let length = size
            .checked_add(u64::try_from(header.len())?)
            .context("native upload length overflow")?;
        let body = reqwest::blocking::Body::sized(Cursor::new(header).chain(reader), length);
        Ok(self
            .request(operation)?
            .body(body)
            .send()?
            .error_for_status()?)
    }

    /// Commit the negotiated result.
    ///
    /// # Errors
    /// Returns an error if uploads are unfinished or publication failed.
    pub fn commit(&self, ticket: Ticket, retained_after_begin: Duration) -> Result<ResultManifest> {
        self.control(
            "commit",
            &CommitRequest {
                ticket,
                retained_after_begin_millis: u64::try_from(retained_after_begin.as_millis())
                    .unwrap_or(u64::MAX),
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
        self.control("status", &ticket)
    }

    /// Release a result ticket or cancel an unfinished action.
    ///
    /// # Errors
    /// Returns an error if the ticket cannot be closed.
    pub fn close(&self, ticket: Ticket) -> Result<()> {
        self.control("close", &ticket)
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
        copy_verified(
            self.download_response(ticket, blob.id)?,
            blob,
            &mut destination,
        )
    }

    fn download_response(&self, ticket: Ticket, id: ContentId) -> Result<Box<dyn Read + Send>> {
        self.try_download_response(ticket, id, self.timeout)?
            .context("native content not yet available")
    }

    fn try_download_response(
        &self,
        ticket: Ticket,
        id: ContentId,
        timeout: Duration,
    ) -> Result<Option<Box<dyn Read + Send>>> {
        let request = codec().serialize(&DownloadRequest { ticket, id })?;
        let response = self
            .request("download")?
            .timeout(timeout)
            .header("X-Sccache-Accept-Blob-Codec", "zstd")
            .body(request)
            .send()?;
        if response.status() == reqwest::StatusCode::ACCEPTED {
            return Ok(None);
        }
        let response = response.error_for_status()?;
        match response.headers().get("X-Sccache-Blob-Codec") {
            None => Ok(Some(Box::new(response))),
            Some(value) if value.as_bytes() == b"zstd" => {
                Ok(Some(Box::new(zstd::stream::read::Decoder::new(response)?)))
            }
            Some(other) => anyhow::bail!("unsupported native blob codec: {other:?}"),
        }
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
pub use client::{NativeBuildPolicy, NativeBuildResult, NativeBuildSource};
#[cfg(all(target_os = "linux", feature = "dist-client"))]
pub use local::LocalExecutor;

#[cfg(all(target_os = "linux", feature = "dist-client"))]
pub(crate) mod broker;
