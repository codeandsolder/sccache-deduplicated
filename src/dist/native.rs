//! Client and worker adapters for the scheduler's native cache protocol.

use std::{
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
        BeginResult, NativeAdmission, NativeRunResult, NativeStatus, ScheduleReply, Ticket,
        TreeOffer, TreeRead, UploadHeader, WorkerAllocation,
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
pub(super) struct DownloadRequest {
    pub ticket: Ticket,
    pub id: ContentId,
}

#[derive(Serialize, Deserialize)]
pub(super) struct OpenTreeRequest {
    pub action: Ticket,
    pub tree: TreeId,
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
        let http = crate::util::new_reqwest_blocking_builder()?
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
            .join(&format!("/api/v2/native/{role}/{operation}"))?;
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
    pub fn admit(&self, spec: &ExecutionSpec, mode: ActionMode) -> Result<NativeAdmission> {
        self.control("admit", &(spec, mode))
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
        let response = http
            .post(url)
            .bearer_auth(&allocation.auth)
            .send()?
            .error_for_status()?;
        decode_response(response, max_response_bytes)
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
    pub fn fetch_tree(
        &self,
        action: Ticket,
        id: TreeId,
        store: &crate::build_runtime::NativeStore,
        renewal_interval: Duration,
        package_import: Option<crate::build_runtime::PackageImportLimits>,
        transport: &worker::PackageTransportTracker,
    ) -> Result<crate::build_runtime::TreeLease> {
        let read = self.open_tree(action, id)?;
        let result = self.with_renewal(read.ticket, renewal_interval, |check| {
            ensure!(
                read.manifest.id()? == id,
                "native tree download identity mismatch"
            );
            let reserved = store.reserve_tree_upload(&read.manifest)?;
            #[cfg(target_os = "linux")]
            let packages = match package_import {
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
            #[cfg(not(target_os = "linux"))]
            let _ = package_import;
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
            let staged = map_packages(updated.missing(), transport.parallelism(), |blob| {
                check()?;
                let _slot = transport.raw_slot(check)?;
                let start = Instant::now();
                let (response, encoding) = self.download_response(read.ticket, blob.id)?;
                let staged = store.stage_expected_physical(*blob, encoding, response)?;
                transport.observe_raw(blob.size, start.elapsed());
                Ok(staged)
            })?;
            let tree = store.publish_tree_pinned(&read.manifest, staged)?;
            #[cfg(target_os = "linux")]
            drop(packages);
            Ok(tree)
        });
        // Best effort: the remote pin also expires automatically.
        let _ = self.close(read.ticket);
        result
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
    pub fn commit(&self, ticket: Ticket) -> Result<ResultManifest> {
        self.control("commit", &ticket)
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
        let (response, encoding) = self.download_response(ticket, blob.id)?;
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
        id: ContentId,
    ) -> Result<(reqwest::blocking::Response, BlobEncoding)> {
        let request = codec().serialize(&DownloadRequest { ticket, id })?;
        let response = self
            .request("download")?
            .body(request)
            .send()?
            .error_for_status()?;
        let descriptor = response
            .headers()
            .get("x-sccache-cas-encoding")
            .context("native download missing physical encoding")?
            .to_str()?;
        let encoding = BlobEncoding::from_http_value(descriptor)?;
        Ok((response, encoding))
    }
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

mod renewal;
#[cfg(all(target_os = "linux", feature = "native-store"))]
mod worker;
#[cfg(all(target_os = "linux", feature = "native-store"))]
pub use worker::{PackageTransportTracker, WorkerDelivery};

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
