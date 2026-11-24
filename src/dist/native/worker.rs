//! Worker-side native compilation orchestration. Inputs are fetched into the
//! native store and results move straight from captured descriptors to the
//! scheduler. There is no legacy archive creation or client-side reupload.

use std::{
    cell::Cell,
    io::{self, Read},
    num::NonZeroUsize,
    sync::{
        Arc, Condvar, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use super::{
    LeaseCheck, NativeCacheClient, PackagePlanRequest, map_packages, retryable_transport_error,
};
use crate::build_runtime::{
    ArchiveLength, BlobRef, CapturedExecution, ExecutionPolicy, ExecutionSpec, NativeServiceBusy,
    NativeStore, PackageArchive, PackageImportLimits, PackageTransferCost, StageBudget, TreeId,
    TreeLease, VerifiedPackage, execute,
    wire::{ActionObservation, ActionRequest, Ticket, WorkerTiming},
};

/// Per-worker observed transfer and decoding rates.
///
/// Initial estimates come from worker configuration and are updated without
/// holding locks during I/O. A poisoned estimate is advisory and recoverable.
#[derive(Clone)]
pub struct PackageTransportTracker {
    timing: Arc<Mutex<WorkerTiming>>,
    slots: Arc<RawDownloadSlots>,
}

struct RawDownloadSlots {
    limit: NonZeroUsize,
    active: Mutex<usize>,
    wake: Condvar,
}

pub(super) struct RawDownloadPermit<'a>(&'a RawDownloadSlots);

impl Drop for RawDownloadPermit<'_> {
    fn drop(&mut self) {
        let mut active = self.0.active.lock().unwrap_or_else(PoisonError::into_inner);
        *active -= 1;
        drop(active);
        self.0.wake.notify_one();
    }
}

impl PackageTransportTracker {
    /// Construct a rate tracker and the shared raw download budget.
    /// # Errors
    /// Returns an error when the initial costs or concurrency are invalid.
    pub fn new(mut initial: WorkerTiming) -> Result<Self> {
        ensure!(initial.valid(), "invalid worker timing estimate");
        initial.revision = 0;
        let limit = NonZeroUsize::new(usize::try_from(initial.transfer.raw_parallelism)?)
            .context("zero raw download parallelism")?;
        Ok(Self {
            timing: Arc::new(Mutex::new(initial)),
            slots: Arc::new(RawDownloadSlots {
                limit,
                active: Mutex::new(0),
                wake: Condvar::new(),
            }),
        })
    }

    /// Maximum concurrent raw content fetches across this worker process.
    #[must_use = "raw transfer concurrency is bounded worker-wide"]
    pub fn parallelism(&self) -> NonZeroUsize {
        self.slots.limit
    }

    /// Acquire one raw HTTP-and-staging slot, checking cancellation while
    /// waiting. A slot is released on every return path, including failures.
    /// # Errors
    /// Returns an error if cancellation or lease renewal failed.
    pub(super) fn raw_slot(&self, check: &LeaseCheck<'_>) -> Result<RawDownloadPermit<'_>> {
        loop {
            check()?;
            let (mut active, _) = self
                .slots
                .wake
                .wait_timeout_while(
                    self.slots
                        .active
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner),
                    Duration::from_millis(50),
                    |in_use| *in_use >= self.slots.limit.get(),
                )
                .unwrap_or_else(PoisonError::into_inner);
            if *active < self.slots.limit.get() {
                *active += 1;
                drop(active);
                return Ok(RawDownloadPermit(&self.slots));
            }
            drop(active);
        }
    }

    /// A point-in-time estimate to send with a package selection request.
    #[must_use = "the estimate changes as the worker observes real work"]
    pub fn estimate(&self) -> PackageTransferCost {
        self.snapshot().transfer
    }

    /// Snapshot both the estimates and their incarnation-local revision.
    #[must_use = "scheduler must not replace newer timing observations with stale heartbeats"]
    pub fn snapshot(&self) -> WorkerTiming {
        *self.timing.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn observe_result(&self, bytes: u64, requests: u64, duration: Duration) {
        let mut timing = self.timing.lock().unwrap_or_else(PoisonError::into_inner);
        timing.result.observe(bytes, requests, duration);
        timing.revision = timing.revision.saturating_add(1);
    }

    /// Update the service-time estimate from a completed sandbox execution.
    pub fn observe_execution(&self, duration: Duration) {
        let observed = u64::try_from(duration.as_nanos())
            .unwrap_or(u64::MAX)
            .clamp(1_000_000, 3_600_000_000_000);
        let mut timing = self.timing.lock().unwrap_or_else(PoisonError::into_inner);
        let previous = timing.execution_nanoseconds;
        timing.execution_nanoseconds = if previous == 0 {
            observed
        } else {
            (3 * previous + observed).div_ceil(4)
        };
        timing.revision = timing.revision.saturating_add(1);
    }

    fn smooth(rate: &mut u64, bytes: u64, duration: Duration) {
        let nanos = duration.as_nanos();
        if bytes < (1 << 20) || nanos < 1_000_000 {
            return;
        }
        let observed = (u128::from(bytes) * 1_000_000_000 / nanos).clamp(1, 1_000_000_000_000);
        let updated = (u128::from(*rate) + observed).div_ceil(2);
        *rate = u64::try_from(updated).unwrap_or(1_000_000_000_000);
    }

    /// Observe actual download and staging time for a verified raw blob.
    pub fn observe_raw(&self, bytes: u64, duration: Duration) {
        let mut timing = self.timing.lock().unwrap_or_else(PoisonError::into_inner);
        let before = timing.transfer;
        let rates = &mut timing.transfer;
        let nanos = duration.as_nanos();
        if (4096..(1 << 20)).contains(&bytes) && (200_000..=2_000_000_000).contains(&nanos) {
            // Small files are dominated by setup and staging. Discount the
            // predicted wire time and update an independent request overhead.
            let wire =
                u128::from(bytes) * 1_000_000_000 / u128::from(rates.download_bytes_per_second);
            let overhead = nanos.saturating_sub(wire).min(5_000_000_000);
            rates.raw_request_nanoseconds =
                u64::try_from((3 * u128::from(rates.raw_request_nanoseconds) + overhead) / 4)
                    .unwrap_or(5_000_000_000);
        } else if bytes >= 1 << 20 {
            let effective = nanos.saturating_sub(u128::from(rates.raw_request_nanoseconds));
            Self::smooth(
                &mut rates.download_bytes_per_second,
                bytes,
                Duration::from_nanos(u64::try_from(effective).unwrap_or(u64::MAX)),
            );
        }
        if timing.transfer != before {
            timing.revision = timing.revision.saturating_add(1);
        }
    }

    /// Observe original delivery plus verified full-package reconstruction.
    /// Measure archive-byte transfer separately from logical raw-blob goodput;
    /// subtract the actual download duration before attributing time to decoding.
    pub fn observe_archive(&self, archive: PackageArchive, duration: Duration, download: Duration) {
        let mut timing = self.timing.lock().unwrap_or_else(PoisonError::into_inner);
        let before = timing.transfer;
        let rates = &mut timing.transfer;
        let effective_download =
            download.saturating_sub(Duration::from_nanos(rates.raw_request_nanoseconds));
        Self::smooth(
            &mut rates.archive_download_bytes_per_second,
            archive.source.size,
            effective_download,
        );
        let transfer_ns = download.as_nanos();
        let entry_cost = u128::from(rates.per_entry_nanoseconds) * u128::from(archive.entry_count);
        let overhead_ns = u128::from(rates.startup_nanoseconds) + entry_cost;
        let decode_ns = duration
            .as_nanos()
            .saturating_sub(transfer_ns.saturating_add(overhead_ns));
        let rate = match archive.source.identity.compression {
            crate::build_runtime::PackageCompression::Tar => &mut rates.decode_tar_bytes_per_second,
            crate::build_runtime::PackageCompression::Gzip => {
                &mut rates.decode_gzip_bytes_per_second
            }
            crate::build_runtime::PackageCompression::Xz => &mut rates.decode_xz_bytes_per_second,
            crate::build_runtime::PackageCompression::Zstd => {
                &mut rates.decode_zstd_bytes_per_second
            }
        };
        // The observed decompression time can be zero when the network was
        // slower than predicted; it is then not a useful decoder sample.
        if decode_ns >= 1_000_000 {
            Self::smooth(
                rate,
                archive.expanded_bytes,
                Duration::from_nanos(u64::try_from(decode_ns).unwrap_or(u64::MAX)),
            );
        }
        if timing.transfer != before {
            timing.revision = timing.revision.saturating_add(1);
        }
    }
}

/// Explicit worker delivery policy for a complete admitted action.
#[derive(Clone, Copy)]
pub struct WorkerDelivery<'a> {
    pub renewal_interval: Duration,
    pub package_import: Option<PackageImportLimits>,
    pub transport: &'a PackageTransportTracker,
    pub execution_queue: &'a crate::dist::execution_queue::ExecutionQueue,
    pub artifact_grace: &'a super::ArtifactGrace,
}

#[cfg(feature = "dist-client")]
#[derive(Clone, Copy)]
pub(super) struct ExecutionControl<'a> {
    pub renewal_interval: Duration,
    pub queue: Option<&'a crate::dist::execution_queue::ExecutionQueue>,
    pub grace: Option<&'a super::ArtifactGrace>,
    pub transport: Option<&'a PackageTransportTracker>,
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use crate::build_runtime::{
        BlobRef, ContentId, PackageCompression, PackageIdentity, PackageSource, TreeId,
    };

    #[test]
    fn slots_bound_parallel_downloads_and_restore_admission_on_drop() -> Result<()> {
        use std::sync::{
            Barrier,
            atomic::{AtomicUsize, Ordering},
        };
        let tracker = PackageTransportTracker::new(WorkerTiming {
            transfer: PackageTransferCost {
                raw_parallelism: 2,
                ..Default::default()
            },
            ..Default::default()
        })?;
        let barrier = Barrier::new(8);
        let running = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        std::thread::scope(|scope| -> Result<()> {
            let threads = (0..8)
                .map(|_| {
                    let tracker = tracker.clone();
                    let barrier = &barrier;
                    let running = &running;
                    let peak = &peak;
                    scope.spawn(move || -> Result<()> {
                        barrier.wait();
                        let _permit = tracker.raw_slot(&|| Ok(()))?;
                        let count = running.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(count, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(30));
                        running.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                })
                .collect::<Vec<_>>();
            for thread in threads {
                thread
                    .join()
                    .map_err(|_| anyhow::anyhow!("raw limiter worker panicked"))??;
            }
            Ok(())
        })?;
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(running.load(Ordering::SeqCst), 0);
        assert!(
            tracker
                .raw_slot(&|| anyhow::bail!("expired session"))
                .is_err()
        );
        let initial = tracker.estimate().raw_request_nanoseconds;
        tracker.observe_raw(8192, Duration::from_millis(35));
        assert!(tracker.estimate().raw_request_nanoseconds > initial);
        assert_eq!(tracker.estimate().raw_parallelism, 2);
        Ok(())
    }

    #[test]
    fn observed_worker_timing_revisions_cover_every_published_service_update() -> Result<()> {
        let tracker = PackageTransportTracker::new(WorkerTiming::default())?;
        let initial = tracker.snapshot();
        assert_eq!(initial.execution_estimate(), 1_000_000_000);
        tracker.observe_execution(Duration::from_millis(50));
        let compiled = tracker.snapshot();
        assert_eq!(compiled.execution_estimate(), 50_000_000);
        assert!(compiled.revision > initial.revision);
        tracker.observe_result(0, 0, Duration::ZERO);
        let published = tracker.snapshot();
        assert_eq!(published.result.expected_bytes, 0);
        assert!(published.revision > compiled.revision);
        tracker.observe_raw(32 << 20, Duration::from_secs(2));
        let transferred = tracker.snapshot();
        assert_ne!(transferred.transfer, published.transfer);
        assert!(transferred.revision > published.revision);
        let mut scheduler = transferred;
        scheduler.adopt(published);
        assert_eq!(scheduler, transferred);
        scheduler.adopt(WorkerTiming {
            revision: transferred.revision + 1,
            execution_nanoseconds: u64::MAX,
            ..transferred
        });
        assert_eq!(scheduler, transferred);
        Ok(())
    }

    #[test]
    fn observed_rates_change_future_costs_without_overreacting_to_tiny_files() -> Result<()> {
        let tracker = PackageTransportTracker::new(WorkerTiming::default())?;
        let initial = tracker.estimate();
        tracker.observe_raw(100, Duration::from_secs(20));
        assert_eq!(tracker.estimate(), initial);
        tracker.observe_raw(32 << 20, Duration::from_secs(2));
        let observed = tracker.estimate();
        assert!(observed.download_bytes_per_second < initial.download_bytes_per_second);
        assert!(observed.download_bytes_per_second > (16 << 20));
        let archive = PackageArchive {
            source: PackageSource {
                identity: PackageIdentity {
                    sha256: [5; 32],
                    compression: PackageCompression::Zstd,
                },
                size: 16 << 20,
            },
            tree: TreeId([4; 32]),
            blob: BlobRef {
                id: ContentId([3; 32]),
                size: 16 << 20,
            },
            expanded_bytes: 64 << 20,
            entry_count: 250,
        };
        tracker.observe_archive(archive, Duration::from_secs(6), Duration::from_secs(1));
        assert!(
            tracker.estimate().decode_zstd_bytes_per_second < observed.decode_zstd_bytes_per_second
        );
        assert_eq!(
            tracker.estimate().download_bytes_per_second,
            observed.download_bytes_per_second
        );
        assert!(
            tracker.estimate().archive_download_bytes_per_second
                < observed.archive_download_bytes_per_second
        );
        assert_eq!(
            tracker.estimate().decode_xz_bytes_per_second,
            observed.decode_xz_bytes_per_second
        );
        Ok(())
    }
}

// Measure the actual archive transfer independently of its subsequent decoder.
struct TimedDownload<'a, R> {
    reader: R,
    start: Instant,
    elapsed: &'a Cell<Option<Duration>>,
}

impl<R: Read> Read for TimedDownload<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(buffer)?;
        if count == 0 && !buffer.is_empty() && self.elapsed.get().is_none() {
            self.elapsed.set(Some(self.start.elapsed()));
        }
        Ok(count)
    }
}

impl NativeCacheClient {
    pub(super) fn reconstruct_packages(
        &self,
        ticket: Ticket,
        missing: &[BlobRef],
        store: &NativeStore,
        limits: PackageImportLimits,
        transport: &PackageTransportTracker,
        check: &LeaseCheck<'_>,
    ) -> Result<Vec<VerifiedPackage>> {
        let plan = self.control(
            "package_plan",
            &PackagePlanRequest {
                ticket,
                missing: missing.to_vec(),
                max_archive_bytes: limits.max_archive_bytes,
                cost: transport.estimate(),
            },
        );
        let offers: Vec<PackageArchive> = match plan {
            Ok(offers) => offers,
            Err(error) => {
                warn!("native original package plan unavailable: {error:#}");
                return Ok(Vec::new());
            }
        };
        let jobs = NonZeroUsize::new(limits.max_concurrent_imports)
            .context("zero package acquisition concurrency")?;
        let packages = map_packages(&offers, jobs, |offer| {
            check()?;
            match self.reconstruct_package(ticket, *offer, store, limits, transport, check) {
                Ok(package) => Ok(Some(package)),
                Err(error) => {
                    check()?;
                    // Package transport is optional. Verify all remaining
                    // input bytes by retrieving the missing blobs directly.
                    warn!("native package reconstruction unavailable: {error:#}");
                    Ok(None)
                }
            }
        })?;
        Ok(packages.into_iter().flatten().collect())
    }

    fn reconstruct_package(
        &self,
        ticket: Ticket,
        offer: PackageArchive,
        store: &NativeStore,
        limits: PackageImportLimits,
        transport: &PackageTransportTracker,
        check: &LeaseCheck<'_>,
    ) -> Result<VerifiedPackage> {
        ensure!(
            !limits.retain_original
                && offer.blob.size == offer.source.size
                && offer.source.size <= limits.max_archive_bytes,
            "invalid native original archive offer"
        );
        let start = Instant::now();
        let executable = std::env::current_exe()?;
        loop {
            check()?;
            let attempted = Instant::now();
            let downloaded = Cell::new(None);
            let (package, reused) = match store.acquire_package(
                offer.source.identity,
                ArchiveLength::Exact(offer.source.size),
                limits,
                &executable,
                || {
                    let start = Instant::now();
                    Ok(TimedDownload {
                        reader: {
                            let (response, encoding) =
                                self.download_response(ticket, offer.blob.id)?;
                            ensure!(
                                encoding == crate::build_runtime::BlobEncoding::Raw,
                                "package must be original bytes"
                            );
                            response
                        },
                        start,
                        elapsed: &downloaded,
                    })
                },
            ) {
                Ok(package) => package,
                Err(error) if error.is::<NativeServiceBusy>() => {
                    ensure!(
                        start.elapsed() < self.timeout,
                        "native worker package reservation deadline exceeded"
                    );
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(error) => return Err(error),
            };
            ensure!(
                package.source() == offer.source && package.tree().id() == offer.tree,
                "reconstructed original package identity mismatch"
            );
            if !reused {
                if let Some(download) = downloaded.get() {
                    transport.observe_archive(offer, attempted.elapsed(), download);
                }
                debug!(
                    "native package transfer estimate after import: {:?}",
                    transport.estimate()
                );
                info!(
                    "native original package reconstructed from {} compressed bytes in {:.3}s",
                    offer.source.size,
                    start.elapsed().as_secs_f64()
                );
            }
            return Ok(package);
        }
    }

    /// Acquire and pin an admitted worker action before it enters the compiler queue.
    /// # Errors
    /// Returns an error if the lease, execution contract or staging fails.
    pub fn prepare_on_worker(
        &self,
        ticket: Ticket,
        spec: &ExecutionSpec,
        store: &NativeStore,
        policy: &ExecutionPolicy,
        delivery: WorkerDelivery<'_>,
        preparation: WorkerPreparation<'_>,
    ) -> Result<PreparedWorker> {
        let started = Instant::now();
        let lease = WorkerLease::start(
            self.clone(),
            ticket,
            spec,
            policy.timeout,
            delivery.renewal_interval,
            preparation.cancelled,
        )?;
        lease.check()?;
        (preparation.on_authorized)()?;
        lease.check()?;
        let mut prepared = self.prepare_execution(
            ExecutionContext {
                ticket,
                spec,
                store,
                policy,
            },
            Some((
                delivery.artifact_grace,
                preparation
                    .estimated_result_bytes
                    .unwrap_or(policy.max_result_bytes)
                    .clamp(1, policy.max_result_bytes),
            )),
            |id, check, on_tree| self.fetch_tree(ticket, id, store, delivery, check, on_tree),
            &|| lease.check(),
            preparation.on_tree,
        )?;
        if prepared.warm_staging.is_some() {
            prepared.warm_staging = Some(started.elapsed());
        }
        Ok(PreparedWorker {
            lease,
            prepared,
            spec: spec.clone(),
        })
    }

    #[cfg(feature = "dist-client")]
    pub(super) fn execute_admitted(
        &self,
        ticket: Ticket,
        spec: &ExecutionSpec,
        store: &NativeStore,
        policy: &ExecutionPolicy,
        control: ExecutionControl<'_>,
        mut fetch: impl FnMut(TreeId, &LeaseCheck<'_>) -> Result<TreeLease>,
    ) -> Result<CapturedExecution> {
        let context = ExecutionContext {
            ticket,
            spec,
            store,
            policy,
        };
        let result = self.with_renewal(ticket, control.renewal_interval, |check| {
            self.verify_execution(ticket, spec.clone())?;
            let prepared = self.prepare_execution(
                context,
                control.grace.map(|grace| (grace, policy.max_result_bytes)),
                |id, check, _| fetch(id, check),
                check,
                &mut |_| {},
            )?;
            let captured = compile(context, control.queue, control.transport, check, || {})?;
            self.publish_execution(context, prepared, captured, control.transport, check)
        });
        if result.is_err() {
            let _ = self.fail(ticket);
        }
        result
    }

    fn prepare_execution(
        &self,
        context: ExecutionContext<'_>,
        grace: Option<(&super::ArtifactGrace, u64)>,
        mut fetch: impl FnMut(TreeId, &LeaseCheck<'_>, &mut dyn FnMut(&TreeLease)) -> Result<TreeLease>,
        check: &LeaseCheck<'_>,
        on_tree: &mut dyn FnMut(&TreeLease),
    ) -> Result<PreparedExecution> {
        let started = Instant::now();
        let mut warm = true;
        let ExecutionContext {
            ticket,
            spec,
            store,
            policy,
        } = context;
        if let Some((grace, _)) = grace {
            grace.reap();
        }
        if let Some(report) = store.maintain_space()? {
            ensure!(
                report.minimum_satisfied,
                "native executor store lacks allocatable space: {report:?}"
            );
        }
        let request = spec.action_request()?;
        ensure!(
            spec.platform == policy.platform,
            "native executor platform mismatch"
        );
        // Reserve output headroom before staged inputs can consume it. Wait for
        // grace capacity without occupying a compiler slot.
        let output = if let Some((grace, predicted)) = grace {
            let started = Instant::now();
            let reservation = loop {
                check()?;
                if let Some(reservation) = grace.reserve(predicted)? {
                    break reservation;
                }
                ensure!(
                    started.elapsed() < policy.timeout,
                    "native artifact grace admission timed out"
                );
                warm = false;
                std::thread::sleep(Duration::from_millis(100));
            };
            Some((reservation, store.reserve_staging(policy.max_result_bytes)?))
        } else {
            None
        };
        let mut inputs = Vec::new();
        for id in &request.input_trees {
            check()?;
            let (tree, hit) = if let Some(tree) = store.lookup_tree(*id)? {
                (Arc::new(tree), true)
            } else {
                warm = false;
                store.acquire_tree(*id, check, || fetch(*id, check, on_tree))?
            };
            if log::log_enabled!(target: "native_cas_replay", log::Level::Trace) {
                let blobs = tree
                    .manifest()
                    .blobs()?
                    .into_iter()
                    .map(|(id, size)| BlobRef { id, size })
                    .collect::<Vec<_>>();
                log::trace!(
                target: "native_cas_replay",
                "{}",
                serde_json::json!({
                    "kind": "tree_access",
                    "tree": id,
                    "hit": hit,
                    "blobs": blobs,
                })
                );
            }
            on_tree(&tree);
            inputs.push(tree);
        }
        // The notification is idempotent. A lost response must not
        // discard the already pinned input closure.
        let announced = Instant::now();
        loop {
            check()?;
            match self.inputs_staged(ticket) {
                Ok(()) => break,
                Err(error)
                    if retryable_transport_error(&error)
                        && announced.elapsed() < policy.timeout =>
                {
                    warm = false;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(PreparedExecution {
            request,
            _inputs: inputs,
            output,
            warm_staging: warm.then(|| started.elapsed()),
        })
    }

    fn publish_execution(
        &self,
        context: ExecutionContext<'_>,
        mut prepared: PreparedExecution,
        measured: MeasuredExecution,
        transport: Option<&PackageTransportTracker>,
        check: &LeaseCheck<'_>,
    ) -> Result<CapturedExecution> {
        let ExecutionContext { ticket, store, .. } = context;
        let MeasuredExecution { captured, duration } = measured;
        check()?;
        if let Some(manifest) = captured.successful_result() {
            let publication_started = Instant::now();
            prepared.request.validate_result(manifest)?;
            let blobs = manifest.blobs()?;
            let retained = if let Some((grace, mut budget)) = prepared.output.take() {
                grace.retain(
                    store,
                    &mut budget,
                    &prepared.request.action_fingerprint()?,
                    manifest,
                    &captured,
                    (context.policy.timeout, check),
                )?
            } else {
                None
            };
            let missing = self.begin(ticket, manifest.clone())?.missing;
            let publication_setup = retained
                .as_ref()
                .is_none_or(|output| output.warm)
                .then(|| publication_started.elapsed());
            // The scheduler recorded its anchor before sending the begin
            // response. Its clock need not be synchronized with ours.
            let retained_after_begin = retained.map_or(Duration::ZERO, |output| {
                output.deadline.saturating_duration_since(Instant::now())
            });
            let bytes = missing
                .iter()
                .map(|blob| blob.size)
                .fold(0_u64, u64::saturating_add);
            let requests = u64::try_from(missing.len())?;
            let started = Instant::now();
            for missing in missing {
                check()?;
                ensure!(
                    blobs.get(&missing.id) == Some(&missing.size),
                    "scheduler requested undeclared output"
                );
                self.upload_stored_file(
                    ticket,
                    missing,
                    captured.physical_encoding(),
                    captured.open_file(missing.id)?,
                )?;
            }
            let upload_duration = started.elapsed();
            let worker_timing = transport.map(|transport| {
                transport.observe_result(bytes, requests, upload_duration);
                transport.snapshot()
            });
            ensure!(
                self.commit(
                    ticket,
                    retained_after_begin,
                    Some(ActionObservation {
                        worker_timing,
                        warm_staging_nanoseconds: prepared
                            .warm_staging
                            .and_then(service_nanoseconds),
                        publication_setup_nanoseconds: publication_setup
                            .and_then(service_nanoseconds),
                        execution_nanoseconds: u64::try_from(duration.as_nanos())
                            .unwrap_or(u64::MAX)
                            .max(1),
                        upload_bytes: bytes,
                        upload_requests: requests,
                        upload_nanoseconds: u64::try_from(upload_duration.as_nanos())
                            .unwrap_or(u64::MAX),
                    })
                )? == *manifest,
                "native publication manifest mismatch"
            );
        } else {
            self.fail(ticket)?;
        }
        Ok(captured)
    }
}

#[derive(Clone, Copy)]
struct ExecutionContext<'a> {
    ticket: Ticket,
    spec: &'a ExecutionSpec,
    store: &'a NativeStore,
    policy: &'a ExecutionPolicy,
}

struct PreparedExecution {
    warm_staging: Option<Duration>,
    request: ActionRequest,
    _inputs: Vec<Arc<TreeLease>>,
    output: Option<(super::grace::GraceReservation, StageBudget)>,
}

fn service_nanoseconds(duration: Duration) -> Option<u64> {
    u64::try_from(duration.as_nanos())
        .ok()
        .filter(|&ns| ns <= 60_000_000_000)
}

struct MeasuredExecution {
    captured: CapturedExecution,
    duration: Duration,
}

fn compile(
    context: ExecutionContext<'_>,
    queue: Option<&crate::dist::execution_queue::ExecutionQueue>,
    transport: Option<&PackageTransportTracker>,
    check: &LeaseCheck<'_>,
    on_start: impl FnOnce(),
) -> Result<MeasuredExecution> {
    let _permit = queue.map(|queue| queue.acquire(check)).transpose()?;
    on_start();
    let started = Instant::now();
    let captured = execute(context.spec, context.store, context.policy, check)?;
    let duration = started.elapsed();
    if captured.successful_result().is_some()
        && let Some(transport) = transport
    {
        transport.observe_execution(duration);
    }
    Ok(MeasuredExecution { captured, duration })
}

// The lease owns cancellation and renewal across queue handoffs. Errors
// release all local reservations and cancel the remote action exactly once.
struct WorkerLease {
    client: NativeCacheClient,
    ticket: Ticket,
    renewals: Option<super::renewal::Renewals>,
    cancelled: Arc<AtomicBool>,
}

impl WorkerLease {
    fn start(
        client: NativeCacheClient,
        ticket: Ticket,
        spec: &ExecutionSpec,
        timeout: Duration,
        interval: Duration,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        let mut lease = Self {
            client,
            ticket,
            renewals: None,
            cancelled,
        };
        // Verification is the delegation barrier: the scheduler cannot
        // authorize this worker until its assignment RPC has returned and
        // the session has installed the delegated publisher.
        let result = (|| {
            let started = Instant::now();
            let mut delay = Duration::from_millis(10);
            loop {
                ensure!(
                    !lease.cancelled.load(Ordering::Acquire),
                    "native worker assignment cancelled"
                );
                let remaining = timeout.saturating_sub(started.elapsed());
                ensure!(
                    !remaining.is_zero(),
                    "native assignment authorization timed out"
                );
                match lease.client.verify_execution(ticket, spec.clone()) {
                    Ok(()) => break,
                    Err(error) if retryable_transport_error(&error) => {
                        debug!("retrying native assignment authorization: {error:#}");
                        std::thread::sleep(delay.min(remaining));
                        delay = (delay * 2).min(Duration::from_millis(200));
                    }
                    Err(error) => return Err(error),
                }
            }
            let renewals = super::renewal::Renewals::start(lease.client.clone(), interval)?;
            renewals.add(ticket)?;
            Ok(renewals)
        })();
        match result {
            Ok(renewals) => {
                lease.renewals = Some(renewals);
                Ok(lease)
            }
            Err(error) => {
                let _ = lease.client.fail(ticket);
                Err(error)
            }
        }
    }

    fn check(&self) -> Result<()> {
        ensure!(
            !self.cancelled.load(Ordering::Acquire),
            "native worker assignment cancelled"
        );
        self.renewals
            .as_ref()
            .context("native worker lease already finished")?
            .check()
    }

    fn finish(mut self) {
        if let Some(renewals) = self.renewals.take()
            && let Err(error) = renewals.finish()
        {
            debug!("Native worker lease ended after terminal publication: {error:#}");
        }
    }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        if let Some(renewals) = self.renewals.take() {
            drop(renewals);
            let _ = self.client.fail(self.ticket);
        }
    }
}

/// Cancellation and verified-tree progress for worker-side preparation.
pub struct WorkerPreparation<'a> {
    pub estimated_result_bytes: Option<u64>,
    pub cancelled: Arc<AtomicBool>,
    pub on_tree: &'a mut dyn FnMut(&TreeLease),
    pub on_authorized: &'a dyn Fn() -> Result<()>,
}

/// A ready action owns its verified input closure and output reservation.
pub struct PreparedWorker {
    prepared: PreparedExecution,
    spec: ExecutionSpec,
    lease: WorkerLease,
}

impl PreparedWorker {
    /// Execute only after compiler admission, retaining output descriptors.
    #[must_use = "publication must finish the lease"]
    pub fn execute(
        self,
        store: &NativeStore,
        policy: &ExecutionPolicy,
        delivery: WorkerDelivery<'_>,
        on_start: impl FnOnce(),
    ) -> CompletedWorker {
        let context = ExecutionContext {
            ticket: self.lease.ticket,
            spec: &self.spec,
            store,
            policy,
        };
        let captured = compile(
            context,
            Some(delivery.execution_queue),
            Some(delivery.transport),
            &|| self.lease.check(),
            on_start,
        );
        CompletedWorker {
            worker: self,
            captured,
        }
    }
}

/// A compiler has exited; publication does not occupy a compiler slot.
pub struct CompletedWorker {
    worker: PreparedWorker,
    captured: Result<MeasuredExecution>,
}

impl CompletedWorker {
    /// Publish retained outputs and finish the scheduler lease.
    /// # Errors
    /// Returns an error for failed publication, verification or cancellation.
    pub fn publish(
        self,
        store: &NativeStore,
        policy: &ExecutionPolicy,
        transport: &PackageTransportTracker,
    ) -> Result<CapturedExecution> {
        let PreparedWorker {
            lease,
            prepared,
            spec,
        } = self.worker;
        let context = ExecutionContext {
            ticket: lease.ticket,
            spec: &spec,
            store,
            policy,
        };
        let captured = lease.client.publish_execution(
            context,
            prepared,
            self.captured?,
            Some(transport),
            &|| lease.check(),
        )?;
        lease.finish();
        Ok(captured)
    }
}
