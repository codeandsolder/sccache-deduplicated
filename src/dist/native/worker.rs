//! Worker-side native compilation orchestration. Inputs are fetched into the
//! native store and results move straight from captured descriptors to the
//! scheduler. There is no legacy archive creation or client-side reupload.

use std::{
    num::NonZeroUsize,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use super::{
    LeaseCheck, NativeCacheClient, PackagePlanRequest, ingress, retryable_transport_error,
};
use crate::build_runtime::{
    ArchiveLength, BlobRef, CapturedExecution, ExecutionPolicy, ExecutionSpec, NativeStore,
    PackageArchive, PackageImportLimits, PackagePreparation, PackageTransferCost, StageBudget,
    TreeId, TreeLease, VerifiedPackage, execute,
    wire::{ActionObservation, ActionRequest, Ticket, WorkerTiming},
};

/// Per-worker observed transfer and decoding rates.
///
/// Initial estimates come from worker configuration and are updated without
/// holding locks during I/O. A poisoned estimate is advisory and recoverable.
#[derive(Clone)]
pub struct PackageTransportTracker {
    timing: Arc<Mutex<WorkerTiming>>,
    slots: Arc<TransferSlots>,
    output_slots: Arc<TransferSlots>,
}

struct TransferSlots {
    limit: NonZeroUsize,
    permits: tokio::sync::Semaphore,
}

impl TransferSlots {
    fn new(limit: NonZeroUsize) -> Self {
        Self {
            limit,
            permits: tokio::sync::Semaphore::new(limit.get()),
        }
    }

    async fn acquire(&self, check: &LeaseCheck<'_>) -> Result<tokio::sync::SemaphorePermit<'_>> {
        let mut acquire = std::pin::pin!(self.permits.acquire());
        loop {
            check()?;
            tokio::select! {
                permit = &mut acquire => return Ok(permit?),
                () = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
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
            slots: Arc::new(TransferSlots::new(limit)),
            output_slots: Arc::new(TransferSlots::new(limit)),
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
    pub(super) async fn raw_slot(
        &self,
        check: &LeaseCheck<'_>,
    ) -> Result<tokio::sync::SemaphorePermit<'_>> {
        self.slots.acquire(check).await
    }

    async fn output_slot(
        &self,
        check: &LeaseCheck<'_>,
    ) -> Result<tokio::sync::SemaphorePermit<'_>> {
        self.output_slots.acquire(check).await
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
    pub artifact_grace: Option<&'a super::ArtifactGrace>,
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

    #[tokio::test]
    async fn slots_bound_parallel_downloads_and_restore_admission_on_drop() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let tracker = PackageTransportTracker::new(WorkerTiming {
            transfer: PackageTransferCost {
                raw_parallelism: 2,
                ..Default::default()
            },
            ..Default::default()
        })?;
        let running = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        futures::future::try_join_all((0..8).map(|_| async {
            let _permit = tracker.raw_slot(&|| Ok(())).await?;
            let count = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(30)).await;
            running.fetch_sub(1, Ordering::SeqCst);
            Ok::<_, anyhow::Error>(())
        }))
        .await?;
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(running.load(Ordering::SeqCst), 0);
        assert!(
            tracker
                .raw_slot(&|| anyhow::bail!("expired session"))
                .await
                .is_err()
        );
        assert_eq!(tracker.slots.permits.available_permits(), 2);
        let initial = tracker.estimate().raw_request_nanoseconds;
        tracker.observe_raw(8192, Duration::from_millis(35));
        assert!(tracker.estimate().raw_request_nanoseconds > initial);
        assert_eq!(tracker.estimate().raw_parallelism, 2);
        Ok(())
    }

    #[tokio::test]
    async fn output_slots_are_shared_across_jobs_but_independent_of_downloads() -> Result<()> {
        let tracker = PackageTransportTracker::new(WorkerTiming {
            transfer: PackageTransferCost {
                raw_parallelism: 2,
                ..Default::default()
            },
            ..Default::default()
        })?;
        let job_a = tracker.clone();
        let job_b = tracker.clone();
        let first = job_a.output_slot(&|| Ok(())).await?;
        let second = job_b.output_slot(&|| Ok(())).await?;
        assert_eq!(tracker.output_slots.permits.available_permits(), 0);
        let incoming = tracker.raw_slot(&|| Ok(())).await?;
        let waiting = tracker.output_slot(&|| Ok(()));
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        drop(first);
        let third = tokio::time::timeout(Duration::from_secs(1), waiting).await??;
        assert_eq!(tracker.output_slots.permits.available_permits(), 0);
        drop((second, third, incoming));
        assert_eq!(tracker.output_slots.permits.available_permits(), 2);
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

impl NativeCacheClient {
    pub(super) async fn reconstruct_packages(
        &self,
        ticket: Ticket,
        missing: &[BlobRef],
        store: &NativeStore,
        limits: PackageImportLimits,
        transport: &PackageTransportTracker,
        check: &LeaseCheck<'_>,
    ) -> Result<Vec<VerifiedPackage>> {
        let plan = self
            .control_with_timeout_async(
                "package_plan",
                &PackagePlanRequest {
                    ticket,
                    missing: missing.to_vec(),
                    max_archive_bytes: limits.max_archive_bytes,
                    cost: transport.estimate(),
                },
                self.timeout,
            )
            .await;
        let offers: Vec<PackageArchive> = match plan {
            Ok(offers) => offers,
            Err(error) => {
                warn!("native original package plan unavailable: {error:#}");
                return Ok(Vec::new());
            }
        };
        let jobs = NonZeroUsize::new(limits.max_concurrent_imports)
            .context("zero package acquisition concurrency")?;
        let packages = ingress::map_bounded(offers, jobs, |offer| async move {
            check()?;
            match self
                .reconstruct_package(ticket, offer, store, limits, transport, check)
                .await
            {
                Ok(package) => Ok(Some(package)),
                Err(error) => {
                    check()?;
                    // Package transport is optional. Verify all remaining
                    // input bytes by retrieving the missing blobs directly.
                    warn!("native package reconstruction unavailable: {error:#}");
                    Ok(None)
                }
            }
        })
        .await?;
        Ok(packages.into_iter().flatten().collect())
    }

    async fn reconstruct_package(
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
        let deadline = start
            .checked_add(self.timeout)
            .context("native worker package reservation deadline overflow")?;
        let cancelled = async {
            loop {
                check()?;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        let prepared = store
            .await_package(
                offer.source.identity,
                ArchiveLength::Exact(offer.source.size),
                limits,
                deadline,
                cancelled,
            )
            .await?;
        check()?;
        let attempted = Instant::now();
        let (package, downloaded) = match prepared {
            PackagePreparation::Cached(package) => (package, None),
            PackagePreparation::Import(upload) => {
                let transfer = Instant::now();
                let (mut response, encoding) = self
                    .try_download_response_async(ticket, offer.blob, self.timeout)
                    .await?
                    .context("native original package unavailable")?;
                ensure!(
                    encoding == crate::build_runtime::BlobEncoding::Raw,
                    "package must be original bytes"
                );
                let (package, finished) = ingress::receive_package(
                    upload,
                    &mut response,
                    None,
                    ArchiveLength::Exact(offer.source.size),
                )
                .await?;
                (package, Some(finished.duration_since(transfer)))
            }
        };
        ensure!(
            package.source() == offer.source && package.tree().id() == offer.tree,
            "reconstructed original package identity mismatch"
        );
        if let Some(download) = downloaded {
            transport.observe_archive(offer, attempted.elapsed(), download);
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
        Ok(package)
    }

    /// Acquire and pin an admitted worker action before it enters the compiler queue.
    /// # Errors
    /// Returns an error if the lease, execution contract or staging fails.
    pub async fn prepare_on_worker<A, F>(
        &self,
        ticket: Ticket,
        spec: &ExecutionSpec,
        store: &NativeStore,
        policy: &ExecutionPolicy,
        delivery: WorkerDelivery<'_>,
        preparation: WorkerPreparation<'_, A>,
    ) -> Result<PreparedWorker>
    where
        A: FnOnce() -> F + Send,
        F: std::future::Future<Output = Result<()>> + Send,
    {
        let started = Instant::now();
        let lease = WorkerLease::start(
            self.clone(),
            ticket,
            spec,
            policy.timeout,
            delivery.renewal_interval,
            preparation.cancelled,
        )
        .await?;
        let result = async {
            lease.check()?;
            (preparation.on_authorized)().await?;
            lease.check()?;
            let request = spec.action_request()?;
            ensure!(
                spec.platform == policy.platform,
                "native executor platform mismatch"
            );
            let check = &|| lease.check();
            let WorkerStorage {
                output,
                cached,
                mut warm,
            } = prepare_worker_storage(
                store,
                policy,
                delivery.artifact_grace,
                &request,
                preparation.estimated_result_bytes,
                check,
            )
            .await?;
            let mut inputs = Vec::new();
            let on_tree = preparation.on_tree;
            for (id, cached) in cached {
                check()?;
                let already_resident = cached.is_some();
                let (tree, hit) = if let Some(tree) = cached {
                    (tree, true)
                } else if delivery.artifact_grace.is_none() {
                    warm = false;
                    // Shared-store acquisition depends on the scheduler's own
                    // producer flights; wait without taking their ownership.
                    (
                        Arc::new(
                            Box::pin(self.fetch_tree(ticket, id, store, delivery, check, on_tree))
                                .await?,
                        ),
                        false,
                    )
                } else {
                    warm = false;
                    let deadline = Instant::now()
                        .checked_add(policy.timeout)
                        .context("input staging deadline overflow")?;
                    let cancelled = async {
                        loop {
                            check()?;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    };
                    Box::pin(store.acquire_tree_async(id, deadline, cancelled, || {
                        self.fetch_tree(ticket, id, store, delivery, check, on_tree)
                    }))
                    .await?
                };
                // Cold acquisition may race assignment/admission on another
                // job. Join the same verified resident lease without blocking
                // the async transport executor on a cold per-tree lookup.
                let tree = if already_resident {
                    tree
                } else {
                    let store = store.clone();
                    tokio::task::spawn_blocking(move || store.remember_resident_tree(tree))
                        .await??
                };
                trace_tree_access(id, &tree, hit)?;
                on_tree(&tree);
                inputs.push(tree);
            }
            warm &= self
                .announce_worker_inputs(ticket, policy.timeout, check)
                .await?;
            Ok(PreparedExecution {
                request,
                inputs,
                output,
                warm_staging: warm.then(|| started.elapsed()),
            })
        }
        .await;
        match result {
            Ok(prepared) => Ok(PreparedWorker {
                lease,
                prepared,
                spec: spec.clone(),
            }),
            Err(error) => {
                lease.fail().await;
                Err(error)
            }
        }
    }

    async fn announce_worker_inputs(
        &self,
        ticket: Ticket,
        timeout: Duration,
        check: &LeaseCheck<'_>,
    ) -> Result<bool> {
        let mut warm = true;
        let announced = Instant::now();
        loop {
            check()?;
            match self
                .control_with_timeout_async::<_, ()>("inputs_staged", &ticket, self.timeout)
                .await
            {
                Ok(()) => return Ok(warm),
                Err(error)
                    if retryable_transport_error(&error) && announced.elapsed() < timeout =>
                {
                    warm = false;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error),
            }
        }
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
            let mut prepared = self.prepare_execution(
                context,
                control.grace.map(|grace| (grace, policy.max_result_bytes)),
                |id, check, _| fetch(id, check),
                check,
                &mut |_| {},
            )?;
            let budget = prepared.take_budget();
            let captured = compile(
                context,
                control.queue,
                control.transport,
                &prepared.inputs,
                budget,
                check,
                || {},
            )?;
            crate::http_client::io_runtime()?.block_on(self.publish_execution(
                context,
                prepared,
                captured,
                control.transport,
                check,
            ))
        });
        if result.is_err() {
            let _ = self.fail(ticket);
        }
        result
    }

    #[cfg(feature = "dist-client")]
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
        maintain_executor_space(store)?;
        let request = spec.action_request()?;
        ensure!(
            spec.platform == policy.platform,
            "native executor platform mismatch"
        );
        // Reserve output headroom before staged inputs can consume it. Wait for
        // grace capacity without occupying a compiler slot.
        let output = if let Some((grace, predicted)) = grace {
            let (reservation, waited) = crate::http_client::io_runtime()?
                .block_on(grace.reserve_until(predicted, policy.timeout, check))?;
            warm &= !waited;
            Some(OutputReservation {
                grace: reservation,
                budget: Some(store.reserve_staging(policy.max_result_bytes)?),
            })
        } else {
            None
        };
        let mut inputs = Vec::new();
        for id in &request.input_trees {
            check()?;
            let (tree, hit) = if let Some(tree) = store.lookup_resident_tree(*id)? {
                (tree, true)
            } else {
                warm = false;
                let (tree, hit) = store.acquire_tree(*id, check, || fetch(*id, check, on_tree))?;
                (store.remember_resident_tree(tree)?, hit)
            };
            trace_tree_access(*id, &tree, hit)?;
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
            inputs,
            output,
            warm_staging: warm.then(|| started.elapsed()),
        })
    }

    async fn upload_result_blobs(
        &self,
        ticket: Ticket,
        captured: &CapturedExecution,
        missing: Vec<BlobRef>,
        scheduler_limit: Option<NonZeroUsize>,
        transport: Option<&PackageTransportTracker>,
        check: &LeaseCheck<'_>,
    ) -> Result<()> {
        let width = transport.map_or(NonZeroUsize::MIN, PackageTransportTracker::parallelism);
        let width = scheduler_limit.map_or(width, |limit| limit.min(width));
        ingress::map_bounded(missing, width, |blob| async move {
            super::upload::retry_busy(self.timeout, || async {
                check()?;
                let slot = if let Some(transport) = transport {
                    Some(transport.output_slot(check).await?)
                } else {
                    None
                };
                let result = self
                    .upload_stored_file_async(
                        ticket,
                        blob,
                        captured.physical_encoding(),
                        captured.open_file(blob.id)?,
                    )
                    .await;
                drop(slot);
                result
            })
            .await
        })
        .await?;
        Ok(())
    }

    async fn publish_execution(
        &self,
        context: ExecutionContext<'_>,
        mut prepared: PreparedExecution,
        measured: MeasuredExecution,
        transport: Option<&PackageTransportTracker>,
        check: &LeaseCheck<'_>,
    ) -> Result<CapturedExecution> {
        let ExecutionContext { ticket, .. } = context;
        let MeasuredExecution { captured, duration } = measured;
        check()?;
        let Some(manifest) = captured.successful_result().cloned() else {
            self.control_with_timeout_async::<_, ()>("fail", &ticket, self.timeout)
                .await?;
            return Ok(captured);
        };
        let publication_started = Instant::now();
        prepared.request.validate_result(&manifest)?;
        let blobs = manifest.blobs()?;
        let (captured, retained) = prepared.retain_output(context, captured, check).await?;
        let (begin, scheduler_limit) = self.begin_result_upload(ticket, manifest.clone()).await?;
        let missing = begin.missing;
        ensure!(
            missing
                .iter()
                .all(|blob| blobs.get(&blob.id) == Some(&blob.size)),
            "scheduler requested undeclared output"
        );
        let publication_setup = retained
            .as_ref()
            .is_none_or(|output| output.warm)
            .then(|| publication_started.elapsed());
        let retained_after_begin = retained.map_or(Duration::ZERO, |output| {
            output.deadline.saturating_duration_since(Instant::now())
        });
        let bytes = missing
            .iter()
            .map(|blob| blob.size)
            .fold(0_u64, u64::saturating_add);
        let requests = u64::try_from(missing.len())?;
        let started = Instant::now();
        self.upload_result_blobs(
            ticket,
            &captured,
            missing,
            scheduler_limit,
            transport,
            check,
        )
        .await?;
        let upload_duration = started.elapsed();
        let worker_timing = transport.map(|transport| {
            transport.observe_result(bytes, requests, upload_duration);
            transport.snapshot()
        });
        let committed: crate::build_runtime::ResultManifest = self
            .control_with_timeout_async(
                "commit",
                &super::CommitRequest {
                    ticket,
                    retained_after_begin_millis: u64::try_from(retained_after_begin.as_millis())
                        .unwrap_or(u64::MAX),
                    observation: Some(ActionObservation {
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
                    }),
                },
                self.timeout,
            )
            .await?;
        ensure!(
            committed == manifest,
            "native publication manifest mismatch"
        );
        Ok(captured)
    }
}

struct WorkerStorage {
    output: Option<OutputReservation>,
    cached: Vec<(TreeId, Option<Arc<TreeLease>>)>,
    warm: bool,
}

/// Pin the already-resident closure in the same blocking task as output-space
/// admission. No network operation holds the blocking pool or an index lock.
async fn prepare_worker_storage(
    store: &NativeStore,
    policy: &ExecutionPolicy,
    grace: Option<&super::ArtifactGrace>,
    request: &ActionRequest,
    estimated_result_bytes: Option<u64>,
    check: &LeaseCheck<'_>,
) -> Result<WorkerStorage> {
    let predicted = estimated_result_bytes
        .unwrap_or(policy.max_result_bytes)
        .clamp(1, policy.max_result_bytes);
    {
        let store = store.clone();
        let grace = grace.cloned();
        tokio::task::spawn_blocking(move || {
            if let Some(grace) = grace {
                grace.reap();
            }
            maintain_executor_space(&store)
        })
        .await??;
    }
    let (reservation, warm) = if let Some(grace) = grace {
        let (reservation, waited) = grace
            .reserve_until(predicted, policy.timeout, check)
            .await?;
        (Some(reservation), !waited)
    } else {
        (None, true)
    };
    check()?;
    let store = store.clone();
    let limit = policy.max_result_bytes;
    let trees = request.input_trees.clone();
    tokio::task::spawn_blocking(move || {
        let output = reservation
            .map(|reservation| {
                Ok::<_, anyhow::Error>(OutputReservation {
                    grace: reservation,
                    budget: Some(store.reserve_staging(limit)?),
                })
            })
            .transpose()?;
        let cached = trees
            .into_iter()
            .map(|id| Ok((id, store.lookup_resident_tree(id)?)))
            .collect::<Result<Vec<_>>>()?;
        Ok(WorkerStorage {
            output,
            cached,
            warm,
        })
    })
    .await?
}

fn maintain_executor_space(store: &NativeStore) -> Result<()> {
    if let Some(report) = store.maintain_space()? {
        ensure!(
            report.minimum_satisfied,
            "native executor store lacks allocatable space: {report:?}"
        );
    }
    Ok(())
}

fn trace_tree_access(id: TreeId, tree: &TreeLease, hit: bool) -> Result<()> {
    if log::log_enabled!(target: "native_cas_replay", log::Level::Trace) {
        let blobs = tree
            .manifest()
            .blobs()?
            .into_iter()
            .map(|(id, size)| BlobRef { id, size })
            .collect::<Vec<_>>();
        log::trace!(target: "native_cas_replay", "{}", serde_json::json!({
            "kind": "tree_access", "tree": id, "hit": hit, "blobs": blobs,
        }));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ExecutionContext<'a> {
    ticket: Ticket,
    spec: &'a ExecutionSpec,
    store: &'a NativeStore,
    policy: &'a ExecutionPolicy,
}

struct OutputReservation {
    grace: super::grace::GraceReservation,
    budget: Option<StageBudget>,
}

struct PreparedExecution {
    warm_staging: Option<Duration>,
    request: ActionRequest,
    inputs: Vec<Arc<TreeLease>>,
    output: Option<OutputReservation>,
}

impl PreparedExecution {
    fn take_budget(&mut self) -> Option<StageBudget> {
        self.output.as_mut().and_then(|output| output.budget.take())
    }

    async fn retain_output(
        &mut self,
        context: ExecutionContext<'_>,
        captured: CapturedExecution,
        check: &LeaseCheck<'_>,
    ) -> Result<(CapturedExecution, Option<super::grace::RetainedOutput>)> {
        let Some(output) = self.output.take() else {
            return Ok((captured, None));
        };
        ensure!(
            output.budget.is_none(),
            "compiler did not consume output reservation"
        );
        output
            .grace
            .retain(
                context.store.clone(),
                self.request.action_fingerprint()?,
                captured,
                (context.policy.timeout, check),
            )
            .await
    }
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
    inputs: &[Arc<TreeLease>],
    budget: Option<StageBudget>,
    check: &LeaseCheck<'_>,
    on_start: impl FnOnce(),
) -> Result<MeasuredExecution> {
    let _permit = queue.map(|queue| queue.acquire(check)).transpose()?;
    on_start();
    let started = Instant::now();
    let captured = execute(
        context.spec,
        context.store,
        context.policy,
        inputs,
        budget,
        check,
    )?;
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
    async fn start(
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
        let result = async {
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
                match lease
                    .client
                    .control_with_timeout_async::<_, ()>(
                        "verify",
                        &super::ExecutionRequest {
                            ticket,
                            spec: spec.clone(),
                        },
                        remaining,
                    )
                    .await
                {
                    Ok(()) => break,
                    Err(error) if retryable_transport_error(&error) => {
                        debug!("retrying native assignment authorization: {error:#}");
                        tokio::time::sleep(delay.min(remaining)).await;
                        delay = (delay * 2).min(Duration::from_millis(200));
                    }
                    Err(error) => return Err(error),
                }
            }
            let renewals = super::renewal::Renewals::start(lease.client.clone(), interval)?;
            renewals.add(ticket)?;
            Ok(renewals)
        }
        .await;
        match result {
            Ok(renewals) => {
                lease.renewals = Some(renewals);
                Ok(lease)
            }
            Err(error) => {
                let _ = lease
                    .client
                    .control_with_timeout_async::<_, ()>("fail", &ticket, lease.client.timeout)
                    .await;
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

    async fn finish(mut self) {
        if let Some(renewals) = self.renewals.take()
            && let Err(error) = renewals.finish_async().await
        {
            debug!("Native worker lease ended after terminal publication: {error:#}");
        }
    }

    async fn fail(mut self) {
        if let Some(renewals) = self.renewals.take() {
            drop(renewals);
            let _ = self
                .client
                .control_with_timeout_async::<_, ()>("fail", &self.ticket, self.client.timeout)
                .await;
        }
    }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        if let Some(renewals) = self.renewals.take() {
            drop(renewals);
            let client = self.client.clone();
            let ticket = self.ticket;
            if let Ok(runtime) = crate::http_client::io_runtime() {
                runtime.spawn(async move {
                    let _ = client
                        .control_with_timeout_async::<_, ()>("fail", &ticket, client.timeout)
                        .await;
                });
            }
        }
    }
}

/// Cancellation and verified-tree progress for worker-side preparation.
pub struct WorkerPreparation<'a, A> {
    pub estimated_result_bytes: Option<u64>,
    pub cancelled: Arc<AtomicBool>,
    pub on_tree: &'a mut (dyn FnMut(&TreeLease) + Send),
    pub on_authorized: A,
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
        mut self,
        store: &NativeStore,
        policy: &ExecutionPolicy,
        delivery: WorkerDelivery<'_>,
        on_start: impl FnOnce(),
    ) -> CompletedWorker {
        let budget = self.prepared.take_budget();
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
            &self.prepared.inputs,
            budget,
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
    pub async fn publish(
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
        let result = match self.captured {
            Ok(captured) => {
                lease
                    .client
                    .publish_execution(context, prepared, captured, Some(transport), &|| {
                        lease.check()
                    })
                    .await
            }
            Err(error) => Err(error),
        };
        match result {
            Ok(captured) => {
                lease.finish().await;
                Ok(captured)
            }
            Err(error) => {
                lease.fail().await;
                Err(error)
            }
        }
    }
}
