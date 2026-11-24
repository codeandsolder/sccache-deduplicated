//! Worker-side native compilation orchestration. Inputs are fetched into the
//! native store and results move straight from captured descriptors to the
//! scheduler. There is no legacy archive creation or client-side reupload.

use std::{
    num::NonZeroUsize,
    sync::{Arc, Condvar, Mutex, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use super::{LeaseCheck, NativeCacheClient, PackagePlanRequest, map_packages};
use crate::build_runtime::{
    ArchiveLength, BlobRef, CapturedExecution, ExecutionPolicy, ExecutionSpec, NativeServiceBusy,
    NativeStore, PackageArchive, PackageImportLimits, PackageTransferCost, TreeId, TreeLease,
    VerifiedPackage, execute, wire::Ticket,
};

/// Per-worker observed transfer and decoding rates.
///
/// Initial estimates come from worker configuration and are updated without
/// holding locks during I/O. A poisoned estimate is advisory and recoverable.
#[derive(Clone)]
pub struct PackageTransportTracker {
    rates: Arc<Mutex<PackageTransferCost>>,
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
    pub fn new(initial: PackageTransferCost) -> Result<Self> {
        initial.validate()?;
        let limit = NonZeroUsize::new(usize::try_from(initial.raw_parallelism)?)
            .context("zero raw download parallelism")?;
        Ok(Self {
            rates: Arc::new(Mutex::new(initial)),
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
        *self.rates.lock().unwrap_or_else(PoisonError::into_inner)
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
        let mut rates = self.rates.lock().unwrap_or_else(PoisonError::into_inner);
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
    }

    /// Observe original delivery plus verified full-package reconstruction.
    /// Subtract the current predicted download cost before attributing the
    /// remainder to the decoder. Queue-wait time is excluded by the caller.
    pub fn observe_archive(&self, archive: PackageArchive, duration: Duration) {
        let mut rates = self.rates.lock().unwrap_or_else(PoisonError::into_inner);
        let transfer_ns = u128::from(archive.source.size) * 1_000_000_000
            / u128::from(rates.download_bytes_per_second);
        let entry_cost = u128::from(rates.per_entry_nanoseconds) * u128::from(archive.entry_count);
        let overhead_ns = u128::from(rates.startup_nanoseconds)
            + u128::from(rates.raw_request_nanoseconds)
            + entry_cost;
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

pub(super) struct ExecutionControl<'a> {
    pub renewal_interval: Duration,
    pub queue: Option<&'a crate::dist::execution_queue::ExecutionQueue>,
    pub grace: Option<&'a super::ArtifactGrace>,
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
        let tracker = PackageTransportTracker::new(PackageTransferCost {
            raw_parallelism: 2,
            ..PackageTransferCost::default()
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
    fn observed_rates_change_future_costs_without_overreacting_to_tiny_files() -> Result<()> {
        let tracker = PackageTransportTracker::new(PackageTransferCost::default())?;
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
        tracker.observe_archive(archive, Duration::from_secs(6));
        assert!(
            tracker.estimate().decode_zstd_bytes_per_second < observed.decode_zstd_bytes_per_second
        );
        assert_eq!(
            tracker.estimate().decode_xz_bytes_per_second,
            observed.decode_xz_bytes_per_second
        );
        Ok(())
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
            let (package, reused) = match store.acquire_package(
                offer.source.identity,
                ArchiveLength::Exact(offer.source.size),
                limits,
                &executable,
                || self.download_response(ticket, offer.blob.id),
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
                transport.observe_archive(offer, attempted.elapsed());
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

    /// Execute an admitted native build and publish successful outputs directly.
    ///
    /// The independent renewal loop keeps the scheduler reservation live
    /// during slow content transfers as well as compilation. Failures abort
    /// the session; the returned failed execution still owns its diagnostics.
    ///
    /// # Errors
    /// Returns an error for mismatched admission, transfer failure, lost
    /// reservation, invalid output or failed publication.
    pub fn execute_on_worker(
        &self,
        ticket: Ticket,
        spec: &ExecutionSpec,
        store: &NativeStore,
        policy: &ExecutionPolicy,
        delivery: WorkerDelivery<'_>,
    ) -> Result<CapturedExecution> {
        self.execute_admitted(
            ticket,
            spec,
            store,
            policy,
            ExecutionControl {
                renewal_interval: delivery.renewal_interval,
                queue: Some(delivery.execution_queue),
                grace: Some(delivery.artifact_grace),
            },
            |id, check| self.fetch_tree(ticket, id, store, delivery, check),
        )
    }

    pub(super) fn execute_admitted(
        &self,
        ticket: Ticket,
        spec: &ExecutionSpec,
        store: &NativeStore,
        policy: &ExecutionPolicy,
        control: ExecutionControl<'_>,
        mut fetch: impl FnMut(TreeId, &LeaseCheck<'_>) -> Result<TreeLease>,
    ) -> Result<CapturedExecution> {
        let result = self.with_renewal(ticket, control.renewal_interval, |check| {
            self.verify_execution(ticket, spec.clone())?;
            if let Some(grace) = control.grace {
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
            let mut output = if let Some(grace) = control.grace {
                let started = Instant::now();
                let reservation = loop {
                    check()?;
                    if let Some(reservation) = grace.reserve(policy.max_result_bytes)? {
                        break reservation;
                    }
                    ensure!(
                        started.elapsed() < policy.timeout,
                        "native artifact grace admission timed out"
                    );
                    std::thread::sleep(Duration::from_millis(100));
                };
                Some((reservation, store.reserve_staging(policy.max_result_bytes)?))
            } else {
                None
            };
            let mut inputs = Vec::new();
            for id in &request.input_trees {
                check()?;
                let (tree, hit) = store.acquire_tree(*id, check, || fetch(*id, check))?;
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
                inputs.push(tree);
            }
            // Keep input leases through the ready queue wait. Only execution consumes compiler capacity.
            let captured = {
                let _permit = control
                    .queue
                    .map(|queue| queue.acquire(check))
                    .transpose()?;
                execute(spec, store, policy, check)?
            };
            check()?;
            if let Some(manifest) = captured.successful_result() {
                request.validate_result(manifest)?;
                let blobs = manifest.blobs()?;
                if let Some((grace, mut budget)) = output.take() {
                    grace.retain(
                        store,
                        &mut budget,
                        &request.action_fingerprint()?,
                        manifest,
                        &captured,
                    )?;
                }
                for missing in self.begin(ticket, manifest.clone())?.missing {
                    check()?;
                    ensure!(
                        blobs.get(&missing.id) == Some(&missing.size),
                        "scheduler requested undeclared output"
                    );
                    self.upload(ticket, missing, captured.open_blob(missing.id)?)?;
                }
                ensure!(
                    self.commit(ticket)? == *manifest,
                    "native publication manifest mismatch"
                );
            } else {
                self.fail(ticket)?;
            }
            drop(inputs);
            Ok(captured)
        });
        if result.is_err() {
            let _ = self.fail(ticket);
        }
        result
    }
}
