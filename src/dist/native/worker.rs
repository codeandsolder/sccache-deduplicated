//! Worker-side native compilation orchestration. Inputs are fetched into the
//! native store and results move straight from captured descriptors to the
//! scheduler. There is no legacy archive creation or client-side reupload.

use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use super::{LeaseCheck, NativeCacheClient, PackagePlanRequest, map_packages};
use crate::build_runtime::{
    ArchiveLength, BlobRef, CapturedExecution, ExecutionPolicy, ExecutionSpec, NativeServiceBusy,
    NativeStore, PackageArchive, PackageImportLimits, PackageTransferCost, TreeId, TreeLease,
    VerifiedPackage, execute, wire::Ticket,
};

/// Per-worker observed transfer and decoding rates. The initial estimates
/// come from worker configuration and are updated without holding locks during
/// I/O. A poisoned estimate is advisory, so it can be recovered safely.
#[derive(Clone)]
pub struct PackageTransportTracker {
    rates: Arc<Mutex<PackageTransferCost>>,
}

impl PackageTransportTracker {
    /// Construct a rate tracker from administrator-provided initial costs.
    /// # Errors
    /// Returns an error when the initial costs are invalid.
    pub fn new(initial: PackageTransferCost) -> Result<Self> {
        initial.validate()?;
        Ok(Self {
            rates: Arc::new(Mutex::new(initial)),
        })
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
        Self::smooth(&mut rates.download_bytes_per_second, bytes, duration);
    }

    /// Observe original delivery plus verified full-package reconstruction.
    /// Subtract the current predicted download cost before attributing the
    /// remainder to the decoder. Queue-wait time is excluded by the caller.
    pub fn observe_archive(&self, archive: PackageArchive, duration: Duration) {
        let mut rates = self.rates.lock().unwrap_or_else(PoisonError::into_inner);
        let transfer_ns = u128::from(archive.source.size) * 1_000_000_000
            / u128::from(rates.download_bytes_per_second);
        let overhead_ns = u128::from(rates.startup_nanoseconds)
            + u128::from(rates.per_entry_nanoseconds) * u128::from(archive.entry_count);
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

#[cfg(test)]
mod transport_tests {
    use super::*;
    use crate::build_runtime::{
        BlobRef, ContentId, PackageCompression, PackageIdentity, PackageSource, TreeId,
    };

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
        renewal_interval: Duration,
        package_import: Option<PackageImportLimits>,
        transport: &PackageTransportTracker,
    ) -> Result<CapturedExecution> {
        self.execute_admitted(ticket, spec, store, policy, renewal_interval, |id, _| {
            self.fetch_tree(
                ticket,
                id,
                store,
                renewal_interval,
                package_import,
                transport,
            )
        })
    }

    pub(super) fn execute_admitted(
        &self,
        ticket: Ticket,
        spec: &ExecutionSpec,
        store: &NativeStore,
        policy: &ExecutionPolicy,
        renewal_interval: Duration,
        mut fetch: impl FnMut(TreeId, &LeaseCheck<'_>) -> Result<TreeLease>,
    ) -> Result<CapturedExecution> {
        let result = self.with_renewal(ticket, renewal_interval, |check| {
            self.verify_execution(ticket, spec.clone())?;
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
            let mut inputs = Vec::new();
            for id in &request.input_trees {
                check()?;
                let tree = match store.lookup_tree(*id)? {
                    Some(tree) => tree,
                    None => fetch(*id, check)?,
                };
                inputs.push(tree);
            }
            let captured = execute(spec, store, policy, check)?;
            check()?;
            if let Some(manifest) = captured.successful_result() {
                request.validate_result(manifest)?;
                let blobs = manifest.blobs()?;
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
