//! Worker-side native compilation orchestration. Inputs are fetched into the
//! native store and results move straight from captured descriptors to the
//! scheduler. There is no legacy archive creation or client-side reupload.

use std::time::{Duration, Instant};

use anyhow::{Result, ensure};

use super::{NativeCacheClient, PackagePlanRequest};
use crate::build_runtime::{
    ArchiveLength, BlobRef, CapturedExecution, ExecutionPolicy, ExecutionSpec, NativeServiceBusy,
    NativeStore, PackageArchive, PackageImportLimits, TreeId, TreeLease, VerifiedPackage, execute,
    wire::Ticket,
};

impl NativeCacheClient {
    pub(super) fn reconstruct_packages(
        &self,
        ticket: Ticket,
        missing: &[BlobRef],
        store: &NativeStore,
        limits: PackageImportLimits,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<VerifiedPackage>> {
        let plan = self.control(
            "package_plan",
            &PackagePlanRequest {
                ticket,
                missing: missing.to_vec(),
                max_archive_bytes: limits.max_archive_bytes,
            },
        );
        let offers: Vec<PackageArchive> = match plan {
            Ok(offers) => offers,
            Err(error) => {
                warn!("native original package plan unavailable: {error:#}");
                return Ok(Vec::new());
            }
        };
        let mut packages = Vec::new();
        for offer in offers {
            check()?;
            match self.reconstruct_package(ticket, offer, store, limits, check) {
                Ok(package) => packages.push(package),
                Err(error) => {
                    // This is a transport optimization, not an input
                    // authority. Exact blob retrieval still verifies every
                    // required byte if archive acquisition cannot help.
                    warn!("native package reconstruction unavailable: {error:#}");
                }
            }
        }
        Ok(packages)
    }

    fn reconstruct_package(
        &self,
        ticket: Ticket,
        offer: PackageArchive,
        store: &NativeStore,
        limits: PackageImportLimits,
        check: &mut dyn FnMut() -> Result<()>,
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
    ) -> Result<CapturedExecution> {
        self.execute_admitted(ticket, spec, store, policy, renewal_interval, |id, _| {
            self.fetch_tree(ticket, id, store, renewal_interval, package_import)
        })
    }

    pub(super) fn execute_admitted(
        &self,
        ticket: Ticket,
        spec: &ExecutionSpec,
        store: &NativeStore,
        policy: &ExecutionPolicy,
        renewal_interval: Duration,
        mut fetch: impl FnMut(TreeId, &mut dyn FnMut() -> Result<()>) -> Result<TreeLease>,
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
            let captured = execute(spec, store, policy, &mut *check)?;
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
