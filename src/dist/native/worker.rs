//! Worker-side native compilation orchestration. Inputs are fetched into the
//! native store and results move straight from captured descriptors to the
//! scheduler. There is no legacy archive creation or client-side reupload.

use std::time::Duration;

use anyhow::{Result, ensure};

use super::NativeCacheClient;
use crate::build_runtime::{
    CapturedExecution, ExecutionPolicy, ExecutionSpec, NativeStore, execute, wire::Ticket,
};

impl NativeCacheClient {
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
    ) -> Result<CapturedExecution> {
        let result = self.with_renewal(ticket, renewal_interval, |check| {
            self.verify_execution(ticket, spec.clone())?;
            if let Some(report) = store.maintain_space()? {
                ensure!(
                    report.minimum_satisfied,
                    "native worker store lacks allocatable space: {report:?}"
                );
            }
            let request = spec.action_request()?;
            ensure!(
                spec.platform == policy.platform,
                "worker execution platform mismatch"
            );
            let mut inputs = Vec::new();
            for id in &request.input_trees {
                check()?;
                let tree = match store.lookup_tree(*id)? {
                    Some(tree) => tree,
                    None => self.fetch_tree(ticket, *id, store, renewal_interval)?,
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
