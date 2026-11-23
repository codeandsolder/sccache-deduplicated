//! Configured native build executor for a distributed worker.

use std::time::Duration;

use anyhow::{Result, ensure};
use sccache::{
    build_runtime::{
        ContentId, ExecutionPolicy, NativeStore, PackageImportLimits, wire::NativeRunResult,
    },
    config::server::NativeWorkerConfig,
    dist::{
        JobId, NativeAssignment,
        native::{NativeCacheClient, PackageTransportTracker, WorkerDelivery},
    },
};

pub(super) struct NativeWorker {
    store: NativeStore,
    client: NativeCacheClient,
    pub(super) policy: ExecutionPolicy,
    renewal_interval: Duration,
    package_import: Option<PackageImportLimits>,
    package_transfer: PackageTransportTracker,
    artifact_grace: sccache::dist::native::ArtifactGrace,
    pub(super) metadata_limit: usize,
}

impl NativeWorker {
    pub(super) fn new(config: NativeWorkerConfig, auth: String) -> Result<Self> {
        ensure!(
            config.directory.is_absolute()
                && config.scratch.is_absolute()
                && config.bubblewrap.is_absolute(),
            "native worker paths must be absolute"
        );
        ensure!(
            !config.platform_contract.is_empty()
                && config.renewal_interval_secs > 0
                && config.execution_timeout_secs > 0
                && config.max_result_bytes > 0,
            "invalid native worker configuration"
        );
        let package_transfer = PackageTransportTracker::new(config.package_transfer)?;
        let grace_bytes = config.artifact_grace_bytes.unwrap_or_else(|| {
            (config.space.max_resident_bytes / 4)
                .max(config.max_result_bytes)
                .min(config.space.max_resident_bytes)
        });
        ensure!(
            grace_bytes <= config.space.max_resident_bytes,
            "artifact grace budget exceeds total native resident budget"
        );
        let artifact_grace = sccache::dist::native::ArtifactGrace::new(
            Duration::from_secs(config.artifact_grace_secs),
            grace_bytes,
        )?;
        if let Some(limits) = config.package_import {
            limits.validate()?;
            ensure!(
                !limits.retain_original,
                "workers do not retain compressed original archives"
            );
        }
        std::fs::create_dir_all(&config.scratch)?;
        let store = NativeStore::open_managed(&config.directory, config.space)?;
        let client = NativeCacheClient::new(
            config.cache_url.to_url(),
            auth,
            Duration::from_secs(config.request_timeout_secs),
            config.max_metadata_bytes,
        )?;
        Ok(Self {
            store,
            client,
            policy: ExecutionPolicy {
                platform: ContentId::of(config.platform_contract.as_bytes()),
                bubblewrap: config.bubblewrap,
                scratch: config.scratch,
                timeout: Duration::from_secs(config.execution_timeout_secs),
                max_result_bytes: config.max_result_bytes,
            },
            renewal_interval: Duration::from_secs(config.renewal_interval_secs),
            package_import: config.package_import,
            package_transfer,
            artifact_grace,
            metadata_limit: usize::try_from(config.max_metadata_bytes)?,
        })
    }

    pub(super) fn pin_resident_inputs(
        &self,
        spec: &sccache::build_runtime::ExecutionSpec,
    ) -> Result<Vec<sccache::build_runtime::TreeLease>> {
        ensure!(
            self.policy.platform == spec.platform,
            "native worker platform unavailable"
        );
        let mut pins = Vec::new();
        for tree in spec.action_request()?.input_trees {
            if let Some(pin) = self.store.lookup_tree(tree)? {
                pins.push(pin);
            }
        }
        Ok(pins)
    }

    pub(super) fn cached_trees(&self) -> Result<Vec<sccache::build_runtime::TreeId>> {
        self.artifact_grace.reap();
        self.store
            .recent_trees(sccache::dist::WorkerCapabilities::MAX_CACHED_TREES)
    }

    pub(super) fn run(
        &self,
        job: JobId,
        assignment: &NativeAssignment,
        execution_queue: &sccache::dist::execution_queue::ExecutionQueue,
    ) -> Result<NativeRunResult> {
        let captured = self.client.clone().for_worker(job).execute_on_worker(
            assignment.ticket,
            &assignment.spec,
            &self.store,
            &self.policy,
            WorkerDelivery {
                renewal_interval: self.renewal_interval,
                package_import: self.package_import,
                transport: &self.package_transfer,
                execution_queue,
                artifact_grace: &self.artifact_grace,
            },
        )?;
        if captured.successful_result().is_some() {
            return Ok(NativeRunResult::Stored);
        }
        captured.failure_result()
    }
}
