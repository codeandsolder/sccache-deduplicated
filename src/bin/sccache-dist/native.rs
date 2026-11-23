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
            metadata_limit: usize::try_from(config.max_metadata_bytes)?,
        })
    }

    pub(super) fn run(&self, job: JobId, assignment: &NativeAssignment) -> Result<NativeRunResult> {
        let captured = self.client.clone().for_worker(job).execute_on_worker(
            assignment.ticket,
            &assignment.spec,
            &self.store,
            &self.policy,
            WorkerDelivery {
                renewal_interval: self.renewal_interval,
                package_import: self.package_import,
                transport: &self.package_transfer,
            },
        )?;
        if captured.successful_result().is_some() {
            return Ok(NativeRunResult::Stored);
        }
        captured.failure_result()
    }
}
