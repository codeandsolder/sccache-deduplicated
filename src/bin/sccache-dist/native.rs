//! Configured native build executor for a distributed worker.

use std::{io::Read, os::unix::process::ExitStatusExt, time::Duration};

use anyhow::{Result, ensure};
use sccache::{
    build_runtime::{
        BlobRef, CapturedExecution, ContentId, ExecutionPolicy, NativeStore, wire::NativeRunResult,
    },
    config::server::NativeWorkerConfig,
    dist::{JobId, NativeAssignment, native::NativeCacheClient},
};

pub(super) struct NativeWorker {
    store: NativeStore,
    client: NativeCacheClient,
    pub(super) policy: ExecutionPolicy,
    renewal_interval: Duration,
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
        std::fs::create_dir_all(&config.scratch)?;
        let store = NativeStore::open(&config.directory)?;
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
            metadata_limit: usize::try_from(config.max_metadata_bytes)?,
        })
    }

    pub(super) fn run(&self, job: JobId, assignment: &NativeAssignment) -> Result<NativeRunResult> {
        let captured = self.client.clone().for_worker(job).execute_on_worker(
            assignment.ticket,
            &assignment.spec,
            &self.store,
            &self.policy,
            self.renewal_interval,
        )?;
        if captured.successful_result().is_some() {
            return Ok(NativeRunResult::Stored);
        }
        let (stdout, stderr) = captured.diagnostics();
        Ok(NativeRunResult::Failed {
            code: captured.status().code(),
            signal: captured.status().signal(),
            stdout: diagnostic(&captured, stdout)?,
            stderr: diagnostic(&captured, stderr)?,
        })
    }
}

fn diagnostic(captured: &CapturedExecution, reference: Option<BlobRef>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if let Some(reference) = reference {
        captured.open_blob(reference.id)?.read_to_end(&mut bytes)?;
        ensure!(
            u64::try_from(bytes.len())? == reference.size,
            "failed diagnostic length mismatch"
        );
    }
    Ok(bytes)
}
