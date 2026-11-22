//! Owner-local execution shares the exact native sandbox and scheduler
//! publication path with remote workers.
use std::{
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, ensure};

use super::{LeaseCheck, NativeBuildPolicy, NativeCacheClient, client::InputProvider};
use crate::{
    build_runtime::{
        CapturedExecution, ContentId, ExecutionPolicy, ExecutionSpec, NativeStore, TreeId,
        TreeLease, wire::Ticket,
    },
    config::{NativeExecutionPreference, NativeLocalConfig},
};

/// One daemon-owned local executor with a bounded job pool and private input CAS.
pub struct LocalExecutor {
    config: NativeLocalConfig,
    platform: ContentId,
    store: Mutex<Option<Arc<NativeStore>>>,
    active: Mutex<usize>,
    available: Condvar,
}

impl LocalExecutor {
    #[must_use = "the executor owns local input storage and admission"]
    pub const fn new(config: NativeLocalConfig, platform: ContentId) -> Self {
        Self {
            config,
            platform,
            store: Mutex::new(None),
            active: Mutex::new(0),
            available: Condvar::new(),
        }
    }

    #[must_use = "the preference controls action placement"]
    pub const fn prefers_local(&self) -> bool {
        matches!(self.config.preference, NativeExecutionPreference::Local)
    }

    fn store(&self) -> Result<Arc<NativeStore>> {
        let mut guard = self
            .store
            .lock()
            .map_err(|_| anyhow!("native local store lock poisoned"))?;
        if let Some(store) = guard.as_ref() {
            return Ok(Arc::clone(store));
        }
        self.config.validate()?;
        std::fs::create_dir_all(&self.config.scratch)?;
        let store = Arc::new(NativeStore::open_managed(
            &self.config.directory,
            self.config.space,
        )?);
        *guard = Some(Arc::clone(&store));
        drop(guard);
        Ok(store)
    }

    fn slot(&self, start: Instant, timeout: Duration, check: &LeaseCheck<'_>) -> Result<Slot<'_>> {
        self.config.validate()?;
        let mut active = self
            .active
            .lock()
            .map_err(|_| anyhow!("native local job lock poisoned"))?;
        loop {
            let remaining = timeout.saturating_sub(start.elapsed());
            ensure!(
                !remaining.is_zero(),
                "native local admission deadline exceeded"
            );
            check()?;
            if *active < self.config.max_jobs {
                *active += 1;
                drop(active);
                return Ok(Slot(self));
            }
            let (guard, _) = self
                .available
                .wait_timeout(active, remaining.min(Duration::from_millis(100)))
                .map_err(|_| anyhow!("native local job lock poisoned"))?;
            active = guard;
        }
    }

    /// Stage only missing input bytes from the original caller, not from a
    /// round-trip download through the scheduler. The lease protects them
    /// during input negotiation and the subsequent build.
    pub(super) fn prepare_input(
        &self,
        id: TreeId,
        inputs: &mut impl InputProvider,
        check: &LeaseCheck<'_>,
    ) -> Result<TreeLease> {
        let store = self.store()?;
        if let Some(tree) = store.lookup_tree(id)? {
            return Ok(tree);
        }
        let manifest = inputs.manifest(id)?;
        ensure!(
            manifest.id()? == id,
            "local input provider supplied wrong tree"
        );
        let reservation = store.reserve_tree_upload(&manifest)?;
        debug!(
            "native local input {id:?}: staging {} missing blobs, {} bytes directly from caller",
            reservation.missing().len(),
            reservation
                .missing()
                .iter()
                .map(|blob| u128::from(blob.size))
                .sum::<u128>()
        );
        let mut staged = Vec::new();
        for &blob in reservation.missing() {
            check()?;
            staged.push(store.stage_expected(blob, inputs.open_blob(id, blob)?)?);
        }
        store.publish_tree_pinned(&manifest, staged)
    }

    pub(super) fn execute(
        &self,
        client: &NativeCacheClient,
        ticket: Ticket,
        spec: &ExecutionSpec,
        inputs: &mut impl InputProvider,
        policy: &NativeBuildPolicy,
        start: Instant,
    ) -> Result<CapturedExecution> {
        let _slot = client.with_renewal(ticket, policy.renewal_interval, |check| {
            self.slot(start, policy.timeout, check)
        })?;
        let store = self.store()?;
        let timeout = policy.timeout.saturating_sub(start.elapsed());
        ensure!(
            !timeout.is_zero(),
            "native local execution deadline exceeded"
        );
        client.execute_admitted(
            ticket,
            spec,
            &store,
            &ExecutionPolicy {
                platform: self.platform,
                bubblewrap: self.config.bubblewrap.clone(),
                scratch: self.config.scratch.clone(),
                timeout,
                max_result_bytes: policy.max_result_bytes,
            },
            policy.renewal_interval,
            |id, check| self.prepare_input(id, inputs, check),
        )
    }
}

struct Slot<'a>(&'a LocalExecutor);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        match self.0.active.lock() {
            Ok(mut active) => {
                *active -= 1;
                drop(active);
                self.0.available.notify_one();
            }
            Err(error) => error!("native local job lock poisoned: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_runtime::SpacePolicy;

    #[test]
    fn local_slots_bound_parallel_execution_and_respond_to_cancellation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let executor = LocalExecutor::new(
            NativeLocalConfig {
                preference: NativeExecutionPreference::Local,
                max_jobs: 1,
                directory: directory.path().join("input"),
                scratch: directory.path().join("scratch"),
                bubblewrap: "/usr/bin/bwrap".into(),
                space: SpacePolicy {
                    min_available_bytes: 1,
                    target_available_bytes: 1,
                    max_evictions_per_pass: 1,
                    gc_batch: 1,
                },
            },
            ContentId::of(b"platform"),
        );
        let first = executor.slot(Instant::now(), Duration::from_secs(1), &|| Ok(()))?;
        assert!(
            executor
                .slot(Instant::now(), Duration::from_millis(5), &|| Ok(()))
                .is_err()
        );
        assert!(
            executor
                .slot(Instant::now(), Duration::from_secs(1), &|| anyhow::bail!(
                    "cancelled"
                ))
                .is_err()
        );
        drop(first);
        let next = executor.slot(Instant::now(), Duration::from_secs(1), &|| Ok(()))?;
        drop(next);
        Ok(())
    }
}
