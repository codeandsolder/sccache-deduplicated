//! Configured native build executor for a distributed worker.

use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, ensure};
use sccache::{
    build_runtime::{
        BlobResidency, CapturedExecution, ContentId, ExecutionPolicy, NativeStore,
        PackageImportLimits, PackageTransferCost, wire::WorkerTiming,
    },
    config::server::NativeWorkerConfig,
    dist::{
        JobId, NativeAssignment, NativePlacement,
        native::{
            CompletedWorker, NativeCacheClient, PackageTransportTracker, PreparedWorker,
            WorkerDelivery, WorkerPreparation,
        },
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
    placement: Mutex<PlacementCache>,
    pub(super) metadata_limit: usize,
    pub(super) max_inflight_jobs: Option<usize>,
}

impl NativeWorker {
    pub(super) fn new(
        config: NativeWorkerConfig,
        peer: std::sync::Arc<sccache_cluster_identity::PeerCredentials>,
    ) -> Result<Self> {
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

        let grace_bytes = config.artifact_grace_bytes.unwrap_or_else(|| {
            (config.space.max_resident_bytes / 4)
                .max(config.max_result_bytes.saturating_mul(2))
                .min(config.space.max_resident_bytes)
        });
        ensure!(
            (config.max_result_bytes..=config.space.max_resident_bytes).contains(&grace_bytes),
            "artifact grace budget must fit one maximum result and the resident budget"
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
        let scope = ContentId::of(
            format!(
                "{}\n{}",
                config.cache_url.to_url(),
                config.platform_contract
            )
            .as_bytes(),
        );
        let (placement, timing) = PlacementCache::open(
            config.directory.join("worker-timing.json"),
            scope,
            config.package_transfer,
        );
        let package_transfer = PackageTransportTracker::new(timing)?;
        let _ = store.can_clone_into(&config.scratch)?;
        let client = NativeCacheClient::new(
            &config.cache_url.to_url(),
            peer,
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
            placement: Mutex::new(placement),
            metadata_limit: usize::try_from(config.max_metadata_bytes)?,
            max_inflight_jobs: config.max_inflight_jobs.map(std::num::NonZeroUsize::get),
        })
    }

    pub(super) fn pin_resident_inputs(
        &self,
        assignment: &NativeAssignment,
    ) -> Result<super::NativeInputPins> {
        ensure!(
            self.policy.platform == assignment.spec.platform,
            "native worker platform unavailable"
        );
        let blobs = self.store.reserve_blobs(assignment.input_blobs.clone())?;
        let mut trees = Vec::new();
        for tree in assignment.spec.action_request()?.input_trees {
            if let Some(pin) = self.store.lookup_tree(tree)? {
                trees.push(pin);
            }
        }
        Ok(super::NativeInputPins {
            _trees: trees,
            _blobs: blobs,
        })
    }

    pub(super) fn open_blob(
        &self,
        blob: sccache::build_runtime::BlobRef,
    ) -> Result<Option<(std::fs::File, sccache::build_runtime::BlobEncoding)>> {
        self.store.open_available_physical(blob)
    }

    pub(super) fn placement(&self, queue: sccache::dist::NativeQueueSnapshot) -> NativePlacement {
        self.artifact_grace.reap();
        let timing = self.package_transfer.snapshot();
        let mut cache = self
            .placement
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut placement = cache.refresh(&self.store, timing, queue);
        drop(cache);
        placement.cache_path_rates = self.client.path_rates();
        placement.peer_download_rates = self.client.peer_download_rates();
        placement.interfaces = self.client.interface_report();
        placement.package_limits =
            self.package_import
                .map(|limits| sccache::build_runtime::PackageDeliveryLimits {
                    max_archive_bytes: limits.max_archive_bytes,
                    max_expanded_bytes: limits.max_expanded_bytes,
                    max_entries: u64::try_from(limits.max_entries).unwrap_or(u64::MAX),
                    parallelism: u32::try_from(limits.max_concurrent_imports.min(32)).unwrap_or(32),
                });
        placement
    }

    pub(super) fn transfer_parallelism(&self) -> usize {
        self.package_transfer.parallelism().get()
    }

    fn delivery<'a>(
        &'a self,
        queue: &'a sccache::dist::execution_queue::ExecutionQueue,
    ) -> WorkerDelivery<'a> {
        WorkerDelivery {
            renewal_interval: self.renewal_interval,
            package_import: self.package_import,
            transport: &self.package_transfer,
            execution_queue: queue,
            artifact_grace: &self.artifact_grace,
        }
    }

    pub(super) fn prepare(
        &self,
        job: JobId,
        assignment: &NativeAssignment,
        queue: &sccache::dist::execution_queue::ExecutionQueue,
        preparation: WorkerPreparation<'_>,
    ) -> Result<PreparedWorker> {
        self.client.clone().for_worker(job).prepare_on_worker(
            assignment.ticket,
            &assignment.spec,
            &self.store,
            &self.policy,
            self.delivery(queue),
            preparation,
        )
    }

    pub(super) fn execute(
        &self,
        prepared: PreparedWorker,
        queue: &sccache::dist::execution_queue::ExecutionQueue,
        on_start: impl FnOnce(),
    ) -> CompletedWorker {
        prepared.execute(&self.store, &self.policy, self.delivery(queue), on_start)
    }

    pub(super) fn publish(&self, completed: CompletedWorker) -> Result<CapturedExecution> {
        completed.publish(&self.store, &self.policy, &self.package_transfer)
    }
}

#[derive(Serialize, Deserialize)]
struct SavedTiming {
    scope: ContentId,
    observed_at: u64,
    timing: WorkerTiming,
}

struct PlacementCache {
    path: PathBuf,
    scope: ContentId,
    last_saved: WorkerTiming,
    checkpoint: Instant,
    inventory: Option<(Instant, Option<BlobResidency>)>,
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl PlacementCache {
    fn open(
        path: PathBuf,
        scope: ContentId,
        configured: PackageTransferCost,
    ) -> (Self, WorkerTiming) {
        let mut timing = WorkerTiming {
            transfer: configured,
            ..Default::default()
        };
        match std::fs::File::open(&path) {
            Ok(file) => match serde_json::from_reader::<_, SavedTiming>(file) {
                Ok(saved)
                    if saved.scope == scope
                        && unix_seconds()
                            .checked_sub(saved.observed_at)
                            .is_some_and(|age| age <= 24 * 60 * 60)
                        && saved.timing.valid() =>
                {
                    timing = saved.timing;
                    timing.revision = 0;
                    // Concurrency is configuration, not a learned rate.
                    timing.transfer.raw_parallelism = configured.raw_parallelism;
                }
                Ok(_) => {}
                Err(error) => warn!("Ignoring invalid native worker timing checkpoint: {error:#}"),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => warn!("Could not read native worker timing checkpoint: {error:#}"),
        }
        (
            Self {
                path,
                scope,
                last_saved: timing,
                checkpoint: Instant::now(),
                inventory: None,
            },
            timing,
        )
    }

    fn refresh(
        &mut self,
        store: &NativeStore,
        timing: WorkerTiming,
        queue: sccache::dist::NativeQueueSnapshot,
    ) -> NativePlacement {
        let now = Instant::now();
        if self
            .inventory
            .as_ref()
            .is_none_or(|(created, _)| now.duration_since(*created) >= Duration::from_secs(15))
        {
            let residency = store.blob_residency().unwrap_or_else(|error| {
                warn!("Native worker residency snapshot unavailable: {error:#}");
                None
            });
            self.inventory = Some((now, residency));
        }
        if now.duration_since(self.checkpoint) >= Duration::from_secs(60) {
            self.checkpoint = now;
            if self.last_saved != timing {
                match self.save(timing) {
                    Ok(()) => self.last_saved = timing,
                    Err(error) => warn!("Native worker timing checkpoint failed: {error:#}"),
                }
            }
        }
        NativePlacement {
            package_limits: None,
            residency: self
                .inventory
                .as_ref()
                .and_then(|(_, summary)| summary.clone()),
            timing,
            cache_path_rates: Default::default(),
            peer_download_rates: Vec::new(),
            interfaces: Default::default(),
            queue,
        }
    }

    fn save(&self, timing: WorkerTiming) -> Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer(
            &mut temporary,
            &SavedTiming {
                scope: self.scope,
                observed_at: unix_seconds(),
                timing,
            },
        )?;
        temporary.as_file().sync_all()?;
        temporary.persist(&self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_checkpoint_is_scoped_to_route_and_expires() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("timing.json");
        let scope = ContentId::of(b"worker route");
        let configured = PackageTransferCost::default();
        let (cache, mut timing) = PlacementCache::open(path.clone(), scope, configured);
        timing.transfer.download_bytes_per_second = 3_000_000;
        timing.execution_nanoseconds = 20_000_000;
        cache.save(timing)?;
        let (_, restored) = PlacementCache::open(path.clone(), scope, configured);
        assert_eq!(restored, timing);
        let (_, other) =
            PlacementCache::open(path.clone(), ContentId::of(b"other route"), configured);
        assert_eq!(other.transfer, configured);
        let mut file = std::fs::File::create(&path)?;
        serde_json::to_writer(
            &mut file,
            &SavedTiming {
                scope,
                observed_at: unix_seconds().saturating_sub(86_401),
                timing,
            },
        )?;
        let (_, stale) = PlacementCache::open(path, scope, configured);
        assert_eq!(stale.transfer, configured);
        Ok(())
    }
}
