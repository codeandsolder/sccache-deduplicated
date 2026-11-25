//! Bounded, atomic checkpoints of advisory action histories. Monotonic ages
//! are stored relative to a wall-clock checkpoint, never as Instant values.

use super::{
    ActionClass, ActionCost, ActionCosts, CostBook, MAX_AGE, MAX_CLASSES, Sample, WorkerScope,
    history::MAX_WORKERS,
    overhead::{OverheadHistory, TimedMean},
};
use anyhow::{Result, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const VERSION: u32 = 6;
const LIMIT: u64 = 16 << 20;
const INTERVAL: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize)]
struct SavedSample {
    class: ActionClass,
    cost: ActionCost,
    result_peak_bytes: u64,
    age_millis: u64,
    observations: u64,
}

#[derive(Serialize, Deserialize)]
struct SavedMean {
    value: u64,
    age_millis: u64,
}

impl SavedMean {
    fn capture(sample: Option<TimedMean>, now: Instant) -> Option<Self> {
        let sample = sample?;
        let age = now.saturating_duration_since(sample.seen);
        (age < MAX_AGE).then(|| Self {
            value: sample.value,
            age_millis: u64::try_from(age.as_millis()).unwrap_or(u64::MAX),
        })
    }

    fn restore(self, now: Instant, elapsed: u64) -> Option<TimedMean> {
        let age = Duration::from_millis(elapsed.saturating_add(self.age_millis));
        if age >= MAX_AGE || self.value > 60_000_000_000 {
            return None;
        }
        Some(TimedMean {
            value: self.value,
            seen: now.checked_sub(age)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct SavedWorker {
    scope: WorkerScope,
    staging: Option<SavedMean>,
    publication: Option<SavedMean>,
    samples: Vec<SavedSample>,
}

#[derive(Serialize, Deserialize)]
struct SavedDelivery {
    key: super::receiver::Key,
    selected: u64,
    remote: u64,
    count: u64,
    age_millis: u64,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u32,
    listener: SocketAddr,
    saved_at_millis: u64,
    workers: Vec<SavedWorker>,
    deliveries: Vec<SavedDelivery>,
}

fn unix_millis() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(LIMIT)
        .reject_trailing_bytes()
}

impl Snapshot {
    fn capture(book: &CostBook, listener: SocketAddr, now: Instant, wall: u64) -> Self {
        let workers = book
            .workers
            .iter()
            .filter_map(|(&scope, costs)| {
                let samples: Vec<_> = costs
                    .entries
                    .iter()
                    .filter_map(|(&class, sample)| {
                        let age = now.saturating_duration_since(sample.seen);
                        (age < MAX_AGE).then(|| SavedSample {
                            class,
                            cost: sample.cost,
                            result_peak_bytes: sample.result_peak_bytes,
                            age_millis: u64::try_from(age.as_millis()).unwrap_or(u64::MAX),
                            observations: sample.observations,
                        })
                    })
                    .collect();
                (!samples.is_empty()).then_some(SavedWorker {
                    scope,
                    samples,
                    staging: SavedMean::capture(costs.overhead.staging, now),
                    publication: SavedMean::capture(costs.overhead.publication, now),
                })
            })
            .collect();
        Self {
            version: VERSION,
            listener,
            saved_at_millis: wall,
            workers,
            deliveries: book
                .receivers
                .samples
                .iter()
                .filter_map(|(&key, sample)| {
                    let age = now.saturating_duration_since(sample.seen);
                    (age < super::receiver::TTL).then(|| SavedDelivery {
                        key,
                        selected: sample.selected,
                        remote: sample.remote,
                        count: sample.count,
                        age_millis: u64::try_from(age.as_millis()).unwrap_or(u64::MAX),
                    })
                })
                .collect(),
        }
    }

    fn restore(self, listener: SocketAddr, now: Instant, wall: u64) -> Result<CostBook> {
        ensure!(
            self.version == VERSION,
            "unsupported action cost checkpoint version"
        );
        ensure!(
            self.listener == listener,
            "action cost checkpoint belongs to another listener"
        );
        let Some(elapsed) = wall.checked_sub(self.saved_at_millis) else {
            return Ok(CostBook::default());
        };
        ensure!(
            self.workers.len() <= MAX_WORKERS,
            "too many worker histories"
        );
        let mut book = CostBook::default();
        for worker in self.workers {
            ensure!(
                worker.samples.len() <= MAX_CLASSES,
                "too many action classes"
            );
            let mut entries = BTreeMap::new();
            for sample in worker.samples {
                let age = Duration::from_millis(elapsed.saturating_add(sample.age_millis));
                if age >= MAX_AGE
                    || sample.observations == 0
                    || !sample.cost.valid()
                    || sample.result_peak_bytes > 1 << 40
                    || sample.cost.result_bytes > sample.result_peak_bytes
                {
                    continue;
                }
                if let Some(seen) = now.checked_sub(age) {
                    ensure!(
                        entries
                            .insert(
                                sample.class,
                                Sample {
                                    cost: sample.cost,
                                    result_peak_bytes: sample.result_peak_bytes,
                                    seen,
                                    observations: sample.observations,
                                }
                            )
                            .is_none(),
                        "duplicate action class in checkpoint"
                    );
                }
            }
            if !entries.is_empty() {
                ensure!(
                    book.workers
                        .insert(
                            worker.scope,
                            ActionCosts {
                                entries,
                                overhead: OverheadHistory {
                                    staging: worker
                                        .staging
                                        .and_then(|sample| sample.restore(now, elapsed)),
                                    publication: worker
                                        .publication
                                        .and_then(|sample| sample.restore(now, elapsed))
                                }
                            }
                        )
                        .is_none(),
                    "duplicate worker history"
                );
            }
        }
        ensure!(
            self.deliveries.len() <= super::receiver::LIMIT,
            "too many receiver histories"
        );
        for saved in self.deliveries {
            let age = Duration::from_millis(elapsed.saturating_add(saved.age_millis));
            if age >= super::receiver::TTL {
                continue;
            }
            let Some(seen) = now.checked_sub(age) else {
                continue;
            };
            let sample = super::receiver::Sample {
                selected: saved.selected,
                remote: saved.remote,
                count: saved.count,
                seen,
            };
            if sample.valid() {
                ensure!(
                    book.receivers.samples.insert(saved.key, sample).is_none(),
                    "duplicate receiver history in checkpoint"
                );
            }
        }
        Ok(book)
    }
}

fn load(path: &Path, listener: SocketAddr, now: Instant, wall: u64) -> Result<CostBook> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CostBook::default());
        }
        Err(error) => return Err(error.into()),
    };
    ensure!(
        file.metadata()?.len() <= LIMIT,
        "action cost checkpoint exceeds limit"
    );
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= LIMIT,
        "action cost checkpoint exceeds limit"
    );
    let snapshot: Snapshot = codec().deserialize(&bytes)?;
    snapshot.restore(listener, now, wall)
}

fn save(path: &Path, snapshot: &Snapshot) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    codec().serialize_into(&mut file, snapshot)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}

pub(crate) fn start(
    book: &Arc<Mutex<CostBook>>,
    path: PathBuf,
    listener: SocketAddr,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match load(&path, listener, Instant::now(), unix_millis()?) {
        Ok(restored) => {
            *book
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = restored;
        }
        Err(error) => warn!("Ignoring native action cost checkpoint: {error:#}"),
    }
    let book = Arc::downgrade(book);
    thread::Builder::new()
        .name("native-action-cost-checkpoint".into())
        .spawn(move || {
            let mut saved_revision = 0;
            loop {
                thread::sleep(INTERVAL);
                let Some(book) = book.upgrade() else {
                    break;
                };
                let Ok(wall) = unix_millis() else {
                    continue;
                };
                let snapshot = {
                    let book = book
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if book.revision == saved_revision {
                        None
                    } else {
                        Some((
                            book.revision,
                            Snapshot::capture(&book, listener, Instant::now(), wall),
                        ))
                    }
                };
                if let Some((revision, snapshot)) = snapshot {
                    match save(&path, &snapshot) {
                        Ok(()) => saved_revision = revision,
                        Err(error) => warn!("Native action cost checkpoint failed: {error:#}"),
                    }
                }
            }
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccache::{
        build_runtime::{ContentId, wire::ActionObservation},
        dist::NativePlacement,
    };

    #[test]
    fn native_action_cost_checkpoint_restores_fresh_history_and_rejects_wrong_route() -> Result<()>
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("action-costs.bin");
        let listener = SocketAddr::from(([127, 0, 0, 1], 1001));
        let scope = WorkerScope {
            peer: sccache::dist::ServerId::from_digest([2; 32]),
            platform: ContentId::of(b"platform"),
        };
        let class = ActionClass(ContentId::of(b"command"));
        let now = Instant::now();
        let wall = 1_000_000_000;
        let mut book = CostBook::default();
        for _ in 0..4 {
            book.observe(
                scope,
                class,
                ActionObservation {
                    execution_nanoseconds: 123_000_000,
                    worker_timing: None,
                    warm_staging_nanoseconds: Some(10_000_000),
                    publication_setup_nanoseconds: Some(5_000_000),
                    upload_bytes: 100,
                    upload_requests: 1,
                    upload_nanoseconds: 1000,
                },
                752,
                now,
            );
        }
        let profile = ContentId::of(b"final-only");
        let receipt = sccache::build_runtime::DeliveryReceipt {
            worker: scope.peer,
            job: 1,
            requester: scope.peer,
            profile,
            result_bytes: 1000,
            elapsed: Duration::from_secs(1),
            observation: sccache::build_runtime::wire::ClientDeliveryObservation {
                selected_bytes: 500,
                direct_bytes: 100,
                scheduler_bytes: 0,
                unique_blobs: 1,
                staging_nanoseconds: 0,
            },
        };
        for _ in 0..4 {
            book.observe_delivery(receipt, now);
        }
        save(&path, &Snapshot::capture(&book, listener, now, wall))?;
        let restored = load(
            &path,
            listener,
            now + Duration::from_secs(60),
            wall + 60_000,
        )?;
        let placement = NativePlacement::default();
        assert_eq!(
            restored
                .predict(scope, class, &placement, now + Duration::from_secs(60))
                .execution_nanoseconds,
            123_000_000
        );
        let restored_cost =
            restored.predict(scope, class, &placement, now + Duration::from_secs(60));
        assert_eq!(restored_cost.output_bytes, 100);
        assert_eq!(restored_cost.result_bytes, 752);
        assert_eq!(
            restored.delivery_fraction(scope.peer, profile, now + Duration::from_secs(60)),
            100_000
        );
        assert_eq!(
            restored
                .predict(scope, class, &placement, now + Duration::from_secs(60))
                .phase,
            super::super::PhaseCost {
                staging_nanoseconds: 10_000_000,
                publication_nanoseconds: 5_000_000
            }
        );
        let expired_wall = wall + u64::try_from(MAX_AGE.as_millis())?;
        assert!(
            load(&path, listener, now + MAX_AGE, expired_wall)?
                .workers
                .is_empty()
        );
        assert!(load(&path, listener, now, wall - 1)?.workers.is_empty());
        assert!(load(&path, SocketAddr::from(([127, 0, 0, 1], 1002)), now, wall).is_err());
        fs::write(&path, b"invalid data")?;
        assert!(load(&path, listener, now, wall).is_err());
        Ok(())
    }
}
