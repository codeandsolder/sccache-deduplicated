//! Scheduler-coordinated, bounded low-priority calibration rounds.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use rouille::{Request, Response, ResponseBody};

use super::{encode, metadata, network};
use crate::{
    build_runtime::{
        Direction, DirectionSnapshot, IdlePermit, MeteredReader, NetworkMeter, NetworkSnapshot,
        Peer, ProbePayload, ProbeStream,
    },
    dist::native::{
        codec,
        probe::{
            PROBE_DURATION, PROBE_HTTP_TIMEOUT, PROBE_IDLE, PROBE_MIN_BYTES, ProbeGrant,
            ProbeOffer, ProbeReceipt,
        },
    },
};

const MAX_WORKERS: usize = 32;
const MAX_HISTORY: usize = 512;
const JOIN_WINDOW: Duration = Duration::from_secs(4);
const POLL_FRESHNESS: Duration = Duration::from_secs(8);
const RETRY_DELAY: Duration = Duration::from_mins(1);
const REFRESH_DELAY: Duration = Duration::from_mins(30);

mod budget;
use budget::Budget;

type Cohort = BTreeSet<Peer>;
type ProbeKey = (Direction, Cohort);

#[derive(Default)]
struct Progress {
    issued: Cohort,
    claimed: Cohort,
    completed: BTreeMap<Peer, (u64, Duration)>,
    receipts: BTreeMap<Peer, (u64, Duration)>,
}

struct Round {
    id: u64,
    key: ProbeKey,
    permit: IdlePermit,
    starts: Instant,
    expires: Instant,
    meter: NetworkMeter,
    budgets: BTreeMap<Peer, u64>,
    progress: Mutex<Progress>,
}

impl Round {
    fn offer(&self, peer: Peer, now: Instant) -> Option<ProbeGrant> {
        if now >= self.starts || !self.permit.valid() {
            return None;
        }
        let bytes = *self.budgets.get(&peer)?;
        let mut progress = self.progress.lock().unwrap_or_else(PoisonError::into_inner);
        if !progress.issued.insert(peer) {
            return None;
        }
        Some(ProbeGrant {
            round: self.id,
            direction: self.key.0,
            bytes,
            delay_millis: u64::try_from(self.starts.duration_since(now).as_millis())
                .unwrap_or(4000),
        })
    }

    fn claim(&self, peer: Peer, id: u64, direction: Direction, now: Instant) -> Result<u64> {
        ensure!(
            self.id == id
                && self.key.0 == direction
                && now
                    >= self
                        .starts
                        .checked_sub(Duration::from_millis(250))
                        .unwrap_or(self.starts)
                && now < self.starts + PROBE_DURATION
                && now < self.expires
                && self.permit.valid(),
            "expired or preempted probe round"
        );
        let bytes = *self
            .budgets
            .get(&peer)
            .context("worker is not in calibration cohort")?;
        let mut progress = self.progress.lock().unwrap_or_else(PoisonError::into_inner);
        ensure!(
            progress.issued.contains(&peer) && progress.claimed.insert(peer),
            "invalid or repeated calibration claim"
        );
        Ok(bytes)
    }

    fn receipt(&self, peer: Peer, receipt: ProbeReceipt) -> Result<()> {
        ensure!(
            self.id == receipt.round
                && self.key.0 == Direction::Send
                && self.permit.valid()
                && Instant::now() < self.expires,
            "invalid calibration receipt"
        );
        let elapsed = Duration::from_nanos(receipt.elapsed_nanos);
        ensure!(
            !elapsed.is_zero() && elapsed <= PROBE_HTTP_TIMEOUT,
            "invalid calibration duration"
        );
        let mut progress = self.progress.lock().unwrap_or_else(PoisonError::into_inner);
        let &(sent, server_elapsed) = progress
            .completed
            .get(&peer)
            .context("calibration receipt has no completed download")?;
        ensure!(
            sent == receipt.bytes && !progress.receipts.contains_key(&peer),
            "calibration receipt does not match a completed download"
        );
        progress
            .receipts
            .insert(peer, (receipt.bytes, elapsed.max(server_elapsed)));
        Ok(())
    }

    fn complete(&self) -> bool {
        let progress = self.progress.lock().unwrap_or_else(PoisonError::into_inner);
        progress.completed.len() == self.key.1.len()
            && (self.key.0 == Direction::Receive || progress.receipts.len() == self.key.1.len())
    }
}

struct ProbeSlot(Arc<AtomicUsize>);

impl Drop for ProbeSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct MeasuredProbe<R> {
    inner: MeteredReader<ProbeStream<R>>,
    round: Arc<Round>,
    peer: Peer,
    start: Instant,
    bytes: u64,
    finished: bool,
    _slot: ProbeSlot,
}

impl<R: Read> Read for MeasuredProbe<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        if count == 0 && !buffer.is_empty() && !self.finished {
            self.finished = true;
            if self.round.permit.valid() {
                self.round
                    .progress
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .completed
                    .insert(self.peer, (self.bytes, self.start.elapsed()));
            }
        }
        Ok(count)
    }
}

struct Planner {
    workers: BTreeMap<Peer, Instant>,
    history: BTreeMap<ProbeKey, Instant>,
    round: Option<Arc<Round>>,
    next_round: u64,
    next_start: Instant,
    budget: Budget,
}

impl Planner {
    fn new(now: Instant, max_bytes: u64) -> Self {
        Self {
            workers: BTreeMap::new(),
            history: BTreeMap::new(),
            round: None,
            next_round: 0,
            next_start: now + JOIN_WINDOW,
            budget: Budget::new(max_bytes.saturating_mul(16), now),
        }
    }

    fn available(&self, key: &ProbeKey, now: Instant) -> bool {
        self.history.get(key).is_none_or(|&until| now >= until)
    }

    fn select(
        &self,
        network: &NetworkSnapshot,
        now: Instant,
        parallelism: usize,
    ) -> Option<ProbeKey> {
        let directions = [
            (Direction::Send, &network.send),
            (Direction::Receive, &network.receive),
        ];
        let workers: Cohort = self
            .workers
            .iter()
            .filter(|(_, last)| now.duration_since(**last) <= POLL_FRESHNESS)
            .map(|(&peer, _)| peer)
            .collect();
        // Fresh real traffic can supply the initial per-peer lower bound.
        for (direction, snapshot) in directions {
            for &peer in &workers {
                let key = (direction, BTreeSet::from([peer]));
                if !known(snapshot, peer) && self.available(&key, now) {
                    return Some(key);
                }
            }
        }
        if parallelism < 2 {
            return None;
        }
        for (direction, snapshot) in directions {
            let known_workers: Cohort = workers
                .iter()
                .copied()
                .filter(|&peer| known(snapshot, peer))
                .collect();
            if known_workers.len() < 2 {
                continue;
            }
            if let Some(key) =
                self.select_group(direction, snapshot, &known_workers, now, parallelism)
            {
                return Some(key);
            }
        }
        None
    }
    fn select_group(
        &self,
        direction: Direction,
        snapshot: &DirectionSnapshot,
        workers: &Cohort,
        now: Instant,
        parallelism: usize,
    ) -> Option<ProbeKey> {
        let eligible = |members: Cohort| {
            let key = (direction, members);
            (self.available(&key, now) && !covered(snapshot, &key.1)).then_some(key)
        };
        // Prefer one all-worker experiment, or overlapping cohorts of the
        // maximum feasible size when the listener cannot fit the full fleet.
        let width = parallelism.min(workers.len());
        let ordered: Vec<_> = workers.iter().copied().collect();
        let mut candidates = BTreeSet::new();
        if width == 2 {
            candidates.extend(pairs(workers));
        } else {
            for start in 0..ordered.len() {
                let cohort = ordered
                    .iter()
                    .cycle()
                    .skip(start)
                    .take(width)
                    .copied()
                    .collect();
                candidates.insert(cohort);
            }
        }
        if let Some(key) = candidates
            .into_iter()
            .filter_map(eligible)
            .min_by_key(|key| self.history.get(key))
        {
            return Some(key);
        }
        // Refine a shared group only when contention was actually observed.
        // Independent or inconclusive all-host rounds do not trigger an
        // exhaustive pairwise sweep.
        snapshot
            .shared
            .iter()
            .filter(|constraint| constraint.members.len() > 2)
            .flat_map(|constraint| {
                let members = constraint.members.intersection(workers).copied().collect();
                pairs(&members)
            })
            .filter_map(eligible)
            .min_by_key(|key| self.history.get(key))
    }
}

fn pairs(members: &Cohort) -> Vec<Cohort> {
    let mut pairs = Vec::new();
    for &a in members {
        for &b in members.range((std::ops::Bound::Excluded(a), std::ops::Bound::Unbounded)) {
            pairs.push(BTreeSet::from([a, b]));
        }
    }
    pairs
}

fn known(snapshot: &DirectionSnapshot, peer: Peer) -> bool {
    snapshot.peers.get(&peer).is_some_and(|entry| {
        entry.observed_bytes_per_second > 0 || entry.calibrated_bytes_per_second > 0
    })
}

fn covered(snapshot: &DirectionSnapshot, members: &Cohort) -> bool {
    snapshot
        .shared
        .iter()
        .any(|constraint| &constraint.members == members)
}

pub(super) struct ProbeCoordinator {
    passive: Arc<NetworkMeter>,
    calibrated: Arc<NetworkMeter>,
    planner: Mutex<Planner>,
    max_bytes: u64,
    parallelism: usize,
    active: Arc<AtomicUsize>,
}

impl ProbeCoordinator {
    pub(super) fn start(
        passive: &Arc<NetworkMeter>,
        path: PathBuf,
        listener: SocketAddr,
        max_bytes: u64,
        parallelism: usize,
    ) -> Result<Arc<Self>> {
        let calibrated = Arc::new(NetworkMeter::default());
        network::start(&calibrated, path, listener)?;
        let coordinator = Arc::new(Self {
            passive: Arc::clone(passive),
            calibrated,
            planner: Mutex::new(Planner::new(Instant::now(), max_bytes)),
            max_bytes,
            parallelism,
            active: Arc::new(AtomicUsize::new(0)),
        });
        let weak = Arc::downgrade(&coordinator);
        std::thread::Builder::new()
            .name("native-probe-coordinator".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(250));
                    let Some(coordinator) = weak.upgrade() else {
                        break;
                    };
                    coordinator.tick();
                }
            })?;
        Ok(coordinator)
    }

    pub(super) fn snapshot(&self) -> NetworkSnapshot {
        self.passive
            .snapshot()
            .with_calibration(&self.calibrated.snapshot())
    }

    fn tick(&self) {
        let now = Instant::now();
        let passive = self.passive.snapshot();
        self.calibrated.invalidate_calibration(&passive);
        let mut planner = self.planner.lock().unwrap_or_else(PoisonError::into_inner);
        planner
            .workers
            .retain(|_, seen| now.duration_since(*seen) <= POLL_FRESHNESS);
        if let Some(round) = &planner.round {
            round.meter.sample();
            if round.permit.valid() && !round.complete() && now < round.expires {
                return;
            }
        }
        if let Some(round) = planner.round.take() {
            let successful = round.permit.valid() && round.complete();
            if successful {
                if round.key.1.len() == 1 {
                    let progress = round
                        .progress
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    let observations = match round.key.0 {
                        Direction::Send => &progress.receipts,
                        Direction::Receive => &progress.completed,
                    };
                    for (&peer, &(bytes, elapsed)) in observations {
                        self.calibrated
                            .observe_isolated_probe(round.key.0, peer, bytes, elapsed);
                    }
                } else {
                    let measured = round.meter.snapshot();
                    let direction = match round.key.0 {
                        Direction::Send => &measured.send,
                        Direction::Receive => &measured.receive,
                    };
                    self.calibrated
                        .observe_group_probe(round.key.0, &round.key.1, direction);
                }
            }
            if planner.history.len() >= MAX_HISTORY
                && let Some(oldest) = planner
                    .history
                    .iter()
                    .min_by_key(|(_, until)| *until)
                    .map(|(key, _)| key.clone())
            {
                planner.history.remove(&oldest);
            }
            planner.history.insert(
                round.key.clone(),
                now + if successful {
                    REFRESH_DELAY
                } else {
                    RETRY_DELAY
                },
            );
            planner.next_start = now + PROBE_IDLE;
        }
    }

    fn offer(&self, peer: Peer) -> ProbeOffer {
        let now = Instant::now();
        let mut planner = self.planner.lock().unwrap_or_else(PoisonError::into_inner);
        if planner.workers.len() >= MAX_WORKERS && !planner.workers.contains_key(&peer) {
            return ProbeOffer::Wait;
        }
        planner.workers.insert(peer, now);
        if planner.round.is_none()
            && self.active.load(Ordering::Acquire) == 0
            && now >= planner.next_start
            && let Some(permit) = self.passive.idle_gate().permit(PROBE_IDLE)
        {
            let network = self.snapshot();
            if let Some(key) = planner.select(&network, now, self.parallelism) {
                let meter = NetworkMeter::default();
                let direction = match key.0 {
                    Direction::Send => &network.send,
                    Direction::Receive => &network.receive,
                };
                let budgets: BTreeMap<_, u64> = key
                    .1
                    .iter()
                    .map(|&peer| {
                        let rate = direction.peers.get(&peer).map_or(0, |entry| {
                            entry
                                .observed_bytes_per_second
                                .max(entry.calibrated_bytes_per_second)
                        });
                        let bytes = if rate == 0 {
                            self.max_bytes
                        } else {
                            rate.saturating_mul(3)
                                .clamp(PROBE_MIN_BYTES, self.max_bytes)
                        };
                        // Seed only the temporary group estimator, not the
                        // persisted calibration model, with independent bounds.
                        if key.1.len() > 1 {
                            meter.observe_calibration_rate(key.0, peer, rate);
                        }
                        (peer, bytes)
                    })
                    .collect();
                let reserved = budgets.values().copied().fold(0_u64, u64::saturating_add);
                if !planner.budget.reserve(reserved, now) {
                    planner.next_start = now + RETRY_DELAY;
                    return ProbeOffer::Wait;
                }
                planner.next_round = planner.next_round.wrapping_add(1);
                planner.round = Some(Arc::new(Round {
                    id: planner.next_round,
                    key,
                    permit,
                    starts: now + JOIN_WINDOW,
                    expires: now + JOIN_WINDOW + PROBE_HTTP_TIMEOUT + PROBE_DURATION,
                    meter,
                    budgets,
                    progress: Mutex::new(Progress::default()),
                }));
            }
        }
        planner
            .round
            .as_ref()
            .and_then(|round| round.offer(peer, now))
            .map_or(ProbeOffer::Wait, ProbeOffer::Granted)
    }

    fn acquire_slot(&self) -> Result<ProbeSlot> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            ensure!(
                active < self.parallelism,
                "calibration stream capacity exhausted"
            );
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(ProbeSlot(Arc::clone(&self.active))),
                Err(actual) => active = actual,
            }
        }
    }

    fn stream<R: Read>(
        &self,
        peer: Peer,
        id: u64,
        direction: Direction,
        reader: R,
    ) -> Result<MeasuredProbe<R>> {
        let round = self
            .planner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .round
            .clone()
            .context("no active calibration round")?;
        let slot = self.acquire_slot()?;
        let bytes = round.claim(peer, id, direction, Instant::now())?;
        let duration = match direction {
            Direction::Send => PROBE_DURATION,
            Direction::Receive => PROBE_HTTP_TIMEOUT,
        };
        let bounded = ProbeStream::new(reader, round.permit.clone(), bytes, duration);
        let inner = round.meter.meter(direction, peer, bounded, 0, None);
        Ok(MeasuredProbe {
            _slot: slot,
            inner,
            round,
            peer,
            start: Instant::now(),
            bytes: 0,
            finished: false,
        })
    }

    pub(super) fn dispatch(
        &self,
        request: &Request,
        address: SocketAddr,
        operation: &str,
        limit: usize,
    ) -> Result<Response> {
        let peer = Peer::Worker(address);
        match operation {
            "probe_offer" => encode(&self.offer(peer), limit),
            "probe_download" => {
                let id: u64 = metadata(request, limit)?;
                let stream = self.stream(
                    peer,
                    id,
                    Direction::Send,
                    ProbePayload::new(&id.to_le_bytes()),
                )?;
                Ok(Response {
                    status_code: 200,
                    headers: vec![("Content-Type".into(), "application/octet-stream".into())],
                    data: ResponseBody::from_reader(stream),
                    upgrade: None,
                })
            }
            "probe_receipt" => {
                let receipt = metadata(request, limit.min(24))?;
                let round = self
                    .planner
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .round
                    .clone()
                    .context("no active calibration round")?;
                round.receipt(peer, receipt)?;
                encode(&(), limit)
            }
            "probe_upload" => {
                let mut body = request.data().context("missing calibration body")?;
                let id: u64 = codec().with_limit(8).deserialize_from(&mut body)?;
                let mut stream = self.stream(peer, id, Direction::Receive, body)?;
                io::copy(&mut stream, &mut io::sink())?;
                encode(&(), limit)
            }
            _ => Ok(Response::empty_404()),
        }
    }
}

#[cfg(test)]
mod tests;
