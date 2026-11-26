//! Advisory, directional HTTP-body transfer measurements and shared-resource
//! predictions. Logical CAS bytes and encoded transport bytes are not equivalent.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Peer {
    Worker(crate::PeerId),
    Client(crate::PeerId),
    Upstream,
    Other,
    WorkerPath(crate::PeerId, NetworkPath),
    ClientPath(crate::PeerId, NetworkPath),
    UpstreamPath(NetworkPath),
}

pub use sccache_peer_identity::NetworkPath;

impl Peer {
    /// Actual scheduler-local socket endpoints, when known.
    #[must_use = "capacity constraints require a concrete path"]
    pub const fn path(self) -> Option<NetworkPath> {
        match self {
            Self::WorkerPath(_, path) | Self::ClientPath(_, path) | Self::UpstreamPath(path) => {
                Some(path)
            }
            _ => None,
        }
    }

    /// The stable principal; path changes must not change job ownership.
    #[must_use = "principal identity groups the same member's outstanding demand"]
    pub const fn principal(self) -> Self {
        match self {
            Self::WorkerPath(id, _) => Self::Worker(id),
            Self::ClientPath(id, _) => Self::Client(id),
            Self::UpstreamPath(_) => Self::Upstream,
            peer => peer,
        }
    }

    /// Attribute one observation to a concrete scheduler-relative route.
    #[must_use = "the route-specific peer keys capacity evidence"]
    pub const fn on_path(self, path: NetworkPath) -> Self {
        if !path.valid() {
            return self.principal();
        }
        match self.principal() {
            Self::Worker(id) => Self::WorkerPath(id, path),
            Self::Client(id) => Self::ClientPath(id, path),
            Self::Upstream => Self::UpstreamPath(path),
            peer => peer,
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Direction {
    Send,
    Receive,
}

const MAX_PEERS: usize = 512;
const MAX_GROUPS: usize = 64;
const MIN_RATE: u64 = 64 * 1024;
const MAX_RATE: u64 = 1_000_000_000_000;
const MAX_AGE: Duration = Duration::from_mins(30);

#[derive(Default)]
struct Activity {
    active: usize,
    idle_epoch: u64,
}

#[derive(Default)]
struct Counters {
    activity: Mutex<Activity>,
    bytes: AtomicU64,
    remaining: AtomicU64,
    completed_wire: AtomicU64,
    completed_logical: AtomicU64,
}

#[derive(Clone, Copy, Default)]
struct Sample {
    bytes: u64,
    active: usize,
    idle_epoch: u64,
    completed_wire: u64,
    completed_logical: u64,
}

impl Counters {
    fn sample(&self) -> Sample {
        let activity = self.activity.lock().unwrap_or_else(PoisonError::into_inner);
        Sample {
            bytes: self.bytes.load(Ordering::Relaxed),
            active: activity.active,
            idle_epoch: activity.idle_epoch,
            completed_wire: self.completed_wire.load(Ordering::Relaxed),
            completed_logical: self.completed_logical.load(Ordering::Relaxed),
        }
    }
}

/// A streaming body observation. Lifetime and active-flow counters are released
/// even when the transport aborts before the body has been consumed.
pub struct MeteredReader<R> {
    reader: R,
    counters: Arc<Counters>,
    logical_size: u64,
    exact_wire_size: Option<u64>,
    remaining: u64,
    read: u64,
    complete: bool,
}

impl<R> MeteredReader<R> {
    fn finish(&mut self) {
        if !self.complete {
            self.complete = true;
            let _activity = self
                .counters
                .activity
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.counters
                .completed_wire
                .fetch_add(self.read, Ordering::Relaxed);
            self.counters
                .completed_logical
                .fetch_add(self.logical_size, Ordering::Relaxed);
        }
    }
}

impl<R: Read> Read for MeteredReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(buffer)?;
        let bytes = u64::try_from(count).unwrap_or(u64::MAX);
        self.read = self.read.saturating_add(bytes);
        let consumed = self.remaining.min(bytes);
        self.remaining -= consumed;
        self.counters
            .remaining
            .fetch_sub(consumed, Ordering::Relaxed);
        self.counters.bytes.fetch_add(bytes, Ordering::Relaxed);
        if self.exact_wire_size == Some(self.read)
            || (count == 0 && !buffer.is_empty() && self.exact_wire_size.is_none())
        {
            self.finish();
        }
        Ok(count)
    }
}

impl<R> Drop for MeteredReader<R> {
    fn drop(&mut self) {
        let mut activity = self
            .counters
            .activity
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.counters
            .remaining
            .fetch_sub(self.remaining, Ordering::Relaxed);
        activity.active -= 1;
        if activity.active == 0 {
            activity.idle_epoch = activity.idle_epoch.wrapping_add(1);
        }
    }
}

struct PeerRecord {
    counters: Arc<Counters>,
    previous: Sample,
    peak: u64,
    peak_at: Instant,
    isolated: u64,
    isolated_at: Instant,
    wire_per_mille: u64,
    last_active: Instant,
}

impl PeerRecord {
    fn new(now: Instant) -> Self {
        Self {
            counters: Arc::new(Counters::default()),
            previous: Sample::default(),
            peak: 0,
            peak_at: now,
            isolated: 0,
            isolated_at: now,
            wire_per_mille: 1000,
            last_active: now,
        }
    }
    fn sample(&mut self, now: Instant, elapsed: Duration) -> PeerWindow {
        let current = self.counters.sample();
        let bytes = current.bytes.wrapping_sub(self.previous.bytes);
        let wire = current
            .completed_wire
            .wrapping_sub(self.previous.completed_wire);
        let logical = current
            .completed_logical
            .wrapping_sub(self.previous.completed_logical);
        if logical >= 1 << 20 {
            let ratio = (u128::from(wire) * 1000 / u128::from(logical)).clamp(1, 1100);
            let ratio = u64::try_from(ratio).unwrap_or(1000);
            self.wire_per_mille = (3 * self.wire_per_mille + ratio).div_ceil(4);
        }
        if now.duration_since(self.peak_at) > MAX_AGE {
            self.peak = 0;
        }
        if now.duration_since(self.isolated_at) > MAX_AGE {
            self.isolated = 0;
        }
        if bytes != 0 || current.active != 0 {
            self.last_active = now;
        }
        let rate = u64::try_from(u128::from(bytes) * 1_000_000_000 / elapsed.as_nanos())
            .unwrap_or(MAX_RATE)
            .min(MAX_RATE);
        let continuous = current.active > 0
            && self.previous.active > 0
            && current.idle_epoch == self.previous.idle_epoch;
        let sustained = continuous && rate >= MIN_RATE;
        if sustained && rate >= self.peak {
            self.peak = rate;
            self.peak_at = now;
        }
        let partial =
            !sustained && (bytes != 0 || current.active != 0 || self.previous.active != 0);
        self.previous = current;
        PeerWindow {
            bytes,
            rate,
            isolated: self.isolated,
            sustained,
            partial,
        }
    }
}

struct PeerWindow {
    bytes: u64,
    rate: u64,
    isolated: u64,
    sustained: bool,
    partial: bool,
}

struct Evidence {
    count: u8,
    minimum: u64,
    maximum: u64,
    seen: Instant,
}

/// A sustained effective body-throughput constraint, not a claim about the
/// physical location of a bottleneck.
#[derive(Debug, Clone)]
pub struct SharedCapacity {
    pub members: BTreeSet<Peer>,
    pub bytes_per_second: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct PeerCapacity {
    /// Largest recent sustained observation; an observed lower bound, not a
    /// proven physical link ceiling.
    pub observed_bytes_per_second: u64,
    pub isolated_bytes_per_second: u64,
    pub wire_per_mille: u64,
    pub active_remaining_bytes: u64,
    pub body_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DirectionSnapshot {
    pub peers: BTreeMap<Peer, PeerCapacity>,
    pub shared: Vec<SharedCapacity>,
    pub independent: Vec<ConcurrentCapacity>,
}

impl DirectionSnapshot {
    #[must_use = "placement converts logical demand to estimated transport bytes"]
    pub fn wire_bytes(&self, peer: Peer, logical_bytes: u128) -> u128 {
        let ratio = self
            .peers
            .get(&peer)
            .map_or(1000, |entry| entry.wire_per_mille);
        logical_bytes
            .saturating_mul(u128::from(ratio))
            .div_ceil(1000)
    }

    /// Aggregate effective logical goodput from sustained encoded-body windows.
    #[must_use = "the estimate supplements per-request delivery samples"]
    pub fn logical_rate(&self, peer: Peer, fallback: u64) -> u64 {
        self.peers
            .get(&peer)
            .map_or(fallback, |entry| {
                let rate = u128::from(entry.observed_bytes_per_second) * 1000
                    / u128::from(entry.wire_per_mille.max(1));
                u64::try_from(rate)
                    .unwrap_or(MAX_RATE)
                    .min(MAX_RATE)
                    .max(fallback)
            })
            .max(1)
    }

    /// Estimate transport service rate from sustained observations, using the
    /// configured/effective fallback until there is better evidence.
    #[must_use = "the rate is an advisory placement estimate"]
    pub fn rate(&self, peer: Peer, fallback: u64) -> u64 {
        self.peers
            .get(&peer)
            .map_or(fallback, |entry| {
                entry.observed_bytes_per_second.max(fallback)
            })
            .max(1)
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetworkSnapshot {
    pub send: DirectionSnapshot,
    pub receive: DirectionSnapshot,
    pub interfaces: crate::wire::InterfaceReport,
}

#[derive(Default)]
struct DirectionMeter {
    peers: BTreeMap<Peer, PeerRecord>,
    evidence: BTreeMap<BTreeSet<Peer>, Evidence>,
    independent: BTreeMap<BTreeSet<Peer>, overlap::IndependentEvidence>,
}

impl DirectionMeter {
    fn record(&mut self, mut peer: Peer, now: Instant) -> &mut PeerRecord {
        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&peer) {
            peer = Peer::Other;
        }
        self.peers
            .entry(peer)
            .or_insert_with(|| PeerRecord::new(now))
    }

    fn sample(
        &mut self,
        now: Instant,
        elapsed: Duration,
        clean: impl FnOnce(&BTreeMap<Peer, u64>) -> bool,
    ) {
        let mut sustained = BTreeMap::new();
        let mut partial = elapsed > Duration::from_secs(3);
        let mut current_rates = BTreeMap::new();
        let mut current_bytes = BTreeMap::new();
        for (&peer, record) in &mut self.peers {
            let window = record.sample(now, elapsed);
            if window.bytes > 0 {
                current_bytes.insert(peer, window.bytes);
                current_rates.insert(peer, window.rate);
            }
            if window.sustained {
                sustained.insert(peer, (window.rate, window.isolated));
            }
            partial |= window.partial;
        }

        partial |= !clean(&current_bytes);
        self.peers.retain(|_, record| {
            record.previous.active != 0 || now.duration_since(record.last_active) <= MAX_AGE
        });
        // Any observation that exceeds a prior group ceiling contradicts that
        // ceiling, even if the active set has changed.
        self.evidence.retain(|members, evidence| {
            let total = members
                .iter()
                .map(|peer| current_rates.get(peer).copied().unwrap_or(0))
                .sum::<u64>();
            now.duration_since(evidence.seen) <= MAX_AGE
                && total <= evidence.maximum.saturating_mul(115) / 100
        });

        self.independent
            .retain(|_, evidence| now.duration_since(evidence.seen) <= MAX_AGE);
        if !partial
            && sustained.len() == 1
            && let Some((peer, &(rate, _))) = sustained.first_key_value()
            && let Some(record) = self.peers.get_mut(peer)
            && rate >= record.isolated
        {
            record.isolated = rate;
            record.isolated_at = now;
        }
        // Only infer contention from aligned, continuously backlogged body
        // windows with evidence that every participant can go faster.
        if partial || sustained.len() < 2 || sustained.contains_key(&Peer::Other) {
            return;
        }
        let members: BTreeSet<_> = sustained.keys().copied().collect();
        let total: u64 = sustained.values().map(|(rate, _)| *rate).sum();
        let independent: u64 = sustained.values().map(|(_, peak)| *peak).sum();
        let slowed = sustained
            .values()
            .all(|&(rate, peak)| peak > 0 && rate.saturating_mul(100) <= peak.saturating_mul(85));
        if !slowed || total.saturating_mul(100) > independent.saturating_mul(80) {
            self.observe_independence(&members, &sustained, now);
            return;
        }
        if self.evidence.len() >= MAX_GROUPS
            && !self.evidence.contains_key(&members)
            && let Some(oldest) = self
                .evidence
                .iter()
                .min_by_key(|(_, entry)| entry.seen)
                .map(|(key, _)| key.clone())
        {
            self.evidence.remove(&oldest);
        }
        self.independent
            .retain(|cohort, _| !members.is_subset(cohort));
        let evidence = self.evidence.entry(members).or_insert(Evidence {
            count: 0,
            minimum: total,
            maximum: total,
            seen: now,
        });
        let minimum = evidence.minimum.min(total);
        let maximum = evidence.maximum.max(total);
        if maximum.saturating_mul(100) > minimum.saturating_mul(120) {
            *evidence = Evidence {
                count: 1,
                minimum: total,
                maximum: total,
                seen: now,
            };
        } else {
            evidence.count = evidence.count.saturating_add(1);
            evidence.minimum = minimum;
            evidence.maximum = maximum;
            evidence.seen = now;
        }
    }

    fn snapshot(&self) -> DirectionSnapshot {
        DirectionSnapshot {
            peers: self
                .peers
                .iter()
                .map(|(&peer, record)| {
                    (
                        peer,
                        PeerCapacity {
                            observed_bytes_per_second: record.peak,
                            isolated_bytes_per_second: record.isolated,
                            wire_per_mille: record.wire_per_mille,
                            active_remaining_bytes: record
                                .counters
                                .remaining
                                .load(Ordering::Relaxed),
                            body_bytes: record.counters.bytes.load(Ordering::Relaxed),
                        },
                    )
                })
                .collect(),
            independent: self
                .independent
                .values()
                .filter(|evidence| evidence.count >= 3)
                .map(|evidence| ConcurrentCapacity {
                    rates: evidence.rates.clone(),
                })
                .collect(),
            shared: self
                .evidence
                .iter()
                .filter(|(_, evidence)| evidence.count >= 3)
                .map(|(members, evidence)| SharedCapacity {
                    members: members.clone(),
                    bytes_per_second: evidence.maximum,
                })
                .collect(),
        }
    }
}

struct State {
    last_sample: Instant,
    send: DirectionMeter,
    receive: DirectionMeter,
}

impl State {
    const fn direction(&mut self, direction: Direction) -> &mut DirectionMeter {
        match direction {
            Direction::Send => &mut self.send,
            Direction::Receive => &mut self.receive,
        }
    }
}

/// One scheduler-wide meter across all authenticated native body transfers.
/// Byte accounting is per-peer and atomic; no global lock during I/O.
pub struct NetworkMeter {
    state: Mutex<State>,
}

impl Default for NetworkMeter {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                last_sample: Instant::now(),
                send: DirectionMeter::default(),
                receive: DirectionMeter::default(),
            }),
        }
    }
}

impl NetworkMeter {
    /// Observe encoded bytes and the logical size of a streaming body.
    /// For compressed bodies the total wire size is not known until EOF.
    pub fn meter<R>(
        &self,
        direction: Direction,
        peer: Peer,
        reader: R,
        logical_size: u64,
        exact_wire_size: Option<u64>,
    ) -> MeteredReader<R> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let record = state.direction(direction).record(peer, Instant::now());
        let remaining = exact_wire_size.unwrap_or_else(|| {
            u64::try_from(u128::from(logical_size) * u128::from(record.wire_per_mille) / 1000)
                .unwrap_or(u64::MAX)
        });
        // Registration and activation are atomic with respect to sampling/pruning.
        let counters = Arc::clone(&record.counters);
        let remaining = remaining.min(1 << 40);
        {
            let mut activity = counters
                .activity
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            counters.remaining.fetch_add(remaining, Ordering::Relaxed);
            activity.active += 1;
        }
        drop(state);
        MeteredReader {
            reader,
            counters,
            logical_size,
            exact_wire_size,
            remaining,
            read: 0,
            complete: false,
        }
    }

    /// Advance the estimator on synchronized windows from a maintenance thread.
    pub fn sample(&self, mut clean: impl FnMut(Direction, &BTreeMap<Peer, u64>) -> bool) {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let elapsed = now.duration_since(state.last_sample);
        if elapsed < Duration::from_millis(200) {
            return;
        }
        state
            .send
            .sample(now, elapsed, |bytes| clean(Direction::Send, bytes));
        state
            .receive
            .sample(now, elapsed, |bytes| clean(Direction::Receive, bytes));
        state.last_sample = now;
    }

    #[must_use = "the snapshot is used for advisory scheduling"]
    pub fn snapshot(&self) -> NetworkSnapshot {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        NetworkSnapshot {
            send: state.send.snapshot(),
            receive: state.receive.snapshot(),
            interfaces: crate::wire::InterfaceReport::default(),
        }
    }
}

mod overlap;
pub use overlap::ConcurrentCapacity;
mod checkpoint;
pub use checkpoint::NetworkCheckpoint;
mod simulation;
pub use simulation::{TransferDemand, transfer_seconds};

#[cfg(test)]
mod tests;

/// Learned effective output transfer cost. Byte sizes refer to the blobs the
/// scheduler actually requested, not the entire compiler result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResultTransferEstimate {
    pub expected_bytes: u64,
    pub expected_requests: u64,
    pub bytes_per_second: u64,
    pub request_nanoseconds: u64,
    pub observations: u64,
}

impl Default for ResultTransferEstimate {
    fn default() -> Self {
        Self {
            expected_bytes: 1 << 20,
            expected_requests: 1,
            bytes_per_second: 128 << 20,
            request_nanoseconds: 2_000_000,
            observations: 0,
        }
    }
}

impl ResultTransferEstimate {
    #[must_use = "untrusted worker telemetry must be validated"]
    pub fn valid(self) -> bool {
        self.expected_bytes <= 1 << 40
            && self.expected_requests <= 1_000_000
            && (1..=MAX_RATE).contains(&self.bytes_per_second)
            && self.request_nanoseconds <= 60_000_000_000
    }

    /// Observe a successful result publication, including zero missing blobs.
    /// Small uploads primarily measure fixed request/staging overhead.
    pub fn observe(&mut self, bytes: u64, requests: u64, elapsed: Duration) {
        let bytes = bytes.min(1 << 40);
        let requests = requests.min(1_000_000);
        let smooth = |old: u64, new: u64| {
            if new >= old {
                old + (new - old).div_ceil(4)
            } else {
                old - (old - new).div_ceil(4)
            }
        };
        if self.observations == 0 {
            self.expected_bytes = bytes;
            self.expected_requests = requests;
        } else {
            self.expected_bytes = smooth(self.expected_bytes, bytes);
            self.expected_requests = smooth(self.expected_requests, requests);
        }
        self.observations = self.observations.saturating_add(1);
        if requests == 0 {
            return;
        }
        let nanos = elapsed.as_nanos();
        if bytes >= 1 << 20 {
            let transfer =
                nanos.saturating_sub(u128::from(requests) * u128::from(self.request_nanoseconds));
            if transfer >= 1_000_000 {
                let rate =
                    (u128::from(bytes) * 1_000_000_000 / transfer).clamp(1, u128::from(MAX_RATE));
                self.bytes_per_second = smooth(
                    self.bytes_per_second,
                    u64::try_from(rate).unwrap_or(MAX_RATE),
                );
            }
        } else {
            let transfer =
                u128::from(bytes) * 1_000_000_000 / u128::from(self.bytes_per_second.max(1));
            let overhead = nanos.saturating_sub(transfer) / u128::from(requests);
            let overhead = u64::try_from(overhead.min(60_000_000_000)).unwrap_or(60_000_000_000);
            self.request_nanoseconds = smooth(self.request_nanoseconds, overhead);
        }
    }

    #[must_use = "the duration is used in the completion estimate"]
    pub fn seconds(self) -> f64 {
        transfer_seconds(u128::from(self.expected_bytes), self.bytes_per_second)
            + Duration::from_nanos(
                self.expected_requests
                    .saturating_mul(self.request_nanoseconds),
            )
            .as_secs_f64()
    }
}
