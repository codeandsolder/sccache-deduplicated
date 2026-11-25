//! Short-lived, authenticated path measurements. A peer's identity remains
//! independent of the currently preferred interface.
pub(super) mod interface;

use crate::build_runtime::wire::CachePathRate;
#[cfg(all(target_os = "linux", feature = "native-store"))]
use crate::build_runtime::wire::{MAX_PEER_DOWNLOAD_RATES, PeerDownloadRate};
use sccache_peer_identity::{NetworkPath, PeerId, Role, RouteSet};
use std::{
    collections::HashMap,
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

pub const PROBE_PATH: &str = "/api/v1/cluster/probe";
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(350);
const SUCCESS_TTL: Duration = Duration::from_secs(60);
const FAILURE_TTL: Duration = Duration::from_secs(10);
const MAX_PATHS: usize = 4096;
const MAX_PROBES: usize = 16;
const RATE_TTL: Duration = Duration::from_secs(180);
const MIN_SAMPLE_BYTES: u64 = 1024 * 1024;
const DEFAULT_RATE: u64 = 16 * 1024 * 1024;
static PROBES: AtomicUsize = AtomicUsize::new(0);

/// A concrete outbound transport candidate. Source-bound routes are only
/// discovered for local on-link networks; unbound routes preserve policy
/// routing, VPN and routed fallbacks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Route {
    pub address: SocketAddr,
    pub source: Option<IpAddr>,
}

impl Route {
    #[must_use = "the route preserves kernel routing and fallback semantics"]
    pub const fn unbound(address: SocketAddr) -> Self {
        Self {
            address,
            source: None,
        }
    }
    #[must_use = "the binding identifies the selected source interface"]
    pub fn binding(self) -> Option<(IpAddr, Option<String>)> {
        self.source.map(|ip| (ip, interface::binding(ip)))
    }
}

fn candidates(routes: &RouteSet) -> Vec<Route> {
    let mut candidates = routes.iter().map(Route::unbound).collect::<Vec<_>>();
    for address in routes.iter() {
        candidates.extend(
            interface::direct_sources(address.ip())
                .into_iter()
                .map(|source| Route {
                    address,
                    source: Some(source),
                }),
        );
    }
    candidates
}

#[derive(Clone, Copy, Default)]
pub struct ConnectionPath {
    pub reported: Option<NetworkPath>,
    pub local: Option<IpAddr>,
    pub quality: interface::Quality,
}

impl ConnectionPath {
    pub fn from_response(
        headers: &reqwest::header::HeaderMap,
        extensions: &http::Extensions,
    ) -> Self {
        let reported = reported_path(headers);
        let local = extensions
            .get::<hyper_util::client::legacy::connect::HttpInfo>()
            .map(|info| info.local_addr().ip().to_canonical())
            .or_else(|| reported.map(|path| path.remote));
        Self {
            reported,
            local,
            quality: interface::Quality::Unknown,
        }
    }
    #[cfg(test)]
    fn reported(path: Option<NetworkPath>) -> Self {
        Self {
            local: path.map(|path| path.remote),
            reported: path,
            quality: interface::Quality::Unknown,
        }
    }
}

/// Global admission for probe tasks, released on cancellation as well.
pub struct Probe {
    pub address: Route,
}

impl Probe {
    fn acquire(address: Route) -> Option<Self> {
        let mut count = PROBES.load(Ordering::Relaxed);
        while count < MAX_PROBES {
            match PROBES.compare_exchange_weak(
                count,
                count + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Self { address }),
                Err(actual) => count = actual,
            }
        }
        None
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        PROBES.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
pub enum Transfer {
    Upload(u64),
    Download(u64),
}

impl Transfer {
    const fn index(self) -> usize {
        match self {
            Self::Upload(_) => 0,
            Self::Download(_) => 1,
        }
    }

    const fn bytes(self) -> u64 {
        match self {
            Self::Upload(bytes) | Self::Download(bytes) => bytes,
        }
    }
}

#[derive(Clone, Copy)]
struct Rate {
    path: Option<NetworkPath>,
    local: Option<IpAddr>,
    quality: interface::Quality,
    wire_per_mille: u64,
    bytes_per_second: u64,
    expires: Instant,
}

fn updated_rate(
    previous: Option<Rate>,
    connection: ConnectionPath,
    observed: u64,
    now: Instant,
) -> Rate {
    let previous = previous.filter(|rate| {
        rate.expires > now && (rate.path, rate.local) == (connection.reported, connection.local)
    });
    if let Some(prior) = previous
        && prior.quality == interface::Quality::Clean
        && connection.quality != interface::Quality::Clean
        && observed <= prior.bytes_per_second
    {
        // Do not extend an old clean estimate indefinitely with busy samples.
        return prior;
    }
    let rate = previous.map_or(observed, |prior| {
        if connection.quality == interface::Quality::Clean
            && prior.quality != interface::Quality::Clean
        {
            observed
        } else {
            (prior.bytes_per_second + observed).div_ceil(2)
        }
    });
    Rate {
        path: connection.reported,
        local: connection.local,
        quality: connection.quality,
        wire_per_mille: previous.map_or(1000, |rate| rate.wire_per_mille),
        bytes_per_second: rate,
        expires: now + RATE_TTL,
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct Key {
    peer: PeerId,
    role: Role,
    address: Route,
}

#[derive(Clone, Copy)]
struct Sample {
    measured: Option<Duration>,
    local: Option<IpAddr>,
    expires: Instant,
    pending_until: Instant,
    rates: [Option<Rate>; 2],
    verified: Option<Rate>,
}

impl Sample {
    fn loaded_cost(
        &self,
        interfaces: &interface::Snapshot,
        address: Route,
        role: Role,
        transfer: Transfer,
        nominal: u128,
        now: Instant,
    ) -> u128 {
        let local = address.source.or_else(|| {
            self.rates[transfer.index()]
                .filter(|rate| rate.expires > now)
                .and_then(|rate| rate.local)
                .or(self.local)
        });
        let clean_wire = self.rates[transfer.index()]
            .filter(|rate| rate.expires > now && rate.quality == interface::Quality::Clean)
            .map(|rate| rate.bytes_per_second);
        let encoded = if role == Role::Worker && matches!(transfer, Transfer::Download(_)) {
            self.verified.filter(|rate| rate.expires > now).map_or_else(
                || transfer.bytes(),
                |rate| {
                    transfer
                        .bytes()
                        .saturating_mul(rate.wire_per_mille)
                        .div_ceil(1000)
                },
            )
        } else {
            transfer.bytes()
        };
        let endpoint = local.map(|local| {
            let remote = self.rates[transfer.index()]
                .filter(|rate| rate.expires > now)
                .and_then(|rate| rate.path)
                .map_or_else(|| address.address.ip(), |path| path.local);
            NetworkPath::new(local, remote)
        });
        let load = interfaces.cost(local, transfer, clean_wire, nominal);
        interfaces.overlap_cost(endpoint, transfer, encoded, load)
    }
}

#[derive(Default)]
pub struct RouteBook {
    samples: Mutex<HashMap<Key, Sample>>,
    transfers: AtomicUsize,
}

impl RouteBook {
    /// Reserve only stale candidates, preventing parallel requests from
    /// generating duplicate probe batches.
    pub fn reserve(&self, peer: PeerId, role: Role, routes: &RouteSet) -> Vec<Probe> {
        if !routes.valid() {
            return Vec::new();
        }
        let now = Instant::now();
        let mut samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        if samples.len() >= MAX_PATHS {
            samples.retain(|_, sample| {
                sample.expires > now
                    || sample.pending_until > now
                    || sample.rates.iter().flatten().any(|rate| rate.expires > now)
                    || sample.verified.is_some_and(|rate| rate.expires > now)
            });
        }
        let mut pending = Vec::new();
        for address in candidates(routes) {
            let key = Key {
                peer,
                role,
                address,
            };
            if samples
                .get(&key)
                .is_some_and(|sample| sample.expires > now || sample.pending_until > now)
                || (samples.len() >= MAX_PATHS && !samples.contains_key(&key))
            {
                continue;
            }
            let Some(probe) = Probe::acquire(address) else {
                break;
            };
            let sample = samples.entry(key).or_insert(Sample {
                measured: None,
                local: None,
                expires: now,
                pending_until: now,
                rates: [None; 2],
                verified: None,
            });
            sample.pending_until = now + FAILURE_TTL;
            pending.push(probe);
        }
        drop(samples);
        pending
    }

    pub fn observe(&self, peer: PeerId, role: Role, address: Route, elapsed: Option<Duration>) {
        self.observe_path(peer, role, address, elapsed, ConnectionPath::default());
    }

    pub fn observe_path(
        &self,
        peer: PeerId,
        role: Role,
        address: Route,
        elapsed: Option<Duration>,
        connection: ConnectionPath,
    ) {
        let path = connection.reported;
        let mut samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        let key = Key {
            peer,
            role,
            address,
        };
        if samples.len() < MAX_PATHS || samples.contains_key(&key) {
            let sample = samples.entry(key).or_insert_with(|| Sample {
                measured: None,
                local: None,
                expires: Instant::now(),
                pending_until: Instant::now(),
                rates: [None; 2],
                verified: None,
            });
            // The probe uses the same blocking pool as downloads. It cannot
            // invalidate the upload sample: the separate async upload pool
            // may still be connected through a different source interface.
            if let Some(path) = path
                && sample.rates[Transfer::Download(0).index()]
                    .is_some_and(|rate| rate.path != Some(path))
            {
                sample.rates[Transfer::Download(0).index()] = None;
            }
            if elapsed.is_none()
                || path
                    .is_some_and(|path| sample.verified.is_some_and(|rate| rate.path != Some(path)))
            {
                sample.verified = None;
            }
            sample.pending_until = Instant::now();
            sample.measured = elapsed;
            sample.local = connection.local;
            sample.expires = Instant::now()
                + if elapsed.is_some() {
                    SUCCESS_TTL
                } else {
                    FAILURE_TTL
                };
        }
        drop(samples);
    }

    /// Record completed encoded-body goodput, separately in each direction.
    /// Short transfers are too dominated by setup/scheduling to estimate bandwidth.
    pub fn transferred(
        &self,
        peer: PeerId,
        role: Role,
        address: Route,
        transfer: Transfer,
        elapsed: Duration,
        connection: ConnectionPath,
    ) {
        if transfer.bytes() < MIN_SAMPLE_BYTES || elapsed < Duration::from_millis(2) {
            return;
        }
        let now = Instant::now();
        let mut samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        let key = Key {
            peer,
            role,
            address,
        };
        if samples.len() >= MAX_PATHS && !samples.contains_key(&key) {
            return;
        }
        let sample = samples.entry(key).or_insert(Sample {
            measured: None,
            local: None,
            expires: now,
            pending_until: now,
            rates: [None; 2],
            verified: None,
        });
        if sample.measured.is_some() {
            sample.expires = now + SUCCESS_TTL;
        }
        let slot = &mut sample.rates[transfer.index()];
        let observed = u64::try_from(
            (u128::from(transfer.bytes()) * 1_000_000_000 / elapsed.as_nanos())
                .clamp(64 * 1024, 1_000_000_000_000),
        )
        .unwrap_or(1_000_000_000_000);
        *slot = Some(updated_rate(*slot, connection, observed, now));
        drop(samples);
    }

    /// Only successful content verification supplies a logical service rate.
    #[cfg(all(target_os = "linux", feature = "native-store"))]
    pub fn verified_download(
        &self,
        peer: PeerId,
        address: Route,
        connection: ConnectionPath,
        bytes: u64,
        encoded_length: Option<u64>,
        elapsed: Duration,
    ) {
        if bytes < MIN_SAMPLE_BYTES
            || elapsed < Duration::from_millis(2)
            || !connection.reported.is_some_and(NetworkPath::valid)
        {
            return;
        }
        let now = Instant::now();
        let mut samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(sample) = samples.get_mut(&Key {
            peer,
            role: Role::Worker,
            address,
        }) else {
            return;
        };
        let observed = u64::try_from(
            (u128::from(bytes) * 1_000_000_000 / elapsed.as_nanos())
                .clamp(64 * 1024, 1_000_000_000_000),
        )
        .unwrap_or(1_000_000_000_000);
        let mut rate = updated_rate(sample.verified, connection, observed, now);
        if let Some(wire) = encoded_length {
            let ratio = u64::try_from((u128::from(wire) * 1000 / u128::from(bytes)).clamp(1, 1100))
                .unwrap_or(1000);
            rate.wire_per_mille = if sample.verified.is_some_and(|previous| {
                previous.expires > now && previous.path == connection.reported
            }) {
                (rate.wire_per_mille + ratio).div_ceil(2)
            } else {
                ratio
            };
        }
        sample.verified = Some(rate);
        drop(samples);
    }

    #[cfg(all(target_os = "linux", feature = "native-store"))]
    pub fn peer_download_rates(&self) -> Vec<PeerDownloadRate> {
        let now = Instant::now();
        let interfaces = interface::snapshot();
        let samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        let mut best = std::collections::BTreeMap::<PeerId, (u128, PeerDownloadRate)>::new();
        for (key, sample) in samples.iter() {
            if key.role != Role::Worker || sample.measured.is_none() || sample.expires <= now {
                continue;
            }
            let Some(rate) = sample.verified.filter(|rate| rate.expires > now) else {
                continue;
            };
            let Some(path) = rate.path else {
                continue;
            };
            let observed = PeerDownloadRate {
                source: key.peer,
                path,
                logical_bytes_per_second: rate.bytes_per_second,
                wire_per_mille: rate.wire_per_mille,
            };
            let nominal = (u128::from(4_u64 << 20) * 1_000_000_000)
                .div_ceil(u128::from(rate.bytes_per_second));
            let clean_wire = sample.rates[Transfer::Download(0).index()]
                .filter(|rate| rate.expires > now && rate.quality == interface::Quality::Clean)
                .map(|rate| rate.bytes_per_second);
            let transfer = Transfer::Download(4 << 20);
            let wire = (4_u64 << 20)
                .saturating_mul(rate.wire_per_mille)
                .div_ceil(1000);
            let load = interfaces.cost(rate.local, transfer, clean_wire, nominal);
            let endpoint = rate.local.map(|local| NetworkPath::new(local, path.local));
            let cost = sample.measured.map_or(0, |rtt| rtt.as_nanos())
                + interfaces.overlap_cost(endpoint, transfer, wire, load);
            best.entry(key.peer)
                .and_modify(|current| {
                    if (cost, observed.path) < (current.0, current.1.path) {
                        *current = (cost, observed);
                    }
                })
                .or_insert((cost, observed));
        }
        drop(samples);
        let mut best = best.into_values().map(|(_, rate)| rate).collect::<Vec<_>>();
        best.sort_unstable_by_key(|rate| {
            (
                std::cmp::Reverse(rate.logical_bytes_per_second),
                rate.source,
            )
        });
        best.truncate(MAX_PEER_DOWNLOAD_RATES);
        best.sort_unstable_by_key(|rate| rate.source);
        best
    }

    pub fn best_rate(
        &self,
        peer: PeerId,
        role: Role,
        routes: &RouteSet,
        transfer: Transfer,
    ) -> Option<CachePathRate> {
        let representative = match transfer {
            Transfer::Upload(_) => Transfer::Upload(4 << 20),
            Transfer::Download(_) => Transfer::Download(4 << 20),
        };
        let ranked = self.ranked(peer, role, routes, Some(representative), false);
        let now = Instant::now();
        let samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        let best = ranked.into_iter().find_map(|(_, _, _, address)| {
            let rate = samples
                .get(&Key {
                    peer,
                    role,
                    address,
                })?
                .rates[transfer.index()]
            .filter(|rate| rate.expires > now)?;
            Some(CachePathRate {
                path: rate.path?,
                bytes_per_second: rate.bytes_per_second,
            })
        });
        drop(samples);
        best
    }

    pub(super) fn local_source(&self, peer: PeerId, role: Role, address: Route) -> Option<IpAddr> {
        address.source.or_else(|| {
            self.samples
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&Key {
                    peer,
                    role,
                    address,
                })
                .and_then(|sample| sample.rates[Transfer::Upload(0).index()])
                .and_then(|rate| rate.local)
        })
    }

    /// Rank by authenticated RTT for control messages, or estimated
    /// completion time for real bulk transfers. Occasionally use an
    /// unmeasured authenticated candidate to learn its bandwidth.
    pub fn ordered(
        &self,
        peer: PeerId,
        role: Role,
        routes: &RouteSet,
        transfer: Option<Transfer>,
    ) -> Vec<Route> {
        let explore = transfer.is_some_and(|transfer| transfer.bytes() >= MIN_SAMPLE_BYTES)
            && self
                .transfers
                .fetch_add(1, Ordering::Relaxed)
                .is_multiple_of(16);
        let mut result = self
            .ranked(peer, role, routes, transfer, explore)
            .into_iter()
            .map(|(_, _, _, address)| address)
            .collect::<Vec<_>>();
        if !result.contains(&Route::unbound(routes.primary)) {
            result.push(Route::unbound(routes.primary));
        }
        result
    }

    /// Compare alternative sources without consuming an exploration slot.
    pub fn estimated_cost(
        &self,
        peer: PeerId,
        role: Role,
        routes: &RouteSet,
        transfer: Transfer,
    ) -> Option<u128> {
        self.ranked(peer, role, routes, Some(transfer), false)
            .first()
            .map(|(_, cost, _, _)| *cost)
    }

    fn ranked(
        &self,
        peer: PeerId,
        role: Role,
        routes: &RouteSet,
        transfer: Option<Transfer>,
        explore: bool,
    ) -> Vec<(bool, u128, bool, Route)> {
        let now = Instant::now();
        let interfaces = interface::snapshot();
        let candidates = candidates(routes);
        let samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        let rate = |address| {
            transfer.and_then(|transfer| {
                let sample = samples.get(&Key {
                    peer,
                    role,
                    address,
                })?;
                let verified = if role == Role::Worker && matches!(transfer, Transfer::Download(_))
                {
                    sample.verified.filter(|rate| rate.expires > now)
                } else {
                    None
                };
                verified
                    .or_else(|| sample.rates[transfer.index()].filter(|rate| rate.expires > now))
                    .map(|rate| rate.bytes_per_second)
            })
        };
        let baseline = candidates
            .iter()
            .copied()
            .filter_map(rate)
            .max()
            .unwrap_or(DEFAULT_RATE);
        let mut ranked = candidates
            .into_iter()
            .filter_map(|address| {
                let sample = samples.get(&Key {
                    peer,
                    role,
                    address,
                })?;
                let rtt = (sample.expires > now
                    || (sample.pending_until > now
                        && now.saturating_duration_since(sample.expires) < FAILURE_TTL))
                    .then_some(sample.measured)
                    .flatten()?;
                let known = rate(address);
                let cost = rtt.as_nanos()
                    + transfer.map_or(0, |transfer| {
                        let rate = known.unwrap_or_else(|| {
                            if address.address.ip().is_loopback() {
                                baseline.max(256 << 20)
                            } else {
                                baseline
                            }
                        });
                        let nominal = (u128::from(transfer.bytes()) * 1_000_000_000)
                            .div_ceil(u128::from(rate));
                        sample.loaded_cost(&interfaces, address, role, transfer, nominal, now)
                    });
                Some((
                    !explore || known.is_some(),
                    cost,
                    address.source.is_none(),
                    address,
                ))
            })
            .collect::<Vec<_>>();
        drop(samples);
        ranked.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.cmp(&b.2))
                .then_with(|| a.3.cmp(&b.3))
        });
        ranked
    }
}

pub(super) fn reported_path(headers: &reqwest::header::HeaderMap) -> Option<NetworkPath> {
    headers
        .get(sccache_cluster_identity::PATH_HEADER)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Measure completed wire bodies, never truncated or abandoned ones.
pub struct MeasuredReader<R> {
    reader: R,
    book: Arc<RouteBook>,
    key: Key,
    length: Option<u64>,
    bytes: u64,
    start: Instant,
    finished: bool,
    connection: ConnectionPath,
    interface: Option<interface::Activity>,
}

impl<R> MeasuredReader<R> {
    pub fn new(
        reader: R,
        book: Arc<RouteBook>,
        peer: PeerId,
        role: Role,
        address: Route,
        length: Option<u64>,
        connection: ConnectionPath,
    ) -> Self {
        Self {
            reader,
            book,
            key: Key {
                peer,
                role,
                address,
            },
            length,
            bytes: 0,
            start: Instant::now(),
            finished: false,
            connection,
            interface: interface::activity(
                connection.local,
                Transfer::Download(length.unwrap_or(0)),
                connection
                    .local
                    .zip(connection.reported)
                    .map(|(local, path)| NetworkPath::new(local, path.local)),
            ),
        }
    }

    #[cfg(all(target_os = "linux", feature = "native-store"))]
    pub fn connection_evidence(&self) -> (ConnectionPath, Option<interface::Evidence>) {
        (
            self.connection,
            self.interface.as_ref().map(interface::Activity::evidence),
        )
    }

    pub const fn content_length(&self) -> Option<u64> {
        self.length
    }
}

impl<R: Read> Read for MeasuredReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = match self.reader.read(buffer) {
            Ok(count) => count,
            Err(error) => {
                if error.kind() != io::ErrorKind::Interrupted {
                    self.book
                        .observe(self.key.peer, self.key.role, self.key.address, None);
                }
                return Err(error);
            }
        };
        if count == 0 && !buffer.is_empty() && self.length.is_some_and(|length| self.bytes < length)
        {
            self.book
                .observe(self.key.peer, self.key.role, self.key.address, None);
        }
        self.bytes = self.bytes.saturating_add(count as u64);
        if let Some(activity) = &mut self.interface {
            activity.bytes(count as u64);
        }
        if !self.finished
            && (self.length == Some(self.bytes)
                || (self.length.is_none() && count == 0 && !buffer.is_empty()))
        {
            self.finished = true;
            if let Some(activity) = self.interface.take() {
                let evidence = activity.evidence();
                drop(activity);
                self.connection.quality = evidence.quality();
            }
            self.book.transferred(
                self.key.peer,
                self.key.role,
                self.key.address,
                Transfer::Download(self.bytes),
                self.start.elapsed(),
                self.connection,
            );
        }
        Ok(count)
    }
}

/// Discover only addresses covered by the actual listener. No DNS or
/// multicast infrastructure is required; the configured address is retained.
#[cfg(all(feature = "dist-server", target_os = "linux"))]
pub fn discover(primary: SocketAddr, bind: SocketAddr) -> RouteSet {
    if !bind.ip().is_unspecified() {
        return RouteSet::new(primary, [bind]);
    }
    RouteSet::new(primary, interface::advertised_addresses(primary, bind))
}

#[cfg(all(feature = "dist-server", target_os = "freebsd"))]
pub fn discover(primary: SocketAddr, bind: SocketAddr) -> RouteSet {
    use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
    use std::net::{IpAddr, SocketAddrV6};
    if !bind.ip().is_unspecified() {
        return RouteSet::new(primary, [bind]);
    }
    let candidates = getifaddrs()
        .into_iter()
        .flatten()
        .filter_map(|interface| {
            if !interface.flags.contains(InterfaceFlags::IFF_UP) {
                return None;
            }
            let address = interface.address?;
            if let Some(v4) = address.as_sockaddr_in() {
                Some(SocketAddr::new(IpAddr::V4(v4.ip()), bind.port()))
            } else {
                let v6 = address.as_sockaddr_in6()?;
                Some(SocketAddr::V6(SocketAddrV6::new(
                    v6.ip(),
                    bind.port(),
                    0,
                    v6.scope_id(),
                )))
            }
        })
        .filter(|address| bind.is_ipv6() || address.is_ipv4());
    RouteSet::new(primary, candidates)
}

#[cfg(all(
    feature = "dist-server",
    not(any(target_os = "linux", target_os = "freebsd"))
))]
pub fn discover(primary: SocketAddr, bind: SocketAddr) -> RouteSet {
    RouteSet::new(primary, [bind])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn busy_samples_do_not_replace_clean_rate_or_extend_its_lifetime() {
        let now = Instant::now();
        let clean = ConnectionPath {
            quality: interface::Quality::Clean,
            ..ConnectionPath::default()
        };
        let busy = ConnectionPath {
            quality: interface::Quality::Busy,
            ..clean
        };
        let fast = updated_rate(None, clean, 100 << 20, now);
        let later = now + Duration::from_secs(1);
        let observed = updated_rate(Some(fast), busy, 5 << 20, later);
        assert_eq!(observed.bytes_per_second, fast.bytes_per_second);
        assert_eq!(observed.expires, fast.expires);
        let expired = updated_rate(Some(fast), busy, 5 << 20, fast.expires);
        assert_eq!(expired.bytes_per_second, 5 << 20);
        let recovered = updated_rate(Some(expired), clean, 100 << 20, fast.expires);
        assert_eq!(recovered.bytes_per_second, 100 << 20);
    }

    #[test]
    fn route_selection_is_identity_bound_and_retains_fallback() -> anyhow::Result<()> {
        let primary = "192.0.2.1:10501".parse()?;
        let lan = "198.51.100.1:10501".parse()?;
        let routes = RouteSet::new(primary, [lan, lan, "0.0.0.0:10501".parse()?]);
        assert!(routes.valid());
        let peer = PeerId::from_digest([1; 32]);
        let other = PeerId::from_digest([2; 32]);
        let book = RouteBook::default();
        assert_eq!(
            book.ordered(peer, Role::Worker, &routes, None),
            [Route::unbound(primary)]
        );
        assert_eq!(
            book.reserve(peer, Role::Worker, &routes)
                .iter()
                .map(|probe| probe.address)
                .collect::<Vec<_>>(),
            [Route::unbound(primary), Route::unbound(lan)]
        );
        assert!(book.reserve(peer, Role::Worker, &routes).is_empty());
        book.observe(
            peer,
            Role::Worker,
            Route::unbound(primary),
            Some(Duration::from_millis(20)),
        );
        book.observe(
            peer,
            Role::Worker,
            Route::unbound(lan),
            Some(Duration::from_millis(2)),
        );
        assert_eq!(
            book.ordered(peer, Role::Worker, &routes, None),
            [Route::unbound(lan), Route::unbound(primary)]
        );
        assert_eq!(
            book.ordered(other, Role::Worker, &routes, None),
            [Route::unbound(primary)]
        );
        book.observe(peer, Role::Worker, Route::unbound(lan), None);
        assert_eq!(
            book.ordered(peer, Role::Worker, &routes, None),
            [Route::unbound(primary)]
        );
        Ok(())
    }
    #[test]
    fn route_selection_distinguishes_latency_and_direction() -> anyhow::Result<()> {
        let primary = "192.0.2.1:10501".parse()?;
        let lan = "198.51.100.1:10501".parse()?;
        let routes = RouteSet::new(primary, [lan]);
        let peer = PeerId::from_digest([1; 32]);
        let book = RouteBook::default();
        book.observe(
            peer,
            Role::Worker,
            Route::unbound(primary),
            Some(Duration::from_millis(1)),
        );
        book.observe(
            peer,
            Role::Worker,
            Route::unbound(lan),
            Some(Duration::from_millis(10)),
        );
        for (address, upload, download) in [(primary, 2, 100), (lan, 100, 2)] {
            book.transferred(
                peer,
                Role::Worker,
                Route::unbound(address),
                Transfer::Upload(upload << 20),
                Duration::from_secs(1),
                ConnectionPath::reported(None),
            );
            book.transferred(
                peer,
                Role::Worker,
                Route::unbound(address),
                Transfer::Download(download << 20),
                Duration::from_secs(1),
                ConnectionPath::reported(None),
            );
        }
        assert_eq!(
            book.ordered(peer, Role::Worker, &routes, None),
            [Route::unbound(primary), Route::unbound(lan)]
        );
        assert_eq!(
            book.ordered(
                peer,
                Role::Worker,
                &routes,
                Some(Transfer::Upload(100 << 20))
            ),
            [Route::unbound(lan), Route::unbound(primary)]
        );
        assert_eq!(
            book.ordered(
                peer,
                Role::Worker,
                &routes,
                Some(Transfer::Download(100 << 20))
            ),
            [Route::unbound(primary), Route::unbound(lan)]
        );
        Ok(())
    }
    #[test]
    fn changed_source_does_not_reuse_rate_or_invalidate_other_pool() -> anyhow::Result<()> {
        let primary = "192.0.2.1:10501".parse()?;
        let peer = PeerId::from_digest([1; 32]);
        let routes = RouteSet::new(primary, []);
        let book = RouteBook::default();
        let first = "192.0.2.1,192.0.2.2".parse()?;
        let second = "192.0.2.1,192.0.2.3".parse()?;
        book.observe_path(
            peer,
            Role::Scheduler,
            Route::unbound(primary),
            Some(Duration::from_millis(1)),
            ConnectionPath::reported(Some(first)),
        );
        for transfer in [Transfer::Upload(32 << 20), Transfer::Download(32 << 20)] {
            book.transferred(
                peer,
                Role::Scheduler,
                Route::unbound(primary),
                transfer,
                Duration::from_secs(1),
                ConnectionPath::reported(Some(first)),
            );
        }
        assert_eq!(
            book.best_rate(peer, Role::Scheduler, &routes, Transfer::Download(0))
                .map(|rate| rate.path),
            Some(first)
        );
        book.observe_path(
            peer,
            Role::Scheduler,
            Route::unbound(primary),
            Some(Duration::from_millis(1)),
            ConnectionPath::reported(Some(second)),
        );
        assert!(
            book.best_rate(peer, Role::Scheduler, &routes, Transfer::Download(0))
                .is_none()
        );
        assert_eq!(
            book.best_rate(peer, Role::Scheduler, &routes, Transfer::Upload(0)),
            Some(CachePathRate {
                path: first,
                bytes_per_second: 32 << 20
            })
        );
        book.transferred(
            peer,
            Role::Scheduler,
            Route::unbound(primary),
            Transfer::Upload(4 << 20),
            Duration::from_secs(1),
            ConnectionPath::reported(Some(second)),
        );
        assert_eq!(
            book.best_rate(peer, Role::Scheduler, &routes, Transfer::Upload(0)),
            Some(CachePathRate {
                path: second,
                bytes_per_second: 4 << 20
            })
        );
        Ok(())
    }
    #[cfg(all(target_os = "linux", feature = "native-store"))]
    #[test]
    fn only_verified_current_peer_rates_enter_the_snapshot() -> anyhow::Result<()> {
        let peer = PeerId::from_digest([1; 32]);
        let endpoint = "192.168.76.1:10501".parse()?;
        let path = "192.168.76.1,192.168.76.2".parse()?;
        let book = RouteBook::default();
        book.observe_path(
            peer,
            Role::Worker,
            Route::unbound(endpoint),
            Some(Duration::from_millis(2)),
            ConnectionPath::reported(Some(path)),
        );
        book.transferred(
            peer,
            Role::Worker,
            Route::unbound(endpoint),
            Transfer::Download(4 << 20),
            Duration::from_secs(1),
            ConnectionPath::reported(Some(path)),
        );
        assert!(book.peer_download_rates().is_empty());
        book.verified_download(
            peer,
            Route::unbound(endpoint),
            ConnectionPath::reported(Some(path)),
            8 << 20,
            Some(4 << 20),
            Duration::from_secs(1),
        );
        assert_eq!(
            book.peer_download_rates(),
            [PeerDownloadRate {
                source: peer,
                path,
                logical_bytes_per_second: 8 << 20,
                wire_per_mille: 500,
            }]
        );
        book.observe_path(
            peer,
            Role::Worker,
            Route::unbound(endpoint),
            Some(Duration::from_millis(2)),
            ConnectionPath::reported(Some("192.168.76.1,192.168.76.3".parse()?)),
        );
        assert!(book.peer_download_rates().is_empty());
        Ok(())
    }
}
