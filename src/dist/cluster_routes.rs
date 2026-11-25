//! Short-lived, authenticated path measurements. A peer's identity remains
//! independent of the currently preferred interface.
use crate::build_runtime::wire::CachePathRate;
use sccache_peer_identity::{NetworkPath, PeerId, Role, RouteSet};
use std::{
    collections::HashMap,
    io::{self, Read},
    net::SocketAddr,
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

/// Global admission for probe tasks, released on cancellation as well.
pub struct Probe {
    pub address: SocketAddr,
}

impl Probe {
    fn acquire(address: SocketAddr) -> Option<Self> {
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
    bytes_per_second: u64,
    expires: Instant,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct Key {
    peer: PeerId,
    role: Role,
    address: SocketAddr,
}

#[derive(Clone, Copy)]
struct Sample {
    measured: Option<Duration>,
    expires: Instant,
    rates: [Option<Rate>; 2],
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
        if routes.alternatives.is_empty() || !routes.valid() {
            return Vec::new();
        }
        let now = Instant::now();
        let mut samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        if samples.len() >= MAX_PATHS {
            samples.retain(|_, sample| {
                sample.expires > now || sample.rates.iter().flatten().any(|rate| rate.expires > now)
            });
        }
        let mut pending = Vec::new();
        for address in routes.iter() {
            let key = Key {
                peer,
                role,
                address,
            };
            if samples.get(&key).is_some_and(|sample| sample.expires > now)
                || (samples.len() >= MAX_PATHS && !samples.contains_key(&key))
            {
                continue;
            }
            let Some(probe) = Probe::acquire(address) else {
                break;
            };
            let sample = samples.entry(key).or_insert(Sample {
                measured: None,
                expires: now,
                rates: [None; 2],
            });
            sample.expires = now + FAILURE_TTL;
            // Expired observations cannot qualify a path while its refresh is pending.
            sample.measured = None;
            pending.push(probe);
        }
        drop(samples);
        pending
    }

    pub fn observe(
        &self,
        peer: PeerId,
        role: Role,
        address: SocketAddr,
        elapsed: Option<Duration>,
    ) {
        self.observe_path(peer, role, address, elapsed, None);
    }

    pub fn observe_path(
        &self,
        peer: PeerId,
        role: Role,
        address: SocketAddr,
        elapsed: Option<Duration>,
        path: Option<NetworkPath>,
    ) {
        let mut samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        let key = Key {
            peer,
            role,
            address,
        };
        if samples.len() < MAX_PATHS || samples.contains_key(&key) {
            let sample = samples.entry(key).or_insert_with(|| Sample {
                measured: None,
                expires: Instant::now(),
                rates: [None; 2],
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
            sample.measured = elapsed;
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
        address: SocketAddr,
        transfer: Transfer,
        elapsed: Duration,
        path: Option<NetworkPath>,
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
            expires: now,
            rates: [None; 2],
        });
        let slot = &mut sample.rates[transfer.index()];
        let observed = u64::try_from(
            (u128::from(transfer.bytes()) * 1_000_000_000 / elapsed.as_nanos())
                .clamp(64 * 1024, 1_000_000_000_000),
        )
        .unwrap_or(1_000_000_000_000);
        let rate = slot
            .filter(|rate| rate.expires > now && rate.path == path)
            .map_or(observed, |rate| {
                (rate.bytes_per_second + observed).div_ceil(2)
            });
        *slot = Some(Rate {
            path,
            bytes_per_second: rate,
            expires: now + RATE_TTL,
        });
        drop(samples);
    }

    pub fn best_rate(
        &self,
        peer: PeerId,
        role: Role,
        routes: &RouteSet,
        transfer: Transfer,
    ) -> Option<CachePathRate> {
        let now = Instant::now();
        let samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        routes
            .iter()
            .filter_map(|address| {
                let sample = samples.get(&Key {
                    peer,
                    role,
                    address,
                })?;
                // Alternate paths require a fresh authenticated reachability probe.
                // An actually used configured primary needs no extra probe when it
                // is the only endpoint; a recent failure disqualifies either path.
                let usable = if address == routes.primary {
                    sample.measured.is_some() || sample.expires <= now
                } else {
                    sample.measured.is_some() && sample.expires > now
                };
                if !usable {
                    return None;
                }
                sample.rates[transfer.index()]
                    .filter(|rate| rate.expires > now)
                    .and_then(|rate| {
                        Some(CachePathRate {
                            path: rate.path?,
                            bytes_per_second: rate.bytes_per_second,
                        })
                    })
            })
            .max_by_key(|rate| rate.bytes_per_second)
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
    ) -> Vec<SocketAddr> {
        let now = Instant::now();
        let samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        let rate = |address| {
            transfer.and_then(|transfer| {
                samples
                    .get(&Key {
                        peer,
                        role,
                        address,
                    })?
                    .rates[transfer.index()]
                .filter(|rate| rate.expires > now)
                .map(|rate| rate.bytes_per_second)
            })
        };
        let baseline = routes.iter().filter_map(rate).max().unwrap_or(DEFAULT_RATE);
        let explore = transfer.is_some_and(|transfer| transfer.bytes() >= MIN_SAMPLE_BYTES)
            && self
                .transfers
                .fetch_add(1, Ordering::Relaxed)
                .is_multiple_of(16);
        let mut ranked = routes
            .iter()
            .filter_map(|address| {
                let sample = samples.get(&Key {
                    peer,
                    role,
                    address,
                })?;
                let rtt = (sample.expires > now)
                    .then_some(sample.measured)
                    .flatten()?;
                let known = rate(address);
                let cost = rtt.as_nanos()
                    + transfer.map_or(0, |transfer| {
                        (u128::from(transfer.bytes()) * 1_000_000_000)
                            .div_ceil(u128::from(known.unwrap_or(baseline)))
                    });
                Some((
                    !explore || known.is_some(),
                    cost,
                    address != routes.primary,
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
        let mut result = ranked
            .into_iter()
            .map(|(_, _, _, address)| address)
            .collect::<Vec<_>>();
        if !result.contains(&routes.primary) {
            result.push(routes.primary);
        }
        result
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
    path: Option<NetworkPath>,
}

impl<R> MeasuredReader<R> {
    pub fn new(
        reader: R,
        book: Arc<RouteBook>,
        peer: PeerId,
        role: Role,
        address: SocketAddr,
        length: Option<u64>,
        path: Option<NetworkPath>,
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
            path,
        }
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
        if !self.finished
            && (self.length == Some(self.bytes)
                || (self.length.is_none() && count == 0 && !buffer.is_empty()))
        {
            self.finished = true;
            self.book.transferred(
                self.key.peer,
                self.key.role,
                self.key.address,
                Transfer::Download(self.bytes),
                self.start.elapsed(),
                self.path,
            );
        }
        Ok(count)
    }
}

/// Discover only addresses covered by the actual listener. No DNS or
/// multicast infrastructure is required; the configured address is retained.
#[cfg(all(
    feature = "dist-server",
    any(target_os = "linux", target_os = "freebsd")
))]
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
            if !interface.flags.contains(InterfaceFlags::IFF_UP)
                || interface.flags.contains(InterfaceFlags::IFF_LOOPBACK)
            {
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
    fn route_selection_is_identity_bound_and_retains_fallback() -> anyhow::Result<()> {
        let primary = "100.64.0.1:10501".parse()?;
        let lan = "192.168.0.1:10501".parse()?;
        let routes = RouteSet::new(primary, [lan, lan, "0.0.0.0:10501".parse()?]);
        assert!(routes.valid());
        let peer = PeerId::from_digest([1; 32]);
        let other = PeerId::from_digest([2; 32]);
        let book = RouteBook::default();
        assert_eq!(book.ordered(peer, Role::Worker, &routes, None), [primary]);
        assert_eq!(
            book.reserve(peer, Role::Worker, &routes)
                .iter()
                .map(|probe| probe.address)
                .collect::<Vec<_>>(),
            [primary, lan]
        );
        assert!(book.reserve(peer, Role::Worker, &routes).is_empty());
        book.observe(peer, Role::Worker, primary, Some(Duration::from_millis(20)));
        book.observe(peer, Role::Worker, lan, Some(Duration::from_millis(2)));
        assert_eq!(
            book.ordered(peer, Role::Worker, &routes, None),
            [lan, primary]
        );
        assert_eq!(book.ordered(other, Role::Worker, &routes, None), [primary]);
        book.observe(peer, Role::Worker, lan, None);
        assert_eq!(book.ordered(peer, Role::Worker, &routes, None), [primary]);
        Ok(())
    }
    #[test]
    fn route_selection_distinguishes_latency_and_direction() -> anyhow::Result<()> {
        let primary = "100.64.0.1:10501".parse()?;
        let lan = "192.168.0.1:10501".parse()?;
        let routes = RouteSet::new(primary, [lan]);
        let peer = PeerId::from_digest([1; 32]);
        let book = RouteBook::default();
        book.observe(peer, Role::Worker, primary, Some(Duration::from_millis(1)));
        book.observe(peer, Role::Worker, lan, Some(Duration::from_millis(10)));
        for (address, upload, download) in [(primary, 2, 100), (lan, 100, 2)] {
            book.transferred(
                peer,
                Role::Worker,
                address,
                Transfer::Upload(upload << 20),
                Duration::from_secs(1),
                None,
            );
            book.transferred(
                peer,
                Role::Worker,
                address,
                Transfer::Download(download << 20),
                Duration::from_secs(1),
                None,
            );
        }
        assert_eq!(
            book.ordered(peer, Role::Worker, &routes, None),
            [primary, lan]
        );
        assert_eq!(
            book.ordered(
                peer,
                Role::Worker,
                &routes,
                Some(Transfer::Upload(100 << 20))
            ),
            [lan, primary]
        );
        assert_eq!(
            book.ordered(
                peer,
                Role::Worker,
                &routes,
                Some(Transfer::Download(100 << 20))
            ),
            [primary, lan]
        );
        Ok(())
    }
    #[test]
    fn changed_source_does_not_reuse_rate_or_invalidate_other_pool() -> anyhow::Result<()> {
        let primary = "100.64.0.1:10501".parse()?;
        let peer = PeerId::from_digest([1; 32]);
        let routes = RouteSet::new(primary, []);
        let book = RouteBook::default();
        let first = "100.64.0.1,100.64.0.2".parse()?;
        let second = "100.64.0.1,100.64.0.3".parse()?;
        book.observe_path(
            peer,
            Role::Scheduler,
            primary,
            Some(Duration::from_millis(1)),
            Some(first),
        );
        for transfer in [Transfer::Upload(32 << 20), Transfer::Download(32 << 20)] {
            book.transferred(
                peer,
                Role::Scheduler,
                primary,
                transfer,
                Duration::from_secs(1),
                Some(first),
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
            primary,
            Some(Duration::from_millis(1)),
            Some(second),
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
            primary,
            Transfer::Upload(4 << 20),
            Duration::from_secs(1),
            Some(second),
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
}
