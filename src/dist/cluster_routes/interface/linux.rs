//! Linux interface counters include traffic from every process. Local address
//! ownership is refreshed on demand; ambiguous addresses supply no evidence.
#[cfg(feature = "dist-server")]
mod meter_window;
mod overlap;
use super::{Evidence, Quality, SAMPLE_INTERVAL, Transfer};
use crate::build_runtime::{
    Direction, NetworkPath,
    wire::{EndpointFlow, EndpointOverlap},
};
#[cfg(feature = "dist-server")]
pub(in crate::dist) use meter_window::MeterSampler;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, LazyLock, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const TTL: Duration = Duration::from_secs(30);
const MAX_INTERFACES: usize = 256;
const SCALE: u64 = 1000;

#[derive(Default)]
struct Counters {
    active: AtomicU64,
    generation: AtomicU64,
    unattributed: AtomicU64,
    unknown_epoch: AtomicU64,
    managed: AtomicU64,
}
struct Sample {
    total: u64,
    managed: u64,
    rate: u64,
    external: u64,
    peak: u64,
    peak_at: Instant,
    aligned: bool,
    unknown_epoch: u64,
    counters: Arc<Counters>,
}

impl Sample {
    fn new(total: u64, now: Instant) -> Self {
        Self {
            total,
            managed: 0,
            rate: 0,
            external: 0,
            peak: 0,
            peak_at: now,
            aligned: false,
            unknown_epoch: 0,
            counters: Arc::default(),
        }
    }

    fn update(&mut self, total: u64, now: Instant, elapsed: Duration) {
        let managed = self.counters.managed.load(Ordering::Relaxed);
        let unknown_epoch = self.counters.unknown_epoch.load(Ordering::Relaxed);
        // Link replacement, counter reset or suspended sampling invalidates
        // this window rather than introducing a huge unsigned delta.
        if let Some(bytes) = total.checked_sub(self.total).filter(|_| elapsed <= TTL) {
            let own = managed.wrapping_sub(self.managed);
            self.rate = per_second(bytes, elapsed);
            self.external = per_second(bytes.saturating_sub(own), elapsed);
            self.aligned = bytes >= own.saturating_mul(9) / 10
                && bytes.saturating_sub(own) <= own / 8 + (64 << 10)
                && self.counters.unattributed.load(Ordering::Relaxed) == 0
                && unknown_epoch == self.unknown_epoch;
            if now.duration_since(self.peak_at) >= TTL || self.rate >= self.peak {
                self.peak = self.rate;
                self.peak_at = now;
            }
        } else {
            self.rate = 0;
            self.external = 0;
            self.peak = 0;
            self.aligned = false;
            self.peak_at = now;
        }
        self.total = total;
        self.managed = managed;
        self.unknown_epoch = unknown_epoch;
    }
}

fn per_second(bytes: u64, elapsed: Duration) -> u64 {
    u64::try_from(u128::from(bytes) * 1_000_000_000 / elapsed.as_nanos().max(1)).unwrap_or(u64::MAX)
}

struct Link {
    index: u32,
    // Reported nominal speed is only available for real, non-wireless
    // Ethernet devices. Never infer an independent physical capacity
    // from a TUN, bridge, VLAN, or other virtual interface.
    ceiling: Option<u64>,
    directions: [Sample; 2],
}

struct Book {
    updated: Option<Instant>,
    addresses: BTreeMap<IpAddr, LocalAddress>,
    links: BTreeMap<String, Link>,
    overlap: overlap::Learner,
}

static BOOK: LazyLock<Mutex<Book>> = LazyLock::new(|| {
    Mutex::new(Book {
        updated: None,
        addresses: BTreeMap::new(),
        links: BTreeMap::new(),
        overlap: overlap::Learner::default(),
    })
});

#[derive(Clone)]
struct LocalAddress {
    name: String,
    mask: IpAddr,
}

fn interface_priority(name: &str) -> u8 {
    if name == "lo" {
        0
    } else if Path::new("/sys/class/net")
        .join(name)
        .join("device")
        .exists()
    {
        1
    } else {
        2
    }
}

fn on_link(source: IpAddr, mask: IpAddr, destination: IpAddr) -> bool {
    match (source, mask, destination) {
        (IpAddr::V4(source), IpAddr::V4(mask), IpAddr::V4(destination)) => {
            let mask = u32::from(mask);
            u32::from(source) & mask == u32::from(destination) & mask
        }
        (IpAddr::V6(source), IpAddr::V6(mask), IpAddr::V6(destination)) => {
            let mask = u128::from(mask);
            u128::from(source) & mask == u128::from(destination) & mask
        }
        _ => false,
    }
}

fn interface_addresses() -> BTreeMap<IpAddr, LocalAddress> {
    use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
    let mut addresses = BTreeMap::<IpAddr, LocalAddress>::new();
    let mut ambiguous = BTreeSet::new();
    for entry in getifaddrs().into_iter().flatten() {
        if !entry
            .flags
            .contains(InterfaceFlags::IFF_UP | InterfaceFlags::IFF_RUNNING)
        {
            continue;
        }
        let Some(address) = entry.address else {
            continue;
        };
        let Some(mask) = entry.netmask else {
            continue;
        };
        let (ip, mask) = if let (Some(v4), Some(mask)) =
            (address.as_sockaddr_in(), mask.as_sockaddr_in())
        {
            (IpAddr::V4(v4.ip()), IpAddr::V4(mask.ip()))
        } else if let (Some(v6), Some(mask)) = (address.as_sockaddr_in6(), mask.as_sockaddr_in6()) {
            (IpAddr::V6(v6.ip()), IpAddr::V6(mask.ip()))
        } else {
            continue;
        };
        if addresses
            .get(&ip)
            .is_some_and(|old| old.name != entry.interface_name)
        {
            ambiguous.insert(ip);
        }
        addresses.insert(
            ip,
            LocalAddress {
                name: entry.interface_name,
                mask,
            },
        );
    }
    addresses.retain(|ip, _| !ambiguous.contains(ip));
    addresses
}

fn counters(contents: &str) -> impl Iterator<Item = (&str, [u64; 2])> {
    contents.lines().filter_map(|line| {
        let (name, fields) = line.split_once(':')?;
        let mut fields = fields.split_whitespace();
        let rx = fields.next()?.parse().ok()?;
        let tx = fields.nth(7)?.parse().ok()?;
        Some((name.trim(), [tx, rx]))
    })
}

fn read_number<T: std::str::FromStr>(path: &Path) -> Option<T> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn ethernet_ceiling(path: &Path) -> Option<u64> {
    if !path.join("device").exists()
        || path.join("wireless").exists()
        || path.join("phy80211").exists()
        || read_number::<u32>(&path.join("type"))? != 1
        || fs::read_to_string(path.join("duplex")).ok()?.trim() != "full"
    {
        return None;
    }
    let speed = read_number::<u64>(&path.join("speed"))?;
    (speed > 0 && speed <= 1_000_000).then_some(speed.saturating_mul(125_000))
}

impl Book {
    fn refresh(&mut self, now: Instant) {
        let elapsed = self
            .updated
            .map_or(Duration::ZERO, |updated| now.duration_since(updated));
        if self.updated.is_some() && elapsed < SAMPLE_INTERVAL {
            return;
        }
        let Ok(contents) = fs::read_to_string("/proc/net/dev") else {
            self.links.clear();
            self.addresses.clear();
            self.updated = None;
            self.overlap = overlap::Learner::default();
            return;
        };
        let mut seen = BTreeSet::new();
        for (name, total) in counters(&contents).take(MAX_INTERFACES) {
            let path = Path::new("/sys/class/net").join(name);
            let Some(index) = read_number::<u32>(&path.join("ifindex")) else {
                continue;
            };
            seen.insert(name);
            let link = self.links.entry(name.to_owned()).or_insert_with(|| Link {
                index,
                ceiling: ethernet_ceiling(&path),
                directions: total.map(|bytes| Sample::new(bytes, now)),
            });
            if link.index != index {
                *link = Link {
                    index,
                    ceiling: ethernet_ceiling(&path),
                    directions: total.map(|bytes| Sample::new(bytes, now)),
                };
            } else if !elapsed.is_zero() {
                for (sample, bytes) in link.directions.iter_mut().zip(total) {
                    sample.update(bytes, now, elapsed);
                }
                link.ceiling = ethernet_ceiling(&path);
            }
        }
        self.links.retain(|name, _| seen.contains(name.as_str()));
        self.addresses = interface_addresses();
        if !elapsed.is_zero() {
            let addresses = &self.addresses;
            let links = &self.links;
            self.overlap.sample(now, elapsed, |flow| {
                let index = match flow.direction {
                    Direction::Send => 0,
                    Direction::Receive => 1,
                };
                addresses
                    .get(&flow.path.local)
                    .and_then(|address| links.get(&address.name))
                    .is_some_and(|link| link.directions[index].aligned)
            });
        }
        self.updated = Some(now);
    }
}

/// A body stream increments its managed payload bytes and releases its
/// active reservation on EOF, early response, cancellation or error.
pub(in crate::dist) struct Activity {
    counters: Arc<Counters>,
    stat: PathBuf,
    start_total: Option<u64>,
    start_active: u64,
    generation: u64,
    bytes: u64,
    evidence: Evidence,
    flow: Option<Arc<overlap::Counters>>,
    next_sample: Instant,
}

fn classify(start: Option<u64>, end: Option<u64>, bytes: u64, overlapped: bool) -> Quality {
    if overlapped {
        return Quality::Busy;
    }
    let Some(total) = start
        .zip(end)
        .and_then(|(start, end)| end.checked_sub(start))
    else {
        return Quality::Unknown;
    };
    // Socket buffering, offload and protocol overhead make body byte and
    // interface counter boundaries approximate. Only classify substantial,
    // aligned windows; never infer an isolated rate from missing counters.
    if bytes < 1 << 20 || total < bytes.saturating_mul(9) / 10 {
        return Quality::Unknown;
    }
    if total.saturating_sub(bytes) > bytes / 8 + (64 << 10) {
        Quality::Busy
    } else {
        Quality::Clean
    }
}

impl Activity {
    pub(in crate::dist) fn bytes(&mut self, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.counters.managed.fetch_add(bytes, Ordering::Relaxed);
        if let Some(flow) = &self.flow {
            flow.bytes(bytes);
        }
        let now = Instant::now();
        if now >= self.next_sample {
            self.next_sample = now + SAMPLE_INTERVAL;
            if let Ok(mut book) = BOOK.try_lock() {
                book.refresh(now);
            }
        }
    }

    pub(in crate::dist) fn evidence(&self) -> Evidence {
        self.evidence.clone()
    }
}

impl Drop for Activity {
    fn drop(&mut self) {
        let overlapped = self.start_active != 0
            || self.counters.generation.load(Ordering::Relaxed) != self.generation;
        self.evidence.record(classify(
            self.start_total,
            read_number(&self.stat),
            self.bytes,
            overlapped,
        ));
        // Synchronize lifecycle transitions with the aligned window sampler.
        let mut book = BOOK.lock().unwrap_or_else(PoisonError::into_inner);
        book.refresh(Instant::now());
        if let Some(flow) = &self.flow {
            flow.finish();
        } else {
            self.counters.unattributed.fetch_sub(1, Ordering::Relaxed);
        }
        self.counters.active.fetch_sub(1, Ordering::Relaxed);
        drop(book);
    }
}

pub(in crate::dist) fn activity(
    local: Option<IpAddr>,
    transfer: Transfer,
    path: Option<NetworkPath>,
) -> Option<Activity> {
    let local = local?;
    if transfer.bytes() < 256 * 1024 {
        return None;
    }
    let mut book = BOOK.lock().unwrap_or_else(PoisonError::into_inner);
    let now = Instant::now();
    book.refresh(now);
    let name = &book.addresses.get(&local)?.name;
    let link = book.links.get(name)?;
    let counters = Arc::clone(&link.directions[transfer.index()].counters);
    let stat = Path::new("/sys/class/net")
        .join(name)
        .join("statistics")
        .join(match transfer {
            Transfer::Upload(_) => "tx_bytes",
            Transfer::Download(_) => "rx_bytes",
        });
    let start_total = read_number(&stat);
    let start_active = counters.active.fetch_add(1, Ordering::Relaxed);
    let generation = counters
        .generation
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    let direction = match transfer {
        Transfer::Upload(_) => Direction::Send,
        Transfer::Download(_) => Direction::Receive,
    };
    let flow = path
        .filter(|path| {
            path.local == local
                && path.valid()
                && !path.local.is_loopback()
                && !path.remote.is_loopback()
        })
        .and_then(|path| book.overlap.start(EndpointFlow { path, direction }, now));
    if flow.is_none() {
        counters.unattributed.fetch_add(1, Ordering::Relaxed);
        counters.unknown_epoch.fetch_add(1, Ordering::Relaxed);
    }
    drop(book);
    Some(Activity {
        counters,
        stat,
        start_total,
        start_active,
        generation,
        bytes: 0,
        evidence: Evidence::default(),
        flow,
        next_sample: now + SAMPLE_INTERVAL,
    })
}

#[derive(Clone, Copy)]
struct Load {
    active: u64,
    rate: u64,
    external: u64,
    observed: u64,
    ceiling: Option<u64>,
}

/// A single coherent local snapshot is reused for every competing route.
pub(in crate::dist) struct Snapshot {
    addresses: BTreeMap<IpAddr, [Load; 2]>,
    active: BTreeMap<EndpointFlow, u64>,
    overlaps: Vec<EndpointOverlap>,
}

impl Load {
    fn cost(self, clean_wire_rate: Option<u64>, predicted: u128) -> u128 {
        // Do not infer a capacity from an idle or lightly utilized link.
        // An observed peak is merely a conservative service prior; nominal
        // Ethernet line rate, when known, bounds the available headroom.
        let Some(capacity) = self
            .ceiling
            .or_else(|| clean_wire_rate.map(|rate| rate.max(self.observed)))
        else {
            return predicted.saturating_mul(u128::from(self.active.saturating_add(1)));
        };
        let external = self.external.min(self.rate).min(capacity);
        let remaining = capacity.saturating_sub(external).max(capacity / 8).max(1);
        let penalty = u64::try_from(
            (u128::from(capacity) * u128::from(SCALE)).div_ceil(u128::from(remaining)),
        )
        .unwrap_or(u64::MAX);
        // Managed bytes have already been subtracted from external load.
        // Competing active streams share the remaining service, not the
        // entire interface rate a second time.
        predicted
            .saturating_mul(u128::from(penalty))
            .saturating_mul(u128::from(self.active.saturating_add(1)))
            .div_ceil(u128::from(SCALE))
    }
}

impl Snapshot {
    pub(in crate::dist) fn cost(
        &self,
        local: Option<IpAddr>,
        transfer: Transfer,
        clean_wire_rate: Option<u64>,
        predicted: u128,
    ) -> u128 {
        local
            .and_then(|local| self.addresses.get(&local))
            .map_or(predicted, |load| {
                load[transfer.index()].cost(clean_wire_rate, predicted)
            })
    }

    /// A learned cross-interface bottleneck is charged only while its
    /// actual peer flow is active. It is an additional lower bound, not
    /// an additive penalty on the already-accounted local interface.
    pub(in crate::dist) fn overlap_cost(
        &self,
        path: Option<NetworkPath>,
        transfer: Transfer,
        wire_bytes: u64,
        predicted: u128,
    ) -> u128 {
        let Some(path) = path else {
            return predicted;
        };
        let direction = match transfer {
            Transfer::Upload(_) => Direction::Send,
            Transfer::Download(_) => Direction::Receive,
        };
        let flow = EndpointFlow { path, direction };
        let own = self.active.get(&flow).copied().unwrap_or(0);
        self.overlaps
            .iter()
            .filter_map(|overlap| {
                let other = overlap
                    .flows
                    .iter()
                    .copied()
                    .find(|&key| key != flow && overlap.flows.contains(&flow))?;
                let active = self.active.get(&other).copied()?;
                let participants = own.saturating_add(active).saturating_add(1);
                Some(
                    (u128::from(wire_bytes) * 1_000_000_000 * u128::from(participants))
                        .div_ceil(u128::from(overlap.bytes_per_second)),
                )
            })
            .fold(predicted, u128::max)
    }
}

pub(in crate::dist) fn snapshot() -> Snapshot {
    let mut book = BOOK.lock().unwrap_or_else(PoisonError::into_inner);
    book.refresh(Instant::now());
    let addresses = book
        .addresses
        .iter()
        .filter_map(|(&address, name)| {
            let link = book.links.get(&name.name)?;
            Some((
                address,
                link.directions.each_ref().map(|sample| Load {
                    active: sample.counters.active.load(Ordering::Relaxed),
                    rate: sample.rate,
                    external: sample.external,
                    observed: sample.peak,
                    ceiling: link.ceiling,
                }),
            ))
        })
        .collect();
    let active = book.overlap.active();
    let overlaps = book.overlap.report(Instant::now());
    drop(book);
    Snapshot {
        addresses,
        active,
        overlaps,
    }
}

pub(in crate::dist) fn report() -> crate::build_runtime::wire::InterfaceReport {
    use crate::build_runtime::wire::{InterfaceDirection, InterfaceReport, InterfaceTraffic};
    let mut book = BOOK.lock().unwrap_or_else(PoisonError::into_inner);
    book.refresh(Instant::now());
    let mut groups = BTreeMap::<&str, Vec<IpAddr>>::new();
    for (&ip, address) in &book.addresses {
        if sccache_peer_identity::RouteSet::eligible(std::net::SocketAddr::new(ip, 1)) {
            groups.entry(&address.name).or_default().push(ip);
        }
    }
    let mut groups = groups.into_iter().collect::<Vec<_>>();
    groups.sort_unstable_by_key(|(name, _)| (interface_priority(name), *name));
    let direction = |sample: &Sample| InterfaceDirection {
        total_bytes_per_second: sample.rate.min(1_000_000_000_000),
        external_bytes_per_second: sample.external.min(sample.rate).min(1_000_000_000_000),
        active_streams: u32::try_from(sample.counters.active.load(Ordering::Relaxed).min(4096))
            .unwrap_or(4096),
    };
    let mut interfaces = groups
        .into_iter()
        .take(16)
        .filter_map(|(name, mut addresses)| {
            let link = book.links.get(name)?;
            addresses.truncate(8);
            Some(InterfaceTraffic {
                index: link.index,
                addresses,
                nominal_capacity: link.ceiling,
                send: direction(&link.directions[0]),
                receive: direction(&link.directions[1]),
            })
        })
        .collect::<Vec<_>>();
    let mut overlaps = book.overlap.report(Instant::now());
    drop(book);
    interfaces.sort_unstable_by_key(|interface| interface.index);
    overlaps.retain(|overlap| {
        overlap.flows.iter().all(|flow| {
            interfaces
                .iter()
                .any(|interface| interface.addresses.binary_search(&flow.path.local).is_ok())
        })
    });
    InterfaceReport {
        interfaces,
        overlaps,
    }
}

pub(in crate::dist) fn binding(ip: IpAddr) -> Option<String> {
    let mut book = BOOK.lock().unwrap_or_else(PoisonError::into_inner);
    book.refresh(Instant::now());
    book.addresses.get(&ip).map(|address| address.name.clone())
}

/// One directly reachable source address per local interface and remote
/// endpoint. Keep the kernel's unbound route as an independent fallback.
pub(in crate::dist) fn direct_sources(destination: IpAddr) -> Vec<IpAddr> {
    use sccache_peer_identity::RouteSet;
    let mut book = BOOK.lock().unwrap_or_else(PoisonError::into_inner);
    book.refresh(Instant::now());
    let mut names = BTreeSet::new();
    let mut candidates = book
        .addresses
        .iter()
        .filter(|(source, address)| {
            !destination.is_loopback()
                && **source != destination
                && !source.is_loopback()
                && RouteSet::eligible(std::net::SocketAddr::new(**source, 1))
                && on_link(**source, address.mask, destination)
        })
        .collect::<Vec<_>>();
    candidates
        .sort_unstable_by_key(|(source, address)| (interface_priority(&address.name), **source));
    let sources = candidates
        .into_iter()
        .filter_map(|(&source, address)| names.insert(address.name.as_str()).then_some(source))
        .take(4)
        .collect();
    drop(book);
    sources
}

#[cfg(feature = "dist-server")]
pub(in crate::dist) fn advertised_addresses(
    primary: std::net::SocketAddr,
    bind: std::net::SocketAddr,
) -> Vec<std::net::SocketAddr> {
    use sccache_peer_identity::RouteSet;
    use std::net::SocketAddr;
    let addresses = interface_addresses();
    let ipv4_only = bind.is_ipv4();
    let mut candidates = addresses
        .iter()
        .filter_map(|(&ip, address)| {
            let socket = SocketAddr::new(ip, bind.port());
            (socket != primary && (!ipv4_only || ip.is_ipv4()) && RouteSet::eligible(socket))
                .then_some((socket, address.name.as_str()))
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|(socket, name)| (interface_priority(name), *name, *socket));
    // First give each interface/family a slot; then include additional
    // addresses where the canonical bounded advertisement has room.
    let mut seen = BTreeSet::new();
    let (first, rest): (Vec<_>, Vec<_>) = candidates
        .into_iter()
        .partition(|(socket, name)| seen.insert((*name, socket.is_ipv4())));
    let ordered = first
        .into_iter()
        .chain(rest)
        .map(|(socket, _)| socket)
        .collect::<Vec<_>>();
    let mut v4 = ordered.iter().copied().filter(SocketAddr::is_ipv4);
    let mut v6 = ordered.iter().copied().filter(SocketAddr::is_ipv6);
    let mut result = Vec::new();
    while result.len() < RouteSet::MAX_ALTERNATIVES {
        let next = if result.len().is_multiple_of(2) {
            v4.next().or_else(|| v6.next())
        } else {
            v6.next().or_else(|| v4.next())
        };
        let Some(next) = next else {
            break;
        };
        result.push(next);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_interface_traffic_is_sampled_without_double_counting_managed_payload() {
        let now = Instant::now();
        let mut sample = Sample::new(10, now);
        sample.counters.managed.store(40 << 20, Ordering::Relaxed);
        sample.update(
            10 + (100 << 20),
            now + Duration::from_secs(1),
            Duration::from_secs(1),
        );
        assert_eq!(sample.rate, 100 << 20);
        assert_eq!(sample.external, 60 << 20);
        let loaded = Load {
            active: 1,
            rate: sample.rate,
            external: sample.external,
            observed: sample.peak,
            ceiling: Some(120 << 20),
        };
        assert_eq!(loaded.cost(None, 1000), 4000);
        assert_eq!(
            Load {
                active: 0,
                external: 0,
                ..loaded
            }
            .cost(None, 1000),
            1000
        );
        sample.update(1, now + Duration::from_secs(2), Duration::from_secs(1));
        assert_eq!(sample.rate, 0);
        assert_eq!(sample.external, 0);
    }

    #[test]
    fn learned_overlap_only_penalizes_active_matching_pair() -> anyhow::Result<()> {
        let a = EndpointFlow {
            path: "192.0.2.1,192.0.2.2".parse()?,
            direction: Direction::Send,
        };
        let b = EndpointFlow {
            path: "198.51.100.1,198.51.100.2".parse()?,
            direction: Direction::Receive,
        };
        let mut snapshot = Snapshot {
            addresses: BTreeMap::new(),
            active: BTreeMap::from([(b, 1)]),
            overlaps: vec![EndpointOverlap {
                flows: [a, b],
                bytes_per_second: 100 << 20,
            }],
        };
        assert_eq!(
            snapshot.overlap_cost(Some(a.path), Transfer::Upload(100 << 20), 100 << 20, 1),
            2_000_000_000
        );
        assert_eq!(
            snapshot.overlap_cost(Some(a.path), Transfer::Download(100 << 20), 100 << 20, 1),
            1
        );
        snapshot.active.clear();
        assert_eq!(
            snapshot.overlap_cost(Some(a.path), Transfer::Upload(100 << 20), 100 << 20, 1),
            1
        );
        Ok(())
    }

    #[test]
    fn same_subnet_candidate_matching_distinguishes_ip_families() -> anyhow::Result<()> {
        assert!(on_link(
            "192.168.1.2".parse()?,
            "255.255.255.0".parse()?,
            "192.168.1.3".parse()?
        ));
        assert!(!on_link(
            "192.168.76.2".parse()?,
            "255.255.255.0".parse()?,
            "192.168.1.3".parse()?
        ));
        assert!(on_link(
            "fd01::2".parse()?,
            "ffff:ffff:ffff:ffff::".parse()?,
            "fd01::3".parse()?
        ));
        assert!(!on_link(
            "fd01::2".parse()?,
            "ffff:ffff:ffff:ffff::".parse()?,
            "192.168.1.3".parse()?
        ));
        Ok(())
    }

    #[test]
    fn isolated_measurement_rejects_external_and_concurrent_traffic() {
        assert_eq!(
            classify(Some(0), Some((10 << 20) + 1000), 10 << 20, false),
            Quality::Clean
        );
        assert_eq!(
            classify(Some(0), Some(15 << 20), 10 << 20, false),
            Quality::Busy
        );
        assert_eq!(
            classify(Some(0), Some(10 << 20), 10 << 20, true),
            Quality::Busy
        );
        assert_eq!(
            classify(Some(100), Some(0), 10 << 20, false),
            Quality::Unknown
        );
        assert_eq!(
            classify(None, Some(10 << 20), 10 << 20, false),
            Quality::Unknown
        );
    }

    #[test]
    fn proc_counters_use_correct_direction_and_ignore_headers() {
        let text = "Inter-| Receive | Transmit\neth0: 100 2 0 0 0 0 0 0 200 3 0 0 0 0 0 0\nwlan0: 400 2 0 0 0 0 0 0 800 3 0 0 0 0 0 0\n";
        assert_eq!(
            counters(text).collect::<Vec<_>>(),
            [("eth0", [200, 100]), ("wlan0", [800, 400])]
        );
    }
}
