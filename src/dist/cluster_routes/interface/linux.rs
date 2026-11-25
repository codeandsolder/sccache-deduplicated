//! Linux interface counters include traffic from every process. Local address
//! ownership is refreshed on demand; ambiguous addresses supply no evidence.
use super::{Evidence, Quality, SAMPLE_INTERVAL, Transfer};
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
    managed: AtomicU64,
}
struct Sample {
    total: u64,
    managed: u64,
    rate: u64,
    external: u64,
    peak: u64,
    peak_at: Instant,
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
            counters: Arc::default(),
        }
    }

    fn update(&mut self, total: u64, now: Instant, elapsed: Duration) {
        let managed = self.counters.managed.load(Ordering::Relaxed);
        // Link replacement, counter reset or suspended sampling invalidates
        // this window rather than introducing a huge unsigned delta.
        if let Some(bytes) = total.checked_sub(self.total).filter(|_| elapsed <= TTL) {
            let own = managed.wrapping_sub(self.managed);
            self.rate = per_second(bytes, elapsed);
            self.external = per_second(bytes.saturating_sub(own), elapsed);
            if now.duration_since(self.peak_at) >= TTL || self.rate >= self.peak {
                self.peak = self.rate;
                self.peak_at = now;
            }
        } else {
            self.rate = 0;
            self.external = 0;
            self.peak = 0;
            self.peak_at = now;
        }
        self.total = total;
        self.managed = managed;
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
}

static BOOK: LazyLock<Mutex<Book>> = LazyLock::new(|| {
    Mutex::new(Book {
        updated: None,
        addresses: BTreeMap::new(),
        links: BTreeMap::new(),
    })
});

#[derive(Clone)]
struct LocalAddress {
    name: String,
    mask: IpAddr,
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
        if !entry.flags.contains(InterfaceFlags::IFF_UP) {
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
        self.counters.active.fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut book) = BOOK.lock() {
            book.refresh(Instant::now());
        }
    }
}

pub(in crate::dist) fn activity(local: Option<IpAddr>, transfer: Transfer) -> Option<Activity> {
    let local = local?;
    if transfer.bytes() < 256 * 1024 {
        return None;
    }
    let mut book = BOOK.lock().unwrap_or_else(PoisonError::into_inner);
    book.refresh(Instant::now());
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
    drop(book);
    Some(Activity {
        counters,
        stat,
        start_total,
        start_active,
        generation,
        bytes: 0,
        evidence: Evidence::default(),
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
    drop(book);
    Snapshot { addresses }
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
    let mut sources = Vec::new();
    if !destination.is_loopback() {
        for (&source, address) in &book.addresses {
            if source != destination
                && !source.is_loopback()
                && RouteSet::eligible(std::net::SocketAddr::new(source, 1))
                && on_link(source, address.mask, destination)
                && names.insert(address.name.as_str())
            {
                sources.push(source);
            }
        }
    }
    drop(book);
    sources.truncate(4);
    sources
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
