//! Independently aligned total-interface counters for the scheduler meter.
//! Sum body deltas by actual local interface before comparing total bytes;
//! never subtract each path from the same counter separately.
use super::{counters, interface_addresses, read_number};
use crate::build_runtime::{Direction, Peer};
use std::{collections::BTreeMap, fs, net::IpAddr, path::Path};

struct Snapshot {
    addresses: BTreeMap<IpAddr, String>,
    counters: BTreeMap<String, (u32, [u64; 2])>,
}

impl Snapshot {
    fn capture() -> Option<Self> {
        let contents = fs::read_to_string("/proc/net/dev").ok()?;
        let counters = counters(&contents)
            .filter_map(|(name, bytes)| {
                let index = read_number(&Path::new("/sys/class/net").join(name).join("ifindex"))?;
                Some((name.to_owned(), (index, bytes)))
            })
            .collect();
        let addresses = interface_addresses()
            .into_iter()
            .map(|(ip, address)| (ip, address.name))
            .collect();
        Some(Self {
            addresses,
            counters,
        })
    }

    fn clean(&self, previous: &Self, direction: Direction, bodies: &BTreeMap<Peer, u64>) -> bool {
        let mut totals = BTreeMap::<&str, u64>::new();
        for (&peer, &bytes) in bodies {
            let Some(path) = peer.path() else {
                return false;
            };
            let Some(interface) = self.addresses.get(&path.local) else {
                return false;
            };
            if previous.addresses.get(&path.local) != Some(interface) {
                return false;
            }
            let total = totals.entry(interface).or_default();
            *total = total.saturating_add(bytes);
        }
        let index = match direction {
            Direction::Send => 0,
            Direction::Receive => 1,
        };
        totals.into_iter().all(|(name, body)| {
            let Some((old_index, old)) = previous.counters.get(name) else {
                return false;
            };
            let Some((new_index, new)) = self.counters.get(name) else {
                return false;
            };
            if old_index != new_index {
                return false;
            }
            let Some(total) = new[index].checked_sub(old[index]) else {
                return false;
            };
            total >= body.saturating_mul(9) / 10
                && total.saturating_sub(body) <= body / 8 + (64 << 10)
        })
    }
}

#[derive(Default)]
pub(in crate::dist) struct MeterSampler {
    previous: Option<Snapshot>,
}

impl MeterSampler {
    /// Capture at the same maintenance boundary as the native body meter.
    pub(in crate::dist) fn sample(&mut self) -> impl Fn(Direction, &BTreeMap<Peer, u64>) -> bool {
        let current = Snapshot::capture();
        let previous = std::mem::replace(&mut self.previous, current);
        move |direction, bodies| {
            self.previous
                .as_ref()
                .zip(previous.as_ref())
                .is_some_and(|(current, previous)| current.clean(previous, direction, bodies))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_runtime::{NetworkPath, PeerId};

    #[test]
    fn aggregate_by_interface_and_reject_unrelated_traffic() -> anyhow::Result<()> {
        let local: IpAddr = "192.0.2.1".parse()?;
        let second_local: IpAddr = "192.0.2.2".parse()?;
        let peer = |id, local, remote| {
            Peer::Worker(PeerId::from_digest([id; 32])).on_path(NetworkPath::new(local, remote))
        };
        let a = peer(1, local, "198.51.100.1".parse()?);
        let b = peer(2, second_local, "198.51.100.2".parse()?);
        let addresses = BTreeMap::from([(local, "eth0".into()), (second_local, "eth0".into())]);
        let previous = Snapshot {
            addresses: addresses.clone(),
            counters: BTreeMap::from([("eth0".into(), (2, [0, 0]))]),
        };
        let mut current = Snapshot {
            addresses,
            counters: BTreeMap::from([("eth0".into(), (2, [100 << 20, 500 << 20]))]),
        };
        let bodies = BTreeMap::from([(a, 50 << 20), (b, 50 << 20)]);
        assert!(current.clean(&previous, Direction::Send, &bodies));
        assert!(!current.clean(&previous, Direction::Receive, &bodies));
        current.counters.get_mut("eth0").unwrap().1[0] = 150 << 20;
        assert!(!current.clean(&previous, Direction::Send, &bodies));
        current.counters.get_mut("eth0").unwrap().1[0] = 100 << 20;
        current.counters.get_mut("eth0").unwrap().0 = 3;
        assert!(!current.clean(&previous, Direction::Send, &bodies));
        Ok(())
    }
}
