//! Short-lived, authenticated path measurements. A peer's identity remains
//! independent of the currently preferred interface.
use sccache_peer_identity::{PeerId, Role, RouteSet};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

pub const PROBE_PATH: &str = "/api/v1/cluster/probe";
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(350);
const SUCCESS_TTL: Duration = Duration::from_secs(60);
const FAILURE_TTL: Duration = Duration::from_secs(10);
const MAX_PATHS: usize = 4096;

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
}

#[derive(Default)]
pub struct RouteBook {
    samples: Mutex<HashMap<Key, Sample>>,
}

impl RouteBook {
    /// Reserve only stale candidates, preventing parallel requests from
    /// generating duplicate probe batches.
    pub fn reserve(&self, peer: PeerId, role: Role, routes: &RouteSet) -> Vec<SocketAddr> {
        if routes.alternatives.is_empty() || !routes.valid() {
            return Vec::new();
        }
        let now = Instant::now();
        let mut samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        if samples.len() >= MAX_PATHS {
            samples.retain(|_, sample| sample.expires > now);
        }
        let mut pending = Vec::new();
        for address in routes.iter() {
            let key = Key {
                peer,
                role,
                address,
            };
            if samples.get(&key).is_some_and(|sample| sample.expires > now)
                || samples.len() >= MAX_PATHS
            {
                continue;
            }
            samples.insert(
                key,
                Sample {
                    measured: None,
                    expires: now + FAILURE_TTL,
                },
            );
            pending.push(address);
        }
        pending
    }

    pub fn observe(
        &self,
        peer: PeerId,
        role: Role,
        address: SocketAddr,
        elapsed: Option<Duration>,
    ) {
        let mut samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        let key = Key {
            peer,
            role,
            address,
        };
        if samples.len() < MAX_PATHS || samples.contains_key(&key) {
            samples.insert(
                key,
                Sample {
                    measured: elapsed,
                    expires: Instant::now()
                        + if elapsed.is_some() {
                            SUCCESS_TTL
                        } else {
                            FAILURE_TTL
                        },
                },
            );
        }
    }

    /// Sort usable, measured routes by actual authenticated request latency.
    /// Always include the configured fallback, even when its last probe failed.
    pub fn ordered(&self, peer: PeerId, role: Role, routes: &RouteSet) -> Vec<SocketAddr> {
        let now = Instant::now();
        let samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        let mut ranked = routes
            .iter()
            .filter_map(|address| {
                let key = Key {
                    peer,
                    role,
                    address,
                };
                let sample = samples.get(&key)?;
                (sample.expires > now)
                    .then_some(sample.measured)
                    .flatten()
                    .map(|rtt| (rtt, address != routes.primary, address))
            })
            .collect::<Vec<_>>();
        ranked.sort_unstable();
        let mut result = ranked
            .into_iter()
            .map(|(_, _, address)| address)
            .collect::<Vec<_>>();
        if !result.contains(&routes.primary) {
            result.push(routes.primary);
        }
        result
    }
}

/// Discover only addresses covered by the actual listener. No DNS or
/// multicast infrastructure is required; the configured address is retained.
#[cfg(all(feature = "dist-server", target_os = "linux"))]
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

#[cfg(all(feature = "dist-server", not(target_os = "linux")))]
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
        assert_eq!(book.ordered(peer, Role::Worker, &routes), [primary]);
        assert_eq!(book.reserve(peer, Role::Worker, &routes), [primary, lan]);
        assert!(book.reserve(peer, Role::Worker, &routes).is_empty());
        book.observe(peer, Role::Worker, primary, Some(Duration::from_millis(20)));
        book.observe(peer, Role::Worker, lan, Some(Duration::from_millis(2)));
        assert_eq!(book.ordered(peer, Role::Worker, &routes), [lan, primary]);
        assert_eq!(book.ordered(other, Role::Worker, &routes), [primary]);
        book.observe(peer, Role::Worker, lan, None);
        assert_eq!(book.ordered(peer, Role::Worker, &routes), [primary]);
        Ok(())
    }
}
