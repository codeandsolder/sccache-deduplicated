//! Cluster transport shared by the legacy archive and native CAS RPCs.
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use sccache_cluster_identity::{PeerConfig, PeerCredentials, PeerId, Role, TlsCredentials};

use super::cluster_routes::{
    MeasuredReader, PROBE_PATH, PROBE_TIMEOUT, Probe, RouteBook, Transfer,
};
use sccache_peer_identity::RouteSet;

type Current = dyn Fn() -> Result<Arc<TlsCredentials>> + Send + Sync;

/// Bind to all interfaces of the configured address family (loopback-only
/// endpoints remain loopback-only).
pub fn wildcard(address: SocketAddr) -> SocketAddr {
    if address.ip().is_loopback() {
        return address;
    }
    let ip = match address.ip() {
        std::net::IpAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, address.port())
}

/// Open a persisted peer from synchronous daemon/worker initialization.
pub fn open_peer(
    config: PeerConfig,
    scheduler: &reqwest::Url,
    role: Role,
    token: &str,
) -> Result<Arc<PeerCredentials>> {
    let address = sccache_cluster_identity::endpoint(scheduler)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let peer = runtime.block_on(PeerCredentials::open(config, address, role, token))?;
    if let Err(error) = runtime.block_on(peer.refresh()) {
        warn!("Cluster certificate renewal will be retried: {error:#}");
    }
    Ok(Arc::new(peer))
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PathKey {
    peer: PeerId,
    address: SocketAddr,
    role: Role,
}

type BlockingPath = (Arc<TlsCredentials>, reqwest::blocking::Client, reqwest::Url);

/// Reusable per-path pools. A renewed leaf invalidates only the affected pools.
pub struct BlockingRoutes {
    current: Arc<Current>,
    paths: Mutex<HashMap<PathKey, BlockingPath>>,
    book: Arc<RouteBook>,
}

impl BlockingRoutes {
    pub fn new(current: impl Fn() -> Result<Arc<TlsCredentials>> + Send + Sync + 'static) -> Self {
        Self {
            current: Arc::new(current),
            paths: Mutex::default(),
            book: Arc::default(),
        }
    }

    pub fn for_peer(peer: Arc<PeerCredentials>) -> Self {
        Self::new(move || peer.current())
    }

    fn probe(&self, peer: PeerId, role: Role, probe: Probe) {
        let address = probe.address;
        let start = Instant::now();
        let result = (|| -> Result<bool> {
            let (client, base) = self.endpoint(peer, role, address)?;
            let response = client
                .get(base.join(PROBE_PATH)?)
                .timeout(PROBE_TIMEOUT)
                .send()?;
            Ok(response.status() == reqwest::StatusCode::NO_CONTENT)
        })();
        self.book.observe(
            peer,
            role,
            address,
            result
                .ok()
                .filter(|success| *success)
                .map(|_| start.elapsed()),
        );
    }

    /// Probe in parallel, without sending any application request or job token.
    pub fn select(&self, peer: PeerId, role: Role, routes: &RouteSet) -> Vec<SocketAddr> {
        let pending = self.book.reserve(peer, role, routes);
        std::thread::scope(|scope| {
            for address in pending {
                scope.spawn(move || self.probe(peer, role, address));
            }
        });
        self.book.ordered(peer, role, routes, None)
    }

    /// Refresh measurements outside the heartbeat and allocation request pools.
    pub fn prime(self: &Arc<Self>, peer: PeerId, role: Role, routes: &RouteSet) {
        let pending = self.book.reserve(peer, role, routes);
        for address in pending {
            let this = Arc::clone(self);
            let _ = std::thread::Builder::new()
                .name("cluster-route-probe".into())
                .spawn(move || this.probe(peer, role, address));
        }
    }

    pub fn ordered(&self, peer: PeerId, role: Role, routes: &RouteSet) -> Vec<SocketAddr> {
        self.book.ordered(peer, role, routes, None)
    }

    pub(super) fn ordered_transfer(
        &self,
        peer: PeerId,
        role: Role,
        routes: &RouteSet,
        transfer: Transfer,
    ) -> Vec<SocketAddr> {
        self.book.ordered(peer, role, routes, Some(transfer))
    }

    pub(super) fn best_rate(
        &self,
        peer: PeerId,
        role: Role,
        routes: &RouteSet,
        transfer: Transfer,
    ) -> Option<u64> {
        self.book.best_rate(peer, role, routes, transfer)
    }

    pub(super) fn transferred(
        &self,
        peer: PeerId,
        role: Role,
        address: SocketAddr,
        transfer: Transfer,
        elapsed: Duration,
    ) {
        self.book
            .transferred(peer, role, address, transfer, elapsed);
    }

    pub(super) fn measure_response(
        &self,
        peer: PeerId,
        role: Role,
        address: SocketAddr,
        response: reqwest::blocking::Response,
    ) -> MeasuredReader<reqwest::blocking::Response> {
        let length = response.content_length();
        MeasuredReader::new(
            response,
            Arc::clone(&self.book),
            peer,
            role,
            address,
            length,
        )
    }

    pub fn failed(&self, peer: PeerId, role: Role, address: SocketAddr) {
        self.book.observe(peer, role, address, None);
    }

    pub fn endpoint(
        &self,
        peer: PeerId,
        role: Role,
        address: SocketAddr,
    ) -> Result<(reqwest::blocking::Client, reqwest::Url)> {
        let credentials = (self.current)()?;
        let key = PathKey {
            peer,
            role,
            address,
        };
        let mut paths = self
            .paths
            .lock()
            .map_err(|_| anyhow::anyhow!("cluster route pool poisoned"))?;
        if let Some((saved, client, base)) = paths.get(&key)
            && Arc::ptr_eq(saved, &credentials)
        {
            return Ok((client.clone(), base.clone()));
        }
        let (client, base) = sccache_cluster_identity::blocking_client(
            &credentials,
            peer,
            role,
            address,
            Duration::from_mins(20),
        )?;
        if paths.len() >= 256 {
            paths.clear();
        }
        paths.insert(key, (credentials, client.clone(), base.clone()));
        Ok((client, base))
    }
}

/// Refresh the member certificate outside the asynchronous request path.
pub fn refresh_blocking(peer: &PeerCredentials) -> Result<Arc<TlsCredentials>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime
        .block_on(peer.refresh())
        .context("renew cluster credential")
}
