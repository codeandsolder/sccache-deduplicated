//! Cluster transport shared by the legacy archive and native CAS RPCs.
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use sccache_cluster_identity::{
    ClusterHttpClient, PeerConfig, PeerCredentials, PeerId, Role, TlsCredentials,
};

use super::cluster_routes::{
    MeasuredReader, PROBE_PATH, PROBE_TIMEOUT, Probe, RouteBook, Transfer,
};
use sccache_peer_identity::RouteSet;

type Current = dyn Fn() -> Result<Arc<TlsCredentials>> + Send + Sync;

/// A default data listener is dual-stack, including when its configured
/// reliable route is IPv4. Loopback-only endpoints remain loopback-only.
#[cfg(feature = "dist-server")]
#[must_use = "the returned address defines the listener bind"]
pub const fn wildcard(address: SocketAddr) -> SocketAddr {
    if address.ip().is_loopback() {
        address
    } else {
        SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            address.port(),
        )
    }
}

/// Open a persisted peer from synchronous daemon/worker initialization.
///
/// # Errors
/// Returns an error when scheduler resolution, runtime initialization or enrollment fails.
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
    role: Role,
    address: SocketAddr,
}

struct TransportPath {
    credentials: Arc<TlsCredentials>,
    blocking: Option<(reqwest::blocking::Client, reqwest::Url)>,
    streaming: Option<Arc<ClusterHttpClient>>,
}

/// Reusable per-path pools. A renewed leaf invalidates only the affected pools.
pub struct BlockingRoutes {
    current: Arc<Current>,
    paths: Mutex<HashMap<PathKey, TransportPath>>,
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
        let result = (|| -> Result<(bool, Option<sccache_peer_identity::NetworkPath>)> {
            let (client, base) = self.endpoint(peer, role, address)?;
            let response = client
                .get(base.join(PROBE_PATH)?)
                .timeout(PROBE_TIMEOUT)
                .send()?;
            Ok((
                response.status() == reqwest::StatusCode::NO_CONTENT,
                super::cluster_routes::reported_path(response.headers()),
            ))
        })();
        let (elapsed, path) = result
            .ok()
            .filter(|(success, _)| *success)
            .map_or((None, None), |(_, path)| (Some(start.elapsed()), path));
        self.book.observe_path(peer, role, address, elapsed, path);
        drop(probe);
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
    ) -> Option<crate::build_runtime::wire::CachePathRate> {
        self.book.best_rate(peer, role, routes, transfer)
    }

    pub(super) fn transferred(
        &self,
        peer: PeerId,
        role: Role,
        address: SocketAddr,
        transfer: Transfer,
        elapsed: Duration,
        path: Option<sccache_peer_identity::NetworkPath>,
    ) {
        self.book
            .transferred(peer, role, address, transfer, elapsed, path);
    }

    pub(super) fn measure_response(
        &self,
        peer: PeerId,
        role: Role,
        address: SocketAddr,
        response: reqwest::blocking::Response,
    ) -> MeasuredReader<reqwest::blocking::Response> {
        let length = response.content_length();
        let path = super::cluster_routes::reported_path(response.headers());
        MeasuredReader::new(
            response,
            Arc::clone(&self.book),
            peer,
            role,
            address,
            length,
            path,
        )
    }

    pub fn failed(&self, peer: PeerId, role: Role, address: SocketAddr) {
        self.book.observe(peer, role, address, None);
    }

    fn with_path<T>(
        &self,
        peer: PeerId,
        role: Role,
        address: SocketAddr,
        open: impl FnOnce(&mut TransportPath) -> Result<T>,
    ) -> Result<T> {
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
        if paths.len() >= 256 && !paths.contains_key(&key) {
            paths.clear();
        }
        let path = paths.entry(key).or_insert_with(|| TransportPath {
            credentials: Arc::clone(&credentials),
            blocking: None,
            streaming: None,
        });
        if !Arc::ptr_eq(&path.credentials, &credentials) {
            *path = TransportPath {
                credentials,
                blocking: None,
                streaming: None,
            };
        }
        let result = open(path);
        drop(paths);
        result
    }

    /// Open or reuse a client pinned to the enrolled peer and chosen endpoint.
    ///
    /// # Errors
    /// Returns an error if credential lookup or transport initialization fails.
    pub fn endpoint(
        &self,
        peer: PeerId,
        role: Role,
        address: SocketAddr,
    ) -> Result<(reqwest::blocking::Client, reqwest::Url)> {
        self.with_path(peer, role, address, |path| {
            if let Some(client) = &path.blocking {
                return Ok(client.clone());
            }
            let client = sccache_cluster_identity::blocking_client(
                &path.credentials,
                peer,
                role,
                address,
                Duration::from_mins(20),
            )?;
            path.blocking = Some(client.clone());
            Ok(client)
        })
    }

    pub(super) fn streaming_endpoint(
        &self,
        peer: PeerId,
        role: Role,
        address: SocketAddr,
    ) -> Result<Arc<ClusterHttpClient>> {
        self.with_path(peer, role, address, |path| {
            if let Some(client) = &path.streaming {
                return Ok(Arc::clone(client));
            }
            let client = Arc::new(ClusterHttpClient::new(
                &path.credentials,
                peer,
                role,
                address,
            )?);
            path.streaming = Some(Arc::clone(&client));
            Ok(client)
        })
    }
}

/// Refresh the member certificate outside the asynchronous request path.
///
/// # Errors
/// Returns an error when runtime initialization or renewal fails.
pub fn refresh_blocking(peer: &PeerCredentials) -> Result<Arc<TlsCredentials>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime
        .block_on(peer.refresh())
        .context("renew cluster credential")
}
