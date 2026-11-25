//! Cluster transport shared by the legacy archive and native CAS RPCs.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[cfg(feature = "dist-server")]
use std::net::SocketAddr;

use crate::http_client::{ResponseReader, io_runtime};
use anyhow::{Context, Result};
use sccache_cluster_identity::{
    ClusterHttpClient, PeerConfig, PeerCredentials, PeerId, Role, TlsCredentials,
};

pub use super::cluster_routes::Route;
use super::cluster_routes::{
    ConnectionPath, MeasuredReader, PROBE_PATH, PROBE_TIMEOUT, Probe, RouteBook, Transfer,
};
use sccache_peer_identity::RouteSet;

type Current = dyn Fn() -> Result<Arc<TlsCredentials>> + Send + Sync;

/// Total interface traffic and learned directional path overlap on this host.
#[must_use = "the report supplies endpoint network forecasts"]
pub fn interface_report() -> crate::build_runtime::wire::InterfaceReport {
    super::cluster_routes::interface::report()
}

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
    scheduler: &url::Url,
    role: Role,
    enrollment_token: impl Fn() -> Result<String> + Send + Sync + 'static,
) -> Result<Arc<PeerCredentials>> {
    let address = sccache_cluster_identity::endpoint(scheduler)?;
    let runtime = io_runtime()?;
    let peer = runtime.block_on(PeerCredentials::open(
        config,
        address,
        role,
        enrollment_token,
    ))?;
    if let Err(error) = runtime.block_on(peer.refresh()) {
        warn!("Cluster certificate renewal will be retried: {error:#}");
    }
    Ok(Arc::new(peer))
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PathKey {
    peer: PeerId,
    role: Role,
    address: Route,
}

struct TransportPath {
    credentials: Arc<TlsCredentials>,
    streaming: Option<Arc<ClusterHttpClient>>,
}

/// Reusable per-path pools. A renewed leaf invalidates only the affected pools.
pub struct ClusterRoutes {
    current: Arc<Current>,
    paths: Mutex<HashMap<PathKey, TransportPath>>,
    book: Arc<RouteBook>,
}

impl ClusterRoutes {
    pub fn new(current: impl Fn() -> Result<Arc<TlsCredentials>> + Send + Sync + 'static) -> Self {
        Self {
            current: Arc::new(current),
            paths: Mutex::default(),
            book: Arc::default(),
        }
    }

    pub fn for_peer(peer: Arc<PeerCredentials>) -> Self {
        Self::new(move || {
            let current = peer.current()?;
            anyhow::ensure!(
                !current.renewal_due(Duration::ZERO)?,
                "cluster credential expired"
            );
            Ok(current)
        })
    }

    async fn probe(&self, peer: PeerId, role: Role, probe: Probe) {
        let address = probe.address;
        let start = Instant::now();
        let result = async {
            let (client, base) = self.endpoint(peer, role, address)?;
            let response = client
                .get(base.join(PROBE_PATH)?.as_str())
                .timeout(PROBE_TIMEOUT)
                .send()
                .await?;
            Ok::<_, anyhow::Error>((
                response.status() == http::StatusCode::NO_CONTENT,
                ConnectionPath::from_response(&response),
            ))
        }
        .await;
        let (elapsed, path) = result.ok().filter(|(success, _)| *success).map_or_else(
            || (None, ConnectionPath::default()),
            |(_, path)| (Some(start.elapsed()), path),
        );
        self.book.observe_path(peer, role, address, elapsed, path);
        drop(probe);
    }

    /// Probe in parallel, without sending any application request or job token.
    pub fn select(&self, peer: PeerId, role: Role, routes: &RouteSet) -> Vec<Route> {
        self.probe_routes([(peer, role, routes)]);
        self.book.ordered(peer, role, routes, None)
    }

    pub(super) fn probe_routes<'a>(
        &self,
        routes: impl IntoIterator<Item = (PeerId, Role, &'a RouteSet)>,
    ) {
        let Ok(runtime) = io_runtime() else {
            return;
        };
        let probes = routes.into_iter().flat_map(|(peer, role, routes)| {
            self.book
                .reserve(peer, role, routes)
                .into_iter()
                .map(move |probe| self.probe(peer, role, probe))
        });
        runtime.block_on(futures::future::join_all(probes));
    }

    /// Refresh measurements outside the heartbeat and allocation request pools.
    pub fn prime(self: &Arc<Self>, peer: PeerId, role: Role, routes: &RouteSet) {
        let Ok(runtime) = io_runtime() else {
            return;
        };
        for probe in self.book.reserve(peer, role, routes) {
            let this = Arc::clone(self);
            runtime.spawn(async move {
                this.probe(peer, role, probe).await;
            });
        }
    }

    pub fn ordered(&self, peer: PeerId, role: Role, routes: &RouteSet) -> Vec<Route> {
        self.book.ordered(peer, role, routes, None)
    }

    pub(super) fn ordered_transfer(
        &self,
        peer: PeerId,
        role: Role,
        routes: &RouteSet,
        transfer: Transfer,
    ) -> Vec<Route> {
        self.book.ordered(peer, role, routes, Some(transfer))
    }

    pub(super) fn estimated_cost(
        &self,
        peer: PeerId,
        role: Role,
        routes: &RouteSet,
        transfer: Transfer,
    ) -> Option<u128> {
        self.book.estimated_cost(peer, role, routes, transfer)
    }

    #[cfg(all(target_os = "linux", feature = "native-store"))]
    pub(super) fn verified_download(
        &self,
        peer: PeerId,
        address: Route,
        path: ConnectionPath,
        bytes: u64,
        encoded_length: Option<u64>,
        elapsed: Duration,
    ) {
        self.book
            .verified_download(peer, address, path, bytes, encoded_length, elapsed);
    }

    #[cfg(all(target_os = "linux", feature = "native-store"))]
    pub(super) fn peer_download_rates(&self) -> Vec<crate::build_runtime::wire::PeerDownloadRate> {
        self.book.peer_download_rates()
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
        address: Route,
        transfer: Transfer,
        elapsed: Duration,
        path: ConnectionPath,
    ) {
        self.book
            .transferred(peer, role, address, transfer, elapsed, path);
    }

    pub(super) fn measure_response(
        &self,
        peer: PeerId,
        role: Role,
        address: Route,
        response: wreq::Response,
    ) -> Result<MeasuredReader<ResponseReader>> {
        let length = response.content_length();
        let path = ConnectionPath::from_response(&response);
        Ok(MeasuredReader::new(
            ResponseReader::new(response)?,
            Arc::clone(&self.book),
            peer,
            role,
            address,
            length,
            path,
        ))
    }

    pub(super) fn local_source(
        &self,
        peer: PeerId,
        role: Role,
        address: Route,
    ) -> Option<std::net::IpAddr> {
        self.book.local_source(peer, role, address)
    }

    pub fn failed(&self, peer: PeerId, role: Role, address: Route) {
        self.book.observe(peer, role, address, None);
    }

    fn with_path<T>(
        &self,
        peer: PeerId,
        role: Role,
        address: Route,
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
            streaming: None,
        });
        if !Arc::ptr_eq(&path.credentials, &credentials) {
            *path = TransportPath {
                credentials,
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
        address: Route,
    ) -> Result<(wreq::Client, url::Url)> {
        let transport = self.streaming_endpoint(peer, role, address)?;
        Ok((transport.client(), transport.base().clone()))
    }

    pub(super) fn streaming_endpoint(
        &self,
        peer: PeerId,
        role: Role,
        address: Route,
    ) -> Result<Arc<ClusterHttpClient>> {
        self.with_path(peer, role, address, |path| {
            if let Some(client) = &path.streaming {
                return Ok(Arc::clone(client));
            }
            let binding = address.binding();
            let client = Arc::new(match binding.as_ref() {
                Some((ip, name)) => ClusterHttpClient::new_bound(
                    &path.credentials,
                    peer,
                    role,
                    address.address,
                    (*ip, name.as_deref()),
                )?,
                None => ClusterHttpClient::new(&path.credentials, peer, role, address.address)?,
            });
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
    let runtime = io_runtime()?;
    runtime
        .block_on(peer.refresh())
        .context("renew cluster credential")
}
