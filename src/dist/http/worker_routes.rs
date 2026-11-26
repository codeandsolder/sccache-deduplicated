//! Route pools are keyed by peer identity and actual endpoint, not leaf digest.
use anyhow::{Context, Result};
use sccache_cluster_identity::{ClusterHttpClient, PeerCredentials, Role, TlsCredentials};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use super::{
    common::WorkerRouteHttpResponse,
    transport::{RequestClass, send_async},
    urls,
};
use crate::dist::{
    ServerId,
    cluster_routes::{ConnectionPath, PROBE_PATH, PROBE_TIMEOUT, Probe, Route, RouteBook},
};
use sccache_peer_identity::RouteSet;

type Path = (Arc<TlsCredentials>, Arc<ClusterHttpClient>);

pub(super) struct WorkerRoutes {
    peer: Arc<PeerCredentials>,
    workers: Mutex<HashMap<ServerId, RouteSet>>,
    paths: Mutex<HashMap<(ServerId, Role, Route), Path>>,
    book: RouteBook,
}

impl WorkerRoutes {
    pub(super) fn new(peer: Arc<PeerCredentials>) -> Self {
        Self {
            peer,
            workers: Mutex::default(),
            paths: Mutex::default(),
            book: RouteBook::default(),
        }
    }

    async fn path(
        &self,
        id: ServerId,
        role: Role,
        address: Route,
    ) -> Result<Arc<ClusterHttpClient>> {
        let credentials = match self.peer.refresh().await {
            Ok(credentials) => credentials,
            Err(error) => {
                warn!("Cluster credential renewal will be retried: {error:#}");
                let current = self.peer.current()?;
                if current.renewal_due(Duration::ZERO)? {
                    return Err(error);
                }
                current
            }
        };
        let mut paths = self
            .paths
            .lock()
            .map_err(|_| anyhow::anyhow!("cluster paths poisoned"))?;
        let key = (id, role, address);
        if let Some((saved, path)) = paths.get(&key)
            && Arc::ptr_eq(saved, &credentials)
        {
            return Ok(Arc::clone(path));
        }
        let binding = address.binding();
        let path = Arc::new(match binding.as_ref() {
            Some((ip, name)) => ClusterHttpClient::new_bound(
                &credentials,
                id,
                role,
                address.address,
                (*ip, name.as_deref()),
            )?,
            None => ClusterHttpClient::new(&credentials, id, role, address.address)?,
        });
        if paths.len() >= 256 {
            paths.clear();
        }
        paths.insert(key, (credentials, Arc::clone(&path)));
        drop(paths);
        Ok(path)
    }

    pub(super) async fn control(&self) -> Result<Arc<ClusterHttpClient>> {
        self.path(
            self.peer.scheduler_id(),
            Role::Scheduler,
            Route::unbound(self.peer.scheduler_address()),
        )
        .await
    }

    pub(super) fn allocation(&self, server: ServerId, routes: RouteSet) -> Result<()> {
        let mut workers = self
            .workers
            .lock()
            .map_err(|_| anyhow::anyhow!("worker routes poisoned"))?;
        if workers.len() >= 256 {
            workers.clear();
        }
        anyhow::ensure!(routes.valid(), "invalid worker route advertisement");
        workers.insert(server, routes);
        drop(workers);
        Ok(())
    }

    async fn refresh_route(&self, server: ServerId) -> Result<RouteSet> {
        let scheduler = self.control().await?;
        let url = urls::scheduler_worker_route(scheduler.base(), server)?;
        let reply: WorkerRouteHttpResponse =
            send_async(scheduler.client().get(url.as_str()), RequestClass::Control).await?;
        self.allocation(server, reply.routes.clone())?;
        Ok(reply.routes)
    }

    async fn addresses(&self, server: ServerId) -> Result<RouteSet> {
        let address = self
            .workers
            .lock()
            .map_err(|_| anyhow::anyhow!("worker routes poisoned"))?
            .get(&server)
            .cloned();
        match address {
            Some(address) => Ok(address),
            None => self.refresh_route(server).await,
        }
    }

    async fn probe(&self, server: ServerId, probe: Probe) {
        let address = probe.address;
        let start = Instant::now();
        let result = async {
            let path = self.path(server, Role::Worker, address).await?;
            let response = path
                .request(http::Method::GET, PROBE_PATH)?
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
        self.book
            .observe_path(server, Role::Worker, address, elapsed, path);
        drop(probe);
    }

    pub(super) async fn send<T: serde::de::DeserializeOwned>(
        &self,
        server: ServerId,
        class: RequestClass,
        request: impl Fn(&wreq::Client, &url::Url) -> Result<wreq::RequestBuilder>,
    ) -> Result<T> {
        let mut routes = self.addresses(server).await?;
        let mut last_error = None;
        for pass in 0..2 {
            let pending = self.book.reserve(server, Role::Worker, &routes);
            futures::future::join_all(
                pending
                    .into_iter()
                    .map(|address| self.probe(server, address)),
            )
            .await;
            for address in self.book.ordered(server, Role::Worker, &routes, None) {
                let path = self.path(server, Role::Worker, address).await?;
                match send_async(request(&path.client(), path.base())?, class).await {
                    Err(error)
                        if error
                            .downcast_ref::<wreq::Error>()
                            .is_some_and(wreq::Error::is_connect) =>
                    {
                        self.book.observe(server, Role::Worker, address, None);
                        last_error = Some(error);
                    }
                    result => return result,
                }
            }
            if pass == 0 {
                let replacement = self
                    .refresh_route(server)
                    .await
                    .context("refresh worker endpoints")?;
                if replacement == routes {
                    break;
                }
                routes = replacement;
            }
        }
        Err(last_error.context("no worker route available")?)
    }
}
