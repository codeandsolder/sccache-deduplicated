//! Route pools are keyed by peer identity and actual endpoint, not leaf digest.
use anyhow::{Context, Result};
use sccache_cluster_identity::{ClusterHttpClient, PeerCredentials, Role, TlsCredentials};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use super::{
    common::WorkerRouteHttpResponse,
    transport::{RequestClass, send_async},
    urls,
};
use crate::dist::{
    ServerId,
    cluster_routes::{PROBE_PATH, PROBE_TIMEOUT, RouteBook},
};
use sccache_peer_identity::RouteSet;

type Path = (Arc<TlsCredentials>, Arc<ClusterHttpClient>);

pub(super) struct WorkerRoutes {
    peer: Arc<PeerCredentials>,
    workers: Mutex<HashMap<ServerId, RouteSet>>,
    paths: Mutex<HashMap<(ServerId, Role, SocketAddr), Path>>,
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
        address: SocketAddr,
    ) -> Result<Arc<ClusterHttpClient>> {
        let credentials = match self.peer.refresh().await {
            Ok(credentials) => credentials,
            Err(error) => {
                warn!("Cluster credential renewal will be retried: {error:#}");
                self.peer.current()?
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
        let path = Arc::new(ClusterHttpClient::new(&credentials, id, role, address)?);
        if paths.len() >= 256 {
            paths.clear();
        }
        paths.insert(key, (credentials, Arc::clone(&path)));
        Ok(path)
    }

    pub(super) async fn control(&self) -> Result<Arc<ClusterHttpClient>> {
        self.path(
            self.peer.scheduler_id(),
            Role::Scheduler,
            self.peer.scheduler_address(),
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
        Ok(())
    }

    async fn refresh_route(&self, server: ServerId) -> Result<RouteSet> {
        let scheduler = self.control().await?;
        let url = urls::scheduler_worker_route(scheduler.base(), server)?;
        let reply: WorkerRouteHttpResponse =
            send_async(scheduler.client().get(url), RequestClass::Control).await?;
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

    async fn probe(&self, server: ServerId, address: SocketAddr) {
        let start = Instant::now();
        let result = async {
            let path = self.path(server, Role::Worker, address).await?;
            let response = path
                .request(reqwest::Method::GET, PROBE_PATH)?
                .timeout(PROBE_TIMEOUT)
                .send()
                .await?;
            Ok::<_, anyhow::Error>(response.status() == reqwest::StatusCode::NO_CONTENT)
        }
        .await;
        self.book.observe(
            server,
            Role::Worker,
            address,
            result
                .ok()
                .filter(|success| *success)
                .map(|_| start.elapsed()),
        );
    }

    pub(super) async fn send<T: serde::de::DeserializeOwned>(
        &self,
        server: ServerId,
        class: RequestClass,
        request: impl Fn(&reqwest::Client, &reqwest::Url) -> Result<reqwest::RequestBuilder>,
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
            for address in self.book.ordered(server, Role::Worker, &routes) {
                let path = self.path(server, Role::Worker, address).await?;
                match send_async(request(&path.client(), path.base())?, class).await {
                    Err(error)
                        if error
                            .downcast_ref::<reqwest::Error>()
                            .is_some_and(reqwest::Error::is_connect) =>
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
