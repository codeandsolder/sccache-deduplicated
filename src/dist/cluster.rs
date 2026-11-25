//! Cluster transport shared by the legacy archive and native CAS RPCs.
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use sccache_cluster_identity::{PeerConfig, PeerCredentials, PeerId, Role, TlsCredentials};

type Current = dyn Fn() -> Result<Arc<TlsCredentials>> + Send + Sync;

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
}

impl BlockingRoutes {
    pub fn new(current: impl Fn() -> Result<Arc<TlsCredentials>> + Send + Sync + 'static) -> Self {
        Self {
            current: Arc::new(current),
            paths: Mutex::default(),
        }
    }

    pub fn for_peer(peer: Arc<PeerCredentials>) -> Self {
        Self::new(move || peer.current())
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
