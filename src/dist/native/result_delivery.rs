//! Recipient-bound direct delivery of committed result content. The scheduler
//! remains the durable authority; a worker is only an alternate payload source.
use std::{
    collections::BTreeMap,
    io::{self, Seek, Write},
    time::{Duration, Instant},
};

use super::{NativeCacheClient, ResultSourceRequest, codec};
use crate::build_runtime::{
    BlobEncoding, BlobRef, ContentId, transfer_native_blob,
    wire::{BlobSource, MAX_BLOB_SOURCES, MAX_SOURCE_BATCH, Ticket},
};
use crate::dist::cluster_routes::Transfer;
use anyhow::{Context, Result, ensure};
use sccache_cluster_identity::Role;

/// The source plan is advisory, scoped to a result lease, and refreshed before
/// grants expire. The broker may request only selected results.
pub(super) struct ResultDelivery<'a> {
    client: &'a NativeCacheClient,
    ticket: Ticket,
    declared: &'a BTreeMap<ContentId, u64>,
    sources: BTreeMap<ContentId, Vec<BlobSource>>,
    obtained: Instant,
}

impl<'a> ResultDelivery<'a> {
    pub(super) fn new(
        client: &'a NativeCacheClient,
        ticket: Ticket,
        declared: &'a BTreeMap<ContentId, u64>,
    ) -> Self {
        Self {
            client,
            ticket,
            declared,
            sources: BTreeMap::new(),
            obtained: Instant::now(),
        }
    }

    fn refresh(&mut self, blob: BlobRef) {
        if self.obtained.elapsed() >= Duration::from_secs(45) {
            self.sources.clear();
            self.obtained = Instant::now();
        }
        if self.sources.contains_key(&blob.id) {
            return;
        }
        let batch = self
            .declared
            .range(blob.id..)
            .filter(|(id, _)| !self.sources.contains_key(id))
            .take(MAX_SOURCE_BATCH)
            .map(|(&id, &size)| BlobRef { id, size })
            .collect::<Vec<_>>();
        let request = ResultSourceRequest {
            ticket: self.ticket,
            blobs: batch,
        };
        let reply: Result<Vec<(BlobRef, Vec<BlobSource>)>> =
            self.client.control("result_sources", &request);
        // The scheduler is still a valid delivery source if planning fails.
        for requested in &request.blobs {
            self.sources.insert(requested.id, Vec::new());
        }
        match reply {
            Ok(reply) => {
                for (offered, sources) in reply {
                    if request.blobs.contains(&offered)
                        && sources.len() <= MAX_BLOB_SOURCES
                        && sources.iter().all(|source| source.routes.valid())
                    {
                        self.sources.insert(offered.id, sources);
                    }
                }
            }
            Err(error) => debug!("native result source discovery unavailable: {error:#}"),
        }
    }

    pub(super) fn download(&mut self, blob: BlobRef, mut destination: impl Write) -> Result<()> {
        ensure!(
            self.declared.get(&blob.id) == Some(&blob.size),
            "undeclared native result blob"
        );
        self.refresh(blob);
        let sources = self
            .sources
            .get(&blob.id)
            .context("missing result source plan")?;
        if !sources.is_empty()
            && self
                .client
                .try_peer_result(blob, sources, &mut destination)?
        {
            return Ok(());
        }
        self.client.download(self.ticket, blob, destination)
    }
}

impl NativeCacheClient {
    fn try_peer_result(
        &self,
        blob: BlobRef,
        sources: &[BlobSource],
        mut destination: impl Write,
    ) -> Result<bool> {
        let transfer = Transfer::Download(blob.size);
        let cache_routes = self.cache_routes();
        // Probes authenticate every candidate with the same enrolled peer key.
        // Global probe admission is shared with all other cluster traffic.
        self.routes.probe_routes(
            sources
                .iter()
                .map(|source| (source.peer, Role::Worker, &source.routes)),
        );
        let scheduler_cost = self
            .routes
            .estimated_cost(
                self.peer.scheduler_id(),
                Role::Scheduler,
                &cache_routes,
                transfer,
            )
            .unwrap_or(50_000_000 + u128::from(blob.size) * 1_000_000_000 / (16 << 20));
        let mut candidates = sources
            .iter()
            .filter_map(|source| {
                let cost = self.routes.estimated_cost(
                    source.peer,
                    Role::Worker,
                    &source.routes,
                    transfer,
                )?;
                (cost <= scheduler_cost).then_some((cost, source))
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(cost, _)| *cost);
        if candidates.is_empty() {
            return Ok(false);
        }
        // Never write unverified or partial peer content to the caller's
        // stream. This also permits fallback for non-seekable IPC destinations.
        let mut staging = tempfile::tempfile()?;
        let started = Instant::now();
        for (cost, source) in candidates {
            let budget =
                self.timeout
                    .min(Duration::from_secs(5).saturating_add(Duration::from_nanos(
                        u64::try_from(cost.saturating_mul(4)).unwrap_or(u64::MAX),
                    )));
            for address in
                self.routes
                    .ordered_transfer(source.peer, Role::Worker, &source.routes, transfer)
            {
                let remaining = budget.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Ok(false);
                }
                staging.set_len(0)?;
                staging.rewind()?;
                match self.receive_peer_result(blob, source, address, remaining, &mut staging) {
                    Ok(true) => {
                        staging.rewind()?;
                        io::copy(&mut staging, &mut destination)?;
                        return Ok(true);
                    }
                    Ok(false) => break,
                    Err(error) => {
                        self.routes.failed(source.peer, Role::Worker, address);
                        debug!("native direct result delivery failed: {error:#}");
                    }
                }
            }
        }
        Ok(false)
    }

    fn receive_peer_result(
        &self,
        blob: BlobRef,
        source: &BlobSource,
        address: std::net::SocketAddr,
        remaining: Duration,
        staging: &mut std::fs::File,
    ) -> Result<bool> {
        let (client, base) = self.routes.endpoint(source.peer, Role::Worker, address)?;
        let response = client
            .post(crate::dist::http::urls::server_native_blob(&base)?)
            .bearer_auth(&source.token)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .timeout(remaining)
            .body(codec().serialize(&blob)?)
            .send()?;
        if matches!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND
                | reqwest::StatusCode::UNAUTHORIZED
                | reqwest::StatusCode::FORBIDDEN
        ) {
            return Ok(false);
        }
        let response = response.error_for_status()?;
        let encoding = BlobEncoding::from_http_value(
            response
                .headers()
                .get("x-sccache-cas-encoding")
                .context("missing peer encoding")?
                .to_str()?,
        )?;
        let reader = self
            .routes
            .measure_response(source.peer, Role::Worker, address, response);
        transfer_native_blob(reader, io::sink(), staging, blob, encoding)?;
        Ok(true)
    }
}
