//! A receiver negotiates exact content against its authorized lease. The same
//! peer transport serves committed results and worker input closures.
use anyhow::{Context, Result};
use bincode::Options;
use sccache_cluster_identity::Role;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use super::{BlobSourceRequest, NativeCacheClient, codec};
use crate::{
    build_runtime::{
        BlobEncoding, BlobRef, ContentId,
        wire::{BlobSource, BlobSourcePlan, MAX_BLOB_SOURCES, MAX_SOURCE_BATCH, Ticket},
    },
    dist::cluster_routes::{MeasuredReader, Transfer},
};

impl NativeCacheClient {
    pub(in crate::dist) fn source_plans(
        &self,
        ticket: Ticket,
        blobs: &[BlobRef],
    ) -> BTreeMap<ContentId, BlobSourcePlan> {
        let mut plans = BTreeMap::new();
        for batch in blobs.chunks(MAX_SOURCE_BATCH) {
            let reply: Result<Vec<BlobSourcePlan>> = self.control(
                "blob_sources",
                &BlobSourceRequest {
                    ticket,
                    blobs: batch.to_vec(),
                },
            );
            match reply {
                Ok(reply) => {
                    for plan in reply {
                        if batch.contains(&plan.blob)
                            && plan.sources.len() <= MAX_BLOB_SOURCES
                            && plan.sources.iter().all(|source| source.routes.valid())
                        {
                            plans.insert(plan.blob.id, plan);
                        }
                    }
                }
                Err(error) => debug!("native peer source discovery unavailable: {error:#}"),
            }
        }
        plans
    }

    pub(super) fn probe_sources<'a>(&self, plans: impl IntoIterator<Item = &'a BlobSourcePlan>) {
        self.routes.probe_routes(plans.into_iter().flat_map(|plan| {
            plan.sources
                .iter()
                .map(|source| (source.peer, Role::Worker, &source.routes))
        }));
    }

    fn direct_candidates<'a>(&self, plan: &'a BlobSourcePlan) -> Vec<(u128, &'a BlobSource)> {
        if plan.sources.is_empty() {
            return Vec::new();
        }
        let transfer = Transfer::Download(plan.blob.size);
        let scheduler_cost = if plan.scheduler_present {
            self.routes
                .estimated_cost(
                    self.peer.scheduler_id(),
                    Role::Scheduler,
                    &self.cache_routes(),
                    transfer,
                )
                .unwrap_or_else(|| {
                    50_000_000 + u128::from(plan.blob.size) * 1_000_000_000 / (16 << 20)
                })
        } else {
            // A scheduler miss would require another content acquisition and
            // relay. Prefer an authenticated peer; no origin bytes are needed.
            u128::MAX
        };
        let mut candidates = plan
            .sources
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
        candidates
    }

    pub(super) fn has_direct_source(&self, plan: &BlobSourcePlan) -> bool {
        !self.direct_candidates(plan).is_empty()
    }

    /// The consumer stages and verifies before returning success. Each retry
    /// starts with a fresh consumer invocation; no unverified prefix escapes.
    pub(in crate::dist) fn try_peer_blob<T>(
        &self,
        plan: &BlobSourcePlan,
        mut consume: impl FnMut(MeasuredReader<reqwest::blocking::Response>, BlobEncoding) -> Result<T>,
    ) -> Option<T> {
        self.probe_sources([plan]);
        let blob = plan.blob;
        let started = Instant::now();
        for (cost, source) in self.direct_candidates(plan) {
            let budget =
                self.timeout
                    .min(Duration::from_secs(5).saturating_add(Duration::from_nanos(
                        u64::try_from(cost.saturating_mul(4)).unwrap_or(u64::MAX),
                    )));
            for address in self.routes.ordered_transfer(
                source.peer,
                Role::Worker,
                &source.routes,
                Transfer::Download(blob.size),
            ) {
                let remaining = budget.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    break;
                }
                match self.receive_peer_blob(blob, source, address, remaining) {
                    Ok(Some((reader, encoding))) => match consume(reader, encoding) {
                        Ok(value) => return Some(value),
                        Err(error) => debug!("native peer content rejected: {error:#}"),
                    },
                    Ok(None) => break,
                    Err(error) => {
                        self.routes.failed(source.peer, Role::Worker, address);
                        debug!("native direct content delivery failed: {error:#}");
                    }
                }
            }
        }
        None
    }

    fn receive_peer_blob(
        &self,
        blob: BlobRef,
        source: &BlobSource,
        address: std::net::SocketAddr,
        remaining: Duration,
    ) -> Result<Option<(MeasuredReader<reqwest::blocking::Response>, BlobEncoding)>> {
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
            return Ok(None);
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
        Ok(Some((reader, encoding)))
    }
}

#[cfg(feature = "dist-client")]
impl NativeCacheClient {
    /// A negotiated manifest is not a successful result until the scheduler
    /// confirms its durable publication. Wait only to the action's deadline.
    pub(super) fn await_result_commit(
        &self,
        ticket: Ticket,
        deadline: Instant,
    ) -> Result<crate::build_runtime::ResultManifest> {
        use crate::build_runtime::wire::NativeStatus;
        let mut delay = Duration::from_millis(10);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.status(ticket) {
                Ok(NativeStatus::Ready(manifest)) => return Ok(manifest),
                Ok(NativeStatus::Failed) => anyhow::bail!("native result publication failed"),
                Ok(NativeStatus::Compiling | NativeStatus::Negotiated(_)) => {}
                Err(error) if super::retryable_transport_error(&error) => {}
                Err(error) => return Err(error),
            }
            anyhow::ensure!(!remaining.is_zero(), "native publication deadline exceeded");
            std::thread::sleep(delay.min(remaining));
            delay = (delay * 2).min(Duration::from_millis(100));
        }
    }
}

#[cfg(feature = "dist-client")]
pub(super) struct ResultDelivery<'a> {
    client: &'a NativeCacheClient,
    ticket: Ticket,
    declared: &'a BTreeMap<ContentId, u64>,
    plans: BTreeMap<ContentId, Option<BlobSourcePlan>>,
    obtained: Instant,
    publication_deadline: Option<Instant>,
}

#[cfg(feature = "dist-client")]
impl<'a> ResultDelivery<'a> {
    pub(super) fn new(
        client: &'a NativeCacheClient,
        ticket: Ticket,
        declared: &'a BTreeMap<ContentId, u64>,
        publication_deadline: Option<Instant>,
    ) -> Self {
        Self {
            client,
            ticket,
            declared,
            plans: BTreeMap::new(),
            obtained: Instant::now(),
            publication_deadline,
        }
    }

    fn refresh(&mut self, blob: BlobRef) {
        if self.obtained.elapsed() >= Duration::from_secs(45) {
            self.plans.clear();
            self.obtained = Instant::now();
        }
        if self.plans.contains_key(&blob.id) {
            return;
        }
        let batch = self
            .declared
            .range(blob.id..)
            .filter(|(id, _)| !self.plans.contains_key(id))
            .take(MAX_SOURCE_BATCH)
            .map(|(&id, &size)| BlobRef { id, size })
            .collect::<Vec<_>>();
        let mut plans = self.client.source_plans(self.ticket, &batch);
        self.plans.extend(
            batch
                .into_iter()
                .map(|blob| (blob.id, plans.remove(&blob.id))),
        );
    }

    fn wait_for_fallback(&mut self) -> Result<()> {
        if let Some(deadline) = self.publication_deadline {
            self.client.await_result_commit(self.ticket, deadline)?;
            self.publication_deadline = None;
        }
        Ok(())
    }

    pub(super) fn download(
        &mut self,
        blob: BlobRef,
        mut destination: impl std::io::Write,
    ) -> Result<()> {
        use std::io::{self, Seek};
        anyhow::ensure!(
            self.declared.get(&blob.id) == Some(&blob.size),
            "undeclared native result blob"
        );
        self.refresh(blob);
        if let Some(plan) = self.plans.get(&blob.id).and_then(Option::as_ref)
            && let Some(mut staging) = self.client.try_peer_blob(plan, |reader, encoding| {
                let mut staging = tempfile::tempfile()?;
                crate::build_runtime::transfer_native_blob(
                    reader,
                    io::sink(),
                    &mut staging,
                    blob,
                    encoding,
                )?;
                staging.rewind()?;
                Ok(staging)
            })
        {
            io::copy(&mut staging, &mut destination)?;
            return Ok(());
        }
        if let Some(deadline) = self.publication_deadline {
            let timeout = self
                .client
                .timeout
                .min(deadline.saturating_duration_since(Instant::now()));
            if !timeout.is_zero() {
                match self
                    .client
                    .try_download_response(self.ticket, blob, timeout)
                {
                    Ok(Some((reader, encoding))) => {
                        return crate::build_runtime::transfer_native_blob(
                            reader,
                            io::sink(),
                            destination,
                            blob,
                            encoding,
                        );
                    }
                    Ok(None) => {}
                    Err(error) if super::retryable_transport_error(&error) => {
                        debug!("retrying provisional scheduler delivery after commit: {error:#}")
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        self.wait_for_fallback()?;
        self.client.download(self.ticket, blob, destination)
    }
}
