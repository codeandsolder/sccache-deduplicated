//! A receiver negotiates exact content against its authorized lease. The same
//! peer transport serves committed results and worker input closures.
use anyhow::{Context, Result};
use bincode::Options;
use sccache_cluster_identity::Role;
use std::{
    collections::BTreeMap,
    future::Future,
    time::{Duration, Instant},
};

use super::{BlobSourceRequest, NativeCacheClient, codec};
use crate::{
    build_runtime::{
        BlobEncoding, BlobRef, ContentId,
        wire::{BlobSource, BlobSourcePlan, MAX_BLOB_SOURCES, MAX_SOURCE_BATCH, Ticket},
    },
    dist::{
        cluster::AsyncResponseReader,
        cluster_routes::{MeasuredReader, Transfer},
    },
};

impl NativeCacheClient {
    pub(in crate::dist) fn source_plans(
        &self,
        ticket: Ticket,
        blobs: &[BlobRef],
    ) -> BTreeMap<ContentId, BlobSourcePlan> {
        self.source_plans_for("blob_sources", ticket, blobs)
    }

    pub(super) fn retained_source_plans(
        &self,
        group: Ticket,
        blobs: &[BlobRef],
    ) -> BTreeMap<ContentId, BlobSourcePlan> {
        self.source_plans_for("retain_sources", group, blobs)
    }

    fn source_plans_for(
        &self,
        operation: &str,
        ticket: Ticket,
        blobs: &[BlobRef],
    ) -> BTreeMap<ContentId, BlobSourcePlan> {
        let mut plans = BTreeMap::new();
        for batch in blobs.chunks(MAX_SOURCE_BATCH) {
            let reply: Result<Vec<BlobSourcePlan>> = self.control(
                operation,
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

    fn direct_candidates<'a>(
        &self,
        plan: &'a BlobSourcePlan,
        routes: Option<&sccache_peer_identity::RouteSet>,
    ) -> Vec<(u128, &'a BlobSource)> {
        if plan.sources.is_empty() {
            return Vec::new();
        }
        let transfer = Transfer::Download(plan.blob.size);
        let scheduler_cost = if let Some(routes) = routes {
            self.routes
                .estimated_cost(self.peer.scheduler_id(), Role::Scheduler, routes, transfer)
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
        !plan.sources.is_empty()
            && !self
                .direct_candidates(
                    plan,
                    plan.scheduler_present.then(|| self.cache_routes()).as_ref(),
                )
                .is_empty()
    }

    /// Synchronous compiler/IPC sinks remain at the synchronous boundary.
    /// Routing, HTTP bodies and worker CAS consumers use the same async path.
    pub(in crate::dist) fn try_peer_blob<T>(
        &self,
        plan: &BlobSourcePlan,
        mut consume: impl FnMut(
            tokio_util::io::SyncIoBridge<MeasuredReader<AsyncResponseReader>>,
            BlobEncoding,
        ) -> Result<T>,
    ) -> Option<T> {
        crate::http_client::io_runtime()
            .ok()?
            .block_on(self.try_peer_blob_async(plan, |reader, encoding| {
                let reader = tokio_util::io::SyncIoBridge::new(reader);
                std::future::ready(tokio::task::block_in_place(|| consume(reader, encoding)))
            }))
    }

    /// The consumer verifies before success. A rejected transfer starts with
    /// a fresh consumer, and never exposes its unverified prefix.
    #[expect(
        clippy::future_not_send,
        reason = "also serves synchronous non-Send IPC output sinks; worker consumers are Send"
    )]
    pub(super) async fn try_peer_blob_async<T, F, Fut>(
        &self,
        plan: &BlobSourcePlan,
        mut consume: F,
    ) -> Option<T>
    where
        F: FnMut(MeasuredReader<AsyncResponseReader>, BlobEncoding) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        if plan.sources.is_empty() {
            return None;
        }
        self.routes
            .probe_routes_async(
                plan.sources
                    .iter()
                    .map(|source| (source.peer, Role::Worker, &source.routes))
                    .collect(),
            )
            .await;
        let cache_routes = if plan.scheduler_present {
            Some(self.cache_routes_async().await)
        } else {
            None
        };
        let blob = plan.blob;
        let started = Instant::now();
        for (cost, source) in self.direct_candidates(plan, cache_routes.as_ref()) {
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
                let attempt = Instant::now();
                match self
                    .receive_peer_blob(blob, source, address, remaining)
                    .await
                {
                    Ok(Some((reader, encoding))) => {
                        let encoded_length = reader.content_length();
                        let (mut connection, evidence) = reader.connection_evidence();
                        match consume(reader, encoding).await {
                            Ok(value) => {
                                if connection.reported.is_some() {
                                    connection.quality = evidence
                                        .map_or(connection.quality, |sample| sample.quality());
                                    self.routes.verified_download(
                                        source.peer,
                                        address,
                                        connection,
                                        blob.size,
                                        encoded_length,
                                        attempt.elapsed(),
                                    );
                                }
                                return Some(value);
                            }
                            Err(error) => {
                                self.routes.failed(source.peer, Role::Worker, address);
                                debug!("native peer content rejected: {error:#}");
                            }
                        }
                    }

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

    async fn receive_peer_blob(
        &self,
        blob: BlobRef,
        source: &BlobSource,
        address: crate::dist::cluster_routes::Route,
        remaining: Duration,
    ) -> Result<Option<(MeasuredReader<AsyncResponseReader>, BlobEncoding)>> {
        let (client, base) = self.routes.endpoint(source.peer, Role::Worker, address)?;
        let response = client
            .post(crate::dist::http::urls::server_native_blob(&base)?.as_str())
            .bearer_auth(&source.token)
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .timeout(remaining)
            .body(codec().serialize(&blob)?)
            .send()
            .await?;
        if matches!(
            response.status(),
            http::StatusCode::NOT_FOUND
                | http::StatusCode::UNAUTHORIZED
                | http::StatusCode::FORBIDDEN
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
        let reader =
            self.routes
                .measure_response_async(source.peer, Role::Worker, address, response);
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
            anyhow::ensure!(!remaining.is_zero(), "native publication deadline exceeded");
            match self.control_with_timeout(
                "status",
                &super::StatusRequest {
                    ticket,
                    preview: false,
                },
                remaining,
            ) {
                Ok(NativeStatus::Ready(manifest)) => return Ok(manifest),
                Ok(NativeStatus::Failed) => anyhow::bail!("native result publication failed"),
                Ok(NativeStatus::Compiling | NativeStatus::Negotiated(_)) => {}
                Err(error) if super::retryable_transport_error(&error) => {}
                Err(error) => return Err(error),
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
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
    delivered: std::collections::BTreeSet<ContentId>,
    observation: crate::build_runtime::wire::ClientDeliveryObservation,
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
            delivered: std::collections::BTreeSet::new(),
            observation: crate::build_runtime::wire::ClientDeliveryObservation::default(),
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

    pub(super) fn observation(
        &self,
        elapsed: Duration,
    ) -> crate::build_runtime::wire::ClientDeliveryObservation {
        crate::build_runtime::wire::ClientDeliveryObservation {
            selected_bytes: self.declared.values().copied().sum(),
            staging_nanoseconds: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
            ..self.observation
        }
    }

    fn record(&mut self, blob: BlobRef, direct: bool) {
        if self.delivered.insert(blob.id) {
            self.observation.unique_blobs += 1;
            if direct {
                self.observation.direct_bytes += blob.size;
            } else {
                self.observation.scheduler_bytes += blob.size;
            }
        }
    }

    pub(super) fn download(
        &mut self,
        blob: BlobRef,
        destination: &mut super::client::BlobSink<'_>,
    ) -> Result<()> {
        use super::client::BlobSink;
        use std::io::{self, Seek};
        anyhow::ensure!(
            self.declared.get(&blob.id) == Some(&blob.size),
            "undeclared native result blob"
        );
        self.refresh(blob);
        if let Some(plan) = self.plans.get(&blob.id).and_then(Option::as_ref) {
            // Only IPC needs a separate spool: its frame cannot be rewound
            // after a failed peer transfer. File and memory staging can.
            let mut spool = matches!(destination, BlobSink::Stream(_))
                .then(tempfile::tempfile)
                .transpose()?;
            let direct = {
                let mut target = spool
                    .as_mut()
                    .map_or_else(|| destination.reborrow(), BlobSink::File);
                self.client
                    .try_peer_blob(plan, |reader, encoding| {
                        target.reset()?;
                        crate::build_runtime::transfer_native_blob(
                            reader,
                            io::sink(),
                            &mut target,
                            blob,
                            encoding,
                        )
                    })
                    .is_some()
            };
            if direct {
                if let Some(mut file) = spool {
                    file.rewind()?;
                    io::copy(&mut file, &mut *destination)?;
                }
                self.record(blob, true);
                return Ok(());
            }
            if !matches!(destination, BlobSink::Stream(_)) {
                destination.reset()?;
            }
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
                        crate::build_runtime::transfer_native_blob(
                            reader,
                            io::sink(),
                            destination,
                            blob,
                            encoding,
                        )?;
                        self.record(blob, false);
                        return Ok(());
                    }
                    Ok(None) => {}
                    Err(error) if super::retryable_transport_error(&error) => {
                        debug!("retrying provisional scheduler delivery after commit: {error:#}");
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        self.wait_for_fallback()?;
        self.client.download(self.ticket, blob, destination)?;
        self.record(blob, false);
        Ok(())
    }
}
