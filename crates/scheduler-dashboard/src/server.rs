//! Scheduler-local HTTP listener, independent sampler and SSE broadcast.
use std::{
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    extract::{Query, Request},
    http::header,
    response::{
        IntoResponse,
        sse::{KeepAlive, Sse},
    },
    routing::{get, post},
};
use leptos::prelude::*;
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};

use crate::{
    DashboardData, MetricsView, NativeEvent, NativeTelemetry, Sample, Snapshot, apply_event,
    make_patch,
};

mod broadcast;
mod metrics;

#[derive(Clone)]
pub(crate) struct DashboardState {
    feed: Arc<broadcast::Feed<DashboardData>>,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            feed: Arc::new(broadcast::Feed::new(DashboardData::default(), 32)),
        }
    }
}

impl DashboardState {
    pub(crate) fn snapshot(&self) -> DashboardData {
        self.feed.inspect(Clone::clone)
    }

    fn publish(
        &self,
        result: Result<Snapshot>,
        history: bool,
        telemetry: Option<NativeTelemetry>,
        timestamp: u64,
    ) -> Result<()> {
        self.feed.publish(|state| {
            let sample = history.then(|| Sample {
                admission: telemetry.as_ref().and_then(|value| value.admission),
                unix_secs: timestamp,
                totals: result.as_ref().ok().map(|snapshot| snapshot.totals.clone()),
            });
            let mut patch = match result {
                Ok(snapshot) => {
                    if !history
                        && state.snapshot.as_ref() == Some(&snapshot)
                        && state.error.is_none()
                        && telemetry.is_none()
                    {
                        return Ok(None);
                    }
                    make_patch(state, Some(&snapshot), Some(timestamp), sample, None)
                }
                Err(error) => {
                    // A change wake-up is an optional low-latency projection.
                    // Avoid flickering a warning on momentary lock contention.
                    if !history && telemetry.is_none() {
                        return Ok(None);
                    }
                    let message = "Scheduler snapshot unavailable; showing last successful sample";
                    if state.error.as_deref() != Some(message) {
                        log::warn!("dashboard sample failed: {error:#}");
                    }
                    make_patch(state, None, None, sample, Some(message.into()))
                }
            };
            if let Some(mut telemetry) = telemetry {
                telemetry.sampled_at = timestamp;
                if telemetry.cache.is_some() {
                    telemetry.cache_sampled_at = Some(timestamp);
                } else if telemetry.cache_error.is_some()
                    && let Some(previous) = &state.telemetry
                {
                    telemetry.cache.clone_from(&previous.cache);
                    telemetry.cache_sampled_at = previous.cache_sampled_at;
                }
                patch.telemetry = Some(telemetry);
            }
            let event = NativeEvent::Patch(Box::new(patch));
            let payload: Arc<str> = serde_json::to_string(&event)?.into();
            ensure!(
                apply_event(state, event),
                "internal dashboard revision mismatch"
            );
            Ok(Some(payload))
        })
    }
}

pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Bind only a loopback listener. Assets and the metrics endpoint are explicit
/// deployment configuration, not inferred from environment variables.
///
/// # Errors
/// Returns an error on invalid configuration, missing assets or bind failure.
pub fn spawn(
    address: SocketAddr,
    assets: &Path,
    metrics_url: Option<&str>,
    metrics_ingress_host: Option<&str>,
    snapshot: impl Fn() -> Result<Snapshot> + Send + 'static,
    telemetry: impl Fn() -> Option<NativeTelemetry> + Send + 'static,
    wake: std::sync::mpsc::Receiver<()>,
) -> Result<SocketAddr> {
    ensure!(
        address.ip().is_loopback(),
        "dashboard listener must be loopback"
    );
    ensure!(
        assets.is_absolute(),
        "dashboard assets must be an absolute path"
    );
    for name in [
        "sccache-dashboard.js",
        "sccache-dashboard_bg.wasm",
        "sccache-dashboard.css",
    ] {
        ensure!(
            assets.join(name).is_file(),
            "dashboard asset missing: {name}"
        );
    }
    let metrics = metrics::MetricsService::new(metrics_url, metrics_ingress_host)?;
    let listener = TcpListener::bind(address).context("bind scheduler dashboard")?;
    let address = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let state = DashboardState::default();
    let status_state = state.clone();
    std::thread::Builder::new()
        .name("scheduler-dashboard-sampler".into())
        .spawn(move || {
            sample_loop(&status_state, snapshot, telemetry, &wake);
        })?;
    let router = router(state, metrics, assets);
    std::thread::Builder::new()
        .name("scheduler-dashboard-http".into())
        .spawn(move || {
            runtime.block_on(async move {
                let result = async {
                    let listener = tokio::net::TcpListener::from_std(listener)?;
                    axum::serve(listener, router).await
                }
                .await;
                if let Err(error) = result {
                    log::error!("scheduler dashboard listener failed: {error}");
                }
            });
        })?;
    log::info!("Scheduler status dashboard listening on http://{address}");
    Ok(address)
}

fn sample_loop(
    state: &DashboardState,
    snapshot: impl Fn() -> Result<Snapshot>,
    telemetry: impl Fn() -> Option<NativeTelemetry>,
    wake: &std::sync::mpsc::Receiver<()>,
) {
    use std::time::Instant;
    const HISTORY_INTERVAL: Duration = Duration::from_secs(2);
    const MIN_CHANGE_INTERVAL: Duration = Duration::from_millis(100);
    let mut next_history = Instant::now();
    loop {
        let instant = Instant::now();
        let history = instant >= next_history;
        if history {
            next_history = instant + HISTORY_INTERVAL;
        }
        let timestamp = now();
        if let Err(error) = state.publish(
            snapshot(),
            history,
            if history { telemetry() } else { None },
            timestamp,
        ) {
            log::error!("dashboard publish failed: {error:#}");
        }
        let next_change = Instant::now() + MIN_CHANGE_INTERVAL;
        match wake.recv_timeout(next_history.saturating_duration_since(Instant::now())) {
            Ok(()) => {
                // Keep periodic history even while nobody is watching, but
                // avoid taking scheduler locks for every mutation in that case.
                let deadline = if state.feed.has_subscribers() {
                    next_change.min(next_history)
                } else {
                    next_history
                };
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                if wake.try_recv() == Err(std::sync::mpsc::TryRecvError::Disconnected) {
                    return;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn router(state: DashboardState, metrics: metrics::MetricsService, assets: &Path) -> Router {
    let _ = any_spawner::Executor::init_tokio();
    let ssr_state = state.clone();
    let api_state = state.clone();
    let options = leptos::config::LeptosOptions::builder()
        .output_name("sccache-dashboard")
        .site_pkg_dir("pkg")
        .build();
    let render = leptos_axum::render_app_to_stream_with_context(
        move || provide_context(ssr_state.clone()),
        move || crate::app::shell(options.clone()),
    );
    Router::new()
        .route("/", get(render))
        .route(
            "/api/snapshot",
            post(move |request: Request| {
                let state = api_state.clone();
                async move {
                    leptos_axum::handle_server_fns_with_context(
                        move || provide_context(state.clone()),
                        request,
                    )
                    .await
                }
            }),
        )
        .route(
            "/api/events",
            get(move || {
                let state = state.clone();
                async move {
                    Sse::new(broadcast::events(state.feed, ())).keep_alive(KeepAlive::default())
                }
            }),
        )
        .route(
            "/api/metrics/events",
            get(move |Query(view): Query<MetricsView>| {
                let metrics = metrics.clone();
                async move { metrics.events(view).into_response() }
            }),
        )
        .nest_service("/pkg", ServeDir::new(assets))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            header::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            header::HeaderValue::from_static("DENY"),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HISTORY_CAPACITY;

    #[test]
    fn failed_samples_preserve_last_good_data_and_history_is_bounded() -> Result<()> {
        let state = DashboardState::default();
        for index in 0..=HISTORY_CAPACITY {
            state.publish(
                Ok(Snapshot::default()),
                true,
                None,
                u64::try_from(index)? * 2,
            )?;
        }
        state.publish(
            Err(anyhow::anyhow!("failure")),
            true,
            None,
            u64::try_from(HISTORY_CAPACITY)? * 2 + 2,
        )?;
        let status = state.snapshot();
        assert_eq!(status.history.len(), HISTORY_CAPACITY);
        assert!(status.snapshot.is_some());
        assert!(status.error.is_some());
        assert!(
            status
                .history
                .last()
                .is_some_and(|sample| sample.totals.is_none())
        );
        Ok(())
    }

    #[test]
    fn transport_samples_are_independent_and_failed_cas_retains_previous_stats() -> Result<()> {
        let state = DashboardState::default();
        let cache = crate::Cache {
            actions: 7,
            results: 2,
            trees: 3,
            blobs: 4,
            logical_bytes: 5,
            pending_gc_blobs: 6,
            pending_gc_bytes: 7,
        };
        state.publish(
            Ok(Snapshot::default()),
            true,
            Some(NativeTelemetry {
                cache: Some(cache.clone()),
                ..Default::default()
            }),
            10,
        )?;
        let previous = state.snapshot();
        state.publish(Ok(Snapshot::default()), false, None, 11)?;
        assert_eq!(state.snapshot(), previous);
        state.publish(
            Err(anyhow::anyhow!("scheduler failed")),
            true,
            Some(NativeTelemetry {
                cache_error: Some("CAS unavailable; showing last successful sample".into()),
                admission: Some(crate::AdmissionCounts {
                    hits: 17,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            12,
        )?;
        let snapshot = state.snapshot();
        assert!(snapshot.error.is_some());
        assert_eq!(snapshot.history.len(), 2);
        let sample = snapshot.history.last().context("missing sample")?;
        assert!(sample.totals.is_none());
        assert_eq!(sample.admission.map(|counts| counts.hits), Some(17));
        let telemetry = snapshot.telemetry.context("telemetry missing")?;
        assert_eq!(telemetry.cache, Some(cache));
        assert!(telemetry.cache_error.is_some());
        assert_eq!(telemetry.cache_sampled_at, Some(10));
        assert_eq!(telemetry.sampled_at, 12);
        Ok(())
    }

    #[tokio::test]
    async fn subscription_reset_has_no_gap_and_lag_is_resynchronizable() -> Result<()> {
        let state = DashboardState::default();
        state.publish(Ok(Snapshot::default()), true, None, 1)?;
        let (reset, mut rx) = state.feed.subscribe()?;
        let mut client = DashboardData::default();
        assert!(apply_event(&mut client, serde_json::from_str(&reset)?));
        state.publish(Ok(Snapshot::default()), true, None, 2)?;
        let event = rx.recv().await?;
        assert!(apply_event(&mut client, serde_json::from_str(&event)?));
        assert_eq!(client, state.snapshot());
        for timestamp in 3..43 {
            state.publish(Ok(Snapshot::default()), true, None, timestamp)?;
        }
        assert!(matches!(
            rx.recv().await,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_))
        ));
        let (reset, _) = state.feed.subscribe()?;
        assert!(apply_event(&mut client, serde_json::from_str(&reset)?));
        assert_eq!(client, state.snapshot());
        Ok(())
    }

    #[tokio::test]
    async fn change_notification_does_not_grow_history() -> Result<()> {
        let state = DashboardState::default();
        state.publish(Ok(Snapshot::default()), true, None, 1)?;
        let (reset, mut rx) = state.feed.subscribe()?;
        let mut client = DashboardData::default();
        assert!(apply_event(&mut client, serde_json::from_str(&reset)?));
        let mut snapshot = Snapshot::default();
        snapshot.totals.workers = 2;
        state.publish(Ok(snapshot), false, None, 2)?;
        let event = rx.recv().await?;
        assert!(apply_event(&mut client, serde_json::from_str(&event)?));
        assert_eq!(client.history.len(), 1);
        assert_eq!(
            client
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.totals.workers),
            Some(2)
        );
        assert_eq!(client, state.snapshot());
        Ok(())
    }

    async fn first_event(response: wreq::Response) -> Result<NativeEvent> {
        use futures::StreamExt as _;
        let mut buffer = Vec::new();
        let mut body = std::pin::pin!(response.bytes_stream());
        loop {
            let chunk = body
                .next()
                .await
                .context("event stream ended before data")??;
            buffer.extend_from_slice(&chunk);
            if let Some(end) = buffer.windows(2).position(|pair| pair == b"\n\n") {
                let message = std::str::from_utf8(&buffer[..end])?;
                let data = message
                    .lines()
                    .find_map(|line| line.strip_prefix("data: "))
                    .context("event data missing")?;
                return Ok(serde_json::from_str(data)?);
            }
        }
    }

    #[tokio::test]
    async fn http_stream_reconnects_with_current_snapshot() -> Result<()> {
        let state = DashboardState::default();
        state.publish(Ok(Snapshot::default()), true, None, 1)?;
        let metrics = metrics::MetricsService::new(None, None)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let router = router(state.clone(), metrics, Path::new("."));
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let client = wreq::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()?;
        let response = client
            .get(format!("{base}/api/events"))
            .send()
            .await?
            .error_for_status()?;
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        let mut snapshot = DashboardData::default();
        assert!(apply_event(&mut snapshot, first_event(response).await?));
        assert_eq!(snapshot, state.snapshot());
        let mut changed = Snapshot::default();
        changed.totals.workers = 7;
        state.publish(Ok(changed), false, None, 2)?;
        let response = client
            .get(format!("{base}/api/events"))
            .send()
            .await?
            .error_for_status()?;
        assert!(apply_event(&mut snapshot, first_event(response).await?));
        assert_eq!(snapshot, state.snapshot());
        assert_eq!(
            snapshot
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.totals.workers),
            Some(7)
        );
        let html = client
            .get(&base)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        assert!(html.contains("Scheduler status"));
        assert!(html.contains("sccache-dashboard.css"));
        assert!(html.contains("Scheduler activity"));
        assert!(!html.contains("id=\"jobs\""));
        assert!(!html.contains("id=\"topology\""));
        assert!(!html.contains("id=\"metrics\""));
        server.abort();
        Ok(())
    }
}
