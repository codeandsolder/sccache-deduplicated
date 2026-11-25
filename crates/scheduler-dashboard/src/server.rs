//! Scheduler-local HTTP listener, independent sampler and SSE broadcast.
use std::{
    convert::Infallible,
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    extract::{Query, Request},
    http::header,
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures::{Stream, stream};
use leptos::prelude::*;
use tokio::sync::broadcast;
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};

use crate::{DashboardData, MetricsView, NativeEvent, Sample, Snapshot, apply_event, make_patch};

mod metrics;

#[derive(Clone)]
pub(crate) struct DashboardState {
    data: Arc<Mutex<DashboardData>>,
    changes: broadcast::Sender<Arc<str>>,
}

impl Default for DashboardState {
    fn default() -> Self {
        let (changes, _) = broadcast::channel(32);
        Self {
            data: Arc::default(),
            changes,
        }
    }
}

impl DashboardState {
    fn lock(&self) -> MutexGuard<'_, DashboardData> {
        self.data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn snapshot(&self) -> DashboardData {
        self.lock().clone()
    }

    fn publish(&self, result: Result<Snapshot>, history: bool) -> Result<()> {
        let mut state = self.lock();
        let patch = match result {
            Ok(snapshot) => {
                if !history && state.snapshot.as_ref() == Some(&snapshot) && state.error.is_none() {
                    return Ok(());
                }
                let timestamp = now();
                let sample = history.then(|| Sample {
                    unix_secs: timestamp,
                    totals: snapshot.totals.clone(),
                });
                let mut patch = make_patch(&state, Some(&snapshot), sample, None);
                patch.sampled_at = Some(timestamp);
                patch
            }
            Err(error) => {
                log::warn!("dashboard sample failed: {error:#}");
                make_patch(
                    &state,
                    None,
                    None,
                    Some("Scheduler snapshot unavailable; showing last successful sample".into()),
                )
            }
        };
        let event = NativeEvent::Patch(Box::new(patch));
        let payload: Arc<str> = serde_json::to_string(&event)?.into();
        ensure!(
            apply_event(&mut state, event),
            "internal dashboard revision mismatch"
        );
        // Serialize once per producer update, not once per connected browser.
        // Subscription/reset also takes this lock, eliminating the initial-state race.
        let _ = self.changes.send(payload);
        Ok(())
    }

    fn subscribe(&self) -> Result<(String, broadcast::Receiver<Arc<str>>)> {
        let state = self.lock();
        let rx = self.changes.subscribe();
        let reset = serde_json::to_string(&NativeEvent::Reset(state.clone()))?;
        Ok((reset, rx))
    }
}

pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn event(data: impl AsRef<str>) -> Event {
    Event::default().data(data.as_ref())
}

fn native_stream(state: DashboardState) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::unfold(
        (state, None),
        |(state, rx): (DashboardState, Option<broadcast::Receiver<Arc<str>>>)| async move {
            let next = match rx {
                Some(mut rx) => match rx.recv().await {
                    Ok(payload) => Some((event(payload), rx)),
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        state.subscribe().ok().map(|(reset, rx)| (event(reset), rx))
                    }
                    Err(broadcast::error::RecvError::Closed) => None,
                },
                None => state.subscribe().ok().map(|(reset, rx)| (event(reset), rx)),
            };
            next.map(|(event, rx)| (Ok(event), (state, Some(rx))))
        },
    )
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
    snapshot: impl Fn() -> Result<Snapshot> + Send + 'static,
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
    let metrics = metrics::MetricsService::new(metrics_url)?;
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
            sample_loop(status_state, snapshot, wake);
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
    state: DashboardState,
    snapshot: impl Fn() -> Result<Snapshot>,
    wake: std::sync::mpsc::Receiver<()>,
) {
    use std::time::Instant;
    const HISTORY_INTERVAL: Duration = Duration::from_secs(2);
    const MIN_CHANGE_INTERVAL: Duration = Duration::from_millis(100);
    let mut next_history = Instant::now();
    loop {
        let now = Instant::now();
        let history = now >= next_history;
        if history {
            next_history = now + HISTORY_INTERVAL;
        }
        if let Err(error) = state.publish(snapshot(), history) {
            log::error!("dashboard publish failed: {error:#}");
        }
        let next_change = Instant::now() + MIN_CHANGE_INTERVAL;
        match wake.recv_timeout(next_history.saturating_duration_since(Instant::now())) {
            Ok(()) => {
                std::thread::sleep(next_change.saturating_duration_since(Instant::now()));
                let _ = wake.try_recv();
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
                async move { Sse::new(native_stream(state)).keep_alive(KeepAlive::default()) }
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
        for _ in 0..=HISTORY_CAPACITY {
            state.publish(Ok(Snapshot::default()), true)?;
        }
        state.publish(Err(anyhow::anyhow!("failure")), true)?;
        let status = state.snapshot();
        assert_eq!(status.history.len(), HISTORY_CAPACITY);
        assert!(status.snapshot.is_some());
        assert!(status.error.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn subscription_reset_has_no_gap_and_lag_is_resynchronizable() -> Result<()> {
        let state = DashboardState::default();
        state.publish(Ok(Snapshot::default()), true)?;
        let (reset, mut rx) = state.subscribe()?;
        let mut client = DashboardData::default();
        assert!(apply_event(&mut client, serde_json::from_str(&reset)?));
        state.publish(Ok(Snapshot::default()), true)?;
        let event = rx.recv().await?;
        assert!(apply_event(&mut client, serde_json::from_str(&event)?));
        assert_eq!(client, state.snapshot());
        for _ in 0..40 {
            state.publish(Ok(Snapshot::default()), true)?;
        }
        assert!(matches!(
            rx.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
        let (reset, _) = state.subscribe()?;
        assert!(apply_event(&mut client, serde_json::from_str(&reset)?));
        assert_eq!(client, state.snapshot());
        Ok(())
    }

    #[tokio::test]
    async fn change_notification_does_not_grow_history() -> Result<()> {
        let state = DashboardState::default();
        state.publish(Ok(Snapshot::default()), true)?;
        let (reset, mut rx) = state.subscribe()?;
        let mut client = DashboardData::default();
        assert!(apply_event(&mut client, serde_json::from_str(&reset)?));
        let mut snapshot = Snapshot::default();
        snapshot.totals.workers = 2;
        state.publish(Ok(snapshot), false)?;
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

    async fn first_event(response: &mut reqwest::Response) -> Result<NativeEvent> {
        let mut buffer = Vec::new();
        loop {
            let chunk = response
                .chunk()
                .await?
                .context("event stream ended before data")?;
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
        state.publish(Ok(Snapshot::default()), true)?;
        let metrics = metrics::MetricsService::new(None)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let router = router(state.clone(), metrics, Path::new("."));
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()?;
        let mut response = client
            .get(format!("{base}/api/events"))
            .send()
            .await?
            .error_for_status()?;
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        let mut snapshot = DashboardData::default();
        assert!(apply_event(
            &mut snapshot,
            first_event(&mut response).await?
        ));
        assert_eq!(snapshot, state.snapshot());
        drop(response);
        let mut changed = Snapshot::default();
        changed.totals.workers = 7;
        state.publish(Ok(changed), false)?;
        let mut response = client
            .get(format!("{base}/api/events"))
            .send()
            .await?
            .error_for_status()?;
        assert!(apply_event(
            &mut snapshot,
            first_event(&mut response).await?
        ));
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
        server.abort();
        Ok(())
    }
}
