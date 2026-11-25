//! Local-only HTTP listener and bounded, independently sampled status state.
use std::{
    collections::{BTreeMap, VecDeque},
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    extract::Request,
    http::header,
    routing::{get, post},
};
use futures::{StreamExt, stream};
use leptos::prelude::*;
use serde::Deserialize;
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};

use crate::{DashboardData, MetricPanel, MetricSeries, MetricsData, Sample, Snapshot};

const HISTORY_CAPACITY: usize = 900;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_SERIES: usize = 128;
const MAX_POINTS: usize = 121;

#[derive(Clone, Default)]
pub(crate) struct DashboardState {
    pub(crate) status: Arc<Mutex<DashboardData>>,
    pub(crate) metrics: Arc<Mutex<MetricsData>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn update_status(state: &DashboardState, history: &mut VecDeque<Sample>, result: Result<Snapshot>) {
    let mut status = state
        .status
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match result {
        Ok(snapshot) => {
            let timestamp = now();
            if history.len() == HISTORY_CAPACITY {
                history.pop_front();
            }
            history.push_back(Sample {
                unix_secs: timestamp,
                totals: snapshot.totals.clone(),
            });
            *status = DashboardData {
                sampled_at: Some(timestamp),
                snapshot: Some(snapshot),
                history: history.iter().cloned().collect(),
                error: None,
            };
        }
        Err(error) => {
            log::warn!("dashboard sample failed: {error:#}");
            status.error =
                Some("Scheduler snapshot unavailable; showing last successful sample".into());
        }
    }
}

#[derive(Deserialize)]
struct PanelDefinition {
    title: String,
    unit: String,
    queries: Vec<QueryDefinition>,
}

#[derive(Deserialize)]
struct QueryDefinition {
    expr: String,
    legend: String,
}

#[derive(Deserialize)]
struct QueryResponse {
    status: String,
    data: Option<QueryData>,
}

#[derive(Deserialize)]
struct QueryData {
    result: Vec<QuerySeries>,
}

#[derive(Deserialize)]
struct QuerySeries {
    metric: BTreeMap<String, String>,
    values: Vec<(f64, String)>,
}

fn series_label(labels: &BTreeMap<String, String>, legend: &str) -> String {
    if legend.is_empty() || legend == "__auto" {
        return if labels.is_empty() {
            "Total".into()
        } else {
            labels
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
    }
    labels
        .iter()
        .fold(legend.to_owned(), |label, (key, value)| {
            label.replace(&format!("{{{{{key}}}}}"), value)
        })
}

async fn query(
    client: &reqwest::Client,
    url: &reqwest::Url,
    definition: &QueryDefinition,
    end: u64,
) -> Result<Vec<MetricSeries>> {
    let response = client
        .get(url.clone())
        .query(&[
            ("query", definition.expr.clone()),
            ("start", end.saturating_sub(3600).to_string()),
            ("end", end.to_string()),
            ("step", "30".to_owned()),
        ])
        .send()
        .await?
        .error_for_status()?;
    let mut bytes = Vec::new();
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_RESPONSE_BYTES,
            "metrics response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    let response: QueryResponse = serde_json::from_slice(&bytes)?;
    ensure!(response.status == "success", "metrics query failed");
    let data = response.data.context("metrics result missing")?;
    ensure!(data.result.len() <= MAX_SERIES, "too many metric series");
    data.result
        .into_iter()
        .map(|series| {
            ensure!(series.values.len() <= MAX_POINTS, "too many metric points");
            Ok(MetricSeries {
                label: series_label(&series.metric, &definition.legend),
                points: series
                    .values
                    .into_iter()
                    .map(|(time, raw)| {
                        (
                            time,
                            raw.parse::<f64>().ok().filter(|value| value.is_finite()),
                        )
                    })
                    .collect(),
            })
        })
        .collect()
}

async fn read_panel(
    client: &reqwest::Client,
    url: &reqwest::Url,
    definition: &PanelDefinition,
    end: u64,
) -> MetricPanel {
    let mut panel = MetricPanel {
        title: definition.title.clone(),
        unit: definition.unit.clone(),
        series: Vec::new(),
        error: None,
    };
    for definition in &definition.queries {
        match query(client, url, definition, end).await {
            Ok(series) => panel.series.extend(series),
            Err(error) => {
                log::warn!("dashboard metrics panel {}: {error:#}", panel.title);
                panel.error = Some("One or more queries failed".into());
            }
        }
    }
    panel
}

async fn refresh_metrics(
    state: DashboardState,
    url: reqwest::Url,
    definitions: Vec<PanelDefinition>,
    client: reqwest::Client,
) {
    loop {
        let end = now();
        let panels = stream::iter(
            definitions
                .iter()
                .map(|definition| read_panel(&client, &url, definition, end)),
        )
        .buffered(4)
        .collect::<Vec<_>>()
        .await;
        *state
            .metrics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = MetricsData {
            configured: true,
            sampled_at: Some(end),
            panels,
        };
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// Bind only a loopback listener. Assets and the metrics endpoint are explicit
/// deployment configuration, not inferred from environment variables.
pub fn spawn(
    address: SocketAddr,
    assets: &Path,
    metrics_url: Option<&str>,
    snapshot: impl Fn() -> Result<Snapshot> + Send + 'static,
) -> Result<()> {
    ensure!(
        address.ip().is_loopback(),
        "dashboard listener must be loopback"
    );
    ensure!(
        assets.is_absolute(),
        "dashboard assets must be an absolute path"
    );
    for name in ["sccache-dashboard.js", "sccache-dashboard_bg.wasm"] {
        ensure!(
            assets.join(name).is_file(),
            "dashboard asset missing: {name}"
        );
    }
    let metrics = metrics_url
        .map(|url| -> Result<_> {
            let url = reqwest::Url::parse(url)?;
            ensure!(
                matches!(url.scheme(), "http" | "https")
                    && url.host().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "metrics URL must be an HTTP(S) base URL without credentials or query"
            );
            let url = url.join("/api/v1/query_range")?;
            let definitions: Vec<PanelDefinition> =
                serde_json::from_str(include_str!("panels.json"))?;
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()?;
            Ok((url, definitions, client))
        })
        .transpose()?;
    let listener = TcpListener::bind(address).context("bind scheduler dashboard")?;
    listener.set_nonblocking(true)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let state = DashboardState::default();
    state
        .metrics
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .configured = metrics.is_some();
    let status_state = state.clone();
    std::thread::Builder::new()
        .name("scheduler-dashboard-sampler".into())
        .spawn(move || {
            let mut history = VecDeque::with_capacity(HISTORY_CAPACITY);
            loop {
                update_status(&status_state, &mut history, snapshot());
                std::thread::sleep(Duration::from_secs(2));
            }
        })?;
    // We construct explicit routes rather than generate a Leptos route list.
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
    let router = Router::new()
        .route("/", get(render))
        .route(
            "/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("style.css"),
                )
            }),
        )
        .route(
            "/api/{*fn_name}",
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
        .nest_service("/pkg", ServeDir::new(assets))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            header::HeaderValue::from_static("nosniff"),
        ));
    std::thread::Builder::new()
        .name("scheduler-dashboard-http".into())
        .spawn(move || {
            runtime.block_on(async move {
                if let Some((url, definitions, client)) = metrics {
                    tokio::spawn(refresh_metrics(state, url, definitions, client));
                }
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_samples_preserve_last_good_data_and_history_is_bounded() {
        let state = DashboardState::default();
        let mut history = VecDeque::new();
        for _ in 0..=HISTORY_CAPACITY {
            update_status(&state, &mut history, Ok(Snapshot::default()));
        }
        update_status(&state, &mut history, Err(anyhow::anyhow!("failure")));
        let status = state.status.lock().unwrap();
        assert_eq!(status.history.len(), HISTORY_CAPACITY);
        assert!(status.snapshot.is_some());
        assert!(status.error.is_some());
    }

    #[test]
    fn metrics_manifest_contains_no_grafana_variables() {
        let panels: Vec<PanelDefinition> =
            serde_json::from_str(include_str!("panels.json")).unwrap();
        assert!(panels.len() >= 30);
        assert!(
            panels
                .iter()
                .flat_map(|panel| &panel.queries)
                .all(|query| !query.expr.contains('$')
                    || !query.expr.contains("$__") && !query.expr.contains("$client"))
        );
    }
}
