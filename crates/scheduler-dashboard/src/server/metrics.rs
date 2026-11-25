//! Fixed PromQL templates and demand-driven, shared historical SSE feeds.
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use axum::{
    http::StatusCode,
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures::{Stream, StreamExt, stream};
use serde::Deserialize;
use tokio::sync::{Semaphore, broadcast, watch};

use crate::{
    MetricPanel, MetricSeries, MetricsData, MetricsEvent, MetricsView, make_metrics_patch,
};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_SERIES: usize = 128;
const MAX_POINTS: usize = 512;
const MAX_VIEWS: usize = 8;

#[derive(Clone, Deserialize)]
struct PanelDefinition {
    title: String,
    unit: String,
    queries: Vec<QueryDefinition>,
}

#[derive(Clone, Deserialize)]
struct QueryDefinition {
    expr: String,
    legend: String,
}

#[derive(Deserialize)]
struct QueryResponse<T> {
    status: String,
    data: Option<T>,
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

struct Source {
    base: reqwest::Url,
    client: reqwest::Client,
    definitions: Vec<PanelDefinition>,
    queries: Semaphore,
}

#[derive(Clone)]
pub(super) struct MetricsService {
    source: Option<Arc<Source>>,
    feeds: Arc<Mutex<BTreeMap<MetricsView, Weak<Feed>>>>,
}

struct Feed {
    data: Mutex<MetricsData>,
    changes: broadcast::Sender<Arc<str>>,
    // Once the last lease is dropped this feed cannot be resurrected.
    subscribers: Mutex<usize>,
    stopped: watch::Sender<bool>,
}

impl Feed {
    fn new(view: MetricsView) -> Self {
        let (changes, _) = broadcast::channel(4);
        let (stopped, _) = watch::channel(false);
        Self {
            data: Mutex::new(MetricsData {
                configured: true,
                view,
                ..Default::default()
            }),
            changes,
            subscribers: Mutex::new(1),
            stopped,
        }
    }

    fn try_lease(self: &Arc<Self>) -> Option<Lease> {
        let mut count = self
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *count == 0 {
            return None;
        }
        *count += 1;
        Some(Lease(Arc::clone(self)))
    }

    fn active(&self) -> bool {
        !*self.stopped.borrow()
    }

    fn subscribe(&self) -> Result<(String, broadcast::Receiver<Arc<str>>)> {
        let data = self
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let receiver = self.changes.subscribe();
        Ok((
            serde_json::to_string(&MetricsEvent::Reset(data.clone()))?,
            receiver,
        ))
    }

    fn publish(&self, mut data: MetricsData) -> Result<()> {
        let mut previous = self
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let patch = make_metrics_patch(&previous, &data);
        data.revision = patch.revision;
        let payload: Arc<str> = serde_json::to_string(&MetricsEvent::Patch(patch))?.into();
        *previous = data;
        let _ = self.changes.send(payload);
        Ok(())
    }
}

struct Lease(Arc<Feed>);

impl Drop for Lease {
    fn drop(&mut self) {
        let mut count = self
            .0
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count -= 1;
        if *count == 0 {
            self.0.stopped.send_replace(true);
        }
    }
}

fn feed_stream(
    feed: Arc<Feed>,
    subscription: Lease,
) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::unfold(
        (feed, subscription, None),
        |(feed, subscription, receiver): (_, _, Option<broadcast::Receiver<Arc<str>>>)| async move {
            let next = match receiver {
                Some(mut receiver) => match receiver.recv().await {
                    Ok(payload) => Some((super::event(payload), receiver)),
                    Err(broadcast::error::RecvError::Lagged(_)) => feed
                        .subscribe()
                        .ok()
                        .map(|(reset, receiver)| (super::event(reset), receiver)),
                    Err(broadcast::error::RecvError::Closed) => None,
                },
                None => feed
                    .subscribe()
                    .ok()
                    .map(|(reset, receiver)| (super::event(reset), receiver)),
            };
            next.map(|(event, receiver)| (Ok(event), (feed, subscription, Some(receiver))))
        },
    )
}

impl MetricsService {
    pub(super) fn new(url: Option<&str>) -> Result<Self> {
        let source = url
            .map(|url| -> Result<_> {
                let mut base = reqwest::Url::parse(url)?;
                ensure!(
                    matches!(base.scheme(), "http" | "https")
                        && base.host().is_some()
                        && base.username().is_empty()
                        && base.password().is_none()
                        && base.query().is_none()
                        && base.fragment().is_none(),
                    "metrics URL must be an HTTP(S) base URL without credentials or query"
                );
                if !base.path().ends_with('/') {
                    base.set_path(&format!("{}/", base.path()));
                }
                Ok(Arc::new(Source {
                    base,
                    client: reqwest::Client::builder()
                        .timeout(Duration::from_secs(10))
                        .redirect(reqwest::redirect::Policy::none())
                        .no_proxy()
                        .build()?,
                    definitions: serde_json::from_str(include_str!("../panels.json"))?,
                    queries: Semaphore::new(4),
                }))
            })
            .transpose()?;
        Ok(Self {
            source,
            feeds: Arc::default(),
        })
    }

    pub(super) fn events(&self, view: MetricsView) -> Response {
        if view.client.len() > 253 || view.client.chars().any(char::is_control) {
            return (StatusCode::BAD_REQUEST, "invalid client label").into_response();
        }
        let Some(source) = &self.source else {
            let data = MetricsData {
                view,
                ..Default::default()
            };
            return match serde_json::to_string(&MetricsEvent::Reset(data)) {
                Ok(payload) => Sse::new(
                    stream::once(async move { Ok::<_, Infallible>(super::event(payload)) })
                        .chain(stream::pending()),
                )
                .keep_alive(KeepAlive::default())
                .into_response(),
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
        };
        let (feed, subscriber) = {
            let mut feeds = self
                .feeds
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            feeds.retain(|_, weak| weak.upgrade().is_some_and(|feed| feed.active()));
            if let Some((feed, subscription)) =
                feeds.get(&view).and_then(Weak::upgrade).and_then(|feed| {
                    let lease = feed.try_lease()?;
                    Some((feed, lease))
                })
            {
                (feed, subscription)
            } else {
                feeds.remove(&view);
                if feeds.len() >= MAX_VIEWS {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "too many distinct metrics views",
                    )
                        .into_response();
                }
                let feed = Arc::new(Feed::new(view.clone()));
                let subscription = Lease(Arc::clone(&feed));
                feeds.insert(view.clone(), Arc::downgrade(&feed));
                let (source, task_feed) = (Arc::clone(source), Arc::clone(&feed));
                tokio::spawn(async move {
                    let mut stopped = task_feed.stopped.subscribe();
                    tokio::select! {
                        _ = stopped.wait_for(|stopped| *stopped) => {}
                        () = refresh(source, &task_feed, view) => {}
                    }
                });
                (feed, subscription)
            }
        };
        Sse::new(feed_stream(feed, subscriber))
            .keep_alive(KeepAlive::default())
            .into_response()
    }
}

fn series_label(labels: &BTreeMap<String, String>, legend: &str) -> String {
    if legend.is_empty() || legend == "__auto" {
        if labels.is_empty() {
            "Total".into()
        } else {
            labels
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(", ")
        }
    } else {
        labels
            .iter()
            .fold(legend.to_owned(), |label, (key, value)| {
                label.replace(&format!("{{{{{key}}}}}"), value)
            })
    }
}

fn quote_client(client: &str) -> String {
    // Escape the regex metacharacters, then the PromQL quoted-string layer.
    // The template already contains the enclosing quotation marks.
    if client.is_empty() {
        return ".*".into();
    }
    let mut pattern = String::new();
    for ch in client.chars() {
        if ".+*?()|[]{}^$\\".contains(ch) {
            pattern.push('\\');
        }
        pattern.push(ch);
    }
    let quoted = serde_json::Value::String(pattern).to_string();
    quoted[1..quoted.len() - 1].to_owned()
}

fn expression(definition: &QueryDefinition, view: &MetricsView) -> String {
    // Range windows stay explicit; rates are at least 5 min and span several
    // points at coarser resolutions. No raw query from browser input.
    definition
        .expr
        .replace(
            "$__rate_interval",
            &format!("{}s", (view.range.step() * 4).max(300)),
        )
        .replace("$__range", &format!("{}s", view.range.seconds()))
        .replace("$client", &quote_client(&view.client))
}

async fn get_json<T: serde::de::DeserializeOwned>(source: &Source, url: reqwest::Url) -> Result<T> {
    let _permit = source.queries.acquire().await?;
    let response = source.client.get(url).send().await?.error_for_status()?;
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
    let response: QueryResponse<T> = serde_json::from_slice(&bytes)?;
    ensure!(response.status == "success", "metrics query failed");
    response.data.context("metrics result missing")
}

async fn query(
    source: &Source,
    definition: &QueryDefinition,
    view: &MetricsView,
    end: u64,
    index: usize,
) -> Result<Vec<MetricSeries>> {
    let mut url = source.base.join("api/v1/query_range")?;
    url.query_pairs_mut()
        .append_pair("query", &expression(definition, view))
        .append_pair(
            "start",
            &end.saturating_sub(view.range.seconds()).to_string(),
        )
        .append_pair("end", &end.to_string())
        .append_pair("step", &view.range.step().to_string());
    let data: QueryData = get_json(source, url).await?;
    ensure!(data.result.len() <= MAX_SERIES, "too many metric series");
    data.result
        .into_iter()
        .map(|series| {
            ensure!(series.values.len() <= MAX_POINTS, "too many metric points");
            let mut points = series
                .values
                .into_iter()
                .map(|(time, raw)| {
                    (
                        time,
                        raw.parse::<f64>().ok().filter(|value| value.is_finite()),
                    )
                })
                .collect::<Vec<_>>();
            ensure!(
                points.iter().all(|(time, _)| time.is_finite()),
                "invalid metric timestamp"
            );
            points.sort_unstable_by(|a, b| a.0.total_cmp(&b.0));
            points.dedup_by(|a, b| a.0 == b.0);
            Ok(MetricSeries {
                key: format!("{index}:{}", serde_json::to_string(&series.metric)?),
                label: series_label(&series.metric, &definition.legend),
                points,
            })
        })
        .collect()
}

async fn read_panel(
    source: Arc<Source>,
    key: usize,
    definition: PanelDefinition,
    view: MetricsView,
    end: u64,
) -> MetricPanel {
    let mut panel = MetricPanel {
        key,
        title: definition.title,
        unit: definition.unit,
        series: Vec::new(),
        error: None,
    };
    for (index, definition) in definition.queries.iter().enumerate() {
        match query(&source, definition, &view, end, index).await {
            Ok(series) => panel.series.extend(series),
            Err(error) => {
                log::warn!("dashboard metrics panel {}: {error:#}", panel.title);
                panel.error = Some("One or more queries failed".into());
            }
        }
    }
    panel.series.sort_unstable_by(|a, b| a.key.cmp(&b.key));
    panel
}

async fn clients(source: &Source, end: u64, view: &MetricsView) -> Result<Vec<String>> {
    let mut url = source.base.join("api/v1/label/instance/values")?;
    url.query_pairs_mut()
        .append_pair("match[]", "sccache_info{resolution=\"raw\"}")
        .append_pair(
            "start",
            &end.saturating_sub(view.range.seconds()).to_string(),
        )
        .append_pair("end", &end.to_string());
    let mut labels: Vec<String> = get_json(source, url).await?;
    ensure!(labels.len() <= 4096, "too many client labels");
    labels.sort_unstable();
    labels.dedup();
    Ok(labels)
}

async fn refresh(source: Arc<Source>, feed: &Feed, view: MetricsView) {
    loop {
        // Fixed time grid makes consecutive queries comparable, including late
        // data arrivals. Account for the backend ingestion latency.
        let step = view.range.step();
        let end = super::now().saturating_sub(3) / step * step;
        let client_list = clients(&source, end, &view).await;
        let queries = source
            .definitions
            .clone()
            .into_iter()
            .enumerate()
            .map(|(key, definition)| {
                read_panel(Arc::clone(&source), key, definition, view.clone(), end)
            })
            .collect::<Vec<_>>();
        let panels = stream::iter(queries).buffered(4).collect::<Vec<_>>().await;
        let (clients, error) = match client_list {
            Ok(clients) => (clients, None),
            Err(error) => {
                log::warn!("dashboard client labels unavailable: {error:#}");
                (
                    feed.data
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clients
                        .clone(),
                    Some("Client discovery unavailable".into()),
                )
            }
        };
        let data = MetricsData {
            configured: true,
            view: view.clone(),
            sampled_at: Some(end),
            clients,
            error,
            panels,
            ..Default::default()
        };
        if let Err(error) = feed.publish(data) {
            log::error!("dashboard metric publish failed: {error:#}");
        }
        tokio::time::sleep(Duration::from_secs(step.max(15))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn final_lease_cannot_be_resurrected() {
        let feed = Arc::new(Feed::new(MetricsView::default()));
        let first = Lease(Arc::clone(&feed));
        let second = feed.try_lease().expect("active feed");
        drop(first);
        assert!(feed.active());
        drop(second);
        assert!(!feed.active());
        assert!(feed.try_lease().is_none());
    }

    #[test]
    fn manifest_is_complete_and_client_cannot_inject_promql() -> Result<()> {
        let panels: Vec<PanelDefinition> = serde_json::from_str(include_str!("../panels.json"))?;
        assert_eq!(panels.len(), 33);
        let view = MetricsView {
            client: "host.*\"} or vector(1) #".into(),
            ..Default::default()
        };
        let escaped = quote_client(&view.client);
        assert!(escaped.contains("\\\\."));
        let quoted = format!("\"{escaped}\"");
        let decoded: String = serde_json::from_str(&quoted)?;
        assert!(decoded.contains("\\.\\*"));
        assert!(panels.iter().flat_map(|panel| &panel.queries).all(|query| {
            let result = expression(query, &view);
            !result.contains("$__") && !result.contains("$client")
        }));
        Ok(())
    }
}
