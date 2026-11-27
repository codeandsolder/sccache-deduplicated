//! Fixed `PromQL` templates and demand-driven, shared historical SSE feeds.
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
        sse::{KeepAlive, Sse},
    },
};
use futures::{StreamExt, stream};
use serde::Deserialize;
use tokio::sync::{Semaphore, watch};

use crate::{
    MetricPanel, MetricSeries, MetricsData, MetricsEvent, MetricsView, PanelKind,
    make_metrics_patch,
};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_SERIES: usize = 128;
const MAX_POINTS: usize = 512;
const MAX_VIEWS: usize = 8;

#[derive(Clone, Deserialize)]
struct PanelDefinition {
    kind: PanelKind,
    title: String,
    unit: String,
    queries: Vec<QueryDefinition>,
    #[serde(default)]
    requires_client: bool,
    #[serde(default)]
    group: crate::MetricGroup,
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
    base: url::Url,
    client: wreq::Client,
    definitions: Vec<PanelDefinition>,
    ingress_host: Option<String>,
    queries: Semaphore,
}

#[derive(Clone)]
pub(super) struct MetricsService {
    source: Option<Arc<Source>>,
    feeds: Arc<Mutex<BTreeMap<MetricsView, Weak<Feed>>>>,
}

struct Feed {
    data: Arc<super::broadcast::Feed<MetricsData>>,
    // Once the last lease is dropped this feed cannot be resurrected.
    subscribers: Mutex<usize>,
    stopped: watch::Sender<bool>,
}

impl Feed {
    fn new(view: MetricsView) -> Self {
        let (stopped, _) = watch::channel(false);
        Self {
            data: Arc::new(super::broadcast::Feed::new(
                MetricsData {
                    configured: true,
                    view,
                    ..Default::default()
                },
                4,
            )),
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
        drop(count);
        Some(Lease(Arc::clone(self)))
    }

    fn active(&self) -> bool {
        !*self.stopped.borrow()
    }

    fn publish(&self, mut data: MetricsData) -> Result<()> {
        self.data.publish(|previous| {
            let patch = make_metrics_patch(previous, &data);
            data.revision = patch.revision;
            let payload = serde_json::to_string(&MetricsEvent::Patch(patch))?.into();
            *previous = data;
            Ok(Some(payload))
        })
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

impl MetricsService {
    pub(super) fn new(url: Option<&str>, ingress_host: Option<&str>) -> Result<Self> {
        ensure!(
            ingress_host.is_none_or(|host| !host.is_empty()
                && host.len() <= 253
                && !host.chars().any(char::is_control)),
            "invalid metrics ingress host"
        );
        ensure!(
            url.is_some() || ingress_host.is_none(),
            "metrics ingress host requires a metrics URL"
        );
        let source = url
            .map(|url| -> Result<_> {
                let mut base = url::Url::parse(url)?;
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
                    client: wreq::Client::builder()
                        .timeout(Duration::from_secs(10))
                        .redirect(wreq::redirect::Policy::none())
                        .no_proxy()
                        .build()?,
                    definitions: serde_json::from_str(include_str!("../panels.json"))?,
                    ingress_host: ingress_host.map(str::to_owned),
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
            return serde_json::to_string(&MetricsEvent::Reset(data)).map_or_else(
                |_| StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                |payload| {
                    Sse::new(
                        stream::once(async move {
                            Ok::<_, Infallible>(super::broadcast::event(payload))
                        })
                        .chain(stream::pending()),
                    )
                    .keep_alive(KeepAlive::default())
                    .into_response()
                },
            );
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
                drop(feeds);
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
                drop(feeds);
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
        Sse::new(super::broadcast::events(Arc::clone(&feed.data), subscriber))
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

fn quote_label(value: &str) -> String {
    let quoted = serde_json::Value::String(value.to_owned()).to_string();
    quoted[1..quoted.len() - 1].to_owned()
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
    quote_label(&pattern)
}

fn expression(
    definition: &QueryDefinition,
    view: &MetricsView,
    ingress_host: Option<&str>,
) -> String {
    let rate = format!("{}s", (view.range.step() * 4).max(300));
    let range = format!("{}s", view.range.seconds());
    let client = quote_client(&view.client);
    let host = quote_label(ingress_host.unwrap_or_default());
    let substitutions = [
        ("$__rate_interval", rate.as_str()),
        ("$__range", range.as_str()),
        ("$ingress_host", host.as_str()),
        ("$client", client.as_str()),
    ];
    let mut output = String::new();
    let mut rest = definition.expr.as_str();
    while let Some((position, token, value)) = substitutions
        .iter()
        .filter_map(|(token, value)| rest.find(token).map(|position| (position, *token, *value)))
        .min_by_key(|(position, _, _)| *position)
    {
        output.push_str(&rest[..position]);
        output.push_str(value);
        rest = &rest[position + token.len()..];
    }
    output.push_str(rest);
    output
}

async fn get_json<T: serde::de::DeserializeOwned>(source: &Source, url: url::Url) -> Result<T> {
    let _permit = source.queries.acquire().await?;
    let response = source
        .client
        .get(url.as_str())
        .send()
        .await?
        .error_for_status()?;
    let mut bytes = Vec::new();
    let mut body = std::pin::pin!(response.bytes_stream());
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
    window: QueryWindow,
    index: usize,
) -> Result<Vec<MetricSeries>> {
    let mut url = source.base.join("api/v1/query_range")?;
    url.query_pairs_mut()
        .append_pair(
            "query",
            &expression(definition, view, source.ingress_host.as_deref()),
        )
        .append_pair("start", &window.start.to_string())
        .append_pair("end", &window.end.to_string())
        .append_pair("step", &view.range.step().to_string());
    let data: QueryData = get_json(source, url).await?;
    decode_series(data, definition, window, view.range.step(), index)
}

fn decode_series(
    data: QueryData,
    definition: &QueryDefinition,
    window: QueryWindow,
    step: u64,
    index: usize,
) -> Result<Vec<MetricSeries>> {
    ensure!(data.result.len() <= MAX_SERIES, "too many metric series");
    let mut keys = std::collections::BTreeSet::new();
    data.result
        .into_iter()
        .map(|series| {
            let key = format!("{index}:{}", serde_json::to_string(&series.metric)?);
            ensure!(keys.insert(key.clone()), "duplicate metric series");
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
            let start = timestamp_seconds(window.start);
            let end = timestamp_seconds(window.end);
            let step = timestamp_seconds(step);
            ensure!(
                points.iter().all(|(time, _)| time.is_finite()
                    && *time >= start
                    && *time <= end
                    && (time - start).rem_euclid(step).total_cmp(&0.0).is_eq()),
                "metric timestamp outside the requested grid"
            );
            points.sort_unstable_by(|a, b| a.0.total_cmp(&b.0));
            ensure!(
                points
                    .windows(2)
                    .all(|pair| pair[0].0.total_cmp(&pair[1].0).is_lt()),
                "duplicate metric timestamp"
            );
            Ok(MetricSeries {
                key,
                label: series_label(&series.metric, &definition.legend),
                points,
            })
        })
        .collect()
}

#[derive(Clone, Copy)]
struct QueryWindow {
    start: u64,
    end: u64,
    retain_from: u64,
}

impl QueryWindow {
    fn new(view: &MetricsView, end: u64, previous_end: Option<u64>, full: bool) -> Self {
        let retain_from = end.saturating_sub(view.range.seconds());
        let step = view.range.step();
        // Re-query the trailing five minutes or four buckets, whichever is
        // longer. Periodic full reconciliation handles arbitrarily late
        // corrections and changed historical label sets.
        let overlap = 300_u64.div_ceil(step).max(4) * step;
        let start = if full {
            retain_from
        } else {
            previous_end.map_or(retain_from, |previous| {
                previous.min(end).saturating_sub(overlap).max(retain_from)
            })
        };
        Self {
            start,
            end,
            retain_from,
        }
    }
}

fn merge_window(
    previous: &[MetricSeries],
    incoming: Vec<MetricSeries>,
    window: QueryWindow,
) -> Result<Vec<MetricSeries>> {
    let mut merged = BTreeMap::new();
    for series in previous {
        // Successful responses replace the entire requested interval,
        // including disappearing series. Copy only retained older points.
        let first = series
            .points
            .partition_point(|(time, _)| *time < timestamp_seconds(window.retain_from));
        let end = series
            .points
            .partition_point(|(time, _)| *time < timestamp_seconds(window.start));
        if first < end {
            merged.insert(
                series.key.clone(),
                MetricSeries {
                    key: series.key.clone(),
                    label: series.label.clone(),
                    points: series.points[first..end].to_vec(),
                },
            );
        }
    }
    for mut series in incoming {
        if let Some(mut prior) = merged.remove(&series.key) {
            prior.points.append(&mut series.points);
            series.points = prior.points;
        }
        merged.insert(series.key.clone(), series);
    }
    // A series cap must apply to the retained history, not merely to
    // individual incremental responses whose labels can change over time.
    ensure!(
        merged.len() <= MAX_SERIES,
        "too many retained metric series"
    );
    ensure!(
        merged
            .values()
            .all(|series| series.points.len() <= MAX_POINTS),
        "too many retained metric points"
    );
    Ok(merged.into_values().collect())
}

fn current_only(kind: PanelKind) -> bool {
    matches!(kind, PanelKind::Stat | PanelKind::Bargauge)
}

fn retained_on_error(
    previous: Vec<MetricSeries>,
    window: QueryWindow,
) -> impl Iterator<Item = MetricSeries> {
    previous.into_iter().filter_map(move |mut series| {
        series.points.retain(|(time, _)| {
            *time >= timestamp_seconds(window.retain_from) && *time <= timestamp_seconds(window.end)
        });
        (!series.points.is_empty()).then_some(series)
    })
}

async fn read_panel(
    source: Arc<Source>,
    key: usize,
    definition: PanelDefinition,
    view: MetricsView,
    window: QueryWindow,
    previous: Option<MetricPanel>,
) -> MetricPanel {
    let mut panel = MetricPanel {
        key,
        group: definition.group,
        kind: definition.kind,
        title: definition.title,
        unit: definition.unit,
        series: Vec::new(),
        error: None,
    };
    if definition.requires_client && view.client.is_empty() {
        panel.error = Some("Select a client to inspect its cache distributions".into());
        return panel;
    }
    if source.ingress_host.is_none()
        && definition
            .queries
            .iter()
            .any(|query| query.expr.contains("$ingress_host"))
    {
        panel.error = Some("Scheduler ingress hostname not configured".into());
        return panel;
    }
    let mut previous_by_query: BTreeMap<usize, Vec<MetricSeries>> = BTreeMap::new();
    if let Some(previous) = previous {
        for series in previous.series {
            if let Some(index) = series
                .key
                .split_once(':')
                .and_then(|(index, _)| index.parse::<usize>().ok())
            {
                previous_by_query.entry(index).or_default().push(series);
            }
        }
    }
    let mut failed = 0;
    let count = definition.queries.len();
    for (index, definition) in definition.queries.iter().enumerate() {
        let previous = previous_by_query.remove(&index).unwrap_or_default();
        let instantaneous = current_only(panel.kind);
        let query_window = if instantaneous {
            QueryWindow {
                start: window.end,
                ..window
            }
        } else {
            window
        };
        let result = query(&source, definition, &view, query_window, index)
            .await
            .and_then(|series| {
                if instantaneous {
                    Ok(series)
                } else {
                    merge_window(&previous, series, window)
                }
            });
        match result {
            Ok(series) => panel.series.extend(series),
            Err(error) => {
                log::warn!("dashboard metrics panel {}: {error:#}", panel.title);
                failed += 1;
                // Keep the last successful data within the selected range.
                // The failure message makes the stale part explicit.
                panel.series.extend(retained_on_error(previous, window));
            }
        }
    }
    if failed != 0 {
        panel.error = Some(format!(
            "{failed}/{count} queries failed; retained available previous samples"
        ));
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
    let mut last_full = None;
    loop {
        let step = view.range.step();
        let end = super::now().saturating_sub(3) / step * step;
        let previous = feed.data.inspect(Clone::clone);
        // Do not query the same grid point repeatedly after a short cycle.
        // Failed panels are retried on the following grid.
        if previous.sampled_at == Some(end) {
            tokio::time::sleep(Duration::from_secs(step.min(15))).await;
            continue;
        }
        let full = last_full.is_none_or(|last| end.saturating_sub(last) >= (step * 4).max(600))
            || previous.sampled_at.is_some_and(|last| end < last);
        let previous_end = previous.sampled_at;
        let mut old_panels: BTreeMap<_, _> = previous
            .panels
            .into_iter()
            .map(|panel| (panel.key, panel))
            .collect();
        let client_list = clients(&source, end, &view).await;
        let queries = source
            .definitions
            .clone()
            .into_iter()
            .enumerate()
            .filter(|(_, definition)| definition.group == view.group)
            .map(|(key, definition)| {
                let old = old_panels.remove(&key);
                let full = full || old.as_ref().is_none_or(|panel| panel.error.is_some());
                let window = QueryWindow::new(&view, end, previous_end, full);
                read_panel(
                    Arc::clone(&source),
                    key,
                    definition,
                    view.clone(),
                    window,
                    old,
                )
            })
            .collect::<Vec<_>>();
        let panels = stream::iter(queries).buffered(4).collect::<Vec<_>>().await;
        if full {
            last_full = Some(end);
        }
        let (clients, error) = match client_list {
            Ok(clients) => (clients, None),
            Err(error) => {
                log::warn!("dashboard client labels unavailable: {error:#}");
                (
                    previous.clients,
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
        // Align the next query with the time grid, but avoid hammering the
        // store when the queries themselves take longer than one bucket.
        let delay = end
            .saturating_add(step)
            .saturating_add(3)
            .saturating_sub(super::now())
            .max(15);
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn series(key: &str, points: &[(f64, Option<f64>)]) -> MetricSeries {
        MetricSeries {
            key: key.into(),
            label: key.into(),
            points: points.to_vec(),
        }
    }

    #[test]
    fn successful_overlap_replaces_missing_and_corrected_points() {
        let window = QueryWindow {
            retain_from: 2,
            start: 4,
            end: 7,
        };
        let previous = vec![
            series(
                "a",
                &[
                    (1.0, Some(1.0)),
                    (2.0, Some(2.0)),
                    (3.0, Some(3.0)),
                    (4.0, Some(4.0)),
                    (5.0, Some(5.0)),
                ],
            ),
            series("b", &[(4.0, Some(4.0))]),
            series("c", &[(3.0, Some(3.0)), (4.0, Some(4.0))]),
        ];
        let incoming = vec![
            series("a", &[(4.0, Some(40.0)), (6.0, None), (7.0, Some(7.0))]),
            series("d", &[(7.0, Some(1.0))]),
        ];
        let merged = merge_window(&previous, incoming, window).unwrap();
        assert_eq!(
            merged,
            vec![
                series(
                    "a",
                    &[
                        (2.0, Some(2.0)),
                        (3.0, Some(3.0)),
                        (4.0, Some(40.0)),
                        (6.0, None),
                        (7.0, Some(7.0))
                    ]
                ),
                series("c", &[(3.0, Some(3.0))]),
                series("d", &[(7.0, Some(1.0))]),
            ]
        );
    }

    #[test]
    fn metric_grid_rejects_duplicate_out_of_range_and_off_grid_points() {
        let definition = QueryDefinition {
            expr: "vector(1)".into(),
            legend: "".into(),
        };
        let window = QueryWindow {
            start: 10,
            end: 20,
            retain_from: 10,
        };
        for values in [
            vec![(10.0, "1".into()), (10.0, "2".into())],
            vec![(9.0, "1".into())],
            vec![(21.0, "1".into())],
            vec![(11.0, "1".into())],
        ] {
            let data = QueryData {
                result: vec![QuerySeries {
                    metric: BTreeMap::new(),
                    values,
                }],
            };
            assert!(decode_series(data, &definition, window, 5, 0).is_err());
        }
        let data = QueryData {
            result: vec![QuerySeries {
                metric: BTreeMap::new(),
                values: vec![(15.0, "NaN".into()), (10.0, "1".into())],
            }],
        };
        let series = decode_series(data, &definition, window, 5, 0).unwrap();
        assert_eq!(series[0].points, [(10.0, Some(1.0)), (15.0, None)]);
    }

    #[test]
    fn incremental_series_churn_cannot_exceed_history_cap() {
        let previous = (0..MAX_SERIES)
            .map(|key| series(&key.to_string(), &[(1.0, Some(1.0))]))
            .collect::<Vec<_>>();
        let incoming = vec![series("new", &[(2.0, Some(2.0))])];
        let window = QueryWindow {
            retain_from: 1,
            start: 2,
            end: 2,
        };
        assert!(merge_window(&previous, incoming, window).is_err());
        assert!(current_only(PanelKind::Stat));
        assert!(current_only(PanelKind::Bargauge));
        assert!(!current_only(PanelKind::Timeseries));
        assert!(!current_only(PanelKind::Table));
    }

    #[test]
    fn incremental_grid_does_not_skip_after_long_gap() {
        let view = MetricsView::default();
        let window = QueryWindow::new(&view, 7200, Some(3600), false);
        assert_eq!(window.start, 3600);
        let window = QueryWindow::new(&view, 7200, Some(7185), false);
        assert_eq!(window.start, 6885);
        assert_eq!(window.start % view.range.step(), 0);
    }

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
        assert_eq!(panels.len(), 50);
        assert_eq!(
            panels
                .iter()
                .filter(|panel| panel.group == crate::MetricGroup::CacheStorage)
                .count(),
            10
        );
        assert!(
            panels
                .iter()
                .any(|panel| panel.group == crate::MetricGroup::CacheHits)
        );
        assert!(
            panels
                .iter()
                .any(|panel| panel.group == crate::MetricGroup::Fleet)
        );
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
            let result = expression(query, &view, Some("scheduler.example.org"));
            !result.contains("$__")
                && !result.contains("$client")
                && !result.contains("$ingress_host")
        }));
        Ok(())
    }
}

// Unix epoch seconds fit exactly in f64 throughout the supported clock range.
#[expect(
    clippy::cast_precision_loss,
    reason = "metric query timestamps are Unix seconds, not arbitrary large counters"
)]
const fn timestamp_seconds(seconds: u64) -> f64 {
    seconds as f64
}
