//! Bounded, typed `VictoriaTraces` queries. No browser-supplied query language
//! or backend URL is forwarded to the trace database.

use anyhow::{Context, Result, ensure};
use futures::StreamExt as _;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

use crate::traces::{
    PhaseAggregate, SpanKind, TraceDetail, TraceOverview, TraceSearch, TraceSpan, TraceSummary,
};

const LIMIT: usize = 100;
const SPAN_LIMIT: usize = 4096;
const MAX_RESPONSE: usize = 8 * 1024 * 1024;
const PARTITION_ROWS: u64 = 100_000;
const MAX_PARTITIONS: usize = 128;
const MAX_PROBES: usize = 512;
const SEARCH_TIMEOUT: Duration = Duration::from_secs(30);
const FLEET_FILTER: &str =
    r#""resource_attr:service.name":in(sccache-client,sccache-scheduler,sccache-worker)"#;
mod histogram;
use histogram::PhaseGroups;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Window {
    start: i128,
    end: i128,
}

impl Window {
    fn recent(seconds: u32) -> Self {
        let end = jiff::Timestamp::now().as_nanosecond();
        Self {
            start: end - i128::from(seconds) * 1_000_000_000,
            end,
        }
    }

    fn split(self) -> Result<[Self; 2]> {
        ensure!(
            self.end - self.start > 1,
            "too many spans at one timestamp; narrow the trace range"
        );
        let middle = self.start + (self.end - self.start) / 2;
        Ok([
            Self {
                start: self.start,
                end: middle,
            },
            Self {
                start: middle,
                end: self.end,
            },
        ])
    }
}

// Retry delivery preserves all of these fields byte-for-byte. Deduplicate
// before limits, sorting or aggregates so transport retries cannot bias p99.
const ROOT_FIELDS: &str = r#"trace_id,span_id,duration,start_time_unix_nano,"resource_attr:host.name","resource_attr:service.version","span_attr:sccache.compiler","span_attr:sccache.output","span_attr:sccache.outcome","span_attr:sccache.worker","span_attr:sccache.action_key""#;
const SPAN_FIELDS: &str = r#"trace_id,span_id,parent_span_id,name,start_time_unix_nano,duration,status_code,"resource_attr:service.name","resource_attr:host.name","resource_attr:service.version","span_attr:sccache.producer_trace_id","span_attr:sccache.span_kind","span_attr:sccache.omitted_intervals","span_attr:sccache.compiler","span_attr:sccache.output","span_attr:sccache.outcome","span_attr:sccache.worker","span_attr:sccache.action_key""#;
const AGGREGATE_FIELDS: &str = r#"trace_id,span_id,name,duration,"resource_attr:service.name","resource_attr:host.name","resource_attr:service.version""#;

#[derive(Clone)]
pub struct TraceService(Option<Arc<Source>>);

struct Source {
    base: url::Url,
    client: wreq::Client,
    queries: Semaphore,
}

type Row = BTreeMap<String, String>;

impl TraceService {
    pub(super) fn new(url: Option<&str>) -> Result<Self> {
        let source = url
            .map(|url| -> Result<_> {
                let (base, client) = super::telemetry_source(url)?;
                Ok(Arc::new(Source {
                    base,
                    client,
                    queries: Semaphore::new(4),
                }))
            })
            .transpose()?;
        Ok(Self(source))
    }

    fn source(&self) -> Result<&Source> {
        self.0.as_deref().context("trace storage not configured")
    }

    pub(crate) async fn search(&self, search: TraceSearch) -> Result<TraceOverview> {
        let filter = search_filter(&search)?;
        let source = self.source()?;
        let window = Window::recent(search.lookback_secs);
        let (roots, phases) = tokio::join!(
            tokio::time::timeout(
                SEARCH_TIMEOUT,
                source.roots(&filter, window, search.slowest)
            ),
            tokio::time::timeout(SEARCH_TIMEOUT, source.phases(window)),
        );
        let (traces, trace_error) = search_result(roots);
        let (phases, phase_error) = search_result(phases);
        Ok(TraceOverview {
            traces,
            trace_error,
            phases,
            phase_error,
        })
    }

    pub(crate) async fn detail(&self, id: String) -> Result<TraceDetail> {
        ensure!(valid_id(&id, 32), "invalid trace ID");
        let query = format!(
            "trace_id:={quoted} | uniq by ({SPAN_FIELDS}) | sort by (start_time_unix_nano) | limit {limit}",
            quoted = serde_json::to_string(&id)?,
            limit = SPAN_LIMIT + 1
        );
        let mut rows = self
            .source()?
            .rows(&query, SPAN_LIMIT + 1, Window::recent(604_800))
            .await?;
        let truncated = rows.len() > SPAN_LIMIT;
        rows.truncate(SPAN_LIMIT);
        let root = rows.iter().find(|row| {
            row.get("name").is_some_and(|name| name == "compile")
                && row
                    .get("resource_attr:service.name")
                    .is_some_and(|service| service == "sccache-client")
                && row.get("parent_span_id").is_none_or(String::is_empty)
        });
        let request = root.cloned().map(summary).transpose()?;
        let omitted_intervals = root
            .and_then(|row| row.get("span_attr:sccache.omitted_intervals"))
            .filter(|value| !value.is_empty())
            .map(|value| value.parse::<u64>())
            .transpose()?
            .unwrap_or_default();
        let spans = rows.into_iter().map(span).collect::<Result<Vec<_>>>()?;
        ensure!(!spans.is_empty(), "trace not found or not yet visible");
        Ok(TraceDetail {
            id,
            request,
            omitted_intervals,
            spans,
            truncated,
        })
    }
}

fn search_result<T>(
    result: Result<Result<Vec<T>>, tokio::time::error::Elapsed>,
) -> (Vec<T>, Option<String>) {
    match result {
        Ok(Ok(rows)) => (rows, None),
        Ok(Err(error)) => (Vec::new(), Some(format!("{error:#}"))),
        Err(_) => (
            Vec::new(),
            Some("Trace query exceeded its time budget; select a shorter range.".into()),
        ),
    }
}

impl Source {
    // Immutable replay timestamps belong to exactly one half-open partition.
    // Count raw rows, not deduplicated IDs, before allocating a backend hash table.
    async fn partitions(&self, filter: &str, window: Window) -> Result<Vec<Window>> {
        let query = format!("{filter} | stats count() as count");
        let mut pending = vec![window];
        let mut windows = Vec::new();
        let mut probes = 0;
        while let Some(window) = pending.pop() {
            probes += 1;
            ensure!(
                probes <= MAX_PROBES,
                "trace count query budget exhausted; select a shorter range"
            );
            let mut rows = self.rows(&query, 1, window).await?;
            let count = rows
                .pop()
                .map_or(Ok(0), |mut row| integer(&mut row, "count"))?;
            if count > PARTITION_ROWS {
                pending.extend(window.split()?);
            } else if count != 0 {
                ensure!(
                    windows.len() < MAX_PARTITIONS,
                    "trace partition budget exhausted; select a shorter range"
                );
                windows.push(window);
            }
        }
        Ok(windows)
    }

    async fn roots(
        &self,
        filter: &str,
        window: Window,
        slowest: bool,
    ) -> Result<Vec<TraceSummary>> {
        let order = if slowest {
            "duration desc"
        } else {
            "start_time_unix_nano desc"
        };
        let query = format!(
            "{filter} | uniq by ({ROOT_FIELDS}) | sort by ({order}, trace_id) | limit {LIMIT}"
        );
        let mut roots = Vec::new();
        for window in self.partitions(filter, window).await? {
            for row in self.rows(&query, LIMIT, window).await? {
                roots.push(summary(row)?);
            }
            roots.sort_unstable_by(|a, b| {
                let order = if slowest {
                    b.duration_ns.cmp(&a.duration_ns)
                } else {
                    b.start_ns.cmp(&a.start_ns)
                };
                order.then_with(|| a.id.cmp(&b.id))
            });
            roots.truncate(LIMIT);
        }
        Ok(roots)
    }

    async fn phases(&self, window: Window) -> Result<Vec<PhaseAggregate>> {
        let query = format!(
            r#"{FLEET_FILTER} | uniq by ({AGGREGATE_FIELDS}) | stats by (name,"resource_attr:service.name","resource_attr:host.name","resource_attr:service.version") count() as count, histogram(duration) as bins, sum(duration) as total, min(duration) as minimum, max(duration) as maximum"#
        );
        let mut groups = PhaseGroups::default();
        for window in self.partitions(FLEET_FILTER, window).await? {
            for row in self.rows(&query, histogram::MAX_GROUPS, window).await? {
                groups.add(row)?;
            }
        }
        groups.finish()
    }

    async fn rows(&self, query: &str, limit: usize, window: Window) -> Result<Vec<Row>> {
        let _permit = self
            .queries
            .try_acquire()
            .context("trace query capacity exhausted")?;
        let start = jiff::Timestamp::from_nanosecond(window.start)?.to_string();
        let end = jiff::Timestamp::from_nanosecond(window.end)?.to_string();
        let response = self
            .client
            .post(self.base.join("select/logsql/query")?.as_str())
            .form(&[("query", query), ("start", &start), ("end", &end)])
            .send()
            .await?
            .error_for_status()?;
        ensure!(
            response
                .content_length()
                .is_none_or(|length| length <= MAX_RESPONSE as u64),
            "trace response exceeds byte budget"
        );
        let mut stream = std::pin::pin!(response.bytes_stream());
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            ensure!(
                body.len().saturating_add(chunk.len()) <= MAX_RESPONSE,
                "trace response exceeds byte budget"
            );
            body.extend_from_slice(&chunk);
        }
        let mut rows = Vec::new();
        for line in body
            .split(|&byte| byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            ensure!(rows.len() < limit, "trace response exceeds row budget");
            rows.push(serde_json::from_slice(line)?);
        }
        Ok(rows)
    }
}

fn valid_id(id: &str, width: usize) -> bool {
    id.len() == width
        && id.bytes().all(|byte| byte.is_ascii_hexdigit())
        && id.bytes().any(|byte| byte != b'0')
}

fn search_filter(search: &TraceSearch) -> Result<String> {
    use std::fmt::Write as _;
    ensure!(
        matches!(search.lookback_secs, 300 | 3600 | 86400 | 604_800),
        "unsupported trace time range"
    );
    let mut query = r#"name:="compile" "resource_attr:service.name":="sccache-client""#.to_owned();
    for (field, value) in [
        ("resource_attr:host.name", &search.host),
        ("resource_attr:service.version", &search.revision),
        ("span_attr:sccache.compiler", &search.compiler),
        ("span_attr:sccache.output", &search.output),
        ("span_attr:sccache.outcome", &search.outcome),
    ] {
        ensure!(
            value.len() <= 256 && !value.chars().any(char::is_control),
            "invalid trace filter"
        );
        if !value.is_empty() {
            write!(query, " {field:?}:={}", serde_json::to_string(value)?)?;
        }
    }
    Ok(query)
}

fn take(row: &mut Row, key: &str) -> String {
    row.remove(key).unwrap_or_default()
}

fn integer(row: &mut Row, key: &str) -> Result<u64> {
    take(row, key)
        .parse()
        .with_context(|| format!("invalid trace field {key}"))
}

fn number(row: &mut Row, key: &str) -> Result<f64> {
    let value: f64 = take(row, key)
        .parse()
        .with_context(|| format!("invalid trace statistic {key}"))?;
    ensure!(value.is_finite() && value >= 0.0, "invalid trace statistic");
    Ok(value)
}

fn summary(mut row: Row) -> Result<TraceSummary> {
    let id = take(&mut row, "trace_id");
    ensure!(valid_id(&id, 32), "invalid stored trace ID");
    Ok(TraceSummary {
        id,
        start_ns: integer(&mut row, "start_time_unix_nano")?,
        duration_ns: integer(&mut row, "duration")?,
        host: take(&mut row, "resource_attr:host.name"),
        revision: take(&mut row, "resource_attr:service.version"),
        compiler: take(&mut row, "span_attr:sccache.compiler"),
        output: take(&mut row, "span_attr:sccache.output"),
        outcome: take(&mut row, "span_attr:sccache.outcome"),
        worker: take(&mut row, "span_attr:sccache.worker"),
        action: take(&mut row, "span_attr:sccache.action_key"),
    })
}

fn span(mut row: Row) -> Result<TraceSpan> {
    let id = take(&mut row, "span_id");
    let parent = take(&mut row, "parent_span_id");
    ensure!(
        valid_id(&id, 16) && (parent.is_empty() || valid_id(&parent, 16)),
        "invalid stored span ID"
    );
    let producer = take(&mut row, "span_attr:sccache.producer_trace_id");
    Ok(TraceSpan {
        id,
        parent,
        name: take(&mut row, "name"),
        kind: match take(&mut row, "span_attr:sccache.span_kind").as_str() {
            "phase" => SpanKind::Phase,
            "interval" => SpanKind::Interval,
            _ => SpanKind::Other,
        },
        service: take(&mut row, "resource_attr:service.name"),
        host: take(&mut row, "resource_attr:host.name"),
        revision: take(&mut row, "resource_attr:service.version"),
        start_ns: integer(&mut row, "start_time_unix_nano")?,
        duration_ns: integer(&mut row, "duration")?,
        error: take(&mut row, "status_code") == "2",
        producer: valid_id(&producer, 32).then_some(producer),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_is_bounded_and_filter_is_literal() -> Result<()> {
        let mut search = TraceSearch {
            output: "a\" | limit 100000".into(),
            ..Default::default()
        };
        let query = search_filter(&search)?;
        assert!(query.contains(r#""span_attr:sccache.output":="a\" | limit 100000""#));
        assert!(!query.contains(" | uniq by ("));
        let [left, right] = Window { start: 17, end: 22 }.split()?;
        assert_eq!(left, Window { start: 17, end: 19 });
        assert_eq!(right, Window { start: 19, end: 22 });
        assert!(Window { start: 1, end: 2 }.split().is_err());
        search.lookback_secs = 1;
        assert!(search_filter(&search).is_err());
        assert!(!valid_id("../metrics", 32));
        Ok(())
    }

    #[test]
    fn nanosecond_timeline_fields_are_exact() -> Result<()> {
        let row: Row = serde_json::from_str(
            r#"{"span_id":"1111111111111111","parent_span_id":"2222222222222222","name":"hash_inputs","start_time_unix_nano":"1795788023036154756","duration":"23","status_code":"2","resource_attr:host.name":"acer"}"#,
        )?;
        let span = span(row)?;
        assert_eq!(span.start_ns, 1795788023036154756);
        assert_eq!(span.duration_ns, 23);
        assert!(span.error);
        Ok(())
    }
}
