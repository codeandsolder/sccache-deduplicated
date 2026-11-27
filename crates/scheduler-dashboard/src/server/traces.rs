//! Bounded, typed VictoriaTraces queries. No browser-supplied query language
//! or backend URL is forwarded to the trace database.

use anyhow::{Context, Result, ensure};
use futures::StreamExt as _;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

use crate::traces::{
    PhaseAggregate, TraceDetail, TraceOverview, TraceSearch, TraceSpan, TraceSummary,
};

const LIMIT: usize = 100;
const SPAN_LIMIT: usize = 4096;
const MAX_RESPONSE: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct TraceService(Option<Arc<Source>>);

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
                let mut base = url::Url::parse(url)?;
                ensure!(
                    matches!(base.scheme(), "http" | "https")
                        && base.host().is_some()
                        && base.username().is_empty()
                        && base.password().is_none()
                        && base.query().is_none()
                        && base.fragment().is_none(),
                    "invalid trace query base URL"
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
        let (query, aggregate) = search_queries(&search)?;
        let source = self.source()?;
        let (roots, phases) =
            tokio::try_join!(source.rows(&query, LIMIT), source.rows(&aggregate, 200))?;
        Ok(TraceOverview {
            traces: roots.into_iter().map(summary).collect::<Result<_>>()?,
            phases: phases.into_iter().map(phase).collect::<Result<_>>()?,
        })
    }

    pub(crate) async fn detail(&self, id: String) -> Result<TraceDetail> {
        ensure!(valid_id(&id, 32), "invalid trace ID");
        let query = format!(
            "_time:7d trace_id:={quoted} | sort by (start_time_unix_nano) | limit {limit} | fields span_id,parent_span_id,name,start_time_unix_nano,duration,status_code,\"resource_attr:service.name\",\"resource_attr:host.name\"",
            quoted = serde_json::to_string(&id)?,
            limit = SPAN_LIMIT + 1
        );
        let mut rows = self.source()?.rows(&query, SPAN_LIMIT + 1).await?;
        let truncated = rows.len() > SPAN_LIMIT;
        rows.truncate(SPAN_LIMIT);
        let spans = rows.into_iter().map(span).collect::<Result<Vec<_>>>()?;
        ensure!(!spans.is_empty(), "trace not found or not yet visible");
        Ok(TraceDetail {
            id,
            spans,
            truncated,
        })
    }
}

impl Source {
    async fn rows(&self, query: &str, limit: usize) -> Result<Vec<Row>> {
        let _permit = self
            .queries
            .try_acquire()
            .context("trace query capacity exhausted")?;
        let response = self
            .client
            .post(self.base.join("select/logsql/query")?.as_str())
            .form(&[("query", query)])
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

fn search_queries(search: &TraceSearch) -> Result<(String, String)> {
    use std::fmt::Write as _;
    let range = match search.lookback_secs {
        300 => "5m",
        3600 => "1h",
        86400 => "1d",
        604800 => "7d",
        _ => anyhow::bail!("unsupported trace time range"),
    };
    let mut query = format!(
        "_time:{range} name:=\"compile\" \"resource_attr:service.name\":=\"sccache-client\""
    );
    for (field, value) in [
        ("resource_attr:host.name", &search.host),
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
    let order = if search.slowest {
        "duration desc"
    } else {
        "start_time_unix_nano desc"
    };
    write!(
        query,
        " | sort by ({order}) | limit {LIMIT} | fields trace_id,duration,start_time_unix_nano,\"resource_attr:host.name\",\"span_attr:sccache.compiler\",\"span_attr:sccache.output\",\"span_attr:sccache.outcome\",\"span_attr:sccache.worker\",\"span_attr:sccache.action_key\""
    )?;
    // Aggregates are explicitly fleet-wide, not a sum of the selected roots'
    // children. Nested and concurrent spans are not additive.
    let aggregate = format!(
        "_time:{range} \"resource_attr:service.name\":in(sccache-client,sccache-scheduler,sccache-worker) | stats by (name,\"resource_attr:service.name\",\"resource_attr:host.name\",\"resource_attr:service.version\") count() as count, quantile(0.5,duration) as p50, quantile(0.95,duration) as p95, quantile(0.99,duration) as p99, sum(duration) as total | sort by (total desc) | limit 200"
    );
    Ok((query, aggregate))
}

fn take(row: &mut Row, key: &str) -> String {
    row.remove(key).unwrap_or_default()
}

fn integer(row: &mut Row, key: &str) -> Result<u64> {
    Ok(take(row, key)
        .parse()
        .with_context(|| format!("invalid trace field {key}"))?)
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
    Ok(TraceSpan {
        id,
        parent,
        name: take(&mut row, "name"),
        service: take(&mut row, "resource_attr:service.name"),
        host: take(&mut row, "resource_attr:host.name"),
        start_ns: integer(&mut row, "start_time_unix_nano")?,
        duration_ns: integer(&mut row, "duration")?,
        error: take(&mut row, "status_code") == "2",
    })
}

fn phase(mut row: Row) -> Result<PhaseAggregate> {
    Ok(PhaseAggregate {
        service: take(&mut row, "resource_attr:service.name"),
        host: take(&mut row, "resource_attr:host.name"),
        version: take(&mut row, "resource_attr:service.version"),
        phase: take(&mut row, "name"),
        count: integer(&mut row, "count")?,
        p50_ns: number(&mut row, "p50")?,
        p95_ns: number(&mut row, "p95")?,
        p99_ns: number(&mut row, "p99")?,
        total_ns: number(&mut row, "total")?,
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
        let (query, aggregate) = search_queries(&search)?;
        assert!(query.contains(r#""span_attr:sccache.output":="a\" | limit 100000""#));
        assert!(query.contains(" | limit 100 | fields "));
        assert!(aggregate.contains("quantile(0.99,duration)"));
        search.lookback_secs = 1;
        assert!(search_queries(&search).is_err());
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
