//! Use the official OTLP protobuf types with the existing HTTP stack, rather
//! than pulling in a second HTTP/TLS client for telemetry.

use super::{LatencySpan, TraceConfig};
use anyhow::{Result, ensure};
use opentelemetry_proto::tonic::{
    collector::trace::v1::{ExportTraceServiceRequest, ExportTraceServiceResponse},
    common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value::Value},
    resource::v1::Resource,
    trace::v1::{ResourceSpans, ScopeSpans, Span, Status, span::Link, status::StatusCode},
};
use prost::Message as _;
use std::{
    collections::BTreeMap,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;

const QUEUE: usize = 256;
const BATCH_REQUESTS: usize = 32;
const MAX_BATCH_SPANS: usize = 8192;
static EXPORT: OnceLock<Exporter> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);

struct Exporter {
    config: TraceConfig,
    sender: mpsc::Sender<Vec<LatencySpan>>,
}

pub(super) fn configure(config: &TraceConfig) -> Result<()> {
    if let Some(existing) = EXPORT.get() {
        ensure!(
            &existing.config == config,
            "conflicting trace exporter configuration"
        );
        return Ok(());
    }
    let endpoint = url::Url::parse(&config.endpoint)?;
    ensure!(
        matches!(endpoint.scheme(), "http" | "https")
            && endpoint.host_str().is_some()
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.fragment().is_none(),
        "trace endpoint must be an HTTP(S) URL without embedded credentials or fragment"
    );
    ensure!(
        !config.instance.is_empty() && config.instance.len() <= 256,
        "invalid trace instance"
    );
    let (sender, receiver) = mpsc::channel(QUEUE);
    let config = config.clone();
    let instance = config.instance.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    std::thread::Builder::new()
        .name("sccache-otlp".into())
        .spawn(move || {
            runtime.block_on(run(receiver, endpoint, instance));
        })?;
    EXPORT
        .set(Exporter { config, sender })
        .map_err(|_| anyhow::anyhow!("trace exporter initialized concurrently"))?;
    Ok(())
}

pub(super) fn enabled() -> bool {
    EXPORT.get().is_some()
}

pub(super) fn submit(spans: Vec<LatencySpan>) {
    if let Some(export) = EXPORT.get() {
        let count = u64::try_from(spans.len()).unwrap_or(u64::MAX);
        if export.sender.try_send(spans).is_err() {
            DROPPED.fetch_add(count, Ordering::Relaxed);
        }
    }
}

fn attribute(key: &str, value: String) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(Value::StringValue(value)),
        }),
        ..Default::default()
    }
}

fn request(spans: Vec<LatencySpan>, instance: &str) -> ExportTraceServiceRequest {
    let mut groups = BTreeMap::<_, Vec<Span>>::new();
    for span in spans {
        groups.entry(span.service).or_default().push(Span {
            trace_id: span.context.trace_id.to_vec(),
            span_id: span.context.span_id.to_vec(),
            parent_span_id: span
                .parent
                .map_or_else(Vec::new, |parent| parent.span_id.to_vec()),
            links: span
                .links
                .into_iter()
                .map(|link| Link {
                    trace_id: link.trace_id.to_vec(),
                    span_id: link.span_id.to_vec(),
                    ..Default::default()
                })
                .collect(),
            name: span.name.into(),
            kind: if span.parent.is_none() { 2 } else { 1 },
            start_time_unix_nano: span.start,
            end_time_unix_nano: span.end.max(span.start),
            attributes: span
                .attributes
                .into_iter()
                .map(|(key, value)| attribute(key, value))
                .collect(),
            status: Some(Status {
                code: if span.error {
                    StatusCode::Error as i32
                } else {
                    StatusCode::Unset as i32
                },
                ..Default::default()
            }),
            ..Default::default()
        });
    }
    ExportTraceServiceRequest {
        resource_spans: groups
            .into_iter()
            .map(|(service, spans)| ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![
                        attribute("service.name", service.into()),
                        attribute("host.name", instance.into()),
                        attribute("service.version", crate::VERSION.into()),
                    ],
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    scope: Some(InstrumentationScope {
                        name: "sccache.latency".into(),
                        ..Default::default()
                    }),
                    spans,
                    ..Default::default()
                }],
                ..Default::default()
            })
            .collect(),
    }
}

async fn send(client: &wreq::Client, endpoint: &url::Url, body: Vec<u8>) -> Result<()> {
    let response = client
        .post(endpoint.as_str())
        .header("Content-Type", "application/x-protobuf")
        .timeout(Duration::from_secs(5))
        .body(body)
        .send()
        .await?
        .error_for_status()?;
    // OTLP success may carry a partial rejection. Do not report it as success.
    let bytes = crate::http_client::read_bounded_bytes_async(response, 65536).await?;
    let reply = ExportTraceServiceResponse::decode(bytes.as_slice())?;
    if let Some(partial) = reply.partial_success {
        ensure!(
            partial.rejected_spans == 0,
            "OTLP backend rejected {} spans",
            partial.rejected_spans
        );
    }
    Ok(())
}

async fn run(mut receiver: mpsc::Receiver<Vec<LatencySpan>>, endpoint: url::Url, instance: String) {
    let client = match wreq::Client::builder()
        .no_proxy()
        .redirect(wreq::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            log::error!("trace HTTP client unavailable: {error}");
            return;
        }
    };
    while let Some(mut spans) = receiver.recv().await {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        for _ in 1..BATCH_REQUESTS {
            if spans.len() >= MAX_BATCH_SPANS {
                break;
            }
            match tokio::time::timeout_at(deadline, receiver.recv()).await {
                Ok(Some(mut next)) => spans.append(&mut next),
                _ => break,
            }
        }
        let count = u64::try_from(spans.len()).unwrap_or(u64::MAX);
        let body = request(spans, &instance).encode_to_vec();
        // An ambiguous transport error is not retried: OTLP has no exactly-once
        // guarantee and duplicates would distort latency aggregation.
        if let Err(error) = send(&client, &endpoint, body).await {
            DROPPED.fetch_add(count, Ordering::Relaxed);
            log::warn!("OTLP trace batch lost: {error:#}");
        }
        let dropped = DROPPED.swap(0, Ordering::Relaxed);
        if dropped != 0 {
            log::warn!("OTLP spans dropped: {dropped}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::latency_trace::TraceContext;

    #[test]
    fn protobuf_preserves_causal_ids_and_timestamps() -> Result<()> {
        let root = TraceContext::request("test");
        let mut span = LatencySpan::child(root, "sccache-client", "hash_inputs", 10, 20);
        let producer = TraceContext::request("producer");
        span.links.push(producer);
        let id = span.context;
        let message = ExportTraceServiceRequest::decode(
            request(vec![span], "test-host").encode_to_vec().as_slice(),
        )?;
        let span = &message.resource_spans[0].scope_spans[0].spans[0];
        assert_eq!(span.trace_id, root.trace_id);
        assert_eq!(span.parent_span_id, root.span_id);
        assert_eq!(span.span_id, id.span_id);
        assert_eq!(span.start_time_unix_nano, 10);
        assert_eq!(span.end_time_unix_nano, 20);
        assert_eq!(span.links.len(), 1);
        assert_eq!(span.links[0].trace_id, producer.trace_id);
        assert_eq!(span.links[0].span_id, producer.span_id);
        Ok(())
    }
}
