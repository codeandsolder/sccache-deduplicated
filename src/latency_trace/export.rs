//! Use the official OTLP protobuf types with the existing HTTP stack, rather
//! than pulling in a second HTTP/TLS client for telemetry.

use super::{
    LatencySpan, TraceConfig,
    spool::{MAX_BODY, Spool},
};
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
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};

const QUEUE: usize = 256;
const BATCH_REQUESTS: usize = 32;
const MAX_BATCH_SPANS: usize = 8192;
const MEMORY_BUDGET: usize = 16 * 1024 * 1024;
const MAX_BATCH_MEMORY: usize = MAX_BODY / 2;
const RETRY_MAX: Duration = Duration::from_secs(30);
static EXPORT: OnceLock<Exporter> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);

struct Exporter {
    config: TraceConfig,
    sender: mpsc::Sender<Message>,
    budget: Arc<Semaphore>,
}

struct Submission {
    spans: Vec<LatencySpan>,
    bytes: usize,
    _permit: OwnedSemaphorePermit,
}

enum Message {
    Spans(Submission),
    Flush(std::sync::mpsc::SyncSender<()>),
}

struct Delivery {
    spool: Mutex<Spool>,
    ready: Notify,
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
        !config.instance.is_empty()
            && config.instance.len() <= 256
            && !config.instance.chars().any(char::is_control),
        "invalid trace instance"
    );
    let delivery = Arc::new(Delivery {
        spool: Mutex::new(Spool::open(
            &config.spool_directory,
            config.max_spool_bytes,
        )?),
        ready: Notify::new(),
    });
    let client = wreq::Client::builder()
        .no_proxy()
        .redirect(wreq::redirect::Policy::none())
        .build()?;
    let (sender, receiver) = mpsc::channel(QUEUE);
    let config = config.clone();
    let instance = config.instance.clone();
    let writer_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let delivery_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let writer = Arc::clone(&delivery);
    std::thread::Builder::new()
        .name("sccache-trace-spool".into())
        .spawn(move || writer_runtime.block_on(write_spool(receiver, &writer, &instance)))?;
    std::thread::Builder::new()
        .name("sccache-otlp".into())
        .spawn(move || delivery_runtime.block_on(deliver(&delivery, &client, &endpoint)))?;
    EXPORT
        .set(Exporter {
            config,
            sender,
            budget: Arc::new(Semaphore::new(MEMORY_BUDGET)),
        })
        .map_err(|_| anyhow::anyhow!("trace exporter initialized concurrently"))?;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "dist-client"))]
pub(super) fn instance() -> Option<&'static str> {
    EXPORT.get().map(|export| export.config.instance.as_str())
}

pub(super) fn enabled() -> bool {
    EXPORT.get().is_some()
}

fn submission_size(spans: &[LatencySpan], capacity: usize) -> usize {
    spans.iter().fold(
        capacity.saturating_mul(size_of::<LatencySpan>()),
        |bytes, span| {
            let attributes = span.attributes.iter().fold(
                span.attributes
                    .capacity()
                    .saturating_mul(size_of::<(&str, String)>()),
                |bytes, (_, value)| bytes.saturating_add(value.capacity()),
            );
            bytes.saturating_add(attributes).saturating_add(
                span.links
                    .capacity()
                    .saturating_mul(size_of::<super::TraceContext>()),
            )
        },
    )
}

pub(super) fn submit(spans: Vec<LatencySpan>) {
    if let Some(export) = EXPORT.get() {
        if spans.is_empty() {
            return;
        }
        let count = u64::try_from(spans.len()).unwrap_or(u64::MAX);
        let bytes = submission_size(&spans, spans.capacity());
        let accepted = u32::try_from(bytes)
            .ok()
            .filter(|_| bytes <= MAX_BATCH_MEMORY)
            .and_then(|bytes| {
                Arc::clone(&export.budget)
                    .try_acquire_many_owned(bytes)
                    .ok()
            })
            .is_some_and(|permit| {
                export
                    .sender
                    .try_send(Message::Spans(Submission {
                        spans,
                        bytes,
                        _permit: permit,
                    }))
                    .is_ok()
            });
        if !accepted {
            DROPPED.fetch_add(count, Ordering::Relaxed);
        }
    }
}

/// A shutdown barrier waits for disk publication, not remote availability.
pub(super) fn flush() {
    if let Some(export) = EXPORT.get() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let enqueued = enqueue_barrier(export, &sender, deadline);
        drop(sender);
        if !enqueued {
            log::warn!("trace spool shutdown flush unavailable");
        } else if receiver
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .is_err()
        {
            log::warn!("trace spool shutdown flush timed out");
        }
    }
}

fn enqueue_barrier(
    export: &Exporter,
    sender: &std::sync::mpsc::SyncSender<()>,
    deadline: std::time::Instant,
) -> bool {
    loop {
        match export.sender.try_send(Message::Flush(sender.clone())) {
            Ok(()) => return true,
            Err(mpsc::error::TrySendError::Full(_)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return false,
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
                        attribute("service.version", crate::BUILD_REVISION.into()),
                        attribute("sccache.package_version", crate::VERSION.into()),
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

enum SendResult {
    Delivered,
    Retry(anyhow::Error),
    Rejected {
        rejected: Option<u64>,
        error: anyhow::Error,
    },
}

async fn send(client: &wreq::Client, endpoint: &url::Url, body: Vec<u8>) -> SendResult {
    let response = match client
        .post(endpoint.as_str())
        .header("Content-Type", "application/x-protobuf")
        .timeout(Duration::from_secs(5))
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => return SendResult::Retry(error.into()),
    };
    let status = response.status();
    if !status.is_success() {
        let error = anyhow::anyhow!("OTLP HTTP status {status}");
        // Malformed payloads cannot improve on retry. Auth/configuration
        // failures are retained to permit recovery after operator repair.
        return if matches!(status.as_u16(), 400 | 413 | 415 | 422) {
            SendResult::Rejected {
                rejected: None,
                error,
            }
        } else {
            SendResult::Retry(error)
        };
    }
    let bytes = match crate::http_client::read_bounded_bytes_async(response, 65_536).await {
        Ok(bytes) => bytes,
        Err(error) => return SendResult::Retry(error),
    };
    let reply = match ExportTraceServiceResponse::decode(bytes.as_slice()) {
        Ok(reply) => reply,
        Err(error) => return SendResult::Retry(error.into()),
    };
    if let Some(partial) = reply.partial_success
        && partial.rejected_spans != 0
    {
        // Retrying partial success cannot recover the rejected subset alone.
        let Ok(rejected) = u64::try_from(partial.rejected_spans) else {
            return SendResult::Retry(anyhow::anyhow!("invalid OTLP partial rejection count"));
        };
        return SendResult::Rejected {
            rejected: Some(rejected),
            error: anyhow::anyhow!("OTLP partial success"),
        };
    }
    SendResult::Delivered
}

fn report_drops() {
    let dropped = DROPPED.swap(0, Ordering::Relaxed);
    if dropped != 0 {
        log::warn!("OTLP spans dropped before durable delivery: {dropped}");
    }
}

fn persist(delivery: &Delivery, instance: &str, submissions: Vec<Submission>) {
    let count = submissions
        .iter()
        .map(|batch| u64::try_from(batch.spans.len()).unwrap_or(u64::MAX))
        .sum::<u64>();
    let spans = submissions
        .into_iter()
        .flat_map(|batch| batch.spans)
        .collect();
    let body = request(spans, instance).encode_to_vec();
    let result = delivery
        .spool
        .lock()
        .map_err(|_| anyhow::anyhow!("trace spool lock poisoned"))
        .and_then(|mut spool| spool.push(count, &body));
    match result {
        Ok(true) => {}
        Ok(false) => {
            DROPPED.fetch_add(count, Ordering::Relaxed);
        }
        Err(error) => {
            DROPPED.fetch_add(count, Ordering::Relaxed);
            log::warn!("trace spool publication failed: {error:#}");
        }
    }
    // A rename may have succeeded before a directory-sync failure.
    delivery.ready.notify_one();
    report_drops();
}

#[derive(Default)]
struct Batch {
    submissions: Vec<Submission>,
    bytes: usize,
    count: usize,
}

impl Batch {
    const fn is_empty(&self) -> bool {
        self.submissions.is_empty()
    }

    const fn fits(&self, next: &Submission) -> bool {
        self.submissions.len() < BATCH_REQUESTS
            && self.bytes.saturating_add(next.bytes) <= MAX_BATCH_MEMORY
            && self.count.saturating_add(next.spans.len()) <= MAX_BATCH_SPANS
    }

    fn push(&mut self, submission: Submission) {
        self.bytes += submission.bytes;
        self.count += submission.spans.len();
        self.submissions.push(submission);
    }

    fn flush(&mut self, delivery: &Delivery, instance: &str) {
        if !self.is_empty() {
            let submissions = std::mem::take(&mut self.submissions);
            self.bytes = 0;
            self.count = 0;
            persist(delivery, instance, submissions);
        }
    }
}

async fn write_spool(mut receiver: mpsc::Receiver<Message>, delivery: &Delivery, instance: &str) {
    let mut batch = Batch::default();
    let mut deadline = tokio::time::Instant::now();
    loop {
        let message = if batch.is_empty() {
            Ok(receiver.recv().await)
        } else {
            tokio::time::timeout_at(deadline, receiver.recv()).await
        };
        match message {
            Ok(Some(Message::Spans(submission))) => {
                if batch.is_empty() || !batch.fits(&submission) {
                    batch.flush(delivery, instance);
                    deadline = tokio::time::Instant::now() + Duration::from_millis(100);
                }
                batch.push(submission);
                if batch.submissions.len() == BATCH_REQUESTS {
                    batch.flush(delivery, instance);
                }
            }
            Ok(Some(Message::Flush(sender))) => {
                batch.flush(delivery, instance);
                let _ = sender.send(());
            }
            Err(_) => batch.flush(delivery, instance),
            Ok(None) => {
                batch.flush(delivery, instance);
                break;
            }
        }
    }
    drop(batch);
}

async fn deliver(delivery: &Delivery, client: &wreq::Client, endpoint: &url::Url) {
    let mut delay = Duration::from_millis(250);
    loop {
        let record = delivery
            .spool
            .lock()
            .map_err(|_| anyhow::anyhow!("trace spool lock poisoned"))
            .and_then(|mut spool| spool.front());
        let record = match record {
            Ok(Some(record)) => record,
            Ok(None) => {
                tokio::select! {
                    () = delivery.ready.notified() => {}
                    () = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                report_drops();
                continue;
            }
            Err(error) => {
                log::warn!("trace spool read failed: {error:#}");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(RETRY_MAX);
                continue;
            }
        };
        match send(client, endpoint, record.body).await {
            SendResult::Retry(error) => {
                log::warn!("trace batch retained for retry: {error:#}");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(RETRY_MAX);
                continue;
            }
            SendResult::Rejected {
                rejected: Some(rejected),
                ..
            } if rejected > record.count => {
                log::warn!(
                    "invalid OTLP rejection count {rejected} for {} spans; retaining batch",
                    record.count
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(RETRY_MAX);
                continue;
            }
            SendResult::Rejected { rejected, error } => {
                log::warn!(
                    "OTLP permanently rejected {} of {} spans: {error:#}",
                    rejected.unwrap_or(record.count),
                    record.count
                );
            }
            SendResult::Delivered => {}
        }
        let ack = delivery
            .spool
            .lock()
            .map_err(|_| anyhow::anyhow!("trace spool lock poisoned"))
            .and_then(|mut spool| spool.ack(record.sequence));
        if let Err(error) = ack {
            log::warn!("trace spool acknowledgement failed: {error:#}");
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(RETRY_MAX);
        } else {
            delay = Duration::from_millis(250);
        }
    }
}

#[cfg(all(test, feature = "dist-server"))]
mod delivery_tests;

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
