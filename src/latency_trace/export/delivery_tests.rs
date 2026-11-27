use super::*;
use anyhow::Context as _;
use axum::{Router, body::Bytes, routing::post};
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::{sync::mpsc::UnboundedReceiver, task::JoinHandle};

struct Receiver {
    endpoint: url::Url,
    mode: Arc<AtomicU8>,
    attempts: UnboundedReceiver<Vec<u8>>,
    server: JoinHandle<std::io::Result<()>>,
}

impl Receiver {
    async fn start() -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = url::Url::parse(&format!("http://{}/v1/traces", listener.local_addr()?))?;
        let mode = Arc::new(AtomicU8::new(0));
        let state = Arc::clone(&mode);
        let (sender, attempts) = mpsc::unbounded_channel();
        let router = Router::new().route(
            "/v1/traces",
            post(move |body: Bytes| {
                let mode = Arc::clone(&state);
                let sender = sender.clone();
                async move {
                    let response = match mode.load(Ordering::Acquire) {
                        0 => (http::StatusCode::SERVICE_UNAVAILABLE, Vec::new()),
                        1 => {
                            mode.store(2, Ordering::Release);
                            // The backend may already have accepted the record.
                            // The response cannot be decoded, so retry unchanged.
                            (http::StatusCode::OK, vec![0])
                        }
                        _ => (http::StatusCode::OK, Vec::new()),
                    };
                    let _ = sender.send(body.to_vec());
                    response
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        Ok(Self {
            endpoint,
            mode,
            attempts,
            server,
        })
    }

    async fn next(&mut self) -> Result<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(5), self.attempts.recv())
            .await?
            .context("mock collector stopped")
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn open(path: &std::path::Path) -> Result<Arc<Delivery>> {
    Ok(Arc::new(Delivery {
        spool: Mutex::new(Spool::open(path, 1024 * 1024)?),
        ready: Notify::new(),
    }))
}

fn start_delivery(delivery: &Arc<Delivery>, endpoint: &url::Url) -> Result<JoinHandle<()>> {
    let delivery = Arc::clone(delivery);
    let endpoint = endpoint.clone();
    let client = wreq::Client::builder().no_proxy().build()?;
    Ok(tokio::spawn(async move {
        deliver(&delivery, &client, &endpoint).await
    }))
}

fn submission(name: &'static str) -> Result<Message> {
    let parent = crate::latency_trace::TraceContext::request(name);
    let spans = vec![LatencySpan::child(parent, "sccache-client", name, 10, 20)];
    let bytes = submission_size(&spans, spans.capacity());
    let permit =
        Arc::new(Semaphore::new(MEMORY_BUDGET)).try_acquire_many_owned(u32::try_from(bytes)?)?;
    Ok(Message::Spans(Submission {
        spans,
        bytes,
        _permit: permit,
    }))
}

#[tokio::test]
async fn outage_persists_independent_of_delivery_and_replays_identical_bytes() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut collector = Receiver::start().await?;
    let delivery = open(directory.path())?;
    let transport = start_delivery(&delivery, &collector.endpoint)?;
    let (sender, receiver) = mpsc::channel(QUEUE);
    let writer_state = Arc::clone(&delivery);
    let writer =
        tokio::spawn(async move { write_spool(receiver, &writer_state, "test-host").await });
    sender
        .send(submission("first")?)
        .await
        .map_err(|_| anyhow::anyhow!("spool writer stopped"))?;
    let first = collector.next().await?;
    sender
        .send(submission("second")?)
        .await
        .map_err(|_| anyhow::anyhow!("spool writer stopped"))?;
    drop(sender);
    writer.await?;
    transport.abort();
    let _ = transport.await;
    drop(delivery);
    // Reconstruct the spool from disk, with no in-memory state preserved.
    let delivery = open(directory.path())?;
    while collector.attempts.try_recv().is_ok() {}
    collector.mode.store(1, Ordering::Release);
    let transport = start_delivery(&delivery, &collector.endpoint)?;
    assert_eq!(collector.next().await?, first);
    assert_eq!(collector.next().await?, first);
    let second = collector.next().await?;
    let decoded = ExportTraceServiceRequest::decode(second.as_slice())?;
    assert_eq!(
        decoded.resource_spans[0].scope_spans[0].spans[0].name,
        "second"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let empty = delivery.spool.lock().expect("spool").front()?.is_none();
            if empty {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    transport.abort();
    let _ = transport.await;
    Ok(())
}
