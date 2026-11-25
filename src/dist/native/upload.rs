//! Demand-driven streaming for synchronous input providers. Unlike reqwest's
//! blocking body adapter, a failed connection cannot read ahead from IPC.
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use std::{
    io::{self, Read},
    sync::{OnceLock, mpsc},
};
use tokio::{runtime::Runtime, sync::oneshot};

const CHUNK: usize = 128 * 1024;
static RUNTIME: OnceLock<io::Result<Runtime>> = OnceLock::new();

enum Event {
    Read(oneshot::Sender<io::Result<Option<Bytes>>>),
    Complete(Result<Vec<u8>>),
}

pub(super) struct Attempt {
    pub result: Result<Vec<u8>>,
    /// Bytes actually read from the caller's source, including the metadata.
    pub consumed: u64,
}

async fn reply(
    request: reqwest::RequestBuilder,
    length: u64,
    limit: u64,
    demand: mpsc::Sender<Event>,
) -> Result<Vec<u8>> {
    let stream = futures::stream::unfold(Some(demand), |state| async move {
        let demand = state?;
        let (send, receive) = oneshot::channel();
        demand.send(Event::Read(send)).ok()?;
        match receive.await.ok()? {
            Ok(Some(bytes)) => Some((Ok(bytes), Some(demand))),
            Ok(None) => None,
            Err(error) => Some((Err(error), None)),
        }
    });
    let mut response = request
        .header(reqwest::header::CONTENT_LENGTH, length)
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await?
        .error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            (bytes.len() as u64).saturating_add(chunk.len() as u64) <= limit,
            "native upload response exceeds configured limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Only the calling thread reads the source, and only when the HTTP body is
/// polled. The stream never owns the IPC reader, even during cancellation.
pub(super) fn send(
    request: reqwest::RequestBuilder,
    length: u64,
    limit: u64,
    mut source: impl Read,
) -> Result<Attempt> {
    let runtime = RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("native-upload-io")
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(|error| anyhow::anyhow!("initialize native upload runtime: {error}"))?;
    let (events, receive) = mpsc::channel();
    let demand = events.clone();
    runtime.spawn(async move {
        let result = reply(request, length, limit, demand).await;
        let _ = events.send(Event::Complete(result));
    });
    let mut consumed = 0_u64;
    let mut local_error = None;
    loop {
        match receive
            .recv()
            .context("native upload transport terminated")?
        {
            Event::Read(send) => {
                let remaining = length.saturating_sub(consumed);
                if remaining == 0 {
                    let _ = send.send(Ok(None));
                    continue;
                }
                let mut buffer = vec![0; usize::try_from(remaining.min(CHUNK as u64))?];
                let read = loop {
                    match source.read(&mut buffer) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        result => break result,
                    }
                };
                let result = match read {
                    Ok(0) => Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated native upload",
                    )),
                    Ok(count) => {
                        consumed += count as u64;
                        buffer.truncate(count);
                        Ok(Some(Bytes::from(buffer)))
                    }
                    Err(error) => Err(error),
                };
                if let Err(error) = &result {
                    local_error = Some(io::Error::new(error.kind(), error.to_string()));
                }
                let _ = send.send(result);
            }
            Event::Complete(result) => {
                return Ok(Attempt {
                    result: local_error.map_or(result, |error| Err(error.into())),
                    consumed,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[test]
    fn refused_connection_does_not_read_nonseekable_source() -> Result<()> {
        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = socket.local_addr()?;
        drop(socket);
        let request = reqwest::Client::builder()
            .no_proxy()
            .build()?
            .post(format!("http://{address}/upload"))
            .timeout(std::time::Duration::from_secs(2));
        let mut bytes = &b"unconsumed bytes"[..];
        let attempt = send(request, bytes.len() as u64, 1024, &mut bytes)?;
        assert!(attempt.result.is_err());
        assert_eq!(attempt.consumed, 0);
        assert_eq!(bytes, b"unconsumed bytes");
        Ok(())
    }
}
