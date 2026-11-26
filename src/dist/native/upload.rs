//! Demand-driven streaming for synchronous input providers. Unlike reqwest's
//! blocking body adapter, a failed connection cannot read ahead from IPC.
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use futures::StreamExt;
use std::{
    io::{self, Read},
    sync::mpsc,
};
use tokio::sync::oneshot;

const CHUNK: usize = 128 * 1024;

enum Event {
    Read(oneshot::Sender<io::Result<Option<Bytes>>>),
    Complete(Result<Reply>),
}

pub(super) struct Attempt {
    pub result: Result<Reply>,
    /// Bytes actually read from the caller's source, including the metadata.
    pub consumed: u64,
}

pub(super) struct Reply {
    pub bytes: Vec<u8>,
    pub path: super::super::cluster_routes::ConnectionPath,
}

async fn reply(
    request: wreq::RequestBuilder,
    length: u64,
    limit: u64,
    demand: mpsc::Sender<Event>,
) -> Result<Reply> {
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
    reply_stream(request, length, limit, stream).await
}

async fn reply_stream(
    request: wreq::RequestBuilder,
    length: u64,
    limit: u64,
    stream: impl futures::Stream<Item = io::Result<Bytes>> + Send + 'static,
) -> Result<Reply> {
    let response = request
        .header(http::header::CONTENT_LENGTH, length)
        .body(wreq::Body::wrap_stream(stream))
        .send()
        .await?
        .error_for_status()?;
    let path = super::super::cluster_routes::ConnectionPath::from_response(&response);
    let mut bytes = Vec::new();
    let mut stream = std::pin::pin!(response.bytes_stream());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            (bytes.len() as u64).saturating_add(chunk.len() as u64) <= limit,
            "native upload response exceeds configured limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(Reply { bytes, path })
}

/// Only the calling thread reads the source, and only when the HTTP body is
/// polled. The stream never owns the IPC reader, even during cancellation.
pub(super) fn send(
    request: wreq::RequestBuilder,
    length: u64,
    limit: u64,
    mut source: impl Read,
) -> Result<Attempt> {
    let runtime = crate::http_client::io_runtime()?;
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

/// Demand-driven immutable file upload. There is no synchronous producer,
/// no temporary copy, and at most one completion read per body poll.
#[cfg(all(unix, feature = "native-store"))]
pub(super) async fn send_file(
    request: wreq::RequestBuilder,
    header: Bytes,
    file: std::sync::Arc<std::fs::File>,
    size: u64,
    limit: u64,
    activity: Option<crate::dist::cluster_routes::interface::Activity>,
) -> Result<Attempt> {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    };
    let length = size
        .checked_add(header.len() as u64)
        .context("native upload length overflow")?;
    let consumed = Arc::new(AtomicU64::new(0));
    let local_error = Arc::new(Mutex::new(None));
    let count = Arc::clone(&consumed);
    let errors = Arc::clone(&local_error);
    let stream = futures::stream::try_unfold(
        (Some(header), file, 0_u64, activity),
        move |(header, file, offset, mut activity)| {
            let count = Arc::clone(&count);
            let errors = Arc::clone(&errors);
            async move {
                let (bytes, next) = if let Some(header) = header {
                    (header, offset)
                } else if offset < size {
                    let width = usize::try_from((size - offset).min(CHUNK as u64))
                        .map_err(io::Error::other)?;
                    match crate::build_runtime::read_file_at(Arc::clone(&file), offset, width, ())
                        .await
                    {
                        Ok((bytes, ())) => (Bytes::from(bytes), offset + width as u64),
                        Err(error) => {
                            let description = format!("{error:#}");
                            *errors
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
                            return Err(io::Error::other(description));
                        }
                    }
                } else {
                    return Ok(None);
                };
                count.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                if let Some(activity) = &mut activity {
                    activity.bytes(bytes.len() as u64);
                }
                Ok(Some((bytes, (None, file, next, activity))))
            }
        },
    );
    let result = reply_stream(request, length, limit, stream).await;
    let local_error = local_error
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    Ok(Attempt {
        result: local_error.map_or(result, Err),
        consumed: consumed.load(Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[cfg(all(unix, feature = "native-store"))]
    #[tokio::test]
    async fn refused_connection_does_not_read_immutable_file() -> Result<()> {
        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = socket.local_addr()?;
        drop(socket);
        let request = wreq::Client::builder()
            .no_proxy()
            .build()?
            .post(format!("http://{address}/upload"))
            .timeout(std::time::Duration::from_secs(2));
        // A declared but absent payload would return a local truncation
        // error if the stream were read before a connection exists.
        let file = std::sync::Arc::new(tempfile::tempfile()?);
        let attempt = send_file(
            request,
            Bytes::from_static(b"metadata"),
            file,
            1 << 20,
            1024,
            None,
        )
        .await?;
        assert!(attempt.result.is_err());
        assert_eq!(attempt.consumed, 0);
        Ok(())
    }

    #[cfg(all(unix, feature = "native-store"))]
    #[tokio::test]
    async fn immutable_file_body_reads_exact_positional_range() -> Result<()> {
        use std::{
            io::{Seek, SeekFrom, Write},
            sync::Arc,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let bytes = (0..(3 * CHUNK + 17))
            .map(|index| u8::try_from(index % 251).unwrap_or_default())
            .collect::<Vec<_>>();
        let mut file = tempfile::tempfile()?;
        file.write_all(&bytes)?;
        file.seek(SeekFrom::Start(123))?;
        let file = Arc::new(file);
        let expected = [b"metadata".as_slice(), &bytes].concat();
        let size = bytes.len() as u64;
        let length = expected.len();
        let receiver = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(stream.read_u8().await?);
                ensure!(headers.len() <= 16 * 1024, "oversized request headers");
            }
            let mut actual = vec![0; length];
            stream.read_exact(&mut actual).await?;
            assert_eq!(actual, expected);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await?;
            Ok::<_, anyhow::Error>(())
        });
        let request = wreq::Client::builder()
            .no_proxy()
            .build()?
            .post(format!("http://{address}/upload"))
            .timeout(std::time::Duration::from_secs(5));
        let attempt = send_file(
            request,
            Bytes::from_static(b"metadata"),
            Arc::clone(&file),
            size,
            1024,
            None,
        )
        .await?;
        assert_eq!(attempt.result?.bytes, b"OK");
        assert_eq!(attempt.consumed, length as u64);
        receiver.await??;
        assert_eq!((&*file).stream_position()?, 123);
        Ok(())
    }

    #[test]
    fn refused_connection_does_not_read_nonseekable_source() -> Result<()> {
        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = socket.local_addr()?;
        drop(socket);
        let request = wreq::Client::builder()
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
