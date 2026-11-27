//! Shared HTTP client construction and bounded authentication JSON.
//!
//! The base async builder deliberately has no request timeout: object storage
//! may stream large files. Short authentication/control operations set their
//! own deadline. The blocking builder has finite defaults for scheduler use.

use crate::errors::{Context, Result, anyhow};
use serde::de::DeserializeOwned;
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
use std::io::Read;
use std::time::Duration;

/// Maximum size of a provider JWKS response.
pub const JWKS_LIMIT: usize = 1024 * 1024;
/// Maximum size of OAuth and metadata token responses.
pub const TOKEN_JSON_LIMIT: usize = 64 * 1024;
/// Total deadline for authentication requests.
pub const AUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Public-CA HTTP client; storage operations set their own deadlines.
pub(crate) fn new_http_client_builder() -> wreq::ClientBuilder {
    wreq::Client::builder().redirect(wreq::redirect::Policy::limited(10))
}

/// Shared asynchronous network reactor for synchronous compiler/storage callers.
/// Use only at synchronous boundaries; async callers await requests directly.
/// # Errors
/// Returns an error if the shared network runtime cannot be initialized.
#[cfg(any(feature = "dist-server", feature = "dist-client"))]
pub fn io_runtime() -> Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: std::sync::OnceLock<std::io::Result<tokio::runtime::Runtime>> =
        std::sync::OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(crate::util::num_cpus())
                .thread_name("sccache-http-io")
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(|error| anyhow!("initialize HTTP runtime: {error}"))
}

/// A bounded asynchronous download feeding a synchronous storage consumer.
/// Dropping the reader cancels the producer, including a pending body read.
#[cfg(any(feature = "dist-server", feature = "dist-client"))]
pub(crate) struct ResponseReader {
    chunks: tokio::sync::mpsc::Receiver<std::io::Result<Option<bytes::Bytes>>>,
    current: bytes::Bytes,
    producer: tokio::task::JoinHandle<()>,
    finished: bool,
}

#[cfg(any(feature = "dist-server", feature = "dist-client"))]
impl ResponseReader {
    pub(crate) fn new(response: wreq::Response) -> Result<Self> {
        use futures::StreamExt;
        let (tx, chunks) = tokio::sync::mpsc::channel(2);
        let producer = io_runtime()?.spawn(async move {
            let mut stream = std::pin::pin!(response.bytes_stream());
            while let Some(chunk) = stream.next().await {
                let mut chunk = match chunk {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        let _ = tx
                            .send(Err(std::io::Error::other(error.without_uri())))
                            .await;
                        return;
                    }
                };
                while !chunk.is_empty() {
                    let piece = chunk.split_to(chunk.len().min(128 * 1024));
                    if tx.send(Ok(Some(piece))).await.is_err() {
                        return;
                    }
                }
            }
            let _ = tx.send(Ok(None)).await;
        });
        Ok(Self {
            chunks,
            current: bytes::Bytes::new(),
            producer,
            finished: false,
        })
    }
}

#[cfg(any(feature = "dist-server", feature = "dist-client"))]
impl Read for ResponseReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use bytes::Buf;
        if buffer.is_empty() || self.finished {
            return Ok(0);
        }
        while self.current.is_empty() {
            match self.chunks.blocking_recv() {
                Some(Ok(Some(chunk))) => self.current = chunk,
                Some(Ok(None)) => {
                    self.finished = true;
                    return Ok(0);
                }
                Some(Err(error)) => {
                    self.finished = true;
                    return Err(error);
                }
                None => {
                    self.finished = true;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "HTTP download producer terminated",
                    ));
                }
            }
        }
        let count = buffer.len().min(self.current.len());
        buffer[..count].copy_from_slice(&self.current[..count]);
        self.current.advance(count);
        Ok(count)
    }
}

#[cfg(any(feature = "dist-server", feature = "dist-client"))]
impl Drop for ResponseReader {
    fn drop(&mut self) {
        self.producer.abort();
    }
}

/// Read an authentication response body with an explicit byte budget.
///
/// # Errors
/// Returns an error on transport failure or oversized response.
pub async fn read_bounded_bytes_async(response: wreq::Response, limit: usize) -> Result<Vec<u8>> {
    use futures::StreamExt;
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        anyhow::bail!("authentication HTTP response exceeds {limit} bytes");
    }
    let mut data = Vec::new();
    let mut stream = std::pin::pin!(response.bytes_stream());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let total = data
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("authentication HTTP response exceeds {limit} bytes"))?;
        anyhow::ensure!(
            total <= limit,
            "authentication HTTP response exceeds {limit} bytes"
        );
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

/// Parse a bounded asynchronous authentication JSON body, including chunked
/// responses which do not advertise a Content-Length.
///
/// # Errors
/// Returns an error for oversized, unreadable or malformed JSON bodies.
pub async fn read_bounded_json_async<T: DeserializeOwned>(
    response: wreq::Response,
    limit: usize,
) -> Result<T> {
    let data = read_bounded_bytes_async(response, limit).await?;
    serde_json::from_slice(&data).context("failed to decode authentication JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn http_builders_load_trust_roots() -> crate::errors::Result<()> {
        new_http_client_builder().build()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn http_builders_survive_missing_system_ca_store() -> crate::errors::Result<()> {
        // Isolate the platform verifier's environment from concurrently running
        // tests, including any other HTTP clients they construct.
        let dir = tempfile::tempdir()?;
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "http_client::tests::http_builders_load_trust_roots",
            ])
            .env("SSL_CERT_FILE", dir.path().join("missing-ca-file"))
            .env("SSL_CERT_DIR", dir.path().join("missing-ca-dir"))
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("1 passed"), "{stdout}");
        Ok(())
    }

    fn local_response(body: Vec<u8>, content_length: bool) -> (url::Url, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener");
        let url = format!("http://{}/oauth", listener.local_addr().expect("address"))
            .parse()
            .expect("test URL");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            let mut headers = String::from(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n",
            );
            if content_length {
                headers.push_str(&format!("Content-Length: {}\r\n", body.len()));
            }
            headers.push_str("\r\n");
            if stream.write_all(headers.as_bytes()).is_ok() {
                let _ = stream.write_all(&body);
            }
        });
        (url, server)
    }

    #[tokio::test]
    async fn async_json_reader_limits_unknown_length_responses() {
        let (url, server) = local_response(vec![b'x'; TOKEN_JSON_LIMIT + 1], false);
        let client = new_http_client_builder().build().expect("client");
        let res = client.get(url.as_str()).send().await.expect("response");
        assert!(
            read_bounded_json_async::<serde_json::Value>(res, TOKEN_JSON_LIMIT)
                .await
                .expect_err("oversized body")
                .to_string()
                .contains("exceeds")
        );
        server.join().expect("server");
    }

    #[tokio::test]
    async fn async_json_reader_accepts_small_json() {
        let (url, server) = local_response(br#"{"access_token":"test"}"#.to_vec(), false);
        let client = new_http_client_builder().build().expect("client");
        let res = client.get(url.as_str()).send().await.expect("response");
        let value: serde_json::Value = read_bounded_json_async(res, TOKEN_JSON_LIMIT)
            .await
            .expect("JSON");
        assert_eq!(value["access_token"], "test");
        server.join().expect("server");
    }
}
