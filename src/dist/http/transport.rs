//! Distributed HTTP transport policy.
//!
//! Control-plane replies have bounded memory and strict request deadlines.
//! Build results may contain arbitrarily large compressed artifacts and are
//! intentionally not assigned an artificial size limit here.
use crate::errors::{Context, Result, anyhow};
use bincode::Options;
#[cfg(feature = "dist-server")]
use std::io::Read;
#[cfg(any(feature = "dist-client", test))]
use std::time::Duration;

const CONTROL_RESPONSE_LIMIT: usize = 16 * 1024 * 1024;
const ERROR_RESPONSE_LIMIT: usize = 64 * 1024;
#[cfg(feature = "dist-client")]
#[cfg(feature = "dist-client")]
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_mins(20);

/// Decide whether the expected response is small protocol metadata or a
/// compressed build result which may legitimately exceed ordinary limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestClass {
    /// Scheduler and worker control messages, which must return promptly.
    Control,
    /// Optional display metadata: failure must not affect compilation.
    WorkerName,
    /// Toolchain uploads can actively stream for many minutes.
    ToolchainUpload,
    /// Large compressed build results must preserve existing size semantics.
    BuildResult,
}

#[cfg(feature = "dist-client")]
impl RequestClass {
    const fn timeout(self) -> Duration {
        match self {
            Self::Control => Duration::from_secs(90),
            Self::WorkerName => Duration::from_secs(1),
            Self::ToolchainUpload | Self::BuildResult => HTTP_REQUEST_TIMEOUT,
        }
    }
}

const fn response_limit(success: bool, class: RequestClass) -> Option<usize> {
    if success {
        match class {
            RequestClass::Control | RequestClass::WorkerName | RequestClass::ToolchainUpload => {
                Some(CONTROL_RESPONSE_LIMIT)
            }
            RequestClass::BuildResult => None,
        }
    } else {
        Some(ERROR_RESPONSE_LIMIT)
    }
}

/// Decode bincode with the same fixed-width wire encoding as the original
/// protocol, but restrict the deserializer to bytes actually received. This
/// prevents length prefixes from claiming unbounded allocation independently
/// of the HTTP body budget.
pub(super) fn decode_bincode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> bincode::Result<T> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)
}

/// Read at most a policy budget, independent of Content-Length and without
/// preallocating from peer-supplied lengths. Used for both inbound control RPCs
/// and the synchronous client side.
#[cfg(feature = "dist-server")]
#[derive(Debug)]
pub(super) enum BoundedReadError {
    Io(std::io::Error),
    TooLarge,
}

#[cfg(feature = "dist-server")]
pub(super) fn read_bounded(
    mut input: impl Read,
    limit: usize,
) -> std::result::Result<Vec<u8>, BoundedReadError> {
    let mut body = Vec::new();
    input
        .by_ref()
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut body)
        .map_err(BoundedReadError::Io)?;
    if body.len() > limit {
        return Err(BoundedReadError::TooLarge);
    }
    Ok(body)
}

#[cfg(feature = "dist-server")]
pub(super) const CONTROL_REQUEST_LIMIT: usize = CONTROL_RESPONSE_LIMIT;

fn check_advertised_length(length: Option<u64>, limit: usize) -> Result<()> {
    if length.is_some_and(|len| len > limit as u64) {
        anyhow::bail!("distributed HTTP response exceeds {limit} bytes");
    }
    Ok(())
}

#[cfg(feature = "dist-client")]
pub async fn send_async<T: serde::de::DeserializeOwned>(
    req: wreq::RequestBuilder,
    class: RequestClass,
) -> Result<T> {
    send(req.timeout(class.timeout()), Some(class)).await
}

#[cfg(feature = "dist-server")]
pub(super) async fn send_control<T: serde::de::DeserializeOwned>(
    req: wreq::RequestBuilder,
) -> Result<T> {
    send(req, None).await
}

async fn send<T: serde::de::DeserializeOwned>(
    req: wreq::RequestBuilder,
    class: Option<RequestClass>,
) -> Result<T> {
    let res = req.send().await?;
    let status = res.status();
    let limit = response_limit(status.is_success(), class.unwrap_or(RequestClass::Control));
    let bytes = if let Some(limit) = limit {
        check_advertised_length(res.content_length(), limit)?;
        let mut body = Vec::new();
        use futures::StreamExt;
        let mut stream = std::pin::pin!(res.bytes_stream());
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let total = body
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| anyhow!("distributed HTTP response size overflow"))?;
            if total > limit {
                anyhow::bail!("distributed HTTP response exceeds {limit} bytes");
            }
            body.extend_from_slice(&chunk);
        }
        bytes::Bytes::from(body)
    } else {
        res.bytes().await?
    };
    if !status.is_success() {
        let message = format!(
            "Error {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
        );
        if status.is_client_error() {
            anyhow::bail!(crate::errors::HttpClientError(message));
        }
        anyhow::bail!(message);
    }
    decode_bincode(&bytes).context("failed to decode distributed HTTP response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "dist-client", feature = "dist-server"))]
    fn mock_response(
        status: u16,
        body: Vec<u8>,
        reported_length: Option<usize>,
    ) -> (url::Url, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("test listener");
        let url = format!(
            "http://{}/test",
            listener.local_addr().expect("local address")
        )
        .parse()
        .expect("URL");
        let handler = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept test request");
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .expect("set write timeout");
            let mut request = [0; 1024];
            let _ = socket.read(&mut request);
            let reason = if status == 200 { "OK" } else { "Error" };
            let length = reported_length.unwrap_or(body.len());
            let header = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
            );
            if socket.write_all(header.as_bytes()).is_ok() {
                let _ = socket.write_all(&body);
            }
        });
        (url, handler)
    }

    #[cfg(feature = "dist-server")]
    #[tokio::test]
    async fn control_errors_cannot_buffer_unbounded_bodies() {
        let (url, handler) = mock_response(500, vec![b'x'; ERROR_RESPONSE_LIMIT + 1], None);
        let client = wreq::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("test client");
        let result = send_control::<u8>(client.get(url.as_str())).await;
        assert!(result.unwrap_err().to_string().contains("exceeds"));
        handler.join().expect("response server");
    }

    #[cfg(feature = "dist-client")]
    #[tokio::test]
    async fn async_control_rejects_oversized_response_without_content_length_claim() {
        let payload = vec![b'x'; CONTROL_RESPONSE_LIMIT + 1];
        // A body larger than the control-plane limit must be rejected even
        // when the declared length is incorrect or missing.
        let (url, handler) = mock_response(200, payload, Some(CONTROL_RESPONSE_LIMIT + 1));
        let client = wreq::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("test client");
        let result = send_async::<Vec<u8>>(client.get(url.as_str()), RequestClass::Control).await;
        assert!(result.unwrap_err().to_string().contains("exceeds"));
        handler.join().expect("response server");
    }

    #[cfg(feature = "dist-client")]
    #[tokio::test]
    async fn async_build_result_accepts_payload_larger_than_control_limit() {
        let payload = vec![123u8; CONTROL_RESPONSE_LIMIT + 1];
        let serialized = bincode::serialize(&payload).expect("encode build response");
        let (url, handler) = mock_response(200, serialized, None);
        let client = wreq::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("test client");
        let result: Vec<u8> = send_async(client.get(url.as_str()), RequestClass::BuildResult)
            .await
            .expect("large result must remain supported");
        assert_eq!(result.len(), CONTROL_RESPONSE_LIMIT + 1);
        assert_eq!(result[0], 123);
        handler.join().expect("response server");
    }

    #[cfg(feature = "dist-client")]
    #[tokio::test]
    async fn async_server_error_body_has_separate_smaller_budget() {
        let (url, handler) = mock_response(500, vec![b'x'; ERROR_RESPONSE_LIMIT + 1], None);
        let client = wreq::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("test client");
        let result = send_async::<u8>(client.get(url.as_str()), RequestClass::BuildResult).await;
        assert!(result.unwrap_err().to_string().contains("exceeds"));
        handler.join().expect("response server");
    }

    #[cfg(feature = "dist-client")]
    #[test]
    fn control_plane_is_bounded_and_build_output_is_not() {
        assert_eq!(
            response_limit(true, RequestClass::Control),
            Some(16 * 1024 * 1024)
        );
        assert_eq!(response_limit(true, RequestClass::BuildResult), None);
        for class in [
            RequestClass::Control,
            RequestClass::WorkerName,
            RequestClass::ToolchainUpload,
            RequestClass::BuildResult,
        ] {
            assert_eq!(response_limit(false, class), Some(64 * 1024));
        }
        assert_eq!(RequestClass::Control.timeout(), Duration::from_secs(90));
        assert_eq!(RequestClass::WorkerName.timeout(), Duration::from_secs(1));
        assert_eq!(
            RequestClass::ToolchainUpload.timeout(),
            Duration::from_mins(20)
        );
        assert_eq!(RequestClass::BuildResult.timeout(), Duration::from_mins(20));
    }

    #[cfg(feature = "dist-server")]
    #[test]
    fn inbound_body_limit_applies_with_or_without_content_length() {
        let maximum = 100;
        let valid = read_bounded(std::io::Cursor::new(vec![0; maximum]), maximum)
            .expect("body exactly at limit");
        assert_eq!(valid.len(), maximum);
        let oversized = read_bounded(std::io::Cursor::new(vec![0; maximum + 1]), maximum);
        assert!(matches!(
            oversized.expect_err("body over budget"),
            BoundedReadError::TooLarge
        ));
    }

    #[cfg(feature = "dist-server")]
    #[test]
    fn io_invalid_data_is_not_confused_with_size_limit() {
        struct BrokenReader;
        impl Read for BrokenReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed transfer framing",
                ))
            }
        }
        assert!(matches!(
            read_bounded(BrokenReader, 100),
            Err(BoundedReadError::Io(error))
                if error.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn bincode_decoder_rejects_claimed_lengths_beyond_received_bytes() {
        let reported_length = 1_000_000_u64.to_le_bytes();
        assert!(decode_bincode::<Vec<u8>>(&reported_length).is_err());
        let encoded = bincode::serialize(&vec![1_u8, 2, 3]).expect("encode");
        assert_eq!(
            decode_bincode::<Vec<u8>>(&encoded).expect("valid bincode"),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn advertised_body_limit_rejects_only_oversized_responses() {
        assert!(check_advertised_length(None, 8).is_ok());
        assert!(check_advertised_length(Some(8), 8).is_ok());
        assert!(check_advertised_length(Some(9), 8).is_err());
    }
}
