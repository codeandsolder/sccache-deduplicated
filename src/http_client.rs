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

#[cfg(all(feature = "reqwest", not(target_os = "android"), any(unix, windows)))]
fn mozilla_root_certificates() -> reqwest::Result<Vec<reqwest::Certificate>> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|cert| reqwest::Certificate::from_der(cert.as_ref()))
        .collect()
}

/// Use the platform verifier augmented with Mozilla roots on platforms where
/// reqwest supports merging roots. Android uses its own platform verifier.
pub(crate) fn new_reqwest_client_builder() -> reqwest::Result<reqwest::ClientBuilder> {
    let builder = reqwest::Client::builder();
    #[cfg(all(not(target_os = "android"), any(unix, windows)))]
    let builder = builder.tls_certs_merge(mozilla_root_certificates()?);
    Ok(builder)
}

#[cfg(any(feature = "dist-server", feature = "dist-client"))]
pub(crate) fn new_reqwest_blocking_builder() -> reqwest::Result<reqwest::blocking::ClientBuilder> {
    // Include certificate-rebuilt scheduler clients: all blocking control-plane
    // requests need finite deadlines even after trust-root rotation.
    let builder = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(90));
    #[cfg(all(not(target_os = "android"), any(unix, windows)))]
    let builder = builder.tls_certs_merge(mozilla_root_certificates()?);
    Ok(builder)
}

/// Build the blocking HTTP client used by distributed components.
/// Pooling is disabled because connections may outlive their original runtime.
/// # Errors
/// Returns an error if reqwest cannot initialize the configured client.
#[cfg(any(feature = "dist-server", feature = "dist-client"))]
pub fn new_reqwest_blocking_client() -> Result<reqwest::blocking::Client> {
    new_reqwest_blocking_builder()?
        .pool_max_idle_per_host(0)
        .build()
        .context("failed to build blocking HTTP client")
}

/// Parse an authentication JSON response without trusting Content-Length or
/// allocating unbounded memory for chunked/streamed bodies.
///
/// # Errors
/// Returns an error if the body is too large, unreadable or malformed JSON.
#[cfg(any(feature = "dist-server", feature = "dist-client"))]
pub fn read_bounded_json<T: DeserializeOwned>(
    mut response: reqwest::blocking::Response,
    limit: usize,
) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        anyhow::bail!("authentication HTTP response exceeds {limit} bytes");
    }
    let mut data = Vec::new();
    response
        .by_ref()
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut data)
        .context("failed to read authentication JSON")?;
    anyhow::ensure!(
        data.len() <= limit,
        "authentication HTTP response exceeds {limit} bytes"
    );
    serde_json::from_slice(&data).context("failed to decode authentication JSON")
}

/// Read an authentication response body with an explicit byte budget.
///
/// # Errors
/// Returns an error on transport failure or oversized response.
pub async fn read_bounded_bytes_async(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        anyhow::bail!("authentication HTTP response exceeds {limit} bytes");
    }
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await? {
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
    response: reqwest::Response,
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
        new_reqwest_client_builder()?.build()?;
        #[cfg(any(feature = "dist-server", feature = "dist-client"))]
        new_reqwest_blocking_client()?;
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

    fn local_response(
        body: Vec<u8>,
        content_length: bool,
    ) -> (reqwest::Url, thread::JoinHandle<()>) {
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

    #[cfg(any(feature = "dist-server", feature = "dist-client"))]
    #[test]
    fn blocking_json_reader_limits_unknown_length_responses() {
        let (url, server) = local_response(vec![b'x'; TOKEN_JSON_LIMIT + 1], false);
        let client = new_reqwest_blocking_client().expect("client");
        let res = client.get(url).send().expect("response");
        assert!(
            read_bounded_json::<serde_json::Value>(res, TOKEN_JSON_LIMIT)
                .expect_err("oversized body")
                .to_string()
                .contains("exceeds")
        );
        server.join().expect("server");
    }

    #[cfg(any(feature = "dist-server", feature = "dist-client"))]
    #[test]
    fn blocking_json_reader_accepts_small_json() {
        let (url, server) = local_response(br#"{"keys":[]}"#.to_vec(), true);
        let client = new_reqwest_blocking_client().expect("client");
        let res = client.get(url).send().expect("response");
        let value: serde_json::Value =
            read_bounded_json(res, JWKS_LIMIT).expect("well-formed JSON");
        assert_eq!(value["keys"].as_array().expect("keys").len(), 0);
        server.join().expect("server");
    }

    #[tokio::test]
    async fn async_json_reader_limits_unknown_length_responses() {
        let (url, server) = local_response(vec![b'x'; TOKEN_JSON_LIMIT + 1], false);
        let client = new_reqwest_client_builder()
            .expect("client builder")
            .build()
            .expect("client");
        let res = client.get(url).send().await.expect("response");
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
        let client = new_reqwest_client_builder()
            .expect("client builder")
            .build()
            .expect("client");
        let res = client.get(url).send().await.expect("response");
        let value: serde_json::Value = read_bounded_json_async(res, TOKEN_JSON_LIMIT)
            .await
            .expect("JSON");
        assert_eq!(value["access_token"], "test");
        server.join().expect("server");
    }
}
