use bytes::Bytes;
use futures::channel::oneshot;
use http::HeaderValue;
use http::StatusCode;
use http::header::CONTENT_TYPE;
use http_body_util::Full;
use hyper::{Method, Response, Uri};
use serde::Serialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use crate::errors::{Context, Result, anyhow, bail};
use crate::util::new_client_runtime;

// These (arbitrary) ports need to be registered as valid redirect urls in the oauth provider you're using
pub const VALID_PORTS: &[u16] = &[12731, 32492, 56909];
// If token is valid for under this amount of time, print a warning
const MIN_TOKEN_VALIDITY: Duration = Duration::from_hours(48);
const MIN_TOKEN_VALIDITY_WARNING: &str = "two days";

fn query_pairs(url: &str) -> Result<HashMap<String, String>> {
    // Url::parse operates on absolute URLs, so ensure there's a prefix
    let url = Url::parse("http://unused_base")
        .context("Failed to parse internal query-parameter base URL")?
        .join(url)
        .context("Failed to parse url while extracting query params")?;
    Ok(url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect())
}

fn response(
    status: StatusCode,
    content_type: &'static str,
    body: impl Into<Bytes>,
) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

fn html_response(body: &'static str) -> Response<Full<Bytes>> {
    response(StatusCode::OK, "text/html; charset=utf-8", body)
}

fn json_response<T: Serialize + ?Sized>(data: &T) -> Result<Response<Full<Bytes>>> {
    let body = serde_json::to_vec(data).context("Failed to serialize to JSON")?;
    Ok(response(StatusCode::OK, "application/json", body))
}

const REDIRECT_WITH_AUTH_JSON: &str = r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"></head>
<body>
    <script>
    function writemsg(m) {
        document.body.appendChild(document.createTextNode(m.toString()));
        document.body.appendChild(document.createElement('br'));
    }
    function go() {
        writemsg('Retrieving details of authenticator...');
        fetch('/auth_detail.json').then(function (response) {
            if (!response.ok) {
                throw 'Error during retrieval - ' + response.status + ': ' + response.statusText;
            }
            writemsg('Using details to redirect to authentication page...');
            return response.json()
        }).then(function (auth_url) {
            window.location.href = auth_url;
        }).catch(writemsg);
    }
    go();
    </script>
</body>
</html>
"#;

mod code_grant_pkce {
    use super::warn_if_short_lived;
    use crate::http_client::{self, new_reqwest_blocking_client};
    use crate::util::BASE64_URL_SAFE_ENGINE;
    use base64::Engine;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use url::Url;

    use crate::errors::{Context, Result, bail};

    // Code request - https://tools.ietf.org/html/rfc7636#section-4.3
    const CLIENT_ID_PARAM: &str = "client_id";
    const CODE_CHALLENGE_PARAM: &str = "code_challenge";
    const CODE_CHALLENGE_METHOD_PARAM: &str = "code_challenge_method";
    const CODE_CHALLENGE_METHOD_VALUE: &str = "S256";
    const REDIRECT_PARAM: &str = "redirect_uri";
    const RESPONSE_TYPE_PARAM: &str = "response_type";
    const RESPONSE_TYPE_PARAM_VALUE: &str = "code";
    const STATE_PARAM: &str = "state";
    // Code response - https://tools.ietf.org/html/rfc6749#section-4.1.2
    const CODE_RESULT_PARAM: &str = "code";
    const STATE_RESULT_PARAM: &str = "state";

    // Token request - https://tools.ietf.org/html/rfc7636#section-4.5
    #[derive(Serialize)]
    struct TokenRequest<'a> {
        client_id: &'a str,
        code_verifier: &'a str,
        code: &'a str,
        grant_type: &'a str,
        redirect_uri: &'a str,
    }
    const GRANT_TYPE_PARAM_VALUE: &str = "authorization_code";
    // Token response - https://tools.ietf.org/html/rfc6749#section-5.1
    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        token_type: String,
        expires_in: u64, // Technically not required by the spec
    }
    const TOKEN_TYPE_RESULT_PARAM_VALUE: &str = "bearer"; // case-insensitive

    const NUM_CODE_VERIFIER_BYTES: usize = 256 / 8;

    #[must_use = "the verifier and matching challenge must be retained for the OAuth exchange"]
    pub fn generate_verifier_and_challenge() -> (String, String) {
        let mut code_verifier_bytes = vec![0; NUM_CODE_VERIFIER_BYTES];
        rand::fill(&mut code_verifier_bytes);
        let code_verifier = BASE64_URL_SAFE_ENGINE.encode(&code_verifier_bytes);
        let mut hasher = Sha256::new();
        hasher.update(&code_verifier);
        let code_challenge = BASE64_URL_SAFE_ENGINE.encode(hasher.finalize());
        (code_verifier, code_challenge)
    }

    pub fn finish_url(
        client_id: &str,
        url: &mut Url,
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
    ) {
        url.query_pairs_mut()
            .append_pair(CLIENT_ID_PARAM, client_id)
            .append_pair(CODE_CHALLENGE_PARAM, code_challenge)
            .append_pair(CODE_CHALLENGE_METHOD_PARAM, CODE_CHALLENGE_METHOD_VALUE)
            .append_pair(REDIRECT_PARAM, redirect_uri)
            .append_pair(RESPONSE_TYPE_PARAM, RESPONSE_TYPE_PARAM_VALUE)
            .append_pair(STATE_PARAM, state);
    }

    pub(super) fn handle_code_response(
        params: &HashMap<String, String>,
    ) -> Result<(String, String)> {
        let code = params
            .get(CODE_RESULT_PARAM)
            .context("No code found in response")?;
        let state = params
            .get(STATE_RESULT_PARAM)
            .context("No state found in response")?;
        Ok((code.to_owned(), state.to_owned()))
    }

    fn handle_token_response(res: TokenResponse) -> Result<(String, Instant)> {
        let token = res.access_token;
        if res.token_type.to_lowercase() != TOKEN_TYPE_RESULT_PARAM_VALUE {
            bail!("Token type in response is not {TOKEN_TYPE_RESULT_PARAM_VALUE}")
        }
        // Calculate ASAP the actual time at which the token will expire.
        let expires_at = Instant::now()
            .checked_add(Duration::from_secs(res.expires_in))
            .context("Token expiry is too far in the future")?;
        Ok((token, expires_at))
    }

    pub(super) const SUCCESS_AFTER_REDIRECT: &str = r#"<!doctype html>
    <html lang="en">
    <head><meta charset="utf-8"></head>
    <body>In-browser step of authentication complete, you can now close this page!</body>
    </html>
    "#;

    pub fn code_to_token(
        token_url: &str,
        client_id: &str,
        code_verifier: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<String> {
        let token_request = TokenRequest {
            client_id,
            code_verifier,
            code,
            grant_type: GRANT_TYPE_PARAM_VALUE,
            redirect_uri,
        };
        let client = new_reqwest_blocking_client()?;
        let res = client
            .post(token_url)
            .timeout(http_client::AUTH_REQUEST_TIMEOUT)
            .json(&token_request)
            .send()?;
        if !res.status().is_success() {
            bail!(
                "Sending code to {token_url} failed, HTTP error: {}",
                res.status()
            )
        }

        let (token, expires_at) = handle_token_response(
            http_client::read_bounded_json(res, http_client::TOKEN_JSON_LIMIT)
                .context("Failed to parse token response as JSON")?,
        )?;
        warn_if_short_lived(expires_at);
        Ok(token)
    }
}

mod implicit {

    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use url::Url;

    use crate::errors::{Context, Result, anyhow, bail};

    // Request - https://tools.ietf.org/html/rfc6749#section-4.2.1
    const CLIENT_ID_PARAM: &str = "client_id";
    const REDIRECT_PARAM: &str = "redirect_uri";
    const RESPONSE_TYPE_PARAM: &str = "response_type";
    const RESPONSE_TYPE_PARAM_VALUE: &str = "token";
    const STATE_PARAM: &str = "state";
    // Response - https://tools.ietf.org/html/rfc6749#section-4.2.2
    const TOKEN_RESULT_PARAM: &str = "access_token";
    const TOKEN_TYPE_RESULT_PARAM: &str = "token_type";
    const TOKEN_TYPE_RESULT_PARAM_VALUE: &str = "bearer"; // case-insensitive
    const EXPIRES_IN_RESULT_PARAM: &str = "expires_in"; // Technically not required by the spec
    const STATE_RESULT_PARAM: &str = "state";

    pub fn finish_url(client_id: &str, url: &mut Url, redirect_uri: &str, state: &str) {
        url.query_pairs_mut()
            .append_pair(CLIENT_ID_PARAM, client_id)
            .append_pair(REDIRECT_PARAM, redirect_uri)
            .append_pair(RESPONSE_TYPE_PARAM, RESPONSE_TYPE_PARAM_VALUE)
            .append_pair(STATE_PARAM, state);
    }

    pub(super) fn handle_response(
        params: &HashMap<String, String>,
    ) -> Result<(String, Instant, String)> {
        let token = params
            .get(TOKEN_RESULT_PARAM)
            .context("No token found in response")?;
        let bearer = params
            .get(TOKEN_TYPE_RESULT_PARAM)
            .context("No token type found in response")?;
        if bearer.to_lowercase() != TOKEN_TYPE_RESULT_PARAM_VALUE {
            bail!("Token type in response is not {TOKEN_TYPE_RESULT_PARAM_VALUE}")
        }
        let expires_in = params
            .get(EXPIRES_IN_RESULT_PARAM)
            .context("No expiry found in response")?;
        // Calculate ASAP the actual time at which the token will expire.
        let expires_in = expires_in
            .parse()
            .map_err(|_| anyhow!("Failed to parse expiry as integer"))?;
        let expires_at = Instant::now()
            .checked_add(Duration::from_secs(expires_in))
            .context("Token expiry is too far in the future")?;
        let state = params
            .get(STATE_RESULT_PARAM)
            .context("No state found in response")?;
        Ok((token.to_owned(), expires_at, state.to_owned()))
    }

    pub(super) const SAVE_AUTH_AFTER_REDIRECT: &str = r#"<!doctype html>
    <html lang="en">
    <head><meta charset="utf-8"></head>
    <body>
        <script>
        function writemsg(m) {
            document.body.appendChild(document.createTextNode(m.toString()));
            document.body.appendChild(document.createElement('br'));
        }
        function go() {
            writemsg('Saving authentication details...');
            var qs = window.location.hash.slice(1);
            if (qs.length === 0) {
                writemsg("ERROR: No URL hash returned from authorizer");
                return
            }
            fetch('/save_auth?' + qs, { method: 'POST' }).then(function (response) {
                if (!response.ok) {
                    throw 'Error during saving authentication - ' + response.status + ': ' + response.statusText;
                }
                writemsg('Authentication complete, you can now close this page!');
            }).catch(writemsg);
        }
        go();
        </script>
    </body>
    </html>
    "#;
}

use tokio::net::TcpListener;

fn warn_if_short_lived(expires_at: Instant) {
    if expires_at.saturating_duration_since(Instant::now()) < MIN_TOKEN_VALIDITY {
        warn!("Token retrieved expires in under {MIN_TOKEN_VALIDITY_WARNING}");
        eprintln!("sccache: Token retrieved expires in under {MIN_TOKEN_VALIDITY_WARNING}");
    }
}

#[derive(Clone, Copy)]
enum CallbackFlow {
    Code,
    Implicit,
}

struct CallbackSession {
    flow: CallbackFlow,
    auth_url: Url,
    expected_state: String,
    result: Mutex<Option<oneshot::Sender<String>>>,
}

impl CallbackSession {
    fn complete(&self, state: &str, value: String) -> Result<()> {
        if state != self.expected_state {
            bail!("Mismatched auth states after redirect");
        }
        let sender = self
            .result
            .lock()
            .map_err(|_| anyhow!("OAuth callback lock is poisoned"))?
            .take()
            .context("OAuth callback already completed")?;
        // A dropped receiver must not expose the authorization code or token.
        sender
            .send(value)
            .map_err(|_| anyhow!("OAuth callback receiver was dropped"))
    }

    fn handle(&self, method: &Method, uri: &Uri) -> Result<Response<Full<Bytes>>> {
        debug!("Handling {method} {}", safe_request_path(uri));
        match (self.flow, method, uri.path()) {
            (_, &Method::GET, "/") => Ok(html_response(REDIRECT_WITH_AUTH_JSON)),
            (_, &Method::GET, "/auth_detail.json") => json_response(self.auth_url.as_str()),
            (CallbackFlow::Code, &Method::GET, "/redirect") => {
                let params = query_pairs(&uri.to_string())?;
                let (code, state) = code_grant_pkce::handle_code_response(&params)
                    .context("Failed to handle response from redirect")?;
                self.complete(&state, code)?;
                Ok(html_response(code_grant_pkce::SUCCESS_AFTER_REDIRECT))
            }
            (CallbackFlow::Implicit, &Method::GET, "/redirect") => {
                Ok(html_response(implicit::SAVE_AUTH_AFTER_REDIRECT))
            }
            (CallbackFlow::Implicit, &Method::POST, "/save_auth") => {
                let params = query_pairs(&uri.to_string())?;
                let (token, expires_at, state) = implicit::handle_response(&params)
                    .context("Failed to save auth after redirect")?;
                self.complete(&state, token)?;
                warn_if_short_lived(expires_at);
                json_response(&"")
            }
            _ => {
                warn!("Route not found");
                Ok(response(
                    StatusCode::NOT_FOUND,
                    "text/plain; charset=utf-8",
                    "",
                ))
            }
        }
    }
}

struct HyperBuilderWrap {
    listener: TcpListener,
}

impl HyperBuilderWrap {
    pub async fn try_bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;

        Ok(Self { listener })
    }

    async fn serve(
        &self,
        session: Arc<CallbackSession>,
        mut result: oneshot::Receiver<String>,
    ) -> Result<String> {
        use hyper::server::conn::http1;
        use hyper_util::rt::tokio::TokioIo;

        let shutdown = CancellationToken::new();
        let mut connections = tokio::task::JoinSet::new();
        let value = loop {
            tokio::select! {
                biased;
                value = &mut result => break value.context("OAuth callback result was dropped"),
                completed = connections.join_next(), if !connections.is_empty() => {
                    completed.context("missing OAuth connection task")??;
                }
                accepted = self.listener.accept() => {
                    let (tcp, _) = accepted.context("OAuth client auth web server failed")?;
                    let session = Arc::clone(&session);
                    let shutdown = shutdown.clone();
                    connections.spawn(async move {
                        let connection = http1::Builder::new().serve_connection(
                            TokioIo::new(tcp),
                            hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                                let session = Arc::clone(&session);
                                async move {
                                    let response = session
                                        .handle(req.method(), req.uri())
                                        .unwrap_or_else(|error| error_code_response(req.uri(), error));
                                    Ok::<_, Infallible>(response)
                                }
                            }),
                        );
                        tokio::pin!(connection);
                        let outcome = tokio::select! {
                            outcome = &mut connection => outcome,
                            () = shutdown.cancelled() => {
                                connection.as_mut().graceful_shutdown();
                                connection.await
                            }
                        };
                        if let Err(error) = outcome {
                            warn!("OAuth client connection failed: {error}");
                        }
                    });
                }
            }
        };
        // Flush the callback response before dropping the current-thread runtime.
        // A peer that never finishes reading must not block authentication indefinitely.
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(completed) = connections.join_next().await {
                if let Err(error) = completed {
                    warn!("OAuth client connection task failed: {error}");
                }
            }
        })
        .await;
        value
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

fn safe_request_path(uri: &hyper::Uri) -> &str {
    uri.path()
}

fn error_code_response<E>(uri: &hyper::Uri, e: E) -> Response<Full<Bytes>>
where
    E: std::fmt::Debug,
{
    let body = format!("{e:?}");
    let path = safe_request_path(uri);
    eprintln!("sccache: Error during a request to {path} on the client auth web server\n{body}");
    response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "text/plain; charset=utf-8",
        body,
    )
}

/// Try to bind a TCP stream to any of the available port out of [`VALID_PORTS`].
async fn try_bind() -> Result<HyperBuilderWrap> {
    // Try all the valid ports
    for &port in VALID_PORTS {
        let mut addrs = ("localhost", port)
            .to_socket_addrs()
            .with_context(|| format!("Failed to resolve localhost:{port}"))?;
        let addr = addrs
            .next()
            .with_context(|| format!("localhost:{port} resolved to no addresses"))?;

        // Hyper binds with reuseaddr and reuseport so binding won't fail as you'd expect on Linux
        match TcpStream::connect(addr) {
            // Already open
            Ok(_) => continue,
            // Doesn't seem to be open
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => (),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("Failed to check {addr} is available for binding"));
            }
        }

        match HyperBuilderWrap::try_bind(addr).await {
            Ok(s) => return Ok(s),
            Err(ref error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(e) => return Err(e).with_context(|| format!("Failed to bind to {addr}")),
        }
    }
    bail!("Could not bind to any valid port: ({VALID_PORTS:?})")
}

fn run_callback(
    flow: CallbackFlow,
    mut auth_url: Url,
    configure: impl FnOnce(&mut Url, &str, &str),
) -> Result<(String, String)> {
    let runtime = new_client_runtime()?;
    let server = runtime.block_on(try_bind())?;
    let port = server.local_addr()?.port();
    let redirect_uri = format!("http://localhost:{port}/redirect");
    let expected_state = Uuid::new_v4().as_simple().to_string();
    configure(&mut auth_url, &redirect_uri, &expected_state);

    let (sender, receiver) = oneshot::channel();
    let session = Arc::new(CallbackSession {
        flow,
        auth_url,
        expected_state,
        result: Mutex::new(Some(sender)),
    });
    info!("Listening on http://localhost:{port} with 1 thread.");
    println!("sccache: Please visit http://localhost:{port} in your browser");
    let value = runtime.block_on(server.serve(session, receiver))?;
    Ok((value, redirect_uri))
}

/// Complete an `OAuth2` authorization-code + PKCE flow using a temporary local callback server.
///
/// # Errors
///
/// Returns an error if the local callback server cannot be started, OAuth state cannot be
/// maintained, the authorization callback fails, or the token exchange fails.
///
/// <https://auth0.com/docs/api-auth/tutorials/authorization-code-grant-pkce>
pub fn get_token_oauth2_code_grant_pkce(
    client_id: &str,
    auth_url: Url,
    token_url: &str,
) -> Result<String> {
    let (verifier, challenge) = code_grant_pkce::generate_verifier_and_challenge();
    let (code, redirect_uri) =
        run_callback(CallbackFlow::Code, auth_url, |url, redirect, state| {
            code_grant_pkce::finish_url(client_id, url, redirect, state, &challenge);
        })?;
    info!("Server finished, using code to request token");
    code_grant_pkce::code_to_token(token_url, client_id, &verifier, &code, &redirect_uri)
        .context("Failed to convert oauth2 code into a token")
}

/// Complete an `OAuth2` implicit flow using a temporary local callback server.
///
/// # Errors
///
/// Returns an error if the local callback server cannot be started, OAuth state cannot be
/// maintained, or the authorization callback does not yield a valid token.
///
/// <https://auth0.com/docs/api-auth/tutorials/implicit-grant>
pub fn get_token_oauth2_implicit(client_id: &str, auth_url: Url) -> Result<String> {
    let (token, _) = run_callback(CallbackFlow::Implicit, auth_url, |url, redirect, state| {
        implicit::finish_url(client_id, url, redirect, state);
    })?;
    info!("Server finished, returning token");
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn session(
        flow: CallbackFlow,
        expected_state: &str,
    ) -> Result<(Arc<CallbackSession>, oneshot::Receiver<String>)> {
        let (sender, receiver) = oneshot::channel();
        Ok((
            Arc::new(CallbackSession {
                flow,
                auth_url: Url::parse("https://example.invalid/authorize")?,
                expected_state: expected_state.to_owned(),
                result: Mutex::new(Some(sender)),
            }),
            receiver,
        ))
    }

    #[test]
    fn callbacks_are_isolated_and_single_use() -> Result<()> {
        let (first, mut first_result) = session(CallbackFlow::Code, "first")?;
        let (second, mut second_result) = session(CallbackFlow::Code, "second")?;
        let wrong = "/redirect?code=wrong&state=second".parse()?;
        assert!(first.handle(&Method::GET, &wrong).is_err());
        assert_eq!(first_result.try_recv()?, None);

        let valid = "/redirect?code=one&state=first".parse()?;
        assert_eq!(first.handle(&Method::GET, &valid)?.status(), StatusCode::OK);
        assert_eq!(first_result.try_recv()?.as_deref(), Some("one"));
        assert!(first.handle(&Method::GET, &valid).is_err());
        assert_eq!(second_result.try_recv()?, None);

        let valid = "/redirect?code=two&state=second".parse()?;
        assert_eq!(
            second.handle(&Method::GET, &valid)?.status(),
            StatusCode::OK
        );
        assert_eq!(second_result.try_recv()?.as_deref(), Some("two"));
        Ok(())
    }

    #[test]
    fn implicit_callback_validates_token_and_state() -> Result<()> {
        let (session, mut result) = session(CallbackFlow::Implicit, "expected")?;
        let redirect = "/redirect".parse()?;
        assert_eq!(
            session.handle(&Method::GET, &redirect)?.status(),
            StatusCode::OK
        );
        assert_eq!(result.try_recv()?, None);

        for callback in [
            "/save_auth?access_token=token&token_type=other&expires_in=999999&state=expected",
            "/save_auth?access_token=token&token_type=bearer&expires_in=invalid&state=expected",
            "/save_auth?access_token=token&token_type=bearer&expires_in=999999&state=wrong",
        ] {
            assert!(session.handle(&Method::POST, &callback.parse()?).is_err());
            assert_eq!(result.try_recv()?, None);
        }
        let valid =
            "/save_auth?access_token=token&token_type=Bearer&expires_in=999999&state=expected"
                .parse()?;
        assert_eq!(
            session.handle(&Method::GET, &valid)?.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            session.handle(&Method::POST, &valid)?.status(),
            StatusCode::OK
        );
        assert_eq!(result.try_recv()?.as_deref(), Some("token"));
        assert!(session.handle(&Method::POST, &valid).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn callback_server_delivers_response_before_shutdown() -> Result<()> {
        let server = HyperBuilderWrap::try_bind("127.0.0.1:0".parse()?).await?;
        let address = server.local_addr()?;
        let (session, result) = session(CallbackFlow::Code, "expected")?;

        let request = async {
            let mut stream = tokio::net::TcpStream::connect(address).await?;
            stream
                .write_all(
                    b"GET /redirect?code=abc&state=expected HTTP/1.1\r\nHost: localhost\r\n\r\n",
                )
                .await?;
            let mut received = String::new();
            stream.read_to_string(&mut received).await?;
            assert!(received.starts_with("HTTP/1.1 200 OK"), "{received}");
            assert!(received.contains("In-browser step of authentication complete"));
            Ok::<_, anyhow::Error>(())
        };
        let (code, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(server.serve(session, result), request)
        })
        .await??;
        assert_eq!(code, "abc");
        Ok(())
    }

    #[tokio::test]
    async fn auth_details_belong_to_the_session() -> Result<()> {
        let (session, _) = session(CallbackFlow::Code, "expected")?;
        let response = session.handle(&Method::GET, &"/auth_detail.json".parse()?)?;
        let body = response.into_body().collect().await?.to_bytes();
        assert_eq!(
            serde_json::from_slice::<String>(&body)?,
            "https://example.invalid/authorize"
        );
        Ok(())
    }

    #[test]
    fn closed_receiver_does_not_disclose_code() -> Result<()> {
        let (session, result) = session(CallbackFlow::Code, "expected")?;
        drop(result);
        let error = session
            .complete("expected", "private-code".to_owned())
            .unwrap_err();
        assert!(!format!("{error:?}").contains("private-code"));
        Ok(())
    }

    #[test]
    fn oauth_log_path_excludes_query_secrets() -> anyhow::Result<()> {
        let uri: hyper::Uri = "/save_auth?access_token=super-secret&state=also-secret".parse()?;
        assert_eq!(safe_request_path(&uri), "/save_auth");
        Ok(())
    }
}
