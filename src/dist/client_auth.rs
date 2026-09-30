use bytes::Bytes;
use futures::channel::oneshot;
use http::HeaderValue;
use http::StatusCode;
use http::header::CONTENT_TYPE;
use http_body_util::Full;
use hyper::Response;
use serde::Serialize;
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::Duration;
use url::Url;
use uuid::Uuid;

use crate::errors::*;
use crate::util::new_client_runtime;

// These (arbitrary) ports need to be registered as valid redirect urls in the oauth provider you're using
pub const VALID_PORTS: &[u16] = &[12731, 32492, 56909];
// If token is valid for under this amount of time, print a warning
const MIN_TOKEN_VALIDITY: Duration = Duration::from_secs(2 * 24 * 60 * 60);
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

fn json_response<T: Serialize>(data: &T) -> Result<Response<Full<Bytes>>> {
    let body = serde_json::to_vec(data).context("Failed to serialize to JSON")?;
    Ok(response(StatusCode::OK, "application/json", body))
}

const REDIRECT_WITH_AUTH_JSON: &str = r##"<!doctype html>
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
"##;

mod code_grant_pkce {
    use super::{
        MIN_TOKEN_VALIDITY, MIN_TOKEN_VALIDITY_WARNING, REDIRECT_WITH_AUTH_JSON, html_response,
        json_response, query_pairs,
    };
    use crate::util::BASE64_URL_SAFE_ENGINE;
    use crate::util::new_reqwest_blocking_client;
    use base64::Engine;
    use bytes::Bytes;
    use futures::channel::oneshot;
    use http_body_util::Full;
    use hyper::{Method, Request, Response, StatusCode};
    use rand::{RngCore, rngs::OsRng};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use url::Url;

    use crate::errors::*;

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

    pub struct State {
        pub auth_url: String,
        pub auth_state_value: String,
        pub code_tx: mpsc::SyncSender<String>,
        pub shutdown_tx: Option<oneshot::Sender<()>>,
    }

    pub static STATE: Mutex<Option<State>> = Mutex::new(None);

    pub fn generate_verifier_and_challenge() -> Result<(String, String)> {
        let mut code_verifier_bytes = vec![0; NUM_CODE_VERIFIER_BYTES];
        OsRng.fill_bytes(&mut code_verifier_bytes);
        let code_verifier = BASE64_URL_SAFE_ENGINE.encode(&code_verifier_bytes);
        let mut hasher = Sha256::new();
        hasher.update(&code_verifier);
        let code_challenge = BASE64_URL_SAFE_ENGINE.encode(hasher.finalize());
        Ok((code_verifier, code_challenge))
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

    fn handle_code_response(params: HashMap<String, String>) -> Result<(String, String)> {
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
            bail!(
                "Token type in response is not {}",
                TOKEN_TYPE_RESULT_PARAM_VALUE
            )
        }
        // Calculate ASAP the actual time at which the token will expire.
        let expires_at = Instant::now()
            .checked_add(Duration::from_secs(res.expires_in))
            .context("Token expiry is too far in the future")?;
        Ok((token, expires_at))
    }

    const SUCCESS_AFTER_REDIRECT: &str = r##"<!doctype html>
    <html lang="en">
    <head><meta charset="utf-8"></head>
    <body>In-browser step of authentication complete, you can now close this page!</body>
    </html>
    "##;

    pub fn serve(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>> {
        let mut state = STATE
            .lock()
            .map_err(|_| anyhow!("OAuth PKCE state lock is poisoned"))?;
        let state = state
            .as_mut()
            .context("OAuth PKCE state is not initialized")?;
        debug!("Handling {} {}", req.method(), req.uri());
        let response = match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => html_response(REDIRECT_WITH_AUTH_JSON),
            (&Method::GET, "/auth_detail.json") => json_response(&state.auth_url)?,
            (&Method::GET, "/redirect") => {
                let query_pairs = query_pairs(&req.uri().to_string())?;
                let (code, auth_state) = handle_code_response(query_pairs)
                    .context("Failed to handle response from redirect")?;
                if auth_state != state.auth_state_value {
                    return Err(anyhow!("Mismatched auth states after redirect"));
                }
                // Deliberately in reverse order for a 'happens-before' relationship
                state
                    .code_tx
                    .try_send(code)
                    .map_err(|error| anyhow!("Failed to deliver OAuth code: {error}"))?;
                let shutdown_tx = state
                    .shutdown_tx
                    .take()
                    .context("OAuth PKCE shutdown was already requested")?;
                shutdown_tx
                    .send(())
                    .map_err(|_| anyhow!("OAuth server shutdown receiver was dropped"))?;
                html_response(SUCCESS_AFTER_REDIRECT)
            }
            _ => {
                warn!("Route not found");
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body("".into())?
            }
        };

        Ok(response)
    }

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
        let client = new_reqwest_blocking_client();
        let res = client.post(token_url).json(&token_request).send()?;
        if !res.status().is_success() {
            bail!(
                "Sending code to {} failed, HTTP error: {}",
                token_url,
                res.status()
            )
        }

        let (token, expires_at) = handle_token_response(
            res.json()
                .context("Failed to parse token response as JSON")?,
        )?;
        if expires_at.saturating_duration_since(Instant::now()) < MIN_TOKEN_VALIDITY {
            warn!(
                "Token retrieved expires in under {}",
                MIN_TOKEN_VALIDITY_WARNING
            );
            eprintln!(
                "sccache: Token retrieved expires in under {}",
                MIN_TOKEN_VALIDITY_WARNING
            );
        }
        Ok(token)
    }
}

mod implicit {
    use super::{
        MIN_TOKEN_VALIDITY, MIN_TOKEN_VALIDITY_WARNING, REDIRECT_WITH_AUTH_JSON, html_response,
        json_response, query_pairs,
    };
    use bytes::Bytes;
    use futures::channel::oneshot;
    use http_body_util::Full;
    use hyper::{Method, Request, Response, StatusCode};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use url::Url;

    use crate::errors::*;

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

    pub struct State {
        pub auth_url: String,
        pub auth_state_value: String,
        pub token_tx: mpsc::SyncSender<String>,
        pub shutdown_tx: Option<oneshot::Sender<()>>,
    }

    pub static STATE: Mutex<Option<State>> = Mutex::new(None);

    pub fn finish_url(client_id: &str, url: &mut Url, redirect_uri: &str, state: &str) {
        url.query_pairs_mut()
            .append_pair(CLIENT_ID_PARAM, client_id)
            .append_pair(REDIRECT_PARAM, redirect_uri)
            .append_pair(RESPONSE_TYPE_PARAM, RESPONSE_TYPE_PARAM_VALUE)
            .append_pair(STATE_PARAM, state);
    }

    fn handle_response(params: HashMap<String, String>) -> Result<(String, Instant, String)> {
        let token = params
            .get(TOKEN_RESULT_PARAM)
            .context("No token found in response")?;
        let bearer = params
            .get(TOKEN_TYPE_RESULT_PARAM)
            .context("No token type found in response")?;
        if bearer.to_lowercase() != TOKEN_TYPE_RESULT_PARAM_VALUE {
            bail!(
                "Token type in response is not {}",
                TOKEN_TYPE_RESULT_PARAM_VALUE
            )
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

    const SAVE_AUTH_AFTER_REDIRECT: &str = r##"<!doctype html>
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
    "##;

    pub fn serve(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>> {
        let mut state = STATE
            .lock()
            .map_err(|_| anyhow!("OAuth implicit state lock is poisoned"))?;
        let state = state
            .as_mut()
            .context("OAuth implicit state is not initialized")?;
        debug!("Handling {} {}", req.method(), req.uri());
        let response = match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => html_response(REDIRECT_WITH_AUTH_JSON),
            (&Method::GET, "/auth_detail.json") => json_response(&state.auth_url)?,
            (&Method::GET, "/redirect") => html_response(SAVE_AUTH_AFTER_REDIRECT),
            (&Method::POST, "/save_auth") => {
                let query_pairs = query_pairs(&req.uri().to_string())?;
                let (token, expires_at, auth_state) =
                    handle_response(query_pairs).context("Failed to save auth after redirect")?;
                if auth_state != state.auth_state_value {
                    return Err(anyhow!("Mismatched auth states after redirect"));
                }
                if expires_at.saturating_duration_since(Instant::now()) < MIN_TOKEN_VALIDITY {
                    warn!(
                        "Token retrieved expires in under {}",
                        MIN_TOKEN_VALIDITY_WARNING
                    );
                    eprintln!(
                        "sccache: Token retrieved expires in under {}",
                        MIN_TOKEN_VALIDITY_WARNING
                    );
                }
                // Deliberately in reverse order for a 'happens-before' relationship
                state
                    .token_tx
                    .try_send(token)
                    .map_err(|error| anyhow!("Failed to deliver OAuth token: {error}"))?;
                let shutdown_tx = state
                    .shutdown_tx
                    .take()
                    .context("OAuth implicit shutdown was already requested")?;
                shutdown_tx
                    .send(())
                    .map_err(|_| anyhow!("OAuth server shutdown receiver was dropped"))?;
                json_response(&"")?
            }
            _ => {
                warn!("Route not found");
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body("".into())?
            }
        };

        Ok(response)
    }
}

use tokio::net::TcpListener;

struct HyperBuilderWrap {
    listener: TcpListener,
}

impl HyperBuilderWrap {
    pub async fn try_bind(addr: SocketAddr) -> io::Result<HyperBuilderWrap> {
        let listener = TcpListener::bind(addr).await?;

        Ok(HyperBuilderWrap { listener })
    }

    // Typing out a hyper service is a major pain, so let's focus on our simple
    // `fn(Request<Body>) -> Response<Body>` handler functions; to reduce repetition
    // we create a relevant service using hyper's own helper factory functions.
    async fn serve<F>(&mut self, sfn: F) -> io::Result<()>
    where
        F: Fn(hyper::Request<hyper::body::Incoming>) -> anyhow::Result<Response<Full<Bytes>>>
            + Send
            + 'static
            + Copy
            + Sync,
    {
        use hyper::server::conn::http1;
        use hyper_util::rt::tokio::TokioIo;

        loop {
            let (tcp, _) = self.listener.accept().await?;
            let io = TokioIo::new(tcp);
            tokio::task::spawn(async move {
                let conn = http1::Builder::new().serve_connection(
                    io,
                    hyper::service::service_fn(|req| async move {
                        let uri = req.uri().clone();
                        sfn(req).or_else(|e| error_code_response(uri, e))
                    }),
                );
                tokio::pin!(conn);
                if let Err(error) = conn.await {
                    warn!("OAuth client connection failed: {error}");
                }
            });
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

fn error_code_response<E>(uri: hyper::Uri, e: E) -> hyper::Result<Response<Full<Bytes>>>
where
    E: std::fmt::Debug,
{
    let body = format!("{:?}", e);
    eprintln!(
        "sccache: Error during a request to {} on the client auth web server\n{}",
        uri, body
    );
    Ok::<Response<Full<Bytes>>, hyper::Error>(response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "text/plain; charset=utf-8",
        body,
    ))
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
                    .with_context(|| format!("Failed to check {} is available for binding", addr));
            }
        }

        match HyperBuilderWrap::try_bind(addr).await {
            Ok(s) => return Ok(s),
            Err(ref error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(e) => return Err(e).with_context(|| format!("Failed to bind to {}", addr)),
        }
    }
    bail!("Could not bind to any valid port: ({:?})", VALID_PORTS)
}

async fn serve_until_shutdown<F>(
    server: &mut HyperBuilderWrap,
    sfn: F,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<()>
where
    F: Fn(hyper::Request<hyper::body::Incoming>) -> anyhow::Result<Response<Full<Bytes>>>
        + Send
        + 'static
        + Copy
        + Sync,
{
    tokio::select! {
        result = server.serve(sfn) => {
            result.context("OAuth client auth web server failed")?;
        }
        result = shutdown_rx => {
            result.context("OAuth client auth shutdown signal was dropped")?;
        }
    }
    Ok(())
}

// https://auth0.com/docs/api-auth/tutorials/authorization-code-grant-pkce
pub fn get_token_oauth2_code_grant_pkce(
    client_id: &str,
    mut auth_url: Url,
    token_url: &str,
) -> Result<String> {
    let runtime = new_client_runtime()?;
    let mut server = runtime.block_on(async move { try_bind().await })?;
    let port = server.local_addr()?.port();

    let _guard = runtime.enter();
    let redirect_uri = format!("http://localhost:{port}/redirect");
    let auth_state_value = Uuid::new_v4().as_simple().to_string();
    let (verifier, challenge) = code_grant_pkce::generate_verifier_and_challenge()?;
    code_grant_pkce::finish_url(
        client_id,
        &mut auth_url,
        &redirect_uri,
        &auth_state_value,
        &challenge,
    );

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (code_tx, code_rx) = mpsc::sync_channel(1);
    let state = code_grant_pkce::State {
        auth_url: auth_url.to_string(),
        auth_state_value,
        code_tx,
        shutdown_tx: Some(shutdown_tx),
    };
    {
        let mut state_slot = code_grant_pkce::STATE
            .lock()
            .map_err(|_| anyhow!("OAuth PKCE state lock is poisoned"))?;
        if state_slot.is_some() {
            bail!("OAuth PKCE authentication is already in progress");
        }
        *state_slot = Some(state);
    }

    info!("Listening on http://localhost:{port} with 1 thread.");
    println!("sccache: Please visit http://localhost:{port} in your browser");

    let serve_result = runtime.block_on(serve_until_shutdown(
        &mut server,
        code_grant_pkce::serve,
        shutdown_rx,
    ));
    let code_result = code_rx
        .try_recv()
        .context("OAuth server stopped without returning an authorization code");
    let clear_result = code_grant_pkce::STATE
        .lock()
        .map_err(|_| anyhow!("OAuth PKCE state lock is poisoned"))
        .map(|mut state_slot| *state_slot = None);

    serve_result?;
    clear_result?;
    let code = code_result?;

    info!("Server finished, using code to request token");
    code_grant_pkce::code_to_token(token_url, client_id, &verifier, &code, &redirect_uri)
        .context("Failed to convert oauth2 code into a token")
}

// https://auth0.com/docs/api-auth/tutorials/implicit-grant
pub fn get_token_oauth2_implicit(client_id: &str, mut auth_url: Url) -> Result<String> {
    let runtime = new_client_runtime()?;
    let mut server = runtime.block_on(async move { try_bind().await })?;
    let port = server.local_addr()?.port();
    let _guard = runtime.enter();

    let redirect_uri = format!("http://localhost:{port}/redirect");
    let auth_state_value = Uuid::new_v4().as_simple().to_string();
    implicit::finish_url(client_id, &mut auth_url, &redirect_uri, &auth_state_value);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (token_tx, token_rx) = mpsc::sync_channel(1);
    let state = implicit::State {
        auth_url: auth_url.to_string(),
        auth_state_value,
        token_tx,
        shutdown_tx: Some(shutdown_tx),
    };
    {
        let mut state_slot = implicit::STATE
            .lock()
            .map_err(|_| anyhow!("OAuth implicit state lock is poisoned"))?;
        if state_slot.is_some() {
            bail!("OAuth implicit authentication is already in progress");
        }
        *state_slot = Some(state);
    }

    info!("Listening on http://localhost:{port} with 1 thread.");
    println!("sccache: Please visit http://localhost:{port} in your browser");

    let serve_result = runtime.block_on(serve_until_shutdown(
        &mut server,
        implicit::serve,
        shutdown_rx,
    ));
    let token_result = token_rx
        .try_recv()
        .context("OAuth server stopped without returning a token");
    let clear_result = implicit::STATE
        .lock()
        .map_err(|_| anyhow!("OAuth implicit state lock is poisoned"))
        .map(|mut state_slot| *state_slot = None);

    serve_result?;
    clear_result?;

    info!("Server finished, returning token");
    token_result
}
