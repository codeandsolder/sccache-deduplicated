//! Native HTTPS: TLS authenticates connections, while only the enrollment
//! route admits a connection without a client certificate.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use openssl::{asn1::Asn1Time, x509::X509};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsAcceptor;

use super::{
    EnrollmentAuthority, EnrollmentRequest, EnrollmentResponse, PeerId, Role, TlsCredentials,
    authenticated_peer,
};

mod client;
pub use client::{ClusterHttpClient, EnrollmentClient};

const CONTROL_LIMIT: usize = 64 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(15);
const ENROLL_WORKER: &str = "/api/v1/cluster/enroll/worker";
const ENROLL_CLIENT: &str = "/api/v1/cluster/enroll/client";
const RENEW: &str = "/api/v1/cluster/renew";

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(CONTROL_LIMIT as u64)
        .reject_trailing_bytes()
}

/// Peer metadata derived exclusively from the verified TLS connection.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedPeer {
    id: PeerId,
    role: Role,
    expires: SystemTime,
    remote_addr: SocketAddr,
}

impl AuthenticatedPeer {
    /// Cryptographic peer identity.
    #[must_use = "the peer identifier is required for authorization"]
    pub const fn id(self) -> PeerId {
        self.id
    }

    /// Issuer-authorized peer role.
    #[must_use = "the peer role is required for authorization"]
    pub const fn role(self) -> Role {
        self.role
    }

    /// Socket endpoint for this connection, not part of the peer identity.
    #[must_use = "the address identifies the connection path"]
    pub const fn remote_addr(self) -> SocketAddr {
        self.remote_addr
    }

    fn from_verified_leaf(der: &[u8], remote_addr: SocketAddr) -> Result<Self> {
        let leaf = X509::from_der(der)?;
        let (id, role) = [Role::Scheduler, Role::Worker, Role::Client]
            .into_iter()
            .find_map(|role| authenticated_peer(&leaf, role).ok().map(|id| (id, role)))
            .context("invalid cluster peer identity")?;
        let remaining = Asn1Time::from_unix(0)?.diff(leaf.not_after())?;
        let seconds = i64::from(remaining.days) * 86400 + i64::from(remaining.secs);
        let remaining =
            Duration::from_secs(u64::try_from(seconds).context("expired cluster peer")?);
        let expires = SystemTime::UNIX_EPOCH
            .checked_add(remaining)
            .context("invalid cluster peer expiry")?;
        Ok(Self {
            id,
            role,
            expires,
            remote_addr,
        })
    }

    fn valid(self) -> bool {
        SystemTime::now() < self.expires
    }
}

/// Streaming HTTP response body. Enrollment uses small fixed bodies, while
/// normal request handlers may supply streaming CAS responses.
pub type ClusterBody = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

fn response(status: StatusCode, body: impl Into<Bytes>) -> Response<ClusterBody> {
    let mut response = Response::new(
        Full::new(body.into())
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response
}

fn server_config(credentials: &TlsCredentials) -> Result<ServerConfig> {
    ensure!(
        credentials.role != Role::Client,
        "client-only credential cannot serve TLS"
    );
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(credentials.ca.to_der()?))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider));
    let verifier = if credentials.role == Role::Scheduler {
        verifier.allow_unauthenticated()
    } else {
        verifier
    }
    .build()?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(credentials.certificate.to_der()?)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                credentials.identity.private_key().private_key_to_pkcs8()?,
            )),
        )?;
    // Recheck the full current client certificate on every new connection.
    config.send_tls13_tickets = 0;
    Ok(config)
}

/// Shared TLS listener configuration. Replacing credentials only affects
/// future handshakes; in-flight streams retain their authenticated identity.
pub struct ClusterListener {
    config: RwLock<Arc<ServerConfig>>,
    id: PeerId,
    role: Role,
    ca_fingerprint: [u8; 32],
}

impl ClusterListener {
    /// Construct a scheduler or worker listener using its own role-bound leaf.
    ///
    /// # Errors
    /// Returns an error if credentials cannot configure TLS.
    pub fn new(credentials: &TlsCredentials) -> Result<Self> {
        Ok(Self {
            config: RwLock::new(Arc::new(server_config(credentials)?)),
            id: credentials.id()?,
            role: credentials.role,
            ca_fingerprint: openssl::sha::sha256(&credentials.ca.to_der()?),
        })
    }

    /// Reload a same-identity leaf for subsequent TLS handshakes.
    ///
    /// # Errors
    /// Returns an error if credentials cannot configure TLS or the lock is poisoned.
    pub fn reload(&self, credentials: &TlsCredentials) -> Result<()> {
        ensure!(
            self.id == credentials.id()?
                && self.role == credentials.role
                && self.ca_fingerprint == openssl::sha::sha256(&credentials.ca.to_der()?),
            "listener renewal cannot change the local identity, role or CA"
        );
        let config = Arc::new(server_config(credentials)?);
        *self
            .config
            .write()
            .map_err(|_| anyhow::anyhow!("cluster TLS configuration poisoned"))? = config;
        Ok(())
    }

    /// Serve a scheduler connection with initial enrollment and mTLS dispatch.
    ///
    /// # Errors
    /// Returns an error for wrong listener role, failed TLS or HTTP failure.
    pub async fn serve_scheduler<H, F>(
        &self,
        socket: TcpStream,
        enrollment: Arc<SchedulerEnrollment>,
        handler: H,
    ) -> Result<()>
    where
        H: Fn(AuthenticatedPeer, Request<Incoming>) -> F + Send + Sync + 'static,
        F: Future<Output = Response<ClusterBody>> + Send,
    {
        ensure!(self.role == Role::Scheduler, "not a scheduler listener");
        let handler = Arc::new(handler);
        self.serve_connection(socket, move |peer, address, request| {
            let enrollment = Arc::clone(&enrollment);
            let handler = Arc::clone(&handler);
            async move {
                enrollment
                    .dispatch(peer, address, request, handler.as_ref())
                    .await
            }
        })
        .await
    }

    /// Serve a worker connection. All requests require mTLS and an authorized
    /// principal; no worker-side bootstrap path exists.
    ///
    /// # Errors
    /// Returns an error for wrong listener role, failed TLS or HTTP failure.
    pub async fn serve_worker<A, H, F>(
        &self,
        socket: TcpStream,
        authorize: A,
        handler: H,
    ) -> Result<()>
    where
        A: Fn(AuthenticatedPeer) -> bool + Send + Sync + 'static,
        H: Fn(AuthenticatedPeer, Request<Incoming>) -> F + Send + Sync + 'static,
        F: Future<Output = Response<ClusterBody>> + Send,
    {
        ensure!(self.role == Role::Worker, "not a worker listener");
        let handler = Arc::new(handler);
        let authorize = Arc::new(authorize);
        self.serve_connection(socket, move |peer, _, request| {
            let handler = Arc::clone(&handler);
            let authorize = Arc::clone(&authorize);
            async move {
                match peer.filter(|peer| peer.valid() && authorize(*peer)) {
                    Some(peer) => handler(peer, request).await,
                    None => response(StatusCode::UNAUTHORIZED, "cluster authentication required"),
                }
            }
        })
        .await
    }

    // The caller owns connection admission and listener lifecycle. Peer metadata
    // is exclusively derived from rustls, never from HTTP request headers.
    async fn serve_connection<H, F>(&self, socket: TcpStream, handler: H) -> Result<()>
    where
        H: Fn(Option<AuthenticatedPeer>, SocketAddr, Request<Incoming>) -> F + Send + Sync,
        F: Future<Output = Response<ClusterBody>> + Send,
    {
        let address = socket.peer_addr()?;
        let config = self
            .config
            .read()
            .map_err(|_| anyhow::anyhow!("cluster TLS configuration poisoned"))?
            .clone();
        let stream = timeout(CONTROL_TIMEOUT, TlsAcceptor::from(config).accept(socket)).await??;
        let peer = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|leaf| AuthenticatedPeer::from_verified_leaf(leaf.as_ref(), address))
            .transpose()?;
        let service = service_fn(move |request| {
            let future = handler(peer, address, request);
            async move { Ok::<_, Infallible>(future.await) }
        });
        http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(CONTROL_TIMEOUT)
            .serve_connection(TokioIo::new(stream), service)
            .await?;
        Ok(())
    }
}

type Authorize = dyn Fn(Role, SocketAddr, &str) -> bool + Send + Sync;

/// Scheduler-local enrollment routing and authorization. Unknown or revoked
/// principals never reach application handlers.
pub struct SchedulerEnrollment {
    authority: EnrollmentAuthority,
    authorize: Arc<Authorize>,
}

impl SchedulerEnrollment {
    /// Install the existing scheduler's role-bound initial authorization policy.
    pub fn new(
        authority: EnrollmentAuthority,
        authorize: impl Fn(Role, SocketAddr, &str) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            authority,
            authorize: Arc::new(authorize),
        }
    }

    /// Access the scheduler-owned issuer and durable registry.
    #[must_use = "the authority is required for local management"]
    pub const fn authority(&self) -> &EnrollmentAuthority {
        &self.authority
    }

    async fn dispatch<H, F>(
        self: &Arc<Self>,
        peer: Option<AuthenticatedPeer>,
        address: SocketAddr,
        request: Request<Incoming>,
        handler: &H,
    ) -> Response<ClusterBody>
    where
        H: Fn(AuthenticatedPeer, Request<Incoming>) -> F,
        F: Future<Output = Response<ClusterBody>>,
    {
        let role = match request.uri().path() {
            ENROLL_WORKER => Some(Role::Worker),
            ENROLL_CLIENT => Some(Role::Client),
            _ => None,
        };
        if let Some(role) = role {
            if peer.is_some() {
                return response(StatusCode::FORBIDDEN, "use authenticated renewal");
            }
            return self.enroll(address, role, request).await;
        }
        let Some(peer) = peer.filter(|peer| {
            peer.valid()
                && self
                    .authority
                    .registry()
                    .is_active(peer.id, peer.role)
                    .unwrap_or(false)
        }) else {
            return response(StatusCode::UNAUTHORIZED, "cluster authentication required");
        };
        if request.uri().path() == RENEW {
            return self.renew(peer, request).await;
        }
        handler(peer, request).await
    }

    async fn enroll(
        self: &Arc<Self>,
        address: SocketAddr,
        role: Role,
        request: Request<Incoming>,
    ) -> Response<ClusterBody> {
        let Some(token) = request
            .headers()
            .get(hyper::header::AUTHORIZATION)
            .and_then(|header| header.to_str().ok())
            .and_then(|header| header.strip_prefix("Bearer "))
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
        else {
            return response(
                StatusCode::UNAUTHORIZED,
                "enrollment authorization required",
            );
        };
        let csr = match decode(request).await {
            Ok(csr) => csr,
            Err(error) => return error,
        };
        let enrollment = Arc::clone(self);
        issue_result(
            tokio::task::spawn_blocking(move || {
                enrollment.authority.enroll(&csr, || {
                    (enrollment.authorize)(role, address, &token).then_some(role)
                })
            })
            .await,
        )
    }

    async fn renew(
        self: &Arc<Self>,
        peer: AuthenticatedPeer,
        request: Request<Incoming>,
    ) -> Response<ClusterBody> {
        let csr = match decode(request).await {
            Ok(csr) => csr,
            Err(error) => return error,
        };
        let enrollment = Arc::clone(self);
        issue_result(
            tokio::task::spawn_blocking(move || {
                enrollment.authority.renew(&csr, peer.id, peer.role)
            })
            .await,
        )
    }
}

async fn decode(
    request: Request<Incoming>,
) -> std::result::Result<EnrollmentRequest, Response<ClusterBody>> {
    if request.method() != Method::POST
        || request.uri().query().is_some()
        || request
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some("application/octet-stream")
    {
        return Err(response(
            StatusCode::BAD_REQUEST,
            "invalid enrollment request",
        ));
    }
    let bytes = timeout(
        CONTROL_TIMEOUT,
        Limited::new(request.into_body(), CONTROL_LIMIT).collect(),
    )
    .await
    .map_err(|_| response(StatusCode::REQUEST_TIMEOUT, "enrollment body timed out"))?
    .map_err(|_| response(StatusCode::BAD_REQUEST, "invalid enrollment body"))?
    .to_bytes();
    codec()
        .deserialize(&bytes)
        .map_err(|_| response(StatusCode::BAD_REQUEST, "invalid enrollment body"))
}

fn issue_result(
    result: std::result::Result<Result<EnrollmentResponse>, tokio::task::JoinError>,
) -> Response<ClusterBody> {
    match result {
        Ok(Ok(issued)) => match codec().serialize(&issued) {
            Ok(bytes) => {
                let mut reply = response(StatusCode::OK, bytes);
                reply.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/octet-stream"),
                );
                reply
            }
            Err(_) => response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "certificate encoding failed",
            ),
        },
        Ok(Err(_)) => response(StatusCode::FORBIDDEN, "certificate request denied"),
        Err(_) => response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "certificate issuance failed",
        ),
    }
}
