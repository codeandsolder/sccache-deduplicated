//! Native HTTPS: TLS authenticates connections, while only the enrollment
//! route admits a connection without a client certificate.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::Body,
    extract::{Extension, Request},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{MethodRouter, any, get},
};
use bincode::Options;
use btls::{
    asn1::Asn1Time,
    ssl::{
        Ssl, SslContext, SslContextBuilder, SslMethod, SslOptions, SslSessionCacheMode,
        SslVerifyMode, SslVersion,
    },
    x509::{X509, store::X509StoreBuilder},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{net::TcpStream, time::timeout};
use tokio_btls::SslStream;
use tower::ServiceExt as _;

use super::{
    EnrollmentAuthority, EnrollmentRequest, EnrollmentResponse, NetworkPath, PeerId, Role,
    TlsCredentials, authenticated_peer,
};

mod client;
mod idle_write;
pub use client::{ClusterHttpClient, EnrollmentClient};

pub const PATH_HEADER: &str = "x-sccache-network-path";

const CONTROL_LIMIT: usize = 64 * 1024;
const HTTP_HEADER_LIMIT: usize = 64 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(15);
const ENROLL_WORKER: &str = "/api/v1/cluster/enroll/worker";
const ENROLL_CLIENT: &str = "/api/v1/cluster/enroll/client";
const RENEW: &str = "/api/v1/cluster/renew";
const PROBE: &str = "/api/v1/cluster/probe";

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
    path: NetworkPath,
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

    /// Actual local and remote IP addresses of this authenticated connection.
    #[must_use = "the path identifies the observed transport endpoints"]
    pub const fn path(self) -> NetworkPath {
        self.path
    }

    fn from_verified_leaf(der: &[u8], remote_addr: SocketAddr, path: NetworkPath) -> Result<Self> {
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
            path,
        })
    }

    fn valid(self) -> bool {
        SystemTime::now() < self.expires
    }
}

fn response(status: StatusCode, body: impl Into<Bytes>) -> Response {
    (status, Body::from(body.into())).into_response()
}

#[derive(Clone, Copy)]
struct ConnectionInfo {
    peer: Option<AuthenticatedPeer>,
    address: SocketAddr,
}

/// A routing tree bound to one TLS listener identity and enrollment policy.
///
/// Only the listener can construct it, so an application cannot bypass
/// transport-derived peer authorization by serving a bare Axum router.
#[derive(Clone)]
pub struct ClusterRouter {
    router: Router,
    id: PeerId,
    role: Role,
    ca_fingerprint: [u8; 32],
    allow_enrollment: bool,
}

fn authenticated(
    router: Router,
    authorize: impl Fn(AuthenticatedPeer) -> bool + Clone + Send + Sync + 'static,
) -> Router {
    router.layer(middleware::from_fn(
        move |Extension(connection): Extension<ConnectionInfo>,
              mut request: Request,
              next: Next| {
            let peer = connection
                .peer
                .filter(|peer| peer.valid() && authorize(*peer));
            async move {
                match peer {
                    Some(peer) => {
                        request.extensions_mut().insert(peer);
                        next.run(request).await
                    }
                    None => response(StatusCode::UNAUTHORIZED, "cluster authentication required"),
                }
            }
        },
    ))
}

fn probe() -> MethodRouter {
    get(|| std::future::ready(StatusCode::NO_CONTENT))
        .head(|| std::future::ready(StatusCode::NOT_FOUND))
        .fallback(|| std::future::ready(StatusCode::NOT_FOUND))
}

fn server_config(credentials: &TlsCredentials, allow_enrollment: bool) -> Result<SslContext> {
    ensure!(
        credentials.role != Role::Client,
        "client-only credential cannot serve TLS"
    );
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(&credentials.ca)?;
    let mut config = SslContextBuilder::new(SslMethod::tls())?;
    config.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    config.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    config.set_cert_store(store.build())?;
    config.set_certificate(&credentials.certificate)?;
    config.set_private_key(credentials.identity.private_key())?;
    config.check_private_key()?;
    config.add_client_ca(&credentials.ca)?;
    let mut mode = SslVerifyMode::PEER;
    if !allow_enrollment {
        mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
    }
    config.set_verify(mode)?;
    // Every new connection must present its currently valid identity.
    let _ = config.set_options(SslOptions::NO_TICKET);
    let _ = config.set_session_cache_mode(SslSessionCacheMode::OFF);
    Ok(config.build())
}

/// Shared TLS listener configuration. Replacing credentials only affects
/// future handshakes; in-flight streams retain their authenticated identity.
pub struct ClusterListener {
    config: RwLock<Arc<SslContext>>,
    id: PeerId,
    role: Role,
    ca_fingerprint: [u8; 32],
    allow_enrollment: bool,
}

impl ClusterListener {
    /// Construct a scheduler or worker listener using its own role-bound leaf.
    ///
    /// # Errors
    /// Returns an error if credentials cannot configure TLS.
    pub fn new(credentials: &TlsCredentials) -> Result<Self> {
        Self::with_enrollment(credentials, credentials.role == Role::Scheduler)
    }

    /// Construct a scheduler data listener that requires a client certificate
    /// during the TLS handshake and never accepts enrollment or renewal.
    ///
    /// # Errors
    /// Returns an error for non-scheduler credentials or invalid TLS configuration.
    pub fn new_data(credentials: &TlsCredentials) -> Result<Self> {
        ensure!(
            credentials.role == Role::Scheduler,
            "not scheduler credentials"
        );
        Self::with_enrollment(credentials, false)
    }

    fn with_enrollment(credentials: &TlsCredentials, allow_enrollment: bool) -> Result<Self> {
        Ok(Self {
            config: RwLock::new(Arc::new(server_config(credentials, allow_enrollment)?)),
            allow_enrollment,
            id: credentials.id()?,
            role: credentials.role,
            ca_fingerprint: btls::sha::sha256(&credentials.ca.to_der()?),
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
                && self.ca_fingerprint == btls::sha::sha256(&credentials.ca.to_der()?),
            "listener renewal cannot change the local identity, role or CA"
        );
        let config = Arc::new(server_config(credentials, self.allow_enrollment)?);
        *self
            .config
            .write()
            .map_err(|_| anyhow::anyhow!("cluster TLS configuration poisoned"))? = config;
        Ok(())
    }

    /// Prepare the scheduler's enrollment, renewal and authenticated application routes.
    /// # Errors
    /// Returns an error if called for a non-scheduler listener.
    pub fn scheduler_router(
        &self,
        enrollment: Arc<SchedulerEnrollment>,
        data: Router,
    ) -> Result<ClusterRouter> {
        ensure!(self.role == Role::Scheduler, "not a scheduler listener");
        let allow_enrollment = self.allow_enrollment;
        let authorization = Arc::clone(&enrollment);
        let renewal = Arc::clone(&enrollment);
        let protected = authenticated(
            Router::new()
                .route(PROBE, probe())
                .route(
                    RENEW,
                    any(
                        move |Extension(peer): Extension<AuthenticatedPeer>, request: Request| {
                            let renewal = Arc::clone(&renewal);
                            async move {
                                if allow_enrollment {
                                    renewal.renew(peer, request).await
                                } else {
                                    StatusCode::NOT_FOUND.into_response()
                                }
                            }
                        },
                    ),
                )
                .fallback_service(data),
            move |peer| {
                authorization
                    .authority
                    .registry()
                    .is_active(peer.id, peer.role)
                    .unwrap_or(false)
            },
        );
        let router = Router::new()
            .route(
                ENROLL_WORKER,
                enrollment_route(Arc::clone(&enrollment), Role::Worker, allow_enrollment),
            )
            .route(
                ENROLL_CLIENT,
                enrollment_route(enrollment, Role::Client, allow_enrollment),
            )
            .fallback_service(protected);
        Ok(self.bind_router(router))
    }

    /// Prepare worker application routes. All requests require an authorized
    /// mTLS principal; no worker-side bootstrap path exists.
    /// # Errors
    /// Returns an error if called for a non-worker listener.
    pub fn worker_router(
        &self,
        authorize: impl Fn(AuthenticatedPeer) -> bool + Clone + Send + Sync + 'static,
        data: Router,
    ) -> Result<ClusterRouter> {
        ensure!(self.role == Role::Worker, "not a worker listener");
        Ok(self.bind_router(authenticated(
            Router::new().route(PROBE, probe()).fallback_service(data),
            authorize,
        )))
    }

    const fn bind_router(&self, router: Router) -> ClusterRouter {
        ClusterRouter {
            router,
            id: self.id,
            role: self.role,
            ca_fingerprint: self.ca_fingerprint,
            allow_enrollment: self.allow_enrollment,
        }
    }

    /// Serve one socket with a router prepared for this listener. The caller
    /// owns connection admission and listener lifecycle.
    /// # Errors
    /// Returns an error if the router belongs to another listener or if
    /// TLS or HTTP transport fails.
    pub async fn serve(&self, socket: TcpStream, router: ClusterRouter) -> Result<()> {
        ensure!(
            router.id == self.id
                && router.role == self.role
                && router.ca_fingerprint == self.ca_fingerprint
                && router.allow_enrollment == self.allow_enrollment,
            "cluster router belongs to a different listener"
        );
        let address = match socket.peer_addr()? {
            SocketAddr::V6(address) if address.ip().to_ipv4_mapped().is_some() => SocketAddr::new(
                std::net::IpAddr::V6(*address.ip()).to_canonical(),
                address.port(),
            ),
            address => address,
        };
        let path = NetworkPath::new(socket.local_addr()?.ip(), address.ip());
        let path_header = hyper::header::HeaderValue::from_str(&path.to_string())?;
        let config = self
            .config
            .read()
            .map_err(|_| anyhow::anyhow!("cluster TLS configuration poisoned"))?
            .clone();
        let mut stream = SslStream::new(Ssl::new(&config)?, socket)?;
        timeout(CONTROL_TIMEOUT, std::pin::Pin::new(&mut stream).accept()).await??;
        let peer = stream
            .ssl()
            .peer_certificate()
            .map(|leaf| {
                stream.ssl().verify_result()?;
                AuthenticatedPeer::from_verified_leaf(&leaf.to_der()?, address, path)
            })
            .transpose()?;
        let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
            let mut request = request.map(Body::new);
            request
                .extensions_mut()
                .insert(ConnectionInfo { peer, address });
            let future = router.router.clone().oneshot(request);
            let path_header = path_header.clone();
            async move {
                let mut response = match future.await {
                    Ok(response) => response,
                    Err(never) => match never {},
                };
                if peer.is_some() {
                    response.headers_mut().insert(PATH_HEADER, path_header);
                }
                Ok::<_, Infallible>(response)
            }
        });
        http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(CONTROL_TIMEOUT)
            .max_buf_size(HTTP_HEADER_LIMIT)
            .serve_connection(
                TokioIo::new(idle_write::IdleWrite::new(stream, Duration::from_secs(90))),
                service,
            )
            .await?;
        Ok(())
    }
}

type Authorize = dyn Fn(Role, PeerId, SocketAddr, &str) -> bool + Send + Sync;

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
        authorize: impl Fn(Role, PeerId, SocketAddr, &str) -> bool + Send + Sync + 'static,
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

    async fn enroll(
        self: &Arc<Self>,
        address: SocketAddr,
        role: Role,
        request: Request,
    ) -> Response {
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
            Err((status, message)) => return response(status, message),
        };
        let enrollment = Arc::clone(self);
        issue_result(
            tokio::task::spawn_blocking(move || {
                enrollment.authority.enroll(&csr, |id| {
                    (enrollment.authorize)(role, id, address, &token).then_some(role)
                })
            })
            .await,
        )
    }

    async fn renew(self: &Arc<Self>, peer: AuthenticatedPeer, request: Request) -> Response {
        let csr = match decode(request).await {
            Ok(csr) => csr,
            Err((status, message)) => return response(status, message),
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

fn enrollment_route(
    enrollment: Arc<SchedulerEnrollment>,
    role: Role,
    enabled: bool,
) -> MethodRouter {
    any(
        move |Extension(connection): Extension<ConnectionInfo>, request: Request| {
            let enrollment = Arc::clone(&enrollment);
            async move {
                if !enabled {
                    return StatusCode::NOT_FOUND.into_response();
                }
                if connection.peer.is_some() {
                    return response(StatusCode::FORBIDDEN, "use authenticated renewal");
                }
                enrollment.enroll(connection.address, role, request).await
            }
        },
    )
}

async fn decode(
    request: Request,
) -> std::result::Result<EnrollmentRequest, (StatusCode, &'static str)> {
    if request.method() != Method::POST
        || request.uri().query().is_some()
        || request
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some("application/octet-stream")
    {
        return Err((StatusCode::BAD_REQUEST, "invalid enrollment request"));
    }
    let bytes = timeout(
        CONTROL_TIMEOUT,
        Limited::new(request.into_body(), CONTROL_LIMIT).collect(),
    )
    .await
    .map_err(|_| (StatusCode::REQUEST_TIMEOUT, "enrollment body timed out"))?
    .map_err(|_| (StatusCode::BAD_REQUEST, "invalid enrollment body"))?
    .to_bytes();
    codec()
        .deserialize(&bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid enrollment body"))
}

fn issue_result(
    result: std::result::Result<Result<EnrollmentResponse>, tokio::task::JoinError>,
) -> Response {
    match result {
        Ok(Ok(issued)) => codec().serialize(&issued).map_or_else(
            |_| {
                response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "certificate encoding failed",
                )
            },
            |bytes| {
                let mut reply = response(StatusCode::OK, bytes);
                reply.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/octet-stream"),
                );
                reply
            },
        ),
        Ok(Err(_)) => response(StatusCode::FORBIDDEN, "certificate request denied"),
        Err(_) => response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "certificate issuance failed",
        ),
    }
}
