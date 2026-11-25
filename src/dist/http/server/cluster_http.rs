//! Native mTLS adapter for the synchronous compiler/CAS handlers. Request
//! bodies remain streaming; TLS-authenticated identity is not an HTTP header.

use std::{
    cell::RefCell,
    collections::BTreeSet,
    io::{self, Read},
    net::{SocketAddr, TcpListener},
    sync::{Arc, RwLock},
    time::Duration,
};

use bytes::Bytes;
use futures::{StreamExt, stream};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::{
    Response, StatusCode,
    body::{Frame, Incoming},
};
use sccache_cluster_identity::{
    AuthenticatedPeer, ClusterBody, ClusterListener, PeerId, Role, SchedulerEnrollment,
};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_util::io::{StreamReader, SyncIoBridge};

use crate::{
    dist::cluster_routes::{Transfer, interface::TrackedReader},
    errors::{Context, Result},
};

/// The single request abstraction used by all synchronous dist handlers.
pub(super) struct Request {
    parts: http::request::Parts,
    id: PeerId,
    role: Role,
    remote_addr: SocketAddr,
    path: sccache_cluster_identity::NetworkPath,
    body: RefCell<Option<Box<dyn Read + Send>>>,
}

impl Request {
    fn new(peer: AuthenticatedPeer, request: hyper::Request<Incoming>) -> Self {
        let (parts, body) = request.into_parts();
        let stream = stream::unfold(Some(body.into_data_stream()), |state| async move {
            let mut data = state?;
            match tokio::time::timeout(BODY_IDLE_TIMEOUT, data.next()).await {
                Ok(Some(Ok(bytes))) => Some((Ok(bytes), Some(data))),
                Ok(Some(Err(error))) => Some((Err(io::Error::other(error)), None)),
                Ok(None) => None,
                Err(_) => Some((
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "distributed request body idle",
                    )),
                    None,
                )),
            }
        });
        let reader = SyncIoBridge::new(StreamReader::new(Box::pin(stream)));
        let length = parts
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let reader =
            TrackedReader::new(reader, Some(peer.path().local), Transfer::Download(length));
        Self {
            parts,
            id: peer.id(),
            role: peer.role(),
            remote_addr: peer.remote_addr(),
            path: peer.path(),
            body: RefCell::new(Some(Box::new(reader))),
        }
    }

    pub(super) fn method(&self) -> &str {
        self.parts.method.as_str()
    }
    pub(super) fn raw_url(&self) -> &str {
        self.parts
            .uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str)
    }
    pub(super) fn url(&self) -> &str {
        self.parts.uri.path()
    }
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.parts.headers.get(name)?.to_str().ok()
    }
    pub(super) fn data(&self) -> Option<Box<dyn Read + Send>> {
        self.body.borrow_mut().take()
    }
    pub(super) const fn id(&self) -> PeerId {
        self.id
    }
    pub(super) const fn role(&self) -> Role {
        self.role
    }
    pub(super) const fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
    pub(super) const fn path(&self) -> sccache_cluster_identity::NetworkPath {
        self.path
    }
    #[cfg(test)]
    pub(super) fn fake_http_from(
        address: SocketAddr,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Self {
        let mut builder = hyper::Request::builder().method(method).uri(url);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let (parts, ()) = builder.body(()).expect("test HTTP request").into_parts();
        Self {
            parts,
            id: PeerId::from_digest([1; 32]),
            role: Role::Client,
            remote_addr: address,
            path: sccache_cluster_identity::NetworkPath::new(address.ip(), address.ip()),
            body: RefCell::new(Some(Box::new(io::Cursor::new(body)))),
        }
    }
}

fn error_response(status: StatusCode, message: &'static str) -> Response<ClusterBody> {
    let mut reply = Response::new(
        Full::new(Bytes::from_static(message.as_bytes()))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *reply.status_mut() = status;
    reply
}

const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

type Handler = dyn Fn(&Request) -> rouille::Response + Send + Sync;

async fn dispatch(
    peer: AuthenticatedPeer,
    request: hyper::Request<Incoming>,
    handler: Arc<Handler>,
    admission: Arc<Semaphore>,
) -> Response<ClusterBody> {
    let Ok(permit) = admission.try_acquire_owned() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "distributed HTTP pool busy",
        );
    };
    let request = Request::new(peer, request);
    let (send, receive) = oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let response = handler(&request);
        let (reader, length) = response.data.into_reader_and_size();
        let mut reader = TrackedReader::new(
            reader,
            Some(request.path().local),
            Transfer::Upload(
                length
                    .and_then(|length| u64::try_from(length).ok())
                    .unwrap_or(0),
            ),
        );
        let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(2);
        let stream = stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|chunk| {
                (
                    chunk.map(Frame::data).map_err(|error| {
                        Box::new(error) as Box<dyn std::error::Error + Send + Sync>
                    }),
                    rx,
                )
            })
        });
        let mut builder = Response::builder().status(response.status_code);
        for (name, value) in response.headers {
            // Hyper owns HTTP framing and connection management.
            if !name.eq_ignore_ascii_case("content-length")
                && !name.eq_ignore_ascii_case("transfer-encoding")
                && !name.eq_ignore_ascii_case("connection")
            {
                builder = builder.header(name.as_ref(), value.as_ref());
            }
        }
        if let Some(length) = length {
            builder = builder.header(http::header::CONTENT_LENGTH, length);
        }
        let response = builder
            .body(StreamBody::new(stream).boxed_unsync())
            .unwrap_or_else(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid response metadata",
                )
            });
        if send.send(response).is_err() {
            return;
        }
        loop {
            let mut buffer = vec![0; 128 * 1024];
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => {
                    buffer.truncate(size);
                    if tx.blocking_send(Ok(Bytes::from(buffer))).is_err() {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    let _ = tx.blocking_send(Err(error));
                    break;
                }
            }
        }
    });
    receive.await.unwrap_or_else(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "distributed HTTP handler terminated",
        )
    })
}

/// Until the initial authenticated snapshot arrives, no remote member except
/// the scheduler may access a worker. Revocations are permanent and monotonic.
#[derive(Default)]
pub(super) struct Revocations(RwLock<Option<BTreeSet<PeerId>>>);

impl Revocations {
    pub(super) fn update(&self, revoked: Vec<PeerId>) {
        if let Ok(mut current) = self.0.write() {
            current.get_or_insert_with(BTreeSet::new).extend(revoked);
        }
    }

    fn permits(&self, peer: PeerId) -> bool {
        self.0.read().is_ok_and(|current| {
            current
                .as_ref()
                .is_some_and(|revoked| !revoked.contains(&peer))
        })
    }
}

#[derive(Clone)]
pub(super) enum ListenerRole {
    Scheduler(Arc<SchedulerEnrollment>),
    Worker {
        scheduler: PeerId,
        revocations: Arc<Revocations>,
    },
}

/// Explicitly configure the address-family behavior; do not depend on
/// the host's IPV6_V6ONLY default. An IPv4-only kernel can still serve
/// the configured reliable IPv4 endpoint when no explicit bind is set.
pub(super) fn bind_socket(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(!address.ip().is_unspecified())?;
    }
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

pub(super) fn bind_data_socket(
    primary: SocketAddr,
    explicit: Option<SocketAddr>,
) -> Result<TcpListener> {
    let address = explicit.unwrap_or_else(|| crate::dist::cluster::wildcard(primary));
    match bind_socket(address) {
        Err(error)
            if explicit.is_none()
                && primary.is_ipv4()
                && address.is_ipv6()
                && (error.kind() == io::ErrorKind::Unsupported
                    || error.kind() == io::ErrorKind::AddrNotAvailable
                    || error.raw_os_error() == Some(libc::EAFNOSUPPORT)
                    || error.raw_os_error() == Some(libc::EPROTONOSUPPORT)) =>
        {
            bind_socket(SocketAddr::new(
                std::net::Ipv4Addr::UNSPECIFIED.into(),
                primary.port(),
            ))
            .context("bind IPv4-only distributed listener")
        }
        result => result.context("bind distributed HTTPS listener"),
    }
}

/// Bind the listener before starting any dependent background services.
pub(super) struct Listener {
    socket: TcpListener,
    tls: Arc<ClusterListener>,
    role: ListenerRole,
    threads: usize,
    handler: Arc<Handler>,
}

impl Listener {
    pub(super) fn bind(
        address: SocketAddr,
        tls: Arc<ClusterListener>,
        role: ListenerRole,
        threads: usize,
        handler: impl Fn(&Request) -> rouille::Response + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::from_socket(bind_socket(address)?, tls, role, threads, handler)
    }

    pub(super) fn from_socket(
        socket: TcpListener,
        tls: Arc<ClusterListener>,
        role: ListenerRole,
        threads: usize,
        handler: impl Fn(&Request) -> rouille::Response + Send + Sync + 'static,
    ) -> Result<Self> {
        anyhow::ensure!(threads > 0, "HTTP handler pool must not be empty");
        Ok(Self {
            socket,
            tls,
            role,
            threads,
            handler: Arc::new(handler),
        })
    }

    #[cfg(test)]
    pub(super) fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    #[cfg(test)]
    pub(super) fn run_until(self, stop: tokio::sync::oneshot::Receiver<()>) -> Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        runtime.block_on(async {
            tokio::select! {
                result = self.run_async() => result,
                _ = stop => Ok(()),
            }
        })
    }

    pub(super) fn run(self) -> Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        runtime.block_on(self.run_async())
    }

    async fn run_async(self) -> Result<()> {
        let Self {
            socket,
            tls,
            role,
            threads,
            handler,
        } = self;
        let socket = tokio::net::TcpListener::from_std(socket)?;
        let connections = Arc::new(Semaphore::new(threads.saturating_mul(4)));
        let requests = Arc::new(Semaphore::new(threads));
        loop {
            let (socket, _) = socket.accept().await?;
            let Ok(connection) = Arc::clone(&connections).try_acquire_owned() else {
                continue;
            };
            let tls = Arc::clone(&tls);
            let role = role.clone();
            let handler = Arc::clone(&handler);
            let requests = Arc::clone(&requests);
            tokio::spawn(async move {
                let _connection = connection;
                let dispatch = move |peer, request| {
                    dispatch(peer, request, Arc::clone(&handler), Arc::clone(&requests))
                };
                let result = match role {
                    ListenerRole::Scheduler(enrollment) => {
                        tls.serve_scheduler(socket, enrollment, dispatch).await
                    }
                    ListenerRole::Worker {
                        scheduler,
                        revocations,
                    } => {
                        tls.serve_worker(
                            socket,
                            move |peer| match peer.role() {
                                Role::Scheduler => peer.id() == scheduler,
                                Role::Client | Role::Worker => revocations.permits(peer.id()),
                            },
                            dispatch,
                        )
                        .await
                    }
                };
                if let Err(error) = result {
                    debug!("distributed HTTPS connection ended: {error:#}");
                }
            });
        }
    }
}

#[cfg(test)]
mod dual_stack_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};

    #[test]
    fn default_data_listener_accepts_both_address_families() -> Result<()> {
        let primary = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 0);
        let listener = bind_data_socket(primary, None)?;
        let bound = listener.local_addr()?;
        let v4 = TcpStream::connect((Ipv4Addr::LOCALHOST, bound.port()))?;
        let (accepted, _) = listener.accept()?;
        drop((v4, accepted));
        if bound.is_ipv6() {
            let v6 = TcpStream::connect((Ipv6Addr::LOCALHOST, bound.port()))?;
            let (accepted, _) = listener.accept()?;
            drop((v6, accepted));
        }
        Ok(())
    }

    #[test]
    fn explicit_ipv4_bind_is_not_widened() -> Result<()> {
        let primary = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
        let listener = bind_data_socket(primary, Some(primary))?;
        assert!(listener.local_addr()?.is_ipv4());
        assert!(listener.local_addr()?.ip().is_loopback());
        Ok(())
    }
}
