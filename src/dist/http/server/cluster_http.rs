//! Native mTLS adapter for the synchronous compiler/CAS handlers. Request
//! bodies remain streaming; TLS-authenticated identity is not an HTTP header.

use std::{
    cell::RefCell,
    collections::BTreeSet,
    io::{self, Read},
    net::{SocketAddr, TcpListener},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, HttpBody as _},
    extract::rejection::PathRejection,
    extract::{Extension, Path, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{MethodFilter, MethodRouter, on},
};
use bytes::Bytes;
use futures::{StreamExt, stream};
use http::StatusCode;
use sccache_cluster_identity::{
    AuthenticatedPeer, ClusterListener, PeerId, Role, SchedulerEnrollment,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::io::{StreamReader, SyncIoBridge};

use crate::{
    dist::cluster_routes::{
        Transfer,
        interface::{self, TrackedReader},
    },
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
    fn new(peer: AuthenticatedPeer, request: axum::extract::Request) -> Self {
        let (parts, body) = request.into_parts();
        let reader = SyncIoBridge::new(StreamReader::new(Box::pin(idle_bounded_body(body))));
        let length = parts
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let reader = TrackedReader::new(
            reader,
            Some(peer.path().local),
            Transfer::Download(length),
            Some(peer.path()),
        );
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
        let mut builder = http::Request::builder().method(method).uri(url);
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

const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

fn idle_bounded_body(body: Body) -> impl futures::Stream<Item = io::Result<Bytes>> + Send {
    stream::unfold(Some(body.into_data_stream()), |state| async move {
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
    })
}

// Blocking filesystem/compilation operations retain admission even if the HTTP
// caller cancels. TLS and HTTP parsing stay on the asynchronous runtime.
async fn blocking_reply(
    permit: Arc<OwnedSemaphorePermit>,
    operation: impl FnOnce() -> Response + Send + 'static,
) -> Response {
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    {
        Ok(response) => response,
        Err(error) => {
            warn!("distributed HTTP handler terminated: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "distributed HTTP handler terminated",
            )
                .into_response()
        }
    }
}

pub(super) fn route<S, F>(method: MethodFilter, handler: F) -> MethodRouter<Arc<S>>
where
    S: Send + Sync + 'static,
    F: Fn(&S, &Request) -> Response + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let router = on(
        method,
        move |State(state): State<Arc<S>>,
              Extension(peer): Extension<AuthenticatedPeer>,
              Extension(permit): Extension<Arc<OwnedSemaphorePermit>>,
              request: axum::extract::Request| {
            let handler = Arc::clone(&handler);
            let request = Request::new(peer, request);
            async move { blocking_reply(permit, move || handler(&state, &request)).await }
        },
    );
    if method == MethodFilter::GET {
        router.head(|| std::future::ready(StatusCode::NOT_FOUND))
    } else {
        router
    }
}

pub(super) fn path_route<S, P, F>(method: MethodFilter, handler: F) -> MethodRouter<Arc<S>>
where
    S: Send + Sync + 'static,
    P: serde::de::DeserializeOwned + Send + 'static,
    F: Fn(&S, &Request, P) -> Response + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let router = on(
        method,
        move |State(state): State<Arc<S>>,
              Extension(peer): Extension<AuthenticatedPeer>,
              Extension(permit): Extension<Arc<OwnedSemaphorePermit>>,
              path: std::result::Result<Path<P>, PathRejection>,
              request: axum::extract::Request| {
            let handler = Arc::clone(&handler);
            let request = Request::new(peer, request);
            async move {
                match path {
                    Ok(Path(path)) => {
                        blocking_reply(permit, move || handler(&state, &request, path)).await
                    }
                    Err(_) => StatusCode::NOT_FOUND.into_response(),
                }
            }
        },
    );
    if method == MethodFilter::GET {
        router.head(|| std::future::ready(StatusCode::NOT_FOUND))
    } else {
        router
    }
}

pub(super) fn routes<S: Send + Sync + 'static>(router: Router<Arc<S>>, state: S) -> Router {
    router
        .method_not_allowed_fallback(|| std::future::ready(StatusCode::NOT_FOUND))
        .with_state(Arc::new(state))
}

/// Stream a blocking file/codec reader with a two-chunk bounded queue. Closing
/// the response closes the receiver and stops the producer without buffering
/// the entire artifact.
const RESPONSE_CHUNK: usize = 128 * 1024;
const RESPONSE_QUEUE: usize = 2;

pub(super) fn reader_body(mut reader: impl Read + Send + 'static) -> Body {
    let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(RESPONSE_QUEUE);
    tokio::task::spawn_blocking(move || {
        while !tx.is_closed() {
            let mut buffer = vec![0; RESPONSE_CHUNK];
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
    Body::from_stream(stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|chunk| (chunk, rx))
    }))
}

pub(super) fn binary(data: Vec<u8>) -> Response {
    (
        [(http::header::CONTENT_TYPE, "application/octet-stream")],
        data,
    )
        .into_response()
}

pub(super) fn file_body(reader: impl Read + Send + 'static, length: u64) -> Response {
    (
        [
            (
                http::header::CONTENT_TYPE,
                "application/octet-stream".to_owned(),
            ),
            (http::header::CONTENT_LENGTH, length.to_string()),
        ],
        reader_body(reader),
    )
        .into_response()
}

#[expect(
    clippy::significant_drop_tightening,
    reason = "the response stream takes ownership of the permit, so admission remains held until the body is drained or cancelled"
)]
async fn admit(
    State(admission): State<Arc<Semaphore>>,
    Extension(peer): Extension<AuthenticatedPeer>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let Ok(permit) = admission.try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "distributed HTTP pool busy",
        )
            .into_response();
    };
    // The response stream must retain the permit even after the handler returns.
    let permit = Arc::new(permit);
    request.extensions_mut().insert(Arc::clone(&permit));
    let response = next.run(request).await;
    let (mut parts, body) = response.into_parts();
    let length = parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| body.size_hint().exact());
    if let Some(length) = length
        && !parts.status.is_informational()
        && parts.status != StatusCode::NO_CONTENT
        && parts.status != StatusCode::NOT_MODIFIED
        && !parts.headers.contains_key(http::header::CONTENT_LENGTH)
        && let Ok(value) = http::HeaderValue::from_str(&length.to_string())
    {
        parts.headers.insert(http::header::CONTENT_LENGTH, value);
    }
    let activity = interface::activity(
        Some(peer.path().local),
        Transfer::Upload(length.unwrap_or(0)),
        Some(peer.path()),
    );
    // Keep the request slot until the response is drained or cancelled.
    let response_state = (body.into_data_stream(), activity, permit);
    let stream = stream::unfold(
        response_state,
        |(mut body, mut activity, permit)| async move {
            body.next().await.map(|chunk| {
                if let Ok(bytes) = &chunk
                    && let Some(activity) = &mut activity
                {
                    activity.bytes(bytes.len() as u64);
                }
                (chunk, (body, activity, permit))
            })
        },
    );
    Response::from_parts(parts, Body::from_stream(stream))
}

/// Until the initial authenticated snapshot arrives, no remote member except
/// the scheduler may access a worker. Revocations are permanent and monotonic.
#[derive(Default)]
pub(super) struct Revocations(RwLock<Option<(Instant, BTreeSet<PeerId>)>>);

impl Revocations {
    pub(super) fn update(&self, revoked: Vec<PeerId>) {
        if let Ok(mut current) = self.0.write() {
            let (updated, entries) =
                current.get_or_insert_with(|| (Instant::now(), BTreeSet::new()));
            *updated = Instant::now();
            entries.extend(revoked);
        }
    }

    fn permits(&self, peer: PeerId) -> bool {
        self.0.read().is_ok_and(|current| {
            current.as_ref().is_some_and(|(updated, revoked)| {
                updated.elapsed() < super::HEARTBEAT_TIMEOUT && !revoked.contains(&peer)
            })
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
/// the host's `IPV6_V6ONLY` default. An IPv4-only kernel can still serve
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
    router: Router,
}

impl Listener {
    pub(super) fn bind(
        address: SocketAddr,
        tls: Arc<ClusterListener>,
        role: ListenerRole,
        threads: usize,
        router: Router,
    ) -> Result<Self> {
        Self::from_socket(bind_socket(address)?, tls, role, threads, router)
    }

    pub(super) fn from_socket(
        socket: TcpListener,
        tls: Arc<ClusterListener>,
        role: ListenerRole,
        threads: usize,
        router: Router,
    ) -> Result<Self> {
        anyhow::ensure!(threads > 0, "HTTP handler pool must not be empty");
        Ok(Self {
            socket,
            tls,
            role,
            threads,
            router,
        })
    }

    pub(super) fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    #[cfg(test)]
    pub(super) fn run_until(self, stop: tokio::sync::oneshot::Receiver<()>) -> Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(self.threads.saturating_mul(2).max(8))
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
            .max_blocking_threads(self.threads.saturating_mul(2).max(8))
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
            router,
        } = self;
        let socket = tokio::net::TcpListener::from_std(socket)?;
        let connections = Arc::new(Semaphore::new(threads.saturating_mul(4)));
        let router = router.layer(middleware::from_fn_with_state(
            Arc::new(Semaphore::new(threads)),
            admit,
        ));
        let router = match role {
            ListenerRole::Scheduler(enrollment) => tls.scheduler_router(enrollment, router)?,
            ListenerRole::Worker {
                scheduler,
                revocations,
            } => tls.worker_router(
                move |peer| match peer.role() {
                    Role::Scheduler => peer.id() == scheduler,
                    Role::Client | Role::Worker => revocations.permits(peer.id()),
                },
                router,
            )?,
        };
        loop {
            let (socket, _) = socket.accept().await?;
            let Ok(connection) = Arc::clone(&connections).try_acquire_owned() else {
                continue;
            };
            let tls = Arc::clone(&tls);
            let router = router.clone();
            tokio::spawn(async move {
                let _connection = connection;
                let result = tls.serve(socket, router).await;
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

#[cfg(test)]
mod revocation_tests {
    use super::*;

    #[test]
    fn stale_snapshots_fail_closed_and_revocations_are_monotonic() {
        let state = Revocations::default();
        let a = PeerId::from_digest([1; 32]);
        let b = PeerId::from_digest([2; 32]);
        assert!(!state.permits(a));
        state.update(vec![b]);
        assert!(state.permits(a));
        assert!(!state.permits(b));
        if let Some((updated, _)) = state.0.write().unwrap().as_mut() {
            *updated -= super::super::HEARTBEAT_TIMEOUT;
        }
        assert!(!state.permits(a));
        state.update(Vec::new());
        assert!(state.permits(a));
        assert!(!state.permits(b));
    }
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(start_paused = true)]
    async fn unfinished_request_body_releases_reader_at_idle_deadline() -> Result<()> {
        let prefix = Bytes::from_static(b"partial archive");
        let source = stream::iter([Ok::<_, io::Error>(prefix.clone())]).chain(stream::pending());
        let mut body = std::pin::pin!(idle_bounded_body(Body::from_stream(source)));
        assert_eq!(body.next().await.transpose()?, Some(prefix));
        let start = tokio::time::Instant::now();
        let Some(Err(error)) =
            tokio::time::timeout(BODY_IDLE_TIMEOUT + Duration::from_secs(1), body.next()).await?
        else {
            anyhow::bail!("unfinished request must time out");
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= BODY_IDLE_TIMEOUT);
        assert!(body.next().await.is_none());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn progressing_body_may_exceed_one_idle_interval() -> Result<()> {
        let chunks = [b"one".as_slice(), b"two", b"three"];
        let source = stream::iter(chunks).then(|chunk| async move {
            tokio::time::sleep(BODY_IDLE_TIMEOUT / 2).await;
            Ok::<_, io::Error>(Bytes::from_static(chunk))
        });
        let mut body = std::pin::pin!(idle_bounded_body(Body::from_stream(source)));
        let start = tokio::time::Instant::now();
        for chunk in chunks {
            assert_eq!(
                body.next().await.transpose()?,
                Some(Bytes::from_static(chunk))
            );
        }
        assert!(body.next().await.is_none());
        assert!(start.elapsed() > BODY_IDLE_TIMEOUT);
        Ok(())
    }

    struct InfiniteReader {
        bytes: Arc<AtomicUsize>,
        stopped: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl Read for InfiniteReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            buffer.fill(0x5a);
            self.bytes.fetch_add(buffer.len(), Ordering::Relaxed);
            Ok(buffer.len())
        }
    }

    impl Drop for InfiniteReader {
        fn drop(&mut self) {
            if let Some(stopped) = self.stopped.take() {
                let _ = stopped.send(());
            }
        }
    }

    #[tokio::test]
    async fn abandoned_response_stops_bounded_reader() {
        let bytes = Arc::new(AtomicUsize::new(0));
        let (stopped, done) = tokio::sync::oneshot::channel();
        let body = reader_body(InfiniteReader {
            bytes: Arc::clone(&bytes),
            stopped: Some(stopped),
        });
        // Two queued chunks plus the producer's in-flight chunk.
        let maximum = (RESPONSE_QUEUE + 1) * RESPONSE_CHUNK;
        tokio::time::timeout(Duration::from_secs(5), async {
            while bytes.load(Ordering::Relaxed) < maximum {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("reader did not fill bounded queue");
        assert_eq!(bytes.load(Ordering::Relaxed), maximum);
        drop(body);
        tokio::time::timeout(Duration::from_secs(5), done)
            .await
            .expect("reader did not stop after cancellation")
            .expect("reader exited without signalling");
        assert_eq!(bytes.load(Ordering::Relaxed), maximum);
    }
}
