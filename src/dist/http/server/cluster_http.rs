//! Native mTLS adapter for the synchronous compiler/CAS handlers. Request
//! bodies remain streaming; TLS-authenticated identity is not an HTTP header.

use std::{
    cell::RefCell,
    collections::BTreeSet,
    fs::File,
    future::Future,
    io::{self, Read},
    net::{SocketAddr, TcpListener},
    sync::{Arc, OnceLock, RwLock},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, HttpBody as _},
    extract::rejection::PathRejection,
    extract::{Extension, Path, State},
    response::{IntoResponse, Response},
    routing::{MethodFilter, MethodRouter, on},
};
use bytes::Bytes;
use futures::{StreamExt, stream};
use http::StatusCode;
use sccache_cluster_identity::{
    AuthenticatedPeer, ClusterListener, PeerId, Role, SchedulerEnrollment,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::io::{StreamReader, SyncIoBridge};

use crate::{
    build_runtime::TransferMeter,
    dist::cluster_routes::{
        Transfer,
        interface::{self, TrackedReader},
    },
    dist::native::ingress::compute,
    errors::{Context, Result},
};

use super::super::transport::BoundedReadError;

enum RequestBody {
    Network(Body),
    Buffered(std::result::Result<Vec<u8>, BoundedReadError>),
}

/// The authenticated request, with either asynchronous metadata extraction
/// or a synchronous bridge for filesystem/codec consumers.
pub(super) struct Request {
    parts: http::request::Parts,
    id: PeerId,
    role: Role,
    remote_addr: SocketAddr,
    path: sccache_cluster_identity::NetworkPath,
    body: RefCell<Option<RequestBody>>,
    admission: Arc<OwnedSemaphorePermit>,
}

impl Request {
    fn new(
        peer: AuthenticatedPeer,
        request: axum::extract::Request,
        admission: Arc<OwnedSemaphorePermit>,
    ) -> Self {
        let (parts, body) = request.into_parts();
        Self {
            parts,
            id: peer.id(),
            role: peer.role(),
            remote_addr: peer.remote_addr(),
            path: peer.path(),
            body: RefCell::new(Some(RequestBody::Network(body))),
            admission,
        }
    }

    pub(super) fn file_body(
        &self,
        file: File,
        length: u64,
        meter: Option<TransferMeter>,
    ) -> Response {
        file_body(file, length, meter, Arc::clone(&self.admission))
    }

    pub(super) fn compressed_file_body(
        &self,
        file: File,
        length: u64,
        meter: Option<TransferMeter>,
    ) -> Result<Response> {
        let (encoder, header) = crate::build_runtime::BlobWireEncoder::new(length)?;
        let body =
            compressed_reader_body(file, encoder, header, meter, Arc::clone(&self.admission));
        Ok((
            [(http::header::CONTENT_TYPE, "application/octet-stream")],
            body,
        )
            .into_response())
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
    fn body_length(&self) -> u64 {
        self.header("Content-Length")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    }

    pub(super) fn data(&self) -> Option<Box<dyn Read + Send>> {
        match self.body.borrow_mut().take()? {
            RequestBody::Network(body) => {
                let reader =
                    SyncIoBridge::new(StreamReader::new(Box::pin(idle_bounded_body(body))));
                Some(Box::new(TrackedReader::new(
                    reader,
                    Some(self.path.local),
                    Transfer::Download(self.body_length()),
                    Some(self.path),
                )))
            }
            RequestBody::Buffered(_) => None,
        }
    }

    pub(super) fn body_stream(
        &mut self,
    ) -> Option<impl futures::Stream<Item = io::Result<Bytes>> + Send + use<>> {
        let body = match self.body.get_mut().take()? {
            RequestBody::Network(body) => body,
            RequestBody::Buffered(Ok(bytes)) => Body::from(bytes),
            RequestBody::Buffered(Err(_)) => return None,
        };
        let mut activity = interface::activity(
            Some(self.path.local),
            Transfer::Download(self.body_length()),
            Some(self.path),
        );
        Some(idle_bounded_body(body).map(move |chunk| {
            if let (Ok(bytes), Some(activity)) = (&chunk, &mut activity) {
                activity.bytes(bytes.len() as u64);
            }
            chunk
        }))
    }

    pub(super) async fn read_bounded(
        &mut self,
        limit: usize,
    ) -> std::result::Result<Vec<u8>, super::super::transport::BoundedReadError> {
        let mut bytes = Vec::new();
        let mut stream = std::pin::pin!(
            self.body_stream()
                .ok_or(BoundedReadError::AlreadyExtracted)?
        );
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(BoundedReadError::Io)?;
            if chunk.len() > limit.saturating_sub(bytes.len()) {
                return Err(BoundedReadError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
    // Buffer only explicitly bounded metadata before dispatching its
    // synchronous parser/database work. Preserve the body error so the
    // route's existing authorization and error mapping remain authoritative.
    async fn buffer_body(&mut self, limit: usize) {
        let body = self.read_bounded(limit).await;
        *self.body.get_mut() = Some(RequestBody::Buffered(body));
    }

    pub(super) fn read_buffered(
        &self,
        limit: usize,
    ) -> std::result::Result<Vec<u8>, BoundedReadError> {
        match self.body.borrow_mut().take() {
            Some(RequestBody::Buffered(body)) => {
                let body = body?;
                if body.len() > limit {
                    return Err(BoundedReadError::TooLarge);
                }
                Ok(body)
            }
            _ => Err(BoundedReadError::AlreadyExtracted),
        }
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
            body: RefCell::new(Some(RequestBody::Buffered(Ok(body)))),
            admission: AdmissionPools::new(1)
                .acquire(AdmissionClass::Bulk)
                .expect("test admission"),
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
    joined_reply(
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation()
        })
        .await,
    )
}

fn joined_reply(result: std::result::Result<Response, tokio::task::JoinError>) -> Response {
    match result {
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

/// Independent bounded lanes: bulk bodies and remote assignment cannot
/// consume the permits reserved for lease/state transitions or metadata.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AdmissionClass {
    Control,
    Metadata,
    Dispatch,
    Bulk,
}

struct AdmissionPools {
    control: Arc<Semaphore>,
    metadata: Arc<Semaphore>,
    dispatch: Arc<Semaphore>,
    bulk: Arc<Semaphore>,
}

impl AdmissionPools {
    fn new(bulk: usize) -> Self {
        Self {
            control: Arc::new(Semaphore::new(Self::control_capacity(bulk))),
            metadata: Arc::new(Semaphore::new(bulk)),
            dispatch: Arc::new(Semaphore::new(bulk)),
            bulk: Arc::new(Semaphore::new(bulk)),
        }
    }

    fn control_capacity(bulk: usize) -> usize {
        (bulk / 8).clamp(2, 8)
    }

    fn total_capacity(bulk: usize) -> usize {
        bulk.saturating_mul(3)
            .saturating_add(Self::control_capacity(bulk))
    }

    fn acquire(&self, class: AdmissionClass) -> Option<Arc<OwnedSemaphorePermit>> {
        let pool = match class {
            AdmissionClass::Control => &self.control,
            AdmissionClass::Metadata => &self.metadata,
            AdmissionClass::Dispatch => &self.dispatch,
            AdmissionClass::Bulk => &self.bulk,
        };
        Arc::clone(pool).try_acquire_owned().ok().map(Arc::new)
    }
}

pub(super) fn route<S, F>(
    method: MethodFilter,
    class: AdmissionClass,
    body_limit: impl Fn(&S) -> Option<usize> + Copy + Send + Sync + 'static,
    handler: F,
) -> MethodRouter<Arc<S>>
where
    S: Send + Sync + 'static,
    F: Fn(&S, &Request) -> Response + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let router = on(
        method,
        move |State(state): State<Arc<S>>,
              Extension(peer): Extension<AuthenticatedPeer>,
              Extension(pools): Extension<Arc<AdmissionPools>>,
              request: axum::extract::Request| {
            let handler = Arc::clone(&handler);
            async move {
                let limit = body_limit(&state);
                admit(pools, class, peer, request, limit, move |request| {
                    handler(&state, &request)
                })
                .await
            }
        },
    );
    if method == MethodFilter::GET {
        router.head(|| std::future::ready(StatusCode::NOT_FOUND))
    } else {
        router
    }
}

/// An admitted operation that can await transport directly. Its task retains
/// admission and finishes state transitions even if the HTTP caller disconnects.
pub(super) fn async_route<S, F, Fut>(
    method: MethodFilter,
    class: AdmissionClass,
    handler: F,
) -> MethodRouter<Arc<S>>
where
    S: Send + Sync + 'static,
    F: Fn(Arc<S>, Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let handler = Arc::new(handler);
    let router = on(
        method,
        move |State(state): State<Arc<S>>,
              Extension(peer): Extension<AuthenticatedPeer>,
              Extension(pools): Extension<Arc<AdmissionPools>>,
              request: axum::extract::Request| {
            let handler = Arc::clone(&handler);
            async move {
                let Some(permit) = pools.acquire(class) else {
                    return busy_response();
                };
                let request = Request::new(peer, request, Arc::clone(&permit));
                let task_permit = Arc::clone(&permit);
                let operation = tokio::spawn(async move {
                    let _permit = task_permit;
                    handler(state, request).await
                });

                let response = joined_reply(operation.await);
                track_response(peer, permit, response)
            }
        },
    );
    if method == MethodFilter::GET {
        router.head(|| std::future::ready(StatusCode::NOT_FOUND))
    } else {
        router
    }
}

pub(super) fn path_route<S, P, F>(
    method: MethodFilter,
    classify: impl Fn(&P) -> AdmissionClass + Copy + Send + Sync + 'static,
    body_limit: impl Fn(&S, &P) -> Option<usize> + Copy + Send + Sync + 'static,
    handler: F,
) -> MethodRouter<Arc<S>>
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
              Extension(pools): Extension<Arc<AdmissionPools>>,
              path: std::result::Result<Path<P>, PathRejection>,
              request: axum::extract::Request| {
            let handler = Arc::clone(&handler);
            async move {
                match path {
                    Ok(Path(path)) => {
                        let class = classify(&path);
                        let limit = body_limit(&state, &path);
                        admit(pools, class, peer, request, limit, move |request| {
                            handler(&state, &request, path)
                        })
                        .await
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

/// Read one chunk per downstream poll. A slow peer holds the reader, not a
/// blocking-pool thread; cancellation can leave at most one read in flight.
const RESPONSE_CHUNK: usize = 128 * 1024;

fn reader_body(
    file: File,
    length: u64,
    meter: Option<TransferMeter>,
    permit: Arc<OwnedSemaphorePermit>,
) -> Body {
    Body::from_stream(stream::try_unfold(
        (Arc::new(file), 0_u64, meter, permit),
        move |(file, offset, mut meter, permit)| async move {
            let count = usize::try_from(length - offset)
                .unwrap_or(usize::MAX)
                .min(RESPONSE_CHUNK);
            if count == 0 {
                if let Some(meter) = &mut meter {
                    meter.eof();
                }
                return Ok(None);
            }
            let (bytes, permit) =
                crate::build_runtime::read_file_at(Arc::clone(&file), offset, count, permit)
                    .await?;
            if let Some(meter) = &mut meter {
                meter.observe(count as u64);
            }
            Ok::<_, anyhow::Error>(Some((
                Bytes::from(bytes),
                (file, offset + count as u64, meter, permit),
            )))
        },
    ))
}

/// Emit the final header immediately and encode at most one frame per demand.
/// Slow receivers retain file/codec state, never an encoder or I/O thread.
fn compressed_reader_body(
    file: File,
    encoder: crate::build_runtime::BlobWireEncoder,
    header: [u8; 32],
    meter: Option<TransferMeter>,
    permit: Arc<OwnedSemaphorePermit>,
) -> Body {
    Body::from_stream(stream::try_unfold(
        (Arc::new(file), 0_u64, encoder, meter, permit, Some(header)),
        |(file, offset, mut encoder, mut meter, permit, header)| async move {
            if let Some(header) = header {
                if let Some(meter) = &mut meter {
                    meter.observe(header.len() as u64);
                }
                return Ok(Some((
                    Bytes::copy_from_slice(&header),
                    (file, offset, encoder, meter, permit, None),
                )));
            }
            let count = encoder.next_frame_size();
            if count == 0 {
                if let Some(meter) = &mut meter {
                    meter.eof();
                }
                return Ok(None);
            }
            let (bytes, permit) =
                crate::build_runtime::read_file_at(Arc::clone(&file), offset, count, permit)
                    .await?;
            let (frame, encoder, file, permit) = compute(move || {
                let frame = encoder.frame(&bytes)?;
                Ok((frame, encoder, file, permit))
            })
            .await?;
            if let Some(meter) = &mut meter {
                meter.observe(frame.len() as u64);
            }
            Ok::<_, anyhow::Error>(Some((
                Bytes::from(frame),
                (file, offset + count as u64, encoder, meter, permit, None),
            )))
        },
    ))
}

pub(super) fn binary(data: Vec<u8>) -> Response {
    (
        [(http::header::CONTENT_TYPE, "application/octet-stream")],
        data,
    )
        .into_response()
}

fn file_body(
    file: File,
    length: u64,
    meter: Option<TransferMeter>,
    permit: Arc<OwnedSemaphorePermit>,
) -> Response {
    (
        [
            (
                http::header::CONTENT_TYPE,
                "application/octet-stream".to_owned(),
            ),
            (http::header::CONTENT_LENGTH, length.to_string()),
        ],
        reader_body(file, length, meter, permit),
    )
        .into_response()
}

fn busy_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "distributed HTTP pool busy",
    )
        .into_response()
}

#[expect(
    clippy::significant_drop_tightening,
    reason = "the buffered request is moved into the blocking operation with its admission guard"
)]
async fn admit(
    pools: Arc<AdmissionPools>,
    class: AdmissionClass,
    peer: AuthenticatedPeer,
    request: axum::extract::Request,
    body_limit: Option<usize>,
    operation: impl FnOnce(Request) -> Response + Send + 'static,
) -> Response {
    let Some(permit) = pools.acquire(class) else {
        return busy_response();
    };
    let mut request = Request::new(peer, request, Arc::clone(&permit));
    if let Some(limit) = body_limit {
        request.buffer_body(limit).await;
    }
    let response = blocking_reply(Arc::clone(&permit), move || operation(request)).await;
    track_response(peer, permit, response)
}

fn track_response(
    peer: AuthenticatedPeer,
    permit: Arc<OwnedSemaphorePermit>,
    response: Response,
) -> Response {
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

// Connection budgets count idle sockets, not admitted application work.
// Reserve half the process descriptor budget for outgoing RPCs, CAS files,
// compilers, listeners, logs and other non-accepted descriptors.
const LISTENER_CONNECTION_LIMIT: usize = 65_536;
const PROCESS_FD_TARGET: u64 = 262_144;

fn connection_capacity(soft_limit: u64) -> usize {
    usize::try_from((soft_limit / 2).min(PROCESS_FD_TARGET / 2)).unwrap_or(usize::MAX)
}

fn process_connections() -> Arc<Semaphore> {
    static CONNECTIONS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(CONNECTIONS.get_or_init(|| {
        use rustix::process::{Resource, getrlimit, setrlimit};
        let mut limit = getrlimit(Resource::Nofile);
        let target = limit.maximum.unwrap_or(PROCESS_FD_TARGET).min(PROCESS_FD_TARGET);
        if limit.current.is_some_and(|current| current < target) {
            let requested = rustix::process::Rlimit {
                current: Some(target),
                maximum: limit.maximum,
            };
            if let Err(error) = setrlimit(Resource::Nofile, requested) {
                warn!("cannot raise distributed server FD limit: {error}");
            }
            limit = getrlimit(Resource::Nofile);
        }
        let soft = limit.current.unwrap_or(PROCESS_FD_TARGET);
        let capacity = connection_capacity(soft);
        info!("distributed socket admission: {capacity} process-wide, {LISTENER_CONNECTION_LIMIT} per listener (FD soft limit {soft})");
        Arc::new(Semaphore::new(capacity))
    }))
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
            .max_blocking_threads(
                AdmissionPools::total_capacity(self.threads)
                    .saturating_mul(2)
                    .max(8),
            )
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
            .worker_threads(crate::util::num_cpus())
            .max_blocking_threads(
                AdmissionPools::total_capacity(self.threads)
                    .saturating_mul(2)
                    .max(8),
            )
            .enable_all()
            .build()?;
        runtime.block_on(self.run_async())
    }

    async fn run_async(self) -> Result<()> {
        crate::build_runtime::initialize_async_disk()?;
        let Self {
            socket,
            tls,
            role,
            threads,
            router,
        } = self;
        let socket = tokio::net::TcpListener::from_std(socket)?;
        let connections = Arc::new(Semaphore::new(LISTENER_CONNECTION_LIMIT));
        let process_connections = process_connections();
        let router = router.layer(Extension(Arc::new(AdmissionPools::new(threads))));
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
            // Backpressure accept rather than accepting and immediately resetting
            // an otherwise valid connection. The process-wide budget spans all listeners.
            let connection = Arc::clone(&connections).acquire_owned().await?;
            let process_connection = Arc::clone(&process_connections).acquire_owned().await?;
            let socket = match socket.accept().await {
                Ok((socket, _)) => socket,
                Err(error) if matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) => {
                    warn!("distributed listener descriptor exhaustion: {error}");
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let tls = Arc::clone(&tls);
            let router = router.clone();
            tokio::spawn(async move {
                let _connection = (connection, process_connection);
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
    use std::io::Write;

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

    #[tokio::test]
    async fn buffered_metadata_preserves_body_budget_and_extraction_error() -> Result<()> {
        let mut request = Request::fake_http_from(
            "127.0.0.1:0".parse()?,
            "POST",
            "/metadata",
            Vec::new(),
            Vec::new(),
        );
        *request.body.get_mut() = Some(RequestBody::Network(Body::from_stream(stream::iter([
            Ok::<_, io::Error>(Bytes::from_static(b"meta")),
            Ok(Bytes::from_static(b"data")),
        ]))));
        request.buffer_body(8).await;
        assert_eq!(request.read_buffered(8).unwrap(), b"metadata");
        assert!(matches!(
            request.read_buffered(8),
            Err(BoundedReadError::AlreadyExtracted)
        ));
        *request.body.get_mut() = Some(RequestBody::Network(Body::from("oversized")));
        request.buffer_body(8).await;
        assert!(matches!(
            request.read_buffered(8),
            Err(BoundedReadError::TooLarge)
        ));
        *request.body.get_mut() = Some(RequestBody::Network(Body::from_stream(stream::once(
            async { Err::<Bytes, _>(io::Error::other("interrupted body")) },
        ))));
        request.buffer_body(8).await;
        assert!(matches!(
            request.read_buffered(8),
            Err(BoundedReadError::Io(_))
        ));
        Ok(())
    }

    #[test]
    fn socket_budget_is_independent_of_request_capacity() {
        assert_eq!(connection_capacity(2_048), 1_024);
        assert_eq!(connection_capacity(262_144), 131_072);
        assert_eq!(connection_capacity(u64::MAX), 131_072);
        assert_eq!(LISTENER_CONNECTION_LIMIT, 65_536);
    }

    #[test]
    fn each_lane_has_independent_bounded_capacity() -> Result<()> {
        let pools = AdmissionPools::new(4);
        for (class, count) in [
            (AdmissionClass::Bulk, 4),
            (AdmissionClass::Dispatch, 4),
            (AdmissionClass::Metadata, 4),
            (AdmissionClass::Control, 2),
        ] {
            let permits = (0..count)
                .map(|_| pools.acquire(class).context("reserved lane permit"))
                .collect::<Result<Vec<_>>>()?;
            assert!(pools.acquire(class).is_none());
            for other in [
                AdmissionClass::Bulk,
                AdmissionClass::Dispatch,
                AdmissionClass::Metadata,
                AdmissionClass::Control,
            ] {
                if class != other {
                    assert!(pools.acquire(other).is_some());
                }
            }
            drop(permits);
            assert!(pools.acquire(class).is_some());
        }
        Ok(())
    }

    #[test]
    fn stalled_response_does_not_occupy_blocking_pool() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let file = tempfile::tempfile()?;
            let length = (2 * RESPONSE_CHUNK) as u64;
            file.set_len(length)?;
            let truncate = file.try_clone()?;
            let pools = AdmissionPools::new(1);
            let permit = pools.acquire(AdmissionClass::Bulk).context("test permit")?;
            let mut body = reader_body(file, length, None, permit).into_data_stream();
            let chunk = tokio::time::timeout(Duration::from_secs(5), body.next())
                .await?
                .context("missing response chunk")??;
            assert_eq!(chunk.len(), RESPONSE_CHUNK);
            tokio::time::timeout(Duration::from_secs(5), tokio::task::spawn_blocking(|| ()))
                .await??;
            assert!(pools.acquire(AdmissionClass::Bulk).is_none());
            // No read-ahead: truncating after the first demand must make the next read fail.
            truncate.set_len(RESPONSE_CHUNK as u64)?;
            assert!(
                body.next()
                    .await
                    .context("missing truncated chunk")?
                    .is_err()
            );
            drop(body);
            assert!(pools.acquire(AdmissionClass::Bulk).is_some());
            Ok(())
        })
    }

    #[tokio::test]
    async fn demand_driven_response_preserves_exact_bytes_and_eof() -> Result<()> {
        let expected = vec![0xa5; RESPONSE_CHUNK + 17];
        let mut file = tempfile::tempfile()?;
        file.write_all(&expected)?;
        let actual = axum::body::to_bytes(
            reader_body(
                file,
                expected.len() as u64,
                None,
                AdmissionPools::new(1)
                    .acquire(AdmissionClass::Bulk)
                    .context("test permit")?,
            ),
            expected.len(),
        )
        .await?;
        assert_eq!(actual.as_ref(), expected.as_slice());
        Ok(())
    }
}
