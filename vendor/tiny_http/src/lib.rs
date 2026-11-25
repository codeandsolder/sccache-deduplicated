//! # Simple usage
//!
//! ## Creating the server
//!
//! The easiest way to create a server is to call `Server::http()`.
//!
//! The `http()` function returns an `IoResult<Server>` which will return an error
//! in the case where the server creation fails (for example if the listening port is already
//! occupied).
//!
//! ```no_run
//! let server = tiny_http::Server::http("0.0.0.0:0").unwrap();
//! ```
//!
//! A newly-created `Server` will immediately start listening for incoming connections and HTTP
//! requests.
//!
//! ## Receiving requests
//!
//! Calling `server.recv()` will block until the next request is available.
//! This function returns an `IoResult<Request>`, so you need to handle the possible errors.
//!
//! ```no_run
//! # let server = tiny_http::Server::http("0.0.0.0:0").unwrap();
//!
//! loop {
//!     // blocks until the next request is received
//!     let request = match server.recv() {
//!         Ok(rq) => rq,
//!         Err(e) => { println!("error: {}", e); break }
//!     };
//!
//!     // do something with the request
//!     // ...
//! }
//! ```
//!
//! In a real-case scenario, you will probably want to spawn multiple worker tasks and call
//! `server.recv()` on all of them. Like this:
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use std::thread;
//! # let server = tiny_http::Server::http("0.0.0.0:0").unwrap();
//! let server = Arc::new(server);
//! let mut guards = Vec::with_capacity(4);
//!
//! for _ in (0 .. 4) {
//!     let server = server.clone();
//!
//!     let guard = thread::spawn(move || {
//!         loop {
//!             let rq = server.recv().unwrap();
//!
//!             // ...
//!         }
//!     });
//!
//!     guards.push(guard);
//! }
//! ```
//!
//! If you don't want to block, you can call `server.try_recv()` instead.
//!
//! ## Handling requests
//!
//! The `Request` object returned by `server.recv()` contains informations about the client's request.
//! The most useful methods are probably `request.method()` and `request.url()` which return
//! the requested method (`GET`, `POST`, etc.) and url.
//!
//! To handle a request, you need to create a `Response` object. See the docs of this object for
//! more infos. Here is an example of creating a `Response` from a file:
//!
//! ```no_run
//! # use std::fs::File;
//! # use std::path::Path;
//! let response = tiny_http::Response::from_file(File::open(&Path::new("image.png")).unwrap());
//! ```
//!
//! All that remains to do is call `request.respond()`:
//!
//! ```no_run
//! # use std::fs::File;
//! # use std::path::Path;
//! # let server = tiny_http::Server::http("0.0.0.0:0").unwrap();
//! # let request = server.recv().unwrap();
//! # let response = tiny_http::Response::from_file(File::open(&Path::new("image.png")).unwrap());
//! let _ = request.respond(response);
//! ```
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(clippy::match_like_matches_macro)]

#[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
use zeroize::Zeroizing;

use std::error::Error;
use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;
use std::io::Result as IoResult;
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use client::ClientConnection;
use connection::Connection;
use util::MessagesQueue;

pub use common::{HTTPVersion, Header, HeaderField, Method, StatusCode};
pub use connection::{ConfigListenAddr, ListenAddr, Listener};
pub use request::{ReadWrite, Request};
pub use response::{Response, ResponseBox};
pub use test::TestRequest;

mod client;
mod common;
mod connection;
mod request;
mod response;
mod ssl;
mod test;
mod util;

// Bound idle reads and writes, not the duration of an actively streaming upload.
pub(crate) const SOCKET_IO_TIMEOUT: Duration = Duration::from_secs(60);

/// Admission permits bound both connection and handshake tasks to avoid
/// resource exhaustion from clients that stall at any protocol stage.
struct AdmissionPermit(Arc<AtomicUsize>);

impl AdmissionPermit {
    fn acquire(active: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        let mut count = active.load(Ordering::Acquire);
        loop {
            if count >= limit {
                return None;
            }
            match active.compare_exchange_weak(
                count,
                count + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self(Arc::clone(active))),
                Err(observed) => count = observed,
            }
        }
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

/// The main class of this library.
///
/// Destroying this object will immediately close the listening socket and the reading
///  part of all the client's connections. Requests that have already been returned by
///  the `recv()` function will not close and the responses will be transferred to the client.
pub struct Server {
    // should be false as long as the server exists
    // when set to true, all the subtasks will close within a few hundreds ms
    close: Arc<AtomicBool>,

    // queue for messages received by child threads
    messages: Arc<MessagesQueue<Message>>,

    // result of TcpListener::local_addr()
    listening_addr: ListenAddr,
}

enum Message {
    Error(IoError),
    NewRequest(Request),
}

impl From<IoError> for Message {
    fn from(e: IoError) -> Message {
        Message::Error(e)
    }
}

impl From<Request> for Message {
    fn from(rq: Request) -> Message {
        Message::NewRequest(rq)
    }
}

// Verify the server is safe to share across threads at compile time.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Server>();
};

pub struct IncomingRequests<'a> {
    server: &'a Server,
}

/// Represents the parameters required to create a server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The addresses to try to listen to.
    pub addr: ConfigListenAddr,

    /// If `Some`, then the server will use SSL to encode the communications.
    pub ssl: Option<SslConfig>,
}

/// Configuration of the server for SSL.
#[derive(Debug, Clone)]
pub struct SslConfig {
    /// Contains the public certificate to send to clients.
    pub certificate: Vec<u8>,
    /// Contains the ultra-secret private key used to decode communications.
    pub private_key: Vec<u8>,
}

impl Server {
    /// Shortcut for a simple server on a specific address.
    #[inline]
    pub fn http<A>(addr: A) -> Result<Server, Box<dyn Error + Send + Sync + 'static>>
    where
        A: ToSocketAddrs,
    {
        Server::new(ServerConfig {
            addr: ConfigListenAddr::from_socket_addrs(addr)?,
            ssl: None,
        })
    }

    /// Shortcut for an HTTPS server on a specific address.
    #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
    #[inline]
    pub fn https<A>(
        addr: A,
        config: SslConfig,
    ) -> Result<Server, Box<dyn Error + Send + Sync + 'static>>
    where
        A: ToSocketAddrs,
    {
        Server::new(ServerConfig {
            addr: ConfigListenAddr::from_socket_addrs(addr)?,
            ssl: Some(config),
        })
    }

    #[cfg(unix)]
    #[inline]
    /// Shortcut for a UNIX socket server at a specific path
    pub fn http_unix(
        path: &std::path::Path,
    ) -> Result<Server, Box<dyn Error + Send + Sync + 'static>> {
        Server::new(ServerConfig {
            addr: ConfigListenAddr::unix_from_path(path),
            ssl: None,
        })
    }

    /// Builds a new server that listens on the specified address.
    pub fn new(config: ServerConfig) -> Result<Server, Box<dyn Error + Send + Sync + 'static>> {
        let listener = config.addr.bind()?;
        Self::from_listener(listener, config.ssl)
    }

    /// Builds a new server using the specified TCP listener.
    ///
    /// This is useful if you've constructed TcpListener using some less usual method
    /// such as from systemd. For other cases, you probably want the `new()` function.
    pub fn from_listener<L: Into<Listener>>(
        listener: L,
        ssl_config: Option<SslConfig>,
    ) -> Result<Server, Box<dyn Error + Send + Sync + 'static>> {
        let listener = listener.into();
        // building the "close" variable
        let close_trigger = Arc::new(AtomicBool::new(false));

        // building the TcpListener
        let (server, local_addr) = {
            let local_addr = listener.local_addr()?;
            log::debug!("Server listening on {}", local_addr);
            (listener, local_addr)
        };

        // building the SSL capabilities
        #[cfg(all(feature = "ssl-openssl", feature = "ssl-rustls"))]
        compile_error!(
            "Features 'ssl-openssl' and 'ssl-rustls' must not be enabled at the same time"
        );
        #[cfg(not(any(feature = "ssl-openssl", feature = "ssl-rustls")))]
        type SslContext = ();
        #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
        type SslContext = crate::ssl::SslContextImpl;
        let ssl: Option<Arc<SslContext>> = {
            match ssl_config {
                #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
                Some(config) => Some(Arc::new(SslContext::from_pem(
                    config.certificate,
                    Zeroizing::new(config.private_key),
                )?)),
                #[cfg(not(any(feature = "ssl-openssl", feature = "ssl-rustls")))]
                Some(_) => return Err(
                    "Building a server with SSL requires enabling the `ssl` feature in tiny-http"
                        .into(),
                ),
                None => None,
            }
        };

        // creating a task where server.accept() is continuously called
        // and ClientConnection objects are pushed in the messages queue
        let messages = MessagesQueue::with_capacity(8);

        let active_connections = Arc::new(AtomicUsize::new(0));
        let max_connections = thread::available_parallelism()
            .map(|cpus| cpus.get().saturating_mul(32))
            .unwrap_or(128)
            .clamp(128, 512);
        #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
        let active_handshakes = Arc::new(AtomicUsize::new(0));
        #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
        let max_handshakes = thread::available_parallelism()
            .map(|cpus| cpus.get().saturating_mul(8))
            .unwrap_or(32)
            .clamp(32, 256);

        let inside_close_trigger = close_trigger.clone();
        let inside_messages = messages.clone();
        thread::spawn(move || {
            // a tasks pool is used to dispatch the connections into threads
            let tasks_pool = util::TaskPool::new();

            log::debug!("Running accept thread");
            while !inside_close_trigger.load(Relaxed) {
                match server.accept() {
                    Ok((sock, _)) => {
                        let connection_permit =
                            match AdmissionPermit::acquire(&active_connections, max_connections) {
                                Some(permit) => permit,
                                None => {
                                    log::warn!("Too many concurrent HTTP connections");
                                    continue;
                                }
                            };
                        // Incomplete HTTP headers and abandoned uploads must
                        // not occupy connection threads indefinitely.
                        if let Err(error) = sock.set_io_timeout(Some(SOCKET_IO_TIMEOUT)) {
                            log::warn!("Could not configure HTTP socket timeout: {}", error);
                            continue;
                        }
                        // A silent TLS peer must not block the accept loop, and
                        // many such peers must not create unbounded threads.
                        #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
                        let mut permit = if ssl.is_some() {
                            match AdmissionPermit::acquire(&active_handshakes, max_handshakes) {
                                Some(permit) => Some(permit),
                                None => {
                                    log::warn!("Too many concurrent TLS handshakes");
                                    continue;
                                }
                            }
                        } else {
                            None
                        };
                        let ssl = ssl.clone();
                        let messages = inside_messages.clone();
                        let mut sock = Some(sock);
                        tasks_pool.spawn(Box::new(move || {
                            let _connection_permit = &connection_permit;
                            let Some(sock) = sock.take() else { return };
                            use util::RefinedTcpStream;
                            let (read_closable, write_closable) = match ssl {
                                None => RefinedTcpStream::new(sock),
                                #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
                                Some(ref ssl) => {
                                    let sock = match ssl.accept(sock) {
                                        Ok(sock) => sock,
                                        Err(error) => {
                                            log::debug!("TLS handshake failed: {}", error);
                                            return;
                                        }
                                    };
                                    RefinedTcpStream::new(sock)
                                }
                                #[cfg(not(any(feature = "ssl-openssl", feature = "ssl-rustls")))]
                                Some(ref _ssl) => unreachable!(),
                            };

                            // Release handshake capacity before reading normal
                            // HTTP bodies, which can take arbitrarily longer.
                            #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
                            drop(permit.take());

                            let client = ClientConnection::new(write_closable, read_closable);
                            // A pipelining client must not enqueue unbounded
                            // requests; allow the next request only after its
                            // predecessor is answered. TLS also needs this to
                            // serialize reader and writer access.
                            let (sender, receiver) = mpsc::channel();
                            for rq in client {
                                messages.push(rq.with_notify_sender(sender.clone()).into());
                                if receiver.recv().is_err() {
                                    break;
                                }
                            }
                        }));
                    }

                    Err(e) => {
                        log::error!("Error accepting new client: {}", e);
                        inside_messages.push(e.into());
                        break;
                    }
                }
            }
            log::debug!("Terminating accept thread");
        });

        // result
        Ok(Server {
            messages,
            close: close_trigger,
            listening_addr: local_addr,
        })
    }

    /// Returns an iterator for all the incoming requests.
    ///
    /// The iterator will return `None` if the server socket is shutdown.
    #[inline]
    pub fn incoming_requests(&self) -> IncomingRequests<'_> {
        IncomingRequests { server: self }
    }

    /// Returns the address the server is listening to.
    #[inline]
    pub fn server_addr(&self) -> ListenAddr {
        self.listening_addr.clone()
    }

    /// Returns the number of clients currently connected to the server.
    pub fn num_connections(&self) -> usize {
        unimplemented!()
        //self.requests_receiver.lock().len()
    }

    /// Blocks until an HTTP request has been submitted and returns it.
    pub fn recv(&self) -> IoResult<Request> {
        match self.messages.pop() {
            Some(Message::Error(err)) => Err(err),
            Some(Message::NewRequest(rq)) => Ok(rq),
            None => Err(IoError::new(IoErrorKind::Other, "thread unblocked")),
        }
    }

    /// Same as `recv()` but doesn't block longer than timeout
    pub fn recv_timeout(&self, timeout: Duration) -> IoResult<Option<Request>> {
        match self.messages.pop_timeout(timeout) {
            Some(Message::Error(err)) => Err(err),
            Some(Message::NewRequest(rq)) => Ok(Some(rq)),
            None => Ok(None),
        }
    }

    /// Same as `recv()` but doesn't block.
    pub fn try_recv(&self) -> IoResult<Option<Request>> {
        match self.messages.try_pop() {
            Some(Message::Error(err)) => Err(err),
            Some(Message::NewRequest(rq)) => Ok(Some(rq)),
            None => Ok(None),
        }
    }

    /// Unblock thread stuck in recv() or incoming_requests().
    /// If there are several such threads, only one is unblocked.
    /// This method allows graceful shutdown of server.
    pub fn unblock(&self) {
        self.messages.unblock();
    }
}

impl Iterator for IncomingRequests<'_> {
    type Item = Request;
    fn next(&mut self) -> Option<Request> {
        self.server.recv().ok()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.close.store(true, Relaxed);
        // Connect briefly to ourselves to unblock the accept thread
        let maybe_stream = match &self.listening_addr {
            ListenAddr::IP(addr) => TcpStream::connect(addr).map(Connection::from),
            #[cfg(unix)]
            ListenAddr::Unix(addr) => {
                // TODO: use connect_addr when its stabilized.
                let path = addr.as_pathname().unwrap();
                std::os::unix::net::UnixStream::connect(path).map(Connection::from)
            }
        };
        if let Ok(stream) = maybe_stream {
            let _ = stream.shutdown(Shutdown::Both);
        }

        #[cfg(unix)]
        if let ListenAddr::Unix(addr) = &self.listening_addr {
            if let Some(path) = addr.as_pathname() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

#[cfg(all(test, any(feature = "ssl-openssl", feature = "ssl-rustls")))]
mod handshake_permit_tests {
    use super::*;

    #[test]
    fn handshake_slots_are_bounded_and_released() {
        let active = Arc::new(AtomicUsize::new(0));
        let first = AdmissionPermit::acquire(&active, 2).expect("first slot");
        let second = AdmissionPermit::acquire(&active, 2).expect("second slot");
        assert!(AdmissionPermit::acquire(&active, 2).is_none());
        assert_eq!(active.load(Ordering::Acquire), 2);
        drop(first);
        assert_eq!(active.load(Ordering::Acquire), 1);
        let third = AdmissionPermit::acquire(&active, 2).expect("reused slot");
        drop(second);
        drop(third);
        assert_eq!(active.load(Ordering::Acquire), 0);
    }
}
