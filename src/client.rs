// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::errors::{Context, Result, anyhow, bail};
use crate::net::Connection;
use crate::protocol::{Request, Response, TransferReply, TransferRequest};
use crate::util;
use anyhow::ensure;
use backon::BlockingRetryable;
use byteorder::{BigEndian, ByteOrder};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// A connection to an sccache server.
pub struct ServerConnection {
    /// A reader for the socket connected to the server.
    reader: BufReader<Box<dyn Connection>>,
    /// A writer for the socket connected to the server.
    writer: BufWriter<Box<dyn Connection>>,
    closed: CancellationToken,
}

impl ServerConnection {
    /// Create a new connection using `stream`.
    pub fn new(conn: Box<dyn Connection>) -> io::Result<Self> {
        conn.set_io_timeout(crate::server::activity::IPC_INACTIVITY_TIMEOUT)?;
        let write_conn = conn.try_clone()?;
        Ok(Self {
            reader: BufReader::new(conn),
            writer: BufWriter::new(write_conn),
            closed: CancellationToken::new(),
        })
    }

    /// Send `request` to the server, read and return a `Response`.
    pub fn request(&mut self, request: Request) -> Result<Response> {
        trace!("ServerConnection::request");
        ensure!(!self.closed.is_cancelled(), IpcTransportFailure);
        if let Err(error) = util::write_length_prefixed_bincode(&mut self.writer, request) {
            return self.invalidate(Err(error));
        }
        trace!("ServerConnection::request: sent request");
        self.read_one_response()
    }

    pub(crate) fn transfer(&mut self, request: TransferRequest) -> Result<TransferReply> {
        match self.request(Request::Transfer(request))? {
            Response::Transfer(reply) => reply.map_err(|error| anyhow!("{error}")),
            other => self.invalidate(Err(anyhow!("unexpected transfer response: {other:?}"))),
        }
    }

    /// Read exactly the advertised number of bytes using bounded frames.
    pub(crate) fn download(
        &mut self,
        mut remaining: u64,
        chunk_bytes: usize,
        mut output: impl Write,
    ) -> Result<()> {
        let result = (|| {
            while remaining > 0 {
                let TransferReply::Chunk(chunk) = self.transfer(TransferRequest::ReadChunk)? else {
                    bail!("expected a download chunk");
                };
                ensure!(
                    !chunk.is_empty()
                        && chunk.len() <= chunk_bytes
                        && chunk.len() as u64 <= remaining,
                    "invalid download chunk size"
                );
                output.write_all(&chunk)?;
                remaining -= chunk.len() as u64;
            }
            Ok(())
        })();
        if result.is_err() && !self.closed.is_cancelled() {
            let _ = self.transfer(TransferRequest::Abort);
        }
        result
    }

    /// Upload exactly the advertised number of bytes. The caller commits a
    /// complete upload with the operation appropriate for its content type.
    pub(crate) fn upload(
        &mut self,
        mut remaining: u64,
        chunk_bytes: usize,
        mut input: impl Read,
    ) -> Result<()> {
        let result = (|| {
            let mut chunk = vec![0; chunk_bytes];
            while remaining > 0 {
                let len = usize::try_from(remaining.min(chunk_bytes as u64))?;
                input.read_exact(&mut chunk[..len])?;
                ensure!(
                    matches!(
                        self.transfer(TransferRequest::WriteChunk(chunk[..len].to_vec()))?,
                        TransferReply::Ack
                    ),
                    "expected upload acknowledgment"
                );
                remaining -= len as u64;
            }
            Ok(())
        })();
        if result.is_err() && !self.closed.is_cancelled() {
            let _ = self.transfer(TransferRequest::Abort);
        }
        result
    }

    pub(crate) fn session_health(&self) -> CancellationToken {
        self.closed.clone()
    }

    fn invalidate<T>(&self, result: Result<T>) -> Result<T> {
        result.map_err(|error| {
            self.closed.cancel();
            let _ = self.reader.get_ref().shutdown();
            error.context(IpcTransportFailure)
        })
    }

    /// Read the next terminal response, consuming liveness notifications.
    pub fn read_one_response(&mut self) -> Result<Response> {
        loop {
            let frame = self.read_frame();
            match self.invalidate(frame)? {
                Response::CompileProgress(activity) => {
                    debug!(
                        "compile request {} {:?}, phase age {} ms, job {:?}, worker {:?}",
                        activity.id,
                        activity.phase,
                        activity.phase_age_ms,
                        activity.distributed_job,
                        activity.worker
                    );
                }
                Response::Heartbeat => {}
                Response::CompileAborted(reason) | Response::RequestAborted(reason) => {
                    return self.invalidate(Err(anyhow!("server abandoned request: {reason}")));
                }
                other => return Ok(other),
            }
        }
    }

    /// Read a single `Response` from the server.
    fn read_frame(&mut self) -> Result<Response> {
        trace!("ServerConnection::read_one_response");
        let mut bytes = [0; 4];
        self.reader.read_exact(&mut bytes).map_err(|e| {
            let context = if e.kind() == io::ErrorKind::UnexpectedEof {
                "the sccache server closed the connection without replying; \
                 it may have crashed, check its log (SCCACHE_ERROR_LOG)"
            } else {
                "Failed to read response header"
            };
            anyhow::Error::new(e).context(context)
        })?;
        let len = BigEndian::read_u32(&bytes);
        trace!("Should read {len} more bytes");
        let mut data = vec![0; len as usize];
        self.reader.read_exact(&mut data)?;
        trace!("Done reading");
        Ok(bincode::deserialize(&data)?)
    }
}

/// IPC failures invalidate the session rather than masquerading as a cache
/// miss or a safe distributed retry.
#[derive(Debug)]
pub(crate) struct IpcTransportFailure;

impl std::fmt::Display for IpcTransportFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("managed IPC session is no longer usable")
    }
}

impl std::error::Error for IpcTransportFailure {}

pub type SharedConnection = Arc<Mutex<ServerConnection>>;

struct AbortTransfer {
    socket: Box<dyn Connection>,
    closed: CancellationToken,
    armed: bool,
}

impl Drop for AbortTransfer {
    fn drop(&mut self) {
        if self.armed {
            self.closed.cancel();
            let _ = self.socket.shutdown();
        }
    }
}

pub async fn connection_task<T: Send + 'static>(
    connection: SharedConnection,
    task: impl FnOnce(&mut ServerConnection) -> Result<T> + Send + 'static,
) -> Result<T> {
    // Waiting for the lock is itself cancellable and occupies no blocking
    // thread. Only the owner of a transaction may invalidate its socket.
    let mut connection = connection.lock_owned().await;
    ensure!(!connection.closed.is_cancelled(), IpcTransportFailure);
    let mut abort = AbortTransfer {
        socket: connection
            .reader
            .get_ref()
            .try_clone()
            .context(IpcTransportFailure)?,
        closed: connection.closed.clone(),
        armed: true,
    };
    let result = tokio::task::spawn_blocking(move || {
        ensure!(!connection.closed.is_cancelled(), IpcTransportFailure);
        task(&mut connection)
    })
    .await
    .context(IpcTransportFailure)?;
    abort.armed = false;
    result
}

/// Establish a TCP connection to an sccache server listening on `addr`.
pub fn connect_to_server(addr: &crate::net::SocketAddr) -> io::Result<ServerConnection> {
    trace!("connect_to_server({addr})");
    let conn = crate::net::connect(addr)?;
    ServerConnection::new(conn)
}

/// Attempt to establish a TCP connection to an sccache server listening on `addr`.
///
/// If the connection fails, retry a few times.
pub fn connect_with_retry(addr: &crate::net::SocketAddr) -> io::Result<ServerConnection> {
    trace!("connect_with_retry({addr})");
    // TODOs:
    // * Pass the server Child in here, so we can stop retrying
    //   if the process exited.
    // * Send a pipe handle to the server process so it can notify
    //   us once it starts the server instead of us polling.
    let backoff = backon::ConstantBuilder::default()
        .with_delay(std::time::Duration::from_millis(500))
        .with_max_times(10);
    match (|| connect_to_server(addr)).retry(backoff).call() {
        Ok(conn) => Ok(conn),
        Err(e) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("Connection to server timed out: {e:?}"),
        )),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn heartbeat_frames_do_not_replace_terminal_response() -> Result<()> {
        use crate::server::activity::{CompileActivity, Phase};
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let stream = TcpStream::connect(listener.local_addr()?)?;
        let (mut server, _) = listener.accept()?;
        let progress = CompileActivity {
            id: "generation-7".into(),
            client_pid: 123,
            output: Some("crate".into()),
            compiler: "rustc".into(),
            cwd: "/build".into(),
            phase: Phase::RunDistributed,
            cancellation_requested: false,
            elapsed_ms: 15000,
            phase_age_ms: 15000,
            waiting_for_jobserver: 0,
            compiler_children: 0,
            distributed_job: Some(42),
            worker: Some("worker".into()),
        };
        util::write_length_prefixed_bincode(
            &mut server,
            Response::CompileProgress(progress.clone()),
        )?;
        util::write_length_prefixed_bincode(&mut server, Response::CompileProgress(progress))?;
        util::write_length_prefixed_bincode(&mut server, Response::Heartbeat)?;
        util::write_length_prefixed_bincode(
            &mut server,
            Response::CompileFinished(crate::protocol::CompileFinished {
                retcode: Some(0),
                ..Default::default()
            }),
        )?;
        let mut conn = ServerConnection::new(Box::new(stream))?;
        let Response::CompileFinished(finished) = conn.read_one_response()? else {
            bail!("heartbeat replaced terminal response");
        };
        assert_eq!(finished.retcode, Some(0));
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_transaction_closes_socket_and_releases_lock() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let stream = TcpStream::connect(listener.local_addr()?)?;
        let (peer, _) = listener.accept().await?;
        let connection = Arc::new(Mutex::new(ServerConnection::new(Box::new(stream))?));
        let closed = connection.lock().await.session_health();
        let (started, running) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(connection_task(Arc::clone(&connection), move |conn| {
            let _ = started.send(());
            conn.read_one_response()
        }));
        running.await?;
        task.abort();
        assert!(
            task.await
                .expect_err("transaction must be cancelled")
                .is_cancelled()
        );
        let next = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connection_task(connection, |conn| conn.request(Request::GetStats)),
        )
        .await?;
        assert!(
            next.expect_err("closed session must not be reused")
                .is::<IpcTransportFailure>()
        );
        assert!(closed.is_cancelled());
        peer.readable().await?;
        assert_eq!(peer.try_read(&mut [0; 1])?, 0);
        Ok(())
    }

    #[test]
    fn silent_open_connection_has_bounded_read() -> Result<()> {
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let stream = TcpStream::connect(listener.local_addr()?)?;
        let (_server, _) = listener.accept()?;
        let mut conn = ServerConnection::new(Box::new(stream))?;
        conn.reader
            .get_ref()
            .set_io_timeout(Duration::from_millis(100))?;
        let error = conn
            .read_one_response()
            .expect_err("silent open socket must time out");
        assert!(matches!(
            error.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
        ));
        Ok(())
    }

    #[test]
    fn test_read_one_response_server_hung_up() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let stream = TcpStream::connect(listener.local_addr()?)?;
        drop(listener.accept()?);
        let mut conn = ServerConnection::new(Box::new(stream))?;
        let err = conn.read_one_response().unwrap_err();
        assert_eq!(
            err.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(io::ErrorKind::UnexpectedEof)
        );
        assert!(
            format!("{err:#}")
                .contains("the sccache server closed the connection without replying"),
            "{err:#}"
        );
        Ok(())
    }
}
