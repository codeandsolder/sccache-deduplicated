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
use std::sync::{Arc, Mutex};

/// A connection to an sccache server.
pub struct ServerConnection {
    /// A reader for the socket connected to the server.
    reader: BufReader<Box<dyn Connection>>,
    /// A writer for the socket connected to the server.
    writer: BufWriter<Box<dyn Connection>>,
}

impl ServerConnection {
    /// Create a new connection using `stream`.
    pub fn new(conn: Box<dyn Connection>) -> io::Result<Self> {
        let write_conn = conn.try_clone()?;
        Ok(Self {
            reader: BufReader::new(conn),
            writer: BufWriter::new(write_conn),
        })
    }

    /// Send `request` to the server, read and return a `Response`.
    pub fn request(&mut self, request: Request) -> Result<Response> {
        trace!("ServerConnection::request");
        util::write_length_prefixed_bincode(&mut self.writer, request)?;
        trace!("ServerConnection::request: sent request");
        self.read_one_response()
    }

    pub(crate) fn transfer(&mut self, request: TransferRequest) -> Result<TransferReply> {
        match self.request(Request::Transfer(request))? {
            Response::Transfer(reply) => reply.map_err(|error| anyhow!("{error}")),
            other => bail!("unexpected transfer response: {other:?}"),
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
        if result.is_err() {
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
        if result.is_err() {
            let _ = self.transfer(TransferRequest::Abort);
        }
        result
    }

    /// Read a single `Response` from the server.
    pub fn read_one_response(&mut self) -> Result<Response> {
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

pub type SharedConnection = Arc<Mutex<ServerConnection>>;

pub async fn connection_task<T: Send + 'static>(
    connection: SharedConnection,
    task: impl FnOnce(&mut ServerConnection) -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(move || {
        let mut connection = connection
            .lock()
            .map_err(|_| anyhow!("IPC connection lock poisoned"))?;
        task(&mut connection)
    })
    .await
    .context("IPC connection task failed")?
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
    fn test_read_one_response_server_hung_up() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        drop(listener.accept().unwrap());
        let mut conn = ServerConnection::new(Box::new(stream)).unwrap();
        let err = conn.read_one_response().unwrap_err();
        assert!(
            err.to_string()
                .starts_with("the sccache server closed the connection without replying"),
            "{err:#}"
        );
    }
}
