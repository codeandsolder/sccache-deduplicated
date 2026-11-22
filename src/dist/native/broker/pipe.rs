//! Bounded byte stream between the Tokio IPC request handler and the
//! blocking native HTTP transaction. No temporary files are involved.

use std::{
    io::{self, Cursor, Read, Write},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use tokio::{runtime::Handle, sync::mpsc, task::JoinHandle};

use crate::{
    client::ServerConnection,
    protocol::{TransferReply, TransferRequest},
};

type Sender = mpsc::Sender<Vec<u8>>;
type Receiver = mpsc::Receiver<Vec<u8>>;

fn io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

#[derive(Clone)]
struct Deadline {
    handle: Handle,
    until: Instant,
}

impl Deadline {
    fn remaining(&self) -> io::Result<Duration> {
        self.until
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native namespace action deadline elapsed",
                )
            })
    }
}

struct Reader {
    incoming: Receiver,
    bytes: Cursor<Vec<u8>>,
    deadline: Deadline,
}

impl Read for Reader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.bytes.read(output)?;
        if count != 0 || output.is_empty() {
            return Ok(count);
        }
        let remaining = self.deadline.remaining()?;
        let next = self
            .deadline
            .handle
            .block_on(async { tokio::time::timeout(remaining, self.incoming.recv()).await })
            .map_err(io_error)?;
        match next {
            Some(bytes) => {
                self.bytes = Cursor::new(bytes);
                self.bytes.read(output)
            }
            None => Ok(0),
        }
    }
}

#[derive(Clone)]
struct SharedReader(Arc<Mutex<Reader>>);

impl Read for SharedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.0.lock().map_err(io_error)?.read(output)
    }
}

pub struct DaemonStream {
    reader: SharedReader,
    outgoing: Sender,
    deadline: Deadline,
    chunk_bytes: usize,
}

impl DaemonStream {
    pub const fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }

    pub fn blob_reader(&self, size: u64) -> impl Read + Send + 'static {
        self.reader.clone().take(size)
    }
}

impl Read for DaemonStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.reader.read(output)
    }
}

impl Write for DaemonStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(self.chunk_bytes);
        if count == 0 {
            return Ok(0);
        }
        let remaining = self.deadline.remaining()?;
        self.deadline
            .handle
            .block_on(async {
                tokio::time::timeout(remaining, self.outgoing.send(bytes[..count].to_vec())).await
            })
            .map_err(io_error)?
            .map_err(io_error)?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The async half of a single scoped native transaction. Dropping either
/// end unblocks its peer; all waits also have the action deadline.
pub struct NativeExchange {
    incoming: Receiver,
    outgoing: Sender,
    deadline: Instant,
    task: Option<JoinHandle<Result<()>>>,
    chunk_bytes: usize,
}

impl NativeExchange {
    pub fn start(
        chunk_bytes: usize,
        timeout: Duration,
        operation: impl FnOnce(DaemonStream) -> Result<()> + Send + 'static,
    ) -> Result<Self> {
        ensure!(
            chunk_bytes > 0 && !timeout.is_zero(),
            "invalid native stream limits"
        );
        let until = Instant::now()
            .checked_add(timeout)
            .context("native stream deadline overflow")?;
        let deadline = Deadline {
            handle: Handle::current(),
            until,
        };
        // A bounded transport queue, not a staging cache.
        let (outgoing, reader) = mpsc::channel(2);
        let (writer, incoming) = mpsc::channel(2);
        let stream = DaemonStream {
            reader: SharedReader(Arc::new(Mutex::new(Reader {
                incoming: reader,
                bytes: Cursor::new(Vec::new()),
                deadline: deadline.clone(),
            }))),
            outgoing: writer,
            deadline,
            chunk_bytes,
        };
        let task = tokio::task::spawn_blocking(move || operation(stream));
        Ok(Self {
            incoming,
            outgoing,
            deadline: until,
            task: Some(task),
            chunk_bytes,
        })
    }

    pub async fn write(&mut self, bytes: Vec<u8>) -> Result<()> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= self.chunk_bytes,
            "invalid native stream chunk"
        );
        if tokio::time::timeout_at(self.deadline.into(), self.outgoing.send(bytes))
            .await?
            .is_err()
        {
            self.join().await?;
            anyhow::bail!("native daemon stopped reading input");
        }
        Ok(())
    }

    pub async fn read(&mut self) -> Result<Vec<u8>> {
        if let Some(bytes) =
            tokio::time::timeout_at(self.deadline.into(), self.incoming.recv()).await?
        {
            return Ok(bytes);
        }
        self.join().await?;
        anyhow::bail!("native daemon closed the action stream");
    }

    async fn join(&mut self) -> Result<()> {
        if let Some(task) = self.task.take() {
            tokio::time::timeout_at(self.deadline.into(), task).await???;
        }
        Ok(())
    }

    pub async fn finish(mut self) -> Result<()> {
        // Close input to the actor and reject a premature End rather than
        // holding either side of the bounded stream open indefinitely.
        self.incoming.close();
        drop(self.outgoing);
        if let Some(task) = self.task.take() {
            tokio::time::timeout_at(self.deadline.into(), task).await???;
        }
        Ok(())
    }
}

pub(super) struct CallerStream<'a> {
    connection: &'a mut ServerConnection,
    chunk_bytes: usize,
    bytes: Cursor<Vec<u8>>,
}

impl<'a> CallerStream<'a> {
    pub(super) const fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }

    pub(super) const fn new(connection: &'a mut ServerConnection, chunk_bytes: usize) -> Self {
        Self {
            connection,
            chunk_bytes,
            bytes: Cursor::new(Vec::new()),
        }
    }
}

impl Read for CallerStream<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.bytes.read(output)?;
        if count != 0 || output.is_empty() {
            return Ok(count);
        }
        let response = self
            .connection
            .transfer(TransferRequest::NativeRead)
            .map_err(io_error)?;
        let TransferReply::Chunk(chunk) = response else {
            return Err(io_error("unexpected native stream response"));
        };
        if chunk.is_empty() || chunk.len() > self.chunk_bytes {
            return Err(io_error("invalid native stream response length"));
        }
        self.bytes = Cursor::new(chunk);
        self.bytes.read(output)
    }
}

impl Write for CallerStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.chunk_bytes.min(bytes.len());
        if count == 0 {
            return Ok(0);
        }
        let response = self
            .connection
            .transfer(TransferRequest::NativeWrite(bytes[..count].to_vec()))
            .map_err(io_error)?;
        if !matches!(response, TransferReply::Ack) {
            return Err(io_error("unexpected native stream write response"));
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
