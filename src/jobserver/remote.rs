//! One authenticated, private socket per credential-isolated executor.
//! No daemon jobserver file descriptor is exposed to compiler subprocesses.
use super::Client;
use anyhow::{Context, Result, ensure};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::{mpsc, oneshot},
};

const ACQUIRE: u8 = 1;
const GRANTED: u8 = 2;
const RELEASE: u8 = 3;

pub(super) struct RemotePermit {
    // Dropping the sender releases the grant even when a command is cancelled.
    _release: oneshot::Sender<()>,
}

#[derive(Clone)]
pub(super) struct RemoteClient {
    requests: mpsc::Sender<oneshot::Sender<RemotePermit>>,
}

impl RemoteClient {
    pub(super) fn new(stream: std::os::unix::net::UnixStream) -> Result<Self> {
        stream.set_nonblocking(true)?;
        let stream = UnixStream::from_std(stream)?;
        let (requests, receiver) = mpsc::channel(1);
        // The task exits when the final client is dropped, or on socket failure.
        tokio::spawn(async move {
            if let Err(error) = client_loop(stream, receiver).await {
                log::debug!("private compiler permit connection closed: {error:#}");
            }
        });
        Ok(Self { requests })
    }

    pub(super) async fn acquire(&self) -> Result<RemotePermit> {
        let (send, receive) = oneshot::channel();
        self.requests
            .send(send)
            .await
            .context("compiler permit broker closed")?;
        receive.await.context("compiler permit grant lost")
    }
}

async fn client_loop(
    mut stream: UnixStream,
    mut requests: mpsc::Receiver<oneshot::Sender<RemotePermit>>,
) -> Result<()> {
    while let Some(request) = requests.recv().await {
        // Cancellation before the request was serviced does not consume a grant.
        if request.is_closed() {
            continue;
        }
        stream.write_u8(ACQUIRE).await?;
        ensure!(
            stream.read_u8().await? == GRANTED,
            "invalid compiler permit grant"
        );
        let (release, released) = oneshot::channel();
        // On a cancelled acquisition the permit is immediately dropped.
        drop(request.send(RemotePermit { _release: release }));
        let _ = released.await;
        stream.write_u8(RELEASE).await?;
    }
    Ok(())
}

pub async fn serve(stream: std::os::unix::net::UnixStream, client: Client) -> Result<()> {
    stream.set_nonblocking(true)?;
    let mut stream = UnixStream::from_std(stream)?;
    loop {
        let mut message = [0];
        if stream.read(&mut message).await? == 0 {
            return Ok(());
        }
        ensure!(message[0] == ACQUIRE, "invalid compiler permit request");
        // If the executor dies in the admission queue, cancel the pending
        // acquisition rather than waiting for an unrelated compiler to finish.
        let token = tokio::select! {
            result = stream.read(&mut message) => {
                ensure!(result? == 0, "unexpected pending compiler permit message");
                return Ok(());
            }
            result = client.acquire() => result?,
        };
        stream.write_u8(GRANTED).await?;
        let read = stream.read(&mut message).await?;
        drop(token);
        if read == 0 {
            return Ok(());
        }
        ensure!(message[0] == RELEASE, "invalid compiler permit release");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::net::UnixStream as StdStream, time::Duration};

    #[tokio::test]
    async fn disconnected_executor_cannot_leak_a_cpu_permit() -> Result<()> {
        let cpu = Client::new_num(1);
        let (socket, peer) = StdStream::pair()?;
        socket.set_nonblocking(true)?;
        let mut socket = UnixStream::from_std(socket)?;
        let broker = crate::util::spawn(serve(peer, cpu.clone()));
        socket.write_u8(ACQUIRE).await?;
        assert_eq!(socket.read_u8().await?, GRANTED);
        drop(socket);
        tokio::time::timeout(Duration::from_secs(5), broker).await???;
        drop(tokio::time::timeout(Duration::from_secs(5), cpu.acquire()).await??);
        // Disconnection before a grant is also bounded by EOF, not by the
        // running compiler's remaining duration.
        let held = cpu.acquire().await?;
        let (socket, peer) = StdStream::pair()?;
        socket.set_nonblocking(true)?;
        let mut socket = UnixStream::from_std(socket)?;
        let broker = crate::util::spawn(serve(peer, cpu.clone()));
        socket.write_u8(ACQUIRE).await?;
        drop(socket);
        tokio::time::timeout(Duration::from_secs(5), broker).await???;
        drop(held);
        drop(tokio::time::timeout(Duration::from_secs(5), cpu.acquire()).await??);
        Ok(())
    }

    #[tokio::test]
    async fn independent_executors_share_physical_permits_and_release_on_exit() -> Result<()> {
        let cpu = Client::new_num(1);
        let (a, a_peer) = StdStream::pair()?;
        let (b, b_peer) = StdStream::pair()?;
        let broker_a = crate::util::spawn(serve(a_peer, cpu.clone()));
        let broker_b = crate::util::spawn(serve(b_peer, cpu));
        let a = RemoteClient::new(a)?;
        let b = RemoteClient::new(b)?;
        let held = a.acquire().await?;
        // A second executor can exist while A runs but cannot start a second
        // physical compiler until the first grant has been returned.
        let mut waiting = Box::pin(b.acquire());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        drop(held);
        let grant = tokio::time::timeout(Duration::from_secs(5), waiting).await??;
        // A cancelled pending request must not leak the next token.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), a.acquire())
                .await
                .is_err()
        );
        drop(grant);
        let grant = tokio::time::timeout(Duration::from_secs(5), a.acquire()).await??;
        drop(grant);
        drop(a);
        drop(b);
        tokio::time::timeout(Duration::from_secs(5), broker_a).await???;
        tokio::time::timeout(Duration::from_secs(5), broker_b).await???;
        Ok(())
    }
}
