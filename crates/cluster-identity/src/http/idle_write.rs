//! An idle deadline for stalled TLS writes, not a limit on stream duration.
use std::{
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Sleep, sleep},
};

pub(super) struct IdleWrite<T> {
    io: T,
    timeout: Duration,
    deadline: Option<Pin<Box<Sleep>>>,
}

impl<T> IdleWrite<T> {
    pub(super) const fn new(io: T, timeout: Duration) -> Self {
        Self {
            io,
            timeout,
            deadline: None,
        }
    }
}

impl<T: Unpin> IdleWrite<T> {
    fn write_op<R>(
        &mut self,
        cx: &mut Context<'_>,
        op: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        match op(Pin::new(&mut self.io), cx) {
            Poll::Ready(result) => {
                self.deadline = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                let deadline = self
                    .deadline
                    .get_or_insert_with(|| Box::pin(sleep(self.timeout)));
                if deadline.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "cluster response write idle",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleWrite<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleWrite<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_op(cx, |io, cx| io.poll_write(cx, buf))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.write_op(cx, |io, cx| io.poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_op(cx, AsyncWrite::poll_flush)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_op(cx, AsyncWrite::poll_shutdown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn progress_resets_deadline_and_stall_times_out() -> anyhow::Result<()> {
        let (sender, mut receiver) = tokio::io::duplex(1);
        let mut stream = IdleWrite::new(sender, Duration::from_millis(50));
        stream.write_all(b"a").await?;
        assert_eq!(receiver.read_u8().await?, b'a');
        stream.write_all(b"b").await?;
        let error = stream.write_all(b"c").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(receiver.read_u8().await?, b'b');
        Ok(())
    }
}
