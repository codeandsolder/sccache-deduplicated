//! Shared completion-based filesystem executor for CAS transport. Each
//! operation owns its buffers, file handles and admission state until the
//! completion arrives, even if the waiting network future is cancelled.

use std::{
    fs::File,
    future::Future,
    io,
    sync::{Arc, OnceLock, mpsc as std_mpsc},
    thread,
};

use anyhow::{Context, Result};
use compio_buf::{BufResult, IntoInner, IoBuf};
use compio_driver::op::{ReadAt, Sync, WriteAt};
use tokio::sync::{Semaphore, mpsc, oneshot};

const MAX_IN_FLIGHT: usize = 256;
type Command = Box<dyn FnOnce() + Send>;

struct DiskExecutor {
    commands: mpsc::Sender<Command>,
    slots: Arc<Semaphore>,
}

impl DiskExecutor {
    fn start() -> Result<Self> {
        let (commands, mut receiver) = mpsc::channel::<Command>(MAX_IN_FLIGHT);
        let (ready, started) = std_mpsc::sync_channel(1);
        thread::Builder::new()
            .name("sccache-disk".into())
            .spawn(move || {
                let runtime = match compio_runtime::Runtime::new() {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                log::info!(
                    "CAS filesystem completion driver: {:?}",
                    runtime.driver_type()
                );
                if ready.send(Ok(())).is_err() {
                    return;
                }
                runtime.block_on(async move {
                    while let Some(command) = receiver.recv().await {
                        command();
                    }
                });
            })?;
        started.recv().context("CAS disk executor startup lost")??;
        Ok(Self {
            commands,
            slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
        })
    }
}

fn executor() -> Result<&'static DiskExecutor> {
    static EXECUTOR: OnceLock<std::result::Result<DiskExecutor, String>> = OnceLock::new();
    EXECUTOR
        .get_or_init(|| DiskExecutor::start().map_err(|error| format!("{error:#}")))
        .as_ref()
        .map_err(|error| anyhow::anyhow!("cannot initialize CAS disk executor: {error}"))
}

/// Start the shared filesystem completion driver before serving traffic.
///
/// # Errors
/// Returns an error if no completion driver can be initialized.
pub fn initialize_async_disk() -> Result<()> {
    executor()?;
    Ok(())
}

/// Construct the future on the disk thread. Only the operation's owned
/// inputs and completed result cross the thread boundary.
pub async fn run<T: Send + 'static, F: Future<Output = Result<T>> + 'static>(
    operation: impl FnOnce() -> F + Send + 'static,
) -> Result<T> {
    let executor = executor()?;
    let permit = Arc::clone(&executor.slots).acquire_owned().await?;
    let (send, receive) = oneshot::channel();
    executor
        .commands
        .send(Box::new(move || {
            compio_runtime::spawn(async move {
                let _permit = permit;
                let result = operation().await;
                let _ = send.send(result);
            })
            .detach();
        }))
        .await
        .map_err(|_| anyhow::anyhow!("CAS disk executor stopped"))?;
    receive.await.context("CAS disk operation lost")?
}

fn checked_offset(offset: u64, done: usize) -> io::Result<u64> {
    offset
        .checked_add(u64::try_from(done).map_err(io::Error::other)?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "CAS file offset overflow"))
}

// Call only from the completion runtime. A bounded initialized Vec avoids
// exposing uninitialized memory, and sliced ownership supports short I/O.
#[expect(
    clippy::future_not_send,
    reason = "runs only on the thread-local Compio completion driver"
)]
async fn read_exact(file: Arc<File>, offset: u64, count: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0; count];
    let mut done = 0;
    while done < count {
        let position = checked_offset(offset, done)?;
        let BufResult(result, slice) = compio_runtime::submit(ReadAt::new(
            Arc::clone(&file),
            position,
            buffer.slice(done..count),
        ))
        .await
        .into_inner();
        buffer = slice.into_inner();
        match result {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => done += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(buffer)
}

/// Read an exact physical file range on the completion driver. The retained
/// value (e.g. a request admission permit) survives cancellation until I/O
/// completes, and is returned alongside the data.
///
/// # Errors
/// Returns an error for a truncated file, invalid range, or I/O failure.
pub async fn read_file_at<T: Send + 'static>(
    file: Arc<File>,
    offset: u64,
    count: usize,
    retained: T,
) -> Result<(Vec<u8>, T)> {
    run(move || async move {
        let bytes = read_exact(file, offset, count).await?;
        Ok((bytes, retained))
    })
    .await
}

#[expect(
    clippy::future_not_send,
    reason = "runs only on the thread-local Compio completion driver"
)]
pub async fn write_all(file: Arc<File>, offset: u64, mut buffer: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut done = 0;
    while done < buffer.len() {
        let position = checked_offset(offset, done)?;
        let BufResult(result, slice) = compio_runtime::submit(WriteAt::new(
            Arc::clone(&file),
            position,
            buffer.slice(done..),
        ))
        .await
        .into_inner();
        buffer = slice.into_inner();
        match result {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => done += written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(buffer)
}

#[expect(
    clippy::future_not_send,
    reason = "runs only on the thread-local Compio completion driver"
)]
pub async fn sync_all(file: Arc<File>) -> io::Result<()> {
    compio_runtime::submit(Sync::new(file, false)).await.0?;
    Ok(())
}

/// Seal an immutable staging file before it enters the durable index.
#[expect(
    clippy::future_not_send,
    reason = "runs only on the thread-local Compio completion driver"
)]
pub async fn seal_file(file: Arc<File>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata_file = Arc::clone(&file);
    compio_runtime::spawn_blocking(move || {
        metadata_file.set_permissions(std::fs::Permissions::from_mode(0o400))
    })
    .await
    .map_err(|error| anyhow::anyhow!("staging permission task failed: {error:?}"))??;
    sync_all(file).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn positional_io_preserves_exact_bytes_and_short_read() -> Result<()> {
        let driver = run(|| async {
            Ok(compio_runtime::Runtime::with_current(
                compio_runtime::Runtime::driver_type,
            ))
        })
        .await?;
        eprintln!("CAS filesystem completion driver: {driver:?}");
        let file = Arc::new(tempfile::tempfile()?);
        let expected: Vec<_> = (0..262_181_u32).map(|i| i.to_le_bytes()[0]).collect();
        let written = expected.clone();
        let writer = Arc::clone(&file);
        run(move || async move {
            let buffer = write_all(Arc::clone(&writer), 17, written).await?;
            assert_eq!(buffer.len(), 262_181);
            sync_all(writer).await?;
            Ok(())
        })
        .await?;
        let (actual, retained) = read_file_at(Arc::clone(&file), 17, expected.len(), 42).await?;
        assert_eq!(retained, 42);
        assert_eq!(actual, expected);
        assert!(
            read_file_at(file, 17, expected.len() + 1, ())
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_does_not_release_state_before_completion() -> Result<()> {
        struct Retained(Option<oneshot::Sender<()>>);
        impl Drop for Retained {
            fn drop(&mut self) {
                if let Some(done) = self.0.take() {
                    let _ = done.send(());
                }
            }
        }
        let (started, wait_started) = oneshot::channel();
        let (resume, wait_resume) = oneshot::channel();
        let (done, mut wait_done) = oneshot::channel();
        let retained = Retained(Some(done));
        let task = tokio::spawn(run(move || async move {
            let _retained = retained;
            let _ = started.send(());
            wait_resume.await?;
            Ok(())
        }));
        wait_started.await?;
        task.abort();
        assert!(wait_done.try_recv().is_err());
        resume
            .send(())
            .map_err(|()| anyhow::anyhow!("disk task stopped early"))?;
        tokio::time::timeout(std::time::Duration::from_secs(5), wait_done).await??;
        Ok(())
    }
}
