//! Shared asynchronous CAS ingestion and CPU codec executor.

use crate::build_runtime::{
    BlobEncoding, BlobRef, NativeStore, NativeUpload, PhysicalStager, StagedBlob, TransferMeter,
};
use anyhow::{Context, Result};
use std::{future::Future, sync::OnceLock};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Process-wide CPU executor. Queued tasks are bounded by admitted requests,
/// and no blocking I/O thread waits for a codec task. Cancellation drops the
/// returned state if the receiver has gone away.
pub(in crate::dist) async fn compute<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    static POOL: OnceLock<
        std::result::Result<rayon_core::ThreadPool, rayon_core::ThreadPoolBuildError>,
    > = OnceLock::new();
    let pool = POOL
        .get_or_init(|| {
            rayon_core::ThreadPoolBuilder::new()
                .num_threads(crate::util::num_cpus())
                .thread_name(|index| format!("sccache-codec-{index}"))
                .build()
        })
        .as_ref()
        .map_err(|error| anyhow::anyhow!("cannot initialize codec pool: {error}"))?;
    let (send, receive) = tokio::sync::oneshot::channel();
    pool.spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
            .unwrap_or_else(|_| Err(anyhow::anyhow!("native codec task panicked")));
        let _ = send.send(result);
    });
    receive.await.context("native codec task lost")?
}

pub(in crate::dist) trait BlobIngress: Send + Sized + 'static {
    fn requires_codec_pool(&self) -> bool;
    fn encode_pending(&mut self, bytes: &[u8]) -> Result<()>;
    fn finish_encoding(&mut self) -> Result<()>;
    fn flush_pending_async(self) -> impl Future<Output = Result<Self>> + Send;
    fn finish_file_async(self) -> impl Future<Output = Result<Self>> + Send;
}

macro_rules! blob_ingress {
    ($type:ty) => {
        impl BlobIngress for $type {
            fn requires_codec_pool(&self) -> bool {
                <$type>::requires_codec_pool(self)
            }
            fn encode_pending(&mut self, bytes: &[u8]) -> Result<()> {
                <$type>::encode_pending(self, bytes)
            }
            fn finish_encoding(&mut self) -> Result<()> {
                <$type>::finish_encoding(self)
            }
            async fn flush_pending_async(self) -> Result<Self> {
                <$type>::flush_pending_async(self).await
            }
            async fn finish_file_async(self) -> Result<Self> {
                <$type>::finish_file_async(self).await
            }
        }
    };
}
blob_ingress!(NativeUpload);
blob_ingress!(PhysicalStager);

pub(in crate::dist) async fn receive_blob<T: BlobIngress>(
    mut upload: T,
    input: &mut (impl AsyncRead + Unpin + Send),
    mut meter: Option<TransferMeter>,
    read_error: impl Fn(std::io::Error) -> anyhow::Error + Send + Sync,
) -> Result<T> {
    // Batch at the CAS frame size rather than dispatch work for each TLS record.
    let mut buffer = vec![0; 256 * 1024];
    let codec_pool = upload.requires_codec_pool();
    loop {
        let mut count = 0;
        while count < buffer.len() {
            let read = input
                .read(&mut buffer[count..])
                .await
                .map_err(&read_error)?;
            if read == 0 {
                if let Some(meter) = &mut meter {
                    meter.eof();
                }
                break;
            }
            count += read;
            if let Some(meter) = &mut meter {
                meter.observe(read as u64);
            }
        }
        if count == 0 {
            break;
        }
        if codec_pool {
            (upload, buffer) = compute(move || {
                upload.encode_pending(&buffer[..count])?;
                Ok((upload, buffer))
            })
            .await?;
        } else {
            upload.encode_pending(&buffer[..count])?;
        }
        upload = upload.flush_pending_async().await?;
        if count < buffer.len() {
            break;
        }
    }
    if codec_pool {
        upload = compute(move || {
            upload.finish_encoding()?;
            Ok(upload)
        })
        .await?;
    } else {
        upload.finish_encoding()?;
    }
    upload.finish_file_async().await
}

/// Bounded independent acquisitions, with no thread per transfer. After an
/// error, stop submitting new work but drain already owned operations.
#[cfg(target_os = "linux")]
pub(super) async fn map_bounded<T, U, F, Fut, I>(
    requests: I,
    width: std::num::NonZeroUsize,
    mut operation: F,
) -> Result<Vec<U>>
where
    T: Send,
    U: Send,
    I: IntoIterator<Item = T> + Send,
    I::IntoIter: Send,
    F: FnMut(T) -> Fut + Send,
    Fut: Future<Output = Result<U>> + Send,
{
    use futures::{StreamExt, stream::FuturesUnordered};
    let mut requests = requests.into_iter();
    let mut active = FuturesUnordered::new();
    for request in requests.by_ref().take(width.get()) {
        active.push(operation(request));
    }
    let mut values = Vec::new();
    let mut failure = None;
    while let Some(result) = active.next().await {
        match result {
            Ok(value) => values.push(value),
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
        if failure.is_none()
            && let Some(request) = requests.next()
        {
            active.push(operation(request));
        }
    }
    failure.map_or(Ok(values), Err)
}

/// Receive into the normal CAS staging reservation, not a second archive.
pub(in crate::dist) async fn stage_blob(
    store: NativeStore,
    blob: BlobRef,
    encoding: BlobEncoding,
    input: &mut (impl AsyncRead + Unpin + Send),
    meter: Option<TransferMeter>,
) -> Result<StagedBlob> {
    let staging =
        tokio::task::spawn_blocking(move || store.prepare_physical(blob, encoding)).await??;
    let staging = receive_blob(staging, input, meter, anyhow::Error::from).await?;
    tokio::task::spawn_blocking(move || staging.finish()).await?
}
