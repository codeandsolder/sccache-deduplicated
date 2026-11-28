//! Connection-owned blob transport. Paths returned by a daemon are never
//! meaningful in a caller's potentially different filesystem namespace.
use crate::errors::{Context, Result, bail};
use crate::protocol::{TransferReply, TransferRequest};
use anyhow::ensure;

pub(super) struct TransferSession {
    chunk_bytes: usize,
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    native: Option<std::sync::Arc<crate::compiler::NativeCompilerClient>>,
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    native_exchange: Option<crate::dist::native::broker::NativeExchange>,
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    intermediate: Option<std::sync::Arc<crate::dist::native::result_session::NativeResultSession>>,
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    intermediate_read: Option<(tokio::fs::File, u64)>,
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    uid: u32,
}

impl TransferSession {
    pub(super) fn new(chunk_bytes: usize) -> Self {
        Self {
            chunk_bytes,
            #[cfg(all(feature = "dist-client", target_os = "linux"))]
            native: None,
            #[cfg(all(feature = "dist-client", target_os = "linux"))]
            native_exchange: None,
            #[cfg(all(feature = "dist-client", target_os = "linux"))]
            intermediate: None,
            #[cfg(all(feature = "dist-client", target_os = "linux"))]
            intermediate_read: None,
            #[cfg(all(feature = "dist-client", target_os = "linux"))]
            uid: 0,
        }
    }

    pub(super) const fn request_budget(
        &self,
        request: &super::SccacheRequest,
        limits: super::activity::CompileLimits,
    ) -> std::time::Duration {
        let _ = request;
        limits.budget(super::activity::Phase::IdentifyToolchain)
    }

    pub(super) const fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }

    pub(super) fn initialize_distribution(&mut self, client: &super::DistClientContainer) {
        #[cfg(all(feature = "dist-client", target_os = "linux"))]
        self.native.clone_from(&client.native);
        let _ = client;
    }

    pub(super) fn native_policy(&self) -> Option<crate::protocol::NativeNamespacePolicy> {
        #[cfg(all(feature = "dist-client", target_os = "linux"))]
        {
            self.native
                .as_ref()
                .map(|client| client.namespace_policy().clone())
        }
        #[cfg(not(all(feature = "dist-client", target_os = "linux")))]
        {
            None
        }
    }

    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    pub(super) const fn set_uid(&mut self, uid: u32) {
        self.uid = uid;
    }

    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    pub(super) async fn handle_intermediate(
        &mut self,
        request: TransferRequest,
        client: Option<std::sync::Arc<crate::compiler::NativeCompilerClient>>,
    ) -> Result<TransferReply> {
        use tokio::io::AsyncReadExt;
        let client = client.context("native distribution unavailable")?;
        let uid = self.uid;
        match request {
            TransferRequest::IntermediateOpen => {
                ensure!(
                    self.intermediate.is_none(),
                    "intermediate session already open"
                );
                let (token, session) =
                    tokio::task::spawn_blocking(move || client.open_intermediate(uid)).await??;
                self.intermediate = Some(session);
                Ok(TransferReply::IntermediateOpened(token))
            }
            TransferRequest::IntermediateAuthorize { session, blob } => {
                client.intermediate(uid, session)?.authorize(blob)?;
                Ok(TransferReply::Ack)
            }
            TransferRequest::IntermediateRead { session, blob } => {
                ensure!(
                    self.intermediate_read.is_none(),
                    "intermediate read already active"
                );
                let group = client.intermediate(uid, session)?;
                let file = tokio::task::spawn_blocking(move || group.read(blob)).await??;
                if blob.size != 0 {
                    self.intermediate_read = Some((tokio::fs::File::from_std(file), blob.size));
                }
                Ok(TransferReply::ReadStarted(Some(blob.size)))
            }
            TransferRequest::IntermediateChunk => {
                let (file, remaining) = self
                    .intermediate_read
                    .as_mut()
                    .context("no intermediate read active")?;
                let size = usize::try_from((*remaining).min(self.chunk_bytes as u64))?;
                ensure!(size != 0, "invalid intermediate chunk limit");
                let mut bytes = vec![0; size];
                file.read_exact(&mut bytes).await?;
                *remaining -= size as u64;
                if *remaining == 0 {
                    self.intermediate_read = None;
                }
                Ok(TransferReply::Chunk(bytes))
            }
            _ => bail!("invalid intermediate request"),
        }
    }

    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    async fn handle_native(&mut self, request: TransferRequest) -> Result<TransferReply> {
        use crate::dist::native::broker::NativeExchange;
        use std::time::Duration;

        match request {
            TransferRequest::NativeStart => {
                ensure!(
                    self.native_exchange.is_none(),
                    "native action already active"
                );
                let client = self
                    .native
                    .clone()
                    .context("native namespace handshake required")?;
                let timeout = Duration::from_secs(client.namespace_policy().build_timeout_secs);
                let uid = self.uid;
                self.native_exchange = Some(NativeExchange::start(
                    self.chunk_bytes,
                    timeout,
                    move |stream| client.serve_namespace(stream, uid),
                )?);
                Ok(TransferReply::Ack)
            }
            TransferRequest::NativeWrite(bytes) => {
                self.native_exchange
                    .as_mut()
                    .context("no native action active")?
                    .write(bytes)
                    .await?;
                Ok(TransferReply::Ack)
            }
            TransferRequest::NativeRead => Ok(TransferReply::Chunk(
                self.native_exchange
                    .as_mut()
                    .context("no native action active")?
                    .read()
                    .await?,
            )),
            TransferRequest::NativeEnd => {
                self.native_exchange
                    .take()
                    .context("no native action active")?
                    .finish()
                    .await?;
                Ok(TransferReply::Ack)
            }
            TransferRequest::Abort => {
                self.abort();
                Ok(TransferReply::Ack)
            }
            _ => bail!("invalid native namespace transfer"),
        }
    }

    pub(super) async fn handle(&mut self, request: TransferRequest) -> Result<TransferReply> {
        let reply = self.handle_request(request).await;
        if reply.is_err() {
            self.abort();
        }
        reply
    }

    fn abort(&mut self) {
        #[cfg(all(feature = "dist-client", target_os = "linux"))]
        {
            self.native_exchange = None;
            self.intermediate_read = None;
        }
    }

    async fn handle_request(&mut self, request: TransferRequest) -> Result<TransferReply> {
        ensure!(
            self.chunk_bytes > 0,
            "IPC frame limit is too small for namespace transfers"
        );
        #[cfg(all(feature = "dist-client", target_os = "linux"))]
        if self.native.is_some() {
            return self.handle_native(request).await;
        }
        let _ = request;
        bail!("native scheduler configuration required")
    }
}
