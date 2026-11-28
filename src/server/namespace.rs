//! Connection-owned blob transport. Paths returned by a daemon are never
//! meaningful in a caller's potentially different filesystem namespace.
use crate::cache::Storage;
use crate::compiler::PreprocessorCacheEntry;
use crate::errors::{Context, Result, anyhow, bail};
use crate::protocol::{StorageBlob, TransferReply, TransferRequest};
use anyhow::ensure;
use bytes::Bytes;
use std::io::Read;

fn validate_storage_key(key: &str) -> Result<()> {
    ensure!(
        key.len() == 64
            && key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid storage key"
    );
    Ok(())
}

enum Transfer {
    Idle,
    Download(Bytes),
    Upload {
        kind: StorageBlob,
        key: String,
        remaining: u64,
        data: Vec<u8>,
    },
}

pub(super) struct TransferSession {
    state: Transfer,
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
            state: Transfer::Idle,
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
                    matches!(self.state, Transfer::Idle) && self.native_exchange.is_none(),
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
            _ => bail!("legacy transfers unavailable in native namespace mode"),
        }
    }

    pub(super) async fn handle(
        &mut self,
        request: TransferRequest,
        storage: &dyn Storage,
    ) -> Result<TransferReply> {
        let reply = self.handle_request(request, storage).await;
        if reply.is_err() {
            self.abort();
        }
        reply
    }

    fn abort(&mut self) {
        self.state = Transfer::Idle;
        #[cfg(all(feature = "dist-client", target_os = "linux"))]
        {
            self.native_exchange = None;
            self.intermediate_read = None;
        }
    }

    fn begin_download(&mut self, data: Option<Bytes>) -> TransferReply {
        let len = data.as_ref().map(|data| data.len() as u64);
        self.state = data
            .filter(|data| !data.is_empty())
            .map_or(Transfer::Idle, Transfer::Download);
        TransferReply::ReadStarted(len)
    }

    fn begin_upload(&mut self, kind: StorageBlob, key: String, len: u64) -> Result<TransferReply> {
        ensure!(
            matches!(self.state, Transfer::Idle),
            "another transfer is active"
        );
        self.state = Transfer::Upload {
            kind,
            key,
            remaining: len,
            data: Vec::new(),
        };
        Ok(TransferReply::WriteStarted)
    }

    fn read_chunk(&mut self) -> Result<TransferReply> {
        let Transfer::Download(data) = &mut self.state else {
            bail!("no download is active");
        };
        let chunk = data.split_to(data.len().min(self.chunk_bytes)).to_vec();
        if data.is_empty() {
            self.state = Transfer::Idle;
        }
        Ok(TransferReply::Chunk(chunk))
    }

    fn write_chunk(&mut self, chunk: Vec<u8>) -> Result<TransferReply> {
        let Transfer::Upload {
            remaining, data, ..
        } = &mut self.state
        else {
            bail!("no upload is active");
        };
        ensure!(
            !chunk.is_empty() && chunk.len() <= self.chunk_bytes,
            "invalid upload chunk size"
        );
        let len = chunk.len() as u64;
        ensure!(len <= *remaining, "upload exceeds declared size");
        data.try_reserve(chunk.len())
            .context("upload does not fit in memory")?;
        data.extend_from_slice(&chunk);
        *remaining -= len;
        Ok(TransferReply::Ack)
    }

    async fn finish_upload(&mut self, storage: &dyn Storage) -> Result<TransferReply> {
        let Transfer::Upload {
            kind,
            key,
            remaining,
            data,
        } = std::mem::replace(&mut self.state, Transfer::Idle)
        else {
            bail!("no upload is active");
        };
        ensure!(remaining == 0, "incomplete upload");
        store_blob(storage, kind, &key, data).await
    }

    async fn handle_request(
        &mut self,
        request: TransferRequest,
        storage: &dyn Storage,
    ) -> Result<TransferReply> {
        ensure!(
            self.chunk_bytes > 0,
            "IPC frame limit is too small for namespace transfers"
        );
        #[cfg(all(feature = "dist-client", target_os = "linux"))]
        if self.native.is_some() {
            return self.handle_native(request).await;
        }
        match request {
            TransferRequest::Read { kind, key } => {
                validate_storage_key(&key)?;
                ensure!(
                    matches!(self.state, Transfer::Idle),
                    "another transfer is active"
                );
                let data = read_blob(storage, kind, &key)
                    .await
                    .with_context(|| format!("namespace storage lookup for key {key}"))
                    .inspect_err(|error| warn!("{error:#}"))?;
                Ok(self.begin_download(data))
            }
            TransferRequest::BeginWrite { kind, key, len } => {
                validate_storage_key(&key)?;
                if let Some(capacity) = storage.max_size().await? {
                    ensure!(len <= capacity, "upload exceeds cache capacity");
                }
                self.begin_upload(kind, key, len)
            }
            TransferRequest::ReadChunk => self.read_chunk(),
            TransferRequest::WriteChunk(chunk) => self.write_chunk(chunk),
            TransferRequest::FinishWrite => self.finish_upload(storage).await,
            TransferRequest::Abort => {
                self.abort();
                Ok(TransferReply::Ack)
            }
            _ => bail!("native scheduler configuration required"),
        }
    }
}

async fn read_blob(storage: &dyn Storage, kind: StorageBlob, key: &str) -> Result<Option<Bytes>> {
    match kind {
        StorageBlob::Cache => storage.get_raw(key).await,
        StorageBlob::Preprocessor => match storage.get_preprocessor_cache_entry(key).await? {
            Some(mut entry) => Ok(Some(
                tokio::task::spawn_blocking(move || -> Result<Bytes> {
                    let mut bytes = Vec::new();
                    entry.read_to_end(&mut bytes)?;
                    Ok(bytes.into())
                })
                .await??,
            )),
            None => Ok(None),
        },
    }
}

async fn store_blob(
    storage: &dyn Storage,
    kind: StorageBlob,
    key: &str,
    bytes: Vec<u8>,
) -> Result<TransferReply> {
    match kind {
        StorageBlob::Cache => {
            storage.put_raw(key, bytes.into()).await?;
        }
        StorageBlob::Preprocessor => {
            let entry = PreprocessorCacheEntry::read(&bytes).map_err(|e| anyhow!("{e}"))?;
            storage.put_preprocessor_cache_entry(key, entry).await?;
        }
    }
    Ok(TransferReply::Ack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{Cache, CacheMode, CacheRead, CacheWrite, IpcStorage};
    use crate::client::ServerConnection;
    use crate::mock_command::ProcessCommandCreator;
    use crate::server::SccacheService;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct MemoryStorage {
        entries: Mutex<HashMap<String, Bytes>>,
    }

    #[async_trait]
    impl Storage for MemoryStorage {
        async fn get(&self, key: &str) -> Result<Cache> {
            self.get_raw(key).await?.map_or(Ok(Cache::Miss), |data| {
                CacheRead::from(Cursor::new(data)).map(Cache::Hit)
            })
        }

        async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
            self.put_raw(key, entry.finish()?.into()).await
        }

        async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
            Ok(self.entries.lock().await.get(key).cloned())
        }

        async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
            self.entries.lock().await.insert(key.to_owned(), data);
            Ok(Duration::ZERO)
        }

        async fn check(&self) -> Result<CacheMode> {
            Ok(CacheMode::ReadWrite)
        }

        fn location(&self) -> String {
            "test-memory".into()
        }

        async fn current_size(&self) -> Result<Option<u64>> {
            Ok(None)
        }

        async fn max_size(&self) -> Result<Option<u64>> {
            Ok(Some(64 * 1024 * 1024))
        }
    }

    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    #[tokio::test]
    async fn abort_releases_intermediate_read_descriptor() -> Result<()> {
        let mut session = TransferSession::new(4096);
        session.intermediate_read = Some((tokio::fs::File::from_std(tempfile::tempfile()?), 8));
        assert!(matches!(
            session
                .handle(TransferRequest::Abort, &MemoryStorage::default())
                .await?,
            TransferReply::Ack
        ));
        assert!(session.intermediate_read.is_none());
        Ok(())
    }

    #[test]
    fn namespace_blob_transport_round_trips_large_cache_entries() -> Result<()> {
        let runtime = crate::util::new_client_runtime()?;
        runtime.block_on(async {
            let storage = Arc::new(MemoryStorage::default());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let service = SccacheService::<ProcessCommandCreator>::mock_with_storage(
                storage.clone(),
                tokio::runtime::Handle::current(),
            );
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await?;
                service.bind(socket).await
            });
            let key = "a".repeat(64);
            let other = "b".repeat(64);
            let data = vec![0x5a; 9 * 1024 * 1024 + 123];
            let expected = data.clone();
            let key_copy = key.clone();
            let other_copy = other.clone();
            let socket = std::net::TcpStream::connect(addr)?;
            let client = IpcStorage::connect(ServerConnection::new(Box::new(socket))?).await?;
            assert!(client.get_raw(&key).await?.is_none());
            client.put_raw(&key, data.into()).await?;
            assert_eq!(
                client.get_raw(&key).await?.as_deref(),
                Some(expected.as_slice())
            );
            assert_eq!(
                storage.get_raw(&key).await?.as_deref(),
                Some(expected.as_slice())
            );

            // The transfer can return bytes successfully while the artifact
            // itself is corrupt. That is a read error, not an absent key.
            let error = client.get(&key).await.unwrap_err();
            assert!(format!("{error:#}").contains(&key));
            assert!(matches!(client.get(&other).await?, Cache::Miss));

            let conn = client.conn();
            crate::client::connection_task(conn, move |conn| {
                assert!(matches!(
                    conn.transfer(TransferRequest::BeginWrite {
                        kind: StorageBlob::Cache,
                        key: other_copy,
                        len: 10,
                    })?,
                    TransferReply::WriteStarted
                ));
                conn.transfer(TransferRequest::WriteChunk(vec![1; 3]))?;
                assert!(conn.transfer(TransferRequest::FinishWrite).is_err());
                // The same connection remains usable after a failed transaction.
                assert!(matches!(
                    conn.transfer(TransferRequest::Read {
                        kind: StorageBlob::Cache,
                        key: key_copy,
                    })?,
                    TransferReply::ReadStarted(Some(_))
                ));
                conn.transfer(TransferRequest::Abort)?;
                Ok(())
            })
            .await?;
            assert!(storage.get_raw(&other).await?.is_none());
            drop(client);
            server.await??;
            Ok(())
        })
    }
}
