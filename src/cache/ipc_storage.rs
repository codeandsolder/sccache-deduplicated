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

use crate::cache::CacheMode;
use crate::cache::cache::Storage;
use crate::cache::cache_io::{Cache, CacheRead, CacheWrite};
use crate::client::{ServerConnection, SharedConnection, connection_task};
use crate::compiler::PreprocessorCacheEntry;
use crate::config::PreprocessorCacheModeConfig;
use crate::errors::{Context, Result, anyhow, bail};
use crate::protocol::{
    NAMESPACE_PROTOCOL_VERSION, Request, Response, StorageBlob, StorageHandshakeInfo,
    TRANSFER_CHUNK_BYTES, TransferReply, TransferRequest,
};
use anyhow::ensure;
use async_trait::async_trait;
use bytes::Bytes;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// `Storage` implementation that forwards all cache operations to the sccache
/// daemon over the existing IPC connection.  Used by CLI processes in
/// client-side mode.
///
/// `ServerConnection` is synchronous and non-`Clone`, so it lives behind a
/// `Mutex` and every RPC dispatches via `tokio::task::spawn_blocking`.  The
/// lock is held for a complete transfer transaction, never across
/// an `.await` point.
pub struct IpcStorage {
    conn: SharedConnection,
    handshake: StorageHandshakeInfo,
}

impl IpcStorage {
    /// Connect to the daemon and perform the `StorageHandshake` RPC.
    /// Returns an `IpcStorage` that can be used as an `Arc<dyn Storage>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake request fails or the daemon returns an unexpected response.
    pub fn connect(mut conn: ServerConnection) -> Result<Self> {
        let resp = conn.request(Request::StorageHandshake)?;
        let handshake = match resp {
            Response::StorageHandshake(info) => info,
            other => bail!("IpcStorage: unexpected handshake response: {other:?}"),
        };
        ensure!(
            handshake.namespace_protocol == NAMESPACE_PROTOCOL_VERSION,
            "incompatible daemon namespace protocol"
        );
        ensure!(
            handshake.transfer_chunk_bytes > 0
                && handshake.transfer_chunk_bytes <= TRANSFER_CHUNK_BYTES,
            "invalid daemon chunk size"
        );
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            handshake,
        })
    }

    /// Return a clone of the underlying connection handle so callers can send
    /// additional RPCs (e.g., `RecordStats`) after the storage is no longer
    /// needed.
    #[must_use = "the returned handle gives access to the existing IPC connection"]
    pub fn conn(&self) -> SharedConnection {
        Arc::clone(&self.conn)
    }

    #[cfg(feature = "dist-client")]
    pub(crate) fn dist_client(
        &self,
        toolchains: Vec<crate::config::DistToolchainConfig>,
    ) -> crate::server::DistClientContainer {
        use crate::server::{DistClientContainer, DistClientState};
        self.handshake.dist_rewrite_includes_only.map_or_else(
            DistClientContainer::new_disabled,
            |rewrite| {
                DistClientContainer::new_with_state(DistClientState::Broker(Arc::new(
                    crate::dist::broker::NamespaceClient::new(
                        self.conn(),
                        self.handshake.transfer_chunk_bytes,
                        rewrite,
                        toolchains,
                    ),
                )))
            },
        )
    }

    async fn read_blob(&self, kind: StorageBlob, key: &str) -> Result<Option<Bytes>> {
        let key = key.to_owned();
        let chunk_bytes = self.handshake.transfer_chunk_bytes;
        connection_task(self.conn(), move |conn| {
            let TransferReply::ReadStarted(len) =
                conn.transfer(TransferRequest::Read { kind, key })?
            else {
                bail!("expected download length");
            };
            let Some(len) = len else {
                return Ok(None);
            };
            let mut data = Vec::new();
            conn.download(len, chunk_bytes, &mut data)?;
            Ok(Some(data.into()))
        })
        .await
    }

    async fn write_blob(&self, kind: StorageBlob, key: &str, data: Bytes) -> Result<()> {
        let key = key.to_owned();
        let len = data.len() as u64;
        let chunk_bytes = self.handshake.transfer_chunk_bytes;
        connection_task(self.conn(), move |conn| {
            ensure!(
                matches!(
                    conn.transfer(TransferRequest::BeginWrite { kind, key, len })?,
                    TransferReply::WriteStarted
                ),
                "expected upload start"
            );
            conn.upload(len, chunk_bytes, data.as_ref())?;
            ensure!(
                matches!(
                    conn.transfer(TransferRequest::FinishWrite)?,
                    TransferReply::Ack
                ),
                "expected upload commit"
            );
            Ok(())
        })
        .await
    }
}

#[async_trait]
impl Storage for IpcStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        // A daemon path can be unavailable or name different bytes in this
        // namespace. Only consume bytes returned by the storage authority.
        match self.get_raw(key).await? {
            Some(bytes) => CacheRead::from(Cursor::new(bytes))
                .with_context(|| format!("IpcStorage: decode archive for key {key}"))
                .map(Cache::Hit),
            None => Ok(Cache::Miss),
        }
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        self.put_raw(key, entry.finish()?.into()).await
    }

    async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
        self.read_blob(StorageBlob::Cache, key).await
    }

    async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
        self.write_blob(StorageBlob::Cache, key, data).await?;
        Ok(Duration::ZERO)
    }

    async fn check(&self) -> Result<CacheMode> {
        Ok(self.handshake.cache_mode)
    }

    fn location(&self) -> String {
        self.handshake.location.clone()
    }

    fn cache_type_name(&self) -> &'static str {
        "ipc"
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(self.handshake.max_size)
    }

    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        self.handshake.preprocessor_cache_mode_config
    }

    fn basedirs(&self) -> &[Vec<u8>] {
        &self.handshake.basedirs
    }

    async fn get_preprocessor_cache_entry(
        &self,
        key: &str,
    ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
        Ok(self
            .read_blob(StorageBlob::Preprocessor, key)
            .await?
            .map(|bytes| Box::new(Cursor::new(bytes)) as Box<dyn crate::lru_disk_cache::ReadSeek>))
    }

    async fn put_preprocessor_cache_entry(
        &self,
        key: &str,
        entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        let mut buf = vec![];
        entry.serialize_to(&mut buf).map_err(|e| anyhow!("{e}"))?;
        self.write_blob(StorageBlob::Preprocessor, key, buf.into())
            .await
    }
}
