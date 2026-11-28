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

use crate::cache::cache::Storage;
use crate::client::{ServerConnection, SharedConnection, connection_task};
use crate::errors::{Result, bail};
use crate::protocol::{
    NAMESPACE_PROTOCOL_VERSION, Request, Response, StorageHandshakeInfo, TRANSFER_CHUNK_BYTES,
};
use anyhow::ensure;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Native session metadata and broker connection for namespace discovery.
///
/// `ServerConnection` is synchronous and non-`Clone`, so it lives behind a
/// `Mutex` and every RPC dispatches via `tokio::task::spawn_blocking`.  The
/// lock is held for a complete transfer transaction; cancellation closes
/// the underlying socket to release a blocked transaction.
pub struct IpcStorage {
    conn: SharedConnection,
    handshake: StorageHandshakeInfo,
    closed: CancellationToken,
}

impl IpcStorage {
    /// Connect to the daemon and perform the `StorageHandshake` RPC.
    /// Returns an `IpcStorage` that can be used as an `Arc<dyn Storage>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake request fails or the daemon returns an unexpected response.
    pub async fn connect(conn: ServerConnection) -> Result<Self> {
        let closed = conn.session_health();
        let conn = Arc::new(Mutex::new(conn));
        let resp = connection_task(Arc::clone(&conn), |conn| {
            conn.request(Request::StorageHandshake)
        })
        .await?;
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
            conn,
            handshake,
            closed,
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
        config: &crate::config::DistConfig,
        #[cfg(target_os = "linux")] digest_provider: Option<
            crate::build_runtime::DescriptorDigestProvider,
        >,
    ) -> crate::server::DistClientContainer {
        use crate::server::DistClientContainer;
        #[cfg(target_os = "linux")]
        if let Some(policy) = &self.handshake.native {
            return DistClientContainer::new_native(
                crate::compiler::NativeCompilerClient::from_namespace(
                    self.conn(),
                    self.handshake.transfer_chunk_bytes,
                    policy.clone(),
                    &config.native_installation_catalogs,
                    digest_provider,
                ),
            );
        }

        let _ = config;
        DistClientContainer::new_disabled()
    }
}

#[async_trait]
impl Storage for IpcStorage {
    fn validate_session(&self) -> Result<()> {
        ensure!(
            !self.closed.is_cancelled(),
            crate::client::IpcTransportFailure
        );
        Ok(())
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

    fn basedirs(&self) -> &[Vec<u8>] {
        &self.handshake.basedirs
    }
}
