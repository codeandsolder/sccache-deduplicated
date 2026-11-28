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

use crate::config::Config;
use crate::errors::Result;
#[cfg(all(feature = "dist-client", target_os = "linux"))]
use anyhow::Context;
use async_trait::async_trait;
use std::sync::Arc;

/// Native compilation session metadata. CAS operations are not part of this interface.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Verify that a connection-owned compilation session remains usable.
    /// A failed session must not turn into a speculative local compilation.
    ///
    /// # Errors
    /// Returns an error if the underlying session is no longer usable.
    fn validate_session(&self) -> Result<()> {
        Ok(())
    }

    /// Get the storage location.
    fn location(&self) -> String;

    /// Describe the native session for diagnostics.
    /// Used for statistics and display purposes.
    fn cache_type_name(&self) -> &'static str {
        "unknown"
    }

    /// Get the current storage usage, if applicable.
    async fn current_size(&self) -> Result<Option<u64>>;

    /// Get the maximum storage size, if applicable.
    async fn max_size(&self) -> Result<Option<u64>>;

    /// Return the base directories for path normalization if configured
    fn basedirs(&self) -> &[Vec<u8>] {
        &[]
    }
}

#[cfg(all(feature = "dist-client", target_os = "linux"))]
struct NativeDiscoveryStorage {
    location: String,
    basedirs: Vec<Vec<u8>>,
}

#[cfg(all(feature = "dist-client", target_os = "linux"))]
#[async_trait]
impl Storage for NativeDiscoveryStorage {
    fn location(&self) -> String {
        self.location.clone()
    }

    fn cache_type_name(&self) -> &'static str {
        "native"
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    fn basedirs(&self) -> &[Vec<u8>] {
        &self.basedirs
    }
}

/// Native action metadata; the daemon does not own an artifact cache.
pub fn storage_from_config(
    config: &Config,
    _: &tokio::runtime::Handle,
) -> Result<Arc<dyn Storage>> {
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    {
        let native = config
            .dist
            .native
            .as_ref()
            .context("native CAS configuration is required")?;
        Ok(Arc::new(NativeDiscoveryStorage {
            location: native.endpoint.to_url().to_string(),
            basedirs: config.basedirs.clone(),
        }))
    }
    #[cfg(not(all(feature = "dist-client", target_os = "linux")))]
    {
        let _ = config;
        anyhow::bail!("native compiler execution requires a Linux distributed client")
    }
}
