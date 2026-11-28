// Copyright 2017 Mozilla Foundation
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

use crate::cache::Storage;
use crate::errors::*;
use async_trait::async_trait;

/// A mock `Storage` implementation.
pub struct MockStorage {
    fail_size_query: bool,
}

impl MockStorage {
    /// Create a test session with no cache storage.
    pub(crate) fn new() -> Self {
        Self {
            fail_size_query: false,
        }
    }

    pub(crate) fn fail_current_size(&mut self) {
        self.fail_size_query = true;
    }
}

#[async_trait]
impl Storage for MockStorage {
    fn location(&self) -> String {
        "Mock Storage".to_string()
    }
    async fn current_size(&self) -> Result<Option<u64>> {
        anyhow::ensure!(!self.fail_size_query, "injected size query failure");
        Ok(None)
    }
    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}
