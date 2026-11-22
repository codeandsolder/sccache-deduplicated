use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Available-space watermarks on a dedicated quota-controlled filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpacePolicy {
    pub min_available_bytes: u64,
    pub target_available_bytes: u64,
    pub max_evictions_per_pass: usize,
    pub gc_batch: usize,
}

impl SpacePolicy {
    /// Validate the watermarks and work bounds.
    ///
    /// # Errors
    /// Returns an error for invalid or zero bounds.
    pub fn validate(self) -> Result<()> {
        ensure!(
            self.min_available_bytes > 0 && self.target_available_bytes >= self.min_available_bytes,
            "invalid native store space watermarks"
        );
        ensure!(
            self.max_evictions_per_pass > 0 && self.gc_batch > 0,
            "native space maintenance requires nonzero work bounds"
        );
        Ok(())
    }
}
