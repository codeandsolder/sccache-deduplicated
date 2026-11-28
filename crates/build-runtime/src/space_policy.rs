use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Available-space watermarks on a dedicated quota-controlled filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpacePolicy {
    pub min_available_bytes: u64,
    pub target_available_bytes: u64,
    /// Optional logical content bound for a store sharing a filesystem.
    /// Omit both logical watermarks on a dedicated physical quota: the
    /// available-space watermarks account for compression, metadata and scratch.
    pub max_resident_bytes: Option<u64>,
    pub target_resident_bytes: Option<u64>,
    pub max_evictions_per_pass: usize,
    pub gc_batch: usize,
}

impl SpacePolicy {
    /// An absent logical bound leaves physical filesystem availability as
    /// the only retention constraint.
    #[must_use = "the returned limit determines resident storage admission"]
    pub const fn resident_limit(self) -> u64 {
        match self.max_resident_bytes {
            Some(limit) => limit,
            None => u64::MAX,
        }
    }

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
            match (self.max_resident_bytes, self.target_resident_bytes) {
                (None, None) => true,
                (Some(max), Some(target)) => target > 0 && target <= max,
                _ => false,
            },
            "logical resident watermarks must both be absent or a valid pair"
        );
        ensure!(
            self.max_evictions_per_pass > 0 && self.gc_batch > 0,
            "native space maintenance requires nonzero work bounds"
        );
        Ok(())
    }
}
