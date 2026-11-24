//! Compact, advisory residency snapshot. False positives affect placement
//! estimates only: every actual input still needs a verified store lease.

use crate::ContentId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobResidency {
    bits: Vec<u8>,
}

impl BlobResidency {
    pub const MAX_BYTES: usize = 1024 * 1024;

    /// Allocate twelve bits per indexed blob, subject to a bounded heartbeat.
    /// Returns no summary rather than a saturated, misleading filter.
    #[must_use = "the snapshot is absent when the index exceeds its budget"]
    pub fn for_count(count: u64) -> Option<Self> {
        let bytes = usize::try_from(count.checked_mul(12)?.div_ceil(8))
            .ok()?
            .max(64);
        (bytes <= Self::MAX_BYTES).then(|| Self {
            bits: vec![0; bytes],
        })
    }

    #[must_use = "untrusted heartbeat summaries must be validated"]
    pub fn valid(&self) -> bool {
        (64..=Self::MAX_BYTES).contains(&self.bits.len())
    }

    fn positions(&self, id: ContentId) -> [usize; 4] {
        let modulus = self.bits.len() * 8;
        std::array::from_fn(|i| {
            let mut digest = [0_u8; 8];
            digest.copy_from_slice(&id.0[i * 8..(i + 1) * 8]);
            // Modulus is bounded to 8 Mi bits and therefore fits usize.
            usize::try_from(u64::from_le_bytes(digest) % modulus as u64).unwrap_or(0)
        })
    }

    pub fn insert(&mut self, id: ContentId) {
        if self.valid() {
            for position in self.positions(id) {
                self.bits[position / 8] |= 1 << (position % 8);
            }
        }
    }

    #[must_use = "membership is an advisory scheduling hint"]
    pub fn may_contain(&self, id: ContentId) -> bool {
        self.valid()
            && self
                .positions(id)
                .into_iter()
                .all(|position| self.bits[position / 8] & (1 << (position % 8)) != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_snapshot_has_no_false_negatives_and_low_false_positive_rate() {
        let mut filter = BlobResidency::for_count(10_000).unwrap();
        for i in 0_u64..10_000 {
            filter.insert(ContentId::of(&i.to_le_bytes()));
        }
        assert!((0_u64..10_000).all(|i| filter.may_contain(ContentId::of(&i.to_le_bytes()))));
        let false_positives = (10_000_u64..20_000)
            .filter(|i| filter.may_contain(ContentId::of(&i.to_le_bytes())))
            .count();
        assert!(false_positives < 150);
        assert!(BlobResidency::for_count(u64::MAX).is_none());
    }
}
