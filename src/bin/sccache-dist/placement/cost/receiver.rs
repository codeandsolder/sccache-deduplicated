//! Receiver-local reuse and selection history. This history is advisory and
//! deliberately expires sooner than compiler service times.
use super::{CostBook, history::blend, smooth};
use sccache::{
    build_runtime::{ContentId, DeliveryReceipt},
    dist::ServerId,
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub(super) const SCALE: u64 = 1_000_000;
pub(super) const LIMIT: usize = 4096;
pub(super) const TTL: Duration = Duration::from_hours(1);

pub(super) type Key = (ServerId, ContentId);

#[derive(Clone, Copy)]
pub(super) struct Sample {
    pub selected: u64,
    pub remote: u64,
    pub count: u64,
    pub seen: Instant,
}

impl Sample {
    pub(super) const fn valid(self) -> bool {
        self.remote <= self.selected && self.selected <= SCALE && self.count > 0
    }
}

#[derive(Default)]
pub(super) struct DeliveryHistory {
    pub(super) samples: BTreeMap<Key, Sample>,
}

fn fraction(bytes: u64, full: u64) -> u64 {
    u64::try_from((u128::from(bytes) * u128::from(SCALE)).div_ceil(u128::from(full)))
        .unwrap_or(SCALE)
}

impl DeliveryHistory {
    fn observe(&mut self, receipt: DeliveryReceipt, now: Instant) -> bool {
        let full = receipt.result_bytes;
        let Some(remote) = receipt
            .observation
            .direct_bytes
            .checked_add(receipt.observation.scheduler_bytes)
        else {
            return false;
        };
        let selected = receipt.observation.selected_bytes;
        if full == 0 || remote > selected || selected > full || full > 1 << 40 {
            return false;
        }
        let key = (receipt.requester, receipt.profile);
        let measured = Sample {
            selected: fraction(selected, full),
            remote: fraction(remote, full),
            count: 1,
            seen: now,
        };
        if let Some(sample) = self.samples.get_mut(&key) {
            *sample = if now.saturating_duration_since(sample.seen) >= TTL {
                measured
            } else {
                Sample {
                    selected: smooth(sample.selected, measured.selected),
                    remote: smooth(sample.remote, measured.remote),
                    count: sample.count.saturating_add(1),
                    seen: now,
                }
            };
            return true;
        }
        if self.samples.len() >= LIMIT
            && let Some(oldest) = self
                .samples
                .iter()
                .min_by_key(|(_, sample)| sample.seen)
                .map(|(&key, _)| key)
        {
            self.samples.remove(&oldest);
        }
        self.samples.insert(key, measured);
        true
    }

    fn predict(&self, key: Key, now: Instant) -> u64 {
        self.samples
            .get(&key)
            .filter(|sample| now.saturating_duration_since(sample.seen) < TTL)
            .map_or(SCALE, |sample| {
                blend(SCALE, sample.remote, sample.count.min(4))
            })
    }
}

impl CostBook {
    pub(crate) fn observe_delivery(&mut self, receipt: DeliveryReceipt, now: Instant) {
        if self.receivers.observe(receipt, now) {
            self.revision = self.revision.wrapping_add(1);
        }
    }

    pub(crate) fn delivery_fraction(
        &self,
        requester: ServerId,
        profile: ContentId,
        now: Instant,
    ) -> u64 {
        self.receivers.predict((requester, profile), now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccache::build_runtime::wire::ClientDeliveryObservation;

    #[test]
    fn selection_and_reuse_are_receiver_specific_and_expire() {
        let now = Instant::now();
        let requester = ServerId::from_digest([1; 32]);
        let other = ServerId::from_digest([2; 32]);
        let final_only = ContentId::of(b"final");
        let all = ContentId::of(b"all");
        let mut book = CostBook::default();
        let receipt = DeliveryReceipt {
            worker: other,
            requester,
            job: 1,
            profile: final_only,
            result_bytes: 1000,
            elapsed: Duration::from_secs(1),
            observation: ClientDeliveryObservation {
                selected_bytes: 400,
                direct_bytes: 100,
                scheduler_bytes: 100,
                unique_blobs: 2,
                staging_nanoseconds: 0,
            },
        };
        assert_eq!(book.delivery_fraction(requester, final_only, now), SCALE);
        book.observe_delivery(receipt, now);
        assert_eq!(book.delivery_fraction(requester, final_only, now), 800_000);
        for _ in 0..3 {
            book.observe_delivery(receipt, now);
        }
        assert_eq!(book.delivery_fraction(requester, final_only, now), 200_000);
        assert_eq!(book.delivery_fraction(requester, all, now), SCALE);
        assert_eq!(book.delivery_fraction(other, final_only, now), SCALE);
        assert_eq!(
            book.delivery_fraction(requester, final_only, now + TTL),
            SCALE
        );
        assert_eq!(
            book.receivers.samples[&(requester, final_only)].selected,
            400_000
        );
    }
}
