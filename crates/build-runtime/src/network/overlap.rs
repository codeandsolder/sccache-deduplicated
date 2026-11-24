//! Infer useful concurrency observations exclusively from demanded transfers.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use super::{DirectionMeter, DirectionSnapshot, MAX_GROUPS, Peer};

/// Evidence at the observed load, not a proof of independent physical links.
#[derive(Debug, Clone)]
pub struct ConcurrentCapacity {
    pub rates: BTreeMap<Peer, u64>,
}

#[derive(Debug, Clone)]
pub(super) struct IndependentEvidence {
    pub(super) count: u8,
    pub(super) rates: BTreeMap<Peer, u64>,
    pub(super) seen: Instant,
}

impl DirectionSnapshot {
    /// Is this exact overlap already explained, or has a superset sustained
    /// at least the current isolated rates? A constrained superset does not
    /// answer which smaller subsets share its bottleneck.
    #[must_use = "the scheduler only explores unanswered concurrency questions"]
    pub fn overlap_known(&self, members: &BTreeSet<Peer>) -> bool {
        self.shared.iter().any(|group| &group.members == members)
            || self.independent.iter().any(|group| {
                members.iter().all(|peer| {
                    let Some(capacity) = self.peers.get(peer) else {
                        return false;
                    };
                    group.rates.get(peer).is_some_and(|&rate| {
                        capacity.isolated_bytes_per_second > 0
                            && capacity.isolated_bytes_per_second <= rate.saturating_mul(115) / 100
                    })
                })
            })
    }
}

impl DirectionMeter {
    pub(super) fn observe_independence(
        &mut self,
        members: &BTreeSet<Peer>,
        sustained: &BTreeMap<Peer, (u64, u64)>,
        now: Instant,
    ) {
        // Require actual independently acquired baselines. A peer's first
        // concurrent observation cannot establish independence by comparison
        // with itself.
        if !sustained
            .values()
            .all(|&(rate, isolated)| isolated > 0 && rate >= isolated.saturating_mul(90) / 100)
        {
            return;
        }
        if self.independent.len() >= MAX_GROUPS
            && !self.independent.contains_key(members)
            && let Some(oldest) = self
                .independent
                .iter()
                .min_by_key(|(_, evidence)| evidence.seen)
                .map(|(key, _)| key.clone())
        {
            self.independent.remove(&oldest);
        }
        let evidence =
            self.independent
                .entry(members.clone())
                .or_insert_with(|| IndependentEvidence {
                    count: 0,
                    rates: sustained
                        .iter()
                        .map(|(&peer, &(rate, _))| (peer, rate))
                        .collect(),
                    seen: now,
                });
        // Retain the weakest sustained rate across the evidence windows.
        // If throughput has increased, start a new observation instead of
        // endlessly retaining a stale lower bound.
        if sustained
            .iter()
            .any(|(peer, &(rate, _))| rate > evidence.rates[peer].saturating_mul(115) / 100)
        {
            evidence.rates = sustained
                .iter()
                .map(|(&peer, &(rate, _))| (peer, rate))
                .collect();
            evidence.count = 0;
        } else {
            for (&peer, &(rate, _)) in sustained {
                if let Some(previous) = evidence.rates.get_mut(&peer) {
                    *previous = (*previous).min(rate);
                }
            }
        }
        evidence.count = evidence.count.saturating_add(1);
        evidence.seen = now;
    }
}
