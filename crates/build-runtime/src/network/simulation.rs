use super::{DirectionSnapshot, MAX_RATE, Peer};
use std::collections::{BTreeMap, BTreeSet};

/// One peer's outstanding transport bytes and estimated individual service rate.
#[derive(Debug, Clone, Copy)]
pub struct TransferDemand {
    pub bytes: u128,
    pub bytes_per_second: u64,
}

impl TransferDemand {
    fn rate(self) -> u64 {
        self.bytes_per_second.clamp(1, MAX_RATE)
    }
}

struct Simulation {
    finished: BTreeMap<Peer, f64>,
    remaining: BTreeMap<Peer, f64>,
}

impl DirectionSnapshot {
    /// Progressive max-min filling across individual and overlapping group
    /// constraints. A peer freezes when either its own rate or a shared
    /// resource has no capacity for another equal increment.
    fn rates(
        &self,
        active: &BTreeMap<Peer, f64>,
        demands: &BTreeMap<Peer, TransferDemand>,
    ) -> BTreeMap<Peer, u64> {
        let mut rates: BTreeMap<_, u64> = active.keys().map(|&peer| (peer, 0)).collect();
        let mut growing: BTreeSet<_> = active.keys().copied().collect();
        while !growing.is_empty() {
            let mut increment = growing
                .iter()
                .map(|peer| demands[peer].rate() - rates[peer])
                .min()
                .unwrap_or(0);
            for group in &self.shared {
                let count = group.members.intersection(&growing).count() as u64;
                if count != 0 {
                    let allocated = group
                        .members
                        .iter()
                        .filter_map(|peer| rates.get(peer))
                        .sum::<u64>();
                    increment =
                        increment.min(group.bytes_per_second.saturating_sub(allocated) / count);
                }
            }
            for peer in &growing {
                if let Some(rate) = rates.get_mut(peer) {
                    *rate += increment;
                }
            }
            let mut frozen: BTreeSet<_> = growing
                .iter()
                .filter(|peer| rates[*peer] >= demands[*peer].rate())
                .copied()
                .collect();
            for group in &self.shared {
                let count = group.members.intersection(&growing).count() as u64;
                let allocated = group
                    .members
                    .iter()
                    .filter_map(|peer| rates.get(peer))
                    .sum::<u64>();
                if count != 0 && group.bytes_per_second.saturating_sub(allocated) < count {
                    frozen.extend(group.members.intersection(&growing).copied());
                }
            }
            if frozen.is_empty() {
                break;
            }
            growing.retain(|peer| !frozen.contains(peer));
        }
        rates
    }

    fn simulate(&self, demands: &BTreeMap<Peer, TransferDemand>, until: f64) -> Simulation {
        let mut remaining: BTreeMap<_, _> = demands
            .iter()
            .filter(|(_, demand)| demand.bytes > 0)
            .map(|(&peer, demand)| (peer, demand.bytes as f64))
            .collect();
        let mut finished = BTreeMap::new();
        if self.shared.is_empty() {
            remaining.retain(|peer, bytes| {
                let rate = demands[peer].rate() as f64;
                let duration = *bytes / rate;
                if duration <= until {
                    finished.insert(*peer, duration);
                    false
                } else {
                    *bytes -= until * rate;
                    true
                }
            });
            return Simulation {
                finished,
                remaining,
            };
        }

        let mut elapsed = 0.0;
        while !remaining.is_empty() && elapsed < until {
            let rates = self.rates(&remaining, demands);
            let next_finish = remaining
                .iter()
                .map(|(peer, bytes)| bytes / rates[peer].max(1) as f64)
                .fold(f64::INFINITY, f64::min);
            let step = next_finish.min(until - elapsed);
            elapsed += step;
            remaining.retain(|peer, bytes| {
                let rate = rates[peer].max(1) as f64;
                if *bytes / rate <= step {
                    finished.insert(*peer, elapsed);
                    false
                } else {
                    *bytes -= step * rate;
                    *bytes > 0.0
                }
            });
        }
        Simulation {
            finished,
            remaining,
        }
    }

    /// Predict completion of concurrent peer backlogs. Reallocate bandwidth
    /// each time a peer finishes.
    #[must_use = "completion times are advisory placement predictions"]
    pub fn finish_times(&self, demands: &BTreeMap<Peer, TransferDemand>) -> BTreeMap<Peer, f64> {
        self.simulate(demands, f64::INFINITY).finished
    }

    /// Advance the existing traffic to a future arrival time, e.g. the
    /// moment a newly scheduled compiler finishes and starts publishing.
    #[must_use = "the remaining demand predicts future contention"]
    pub fn remaining_after(
        &self,
        demands: &BTreeMap<Peer, TransferDemand>,
        seconds: f64,
    ) -> BTreeMap<Peer, TransferDemand> {
        self.simulate(demands, seconds.max(0.0))
            .remaining
            .into_iter()
            .map(|(peer, bytes)| {
                (
                    peer,
                    TransferDemand {
                        bytes: bytes.ceil() as u128,
                        bytes_per_second: demands[&peer].bytes_per_second,
                    },
                )
            })
            .collect()
    }
}
