use super::{DirectionSnapshot, MAX_RATE, Peer};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Convert advisory transfer demand to time, saturating only beyond the
/// representable nanosecond horizon (hundreds of years).
#[must_use = "the duration is used in placement prediction"]
pub fn transfer_seconds(bytes: u128, bytes_per_second: u64) -> f64 {
    seconds(
        bytes
            .saturating_mul(NANOS_PER_SECOND)
            .div_ceil(u128::from(bytes_per_second.max(1))),
    )
}

fn seconds(nanos: u128) -> f64 {
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX)).as_secs_f64()
}

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
    finished: BTreeMap<Peer, u128>,
    // Byte-nanoseconds: retain fractional bytes through each rate transition.
    remaining: BTreeMap<Peer, u128>,
}

impl DirectionSnapshot {
    fn rates(
        &self,
        active: &BTreeMap<Peer, u128>,
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
                let allocated = group
                    .members
                    .iter()
                    .filter_map(|peer| rates.get(peer))
                    .sum::<u64>();
                if let Some(share) = group
                    .bytes_per_second
                    .saturating_sub(allocated)
                    .checked_div(count)
                {
                    increment = increment.min(share);
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

    fn simulate(&self, demands: &BTreeMap<Peer, TransferDemand>, until: u128) -> Simulation {
        let mut remaining: BTreeMap<_, _> = demands
            .iter()
            .filter(|(_, demand)| demand.bytes > 0)
            .map(|(&peer, demand)| (peer, demand.bytes.saturating_mul(NANOS_PER_SECOND)))
            .collect();
        let mut finished = BTreeMap::new();
        if self.shared.is_empty() {
            remaining.retain(|peer, bytes| {
                let rate = u128::from(demands[peer].rate());
                let duration = bytes.div_ceil(rate);
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
        let mut elapsed = 0_u128;
        while !remaining.is_empty() && elapsed < until {
            let rates = self.rates(&remaining, demands);
            let next_finish = remaining
                .iter()
                .map(|(peer, bytes)| bytes.div_ceil(u128::from(rates[peer].max(1))))
                .min()
                .unwrap_or(0);
            let step = next_finish.min(until - elapsed);
            elapsed += step;
            remaining.retain(|peer, bytes| {
                *bytes = bytes.saturating_sub(step.saturating_mul(u128::from(rates[peer].max(1))));
                if *bytes == 0 {
                    finished.insert(*peer, elapsed);
                    false
                } else {
                    true
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
        self.simulate(demands, u128::MAX)
            .finished
            .into_iter()
            .map(|(peer, nanos)| (peer, seconds(nanos)))
            .collect()
    }

    /// Advance the existing traffic to a future arrival time.
    #[must_use = "the remaining demand predicts future contention"]
    pub fn remaining_after(
        &self,
        demands: &BTreeMap<Peer, TransferDemand>,
        delay_seconds: f64,
    ) -> BTreeMap<Peer, TransferDemand> {
        let until = Duration::try_from_secs_f64(delay_seconds.max(0.0))
            .map_or(u128::MAX, |duration| duration.as_nanos());
        self.simulate(demands, until)
            .remaining
            .into_iter()
            .map(|(peer, bytes)| {
                (
                    peer,
                    TransferDemand {
                        bytes: bytes.div_ceil(NANOS_PER_SECOND),
                        bytes_per_second: demands[&peer].bytes_per_second,
                    },
                )
            })
            .collect()
    }
}
