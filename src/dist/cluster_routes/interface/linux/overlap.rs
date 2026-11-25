//! Learn shared effective service from aligned, uncontaminated endpoint windows.
//! No wall-clock synchronization, probe payload, or inferred physical topology.
use crate::build_runtime::wire::{EndpointFlow, EndpointOverlap};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const TTL: Duration = Duration::from_mins(10);
const MAX_FLOWS: usize = 256;
const MAX_PAIRS: usize = 64;
const MIN_RATE: u64 = 64 << 10;

#[derive(Default)]
pub(super) struct Counters {
    active: AtomicU64,
    epoch: AtomicU64,
    bytes: AtomicU64,
}

impl Counters {
    pub(super) fn start(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn bytes(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }
    pub(super) fn finish(&self) {
        if self.active.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.epoch.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn sample(&self) -> Sample {
        Sample {
            active: self.active.load(Ordering::Relaxed),
            epoch: self.epoch.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Sample {
    active: u64,
    epoch: u64,
    bytes: u64,
}

struct Record {
    counters: Arc<Counters>,
    previous: Sample,
    isolated: u64,
    isolated_at: Instant,
    seen: Instant,
}

impl Record {
    fn new(now: Instant) -> Self {
        Self {
            counters: Arc::default(),
            previous: Sample::default(),
            isolated: 0,
            isolated_at: now,
            seen: now,
        }
    }

    fn sample(&mut self, now: Instant, elapsed: Duration) -> Window {
        let current = self.counters.sample();
        let bytes = current.bytes.wrapping_sub(self.previous.bytes);
        let rate = super::per_second(bytes, elapsed).min(1_000_000_000_000);
        let active = current.active != 0 || self.previous.active != 0 || bytes != 0;
        let sustained = current.active != 0
            && self.previous.active != 0
            && current.epoch == self.previous.epoch
            && rate >= MIN_RATE;
        self.previous = current;
        if active {
            self.seen = now;
        }
        if now.saturating_duration_since(self.isolated_at) >= TTL {
            self.isolated = 0;
        }
        Window {
            active,
            sustained,
            rate,
            isolated: self.isolated,
        }
    }
}

#[derive(Clone, Copy)]
struct Window {
    active: bool,
    sustained: bool,
    rate: u64,
    isolated: u64,
}

struct Evidence {
    min: u64,
    max: u64,
    count: u8,
    seen: Instant,
}

#[derive(Default)]
pub(super) struct Learner {
    flows: BTreeMap<EndpointFlow, Record>,
    pairs: BTreeMap<[EndpointFlow; 2], Evidence>,
}

impl Learner {
    pub(super) fn start(&mut self, key: EndpointFlow, now: Instant) -> Option<Arc<Counters>> {
        if self.flows.len() >= MAX_FLOWS && !self.flows.contains_key(&key) {
            return None;
        }
        let counters = Arc::clone(
            &self
                .flows
                .entry(key)
                .or_insert_with(|| Record::new(now))
                .counters,
        );
        counters.start();
        Some(counters)
    }

    pub(super) fn sample(
        &mut self,
        now: Instant,
        elapsed: Duration,
        clean: impl Fn(EndpointFlow) -> bool,
    ) {
        let windows = self
            .flows
            .iter_mut()
            .filter_map(|(&key, record)| {
                let window = record.sample(now, elapsed);
                window.active.then_some((key, window))
            })
            .collect::<BTreeMap<_, _>>();
        let clean = elapsed <= Duration::from_secs(2) && windows.keys().copied().all(clean);
        self.flows
            .retain(|_, record| now.saturating_duration_since(record.seen) < TTL);
        self.pairs.retain(|keys, evidence| {
            let observed = keys
                .iter()
                .filter_map(|key| windows.get(key))
                .filter(|window| window.sustained)
                .map(|window| window.rate)
                .sum::<u64>();
            // Contradictory clean windows invalidate the ceiling even when
            // only one of the previously constrained flows is active.
            now.saturating_duration_since(evidence.seen) < TTL
                && (!clean || observed <= evidence.max.saturating_mul(115) / 100)
        });
        if !clean
            || elapsed > Duration::from_secs(2)
            || windows.values().any(|window| !window.sustained)
        {
            return;
        }
        match windows.len() {
            1 => {
                if let Some((&key, window)) = windows.first_key_value()
                    && let Some(record) = self.flows.get_mut(&key)
                    && window.rate >= record.isolated
                {
                    record.isolated = window.rate;
                    record.isolated_at = now;
                }
            }
            2 => self.observe_pair(now, &windows),
            _ => {}
        }
    }

    fn observe_pair(&mut self, now: Instant, windows: &BTreeMap<EndpointFlow, Window>) {
        let (Some((&a, first)), Some((&b, second))) =
            (windows.first_key_value(), windows.last_key_value())
        else {
            return;
        };
        let keys = [a, b];
        let aggregate = first.rate + second.rate;
        let isolated = first.isolated + second.isolated;
        if first.isolated == 0
            || second.isolated == 0
            || first.rate * 100 > first.isolated * 85
            || second.rate * 100 > second.isolated * 85
            || aggregate * 100 > isolated * 80
            || aggregate < first.isolated.max(second.isolated) * 80 / 100
        {
            return;
        }
        if self.pairs.len() >= MAX_PAIRS
            && !self.pairs.contains_key(&keys)
            && let Some(oldest) = self
                .pairs
                .iter()
                .min_by_key(|(_, evidence)| evidence.seen)
                .map(|(&key, _)| key)
        {
            self.pairs.remove(&oldest);
        }
        let evidence = self.pairs.entry(keys).or_insert(Evidence {
            min: aggregate,
            max: aggregate,
            count: 0,
            seen: now,
        });
        let min = evidence.min.min(aggregate);
        let max = evidence.max.max(aggregate);
        if max * 100 > min * 120 {
            *evidence = Evidence {
                min: aggregate,
                max: aggregate,
                count: 1,
                seen: now,
            };
        } else {
            evidence.min = min;
            evidence.max = max;
            evidence.count = evidence.count.saturating_add(1);
            evidence.seen = now;
        }
    }

    pub(super) fn active(&self) -> BTreeMap<EndpointFlow, u64> {
        self.flows
            .iter()
            .filter_map(|(&key, record)| {
                let count = record.counters.active.load(Ordering::Relaxed);
                (count != 0).then_some((key, count))
            })
            .collect()
    }

    pub(super) fn report(&self, now: Instant) -> Vec<EndpointOverlap> {
        self.pairs
            .iter()
            .filter(|(_, evidence)| {
                evidence.count >= 3 && now.saturating_duration_since(evidence.seen) < TTL
            })
            .map(|(&flows, evidence)| EndpointOverlap {
                flows,
                bytes_per_second: evidence.max,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_runtime::Direction;

    #[test]
    fn learns_only_repeatable_clean_concurrency_and_invalidates_faster_windows()
    -> anyhow::Result<()> {
        let a = EndpointFlow {
            path: "192.0.2.1,192.0.2.2".parse()?,
            direction: Direction::Send,
        };
        let b = EndpointFlow {
            path: "198.51.100.1,198.51.100.2".parse()?,
            direction: Direction::Receive,
        };
        let mut learner = Learner::default();
        let mut now = Instant::now();
        fn tick(learner: &mut Learner, now: &mut Instant, clean: bool) {
            let step = Duration::from_secs(1);
            *now += step;
            learner.sample(*now, step, |_| clean);
        }
        let ca = learner
            .start(a, now)
            .ok_or_else(|| anyhow::anyhow!("flow a unavailable"))?;
        tick(&mut learner, &mut now, true);
        ca.bytes(100 << 20);
        tick(&mut learner, &mut now, true);
        ca.finish();
        tick(&mut learner, &mut now, true);
        let cb = learner
            .start(b, now)
            .ok_or_else(|| anyhow::anyhow!("flow b unavailable"))?;
        tick(&mut learner, &mut now, true);
        cb.bytes(100 << 20);
        tick(&mut learner, &mut now, true);
        cb.finish();
        tick(&mut learner, &mut now, true);
        let ca = learner
            .start(a, now)
            .ok_or_else(|| anyhow::anyhow!("flow a unavailable"))?;
        let cb = learner
            .start(b, now)
            .ok_or_else(|| anyhow::anyhow!("flow b unavailable"))?;
        tick(&mut learner, &mut now, true);
        for _ in 0..3 {
            ca.bytes(50 << 20);
            cb.bytes(50 << 20);
            tick(&mut learner, &mut now, false);
        }
        assert!(learner.report(now).is_empty());
        for _ in 0..3 {
            ca.bytes(50 << 20);
            cb.bytes(50 << 20);
            tick(&mut learner, &mut now, true);
        }
        assert_eq!(
            learner.report(now),
            [EndpointOverlap {
                flows: [a, b],
                bytes_per_second: 100 << 20
            }]
        );
        ca.bytes(100 << 20);
        cb.bytes(100 << 20);
        tick(&mut learner, &mut now, true);
        assert!(learner.report(now).is_empty());
        Ok(())
    }
}
