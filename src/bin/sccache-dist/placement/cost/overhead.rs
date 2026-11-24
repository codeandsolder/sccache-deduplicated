//! Independent, expiring worker-local service estimates. Samples exclude
//! transfer acquisition, compiler queues and known grace-capacity waits.
use super::MAX_AGE;
use sccache::build_runtime::wire::ActionObservation;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub(super) struct TimedMean {
    pub value: u64,
    pub seen: Instant,
}

#[derive(Default)]
pub(super) struct OverheadHistory {
    pub staging: Option<TimedMean>,
    pub publication: Option<TimedMean>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PhaseCost {
    pub staging_nanoseconds: u64,
    pub publication_nanoseconds: u64,
}

fn update(slot: &mut Option<TimedMean>, sample: Option<u64>, now: Instant) {
    let Some(value) = sample.filter(|&value| value <= 60_000_000_000) else {
        return;
    };
    let value = slot
        .filter(|old| now.saturating_duration_since(old.seen) < MAX_AGE)
        .map_or(value, |old| super::smooth(old.value, value));
    *slot = Some(TimedMean { value, seen: now });
}

impl OverheadHistory {
    pub(super) fn observe(&mut self, observation: ActionObservation, now: Instant) {
        update(&mut self.staging, observation.warm_staging_nanoseconds, now);
        update(
            &mut self.publication,
            observation.publication_setup_nanoseconds,
            now,
        );
    }

    pub(super) fn estimate(&self, now: Instant) -> PhaseCost {
        let current = |sample: Option<TimedMean>| {
            sample
                .filter(|sample| now.saturating_duration_since(sample.seen) < MAX_AGE)
                .map_or(0, |sample| sample.value)
        };
        PhaseCost {
            staging_nanoseconds: current(self.staging),
            publication_nanoseconds: current(self.publication),
        }
    }
}

impl PhaseCost {
    pub(super) const fn valid(self) -> bool {
        self.staging_nanoseconds <= 60_000_000_000 && self.publication_nanoseconds <= 60_000_000_000
    }

    pub fn staging(self) -> Duration {
        Duration::from_nanos(self.staging_nanoseconds)
    }

    pub fn publication(self) -> Duration {
        Duration::from_nanos(self.publication_nanoseconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_overhead_only_updates_present_samples_and_expires_independently() {
        let now = Instant::now();
        let mut history = OverheadHistory::default();
        let first = ActionObservation {
            warm_staging_nanoseconds: Some(10_000_000),
            worker_timing: None,
            publication_setup_nanoseconds: Some(20_000_000),
            execution_nanoseconds: 50_000_000,
            upload_bytes: 0,
            upload_requests: 0,
            upload_nanoseconds: 0,
        };
        history.observe(first, now);
        let later = now + Duration::from_secs(60);
        history.observe(
            ActionObservation {
                warm_staging_nanoseconds: None,
                publication_setup_nanoseconds: Some(40_000_000),
                ..first
            },
            later,
        );
        assert_eq!(
            history.estimate(later),
            PhaseCost {
                staging_nanoseconds: 10_000_000,
                publication_nanoseconds: 25_000_000,
            }
        );
        assert_eq!(
            history.estimate(now + MAX_AGE),
            PhaseCost {
                staging_nanoseconds: 0,
                publication_nanoseconds: 25_000_000,
            }
        );
        assert_eq!(history.estimate(later + MAX_AGE), PhaseCost::default());
    }
}
