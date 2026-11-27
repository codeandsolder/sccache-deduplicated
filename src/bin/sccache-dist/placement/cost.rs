//! Bounded, advisory service-time history for real compiler command families.
//! Neither class identity nor predictions participate in cache verification.

use sccache::{
    build_runtime::{ContentId, ExecutionSpec, ResultTransferEstimate, wire::ActionObservation},
    dist::{NativeInputBlobs, NativePlacement},
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

mod checkpoint;
mod receiver;
pub use checkpoint::start as start_checkpoint;
mod history;
mod overhead;
pub use history::{CostBook, WorkerScope};
use overhead::OverheadHistory;
pub use overhead::PhaseCost;
const MAX_CLASSES: usize = 4096;
const MAX_AGE: Duration = Duration::from_hours(24);

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ActionClass(ContentId);

impl ActionClass {
    pub(crate) fn from_spec(spec: &ExecutionSpec) -> anyhow::Result<Self> {
        Ok(Self(spec.placement_class()?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActionCost {
    pub phase: PhaseCost,
    pub execution_nanoseconds: u64,
    /// Missing scheduler upload bytes.
    pub output_bytes: u64,
    /// Full unique logical result, independent of cache residency.
    pub result_bytes: u64,
    pub output_requests: u64,
}

impl ActionCost {
    fn valid(self) -> bool {
        (1..=3_600_000_000_000).contains(&self.execution_nanoseconds)
            && self.output_bytes <= self.result_bytes
            && self.result_bytes <= 1 << 40
            && self.output_requests <= 1_000_000
            && self.phase.valid()
    }
    pub(crate) fn baseline(placement: &NativePlacement) -> Self {
        Self {
            phase: PhaseCost {
                staging_nanoseconds: 0,
                publication_nanoseconds: 0,
            },
            execution_nanoseconds: placement.timing.execution_estimate(),
            output_bytes: placement.timing.result.expected_bytes,
            result_bytes: placement.timing.result.expected_bytes.max(1 << 20),
            output_requests: placement.timing.result.expected_requests,
        }
    }

    pub(crate) const fn result(
        self,
        mut transfer: ResultTransferEstimate,
    ) -> ResultTransferEstimate {
        transfer.expected_bytes = self.output_bytes;
        transfer.expected_requests = self.output_requests;
        transfer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedNative {
    #[cfg(feature = "scheduler-dashboard")]
    pub dashboard: Option<sccache_dashboard::JobDescription>,
    pub packages: std::sync::Arc<sccache::build_runtime::PackageCatalog>,
    pub inputs: NativeInputBlobs,
    pub class: Option<ActionClass>,
    pub cost: Option<ActionCost>,
    pub milestone: Option<super::Milestone>,
}

#[derive(Clone, Copy)]
struct Sample {
    cost: ActionCost,
    result_peak_bytes: u64,
    seen: Instant,
    observations: u64,
}

#[derive(Default)]
pub struct ActionCosts {
    overhead: OverheadHistory,
    entries: BTreeMap<ActionClass, Sample>,
}

const fn smooth(old: u64, new: u64) -> u64 {
    if new >= old {
        old + (new - old).div_ceil(4)
    } else {
        old - (old - new).div_ceil(4)
    }
}

impl ActionCosts {
    #[cfg(test)]
    pub(crate) fn predict(
        &self,
        class: Option<ActionClass>,
        placement: &NativePlacement,
        now: Instant,
    ) -> ActionCost {
        class.map_or(ActionCost::baseline(placement), |class| {
            self.predict_from_prior(class, ActionCost::baseline(placement), now)
        })
    }

    fn fresh(&self, class: ActionClass, now: Instant) -> Option<&Sample> {
        self.entries
            .get(&class)
            .filter(|sample| now.saturating_duration_since(sample.seen) < MAX_AGE)
    }

    fn predict_from_prior(
        &self,
        class: ActionClass,
        baseline: ActionCost,
        now: Instant,
    ) -> ActionCost {
        let Some(sample) = self.fresh(class, now) else {
            return baseline;
        };
        // Shrink a single observation towards the host prior. After several
        // genuine observations, the class-specific estimate dominates.
        let weight = sample.observations.min(4);
        let blend = |prior, learned| history::blend(prior, learned, weight);
        ActionCost {
            phase: baseline.phase,
            execution_nanoseconds: blend(
                baseline.execution_nanoseconds,
                sample.cost.execution_nanoseconds,
            ),
            output_bytes: blend(baseline.output_bytes, sample.cost.output_bytes),
            result_bytes: blend(baseline.result_bytes, sample.cost.result_bytes),
            output_requests: blend(baseline.output_requests, sample.cost.output_requests),
        }
    }

    pub(crate) fn observe(
        &mut self,
        class: ActionClass,
        observed: ActionObservation,
        result_bytes: u64,
        now: Instant,
    ) {
        if !observed.valid() || result_bytes > 1 << 40 || observed.upload_bytes > result_bytes {
            return;
        }
        self.overhead.observe(observed, now);
        let cost = ActionCost {
            phase: PhaseCost::default(),
            execution_nanoseconds: observed.execution_nanoseconds,
            output_bytes: observed.upload_bytes,
            result_bytes,
            output_requests: observed.upload_requests,
        };
        if let Some(sample) = self.entries.get_mut(&class) {
            if now.saturating_duration_since(sample.seen) >= MAX_AGE {
                *sample = Sample {
                    cost,
                    result_peak_bytes: result_bytes,
                    seen: now,
                    observations: 1,
                };
                return;
            }
            sample.cost = ActionCost {
                phase: PhaseCost::default(),
                execution_nanoseconds: smooth(
                    sample.cost.execution_nanoseconds,
                    cost.execution_nanoseconds,
                ),
                output_bytes: smooth(sample.cost.output_bytes, cost.output_bytes),
                result_bytes: smooth(sample.cost.result_bytes, cost.result_bytes),
                output_requests: smooth(sample.cost.output_requests, cost.output_requests),
            };
            sample.result_peak_bytes = sample.result_peak_bytes.max(result_bytes);
            sample.seen = now;
            sample.observations = sample.observations.saturating_add(1);
            return;
        }
        if self.entries.len() >= MAX_CLASSES
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, sample)| sample.seen)
                .map(|(&class, _)| class)
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(
            class,
            Sample {
                cost,
                result_peak_bytes: result_bytes,
                seen: now,
                observations: 1,
            },
        );
    }
}

#[cfg(test)]
mod tests;
