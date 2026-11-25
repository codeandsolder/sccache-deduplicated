//! Cost histories belong to a scheduler's route and worker platform, not
//! to a process nonce. Cross-worker priors use real overlapping commands.

use super::{ActionClass, ActionCost, ActionCosts, MAX_AGE};
use sccache::{
    build_runtime::{ContentId, wire::ActionObservation},
    dist::{NativePlacement, ServerId},
};
use std::{collections::BTreeMap, time::Instant};

pub(super) const MAX_WORKERS: usize = 32;
const RATIO_SCALE: u128 = 1_000_000;
const MAX_CALIBRATION_CLASSES: usize = 32;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct WorkerScope {
    pub peer: ServerId,
    pub platform: ContentId,
}

#[derive(Default)]
pub struct CostBook {
    pub(super) workers: BTreeMap<WorkerScope, ActionCosts>,
    pub(super) revision: u64,
    pub(super) receivers: super::receiver::DeliveryHistory,
}

fn median(mut values: Vec<u64>) -> Option<u64> {
    values.sort_unstable();
    let middle = values.len() / 2;
    let upper = *values.get(middle)?;
    Some(if values.len().is_multiple_of(2) {
        u64::midpoint(upper, values[middle - 1])
    } else {
        upper
    })
}

fn calibration(
    target: Option<&ActionCosts>,
    peer: &ActionCosts,
    requested: ActionClass,
    now: Instant,
) -> Option<u64> {
    let target = target?;
    let ratios = target
        .entries
        .iter()
        .filter_map(|(&class, sample)| {
            if class == requested
                || sample.observations < 2
                || now.saturating_duration_since(sample.seen) >= MAX_AGE
            {
                return None;
            }
            let other = peer.fresh(class, now)?;
            if other.observations < 2 {
                return None;
            }
            let ratio = u128::from(sample.cost.execution_nanoseconds) * RATIO_SCALE
                / u128::from(other.cost.execution_nanoseconds.max(1));
            u64::try_from(ratio.clamp(RATIO_SCALE / 16, RATIO_SCALE * 16)).ok()
        })
        .take(MAX_CALIBRATION_CLASSES)
        .collect::<Vec<_>>();
    // One coincidentally similar crate is not a machine-speed calibration.
    if ratios.len() < 2 {
        return None;
    }
    median(ratios)
}

pub(super) fn blend(prior: u64, learned: u64, weight: u64) -> u64 {
    u64::try_from(
        (u128::from(prior) * u128::from(4 - weight) + u128::from(learned) * u128::from(weight)) / 4,
    )
    .unwrap_or(u64::MAX)
}

impl CostBook {
    pub(crate) fn predict(
        &self,
        scope: WorkerScope,
        class: ActionClass,
        placement: &NativePlacement,
        now: Instant,
    ) -> ActionCost {
        let baseline = ActionCost::baseline(placement);
        let target = self.workers.get(&scope);
        let phase = target.map_or_else(super::PhaseCost::default, |history| {
            history.overhead.estimate(now)
        });
        if let Some(sample) = target.and_then(|history| history.fresh(class, now))
            && sample.observations >= 4
        {
            return ActionCost {
                phase,
                ..sample.cost
            };
        }
        let mut calibrated = Vec::new();
        let mut uncalibrated = Vec::new();
        let mut bytes = Vec::new();
        let mut results = Vec::new();
        let mut requests = Vec::new();
        for (&other, history) in &self.workers {
            if other == scope || other.platform != scope.platform {
                continue;
            }
            let Some(sample) = history.fresh(class, now) else {
                continue;
            };
            bytes.push(sample.cost.output_bytes);
            results.push(sample.cost.result_bytes);
            requests.push(sample.cost.output_requests);
            if let Some(ratio) = calibration(target, history, class, now) {
                let predicted =
                    u128::from(sample.cost.execution_nanoseconds) * u128::from(ratio) / RATIO_SCALE;
                calibrated.push(
                    u64::try_from(predicted.clamp(1, 3_600_000_000_000))
                        .unwrap_or(3_600_000_000_000),
                );
            } else {
                uncalibrated.push(sample.cost.execution_nanoseconds);
            }
        }
        let execution = median(calibrated).map_or_else(
            || {
                median(uncalibrated).map_or(baseline.execution_nanoseconds, |ns| {
                    blend(baseline.execution_nanoseconds, ns, 1)
                })
            },
            |ns| blend(baseline.execution_nanoseconds, ns, 3),
        );
        let prior = ActionCost {
            phase,
            execution_nanoseconds: execution,
            output_bytes: median(bytes).map_or(baseline.output_bytes, |value| {
                blend(baseline.output_bytes, value, 2)
            }),
            result_bytes: median(results).map_or(baseline.result_bytes, |value| {
                blend(baseline.result_bytes, value, 2)
            }),
            output_requests: median(requests).map_or(baseline.output_requests, |value| {
                blend(baseline.output_requests, value, 2)
            }),
        };
        target.map_or(prior, |history| {
            history.predict_from_prior(class, prior, now)
        })
    }

    /// Use actual logical result size, independent of the negotiated upload.
    /// All compatible workers can contribute to this conservative soft hint.
    pub(crate) fn result_reservation(
        &self,
        platform: ContentId,
        class: ActionClass,
        now: Instant,
    ) -> Option<u64> {
        let peak = self
            .workers
            .iter()
            .filter(|(scope, _)| scope.platform == platform)
            .filter_map(|(_, history)| history.fresh(class, now))
            .map(|sample| sample.result_peak_bytes)
            .max()?;
        Some(
            peak.saturating_add(peak.div_ceil(4))
                .saturating_add(64 << 10),
        )
    }

    pub(crate) fn observe(
        &mut self,
        scope: WorkerScope,
        class: ActionClass,
        observation: ActionObservation,
        result_bytes: u64,
        now: Instant,
    ) {
        if !observation.valid() || result_bytes > 1 << 40 || observation.upload_bytes > result_bytes
        {
            return;
        }
        if !self.workers.contains_key(&scope)
            && self.workers.len() >= MAX_WORKERS
            && let Some(oldest) = self
                .workers
                .iter()
                .min_by_key(|(_, costs)| costs.entries.values().map(|sample| sample.seen).max())
                .map(|(&scope, _)| scope)
        {
            self.workers.remove(&oldest);
        }
        self.workers
            .entry(scope)
            .or_default()
            .observe(class, observation, result_bytes, now);
        self.revision = self.revision.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(port: u16) -> WorkerScope {
        WorkerScope {
            peer: ServerId::from_digest(std::array::from_fn(|index| port.to_le_bytes()[index % 2])),
            platform: ContentId::of(b"platform"),
        }
    }

    fn observation(ns: u64) -> ActionObservation {
        ActionObservation {
            execution_nanoseconds: ns,
            worker_timing: None,
            warm_staging_nanoseconds: None,
            publication_setup_nanoseconds: None,
            upload_bytes: 100,
            upload_requests: 1,
            upload_nanoseconds: 10_000,
        }
    }

    #[test]
    fn native_shared_cost_uses_matched_commands_not_different_host_workload_averages() {
        let mut book = CostBook::default();
        let now = Instant::now();
        let slow = scope(1);
        let fast = scope(2);
        let class = ActionClass(ContentId::of(b"requested"));
        for _ in 0..4 {
            book.observe(slow, class, observation(800_000_000), 100, now);
        }
        let placement = NativePlacement::default();
        assert_eq!(
            book.predict(fast, class, &placement, now)
                .execution_nanoseconds,
            950_000_000
        );
        // Two independently observed common commands demonstrate a 4x
        // machine difference. The host-wide prior has not changed.
        for name in [b"common-one".as_slice(), b"common-two"] {
            let common = ActionClass(ContentId::of(name));
            for _ in 0..2 {
                book.observe(slow, common, observation(400_000_000), 100, now);
                book.observe(fast, common, observation(100_000_000), 100, now);
            }
        }
        assert_eq!(
            book.predict(fast, class, &placement, now)
                .execution_nanoseconds,
            400_000_000
        );
        for _ in 0..4 {
            book.observe(fast, class, observation(123_000_000), 100, now);
        }
        assert_eq!(
            book.predict(fast, class, &placement, now)
                .execution_nanoseconds,
            123_000_000
        );
        assert_eq!(
            book.predict(
                WorkerScope {
                    platform: ContentId::of(b"other"),
                    ..fast
                },
                class,
                &placement,
                now
            ),
            ActionCost::baseline(&placement)
        );
        assert_eq!(
            book.predict(fast, class, &placement, now + MAX_AGE),
            ActionCost::baseline(&placement)
        );
    }

    #[test]
    fn native_result_reservation_uses_peak_logical_bytes_not_upload_bytes() {
        let mut book = CostBook::default();
        let now = Instant::now();
        let first = scope(1);
        let second = scope(2);
        let class = ActionClass(ContentId::of(b"crate"));
        let measured = ActionObservation {
            upload_bytes: 0,
            upload_requests: 0,
            ..observation(100_000_000)
        };
        assert_eq!(book.result_reservation(first.platform, class, now), None);
        book.observe(first, class, measured, 4 << 20, now);
        book.observe(second, class, measured, 8 << 20, now);
        book.observe(second, class, measured, 1 << 20, now);
        for _ in 0..3 {
            book.observe(first, class, measured, 4 << 20, now);
        }
        let prediction = book.predict(first, class, &NativePlacement::default(), now);
        assert_eq!(prediction.output_bytes, 0);
        assert_eq!(prediction.result_bytes, 4 << 20);
        assert_eq!(
            book.result_reservation(first.platform, class, now),
            Some((10 << 20) + (64 << 10))
        );
        assert_eq!(
            book.result_reservation(ContentId::of(b"other"), class, now),
            None
        );
        assert_eq!(
            book.result_reservation(first.platform, class, now + MAX_AGE),
            None
        );
    }

    #[test]
    fn native_cost_book_attaches_only_worker_local_phase_observations() {
        let mut book = CostBook::default();
        let now = Instant::now();
        let local = scope(1);
        let peer = scope(2);
        let class = ActionClass(ContentId::of(b"compile"));
        let other_class = ActionClass(ContentId::of(b"link"));
        let measured = ActionObservation {
            warm_staging_nanoseconds: Some(10_000_000),
            worker_timing: None,
            publication_setup_nanoseconds: Some(6_000_000),
            ..observation(100_000_000)
        };
        book.observe(local, class, measured, 100, now);
        let placement = NativePlacement::default();
        let phase = book.predict(local, other_class, &placement, now).phase;
        assert_eq!(phase.staging_nanoseconds, 10_000_000);
        assert_eq!(phase.publication_nanoseconds, 6_000_000);
        assert_eq!(
            book.predict(peer, class, &placement, now).phase,
            Default::default()
        );
        assert_eq!(
            book.predict(local, class, &placement, now + MAX_AGE).phase,
            Default::default()
        );
    }
}
