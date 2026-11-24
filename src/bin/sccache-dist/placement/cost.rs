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
pub(crate) use checkpoint::start as start_checkpoint;
mod history;
pub(crate) use history::{CostBook, WorkerScope};
const MAX_CLASSES: usize = 4096;
const MAX_AGE: Duration = Duration::from_hours(24);

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub(crate) struct ActionClass(ContentId);

impl ActionClass {
    pub(crate) fn from_spec(spec: &ExecutionSpec) -> anyhow::Result<Self> {
        let command = &spec.command;
        let args = &command.arguments;
        // Rust dependency artifact filenames and metadata hashes change
        // with source identity, not necessarily compilation workload.
        // Retain dependency names, all feature/target/codegen switches,
        // crate name, emit mode, and source/output path shape.
        let rust = args
            .iter()
            .any(|arg| arg == b"--crate-name" || arg.starts_with(b"--crate-name="));
        let mut stable = Vec::with_capacity(args.len());
        let mut i = 0;
        while let Some(arg) = args.get(i) {
            i += 1;
            if rust {
                if arg == b"--extern" {
                    if let Some(value) = args.get(i) {
                        stable.push(arg.as_slice());
                        stable.push(value.split(|&byte| byte == b'=').next().unwrap_or(value));
                        i += 1;
                        continue;
                    }
                }
                if let Some(value) = arg.strip_prefix(b"--extern=") {
                    stable.push(b"--extern");
                    stable.push(value.split(|&byte| byte == b'=').next().unwrap_or(value));
                    continue;
                }
                if arg == b"-C" && args.get(i).is_some_and(|value| volatile_codegen(value)) {
                    i += 1;
                    continue;
                }
                if arg.strip_prefix(b"-C").is_some_and(volatile_codegen) {
                    continue;
                }
            }
            stable.push(arg.as_slice());
        }
        let mut hash = blake3::Hasher::new();
        hash.update(b"sccache-placement-command-v1\0");
        bincode::serialize_into(
            &mut hash,
            &(spec.platform, &command.executable, &command.cwd, stable),
        )?;
        Ok(Self(ContentId(*hash.finalize().as_bytes())))
    }
}

fn volatile_codegen(arg: &[u8]) -> bool {
    arg.starts_with(b"metadata=") || arg.starts_with(b"extra-filename=")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ActionCost {
    pub execution_nanoseconds: u64,
    pub output_bytes: u64,
    pub output_requests: u64,
}

impl ActionCost {
    fn valid(self) -> bool {
        (1..=3_600_000_000_000).contains(&self.execution_nanoseconds)
            && self.output_bytes <= 1 << 40
            && self.output_requests <= 1_000_000
    }
    pub(crate) const fn baseline(placement: &NativePlacement) -> Self {
        Self {
            execution_nanoseconds: placement.execution_nanoseconds,
            output_bytes: placement.result.expected_bytes,
            output_requests: placement.result.expected_requests,
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
pub(crate) struct AssignedNative {
    pub inputs: NativeInputBlobs,
    pub class: Option<ActionClass>,
    pub cost: Option<ActionCost>,
}

#[derive(Clone, Copy)]
struct Sample {
    cost: ActionCost,
    seen: Instant,
    observations: u64,
}

#[derive(Default)]
pub(crate) struct ActionCosts {
    entries: BTreeMap<ActionClass, Sample>,
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
            execution_nanoseconds: blend(
                baseline.execution_nanoseconds,
                sample.cost.execution_nanoseconds,
            ),
            output_bytes: blend(baseline.output_bytes, sample.cost.output_bytes),
            output_requests: blend(baseline.output_requests, sample.cost.output_requests),
        }
    }

    pub(crate) fn observe(
        &mut self,
        class: ActionClass,
        observed: ActionObservation,
        now: Instant,
    ) {
        if !observed.valid() {
            return;
        }
        let cost = ActionCost {
            execution_nanoseconds: observed.execution_nanoseconds,
            output_bytes: observed.upload_bytes,
            output_requests: observed.upload_requests,
        };
        if let Some(sample) = self.entries.get_mut(&class) {
            if now.saturating_duration_since(sample.seen) >= MAX_AGE {
                *sample = Sample {
                    cost,
                    seen: now,
                    observations: 1,
                };
                return;
            }
            let smooth = |old: u64, new: u64| {
                if new >= old {
                    old + (new - old).div_ceil(4)
                } else {
                    old - (old - new).div_ceil(4)
                }
            };
            sample.cost = ActionCost {
                execution_nanoseconds: smooth(
                    sample.cost.execution_nanoseconds,
                    cost.execution_nanoseconds,
                ),
                output_bytes: smooth(sample.cost.output_bytes, cost.output_bytes),
                output_requests: smooth(sample.cost.output_requests, cost.output_requests),
            };
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
                seen: now,
                observations: 1,
            },
        );
    }
}

#[cfg(test)]
mod tests;
