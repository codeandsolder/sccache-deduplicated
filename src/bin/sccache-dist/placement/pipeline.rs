//! Forecast a worker's bounded pipeline using relative stage times and the
//! exact input identities already reserved by the scheduler.

use sccache::{
    build_runtime::{ContentId, PackageTransferCost, transfer_seconds, wire::NativeJobPhase},
    dist::{JobId, NativeInputBlobs, NativeJobProgress, NativePlacement},
};
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet},
    time::Duration,
};

pub(super) type Assignments = HashMap<JobId, Option<NativeInputBlobs>>;

/// A completed input closure is exact evidence, independently of the
/// periodic Bloom inventory. The prediction never authorizes content.
pub(super) fn confirmed_inputs(
    assigned: &Assignments,
    placement: &NativePlacement,
) -> HashSet<ContentId> {
    placement
        .queue
        .jobs
        .iter()
        .filter(|(_, job)| job.phase != NativeJobPhase::Terminal && job.remaining_input_blobs == 0)
        .filter_map(|(id, _)| assigned.get(id).and_then(Option::as_ref))
        .flat_map(|inputs| inputs.keys().copied())
        .collect()
}

pub(super) fn resident(
    placement: &NativePlacement,
    confirmed: &HashSet<ContentId>,
    id: ContentId,
) -> bool {
    confirmed.contains(&id)
        || placement
            .residency
            .as_ref()
            .is_some_and(|filter| filter.may_contain(id))
}

fn duration(seconds: f64) -> Duration {
    Duration::try_from_secs_f64(seconds).unwrap_or(Duration::MAX)
}

struct Slots(BinaryHeap<Reverse<Duration>>);

impl Slots {
    fn new(width: u32, jobs: usize) -> Self {
        let width = usize::try_from(width)
            .unwrap_or(usize::MAX)
            .min(jobs.max(1))
            .max(1);
        Self(std::iter::repeat_n(Reverse(Duration::ZERO), width).collect())
    }

    fn available(&self) -> Duration {
        self.0.peek().map_or(Duration::ZERO, |slot| slot.0)
    }

    fn reserve(&mut self, ready: Duration, service: Duration) -> Duration {
        let finish = self.available().max(ready).saturating_add(service);
        if let Some(mut slot) = self.0.peek_mut() {
            *slot = Reverse(finish);
        }
        finish
    }
}

struct StagingTimeline<'a> {
    slots: Slots,
    // Unique logical bytes consume one aggregate worker delivery resource.
    // Request setup can overlap with the next independent byte transfer.
    wire_free: Duration,
    logical_rate: u64,
    contention: f64,
    cost: PackageTransferCost,
    placement: &'a NativePlacement,
    confirmed: HashSet<ContentId>,
    future: HashMap<ContentId, Duration>,
}

impl StagingTimeline<'_> {
    fn stage(
        &mut self,
        inputs: Option<&NativeInputBlobs>,
        progress: Option<&NativeJobProgress>,
    ) -> Duration {
        let start = self.slots.available();
        let mut dependency = start;
        let mut bytes = 0_u128;
        let mut requests = 0_u64;
        let mut new = Vec::new();
        for (&id, &size) in inputs.into_iter().flat_map(|inputs| inputs.iter()) {
            if resident(self.placement, &self.confirmed, id) {
                continue;
            }
            if let Some(&ready) = self.future.get(&id) {
                dependency = dependency.max(ready);
            } else {
                new.push(id);
                bytes += u128::from(size);
                requests = requests.saturating_add(1);
            }
        }
        if let Some(progress) = progress {
            // The last verified remainder can still include blobs supplied by
            // another reservation since it was measured. Never add a second
            // transfer for content already confirmed or forecast on this worker.
            if inputs.is_some() {
                bytes = bytes.min(u128::from(progress.remaining_input_bytes));
                requests = requests.min(progress.remaining_input_blobs);
            } else {
                // A cancelled/orphaned local job may still be draining.
                bytes = u128::from(progress.remaining_input_bytes);
                requests = progress.remaining_input_blobs;
            }
        }
        let wire_done = if bytes == 0 {
            start
        } else {
            self.wire_free = self.wire_free.max(start).saturating_add(duration(
                transfer_seconds(bytes, self.logical_rate) * self.contention,
            ));
            self.wire_free
        };
        let overhead = Duration::from_nanos(
            requests
                .div_ceil(u64::from(self.cost.raw_parallelism))
                .saturating_mul(self.cost.raw_request_nanoseconds),
        );
        let ready = dependency.max(wire_done.saturating_add(overhead));
        for id in new {
            self.future.insert(id, ready);
        }
        self.slots.reserve(ready, Duration::ZERO)
    }
}

#[derive(Clone, Copy)]
struct Pending<'a> {
    id: JobId,
    inputs: Option<&'a NativeInputBlobs>,
    progress: Option<&'a NativeJobProgress>,
}

impl Pending<'_> {
    fn phase(self) -> NativeJobPhase {
        self.progress
            .map_or(NativeJobPhase::Assigned, |job| job.phase)
    }

    fn priority(self) -> (u8, Reverse<u64>, JobId) {
        let phase = match self.phase() {
            NativeJobPhase::Staging => 0,
            NativeJobPhase::Queued => 1,
            _ => 2,
        };
        (
            phase,
            Reverse(self.progress.map_or(0, |job| job.phase_nanoseconds)),
            self.id,
        )
    }
}

fn remaining(service: Duration, progress: Option<&NativeJobProgress>) -> Duration {
    // A job that outlived the average is not already finished. Keep a
    // residual service estimate until the worker reports a phase change.
    service
        .saturating_sub(Duration::from_nanos(
            progress.map_or(0, |job| job.phase_nanoseconds),
        ))
        .max(service / 4)
}

fn output_service(placement: &NativePlacement) -> Duration {
    let result = placement.result;
    duration(transfer_seconds(
        u128::from(result.expected_bytes),
        result.bytes_per_second,
    ))
    .saturating_add(Duration::from_nanos(
        result
            .expected_requests
            .saturating_mul(result.request_nanoseconds),
    ))
}

struct Pipeline {
    compiler: Slots,
    publication: Slots,
    execution: Duration,
    output: Duration,
    ready: Vec<(Duration, bool, JobId, bool)>,
    publish: Vec<(Duration, bool, JobId)>,
}

impl Pipeline {
    fn new(capacity: f64, placement: &NativePlacement, jobs: usize) -> Self {
        let effective = capacity
            .max(1.0)
            .min(f64::from(placement.queue.compiler_slots));
        let width = (1..=placement.queue.compiler_slots)
            .find(|&width| f64::from(width) >= effective)
            .unwrap_or(1);
        let execution = duration(
            Duration::from_nanos(placement.execution_nanoseconds).as_secs_f64() * f64::from(width)
                / effective,
        );
        Self {
            compiler: Slots::new(width, jobs),
            publication: Slots::new(placement.queue.publication_slots, jobs),
            execution,
            output: output_service(placement),
            ready: Vec::new(),
            publish: Vec::new(),
        }
    }

    fn observe(&mut self, job: Pending<'_>) {
        match job.phase() {
            NativeJobPhase::Publishing => {
                self.publication
                    .reserve(Duration::ZERO, remaining(self.output, job.progress));
            }
            NativeJobPhase::AwaitingPublication => {
                self.publish.push((Duration::ZERO, false, job.id))
            }
            NativeJobPhase::Executing => {
                let done = self
                    .compiler
                    .reserve(Duration::ZERO, remaining(self.execution, job.progress));
                self.publish.push((done, false, job.id));
            }
            NativeJobPhase::Ready => self.ready.push((Duration::ZERO, false, job.id, true)),
            NativeJobPhase::Assigned
            | NativeJobPhase::Queued
            | NativeJobPhase::Staging
            | NativeJobPhase::Terminal => (),
        }
    }

    fn finish(mut self, candidate_ready: Duration) -> Duration {
        self.ready.push((candidate_ready, true, JobId(0), true));
        self.ready.sort_unstable();
        for (ready, candidate, id, publishes) in self.ready {
            let done = self.compiler.reserve(ready, self.execution);
            if publishes {
                self.publish.push((done, candidate, id));
            }
        }
        self.publish.sort_unstable();
        for (ready, candidate, _) in self.publish {
            if candidate {
                return self.publication.available().max(ready);
            }
            self.publication.reserve(ready, self.output);
        }
        candidate_ready.saturating_add(self.execution)
    }
}

/// Predict when the new action can start publishing, not merely when a
/// nominal count of outstanding jobs would clear a compiler semaphore.
pub(super) fn publication_start(
    capacity: f64,
    assigned: &Assignments,
    placement: &NativePlacement,
    requested: &NativeInputBlobs,
    logical_rate: u64,
    contention: f64,
) -> f64 {
    let jobs = assigned
        .len()
        .saturating_add(placement.queue.jobs.len())
        .saturating_add(1);
    let mut pipeline = Pipeline::new(capacity, placement, jobs);
    let mut staging = Vec::new();
    let mut pending: Vec<_> = placement
        .queue
        .jobs
        .iter()
        .map(|(&id, progress)| Pending {
            id,
            inputs: assigned.get(&id).and_then(Option::as_ref),
            progress: Some(progress),
        })
        .collect();
    pending.extend(
        assigned
            .iter()
            .filter(|(id, _)| !placement.queue.jobs.contains_key(id))
            .map(|(&id, inputs)| Pending {
                id,
                inputs: inputs.as_ref(),
                progress: None,
            }),
    );
    let native_running = pending
        .iter()
        .filter(|job| job.phase() == NativeJobPhase::Executing)
        .count();
    let mut other_running =
        (placement.queue.compiler_active as usize).saturating_sub(native_running);
    pending.sort_unstable_by_key(|job| job.id);
    for job in pending {
        match job.phase() {
            NativeJobPhase::Assigned | NativeJobPhase::Queued | NativeJobPhase::Staging => {
                if job.progress.is_none() && job.inputs.is_none() {
                    // Archive assignments have no native input manifest.
                    // Restore their already-occupied shared compiler slots.
                    if other_running > 0 {
                        pipeline
                            .compiler
                            .reserve(Duration::ZERO, pipeline.execution);
                        other_running -= 1;
                    } else {
                        pipeline.ready.push((Duration::ZERO, false, job.id, false));
                    }
                } else {
                    staging.push(job);
                }
            }
            _ => pipeline.observe(job),
        }
    }
    for _ in 0..other_running {
        pipeline
            .compiler
            .reserve(Duration::ZERO, pipeline.execution);
    }
    staging.sort_unstable_by_key(|job| job.priority());
    let mut timeline = StagingTimeline {
        slots: Slots::new(placement.queue.staging_slots, jobs),
        wire_free: Duration::ZERO,
        logical_rate,
        contention,
        cost: placement.transfer,
        placement,
        confirmed: confirmed_inputs(assigned, placement),
        future: HashMap::new(),
    };
    for job in staging {
        let ready = timeline.stage(job.inputs, job.progress);
        pipeline.ready.push((ready, false, job.id, true));
    }
    let ready = timeline.stage(Some(requested), None);
    pipeline.finish(ready).as_secs_f64()
}

#[cfg(test)]
mod tests;
