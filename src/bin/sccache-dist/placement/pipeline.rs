//! Forecast a worker's bounded pipeline using relative stage times and the
//! exact input identities already reserved by the scheduler.

use sccache::{
    build_runtime::{
        ContentId, PackageCatalog, PackageDeliveryLimits, PackageTransferCost, transfer_seconds,
        wire::NativeJobPhase,
    },
    dist::{JobId, NativeInputBlobs, NativeJobProgress, NativePlacement},
};
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet},
    time::{Duration, Instant},
};

use super::{
    ActionCost, AssignedNative, RecentResidency,
    delivery::{Delivery, DeliveryRates, DirectInputs, InputTraffic},
};

pub(super) type Assignments = HashMap<JobId, Option<AssignedNative>>;

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
        .flat_map(|job| job.inputs.keys().copied())
        .collect()
}

pub(super) struct WorkerResidency<'a> {
    placement: &'a NativePlacement,
    confirmed: HashSet<ContentId>,
    recent: &'a RecentResidency,
    now: Instant,
}

impl<'a> WorkerResidency<'a> {
    pub(super) fn new(
        assigned: &Assignments,
        placement: &'a NativePlacement,
        recent: &'a RecentResidency,
    ) -> Self {
        Self {
            placement,
            confirmed: confirmed_inputs(assigned, placement),
            recent,
            now: Instant::now(),
        }
    }

    pub(super) fn contains(&self, id: ContentId, size: u64) -> bool {
        self.confirmed.contains(&id)
            || self.recent.contains(id, size, self.now)
            || self
                .placement
                .residency
                .as_ref()
                .is_some_and(|filter| filter.may_contain(id))
    }
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
    rates: DeliveryRates,
    direct: Option<&'a DirectInputs>,
    cost: PackageTransferCost,
    limits: Option<PackageDeliveryLimits>,
    traffic: InputTraffic,
    residency: WorkerResidency<'a>,
    future: HashMap<ContentId, Duration>,
}

impl StagingTimeline<'_> {
    fn stage(
        &mut self,
        inputs: Option<&NativeInputBlobs>,
        progress: Option<&NativeJobProgress>,
        catalog: Option<&PackageCatalog>,
        overhead: Duration,
    ) -> Duration {
        let start = self.slots.available();
        let mut dependency = start;
        let mut bytes = 0_u128;
        let mut requests = 0_u64;
        let mut new = NativeInputBlobs::new();
        for (&id, &size) in inputs.into_iter().flat_map(|inputs| inputs.iter()) {
            if self.residency.contains(id, size) {
                continue;
            }
            if let Some(&ready) = self.future.get(&id) {
                dependency = dependency.max(ready);
            } else {
                new.insert(id, size);
                bytes += u128::from(size);
                requests = requests.saturating_add(1);
            }
        }
        let exact_bytes = bytes;
        let exact_requests = requests;
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
        let delivery = if bytes == exact_bytes && requests == exact_requests {
            Delivery::plan(
                new.clone(),
                catalog,
                self.limits,
                self.cost,
                self.rates,
                self.direct,
            )
        } else {
            // Progress counts cannot identify which digests remain. Do not
            // invent a smaller package cover for this partial closure.
            Delivery::raw(bytes, requests, self.cost, self.rates)
        };
        self.traffic.extend(delivery.traffic);
        let wire_done = if delivery.traffic.wire_bytes == 0 && delivery.traffic.direct_bytes == 0 {
            start
        } else {
            self.wire_free = self
                .wire_free
                .max(start)
                .saturating_add(duration(
                    delivery.traffic.wire_time.as_secs_f64() * self.rates.contention,
                ))
                .saturating_add(delivery.traffic.direct_time);
            self.wire_free
        };
        let setup = if bytes == 0
            && progress.is_some_and(|progress| progress.phase == NativeJobPhase::Staging)
        {
            remaining(overhead, progress)
        } else {
            overhead
        };
        let ready = dependency
            .max(wire_done.saturating_add(delivery.processing))
            .saturating_add(setup);
        for id in new.into_keys() {
            self.future.insert(id, ready);
        }
        self.slots.reserve(ready, Duration::ZERO)
    }
}

#[derive(Clone, Copy)]
struct Pending<'a> {
    id: JobId,
    inputs: Option<&'a AssignedNative>,
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

fn output_service(result: sccache::build_runtime::ResultTransferEstimate) -> Duration {
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
    scaling: f64,
    ready: Vec<(Duration, bool, JobId, bool, Duration, Duration)>,
    publish: Vec<(Duration, bool, JobId, Duration)>,
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
            Duration::from_nanos(placement.timing.execution_estimate()).as_secs_f64()
                * f64::from(width)
                / effective,
        );
        Self {
            compiler: Slots::new(width, jobs),
            publication: Slots::new(placement.queue.publication_slots, jobs),
            execution,
            output: output_service(placement.timing.result),
            scaling: f64::from(width) / effective,
            ready: Vec::new(),
            publish: Vec::new(),
        }
    }

    fn service(
        &self,
        cost: Option<ActionCost>,
        placement: &NativePlacement,
    ) -> (Duration, Duration) {
        cost.map_or((self.execution, self.output), |cost| {
            (
                duration(
                    Duration::from_nanos(cost.execution_nanoseconds).as_secs_f64() * self.scaling,
                ),
                output_service(cost.result(placement.timing.result))
                    .saturating_add(cost.phase.publication()),
            )
        })
    }

    fn observe(&mut self, job: Pending<'_>, placement: &NativePlacement) {
        let (execution, output) = self.service(job.inputs.and_then(|job| job.cost), placement);
        match job.phase() {
            NativeJobPhase::Publishing => {
                self.publication
                    .reserve(Duration::ZERO, remaining(output, job.progress));
            }
            NativeJobPhase::AwaitingPublication => {
                self.publish.push((Duration::ZERO, false, job.id, output));
            }
            NativeJobPhase::Executing => {
                let done = self
                    .compiler
                    .reserve(Duration::ZERO, remaining(execution, job.progress));
                self.publish.push((done, false, job.id, output));
            }
            NativeJobPhase::Ready => {
                self.ready
                    .push((Duration::ZERO, false, job.id, true, execution, output));
            }
            NativeJobPhase::Assigned
            | NativeJobPhase::Queued
            | NativeJobPhase::Staging
            | NativeJobPhase::Terminal => (),
        }
    }

    fn finish(
        mut self,
        candidate_ready: Duration,
        execution: Duration,
        output: Duration,
    ) -> Duration {
        self.ready
            .push((candidate_ready, true, JobId(0), true, execution, output));
        self.ready.sort_unstable();
        for (ready, candidate, id, publishes, execution, output) in self.ready {
            let done = self.compiler.reserve(ready, execution);
            if publishes {
                self.publish.push((done, candidate, id, output));
            }
        }
        self.publish.sort_unstable();
        for (ready, candidate, _, output) in self.publish {
            if candidate {
                return self.publication.available().max(ready);
            }
            self.publication.reserve(ready, output);
        }
        candidate_ready.saturating_add(execution)
    }
}

/// Predict when the new action can start publishing, not merely when a
/// nominal count of outstanding jobs would clear a compiler semaphore.
pub(super) struct PipelineForecast {
    pub inputs_ready_at: f64,
    pub ready_at: f64,
    pub traffic: InputTraffic,
}

fn pending_jobs<'a>(assigned: &'a Assignments, placement: &'a NativePlacement) -> Vec<Pending<'a>> {
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
    pending
}

pub(super) fn publication_forecast(
    forecast: super::WorkerForecast<'_>,
    requested: &NativeInputBlobs,
    catalog: Option<&PackageCatalog>,
    rates: DeliveryRates,
    direct: Option<&DirectInputs>,
) -> PipelineForecast {
    let super::WorkerForecast {
        capacity,
        assigned,
        placement,
        recent,
        cost,
    } = forecast;
    let jobs = assigned
        .len()
        .saturating_add(placement.queue.jobs.len())
        .saturating_add(1);
    let mut pipeline = Pipeline::new(capacity, placement, jobs);
    let mut staging = Vec::new();
    let mut pending = pending_jobs(assigned, placement);
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
                        pipeline.ready.push((
                            Duration::ZERO,
                            false,
                            job.id,
                            false,
                            pipeline.execution,
                            Duration::ZERO,
                        ));
                    }
                } else {
                    staging.push(job);
                }
            }
            _ => pipeline.observe(job, placement),
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
        rates,
        direct,
        cost: placement.timing.transfer,
        limits: placement.package_limits,
        traffic: InputTraffic::default(),
        residency: WorkerResidency::new(assigned, placement, recent),
        future: HashMap::new(),
    };
    for job in staging {
        let ready = timeline.stage(
            job.inputs.map(|job| &job.inputs),
            job.progress,
            job.inputs.map(|job| job.packages.as_ref()),
            job.inputs
                .and_then(|job| job.cost)
                .unwrap_or(cost)
                .phase
                .staging(),
        );
        let (execution, output) = pipeline.service(job.inputs.and_then(|job| job.cost), placement);
        pipeline
            .ready
            .push((ready, false, job.id, true, execution, output));
    }
    let ready = timeline.stage(Some(requested), None, catalog, cost.phase.staging());
    let (execution, output) = pipeline.service(Some(cost), placement);
    PipelineForecast {
        inputs_ready_at: ready.as_secs_f64(),
        ready_at: pipeline.finish(ready, execution, output).as_secs_f64(),
        traffic: timeline.traffic,
    }
}

#[cfg(test)]
mod tests;
