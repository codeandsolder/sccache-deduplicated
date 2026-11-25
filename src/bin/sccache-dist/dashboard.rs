//! Read-only projection of the scheduler's authoritative state.
use std::{
    sync::atomic::Ordering,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow};
use sccache_dashboard::{Job, NativeWorker, Snapshot, Worker};

use super::{Scheduler, ServerDetails};
use sccache::build_runtime::wire::NativeJobPhase;
use sccache::dist::{self, ServerId};

fn timestamp_ms(instant: Instant) -> u64 {
    static ORIGIN: std::sync::OnceLock<(Instant, u64)> = std::sync::OnceLock::new();
    let (origin, unix_ms) = *ORIGIN.get_or_init(|| {
        (
            Instant::now(),
            u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
            )
            .unwrap_or(u64::MAX),
        )
    });
    let millis =
        |duration: std::time::Duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    if instant >= origin {
        unix_ms.saturating_add(millis(instant.duration_since(origin)))
    } else {
        unix_ms.saturating_sub(millis(origin.duration_since(instant)))
    }
}

fn worker(id: ServerId, details: &ServerDetails, scheduler: &Scheduler, draining: bool) -> Worker {
    let address = id.addr().to_string();
    let max_jobs = scheduler.job_slack.max_jobs(details.cpu_capacity);
    let demand = details.compiler_demand();
    let native = details
        .capabilities
        .native_placement
        .as_ref()
        .map(|placement| {
            let queue = &placement.queue;
            let phases = [
                NativeJobPhase::Assigned,
                NativeJobPhase::Queued,
                NativeJobPhase::Staging,
                NativeJobPhase::Ready,
                NativeJobPhase::Executing,
                NativeJobPhase::AwaitingPublication,
                NativeJobPhase::Publishing,
                NativeJobPhase::Terminal,
            ];
            let mut counts = [0_usize; 8];
            let mut remaining = 0_u64;
            for progress in queue.jobs.values() {
                let index = match progress.phase {
                    NativeJobPhase::Assigned => 0,
                    NativeJobPhase::Queued => 1,
                    NativeJobPhase::Staging => 2,
                    NativeJobPhase::Ready => 3,
                    NativeJobPhase::Executing => 4,
                    NativeJobPhase::AwaitingPublication => 5,
                    NativeJobPhase::Publishing => 6,
                    NativeJobPhase::Terminal => 7,
                };
                counts[index] += 1;
                remaining = remaining.saturating_add(progress.remaining_input_bytes);
            }
            NativeWorker {
                reservations: queue.jobs.len(),
                capacity: queue.capacity,
                compiler_active: queue.compiler_active,
                compiler_slots: queue.compiler_slots,
                staging_slots: queue.staging_slots,
                publication_slots: queue.publication_slots,
                phases: phases
                    .into_iter()
                    .zip(counts)
                    .filter(|(_, count)| *count != 0)
                    .map(|(phase, count)| (format!("{phase:?}"), count))
                    .collect(),
                remaining_input_bytes: remaining,
                timing_revision: placement.timing.revision,
                execution_ns: placement.timing.execution_nanoseconds,
                input_bytes_per_second: placement.timing.transfer.download_bytes_per_second,
                output_bytes_per_second: placement.timing.result.bytes_per_second,
                output_observations: placement.timing.result.observations,
                residency_reported: placement.residency.is_some(),
            }
        });
    let slots = if draining {
        0
    } else {
        max_jobs.saturating_sub(demand)
    };
    let archive_available = details.capabilities.archive.then_some(slots);
    let native_available = native
        .as_ref()
        .map(|_| slots.min(details.native_headroom()));
    Worker {
        name: details
            .worker_name
            .clone()
            .unwrap_or_else(|| address.clone()),
        address,
        heartbeat_at_ms: timestamp_ms(details.last_seen),
        last_error_at_ms: details.last_error.map(timestamp_ms),
        cpu_capacity: details.cpu_capacity,
        assigned: details.jobs_assigned.len(),
        assigning: details.jobs_assigning.len(),
        compiler_demand: demand,
        max_jobs,
        available: archive_available.unwrap_or_else(|| native_available.unwrap_or(0)),
        archive_available,
        native_available,
        native,
    }
}

pub(super) fn snapshot(scheduler: &Scheduler) -> Result<Snapshot> {
    // Filesystem checks and ordering work must not hold the scheduler mutexes.
    let draining = scheduler.is_draining();
    let jobs = scheduler
        .jobs
        .lock()
        .map_err(|_| anyhow!("jobs mutex poisoned"))?;
    let servers = scheduler
        .servers
        .lock()
        .map_err(|_| anyhow!("servers mutex poisoned"))?;
    let now = Instant::now();
    let mut snapshot = Snapshot::default();
    snapshot.totals.draining = draining;
    snapshot.totals.allocated_ids = scheduler.job_count.load(Ordering::Relaxed);
    for (&id, details) in servers.iter() {
        if now.saturating_duration_since(details.last_seen) > dist::http::HEARTBEAT_TIMEOUT {
            continue;
        }
        let worker = worker(id, details, scheduler, draining);
        let totals = &mut snapshot.totals;
        totals.workers += 1;
        totals.cpu_capacity += worker.cpu_capacity;
        totals.assigned = totals.assigned.saturating_add(worker.assigned);
        totals.assigning = totals.assigning.saturating_add(worker.assigning);
        totals.compiler_demand = totals
            .compiler_demand
            .saturating_add(worker.compiler_demand);
        totals.max_jobs = totals.max_jobs.saturating_add(worker.max_jobs);
        totals.available = totals.available.saturating_add(worker.available);
        if let Some(native) = &worker.native {
            totals.compiler_active = totals
                .compiler_active
                .saturating_add(native.compiler_active as usize);
        }
        for job_id in details.jobs_assigned.keys() {
            let progress = details
                .capabilities
                .native_placement
                .as_ref()
                .and_then(|placement| placement.queue.jobs.get(job_id));
            let (state, assigned_at, state_since, prediction) =
                if let Some(detail) = jobs.get(job_id) {
                    (
                        detail.state.to_string(),
                        Some(detail.assigned_at),
                        Some(detail.state_since),
                        detail.prediction,
                    )
                } else if let Some(&since) = details.jobs_assigning.get(job_id) {
                    ("Assigning".into(), Some(since), Some(since), None)
                } else {
                    // Preserve the reservation in the count, but never invent a timestamp.
                    ("Missing scheduler state".into(), None, None, None)
                };
            snapshot.jobs.push(Job {
                id: job_id.to_string(),
                worker: worker.name.clone(),
                worker_address: worker.address.clone(),
                state,
                native_phase: progress.map(|progress| format!("{:?}", progress.phase)),
                native_phase_observed_ns: progress.map(|progress| progress.phase_nanoseconds),
                assigned_at_ms: assigned_at.map(timestamp_ms),
                state_since_ms: state_since.map(timestamp_ms),
                remaining_input_bytes: progress.map(|progress| progress.remaining_input_bytes),
                remaining_input_blobs: progress.map(|progress| progress.remaining_input_blobs),
                predicted_completion_secs: prediction
                    .map(|estimate| estimate.completion_seconds)
                    .filter(|value| value.is_finite()),
            });
        }
        snapshot.workers.push(worker);
    }
    drop(servers);
    drop(jobs);
    snapshot
        .workers
        .sort_unstable_by(|a, b| a.address.cmp(&b.address));
    snapshot
        .jobs
        .sort_unstable_by(|a, b| (a.assigned_at_ms, &a.id).cmp(&(b.assigned_at_ms, &b.id)));
    Ok(snapshot)
}
