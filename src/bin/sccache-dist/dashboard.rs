//! Read-only projection of the scheduler's authoritative state.
use std::{collections::BTreeMap, sync::atomic::Ordering, time::Instant};

use anyhow::{Result, anyhow};
use sccache_dashboard::{Job, NativeWorker, Snapshot, Worker};

use super::{Scheduler, ServerDetails};
use sccache::dist::{self, ServerId};

const MAX_DISPLAYED_JOBS: usize = 1000;

fn worker(
    id: ServerId,
    details: &ServerDetails,
    scheduler: &Scheduler,
    now: Instant,
    draining: bool,
) -> Worker {
    let address = id.addr().to_string();
    let max_jobs = scheduler.job_slack.max_jobs(details.cpu_capacity);
    let demand = details.compiler_demand();
    let native = details
        .capabilities
        .native_placement
        .as_ref()
        .map(|placement| {
            let queue = &placement.queue;
            let mut phases = BTreeMap::new();
            let mut remaining = 0_u64;
            for progress in queue.jobs.values() {
                *phases
                    .entry(format!("{:?}", progress.phase))
                    .or_insert(0_usize) += 1;
                remaining = remaining.saturating_add(progress.remaining_input_bytes);
            }
            NativeWorker {
                reservations: queue.jobs.len(),
                capacity: queue.capacity,
                compiler_active: queue.compiler_active,
                compiler_slots: queue.compiler_slots,
                staging_slots: queue.staging_slots,
                publication_slots: queue.publication_slots,
                phases: phases.into_iter().collect(),
                remaining_input_bytes: remaining,
                timing_revision: placement.timing.revision,
                execution_ns: placement.timing.execution_nanoseconds,
                input_bytes_per_second: placement.timing.transfer.download_bytes_per_second,
                output_bytes_per_second: placement.timing.result.bytes_per_second,
                output_observations: placement.timing.result.observations,
                residency_reported: placement.residency.is_some(),
            }
        });
    Worker {
        name: details
            .worker_name
            .clone()
            .unwrap_or_else(|| address.clone()),
        address,
        heartbeat_age_secs: now
            .saturating_duration_since(details.last_seen)
            .as_secs_f64(),
        last_error_age_secs: details
            .last_error
            .map(|error| now.saturating_duration_since(error).as_secs_f64()),
        cpu_capacity: details.cpu_capacity,
        assigned: details.jobs_assigned.len(),
        assigning: details.jobs_assigning.len(),
        compiler_demand: demand,
        max_jobs,
        available: if draining {
            0
        } else {
            max_jobs
                .saturating_sub(demand)
                .min(details.native_headroom())
        },
        archive: details.capabilities.archive,
        native,
    }
}

pub(super) fn snapshot(scheduler: &Scheduler) -> Result<Snapshot> {
    let jobs = scheduler
        .jobs
        .lock()
        .map_err(|_| anyhow!("jobs mutex poisoned"))?;
    let servers = scheduler
        .servers
        .lock()
        .map_err(|_| anyhow!("servers mutex poisoned"))?;
    let now = Instant::now();
    let draining = scheduler.is_draining();
    let live = servers
        .iter()
        .filter(|(_, details)| {
            now.saturating_duration_since(details.last_seen) <= dist::http::HEARTBEAT_TIMEOUT
        })
        .collect::<Vec<_>>();
    let mut snapshot = Snapshot::default();
    snapshot.totals.draining = draining;
    snapshot.totals.allocated_ids = scheduler.job_count.load(Ordering::Relaxed);
    for (&id, details) in live {
        let worker = worker(id, details, scheduler, now, draining);
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
        snapshot.workers.push(worker);
    }
    snapshot
        .workers
        .sort_unstable_by(|a, b| a.address.cmp(&b.address));
    let mut active = jobs
        .iter()
        .filter_map(|(id, detail)| {
            let server = servers.get(&detail.server_id)?;
            if now.saturating_duration_since(server.last_seen) > dist::http::HEARTBEAT_TIMEOUT {
                return None;
            }
            Some((id, detail, server))
        })
        .collect::<Vec<_>>();
    snapshot.jobs_total = active.len();
    active.sort_unstable_by_key(|(id, detail, _)| (detail.assigned_at, **id));
    for (id, detail, server) in active.into_iter().take(MAX_DISPLAYED_JOBS) {
        let progress = server
            .capabilities
            .native_placement
            .as_ref()
            .and_then(|placement| placement.queue.jobs.get(id));
        snapshot.jobs.push(Job {
            id: id.to_string(),
            worker: server
                .worker_name
                .clone()
                .unwrap_or_else(|| detail.server_id.addr().to_string()),
            state: detail.state.to_string(),
            native_phase: progress.map(|progress| format!("{:?}", progress.phase)),
            age_secs: now
                .saturating_duration_since(detail.assigned_at)
                .as_secs_f64(),
            phase_age_secs: now
                .saturating_duration_since(detail.state_since)
                .as_secs_f64(),
            remaining_input_bytes: progress.map(|progress| progress.remaining_input_bytes),
            remaining_input_blobs: progress.map(|progress| progress.remaining_input_blobs),
            predicted_completion_secs: detail
                .prediction
                .map(|estimate| estimate.completion_seconds)
                .filter(|value| value.is_finite()),
        });
    }
    Ok(snapshot)
}
