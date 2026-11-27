//! Read-only projection of the scheduler's authoritative state.
use std::{
    sync::atomic::Ordering,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow};
use sccache_dashboard::{
    HostRole, Job, JobDescription, NativeWorker, NetworkHost, NetworkLink, RouteEvidence, Snapshot,
    Worker,
};

use super::{JobDetail, Scheduler, ServerDetails};
use sccache::build_runtime::wire::NativeJobPhase;
use sccache::dist::{self, JobId, ServerId};

// Keep only bounded, human-facing labels. Never retain argv, environment,
// authorization, or absolute paths in the dashboard's job roster.
fn label(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|character| !character.is_control())
        .take(96)
        .collect()
}

fn basename(path: &[u8]) -> String {
    label(path.rsplit(|byte| *byte == b'/').next().unwrap_or(path))
}

fn argument_value(arguments: &[Vec<u8>], flag: &[u8]) -> Option<String> {
    arguments.iter().enumerate().find_map(|(index, argument)| {
        let value = if argument == flag {
            arguments.get(index + 1)?.as_slice()
        } else {
            argument.strip_prefix(flag)?.strip_prefix(b"=")?
        };
        // A custom target JSON path is not a target triple. Use only its basename.
        let value = basename(value);
        (!value.is_empty()).then_some(value)
    })
}

pub fn describe_native(assignment: &dist::NativeAssignment) -> JobDescription {
    let spec = &assignment.spec;
    let subject = argument_value(&spec.command.arguments, b"--crate-name").or_else(|| {
        let mut outputs = spec.outputs.values();
        let first = basename(outputs.next()?.path.as_bytes());
        let remaining = outputs.len();
        Some(if remaining == 0 {
            first
        } else {
            format!("{first} (+{remaining} outputs)")
        })
    });
    JobDescription {
        executable: basename(spec.command.executable.as_bytes()),
        subject,
        target: argument_value(&spec.command.arguments, b"--target"),
        requester: assignment.receiver.as_ref().map(|(id, _)| id.to_string()),
        input_bytes: assignment
            .input_blobs
            .values()
            .copied()
            .fold(0, u64::saturating_add),
        input_blobs: assignment.input_blobs.len(),
    }
}

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
    let identity = id.to_string();
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
                cache_analytics: placement.cache_analytics.clone(),
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
            .unwrap_or_else(|| identity.clone()),
        id: identity,
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

fn node(
    id: ServerId,
    name: String,
    role: HostRole,
    status: &str,
    report: &sccache::build_runtime::wire::InterfaceReport,
) -> NetworkHost {
    let interfaces = report
        .interfaces
        .iter()
        .map(|interface| sccache_dashboard::HostInterface {
            index: interface.index,
            addresses: interface
                .addresses
                .iter()
                .map(ToString::to_string)
                .collect(),
            nominal_bytes_per_second: interface.nominal_capacity,
            tx_bytes_per_second: interface.send.total_bytes_per_second,
            rx_bytes_per_second: interface.receive.total_bytes_per_second,
            external_tx_bytes_per_second: interface.send.external_bytes_per_second,
            external_rx_bytes_per_second: interface.receive.external_bytes_per_second,
        })
        .collect::<Vec<_>>();
    let addresses = interfaces
        .iter()
        .flat_map(|interface| interface.addresses.iter().cloned())
        .collect();
    NetworkHost {
        id: id.to_string(),
        name,
        role,
        status: status.into(),
        addresses,
        interfaces,
    }
}

fn peer_links(
    snapshot: &mut Snapshot,
    receiver: ServerId,
    rates: &[sccache::build_runtime::wire::PeerDownloadRate],
) {
    for rate in rates {
        let source = rate.source.to_string();
        let target = receiver.to_string();
        let path = rate.path;
        snapshot.topology.links.push(NetworkLink {
            id: format!("{source}>{target}|{}|{}", path.local, path.remote),
            source,
            target,
            source_address: Some(path.local.to_string()),
            target_address: Some(path.remote.to_string()),
            evidence: RouteEvidence::Measured,
            wire_bytes_per_second: None,
            logical_bytes_per_second: Some(rate.logical_bytes_per_second),
            remaining_bytes: None,
        });
    }
}

fn accumulate_worker(snapshot: &mut Snapshot, worker: &Worker) {
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
}

fn project_job(
    job_id: JobId,
    details: &ServerDetails,
    worker: &Worker,
    detail: Option<&JobDetail>,
) -> Job {
    let progress = details
        .capabilities
        .native_placement
        .as_ref()
        .and_then(|placement| placement.queue.jobs.get(&job_id));
    let (state, assigned_at, state_since, prediction) = detail.map_or_else(
        || {
            details.jobs_assigning.get(&job_id).map_or_else(
                // Preserve the reservation in the count, but never invent a timestamp.
                || ("Missing scheduler state".into(), None, None, None),
                |&since| ("Assigning".into(), Some(since), Some(since), None),
            )
        },
        |detail| {
            (
                detail.state.to_string(),
                Some(detail.assigned_at),
                Some(detail.state_since),
                detail.prediction,
            )
        },
    );
    Job {
        id: job_id.to_string(),
        description: details
            .jobs_assigned
            .get(&job_id)
            .and_then(Option::as_ref)
            .and_then(|native| native.dashboard.clone()),
        worker: worker.name.clone(),
        worker_id: worker.id.clone(),
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
    }
}

pub fn snapshot(scheduler: &Scheduler) -> Result<Snapshot> {
    // Filesystem checks and ordering work must not hold the scheduler mutexes.
    let draining = scheduler.is_draining();
    let jobs = scheduler
        .jobs
        .try_lock()
        .map_err(|error| anyhow!("dashboard jobs lock unavailable: {error}"))?;
    let servers = scheduler
        .servers
        .try_lock()
        .map_err(|error| anyhow!("dashboard servers lock unavailable: {error}"))?;
    let now = Instant::now();
    let mut snapshot = Snapshot::default();
    snapshot.totals.draining = draining;
    snapshot.totals.allocated_ids = scheduler.job_count.load(Ordering::Relaxed);
    for (&id, details) in servers.iter() {
        if now.saturating_duration_since(details.last_seen) > dist::http::HEARTBEAT_TIMEOUT {
            continue;
        }
        let worker = worker(id, details, scheduler, draining);
        let report = details
            .capabilities
            .native_placement
            .as_ref()
            .map(|placement| &placement.interfaces);
        let empty = sccache::build_runtime::wire::InterfaceReport::default();
        snapshot.topology.hosts.push(node(
            id,
            worker.name.clone(),
            HostRole::Worker,
            "Online",
            report.unwrap_or(&empty),
        ));
        if let Some(placement) = &details.capabilities.native_placement {
            peer_links(&mut snapshot, id, &placement.peer_download_rates);
        }
        accumulate_worker(&mut snapshot, &worker);
        for &job_id in details.jobs_assigned.keys() {
            snapshot
                .jobs
                .push(project_job(job_id, details, &worker, jobs.get(&job_id)));
        }
        snapshot.workers.push(worker);
    }
    drop(servers);
    drop(jobs);
    let clients = scheduler
        .dashboard_clients
        .try_lock()
        .map_err(|error| anyhow!("dashboard client registry unavailable: {error}"))?;
    for (&id, (seen, rates)) in clients.iter() {
        if now.saturating_duration_since(*seen) > dist::http::HEARTBEAT_TIMEOUT {
            continue;
        }
        snapshot.topology.hosts.push(node(
            id,
            format!("Client {}", &id.to_string()[..12]),
            HostRole::Client,
            "Recently requested work",
            &rates.interfaces,
        ));
        peer_links(&mut snapshot, id, &rates.peers);
    }
    drop(clients);
    snapshot.workers.sort_unstable_by(|a, b| a.id.cmp(&b.id));
    snapshot
        .jobs
        .sort_unstable_by(|a, b| (a.assigned_at_ms, &a.id).cmp(&(b.assigned_at_ms, &b.id)));
    Ok(snapshot)
}
