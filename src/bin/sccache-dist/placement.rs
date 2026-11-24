//! Native placement prediction over verified content, worker timing and
//! directional shared-link observations.
use super::ServerDetails;
mod cost;
mod exploration;
pub(super) use cost::{ActionClass, ActionCost, ActionCosts, AssignedNative};
mod pipeline;
mod retained;
pub(super) use exploration::{Exploration, choose_worker};
pub(super) use retained::RecentResidency;
use sccache::{
    build_runtime::{
        DirectionSnapshot, NetworkSnapshot, Peer, ResultTransferEstimate, TransferDemand,
        transfer_seconds,
    },
    dist::{self, ServerId},
};
use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};

/// Exact missing content union for a worker, excluding advisory resident blobs.
/// A warm new action does not depend on the unrelated backlog.
fn native_missing_inputs(
    assigned: &pipeline::Assignments,
    placement: &dist::NativePlacement,
    recent: &RecentResidency,
    requested: Option<&dist::NativeInputBlobs>,
) -> (u128, usize) {
    let residency = pipeline::WorkerResidency::new(assigned, placement, recent);
    let mut missing = dist::NativeInputBlobs::new();
    if let Some(inputs) = requested {
        missing.extend(
            inputs
                .iter()
                .filter(|(id, size)| !residency.contains(**id, **size))
                .map(|(&id, &size)| (id, size)),
        );
        if missing.is_empty() {
            return (0, 0);
        }
    }
    for (&id, &size) in assigned
        .iter()
        .filter(|(job, _)| {
            placement.queue.jobs.get(job).is_none_or(|progress| {
                progress.phase != sccache::build_runtime::wire::NativeJobPhase::Terminal
            })
        })
        .filter_map(|(_, inputs)| inputs.as_ref())
        .flat_map(|job| job.inputs.iter())
    {
        if !residency.contains(id, size) {
            missing.entry(id).or_insert(size);
        }
    }
    (
        missing.values().map(|&size| u128::from(size)).sum(),
        missing.len(),
    )
}

pub(super) struct NativeTransferPlan<'a> {
    send: &'a DirectionSnapshot,
    receive: &'a DirectionSnapshot,
    send_demands: BTreeMap<Peer, TransferDemand>,
    send_baseline: BTreeMap<Peer, f64>,
    receive_demands: BTreeMap<Peer, TransferDemand>,
}

fn active_demands(network: &DirectionSnapshot) -> BTreeMap<Peer, TransferDemand> {
    network
        .peers
        .iter()
        .filter(|(_, capacity)| capacity.active_remaining_bytes > 0)
        .map(|(&peer, capacity)| {
            (
                peer,
                TransferDemand {
                    bytes: u128::from(capacity.active_remaining_bytes),
                    bytes_per_second: if capacity.observed_bytes_per_second == 0 {
                        128 << 20
                    } else {
                        capacity.observed_bytes_per_second
                    },
                },
            )
        })
        .collect()
}

fn marginal_completion(
    network: &DirectionSnapshot,
    demands: &BTreeMap<Peer, TransferDemand>,
    baseline: &BTreeMap<Peer, f64>,
    peer: Peer,
    demand: TransferDemand,
) -> (f64, f64) {
    if network.shared.is_empty() {
        return (transfer_seconds(demand.bytes, demand.bytes_per_second), 0.0);
    }
    let mut updated = demands.clone();
    updated.insert(peer, demand);
    let after = network.finish_times(&updated);
    let externality = baseline
        .iter()
        .filter(|(other, _)| **other != peer)
        .map(|(other, before)| (after.get(other).copied().unwrap_or(*before) - before).max(0.0))
        .sum();
    (after.get(&peer).copied().unwrap_or(0.0), externality)
}

impl<'a> NativeTransferPlan<'a> {
    pub(super) fn new(
        network: &'a NetworkSnapshot,
        servers: &HashMap<ServerId, ServerDetails>,
    ) -> Self {
        let mut send_demands = active_demands(&network.send);
        // Other workers' predicted input closures are only needed if they can
        // contend for a known shared resource. Avoid scanning them otherwise.
        if !network.send.shared.is_empty() {
            for (&id, details) in servers {
                if let Some(placement) = &details.capabilities.native_placement {
                    let peer = Peer::Worker(id.addr());
                    let (bytes, _) = native_missing_inputs(
                        &details.jobs_assigned,
                        placement,
                        &details.recent_residency,
                        None,
                    );
                    let demand = Self::input_demand(
                        &network.send,
                        peer,
                        bytes,
                        placement.transfer.download_bytes_per_second,
                    );
                    if demand.bytes > 0 {
                        send_demands.insert(peer, demand);
                    }
                }
            }
        }
        let send_baseline = network.send.finish_times(&send_demands);
        Self {
            send: &network.send,
            receive: &network.receive,
            send_demands,
            send_baseline,
            receive_demands: active_demands(&network.receive),
        }
    }

    fn input_demand(
        network: &DirectionSnapshot,
        peer: Peer,
        logical: u128,
        logical_rate: u64,
    ) -> TransferDemand {
        let bytes = network.wire_bytes(peer, logical);
        let active = network
            .peers
            .get(&peer)
            .map_or(0, |capacity| capacity.active_remaining_bytes);
        let fallback =
            u64::try_from(network.wire_bytes(peer, u128::from(logical_rate))).unwrap_or(u64::MAX);
        TransferDemand {
            // Active worker input bytes already belong to the reserved input union.
            bytes: bytes.max(u128::from(active)),
            bytes_per_second: network.rate(peer, fallback),
        }
    }

    fn input_completion(&self, peer: Peer, logical: u128, logical_rate: u64) -> (f64, f64) {
        if logical == 0 {
            return (0.0, 0.0);
        }
        let demand = Self::input_demand(self.send, peer, logical, logical_rate);
        marginal_completion(
            self.send,
            &self.send_demands,
            &self.send_baseline,
            peer,
            demand,
        )
    }

    fn result_completion(
        &self,
        peer: Peer,
        ready_at: f64,
        result: ResultTransferEstimate,
    ) -> (f64, f64) {
        if result.expected_bytes == 0 {
            return (0.0, 0.0);
        }
        // Output publication starts after staging, queue wait and execution.
        // Do not charge traffic that has already drained by that point.
        let remaining = self
            .receive
            .remaining_after(&self.receive_demands, ready_at);
        let baseline = self.receive.finish_times(&remaining);
        let already_pending = remaining.get(&peer).map_or(0, |demand| demand.bytes);
        let demand = TransferDemand {
            bytes: already_pending.saturating_add(u128::from(result.expected_bytes)),
            bytes_per_second: self.receive.rate(peer, result.bytes_per_second),
        };
        marginal_completion(self.receive, &remaining, &baseline, peer, demand)
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub(super) struct PlacementEstimate {
    pub(super) seconds: f64,
    pub(super) completion_seconds: f64,
    missing_input_union_bytes: u128,
    ready_at: f64,
}

/// Overlap compiler queue waiting
/// and input delivery. Include the measured
/// effective application service time and the marginal delay to other peers.
#[derive(Clone, Copy)]
pub(super) struct WorkerForecast<'a> {
    pub capacity: f64,
    pub assigned: &'a pipeline::Assignments,
    pub placement: &'a dist::NativePlacement,
    pub recent: &'a RecentResidency,
    pub cost: ActionCost,
}

impl<'a> WorkerForecast<'a> {
    pub(super) fn new(
        details: &'a ServerDetails,
        class: Option<ActionClass>,
        now: std::time::Instant,
    ) -> Option<Self> {
        let placement = details.capabilities.native_placement.as_ref()?;
        Some(Self {
            capacity: details.cpu_capacity,
            assigned: &details.jobs_assigned,
            placement,
            recent: &details.recent_residency,
            cost: details.action_costs.predict(class, placement, now),
        })
    }
}

pub(super) fn native_estimate(
    forecast: WorkerForecast<'_>,
    requested: &dist::NativeInputBlobs,
    peer: Peer,
    plan: &NativeTransferPlan<'_>,
) -> PlacementEstimate {
    let WorkerForecast {
        assigned,
        placement,
        recent,
        cost: action,
        ..
    } = forecast;
    let (bytes, _) = native_missing_inputs(assigned, placement, recent, Some(requested));
    let cost = placement.transfer;
    let (network, externality) = plan.input_completion(peer, bytes, cost.download_bytes_per_second);
    let logical_rate = plan.send.logical_rate(peer, cost.download_bytes_per_second);
    // A warm candidate adds no network traffic but existing staging still
    // consumes the worker's aggregate link. Use the baseline contention for it.
    let (backlog, network_time) = if bytes == 0 {
        let (backlog, _) = native_missing_inputs(assigned, placement, recent, None);
        (
            backlog,
            plan.input_completion(peer, backlog, cost.download_bytes_per_second)
                .0,
        )
    } else {
        (bytes, network)
    };
    let unconstrained = transfer_seconds(backlog, logical_rate);
    let contention = if unconstrained > 0.0 {
        (network_time / unconstrained).max(1.0)
    } else {
        1.0
    };
    let ready_at = pipeline::publication_start(forecast, requested, logical_rate, contention);
    let result = action.result(placement.result);
    let (output_network, output_externality) = plan.result_completion(peer, ready_at, result);
    let output_processing =
        transfer_seconds(u128::from(result.expected_bytes), result.bytes_per_second);
    let output_overhead = Duration::from_nanos(
        result
            .expected_requests
            .saturating_mul(result.request_nanoseconds),
    )
    .as_secs_f64();
    let completion_seconds = ready_at + output_network.max(output_processing) + output_overhead;
    PlacementEstimate {
        ready_at,
        completion_seconds,
        missing_input_union_bytes: bytes,
        seconds: completion_seconds + externality + output_externality,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccache::build_runtime::{PeerCapacity, SharedCapacity};

    fn worker(port: u16) -> Peer {
        Peer::Worker(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn constrained(a: Peer, b: Peer) -> DirectionSnapshot {
        DirectionSnapshot {
            peers: BTreeMap::from([(
                a,
                PeerCapacity {
                    observed_bytes_per_second: 100_000_000,
                    isolated_bytes_per_second: 100_000_000,
                    wire_per_mille: 1000,
                    active_remaining_bytes: 100_000_000,
                    body_bytes: 0,
                },
            )]),
            independent: Vec::new(),
            shared: vec![SharedCapacity {
                members: [a, b].into_iter().collect(),
                bytes_per_second: 100_000_000,
            }],
        }
    }

    #[test]
    fn native_shared_send_penalizes_new_contention_not_reusing_existing_backlog() {
        let a = worker(1);
        let b = worker(2);
        let c = worker(3);
        let network = NetworkSnapshot {
            send: constrained(a, b),
            receive: DirectionSnapshot::default(),
        };
        let plan = NativeTransferPlan::new(&network, &HashMap::new());
        assert_eq!(
            plan.input_completion(a, 100_000_000, 100_000_000),
            (1.0, 0.0)
        );
        assert_eq!(
            plan.input_completion(b, 100_000_000, 100_000_000),
            (2.0, 1.0)
        );
        assert_eq!(
            plan.input_completion(c, 100_000_000, 100_000_000),
            (1.0, 0.0)
        );
        assert_eq!(plan.input_completion(b, 0, 100_000_000), (0.0, 0.0));
    }

    #[test]
    fn native_result_upload_is_predicted_at_completion_not_admission() {
        let a = worker(1);
        let b = worker(2);
        let network = NetworkSnapshot {
            send: DirectionSnapshot::default(),
            receive: constrained(a, b),
        };
        let plan = NativeTransferPlan::new(&network, &HashMap::new());
        let result = ResultTransferEstimate {
            expected_bytes: 100_000_000,
            bytes_per_second: 100_000_000,
            ..ResultTransferEstimate::default()
        };
        assert_eq!(plan.result_completion(b, 0.0, result), (2.0, 1.0));
        assert_eq!(plan.result_completion(b, 0.5, result), (1.5, 0.5));
        assert_eq!(plan.result_completion(b, 2.0, result), (1.0, 0.0));
    }
}
