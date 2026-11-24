//! Native placement prediction over verified content, worker timing and
//! directional shared-link observations.
use super::ServerDetails;
use sccache::{
    build_runtime::{
        DirectionSnapshot, NetworkSnapshot, Peer, ResultTransferEstimate, TransferDemand,
    },
    dist::{self, JobId, ServerId},
};
use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};

/// Exact missing content union for a worker, excluding advisory resident blobs.
/// A warm new action does not depend on the unrelated backlog.
fn native_missing_inputs(
    assigned: &HashMap<JobId, dist::NativeInputBlobs>,
    placement: &dist::NativePlacement,
    requested: Option<&dist::NativeInputBlobs>,
) -> (u128, usize) {
    let resident = |id| {
        placement
            .residency
            .as_ref()
            .is_some_and(|filter| filter.may_contain(id))
    };
    let mut missing = dist::NativeInputBlobs::new();
    if let Some(inputs) = requested {
        missing.extend(
            inputs
                .iter()
                .filter(|(id, _)| !resident(**id))
                .map(|(&id, &size)| (id, size)),
        );
        if missing.is_empty() {
            return (0, 0);
        }
    }
    for (&id, &size) in assigned.values().flat_map(|inputs| inputs.iter()) {
        if !resident(id) {
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
        return (
            demand.bytes as f64 / demand.bytes_per_second.max(1) as f64,
            0.0,
        );
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
                    let (bytes, _) = native_missing_inputs(&details.jobs_assigned, placement, None);
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

/// Overlap compiler queue waiting
/// and input delivery. Include the measured
/// effective application service time and the marginal delay to other peers.
pub(super) fn native_eta_seconds(
    capacity: f64,
    assigned: &HashMap<JobId, dist::NativeInputBlobs>,
    placement: &dist::NativePlacement,
    requested: &dist::NativeInputBlobs,
    peer: Peer,
    plan: &NativeTransferPlan<'_>,
) -> f64 {
    let (bytes, requests) = native_missing_inputs(assigned, placement, Some(requested));
    let cost = placement.transfer;
    let (network, externality) = plan.input_completion(peer, bytes, cost.download_bytes_per_second);
    let logical_rate = plan.send.logical_rate(peer, cost.download_bytes_per_second);
    let staging_seconds = bytes as f64 / logical_rate as f64;
    let batches = (requests as u128).div_ceil(u128::from(cost.raw_parallelism));
    let overhead = Duration::from_nanos(
        u64::try_from(batches * u128::from(cost.raw_request_nanoseconds)).unwrap_or(u64::MAX),
    )
    .as_secs_f64();
    let transfer_seconds = network.max(staging_seconds) + overhead;
    let execution = Duration::from_nanos(placement.execution_nanoseconds).as_secs_f64();
    let capacity = capacity.max(1.0);
    let queue = (assigned.len() as f64 + 1.0 - capacity).max(0.0) / capacity * execution;
    let ready_at = queue.max(transfer_seconds) + execution;
    let (output_network, output_externality) =
        plan.result_completion(peer, ready_at, placement.result);
    let output_processing =
        placement.result.expected_bytes as f64 / placement.result.bytes_per_second as f64;
    let output_overhead = Duration::from_nanos(
        placement
            .result
            .expected_requests
            .saturating_mul(placement.result.request_nanoseconds),
    )
    .as_secs_f64();
    ready_at
        + output_network.max(output_processing)
        + output_overhead
        + externality
        + output_externality
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
                    wire_per_mille: 1000,
                    active_remaining_bytes: 100_000_000,
                    body_bytes: 0,
                },
            )]),
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
