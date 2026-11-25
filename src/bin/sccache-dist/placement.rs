//! Native placement prediction over verified content, worker timing and
//! directional shared-link observations.
use super::ServerDetails;
mod cost;
mod delivery;
use delivery::{DeliveryRates, DirectInputs, InputTraffic};
mod exploration;
pub(super) use cost::{
    ActionClass, ActionCost, AssignedNative, CostBook, WorkerScope, start_checkpoint,
};
mod milestone;
pub(super) use milestone::Milestone;
mod pipeline;
mod retained;
pub(super) use exploration::{Exploration, choose_worker};
pub(super) use retained::RecentResidency;
use sccache::{
    build_runtime::{
        Direction, DirectionSnapshot, NetworkSnapshot, PackageCatalog, Peer,
        ResultTransferEstimate, TransferDemand, transfer_seconds,
        wire::{CachePathRate, CachePathRates, ClientDeliveryRates},
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
    packages: Option<&'a PackageCatalog>,
    send: &'a DirectionSnapshot,
    receive: &'a DirectionSnapshot,
    send_demands: BTreeMap<Peer, TransferDemand>,
    send_baseline: BTreeMap<Peer, f64>,
    receive_demands: BTreeMap<Peer, TransferDemand>,
    path_rates: BTreeMap<Peer, CachePathRates>,
    direct_inputs: BTreeMap<Peer, DirectInputs>,
    receiver: Option<&'a (ServerId, ClientDeliveryRates)>,
}

const fn directional_rate(rates: CachePathRates, direction: Direction) -> Option<CachePathRate> {
    match direction {
        Direction::Send => rates.download,
        Direction::Receive => rates.upload,
    }
}

fn predicted_peer(peer: Peer, rate: Option<CachePathRate>) -> Peer {
    rate.map_or(peer, |rate| peer.on_path(rate.path))
}

fn active_on_other_paths(network: &DirectionSnapshot, peer: Peer) -> u128 {
    network
        .peers
        .iter()
        .filter(|(other, _)| **other != peer && other.principal() == peer.principal())
        .map(|(_, capacity)| u128::from(capacity.active_remaining_bytes))
        .sum()
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
    direction: Direction,
) -> (f64, f64) {
    let relevant = |other: Peer| {
        other == peer
            || (direction == Direction::Send
                && matches!(peer.principal(), Peer::Worker(_))
                && other.principal() == peer.principal())
    };
    if network.shared.is_empty() {
        let completion = transfer_seconds(demand.bytes, demand.bytes_per_second);
        let other_completion = demands
            .iter()
            .filter(|(other, _)| **other != peer && relevant(**other))
            .map(|(_, other)| transfer_seconds(other.bytes, other.bytes_per_second))
            .fold(0.0, f64::max);
        return (completion.max(other_completion), 0.0);
    }
    let mut updated = demands.clone();
    updated.insert(peer, demand);
    let after = network.finish_times(&updated);
    let externality = baseline
        .iter()
        .filter(|(other, _)| other.principal() != peer.principal())
        .map(|(other, before)| (after.get(other).copied().unwrap_or(*before) - before).max(0.0))
        .sum();
    let completion = after
        .iter()
        .filter(|(other, _)| relevant(**other))
        .map(|(_, &seconds)| seconds)
        .fold(0.0, f64::max);
    (completion, externality)
}

/// Build the bounded direct-source forecast from the exact input unions,
/// current receiver measurements and the source's authenticated residency.
fn direct_input_forecasts(
    servers: &HashMap<ServerId, ServerDetails>,
    requested: Option<&dist::NativeInputBlobs>,
) -> BTreeMap<Peer, DirectInputs> {
    let mut forecasts = BTreeMap::new();
    let now = std::time::Instant::now();
    for (&receiver, details) in servers {
        let Some(placement) = &details.capabilities.native_placement else {
            continue;
        };
        if placement.peer_download_rates.is_empty()
            || now.duration_since(details.last_seen) >= Duration::from_secs(20)
        {
            continue;
        }
        let mut inputs = dist::NativeInputBlobs::new();
        inputs.extend(
            requested
                .into_iter()
                .flat_map(|inputs| inputs.iter())
                .map(|(&id, &size)| (id, size)),
        );
        for job in details.jobs_assigned.values().flatten() {
            inputs.extend(job.inputs.iter().map(|(&id, &size)| (id, size)));
        }
        let mut direct = DirectInputs::new();
        for rate in &placement.peer_download_rates {
            let Some(source) = servers.get(&rate.source) else {
                continue;
            };
            if rate.source == receiver
                || source.last_error.is_some()
                || now.duration_since(source.last_seen) >= Duration::from_secs(20)
            {
                continue;
            }
            let Some(source_placement) = &source.capabilities.native_placement else {
                continue;
            };
            let residency = pipeline::WorkerResidency::new(
                &source.jobs_assigned,
                source_placement,
                &source.recent_residency,
            );
            for (&id, &size) in &inputs {
                if residency.contains(id, size) {
                    direct
                        .entry(id)
                        .and_modify(|best| *best = (*best).max(rate.logical_bytes_per_second))
                        .or_insert(rate.logical_bytes_per_second);
                }
            }
        }
        if !direct.is_empty() {
            forecasts.insert(Peer::Worker(receiver), direct);
        }
    }
    forecasts
}

impl<'a> NativeTransferPlan<'a> {
    pub(super) fn new(
        network: &'a NetworkSnapshot,
        servers: &HashMap<ServerId, ServerDetails>,
        packages: Option<&'a PackageCatalog>,
        requested: Option<&dist::NativeInputBlobs>,
    ) -> Self {
        let path_rates: BTreeMap<_, _> = servers
            .iter()
            .filter_map(|(&id, details)| {
                let rates = details
                    .capabilities
                    .native_placement
                    .as_ref()?
                    .cache_path_rates;
                rates.valid().then_some((Peer::Worker(id), rates))
            })
            .collect();
        let direct_inputs = direct_input_forecasts(servers, requested);
        let mut send_demands = active_demands(&network.send);
        let mut receive_demands = active_demands(&network.receive);
        for (peer, rates) in &path_rates {
            if let Some(rate) = rates.download
                && let Some(demand) = send_demands.get_mut(&peer.on_path(rate.path))
            {
                demand.bytes_per_second = rate.bytes_per_second;
            }
            if let Some(rate) = rates.upload
                && let Some(demand) = receive_demands.get_mut(&peer.on_path(rate.path))
            {
                demand.bytes_per_second = rate.bytes_per_second;
            }
        }
        // Other workers' predicted input closures are only needed if they can
        // contend for a known shared resource. Avoid scanning them otherwise.
        if !network.send.shared.is_empty() {
            for (&id, details) in servers {
                if let Some(placement) = &details.capabilities.native_placement {
                    let rate = placement.cache_path_rates.download;
                    let peer = predicted_peer(Peer::Worker(id), rate);
                    let Some(forecast) = WorkerForecast::new(details, None) else {
                        continue;
                    };
                    let rates = DeliveryRates::new(
                        &network.send,
                        peer,
                        placement.timing.transfer,
                        rate.map(|rate| rate.bytes_per_second),
                    );
                    let traffic = pipeline::publication_forecast(
                        forecast,
                        &dist::NativeInputBlobs::new(),
                        None,
                        rates,
                        direct_inputs.get(&Peer::Worker(id)),
                    )
                    .traffic;
                    if traffic.wire_bytes > 0 {
                        let demand = Self::input_demand(
                            &network.send,
                            peer,
                            traffic,
                            rate.map(|rate| rate.bytes_per_second),
                        );
                        send_demands.insert(peer, demand);
                    }
                }
            }
        }
        let send_baseline = network.send.finish_times(&send_demands);
        Self {
            packages,
            send: &network.send,
            receive: &network.receive,
            send_demands,
            send_baseline,
            receive_demands,
            path_rates,
            direct_inputs,
            receiver: None,
        }
    }

    pub(super) const fn with_receiver(
        mut self,
        receiver: Option<&'a (ServerId, ClientDeliveryRates)>,
    ) -> Self {
        self.receiver = receiver;
        self
    }

    /// Publication and receiver delivery are separate consumers. The latter
    /// may require a full result even when the scheduler misses no blobs.
    fn client_completion(
        &self,
        worker: Peer,
        negotiation_at: f64,
        publication: f64,
        cost: ActionCost,
    ) -> (f64, f64) {
        let Some((id, rates)) = self.receiver else {
            return (publication, 0.0);
        };
        let client = predicted_peer(Peer::Client(*id), rates.scheduler);
        let wire_rate = rates.scheduler.map_or_else(
            || self.send.rate(client, 16 << 20),
            |rate| rate.bytes_per_second,
        );
        let full = u128::from(cost.result_bytes);
        let scheduler_wire = self.send.wire_bytes(client, full);
        let scheduler_seconds = transfer_seconds(scheduler_wire, wire_rate);
        let direct_rate = match worker.principal() {
            Peer::Worker(source) => rates
                .peers
                .binary_search_by_key(&source, |rate| rate.source)
                .ok()
                .map(|index| rates.peers[index].logical_bytes_per_second),
            _ => None,
        };
        if let Some(rate) = direct_rate {
            // Direct is preferred for scheduler misses; for already resident
            // content the receiver chooses the faster observed service.
            let direct_seconds = transfer_seconds(full, rate);
            if direct_seconds <= scheduler_seconds {
                return (publication.max(direct_seconds), 0.0);
            }
            let missing = u128::from(cost.output_bytes).min(full);
            let cached = full - missing;
            let (cached_seconds, externality) =
                self.client_scheduler_completion(client, negotiation_at, cached, wire_rate);
            let delivery = cached_seconds + transfer_seconds(missing, rate);
            return (publication.max(delivery), externality);
        }
        // The exact future manifest is not known. Verified resident bytes
        // can be staged early; absent bytes become available at commit.
        let missing = u128::from(cost.output_bytes).min(full);
        let (cached, first_delay) =
            self.client_scheduler_completion(client, negotiation_at, full - missing, wire_rate);
        let ready = publication.max(cached);
        let (remainder, second_delay) =
            self.client_scheduler_completion(client, negotiation_at + ready, missing, wire_rate);
        (ready + remainder, first_delay + second_delay)
    }

    fn client_scheduler_completion(
        &self,
        peer: Peer,
        start: f64,
        logical_bytes: u128,
        wire_rate: u64,
    ) -> (f64, f64) {
        if logical_bytes == 0 {
            return (0.0, 0.0);
        }
        let remaining = self.send.remaining_after(&self.send_demands, start);
        let baseline = self.send.finish_times(&remaining);
        let active = remaining.get(&peer).map_or(0, |demand| demand.bytes);
        let demand = TransferDemand {
            bytes: active.saturating_add(self.send.wire_bytes(peer, logical_bytes)),
            bytes_per_second: wire_rate,
        };
        marginal_completion(
            self.send,
            &remaining,
            &baseline,
            peer,
            demand,
            Direction::Send,
        )
    }

    fn input_demand(
        network: &DirectionSnapshot,
        peer: Peer,
        traffic: InputTraffic,
        current_wire_rate: Option<u64>,
    ) -> TransferDemand {
        let bytes = traffic
            .wire_bytes
            .saturating_sub(active_on_other_paths(network, peer));
        let active = network
            .peers
            .get(&peer)
            .map_or(0, |capacity| capacity.active_remaining_bytes);
        let fallback = traffic.effective_rate();
        TransferDemand {
            // Active worker input bytes already belong to the reserved input union.
            bytes: bytes.max(u128::from(active)),
            bytes_per_second: current_wire_rate.unwrap_or_else(|| network.rate(peer, fallback)),
        }
    }

    fn path_rate(&self, peer: Peer, direction: Direction) -> Option<CachePathRate> {
        self.path_rates
            .get(&peer.principal())
            .and_then(|rates| directional_rate(*rates, direction))
    }

    fn path_peer(&self, peer: Peer, direction: Direction) -> Peer {
        predicted_peer(peer, self.path_rate(peer, direction))
    }

    fn input_completion(&self, peer: Peer, traffic: InputTraffic) -> (f64, f64) {
        if traffic.wire_bytes == 0 {
            return (0.0, 0.0);
        }
        let rate = self.path_rate(peer, Direction::Send);
        let peer = predicted_peer(peer, rate);
        let demand = Self::input_demand(
            self.send,
            peer,
            traffic,
            rate.map(|rate| rate.bytes_per_second),
        );
        // All paths already carrying this input union remain in the model.
        marginal_completion(
            self.send,
            &self.send_demands,
            &self.send_baseline,
            peer,
            demand,
            Direction::Send,
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
        let rate = self.path_rate(peer, Direction::Receive);
        let peer = predicted_peer(peer, rate);
        let already_pending = remaining.get(&peer).map_or(0, |demand| demand.bytes);
        let demand = TransferDemand {
            bytes: already_pending.saturating_add(
                self.receive
                    .wire_bytes(peer, u128::from(result.expected_bytes)),
            ),
            bytes_per_second: rate.map_or_else(
                || self.receive.rate(peer, result.bytes_per_second),
                |rate| rate.bytes_per_second,
            ),
        };
        marginal_completion(
            self.receive,
            &remaining,
            &baseline,
            peer,
            demand,
            Direction::Receive,
        )
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub(super) struct PlacementEstimate {
    pub(super) seconds: f64,
    pub(super) completion_seconds: f64,
    missing_input_union_bytes: u128,
    input_wire_bytes: u128,
    direct_input_bytes: u128,
    pub(super) archive_bytes: u128,
    pub(super) inputs_ready_at: f64,
    pub(super) ready_at: f64,
    pub(super) negotiation_at: f64,
    pub(super) publication_at: f64,
    post_negotiation_seconds: f64,
    pub(super) cost: ActionCost,
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
    pub(super) fn new(details: &'a ServerDetails, cost: Option<ActionCost>) -> Option<Self> {
        let placement = details.capabilities.native_placement.as_ref()?;
        Some(Self {
            capacity: details.cpu_capacity,
            assigned: &details.jobs_assigned,
            placement,
            recent: &details.recent_residency,
            cost: cost.unwrap_or_else(|| ActionCost::baseline(placement)),
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
    let mut rates = DeliveryRates::new(
        plan.send,
        plan.path_peer(peer, Direction::Send),
        placement.timing.transfer,
        placement
            .cache_path_rates
            .download
            .map(|rate| rate.bytes_per_second),
    );
    let direct = plan.direct_inputs.get(&peer.principal());
    let initial = pipeline::publication_forecast(forecast, requested, plan.packages, rates, direct);
    let (network, externality) = plan.input_completion(peer, initial.traffic);
    let unconstrained = initial.traffic.wire_time.as_secs_f64();
    if unconstrained > 0.0 {
        rates.contention = (network / unconstrained).max(1.0);
    }
    let adjusted = if rates.contention > 1.0 {
        pipeline::publication_forecast(forecast, requested, plan.packages, rates, direct)
    } else {
        initial
    };
    let ready_at = adjusted.ready_at;
    let negotiation_at = ready_at + action.phase.publication().as_secs_f64();
    // Already resident candidates do not increase the existing backlog.
    let externality = if bytes == 0 { 0.0 } else { externality };
    let result = action.result(placement.timing.result);
    let (output_network, output_externality) = plan.result_completion(peer, negotiation_at, result);
    let output_processing =
        transfer_seconds(u128::from(result.expected_bytes), result.bytes_per_second);
    let output_overhead = Duration::from_nanos(
        result
            .expected_requests
            .saturating_mul(result.request_nanoseconds),
    )
    .as_secs_f64();
    let publication = output_network.max(output_processing) + output_overhead;
    let (delivery, delivery_externality) =
        plan.client_completion(peer, negotiation_at, publication, action);
    let completion_seconds = negotiation_at + delivery;
    PlacementEstimate {
        ready_at,
        negotiation_at,
        inputs_ready_at: adjusted.inputs_ready_at,
        completion_seconds,
        publication_at: negotiation_at + publication,
        post_negotiation_seconds: delivery,
        missing_input_union_bytes: bytes,
        input_wire_bytes: adjusted.traffic.wire_bytes,
        direct_input_bytes: adjusted.traffic.direct_bytes,
        archive_bytes: adjusted.traffic.archive_bytes,
        cost: action,
        seconds: completion_seconds + externality + output_externality + delivery_externality,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccache::build_runtime::{PeerCapacity, SharedCapacity};

    fn worker(port: u16) -> Peer {
        Peer::Worker(ServerId::from_digest(std::array::from_fn(|index| {
            port.to_le_bytes()[index % 2]
        })))
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
        let plan = NativeTransferPlan::new(&network, &HashMap::new(), None, None);
        assert_eq!(
            plan.input_completion(
                a,
                InputTraffic {
                    wire_bytes: 100_000_000,
                    archive_bytes: 0,
                    wire_time: Duration::from_secs(1),
                    ..InputTraffic::default()
                }
            ),
            (1.0, 0.0)
        );
        assert_eq!(
            plan.input_completion(
                b,
                InputTraffic {
                    wire_bytes: 100_000_000,
                    archive_bytes: 0,
                    wire_time: Duration::from_secs(1),
                    ..InputTraffic::default()
                }
            ),
            (2.0, 1.0)
        );
        assert_eq!(
            plan.input_completion(
                c,
                InputTraffic {
                    wire_bytes: 100_000_000,
                    archive_bytes: 0,
                    wire_time: Duration::from_secs(1),
                    ..InputTraffic::default()
                }
            ),
            (1.0, 0.0)
        );
        assert_eq!(
            plan.input_completion(b, InputTraffic::default()),
            (0.0, 0.0)
        );
    }

    #[test]
    fn native_result_upload_is_predicted_at_completion_not_admission() {
        let a = worker(1);
        let b = worker(2);
        let network = NetworkSnapshot {
            send: DirectionSnapshot::default(),
            receive: constrained(a, b),
        };
        let plan = NativeTransferPlan::new(&network, &HashMap::new(), None, None);
        let result = ResultTransferEstimate {
            expected_bytes: 100_000_000,
            bytes_per_second: 100_000_000,
            ..ResultTransferEstimate::default()
        };
        assert_eq!(plan.result_completion(b, 0.0, result), (2.0, 1.0));
        assert_eq!(plan.result_completion(b, 0.5, result), (1.5, 0.5));
        assert_eq!(plan.result_completion(b, 2.0, result), (1.0, 0.0));
    }
    #[test]
    fn changing_route_does_not_inherit_old_path_contention() -> anyhow::Result<()> {
        let a = worker(1);
        let b = worker(2);
        let overlay = "100.64.0.1,100.64.0.2".parse()?;
        let ethernet = "192.168.76.2,192.168.76.1".parse()?;
        let other_overlay = "100.64.0.1,100.64.0.3".parse()?;
        let network = NetworkSnapshot {
            send: constrained(a.on_path(overlay), b.on_path(other_overlay)),
            receive: DirectionSnapshot::default(),
        };
        let mut plan = NativeTransferPlan::new(&network, &HashMap::new(), None, None);
        let traffic = InputTraffic {
            wire_bytes: 100_000_000,
            archive_bytes: 0,
            wire_time: Duration::from_secs(1),
            ..InputTraffic::default()
        };
        let rate = |path| CachePathRate {
            path,
            bytes_per_second: 100_000_000,
        };
        plan.path_rates.insert(
            b,
            CachePathRates {
                download: Some(rate(other_overlay)),
                upload: None,
            },
        );
        assert_eq!(plan.input_completion(b, traffic), (2.0, 1.0));
        plan.path_rates.insert(
            b,
            CachePathRates {
                download: Some(rate(ethernet)),
                upload: None,
            },
        );
        assert_eq!(plan.input_completion(b, traffic), (1.0, 0.0));

        plan.path_rates.insert(
            a,
            CachePathRates {
                download: Some(rate(ethernet)),
                upload: None,
            },
        );
        assert_eq!(plan.input_completion(a, traffic), (1.0, 0.0));
        // 100 MB are already arriving over the overlay. Only the extra
        // 100 MB belongs to the newly selected route, not all 200 MB.
        let extra = InputTraffic {
            wire_bytes: 200_000_000,
            ..traffic
        };
        assert_eq!(plan.input_completion(a, extra), (1.0, 0.0));
        Ok(())
    }
    #[test]
    fn full_client_result_is_independent_of_scheduler_missing_uploads() -> anyhow::Result<()> {
        use sccache::build_runtime::wire::{ClientDeliveryRates, PeerDownloadRate};
        let network = NetworkSnapshot::default();
        let server =
            ServerId::from_digest(std::array::from_fn(|index| 1_u16.to_le_bytes()[index % 2]));
        let requester = sccache::dist::ServerId::from_digest([7; 32]);
        let path = "192.168.76.1,192.168.76.2".parse()?;
        let mut rates = ClientDeliveryRates {
            scheduler: Some(CachePathRate {
                path,
                bytes_per_second: 10 << 20,
            }),
            peers: Vec::new(),
        };
        let cost = ActionCost {
            phase: Default::default(),
            execution_nanoseconds: 1,
            output_bytes: 0,
            result_bytes: 100 << 20,
            output_requests: 0,
        };
        let receiver = (requester, rates.clone());
        let plan = NativeTransferPlan::new(&network, &HashMap::new(), None, None)
            .with_receiver(Some(&receiver));
        assert_eq!(
            plan.client_completion(worker(1), 0.0, 0.0, cost),
            (10.0, 0.0)
        );
        let missing = ActionCost {
            output_bytes: 100 << 20,
            ..cost
        };
        assert_eq!(
            plan.client_completion(worker(1), 0.0, 5.0, missing),
            (15.0, 0.0)
        );
        rates.peers.push(PeerDownloadRate {
            source: server,
            path,
            logical_bytes_per_second: 100 << 20,
        });
        let receiver = (requester, rates);
        let plan = NativeTransferPlan::new(&network, &HashMap::new(), None, None)
            .with_receiver(Some(&receiver));
        assert_eq!(
            plan.client_completion(worker(1), 0.0, 0.0, cost),
            (1.0, 0.0)
        );
        assert_eq!(
            plan.client_completion(worker(1), 0.0, 5.0, missing),
            (5.0, 0.0)
        );
        Ok(())
    }
}
