//! Learn missing directional concurrency relationships through existing work.
//! No probe payload, additional request, delayed start or cache warming.

use super::{NativeTransferPlan, native_estimate};
use crate::ServerDetails;
use sccache::{
    build_runtime::{Direction, DirectionSnapshot, Peer},
    dist::{NativeInputBlobs, ServerId},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::{Duration, Instant},
};

// At 250 ms sampling, leave enough time for three complete overlapping windows
// and an initial transition. Longer natural overlaps are always observed.
const MIN_OVERLAP: f64 = 1.25;
const ASSIGNMENT_MARGIN: f64 = 0.25;
const COOLDOWN: Duration = Duration::from_mins(1);
const MAX_ATTEMPTS: usize = 128;

type Question = (Direction, BTreeSet<Peer>);

#[derive(Default)]
pub(crate) struct Exploration {
    attempts: BTreeMap<Question, Instant>,
}

impl Exploration {
    fn available(&self, question: &Question, now: Instant) -> bool {
        self.attempts
            .get(question)
            .is_none_or(|&previous| now.saturating_duration_since(previous) >= COOLDOWN)
    }

    fn record(&mut self, question: Question, now: Instant) {
        self.attempts
            .retain(|_, previous| now.saturating_duration_since(*previous) < COOLDOWN);
        if self.attempts.len() >= MAX_ATTEMPTS
            && !self.attempts.contains_key(&question)
            && let Some(oldest) = self
                .attempts
                .iter()
                .min_by_key(|(_, timestamp)| **timestamp)
                .map(|(key, _)| key.clone())
        {
            self.attempts.remove(&oldest);
        }
        self.attempts.insert(question, now);
    }
}

/// The question is only useful if there is already enough real traffic to
/// sustain a comparable overlap, and each peer has a fresh isolated baseline.
fn question(
    network: &DirectionSnapshot,
    direction: Direction,
    peer: Peer,
    encoded_bytes: u128,
    delay: f64,
) -> Option<Question> {
    let capacity = network.peers.get(&peer)?;
    let rate = capacity.isolated_bytes_per_second;
    if rate == 0 || sccache::build_runtime::transfer_seconds(encoded_bytes, rate) < MIN_OVERLAP {
        return None;
    }
    let remaining = network.remaining_after(&super::active_demands(network), delay);
    if remaining.contains_key(&peer) {
        // This worker is already contributing to the measured active set.
        return None;
    }
    let mut cohort = BTreeSet::from([peer]);
    for (other, demand) in remaining {
        let other_capacity = network.peers.get(&other)?;
        if sccache::build_runtime::transfer_seconds(demand.bytes, demand.bytes_per_second)
            < MIN_OVERLAP
        {
            continue;
        }
        if other == Peer::Other || other_capacity.isolated_bytes_per_second == 0 {
            return None;
        }
        cohort.insert(other);
    }
    if cohort.len() < 2 || network.overlap_known(&cohort) {
        return None;
    }
    Some((direction, cohort))
}

fn additional_inputs(details: &ServerDetails, requested: &NativeInputBlobs) -> NativeInputBlobs {
    let placement = details.capabilities.native_placement.as_ref();
    let residency = placement.map(|placement| {
        super::pipeline::WorkerResidency::new(
            &details.jobs_assigned,
            placement,
            &details.recent_residency,
        )
    });
    let mut missing: NativeInputBlobs = requested
        .iter()
        .filter(|(id, size)| {
            !residency
                .as_ref()
                .is_some_and(|residency| residency.contains(**id, **size))
        })
        .map(|(&id, &bytes)| (id, bytes))
        .collect();
    for id in details
        .jobs_assigned
        .iter()
        .filter(|(id, _)| {
            placement.is_none_or(|placement| {
                placement.queue.jobs.get(id).is_none_or(|job| {
                    job.phase != sccache::build_runtime::wire::NativeJobPhase::Terminal
                })
            })
        })
        .filter_map(|(_, inputs)| inputs.as_ref())
        .flat_map(|job| job.inputs.keys())
    {
        missing.remove(id);
    }
    missing
}

fn logical_size(inputs: &NativeInputBlobs) -> u128 {
    inputs.values().map(|&bytes| u128::from(bytes)).sum()
}

fn no_extra_inputs(candidate: &NativeInputBlobs, baseline: &NativeInputBlobs) -> bool {
    candidate
        .iter()
        .all(|(id, size)| baseline.get(id) == Some(size))
}

struct Opportunity<'a> {
    server: ServerId,
    inputs: NativeInputBlobs,
    encoded: u128,
    forecast: Option<super::WorkerForecast<'a>>,
}

impl<'a> Opportunity<'a> {
    fn new(
        server: ServerId,
        details: &'a ServerDetails,
        requested: &NativeInputBlobs,
        prediction: Option<&super::PlacementEstimate>,
        plan: &NativeTransferPlan<'_>,
    ) -> Self {
        let inputs = additional_inputs(details, requested);
        let encoded = plan
            .send
            .wire_bytes(Peer::Worker(server.addr()), logical_size(&inputs));
        Self {
            server,
            inputs,
            encoded,
            forecast: super::WorkerForecast::new(details, prediction.map(|estimate| estimate.cost)),
        }
    }

    fn question(
        &self,
        requested: &NativeInputBlobs,
        plan: &NativeTransferPlan<'_>,
        history: &Exploration,
        now: Instant,
    ) -> Option<Question> {
        let peer = Peer::Worker(self.server.addr());
        if let Some(question) = question(
            plan.send,
            Direction::Send,
            peer,
            self.encoded,
            ASSIGNMENT_MARGIN,
        ) && history.available(&question, now)
        {
            return Some(question);
        }
        let forecast = self.forecast?;
        if forecast.placement.timing.result.observations == 0 {
            return None;
        }
        let estimate = native_estimate(forecast, requested, peer, plan);
        question(
            plan.receive,
            Direction::Receive,
            peer,
            u128::from(forecast.cost.output_bytes),
            estimate.negotiation_at,
        )
        .filter(|question| history.available(question, now))
    }

    fn no_extra_traffic(&self, baseline: &Self) -> bool {
        let result_bytes = |opportunity: &Self| {
            opportunity
                .forecast
                .map(|forecast| forecast.cost.output_bytes)
        };
        self.encoded <= baseline.encoded
            && no_extra_inputs(&self.inputs, &baseline.inputs)
            && result_bytes(self) <= result_bytes(baseline)
    }
}

/// Prefer an already useful opportunity, otherwise explore only among
/// near-equivalent placements with no additional estimated traffic. This
/// changes *which already admitted worker executes the real job*, not what
/// data is requested. Never idle an executor or postpone a transfer.
pub(crate) fn choose_worker(
    candidates: &[(ServerId, f64)],
    servers: &HashMap<ServerId, ServerDetails>,
    requested: &NativeInputBlobs,
    predictions: &BTreeMap<std::net::SocketAddr, super::PlacementEstimate>,
    plan: &NativeTransferPlan<'_>,
    history: &mut Exploration,
    now: Instant,
) -> Option<ServerId> {
    let &(best, best_eta) = candidates.iter().min_by(|(a, left), (b, right)| {
        left.total_cmp(right).then_with(|| a.addr().cmp(&b.addr()))
    })?;
    let limit = best_eta + (best_eta * 0.01).min(0.020);
    if predictions
        .values()
        .any(|prediction| prediction.archive_bytes > 0)
    {
        return Some(best);
    }
    if !candidates
        .iter()
        .any(|(id, eta)| *id != best && *eta <= limit)
        || (plan
            .send
            .peers
            .values()
            .all(|peer| peer.active_remaining_bytes == 0)
            && plan
                .receive
                .peers
                .values()
                .all(|peer| peer.active_remaining_bytes == 0))
    {
        return Some(best);
    }
    let baseline = Opportunity::new(
        best,
        servers.get(&best)?,
        requested,
        predictions.get(&best.addr()),
        plan,
    );
    if baseline.question(requested, plan, history, now).is_some() {
        return Some(best);
    }
    // At most 1% and 20 ms predicted total completion cost; unknown real
    // contention can of course differ from the estimate.
    let alternative = candidates
        .iter()
        .filter(|(id, eta)| *id != best && *eta <= limit)
        .filter_map(|&(id, eta)| {
            let candidate = Opportunity::new(
                id,
                servers.get(&id)?,
                requested,
                predictions.get(&id.addr()),
                plan,
            );
            if !candidate.no_extra_traffic(&baseline) {
                return None;
            }
            let question = candidate.question(requested, plan, history, now)?;
            Some((id, eta, question))
        })
        .min_by(|(a, left, _), (b, right, _)| {
            left.total_cmp(right).then_with(|| a.addr().cmp(&b.addr()))
        });
    if let Some((id, _, question)) = alternative {
        debug!("Native placement learning from demanded transfers: {question:?}");
        history.record(question, now);
        Some(id)
    } else {
        Some(best)
    }
}

#[cfg(test)]
mod tests;
