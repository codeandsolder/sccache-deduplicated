use std::{
    collections::BTreeSet,
    sync::PoisonError,
    time::{Duration, Instant},
};

use super::{
    Direction, DirectionSnapshot, Evidence, MAX_GROUPS, MAX_RATE, MIN_RATE, NetworkMeter,
    NetworkSnapshot, Peer, PeerCapacity, SharedCapacity,
};

impl DirectionSnapshot {
    fn merge_calibration(&mut self, calibrated: &Self) {
        for (&peer, entry) in &calibrated.peers {
            if entry.observed_bytes_per_second == 0 {
                continue;
            }
            let passive = self.peers.entry(peer).or_insert(PeerCapacity {
                observed_bytes_per_second: 0,
                calibrated_bytes_per_second: 0,
                latest_bytes_per_second: 0,
                wire_per_mille: 1000,
                active_remaining_bytes: 0,
                body_bytes: 0,
            });
            passive.calibrated_bytes_per_second = entry.observed_bytes_per_second;
        }
        for constraint in &calibrated.shared {
            if contradicted(self, constraint) {
                continue;
            }
            if let Some(existing) = self
                .shared
                .iter_mut()
                .find(|group| group.members == constraint.members)
            {
                existing.bytes_per_second =
                    existing.bytes_per_second.max(constraint.bytes_per_second);
            } else {
                self.shared.push(constraint.clone());
            }
        }
    }
}

fn contradicted(passive: &DirectionSnapshot, constraint: &SharedCapacity) -> bool {
    let limit = constraint.bytes_per_second.saturating_mul(115) / 100;
    let aggregate = constraint
        .members
        .iter()
        .filter_map(|peer| passive.peers.get(peer))
        .map(|entry| entry.latest_bytes_per_second)
        .fold(0_u64, u64::saturating_add);
    aggregate > limit
        || constraint
            .members
            .iter()
            .filter_map(|peer| passive.peers.get(peer))
            .any(|entry| entry.observed_bytes_per_second > limit)
}

impl NetworkSnapshot {
    /// Combine independent network-only calibration with real CAS measurements.
    /// Probes never change compression ratios or active real-work demand.
    #[must_use = "the combined snapshot is used for placement"]
    pub fn with_calibration(mut self, calibrated: &Self) -> Self {
        self.send.merge_calibration(&calibrated.send);
        self.receive.merge_calibration(&calibrated.receive);
        self
    }
}

impl NetworkMeter {
    /// Record a verified observation in a calibration-only meter. This must
    /// not be called on the passive CAS meter.
    pub fn observe_calibration_rate(
        &self,
        direction: Direction,
        peer: Peer,
        bytes_per_second: u64,
    ) {
        if !(MIN_RATE..=MAX_RATE).contains(&bytes_per_second) {
            return;
        }
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let record = state.direction(direction).record(peer, now);
        record.peak = record.peak.max(bytes_per_second);
        record.peak_at = now;
        record.last_active = now;
    }

    /// Accept a completed, non-preempted isolated calibration.
    pub fn observe_isolated_probe(
        &self,
        direction: Direction,
        peer: Peer,
        bytes: u64,
        elapsed: Duration,
    ) {
        if bytes < 64 * 1024
            || elapsed < Duration::from_millis(10)
            || (bytes < 1 << 20 && elapsed < Duration::from_millis(100))
        {
            return;
        }
        let rate = u128::from(bytes) * 1_000_000_000 / elapsed.as_nanos();
        self.observe_calibration_rate(
            direction,
            peer,
            u64::try_from(rate.min(u128::from(MAX_RATE))).unwrap_or(MAX_RATE),
        );
    }

    /// Accept shared constraints measured within one completed coordinated round.
    pub fn observe_group_probe(
        &self,
        direction: Direction,
        members: &BTreeSet<Peer>,
        measured: &DirectionSnapshot,
    ) {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let meter = state.direction(direction);
        let Some(constraint) = measured
            .shared
            .iter()
            .find(|entry| &entry.members == members)
        else {
            return;
        };
        if meter.evidence.len() >= MAX_GROUPS
            && !meter.evidence.contains_key(members)
            && let Some(oldest) = meter
                .evidence
                .iter()
                .min_by_key(|(_, evidence)| evidence.seen)
                .map(|(key, _)| key.clone())
        {
            meter.evidence.remove(&oldest);
        }
        meter.evidence.insert(
            members.clone(),
            Evidence {
                count: 3,
                minimum: constraint.bytes_per_second,
                maximum: constraint.bytes_per_second,
                seen: now,
            },
        );
    }

    /// Real observations are allowed to invalidate synthetic constraints.
    pub fn invalidate_calibration(&self, passive: &NetworkSnapshot) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        for (direction, observed) in [
            (Direction::Send, &passive.send),
            (Direction::Receive, &passive.receive),
        ] {
            let meter = state.direction(direction);
            meter.evidence.retain(|members, evidence| {
                !contradicted(
                    observed,
                    &SharedCapacity {
                        members: members.clone(),
                        bytes_per_second: evidence.maximum,
                    },
                )
            });
        }
    }
}
