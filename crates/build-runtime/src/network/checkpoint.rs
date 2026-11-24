//! Persist learned directional capacity estimates, never in-flight demand.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::{
    DirectionMeter, Evidence, MAX_AGE, MAX_GROUPS, MAX_PEERS, MAX_RATE, NetworkMeter, Peer,
    PeerRecord,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkCheckpoint {
    captured_at: u64,
    send: DirectionCheckpoint,
    receive: DirectionCheckpoint,
}

#[derive(Debug, Serialize, Deserialize)]
struct DirectionCheckpoint {
    peers: Vec<PeerCheckpoint>,
    groups: Vec<GroupCheckpoint>,
    independent: Vec<IndependentCheckpoint>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PeerCheckpoint {
    peer: Peer,
    peak: u64,
    isolated: u64,
    isolated_age_secs: u64,
    wire_per_mille: u64,
    age_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupCheckpoint {
    members: std::collections::BTreeSet<Peer>,
    minimum: u64,
    maximum: u64,
    count: u8,
    age_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct IndependentCheckpoint {
    rates: Vec<(Peer, u64)>,
    age_secs: u64,
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn observed_at(now: Instant, elapsed: u64, age: u64) -> Option<Instant> {
    let age = Duration::from_secs(elapsed.checked_add(age)?);
    if age > MAX_AGE {
        return None;
    }
    now.checked_sub(age)
}

impl DirectionCheckpoint {
    fn capture(direction: &DirectionMeter, now: Instant) -> Self {
        Self {
            peers: direction
                .peers
                .iter()
                .filter(|(_, record)| {
                    record.peak > 0 && now.saturating_duration_since(record.peak_at) <= MAX_AGE
                })
                .map(|(&peer, record)| PeerCheckpoint {
                    peer,
                    peak: record.peak,
                    isolated: record.isolated,
                    isolated_age_secs: now.saturating_duration_since(record.isolated_at).as_secs(),
                    wire_per_mille: record.wire_per_mille,
                    age_secs: now.saturating_duration_since(record.peak_at).as_secs(),
                })
                .collect(),
            independent: direction
                .independent
                .values()
                .filter(|evidence| {
                    evidence.count >= 3 && now.saturating_duration_since(evidence.seen) <= MAX_AGE
                })
                .map(|evidence| IndependentCheckpoint {
                    rates: evidence
                        .rates
                        .iter()
                        .map(|(&peer, &rate)| (peer, rate))
                        .collect(),
                    age_secs: now.saturating_duration_since(evidence.seen).as_secs(),
                })
                .collect(),
            groups: direction
                .evidence
                .iter()
                .filter(|(_, evidence)| {
                    evidence.count >= 3 && now.saturating_duration_since(evidence.seen) <= MAX_AGE
                })
                .map(|(members, evidence)| GroupCheckpoint {
                    members: members.clone(),
                    minimum: evidence.minimum,
                    maximum: evidence.maximum,
                    count: evidence.count,
                    age_secs: now.saturating_duration_since(evidence.seen).as_secs(),
                })
                .collect(),
        }
    }

    fn restore(self, now: Instant, elapsed: u64) -> DirectionMeter {
        let mut direction = DirectionMeter::default();
        for peer in self.peers.into_iter().take(MAX_PEERS) {
            if !(1..=MAX_RATE).contains(&peer.peak) || !(1..=1100).contains(&peer.wire_per_mille) {
                continue;
            }
            let Some(seen) = observed_at(now, elapsed, peer.age_secs) else {
                continue;
            };
            let mut record = PeerRecord::new(seen);
            record.peak = peer.peak;
            if peer.isolated <= MAX_RATE
                && let Some(isolated_at) = observed_at(now, elapsed, peer.isolated_age_secs)
            {
                record.isolated = peer.isolated;
                record.isolated_at = isolated_at;
            }
            record.wire_per_mille = peer.wire_per_mille;
            direction.peers.insert(peer.peer, record);
        }
        for group in self.groups.into_iter().take(MAX_GROUPS) {
            if group.members.len() < 2
                || group.members.len() > MAX_PEERS
                || group.count < 3
                || group.minimum == 0
                || group.maximum < group.minimum
                || group.maximum > MAX_RATE.saturating_mul(MAX_PEERS as u64)
            {
                continue;
            }
            let Some(seen) = observed_at(now, elapsed, group.age_secs) else {
                continue;
            };
            direction.evidence.insert(
                group.members,
                Evidence {
                    count: group.count,
                    minimum: group.minimum,
                    maximum: group.maximum,
                    seen,
                },
            );
        }
        for group in self.independent.into_iter().take(MAX_GROUPS) {
            if group.rates.len() < 2
                || group.rates.len() > MAX_PEERS
                || group
                    .rates
                    .iter()
                    .any(|(_, rate)| !(1..=MAX_RATE).contains(rate))
            {
                continue;
            }
            let Some(seen) = observed_at(now, elapsed, group.age_secs) else {
                continue;
            };
            let rates: std::collections::BTreeMap<_, _> = group.rates.into_iter().collect();
            if rates.len() < 2 {
                continue;
            }
            direction.independent.insert(
                rates.keys().copied().collect(),
                super::overlap::IndependentEvidence {
                    count: 3,
                    rates,
                    seen,
                },
            );
        }
        direction
    }
}

impl NetworkMeter {
    /// Capture only measurements that still have predictive value.
    #[must_use = "the checkpoint is intended for persistent storage"]
    pub fn checkpoint(&self) -> Option<NetworkCheckpoint> {
        let now = Instant::now();
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let send = DirectionCheckpoint::capture(&state.send, now);
        let receive = DirectionCheckpoint::capture(&state.receive, now);
        drop(state);
        if send.peers.is_empty()
            && receive.peers.is_empty()
            && send.groups.is_empty()
            && receive.groups.is_empty()
            && send.independent.is_empty()
            && receive.independent.is_empty()
        {
            return None;
        }
        Some(NetworkCheckpoint {
            captured_at: epoch_seconds(),
            send,
            receive,
        })
    }

    /// Restore validated, unexpired measurements before serving traffic.
    /// Active flows and outstanding bytes are deliberately not checkpointed.
    pub fn restore(&self, checkpoint: NetworkCheckpoint) {
        let now = Instant::now();
        let Some(elapsed) = epoch_seconds().checked_sub(checkpoint.captured_at) else {
            return;
        };
        if elapsed > MAX_AGE.as_secs() {
            return;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.send.peers.is_empty() && state.receive.peers.is_empty() {
            state.send = checkpoint.send.restore(now, elapsed);
            state.receive = checkpoint.receive.restore(now, elapsed);
            state.last_sample = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, net::SocketAddr, sync::atomic::Ordering};

    #[test]
    fn checkpoint_preserves_fresh_directional_rates_not_pending_transfers() -> anyhow::Result<()> {
        let meter = NetworkMeter::default();
        let a = Peer::Worker(SocketAddr::from(([127, 0, 0, 1], 1)));
        let b = Peer::Worker(SocketAddr::from(([127, 0, 0, 1], 2)));
        let now = Instant::now();
        {
            let mut state = meter.state.lock().unwrap();
            for peer in [a, b] {
                let record = state.send.record(peer, now);
                record.peak = 100_000_000;
                record.counters.remaining.store(99, Ordering::Relaxed);
            }
            state.send.evidence.insert(
                BTreeSet::from([a, b]),
                Evidence {
                    count: 3,
                    minimum: 99_000_000,
                    maximum: 100_000_000,
                    seen: now,
                },
            );
            state.receive.record(a, now).peak = 10_000_000;
        }
        let saved = meter.checkpoint().unwrap();
        let saved = serde_json::to_vec(&saved)?;
        let restored = NetworkMeter::default();
        restored.restore(serde_json::from_slice(&saved)?);
        let snapshot = restored.snapshot();
        assert_eq!(
            snapshot.send.peers[&a].observed_bytes_per_second,
            100_000_000
        );
        assert_eq!(snapshot.send.peers[&a].active_remaining_bytes, 0);
        assert_eq!(snapshot.send.shared.len(), 1);
        assert_eq!(
            snapshot.receive.peers[&a].observed_bytes_per_second,
            10_000_000
        );
        assert!(snapshot.receive.shared.is_empty());
        let mut stale: NetworkCheckpoint = serde_json::from_slice(&saved)?;
        stale.captured_at = stale.captured_at.saturating_sub(MAX_AGE.as_secs() + 1);
        let expired = NetworkMeter::default();
        expired.restore(stale);
        assert!(expired.snapshot().send.peers.is_empty());
        Ok(())
    }
}
