//! Read-only projection of the existing CAS and transport measurements.
use crate::build_runtime::{NativeSessions, NetworkMeter, SessionStatus, SpaceStatus};
use sccache_dashboard::{
    CacheSpace, ManifestCache, NativeService, NativeTelemetry, RecoveryQueue, TicketCounts,
};

fn service(status: SessionStatus) -> NativeService {
    NativeService {
        max_sessions: status.max_sessions,
        max_uploads: status.max_uploads,
        active_uploads: status.active_uploads,
        manifest_budget_bytes: status.manifest_budget_bytes,
        tickets: status.tickets.map(|tickets| TicketCounts {
            registered: tickets.registered,
            action: tickets.action,
            tree: tickets.tree,
            pending: tickets.pending,
            publishing: tickets.publishing,
            ready: tickets.ready,
            failed: tickets.failed,
            expired: tickets.expired,
            busy: tickets.busy,
        }),
        manifests: status.manifests.map(|manifest| ManifestCache {
            entries: manifest.entries,
            bytes: manifest.bytes,
        }),
        recovery: status.recovery.map(|queue| RecoveryQueue {
            queued: queue.queued,
            queued_bytes: queue.queued_bytes,
            ready: queue.ready,
            cooldown: queue.cooldown,
        }),
    }
}

fn space(status: SpaceStatus) -> CacheSpace {
    CacheSpace {
        available_bytes: status.available_bytes,
        reserved_bytes: status.reserved_bytes,
        min_available_bytes: status.policy.map(|policy| policy.min_available_bytes),
        target_available_bytes: status.policy.map(|policy| policy.target_available_bytes),
        max_resident_bytes: status.policy.map(|policy| policy.max_resident_bytes),
        target_resident_bytes: status.policy.map(|policy| policy.target_resident_bytes),
    }
}

pub(super) fn snapshot(sessions: &NativeSessions, network: &NetworkMeter) -> NativeTelemetry {
    let mut snapshot = NativeTelemetry::default();
    match sessions.store().stats() {
        Ok(stats) => {
            snapshot.cache = Some(sccache_dashboard::Cache {
                actions: stats.actions,
                results: stats.results,
                trees: stats.trees,
                blobs: stats.blobs,
                logical_bytes: stats.logical_bytes,
                pending_gc_blobs: stats.pending_gc_blobs,
                pending_gc_bytes: stats.pending_gc_bytes,
            })
        }
        Err(error) => {
            warn!("dashboard CAS stats unavailable: {error:#}");
            snapshot.cache_error = Some(
                "CAS statistics unavailable; showing last successful sample if present".into(),
            );
        }
    }
    match sessions.store().space_status() {
        Ok(status) => snapshot.space = Some(space(status)),
        Err(error) => {
            warn!("dashboard CAS space unavailable: {error:#}");
            snapshot.space_error = Some("CAS space observation unavailable".into());
        }
    }
    match sessions.telemetry() {
        Ok(status) => snapshot.service = Some(service(status)),
        Err(error) => {
            warn!("dashboard native service telemetry unavailable: {error:#}");
            snapshot.service_error = Some("Native service observation unavailable".into());
        }
    }
    let network = network.snapshot();
    for (name, direction) in [("Send", network.send), ("Receive", network.receive)] {
        for (peer, capacity) in direction.peers {
            snapshot.network.push(sccache_dashboard::NetworkPeer {
                peer: format!("{peer:?}"),
                direction: name.into(),
                observed_bytes_per_second: capacity.observed_bytes_per_second,
                isolated_bytes_per_second: capacity.isolated_bytes_per_second,
                wire_per_mille: capacity.wire_per_mille,
                remaining_bytes: capacity.active_remaining_bytes,
                body_bytes: capacity.body_bytes,
            });
        }
        for group in direction.independent {
            snapshot
                .independent_capacity
                .push(sccache_dashboard::ConcurrentGroup {
                    direction: name.into(),
                    rates: group
                        .rates
                        .into_iter()
                        .map(|(peer, rate)| (format!("{peer:?}"), rate))
                        .collect(),
                });
        }
        for capacity in direction.shared {
            snapshot
                .shared_capacity
                .push(sccache_dashboard::NetworkGroup {
                    direction: name.into(),
                    peers: capacity
                        .members
                        .iter()
                        .map(|peer| format!("{peer:?}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    bytes_per_second: capacity.bytes_per_second,
                });
        }
    }
    snapshot
}
