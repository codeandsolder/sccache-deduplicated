//! Read-only projection of the existing CAS and transport measurements.
pub(super) fn snapshot(
    sessions: &crate::build_runtime::NativeSessions,
    network: &crate::build_runtime::NetworkMeter,
) -> sccache_dashboard::NativeTelemetry {
    let mut snapshot = sccache_dashboard::NativeTelemetry::default();
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
            snapshot.cache_error = Some("CAS statistics unavailable".into());
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
