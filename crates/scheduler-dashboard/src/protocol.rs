//! Shared deterministic delta protocol; neither a browser nor a slow SSE
//! consumer can silently continue with a missing revision.
use std::collections::BTreeMap;

use crate::{DashboardData, HISTORY_CAPACITY, NativeEvent, NativePatch, Rows, Sample, Snapshot};

fn diff_rows<T: Clone + PartialEq>(old: &[T], new: &[T], key: impl Fn(&T) -> &str) -> Rows<T> {
    let mut previous: BTreeMap<_, _> = old.iter().map(|row| (key(row), row)).collect();
    let upsert = new
        .iter()
        .filter(|row| previous.remove(key(row)) != Some(*row))
        .cloned()
        .collect();
    let remove = previous.into_keys().map(str::to_owned).collect();
    Rows { upsert, remove }
}

fn apply_rows<T>(rows: &mut Vec<T>, delta: Rows<T>, key: impl Fn(&T) -> &str) {
    if delta.upsert.is_empty() && delta.remove.is_empty() {
        return;
    }
    let mut indexed: BTreeMap<String, T> = rows
        .drain(..)
        .map(|row| (key(&row).to_owned(), row))
        .collect();
    for removed in delta.remove {
        indexed.remove(&removed);
    }
    for row in delta.upsert {
        indexed.insert(key(&row).to_owned(), row);
    }
    rows.extend(indexed.into_values());
}

#[must_use = "the patch advances the native feed revision"]
pub fn make_patch(
    previous: &DashboardData,
    snapshot: Option<&Snapshot>,
    sampled_at: Option<u64>,
    sample: Option<Sample>,
    error: Option<String>,
) -> NativePatch {
    let mut patch = NativePatch {
        revision: previous.revision.saturating_add(1),
        sampled_at,
        sample,
        error,
        ..Default::default()
    };
    if let Some(new) = snapshot {
        let empty = Snapshot::default();
        let old = previous.snapshot.as_ref().unwrap_or(&empty);
        patch.totals =
            (previous.snapshot.is_none() || old.totals != new.totals).then(|| new.totals.clone());
        patch.workers = diff_rows(&old.workers, &new.workers, |row| &row.id);
        patch.jobs = diff_rows(&old.jobs, &new.jobs, |row| &row.id);
        patch.hosts = diff_rows(&old.topology.hosts, &new.topology.hosts, |row| &row.id);
        patch.links = diff_rows(&old.topology.links, &new.topology.links, |row| &row.id);
    }
    patch
}

/// Returns false for an invalid sequence; callers must reconnect for a reset.
pub fn apply_event(state: &mut DashboardData, event: NativeEvent) -> bool {
    let patch = match event {
        NativeEvent::Reset(reset) => {
            *state = *reset;
            return true;
        }
        NativeEvent::Patch(patch) => *patch,
    };
    if patch.revision != state.revision.saturating_add(1) {
        return false;
    }
    state.revision = patch.revision;
    state.error = patch.error;
    if let Some(sample) = patch.sample {
        if state.history.len() >= HISTORY_CAPACITY {
            state.history.remove(0);
        }
        state.history.push(sample);
    }
    if let Some(sampled_at) = patch.sampled_at {
        state.sampled_at = Some(sampled_at);
        let snapshot = state.snapshot.get_or_insert_with(Snapshot::default);
        if let Some(totals) = patch.totals {
            snapshot.totals = totals;
        }
        apply_rows(&mut snapshot.workers, patch.workers, |row| &row.id);
        apply_rows(&mut snapshot.topology.hosts, patch.hosts, |row| &row.id);
        apply_rows(&mut snapshot.topology.links, patch.links, |row| &row.id);
        if !patch.jobs.upsert.is_empty() || !patch.jobs.remove.is_empty() {
            apply_rows(&mut snapshot.jobs, patch.jobs, |row| &row.id);
            snapshot
                .jobs
                .sort_unstable_by(|a, b| (a.assigned_at_ms, &a.id).cmp(&(b.assigned_at_ms, &b.id)));
        }
    }
    if let Some(telemetry) = patch.telemetry {
        state.telemetry = Some(telemetry);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Job, Totals};

    fn job(id: &str) -> Job {
        Job {
            id: id.into(),
            worker: "worker".into(),
            worker_id: "127.0.0.1:1".into(),
            state: "ready".into(),
            native_phase: None,
            native_phase_observed_ns: None,
            assigned_at_ms: Some(100),
            state_since_ms: Some(100),
            remaining_input_bytes: None,
            remaining_input_blobs: None,
            predicted_completion_secs: None,
        }
    }

    #[test]
    fn patches_reconstruct_snapshot_and_reject_gap() {
        let mut state = DashboardData::default();
        let mut snapshot = Snapshot {
            jobs: vec![job("1"), job("2")],
            ..Default::default()
        };
        let sample = Sample {
            unix_secs: 1,
            totals: Totals::default(),
        };
        let patch = make_patch(
            &state,
            Some(&snapshot),
            Some(sample.unix_secs),
            Some(sample.clone()),
            None,
        );
        assert!(apply_event(&mut state, NativeEvent::Patch(Box::new(patch))));
        assert_eq!(state.snapshot.as_ref(), Some(&snapshot));
        snapshot.jobs.remove(0);
        snapshot.jobs[0].state = "started".into();
        let patch = make_patch(
            &state,
            Some(&snapshot),
            Some(sample.unix_secs),
            Some(sample),
            None,
        );
        assert_eq!(patch.jobs.remove, vec!["1"]);
        assert_eq!(patch.jobs.upsert.len(), 1);
        let wire = serde_json::to_string(&NativeEvent::Patch(Box::new(patch))).unwrap();
        assert!(apply_event(
            &mut state,
            serde_json::from_str(&wire).unwrap()
        ));
        assert_eq!(state.snapshot.as_ref(), Some(&snapshot));
        assert!(!apply_event(
            &mut state,
            serde_json::from_str(&wire).unwrap()
        ));
    }

    #[test]
    fn topology_updates_and_removals_share_the_native_revision_stream() {
        use crate::{HostRole, NetworkHost, NetworkLink, RouteEvidence};
        let host = |id: &str, role| NetworkHost {
            id: id.into(),
            name: id.into(),
            role,
            status: "Observed".into(),
            addresses: Vec::new(),
            interfaces: Vec::new(),
        };
        let mut snapshot = Snapshot::default();
        snapshot.topology.hosts = vec![
            host("a", HostRole::Scheduler),
            host("b", HostRole::Worker),
            host("c", HostRole::Client),
        ];
        snapshot.topology.links = vec![NetworkLink {
            id: "a-b".into(),
            source: "a".into(),
            target: "b".into(),
            source_address: None,
            target_address: None,
            evidence: RouteEvidence::Advertised,
            wire_bytes_per_second: None,
            logical_bytes_per_second: None,
            remaining_bytes: None,
        }];
        let mut state = DashboardData::default();
        let patch = make_patch(&state, Some(&snapshot), Some(1), None, None);
        assert!(apply_event(&mut state, NativeEvent::Patch(Box::new(patch))));
        snapshot.topology.hosts.remove(2);
        snapshot.topology.links[0].evidence = RouteEvidence::Measured;
        snapshot.topology.links[0].wire_bytes_per_second = Some(1000);
        let patch = make_patch(&state, Some(&snapshot), Some(2), None, None);
        assert_eq!(patch.hosts.remove, ["c"]);
        assert!(patch.hosts.upsert.is_empty());
        assert_eq!(patch.links.upsert.len(), 1);
        let json = serde_json::to_string(&NativeEvent::Patch(Box::new(patch))).unwrap();
        assert!(apply_event(
            &mut state,
            serde_json::from_str(&json).unwrap()
        ));
        assert_eq!(state.snapshot.as_ref(), Some(&snapshot));
        snapshot.topology.links.clear();
        let patch = make_patch(&state, Some(&snapshot), Some(3), None, None);
        assert_eq!(patch.links.remove, ["a-b"]);
        assert!(apply_event(&mut state, NativeEvent::Patch(Box::new(patch))));
        assert_eq!(state.snapshot.as_ref(), Some(&snapshot));
    }

    #[test]
    fn unchanged_sample_carries_no_rows_or_history() {
        let snapshot = Snapshot::default();
        let state = DashboardData {
            snapshot: Some(snapshot.clone()),
            ..Default::default()
        };
        let patch = make_patch(
            &state,
            Some(&snapshot),
            Some(1),
            Some(Sample {
                unix_secs: 1,
                totals: Totals::default(),
            }),
            None,
        );
        assert!(patch.workers.upsert.is_empty());
        assert!(patch.jobs.upsert.is_empty());
        assert!(patch.totals.is_none());
        assert!(patch.telemetry.is_none());
    }
}

use crate::{
    MetricPanel, MetricSeries, MetricsData, MetricsEvent, MetricsPatch, PanelPatch, SeriesPatch,
};

fn series_patch(old: &MetricSeries, new: &MetricSeries) -> Option<SeriesPatch> {
    if old.label != new.label {
        return Some(SeriesPatch::Replace(new.clone()));
    }
    // Query responses are sorted, finite timestamps; use a linear merge so
    // rolling ranges and late corrections send only genuinely changed points.
    let mut left = old.points.iter().peekable();
    let mut right = new.points.iter().peekable();
    let mut upsert = Vec::new();
    let mut remove = Vec::new();
    loop {
        match (left.peek(), right.peek()) {
            (Some(a), Some(b)) => match a.0.total_cmp(&b.0) {
                std::cmp::Ordering::Less => {
                    remove.push(a.0);
                    left.next();
                }
                std::cmp::Ordering::Greater => {
                    upsert.push(**b);
                    right.next();
                }
                std::cmp::Ordering::Equal => {
                    if a.1 != b.1 {
                        upsert.push(**b);
                    }
                    left.next();
                    right.next();
                }
            },
            (Some(a), None) => {
                remove.push(a.0);
                left.next();
            }
            (None, Some(b)) => {
                upsert.push(**b);
                right.next();
            }
            (None, None) => break,
        }
    }
    if upsert.is_empty() && remove.is_empty() {
        None
    } else {
        Some(SeriesPatch::Update {
            key: new.key.clone(),
            upsert,
            remove,
        })
    }
}

fn panel_patch(old: &MetricPanel, new: &MetricPanel) -> Option<PanelPatch> {
    if old.title != new.title || old.unit != new.unit || old.kind != new.kind {
        return Some(PanelPatch::Replace(new.clone()));
    }
    let mut previous: BTreeMap<_, _> = old
        .series
        .iter()
        .map(|series| (series.key.as_str(), series))
        .collect();
    let series = new
        .series
        .iter()
        .filter_map(|series| {
            previous.remove(series.key.as_str()).map_or_else(
                || Some(SeriesPatch::Replace(series.clone())),
                |old| series_patch(old, series),
            )
        })
        .collect::<Vec<_>>();
    let removed = previous.into_keys().map(str::to_owned).collect::<Vec<_>>();
    if series.is_empty() && removed.is_empty() && old.error == new.error {
        None
    } else {
        Some(PanelPatch::Update {
            key: new.key,
            error: new.error.clone(),
            series,
            removed,
        })
    }
}

#[must_use = "the patch advances the metrics feed revision"]
pub fn make_metrics_patch(old: &MetricsData, new: &MetricsData) -> MetricsPatch {
    let previous: BTreeMap<_, _> = old.panels.iter().map(|panel| (panel.key, panel)).collect();
    MetricsPatch {
        revision: old.revision.saturating_add(1),
        sampled_at: new.sampled_at,
        error: new.error.clone(),
        clients: (old.clients != new.clients).then(|| new.clients.clone()),
        panels: new
            .panels
            .iter()
            .filter_map(|panel| {
                previous.get(&panel.key).map_or_else(
                    || Some(PanelPatch::Replace(panel.clone())),
                    |old| panel_patch(old, panel),
                )
            })
            .collect(),
    }
}

fn apply_series_patch(panel: &mut MetricPanel, patch: SeriesPatch) -> bool {
    match patch {
        SeriesPatch::Replace(series) => {
            if let Some(old) = panel.series.iter_mut().find(|old| old.key == series.key) {
                *old = series;
            } else {
                panel.series.push(series);
            }
        }
        SeriesPatch::Update {
            key,
            upsert,
            remove,
        } => {
            let Some(series) = panel.series.iter_mut().find(|series| series.key == key) else {
                return false;
            };
            series.points.retain(|(time, _)| {
                remove
                    .binary_search_by(|other| other.total_cmp(time))
                    .is_err()
            });
            for point in upsert {
                match series
                    .points
                    .binary_search_by(|other| other.0.total_cmp(&point.0))
                {
                    Ok(index) => series.points[index] = point,
                    Err(index) => series.points.insert(index, point),
                }
            }
        }
    }
    true
}

pub fn apply_metrics_event(state: &mut MetricsData, event: MetricsEvent) -> bool {
    let patch = match event {
        MetricsEvent::Reset(data) => {
            *state = data;
            return true;
        }
        MetricsEvent::Patch(patch) => patch,
    };
    if patch.revision != state.revision.saturating_add(1) {
        return false;
    }
    state.revision = patch.revision;
    state.sampled_at = patch.sampled_at;
    state.error = patch.error;
    if let Some(clients) = patch.clients {
        state.clients = clients;
    }
    for patch in patch.panels {
        match patch {
            PanelPatch::Replace(panel) => {
                if let Some(old) = state.panels.iter_mut().find(|old| old.key == panel.key) {
                    *old = panel;
                } else {
                    state.panels.push(panel);
                }
            }
            PanelPatch::Update {
                key,
                error,
                series,
                removed,
            } => {
                let Some(panel) = state.panels.iter_mut().find(|panel| panel.key == key) else {
                    return false;
                };
                panel.error = error;
                panel.series.retain(|series| !removed.contains(&series.key));
                for patch in series {
                    if !apply_series_patch(panel, patch) {
                        return false;
                    }
                }
                panel.series.sort_unstable_by(|a, b| a.key.cmp(&b.key));
            }
        }
    }
    state.panels.sort_unstable_by_key(|panel| panel.key);
    true
}

#[cfg(test)]
mod metrics_tests {
    use super::*;
    #[test]
    fn rolling_range_and_late_correction_reconstruct_exact_data() {
        let panel = MetricPanel {
            key: 0,
            kind: crate::PanelKind::Timeseries,
            title: "Test".into(),
            unit: "s".into(),
            series: vec![MetricSeries {
                key: "series".into(),
                label: "Series".into(),
                points: vec![(1.0, Some(1.0)), (2.0, Some(2.0)), (3.0, None)],
            }],
            error: None,
        };
        let mut old = MetricsData {
            configured: true,
            panels: vec![panel],
            ..Default::default()
        };
        let mut new = old.clone();
        new.revision = 1;
        new.panels[0].series[0].points = vec![(2.0, Some(4.0)), (3.0, None), (4.0, Some(5.0))];
        let patch = make_metrics_patch(&old, &new);
        let wire = serde_json::to_string(&MetricsEvent::Patch(patch)).unwrap();
        assert!(apply_metrics_event(
            &mut old,
            serde_json::from_str(&wire).unwrap()
        ));
        assert_eq!(old, new);
    }
}
