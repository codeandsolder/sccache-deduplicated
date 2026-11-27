//! Ephemeral, bounded client observations. They are never used for admission
//! or cache identity and never extend an action's deadline.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::{
    PeerId,
    wire::{LiveTraceBatch, LiveTraceRow, LiveTraceSnapshot, MAX_LIVE_TRACE_ROWS, TraceContext},
};
use anyhow::{Result, anyhow, ensure};

const MAX_REPORTERS: usize = 128;
const MAX_VISIBLE: usize = 2048;
const TTL: Duration = Duration::from_secs(10);

struct Report {
    received: Instant,
    batch: Arc<LiveTraceBatch>,
}

#[derive(Default)]
pub(super) struct LiveTraces {
    reports: Mutex<BTreeMap<(PeerId, u64), Report>>,
}

impl LiveTraces {
    pub(super) fn report(&self, peer: PeerId, batch: LiveTraceBatch, now: Instant) -> Result<()> {
        ensure!(batch.valid(), "invalid live trace observation");
        let mut reports = self
            .reports
            .lock()
            .map_err(|_| anyhow!("live trace registry poisoned"))?;
        reports.retain(|_, report| now.saturating_duration_since(report.received) < TTL);
        let key = (peer, batch.generation);
        if batch.active == 0 {
            reports.remove(&key);
            return Ok(());
        }
        ensure!(
            reports.contains_key(&key) || reports.len() < MAX_REPORTERS,
            "live trace reporter capacity exhausted"
        );
        reports.insert(
            key,
            Report {
                received: now,
                batch: Arc::new(batch),
            },
        );
        drop(reports);
        Ok(())
    }

    pub(super) fn snapshot(&self, now: Instant) -> Result<LiveTraceSnapshot> {
        let mut reports = self
            .reports
            .lock()
            .map_err(|_| anyhow!("live trace registry poisoned"))?;
        reports.retain(|_, report| now.saturating_duration_since(report.received) < TTL);
        let current = reports
            .iter()
            .map(|(&(peer, _), report)| (peer, report.received, Arc::clone(&report.batch)))
            .collect::<Vec<_>>();
        drop(reports);
        let mut snapshot = LiveTraceSnapshot::default();
        let mut candidates = Vec::new();
        for (peer, received, batch) in &current {
            snapshot.active = snapshot.active.saturating_add(batch.active);
            let age_ms = u64::try_from(now.saturating_duration_since(*received).as_millis())
                .unwrap_or(u64::MAX);
            candidates.extend(
                batch
                    .requests
                    .iter()
                    .map(|request| (*peer, batch.instance.as_str(), age_ms, request)),
            );
        }
        // Clone only the bounded projection, not the complete fleet snapshot.
        candidates.sort_unstable_by(|a, b| {
            b.3.elapsed_ms
                .cmp(&a.3.elapsed_ms)
                .then_with(|| a.3.trace.trace_id.cmp(&b.3.trace.trace_id))
        });
        snapshot.rows = candidates
            .into_iter()
            .take(MAX_VISIBLE)
            .map(
                |(peer, instance, observation_age_ms, request)| LiveTraceRow {
                    peer,
                    instance: instance.to_owned(),
                    observation_age_ms,
                    request: request.clone(),
                },
            )
            .collect();
        Ok(snapshot)
    }
}

impl LiveTraceBatch {
    fn valid(&self) -> bool {
        fn label(s: &str) -> bool {
            s.len() <= 256 && !s.chars().any(char::is_control)
        }
        if self.instance.is_empty()
            || !label(&self.instance)
            || self.requests.len() > MAX_LIVE_TRACE_ROWS
            || self.active < u64::try_from(self.requests.len()).unwrap_or(u64::MAX)
            || self.active > 1_000_000
        {
            return false;
        }
        let mut ids = BTreeSet::new();
        self.requests.iter().all(|request| {
            request.trace.valid()
                && ids.insert(request.trace.trace_id)
                && request.phase_age_ms <= request.elapsed_ms
                && label(&request.compiler)
                && label(&request.output)
                && label(&request.phase)
                && label(&request.worker)
                && request.producer.is_none_or(TraceContext::valid)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::LiveTraceRequest;

    #[test]
    fn report_replaces_expires_and_clears_without_fabricated_completion() -> Result<()> {
        let peer = PeerId::from_digest([1; 32]);
        let now = Instant::now();
        let registry = LiveTraces::default();
        let mut report = LiveTraceBatch {
            generation: 1,
            instance: "test".into(),
            active: 2,
            requests: vec![LiveTraceRequest {
                trace: TraceContext::request("live"),
                compiler: "rustc".into(),
                output: "crate".into(),
                phase: "hash_inputs".into(),
                elapsed_ms: 100,
                phase_age_ms: 50,
                worker: String::new(),
                job: None,
                producer: None,
            }],
        };
        registry.report(peer, report.clone(), now)?;
        let snapshot = registry.snapshot(now + Duration::from_secs(1))?;
        assert_eq!(snapshot.active, 2);
        assert_eq!(snapshot.rows.len(), 1);
        assert_eq!(snapshot.rows[0].observation_age_ms, 1000);
        report.requests[0].phase = "cache_lookup".into();
        registry.report(peer, report.clone(), now + Duration::from_secs(2))?;
        assert_eq!(
            registry.snapshot(now + Duration::from_secs(2))?.rows[0]
                .request
                .phase,
            "cache_lookup"
        );
        assert!(
            registry
                .snapshot(now + Duration::from_secs(12))?
                .rows
                .is_empty()
        );
        registry.report(peer, report.clone(), now + Duration::from_secs(13))?;
        report.active = 0;
        report.requests.clear();
        registry.report(peer, report, now + Duration::from_secs(14))?;
        assert_eq!(registry.snapshot(now + Duration::from_secs(14))?.active, 0);
        Ok(())
    }
}
