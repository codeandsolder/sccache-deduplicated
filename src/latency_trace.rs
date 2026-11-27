//! Request latency instrumentation and bounded OTLP export. Trace identities
//! are deliberately independent of the action/cache identity.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceConfig {
    pub endpoint: String,
    pub instance: String,
    pub spool_directory: std::path::PathBuf,
    pub max_spool_bytes: u64,
}

pub use crate::build_runtime::wire::TraceContext;

fn child_context(parent: TraceContext) -> TraceContext {
    let mut span_id: [u8; 8] = rand::random();
    if span_id == [0; 8] {
        span_id[0] = 1;
    }
    TraceContext { span_id, ..parent }
}

#[must_use = "the timestamp is used to align host-local monotonic durations"]
pub fn unix_nanos() -> u64 {
    nanos(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default(),
    )
}

#[must_use = "the duration is represented in OTLP nanoseconds"]
pub fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug)]
pub struct LatencySpan {
    pub context: TraceContext,
    pub parent: Option<TraceContext>,
    pub links: Vec<TraceContext>,
    pub service: &'static str,
    pub name: &'static str,
    pub start: u64,
    pub end: u64,
    pub attributes: Vec<(&'static str, String)>,
    pub error: bool,
}

impl LatencySpan {
    #[must_use = "the returned span must be submitted to the exporter"]
    pub fn child(
        parent: TraceContext,
        service: &'static str,
        name: &'static str,
        start: u64,
        end: u64,
    ) -> Self {
        Self {
            context: child_context(parent),
            parent: Some(parent),
            links: Vec::new(),
            service,
            name,
            start,
            end: end.max(start),
            attributes: Vec::new(),
            error: false,
        }
    }
}

/// A host-local duration uses the monotonic clock even when NTP adjusts UTC.
pub struct SpanGuard {
    context: TraceContext,
    parent: TraceContext,
    service: &'static str,
    name: &'static str,
    start: u64,
    clock: std::time::Instant,
    error: bool,
}

impl SpanGuard {
    #[must_use = "keep the guard alive for the operation being measured"]
    pub fn new(parent: TraceContext, service: &'static str, name: &'static str) -> Self {
        Self {
            context: child_context(parent),
            parent,
            service,
            name,
            start: unix_nanos(),
            clock: std::time::Instant::now(),
            error: true,
        }
    }

    #[must_use = "propagate this span as the parent of downstream operations"]
    pub const fn context(&self) -> TraceContext {
        self.context
    }

    pub const fn succeed(&mut self) {
        self.error = false;
    }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        submit(vec![LatencySpan {
            context: self.context,
            parent: Some(self.parent),
            links: Vec::new(),
            service: self.service,
            name: self.name,
            start: self.start,
            end: self.start.saturating_add(nanos(self.clock.elapsed())),
            attributes: Vec::new(),
            error: self.error,
        }]);
    }
}

/// Configure trace export once per daemon process. A colocated worker shares
/// the scheduler's exporter but uses its own service name.
/// # Errors
/// Invalid endpoints or failure to initialize the export thread.
pub fn configure(config: Option<&TraceConfig>) -> anyhow::Result<()> {
    let Some(config) = config else { return Ok(()) };
    #[cfg(feature = "http-client")]
    {
        export::configure(config)
    }
    #[cfg(not(feature = "http-client"))]
    {
        let _ = config;
        anyhow::bail!("trace export requires the http-client feature")
    }
}

#[must_use = "skip export work when tracing has not been configured"]
pub fn enabled() -> bool {
    #[cfg(feature = "http-client")]
    {
        export::enabled()
    }
    #[cfg(not(feature = "http-client"))]
    {
        false
    }
}

/// Persist queued traces before a graceful client daemon shutdown.
pub fn flush() {
    #[cfg(feature = "http-client")]
    export::flush();
}

pub fn submit(spans: Vec<LatencySpan>) {
    #[cfg(feature = "http-client")]
    export::submit(spans);
    #[cfg(not(feature = "http-client"))]
    drop(spans);
}

#[cfg(all(target_os = "linux", feature = "dist-client"))]
pub(crate) fn instance() -> Option<&'static str> {
    export::instance()
}

#[cfg(feature = "http-client")]
mod export;
#[cfg(feature = "http-client")]
mod spool;

/// Records successive worker phases, including queue and publication waits.
/// The owned guard crosses queue handoffs; no thread-local scope is required.
pub struct PhaseTrace {
    root: LatencySpan,
    clock: std::time::Instant,
    phase: &'static str,
    phase_start: u64,
    spans: Vec<LatencySpan>,
}

impl PhaseTrace {
    #[must_use = "retain across all worker queue handoffs"]
    pub fn new(
        parent: TraceContext,
        service: &'static str,
        name: &'static str,
        first_phase: &'static str,
        attributes: Vec<(&'static str, String)>,
    ) -> Self {
        let start = unix_nanos();
        let mut root = LatencySpan::child(parent, service, name, start, start);
        root.attributes = attributes;
        root.error = true;
        Self {
            root,
            clock: std::time::Instant::now(),
            phase: first_phase,
            phase_start: start,
            spans: Vec::new(),
        }
    }

    fn timestamp(&self) -> u64 {
        self.root.start.saturating_add(nanos(self.clock.elapsed()))
    }

    fn close_phase(&mut self, now: u64) {
        self.spans.push(LatencySpan::child(
            self.root.context,
            self.root.service,
            self.phase,
            self.phase_start,
            now,
        ));
    }

    pub fn phase(&mut self, phase: &'static str) {
        if self.phase != phase {
            let now = self.timestamp();
            self.close_phase(now);
            self.phase = phase;
            self.phase_start = now;
        }
    }

    pub fn finish(mut self, failed: bool) {
        self.root.error = failed;
    }
}

impl Drop for PhaseTrace {
    fn drop(&mut self) {
        let now = self.timestamp();
        self.close_phase(now);
        self.root.end = now;
        self.spans.push(self.root.clone());
        submit(std::mem::take(&mut self.spans));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_identity_is_independent_of_cache_identity() {
        let first = TraceContext::request("request1");
        let second = TraceContext::request("request2");
        assert_ne!(first.trace_id, second.trace_id);
        assert!(first.valid());
        assert_eq!(first, TraceContext::request("request1"));
        let child = child_context(first);
        assert_eq!(first.trace_id, child.trace_id);
        assert_ne!(first.span_id, child.span_id);
    }
}
