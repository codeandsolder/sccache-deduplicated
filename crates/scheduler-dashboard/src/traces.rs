//! Typed request latency query and timeline data shared by SSR and WASM.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceSearch {
    pub lookback_secs: u32,
    pub host: String,
    pub revision: String,
    pub compiler: String,
    pub output: String,
    pub outcome: String,
    pub slowest: bool,
}

impl Default for TraceSearch {
    fn default() -> Self {
        Self {
            lookback_secs: 3600,
            host: String::new(),
            revision: String::new(),
            compiler: String::new(),
            output: String::new(),
            outcome: String::new(),
            slowest: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceSummary {
    pub id: String,
    pub start_ns: u64,
    pub duration_ns: u64,
    pub host: String,
    pub revision: String,
    pub compiler: String,
    pub output: String,
    pub outcome: String,
    pub worker: String,
    pub action: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SpanKind {
    Phase,
    Interval,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceSpan {
    pub id: String,
    pub parent: String,
    pub service: String,
    pub host: String,
    pub revision: String,
    pub name: String,
    pub kind: SpanKind,
    pub start_ns: u64,
    pub duration_ns: u64,
    pub error: bool,
    pub producer: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceDetail {
    pub id: String,
    pub request: Option<TraceSummary>,
    pub omitted_intervals: u64,
    pub spans: Vec<TraceSpan>,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PhaseAggregate {
    pub service: String,
    pub host: String,
    pub version: String,
    pub phase: String,
    pub count: u64,
    pub p50_ns: f64,
    pub p95_ns: f64,
    pub p99_ns: f64,
    pub total_ns: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TraceOverview {
    pub traces: Vec<TraceSummary>,
    pub trace_error: Option<String>,
    pub phases: Vec<PhaseAggregate>,
    pub phase_error: Option<String>,
}

mod attribution;
pub use attribution::{PhaseBreakdown, PhaseDuration, phase_breakdowns};
