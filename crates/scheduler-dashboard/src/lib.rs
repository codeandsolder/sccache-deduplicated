//! Scheduler-local Leptos SSR and WASM hydration application.
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "ssr", feature = "hydrate"))]
mod app;
#[cfg(feature = "ssr")]
pub mod server;
#[cfg(any(feature = "ssr", feature = "hydrate"))]
mod styles;

#[cfg(all(feature = "hydrate", target_arch = "wasm32"))]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    leptos::mount::hydrate_body(app::App);
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Totals {
    pub workers: usize,
    pub cpu_capacity: f64,
    pub assigned: usize,
    pub assigning: usize,
    pub compiler_active: usize,
    pub compiler_demand: usize,
    pub max_jobs: usize,
    pub available: usize,
    pub allocated_ids: usize,
    pub draining: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Worker {
    pub address: String,
    pub name: String,
    pub heartbeat_at_ms: u64,
    pub last_error_at_ms: Option<u64>,
    pub cpu_capacity: f64,
    pub assigned: usize,
    pub assigning: usize,
    pub compiler_demand: usize,
    pub max_jobs: usize,
    pub available: usize,
    pub archive: bool,
    pub native: Option<NativeWorker>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeWorker {
    pub reservations: usize,
    pub capacity: u32,
    pub compiler_active: u32,
    pub compiler_slots: u32,
    pub staging_slots: u32,
    pub publication_slots: u32,
    pub phases: Vec<(String, usize)>,
    pub remaining_input_bytes: u64,
    pub timing_revision: u64,
    pub execution_ns: u64,
    pub input_bytes_per_second: u64,
    pub output_bytes_per_second: u64,
    pub output_observations: u64,
    pub residency_reported: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub worker: String,
    pub state: String,
    pub native_phase: Option<String>,
    pub assigned_at_ms: u64,
    pub state_since_ms: u64,
    pub remaining_input_bytes: Option<u64>,
    pub remaining_input_blobs: Option<u64>,
    pub predicted_completion_secs: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkPeer {
    pub peer: String,
    pub direction: String,
    pub observed_bytes_per_second: u64,
    pub isolated_bytes_per_second: u64,
    pub wire_per_mille: u64,
    pub remaining_bytes: u64,
    pub body_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkGroup {
    pub direction: String,
    pub peers: String,
    pub bytes_per_second: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cache {
    pub actions: u64,
    pub results: u64,
    pub trees: u64,
    pub blobs: u64,
    pub logical_bytes: u64,
    pub pending_gc_blobs: u64,
    pub pending_gc_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub totals: Totals,
    pub workers: Vec<Worker>,
    pub jobs: Vec<Job>,
    pub jobs_total: usize,
    pub cache: Option<Cache>,
    pub cache_error: Option<String>,
    pub network: Vec<NetworkPeer>,
    pub shared_capacity: Vec<NetworkGroup>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    pub unix_secs: u64,
    pub totals: Totals,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DashboardData {
    pub revision: u64,
    pub sampled_at: Option<u64>,
    pub snapshot: Option<Snapshot>,
    pub history: Vec<Sample>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricSeries {
    pub key: String,
    pub label: String,
    pub points: Vec<(f64, Option<f64>)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricPanel {
    pub key: usize,
    pub title: String,
    pub unit: String,
    pub series: Vec<MetricSeries>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct MetricsData {
    pub revision: u64,
    pub error: Option<String>,
    pub view: MetricsView,
    pub clients: Vec<String>,
    pub configured: bool,
    pub sampled_at: Option<u64>,
    pub panels: Vec<MetricPanel>,
}

pub const HISTORY_CAPACITY: usize = 900;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TimeRange {
    FifteenMinutes,
    #[default]
    OneHour,
    SixHours,
    OneDay,
    SevenDays,
}

impl TimeRange {
    pub const ALL: [Self; 5] = [
        Self::FifteenMinutes,
        Self::OneHour,
        Self::SixHours,
        Self::OneDay,
        Self::SevenDays,
    ];

    pub const fn seconds(self) -> u64 {
        match self {
            Self::FifteenMinutes => 900,
            Self::OneHour => 3600,
            Self::SixHours => 21600,
            Self::OneDay => 86400,
            Self::SevenDays => 604800,
        }
    }

    pub const fn step(self) -> u64 {
        match self {
            Self::FifteenMinutes => 5,
            Self::OneHour => 15,
            Self::SixHours => 60,
            Self::OneDay => 300,
            Self::SevenDays => 1800,
        }
    }

    pub const fn value(self) -> &'static str {
        match self {
            Self::FifteenMinutes => "fifteen_minutes",
            Self::OneHour => "one_hour",
            Self::SixHours => "six_hours",
            Self::OneDay => "one_day",
            Self::SevenDays => "seven_days",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::FifteenMinutes => "15 minutes",
            Self::OneHour => "1 hour",
            Self::SixHours => "6 hours",
            Self::OneDay => "24 hours",
            Self::SevenDays => "7 days",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsView {
    pub range: TimeRange,
    /// Exact instance label, not a regular expression or arbitrary query.
    pub client: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NativeEvent {
    Reset(DashboardData),
    Patch(Box<NativePatch>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rows<T> {
    pub upsert: Vec<T>,
    pub remove: Vec<String>,
}

impl<T> Default for Rows<T> {
    fn default() -> Self {
        Self {
            upsert: Vec::new(),
            remove: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheUpdate {
    pub stats: Option<Cache>,
    pub error: Option<String>,
}

/// A patch always belongs to exactly one previous revision. Reset messages
/// replace the whole state after connecting or falling behind the broadcast.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NativePatch {
    pub sampled_at: Option<u64>,
    pub revision: u64,
    pub sample: Option<Sample>,
    pub error: Option<String>,
    pub totals: Option<Totals>,
    pub workers: Rows<Worker>,
    pub jobs: Rows<Job>,
    pub jobs_total: Option<usize>,
    pub cache: Option<CacheUpdate>,
    pub network: Option<Vec<NetworkPeer>>,
    pub shared_capacity: Option<Vec<NetworkGroup>>,
}

mod protocol;
pub use protocol::{apply_event, apply_metrics_event, make_metrics_patch, make_patch};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MetricsEvent {
    Reset(MetricsData),
    Patch(MetricsPatch),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsPatch {
    pub revision: u64,
    pub sampled_at: Option<u64>,
    pub error: Option<String>,
    pub clients: Option<Vec<String>>,
    pub panels: Vec<PanelPatch>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PanelPatch {
    Replace(MetricPanel),
    Update {
        key: usize,
        error: Option<String>,
        series: Vec<SeriesPatch>,
        removed: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SeriesPatch {
    Replace(MetricSeries),
    Update {
        key: String,
        upsert: Vec<(f64, Option<f64>)>,
        remove: Vec<f64>,
    },
}
