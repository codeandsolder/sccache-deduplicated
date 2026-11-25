//! Scheduler-local Leptos SSR and WASM hydration application.
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "ssr", feature = "hydrate"))]
mod app;
#[cfg(feature = "ssr")]
pub mod server;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    leptos::mount::hydrate_body(app::App);
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Worker {
    pub address: String,
    pub name: String,
    pub heartbeat_age_secs: f64,
    pub last_error_age_secs: Option<f64>,
    pub cpu_capacity: f64,
    pub assigned: usize,
    pub assigning: usize,
    pub compiler_demand: usize,
    pub max_jobs: usize,
    pub available: usize,
    pub archive: bool,
    pub native: Option<NativeWorker>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub worker: String,
    pub state: String,
    pub native_phase: Option<String>,
    pub age_secs: f64,
    pub phase_age_secs: f64,
    pub remaining_input_bytes: Option<u64>,
    pub remaining_input_blobs: Option<u64>,
    pub predicted_completion_secs: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPeer {
    pub peer: String,
    pub direction: String,
    pub observed_bytes_per_second: u64,
    pub isolated_bytes_per_second: u64,
    pub wire_per_mille: u64,
    pub remaining_bytes: u64,
    pub body_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGroup {
    pub direction: String,
    pub peers: String,
    pub bytes_per_second: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cache {
    pub actions: u64,
    pub results: u64,
    pub trees: u64,
    pub blobs: u64,
    pub logical_bytes: u64,
    pub pending_gc_blobs: u64,
    pub pending_gc_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub unix_secs: u64,
    pub totals: Totals,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DashboardData {
    pub sampled_at: Option<u64>,
    pub snapshot: Option<Snapshot>,
    pub history: Vec<Sample>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSeries {
    pub label: String,
    pub points: Vec<(f64, Option<f64>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPanel {
    pub title: String,
    pub unit: String,
    pub series: Vec<MetricSeries>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsData {
    pub configured: bool,
    pub sampled_at: Option<u64>,
    pub panels: Vec<MetricPanel>,
}
