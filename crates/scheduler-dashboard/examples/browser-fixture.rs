//! Deterministic populated dashboard, with a controllable Prometheus-compatible
//! endpoint. Used by the optimized-WASM browser suite, never by production.
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use sccache_build::analytics::CacheDistribution;
use sccache_dashboard::{
    AdmissionCounts, AnalyticsObservation, Cache, CacheSpace, HostInterface, HostRole, Job,
    JobDescription, NativeTelemetry, NativeWorker, NetworkGraph, NetworkHost, NetworkLink,
    NetworkPeer, RouteEvidence, Snapshot, Totals, Worker,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    future::{Ready, ready},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct Fixture {
    phase: Arc<AtomicU64>,
    mode: Arc<AtomicU64>,
    requests: Arc<AtomicU64>,
    selected_queries: Arc<AtomicU64>,
    wake: mpsc::SyncSender<()>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn analytics() -> AnalyticsObservation {
    let mut report = CacheDistribution::default();
    report.record(4096, Some((2048, 4096)), 2, Some(10), Some(60));
    report.record(8192, None, 1, None, None);
    AnalyticsObservation {
        sampled_at: now(),
        report: Some(report),
        error: None,
        maximum_bytes: Some(32 << 30),
    }
}

fn job(index: usize, phase: u64) -> Job {
    let status = match (index, phase) {
        (0, 0) => "Queued",
        (0, 1) | (1, _) => "Staging",
        (0, 2) => "Executing",
        (0, _) => "Terminal",
        _ => "Executing",
    };
    let remaining = match status {
        "Queued" => 4096,
        "Staging" => 2048,
        _ => 0,
    };
    Job {
        id: format!("fixture-job-{index}"),
        description: Some(JobDescription {
            executable: "rustc".into(),
            subject: Some(format!("fixture-crate-{index}")),
            target: Some("x86_64-unknown-linux-gnu".into()),
            requester: Some("fixture-client".into()),
            input_bytes: 4096,
            input_blobs: 4,
        }),
        worker: "fixture-worker".into(),
        worker_id: "worker".into(),
        state: "Ready".into(),
        native_phase: Some(status.into()),
        native_phase_observed_ns: Some(1_000_000_000),
        assigned_at_ms: Some(now().saturating_sub(30) * 1000),
        state_since_ms: Some(now().saturating_sub(10) * 1000),
        remaining_input_bytes: Some(remaining),
        remaining_input_blobs: Some(remaining / 1024),
        predicted_completion_secs: Some(12.0),
    }
}

fn host(id: &str, name: &str, role: HostRole, address: &str, phase: u64) -> NetworkHost {
    NetworkHost {
        id: id.into(),
        name: name.into(),
        role,
        status: "Active".into(),
        addresses: vec![address.into()],
        interfaces: vec![HostInterface {
            index: 1,
            addresses: vec![address.into()],
            nominal_bytes_per_second: Some(125_000_000),
            tx_bytes_per_second: 1_000_000 + phase * 1_000_000,
            rx_bytes_per_second: 2_000_000,
            external_tx_bytes_per_second: 100,
            external_rx_bytes_per_second: 200,
        }],
    }
}

fn snapshot(phase: u64) -> Snapshot {
    let jobs = (0..3)
        .filter(|index| *index != 0 || phase < 4)
        .map(|index| job(index, phase))
        .collect::<Vec<_>>();
    let worker = Worker {
        id: "worker".into(),
        name: "fixture-worker".into(),
        heartbeat_at_ms: now() * 1000,
        last_error_at_ms: None,
        cpu_capacity: 8.0,
        assigned: jobs.len(),
        assigning: 0,
        compiler_demand: jobs.len(),
        max_jobs: 12,
        available: 12 - jobs.len(),
        archive_available: None,
        native_available: Some(12 - jobs.len()),
        native: Some(NativeWorker {
            cache_analytics: Some(analytics().site_summary()),
            reservations: jobs.len(),
            capacity: 12,
            compiler_active: if phase >= 2 { 2 } else { 1 },
            compiler_slots: 8,
            staging_slots: 2,
            publication_slots: 2,
            phases: vec![("Executing".into(), 1)],
            remaining_input_bytes: 4096,
            timing_revision: phase,
            execution_ns: 1_000_000_000,
            input_bytes_per_second: 1_000_000,
            output_bytes_per_second: 2_000_000,
            output_observations: 2,
            residency_reported: true,
        }),
    };
    Snapshot {
        totals: Totals {
            workers: 1,
            cpu_capacity: 8.0,
            assigned: jobs.len(),
            compiler_demand: jobs.len(),
            compiler_active: if phase >= 2 { 2 } else { 1 },
            max_jobs: 12,
            available: 12 - jobs.len(),
            allocated_ids: 3,
            ..Default::default()
        },
        workers: vec![worker],
        jobs,
        topology: NetworkGraph {
            hosts: vec![
                host(
                    "client",
                    "fixture-client",
                    HostRole::Client,
                    "10.0.0.3",
                    phase,
                ),
                host(
                    "scheduler",
                    "fixture-scheduler",
                    HostRole::Scheduler,
                    "10.0.0.1",
                    phase,
                ),
                host(
                    "worker",
                    "fixture-worker",
                    HostRole::Worker,
                    "10.0.0.2",
                    phase,
                ),
            ],
            links: vec![NetworkLink {
                id: "scheduler>worker".into(),
                source: "scheduler".into(),
                target: "worker".into(),
                source_address: Some("10.0.0.1".into()),
                target_address: Some("10.0.0.2".into()),
                evidence: RouteEvidence::Transferring,
                wire_bytes_per_second: Some(1_000_000 + phase * 1_000_000),
                logical_bytes_per_second: Some(2_000_000),
                remaining_bytes: Some(4096),
            }],
        },
    }
}

fn telemetry(phase: u64) -> NativeTelemetry {
    NativeTelemetry {
        admission: Some(AdmissionCounts {
            hits: 80 + phase * 4,
            misses: 20 + phase,
            refreshes: 1,
            ..Default::default()
        }),
        analytics: Some(analytics()),
        cache: Some(Cache {
            actions: 17,
            results: 17,
            trees: 1,
            blobs: 2,
            logical_bytes: 12288,
            pending_gc_blobs: 1,
            pending_gc_bytes: 4096,
        }),
        space: Some(CacheSpace {
            available: 40 << 30,
            reserved: Some(4096),
            min_available: Some(4 << 30),
            target_available: Some(8 << 30),
            max_resident: Some(32 << 30),
            target_resident: Some(28 << 30),
        }),
        network: vec![NetworkPeer {
            peer: "fixture-worker".into(),
            direction: "Send".into(),
            observed_bytes_per_second: 1_000_000,
            isolated_bytes_per_second: 0,
            wire_per_mille: 500,
            remaining_bytes: 4096,
            body_bytes: 12288,
        }],
        ..Default::default()
    }
}

#[derive(Deserialize)]
struct Range {
    query: String,
    start: u64,
    end: u64,
    step: usize,
}

fn labels(State(fixture): State<Fixture>) -> Ready<Json<Value>> {
    fixture.requests.fetch_add(1, Ordering::Relaxed);
    let labels = if fixture.mode.load(Ordering::Relaxed) == 1 {
        vec![]
    } else {
        vec!["fixture-client"]
    };
    ready(Json(json!({"status":"success","data":labels})))
}

fn metrics(State(fixture): State<Fixture>, Query(range): Query<Range>) -> Ready<Json<Value>> {
    fixture.requests.fetch_add(1, Ordering::Relaxed);
    if range.query.contains(r#"instance=~"fixture-client""#) {
        fixture.selected_queries.fetch_add(1, Ordering::Relaxed);
    }
    let mode = fixture.mode.load(Ordering::Relaxed);
    if mode == 3 {
        return ready(Json(
            json!({"status":"success","data":{"resultType":"matrix","result":[]}}),
        ));
    }
    let value = if mode == 0 { "80" } else { "90" };
    let mut points = (range.start..=range.end)
        .step_by(range.step.max(1))
        .map(|time| json!([time, value]))
        .collect::<Vec<_>>();
    if mode == 2 && range.query.contains("sccache_cache_requests_total") {
        points.push(json!([range.end, value])); // duplicate grid timestamp: malformed.
    }
    // A real response has labels and an aligned timestamp grid. The fixed
    // fixture values intentionally exercise rendering, not PromQL arithmetic.
    ready(Json(
        json!({"status":"success","data":{"resultType":"matrix","result":[{"metric":{"instance":"fixture-client","result":"hit","language":"Rust","compiler_language":"rust","level":"0","name":"fixture-tier","backend":"disk","kind":"live","server":"fixture-worker","version":"fixture"},"values":points}]}}),
    ))
}

fn phase(State(fixture): State<Fixture>, Path(value): Path<u64>) -> Ready<()> {
    fixture.phase.store(value, Ordering::Relaxed);
    let _ = fixture.wake.try_send(());
    ready(())
}

fn mode(State(fixture): State<Fixture>, Path(value): Path<u64>) -> Ready<()> {
    fixture.mode.store(value, Ordering::Relaxed);
    ready(())
}

fn count(State(fixture): State<Fixture>) -> Ready<String> {
    ready(fixture.requests.load(Ordering::Relaxed).to_string())
}

fn selected(State(fixture): State<Fixture>) -> Ready<String> {
    ready(fixture.selected_queries.load(Ordering::Relaxed).to_string())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let assets = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .context("missing dashboard assets")?,
    );
    let (wake, receiver) = mpsc::sync_channel(1);
    let fixture = Fixture {
        phase: Arc::default(),
        mode: Arc::default(),
        requests: Arc::default(),
        selected_queries: Arc::default(),
        wake,
    };
    let api = Router::new()
        .route("/api/v1/label/instance/values", get(labels))
        .route("/api/v1/query_range", get(metrics))
        .route("/fixture/phase/{value}", post(phase))
        .route("/fixture/mode/{value}", post(mode))
        .route("/fixture/count", get(count))
        .route("/fixture/selected", get(selected))
        .with_state(fixture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let base = format!("http://{address}");
    let snapshot_state = Arc::clone(&fixture.phase);
    let telemetry_state = Arc::clone(&fixture.phase);
    let dashboard = sccache_dashboard::server::spawn(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &assets,
        Some(&base),
        Some("fixture.example"),
        move || Ok(snapshot(snapshot_state.load(Ordering::Relaxed))),
        move || Some(telemetry(telemetry_state.load(Ordering::Relaxed))),
        receiver,
    )?;
    println!("FIXTURE_METRICS={base}");
    println!("FIXTURE_DASHBOARD=http://{dashboard}");
    axum::serve(listener, api).await?;
    Ok(())
}
