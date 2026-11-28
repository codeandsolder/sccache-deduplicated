//! Deterministic populated dashboard, with a controllable Prometheus-compatible
//! endpoint. Used by the optimized-WASM browser suite, never by production.
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use sccache_build::{
    PeerId,
    analytics::CacheDistribution,
    wire::{LiveTraceRequest, LiveTraceRow, LiveTraceSnapshot, TraceContext},
};
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

const REQUEST: TraceContext = TraceContext {
    trace_id: [0x11; 16],
    span_id: [0x33; 8],
};
const PRODUCER: TraceContext = TraceContext {
    trace_id: [0x22; 16],
    span_id: [0x44; 8],
};
const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

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
        trace_id: Some(PRODUCER.hex_id()),
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
    let jobs = (0..if phase == 8 { 12 } else { 3 })
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
    let rows = if phase == 9 {
        Vec::new()
    } else {
        let count = if phase == 8 { 48 } else { 1 };
        (0..count)
            .map(|index| LiveTraceRow {
                peer: PeerId::from_digest([0x55; 32]),
                instance: "fixture-client".into(),
                observation_age_ms: 20,
                request: LiveTraceRequest {
                    trace: if index == 0 {
                        REQUEST
                    } else {
                        TraceContext {
                            trace_id: [index + 0x33; 16],
                            span_id: [index + 0x33; 8],
                        }
                    },
                    compiler: "rustc".into(),
                    output: if index == 0 {
                        "fixture-traced-crate".into()
                    } else {
                        format!("fixture-live-crate-{index}")
                    },
                    phase: if phase.is_multiple_of(2) {
                        "hash_inputs".into()
                    } else {
                        "wait_for_producer".into()
                    },
                    elapsed_ms: 100 + phase,
                    phase_age_ms: 60,
                    worker: "fixture-worker".into(),
                    job: None,
                    producer: Some(PRODUCER),
                },
            })
            .collect::<Vec<_>>()
    };
    NativeTelemetry {
        live_traces: Some(LiveTraceSnapshot {
            active: u64::try_from(rows.len()).unwrap_or_default(),
            rows,
        }),
        admission: Some(AdmissionCounts {
            hits: 80 + phase * 4,
            misses: 20 + phase,
            refreshes: 1,
            ..Default::default()
        }),
        duplicate_misses: Some(sccache_build::analytics::DuplicateMisses {
            new_keys: 20 + phase,
            identical_outputs: 8 + phase,
            identical_results: 5 + phase,
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

// A LogsQL-shaped fixture exercises the actual typed proxy, server functions,
// SSR hydration and browser query/filter handling without a running database.
const START: u64 = 1_795_788_000_000_000_000;

fn trace_root(context: TraceContext) -> Value {
    let output = if context == REQUEST {
        "fixture-traced-crate"
    } else {
        "fixture-producer"
    };
    let span = if context == REQUEST {
        "3333333333333333"
    } else {
        "4444444444444444"
    };
    json!({
        "trace_id":context.hex_id(),"span_id":span,"name":"compile",
        "duration":"100000000","start_time_unix_nano":START.to_string(),
        "resource_attr:host.name":"fixture-client",
        "resource_attr:service.name":"sccache-client",
        "resource_attr:service.version":REVISION,
        "span_attr:sccache.compiler":"rustc","span_attr:sccache.output":output,
        "span_attr:sccache.outcome":"worker","span_attr:sccache.worker":"fixture-worker",
        "span_attr:sccache.action_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    })
}

fn fixture_span(
    id: &str,
    parent: &str,
    name: &str,
    offset_ms: u64,
    duration_ms: u64,
    kind: &str,
    worker: bool,
) -> Value {
    let (host, service) = if worker {
        ("fixture-worker", "sccache-worker")
    } else {
        ("fixture-client", "sccache-client")
    };
    json!({
        "span_id":id,"parent_span_id":parent,"name":name,
        "duration":(duration_ms*1_000_000).to_string(),
        "start_time_unix_nano":(START+offset_ms*1_000_000).to_string(),
        "resource_attr:host.name":host,"resource_attr:service.name":service,
        "resource_attr:service.version":REVISION,"span_attr:sccache.span_kind":kind,
    })
}

fn trace_children(context: TraceContext) -> Vec<Value> {
    let mut children = vec![trace_root(context)];
    if context == REQUEST {
        let parent = "3333333333333333";
        let mut wait = fixture_span(
            "6666666666666666",
            parent,
            "wait_for_producer",
            30,
            60,
            "phase",
            false,
        );
        wait["span_attr:sccache.producer_trace_id"] = json!(PRODUCER.hex_id());
        children.extend([
            fixture_span(
                "5555555555555555",
                parent,
                "hash_inputs",
                0,
                30,
                "phase",
                false,
            ),
            wait,
            fixture_span(
                "7777777777777777",
                parent,
                "jobserver_wait",
                0,
                50,
                "interval",
                false,
            ),
        ]);
    } else {
        let parent = "4444444444444444";
        let worker = "9999999999999999";
        children.extend([
            fixture_span(
                "8888888888888888",
                parent,
                "run_distributed",
                0,
                100,
                "phase",
                false,
            ),
            fixture_span(worker, parent, "worker_job", 250, 80, "", true),
            fixture_span(
                "aaaaaaaaaaaaaaaa",
                worker,
                "prepare_sandbox",
                250,
                30,
                "phase",
                true,
            ),
            fixture_span(
                "bbbbbbbbbbbbbbbb",
                worker,
                "compiler_process",
                280,
                50,
                "phase",
                true,
            ),
        ]);
    }
    children
}

fn trace_query(body: Bytes) -> Ready<(StatusCode, String)> {
    let body: Vec<u8> = body.into();
    let Some(query) = url::form_urlencoded::parse(&body)
        .find_map(|(name, value)| (name == "query").then(|| value.into_owned()))
    else {
        return ready((StatusCode::BAD_REQUEST, "missing query".into()));
    };
    if query.ends_with(" | stats count() as count") {
        return ready((StatusCode::OK, "{\"count\":\"1\"}\n".into()));
    }
    if !query.contains(" | uniq by (") {
        return ready((
            StatusCode::BAD_REQUEST,
            "query must deduplicate replay".into(),
        ));
    }
    let rows = if query.contains(" | stats by (") {
        vec![
            json!({"name":"hash_inputs","resource_attr:service.name":"sccache-client","resource_attr:host.name":"fixture-client","resource_attr:service.version":REVISION,"count":"1","bins":r#"[{"vmrange":"27830000...31620000","hits":1}]"#,"minimum":"30000000","maximum":"30000000","total":"30000000"}),
        ]
    } else if query.contains("trace_id:=") {
        if query.contains(&REQUEST.hex_id()) {
            trace_children(REQUEST)
        } else if query.contains(&PRODUCER.hex_id()) {
            trace_children(PRODUCER)
        } else {
            Vec::new()
        }
    } else if query.contains(r#""resource_attr:service.version":="#) && !query.contains(REVISION) {
        Vec::new()
    } else {
        std::iter::once(trace_root(REQUEST))
            .chain((1_u8..60).map(|index| {
                let mut row = trace_root(TraceContext {
                    trace_id: [index + 0x66; 16],
                    span_id: [index + 0x66; 8],
                });
                row["span_id"] = json!(format!("{:016x}", index));
                row["span_attr:sccache.output"] = json!(format!("fixture-completed-{index}"));
                row["duration"] = json!((90_000_000 - u64::from(index) * 1_000_000).to_string());
                row
            }))
            .collect()
    };
    let mut body = rows
        .into_iter()
        .map(|row| row.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    body.push('\n');
    ready((StatusCode::OK, body))
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
        .route("/select/logsql/query", post(trace_query))
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
        sccache_dashboard::server::TelemetrySources {
            metrics_url: Some(&base),
            metrics_ingress_host: Some("fixture.example"),
            traces_url: Some(&base),
        },
        move || Ok(snapshot(snapshot_state.load(Ordering::Relaxed))),
        move || Some(telemetry(telemetry_state.load(Ordering::Relaxed))),
        receiver,
    )?;
    println!("FIXTURE_METRICS={base}");
    println!("FIXTURE_DASHBOARD=http://{dashboard}");
    axum::serve(listener, api).await?;
    Ok(())
}
