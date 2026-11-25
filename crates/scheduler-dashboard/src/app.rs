use crate::{DashboardData, MetricSeries, MetricsData, Snapshot as SchedulerSnapshot, Totals};
use leptos::prelude::*;
#[cfg(feature = "ssr")]
use leptos_meta::MetaTags;
use leptos_meta::{Title, provide_meta_context};

#[server(endpoint = "snapshot")]
async fn snapshot() -> Result<DashboardData, ServerFnError> {
    let state = use_context::<crate::server::DashboardState>()
        .ok_or_else(|| ServerFnError::ServerError("Dashboard unavailable".into()))?;
    let data = state
        .status
        .lock()
        .map_err(|_| ServerFnError::ServerError("Status unavailable".into()))?
        .clone();
    Ok(data)
}

#[server(endpoint = "metrics")]
async fn metrics() -> Result<MetricsData, ServerFnError> {
    let state = use_context::<crate::server::DashboardState>()
        .ok_or_else(|| ServerFnError::ServerError("Dashboard unavailable".into()))?;
    let data = state
        .metrics
        .lock()
        .map_err(|_| ServerFnError::ServerError("Metrics unavailable".into()))?
        .clone();
    Ok(data)
}

#[cfg(feature = "ssr")]
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <link rel="stylesheet" href="/style.css"/>
                <leptos::hydration::HydrationScripts options=options/>
                <MetaTags/>
            </head>
            <body><App/></body>
        </html>
    }
}

fn poll_signal(period: std::time::Duration) -> RwSignal<u64> {
    let tick = RwSignal::new(0_u64);
    #[cfg(target_arch = "wasm32")]
    if let Ok(handle) = leptos::leptos_dom::helpers::set_interval_with_handle(
        move || tick.update(|value| *value = value.wrapping_add(1)),
        period,
    ) {
        on_cleanup(move || handle.clear());
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = period;
    tick
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    let native_tick = poll_signal(std::time::Duration::from_secs(2));
    let metrics_tick = poll_signal(std::time::Duration::from_secs(30));
    let status = Resource::new(move || native_tick.get(), |_| snapshot());
    let telemetry = Resource::new(move || metrics_tick.get(), |_| metrics());
    view! {
        <Title text="sccache | Scheduler status"/>
        <header class="top"><div><small>"SCCACHE / DISTRIBUTED BUILD"</small><h1>"Scheduler status"</h1></div>
            <nav><a href="#workers">"Workers"</a><a href="#jobs">"Jobs"</a><a href="#cas">"CAS"</a><a href="#network">"Network"</a><a href="#metrics">"Fleet metrics"</a></nav>
        </header>
        <main>
            <Transition fallback=|| view! { <p>"Waiting for first scheduler sample…"</p> }>
                {move || status.get().map(|result| match result {
                    Ok(data) => view! { <NativeStatus data=data/> }.into_any(),
                    Err(error) => view! { <p class="warning">{error.to_string()}</p> }.into_any(),
                })}
            </Transition>
            <section id="metrics"><h2>"Fleet telemetry / last hour"</h2>
                <p class="muted">"Existing Liberta/Prometheus metrics; 30-second resolution. Rates use a five-minute window. Missing series are not zero."</p>
                <Transition fallback=|| view! { <p>"Loading fleet metrics…"</p> }>
                    {move || telemetry.get().map(|result| match result {
                        Ok(data) => view! { <FleetMetrics data=data/> }.into_any(),
                        Err(error) => view! { <p class="warning">{error.to_string()}</p> }.into_any(),
                    })}
                </Transition>
            </section>
        </main>
    }
}

fn bytes(value: u64) -> String {
    let mut scaled = value as f64;
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"] {
        if scaled < 1024.0 || unit == "TiB" {
            return format!("{scaled:.1} {unit}");
        }
        scaled /= 1024.0;
    }
    value.to_string()
}

fn rate(value: u64) -> String {
    format!("{}/s", bytes(value))
}
fn age(value: f64) -> String {
    format!("{value:.1} s")
}
fn timestamp(value: Option<u64>) -> String {
    value.map_or_else(
        || "not yet sampled".into(),
        |value| format!("Unix time {value}"),
    )
}

#[component]
fn Stat(label: &'static str, value: String) -> impl IntoView {
    view! { <div class="stat"><small>{label}</small><strong>{value}</strong></div> }
}

#[component]
fn NativeStatus(data: DashboardData) -> impl IntoView {
    let Some(snapshot) = data.snapshot else {
        return view! { <p class="warning">{data.error.unwrap_or_else(|| "Waiting for first sample".into())}</p> }.into_any();
    };
    let totals = &snapshot.totals;
    let series = [
        ("Assigned", |t: &Totals| t.assigned),
        (
            "Compiler demand",
            (|t: &Totals| t.compiler_demand) as fn(&Totals) -> usize,
        ),
        (
            "Native executing",
            (|t: &Totals| t.compiler_active) as fn(&Totals) -> usize,
        ),
        (
            "Available",
            (|t: &Totals| t.available) as fn(&Totals) -> usize,
        ),
    ]
    .into_iter()
    .map(|(label, field)| MetricSeries {
        label: label.into(),
        points: data
            .history
            .iter()
            .map(|sample| (sample.unix_secs as f64, Some(field(&sample.totals) as f64)))
            .collect(),
    })
    .collect::<Vec<_>>();
    view! {
        <div class="subhead"><span class=if totals.draining { "warning" } else { "healthy" }>
            {if totals.draining { "DRAINING" } else { "ACCEPTING WORK" }}
        </span><span class="muted">{timestamp(data.sampled_at)}" · sampled every 2 s"</span></div>
        {data.error.map(|error| view! { <p class="warning">{error}</p> })}
        <div class="stats">
            <Stat label="Workers" value=totals.workers.to_string()/>
            <Stat label="CPU capacity" value=format!("{:.1}",totals.cpu_capacity)/>
            <Stat label="Assigned / limit" value=format!("{} / {}",totals.assigned,totals.max_jobs)/>
            <Stat label="Assigning RPCs" value=totals.assigning.to_string()/>
            <Stat label="Native executing" value=totals.compiler_active.to_string()/>
            <Stat label="Compiler demand" value=totals.compiler_demand.to_string()/>
            <Stat label="Available admissions" value=totals.available.to_string()/>
            <Stat label="Job IDs allocated (epoch)" value=totals.allocated_ids.to_string()/>
        </div>
        <section><h2>"Scheduler activity / up to 30 min"</h2><Graph series=series unit="jobs".to_owned()/></section>
        <Details snapshot=snapshot/>
    }.into_any()
}

#[component]
fn Details(snapshot: SchedulerSnapshot) -> impl IntoView {
    let job_count = snapshot.jobs_total;
    let shown = snapshot.jobs.len();
    view! {
        <section id="workers"><h2>"Workers"</h2>
            <div class="tablewrap"><table><thead><tr>
                <th>"Worker"</th><th>"Heartbeat"</th><th>"CPU"</th><th>"Assigned"</th><th>"Demand / limit"</th><th>"Free"</th><th>"Executing / slots"</th><th>"Native queue"</th><th>"Pipeline"</th><th>"Input backlog"</th><th>"Observed / estimated service"</th>
            </tr></thead><tbody>
                {snapshot.workers.into_iter().map(|worker| {
                    let (execution, queue, phases, remaining, timing) = worker.native.as_ref().map_or_else(
                        || ("—".to_owned(), "Archive".to_owned(), "—".to_owned(), "—".to_owned(), "—".to_owned()),
                        |native| (
                            format!("{} / {}",native.compiler_active,native.compiler_slots),
                            format!("{} / {}",native.reservations,native.capacity),
                            native.phases.iter().map(|(phase,count)| format!("{phase}: {count}")).collect::<Vec<_>>().join(" · "),
                            bytes(native.remaining_input_bytes),
                            format!("{} exec · {} in · {} out · rev {} · {} staging / {} publication slots · {} output samples · residency {}",
                                if native.execution_ns == 0 { "unobserved".into() } else { age(native.execution_ns as f64 / 1e9) },
                                rate(native.input_bytes_per_second),rate(native.output_bytes_per_second),native.timing_revision,
                                native.staging_slots,native.publication_slots,native.output_observations,
                                if native.residency_reported {"reported"} else {"unknown"}),
                        ));
                    view! { <tr><td><b>{worker.name}</b><small>{worker.address}</small><small>{if worker.archive {"Archive enabled"} else {"Native only"}}</small></td>
                        <td>{age(worker.heartbeat_age_secs)}{worker.last_error_age_secs.map(|error| view!{<small class="warning">"Last error: "{age(error)}" ago"</small>})}</td>
                        <td>{format!("{:.1}", worker.cpu_capacity)}</td><td>{worker.assigned}" + "{worker.assigning}" RPC"</td>
                        <td>{worker.compiler_demand}" / "{worker.max_jobs}</td><td>{worker.available}</td>
                        <td>{execution}</td><td>{queue}</td><td>{phases}</td><td>{remaining}</td><td>{timing}</td></tr> }
                }).collect_view()}
            </tbody></table></div>
        </section>
        <section id="jobs"><h2>"Active jobs"</h2><p class="muted">{shown}" shown / "{job_count}" active · oldest first"</p>
            <div class="tablewrap"><table><thead><tr><th>"Job"</th><th>"Worker"</th><th>"State"</th><th>"Native phase"</th><th>"Age"</th><th>"Phase age"</th><th>"Input remaining"</th><th>"Predicted completion (at assignment)"</th></tr></thead><tbody>
            {snapshot.jobs.into_iter().map(|job| view!{<tr><td>{job.id}</td><td>{job.worker}</td><td>{job.state}</td><td>{job.native_phase.unwrap_or_else(|| "—".into())}</td><td>{age(job.age_secs)}</td><td>{age(job.phase_age_secs)}</td><td>{job.remaining_input_bytes.map_or_else(|| "—".into(), bytes)}{job.remaining_input_blobs.map(|blobs| format!(" / {blobs} blobs"))}</td><td>{job.predicted_completion_secs.map_or_else(|| "—".into(), age)}</td></tr>}).collect_view()}
            </tbody></table></div>
        </section>
        <section id="cas"><h2>"Scheduler CAS"</h2>
            {snapshot.cache_error.map(|error| view!{<p class="warning">{error}</p>})}
            {snapshot.cache.map_or_else(|| view!{<p class="muted">"No CAS snapshot available."</p>}.into_any(), |cache| view!{
                <div class="stats"><Stat label="Actions" value=cache.actions.to_string()/><Stat label="Results" value=cache.results.to_string()/><Stat label="Trees" value=cache.trees.to_string()/><Stat label="Blobs" value=cache.blobs.to_string()/><Stat label="Logical live bytes" value=bytes(cache.logical_bytes)/><Stat label="GC pending bytes" value=bytes(cache.pending_gc_bytes)/><Stat label="GC pending blobs" value=cache.pending_gc_blobs.to_string()/></div>
            }.into_any())}
        </section>
        <section id="network"><h2>"Native transport"</h2><p class="muted">"Effective HTTP-body throughput estimates, not physical line rates. Missing observations are not proof of zero throughput."</p>
            <div class="tablewrap"><table><thead><tr><th>"Peer"</th><th>"Direction"</th><th>"Observed"</th><th>"Isolated"</th><th>"Wire / logical"</th><th>"Active remaining"</th><th>"Body bytes"</th></tr></thead><tbody>
            {snapshot.network.into_iter().map(|peer| view!{<tr><td>{peer.peer}</td><td>{peer.direction}</td><td>{rate(peer.observed_bytes_per_second)}</td><td>{rate(peer.isolated_bytes_per_second)}</td><td>{format!("{:.1}%",peer.wire_per_mille as f64 / 10.0)}</td><td>{bytes(peer.remaining_bytes)}</td><td>{bytes(peer.body_bytes)}</td></tr>}).collect_view()}
            </tbody></table></div>
            <h3>"Shared capacity observations"</h3>
            <div class="tablewrap"><table><thead><tr><th>"Direction"</th><th>"Peers"</th><th>"Effective capacity"</th></tr></thead><tbody>
            {snapshot.shared_capacity.into_iter().map(|group| view!{<tr><td>{group.direction}</td><td>{group.peers}</td><td>{rate(group.bytes_per_second)}</td></tr>}).collect_view()}
            </tbody></table></div>
        </section>
    }
}

#[component]
fn FleetMetrics(data: MetricsData) -> impl IntoView {
    if !data.configured {
        return view! { <p class="muted">"Fleet data source not configured. Native scheduler status remains available."</p> }.into_any();
    }
    view! {
        <p class="muted">{timestamp(data.sampled_at)}</p>
        <div class="panels">
            {data.panels.into_iter().map(|panel| view! {
                <article><h3>{panel.title}</h3>
                    {panel.error.map(|error| view! { <p class="warning">{error}</p> })}
                    <Graph series=panel.series unit=panel.unit/>
                </article>
            }).collect_view()}
        </div>
    }
    .into_any()
}

const COLORS: [&str; 8] = [
    "#56b4e9", "#e69f00", "#009e73", "#cc79a7", "#f0e442", "#e76f51", "#88aaff", "#b2df8a",
];

fn plot_path(
    points: &[(f64, Option<f64>)],
    min_time: f64,
    max_time: f64,
    min_value: f64,
    max_value: f64,
) -> String {
    use std::fmt::Write;
    let mut path = String::new();
    let mut previous = None;
    for &(time, value) in points {
        if let Some(value) = value.filter(|value| value.is_finite()) {
            let x = 10.0 + (time - min_time) / (max_time - min_time).max(1.0) * 580.0;
            let y = 150.0 - (value - min_value) / (max_value - min_value).max(f64::EPSILON) * 140.0;
            let command = if previous.is_some_and(|last| time - last <= 45.0) {
                'L'
            } else {
                'M'
            };
            let _ = write!(path, "{command}{x:.2},{y:.2} ");
            previous = Some(time);
        } else {
            previous = None;
        }
    }
    path
}

#[component]
fn Graph(series: Vec<MetricSeries>, unit: String) -> impl IntoView {
    let mut min_time = f64::INFINITY;
    let mut max_time = f64::NEG_INFINITY;
    let mut min_value = 0.0_f64;
    let mut max_value = 0.0_f64;
    for (time, value) in series.iter().flat_map(|series| &series.points) {
        if let Some(value) = value.filter(|value| value.is_finite()) {
            min_time = min_time.min(*time);
            max_time = max_time.max(*time);
            min_value = min_value.min(value);
            max_value = max_value.max(value);
        }
    }
    if !min_time.is_finite() {
        return view! { <p class="muted">"No samples"</p> }.into_any();
    }
    view! {
        <div class="axis"><span>{format!("{max_value:.3} {unit}")}</span><span>"Range: "{format!("{:.0} min", (max_time-min_time)/60.0)}</span></div>
        <svg class="chart" viewBox="0 0 600 160" role="img" aria-label="Metric history" preserveAspectRatio="none">
            <path d="M10,10 H590 M10,80 H590 M10,150 H590" stroke="currentColor" opacity="0.2" fill="none"/>
            {series.iter().enumerate().map(|(index, series)| view! {
                <path d=plot_path(&series.points,min_time,max_time,min_value,max_value) stroke=COLORS[index%COLORS.len()] stroke-width="1.5" vector-effect="non-scaling-stroke" fill="none"/>
            }).collect_view()}
        </svg>
        <div class="axis"><span>{format!("{min_value:.3} {unit}")}</span><span>"Latest →"</span></div>
        <div class="legend">{series.into_iter().enumerate().map(|(index, series)| {
            let last = series.points.last().and_then(|(_,value)| *value);
            view! { <div><span style:color=COLORS[index%COLORS.len()]>"● "</span>{series.label}<b>{last.map_or_else(|| "—".into(), |value| format!("{value:.3}"))}</b></div> }
        }).collect_view()}</div>
    }.into_any()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chart_does_not_bridge_missing_samples() {
        let path = plot_path(
            &[(0.0, Some(1.0)), (30.0, None), (60.0, Some(2.0))],
            0.0,
            60.0,
            0.0,
            2.0,
        );
        assert_eq!(path.matches('M').count(), 2);
        assert!(!path.contains('L'));
    }
}
