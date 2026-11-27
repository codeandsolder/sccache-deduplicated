use leptos::prelude::*;

use crate::{
    styles,
    traces::{TraceDetail, TraceOverview, TraceSearch, TraceSpan},
};

#[server(endpoint = "trace_search")]
async fn load_trace_search(search: TraceSearch) -> Result<TraceOverview, ServerFnError> {
    let service = use_context::<crate::server::traces::TraceService>()
        .ok_or_else(|| ServerFnError::new("Trace service unavailable"))?;
    service.search(search).await.map_err(ServerFnError::new)
}

#[server(endpoint = "trace_detail")]
async fn load_trace_detail(id: String) -> Result<TraceDetail, ServerFnError> {
    let service = use_context::<crate::server::traces::TraceService>()
        .ok_or_else(|| ServerFnError::new("Trace service unavailable"))?;
    service.detail(id).await.map_err(ServerFnError::new)
}

fn ms(ns: u64) -> String {
    format!("{}.{:03} ms", ns / 1_000_000, ns % 1_000_000 / 1_000)
}

fn revision_label(revision: &str) -> String {
    if revision
        .get(..40)
        .is_some_and(|sha| sha.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        let base = &revision[..12];
        let suffix = &revision[40..];
        if let Some(digest) = suffix.strip_prefix("-dirty-") {
            return format!(
                "{base}-dirty-{}",
                digest.chars().take(12).collect::<String>()
            );
        }
        format!("{base}{suffix}")
    } else {
        revision.to_owned()
    }
}

fn span_row(
    span: TraceSpan,
    start: u64,
    extent: u64,
    selected: RwSignal<String>,
    lookup: RwSignal<String>,
) -> impl IntoView {
    let offset = span.start_ns.saturating_sub(start);
    let x = u128::from(offset) * 100_000 / u128::from(extent);
    let width = u128::from(span.duration_ns) * 100_000 / u128::from(extent);
    let fill = if span.error {
        "#e36c60"
    } else {
        match span.service.as_str() {
            "sccache-client" => "#60a5fa",
            "sccache-scheduler" => "#a78bfa",
            _ => "#34d399",
        }
    };
    let title = format!(
        "{} · {} · {} · offset {} · revision {}",
        span.host,
        span.name,
        ms(span.duration_ns),
        ms(offset),
        span.revision
    );
    view! {
        <tr>
            <td>{span.host}" / "{span.name}
                {span.producer.map(|id| view!{<button on:click=move |_| {lookup.set(id.clone()); selected.set(id.clone());}>"Producer"</button>})}
            </td>
            <td>{ms(span.duration_ns)}</td>
            <td style="width:55%;min-width:160px">
                <svg viewBox="0 0 100000 8" preserveAspectRatio="none" style="width:100%;height:20px">
                    <title>{title}</title>
                    <rect x=x.to_string() y="0" width=width.max(1).to_string() height="8" fill=fill/>
                </svg>
            </td>
        </tr>
    }
}

#[component]
fn Timeline(
    detail: TraceDetail,
    selected: RwSignal<String>,
    lookup: RwSignal<String>,
) -> impl IntoView {
    let start = detail
        .spans
        .iter()
        .map(|span| span.start_ns)
        .min()
        .unwrap_or_default();
    let end = detail
        .spans
        .iter()
        .map(|span| span.start_ns.saturating_add(span.duration_ns))
        .max()
        .unwrap_or(start);
    let extent = end.saturating_sub(start).max(1);
    let root = detail
        .spans
        .iter()
        .find(|span| span.parent.is_empty() && span.name == "compile");
    let root_duration = root.map_or_else(
        || "Root not visible".to_owned(),
        |span| ms(span.duration_ns),
    );
    let skew = root.is_some_and(|span| {
        start < span.start_ns || end > span.start_ns.saturating_add(span.duration_ns)
    });
    view! {
        <article>
            <h3>"Request "{detail.id}</h3>
            <p>"Client elapsed: "{root_duration}" · observed envelope: "{ms(extent)}</p>
            <p class=styles::muted>"Blue: client · purple: scheduler · green: worker · red: error. Spans overlap; do not sum their durations."</p>
            {detail.truncated.then(|| view!{<p class=styles::warning>"Span limit reached."</p>})}
            {skew.then(|| view!{<p class=styles::warning>"Spans extend outside the client interval: clock skew or asynchronous completion."</p>})}
            <table><thead><tr><th>"Host / phase"</th><th>"Elapsed"</th><th>"Timeline"</th></tr></thead>
                <tbody>{detail.spans.into_iter().map(|span| span_row(span,start,extent,selected,lookup)).collect_view()}</tbody>
            </table>
        </article>
    }
}

#[component]
fn LiveRequests(
    data: super::DashboardSource,
    lookup: RwSignal<String>,
    selected: RwSignal<String>,
) -> impl IntoView {
    let report = data.project(super::Projection::Telemetry, |data| {
        data.and_then(|data| data.telemetry.as_ref())
            .and_then(|telemetry| telemetry.live_traces.clone())
    });
    let rows = Memo::new(move |_| {
        report.with(|report| {
            report.as_ref().map_or_default(|report| {
                report
                    .rows
                    .iter()
                    .cloned()
                    .map(|row| (row.request.trace.hex_id(), row))
                    .collect::<std::collections::BTreeMap<_, _>>()
            })
        })
    });
    let keys = Memo::new(move |_| rows.with(|rows| rows.keys().cloned().collect::<Vec<_>>()));
    view! {
        <h3>"Active client requests"</h3>
        <p class=styles::muted>{move || report.with(|report| report.as_ref().map_or_else(|| "No live observation available".into(), |report| format!("{} reported active; {} displayed. Snapshots expire after 10 s.",report.active,report.rows.len())))}</p>
        <table><thead><tr><th>"Host"</th><th>"Compiler / output"</th><th>"Phase"</th><th>"Phase elapsed"</th><th>"Request elapsed"</th><th>"Worker"</th><th>"Sample age"</th><th>"Trace"</th></tr></thead>
            <tbody><For each=move || keys.get() key=Clone::clone children=move |id| {
                let key=id.clone();
                let row=Memo::new(move |_| rows.with(|rows| rows.get(&key).cloned()));
                view! {<tr>
                    <td>{move || row.with(|row| row.as_ref().map(|row|row.instance.clone()))}</td>
                    <td>{move || row.with(|row| row.as_ref().map(|row|format!("{} / {}",row.request.compiler,row.request.output)))}</td>
                    <td>{move || row.with(|row| row.as_ref().map(|row|row.request.phase.clone()))}</td>
                    <td>{move || row.with(|row| row.as_ref().map(|row|format!("{} ms",row.request.phase_age_ms)))}</td>
                    <td>{move || row.with(|row| row.as_ref().map(|row|format!("{} ms",row.request.elapsed_ms)))}</td>
                    <td>{move || row.with(|row| row.as_ref().map(|row|row.request.worker.clone()))}</td>
                    <td>{move || row.with(|row| row.as_ref().map(|row|format!("{} ms",row.observation_age_ms)))}</td>
                    <td><button on:click=move |_| {lookup.set(id.clone()); selected.set(id.clone());}>"Inspect"</button>
                        {move || row.with(|row| row.as_ref().and_then(|row|row.request.producer)).map(|producer| {
                            let id=producer.hex_id();
                            view!{<button on:click=move |_| {lookup.set(id.clone()); selected.set(id.clone());}>"Producer"</button>}
                        })}
                    </td>
                </tr>}
            }/></tbody>
        </table>
    }
}

#[component]
pub(super) fn TracePanel(data: super::DashboardSource) -> impl IntoView {
    let filters = RwSignal::new(TraceSearch::default());
    let applied = RwSignal::new(TraceSearch::default());
    let revision = RwSignal::new(0_u64);
    let selected = RwSignal::new(String::new());
    let lookup = RwSignal::new(String::new());
    let overview = Resource::new(
        move || (applied.get(), revision.get()),
        |(query, _)| load_trace_search(query),
    );
    let detail = Resource::new(
        move || (selected.get(), revision.get()),
        |(id, _)| async move {
            if id.is_empty() {
                Ok(None)
            } else {
                load_trace_detail(id).await.map(Some)
            }
        },
    );
    let jobs = data.project(super::Projection::Jobs, |data| {
        data.and_then(|data| data.snapshot.as_ref())
            .map_or_else(Vec::new, |snapshot| snapshot.jobs.clone())
    });
    let job_rows = super::keyed_index(jobs, |job| &job.id);
    let job_keys = super::index_keys(job_rows);
    view! {
        <section id="traces">
            <h2>"Request traces"</h2>
            <LiveRequests data=data lookup=lookup selected=selected/>
            <h3>"Active distributed jobs"</h3>
            <p class=styles::muted>"Live scheduler state; worker jobs may outlive the client request. Completed spans become available in trace storage."</p>
            <table><thead><tr><th>"Job"</th><th>"Worker"</th><th>"Phase"</th><th>"Phase elapsed"</th><th>"Trace"</th></tr></thead>
                <tbody><For each=move || job_keys.get() key=Clone::clone children=move |id| {
                    let key=id.clone();
                    let row=Memo::new(move |_| job_rows.with(|rows| rows.get(&key).cloned()));
                    view!{<tr><td>{id}</td>
                        <td>{move || row.with(|job| job.as_ref().map(|job| job.worker.clone()))}</td>
                        <td>{move || row.with(|job| job.as_ref().map(|job| job.native_phase.clone().unwrap_or_else(|| job.state.clone())))}</td>
                        <td>{move || row.with(|job| job.as_ref().and_then(|job| job.native_phase_observed_ns).map_or_else(|| "—".into(), ms))}</td>
                        <td>{move || row.with(|job| job.as_ref().and_then(|job| job.trace_id.clone())).map(|id| view!{<button on:click=move |_| {lookup.set(id.clone()); selected.set(id.clone());}>"Inspect"</button>})}</td>
                    </tr>}
                }/></tbody>
            </table>
            <div class=styles::controls>
                <label>"Range"<select on:change=move |ev| filters.update(|f| f.lookback_secs = event_target_value(&ev).parse().unwrap_or(3600))>
                    <option value="300">"5 minutes"</option><option value="3600" selected=true>"1 hour"</option><option value="86400">"1 day"</option><option value="604800">"7 days"</option>
                </select></label>
                <label>"Host"<input on:input=move |ev| filters.update(|f| f.host=event_target_value(&ev))/></label>
                <label>"Compiler"<input on:input=move |ev| filters.update(|f| f.compiler=event_target_value(&ev))/></label>
                <label>"Output"<input on:input=move |ev| filters.update(|f| f.output=event_target_value(&ev))/></label>
                <label>"Outcome"<input on:input=move |ev| filters.update(|f| f.outcome=event_target_value(&ev))/></label>
                <label>"Order"<select on:change=move |ev| filters.update(|f| f.slowest=event_target_value(&ev)=="slow")><option value="slow">"Slowest"</option><option value="recent">"Recent"</option></select></label>
                <button on:click=move |_| { applied.set(filters.get()); revision.update(|n| *n=n.wrapping_add(1)); }>"Search / refresh"</button>
            </div>
            <div class=styles::controls><label>"Trace ID"<input prop:value=move || lookup.get() on:input=move |ev| lookup.set(event_target_value(&ev))/></label>
                <button on:click=move |_| selected.set(lookup.get())>"Open"</button>
            </div>
            <Suspense fallback=|| view!{<p>"Loading traces…"</p>}>
                {move || overview.get().map(|result| match result {
                    Err(error) => view!{<p class=styles::warning>{error.to_string()}</p>}.into_any(),
                    Ok(data) => view!{
                        <p class=styles::muted>"At most 100 completed requests. New spans may take a few seconds to appear."</p>
                        <table><thead><tr><th>"Host"</th><th>"Revision"</th><th>"Compiler"</th><th>"Output"</th><th>"Outcome"</th><th>"Elapsed"</th><th>"Worker"</th><th>"Trace"</th></tr></thead>
                            <tbody>{data.traces.into_iter().map(|row| {
                                let id=row.id.clone();
                                view!{<tr><td>{row.host}</td><td title=row.revision.clone()>{revision_label(&row.revision)}</td><td>{row.compiler}</td><td>{row.output}</td><td>{row.outcome}</td><td>{ms(row.duration_ns)}</td><td>{row.worker}</td>
                                    <td><button on:click=move |_| {lookup.set(id.clone()); selected.set(id.clone());}>"Inspect"</button></td></tr>}
                            }).collect_view()}</tbody>
                        </table>
                        <h3>"Fleet-wide phase latency"</h3>
                        <p class=styles::muted>"Grouped by phase, service, host and version over the selected range. Other filters apply only to the request list."</p>
                        <table><thead><tr><th>"Service"</th><th>"Host"</th><th>"Revision"</th><th>"Phase"</th><th>"Count"</th><th>"p50 ms"</th><th>"p95 ms"</th><th>"p99 ms"</th><th>"Total s"</th></tr></thead>
                            <tbody>{data.phases.into_iter().map(|row| view!{
                                <tr><td>{row.service}</td><td>{row.host}</td><td title=row.version.clone()>{revision_label(&row.version)}</td><td>{row.phase}</td><td>{row.count}</td>
                                <td>{format!("{:.3}",row.p50_ns/1e6)}</td><td>{format!("{:.3}",row.p95_ns/1e6)}</td><td>{format!("{:.3}",row.p99_ns/1e6)}</td><td>{format!("{:.3}",row.total_ns/1e9)}</td></tr>
                            }).collect_view()}</tbody>
                        </table>
                    }.into_any(),
                })}
            </Suspense>
            <Suspense fallback=|| view!{<p>"Loading timeline…"</p>}>
                {move || detail.get().map(|result| match result {
                    Ok(Some(detail)) => view!{<Timeline detail=detail selected=selected lookup=lookup/>}.into_any(),
                    Ok(None) => ().into_any(),
                    Err(error) => view!{<p class=styles::warning>{error.to_string()}</p>}.into_any(),
                })}
            </Suspense>
        </section>
    }
}
