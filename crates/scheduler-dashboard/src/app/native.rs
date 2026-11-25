//! Scheduler tables use stable identities and independently memoized sections.
use super::{Stat, age, age_since, bytes, chart::graph, display_count, rate, timestamp};
use crate::{
    CacheSpace, DashboardData, Job, MetricSeries, NativeService, NativeTelemetry, Totals, Worker,
    styles,
};
use leptos::prelude::*;

#[component]
pub(super) fn NativeStatus(data: Memo<Option<DashboardData>>) -> impl IntoView {
    let snapshot =
        Memo::new(move |_| data.with(|data| data.as_ref().and_then(|data| data.snapshot.clone())));
    let sampled_at =
        Memo::new(move |_| data.with(|data| data.as_ref().and_then(|data| data.sampled_at)));
    let totals = Memo::new(move |_| {
        snapshot.with(|snapshot| snapshot.as_ref().map(|snapshot| snapshot.totals.clone()))
    });
    let history = Memo::new(move |_| {
        data.with(|data| {
            data.as_ref()
                .map_or_else(Vec::new, |data| data.history.clone())
        })
    });
    let workers = Memo::new(move |_| {
        snapshot.with(|snapshot| {
            snapshot
                .as_ref()
                .map_or_else(Vec::new, |snapshot| snapshot.workers.clone())
        })
    });
    let jobs = Memo::new(move |_| {
        snapshot.with(|snapshot| {
            snapshot
                .as_ref()
                .map_or_else(Vec::new, |snapshot| snapshot.jobs.clone())
        })
    });
    let topology = Memo::new(move |_| {
        snapshot.with(|snapshot| {
            snapshot
                .as_ref()
                .map_or_else(crate::NetworkGraph::default, |snapshot| {
                    snapshot.topology.clone()
                })
        })
    });
    let telemetry =
        Memo::new(move |_| data.with(|data| data.as_ref().and_then(|data| data.telemetry.clone())));
    view! {
        <div class=styles::subhead>
            {move || totals.with(|totals| totals.as_ref().map(|totals| view! {
                <span class=if totals.draining || totals.workers == 0 {styles::warning} else {styles::healthy}>
                    {if totals.draining {"DRAINING"} else if totals.workers == 0 {"NO WORKERS"} else {"ACCEPTING WORK"}}
                </span>
            }))}
            <span class=styles::muted>{move || timestamp(sampled_at.get())}</span>
        </div>
        {move || data.with(|data| data.as_ref().and_then(|data| data.error.clone())).map(|error| view!{<p class=styles::warning>{error}</p>})}
        {move || totals.get().map(|totals| view! {
            <div class=styles::stats>
                <Stat label="Workers" value=totals.workers.to_string()/>
                <Stat label="CPU capacity" value=format!("{:.1}", totals.cpu_capacity)/>
                <Stat label="Assigned / limit" value=format!("{} / {}", totals.assigned, totals.max_jobs)/>
                <Stat label="Assigning RPCs" value=totals.assigning.to_string()/>
                <Stat label="Native executing" value=totals.compiler_active.to_string()/>
                <Stat label="Compiler demand" value=totals.compiler_demand.to_string()/>
                <Stat label="Available admissions" value=totals.available.to_string()/>
                <Stat label="Allocated job IDs" value=totals.allocated_ids.to_string()/>
            </div>
        })}
        <section>
            <h2>"Scheduler activity"</h2>
            {move || {
                type Field = (&'static str, fn(&Totals) -> usize);
                let fields: [Field; 4] = [("Assigned", |t| t.assigned), ("Compiler demand", |t| t.compiler_demand), ("Native executing", |t| t.compiler_active), ("Available", |t| t.available)];
                let series = history.with(|samples| fields.into_iter().map(|(label, field)| MetricSeries {
                    key: label.into(), label: label.into(), points: samples.iter().map(|sample| (display_count(sample.unix_secs), Some(display_count(u64::try_from(field(&sample.totals)).unwrap_or(u64::MAX))))).collect()
                }).collect::<Vec<_>>());
                graph(series, "jobs", 2)
            }}
        </section>
        <WorkerTable workers=workers sampled_at=sampled_at/>
        <JobTable jobs=jobs sampled_at=sampled_at/>
        <CasPanel telemetry=telemetry/>
        <super::topology::Topology graph=topology/>
        <NetworkPanel telemetry=telemetry/>
    }
}

#[component]
fn CasPanel(telemetry: Memo<Option<NativeTelemetry>>) -> impl IntoView {
    let cache = Memo::new(move |_| {
        telemetry.with(|telemetry| {
            telemetry
                .as_ref()
                .map(|telemetry| (telemetry.cache.clone(), telemetry.cache_error.clone()))
        })
    });
    let service = Memo::new(move |_| {
        telemetry.with(|value| {
            value
                .as_ref()
                .map(|value| (value.service, value.service_error.clone()))
        })
    });
    let space = Memo::new(move |_| {
        telemetry.with(|value| {
            value
                .as_ref()
                .map(|value| (value.space, value.space_error.clone()))
        })
    });
    view! {
        <section id="cas"><h2>"Scheduler CAS"</h2>
            <p class=styles::muted>{move || telemetry.with(|value| value.as_ref().map_or_else(|| "No native telemetry yet".into(), |value| timestamp(Some(value.sampled_at))))}</p>
            {move || cache.get().map(|(cache,error)| view! {
                {error.map(|error| view!{<p class=styles::warning>{error}</p>})}
                {cache.map_or_else(|| view!{<p class=styles::muted>"No CAS snapshot available."</p>}.into_any(), |cache| view!{
                    <div class=styles::stats>
                        <Stat label="Actions" value=cache.actions.to_string()/><Stat label="Results" value=cache.results.to_string()/><Stat label="Trees" value=cache.trees.to_string()/><Stat label="Blobs" value=cache.blobs.to_string()/><Stat label="Logical live bytes" value=bytes(cache.logical_bytes)/><Stat label="GC pending bytes" value=bytes(cache.pending_gc_bytes)/><Stat label="GC pending blobs" value=cache.pending_gc_blobs.to_string()/>
                    </div>
                }.into_any())}
            })}
            <h3>"Filesystem and resident budget"</h3>
            {move || space.get().map(|(space,error)|view!{
                {error.map(|error|view!{<p class=styles::warning>{error}</p>})}
                {space.map(|space| {
                    let live = cache.with(|value| value.as_ref().and_then(|(cache,error)| error.is_none().then_some(cache.as_ref()).flatten().map(|cache|cache.logical_bytes.saturating_add(cache.pending_gc_bytes))));
                    view!{<SpaceStatus space=space live=live/>}
                })}
            })}
            <h3>"Native service capacity"</h3>
            {move || service.get().map(|(service,error)|view!{
                {error.map(|error|view!{<p class=styles::warning>{error}</p>})}
                {service.map(|service|view!{<ServiceStatus service=service/>})}
            })}
        </section>
    }
}

#[component]
fn NetworkPanel(telemetry: Memo<Option<NativeTelemetry>>) -> impl IntoView {
    let network = Memo::new(move |_| {
        telemetry.with(|telemetry| {
            telemetry.as_ref().map(|telemetry| {
                (
                    telemetry.network.clone(),
                    telemetry.shared_capacity.clone(),
                    telemetry.independent_capacity.clone(),
                )
            })
        })
    });
    view! {
        <section id="network"><h2>"Native transport"</h2>
            <p class=styles::muted>"Effective HTTP-body throughput estimates, not physical link rates."</p>
            {move || network.get().map(|(peers,groups,independent)| view!{
                <div class=styles::tablewrap><table><thead><tr><th>"Peer"</th><th>"Direction"</th><th>"Observed"</th><th>"Isolated"</th><th>"Wire / logical"</th><th>"Remaining"</th><th>"Body bytes"</th></tr></thead><tbody>
                    {peers.into_iter().map(|peer| view!{
                        <tr><td>{peer.peer}</td><td>{peer.direction}</td><td>{rate(peer.observed_bytes_per_second)}</td><td>{rate(peer.isolated_bytes_per_second)}</td><td>{format!("{:.1}%", display_count(peer.wire_per_mille) / 10.0)}</td><td>{bytes(peer.remaining_bytes)}</td><td>{bytes(peer.body_bytes)}</td></tr>
                    }).collect_view()}
                </tbody></table></div>
                <h3>"Shared capacity observations"</h3>
                <div class=styles::tablewrap><table><thead><tr><th>"Direction"</th><th>"Peers"</th><th>"Effective capacity"</th></tr></thead><tbody>
                    {groups.into_iter().map(|group| view!{<tr><td>{group.direction}</td><td>{group.peers}</td><td>{rate(group.bytes_per_second)}</td></tr>}).collect_view()}
                </tbody></table></div>
                <h3>"Concurrent capacity observations"</h3>
                <p class=styles::muted>"Peers that sustained their isolated rates together at the observed load."</p>
                <div class=styles::tablewrap><table><thead><tr><th>"Direction"</th><th>"Concurrent peer rates"</th></tr></thead><tbody>
                    {independent.into_iter().map(|group| view!{<tr><td>{group.direction}</td><td>{group.rates.into_iter().map(|(peer,value)| format!("{peer}: {}",rate(value))).collect::<Vec<_>>().join(" · ")}</td></tr>}).collect_view()}
                </tbody></table></div>
            })}
        </section>
    }
}

#[component]
fn WorkerTable(workers: Memo<Vec<Worker>>, sampled_at: Memo<Option<u64>>) -> impl IntoView {
    let indexed = super::keyed_index(workers, |worker| &worker.id);
    let keys = super::index_keys(indexed);
    view! {
        <section id="workers"><h2>"Workers"</h2>
            <div class=styles::tablewrap><table><thead><tr>
                <th>"Worker"</th><th>"Heartbeat"</th><th>"CPU"</th><th>"Assigned"</th><th>"Demand / limit"</th><th>"Free"</th><th>"Executing / slots"</th><th>"Native queue"</th><th>"Pipeline"</th><th>"Input backlog"</th><th>"Observed / estimated service"</th>
            </tr></thead><tbody>
                <For each=move || keys.get() key=Clone::clone children=move |key| {
                    let worker = Memo::new(move |_| indexed.with(|workers| workers.get(&key).cloned()));
                    view!{<tr>{move || worker.get().map(|worker| view!{<WorkerCells worker=worker sampled_at=sampled_at/>})}</tr>}
                }/>
            </tbody></table></div>
            {move || workers.with(Vec::is_empty).then(|| view!{<p class=styles::muted>"No active workers"</p>})}
        </section>
    }
}

#[component]
fn WorkerCells(worker: Worker, sampled_at: Memo<Option<u64>>) -> impl IntoView {
    let (execution, queue, phases, remaining, timing) = worker.native.as_ref().map_or_else(
        || ("—".to_owned(), "Archive".to_owned(), "—".to_owned(), "—".to_owned(), "—".to_owned()),
        |native| (
            format!("{} / {}", native.compiler_active, native.compiler_slots),
            format!("{} / {}", native.reservations, native.capacity),
            native.phases.iter().map(|(phase,count)| format!("{phase}: {count}")).collect::<Vec<_>>().join(" · "),
            bytes(native.remaining_input_bytes),
            format!("{} exec · {} in · {} out · rev {} · {} staging / {} publication slots · {} output samples · residency {}",
                if native.execution_ns == 0 { "unobserved".into() } else { age(std::time::Duration::from_nanos(native.execution_ns).as_secs_f64()) },
                rate(native.input_bytes_per_second),rate(native.output_bytes_per_second),native.timing_revision,
                native.staging_slots,native.publication_slots,native.output_observations,
                if native.residency_reported {"reported"} else {"unknown"}),
        ));
    view! {
        <td><b>{worker.name}</b><small>{worker.id}</small><small>{if worker.archive_available.is_some() {"Archive enabled"} else {"Native only"}}</small></td>
        <td>
            <span class=move || if sampled_at.get().is_some_and(|now| now.saturating_mul(1000).saturating_sub(worker.heartbeat_at_ms)>15_000) {styles::warning} else {styles::healthy}>
                {move || age_since(sampled_at.get(), worker.heartbeat_at_ms)}
            </span>
            {worker.last_error_at_ms.map(|error| view!{<small class=styles::warning>"Last error: "{move || age_since(sampled_at.get(), error)}" ago"</small>})}
        </td>
        <td>{format!("{:.1}",worker.cpu_capacity)}</td><td>{worker.assigned}" ("{worker.assigning}" assigning)"</td>
        <td>{worker.compiler_demand}" / "{worker.max_jobs}</td><td>{worker.available}<small>{format!("Archive: {} · Native: {}",worker.archive_available.map_or_else(||"—".into(),|value|value.to_string()),worker.native_available.map_or_else(||"—".into(),|value|value.to_string()))}</small></td>
        <td>{execution}</td><td>{queue}</td><td>{phases}</td><td>{remaining}</td><td>{timing}</td>
    }
}

const PAGE_SIZE: usize = 100;

#[component]
fn JobTable(jobs: Memo<Vec<Job>>, sampled_at: Memo<Option<u64>>) -> impl IntoView {
    let filter = RwSignal::new(String::new());
    let page = RwSignal::new(0_usize);
    let indexed = super::keyed_index(jobs, |job| &job.id);
    let matching = Memo::new(move |_| {
        let filter = filter.get().to_lowercase();
        jobs.with(|jobs| {
            jobs.iter()
                .filter(|job| {
                    filter.is_empty()
                        || [&job.id, &job.worker, &job.worker_id, &job.state]
                            .iter()
                            .any(|value| value.to_lowercase().contains(&filter))
                        || job
                            .native_phase
                            .as_ref()
                            .is_some_and(|phase| phase.to_lowercase().contains(&filter))
                })
                .map(|job| job.id.clone())
                .collect::<Vec<_>>()
        })
    });
    let pages = Memo::new(move |_| matching.with(|jobs| jobs.len().div_ceil(PAGE_SIZE).max(1)));
    let current = Memo::new(move |_| page.get().min(pages.get().saturating_sub(1)));
    let visible = Memo::new(move |_| {
        matching.with(|keys| {
            keys.iter()
                .skip(current.get() * PAGE_SIZE)
                .take(PAGE_SIZE)
                .cloned()
                .collect::<Vec<_>>()
        })
    });
    view! {
        <section id="jobs"><h2>"Active jobs"</h2>
            <div class=styles::controls>
                <label>"Filter" <input type="search" placeholder="Job, worker or phase" prop:value=move || filter.get() on:input=move |event| {filter.set(event_target_value(&event)); page.set(0);}/></label>
                <button disabled=move || current.get() == 0 on:click=move |_| page.set(current.get().saturating_sub(1))>"Previous"</button>
                <button disabled=move || current.get()+1 >= pages.get() on:click=move |_| page.set(current.get()+1)>"Next"</button>
                <span>{move || format!("Page {} / {} · {} matching / {} jobs",current.get()+1,pages.get(),matching.with(Vec::len),jobs.with(Vec::len))}</span>
            </div>
            <div class=styles::tablewrap><table><thead><tr><th>"Job"</th><th>"Worker"</th><th>"State"</th><th>"Native phase"</th><th>"Age"</th><th>"Scheduler state age"</th><th>"Input remaining"</th><th>"Predicted completion (at assignment)"</th></tr></thead><tbody>
                <For each=move || visible.get() key=Clone::clone children=move |key| {
                    let job = Memo::new(move |_| indexed.with(|jobs| jobs.get(&key).cloned()));
                    view!{<tr>{move || job.get().map(|job| view!{<JobCells job=job sampled_at=sampled_at/>})}</tr>}
                }/>
            </tbody></table></div>
        </section>
    }
}

#[component]
fn JobCells(job: Job, sampled_at: Memo<Option<u64>>) -> impl IntoView {
    view! {
        <td>{job.id}</td><td>{job.worker}<small>{job.worker_id}</small></td><td>{job.state}</td><td>{job.native_phase.unwrap_or_else(|| "—".into())}{job.native_phase_observed_ns.map(|ns|view!{<small>{age(std::time::Duration::from_nanos(ns).as_secs_f64())}" at observation"</small>})}</td>
        <td>{move || job.assigned_at_ms.map_or_else(|| "—".into(), |then| age_since(sampled_at.get(),then))}</td><td>{move || job.state_since_ms.map_or_else(|| "—".into(), |then| age_since(sampled_at.get(),then))}</td>
        <td>{job.remaining_input_bytes.map_or_else(|| "—".into(), bytes)}{job.remaining_input_blobs.map(|blobs| format!(" / {blobs} blobs"))}</td>
        <td>{job.predicted_completion_secs.map_or_else(|| "—".into(), age)}</td>
    }
}

#[component]
fn SpaceStatus(space: CacheSpace, live: Option<u64>) -> impl IntoView {
    let physical_headroom = space
        .min_available
        .zip(space.reserved)
        .map(|(minimum, reserved)| {
            space
                .available
                .saturating_sub(minimum)
                .saturating_sub(reserved)
        });
    let resident_headroom = space
        .max_resident
        .zip(live)
        .zip(space.reserved)
        .map(|((maximum, live), reserved)| maximum.saturating_sub(live).saturating_sub(reserved));
    let fmt = |value: Option<u64>| value.map_or_else(|| "—".into(), bytes);
    view! {
        <div class=styles::stats>
            <Stat label="Filesystem free" value=bytes(space.available)/>
            <Stat label="Free minimum / target" value=format!("{} / {}",fmt(space.min_available),fmt(space.target_available))/>
            <Stat label="Staging reserved" value=fmt(space.reserved)/>
            <Stat label="Resident logical / limit" value=format!("{} / {}",fmt(live),fmt(space.max_resident))/>
            <Stat label="Resident target" value=fmt(space.target_resident)/>
            <Stat label="Physical headroom estimate" value=fmt(physical_headroom)/>
            <Stat label="Resident headroom estimate" value=fmt(resident_headroom)/>
        </div>
        {(space.min_available.is_some() && space.reserved.is_none()).then(||view!{<p class=styles::muted>"Space admission or reclamation in progress; reservation observation unavailable."</p>})}
        <p class=styles::muted>"Physical filesystem free space and uncompressed resident bytes are different quantities. Headroom estimates exclude prospective reclamation."</p>
    }
}

#[component]
fn ServiceStatus(service: NativeService) -> impl IntoView {
    view! {
        <div class=styles::stats>
            <Stat label="Registered tickets / limit" value=format!("{} / {}",service.tickets.map_or_else(||"—".into(),|tickets|tickets.registered.to_string()),service.max_sessions)/>
            <Stat label="Upload slots" value=format!("{} / {}",service.active_uploads,service.max_uploads)/>
            <Stat label="Manifest cache" value=service.manifests.map_or_else(||"—".into(),|manifest| format!("{} / {} · {} entries",bytes(manifest.bytes as u64),bytes(service.manifest_budget_bytes as u64),manifest.entries))/>
            <Stat label="Recovery queued" value=service.recovery.map_or_else(||"—".into(),|queue|format!("{} · {}",queue.queued,bytes(queue.queued_bytes as u64))) />
            <Stat label="Recovery ready / cooldown" value=service.recovery.map_or_else(||"—".into(),|queue|format!("{} / {}",queue.ready,queue.cooldown))/>
        </div>
        {service.tickets.map(|tickets|view!{
            <div class=styles::stats>
                <Stat label="Action / tree tickets" value=format!("{} / {}",tickets.action,tickets.tree)/>
                <Stat label="Pending / publishing" value=format!("{} / {}",tickets.pending,tickets.publishing)/>
                <Stat label="Ready / failed" value=format!("{} / {}",tickets.ready,tickets.failed)/>
                <Stat label="Expired (not reaped)" value=tickets.expired.to_string()/>
                <Stat label="Unobserved ticket phases" value=tickets.busy.to_string()/>
            </div>
        })}
        {service.tickets.is_none().then(||view!{<p class=styles::muted>"Ticket map busy; count unavailable in this sample."</p>})}
    }
}
