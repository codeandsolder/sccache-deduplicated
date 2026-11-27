//! Scheduler tables use stable identities and independently memoized sections.
use super::{
    DashboardSource, Projection, Stat, Tab, age, age_since, bytes, chart::HistoryChart,
    display_count, rate, timestamp,
};
use crate::{
    AdmissionCounts, CacheSpace, Job, MetricSeries, NativeService, NativeTelemetry, Sample, Totals,
    Worker, styles,
};
use leptos::prelude::*;

#[component]
pub(super) fn NativeStatus(data: DashboardSource, tab: RwSignal<Tab>) -> impl IntoView {
    let job_controls = JobControls::new();
    let selected_host = RwSignal::new(String::new());
    let sampled_at = data.project(Projection::Clock, |data| {
        data.and_then(|data| data.sampled_at)
    });
    let totals = data.project(Projection::Totals, |data| {
        data.and_then(|data| data.snapshot.as_ref())
            .map(|snapshot| snapshot.totals.clone())
    });
    let history = data.project(Projection::History, |data| {
        data.map_or_else(Vec::new, |data| data.history.clone())
    });
    let workers = data.project(Projection::Workers, |data| {
        data.and_then(|data| data.snapshot.as_ref())
            .map_or_else(Vec::new, |snapshot| snapshot.workers.clone())
    });
    let jobs = data.project(Projection::Jobs, |data| {
        data.and_then(|data| data.snapshot.as_ref())
            .map_or_else(Vec::new, |snapshot| snapshot.jobs.clone())
    });
    let topology = data.project(Projection::Topology, |data| {
        data.and_then(|data| data.snapshot.as_ref())
            .map_or_else(crate::NetworkGraph::default, |snapshot| {
                snapshot.topology.clone()
            })
    });
    let telemetry = data.project(Projection::Telemetry, |data| {
        data.and_then(|data| data.telemetry.clone())
    });
    let error = data.project(Projection::Error, |data| {
        data.and_then(|data| data.error.clone())
    });
    view! {
        <div class=styles::subhead>
            {move || totals.with(|totals| totals.as_ref().map(|totals| view! {
                <span class=if totals.draining || totals.workers == 0 {styles::warning} else {styles::healthy}>
                    {if totals.draining {"DRAINING"} else if totals.workers == 0 {"NO WORKERS"} else {"ACCEPTING WORK"}}
                </span>
            }))}
            <span class=styles::muted>{move || timestamp(sampled_at.get())}</span>
        </div>
        {move || error.get().map(|error| view!{<p class=styles::warning>{error}</p>})}
        {move || match tab.get() {
            Tab::Overview => view! {<Overview totals=totals history=history/>}.into_any(),
            Tab::Workers => view! {<WorkerTable workers=workers sampled_at=sampled_at/>}.into_any(),
            Tab::Jobs => view! {<JobTable jobs=jobs sampled_at=sampled_at controls=job_controls/>}.into_any(),
            Tab::Cas => view! {<CasPanel telemetry=telemetry/>}.into_any(),
            Tab::Topology => view! {<super::topology::Topology graph=topology selected=selected_host/>}.into_any(),
            Tab::CacheHits => view! {<AdmissionPanel telemetry=telemetry history=history/>}.into_any(),
            Tab::CacheAnalytics => view! {<super::analytics::CacheAnalytics telemetry=telemetry workers=workers/>}.into_any(),
            Tab::Network => view! {<NetworkPanel telemetry=telemetry/>}.into_any(),
            Tab::Fleet => ().into_any(),
        }}
    }.into_any()
}

#[component]
fn Overview(totals: Memo<Option<Totals>>, history: Memo<Vec<Sample>>) -> impl IntoView {
    type Field = (&'static str, fn(&Totals) -> String);
    let fields: [Field; 8] = [
        ("Workers", |totals| totals.workers.to_string()),
        ("CPU capacity", |totals| {
            format!("{:.1}", totals.cpu_capacity)
        }),
        ("Assigned / limit", |totals| {
            format!("{} / {}", totals.assigned, totals.max_jobs)
        }),
        ("Assigning RPCs", |totals| totals.assigning.to_string()),
        ("Native executing", |totals| {
            totals.compiler_active.to_string()
        }),
        ("Compiler demand", |totals| {
            totals.compiler_demand.to_string()
        }),
        ("Available admissions", |totals| {
            totals.available.to_string()
        }),
        ("Allocated job IDs", |totals| {
            totals.allocated_ids.to_string()
        }),
    ];
    let activity = Memo::new(move |_| {
        type ActivityField = (&'static str, fn(&Totals) -> usize);
        let fields: [ActivityField; 4] = [
            ("Assigned", |t| t.assigned),
            ("Compiler demand", |t| t.compiler_demand),
            ("Native executing", |t| t.compiler_active),
            ("Available", |t| t.available),
        ];
        history.with(|samples| {
            fields
                .into_iter()
                .map(|(label, field)| MetricSeries {
                    key: label.into(),
                    label: label.into(),
                    points: samples
                        .iter()
                        .map(|sample| {
                            (
                                display_count(sample.unix_secs),
                                Some(display_count(
                                    u64::try_from(field(&sample.totals)).unwrap_or(u64::MAX),
                                )),
                            )
                        })
                        .collect(),
                })
                .collect::<Vec<_>>()
        })
    });
    let unit = Memo::new(|_| "jobs".into());
    let step = Signal::derive(|| 2_u64);
    view! {
        <div class=styles::stats>
            {fields.into_iter().map(|(label, field)| view! {
                <div class=styles::stat><small>{label}</small><strong>{move || totals.with(|totals| totals.as_ref().map_or_else(|| "—".into(), field))}</strong></div>
            }).collect_view()}
        </div>
        <section>
            <h2>"Scheduler activity"</h2>
            <HistoryChart series=activity unit=unit step=step/>
        </section>
    }.into_any()
}

fn admission_window(
    history: &[Sample],
    now: u64,
    current: AdmissionCounts,
    seconds: u64,
) -> Option<(u64, AdmissionCounts)> {
    let start = now.checked_sub(seconds)?;
    let baseline = history
        .iter()
        .rev()
        .find(|sample| sample.unix_secs <= start && sample.admission.is_some())?;
    let elapsed = now.checked_sub(baseline.unix_secs)?;
    // A long gap is not a measurement of the requested rolling window.
    if elapsed > seconds + 10 {
        return None;
    }
    Some((elapsed, current.since(baseline.admission?)?))
}

fn hit_rate_value(counts: AdmissionCounts) -> Option<f64> {
    let total = display_count(counts.hits) + display_count(counts.misses);
    (total > 0.0).then(|| 100.0 * display_count(counts.hits) / total)
}

fn hit_rate(counts: AdmissionCounts) -> String {
    hit_rate_value(counts).map_or_else(|| "—".into(), |rate| format!("{rate:.1}%"))
}

fn admission_history(history: &[Sample]) -> Vec<MetricSeries> {
    [(60, "1-minute hit rate"), (300, "5-minute hit rate")]
        .into_iter()
        .map(|(window, label)| {
            let points = history
                .iter()
                .enumerate()
                .map(|(index, sample)| {
                    let ratio = sample
                        .admission
                        .and_then(|counts| {
                            admission_window(&history[..index], sample.unix_secs, counts, window)
                        })
                        .and_then(|(_, counts)| hit_rate_value(counts));
                    (display_count(sample.unix_secs), ratio)
                })
                .collect();
            MetricSeries {
                key: label.into(),
                label: label.into(),
                points,
            }
        })
        .collect()
}

#[component]
fn AdmissionPanel(
    telemetry: Memo<Option<NativeTelemetry>>,
    history: Memo<Vec<Sample>>,
) -> impl IntoView {
    let latest = Memo::new(move |_| {
        telemetry.with(|value| {
            let value = value.as_ref()?;
            Some((value.sampled_at, value.admission?))
        })
    });
    let series = Memo::new(move |_| history.with(|history| admission_history(history)));
    let unit = Memo::new(|_| "percent".into());
    let step = Signal::derive(|| 2_u64);
    view! {
        <section id="admission"><h2>"Native scheduler cache admissions"</h2>
            <p class=styles::muted>"Live scheduler counters, independent of the external metrics store. Misses are admitted reuse-mode compilations, not every unsuccessful lookup or retry. Forced refresh, in-flight, missing-input, busy and error responses are excluded from the hit-rate denominator. A hit means a result was admitted, not necessarily delivered to the client."</p>
            <div class=styles::tablewrap><table><thead><tr>
                <th>"Window"</th><th>"Hit rate"</th><th>"Hits"</th><th>"Misses"</th><th>"Refreshes"</th><th>"In flight"</th><th>"Missing inputs"</th><th>"Busy"</th><th>"Errors"</th>
            </tr></thead><tbody>
                {move || {
                    let rows = [("1 minute",Some(60)), ("5 minutes",Some(300)), ("15 minutes",Some(900)), ("Since scheduler start",None)];
                    rows.into_iter().map(|(name,seconds)| {
                        let values = latest.get().and_then(|(now,current)| {
                            seconds.map_or(Some((0,current)), |seconds| history.with(|history| admission_window(history,now,current,seconds)))
                        });
                        view! {
                            <tr><td>{name}<small>{values.filter(|(elapsed,_)| *elapsed != 0).map(|(elapsed,_)| format!("{elapsed} s observed"))}</small></td>
                            {values.map_or_else(
                                || view! {<td colspan="8" class=styles::muted>"Collecting samples"</td>}.into_any(),
                                |(_,counts)| view! {
                                    <td><b>{hit_rate(counts)}</b></td><td>{counts.hits}</td><td>{counts.misses}</td><td>{counts.refreshes}</td>
                                    <td>{counts.in_flight}</td><td>{counts.missing_inputs}</td><td>{counts.busy}</td><td>{counts.errors}</td>
                                }.into_any()
                            )}
                            </tr>
                        }
                    }).collect_view()
                }}
            </tbody></table></div>
            <h3>"Rolling native admission hit rate"</h3>
            <HistoryChart series=series unit=unit step=step/>
        </section>
    }.into_any()
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    #[test]
    fn rolling_window_requires_coverage_and_monotonic_counters() {
        let counts = AdmissionCounts {
            hits: 9,
            misses: 1,
            ..Default::default()
        };
        let history = [Sample {
            unix_secs: 99,
            totals: Totals::default(),
            admission: Some(AdmissionCounts {
                hits: 4,
                ..Default::default()
            }),
        }];
        let (elapsed, delta) = admission_window(&history, 400, counts, 300).unwrap();
        assert_eq!(elapsed, 301);
        assert_eq!(delta.hits, 5);
        assert_eq!(delta.misses, 1);
        assert_eq!(hit_rate(delta), "83.3%");
        assert!(admission_window(&history, 400, counts, 900).is_none());
        assert!(admission_window(&history, 420, counts, 300).is_none());
        assert!(admission_window(&history, 400, AdmissionCounts::default(), 300).is_none());
        assert_eq!(hit_rate(AdmissionCounts::default()), "—");
    }

    #[test]
    fn history_uses_deltas_and_keeps_idle_gaps() {
        let sample = |unix_secs, hits, misses| Sample {
            unix_secs,
            totals: Totals::default(),
            admission: Some(AdmissionCounts {
                hits,
                misses,
                ..Default::default()
            }),
        };
        let history = [
            sample(0, 0, 0),
            sample(60, 3, 1),
            sample(120, 3, 1),
            sample(300, 8, 2),
        ];
        let series = admission_history(&history);
        assert!(series[0].points[0].1.is_none());
        assert!(
            series[0].points[1]
                .1
                .is_some_and(|rate| (rate - 75.0).abs() < f64::EPSILON)
        );
        assert!(series[0].points[2].1.is_none());
        assert!(
            series[1].points[3]
                .1
                .is_some_and(|rate| (rate - 80.0).abs() < f64::EPSILON)
        );
    }

    #[test]
    fn worker_label_reports_both_capabilities_independently() {
        assert_eq!(execution_protocols(false, true), "CAS execution");
        assert_eq!(execution_protocols(true, false), "Legacy archive");
        assert_eq!(execution_protocols(true, true), "CAS + legacy archive");
        assert_eq!(execution_protocols(false, false), "No execution protocol");
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
    }.into_any()
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
    }.into_any()
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
                    view!{<tr><WorkerCells worker=worker sampled_at=sampled_at/></tr>}
                }/>
            </tbody></table></div>
            {move || workers.with(Vec::is_empty).then(|| view!{<p class=styles::muted>"No active workers"</p>})}
        </section>
    }.into_any()
}

const fn execution_protocols(archive: bool, native: bool) -> &'static str {
    match (archive, native) {
        (true, true) => "CAS + legacy archive",
        (false, true) => "CAS execution",
        (true, false) => "Legacy archive",
        (false, false) => "No execution protocol",
    }
}

// Keep cell elements alive as the keyed row changes. Reactive text updates
// do not reset table layout, horizontal scroll or the browser's selection.
fn row_text<T, F>(
    row: Memo<Option<T>>,
    format: F,
) -> impl Fn() -> String + Send + Sync + Copy + 'static
where
    T: Send + Sync + 'static,
    F: Fn(&T) -> String + Send + Sync + Copy + 'static,
{
    move || row.with(|value| value.as_ref().map_or_else(String::new, format))
}

fn native_text(
    worker: Memo<Option<Worker>>,
    format: impl Fn(&crate::NativeWorker) -> String + Send + Sync + Copy + 'static,
) -> impl Fn() -> String + Send + Sync + Copy + 'static {
    row_text(worker, move |worker| {
        worker.native.as_ref().map_or_else(|| "—".into(), format)
    })
}

#[component]
fn WorkerCells(worker: Memo<Option<Worker>>, sampled_at: Memo<Option<u64>>) -> impl IntoView {
    let identity = row_text(worker, |worker| worker.id.clone());
    let phases = native_text(worker, |native| {
        native
            .phases
            .iter()
            .map(|(phase, count)| format!("{}: {count}", phase_label(phase)))
            .collect::<Vec<_>>()
            .join(" · ")
    });
    let last_error = row_text(worker, move |worker| {
        worker.last_error_at_ms.map_or_else(String::new, |error| {
            format!("Error: {} ago", age_since(sampled_at.get(), error))
        })
    });
    view! {
        <td><b>{row_text(worker, |worker| worker.name.clone())}</b><small title=identity>{identity}</small>
            <small>{row_text(worker, |worker| execution_protocols(worker.archive_available.is_some(), worker.native_available.is_some()).into())}</small>
        </td>
        <td>
            <span class=move || if worker.with(|worker| worker.as_ref().is_some_and(|worker| sampled_at.get().is_some_and(|now| now.saturating_mul(1000).saturating_sub(worker.heartbeat_at_ms)>15_000))) {styles::warning} else {styles::healthy}>
                {row_text(worker, move |worker| age_since(sampled_at.get(),worker.heartbeat_at_ms))}
            </span>
            <small class=styles::warning title=last_error>{last_error}</small>
        </td>
        <td>{row_text(worker, |worker| format!("{:.1}",worker.cpu_capacity))}</td>
        <td>{row_text(worker, |worker| worker.assigned.to_string())}<small>{row_text(worker, |worker| format!("{} assigning",worker.assigning))}</small></td>
        <td>{row_text(worker, |worker| format!("{} / {}",worker.compiler_demand,worker.max_jobs))}</td>
        <td>{row_text(worker, |worker| worker.available.to_string())}
            <small>{row_text(worker, |worker| format!("Legacy: {}",worker.archive_available.map_or_else(||"—".into(),|value|value.to_string())))}</small>
            <small>{row_text(worker, |worker| format!("CAS: {}",worker.native_available.map_or_else(||"—".into(),|value|value.to_string())))}</small></td>
        <td>{native_text(worker, |native| format!("{} / {}", native.compiler_active, native.compiler_slots))}</td>
        <td>{native_text(worker, |native| format!("{} / {}", native.reservations, native.capacity))}</td>
        <td title=phases><span class=styles::clamped>{phases}</span></td>
        <td>{native_text(worker, |native| bytes(native.remaining_input_bytes))}</td>
        <td>
            {native_text(worker, |native| if native.execution_ns == 0 {"Execution unobserved".into()} else {format!("{} execution", age(std::time::Duration::from_nanos(native.execution_ns).as_secs_f64()))})}
            <small>{native_text(worker, |native| format!("{} in · {} out",rate(native.input_bytes_per_second),rate(native.output_bytes_per_second)))}</small>
            <small>{native_text(worker, |native| format!("{} staging · {} publishing slots",native.staging_slots,native.publication_slots))}</small>
            <small>{native_text(worker, |native| format!("Rev {} · {} output samples",native.timing_revision,native.output_observations))}</small>
            <small>{native_text(worker, |native| if native.residency_reported {"Residency reported".into()} else {"Residency unknown".into()})}</small>
        </td>
    }.into_any()
}

fn phase_label(phase: &str) -> &str {
    match phase {
        "Assigned" => "Assigned",
        "Queued" => "Queued",
        "Staging" => "Staging inputs",
        "Ready" => "Ready to compile",
        "Executing" => "Compiling",
        "AwaitingPublication" => "Waiting to publish",
        "Publishing" => "Publishing outputs",
        "Terminal" => "Finished",
        other => other,
    }
}

const PAGE_SIZE: usize = 100;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum JobSort {
    #[default]
    Oldest,
    Newest,
    InputBacklog,
    Worker,
    Phase,
}

impl JobSort {
    const ALL: [(Self, &'static str, &'static str); 5] = [
        (Self::Oldest, "oldest", "Oldest first"),
        (Self::Newest, "newest", "Newest first"),
        (Self::InputBacklog, "input", "Largest input backlog"),
        (Self::Worker, "worker", "Worker"),
        (Self::Phase, "phase", "Execution phase"),
    ];

    fn value(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(sort, _, _)| *sort == self)
            .map_or("oldest", |(_, value, _)| *value)
    }

    fn from_value(value: &str) -> Self {
        Self::ALL
            .iter()
            .find(|(_, key, _)| *key == value)
            .map_or(Self::Oldest, |(sort, _, _)| *sort)
    }

    fn compare(self, a: &Job, b: &Job) -> std::cmp::Ordering {
        let age = || known_order(a.assigned_at_ms, b.assigned_at_ms, false);
        let order = match self {
            Self::Oldest => age(),
            Self::Newest => known_order(a.assigned_at_ms, b.assigned_at_ms, true),
            Self::InputBacklog => {
                known_order(a.remaining_input_bytes, b.remaining_input_bytes, true)
            }
            Self::Worker => a.worker.cmp(&b.worker).then_with(age),
            Self::Phase => phase_rank(a)
                .cmp(&phase_rank(b))
                .then_with(|| job_phase(a).cmp(job_phase(b)))
                .then_with(age),
        };
        order.then_with(|| a.id.cmp(&b.id))
    }
}

fn known_order(a: Option<u64>, b: Option<u64>, descending: bool) -> std::cmp::Ordering {
    match (a, b) {
        (Some(a), Some(b)) => {
            if descending {
                b.cmp(&a)
            } else {
                a.cmp(&b)
            }
        }
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn phase_rank(job: &Job) -> u8 {
    match job.native_phase.as_deref().unwrap_or(&job.state) {
        "Assigning" | "Assigned" | "Pending" => 0,
        "Queued" => 1,
        "Staging" => 2,
        "Ready" => 3,
        "Executing" | "Started" => 4,
        "AwaitingPublication" => 5,
        "Publishing" => 6,
        "Terminal" | "Complete" => 7,
        _ => u8::MAX,
    }
}

fn job_phase(job: &Job) -> &str {
    job.native_phase
        .as_deref()
        .map_or(job.state.as_str(), phase_label)
}

fn job_matches(job: &Job, terms: &[&str]) -> bool {
    if terms.is_empty() {
        return true;
    }
    // All terms must match, across any combination of fields.
    let mut fields = vec![
        job.id.as_str(),
        job.worker.as_str(),
        job.worker_id.as_str(),
        job.state.as_str(),
        job_phase(job),
    ];
    if let Some(phase) = job.native_phase.as_deref() {
        fields.push(phase);
    }
    if let Some(description) = &job.description {
        fields.extend([
            description.executable.as_str(),
            description.subject.as_deref().unwrap_or_default(),
            description.target.as_deref().unwrap_or_default(),
            description.requester.as_deref().unwrap_or_default(),
        ]);
    }
    let text = fields.join(" ").to_lowercase();
    terms.iter().all(|&term| text.contains(term))
}

fn matching_jobs(jobs: &[Job], query: &str, phase: &str, sort: JobSort) -> Vec<String> {
    let query = query.to_lowercase();
    let terms = query.split_whitespace().collect::<Vec<_>>();
    let mut matching: Vec<_> = jobs
        .iter()
        .filter(|job| (phase.is_empty() || job_phase(job) == phase) && job_matches(job, &terms))
        .collect();
    matching.sort_unstable_by(|a, b| sort.compare(a, b));
    matching.into_iter().map(|job| job.id.clone()).collect()
}

#[derive(Clone, Copy)]
struct JobControls {
    filter: RwSignal<String>,
    phase: RwSignal<String>,
    sort: RwSignal<JobSort>,
    page: RwSignal<usize>,
}

impl JobControls {
    fn new() -> Self {
        Self {
            filter: RwSignal::new(String::new()),
            phase: RwSignal::new(String::new()),
            sort: RwSignal::new(JobSort::Oldest),
            page: RwSignal::new(0),
        }
    }
}

#[component]
fn JobTable(
    jobs: Memo<Vec<Job>>,
    sampled_at: Memo<Option<u64>>,
    controls: JobControls,
) -> impl IntoView {
    let JobControls {
        filter,
        phase,
        sort,
        page,
    } = controls;
    let indexed = super::keyed_index(jobs, |job| &job.id);
    let matching = Memo::new(move |_| {
        jobs.with(|jobs| matching_jobs(jobs, &filter.get(), &phase.get(), sort.get()))
    });
    let phases = Memo::new(move |_| {
        jobs.with(|jobs| {
            let mut counts = std::collections::BTreeMap::<String, usize>::new();
            for job in jobs {
                *counts.entry(job_phase(job).into()).or_default() += 1;
            }
            counts
        })
    });
    let phase_keys = Memo::new(move |_| {
        let mut keys = phases.with(|counts| counts.keys().cloned().collect::<Vec<_>>());
        let selected = phase.get();
        if !selected.is_empty() && !keys.contains(&selected) {
            keys.push(selected);
        }
        keys
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
                <label>"Filter" <input type="search" placeholder="Compiler, crate, target, job, worker or phase" prop:value=move || filter.get() on:input=move |event| {filter.set(event_target_value(&event)); page.set(0);}/></label>
                <label>"Phase"
                    <select prop:value=move || phase.get() on:change=move |event| {phase.set(event_target_value(&event)); page.set(0);}>
                        <option value="">"All phases"</option>
                        <For each=move || phase_keys.get() key=Clone::clone children=move |key| {
                            let name = key.clone();
                            view!{<option value=key>{move || format!("{name} ({})",phases.with(|counts| counts.get(&name).copied().unwrap_or_default()))}</option>}
                        }/>
                    </select>
                </label>
                <label>"Sort"
                    <select prop:value=move || sort.get().value() on:change=move |event| {sort.set(JobSort::from_value(&event_target_value(&event))); page.set(0);}>
                        {JobSort::ALL.into_iter().map(|(_,value,label)| view!{<option value=value>{label}</option>}).collect_view()}
                    </select>
                </label>
                <button disabled=move || current.get() == 0 on:click=move |_| page.set(current.get().saturating_sub(1))>"Previous"</button>
                <button disabled=move || current.get()+1 >= pages.get() on:click=move |_| page.set(current.get()+1)>"Next"</button>
                <span class=styles::page_count>{move || format!("Page {} / {} · {} matching / {} jobs",current.get()+1,pages.get(),matching.with(Vec::len),jobs.with(Vec::len))}</span>
            </div>
            <div class=styles::tablewrap><table><thead><tr><th>"Job"</th><th>"Worker"</th><th>"State"</th><th>"Native phase"</th><th>"Age"</th><th>"Scheduler state age"</th><th>"Input remaining / declared"</th><th>"Predicted completion (at assignment)"</th></tr></thead><tbody>
                <For each=move || visible.get() key=Clone::clone children=move |key| {
                    let job = Memo::new(move |_| indexed.with(|jobs| jobs.get(&key).cloned()));
                    view!{<tr><JobCells job=job sampled_at=sampled_at/></tr>}
                }/>
            </tbody></table></div>
            <p class=styles::muted hidden=move || !matching.with(Vec::is_empty)>{move || if jobs.with(Vec::is_empty) {"No active jobs"} else {"No jobs match the selected filters"}}</p>
        </section>
    }.into_any()
}

fn input_coverage(job: &Job) -> Option<f64> {
    if job.native_phase.as_deref() == Some("Terminal") {
        return None;
    }
    let total = job.description.as_ref()?.input_bytes;
    let remaining = job.remaining_input_bytes?;
    if total == 0 || remaining > total {
        return None;
    }
    Some(100.0 * display_count(total - remaining) / display_count(total))
}

#[component]
fn JobCells(job: Memo<Option<Job>>, sampled_at: Memo<Option<u64>>) -> impl IntoView {
    let title = row_text(job, |job| {
        job.description.as_ref().map_or_else(
            || "Legacy archive job".into(),
            |description| {
                description.subject.as_ref().map_or_else(
                    || description.executable.clone(),
                    |subject| format!("{} · {subject}", description.executable),
                )
            },
        )
    });
    let requester = row_text(job, |job| {
        job.description
            .as_ref()
            .and_then(|description| description.requester.clone())
            .unwrap_or_default()
    });
    let worker_id = row_text(job, |job| job.worker_id.clone());
    view! {
        <td>
            <b class=styles::clamped title=title>{title}</b>
            <small>{row_text(job, |job| job.description.as_ref().map_or_else(String::new, |description| description.target.clone().unwrap_or_else(|| "Target not explicit".into())))}</small>
            <small title=requester>{row_text(job, |job| job.description.as_ref().map_or_else(String::new, |description| description.requester.as_ref().map_or_else(|| "Requester not reported".into(), |id| format!("Client {}", id.chars().take(12).collect::<String>()))))}</small>
            <small>{row_text(job, |job| format!("Job {}",job.id))}</small>
        </td>
        <td>{row_text(job, |job| job.worker.clone())}<small title=worker_id>{worker_id}</small></td>
        <td>{row_text(job, |job| job.state.clone())}</td>
        <td>{row_text(job, |job| job.native_phase.as_deref().map_or_else(|| "—".into(), |phase| phase_label(phase).into()))}
            <small>{row_text(job, |job| job.native_phase_observed_ns.map_or_else(String::new, |ns| format!("{} at observation",age(std::time::Duration::from_nanos(ns).as_secs_f64()))))}</small>
        </td>
        <td>{row_text(job, move |job| job.assigned_at_ms.map_or_else(|| "—".into(), |then| age_since(sampled_at.get(),then)))}</td>
        <td>{row_text(job, move |job| job.state_since_ms.map_or_else(|| "—".into(), |then| age_since(sampled_at.get(),then)))}</td>
        <td>{row_text(job, |job| job.remaining_input_bytes.map_or_else(|| "—".into(), bytes))}
            <small>{row_text(job, |job| job.remaining_input_blobs.map_or_else(String::new, |blobs| format!("{blobs} blobs remaining")))}</small>
            <small>{row_text(job, |job| job.description.as_ref().map_or_else(String::new, |description| format!("{} · {} blobs total", bytes(description.input_bytes), description.input_blobs)))}</small>
            <progress class=styles::input_progress max="100" aria-label="Declared input closure available" hidden=move || job.with(|value| value.as_ref().and_then(input_coverage).is_none()) prop:value=move || job.with(|value| value.as_ref().and_then(input_coverage).unwrap_or_default())/>
        </td>
        <td>{row_text(job, |job| job.predicted_completion_secs.map_or_else(|| "—".into(), age))}</td>
    }.into_any()
}

#[cfg(test)]
mod job_tests {
    use super::*;
    fn job(id: &str, name: &str, phase: &str, remaining: u64) -> Job {
        Job {
            id: id.into(),
            worker: "acer".into(),
            worker_id: "worker-id".into(),
            state: "Started".into(),
            description: Some(crate::JobDescription {
                executable: "rustc".into(),
                subject: Some(name.into()),
                target: Some("x86_64".into()),
                requester: Some("client-id".into()),
                input_bytes: 100,
                input_blobs: 5,
            }),
            native_phase: Some(phase.into()),
            native_phase_observed_ns: None,
            assigned_at_ms: Some(0),
            state_since_ms: None,
            remaining_input_bytes: Some(remaining),
            remaining_input_blobs: None,
            predicted_completion_secs: None,
        }
    }
    #[test]
    fn search_combines_fields_and_sort_preserves_unknowns() {
        let jobs = [
            job("1", "serde", "Staging", 10),
            job("2", "syn", "Executing", 0),
            job("3", "serde", "Staging", 40),
        ];
        assert_eq!(
            matching_jobs(
                &jobs,
                "RUSTC serde acer",
                "Staging inputs",
                JobSort::InputBacklog
            ),
            ["3", "1"]
        );
        assert_eq!(
            matching_jobs(&jobs, "syn compiling", "", JobSort::Newest),
            ["2"]
        );
        assert!(matching_jobs(&jobs, "syn serde", "", JobSort::Oldest).is_empty());
        assert!(
            input_coverage(&jobs[0]).is_some_and(|coverage| (coverage - 90.0).abs() < f64::EPSILON)
        );
        assert_eq!(input_coverage(&job("4", "serde", "Staging", 101)), None);
        assert_eq!(input_coverage(&job("4", "serde", "Terminal", 0)), None);
        let mut unknown = job("4", "serde", "Staging", 0);
        unknown.assigned_at_ms = None;
        unknown.remaining_input_bytes = None;
        assert_eq!(
            matching_jobs(&[unknown.clone(), jobs[0].clone()], "", "", JobSort::Oldest),
            ["1", "4"]
        );
        assert_eq!(
            matching_jobs(&[unknown, jobs[0].clone()], "", "", JobSort::Newest),
            ["1", "4"]
        );
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
