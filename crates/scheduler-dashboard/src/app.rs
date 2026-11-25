#![allow(
    clippy::empty_enum,
    reason = "Leptos component macros generate uninhabited prop-state enums"
)]
#![allow(
    clippy::unused_async,
    reason = "Leptos server-function macro requires an async RPC signature"
)]
use leptos::prelude::*;
#[cfg(feature = "ssr")]
use leptos_meta::MetaTags;
use leptos_meta::{Title, provide_meta_context};

use crate::{DashboardData, MetricsData, MetricsView, TimeRange, styles};

mod chart;
mod native;
#[cfg(target_arch = "wasm32")]
mod sse;
mod topology;

#[server(endpoint = "snapshot")]
async fn snapshot() -> Result<DashboardData, ServerFnError> {
    let state = use_context::<crate::server::DashboardState>()
        .ok_or_else(|| ServerFnError::new("Dashboard unavailable"))?;
    Ok(state.snapshot())
}

#[cfg(feature = "ssr")]
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <link rel="stylesheet" href="/pkg/sccache-dashboard.css"/>
                <leptos::hydration::HydrationScripts options=options/>
                <MetaTags/>
            </head>
            <body><App/></body>
        </html>
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionStatus {
    Connecting,
    Connected,
    #[cfg(target_arch = "wasm32")]
    Reconnecting,
    #[cfg(target_arch = "wasm32")]
    ProtocolError,
    #[cfg(target_arch = "wasm32")]
    Unavailable,
}

impl ConnectionStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Connecting => "Connecting",
            Self::Connected => "Live",
            #[cfg(target_arch = "wasm32")]
            Self::Reconnecting => "Disconnected — reconnecting",
            #[cfg(target_arch = "wasm32")]
            Self::ProtocolError => "Resynchronizing",
            #[cfg(target_arch = "wasm32")]
            Self::Unavailable => "Connection unavailable",
        }
    }
}

#[component]
fn ConnectionIndicator(status: RwSignal<ConnectionStatus>, retry: RwSignal<u64>) -> impl IntoView {
    view! {
        <div class=styles::subhead>
            <span role="status" class=move || if status.get() == ConnectionStatus::Connected { styles::healthy } else { styles::warning }>
                {move || status.get().label()}
            </span>
            <button on:click=move |_| retry.update(|value| *value = value.wrapping_add(1))>"Reconnect"</button>
        </div>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    // The SSR resource is fetched once. After hydration the live stream
    // replaces it atomically; neither history nor snapshots are polled.
    let initial = Resource::new(|| (), |()| snapshot());
    let live = RwSignal::new(None::<DashboardData>);
    let status = RwSignal::new(ConnectionStatus::Connecting);
    let retry = RwSignal::new(0_u64);
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let _ = retry.get();
        sse::connect::<crate::NativeEvent>("/api/events", status, retry, move |event| {
            let mut valid = false;
            live.update(|data| {
                if matches!(&event, crate::NativeEvent::Reset(_)) {
                    *data = Some(DashboardData::default());
                }
                if let Some(data) = data {
                    valid = crate::apply_event(data, event);
                }
            });
            valid
        });
    });
    let data = Memo::new(move |_| live.get().or_else(|| initial.get().and_then(Result::ok)));
    view! {
        <Title text="sccache | Scheduler status"/>
        <header class=styles::top>
            <div><small>"SCCACHE / DISTRIBUTED BUILD"</small><h1>"Scheduler status"</h1></div>
            <nav><a href="#workers">"Workers"</a><a href="#jobs">"Jobs"</a><a href="#cas">"CAS"</a><a href="#topology">"Topology"</a><a href="#network">"Network"</a><a href="#metrics">"Fleet metrics"</a></nav>
        </header>
        <main>
            <ConnectionIndicator status=status retry=retry/>
            <Suspense fallback=|| view! { <p>"Waiting for initial scheduler snapshot…"</p> }>
                <native::NativeStatus data=data/>
            </Suspense>
            <FleetMetrics/>
        </main>
    }
}

#[component]
fn FleetMetrics() -> impl IntoView {
    let view = RwSignal::new(MetricsView::default());
    let data = RwSignal::new(MetricsData::default());
    let clients = RwSignal::new(Vec::<String>::new());
    let status = RwSignal::new(ConnectionStatus::Connecting);
    let retry = RwSignal::new(0_u64);
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let selected = view.get();
        let _ = retry.get();
        data.set(MetricsData {
            view: selected.clone(),
            ..Default::default()
        });
        let Ok(query) = serde_urlencoded::to_string(&selected) else {
            status.set(ConnectionStatus::Unavailable);
            return;
        };
        sse::connect::<crate::MetricsEvent>(
            &format!("/api/metrics/events?{query}"),
            status,
            retry,
            move |event| {
                let mut valid = false;
                data.update(|data| {
                    valid = crate::apply_metrics_event(data, event);
                    if valid && !data.clients.is_empty() {
                        clients.set(data.clients.clone());
                    }
                });
                valid
            },
        );
    });
    let panels = Memo::new(move |_| {
        data.with(|data| {
            data.panels
                .iter()
                .map(|panel| panel.key)
                .collect::<Vec<_>>()
        })
    });
    let panel_data = Memo::new(move |_| {
        data.with(|data| {
            data.panels
                .iter()
                .map(|panel| (panel.key, panel.clone()))
                .collect::<std::collections::BTreeMap<_, _>>()
        })
    });
    let step = Signal::derive(move || data.with(|data| data.view.range.step()));
    view! {
        <section id="metrics"><h2>"Fleet telemetry"</h2>
            <ConnectionIndicator status=status retry=retry/>
            <div class=styles::controls>
                <label>"Range"
                    <select prop:value=move || view.with(|view| view.range.value()) on:change=move |event| {
                        let value = event_target_value(&event);
                        if let Some(range) = TimeRange::ALL.into_iter().find(|range| range.value() == value) {
                            view.update(|view| view.range = range);
                        }
                    }>
                        {TimeRange::ALL.into_iter().map(|range| view!{<option value=range.value()>{range.label()}</option>}).collect_view()}
                    </select>
                </label>
                <label>"Client"
                    <select prop:value=move || view.with(|view| view.client.clone()) on:change=move |event| view.update(|view| view.client = event_target_value(&event))>
                        <option value="">"All clients"</option>
                        <For each=move || clients.get() key=Clone::clone children=|client| { let value = client.clone(); view!{<option value=value>{client}</option>} }/>
                    </select>
                </label>
                <span class=styles::muted>{move || format!("{} s resolution · missing samples are not zero",view.with(|view| view.range.step()))}</span>
            </div>
            <p class=styles::muted>{move || timestamp(data.with(|data| data.sampled_at))}</p>
            {move || data.with(|data| data.error.clone()).map(|error| view!{<p class=styles::warning>{error}</p>})}
            {move || data.with(|data| if !data.configured && status.get() == ConnectionStatus::Connected { Some("Fleet data source not configured; native status remains available.") } else if data.sampled_at.is_none() { Some("Waiting for telemetry…") } else { None }).map(|message| view!{<p class=styles::muted>{message}</p>})}
            <div class=styles::panels>
                <For each=move || panels.get() key=|key| *key children=move |key| {
                    let panel = Memo::new(move |_| panel_data.with(|panels| panels.get(&key).cloned()));
                    view! {
                        <article>{move || panel.get().map(|panel| {
                            let title = panel.title.clone();
                            let error = panel.error.clone();
                            let sampled_at = data.with(|data| data.sampled_at);
                            view! {
                                <h3>{title}</h3>
                                {error.map(|error| view!{<p class=styles::warning>{error}</p>})}
                                <chart::PanelContent panel=panel step=step.get() sampled_at=sampled_at/>
                            }
                        })}</article>
                    }
                }/>
            </div>
        </section>
    }
}

// These values feed rounded human-readable labels and SVG coordinates, never
// admission or cache accounting. The integer authoritative value stays intact.
#[allow(
    clippy::cast_precision_loss,
    reason = "approximate display coordinates and labels"
)]
const fn display_count(value: u64) -> f64 {
    value as f64
}

fn bytes(value: u64) -> String {
    let mut scaled = display_count(value);
    for unit in ["B", "KiB", "MiB", "GiB", "TiB", "PiB"] {
        if scaled < 1024.0 || unit == "PiB" {
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
fn age_since(sampled_at: Option<u64>, then_ms: u64) -> String {
    sampled_at.map_or_else(
        || "—".into(),
        |now| {
            age(
                std::time::Duration::from_millis(now.saturating_mul(1000).saturating_sub(then_ms))
                    .as_secs_f64(),
            )
        },
    )
}
fn timestamp(value: Option<u64>) -> String {
    value
        .and_then(|value| i64::try_from(value).ok())
        .and_then(|value| chrono::DateTime::from_timestamp(value, 0))
        .map_or_else(
            || "Not yet sampled".into(),
            |value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        )
}

#[component]
fn Stat(label: &'static str, value: String) -> impl IntoView {
    view! { <div class=styles::stat><small>{label}</small><strong>{value}</strong></div> }
}
