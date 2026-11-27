//! Dependency-light SVG history charts with gap-aware paths and readable units.
use super::display_count;
use crate::{MetricSeries, styles};
use leptos::prelude::*;
use std::time::Duration;

const COLORS: [&str; 10] = [
    "#56b4e9", "#e69f00", "#009e73", "#cc79a7", "#f0e442", "#e76f51", "#88aaff", "#b2df8a",
    "#e78ac3", "#8dd3c7",
];

#[derive(Clone, Copy, PartialEq)]
struct Bounds {
    start: f64,
    end: f64,
    min: f64,
    max: f64,
}

fn bounds(series: &[MetricSeries], unit: &str) -> Option<Bounds> {
    let mut bounds = Bounds {
        start: f64::INFINITY,
        end: f64::NEG_INFINITY,
        min: 0.0,
        max: 0.0,
    };
    let mut observed = false;
    for &(time, value) in series.iter().flat_map(|series| &series.points) {
        if time.is_finite() {
            bounds.start = bounds.start.min(time);
            bounds.end = bounds.end.max(time);
        }
        if let Some(value) = value.filter(|value| value.is_finite()) {
            observed = true;
            bounds.min = bounds.min.min(value);
            bounds.max = bounds.max.max(value);
        }
    }
    if !observed || !bounds.start.is_finite() {
        return None;
    }
    if unit == "percent" {
        bounds.max = bounds.max.max(100.0);
    }
    if bounds.max <= bounds.min {
        bounds.max = bounds.min + 1.0;
    }
    Some(bounds)
}

fn plot_path(points: &[(f64, Option<f64>)], bounds: Bounds, step: u64) -> String {
    use std::fmt::Write;
    let mut path = String::new();
    let mut previous = None;
    for &(time, value) in points {
        if let Some(value) = value.filter(|value| value.is_finite() && time.is_finite()) {
            let x =
                ((time - bounds.start) / (bounds.end - bounds.start).max(1.0)).mul_add(580.0, 10.0);
            let y = ((value - bounds.min) / (bounds.max - bounds.min)).mul_add(-140.0, 150.0);
            let command = if previous.is_some_and(|last| time - last <= display_count(step) * 1.5) {
                'L'
            } else {
                'M'
            };
            let _ = write!(path, "{command}{x:.2},{y:.2} ");
            // An isolated sample still draws a small dot with round line caps.
            if command == 'M' {
                let _ = write!(path, "l0.01,0 ");
            }
            previous = Some(time);
        } else {
            previous = None;
        }
    }
    path
}

fn value_label(value: f64, unit: &str) -> String {
    match unit {
        "bytes" if value >= 0.0 => {
            let mut scaled = value;
            for unit in ["B", "KiB", "MiB", "GiB", "TiB", "PiB"] {
                if scaled < 1024.0 || unit == "PiB" {
                    return format!("{scaled:.1} {unit}");
                }
                scaled /= 1024.0;
            }
            format!("{value:.0} B")
        }
        "percent" => format!("{value:.1}%"),
        "s" if value.abs() < 0.001 && value != 0.0 => format!("{:.1} µs", value * 1e6),
        "s" if value.abs() < 1.0 && value != 0.0 => format!("{:.1} ms", value * 1e3),
        "s" => format!("{value:.2} s"),
        "bool" => {
            if value == 0.0 {
                "Off".into()
            } else {
                "On".into()
            }
        }
        "ops" | "reqps" => format!("{value:.2}/s"),
        "short" | "" | "jobs" => {
            if value.abs() >= 1e6 {
                format!("{:.2} M", value / 1e6)
            } else if value.abs() >= 1e3 {
                format!("{:.2} k", value / 1e3)
            } else if value.fract() == 0.0 {
                format!("{value:.0}")
            } else {
                format!("{value:.2}")
            }
        }
        _ => format!("{value:.2} {unit}"),
    }
}

fn axis_time(time: f64, range: f64) -> String {
    Duration::try_from_secs_f64(time)
        .ok()
        .and_then(|duration| {
            jiff::Timestamp::new(
                i64::try_from(duration.as_secs()).ok()?,
                i32::try_from(duration.subsec_nanos()).ok()?,
            )
            .ok()
        })
        .map_or_else(
            || "—".into(),
            |date| {
                date.strftime(if range >= 86400.0 {
                    "%m-%d %H:%M"
                } else {
                    "%H:%M:%S"
                })
                .to_string()
            },
        )
}

fn series_color(key: &str) -> &'static str {
    // Stable across series arrival/removal and SSR/hydration.
    let hash = key.bytes().fold(0_u32, |hash, byte| {
        hash.wrapping_mul(31).wrapping_add(u32::from(byte))
    });
    COLORS[usize::try_from(hash).unwrap_or_default() % COLORS.len()]
}

#[component]
pub(super) fn HistoryChart(
    series: Memo<Vec<MetricSeries>>,
    unit: Memo<String>,
    step: Signal<u64>,
) -> impl IntoView {
    let indexed = super::keyed_index(series, |series| &series.key);
    let keys = super::index_keys(indexed);
    let extent = Memo::new(move |_| series.with(|series| unit.with(|unit| bounds(series, unit))));
    let axis = move |maximum: bool| {
        extent.with(|extent| {
            extent.map_or_else(
                || "—".into(),
                |extent| {
                    unit.with(|unit| {
                        value_label(if maximum { extent.max } else { extent.min }, unit)
                    })
                },
            )
        })
    };
    let time = move |end: bool| {
        extent.with(|extent| {
            extent.map_or_else(
                || "—".into(),
                |extent| {
                    axis_time(
                        if end { extent.end } else { extent.start },
                        extent.end - extent.start,
                    )
                },
            )
        })
    };
    view! {
        <div class=styles::axis><span>{move || axis(true)}</span><span>{move || extent.with(|extent| extent.map_or_else(|| "UTC".into(), |extent| format!("{:.0} min · UTC",(extent.end-extent.start)/60.0)))}</span></div>
        <svg class=styles::chart viewBox="0 0 600 160" role="img" aria-label="Metric history" preserveAspectRatio="none">
            <path d="M10,10 H590 M10,80 H590 M10,150 H590" stroke="currentColor" opacity="0.2" fill="none"/>
            <For each=move || keys.get() key=Clone::clone children=move |key| {
                let color = series_color(&key);
                let row = Memo::new(move |_| indexed.with(|series| series.get(&key).cloned()));
                view!{
                    <path d=move || extent.with(|extent| row.with(|row| match (extent,row) { (Some(extent),Some(row)) => plot_path(&row.points,*extent,step.get()), _ => String::new() }))
                        stroke=color stroke-width="1.5" stroke-linecap="round" vector-effect="non-scaling-stroke" fill="none">
                        <title>{move || row.with(|row| row.as_ref().map_or_else(String::new,|row| row.label.clone()))}</title>
                    </path>
                }
            }/>
        </svg>
        <div class=styles::axis><span>{move || axis(false)}</span><span>{move || time(false)}</span><span>{move || time(true)}</span></div>
        <div class=styles::legend>
            <p class=styles::muted hidden=move || extent.with(Option::is_some)>"No samples"</p>
            <For each=move || keys.get() key=Clone::clone children=move |key| {
                let color=series_color(&key);
                let row=Memo::new(move |_| indexed.with(|series| series.get(&key).cloned()));
                view!{<div><span style:color=color>"● "</span>{move || row.with(|row| row.as_ref().map_or_else(String::new,|row| row.label.clone()))}<b>{move || row.with(|row| row.as_ref().and_then(|row| row.points.last()).and_then(|(_,value)| *value).map_or_else(|| "—".into(),|value| unit.with(|unit| value_label(value,unit))))}</b></div>}
            }/>
        </div>
    }.into_any()
}

#[component]
pub(super) fn MetricCard(
    panel: Memo<Option<crate::MetricPanel>>,
    step: Signal<u64>,
    sampled_at: Memo<Option<u64>>,
) -> impl IntoView {
    let kind = Memo::new(move |_| panel.with(|panel| panel.as_ref().map(|panel| panel.kind)));
    let unit = Memo::new(move |_| {
        panel.with(|panel| {
            panel
                .as_ref()
                .map_or_else(String::new, |panel| panel.unit.clone())
        })
    });
    let series = Memo::new(move |_| {
        panel.with(|panel| {
            panel
                .as_ref()
                .map_or_else(Vec::new, |panel| panel.series.clone())
        })
    });
    let error = Memo::new(move |_| {
        panel.with(|panel| panel.as_ref().and_then(|panel| panel.error.clone()))
    });
    view! {
        <article>
            <h3>{move || panel.with(|panel| panel.as_ref().map_or_else(String::new,|panel| panel.title.clone()))}</h3>
            {move || error.get().map(|error| view!{<p class=styles::warning>{error}</p>})}
            {move || if kind.get()==Some(crate::PanelKind::Timeseries) {
                view!{<HistoryChart series=series unit=unit step=step/>}.into_any()
            } else {
                view!{{move || panel.get().map(|panel| view!{<PanelContent panel=panel step=step.get() sampled_at=sampled_at.get()/>})}}.into_any()
            }}
        </article>
    }.into_any()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chart_axis_uses_utc_and_handles_invalid_time() {
        assert_eq!(axis_time(0.0, 60.0), "00:00:00");
        assert_eq!(axis_time(86_401.5, 86_400.0), "01-02 00:00");
        assert_eq!(axis_time(f64::NAN, 60.0), "—");
        assert_eq!(axis_time(-1.0, 60.0), "—");
        assert_eq!(axis_time(f64::MAX, 60.0), "—");
    }

    #[test]
    fn percentage_axis_keeps_full_scale() {
        let series = [MetricSeries {
            key: "hit".into(),
            label: "Hit".into(),
            points: vec![(1.0, Some(12.0)), (2.0, Some(23.0))],
        }];
        assert!(
            bounds(&series, "percent")
                .is_some_and(|extent| (extent.max - 100.0).abs() < f64::EPSILON)
        );
        assert!(
            bounds(&series, "jobs").is_some_and(|extent| (extent.max - 23.0).abs() < f64::EPSILON)
        );
    }

    #[test]
    fn chart_does_not_bridge_missing_samples_or_time_gaps() {
        let bounds = Bounds {
            start: 0.0,
            end: 90.0,
            min: 0.0,
            max: 2.0,
        };
        let path = plot_path(
            &[
                (0.0, Some(1.0)),
                (30.0, None),
                (60.0, Some(2.0)),
                (90.0, Some(1.0)),
            ],
            bounds,
            30,
        );
        assert_eq!(path.matches('M').count(), 2);
        assert_eq!(path.matches('L').count(), 1);
        let path = plot_path(&[(0.0, Some(1.0)), (90.0, Some(1.0))], bounds, 30);
        assert_eq!(path.matches('M').count(), 2);
    }
}

/// Grafana's original panels have different semantics: current values,
/// historical traces, relative work distribution, and version metadata.
#[component]
pub(super) fn PanelContent(
    panel: crate::MetricPanel,
    step: u64,
    sampled_at: Option<u64>,
) -> impl IntoView {
    use crate::PanelKind;
    let current_only =
        panel.group == crate::MetricGroup::CacheHits && panel.kind == PanelKind::Stat;
    let rows = panel
        .series
        .into_iter()
        .filter_map(|series| {
            let (time, value) = if current_only {
                let (time, value) = series.points.last()?;
                (*time, (*value)?)
            } else {
                series
                    .points
                    .iter()
                    .rev()
                    .find_map(|(time, value)| value.map(|value| (*time, value)))?
            };
            if current_only
                && sampled_at
                    .is_some_and(|end| display_count(end) - time > display_count(step) * 1.5)
            {
                return None;
            }
            Some((series.label, time, value))
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return view! {<p class=styles::muted>"No samples"</p>}.into_any();
    }
    let stale = move |time: f64| {
        sampled_at.is_some_and(|end| display_count(end) - time > display_count(step) * 1.5)
    };
    match panel.kind {
        PanelKind::Stat => view! {
            <div class=styles::metricstats>
                {rows.into_iter().map(|(label,time,value)| view!{
                    <div class=styles::metricstat><small>{label}</small><strong>{value_label(value,&panel.unit)}</strong>
                        {stale(time).then(||view!{<small class=styles::warning>"Last observed "{axis_time(time,86_400.0)}" UTC"</small>})}
                    </div>
                }).collect_view()}
            </div>
        }.into_any(),
        PanelKind::Bargauge => {
            let mut rows = rows;
            rows.retain(|(_, _, value)| *value > 0.0);
            rows.sort_unstable_by(|a,b| b.2.total_cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
            let maximum = rows.iter().map(|(_,_,value)| *value).fold(0.0_f64,f64::max);
            view! {
                <div class=styles::gauges>
                    {rows.into_iter().map(|(label,time,value)| view!{
                        <div>
                            <div class=styles::subhead><span>{label}</span><b>{value_label(value,&panel.unit)}</b></div>
                            <meter min="0" max=maximum.max(1.0) value=value.max(0.0)/>
                            {stale(time).then(||view!{<small class=styles::warning>"Last observed "{axis_time(time,86_400.0)}" UTC"</small>})}
                        </div>
                    }).collect_view()}
                </div>
            }.into_any()
        }
        PanelKind::Table => view! {
            <div class=styles::tablewrap>
                <table><thead><tr><th>"Client / version"</th><th>"Last observed (UTC)"</th></tr></thead><tbody>
                    {rows.into_iter().map(|(label,time,_)|view!{<tr><td>{label}</td><td class=if stale(time) {styles::warning} else {styles::muted}>{axis_time(time,86_400.0)}</td></tr>}).collect_view()}
                </tbody></table>
            </div>
        }.into_any(),
        PanelKind::Timeseries => view!{<p class=styles::muted>"No samples"</p>}.into_any(),
    }
}
