//! Dependency-light SVG history charts with gap-aware paths and readable units.
use super::display_count;
use crate::{MetricSeries, styles};
use leptos::prelude::*;
use std::time::Duration;

const COLORS: [&str; 10] = [
    "#56b4e9", "#e69f00", "#009e73", "#cc79a7", "#f0e442", "#e76f51", "#88aaff", "#b2df8a",
    "#e78ac3", "#8dd3c7",
];

#[derive(Clone, Copy)]
struct Bounds {
    start: f64,
    end: f64,
    min: f64,
    max: f64,
}

fn bounds(series: &[MetricSeries]) -> Option<Bounds> {
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
            chrono::DateTime::from_timestamp(
                i64::try_from(duration.as_secs()).ok()?,
                duration.subsec_nanos(),
            )
        })
        .map_or_else(
            || "—".into(),
            |date| {
                date.format(if range >= 86400.0 {
                    "%m-%d %H:%M"
                } else {
                    "%H:%M:%S"
                })
                .to_string()
            },
        )
}

pub(super) fn graph(series: Vec<MetricSeries>, unit: &str, step: u64) -> impl IntoView + use<> {
    let Some(bounds) = bounds(&series) else {
        return view! {<p class=styles::muted>"No samples"</p>}.into_any();
    };
    let range = bounds.end - bounds.start;
    view! {
        <div class=styles::axis><span>{value_label(bounds.max,unit)}</span><span>{format!("{:.0} min · UTC",range/60.0)}</span></div>
        <svg class=styles::chart viewBox="0 0 600 160" role="img" aria-label="Metric history" preserveAspectRatio="none">
            <path d="M10,10 H590 M10,80 H590 M10,150 H590" stroke="currentColor" opacity="0.2" fill="none"/>
            {series.iter().enumerate().map(|(index,series)| view!{
                <path d=plot_path(&series.points,bounds,step) stroke=COLORS[index%COLORS.len()] stroke-width="1.5" stroke-linecap="round" vector-effect="non-scaling-stroke" fill="none"><title>{series.label.clone()}</title></path>
            }).collect_view()}
        </svg>
        <div class=styles::axis><span>{value_label(bounds.min,unit)}</span><span>{axis_time(bounds.start,range)}</span><span>{axis_time(bounds.end,range)}</span></div>
        <div class=styles::legend>{series.into_iter().enumerate().map(|(index,series)| {
            let last = series.points.last().and_then(|(_,value)| *value);
            view!{<div><span style:color=COLORS[index%COLORS.len()]>"● "</span>{series.label}<b>{last.map_or_else(|| "—".into(), |value| value_label(value,unit))}</b></div>}
        }).collect_view()}</div>
    }.into_any()
}

#[cfg(test)]
mod tests {
    use super::*;
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
    if panel.kind == PanelKind::Timeseries {
        return graph(panel.series, &panel.unit, step).into_any();
    }
    let rows = panel
        .series
        .into_iter()
        .filter_map(|series| {
            let (time, value) = series
                .points
                .iter()
                .rev()
                .find_map(|(time, value)| value.map(|value| (*time, value)))?;
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
