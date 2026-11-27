//! Dependency-light SVG history charts with gap-aware paths and readable units.
use super::display_count;
use crate::{MetricSeries, styles};
use leptos::prelude::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

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

fn bounds(series: &[MetricSeries], unit: &str, window: Option<(u64, u64)>) -> Option<Bounds> {
    let (start, end) = window.map_or((f64::INFINITY, f64::NEG_INFINITY), |(start, end)| {
        (display_count(start), display_count(end))
    });
    let mut bounds = Bounds {
        start,
        end,
        min: 0.0,
        max: 0.0,
    };
    for &(time, value) in series.iter().flat_map(|series| &series.points) {
        if !time.is_finite() {
            continue;
        }
        if window.is_some() {
            if time < bounds.start || time > bounds.end {
                continue;
            }
        } else {
            bounds.start = bounds.start.min(time);
            bounds.end = bounds.end.max(time);
        }
        if let Some(value) = value.filter(|value| value.is_finite()) {
            bounds.min = bounds.min.min(value);
            bounds.max = bounds.max.max(value);
        }
    }
    if !bounds.start.is_finite() || bounds.end < bounds.start {
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
        if let Some(value) = value.filter(|value| {
            value.is_finite() && time.is_finite() && time >= bounds.start && time <= bounds.end
        }) {
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

const PATTERNS: [(&str, &str); 5] = [
    ("none", "━"),
    ("6 3", "┄"),
    ("2 3", "┈"),
    ("8 3 2 3", "┅"),
    ("10 5", "╍"),
];

fn reconcile_styles(
    keys: &[String],
    previous: Option<BTreeMap<String, usize>>,
) -> (BTreeMap<String, usize>, bool) {
    let mut styles = previous.unwrap_or_default();
    let mut changed = styles.len() != keys.len();
    let before = styles.len();
    styles.retain(|key, _| keys.binary_search(key).is_ok());
    changed |= before != styles.len();
    let mut used = styles.values().copied().collect::<BTreeSet<_>>();
    for key in keys {
        if !styles.contains_key(key) {
            let index = (0..COLORS.len() * PATTERNS.len())
                .find(|index| !used.contains(index))
                .unwrap_or_else(|| {
                    key.bytes().fold(0_usize, |hash, byte| {
                        hash.wrapping_mul(31).wrapping_add(usize::from(byte))
                    }) % (COLORS.len() * PATTERNS.len())
                });
            styles.insert(key.clone(), index);
            used.insert(index);
            changed = true;
        }
    }
    (styles, changed)
}

fn current_value(series: &MetricSeries, end: f64) -> Option<f64> {
    series
        .points
        .last()
        .filter(|(time, _)| time.total_cmp(&end).is_eq())
        .and_then(|(_, value)| *value)
}

#[component]
pub(super) fn HistoryChart(
    series: Memo<Vec<MetricSeries>>,
    unit: Memo<String>,
    step: Signal<u64>,
    window: Signal<Option<(u64, u64)>>,
) -> impl IntoView {
    let indexed = super::keyed_index(series, |series| &series.key);
    let keys = super::index_keys(indexed);
    let palette =
        Memo::new_owning(move |previous| keys.with(|keys| reconcile_styles(keys, previous)));
    let extent = Memo::new(move |_| {
        series.with(|series| unit.with(|unit| bounds(series, unit, window.get())))
    });
    let observed = Memo::new(move |_| {
        series.with(|series| {
            series
                .iter()
                .any(|series| series.points.iter().any(|(_, value)| value.is_some()))
        })
    });
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
                let style = Memo::new({let key=key.clone(); move |_| palette.with(|styles| styles.get(&key).copied().unwrap_or_default())});
                let row = Memo::new(move |_| indexed.with(|series| series.get(&key).cloned()));
                view!{
                    <path d=move || extent.with(|extent| row.with(|row| match (extent,row) { (Some(extent),Some(row)) => plot_path(&row.points,*extent,step.get()), _ => String::new() }))
                        stroke=move || COLORS[style.get()%COLORS.len()] stroke-dasharray=move || PATTERNS[(style.get()/COLORS.len())%PATTERNS.len()].0 stroke-width="1.5" stroke-linecap="round" vector-effect="non-scaling-stroke" fill="none">
                        <title>{move || row.with(|row| row.as_ref().map_or_else(String::new,|row| row.label.clone()))}</title>
                    </path>
                }
            }/>
        </svg>
        <div class=styles::axis><span>{move || axis(false)}</span><span>{move || time(false)}</span><span>{move || time(true)}</span></div>
        <div class=styles::legend>
            <p class=styles::muted hidden=move || observed.get()>"No samples"</p>
            <For each=move || keys.get() key=Clone::clone children=move |key| {
                let style = Memo::new({let key=key.clone(); move |_| palette.with(|styles| styles.get(&key).copied().unwrap_or_default())});
                let row=Memo::new(move |_| indexed.with(|series| series.get(&key).cloned()));
                view!{<div><span style:color=move || COLORS[style.get()%COLORS.len()]>{move || PATTERNS[(style.get()/COLORS.len())%PATTERNS.len()].1}</span>{move || row.with(|row| row.as_ref().map_or_else(String::new,|row| row.label.clone()))}<b>{move || row.with(|row| extent.with(|extent| extent.and_then(|extent| current_value(row.as_ref()?,extent.end)))).map_or_else(|| "—".into(),|value| unit.with(|unit| value_label(value,unit)))}</b></div>}
            }/>
        </div>
    }.into_any()
}

#[component]
pub(super) fn MetricCard(
    panel: Memo<Option<crate::MetricPanel>>,
    step: Signal<u64>,
    sampled_at: Memo<Option<u64>>,
    window: Signal<Option<(u64, u64)>>,
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
                view!{<HistoryChart series=series unit=unit step=step window=window/>}.into_any()
            } else {
                kind.get().map(|kind| view!{<PanelContent panel=panel kind=kind unit=unit sampled_at=sampled_at/>}).into_any()
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
            bounds(&series, "percent", None)
                .is_some_and(|extent| (extent.max - 100.0).abs() < f64::EPSILON)
        );
        assert!(
            bounds(&series, "jobs", None)
                .is_some_and(|extent| (extent.max - 23.0).abs() < f64::EPSILON)
        );
    }

    #[test]
    fn selected_axis_and_missing_current_point_are_not_shifted() {
        let series = MetricSeries {
            key: "a".into(),
            label: "a".into(),
            points: vec![(20.0, Some(12.0))],
        };
        let extent = bounds(std::slice::from_ref(&series), "percent", Some((0, 60))).unwrap();
        assert!(extent.start.total_cmp(&0.0).is_eq());
        assert!(extent.end.total_cmp(&60.0).is_eq());
        assert!(current_value(&series, 60.0).is_none());
        let mut panel = crate::MetricPanel {
            key: 0,
            group: crate::MetricGroup::CacheHits,
            kind: crate::PanelKind::Stat,
            title: "rate".into(),
            unit: "percent".into(),
            series: vec![series],
            error: None,
        };
        assert!(metric_rows(&panel, Some(60)).is_empty());
        panel.error = Some("failed".into());
        assert!(metric_rows(&panel, Some(60))[0].stale);
    }

    #[test]
    fn chart_styles_survive_roster_changes_without_early_collisions() {
        let keys = (0..12).map(|key| format!("{key:02}")).collect::<Vec<_>>();
        let (first, _) = reconcile_styles(&keys, None);
        assert_eq!(first.values().collect::<BTreeSet<_>>().len(), keys.len());
        let mut updated = keys[1..].to_vec();
        updated.push("new".into());
        let (second, changed) = reconcile_styles(&updated, Some(first.clone()));
        assert!(changed);
        for key in &keys[1..] {
            assert_eq!(first[key], second[key]);
        }
        assert_eq!(
            second.values().collect::<BTreeSet<_>>().len(),
            updated.len()
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

/// Current values come from a single evaluation point. Retained values after
/// query failure remain explicitly stale; the version table is historical.
#[derive(Clone, PartialEq)]
struct MetricRow {
    key: String,
    label: String,
    time: f64,
    value: f64,
    stale: bool,
}

fn metric_rows(panel: &crate::MetricPanel, end: Option<u64>) -> Vec<MetricRow> {
    panel
        .series
        .iter()
        .filter_map(|series| {
            let (time, value) = series
                .points
                .iter()
                .rev()
                .find_map(|(time, value)| value.map(|value| (*time, value)))?;
            let stale = end.is_none_or(|end| !time.total_cmp(&display_count(end)).is_eq());
            if panel.kind != crate::PanelKind::Table && panel.error.is_none() && stale {
                return None;
            }
            Some(MetricRow {
                key: series.key.clone(),
                label: series.label.clone(),
                time,
                value,
                stale,
            })
        })
        .collect()
}

#[component]
fn PanelContent(
    panel: Memo<Option<crate::MetricPanel>>,
    kind: crate::PanelKind,
    unit: Memo<String>,
    sampled_at: Memo<Option<u64>>,
) -> impl IntoView {
    use crate::PanelKind;
    let rows = Memo::new(move |_| {
        panel.with(|panel| {
            panel
                .as_ref()
                .map_or_else(Vec::new, |panel| metric_rows(panel, sampled_at.get()))
        })
    });
    let indexed = super::keyed_index(rows, |row| &row.key);
    let keys = super::index_keys(indexed);
    let maximum = Memo::new(move |_| {
        rows.with(|rows| rows.iter().map(|row| row.value).fold(1.0_f64, f64::max))
    });
    let children = move |key| {
        let row = Memo::new(move |_| indexed.with(|rows| rows.get(&key).cloned()));
        view! { <MetricValueRow row=row kind=kind unit=unit maximum=maximum/> }
    };
    view! {
        <p class=styles::muted hidden=move || !rows.with(Vec::is_empty)>"No samples"</p>
        {match kind {
            PanelKind::Stat => view! { <div class=styles::metricstats><For each=move || keys.get() key=Clone::clone children=children/></div> }.into_any(),
            PanelKind::Bargauge => view! { <div class=styles::gauges><For each=move || keys.get() key=Clone::clone children=children/></div> }.into_any(),
            PanelKind::Table => view! { <div class=styles::tablewrap><table><thead><tr><th>"Client / version"</th><th>"Last observed (UTC)"</th></tr></thead><tbody><For each=move || keys.get() key=Clone::clone children=children/></tbody></table></div> }.into_any(),
            PanelKind::Timeseries => ().into_any(),
        }}
    }.into_any()
}

#[component]
fn MetricValueRow(
    row: Memo<Option<MetricRow>>,
    kind: crate::PanelKind,
    unit: Memo<String>,
    maximum: Memo<f64>,
) -> impl IntoView {
    use crate::PanelKind;
    let label = move || {
        row.with(|row| {
            row.as_ref()
                .map_or_else(String::new, |row| row.label.clone())
        })
    };
    let value = move || {
        row.with(|row| {
            row.as_ref().map_or_else(
                || "—".into(),
                |row| unit.with(|unit| value_label(row.value, unit)),
            )
        })
    };
    let time = move || {
        row.with(|row| {
            row.as_ref()
                .map_or_else(|| "—".into(), |row| axis_time(row.time, 86_400.0))
        })
    };
    let stale = move || row.with(|row| row.as_ref().is_some_and(|row| row.stale));
    match kind {
        PanelKind::Stat => view! {
            <div class=styles::metricstat><small>{label}</small><strong>{value}</strong><small class=styles::warning hidden=move || !stale()>"Last observed "{time}" UTC"</small></div>
        }.into_any(),
        PanelKind::Bargauge => view! {
            <div><div class=styles::subhead><span>{label}</span><b>{value}</b></div>
                <meter min="0" max=move || maximum.get() prop:value=move || row.with(|row|row.as_ref().map_or(0.0,|row|row.value.max(0.0)))/>
                <small class=styles::warning hidden=move || !stale()>"Last observed "{time}" UTC"</small>
            </div>
        }.into_any(),
        PanelKind::Table => view! { <tr><td>{label}</td><td class=move || if stale(){styles::warning}else{styles::muted}>{time}</td></tr> }.into_any(),
        PanelKind::Timeseries => ().into_any(),
    }
}
