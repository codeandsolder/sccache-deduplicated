//! Distinct-content distributions, not per-reference storage sums.
use super::{Stat, bytes, timestamp};
use crate::{NativeTelemetry, Worker, styles};
use leptos::prelude::*;
use sccache_build::analytics::{CacheBucket, CacheDistribution, CacheWeight};

#[component]
pub(super) fn CacheAnalytics(
    telemetry: Memo<Option<NativeTelemetry>>,
    workers: Memo<Vec<Worker>>,
) -> impl IntoView {
    let observation = Memo::new(move |_| {
        telemetry.with(|value| value.as_ref().and_then(|value| value.analytics.clone()))
    });
    view! {
        <section id="cache-analytics">
            <h2>"Cache analytics"</h2>
            <p class=styles::muted>"Scheduler native CAS · independent five-minute snapshots · storage counts each live blob once."</p>
            {move || observation.get().map_or_else(
                || view! { <p class=styles::muted>"Waiting for the first cache analytics snapshot."</p> }.into_any(),
                |observation| view! {
                    <p class=styles::muted>{timestamp(Some(observation.sampled_at))}</p>
                    {observation.error.map(|error| view! { <p class=styles::warning>{error}</p> })}
                    {observation.report.map(|report| view! { <Distribution report=report/> })}
                }.into_any()
            )}
            <FleetStorage workers=workers/>
            <p class=styles::muted>"Legacy L0/L1 distributions, per-tier capacity and shared managed-cache heat are in the fleet metrics view. Select an individual client to inspect distributions."</p>
        </section>
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "display-only ratio of exact integer counters"
)]
fn percent(part: u128, total: u128) -> f64 {
    if total == 0 {
        0.0
    } else {
        100.0 * part as f64 / total as f64
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "display-only ratio of exact integer counters"
)]
fn ratio(numerator: u128, denominator: u128) -> String {
    if denominator == 0 {
        "—".into()
    } else {
        format!("{:.2}×", numerator as f64 / denominator as f64)
    }
}

fn share(part: u64, total: u64) -> String {
    format!("{:.1}%", percent(part.into(), total.into()))
}

fn age_label(bound: u64) -> String {
    match bound {
        3600 => "1 hour".into(),
        86400 => "1 day".into(),
        604800 => "7 days".into(),
        2592000 => "30 days".into(),
        7776000 => "90 days".into(),
        31536000 => "365 days".into(),
        u64::MAX => ">365 days".into(),
        _ => format!("{bound} s"),
    }
}

fn bucket_label(bound: Option<u64>, format: fn(u64) -> String) -> String {
    bound.map_or_else(|| "Unknown".into(), format)
}

#[component]
fn Histogram(
    title: &'static str,
    buckets: Vec<CacheBucket>,
    total: CacheWeight,
    format: fn(u64) -> String,
) -> impl IntoView {
    view! {
        <h3>{title}</h3>
        <div class=styles::tablewrap>
            <table>
                <thead><tr><th>"Bucket upper bound"</th><th>"Objects"</th><th>"Object share"</th><th>"Logical bytes"</th><th>"Logical share"</th><th>"Stored bytes"</th><th>"Allocated bytes"</th></tr></thead>
                <tbody>
                    {buckets.into_iter().map(|bucket| {
                        let weight = bucket.weight;
                        view! {
                            <tr>
                                <td>{bucket_label(bucket.upper, format)}</td>
                                <td>{weight.objects}</td>
                                <td>{share(weight.objects, total.objects)}</td>
                                <td>{bytes(weight.logical_bytes)}</td>
                                <td><progress max="100" value=percent(weight.logical_bytes.into(), total.logical_bytes.into())/><span>{share(weight.logical_bytes, total.logical_bytes)}</span></td>
                                <td>{if weight.measured_objects == 0 {"—".into()} else {bytes(weight.stored_bytes)}}</td>
                                <td>{if weight.measured_objects == 0 {"—".into()} else {bytes(weight.allocated_bytes)}}</td>
                            </tr>
                        }
                    }).collect_view()}
                </tbody>
            </table>
        </div>
    }
}

fn bucket_total(buckets: &[CacheBucket]) -> CacheWeight {
    let mut total = CacheWeight::default();
    for bucket in buckets {
        total.add(&bucket.weight);
    }
    total
}

#[component]
fn EvictionHistogram(
    title: &'static str,
    buckets: Vec<CacheBucket>,
    physical: bool,
) -> impl IntoView {
    let total = bucket_total(&buckets);
    view! {
        <h3>{title}</h3>
        <div class=styles::tablewrap><table>
            <thead><tr><th>"Score upper bound"</th><th>"Roots"</th><th>"Exclusive logical bytes"</th><th>"Measured allocated bytes"</th><th>"Share of independently reclaimable bytes"</th></tr></thead>
            <tbody>{buckets.into_iter().map(|bucket| {
                let weight = bucket.weight;
                let (part, all) = if physical { (weight.allocated_bytes,total.allocated_bytes) } else { (weight.logical_bytes,total.logical_bytes) };
                view! { <tr>
                    <td>{bucket_label(bucket.upper, |value| value.to_string())}</td>
                    <td>{weight.objects}</td><td>{bytes(weight.logical_bytes)}</td>
                    <td>{if weight.measured_objects == 0 {"—".into()} else {bytes(weight.allocated_bytes)}}</td>
                    <td><progress max="100" value=percent(part.into(),all.into())/><span>{share(part,all)}</span></td>
                </tr> }
            }).collect_view()}</tbody>
        </table></div>
    }
}

fn cumulative(buckets: &[CacheBucket]) -> Vec<CacheWeight> {
    let mut total = CacheWeight::default();
    let mut points = vec![total.clone()];
    for bucket in buckets.iter().rev() {
        total.add(&bucket.weight);
        points.push(total.clone());
    }
    points
}

fn curve_path(
    points: &[CacheWeight],
    x: fn(&CacheWeight) -> u128,
    y: fn(&CacheWeight) -> u128,
) -> String {
    use std::fmt::Write;
    let Some(total) = points.last() else {
        return String::new();
    };
    let mut path = String::new();
    if x(total) == 0 || y(total) == 0 {
        return path;
    }
    for (index, point) in points.iter().enumerate() {
        let horizontal = percent(x(point), x(total)).mul_add(5.8, 10.0);
        let vertical = percent(y(point), y(total)).mul_add(-1.4, 150.0);
        let command = if index == 0 { 'M' } else { 'L' };
        let _ = write!(path, "{command}{horizontal:.2},{vertical:.2} ");
    }
    path
}

/// Storage required to cross a reuse percentile is a range, because frequency
/// bins preserve aggregate weights but not ordering inside tied/ranged bins.
fn percentile_range(points: &[CacheWeight], target: u128) -> String {
    let Some(total) = points.last() else {
        return "—".into();
    };
    if total.touches == 0 || total.logical_bytes == 0 {
        return "—".into();
    }
    let threshold = total.touches / 100 * target + (total.touches % 100 * target).div_ceil(100);
    points
        .windows(2)
        .find(|pair| pair[1].touches >= threshold)
        .map_or_else(
            || "—".into(),
            |pair| {
                format!(
                    "{}–{}",
                    share(pair[0].logical_bytes, total.logical_bytes),
                    share(pair[1].logical_bytes, total.logical_bytes),
                )
            },
        )
}

#[component]
fn Distribution(report: CacheDistribution) -> impl IntoView {
    let total = report.total;
    let points = cumulative(&report.frequency);
    let logical = |weight: &CacheWeight| u128::from(weight.logical_bytes);
    let stored = |weight: &CacheWeight| u128::from(weight.stored_bytes);
    let touches = |weight: &CacheWeight| weight.touches;
    let byte_touches = |weight: &CacheWeight| weight.byte_touches;
    let measured_all = total.measured_objects == total.objects && total.objects != 0;
    let path = curve_path(&points, logical, touches);
    let byte_path = curve_path(&points, logical, byte_touches);
    let stored_path = if measured_all {
        curve_path(&points, stored, touches)
    } else {
        String::new()
    };
    view! {
        <div class=styles::stats>
            <Stat label="Distinct live blobs" value=total.objects.to_string()/>
            <Stat label="Unique logical bytes" value=bytes(total.logical_bytes)/>
            <Stat label="Measured file bytes" value=bytes(total.stored_bytes)/>
            <Stat label="Measured allocated bytes" value=bytes(total.allocated_bytes)/>
            <Stat label="Physical coverage" value=share(total.measured_objects,total.objects)/>
            <Stat label="Reference deduplication" value=ratio(report.referenced_bytes,total.logical_bytes.into())/>
            <Stat label="Logical / stored" value=ratio(total.measured_logical_bytes.into(),total.stored_bytes.into())/>
            <Stat label="Logical / allocated" value=ratio(total.measured_logical_bytes.into(),total.allocated_bytes.into())/>
        </div>
        <p class=styles::muted>"Allocation is the sum of reported file blocks, not exclusive pool consumption; filesystem cloning, snapshots and compression can change actual space savings. Ratios use only measured files. References count distinct action/tree owners, not repeated paths within a manifest."</p>
        <h3>"Cumulative reuse vs storage"</h3>
        <p class=styles::muted>"Most-used frequency buckets first. Root touches include publication and lookup; each referencing root contributes to its blobs. Byte-touches estimate logical content reuse, not measured transfer traffic. Lines connect bucket boundaries."</p>
        <div class=styles::axis><span>"100% cumulative reuse"</span><span>"Hot → cold"</span></div>
        <svg class=styles::chart viewBox="0 0 600 160" role="img" aria-label="Cumulative reuse versus storage share" preserveAspectRatio="none">
            <path d="M10,10 H590 M10,80 H590 M10,150 H590 M10,10 V150 M300,10 V150 M590,10 V150" stroke="currentColor" opacity="0.2" fill="none"/>
            <path d="M10,150 L590,10" stroke="currentColor" opacity="0.35" stroke-dasharray="4 4" fill="none"/>
            <path d=path stroke="#56b4e9" stroke-width="2" fill="none"/>
            <path d=byte_path stroke="#e69f00" stroke-width="2" fill="none"/>
            <path d=stored_path stroke="#009e73" stroke-width="2" fill="none"/>
        </svg>
        <div class=styles::axis><span>"0%"</span><span>"Cumulative storage share"</span><span>"100%"</span></div>
        <div class=styles::legend>
            <div><span style:color="#56b4e9">"● "</span>"Root touches / logical bytes"</div>
            <div><span style:color="#e69f00">"● "</span>"Byte-touches / logical bytes"</div>
            {measured_all.then(||view!{<div><span style:color="#009e73">"● "</span>"Root touches / stored file bytes"</div>})}
        </div>
        <div class=styles::tablewrap><table>
            <thead><tr><th>"Reuse percentile"</th><th>"Logical storage share (bucket bounds)"</th></tr></thead>
            <tbody>{[50_u128,90,95,99].into_iter().map(|target| view! {
                <tr><td>{format!("{target}%")}</td><td>{percentile_range(&points,target)}</td></tr>
            }).collect_view()}</tbody>
        </table></div>
        <Histogram title="Object size distribution" buckets=report.size total=total.clone() format=bytes/>
        <Histogram title="Time since last root touch" buckets=report.age_seconds total=total.clone() format=age_label/>
        <Histogram title="Root touch frequency" buckets=report.frequency total=total.clone() format=|bound|bound.to_string()/>
        <h3>"Eviction cost distribution"</h3>
        <p class=styles::muted>"Actual native eviction utility per independently reclaimable byte, lower scores first. Shared blobs are not counted as reclaimable by one root. Active pins and physical allocation are observed best-effort; zero-content roots are omitted."</p>
        <div class=styles::stats>
            <Stat label="Pinned roots" value=report.eviction.pinned_roots.to_string()/>
            <Stat label="Roots with no exclusive logical bytes" value=report.eviction.zero_logical_roots.to_string()/>
            <Stat label="Roots missing physical metadata" value=report.eviction.unmeasured_physical_roots.to_string()/>
        </div>
        <EvictionHistogram title="Logical pressure: eviction score" buckets=report.eviction.logical physical=false/>
        <EvictionHistogram title="Physical pressure: eviction score" buckets=report.eviction.physical physical=true/>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_reports_bounds_not_invented_interpolation() {
        let points = cumulative(&[
            CacheBucket {
                upper: Some(0),
                weight: CacheWeight {
                    objects: 1,
                    logical_bytes: 90,
                    ..Default::default()
                },
            },
            CacheBucket {
                upper: Some(7),
                weight: CacheWeight {
                    objects: 1,
                    logical_bytes: 10,
                    touches: 7,
                    ..Default::default()
                },
            },
        ]);
        assert_eq!(percentile_range(&points, 50), "0.0%–10.0%");
        assert_eq!(percentile_range(&points, 99), "0.0%–10.0%");
        assert_eq!(percentile_range(&[CacheWeight::default()], 90), "—");
    }
}

#[component]
fn FleetStorage(workers: Memo<Vec<Worker>>) -> impl IntoView {
    view! {
        <h3>"Worker native CAS storage"</h3>
        <p class=styles::muted>"Per-host local snapshots. Replicated content is counted separately on each host; these rows cannot be summed to obtain globally unique content."</p>
        <div class=styles::tablewrap><table>
            <thead><tr><th>"Worker"</th><th>"Sample"</th><th>"Objects"</th><th>"Logical / budget"</th><th>"Stored"</th><th>"Allocated"</th><th>"Dedup"</th><th>">7d"</th><th>">30d"</th><th>">90d"</th><th>"Unknown age"</th></tr></thead>
            <tbody>{move || workers.get().into_iter().filter_map(|worker| {
                let native = worker.native?;
                Some(match native.cache_analytics {
                    Some(summary) => {
                        let sampled_at = timestamp(Some(summary.sampled_at));
                        match summary.total {
                            Some(total) => view!{
                                <tr>
                                    <td>{worker.name}</td><td>{sampled_at}</td><td>{total.objects}</td>
                                    <td>{format!("{} / {}",bytes(total.logical_bytes),summary.maximum_bytes.map_or_else(||"—".into(),bytes))}</td>
                                    <td>{format!("{} ({})",bytes(total.stored_bytes),share(total.measured_objects,total.objects))}</td>
                                    <td>{bytes(total.allocated_bytes)}</td>
                                    <td>{ratio(summary.referenced_bytes,total.logical_bytes.into())}</td>
                                    <td>{bytes(summary.older_than_seven_days)}</td><td>{bytes(summary.older_than_thirty_days)}</td><td>{bytes(summary.older_than_ninety_days)}</td><td>{bytes(summary.unknown_age_bytes)}</td>
                                </tr>
                            }.into_any(),
                            None => view!{<tr><td>{worker.name}</td><td>{sampled_at}</td><td colspan="9">"Snapshot failed"</td></tr>}.into_any(),
                        }
                    }
                    None => view!{<tr><td>{worker.name}</td><td colspan="10">"Waiting for snapshot"</td></tr>}.into_any(),
                })
            }).collect_view()}</tbody>
        </table></div>
    }
}
