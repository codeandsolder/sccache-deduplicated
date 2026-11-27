//! Merge disjoint time shards using the backend's fixed histogram buckets.
//! Never average shard percentiles: doing so loses the underlying distribution.

use super::{PhaseAggregate, Row, integer, number, take};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::collections::BTreeMap;

pub(super) const MAX_GROUPS: usize = 2048;
const MAX_BUCKETS: usize = 512;
const DISPLAY_GROUPS: usize = 200;

#[derive(Deserialize)]
struct Bucket {
    vmrange: String,
    hits: u64,
}

fn bounds(range: &str) -> Result<(f64, f64)> {
    let (low, high) = range
        .split_once("...")
        .context("invalid trace histogram range")?;
    let low: f64 = low.parse()?;
    let high: f64 = high.parse()?;
    ensure!(
        low.is_finite() && low >= 0.0 && high > low,
        "invalid trace histogram bounds"
    );
    Ok((low, high))
}

#[derive(Default)]
struct Histogram {
    count: u64,
    total: f64,
    minimum: Option<f64>,
    maximum: f64,
    buckets: BTreeMap<String, u64>,
}

impl Histogram {
    fn add(&mut self, mut row: Row) -> Result<()> {
        let count = integer(&mut row, "count")?;
        let total = number(&mut row, "total")?;
        let minimum = number(&mut row, "minimum")?;
        let maximum = number(&mut row, "maximum")?;
        ensure!(
            count > 0 && minimum <= maximum,
            "invalid trace histogram summary"
        );
        let bins: Vec<Bucket> = serde_json::from_str(&take(&mut row, "bins"))?;
        ensure!(
            bins.len() <= MAX_BUCKETS,
            "trace histogram exceeds bucket budget"
        );
        let mut hits = 0_u64;
        for bucket in bins {
            bounds(&bucket.vmrange)?;
            hits = hits
                .checked_add(bucket.hits)
                .context("trace histogram count overflow")?;
            let entry = self.buckets.entry(bucket.vmrange).or_default();
            *entry = entry
                .checked_add(bucket.hits)
                .context("trace histogram count overflow")?;
        }
        ensure!(
            hits == count && self.buckets.len() <= MAX_BUCKETS,
            "trace histogram count mismatch or bucket budget exceeded"
        );
        self.count = self
            .count
            .checked_add(count)
            .context("trace aggregate count overflow")?;
        self.total += total;
        ensure!(self.total.is_finite(), "trace aggregate duration overflow");
        self.minimum = Some(self.minimum.map_or(minimum, |old| old.min(minimum)));
        self.maximum = self.maximum.max(maximum);
        Ok(())
    }

    fn percentiles(&self) -> Result<[f64; 3]> {
        let minimum = self.minimum.context("empty trace histogram")?;
        let mut ordered = self
            .buckets
            .iter()
            .map(|(range, &hits)| {
                let (low, high) = bounds(range)?;
                Ok((low, high, hits))
            })
            .collect::<Result<Vec<_>>>()?;
        ordered.sort_unstable_by(|a, b| a.0.total_cmp(&b.0));
        let ranks = [50_u64, 95, 99]
            .map(|percent| (u128::from(self.count) * u128::from(percent)).div_ceil(100));
        let mut values = [self.maximum; 3];
        let mut cumulative = 0_u128;
        let mut next = 0;
        let mut previous = 0.0;
        for (low, high, hits) in ordered {
            ensure!(low >= previous, "overlapping trace histogram buckets");
            previous = high;
            cumulative += u128::from(hits);
            while next < ranks.len() && ranks[next] <= cumulative {
                // A bucket upper bound avoids pretending the within-bucket
                // distribution is known. Clamp to the observed min/max.
                values[next] = high.clamp(minimum, self.maximum);
                next += 1;
            }
        }
        ensure!(next == ranks.len(), "incomplete trace histogram");
        Ok(values)
    }
}

#[derive(Default)]
pub(super) struct PhaseGroups(BTreeMap<(String, String, String, String), Histogram>);

impl PhaseGroups {
    pub(super) fn add(&mut self, mut row: Row) -> Result<()> {
        let key = (
            take(&mut row, "resource_attr:service.name"),
            take(&mut row, "resource_attr:host.name"),
            take(&mut row, "resource_attr:service.version"),
            take(&mut row, "name"),
        );
        ensure!(
            self.0.contains_key(&key) || self.0.len() < MAX_GROUPS,
            "trace group budget exceeded; select a shorter range"
        );
        self.0.entry(key).or_default().add(row)
    }

    pub(super) fn finish(self) -> Result<Vec<PhaseAggregate>> {
        let mut phases = Vec::with_capacity(self.0.len());
        for ((service, host, version, phase), histogram) in self.0 {
            let [p50_ns, p95_ns, p99_ns] = histogram.percentiles()?;
            phases.push(PhaseAggregate {
                service,
                host,
                version,
                phase,
                count: histogram.count,
                p50_ns,
                p95_ns,
                p99_ns,
                total_ns: histogram.total,
            });
        }
        phases.sort_unstable_by(|a, b| {
            b.total_ns.total_cmp(&a.total_ns).then_with(|| {
                (&a.service, &a.host, &a.version, &a.phase)
                    .cmp(&(&b.service, &b.host, &b.version, &b.phase))
            })
        });
        phases.truncate(DISPLAY_GROUPS);
        Ok(phases)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merged_distribution_preserves_count_and_uses_global_ranks() -> Result<()> {
        let mut groups = PhaseGroups::default();
        groups.add(serde_json::from_str(r#"{"name":"compile","count":"90","total":"900","minimum":"10","maximum":"10","bins":"[{\"vmrange\":\"9...11\",\"hits\":90}]"}"#)?)?;
        groups.add(serde_json::from_str(r#"{"name":"compile","count":"10","total":"1000","minimum":"100","maximum":"100","bins":"[{\"vmrange\":\"99...110\",\"hits\":10}]"}"#)?)?;
        let rows = groups.finish()?;
        let row = &rows[0];
        assert_eq!(row.count, 100);
        assert_eq!(row.total_ns, 1900.0);
        assert_eq!(row.p50_ns, 11.0);
        assert_eq!(row.p95_ns, 100.0);
        assert_eq!(row.p99_ns, 100.0);
        Ok(())
    }

    #[test]
    fn incomplete_bucket_counts_are_rejected() -> Result<()> {
        let mut groups = PhaseGroups::default();
        let row = serde_json::from_str(
            r#"{"count":"2","total":"10","minimum":"5","maximum":"5","bins":"[{\"vmrange\":\"4...6\",\"hits\":1}]"}"#,
        )?;
        assert!(groups.add(row).is_err());
        Ok(())
    }
}
