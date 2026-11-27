//! Bounded cache-distribution summaries shared by producers and the dashboard.
use serde::{Deserialize, Serialize};

/// Durable count of successful new-key publications whose artifacts were
/// already known under a different action. Complete results include diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateMisses {
    pub new_keys: u64,
    pub identical_outputs: u64,
    pub identical_results: u64,
}

/// All byte counts refer to distinct content, not references to it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheWeight {
    pub objects: u64,
    pub logical_bytes: u64,
    pub stored_bytes: u64,
    pub allocated_bytes: u64,
    pub measured_objects: u64,
    pub measured_logical_bytes: u64,
    pub touches: u128,
    pub byte_touches: u128,
}

impl CacheWeight {
    pub const fn add(&mut self, other: &Self) {
        self.objects = self.objects.saturating_add(other.objects);
        self.logical_bytes = self.logical_bytes.saturating_add(other.logical_bytes);
        self.stored_bytes = self.stored_bytes.saturating_add(other.stored_bytes);
        self.allocated_bytes = self.allocated_bytes.saturating_add(other.allocated_bytes);
        self.measured_objects = self.measured_objects.saturating_add(other.measured_objects);
        self.measured_logical_bytes = self
            .measured_logical_bytes
            .saturating_add(other.measured_logical_bytes);
        self.touches = self.touches.saturating_add(other.touches);
        self.byte_touches = self.byte_touches.saturating_add(other.byte_touches);
    }
}

/// Inclusive upper bound; None is the unknown/unobserved category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheBucket {
    pub upper: Option<u64>,
    pub weight: CacheWeight,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheDistribution {
    pub total: CacheWeight,
    pub referenced_bytes: u128,
    pub size: Vec<CacheBucket>,
    pub age_seconds: Vec<CacheBucket>,
    pub frequency: Vec<CacheBucket>,
    pub eviction: EvictionDistribution,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictionDistribution {
    pub pinned_roots: u64,
    pub zero_logical_roots: u64,
    pub unmeasured_physical_roots: u64,
    pub logical: Vec<CacheBucket>,
    pub physical: Vec<CacheBucket>,
}

impl EvictionDistribution {
    /// Record one eligible root using the native eviction score and its independently reclaimable bytes.
    pub fn record(&mut self, utility: u64, logical: u64, allocated: Option<u64>) {
        let weight = CacheWeight {
            objects: 1,
            logical_bytes: logical,
            allocated_bytes: allocated.unwrap_or(0),
            measured_objects: u64::from(allocated.is_some()),
            ..Default::default()
        };
        if logical == 0 {
            self.zero_logical_roots += 1;
        } else {
            insert(
                &mut self.logical,
                Some(log_bucket(eviction_score(utility, logical))),
                &weight,
            );
        }
        if let Some(allocated) = allocated {
            if allocated != 0 {
                insert(
                    &mut self.physical,
                    Some(log_bucket(eviction_score(utility, allocated))),
                    &weight,
                );
            }
        } else {
            self.unmeasured_physical_roots += 1;
        }
    }
}

fn eviction_score(utility: u64, potential: u64) -> u64 {
    u64::try_from(u128::from(utility) * (1 << 20) / u128::from(potential.max(1)))
        .unwrap_or(u64::MAX)
}

impl CacheDistribution {
    /// Record one distinct live cache object and its observed use.
    pub fn record(
        &mut self,
        logical: u64,
        physical: Option<(u64, u64)>,
        references: u64,
        touches: Option<u64>,
        age: Option<u64>,
    ) -> CacheWeight {
        let (stored, allocated) = physical.unwrap_or_default();
        let weight = CacheWeight {
            objects: 1,
            logical_bytes: logical,
            stored_bytes: stored,
            allocated_bytes: allocated,
            measured_objects: u64::from(physical.is_some()),
            measured_logical_bytes: if physical.is_some() { logical } else { 0 },
            touches: u128::from(touches.unwrap_or_default()),
            byte_touches: u128::from(logical) * u128::from(touches.unwrap_or_default()),
        };
        self.total.add(&weight);
        self.referenced_bytes = self
            .referenced_bytes
            .saturating_add(u128::from(logical) * u128::from(references));
        insert(&mut self.size, Some(log_bucket(logical)), &weight);
        insert(&mut self.frequency, touches.map(log_bucket), &weight);
        record_age_bucket(&mut self.age_seconds, age, &weight);
        weight
    }
}

const fn log_bucket(value: u64) -> u64 {
    if value == 0 {
        0
    } else {
        u64::MAX >> value.leading_zeros()
    }
}

fn insert(buckets: &mut Vec<CacheBucket>, upper: Option<u64>, weight: &CacheWeight) {
    match buckets.binary_search_by_key(&upper, |bucket| bucket.upper) {
        Ok(index) => buckets[index].weight.add(weight),
        Err(index) => buckets.insert(
            index,
            CacheBucket {
                upper,
                weight: weight.clone(),
            },
        ),
    }
}

/// Independent observation; a failure is not an empty cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheAnalyticsSample {
    pub sampled_at: u64,
    pub report: Option<CacheDistribution>,
    pub error: Option<String>,
    pub maximum_bytes: Option<u64>,
}

/// Compact fleet heartbeat projection. Full histograms stay local to the
/// scheduler analytics feed; placement never needs to copy them per job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheSiteSummary {
    pub sampled_at: u64,
    pub maximum_bytes: Option<u64>,
    pub total: Option<CacheWeight>,
    pub referenced_bytes: u128,
    pub older_than_seven_days: u64,
    pub older_than_thirty_days: u64,
    pub older_than_ninety_days: u64,
    pub unknown_age_bytes: u64,
}

impl CacheAnalyticsSample {
    #[must_use = "the summary reports fleet cache usage"]
    pub fn site_summary(self) -> CacheSiteSummary {
        let mut summary = CacheSiteSummary {
            sampled_at: self.sampled_at,
            maximum_bytes: self.maximum_bytes,
            total: None,
            referenced_bytes: 0,
            older_than_seven_days: 0,
            older_than_thirty_days: 0,
            older_than_ninety_days: 0,
            unknown_age_bytes: 0,
        };
        if let Some(report) = self.report {
            for bucket in report.age_seconds {
                let bytes = bucket.weight.logical_bytes;
                if let Some(upper) = bucket.upper {
                    if upper > 604_800 {
                        summary.older_than_seven_days =
                            summary.older_than_seven_days.saturating_add(bytes);
                    }
                    if upper > 2_592_000 {
                        summary.older_than_thirty_days =
                            summary.older_than_thirty_days.saturating_add(bytes);
                    }
                    if upper > 7_776_000 {
                        summary.older_than_ninety_days =
                            summary.older_than_ninety_days.saturating_add(bytes);
                    }
                } else {
                    summary.unknown_age_bytes = summary.unknown_age_bytes.saturating_add(bytes);
                }
            }
            summary.total = Some(report.total);
            summary.referenced_bytes = report.referenced_bytes;
        }
        summary
    }
}

/// Serialized object-byte accounting for object-store and legacy disk tiers.
///
/// Heat is a decaying milli-hit score, never a count of requests. Only the
/// managed tier supplies policy age.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierCacheReport {
    pub sampled_at: u64,
    pub managed_heat: bool,
    pub distribution: CacheDistribution,
    pub policy_age: Vec<CacheBucket>,
}

pub const AGE_UPPER_BOUNDS: [u64; 7] = [
    3600,
    86_400,
    604_800,
    2_592_000,
    7_776_000,
    31_536_000,
    u64::MAX,
];

pub fn record_age_bucket(buckets: &mut Vec<CacheBucket>, age: Option<u64>, weight: &CacheWeight) {
    let upper = age.map(|age| {
        AGE_UPPER_BOUNDS
            .into_iter()
            .find(|&bound| age <= bound)
            .unwrap_or(u64::MAX)
    });
    insert(buckets, upper, weight);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_bytes_and_unknown_usage_are_distinct() {
        let mut report = CacheDistribution::default();
        report.record(10, None, 1, Some(3), Some(86_400));
        report.record(20, None, 1, Some(1), Some(604_801));
        report.record(30, None, 1, Some(0), Some(7_776_001));
        report.record(40, None, 1, None, None);
        assert_eq!(report.frequency[0].upper, None);
        assert_eq!(report.frequency[0].weight.logical_bytes, 40);
        let sample = CacheAnalyticsSample {
            sampled_at: 42,
            report: Some(report),
            error: None,
            maximum_bytes: Some(1000),
        };
        let bytes = bincode::serialize(&sample).unwrap();
        let restored: CacheAnalyticsSample = bincode::deserialize(&bytes).unwrap();
        assert_eq!(restored, sample);
        let summary = restored.site_summary();
        assert_eq!(summary.older_than_seven_days, 50);
        assert_eq!(summary.older_than_thirty_days, 30);
        assert_eq!(summary.older_than_ninety_days, 30);
        assert_eq!(summary.unknown_age_bytes, 40);
    }

    #[test]
    fn histogram_weights_are_additive_and_unknown_is_distinct() {
        let mut report = CacheDistribution::default();
        report.record(10, Some((5, 8)), 3, Some(4), Some(100));
        report.record(40, None, 1, Some(0), None);
        assert_eq!(report.total.logical_bytes, 50);
        assert_eq!(report.total.measured_objects, 1);
        assert_eq!(report.referenced_bytes, 70);
        assert_eq!(report.total.byte_touches, 40);
        assert_eq!(report.age_seconds[0].upper, None);
        assert_eq!(report.frequency[0].upper, Some(0));
        for buckets in [&report.age_seconds, &report.size, &report.frequency] {
            let mut total = CacheWeight::default();
            for bucket in buckets {
                total.add(&bucket.weight);
            }
            assert_eq!(total, report.total);
        }
    }
}
