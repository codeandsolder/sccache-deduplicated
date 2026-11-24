use std::time::{Duration, Instant};

/// Reserve the worst-case bytes before issuing a cohort of grants. Failed
/// rounds consume their reservation too; retries cannot bypass the traffic cap.
pub(super) struct Budget {
    capacity: u64,
    available: u64,
    updated: Instant,
}

impl Budget {
    pub(super) const fn new(capacity: u64, now: Instant) -> Self {
        Self {
            capacity,
            available: capacity,
            updated: now,
        }
    }

    pub(super) fn reserve(&mut self, bytes: u64, now: Instant) -> bool {
        let period = Duration::from_hours(1).as_nanos();
        let elapsed = now.saturating_duration_since(self.updated).as_nanos();
        let refill = (elapsed.saturating_mul(u128::from(self.capacity)) / period)
            .min(u128::from(self.capacity));
        let refill = u64::try_from(refill).unwrap_or(self.capacity);
        if refill != 0 {
            self.available = self.available.saturating_add(refill).min(self.capacity);
            self.updated = now;
        }
        if bytes > self.available {
            return false;
        }
        self.available -= bytes;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_rounds_cannot_exhaust_more_than_the_budget() {
        let now = Instant::now();
        let mut budget = Budget::new(1000, now);
        assert!(budget.reserve(750, now));
        assert!(!budget.reserve(300, now));
        assert!(budget.reserve(250, now));
        assert!(!budget.reserve(1, now));
        assert!(budget.reserve(500, now + Duration::from_mins(30)));
        assert!(!budget.reserve(1, now + Duration::from_mins(30)));
    }
}
