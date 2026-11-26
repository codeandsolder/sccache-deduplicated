// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Byte-weighted LRU eviction over the shared lru implementation.
//! Ordinary count-limited caches use lru directly.
use std::{borrow::Borrow, collections::hash_map::RandomState, fmt, hash::Hash};

/// Measure the weight of an owned cache entry.
pub trait Meter<K, V> {
    /// Return the weight of an entry in bytes or another fixed unit.
    fn measure(&self, key: &K, value: &V) -> u64;
}

/// A weight-bounded cache with immutable values and exact u64 accounting.
///
/// The underlying cache is unbounded by *count*, so only this type decides
/// which entries to evict. In particular, an oversized entry cannot silently
/// overflow the byte counter, including on 32-bit targets.
pub struct WeightedLru<K, V, M> {
    entries: lru::LruCache<K, (V, u64), RandomState>,
    size: u64,
    capacity: u64,
    meter: M,
}

impl<K: Hash + Eq, V, M: Meter<K, V>> WeightedLru<K, V, M> {
    /// Create an empty weighted cache with the given maximum total weight.
    pub fn new(capacity: u64, meter: M) -> Self {
        Self {
            entries: lru::LruCache::unbounded_with_hasher(RandomState::new()),
            size: 0,
            capacity,
            meter,
        }
    }

    /// Maximum total weight.
    pub const fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Total weight of currently retained entries.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Number of retained entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entries remain.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over entries without changing their recency or accounting.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(key, (value, _))| (key, value))
    }

    /// Check membership without refreshing recency.
    pub fn contains_key<Q: Hash + Eq + ?Sized>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
    {
        self.entries.contains(key)
    }

    /// Read a value and refresh its recency.
    pub fn get<Q: Hash + Eq + ?Sized>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        self.entries.get(key).map(|(value, _)| value)
    }

    /// Insert or replace a value, evicting least-recently-used entries as necessary.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let weight = self.meter.measure(&key, &value);
        let previous = self.remove(&key);
        // Preserve the original policy: an oversized item expires the whole
        // cache, including itself. Disk admission rejects these in advance.
        if weight > self.capacity {
            self.entries.clear();
            self.size = 0;
            return previous;
        }
        // Make room before addition, so the total never overflows u64.
        while self.size > self.capacity - weight {
            let _ = self.remove_lru();
        }
        self.entries.put(key, (value, weight));
        self.size += weight;
        previous
    }

    /// Remove a specific entry and subtract its stored weight.
    pub fn remove<Q: Hash + Eq + ?Sized>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
    {
        let (value, weight) = self.entries.pop(key)?;
        self.size -= weight;
        Some(value)
    }

    /// Remove the oldest entry and subtract its stored weight.
    pub fn remove_lru(&mut self) -> Option<(K, V)> {
        let (key, (value, weight)) = self.entries.pop_lru()?;
        self.size -= weight;
        Some((key, value))
    }
}

impl<K: fmt::Debug + Hash + Eq, V: fmt::Debug, M> fmt::Debug for WeightedLru<K, V, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.entries.iter().map(|(key, (value, _))| (key, value)))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Meter, WeightedLru};
    struct Weight;
    impl<K> Meter<K, u64> for Weight {
        fn measure(&self, _: &K, value: &u64) -> u64 {
            *value
        }
    }

    #[test]
    fn weighted_eviction_and_replacement() {
        let mut cache = WeightedLru::new(5, Weight);
        cache.insert("first", 2);
        cache.insert("second", 2);
        assert_eq!(cache.get("first"), Some(&2));
        cache.insert("third", 2);
        assert!(!cache.contains_key("second"));
        assert_eq!(cache.size(), 4);
        assert_eq!(cache.insert("first", 4), Some(2));
        assert!(!cache.contains_key("third"));
        assert_eq!(cache.size(), 4);
        assert_eq!(cache.remove_lru(), Some(("first", 4)));
        assert!(cache.is_empty());
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn snapshot_preserves_eviction_order_and_weight() {
        let mut cache = WeightedLru::new(5, Weight);
        cache.insert("first", 2);
        cache.insert("second", 3);
        assert_eq!(
            cache.iter().collect::<Vec<_>>(),
            vec![(&"second", &3), (&"first", &2)]
        );
        assert_eq!(cache.size(), 5);
        assert_eq!(cache.remove_lru(), Some(("first", 2)));
        assert_eq!(cache.size(), 3);
    }

    #[test]
    fn full_width_accounting_never_overflows() {
        let mut cache = WeightedLru::new(u64::MAX, Weight);
        cache.insert("large", u64::MAX);
        cache.insert("small", 1);
        assert_eq!(cache.size(), 1);
        assert_eq!(cache.len(), 1);
        cache.insert("large", u64::MAX);
        assert_eq!(cache.size(), u64::MAX);
        assert_eq!(cache.remove("large"), Some(u64::MAX));
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn oversized_and_zero_weight_entries() {
        let mut cache = WeightedLru::new(2, Weight);
        cache.insert("first", 2);
        cache.insert("too large", 3);
        assert!(cache.is_empty());
        assert_eq!(cache.size(), 0);
        let mut cache = WeightedLru::new(0, Weight);
        cache.insert("zero", 0);
        assert_eq!(cache.get("zero"), Some(&0));
        cache.insert("nonzero", 1);
        assert!(cache.is_empty());
    }

    #[test]
    fn borrowed_keys_and_nonrefreshing_membership() {
        let mut cache = WeightedLru::new(2, Weight);
        cache.insert(String::from("old"), 1);
        cache.insert(String::from("new"), 1);
        assert!(cache.contains_key("old"));
        cache.insert(String::from("latest"), 1);
        assert!(!cache.contains_key("old"));
        assert_eq!(cache.remove("new"), Some(1));
        assert_eq!(cache.size(), 1);
    }
}
