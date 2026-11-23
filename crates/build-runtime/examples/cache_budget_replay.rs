//! Read native_cas_replay JSONL tree_access records from standard input and
//! compare cache capacity budgets with a deduplicated LRU baseline.
//!
//! Usage: cargo run -p sccache-build --example cache_budget_replay -- 1073741824 4294967296
//! Input may contain journal/syslog prefixes: only JSON tree_access events
//! are considered, and other log lines are ignored.
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::{self, BufRead},
};

use anyhow::{Context, Result, ensure};
use sccache_build::{BlobRef, ContentId, TreeId};
use serde::Deserialize;

#[derive(Deserialize)]
struct TreeAccess {
    tree: TreeId,
    blobs: Vec<BlobRef>,
}

struct Budget {
    max: u64,
    target: u64,
    cached: BTreeMap<TreeId, Vec<BlobRef>>,
    content: BTreeMap<ContentId, (u64, usize)>,
    order: VecDeque<TreeId>,
    resident: u64,
    peak: u64,
    requests: u64,
    hits: u64,
    downloaded: u128,
    evictions: u64,
}

impl Budget {
    fn new(max: u64) -> Self {
        Self {
            max,
            target: max.saturating_mul(3) / 4,
            cached: BTreeMap::new(),
            content: BTreeMap::new(),
            order: VecDeque::new(),
            resident: 0,
            peak: 0,
            requests: 0,
            hits: 0,
            downloaded: 0,
            evictions: 0,
        }
    }

    fn eviction(&mut self) -> Result<()> {
        let old = self.order.pop_front().context("missing cached LRU root")?;
        let blobs = self.cached.remove(&old).context("missing cached tree")?;
        for blob in blobs {
            let (size, count) = self
                .content
                .get_mut(&blob.id)
                .context("missing retained content")?;
            ensure!(*size == blob.size && *count > 0, "invalid reference count");
            *count -= 1;
            if *count == 0 {
                self.resident = self
                    .resident
                    .checked_sub(blob.size)
                    .context("resident accounting underflow")?;
                self.content.remove(&blob.id);
            }
        }
        self.evictions += 1;
        Ok(())
    }

    fn access(&mut self, event: &TreeAccess) -> Result<()> {
        self.requests += 1;
        let blobs = unique(&event.blobs)?;
        if let Some(existing) = self.cached.get(&event.tree) {
            ensure!(
                *existing == blobs,
                "tree identifier has conflicting content"
            );
            self.hits += 1;
            self.order.retain(|root| root != &event.tree);
            self.order.push_back(event.tree);
            return Ok(());
        }

        let standalone = blobs.iter().try_fold(0_u64, |sum, blob| {
            sum.checked_add(blob.size)
                .context("tree byte-size overflow")
        })?;
        if standalone > self.max {
            // A single tree larger than the budget cannot be retained. It
            // may still reuse individual blobs already owned by other trees.
            self.downloaded += blobs
                .iter()
                .filter(|blob| !self.content.contains_key(&blob.id))
                .map(|blob| u128::from(blob.size))
                .sum::<u128>();
            return Ok(());
        }

        // Admission estimates incoming unique content; evict oldest roots
        // until the resulting store fits its 75%-of-max hysteresis target.
        let mut missing = self.missing_bytes(&blobs)?;
        if self.resident.saturating_add(missing) > self.max {
            while !self.order.is_empty() && self.resident.saturating_add(missing) > self.target {
                self.eviction()?;
                missing = self.missing_bytes(&blobs)?;
            }
        }
        ensure!(
            self.resident.saturating_add(missing) <= self.max,
            "budget cannot admit valid tree"
        );
        self.downloaded += u128::from(missing);
        for blob in &blobs {
            match self.content.get_mut(&blob.id) {
                Some((size, count)) => {
                    ensure!(*size == blob.size, "conflicting content length");
                    *count = count.checked_add(1).context("reference count overflow")?;
                }
                None => {
                    self.content.insert(blob.id, (blob.size, 1));
                    self.resident += blob.size;
                }
            }
        }
        self.cached.insert(event.tree, blobs);
        self.order.push_back(event.tree);
        self.peak = self.peak.max(self.resident);
        Ok(())
    }

    fn missing_bytes(&self, blobs: &[BlobRef]) -> Result<u64> {
        blobs
            .iter()
            .filter(|blob| !self.content.contains_key(&blob.id))
            .try_fold(0_u64, |sum, blob| {
                sum.checked_add(blob.size)
                    .context("additional content length overflow")
            })
    }
}

fn unique(blobs: &[BlobRef]) -> Result<Vec<BlobRef>> {
    let mut map = BTreeMap::new();
    for blob in blobs {
        if let Some(size) = map.insert(blob.id, blob.size) {
            ensure!(size == blob.size, "inconsistent content lengths");
        }
    }
    Ok(map
        .into_iter()
        .map(|(id, size)| BlobRef { id, size })
        .collect())
}

fn run(budgets: &mut [Budget], lines: impl BufRead) -> Result<u64> {
    let mut events = 0_u64;
    for (line_number, line) in lines.lines().enumerate() {
        let line = line?;
        let Some(start) = line.find('{') else {
            continue;
        };
        let payload = &line[start..];
        let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
            continue;
        };
        if value.get("kind").and_then(serde_json::Value::as_str) != Some("tree_access") {
            continue;
        }
        let event: TreeAccess = serde_json::from_value(value)
            .with_context(|| format!("invalid tree_access at line {}", line_number + 1))?;
        for budget in budgets.iter_mut() {
            budget.access(&event)?;
        }
        events += 1;
    }
    Ok(events)
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        !args.is_empty(),
        "supply one or more cache budgets in bytes"
    );
    let mut sizes = BTreeSet::new();
    for arg in args {
        let budget = arg.parse::<u64>().context("invalid byte budget")?;
        ensure!(budget > 0, "cache budget must be positive");
        sizes.insert(budget);
    }
    let mut budgets = sizes.into_iter().map(Budget::new).collect::<Vec<_>>();
    let events = run(&mut budgets, io::stdin().lock())?;
    ensure!(events > 0, "no native tree_access events in input");
    println!("budget_bytes\trequests\thits\thit_pct\tdownload_bytes\tevictions\tpeak_bytes");
    for budget in budgets {
        println!(
            "{}\t{}\t{}\t{:.1}\t{}\t{}\t{}",
            budget.max,
            budget.requests,
            budget.hits,
            (budget.hits as f64 * 100.0) / budget.requests as f64,
            budget.downloaded,
            budget.evictions,
            budget.peak
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(tree: u8, blobs: &[(u8, u64)]) -> TreeAccess {
        TreeAccess {
            tree: TreeId([tree; 32]),
            blobs: blobs
                .iter()
                .map(|&(id, size)| BlobRef {
                    id: ContentId([id; 32]),
                    size,
                })
                .collect(),
        }
    }

    #[test]
    fn shared_blob_survives_root_eviction_and_needs_no_retransfer() -> Result<()> {
        let mut cache = Budget::new(100);
        cache.access(&event(1, &[(1, 30), (2, 45)]))?;
        cache.access(&event(2, &[(1, 30), (3, 5)]))?;
        assert_eq!(cache.downloaded, 80);
        cache.access(&event(3, &[(1, 30), (4, 25)]))?;
        assert_eq!(cache.downloaded, 105);
        assert!(!cache.cached.contains_key(&TreeId([1; 32])));
        assert!(cache.content.contains_key(&ContentId([1; 32])));
        assert!(cache.cached.contains_key(&TreeId([2; 32])));
        cache.access(&event(2, &[(1, 30), (3, 5)]))?;
        assert_eq!(cache.downloaded, 105);
        assert_eq!(cache.hits, 1);
        assert!(cache.resident <= cache.max);
        Ok(())
    }

    #[test]
    fn oversized_input_is_streamed_but_not_retained() -> Result<()> {
        let mut cache = Budget::new(10);
        let huge = event(1, &[(1, 100)]);
        cache.access(&huge)?;
        cache.access(&huge)?;
        assert_eq!(cache.downloaded, 200);
        assert_eq!(cache.resident, 0);
        assert_eq!(cache.hits, 0);
        Ok(())
    }

    #[test]
    fn invalid_tree_identity_is_rejected() -> Result<()> {
        let mut cache = Budget::new(100);
        cache.access(&event(1, &[(1, 20)]))?;
        assert!(cache.access(&event(1, &[(2, 20)])).is_err());
        Ok(())
    }

    #[test]
    fn parser_ignores_other_logs_but_rejects_bad_access_events() -> Result<()> {
        let mut cache = vec![Budget::new(100)];
        let mut payload = serde_json::json!({
            "kind":"tree_access",
            "tree":vec![1u8; 32],
            "blobs":[{"id":vec![2u8; 32],"size":16}],
        });
        let log = format!("garbage\nprefix {}\nother log\n", payload);
        assert_eq!(run(&mut cache, log.as_bytes())?, 1);
        assert_eq!(cache[0].downloaded, 16);
        payload["tree"] = serde_json::json!("not a digest");
        assert!(run(&mut cache, format!("{payload}\n").as_bytes()).is_err());
        Ok(())
    }
}
