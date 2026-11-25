//! Read-only distinct-blob accounting. Never hold the mutation lock or invoke
//! eviction while inspecting the store.
use super::*;
use crate::analytics::CacheDistribution;

#[derive(Default)]
struct RootSummary {
    usage: Option<UsageRecord>,
    bytes: u64,
    logical: u64,
    allocated: u64,
    pinned: bool,
    unmeasured: bool,
}

impl NativeStore {
    /// Summarize live blobs using one index snapshot and current root touches.
    ///
    /// A blob shared by multiple roots occupies storage once. Its observed
    /// reuse is the sum of distinct referencing root touches, not network
    /// traffic. Publications also touch roots; these are not cache-hit counts.
    /// Filesystem metadata is sampled best-effort because GC can race the read.
    ///
    /// # Errors
    /// Returns an error on inconsistent index metadata or a database failure.
    pub fn cache_distribution(&self) -> Result<CacheDistribution> {
        let read = self.inner.db.begin_read()?;
        let blobs = read.open_table(super::super::BLOBS)?;
        let owners = read.open_multimap_table(BLOB_ROOTS)?;
        let results = read.open_table(RESULTS)?;
        let aliases = read.open_multimap_table(RESULT_ACTIONS)?;
        let trees = read.open_table(TREES)?;
        let packages = read.open_table(PACKAGES)?;
        let observed = now_ms();
        let mut report = CacheDistribution::default();
        let mut root_summaries = BTreeMap::<Root, RootSummary>::new();
        for entry in blobs.iter()? {
            let (id, size) = entry?;
            let id = ContentId(*id.value());
            let logical = size.value();
            let mut roots = BTreeSet::new();
            for owner in owners.get(&id.0)? {
                let owner = *owner?.value();
                if results.get(&owner)?.is_some() {
                    for action in aliases.get(&owner)? {
                        roots.insert(Root::Action(ActionKey(*action?.value())));
                    }
                } else if trees.get(&owner)?.is_some() {
                    roots.insert(Root::Tree(TreeId(owner)));
                } else if let Some(package) = packages.get(&owner)? {
                    let package: PackageRecord = encoding().deserialize(package.value())?;
                    roots.insert(Root::Tree(package.tree));
                } else {
                    return Err(anyhow!("unknown native blob owner"));
                }
            }
            ensure!(!roots.is_empty(), "live blob has no referencing root");
            let physical = std::fs::metadata(self.inner.blob_path(id))
                .ok()
                .filter(std::fs::Metadata::is_file)
                .map(|metadata| (metadata.len(), metadata.blocks().saturating_mul(512)));
            let mut usage = UsageRecord::default();
            {
                let pins = self.inner.lock_pins()?;
                let reclaimable = roots.len() == 1 && !pins.blobs.contains_key(&id);
                for root in &roots {
                    let summary = root_summaries.entry(*root).or_insert_with(|| RootSummary {
                        usage: pins.usage.get(root).copied(),
                        pinned: match root {
                            Root::Action(action) => pins.actions.contains_key(action),
                            Root::Tree(tree) => pins.trees.contains_key(tree),
                        },
                        ..Default::default()
                    });
                    summary.bytes = summary.bytes.saturating_add(logical);
                    if reclaimable {
                        summary.logical = summary.logical.saturating_add(logical);
                        if let Some((_, allocated)) = physical {
                            summary.allocated = summary.allocated.saturating_add(allocated);
                        } else {
                            summary.unmeasured = true;
                        }
                    }
                    if let Some(record) = summary.usage {
                        usage.hits = usage.hits.saturating_add(record.hits);
                        usage.last_used_ms = usage.last_used_ms.max(record.last_used_ms);
                    }
                }
            }
            let age = (usage.last_used_ms != 0)
                .then(|| observed.saturating_sub(usage.last_used_ms) / 1000);
            report.record(
                logical,
                physical,
                u64::try_from(roots.len())?,
                (usage.last_used_ms != 0).then_some(usage.hits),
                age,
            );
        }
        for summary in root_summaries.values() {
            if summary.pinned {
                report.eviction.pinned_roots += 1;
                continue;
            }
            let utility = reuse_utility(summary.usage.as_ref(), summary.bytes, observed);
            report.eviction.record(
                utility,
                summary.logical,
                (!summary.unmeasured).then_some(summary.allocated),
            );
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActionFingerprint, ActionMode, Artifact};
    use std::io::Cursor;

    #[test]
    fn shared_result_is_counted_once_with_all_action_touches() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = NativeStore::open(temp.path())?;
        let stage = store.stage(Cursor::new(b"same"))?;
        let manifest = ResultManifest {
            outputs: BTreeMap::from([(
                "out".into(),
                Artifact::File {
                    blob: stage.reference(),
                    mode: None,
                },
            )]),
            stdout: None,
            stderr: None,
        };
        let fingerprint = |name: &[u8]| ActionFingerprint {
            schema: "analytics".into(),
            components: BTreeMap::from([("name".into(), ContentId::of(name))]),
        };
        let first = store.publish(
            &fingerprint(b"a"),
            &manifest,
            vec![stage],
            ActionMode::Reuse,
        )?;
        store.publish(&fingerprint(b"b"), &manifest, vec![], ActionMode::Reuse)?;
        let _lease = store.lookup(first.action)?.context("missing result")?;
        let report = store.cache_distribution()?;
        assert_eq!(report.total.objects, 1);
        assert_eq!(report.total.logical_bytes, 4);
        assert_eq!(report.referenced_bytes, 8);
        assert_eq!(report.total.touches, 3);
        assert_eq!(report.total.byte_touches, 12);
        assert_eq!(report.total.measured_objects, 1);
        assert_eq!(
            report.eviction.pinned_roots + report.eviction.zero_logical_roots,
            2
        );
        assert!(report.eviction.logical.is_empty());
        drop(_lease);
        let report = store.cache_distribution()?;
        assert_eq!(report.eviction.pinned_roots, 0);
        assert_eq!(report.eviction.zero_logical_roots, 2);
        Ok(())
    }
}

/// Keeps an expensive analytics scan off scheduler and worker heartbeat paths.
pub struct CacheAnalyticsSampler {
    receiver: std::sync::mpsc::Receiver<crate::analytics::CacheAnalyticsSample>,
    stop: std::sync::mpsc::Sender<()>,
}

impl CacheAnalyticsSampler {
    #[must_use]
    pub fn poll(&self) -> Option<crate::analytics::CacheAnalyticsSample> {
        self.receiver.try_recv().ok()
    }
}

impl Drop for CacheAnalyticsSampler {
    fn drop(&mut self) {
        let _ = self.stop.send(());
    }
}

impl NativeStore {
    /// Start a single independent cache-analytics producer for this daemon.
    ///
    /// # Errors
    /// Returns an error if the sampler thread cannot be created.
    pub fn analytics_sampler(&self) -> Result<CacheAnalyticsSampler> {
        use std::sync::mpsc;
        let store = self.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let (stop, stopping) = mpsc::channel();
        std::thread::Builder::new()
            .name("native-cache-analytics".into())
            .spawn(move || {
                loop {
                    let sampled_at = now_ms() / 1000;
                    let maximum_bytes = store
                        .inner
                        .space_policy
                        .map(|policy| policy.max_resident_bytes);
                    let (report, error) = match store.cache_distribution() {
                        Ok(report) => (Some(report), None),
                        Err(error) => {
                            log::warn!("native cache analytics snapshot failed: {error:#}");
                            (None, Some("Cache analytics snapshot failed".into()))
                        }
                    };
                    let observation = crate::analytics::CacheAnalyticsSample {
                        sampled_at,
                        report,
                        error,
                        maximum_bytes,
                    };
                    if matches!(
                        sender.try_send(observation),
                        Err(mpsc::TrySendError::Disconnected(_))
                    ) {
                        return;
                    }
                    if !matches!(
                        stopping.recv_timeout(Duration::from_mins(5)),
                        Err(mpsc::RecvTimeoutError::Timeout)
                    ) {
                        return;
                    }
                }
            })?;
        Ok(CacheAnalyticsSampler { receiver, stop })
    }
}
