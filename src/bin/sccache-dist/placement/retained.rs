//! Short-lived residency hints from authenticated native publication.
//! The worker's real grace and consumer leases, not this index, own the bytes.

use sccache::build_runtime::{ContentId, ResultManifest};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

const MAX_BLOBS: usize = 8192;
const MAX_INPUT_BLOBS: usize = 65_536;
const INPUT_LIFETIME: Duration = Duration::from_secs(20);
const MAX_LIFETIME: Duration = Duration::from_mins(30);

#[derive(Default)]
struct ExpiringBlobs {
    blobs: BTreeMap<ContentId, (u64, Instant)>,
    expiry: BTreeSet<(Instant, ContentId)>,
}

impl ExpiringBlobs {
    fn contains(&self, id: ContentId, bytes: u64, now: Instant) -> bool {
        self.blobs
            .get(&id)
            .is_some_and(|&(size, expires)| size == bytes && expires > now)
    }

    fn reap(&mut self, now: Instant) {
        while self
            .expiry
            .first()
            .is_some_and(|(expires, _)| *expires <= now)
        {
            if let Some((_, id)) = self.expiry.pop_first() {
                self.blobs.remove(&id);
            }
        }
    }

    fn record(
        &mut self,
        blobs: impl IntoIterator<Item = (ContentId, u64)>,
        expires: Instant,
        now: Instant,
        limit: usize,
    ) {
        self.reap(now);
        if expires <= now {
            return;
        }
        for (id, size) in blobs {
            if let Some(&(previous_size, previous_expiry)) = self.blobs.get(&id) {
                // A duplicate digest can refresh only its existing extent.
                if previous_size != size || previous_expiry >= expires {
                    continue;
                }
                self.expiry.remove(&(previous_expiry, id));
            }
            self.blobs.insert(id, (size, expires));
            self.expiry.insert((expires, id));
            if self.blobs.len() > limit
                && let Some((_, id)) = self.expiry.pop_first()
            {
                self.blobs.remove(&id);
            }
        }
    }
}

/// The two evidence sources have different lifetimes and strength.
/// Acquired inputs were verified and pinned at publication, but may be
/// evicted after the job releases its leases. They bridge the heartbeat
/// inventory refresh interval, not the artifact-grace period.
#[derive(Default)]
pub struct RecentResidency {
    retained: ExpiringBlobs,
    acquired: ExpiringBlobs,
}

impl RecentResidency {
    pub(crate) fn contains(&self, id: ContentId, bytes: u64, now: Instant) -> bool {
        self.retained.contains(id, bytes, now) || self.acquired.contains(id, bytes, now)
    }

    pub(crate) fn retained(&self, id: ContentId, bytes: u64, now: Instant) -> bool {
        self.retained.contains(id, bytes, now)
    }

    pub(crate) fn reap(&mut self, now: Instant) {
        self.retained.reap(now);
        self.acquired.reap(now);
    }

    pub(crate) fn record(
        &mut self,
        manifest: &ResultManifest,
        anchor: Instant,
        retained_after_begin: Duration,
        now: Instant,
    ) -> anyhow::Result<()> {
        if let Some(expires) = anchor.checked_add(retained_after_begin.min(MAX_LIFETIME)) {
            self.retained
                .record(manifest.blobs()?, expires, now, MAX_BLOBS);
        }
        Ok(())
    }

    pub(crate) fn record_inputs(&mut self, inputs: &sccache::dist::NativeInputBlobs, now: Instant) {
        if let Some(expires) = now.checked_add(INPUT_LIFETIME) {
            self.acquired.record(
                inputs.iter().map(|(&id, &size)| (id, size)),
                expires,
                now,
                MAX_INPUT_BLOBS,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccache::build_runtime::{Artifact, BlobRef};

    fn manifest(blob: BlobRef) -> ResultManifest {
        ResultManifest {
            outputs: BTreeMap::from([("result".into(), Artifact::File { blob, mode: None })]),
            stdout: None,
            stderr: None,
        }
    }

    #[test]
    fn native_recent_acquired_inputs_have_independent_expiry_and_capacity() {
        let now = Instant::now();
        let blob = ContentId::of(b"input");
        let mut recent = RecentResidency::default();
        recent.record_inputs(&BTreeMap::from([(blob, 5)]), now);
        assert!(recent.contains(blob, 5, now));
        assert!(!recent.retained(blob, 5, now));
        assert!(!recent.contains(blob, 6, now));
        assert!(!recent.contains(blob, 5, now + INPUT_LIFETIME));
        recent.reap(now + INPUT_LIFETIME);
        assert!(recent.acquired.blobs.is_empty());
        assert!(recent.acquired.expiry.is_empty());
    }

    #[test]
    fn native_retained_outputs_expire_from_negotiation_not_commit_time() -> anyhow::Result<()> {
        let now = Instant::now();
        let blob = BlobRef {
            id: ContentId::of(b"result"),
            size: 6,
        };
        let manifest = manifest(blob);
        let mut outputs = RecentResidency::default();
        let grace = Duration::from_secs(300);
        let committed = now + Duration::from_secs(120);
        outputs.record(&manifest, now, grace, committed)?;
        assert!(outputs.contains(blob.id, blob.size, committed));
        assert!(!outputs.contains(blob.id, blob.size + 1, committed));
        // A repeated commit cannot extend the original deadline.
        outputs.record(&manifest, now, grace, now + Duration::from_secs(240))?;
        assert!(outputs.contains(blob.id, blob.size, now + Duration::from_secs(299)));
        assert!(!outputs.contains(blob.id, blob.size, now + grace));
        outputs.reap(now + grace);
        assert!(outputs.retained.blobs.is_empty());
        assert!(outputs.retained.expiry.is_empty());
        outputs.record(&manifest, now, grace, now + grace)?;
        assert!(outputs.retained.blobs.is_empty());
        Ok(())
    }

    #[test]
    fn native_retained_outputs_keep_longest_pin_and_bound_metadata() -> anyhow::Result<()> {
        let now = Instant::now();
        let blob = BlobRef {
            id: ContentId::of(b"result"),
            size: 6,
        };
        let manifest = manifest(blob);
        let mut outputs = RecentResidency::default();
        outputs.record(&manifest, now, Duration::from_secs(10), now)?;
        outputs.record(
            &manifest,
            now + Duration::from_secs(2),
            Duration::from_secs(20),
            now + Duration::from_secs(2),
        )?;
        outputs.record(&manifest, now, Duration::from_secs(5), now)?;
        assert_eq!(outputs.retained.expiry.len(), 1);
        assert!(outputs.contains(blob.id, blob.size, now + Duration::from_secs(21)));
        let mut large = ResultManifest {
            outputs: BTreeMap::new(),
            stdout: None,
            stderr: None,
        };
        for n in 0..=MAX_BLOBS {
            large.outputs.insert(
                n.to_string(),
                Artifact::File {
                    blob: BlobRef {
                        id: ContentId::of(&n.to_le_bytes()),
                        size: 1,
                    },
                    mode: None,
                },
            );
        }
        outputs.record(&large, now, Duration::from_secs(60), now)?;
        assert_eq!(outputs.retained.blobs.len(), MAX_BLOBS);
        assert_eq!(outputs.retained.expiry.len(), MAX_BLOBS);
        assert!(!outputs.contains(blob.id, blob.size, now));
        Ok(())
    }
}
