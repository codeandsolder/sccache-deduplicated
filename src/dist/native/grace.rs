//! A bounded grace tier over the same immutable worker CAS.

use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use crate::build_runtime::{
    ActionFingerprint, ActionMode, CapturedExecution, ContentId, NativeStore, ResultLease,
};

type Contents = BTreeMap<ContentId, u64>;

struct ProtectedResult {
    expires: Instant,
    contents: Contents,
    _lease: ResultLease,
}

#[derive(Default)]
struct State {
    results: VecDeque<ProtectedResult>,
    refs: BTreeMap<ContentId, (u64, usize)>,
    bytes: u64,
}

impl State {
    fn release(&mut self, contents: &Contents) {
        for id in contents.keys() {
            if let Entry::Occupied(mut entry) = self.refs.entry(*id) {
                let (size, count) = entry.get_mut();
                *count -= 1;
                if *count == 0 {
                    self.bytes -= *size;
                    entry.remove();
                }
            }
        }
    }

    fn reap(&mut self, now: Instant) -> Vec<ProtectedResult> {
        let mut expired = Vec::new();
        while self
            .results
            .front()
            .is_some_and(|entry| entry.expires <= now)
        {
            if let Some(entry) = self.results.pop_front() {
                self.release(&entry.contents);
                expired.push(entry);
            }
        }
        expired
    }

    fn additional(&self, contents: &Contents) -> Result<u64> {
        contents.iter().try_fold(0_u64, |sum, (&id, &size)| {
            if let Some(&(previous, count)) = self.refs.get(&id) {
                ensure!(
                    previous == size && count < usize::MAX,
                    "invalid grace content accounting"
                );
                Ok(sum)
            } else {
                sum.checked_add(size).context("grace bytes overflow")
            }
        })
    }
}

/// Logical grace budget over actual unique result bytes. Existing leases
/// are never evicted early, but a full optional tier cannot delay a build.
#[derive(Clone)]
pub struct ArtifactGrace {
    duration: Duration,
    max_bytes: u64,
    state: Arc<Mutex<State>>,
}

impl ArtifactGrace {
    /// # Errors
    /// Rejects unusable lifetime or storage bounds.
    pub fn new(duration: Duration, max_bytes: u64) -> Result<Self> {
        ensure!(
            !duration.is_zero() && Instant::now().checked_add(duration).is_some() && max_bytes > 0,
            "invalid worker artifact grace policy"
        );
        Ok(Self {
            duration,
            max_bytes,
            state: Arc::new(Mutex::new(State::default())),
        })
    }

    /// Expiry releases only grace leases, not consumer input leases.
    pub fn reap(&self) {
        self.with_reaped(|_| ());
    }

    fn with_reaped<R>(&self, operation: impl FnOnce(&mut State) -> R) -> R {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let expired = state.reap(Instant::now());
        let result = operation(&mut state);
        drop(state);
        // Release CAS pins outside the grace mutex.
        drop(expired);
        result
    }

    fn fits(&self, contents: &Contents) -> Result<bool> {
        self.with_reaped(|state| Ok(state.additional(contents)? <= self.max_bytes - state.bytes))
    }

    fn try_commit(&self, lease: ResultLease) -> Result<Option<Instant>> {
        let contents = lease.manifest().blobs()?;
        let mut lease = Some(lease);
        self.with_reaped(|state| {
            let additional = state.additional(&contents)?;
            if additional > self.max_bytes - state.bytes {
                return Ok(None);
            }
            let expires = Instant::now()
                .checked_add(self.duration)
                .context("grace deadline overflow")?;
            for (&id, &size) in &contents {
                state.refs.entry(id).or_insert((size, 0)).1 += 1;
            }
            state.bytes += additional;
            state.results.push_back(ProtectedResult {
                expires,
                contents,
                _lease: lease.take().context("missing grace lease")?,
            });
            Ok(Some(expires))
        })
    }

    pub(super) async fn retain(
        &self,
        store: NativeStore,
        fingerprint: ActionFingerprint,
        captured: &mut CapturedExecution,
    ) -> Result<Option<RetainedOutput>> {
        let manifest = captured
            .successful_result()
            .context("failed execution cannot be retained")?;
        if manifest.outputs.is_empty()
            || !captured.can_retain()
            || !self.fits(&manifest.blobs()?)?
        {
            return Ok(None);
        }
        let manifest = manifest.clone();
        let staging_store = store.clone();
        let (manifest, existing, warm) = tokio::task::spawn_blocking(move || {
            let existing = staging_store.reserve_upload(&manifest)?;
            let warm = existing.missing().is_empty();
            Ok::<_, anyhow::Error>((manifest, existing, warm))
        })
        .await??;
        let staged = captured.seal_staged(existing.missing()).await?;
        let lease = store
            .publish_pinned_async(fingerprint, manifest, staged, ActionMode::Refresh, existing)
            .await?;
        Ok(self
            .try_commit(lease)?
            .map(|deadline| RetainedOutput { deadline, warm }))
    }
}

pub(super) struct RetainedOutput {
    pub deadline: Instant,
    pub warm: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_runtime::{Artifact, BlobRef, Eviction, ResultManifest};

    fn result(
        store: &NativeStore,
        bytes: &[u8],
        marker: &[u8],
    ) -> Result<(ActionFingerprint, ResultLease)> {
        let blob = BlobRef {
            id: ContentId::of(bytes),
            size: u64::try_from(bytes.len())?,
        };
        let manifest = ResultManifest {
            outputs: BTreeMap::from([("obj".into(), Artifact::File { blob, mode: None })]),
            stdout: None,
            stderr: None,
        };
        let fingerprint = ActionFingerprint {
            schema: "test".into(),
            components: BTreeMap::from([("marker".into(), ContentId::of(marker))]),
        };
        let lease = store.publish_pinned(
            &fingerprint,
            &manifest,
            vec![store.stage_expected(blob, bytes)?],
            ActionMode::Refresh,
        )?;
        Ok((fingerprint, lease))
    }

    #[test]
    fn full_grace_declines_new_content_without_waiting_or_evicting_protected_results() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let pool = ArtifactGrace::new(Duration::from_secs(300), 8)?;
        let (first, lease) = result(&store, b"12345678", b"a")?;
        assert!(pool.try_commit(lease)?.is_some());
        let (second, lease) = result(&store, b"abcdefgh", b"b")?;
        assert!(!pool.fits(&lease.manifest().blobs()?)?);
        assert!(pool.try_commit(lease)?.is_none());
        assert_eq!(store.evict(first.key()?)?, Eviction::Pinned);
        assert!(matches!(
            store.evict(second.key()?)?,
            Eviction::Removed { .. }
        ));
        // A duplicate consumes zero additional bytes even when full.
        let (duplicate, lease) = result(&store, b"12345678", b"c")?;
        assert!(pool.try_commit(lease)?.is_some());
        let mut state = pool.state.lock().unwrap();
        assert_eq!(state.bytes, 8);
        assert_eq!(state.results.len(), 2);
        let expired = state.reap(Instant::now() + Duration::from_secs(301));
        assert_eq!(state.bytes, 0);
        drop(state);
        drop(expired);
        assert!(matches!(
            store.evict(first.key()?)?,
            Eviction::Removed { .. }
        ));
        assert!(matches!(
            store.evict(duplicate.key()?)?,
            Eviction::Removed { .. }
        ));
        Ok(())
    }
}
