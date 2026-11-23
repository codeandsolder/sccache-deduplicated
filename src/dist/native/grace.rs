//! A bounded grace tier over the same immutable worker CAS. Leases keep newly
//! published output content alive without creating another physical store.

use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use crate::build_runtime::{
    ActionFingerprint, ActionMode, CapturedExecution, ContentId, NativeStore, ResultLease,
    ResultManifest,
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

    fn reap(&mut self, now: Instant) {
        while self
            .results
            .front()
            .is_some_and(|entry| entry.expires <= now)
        {
            if let Some(entry) = self.results.pop_front() {
                self.release(&entry.contents);
                drop(entry);
            }
        }
    }
}

/// Logical grace budget, accounting for unique verified content across results.
pub struct ArtifactGrace {
    duration: Duration,
    max_bytes: u64,
    state: Mutex<State>,
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
            state: Mutex::new(State::default()),
        })
    }

    /// Expired artifacts become ordinary eviction candidates. Consumer tree
    /// leases independently protect any content still needed by a job.
    pub fn reap(&self) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reap(Instant::now());
    }

    fn reserve(&self, contents: Contents) -> Result<Option<GraceReservation<'_>>> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.reap(Instant::now());
        let mut additional = 0_u64;
        for (&id, &size) in &contents {
            if let Some(&(previous, count)) = state.refs.get(&id) {
                ensure!(
                    previous == size && count < usize::MAX,
                    "invalid grace content accounting"
                );
            } else {
                additional = additional
                    .checked_add(size)
                    .context("grace bytes overflow")?;
            }
        }
        let bytes = state
            .bytes
            .checked_add(additional)
            .context("grace bytes overflow")?;
        if bytes > self.max_bytes {
            return Ok(None);
        }
        for (&id, &size) in &contents {
            state.refs.entry(id).or_insert((size, 0)).1 += 1;
        }
        state.bytes = bytes;
        drop(state);
        Ok(Some(GraceReservation {
            pool: self,
            contents: Some(contents),
        }))
    }

    pub(super) fn retain(
        &self,
        store: &NativeStore,
        fingerprint: &ActionFingerprint,
        manifest: &ResultManifest,
        captured: &CapturedExecution,
    ) -> Result<bool> {
        if manifest.outputs.is_empty() {
            return Ok(true);
        }
        let Some(grace) = self.reserve(manifest.blobs()?)? else {
            return Ok(false);
        };
        let existing = store.reserve_upload(manifest)?;
        let mut staged = Vec::new();
        for &blob in existing.missing() {
            staged.push(store.stage_expected(blob, captured.open_blob(blob.id)?)?);
        }
        let lease = store.publish_pinned(fingerprint, manifest, staged, ActionMode::Refresh)?;
        grace.commit(lease)?;
        Ok(true)
    }
}

struct GraceReservation<'a> {
    pool: &'a ArtifactGrace,
    contents: Option<Contents>,
}

impl GraceReservation<'_> {
    fn commit(mut self, lease: ResultLease) -> Result<()> {
        let expires = Instant::now()
            .checked_add(self.pool.duration)
            .context("grace deadline overflow")?;
        let mut state = self
            .pool
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let contents = self
            .contents
            .take()
            .context("grace reservation already committed")?;
        // Other publishers can finish in any order. Calculate expiry while
        // holding the queue lock, so its front is always the oldest deadline.
        let expires = state
            .results
            .back()
            .map_or(expires, |last| expires.max(last.expires));
        state.results.push_back(ProtectedResult {
            expires,
            contents,
            _lease: lease,
        });
        drop(state);
        Ok(())
    }
}

impl Drop for GraceReservation<'_> {
    fn drop(&mut self) {
        if let Some(contents) = self.contents.take() {
            self.pool
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .release(&contents);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_runtime::{Artifact, BlobRef, Eviction};

    #[test]
    fn shared_artifacts_charge_once_and_expiry_releases_eviction_pin() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let pool = ArtifactGrace::new(Duration::from_secs(300), 4)?;
        let contents = b"data";
        let blob = BlobRef {
            id: ContentId::of(contents),
            size: 4,
        };
        let manifest = ResultManifest {
            outputs: BTreeMap::from([("obj".into(), Artifact { blob, mode: None })]),
            stdout: None,
            stderr: None,
        };
        let a = ActionFingerprint {
            schema: "test".into(),
            components: BTreeMap::new(),
        };
        let mut b = a.clone();
        b.components.insert("input".into(), ContentId::of(b"other"));
        let first = pool
            .reserve(manifest.blobs()?)?
            .context("first grace reservation")?;
        let lease = store.publish_pinned(
            &a,
            &manifest,
            vec![store.stage_expected(blob, &contents[..])?],
            ActionMode::Reuse,
        )?;
        first.commit(lease)?;
        let second = pool
            .reserve(manifest.blobs()?)?
            .context("shared bytes must not be charged twice")?;
        second.commit(store.publish_pinned(&b, &manifest, Vec::new(), ActionMode::Reuse)?)?;
        assert!(
            pool.reserve(BTreeMap::from([(ContentId::of(b"x"), 1)]))?
                .is_none()
        );
        assert_eq!(store.evict(a.key()?)?, Eviction::Pinned);
        assert_eq!(store.evict(b.key()?)?, Eviction::Pinned);
        let mut state = pool.state.lock().unwrap();
        assert_eq!(state.bytes, 4);
        state.reap(Instant::now() + Duration::from_secs(301));
        assert_eq!(state.bytes, 0);
        drop(state);
        assert!(matches!(store.evict(a.key()?)?, Eviction::Removed { .. }));
        assert!(matches!(store.evict(b.key()?)?, Eviction::Removed { .. }));
        Ok(())
    }
}
