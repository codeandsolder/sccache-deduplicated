//! Scheduler-side admission for one compilation per complete action identity.

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use anyhow::{Result, anyhow};

use crate::{
    ActionFingerprint, ActionKey, ActionMode, NativeStore, Published, ResultLease, ResultManifest,
    StagedBlob,
};

/// The scheduler owns both durable cache data and in-flight compilation keys.
///
/// Admission never holds the in-flight lock while accessing storage, and
/// the actual compiler job runs outside both locks. Transport and worker
/// selection belong to the scheduler using this coordinator.
#[derive(Clone)]
pub struct BuildCoordinator {
    inner: Arc<Inner>,
}

struct Inner {
    store: NativeStore,
    running: Mutex<BTreeSet<ActionKey>>,
}

/// The outcome of an action admission request.
pub enum Admission {
    /// Already published result, pinned for delivery.
    Cached(ResultLease),
    /// Another job is producing this exact action. Retry after its completion.
    InFlight,
    /// Exclusive authorization to assign a build for this action.
    Compile(CompilePermit),
}

impl BuildCoordinator {
    #[must_use = "the coordinator owns the store and active compilation state"]
    pub fn new(store: NativeStore) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                running: Mutex::new(BTreeSet::new()),
            }),
        }
    }

    /// Access the same store for package provisioning, verified uploads,
    /// accounting and eviction.
    #[must_use = "the scheduler uses this store for all native content"]
    pub fn store(&self) -> &NativeStore {
        &self.inner.store
    }

    /// Look up an action or reserve its sole active compilation.
    ///
    /// # Errors
    /// Returns an error for an invalid fingerprint or storage failure.
    pub fn admit(&self, fingerprint: ActionFingerprint, mode: ActionMode) -> Result<Admission> {
        let key = fingerprint.key()?;
        if mode == ActionMode::Reuse
            && let Some(result) = self.store().lookup(key)?
        {
            return Ok(Admission::Cached(result));
        }
        {
            let mut running = self
                .inner
                .running
                .lock()
                .map_err(|_| anyhow!("native action admission lock poisoned"))?;
            if !running.insert(key) {
                return Ok(Admission::InFlight);
            }
        }
        let permit = CompilePermit {
            inner: Arc::clone(&self.inner),
            key,
            fingerprint,
            mode,
        };
        // A previous owner can finish between the first lookup and our
        // reservation. Check again after reserving so we never schedule a
        // second build solely because of that race.
        if mode == ActionMode::Reuse
            && let Some(result) = self.store().lookup(key)?
        {
            return Ok(Admission::Cached(result));
        }
        Ok(Admission::Compile(permit))
    }
}

/// Owns an in-flight action until publication, failure, or cancellation.
///
/// The scheduler retains the permit across worker assignment and upload;
/// a dropped permit makes retry possible without a persistent stale lock.
pub struct CompilePermit {
    inner: Arc<Inner>,
    key: ActionKey,
    fingerprint: ActionFingerprint,
    mode: ActionMode,
}

impl CompilePermit {
    #[must_use = "the key identifies the reserved compilation"]
    pub const fn key(&self) -> ActionKey {
        self.key
    }

    /// Publish a successful result under precisely the reserved action key.
    /// A failed commit releases the permit so another job can retry.
    ///
    /// # Errors
    /// Returns an error for invalid results, missing content or storage failure.
    pub fn publish(self, manifest: &ResultManifest, staged: Vec<StagedBlob>) -> Result<Published> {
        self.inner
            .store
            .publish(&self.fingerprint, manifest, staged, self.mode)
    }

    /// Commit the result and pin it for delivery in the same mutation scope.
    ///
    /// # Errors
    /// Returns an error for invalid results, missing content or storage failure.
    pub fn publish_pinned(
        &self,
        manifest: &ResultManifest,
        staged: Vec<StagedBlob>,
    ) -> Result<ResultLease> {
        self.inner
            .store
            .publish_pinned(&self.fingerprint, manifest, staged, self.mode)
    }
}

impl Drop for CompilePermit {
    fn drop(&mut self) {
        match self.inner.running.lock() {
            Ok(mut running) => {
                if !running.remove(&self.key) {
                    log::error!("native compilation permit lost its reservation");
                }
            }
            Err(error) => log::error!("could not release native compilation permit: {error:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Barrier, thread};

    use super::*;
    use crate::{Artifact, ContentId};
    use anyhow::Result;

    fn fingerprint() -> ActionFingerprint {
        ActionFingerprint {
            schema: "rust".into(),
            components: BTreeMap::from([("input".into(), ContentId::of(b"source"))]),
        }
    }

    #[test]
    fn admission_reuses_committed_results_and_releases_cancelled_jobs() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let coordinator = BuildCoordinator::new(NativeStore::open(dir.path())?);
        let Admission::Compile(permit) = coordinator.admit(fingerprint(), ActionMode::Reuse)?
        else {
            anyhow::bail!("expected new compilation");
        };
        assert!(matches!(
            coordinator.admit(fingerprint(), ActionMode::Reuse)?,
            Admission::InFlight
        ));
        drop(permit);
        let Admission::Compile(permit) = coordinator.admit(fingerprint(), ActionMode::Reuse)?
        else {
            anyhow::bail!("cancelled compilation was not released");
        };
        let staged = coordinator.store().stage(&b"output"[..])?;
        let result = ResultManifest {
            outputs: BTreeMap::from([(
                "output".into(),
                Artifact {
                    blob: staged.reference(),
                    mode: None,
                },
            )]),
            stdout: None,
            stderr: None,
        };
        let key = permit.key();
        assert_eq!(permit.publish(&result, vec![staged])?.action, key);
        let Admission::Cached(lease) = coordinator.admit(fingerprint(), ActionMode::Reuse)? else {
            anyhow::bail!("expected cache hit");
        };
        assert_eq!(lease.manifest(), &result);
        Ok(())
    }

    #[test]
    fn concurrent_requests_receive_exactly_one_compile_permit() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let coordinator = BuildCoordinator::new(NativeStore::open(dir.path())?);
        let barrier = Barrier::new(8);
        let results = thread::scope(|scope| -> Result<Vec<Admission>> {
            let handles = (0..8)
                .map(|_| {
                    let coordinator = coordinator.clone();
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        coordinator.admit(fingerprint(), ActionMode::Reuse)
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| anyhow!("admission thread panicked"))?
                })
                .collect()
        })?;
        assert_eq!(
            results
                .iter()
                .filter(|item| matches!(item, Admission::Compile(_)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|item| matches!(item, Admission::InFlight))
                .count(),
            7
        );
        drop(results);
        assert!(matches!(
            coordinator.admit(fingerprint(), ActionMode::Reuse)?,
            Admission::Compile(_)
        ));
        Ok(())
    }

    #[test]
    fn invalid_publication_releases_admission() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let coordinator = BuildCoordinator::new(NativeStore::open(dir.path())?);
        let Admission::Compile(permit) = coordinator.admit(fingerprint(), ActionMode::Reuse)?
        else {
            anyhow::bail!("expected compilation");
        };
        let staged = coordinator.store().stage(&b"not the output"[..])?;
        let result = ResultManifest {
            outputs: BTreeMap::new(),
            stdout: Some(staged.reference()),
            stderr: None,
        };
        assert!(permit.publish(&result, vec![]).is_err());
        let key = fingerprint().key()?;
        assert!(coordinator.store().lookup(key)?.is_none());
        assert!(matches!(
            coordinator.admit(fingerprint(), ActionMode::Reuse)?,
            Admission::Compile(_)
        ));
        drop(staged);
        Ok(())
    }
}
