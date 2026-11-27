//! Prepare and attach result roots independently of the durable transaction
//! boundary, so synchronous and queued publications share conflict semantics.
use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use redb::{ReadTransaction, ReadableTable, WriteTransaction};

use super::{
    ACTIONS, ActionRecord, Attachment, BLOB_LAYOUTS, BLOBS, BlobIndex, NativeStore,
    PENDING_DELETIONS, Publication, Published, RESULT_ACTIONS, RESULTS, ResultLease, StagedBlob,
    encoding, history, space::Root,
};
use crate::{
    ActionFingerprint, ActionKey, ActionMode, BlobRef, ContentId, ResultId, ResultManifest,
};

pub(super) struct PreparedResult<'a> {
    fingerprint: Cow<'a, ActionFingerprint>,
    manifest: Cow<'a, ResultManifest>,
    action: ActionKey,
    result: ResultId,
    blobs: BTreeMap<ContentId, u64>,
    staged: BTreeMap<ContentId, StagedBlob>,
    mode: ActionMode,
}

pub(super) struct ResultPlan {
    previous: Option<ActionRecord>,
    pub(super) unchanged: bool,
}

impl<'a> PreparedResult<'a> {
    pub(super) fn new(
        store: &NativeStore,
        fingerprint: Cow<'a, ActionFingerprint>,
        manifest: Cow<'a, ResultManifest>,
        staged: Vec<StagedBlob>,
        mode: ActionMode,
    ) -> Result<Self> {
        let action = fingerprint.key()?;
        let result = manifest.id()?;
        let blobs = manifest.blobs()?;
        let staged = store.prepare_staging(&blobs, staged)?;
        // Validate all staged descriptors before entering a shared transaction;
        // one malformed request must not abort unrelated result publications.
        for (&id, blob) in &staged {
            ensure!(
                blobs.get(&id) == Some(&blob.reference().size),
                "staged result length mismatch"
            );
            blob.validate_metadata(&std::fs::symlink_metadata(&blob.path)?)?;
        }
        Ok(Self {
            fingerprint,
            manifest,
            action,
            result,
            blobs,
            staged,
            mode,
        })
    }

    pub(super) fn preflight(
        &self,
        store: &NativeStore,
        read: &ReadTransaction,
    ) -> Result<ResultPlan> {
        let actions = read.open_table(ACTIONS)?;
        let results = read.open_table(RESULTS)?;
        let previous = actions
            .get(&self.action.0)?
            .map(|value| encoding().deserialize::<ActionRecord>(value.value()))
            .transpose()?;
        if let Some(stored) = &previous {
            ensure!(
                stored.fingerprint == *self.fingerprint,
                "conflicting native action fingerprint"
            );
            if stored.result != self.result && self.mode == ActionMode::Reuse {
                let old = results
                    .get(&stored.result.0)?
                    .context("missing indexed result")?;
                let old: ResultManifest = encoding().deserialize(old.value())?;
                ensure!(
                    !store.blobs_present(&old.blobs()?)?,
                    "conflicting result for action {:?}",
                    self.action
                );
            }
        }
        let existing_result = if let Some(stored) = results.get(&self.result.0)? {
            let stored: ResultManifest = encoding().deserialize(stored.value())?;
            ensure!(
                stored == *self.manifest,
                "conflicting native result manifest"
            );
            true
        } else {
            false
        };
        let live = read.open_table(BLOBS)?;
        let pending = read.open_table(PENDING_DELETIONS)?;
        let layouts = read.open_table(BLOB_LAYOUTS)?;
        let index = BlobIndex {
            live: &live,
            pending: &pending,
            layouts: &layouts,
        };
        let mut complete = true;
        for (&id, &size) in &self.blobs {
            complete &= index.inspect(
                &store.inner,
                BlobRef { id, size },
                existing_result,
                self.staged.get(&id),
            )? == Attachment::Live;
        }
        let unchanged = complete
            && existing_result
            && previous
                .as_ref()
                .is_some_and(|old| old.result == self.result);
        Ok(ResultPlan {
            previous,
            unchanged,
        })
    }

    pub(super) const fn published(&self, plan: &ResultPlan) -> Published {
        Published {
            action: self.action,
            result: self.result,
            new_action: plan.previous.is_none(),
        }
    }

    /// Recheck a conditional replacement against the transaction's current
    /// contents: an earlier publication may have repaired the old result.
    pub(super) fn revalidate_replacement(
        &self,
        store: &NativeStore,
        write: &WriteTransaction,
        plan: &ResultPlan,
    ) -> Result<()> {
        let Some(previous) = &plan.previous else {
            return Ok(());
        };
        if self.mode != ActionMode::Reuse || previous.result == self.result {
            return Ok(());
        }
        let results = write.open_table(RESULTS)?;
        let old = results
            .get(&previous.result.0)?
            .context("missing indexed result")?;
        let old: ResultManifest = encoding().deserialize(old.value())?;
        let layouts = write.open_table(BLOB_LAYOUTS)?;
        for (id, size) in old.blobs()? {
            if !store.inner.blob_present(&layouts, id, size)? {
                return Ok(());
            }
        }
        anyhow::bail!("conflicting result for action {:?}", self.action)
    }

    pub(super) fn attach(
        &mut self,
        store: &NativeStore,
        write: &WriteTransaction,
        publication: &mut Publication,
        plan: &ResultPlan,
    ) -> Result<()> {
        let mut actions = write.open_table(ACTIONS)?;
        let mut results = write.open_table(RESULTS)?;
        let mut result_actions = write.open_multimap_table(RESULT_ACTIONS)?;
        // Another action in this transaction may have created or retired an
        // alias of the same immutable result. Inspect the write view, not the
        // preflight read snapshot, for root existence.
        let existing_result = results.get(&self.result.0)?.is_some();
        let same = plan
            .previous
            .as_ref()
            .is_some_and(|old| old.result == self.result);
        ensure!(
            !same || existing_result,
            "existing action result disappeared"
        );
        store.attach_blobs(
            write,
            &self.result.0,
            &self.blobs,
            std::mem::take(&mut self.staged),
            existing_result,
            publication,
        )?;
        if !same {
            if !existing_result {
                results.insert(
                    &self.result.0,
                    encoding().serialize(self.manifest.as_ref())?.as_slice(),
                )?;
            }
            let record = ActionRecord {
                fingerprint: self.fingerprint.as_ref().clone(),
                result: self.result,
            };
            actions.insert(&self.action.0, encoding().serialize(&record)?.as_slice())?;
            result_actions.insert(&self.result.0, &self.action.0)?;
            if let Some(previous) = &plan.previous {
                NativeStore::release_result_reference(
                    write,
                    &mut results,
                    &mut result_actions,
                    self.action,
                    previous.result,
                )?;
            }
        }
        drop(result_actions);
        drop(results);
        drop(actions);
        history::forget(write, self.action)
    }

    pub(super) fn lease(self, store: &NativeStore) -> Result<ResultLease> {
        let mut pins = store.inner.lock_pins()?;
        pins.pin_result(self.action, &self.blobs)?;
        pins.touch(Root::Action(self.action));
        drop(pins);
        Ok(ResultLease {
            inner: Arc::clone(&store.inner),
            action: self.action,
            manifest: self.manifest.into_owned(),
            blobs: self.blobs,
        })
    }
}
