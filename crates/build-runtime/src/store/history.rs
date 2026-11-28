//! Bounded, durable metadata for evicted action results. No content pins.
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, ensure};
use bincode::Options;
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};

use super::{ACTIONS, ActionRecord, NativeStore, RESULTS, duplicate_results, encoding};
use crate::{ActionKey, ResultManifest};

const MANIFESTS: TableDefinition<'static, &[u8; 32], &[u8]> =
    TableDefinition::new("evicted_result_manifests_v1");
const AGE: TableDefinition<'static, u64, &[u8; 32]> = TableDefinition::new("evicted_result_age_v1");
const STATE: TableDefinition<'static, u8, u64> = TableDefinition::new("evicted_result_state_v1");
const BYTES: u8 = 0;
const NEXT: u8 = 1;
const LIMIT: u8 = 2;

#[derive(Serialize, Deserialize)]
struct Receipt {
    sequence: u64,
    manifest: ResultManifest,
}

pub(super) fn initialize(write: &WriteTransaction) -> Result<()> {
    write.open_table(MANIFESTS)?;
    write.open_table(AGE)?;
    let mut state = write.open_table(STATE)?;
    for key in [BYTES, NEXT, LIMIT] {
        if state.get(key)?.is_none() {
            state.insert(key, 0)?;
        }
    }
    Ok(())
}

pub(super) fn configured_limit(db: &redb::Database) -> Result<u64> {
    let read = db.begin_read()?;
    let state = read.open_table(STATE)?;
    Ok(state
        .get(LIMIT)?
        .context("missing result history limit")?
        .value())
}

// Include fixed-size index keys, reverse index entry and value length in
// the budget, not just the variable manifest payload.
fn charge(bytes: usize) -> Result<u64> {
    u64::try_from(bytes)?
        .checked_add(80)
        .context("result history size overflow")
}

pub(super) fn forget(write: &WriteTransaction, action: ActionKey) -> Result<()> {
    let mut manifests = write.open_table(MANIFESTS)?;
    let Some(value) = manifests.remove(&action.0)? else {
        return Ok(());
    };
    let receipt: Receipt = encoding().deserialize(value.value())?;
    let removed = charge(value.value().len())?;
    ensure!(
        write.open_table(AGE)?.remove(receipt.sequence)?.is_some(),
        "missing result history age index"
    );
    let mut state = write.open_table(STATE)?;
    let bytes = state
        .get(BYTES)?
        .context("missing result history size")?
        .value();
    state.insert(
        BYTES,
        bytes
            .checked_sub(removed)
            .context("result history size underflow")?,
    )?;
    Ok(())
}

fn trim(write: &WriteTransaction, limit: u64) -> Result<()> {
    loop {
        let bytes = write
            .open_table(STATE)?
            .get(BYTES)?
            .context("missing result history size")?
            .value();
        if bytes <= limit {
            return Ok(());
        }
        let action = {
            let age = write.open_table(AGE)?;
            let (_, key) = age.first()?.context("missing result history age entry")?;
            ActionKey(*key.value())
        };
        forget(write, action)?;
        duplicate_results::forget(write, action)?;
    }
}

pub(super) fn remember(
    write: &WriteTransaction,
    action: ActionKey,
    manifest: ResultManifest,
    limit: u64,
) -> Result<()> {
    if limit == 0 {
        return Ok(());
    }
    forget(write, action)?;
    let mut state = write.open_table(STATE)?;
    let sequence = state
        .get(NEXT)?
        .context("missing result history sequence")?
        .value();
    let bytes = encoding().serialize(&Receipt { sequence, manifest })?;
    let added = charge(bytes.len())?;
    if added > limit {
        drop(state);
        return duplicate_results::forget(write, action);
    }
    let old = state
        .get(BYTES)?
        .context("missing result history size")?
        .value();
    state.insert(
        NEXT,
        sequence
            .checked_add(1)
            .context("result history sequence overflow")?,
    )?;
    state.insert(
        BYTES,
        old.checked_add(added)
            .context("result history size overflow")?,
    )?;
    drop(state);
    write
        .open_table(MANIFESTS)?
        .insert(&action.0, bytes.as_slice())?;
    write.open_table(AGE)?.insert(sequence, &action.0)?;
    trim(write, limit)
}

pub(super) fn seed_duplicate_index(write: &WriteTransaction) -> Result<()> {
    let receipts = write.open_table(MANIFESTS)?;
    for item in receipts.iter()? {
        let (key, value) = item?;
        let receipt: Receipt = encoding().deserialize(value.value())?;
        duplicate_results::record_existing(write, ActionKey(*key.value()), &receipt.manifest)?;
    }
    Ok(())
}

impl NativeStore {
    /// Enable bounded result receipts at the scheduler. Receipts never pin
    /// bytes, and are pruned transactionally on eviction and limit changes.
    pub(crate) fn enable_result_history(&self, limit: u64) -> Result<()> {
        let _mutation = self.inner.lock_mutations()?;
        let write = self.inner.db.begin_write()?;
        trim(&write, limit)?;
        write.open_table(STATE)?.insert(LIMIT, limit)?;
        write.commit()?;
        self.inner
            .result_history_limit
            .store(limit, Ordering::Release);
        Ok(())
    }

    /// Read the scheduler-authoritative manifest even when its payloads
    /// have been evicted or lost. Never infer a result from a peer's action key.
    ///
    /// # Errors
    /// Returns an error for inconsistent metadata.
    pub fn result_receipt(&self, action: ActionKey) -> Result<Option<ResultManifest>> {
        let read = self.inner.db.begin_read()?;
        let actions = read.open_table(ACTIONS)?;
        if let Some(record) = actions.get(&action.0)? {
            let record: ActionRecord = encoding().deserialize(record.value())?;
            ensure!(
                record.fingerprint.key()? == action,
                "invalid indexed action fingerprint"
            );
            let results = read.open_table(RESULTS)?;
            let manifest: ResultManifest = encoding().deserialize(
                results
                    .get(&record.result.0)?
                    .context("missing indexed result")?
                    .value(),
            )?;
            ensure!(
                manifest.id()? == record.result,
                "invalid indexed result manifest"
            );
            return Ok(Some(manifest));
        }
        let manifests = read.open_table(MANIFESTS)?;
        manifests
            .get(&action.0)?
            .map(|value| {
                let receipt: Receipt = encoding().deserialize(value.value())?;
                receipt.manifest.blobs()?;
                Ok(receipt.manifest)
            })
            .transpose()
    }
}
