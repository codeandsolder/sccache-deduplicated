//! Transactional cross-key duplicate detection, indexed over live actions
//! and the existing bounded evicted-result receipts. No payload scans or pins.
use anyhow::{Context, Result};
use bincode::Options;
use redb::{
    MultimapTableDefinition, ReadableDatabase, ReadableMultimapTable, ReadableTable,
    TableDefinition, WriteTransaction,
};

use super::{ACTIONS, ActionRecord, NativeStore, RESULTS, encoding, history};
use crate::{ActionKey, ResultManifest, analytics::DuplicateMisses, identity::typed_digest};

const ACTION_DIGESTS: TableDefinition<'static, &[u8; 32], &[u8; 64]> =
    TableDefinition::new("duplicate_action_digests_v1");
const OUTPUT_ACTIONS: MultimapTableDefinition<'static, &[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("duplicate_output_actions_v1");
const RESULT_ACTIONS: MultimapTableDefinition<'static, &[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("duplicate_result_actions_v1");
const STATE: TableDefinition<'static, u8, u64> = TableDefinition::new("duplicate_misses_v1");
const INITIALIZED: u8 = 0;
const NEW_KEYS: u8 = 1;
const IDENTICAL_OUTPUTS: u8 = 2;
const IDENTICAL_RESULTS: u8 = 3;

pub(super) fn initialize(write: &WriteTransaction) -> Result<()> {
    write.open_table(ACTION_DIGESTS)?;
    write.open_multimap_table(OUTPUT_ACTIONS)?;
    write.open_multimap_table(RESULT_ACTIONS)?;
    {
        let mut state = write.open_table(STATE)?;
        if state.get(INITIALIZED)?.is_some() {
            return Ok(());
        }
        for key in [NEW_KEYS, IDENTICAL_OUTPUTS, IDENTICAL_RESULTS] {
            state.insert(key, 0)?;
        }
    }
    let actions = write.open_table(ACTIONS)?;
    let results = write.open_table(RESULTS)?;
    for item in actions.iter()? {
        let (key, value) = item?;
        let record: ActionRecord = encoding().deserialize(value.value())?;
        let manifest: ResultManifest = encoding().deserialize(
            results
                .get(&record.result.0)?
                .context("missing indexed result")?
                .value(),
        )?;
        record_existing(write, ActionKey(*key.value()), &manifest)?;
    }
    drop(results);
    drop(actions);
    history::seed_duplicate_index(write)?;
    write.open_table(STATE)?.insert(INITIALIZED, 1)?;
    Ok(())
}

pub(super) fn output_identity(manifest: &ResultManifest) -> Result<[u8; 32]> {
    typed_digest(b"sccache-output-artifacts-v1\0", &manifest.outputs)
}

pub(super) fn forget(write: &WriteTransaction, action: ActionKey) -> Result<()> {
    let digests = {
        let mut actions = write.open_table(ACTION_DIGESTS)?;
        let value = actions.remove(&action.0)?.map(|value| *value.value());
        drop(actions);
        value
    };
    let Some(digests) = digests else {
        return Ok(());
    };
    let (outputs, result) = digests.split_at(32);
    let outputs: &[u8; 32] = outputs.try_into()?;
    let result: &[u8; 32] = result.try_into()?;
    write
        .open_multimap_table(OUTPUT_ACTIONS)?
        .remove(outputs, &action.0)?;
    write
        .open_multimap_table(RESULT_ACTIONS)?
        .remove(result, &action.0)?;
    Ok(())
}

fn record(
    write: &WriteTransaction,
    action: ActionKey,
    outputs: &[u8; 32],
    result: &[u8; 32],
) -> Result<()> {
    let mut digests = [0; 64];
    digests[..32].copy_from_slice(outputs);
    digests[32..].copy_from_slice(result);
    if write
        .open_table(ACTION_DIGESTS)?
        .get(&action.0)?
        .is_some_and(|value| value.value() == &digests)
    {
        return Ok(());
    }
    forget(write, action)?;
    write
        .open_table(ACTION_DIGESTS)?
        .insert(&action.0, &digests)?;
    write
        .open_multimap_table(OUTPUT_ACTIONS)?
        .insert(outputs, &action.0)?;
    write
        .open_multimap_table(RESULT_ACTIONS)?
        .insert(result, &action.0)?;
    Ok(())
}

pub(super) fn record_existing(
    write: &WriteTransaction,
    action: ActionKey,
    manifest: &ResultManifest,
) -> Result<()> {
    record(
        write,
        action,
        &output_identity(manifest)?,
        &manifest.id()?.0,
    )
}

fn increment(state: &mut redb::Table<'_, u8, u64>, key: u8) -> Result<()> {
    let old = state
        .get(key)?
        .context("missing duplicate miss counter")?
        .value();
    state.insert(key, old.saturating_add(1))?;
    Ok(())
}

pub(super) fn observe(
    write: &WriteTransaction,
    action: ActionKey,
    outputs: &[u8; 32],
    result: &[u8; 32],
    new_reuse_action: bool,
    has_outputs: bool,
) -> Result<()> {
    let new_key = write.open_table(ACTION_DIGESTS)?.get(&action.0)?.is_none();
    if new_reuse_action && new_key {
        let same_outputs = write
            .open_multimap_table(OUTPUT_ACTIONS)?
            .get(outputs)?
            .next()
            .transpose()?
            .is_some();
        let same_result = write
            .open_multimap_table(RESULT_ACTIONS)?
            .get(result)?
            .next()
            .transpose()?
            .is_some();
        let mut state = write.open_table(STATE)?;
        increment(&mut state, NEW_KEYS)?;
        if same_outputs && has_outputs {
            increment(&mut state, IDENTICAL_OUTPUTS)?;
        }
        if same_result && has_outputs {
            increment(&mut state, IDENTICAL_RESULTS)?;
        }
    }
    record(write, action, outputs, result)
}

impl NativeStore {
    /// Counts detected distinct-key duplicates from durable successful
    /// publications, including matches against retained eviction receipts.
    /// # Errors
    /// Returns an error if the transactional counter state cannot be read.
    pub fn duplicate_misses(&self) -> Result<DuplicateMisses> {
        let read = self.inner.db.begin_read()?;
        let state = read.open_table(STATE)?;
        let value = |key| -> Result<u64> {
            Ok(state
                .get(key)?
                .context("missing duplicate miss counter")?
                .value())
        };
        Ok(DuplicateMisses {
            new_keys: value(NEW_KEYS)?,
            identical_outputs: value(IDENTICAL_OUTPUTS)?,
            identical_results: value(IDENTICAL_RESULTS)?,
        })
    }
}
