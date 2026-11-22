//! Differential evidence for cache-key simplification, without changing keys.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use redb::{ReadOnlyDatabase, ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};

use super::{ACTIONS, ActionRecord, NativeStore, encoding};
use crate::{ActionKey, ResultId};

/// Observed evidence for jointly ignoring selected named action components.
///
/// Counts are over unordered pairs of distinct actions in the same schema
/// whose other component digests all agree. Successful complete results,
/// including diagnostics and metadata, are compared. Equal results are
/// evidence to investigate, never authorization to merge action identities.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentAudit {
    pub examined_actions: u64,
    pub matched_groups: u64,
    pub matched_actions: u64,
    pub equivalent_pairs: u128,
    pub conflicting_pairs: u128,
    pub equivalent_example: Option<[ActionKey; 2]>,
    pub conflicting_example: Option<[ActionKey; 2]>,
}

#[derive(Default)]
struct Group {
    total: u64,
    outcomes: BTreeMap<ResultId, Outcome>,
}

struct Outcome {
    count: u64,
    example: ActionKey,
}

impl Group {
    fn insert(
        &mut self,
        key: ActionKey,
        result: ResultId,
        report: &mut ComponentAudit,
    ) -> Result<()> {
        // A streaming count of all newly created pairs, without generating
        // pair lists or comparing every combination of equivalent keys.
        let outcome = self.outcomes.entry(result).or_insert(Outcome {
            count: 0,
            example: key,
        });
        let equal = outcome.count;
        report.equivalent_pairs += u128::from(equal);
        report.conflicting_pairs += u128::from(self.total - equal);
        if equal != 0 && report.equivalent_example.is_none() {
            report.equivalent_example = Some([outcome.example, key]);
        }
        outcome.count = equal
            .checked_add(1)
            .context("result cohort count overflow")?;
        if report.conflicting_example.is_none() && self.total != equal {
            let (&_, other) = self
                .outcomes
                .iter()
                .find(|(id, _)| **id != result)
                .context("different outcome cohort missing")?;
            report.conflicting_example = Some([other.example, key]);
        }
        self.total = self
            .total
            .checked_add(1)
            .context("action cohort count overflow")?;
        Ok(())
    }
}

/// Per-schema inventory of action components, including absent-vs-present
/// coverage. No original environment values or contents are exposed.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaInventory {
    pub actions: u64,
    pub components: BTreeMap<String, u64>,
}

/// Inspect an existing index without creating a store, running recovery or
/// changing any cache entries.
///
/// The index must be closed by its writer or supplied as a consistent
/// offline snapshot supported by redb.
pub struct NativeIndexAudit {
    db: ReadOnlyDatabase,
}

impl NativeIndexAudit {
    /// Open an existing, read-only native index.
    /// # Errors
    /// Returns an error if the index cannot be opened safely.
    pub fn open(index: &Path) -> Result<Self> {
        Ok(Self {
            db: ReadOnlyDatabase::open(index)?,
        })
    }

    /// Enumerate schemas and component coverage in one consistent read.
    /// # Errors
    /// Returns an error for inconsistent metadata or I/O failure.
    pub fn inventory(&self) -> Result<BTreeMap<String, SchemaInventory>> {
        inventory(&self.db)
    }

    /// Compare action outcomes after projecting out exactly these components.
    /// # Errors
    /// Returns an error for invalid arguments, metadata or serialization.
    pub fn compare(&self, schema: &str, ignored: &[String]) -> Result<ComponentAudit> {
        compare(&self.db, schema, ignored)
    }
}

impl NativeStore {
    /// Audit the exact effect of dropping a set of components from one schema.
    ///
    /// The read transaction sees a consistent snapshot. Absent and present
    /// components are compared correctly; each action is folded into one
    /// reduced-fingerprint cohort. Memory is linear in examined actions.
    ///
    /// # Errors
    /// Returns an error for invalid arguments, metadata or serialization.
    pub fn audit_components(&self, schema: &str, ignored: &[String]) -> Result<ComponentAudit> {
        compare(&self.inner.db, schema, ignored)
    }
}

fn inventory(db: &impl ReadableDatabase) -> Result<BTreeMap<String, SchemaInventory>> {
    let read = db.begin_read()?;
    let actions = read.open_table(ACTIONS)?;
    let mut schemas = BTreeMap::<String, SchemaInventory>::new();
    for row in actions.iter()? {
        let (key, value) = row?;
        let record: ActionRecord = encoding().deserialize(value.value())?;
        ensure!(
            record.fingerprint.key()?.0 == *key.value(),
            "invalid indexed action fingerprint"
        );
        let entry = schemas.entry(record.fingerprint.schema).or_default();
        entry.actions = entry
            .actions
            .checked_add(1)
            .context("action count overflow")?;
        for component in record.fingerprint.components.into_keys() {
            let count = entry.components.entry(component).or_default();
            *count = count.checked_add(1).context("component count overflow")?;
        }
    }
    Ok(schemas)
}

fn compare(db: &impl ReadableDatabase, schema: &str, ignored: &[String]) -> Result<ComponentAudit> {
    ensure!(
        !schema.is_empty() && !ignored.is_empty(),
        "select a schema and components to ignore"
    );
    let selection: BTreeSet<_> = ignored.iter().collect();
    ensure!(
        selection.len() == ignored.len() && selection.iter().all(|name| !name.is_empty()),
        "empty or duplicate component name"
    );
    let read = db.begin_read()?;
    let actions = read.open_table(ACTIONS)?;
    let mut groups = BTreeMap::<ActionKey, Group>::new();
    let mut report = ComponentAudit::default();
    for row in actions.iter()? {
        let (key, value) = row?;
        let key = ActionKey(*key.value());
        let ActionRecord {
            mut fingerprint,
            result,
        } = encoding().deserialize(value.value())?;
        ensure!(
            fingerprint.key()? == key,
            "invalid indexed action fingerprint"
        );
        if fingerprint.schema != schema {
            continue;
        }
        report.examined_actions = report
            .examined_actions
            .checked_add(1)
            .context("action count overflow")?;
        fingerprint
            .components
            .retain(|name, _| !selection.contains(name));
        let reduced = fingerprint.key()?;
        groups
            .entry(reduced)
            .or_default()
            .insert(key, result, &mut report)?;
    }
    for group in groups.values().filter(|group| group.total > 1) {
        report.matched_groups = report
            .matched_groups
            .checked_add(1)
            .context("group count overflow")?;
        report.matched_actions = report
            .matched_actions
            .checked_add(group.total)
            .context("matched action count overflow")?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActionFingerprint, Artifact, BlobRef, ContentId, ResultManifest};

    fn result(blob: BlobRef) -> ResultManifest {
        ResultManifest {
            outputs: BTreeMap::from([("output".into(), Artifact { blob, mode: None })]),
            stdout: None,
            stderr: None,
        }
    }

    #[test]
    fn audit_counts_equal_and_different_results_without_aliasing_keys() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = NativeStore::open(dir.path())?;
        let first = store.stage(&b"one"[..])?;
        let first_result = result(first.reference());
        let second = store.stage(&b"two"[..])?;
        let second_result = result(second.reference());
        let absent = ActionFingerprint {
            schema: "rust".into(),
            components: BTreeMap::from([("source".into(), ContentId::of(b"x"))]),
        };
        let with = |value: &[u8]| {
            let mut fp = absent.clone();
            fp.components
                .insert("environment/FOO".into(), ContentId::of(value));
            fp
        };
        store.publish(&absent, &first_result, vec![first])?;
        store.publish(&with(b"a"), &first_result, vec![])?;
        store.publish(&with(b"b"), &first_result, vec![])?;
        store.publish(&with(b"c"), &second_result, vec![second])?;
        let mut other_schema = with(b"d");
        other_schema.schema = "c".into();
        store.publish(&other_schema, &second_result, vec![])?;
        let mut other_source = with(b"a");
        other_source
            .components
            .insert("source".into(), ContentId::of(b"y"));
        store.publish(&other_source, &second_result, vec![])?;

        let report = store.audit_components("rust", &["environment/FOO".into()])?;
        assert_eq!(report.examined_actions, 5);
        assert_eq!(report.matched_groups, 1);
        assert_eq!(report.matched_actions, 4);
        assert_eq!(report.equivalent_pairs, 3);
        assert_eq!(report.conflicting_pairs, 3);
        assert!(report.equivalent_example.is_some());
        assert!(report.conflicting_example.is_some());
        assert_eq!(
            store
                .audit_components("rust", &["unrelated".into()])?
                .matched_actions,
            0
        );
        let joint = store.audit_components("rust", &["environment/FOO".into(), "source".into()])?;
        assert_eq!(joint.equivalent_pairs, 3 + 1);
        assert_eq!(joint.conflicting_pairs, 6);
        assert_eq!(store.stats()?.actions, 6);
        drop(store);
        let index = NativeIndexAudit::open(&dir.path().join("index.redb"))?;
        assert_eq!(index.compare("rust", &["environment/FOO".into()])?, report);
        let schemas = index.inventory()?;
        assert_eq!(schemas["rust"].actions, 5);
        assert_eq!(schemas["rust"].components["environment/FOO"], 4);
        assert_eq!(schemas["c"].actions, 1);
        Ok(())
    }
}
