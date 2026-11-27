//! Test selection over revision-relative coverage and explicit input edges.
//! Selection consumes a current inventory, rather than a historical list of
//! executables. Each test keeps its own baseline revision and scope so partial
//! recollection never reinterprets old line numbers in a newer source tree.
use super::coverage::{CRATE_ROOT_SENTINEL_END, HitRange};
use anyhow::{Result, ensure};
use sccache_build::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Stable logical test identity. Unit identity includes package source,
/// target kind/name and host/target build domain; the binary digest does not
/// belong here, because a rebuild must not turn every existing test into a
/// newly discovered test.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TestId {
    pub unit: String,
    pub name: String,
}

/// A successful, completely collected test profile, attributed to one
/// verified executable. Collection must reject incomplete profiles and
/// ambiguous source mappings before constructing this record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub scope: ContentId,
    pub revision: String,
    pub executable: ContentId,
    pub ranges: BTreeSet<HitRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineRange {
    pub start: i64,
    pub end: i64,
}

impl LineRange {
    fn overlaps(self, range: &HitRange) -> bool {
        self.start <= range.line_end && self.end >= range.line_start
    }
}

/// A complete change set relative to one baseline. Line coordinates refer to
/// the OLD side of the diff. The caller must supply static/configured input
/// invalidations for structural changes, new/renamed files, generated inputs,
/// and uncovered resources. Any unclassified change requires a global
/// invalidation, not an empty diff.
#[derive(Debug, Clone, Default)]
pub struct RevisionChanges {
    pub lines: BTreeMap<String, Vec<LineRange>>,
    pub whole_files: BTreeSet<String>,
    pub explicit: BTreeMap<TestId, BTreeSet<String>>,
    pub global: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Reason {
    NewTest,
    InvalidBaseline,
    ScopeChanged,
    RevisionUnavailable,
    GlobalInput(String),
    ExplicitInput(String),
    WholeFile(String),
    StructuralBackstop(String),
    CrateRoot(String),
    CoveredLines(String),
}

pub type Selection = BTreeMap<TestId, BTreeSet<Reason>>;

fn add(selection: &mut Selection, test: &TestId, reason: Reason) {
    selection.entry(test.clone()).or_default().insert(reason);
}

/// Select runnable tests from their latest successful baselines. Ignored or
/// filtered tests must be excluded from inventory by the harness adapter.
/// Missing scopes/revisions and incomplete profiles never authorize skipping.
/// A separate static input graph supplies additional edges; this layer does
/// not infer that a file without coverage is irrelevant.
pub fn select(
    inventory: &BTreeMap<TestId, ContentId>,
    baselines: &BTreeMap<TestId, Baseline>,
    changes: &BTreeMap<String, RevisionChanges>,
) -> Result<Selection> {
    let mut selected = Selection::new();
    let mut groups = BTreeMap::<(ContentId, &str), Vec<(&TestId, &Baseline)>>::new();
    for (test, scope) in inventory {
        let Some(baseline) = baselines.get(test) else {
            add(&mut selected, test, Reason::NewTest);
            continue;
        };
        if baseline.scope != *scope {
            add(&mut selected, test, Reason::ScopeChanged);
            continue;
        }
        if baseline.ranges.is_empty()
            || baseline
                .ranges
                .iter()
                .any(|r| r.file.is_empty() || r.line_start <= 0 || r.line_end < r.line_start)
        {
            add(&mut selected, test, Reason::InvalidBaseline);
            continue;
        }
        if !changes.contains_key(&baseline.revision) {
            add(&mut selected, test, Reason::RevisionUnavailable);
            continue;
        }
        groups
            .entry((*scope, baseline.revision.as_str()))
            .or_default()
            .push((test, baseline));
    }

    for ((_, revision), group) in groups {
        let change = &changes[revision];
        let mut files = BTreeMap::<&str, Vec<(&TestId, &HitRange)>>::new();
        for (test, baseline) in group {
            for path in &change.global {
                add(&mut selected, test, Reason::GlobalInput(path.clone()));
            }
            if let Some(paths) = change.explicit.get(test) {
                for path in paths {
                    add(&mut selected, test, Reason::ExplicitInput(path.clone()));
                }
            }
            for range in &baseline.ranges {
                if change.whole_files.contains(&range.file) {
                    add(&mut selected, test, Reason::WholeFile(range.file.clone()));
                }
                if change.lines.contains_key(&range.file) {
                    files.entry(&range.file).or_default().push((test, range));
                }
            }
        }
        // As in cargo-affected, an old-side hunk outside all executed
        // function extents selects every test which exercised that file.
        // Explicit structural/input rules are unioned independently, so a
        // sentinel or one covered function cannot suppress those rules.
        for (file, hunks) in &change.lines {
            let Some(rows) = files.get(file.as_str()) else {
                continue;
            };
            for hunk in hunks {
                // Insertion at the start of a file has old coordinate zero.
                ensure!(
                    hunk.start >= 0 && hunk.end >= hunk.start,
                    "invalid old-side line range"
                );
                let mut overlapped = false;
                for (test, range) in rows {
                    let sentinel =
                        range.line_start == 1 && range.line_end == CRATE_ROOT_SENTINEL_END;
                    if sentinel || hunk.overlaps(range) {
                        overlapped = true;
                        add(
                            &mut selected,
                            test,
                            if sentinel {
                                Reason::CrateRoot(file.clone())
                            } else {
                                Reason::CoveredLines(file.clone())
                            },
                        );
                    }
                }
                if !overlapped {
                    for (test, _) in rows {
                        add(
                            &mut selected,
                            test,
                            Reason::StructuralBackstop(file.clone()),
                        );
                    }
                }
            }
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test(name: &str) -> TestId {
        TestId {
            unit: "path+workspace#app:lib".into(),
            name: name.into(),
        }
    }

    fn baseline(scope: ContentId, revision: &str, file: &str, start: i64, end: i64) -> Baseline {
        Baseline {
            scope,
            revision: revision.into(),
            executable: ContentId::of(b"verified test binary"),
            ranges: BTreeSet::from([HitRange {
                file: file.into(),
                line_start: start,
                line_end: end,
            }]),
        }
    }

    #[test]
    fn selects_in_baseline_coordinates_and_ignores_removed_tests() -> Result<()> {
        let scope = ContentId::of(b"scope");
        let a = test("a");
        let b = test("b");
        let c = test("new");
        let gone = test("deleted");
        let inventory =
            BTreeMap::from([(a.clone(), scope), (b.clone(), scope), (c.clone(), scope)]);
        let baselines = BTreeMap::from([
            (a.clone(), baseline(scope, "old", "src/lib.rs", 1, 10)),
            (b.clone(), baseline(scope, "newer", "src/lib.rs", 40, 50)),
            (gone.clone(), baseline(scope, "old", "src/lib.rs", 1, 10)),
        ]);
        let changes = BTreeMap::from([
            (
                "old".into(),
                RevisionChanges {
                    lines: BTreeMap::from([(
                        "src/lib.rs".into(),
                        vec![LineRange { start: 5, end: 5 }],
                    )]),
                    ..RevisionChanges::default()
                },
            ),
            ("newer".into(), RevisionChanges::default()),
        ]);
        let result = select(&inventory, &baselines, &changes)?;
        assert_eq!(
            result.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([a.clone(), c.clone()])
        );
        assert!(result[&a].contains(&Reason::CoveredLines("src/lib.rs".into())));
        assert!(result[&c].contains(&Reason::NewTest));
        Ok(())
    }

    #[test]
    fn structural_backstop_and_explicit_inputs_are_independent() -> Result<()> {
        let scope = ContentId::of(b"scope");
        let a = test("a");
        let b = test("b");
        let c = test("c");
        let inventory =
            BTreeMap::from([(a.clone(), scope), (b.clone(), scope), (c.clone(), scope)]);
        let baselines = BTreeMap::from([
            (a.clone(), baseline(scope, "rev", "src/lib.rs", 10, 20)),
            (b.clone(), baseline(scope, "rev", "src/lib.rs", 30, 40)),
            (c.clone(), baseline(scope, "rev", "src/other.rs", 1, 9)),
        ]);
        let mut diff = RevisionChanges {
            lines: BTreeMap::from([("src/lib.rs".into(), vec![LineRange { start: 5, end: 5 }])]),
            explicit: BTreeMap::from([(c.clone(), BTreeSet::from(["fixtures/data.bin".into()]))]),
            ..RevisionChanges::default()
        };
        let result = select(
            &inventory,
            &baselines,
            &BTreeMap::from([("rev".into(), diff.clone())]),
        )?;
        assert!(result[&a].contains(&Reason::StructuralBackstop("src/lib.rs".into())));
        assert!(result[&b].contains(&Reason::StructuralBackstop("src/lib.rs".into())));
        assert!(result[&c].contains(&Reason::ExplicitInput("fixtures/data.bin".into())));
        diff.lines.get_mut("src/lib.rs").unwrap()[0] = LineRange { start: 15, end: 15 };
        let result = select(
            &inventory,
            &baselines,
            &BTreeMap::from([("rev".into(), diff)]),
        )?;
        assert!(result.contains_key(&a));
        assert!(!result.contains_key(&b));
        assert!(result.contains_key(&c));
        Ok(())
    }

    #[test]
    fn missing_revision_changed_scope_and_incomplete_coverage_run() -> Result<()> {
        let scope = ContentId::of(b"scope");
        let old_scope = ContentId::of(b"other scope");
        let a = test("a");
        let b = test("b");
        let c = test("c");
        let d = test("d");
        let inventory = BTreeMap::from([
            (a.clone(), scope),
            (b.clone(), scope),
            (c.clone(), scope),
            (d.clone(), scope),
        ]);
        let mut incomplete = baseline(scope, "rev", "src/lib.rs", 1, 5);
        incomplete.ranges.clear();
        let baselines = BTreeMap::from([
            (a.clone(), baseline(old_scope, "rev", "src/lib.rs", 1, 5)),
            (b.clone(), baseline(scope, "missing", "src/lib.rs", 1, 5)),
            (c.clone(), incomplete),
            (d.clone(), baseline(scope, "rev", "src/lib.rs", 1, 5)),
        ]);
        let changes = BTreeMap::from([(
            "rev".into(),
            RevisionChanges {
                global: BTreeSet::from(["Cargo.lock".into()]),
                ..RevisionChanges::default()
            },
        )]);
        let result = select(&inventory, &baselines, &changes)?;
        assert_eq!(result[&a], BTreeSet::from([Reason::ScopeChanged]));
        assert_eq!(result[&b], BTreeSet::from([Reason::RevisionUnavailable]));
        assert_eq!(result[&c], BTreeSet::from([Reason::InvalidBaseline]));
        assert_eq!(
            result[&d],
            BTreeSet::from([Reason::GlobalInput("Cargo.lock".into())])
        );
        Ok(())
    }
}
