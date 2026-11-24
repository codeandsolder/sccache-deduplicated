use super::*;
use sccache::build_runtime::{
    BuildPath, CommandSpec, ExecutionRoot, TreeId, TreeMetadata, TreeRecipe, TreeTimestamp,
};
use std::collections::BTreeMap;

fn spec(args: &[&str]) -> anyhow::Result<ExecutionSpec> {
    let root = TreeId([0; 32]);
    Ok(ExecutionSpec {
        platform: ContentId::of(b"platform"),
        root: ExecutionRoot {
            id: root,
            recipe: TreeRecipe::union(
                TreeMetadata {
                    mode: 0o755,
                    modified: TreeTimestamp {
                        seconds: 1,
                        nanoseconds: 0,
                    },
                },
                [root],
            ),
        },
        mounts: BTreeMap::new(),
        command: CommandSpec {
            executable: BuildPath::new(b"/toolchain/bin/rustc".to_vec())?,
            arguments: args.iter().map(|arg| arg.as_bytes().to_vec()).collect(),
            cwd: BuildPath::new(b"/src".to_vec())?,
            environment: BTreeMap::new(),
        },
        outputs: BTreeMap::new(),
    })
}

#[test]
fn native_cost_class_ignores_rust_identity_hashes_but_not_codegen() -> anyhow::Result<()> {
    let a = spec(&[
        "--crate-name",
        "foo",
        "--extern",
        "dep=/a/libdep-a.rlib",
        "-C",
        "metadata=123",
        "-Cextra-filename=-aaa",
        "--emit=link",
        "-Copt-level=3",
    ])?;
    let b = spec(&[
        "--crate-name",
        "foo",
        "--extern=dep=/b/libdep-b.rlib",
        "-Cmetadata=456",
        "-C",
        "extra-filename=-bbb",
        "--emit=link",
        "-Copt-level=3",
    ])?;
    assert_eq!(ActionClass::from_spec(&a)?, ActionClass::from_spec(&b)?);
    let mut changed = b.clone();
    changed.command.arguments.push(b"--test".to_vec());
    assert_ne!(
        ActionClass::from_spec(&a)?,
        ActionClass::from_spec(&changed)?
    );
    changed = b.clone();
    changed.command.arguments[6] = b"--emit=metadata".to_vec();
    assert_ne!(
        ActionClass::from_spec(&a)?,
        ActionClass::from_spec(&changed)?
    );
    changed = b.clone();
    changed.platform = ContentId::of(b"different platform");
    assert_ne!(
        ActionClass::from_spec(&a)?,
        ActionClass::from_spec(&changed)?
    );
    Ok(())
}

#[test]
fn native_cost_history_shrinks_expires_and_bounds_samples() -> anyhow::Result<()> {
    let class = ActionClass::from_spec(&spec(&["--crate-name", "foo"])?)?;
    let now = Instant::now();
    let placement = NativePlacement::default();
    let prior = ActionCost::baseline(&placement);
    let mut costs = ActionCosts::default();
    let observation = ActionObservation {
        execution_nanoseconds: 9_000_000_000,
        worker_timing: None,
        warm_staging_nanoseconds: None,
        publication_setup_nanoseconds: None,
        upload_bytes: 0,
        upload_requests: 0,
        upload_nanoseconds: 0,
    };
    assert_eq!(costs.predict(Some(class), &placement, now), prior);
    costs.observe(class, observation, 752, now);
    assert_eq!(
        costs
            .predict(Some(class), &placement, now)
            .execution_nanoseconds,
        3_000_000_000
    );
    for _ in 0..3 {
        costs.observe(class, observation, 752, now);
    }
    assert_eq!(
        costs.predict(Some(class), &placement, now),
        ActionCost {
            phase: Default::default(),
            execution_nanoseconds: observation.execution_nanoseconds,
            output_bytes: 0,
            output_requests: 0,
        }
    );
    assert_eq!(costs.predict(Some(class), &placement, now + MAX_AGE), prior);
    costs.observe(
        class,
        ActionObservation {
            execution_nanoseconds: 0,
            ..observation
        },
        752,
        now,
    );
    assert_eq!(costs.entries[&class].observations, 4);
    costs.observe(class, observation, 752, now + MAX_AGE);
    assert_eq!(costs.entries[&class].observations, 1);
    for n in 0..MAX_CLASSES {
        costs.observe(
            ActionClass(ContentId::of(&n.to_le_bytes())),
            observation,
            752,
            now + MAX_AGE + Duration::from_secs(1),
        );
    }
    assert_eq!(costs.entries.len(), MAX_CLASSES);
    assert!(!costs.entries.contains_key(&class));
    Ok(())
}
