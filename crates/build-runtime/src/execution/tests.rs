use std::{collections::BTreeMap, fs, io::Read, process::Command};

use super::*;
use crate::{
    BuildPath, CommandSpec, ExecutionRoot, OutputSpec, TreeManifest, TreeMetadata, TreeRecipe,
    TreeTimestamp,
};

fn metadata(mode: u32) -> TreeMetadata {
    TreeMetadata {
        mode,
        modified: TreeTimestamp {
            seconds: 1,
            nanoseconds: 0,
        },
    }
}

fn add_parents(entries: &mut BTreeMap<TreePath, TreeEntry>, path: &[u8]) -> Result<()> {
    for (index, _) in path.iter().enumerate().filter(|(_, byte)| **byte == b'/') {
        entries
            .entry(TreePath::new(path[..index].to_vec())?)
            .or_insert(TreeEntry::Directory(metadata(0o755)));
    }
    Ok(())
}

fn shell_root(store: &NativeStore) -> Result<crate::TreeId> {
    let mut entries = BTreeMap::new();
    for path in [
        b"bin".as_slice(),
        b"out",
        b"out/nested",
        b"tmp",
        b"proc",
        b"dev",
        b"src",
        b"other",
    ] {
        entries.insert(
            TreePath::new(path.to_vec())?,
            TreeEntry::Directory(metadata(0o755)),
        );
    }
    let mut paths = BTreeMap::from([(PathBuf::from("/bin/sh"), PathBuf::from("bin/sh"))]);
    let dependencies = Command::new("ldd").arg("/bin/sh").output()?;
    ensure!(
        dependencies.status.success(),
        "cannot determine shell dependencies"
    );
    let dependencies = std::str::from_utf8(&dependencies.stdout)?;
    for line in dependencies.lines() {
        if let Some(path) = line.split_whitespace().find(|part| part.starts_with('/')) {
            paths.insert(
                PathBuf::from(path),
                PathBuf::from(path.strip_prefix('/').context("library path")?),
            );
        }
    }
    let mut staged = BTreeMap::new();
    for (source, target) in paths {
        let path = target.as_os_str().as_bytes();
        add_parents(&mut entries, path)?;
        let blob = store.stage(File::open(source)?)?;
        let reference = blob.reference();
        staged.entry(reference.id).or_insert(blob);
        entries.insert(
            TreePath::new(path.to_vec())?,
            TreeEntry::File {
                blob: reference,
                metadata: metadata(0o755),
            },
        );
    }
    let manifest = TreeManifest {
        root: metadata(0o755),
        entries,
    };
    store.publish_tree(&manifest, staged.into_values().collect())
}

#[test]
#[ignore = "requires Linux Bubblewrap and ldd"]
fn executes_from_content_addressed_inputs_and_captures_outputs_without_archives() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(&dir.path().join("store"))?;
    let root = shell_root(&store)?;
    let input = store.stage(&b"hello native\n"[..])?;
    let tree = TreeManifest {
        root: metadata(0o755),
        entries: BTreeMap::from([(
            TreePath::new(b"input".to_vec())?,
            TreeEntry::File {
                blob: input.reference(),
                metadata: metadata(0o644),
            },
        )]),
    };
    let original_manifest = tree;
    let src = store.publish_tree(&original_manifest, vec![input])?;
    let platform = ContentId::of(b"test platform");
    let mut spec = ExecutionSpec {
        platform, root: ExecutionRoot { id: root, recipe: TreeRecipe::union(metadata(0o755), [root]) },
        mounts: BTreeMap::from([(BuildPath::new(b"/src".to_vec())?, src)]),
        command: CommandSpec {
            executable: BuildPath::new(b"/bin/sh".to_vec())?,
            arguments: vec![b"-c".to_vec(), b"IFS= read -r word < /src/input; printf '%s' \"$word\" > /out/nested/object; printf 'diagnostic' >&2".to_vec()],
            cwd: BuildPath::new(b"/src".to_vec())?,
            environment: BTreeMap::new(),
        },
        outputs: BTreeMap::from([
            ("obj".into(), OutputSpec { path: BuildPath::new(b"/out/nested/object".to_vec())?, required: true, kind: crate::OutputKind::File }),
            ("optional".into(), OutputSpec { path: BuildPath::new(b"/out/optional".to_vec())?, required: false, kind: crate::OutputKind::File }),
        ]),
    };
    let policy = ExecutionPolicy {
        platform,
        bubblewrap: "/usr/bin/bwrap".into(),
        scratch: dir.path().into(),
        timeout: Duration::from_secs(10),
        max_result_bytes: 1024,
    };
    let result = execute(&spec, &store, &policy, || Ok(()))?;
    let manifest = result.successful_result().context("native shell failed")?;
    spec.action_request()?.validate_result(manifest)?;
    let object = manifest.outputs.get("obj").context("object missing")?;
    let mut bytes = Vec::new();
    let mut a = result.open_blob(object.test_file_blob().id)?;
    let mut b = result.open_blob(object.test_file_blob().id)?;
    let mut first = [0];
    a.read_exact(&mut first)?;
    b.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"hello native");
    assert_eq!(first, [b'h']);
    assert_eq!(
        result.diagnostics().1.context("stderr missing")?.id,
        ContentId::of(b"diagnostic")
    );
    assert_eq!(store.stats()?.actions, 0);

    let mut forged = spec.clone();
    forged.root.id = crate::TreeId([0xA5; 32]);
    assert!(execute(&forged, &store, &policy, || Ok(())).is_err());

    // Failures must retain diagnostics without publishing a successful entry.
    spec.command.arguments[1] = b"printf 'failed' >&2; exit 7".to_vec();
    let result = execute(&spec, &store, &policy, || Ok(()))?;
    assert_eq!(result.status().code(), Some(7));
    assert!(result.successful_result().is_none());
    assert_eq!(
        result.diagnostics().1.context("stderr missing")?.id,
        ContentId::of(b"failed")
    );
    // Two mounts of the same tree must be independent even when one is
    // writable. Preserve the compiler's relative output path and input
    // dependencies without rewriting any invocation arguments.
    spec.mounts.insert(BuildPath::new(b"/other".to_vec())?, src);
    spec.outputs = BTreeMap::from([
        (
            "object".into(),
            OutputSpec {
                path: BuildPath::new(b"/src/object".to_vec())?,
                required: true,
                kind: crate::OutputKind::File,
            },
        ),
        (
            "scratch".into(),
            OutputSpec {
                path: BuildPath::new(b"/tmp/result".to_vec())?,
                required: true,
                kind: crate::OutputKind::File,
            },
        ),
    ]);
    spec.command.arguments[1] = br#"printf new > object; test ! -e /other/object || exit 8; IFS= read -r word < /other/input; printf '%s' "$word" > /tmp/result"#.to_vec();
    let result = execute(&spec, &store, &policy, || Ok(()))?;
    let manifest = result
        .successful_result()
        .context("in-place output execution failed")?;
    let mut content = Vec::new();
    result
        .open_blob(manifest.outputs["scratch"].test_file_blob().id)?
        .read_to_end(&mut content)?;
    assert_eq!(content, b"hello native");
    assert!(
        !store
            .lookup_tree(src)?
            .context("missing original tree")?
            .manifest()
            .entries
            .contains_key(&TreePath::new(b"object".to_vec())?)
    );

    let file_outputs = spec.outputs.clone();
    spec.outputs = BTreeMap::from([(
        "codegen".into(),
        OutputSpec {
            path: BuildPath::new(b"/src".to_vec())?,
            required: true,
            kind: crate::OutputKind::Tree,
        },
    )]);
    spec.command.arguments[1] = b"printf generated > /src/first.o; printf second > /src/second.o; printf changed > /src/input".to_vec();
    let result = execute(&spec, &store, &policy, || Ok(()))?;
    let manifest = result
        .successful_result()
        .context("tree output execution failed")?;
    spec.action_request()?.validate_result(manifest)?;
    let Artifact::Tree(tree) = &manifest.outputs["codegen"] else {
        anyhow::bail!("expected complete directory output");
    };
    assert_eq!(tree.entries.len(), 3);
    let mut seen = BTreeMap::new();
    for (path, entry) in &tree.entries {
        let TreeEntry::File { blob, .. } = entry else {
            anyhow::bail!("expected file");
        };
        let mut bytes = Vec::new();
        result.open_blob(blob.id)?.read_to_end(&mut bytes)?;
        seen.insert(path.as_bytes(), bytes);
    }
    assert_eq!(seen[b"first.o".as_slice()], b"generated");
    assert_eq!(seen[b"second.o".as_slice()], b"second");
    assert_eq!(seen[b"input".as_slice()], b"changed");
    assert_eq!(
        store
            .lookup_tree(src)?
            .context("original input")?
            .manifest(),
        &original_manifest
    );
    // Generated-only mode never returns existing input files, even if the
    // original logical output directory also contains compiler dependencies.
    spec.outputs.get_mut("codegen").context("output")?.kind = crate::OutputKind::GeneratedTree;
    spec.command.arguments[1] =
        b"printf generated > /src/first.o; printf second > /src/second.o".to_vec();
    let result = execute(&spec, &store, &policy, || Ok(()))?;
    let manifest = result
        .successful_result()
        .context("generated output execution failed")?;
    let Artifact::GeneratedTree(tree) = &manifest.outputs["codegen"] else {
        anyhow::bail!("expected generated directory output");
    };
    assert_eq!(tree.entries.len(), 2);
    assert!(
        !tree
            .entries
            .contains_key(&TreePath::new(b"input".to_vec())?)
    );
    assert!(
        !manifest
            .blobs()?
            .contains_key(&ContentId::of(b"hello native\n"))
    );
    assert_eq!(manifest.logical_bytes()?, 15);
    for path in [b"first.o".as_slice(), b"second.o"] {
        let Some(TreeEntry::File { blob, .. }) = tree.entries.get(&TreePath::new(path.to_vec())?)
        else {
            anyhow::bail!("generated file missing");
        };
        assert!(result.open_blob(blob.id).is_ok());
    }
    spec.command.arguments[1] = b"printf replaced > /src/input".to_vec();
    assert!(execute(&spec, &store, &policy, || Ok(())).is_err());

    spec.outputs = file_outputs;
    spec.command.arguments[1] = b"printf new > object".to_vec();

    // A preexisting input cannot silently serve as a compiler output.
    spec.outputs.get_mut("object").context("output")?.path =
        BuildPath::new(b"/src/input".to_vec())?;
    assert!(execute(&spec, &store, &policy, || Ok(())).is_err());
    spec.outputs.get_mut("object").context("output")?.path =
        BuildPath::new(b"/src/missing/object".to_vec())?;
    assert!(execute(&spec, &store, &policy, || Ok(())).is_err());
    // A symlink must never make host bytes a cached output.
    spec.command.arguments[1] = b"printf ok > /out/nested/object".to_vec();
    spec.platform = ContentId::of(b"incorrect");
    assert!(execute(&spec, &store, &policy, || Ok(())).is_err());
    Ok(())
}

#[test]
fn rejects_symlink_and_fifo_outputs_without_following_or_blocking() -> Result<()> {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir()?;
    let output = dir.path().join("object");
    symlink("/etc/passwd", &output)?;
    let mut capture = Capture {
        files: BTreeMap::new(),
        remaining: 100,
    };
    let spec = ExecutionSpec {
        platform: ContentId::of(b"platform"),
        root: ExecutionRoot {
            id: crate::TreeId([0; 32]),
            recipe: TreeRecipe::union(metadata(0o755), [crate::TreeId([0; 32])]),
        },
        mounts: BTreeMap::new(),
        command: CommandSpec {
            executable: BuildPath::new(b"/bin/sh".to_vec())?,
            arguments: Vec::new(),
            cwd: BuildPath::new(b"/".to_vec())?,
            environment: BTreeMap::new(),
        },
        outputs: BTreeMap::from([(
            "obj".into(),
            OutputSpec {
                path: BuildPath::new(b"/out/object".to_vec())?,
                required: true,
                kind: crate::OutputKind::File,
            },
        )]),
    };
    let locations = BTreeMap::from([(
        "obj".into(),
        OutputLocation {
            directory: File::open(dir.path())?,
            relative: "object".into(),
            baseline: None,
        },
    )]);
    assert!(capture.outputs(&locations, &spec).is_err());
    fs::remove_file(&output)?;
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &output,
        rustix::fs::FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        0,
    )?;
    assert!(capture.outputs(&locations, &spec).is_err());
    Ok(())
}
