use std::{collections::BTreeMap, fs, io::Read, process::Command};

use super::*;
use crate::{
    BuildPath, CommandSpec, ExecutionRoot, OutputSpec, TreeManifest, TreeMetadata, TreeRecipe,
    TreeTimestamp,
};

fn execute_test(
    spec: &ExecutionSpec,
    store: &NativeStore,
    policy: &ExecutionPolicy,
    budget: Option<StageBudget>,
    progress: impl FnMut() -> Result<()>,
) -> Result<CapturedExecution> {
    let inputs = acquire_execution_inputs(spec, store)?;
    execute(spec, store, policy, &inputs, budget, progress, |_| {})
}

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
            .or_insert_with(|| TreeEntry::Directory(metadata(0o755)));
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

/// Compile-like execution with a stable executable and header tree but
/// different source content. A whole-tree action identity is still supplied
/// each time; the worker reuses the pinned base view internally.

#[test]
#[ignore = "requires Linux Bubblewrap and ldd"]
fn changing_directory_entries_uses_correct_sandbox_namespace() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    verify_directory_execution(tmp.path())?;
    let checkout = std::env::current_dir()?;
    let checkout_backed = tempfile::tempdir_in(checkout)?;
    verify_directory_execution(checkout_backed.path())?;
    Ok(())
}

fn initial_directory_execution_tree(store: &NativeStore) -> Result<(TreeManifest, crate::TreeId)> {
    let shell = shell_root(store)?;
    let mut manifest = store
        .lookup_tree(shell)?
        .context("test shell unavailable")?
        .manifest()
        .clone();
    manifest.entries.insert(
        TreePath::new(b"src/work".to_vec())?,
        TreeEntry::Directory(metadata(0o755)),
    );
    let first_source = store.stage(&b"alpha\n"[..])?;
    let obsolete = store.stage(&b"obsolete"[..])?;
    let headers = store.stage(&b"header"[..])?;
    manifest.entries.insert(
        TreePath::new(b"src/work/source".to_vec())?,
        TreeEntry::File {
            blob: first_source.reference(),
            metadata: metadata(0o644),
        },
    );
    manifest.entries.insert(
        TreePath::new(b"src/work/alias".to_vec())?,
        TreeEntry::Hardlink(TreePath::new(b"src/work/source".to_vec())?),
    );
    manifest.entries.insert(
        TreePath::new(b"src/work/removed".to_vec())?,
        TreeEntry::File {
            blob: obsolete.reference(),
            metadata: metadata(0o644),
        },
    );
    manifest.entries.insert(
        TreePath::new(b"src/work/sym".to_vec())?,
        TreeEntry::Symlink {
            target: b"source".to_vec(),
            modified: metadata(0o755).modified,
        },
    );
    for number in 0..96 {
        manifest.entries.insert(
            TreePath::new(format!("src/header-{number:03}").into_bytes())?,
            TreeEntry::File {
                blob: headers.reference(),
                metadata: metadata(0o644),
            },
        );
    }
    let first = store.publish_tree(&manifest, vec![first_source, obsolete, headers])?;
    Ok((manifest, first))
}

fn shell_output_fixture(
    parent: &Path,
    first: crate::TreeId,
    platform: ContentId,
    script: &[u8],
) -> Result<(ExecutionSpec, ExecutionPolicy)> {
    let spec = ExecutionSpec {
        compiler_result: None,
        platform,
        root: ExecutionRoot {
            id: first,
            recipe: TreeRecipe::union(metadata(0o755), [first]),
        },
        mounts: BTreeMap::new(),
        command: CommandSpec {
            umask: 0o022,
            executable: BuildPath::new(b"/bin/sh".to_vec())?,
            arguments: vec![b"-c".to_vec(), script.to_vec()],
            cwd: BuildPath::new(b"/src".to_vec())?,
            environment: BTreeMap::new(),
        },
        outputs: BTreeMap::from([(
            "object".into(),
            OutputSpec {
                path: BuildPath::new(b"/out/nested/object".to_vec())?,
                required: true,
                kind: crate::OutputKind::File,
            },
        )]),
    };
    let policy = ExecutionPolicy {
        platform,
        bubblewrap: "/usr/bin/bwrap".into(),
        scratch: parent.to_owned(),
        timeout: Duration::from_secs(20),
        max_result_bytes: 1024,
    };
    Ok((spec, policy))
}

fn read_shell_output(
    spec: &ExecutionSpec,
    store: &NativeStore,
    policy: &ExecutionPolicy,
) -> Result<Vec<u8>> {
    let execution = execute_test(spec, store, policy, None, || Ok(()))?;
    let manifest = execution
        .successful_result()
        .context("shell action failed")?;
    let mut bytes = Vec::new();
    execution
        .open_blob(manifest.outputs["object"].test_file_blob().id)?
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn verify_directory_execution(parent: &Path) -> Result<()> {
    let store = NativeStore::open(&parent.join("store"))?;
    let (mut manifest, first) = initial_directory_execution_tree(&store)?;
    let platform = ContentId::of(b"subtree differential");
    let (mut spec, policy) = shell_output_fixture(parent, first, platform, br#"IFS= read -r line < /src/work/sym; if test -e /src/work/removed; then suffix=old; else suffix=new; fi; printf '%s:%s' "$line" "$suffix" > /out/nested/object"#)?;
    let run = |spec: &ExecutionSpec| read_shell_output(spec, &store, &policy);
    assert_eq!(run(&spec)?, b"alpha:old");

    let second_source = store.stage(&b"beta\n"[..])?;
    let added = store.stage(&b"gamma\n"[..])?;
    manifest.entries.insert(
        TreePath::new(b"src/work/source".to_vec())?,
        TreeEntry::File {
            blob: second_source.reference(),
            metadata: metadata(0o644),
        },
    );
    manifest
        .entries
        .remove(&TreePath::new(b"src/work/removed".to_vec())?);
    manifest.entries.insert(
        TreePath::new(b"src/work/added".to_vec())?,
        TreeEntry::File {
            blob: added.reference(),
            metadata: metadata(0o644),
        },
    );
    manifest.entries.insert(
        TreePath::new(b"src/work/sym".to_vec())?,
        TreeEntry::Symlink {
            target: b"added".to_vec(),
            modified: metadata(0o755).modified,
        },
    );
    let second = store.publish_tree(&manifest, vec![second_source, added])?;
    spec.root = ExecutionRoot {
        id: second,
        recipe: TreeRecipe::union(metadata(0o755), [second]),
    };
    assert_eq!(run(&spec)?, b"gamma:new");
    let target = store.lookup_tree(second)?.context("target root missing")?;
    let view = store.mount_tree_protected(target, parent, &[PathBuf::from("out")])?;
    let bindings = view.overlay_bindings().collect::<Vec<_>>();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].0, &TreePath::new(b"src/work".to_vec())?);
    assert_eq!(
        fs::metadata(bindings[0].1.join("source"))?.ino(),
        fs::metadata(bindings[0].1.join("alias"))?.ino()
    );
    Ok(())
}

#[test]
#[ignore = "requires Linux Bubblewrap and ldd"]
fn distinct_roots_execute_their_own_source_bytes_via_cached_file_overlays() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let store = NativeStore::open(&temporary.path().join("store"))?;
    let toolchain = shell_root(&store)?;
    let mut manifest = store
        .lookup_tree(toolchain)?
        .context("test shell tree missing")?
        .manifest()
        .clone();
    let source_path = TreePath::new(b"src/source".to_vec())?;
    let original = store.stage(&b"first\n"[..])?;
    manifest.entries.insert(
        source_path.clone(),
        TreeEntry::File {
            blob: original.reference(),
            metadata: metadata(0o644),
        },
    );
    let header = store.stage(&b"identical header\n"[..])?;
    for index in 0..96 {
        manifest.entries.insert(
            TreePath::new(format!("src/header-{index:03}").into_bytes())?,
            TreeEntry::File {
                blob: header.reference(),
                metadata: metadata(0o644),
            },
        );
    }
    let first = store.publish_tree(&manifest, vec![original, header])?;
    let platform = ContentId::of(b"overlay test platform");
    let (mut spec, policy) = shell_output_fixture(
        temporary.path(),
        first,
        platform,
        br#"IFS= read -r line < /src/source; printf '%s' "$line" > /out/nested/object"#,
    )?;
    let output = |spec: &ExecutionSpec| read_shell_output(spec, &store, &policy);
    assert_eq!(output(&spec)?, b"first");

    let changed = store.stage(&b"second\n"[..])?;
    manifest.entries.insert(
        source_path,
        TreeEntry::File {
            blob: changed.reference(),
            metadata: metadata(0o644),
        },
    );
    let second = store.publish_tree(&manifest, vec![changed])?;
    spec.root = ExecutionRoot {
        id: second,
        recipe: TreeRecipe::union(metadata(0o755), [second]),
    };
    assert_eq!(output(&spec)?, b"second");
    let target = store.lookup_tree(second)?.context("second input missing")?;
    let view = store.mount_tree_protected(target, temporary.path(), &[PathBuf::from("out")])?;
    assert_eq!(view.overlay_bindings().count(), 1);
    assert_eq!(
        view.overlay_stats()
            .context("missing clone statistics")?
            .cloned_files,
        u64::from(store.uses_native_zfs())
    );
    Ok(())
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
        compiler_result: None,
        platform, root: ExecutionRoot { id: root, recipe: TreeRecipe::union(metadata(0o755), [root]) },
        mounts: BTreeMap::from([(BuildPath::new(b"/src".to_vec())?, src)]),
        command: CommandSpec {
            umask: 0o022,
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
    let result = execute_test(&spec, &store, &policy, None, || Ok(()))?;
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
    assert!(execute_test(&forged, &store, &policy, None, || Ok(())).is_err());

    // Failures must retain diagnostics without publishing a successful entry.
    spec.command.arguments[1] = b"printf 'failed' >&2; exit 7".to_vec();
    let result = execute_test(&spec, &store, &policy, None, || Ok(()))?;
    assert_eq!(result.status().code(), Some(7));
    assert!(result.successful_result().is_none());
    assert_eq!(
        result.diagnostics().1.context("stderr missing")?.id,
        ContentId::of(b"failed")
    );
    verify_writable_mounts_and_invalid_outputs(
        &mut spec,
        &store,
        &policy,
        src,
        &original_manifest,
    )?;
    Ok(())
}

fn verify_writable_mounts_and_invalid_outputs(
    spec: &mut ExecutionSpec,
    store: &NativeStore,
    policy: &ExecutionPolicy,
    src: crate::TreeId,
    original_manifest: &TreeManifest,
) -> Result<()> {
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
    let result = execute_test(spec, store, policy, None, || Ok(()))?;
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
    let result = execute_test(spec, store, policy, None, || Ok(()))?;
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
        original_manifest
    );
    // Generated-only mode never returns existing input files, even if the
    // original logical output directory also contains compiler dependencies.
    spec.outputs.get_mut("codegen").context("output")?.kind = crate::OutputKind::GeneratedTree;
    spec.command.arguments[1] =
        b"printf generated > /src/first.o; printf second > /src/second.o".to_vec();
    let result = execute_test(spec, store, policy, None, || Ok(()))?;
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
    assert!(execute_test(spec, store, policy, None, || Ok(())).is_err());

    spec.outputs = file_outputs;
    spec.command.arguments[1] = b"printf new > object".to_vec();

    // A preexisting input cannot silently serve as a compiler output.
    spec.outputs.get_mut("object").context("output")?.path =
        BuildPath::new(b"/src/input".to_vec())?;
    assert!(execute_test(spec, store, policy, None, || Ok(())).is_err());
    spec.outputs.get_mut("object").context("output")?.path =
        BuildPath::new(b"/src/missing/object".to_vec())?;
    assert!(execute_test(spec, store, policy, None, || Ok(())).is_err());
    // A symlink must never make host bytes a cached output.
    spec.command.arguments[1] = b"printf ok > /out/nested/object".to_vec();
    spec.platform = ContentId::of(b"incorrect");
    assert!(execute_test(spec, store, policy, None, || Ok(())).is_err());
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
        staged: BTreeMap::new(),
        budget: None,
        remaining: 100,
        scratch: dir.path().to_path_buf(),
        encoding: crate::BlobEncoding::ZstdChunks,
    };
    let spec = ExecutionSpec {
        compiler_result: None,
        platform: ContentId::of(b"platform"),
        root: ExecutionRoot {
            id: crate::TreeId([0; 32]),
            recipe: TreeRecipe::union(metadata(0o755), [crate::TreeId([0; 32])]),
        },
        mounts: BTreeMap::new(),
        command: CommandSpec {
            umask: 0o022,
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

#[tokio::test]
async fn captured_output_publication_reuses_original_inode() -> Result<()> {
    use crate::{ActionFingerprint, ActionMode, SpacePolicy};
    use std::io::Write as _;

    let dir = tempfile::tempdir()?;
    let store = NativeStore::open_managed(
        dir.path(),
        SpacePolicy {
            min_available_bytes: 100,
            target_available_bytes: 200,
            max_resident_bytes: 1024 * 1024,
            target_resident_bytes: 1024 * 1024,
            max_evictions_per_pass: 4,
            gc_batch: 16,
        },
    )?;
    let mut capture = Capture {
        files: BTreeMap::new(),
        staged: BTreeMap::new(),
        budget: Some(store.reserve_staging(4096)?),
        remaining: 4096,
        scratch: dir.path().to_path_buf(),
        encoding: store.physical_encoding(),
    };
    let bytes = b"one physical compiler output, used twice";
    let mut input = tempfile::tempfile_in(dir.path())?;
    input.write_all(bytes)?;
    let blob = capture.file(input.try_clone()?)?;
    assert_eq!(capture.file(input)?, blob);
    assert_eq!(capture.staged.len(), 1);
    let mut result = CapturedExecution {
        status: ExitStatus::from_raw(0),
        timings: ExecutionTimings::default(),
        manifest: ResultManifest {
            outputs: BTreeMap::from([("obj".into(), Artifact::File { blob, mode: None })]),
            stdout: None,
            stderr: None,
        },
        files: capture.files,
        staged: capture.staged,
        encoding: capture.encoding,
    };
    drop(capture.budget);
    assert_eq!(store.space_status()?.reserved_bytes, Some(blob.size));
    let before = result.open_file(blob.id)?.metadata()?;
    let existing = store.reserve_upload(&result.manifest)?;
    assert_eq!(existing.missing(), &[blob]);
    let staged = result.seal_staged(existing.missing()).await?;
    let lease = store
        .publish_pinned_async(
            ActionFingerprint {
                schema: "capture-test".into(),
                components: BTreeMap::new(),
            },
            result.manifest.clone(),
            staged,
            ActionMode::Reuse,
            existing,
        )
        .await?;
    let after = lease.open_file(blob.id)?.metadata()?;
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    let mut decoded = Vec::new();
    result.open_blob(blob.id)?.read_to_end(&mut decoded)?;
    assert_eq!(decoded, bytes);
    assert_eq!(store.space_status()?.reserved_bytes, Some(0));
    assert_eq!(fs::read_dir(dir.path().join("staging"))?.count(), 0);
    Ok(())
}

#[test]
#[ignore = "requires Linux Bubblewrap and ldd"]
fn resident_execution_isolates_concurrent_writable_state() -> Result<()> {
    for directory in [
        tempfile::tempdir()?,
        tempfile::tempdir_in(std::env::current_dir()?)?,
    ] {
        let store = NativeStore::open(&directory.path().join("store"))?;
        let id = shell_root(&store)?;
        let (spec, policy) = shell_output_fixture(
            directory.path(),
            id,
            ContentId::of(b"resident concurrency"),
            b"",
        )?;
        let inputs = acquire_execution_inputs(&spec, &store)?;
        assert!(admitted_inputs(&spec, &store, &[]).is_err());
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| -> Result<()> {
            let handles = (0..8).map(|index| {
                let (store, policy, inputs, barrier) = (&store, &policy, &inputs, &barrier);
                let mut spec = spec.clone();
                scope.spawn(move || -> Result<()> {
                    let script = format!("test ! -e /tmp/marker && test ! -e /out/nested/object || exit 9; printf '{index}' > /tmp/marker; printf '{index}' > /out/nested/object");
                    spec.command.arguments[1] = script.into_bytes();
                    barrier.wait();
                    let mut phases = Vec::new();
                    let captured = execute(&spec, store, policy, inputs, None, || Ok(()), |phase| phases.push(phase))?;
                    assert_eq!(phases, [ExecutionPhase::Preparation, ExecutionPhase::Process, ExecutionPhase::Capture]);
                    let result = captured.successful_result().context("isolated job failed")?;
                    let mut output = Vec::new();
                    captured.open_blob(result.outputs["object"].test_file_blob().id)?.read_to_end(&mut output)?;
                    assert_eq!(output, index.to_string().as_bytes());
                    Ok(())
                })
            }).collect::<Vec<_>>();
            for handle in handles {
                handle.join().expect("execution worker")?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn pidfd_wait_reaps_completed_and_cancelled_children() -> Result<()> {
    let mut child = RunningChild(Command::new("/bin/sh").args(["-c", "exit 17"]).spawn()?);
    assert_eq!(
        child.wait(Duration::from_secs(5), || Ok(()))?.code(),
        Some(17)
    );
    for timeout in [true, false] {
        let mut child = RunningChild(Command::new("/bin/sleep").arg("30").spawn()?);
        let pidfd = pidfd_open(Pid::from_child(&child.0), PidfdFlags::empty())?;
        let result = if timeout {
            child.wait(Duration::from_millis(10), || Ok(()))
        } else {
            child.wait(Duration::from_secs(5), || anyhow::bail!("cancelled"))
        };
        assert!(result.is_err());
        drop(child);
        let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
        assert_eq!(
            poll(&mut fds, Some(&Timespec::try_from(Duration::ZERO)?))?,
            1
        );
    }
    Ok(())
}
