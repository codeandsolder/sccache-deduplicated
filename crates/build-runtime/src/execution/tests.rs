use std::{collections::BTreeMap, io::Read, process::Command};

use super::*;
use crate::{BuildPath, CommandSpec, OutputSpec, TreeManifest, TreeMetadata, TreeTimestamp};

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
    for path in [b"bin".as_slice(), b"out", b"tmp", b"proc", b"dev", b"src"] {
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
    let src = store.publish_tree(&tree, vec![input])?;
    let platform = ContentId::of(b"test platform");
    let mut spec = ExecutionSpec {
        platform, root,
        mounts: BTreeMap::from([(BuildPath::new(b"/src".to_vec())?, src)]),
        command: CommandSpec {
            executable: BuildPath::new(b"/bin/sh".to_vec())?,
            arguments: vec![b"-c".to_vec(), b"IFS= read -r word < /src/input; printf '%s' \"$word\" > /out/nested/object; printf 'diagnostic' >&2".to_vec()],
            cwd: BuildPath::new(b"/src".to_vec())?,
            environment: BTreeMap::new(),
        },
        outputs: BTreeMap::from([
            ("obj".into(), OutputSpec { path: TreePath::new(b"nested/object".to_vec())?, required: true }),
            ("optional".into(), OutputSpec { path: TreePath::new(b"optional".to_vec())?, required: false }),
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
    let mut a = result.open_blob(object.blob.id)?;
    let mut b = result.open_blob(object.blob.id)?;
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

    // Failures must retain diagnostics without publishing a successful entry.
    spec.command.arguments[1] = b"printf 'failed' >&2; exit 7".to_vec();
    let result = execute(&spec, &store, &policy, || Ok(()))?;
    assert_eq!(result.status().code(), Some(7));
    assert!(result.successful_result().is_none());
    assert_eq!(
        result.diagnostics().1.context("stderr missing")?.id,
        ContentId::of(b"failed")
    );
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
        root: crate::TreeId([0; 32]),
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
                path: TreePath::new(b"object".to_vec())?,
                required: true,
            },
        )]),
    };
    assert!(capture.outputs(&dir, &spec).is_err());
    fs::remove_file(&output)?;
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &output,
        rustix::fs::FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        0,
    )?;
    assert!(capture.outputs(&dir, &spec).is_err());
    Ok(())
}
