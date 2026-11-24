use std::collections::BTreeMap;

use anyhow::{Context, Result};

use crate::{
    ActionFingerprint, Artifact, BlobRef, ContentId, Eviction, NativeStore, ResultManifest,
    TreeEntry, TreeManifest, TreeMetadata, TreePath, TreeTimestamp,
};

fn metadata(mode: u32) -> TreeMetadata {
    TreeMetadata {
        mode,
        modified: TreeTimestamp {
            seconds: 1234,
            nanoseconds: 5678,
        },
    }
}

fn sample_tree(blob: BlobRef) -> Result<TreeManifest> {
    let file = TreePath::new(b"bin/compiler".to_vec())?;
    Ok(TreeManifest {
        root: metadata(0o555),
        entries: BTreeMap::from([
            (
                TreePath::new(b"bin".to_vec())?,
                TreeEntry::Directory(metadata(0o555)),
            ),
            (
                file.clone(),
                TreeEntry::File {
                    blob,
                    metadata: metadata(0o755),
                },
            ),
            (
                TreePath::new(b"bin/hardlink".to_vec())?,
                TreeEntry::Hardlink(file),
            ),
            (
                TreePath::new(b"bin/alias".to_vec())?,
                TreeEntry::Symlink {
                    target: b"compiler".to_vec(),
                    modified: metadata(0o755).modified,
                },
            ),
            (
                TreePath::new(vec![0xff])?,
                TreeEntry::File {
                    blob,
                    metadata: metadata(0o444),
                },
            ),
        ]),
    })
}

/// Repeatable warm-cache benchmark of real compiler header trees.
/// Only runs explicitly when ignored tests are enabled.
#[test]
#[ignore = "benchmark native ZFS clones against reuse of compressed FUSE trees"]
fn benchmark_native_zfs_clones_against_fuse_views() -> Result<()> {
    use std::{fs, io, path::PathBuf, time::Instant};

    let zfs_dir = tempfile::tempdir()?;
    let memory_dir = tempfile::tempdir_in("/dev/shm")?;
    let zfs = NativeStore::open(&zfs_dir.path().join("store"))?;
    let non_zfs = NativeStore::open(&memory_dir.path().join("store"))?;
    if !zfs.uses_native_zfs() {
        return Ok(());
    }
    let input = zfs_dir.path().join("real-compiler-inputs");
    fs::create_dir(&input)?;
    let mut todo = vec![PathBuf::from("/usr/include")];
    let mut bytes = 0_u64;
    let mut names = Vec::new();
    while let Some(dir) = todo.pop() {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        let mut entries = entries.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
        entries.sort_by_key(fs::DirEntry::path);
        for entry in entries {
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                todo.push(entry.path());
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            let size = entry.metadata()?.len();
            if !(64..=2_000_000).contains(&size)
                || bytes + size > 64 * 1024 * 1024
                || names.len() >= 640
            {
                continue;
            }
            let name = format!("input-{:05}.h", names.len());
            fs::copy(entry.path(), input.join(&name))?;
            names.push(name);
            bytes += size;
        }
        if names.len() >= 640 {
            break;
        }
    }
    anyhow::ensure!(names.len() > 100, "insufficient real compiler inputs");
    eprintln!("BENCH corpus files={} logical_bytes={}", names.len(), bytes);
    let start = Instant::now();
    let zfs_lease = zfs.capture_tree(&input)?;
    let zfs_capture = start.elapsed().as_micros();
    let start = Instant::now();
    let fuse_lease = non_zfs.capture_tree(&input)?;
    let fuse_capture = start.elapsed().as_micros();
    eprintln!("BENCH capture backend=zfs micros={zfs_capture}");
    eprintln!("BENCH capture backend=fuse micros={fuse_capture}");

    for iteration in 0..6 {
        let begin = Instant::now();
        let view = zfs_lease.materialize(zfs_dir.path())?;
        let setup = begin.elapsed().as_micros();
        let start = Instant::now();
        let mut total = 0_u64;
        for name in &names {
            let mut file = fs::File::open(view.root().join(name))?;
            total += io::copy(&mut file, &mut io::sink())?;
        }
        let reading = start.elapsed().as_micros();
        anyhow::ensure!(total == bytes, "ZFS materialized content mismatch");
        let stats = view.stats();
        eprintln!(
            "BENCH run={} backend=zfs setup_us={} read_us={} clones={} copies={} copied_bytes={}",
            iteration, setup, reading, stats.cloned_files, stats.copied_files, stats.copied_bytes,
        );
    }
    for iteration in 0..6 {
        let lease = non_zfs
            .lookup_tree(fuse_lease.id())?
            .context("FUSE tree missing")?;
        let start = Instant::now();
        let view = non_zfs.mount_tree(lease, memory_dir.path())?;
        let setup = start.elapsed().as_micros();
        let start = Instant::now();
        let mut total = 0_u64;
        for name in &names {
            let mut file = fs::File::open(view.root().join(name))?;
            total += io::copy(&mut file, &mut io::sink())?;
        }
        let reading = start.elapsed().as_micros();
        anyhow::ensure!(total == bytes, "FUSE virtual content mismatch");
        eprintln!(
            "BENCH run={} backend=fuse setup_us={} read_us={}",
            iteration, setup, reading,
        );
    }
    Ok(())
}

#[test]
fn zfs_plain_content_materializes_without_fuse() -> Result<()> {
    use std::{io::Read, os::unix::fs::MetadataExt};
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let original = b"compiler-output-with-repeating-structure".repeat(18_000);
    let staged = store.stage(original.as_slice())?;
    let blob = staged.reference();
    let tree = TreeManifest {
        root: metadata(0o755),
        entries: BTreeMap::from([
            (
                TreePath::new(b"bin".to_vec())?,
                TreeEntry::Directory(metadata(0o755)),
            ),
            (
                TreePath::new(b"bin/compiler".to_vec())?,
                TreeEntry::File {
                    blob,
                    metadata: metadata(0o755),
                },
            ),
            (
                TreePath::new(b"bin/alias".to_vec())?,
                TreeEntry::Hardlink(TreePath::new(b"bin/compiler".to_vec())?),
            ),
        ]),
    };
    let id = store.publish_tree(&tree, vec![staged])?;
    let lease = store
        .lookup_tree(id)?
        .context("missing native ZFS test tree")?;
    let view = lease.materialize(dir.path())?;
    assert_eq!(std::fs::read(view.root().join("bin/compiler"))?, original);
    assert_eq!(
        std::fs::metadata(view.root().join("bin/compiler"))?.ino(),
        std::fs::metadata(view.root().join("bin/alias"))?.ino()
    );
    assert_eq!(view.stats().cloned_files + view.stats().copied_files, 1);
    eprintln!(
        "CAS backing ZFS={} cloned_files={} copied_files={} copied_bytes={}",
        store.uses_native_zfs(),
        view.stats().cloned_files,
        view.stats().copied_files,
        view.stats().copied_bytes
    );
    if store.uses_native_zfs() {
        let mut physical = Vec::new();
        lease.open_file(blob.id)?.read_to_end(&mut physical)?;
        assert_eq!(physical, original);
    }
    Ok(())
}

#[test]
fn package_trees_and_actions_share_one_blob_index_across_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let staged = store.stage(&b"compiler artifact"[..])?;
    let blob = staged.reference();
    let tree = sample_tree(blob)?;
    let tree_id = store.publish_tree(&tree, vec![staged])?;
    let mut other = tree.clone();
    other.root.mode = 0o755;
    let other_id = store.publish_tree(&other, vec![])?;
    assert_ne!(tree_id, other_id);
    let result = ResultManifest {
        outputs: BTreeMap::from([(
            "output".into(),
            Artifact {
                blob,
                mode: Some(0o600),
            },
        )]),
        stdout: None,
        stderr: None,
    };
    let action = ActionFingerprint {
        schema: "test".into(),
        components: BTreeMap::from([("source".into(), ContentId::of(b"anything"))]),
    };
    let published = store.publish(&action, &result, vec![], crate::ActionMode::Reuse)?;
    assert_eq!(store.stats()?.blobs, 1);
    assert_eq!(store.stats()?.trees, 2);
    assert_eq!(store.stats()?.logical_bytes, blob.size);
    drop(store);

    let store = NativeStore::open(dir.path())?;
    let lease = store.lookup_tree(tree_id)?.context("tree missing")?;
    assert_eq!(lease.manifest(), &tree);
    assert_eq!(store.evict_tree(tree_id)?, Eviction::Pinned);
    assert_eq!(
        store.evict_tree(other_id)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 0
        }
    );
    assert_eq!(
        store.evict(published.action)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 0
        }
    );
    drop(lease);
    assert_eq!(
        store.evict_tree(tree_id)?,
        Eviction::Removed {
            unreferenced_logical_bytes: blob.size
        }
    );
    assert_eq!(store.collect_garbage(100)?.blobs, 1);
    Ok(())
}

#[test]
fn recipe_lease_pins_original_packages_without_creating_an_indexed_root() -> Result<()> {
    use crate::{TreeLayer, TreeRecipe};
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let staged = store.stage(&b"compiler"[..])?;
    let blob = staged.reference();
    let package = store.publish_tree(&sample_tree(blob)?, vec![staged])?;
    let recipe = TreeRecipe {
        directories: metadata(0o755),
        layers: vec![TreeLayer {
            tree: package,
            source: None,
            destination: Some(TreePath::new(b"toolchain".to_vec())?),
        }],
    };
    let lease = store.lease_recipe(&recipe)?;
    assert_ne!(lease.id(), package);
    assert!(store.lookup_tree(lease.id())?.is_none());
    assert_eq!(store.stats()?.trees, 1);
    assert_eq!(store.evict_tree(package)?, Eviction::Pinned);
    assert_eq!(lease.open_decoded(blob.id)?.len(), blob.size);
    drop(lease);
    assert!(matches!(
        store.evict_tree(package)?,
        Eviction::Removed { .. }
    ));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn materialization_preserves_modes_links_and_timestamps_without_mutating_cas() -> Result<()> {
    use std::{
        ffi::OsStr,
        fs,
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    };

    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(&dir.path().join("store"))?;
    let staged = store.stage(&b"compiler artifact"[..])?;
    let blob = staged.reference();
    let tree = sample_tree(blob)?;
    let id = store.publish_tree(&tree, vec![staged])?;
    let lease = store.lookup_tree(id)?.context("tree missing")?;
    let materialized = lease.materialize(dir.path())?;
    let root = materialized.root();
    let file = root.join("bin/compiler");
    let hardlink = root.join("bin/hardlink");
    let symlink = root.join("bin/alias");
    let distinct = root.join(OsStr::from_bytes(&[0xff]));
    assert_eq!(fs::read(&file)?, b"compiler artifact");
    assert_eq!(fs::metadata(&file)?.ino(), fs::metadata(&hardlink)?.ino());
    assert_ne!(fs::metadata(&file)?.ino(), fs::metadata(&distinct)?.ino());
    assert_eq!(fs::metadata(&file)?.mode() & 0o777, 0o755);
    assert_eq!(fs::metadata(&distinct)?.mode() & 0o777, 0o444);
    assert_eq!(fs::read_link(&symlink)?, std::path::Path::new("compiler"));
    assert_eq!(fs::symlink_metadata(&symlink)?.mtime(), 1234);
    assert_eq!(fs::metadata(root.join("bin"))?.mtime_nsec(), 5678);
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755))?;
    fs::write(&file, b"modified")?;
    let mut original = String::new();
    std::io::Read::read_to_string(&mut lease.open_blob(blob.id)?, &mut original)?;
    assert_eq!(original, "compiler artifact");
    let parent = root
        .parent()
        .context("missing materialized parent")?
        .to_owned();
    drop(materialized);
    assert!(!parent.exists());
    Ok(())
}
