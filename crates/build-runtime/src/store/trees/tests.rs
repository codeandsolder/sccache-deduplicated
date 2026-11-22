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
            Artifact::File {
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
    let published = store.publish(&action, &result, vec![])?;
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
    assert_eq!(lease.open_file(blob.id)?.metadata()?.len(), blob.size);
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

#[test]
fn result_tree_and_input_tree_share_and_retain_leaf_blobs() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path())?;
    let staged = store.stage(&b"codegen unit"[..])?;
    let blob = staged.reference();
    let tree = sample_tree(blob)?;
    let id = store.publish_tree(&tree, vec![staged])?;
    let result = ResultManifest {
        outputs: BTreeMap::from([
            ("codegen".into(), Artifact::Tree(tree)),
            (
                "object".into(),
                Artifact::File {
                    blob,
                    mode: Some(0o644),
                },
            ),
        ]),
        stdout: None,
        stderr: None,
    };
    let fingerprint = ActionFingerprint {
        schema: "generated-tree-test".into(),
        components: BTreeMap::from([("compiler".into(), ContentId::of(b"rustc"))]),
    };
    let published = store.publish(&fingerprint, &result, vec![])?;
    assert_eq!(store.stats()?.blobs, 1);
    let lease = store
        .lookup(published.action)?
        .context("result tree missing")?;
    assert_eq!(
        store.evict_tree(id)?,
        Eviction::Removed {
            unreferenced_logical_bytes: 0
        }
    );
    assert_eq!(store.evict(published.action)?, Eviction::Pinned);
    assert_eq!(lease.manifest(), &result);
    assert_eq!(lease.open_file(blob.id)?.metadata()?.len(), blob.size);
    drop(lease);
    assert_eq!(
        store.evict(published.action)?,
        Eviction::Removed {
            unreferenced_logical_bytes: blob.size
        }
    );
    assert_eq!(store.collect_garbage(100)?.blobs, 1);
    Ok(())
}
