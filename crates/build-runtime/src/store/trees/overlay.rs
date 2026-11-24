//! Manifest-derived, namespace-preserving physical overlays for cached CAS views.
//! A complete manifest and action identity remain authoritative; these plans
//! only choose which private inodes to bind over a pinned immutable base.
use std::{collections::BTreeSet, ffi::OsStr, os::unix::ffi::OsStrExt, path::PathBuf};

use crate::{TreeEntry, TreeManifest, TreePath};

/// Paths materialized privately from the target tree. A directory overlay
/// includes *all* descendants, including unchanged entries, so additions,
/// removals, symlinks and intra-directory hardlink groups remain observable.
#[derive(Debug)]
pub struct OverlayPlan {
    pub files: Vec<TreePath>,
    pub directories: Vec<TreePath>,
    pub materialized_entries: usize,
}

fn within(path: &TreePath, directory: &TreePath) -> bool {
    path == directory
        || path
            .as_bytes()
            .strip_prefix(directory.as_bytes())
            .is_some_and(|suffix| suffix.starts_with(b"/"))
}

fn intersects_protected(path: &TreePath, protected: &[PathBuf]) -> bool {
    let path = std::path::Path::new(OsStr::from_bytes(path.as_bytes()));
    protected
        .iter()
        .any(|protected| path.starts_with(protected) || protected.starts_with(path))
}

/// Single-file fast path when every path, directory and hardlink identity is
/// fixed. A file with any hardlink aliases cannot be independently replaced.
pub(super) fn compatible_regular_file_overlays(
    base: &TreeManifest,
    target: &TreeManifest,
    protected: &[PathBuf],
) -> Option<Vec<TreePath>> {
    if base.root != target.root || base.entries.len() != target.entries.len() {
        return None;
    }
    let mut changed = Vec::new();
    for ((base_path, old), (target_path, new)) in base.entries.iter().zip(&target.entries) {
        if base_path != target_path {
            return None;
        }
        if old == new {
            continue;
        }
        match (old, new) {
            (TreeEntry::File { .. }, TreeEntry::File { .. }) => {
                let path = std::path::Path::new(OsStr::from_bytes(target_path.as_bytes()));
                if protected.iter().any(|region| path.starts_with(region)) {
                    return None;
                }
                changed.push(target_path.clone());
            }
            _ => return None,
        }
    }
    if changed.is_empty() {
        return None;
    }
    let changed_targets: BTreeSet<_> = changed.iter().collect();
    if target.entries.values().any(
        |entry| matches!(entry, TreeEntry::Hardlink(source) if changed_targets.contains(source)),
    ) {
        return None;
    }
    Some(changed)
}

/// Find an existing directory that can replace a structurally modified entry
/// without synthesizing a nonexistent mount target. For changed directory
/// metadata, use the directory itself; otherwise its nearest common parent.
fn covering_directory(
    path: &TreePath,
    base: &TreeManifest,
    target: &TreeManifest,
) -> Option<TreePath> {
    let is_directory = |path: &TreePath| {
        matches!(base.entries.get(path), Some(TreeEntry::Directory(_)))
            && matches!(target.entries.get(path), Some(TreeEntry::Directory(_)))
    };
    let mut candidate = if is_directory(path) {
        Some(path.clone())
    } else {
        path.parent()
    };
    while let Some(dir) = candidate {
        if is_directory(&dir) {
            return Some(dir);
        }
        candidate = dir.parent();
    }
    None
}

/// Plan file overlays first, then minimal disjoint existing directory
/// replacements for additions, removals and topology changes.
///
/// Reject cross-region hardlinks, protected writable/nested system regions
/// and changes to the root. Full materialization handles those cases.
pub fn plan_overlays(
    base: &TreeManifest,
    target: &TreeManifest,
    protected: &[PathBuf],
) -> Option<OverlayPlan> {
    if let Some(files) = compatible_regular_file_overlays(base, target, protected) {
        return Some(OverlayPlan {
            materialized_entries: files.len(),
            files,
            directories: Vec::new(),
        });
    }
    if base.root != target.root {
        return None;
    }
    let hardlink_targets: BTreeSet<_> = base
        .entries
        .values()
        .chain(target.entries.values())
        .filter_map(|entry| match entry {
            TreeEntry::Hardlink(target) => Some(target),
            _ => None,
        })
        .collect();
    let keys: BTreeSet<_> = base.entries.keys().chain(target.entries.keys()).collect();
    let mut files = BTreeSet::new();
    let mut structural = BTreeSet::new();
    for key in keys {
        let previous = base.entries.get(key);
        let next = target.entries.get(key);
        if previous == next {
            continue;
        }
        if matches!(
            (previous, next),
            (Some(TreeEntry::File { .. }), Some(TreeEntry::File { .. }))
        ) && !hardlink_targets.contains(key)
        {
            files.insert(key.clone());
        } else {
            structural.insert(covering_directory(key, base, target)?);
        }
    }
    if files.is_empty() && structural.is_empty() {
        return None;
    }
    // Parent directories sort ahead of their descendants in BTreeSet.
    let mut directories: Vec<TreePath> = Vec::new();
    for directory in structural {
        if !directories.iter().any(|outer| within(&directory, outer)) {
            directories.push(directory);
        }
    }
    if directories
        .iter()
        .any(|directory| intersects_protected(directory, protected))
    {
        return None;
    }
    files.retain(|file| !directories.iter().any(|dir| within(file, dir)));
    if files
        .iter()
        .any(|file| intersects_protected(file, protected))
    {
        return None;
    }
    // The inode group of a hardlink must be entirely inside the same private
    // directory overlay, or entirely in the unmodified base. A split would
    // change st_ino/st_nlink or write propagation across writable boundaries.
    for manifest in [base, target] {
        for (alias, entry) in &manifest.entries {
            let TreeEntry::Hardlink(referent) = entry else {
                continue;
            };
            let alias_region = directories.iter().position(|dir| within(alias, dir));
            let target_region = directories.iter().position(|dir| within(referent, dir));
            if alias_region != target_region || files.contains(alias) || files.contains(referent) {
                return None;
            }
        }
    }
    let mut materialized_entries = files.len();
    for path in target.entries.keys() {
        if directories.iter().any(|directory| within(path, directory)) {
            materialized_entries += 1;
        }
    }
    // This limits the path to small changing subtrees, where construction of
    // private directory views beats cloning the entire immutable root.
    (materialized_entries < target.entries.len().div_ceil(2)).then_some(OverlayPlan {
        files: files.into_iter().collect(),
        directories,
        materialized_entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlobRef, ContentId, TreeMetadata, TreeTimestamp};

    fn path(text: &str) -> TreePath {
        TreePath::new(text.as_bytes().to_vec()).expect("test path")
    }

    fn metadata(mode: u32) -> TreeMetadata {
        TreeMetadata {
            mode,
            modified: TreeTimestamp {
                seconds: 123,
                nanoseconds: 345,
            },
        }
    }

    fn file(content: &str) -> TreeEntry {
        TreeEntry::File {
            blob: BlobRef {
                id: ContentId::of(content.as_bytes()),
                size: content.len() as u64,
            },
            metadata: metadata(0o644),
        }
    }

    fn manifest() -> TreeManifest {
        let meta = metadata(0o755);
        let mut entries = std::collections::BTreeMap::from([
            (path("bin"), TreeEntry::Directory(meta)),
            (path("bin/tool"), file("compiler")),
            (path("src"), TreeEntry::Directory(meta)),
            (path("src/work"), TreeEntry::Directory(meta)),
            (path("src/work/source"), file("old source")),
            (
                path("src/work/alias"),
                TreeEntry::Hardlink(path("src/work/source")),
            ),
            (path("src/work/removed"), file("obsolete")),
            (
                path("src/work/sym"),
                TreeEntry::Symlink {
                    target: b"source".to_vec(),
                    modified: meta.modified,
                },
            ),
        ]);
        for index in 0..64 {
            entries.insert(
                path(&format!("bin/header-{index:03}")),
                file("stable header"),
            );
        }
        TreeManifest {
            root: meta,
            entries,
        }
    }

    #[test]
    fn topology_changes_select_one_small_complete_private_directory() {
        let base = manifest();
        base.validate().expect("base manifest");
        let mut changed = base.clone();
        changed.entries.remove(&path("src/work/removed"));
        changed
            .entries
            .insert(path("src/work/new"), file("new content"));
        changed.entries.insert(
            path("src/work/source"),
            file("changed source with the same hardlink group"),
        );
        changed.entries.insert(
            path("src/work/sym"),
            TreeEntry::Symlink {
                target: b"new".to_vec(),
                modified: metadata(0o755).modified,
            },
        );
        changed.validate().expect("target manifest");
        let plan = plan_overlays(&base, &changed, &[]).expect("directory overlay");
        assert_eq!(plan.files, Vec::<TreePath>::new());
        assert_eq!(plan.directories, vec![path("src/work")]);
        assert!(plan.materialized_entries < 10);
        assert!(plan_overlays(&base, &changed, &[PathBuf::from("src/work")]).is_none());
        assert!(plan_overlays(&base, &changed, &[PathBuf::from("src")]).is_none());
        assert!(plan_overlays(&base, &changed, &[PathBuf::from("src/work/out")]).is_none());
    }

    #[test]
    fn metadata_and_type_changes_preserve_original_namespace_boundaries() {
        let base = manifest();
        let mut changed = base.clone();
        changed
            .entries
            .insert(path("src/work"), TreeEntry::Directory(metadata(0o700)));
        let plan = plan_overlays(&base, &changed, &[]).expect("mode update");
        assert_eq!(plan.directories, vec![path("src/work")]);

        let mut target_symlink = base.clone();
        target_symlink.entries.insert(
            path("src/work/removed"),
            TreeEntry::Symlink {
                target: b"source".to_vec(),
                modified: metadata(0o755).modified,
            },
        );
        target_symlink.validate().expect("valid symlink tree");
        let plan = plan_overlays(&base, &target_symlink, &[]).expect("type change");
        assert_eq!(plan.directories, vec![path("src/work")]);

        let mut root = base.clone();
        root.root.mode = 0o700;
        assert!(plan_overlays(&base, &root, &[]).is_none());

        let mut root_child = base.clone();
        root_child.entries.insert(path("at-root"), file("new"));
        assert!(plan_overlays(&base, &root_child, &[]).is_none());
    }

    #[test]
    fn crossing_hardlink_groups_force_a_complete_tree() {
        let mut base = manifest();
        base.entries.insert(
            path("bin/outside-alias"),
            TreeEntry::Hardlink(path("src/work/source")),
        );
        base.validate().expect("cross-boundary hardlink");
        let mut changed = base.clone();
        changed.entries.insert(path("src/work/new"), file("new"));
        changed.validate().expect("changed target");
        assert!(plan_overlays(&base, &changed, &[]).is_none());
        // The same invariant applies if only the target introduces a new
        // cross-boundary hardlink.
        let original = manifest();
        let mut target = original.clone();
        target.entries.insert(
            path("bin/outside-alias"),
            TreeEntry::Hardlink(path("src/work/source")),
        );
        target.entries.insert(path("src/work/new"), file("new"));
        target.validate().expect("new cross-boundary hardlink");
        assert!(plan_overlays(&original, &target, &[]).is_none());
    }

    #[test]
    fn disjoint_directory_churn_and_independent_files_share_one_plan() {
        let mut base = manifest();
        base.entries
            .insert(path("bin/generated"), TreeEntry::Directory(metadata(0o755)));
        base.entries
            .insert(path("bin/generated/obsolete"), file("old"));
        base.validate().expect("baseline tree");

        let mut target = base.clone();
        target.entries.remove(&path("bin/generated/obsolete"));
        target
            .entries
            .insert(path("bin/generated/new"), file("new"));
        target.entries.remove(&path("src/work/removed"));
        target
            .entries
            .insert(path("src/work/added"), file("generated"));
        target
            .entries
            .insert(path("bin/tool"), file("new compiler"));
        target.validate().expect("target tree");
        let plan = plan_overlays(&base, &target, &[]).expect("disjoint overlay plan");
        assert_eq!(
            plan.directories,
            vec![path("bin/generated"), path("src/work")]
        );
        assert_eq!(plan.files, vec![path("bin/tool")]);
        assert!(plan.materialized_entries < target.entries.len() / 2);
    }

    #[test]
    fn independent_file_updates_are_still_the_cheaper_fast_path() {
        let base = manifest();
        let mut changed = base.clone();
        changed.entries.insert(path("bin/tool"), file("new tool"));
        let plan = plan_overlays(&base, &changed, &[]).expect("single file");
        assert_eq!(plan.files, vec![path("bin/tool")]);
        assert_eq!(plan.directories, Vec::<TreePath>::new());
    }
}
