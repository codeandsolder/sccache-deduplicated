//! Project verified Rust installer v3 packages into component installation
//! trees. Select declared payload only; never execute installation scripts.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

use anyhow::{Context, Result, ensure};

use crate::{
    InstallationManifest, NativeStore, TreeEntry, TreeLease, TreeManifest, TreeMetadata, TreePath,
    VerifiedPackage, recipe::project_entries,
};

const CONTROL_BYTES: u64 = 16 * 1024 * 1024;

fn joined(prefix: &TreePath, path: &[u8]) -> Result<TreePath> {
    let mut bytes = prefix.as_bytes().to_vec();
    bytes.push(b'/');
    bytes.extend_from_slice(path);
    TreePath::new(bytes)
}

fn control(package: &TreeLease, path: &TreePath) -> Result<Vec<u8>> {
    let manifest = package.manifest();
    let entry = manifest
        .entries
        .get(path)
        .context("installer control member missing")?;
    let entry = if let TreeEntry::Hardlink(target) = entry {
        manifest
            .entries
            .get(target)
            .context("installer hardlink target missing")?
    } else {
        entry
    };
    let TreeEntry::File { blob, .. } = entry else {
        anyhow::bail!("installer control member is not a regular file");
    };
    ensure!(
        blob.size <= CONTROL_BYTES,
        "installer control file exceeds size limit"
    );
    let mut bytes = Vec::new();
    package
        .open_blob(blob.id)?
        .take(CONTROL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? == blob.size,
        "installer control file length mismatch"
    );
    Ok(bytes)
}

fn lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|&byte| byte == b'\n')
        .filter(|line| !line.is_empty())
}

fn selections(package: &TreeLease, component: &TreePath) -> Result<BTreeMap<TreePath, bool>> {
    let bytes = control(package, &joined(component, b"manifest.in")?)?;
    let mut selections = BTreeMap::new();
    for line in lines(&bytes) {
        let (directory, path) = if let Some(path) = line.strip_prefix(b"file:") {
            (false, path)
        } else if let Some(path) = line.strip_prefix(b"dir:") {
            (true, path)
        } else {
            anyhow::bail!("unsupported Rust installer manifest directive");
        };
        let path = TreePath::new(path.to_vec())?;
        let full = joined(component, path.as_bytes())?;
        let entry = package
            .manifest()
            .entries
            .get(&full)
            .context("declared installer payload missing")?;
        ensure!(
            matches!(entry, TreeEntry::Directory(_)) == directory,
            "installer payload kind differs from declaration"
        );
        if let Some(previous) = selections.insert(path, directory) {
            ensure!(
                previous == directory,
                "conflicting installer payload declarations"
            );
        }
    }
    ensure!(!selections.is_empty(), "empty installer component");
    Ok(selections)
}

fn selected(path: &TreePath, selections: &BTreeMap<TreePath, bool>) -> bool {
    selections.contains_key(path)
        || path
            .as_bytes()
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'/')
            .any(|(index, _)| {
                TreePath::new(path.as_bytes()[..index].to_vec())
                    .is_ok_and(|parent| selections.get(&parent) == Some(&true))
            })
}

fn component_tree(
    package: &TreeLease,
    component: &TreePath,
    directories: TreeMetadata,
) -> Result<TreeManifest> {
    let selections = selections(package, component)?;
    let mut paths = BTreeMap::new();
    let mut prefix = component.as_bytes().to_vec();
    prefix.push(b'/');
    let bounds = (
        std::ops::Bound::Included(prefix.as_slice()),
        std::ops::Bound::Unbounded,
    );
    for (path, _) in package.manifest().entries.range::<[u8], _>(bounds) {
        let Some(local) = path.as_bytes().strip_prefix(prefix.as_slice()) else {
            break;
        };
        let local = TreePath::new(local.to_vec())?;
        if selected(&local, &selections) {
            paths.insert(path, local);
        }
    }
    let mut manifest = TreeManifest {
        root: directories,
        entries: BTreeMap::new(),
    };
    project_entries(package.manifest(), &paths, &mut manifest)?;
    let mut parents = BTreeSet::new();
    for (path, entry) in &mut manifest.entries {
        for (index, _) in path
            .as_bytes()
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'/')
        {
            parents.insert(TreePath::new(path.as_bytes()[..index].to_vec())?);
        }
        match entry {
            TreeEntry::File { metadata, .. } => {
                metadata.mode = if metadata.mode & 0o100 == 0 {
                    0o644
                } else {
                    0o755
                };
                metadata.modified = directories.modified;
            }
            TreeEntry::Symlink { modified, .. } => *modified = directories.modified,
            TreeEntry::Directory(_) | TreeEntry::Hardlink(_) => {}
        }
    }
    for parent in parents {
        manifest
            .entries
            .entry(parent)
            .or_insert(TreeEntry::Directory(directories));
    }
    manifest.validate()?;
    Ok(manifest)
}

impl NativeStore {
    /// Derive independent normalized installation trees from an already
    /// verified Rust installer v3 package, referencing its existing blobs.
    ///
    /// The caller chooses placement and which components to compose. This
    /// does not attest an existing local sysroot.
    /// # Errors
    /// Returns an error for unsupported installer directives, missing payload,
    /// invalid topology or metadata storage failures.
    pub fn publish_rust_installer(
        &self,
        verified: &VerifiedPackage,
        directories: TreeMetadata,
    ) -> Result<InstallationManifest> {
        let package = verified.tree();
        let mut roots = package
            .manifest()
            .entries
            .iter()
            .filter(|(path, _)| !path.as_bytes().contains(&b'/'));
        let (root, entry) = roots.next().context("empty Rust installer package")?;
        ensure!(
            matches!(entry, TreeEntry::Directory(_)) && roots.next().is_none(),
            "Rust installer must have exactly one package directory"
        );
        let version = control(package, &joined(root, b"rust-installer-version")?)?;
        ensure!(
            version == b"3" || version == b"3\n",
            "unsupported Rust installer version"
        );
        let bytes = control(package, &joined(root, b"components")?)?;
        let mut manifests = BTreeMap::new();
        for name in lines(&bytes) {
            let name = std::str::from_utf8(name)?;
            ensure!(!name.contains('/'), "invalid installer component name");
            ensure!(
                !manifests.contains_key(name),
                "duplicate installer component"
            );
            let component = joined(root, name.as_bytes())?;
            let manifest = component_tree(package, &component, directories)?;
            manifests.insert(name.to_owned(), manifest);
        }
        ensure!(
            !manifests.is_empty(),
            "installer package contains no components"
        );
        // Validate all components before publishing any. Publication is
        // idempotent; storage errors can only leave independently valid trees.
        for manifest in manifests.values() {
            self.publish_tree(manifest, Vec::new())?;
        }
        Ok(InstallationManifest {
            source: verified.source(),
            package: package.id(),
            components: manifests,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ArchiveLength, PackageCompression, PackageDecoder, PackageIdentity, PackagePolicy,
        TreeRecipe, TreeTimestamp,
    };
    use sha2::{Digest, Sha256};

    fn fixture(manifest: &[u8]) -> Result<Vec<u8>> {
        let mut archive = tar::Builder::new(Vec::new());
        for (path, bytes, mode) in [
            ("release/rust-installer-version", &b"3\n"[..], 0o644),
            ("release/components", &b"compiler\nstd\n"[..], 0o644),
            ("release/compiler/manifest.in", manifest, 0o644),
            ("release/compiler/bin/rustc", &b"compiler"[..], 0o700),
            (
                "release/compiler/bin/not-selected",
                &b"not installed"[..],
                0o755,
            ),
            ("release/compiler/lib/x", &b"library"[..], 0o644),
            ("release/compiler/lib/nested/y", &b"nested"[..], 0o640),
            (
                "release/std/manifest.in",
                &b"file:lib/std.rlib\n"[..],
                0o644,
            ),
            ("release/std/lib/std.rlib", &b"std"[..], 0o644),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(mode);
            header.set_size(u64::try_from(bytes.len())?);
            header.set_cksum();
            archive.append_data(&mut header, path, bytes)?;
        }
        Ok(archive.into_inner()?)
    }

    fn import(store: &NativeStore, bytes: &[u8]) -> Result<(VerifiedPackage, TreeMetadata)> {
        let modified = TreeTimestamp {
            seconds: 123,
            nanoseconds: 0,
        };
        let directory = TreeMetadata {
            mode: 0o755,
            modified,
        };
        let id = store.import_package(
            PackageIdentity {
                sha256: Sha256::digest(bytes).into(),
                compression: PackageCompression::Tar,
            },
            ArchiveLength::Exact(u64::try_from(bytes.len())?),
            PackagePolicy {
                retain_original: false,
                directory,
                modified,
                max_entries: 100,
                max_expanded_bytes: 100_000,
                max_tar_bytes: 1_000_000,
                max_metadata_bytes: 1_000_000,
            },
            bytes,
            PackageDecoder::InProcess,
        )?;
        Ok((id, directory))
    }

    #[test]
    fn projects_declared_payload_without_copying_blobs() -> Result<()> {
        let scratch = tempfile::tempdir()?;
        let store = NativeStore::open(scratch.path())?;
        let (package, directories) = import(&store, &fixture(b"file:bin/rustc\ndir:lib\n")?)?;
        let before = store.stats()?;
        let components = store.publish_rust_installer(&package, directories)?;
        assert_eq!(components.components.len(), 2);
        let ids = components
            .components
            .values()
            .map(TreeManifest::id)
            .collect::<Result<Vec<_>>>()?;
        let recipe = TreeRecipe::union(directories, ids);
        let installed = store.lease_recipe(&recipe)?;
        let entries = &installed.manifest().entries;
        let path = |name: &str| TreePath::new(name.as_bytes().to_vec());
        assert!(
            matches!(entries.get(&path("bin/rustc")?), Some(TreeEntry::File { metadata, .. }) if metadata.mode == 0o755)
        );
        assert!(entries.contains_key(&path("lib/nested/y")?));
        assert!(entries.contains_key(&path("lib/std.rlib")?));
        for excluded in ["bin/not-selected", "manifest.in", "components", "release"] {
            assert!(!entries.contains_key(&path(excluded)?));
        }
        assert_eq!(store.stats()?.logical_bytes, before.logical_bytes);
        assert_eq!(store.stats()?.blobs, before.blobs);
        assert_eq!(
            store
                .publish_rust_installer(&package, directories)?
                .components,
            components.components
        );
        Ok(())
    }

    #[test]
    fn rejects_missing_payload_and_traversal() -> Result<()> {
        let scratch = tempfile::tempdir()?;
        let store = NativeStore::open(scratch.path())?;
        for manifest in [
            b"file:missing\n".as_slice(),
            b"file:../std/lib/std.rlib\n".as_slice(),
            b"file:lib\n".as_slice(),
        ] {
            let (package, directories) = import(&store, &fixture(manifest)?)?;
            let before = store.stats()?.trees;
            assert!(store.publish_rust_installer(&package, directories).is_err());
            assert_eq!(store.stats()?.trees, before);
        }
        Ok(())
    }
}
