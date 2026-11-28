// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use fs_err as fs;
use std::path::{Component, Path, PathBuf};
use std::str;

use crate::errors::{Context, Result, anyhow, bail};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use self::toolchain_imp::ToolchainPackageBuilder;

mod inputs;
pub(crate) use inputs::CompilerInputs;

#[cfg(target_os = "linux")]
pub(crate) fn native_directory_metadata() -> Result<crate::build_runtime::TreeMetadata> {
    Ok(crate::build_runtime::TreeMetadata {
        mode: 0o755,
        modified: crate::build_runtime::TreeTimestamp {
            seconds: i64::try_from(tar::DETERMINISTIC_TIMESTAMP)?,
            nanoseconds: 0,
        },
    })
}

/// The native planner selects the execution inventory after inspecting
/// the actual input closure for code that can observe the entire installation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ToolchainScope {
    Default,
    RustCompiler,
}

pub trait ToolchainPackager: Send {
    /// Discover the files and logical paths of a native toolchain.
    ///
    /// # Errors
    /// Returns an error if discovery fails or this packager has no native mapping.
    #[cfg(target_os = "linux")]
    fn native_mapping(
        self: Box<Self>,
        _scope: ToolchainScope,
    ) -> Result<crate::build_runtime::MappedTree> {
        bail!("native mapping not supported by this toolchain packager")
    }
}

/// Compiler-specific discovery of native toolchain inputs.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) trait DiscoverToolchain: Send + Sized {
    fn package_builder(self, scope: ToolchainScope) -> Result<ToolchainPackageBuilder>;
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl<T: DiscoverToolchain> ToolchainPackager for T {
    fn native_mapping(
        self: Box<Self>,
        scope: ToolchainScope,
    ) -> Result<crate::build_runtime::MappedTree> {
        self.package_builder(scope)?.into_native_mapping()
    }
}

/// Native input contents and the frontend's explicit codegen-only roles.
#[cfg(target_os = "linux")]
pub struct NativeInputPlan {
    pub mapping: crate::build_runtime::MappedTree,
    pub codegen_only: std::collections::BTreeSet<crate::build_runtime::TreePath>,
}

pub trait InputsPackager: Send {
    /// Discover compiler input files directly in the native content namespace.
    ///
    /// # Errors
    /// Returns an error for unavailable sources or conflicting logical paths.
    #[cfg(target_os = "linux")]
    fn native_mapping(self: Box<Self>) -> Result<NativeInputPlan>;
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod toolchain_imp {
    use super::ToolchainPackager;
    // Unsupported platforms have no native toolchain mapping.
    impl<T: Send> ToolchainPackager for T {}
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod toolchain_imp {
    use super::SimplifyPath;
    use fs_err as fs;
    use std::collections::BTreeMap;
    use std::path::{Component, Path, PathBuf};
    use walkdir::WalkDir;

    use crate::errors::{Context, Result, bail};

    pub struct ToolchainPackageBuilder {
        // Put dirs and file in a deterministic order (map from tar_path -> real_path)
        dir_set: BTreeMap<PathBuf, PathBuf>,
        file_set: BTreeMap<PathBuf, PathBuf>,
        // Symlinks to add to the tar
        // These are _not_ tar safe, and must be made so before being added to the tar (see
        // `tar_safe_path`).
        symlinks: BTreeMap<PathBuf, PathBuf>,
        root_mappings: Vec<(PathBuf, PathBuf)>,
    }

    impl ToolchainPackageBuilder {
        #[must_use = "the returned archive input set must be populated by the caller"]
        pub const fn new() -> Self {
            Self {
                dir_set: BTreeMap::new(),
                file_set: BTreeMap::new(),
                symlinks: BTreeMap::new(),
                root_mappings: Vec::new(),
            }
        }

        pub fn add_root_mapping(&mut self, local_root: PathBuf, archive_root: PathBuf) {
            let local_root = local_root.canonicalize().unwrap_or(local_root);
            self.root_mappings.push((local_root, archive_root));
            self.root_mappings
                .sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        }

        /// Add paths that every packaged toolchain requires.
        ///
        /// # Errors
        ///
        /// Returns an error if a required common path cannot be added.
        pub fn add_common(&mut self) -> Result<()> {
            self.add_dir(PathBuf::from("/tmp"))
        }

        // The stored path is normalized, but GCC can execute helpers using paths
        // like lib/gcc/<target>/<version>/../../../../<target>/bin/as. Linux
        // resolves each intermediate directory before applying parent traversal;
        // omitting an otherwise empty prefix makes the executable inaccessible.
        fn add_lexical_parent_dirs(&mut self, path: &Path) -> Result<()> {
            for dir in super::lexical_parent_traversal_dirs(path) {
                self.add_dir(dir)?;
            }
            Ok(())
        }

        /// Add an executable and the dynamic libraries required to run it.
        ///
        /// # Errors
        ///
        /// Returns an error if a path is not absolute or dependency discovery fails.
        pub fn add_executable_and_deps(&mut self, executable: PathBuf) -> Result<()> {
            let mut remaining = vec![executable];
            while let Some(obj_path) = remaining.pop() {
                if !obj_path.is_absolute() {
                    bail!(
                        "toolchain dependency path is not absolute: {}",
                        obj_path.display()
                    );
                }
                // If any parent directories are a symlink, resolve it first and record the link.
                // This is important because ld-linux may not be configured to look in the resolved
                // or non-resolved directory (i.e., both directories must work at runtime).
                //
                self.add_lexical_parent_dirs(&obj_path)?;
                let tar_path = self.tarify_path(&obj_path)?;
                // If file already in the set, assume we've analysed all deps
                if self.file_set.contains_key(&tar_path) {
                    continue;
                }
                let ldd_libraries =
                    crate::compiler::dynamic_dependencies::find_ldd_libraries(&obj_path, None)
                        .with_context(|| {
                            format!("Failed to analyse {} with ldd", obj_path.display())
                        })?;
                remaining.extend(ldd_libraries);
                self.file_set.insert(tar_path, obj_path);
            }
            Ok(())
        }

        /// Add a directory entry to the package.
        ///
        /// # Errors
        ///
        /// Returns an error if `dir_path` is not an absolute directory or path processing fails.
        pub fn add_dir(&mut self, dir_path: PathBuf) -> Result<()> {
            if !dir_path.is_absolute() {
                bail!(
                    "toolchain directory path is not absolute: {}",
                    dir_path.display()
                );
            }
            if !dir_path.is_dir() {
                bail!(format!(
                    "{} was not a dir when readying for tar",
                    dir_path.to_string_lossy()
                ))
            }
            if matches!(dir_path.components().next_back(), Some(Component::RootDir)) {
                return Ok(());
            }
            let tar_path = self.tarify_path(&dir_path)?;
            self.dir_set.insert(tar_path, dir_path);
            Ok(())
        }

        /// Add a file entry to the package.
        ///
        /// # Errors
        ///
        /// Returns an error if `file_path` is not an absolute file or path processing fails.
        pub fn add_file(&mut self, file_path: PathBuf) -> Result<()> {
            if !file_path.is_absolute() {
                bail!(
                    "toolchain file path is not absolute: {}",
                    file_path.display()
                );
            }
            if !file_path.is_file() {
                bail!(format!(
                    "{} was not a file when readying for tar",
                    file_path.to_string_lossy()
                ))
            }
            self.add_lexical_parent_dirs(&file_path)?;
            let tar_path = self.tarify_path(&file_path)?;
            self.file_set.insert(tar_path, file_path);
            Ok(())
        }

        /// Add all regular files reachable directly beneath `dir_path`.
        ///
        /// # Errors
        ///
        /// Returns an error if directory traversal, metadata lookup, or file insertion fails.
        pub fn add_dir_contents(&mut self, dir_path: &Path) -> Result<()> {
            // Although by not following symlinks we could break a custom
            // constructed toolchain with links everywhere, this is just a
            // best-effort auto packaging
            for entry in WalkDir::new(dir_path).follow_links(false) {
                let entry = entry?;
                let file_type = entry.file_type();
                if file_type.is_dir() {
                    continue;
                }
                if file_type.is_symlink() {
                    let metadata = fs::metadata(entry.path())?;
                    if !metadata.file_type().is_file() {
                        continue;
                    }
                } else if !file_type.is_file() {
                    // Device or other oddity
                    continue;
                }
                trace!("walkdir add_file {}", entry.path().display());
                // It's either a file, or a symlink pointing to a file
                self.add_file(entry.path().to_owned())?;
            }
            Ok(())
        }

        /// Convert discovered toolchain paths directly into native CAS inputs.
        ///
        /// # Errors
        /// Returns an error for conflicting paths or a source that cannot be resolved.
        pub fn into_native_mapping(self) -> Result<crate::build_runtime::MappedTree> {
            use crate::build_runtime::{MappedMetadata, MappedTree, TreePath};
            use std::os::unix::ffi::OsStrExt;

            let directories = super::native_directory_metadata()?;
            let modified = directories.modified;
            let mut mapping = MappedTree::new(directories);
            let relative = |path: &Path| TreePath::new(path.as_os_str().as_bytes().to_vec());
            for mount in ["out", "tmp", "dev", "proc"] {
                mapping.add_directory(relative(Path::new(mount))?)?;
            }
            for path in self.dir_set.keys() {
                mapping.add_directory(relative(path)?)?;
            }
            for (destination, source) in &self.file_set {
                let resolved = source.canonicalize()?;
                anyhow::ensure!(
                    tar_safe_path(self.map_path(&resolved)) == *destination,
                    "toolchain path changed after discovery: {}",
                    source.display()
                );
                mapping.add_file(
                    relative(destination)?,
                    resolved,
                    MappedMetadata::Normalize(modified),
                )?;
            }
            for (from, to) in &self.symlinks {
                let from = self.map_path(from);
                let to = self.map_path(to);
                if from != to {
                    mapping.add_symlink(
                        relative(&tar_safe_path(from))?,
                        to.as_os_str().as_bytes().to_vec(),
                        modified,
                    )?;
                }
            }
            Ok(mapping)
        }

        fn map_path(&self, path: &Path) -> PathBuf {
            for (local_root, archive_root) in &self.root_mappings {
                if let Ok(suffix) = path.strip_prefix(local_root) {
                    return archive_root.join(suffix);
                }
            }
            path.to_owned()
        }

        /// Simplify the path and strip the leading slash.
        ///
        /// Symlinks in the path are recorded for inclusion in the tarball.
        fn tarify_path(&mut self, path: &Path) -> Result<PathBuf> {
            let simplified = SimplifyPath {
                resolved_symlinks: Some(&mut self.symlinks),
            }
            .simplify(path)?;

            Ok(tar_safe_path(self.map_path(&simplified)))
        }
    }

    impl Default for ToolchainPackageBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    #[test]
    fn native_package_identity_tracks_content_not_mount_alias() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        fs::create_dir(&first)?;
        fs::create_dir(&second)?;
        fs::write(first.join("compiler"), b"compiler bytes")?;
        fs::copy(first.join("compiler"), second.join("compiler"))?;
        let inventory = |root: &Path| -> Result<_> {
            let mut builder = ToolchainPackageBuilder::new();
            builder.add_root_mapping(root.to_owned(), PathBuf::from("/toolchain"));
            builder.add_file(root.join("compiler"))?;
            builder.into_native_mapping()?.prepare()
        };
        let original = inventory(&first)?;
        assert_eq!(original.id(), inventory(&second)?.id());
        fs::write(second.join("compiler"), b"different compiler")?;
        assert_ne!(original.id(), inventory(&second)?.id());
        Ok(())
    }

    #[test]
    fn native_cross_toolchain_preserves_gcc_lexical_helper_paths() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let toolchain = temp.path().join("toolchain");
        fs::create_dir_all(toolchain.join("bin"))?;
        fs::create_dir_all(toolchain.join("lib/gcc/cross-target/1"))?;
        fs::create_dir_all(toolchain.join("cross-target/bin"))?;
        fs::write(toolchain.join("cross-target/bin/as"), b"fake assembler")?;
        let reported =
            toolchain.join("bin/../lib/gcc/cross-target/1/../../../../cross-target/bin/as");
        let mut builder = ToolchainPackageBuilder::new();
        builder.add_file(reported.clone())?;
        let store = crate::build_runtime::NativeStore::open(&temp.path().join("store"))?;
        let tree = builder.into_native_mapping()?.prepare()?.import(&store)?;
        let view = tree.materialize(temp.path())?;
        assert_eq!(
            fs::read(view.root().join(reported.strip_prefix("/")?))?,
            b"fake assembler"
        );
        Ok(())
    }

    #[test]
    fn toolchain_root_mapping_changes_archive_identity() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let sysroot = temp.path().join("toolchain");
        std::fs::create_dir_all(sysroot.join("bin"))?;
        let rustc = sysroot.join("bin/rustc");
        std::fs::write(&rustc, b"rustc")?;

        let mut builder = ToolchainPackageBuilder::new();
        builder.add_root_mapping(sysroot, PathBuf::from("/rust"));
        assert_eq!(
            builder.tarify_path(&rustc)?,
            PathBuf::from("rust/bin/rustc")
        );
        Ok(())
    }

    #[cfg(feature = "native-store")]
    #[test]
    fn native_toolchain_mapping_rebases_symlink_sources_and_targets() -> Result<()> {
        use crate::build_runtime::{NativeStore, TreeEntry, TreePath};
        let temp = tempfile::tempdir()?;
        let sysroot = temp.path().join("toolchain");
        std::fs::create_dir_all(sysroot.join("bin"))?;
        std::fs::write(sysroot.join("bin/compiler"), b"compiler")?;
        std::os::unix::fs::symlink("compiler", sysroot.join("bin/alias"))?;

        let mut builder = ToolchainPackageBuilder::new();
        builder.add_root_mapping(sysroot.clone(), "/rust".into());
        builder.add_file(sysroot.join("bin/alias"))?;
        let store = NativeStore::open(&temp.path().join("cas"))?;
        let tree = builder.into_native_mapping()?.prepare()?.import(&store)?;
        let entries = &tree.manifest().entries;
        assert!(matches!(
            entries.get(&TreePath::new(b"rust/bin/compiler".to_vec())?),
            Some(TreeEntry::File { .. })
        ));
        assert!(matches!(
            entries.get(&TreePath::new(b"rust/bin/alias".to_vec())?),
            Some(TreeEntry::Symlink { target, .. }) if target == b"/rust/bin/compiler"
        ));
        Ok(())
    }

    /// Strip a leading slash, if any.
    fn tar_safe_path(path: PathBuf) -> PathBuf {
        path.strip_prefix(Component::RootDir)
            .map(ToOwned::to_owned)
            .unwrap_or(path)
    }
}

/// Return the directory prefixes that must exist to preserve lexical `..` traversal.
///
/// Distributed input archives normally store simplified paths, but compiler arguments may
/// intentionally retain their original lexical spelling. Every parent step requires the
/// directory immediately before it to exist on the worker, even when that directory is not
/// part of the simplified target path.
#[must_use = "the returned directories are needed to reproduce parent traversal on the worker"]
pub fn lexical_parent_traversal_dirs(path: &Path) -> Vec<PathBuf> {
    let mut current = PathBuf::new();
    let mut required = Vec::new();

    for component in path.components() {
        match component {
            Component::ParentDir => {
                if !current.as_os_str().is_empty() {
                    required.push(current.clone());
                    current.pop();
                }
            }
            Component::CurDir => {}
            _ => current.push(component.as_os_str()),
        }
    }

    required
}

/// Plan compiler-input archive paths in a single namespace. In the physical
/// Unix layout this preserves symlink and parent-traversal semantics. In the
/// relocated layout, use the compiler's root mappings and retain the required
/// lexical traversal directories. Directory inputs never imply copying a
/// directory tree.
pub(crate) struct InputArchivePaths {
    transformer: crate::dist::PathTransformer,
    directories: std::collections::BTreeMap<String, PathBuf>,
    #[cfg(unix)]
    physical: Option<PhysicalInputLayout>,
}

impl InputArchivePaths {
    pub(crate) fn new(transformer: crate::dist::PathTransformer) -> Self {
        #[cfg(unix)]
        let physical = transformer
            .path_mappings()
            .next()
            .is_none()
            .then(PhysicalInputLayout::default);
        Self {
            transformer,
            directories: std::collections::BTreeMap::new(),
            #[cfg(unix)]
            physical,
        }
    }

    fn archive_path(&mut self, path: &Path) -> Result<String> {
        self.transformer
            .as_dist_abs(path)
            .with_context(|| format!("Unable to transform compiler input {}", path.display()))
    }

    fn add_mapped_directory(&mut self, directory: PathBuf) -> Result<()> {
        if !directory.is_dir() {
            bail!("Missing compiler input directory {}", directory.display());
        }
        let remote = self.archive_path(&directory)?;
        if remote == "/" {
            return Ok(());
        }
        if remote
            .trim_start_matches('/')
            .split('/')
            .any(|part| part == "..")
        {
            bail!("Unsafe compiler input directory {remote}");
        }
        self.directories.insert(remote, directory);
        Ok(())
    }

    fn resolve(&mut self, path: &Path) -> Result<PathBuf> {
        #[cfg(unix)]
        if let Some(physical) = self.physical.as_mut() {
            return physical.resolve(path);
        }
        for directory in lexical_parent_traversal_dirs(path) {
            self.add_mapped_directory(directory)?;
        }
        simplify_path(path)
    }

    pub(crate) fn file(&mut self, path: &Path) -> Result<(PathBuf, String)> {
        let path = self.resolve(path)?;
        let remote = self.archive_path(&path)?;
        Ok((path, remote))
    }

    pub(crate) fn directory(&mut self, path: &Path) -> Result<String> {
        #[cfg(unix)]
        if let Some(physical) = self.physical.as_mut() {
            let resolved = physical.add_directory(path)?;
            return self.archive_path(&resolved);
        }
        let path = self.resolve(path)?;
        self.add_mapped_directory(path.clone())?;
        self.archive_path(&path)
    }
}

/// Physical-layout Rust inputs must retain the paths by which the compiler
/// reaches them, not merely the bytes at their canonical destinations.
/// Resolve file and directory inputs into a single archive namespace, retaining
/// traversed directories and symlink entries along the way. No archive member
/// contains a parent component, and no file is emitted beneath a symlink.
#[cfg(unix)]
#[derive(Default)]
struct PhysicalInputLayout {
    directories: std::collections::BTreeSet<PathBuf>,
    links: std::collections::BTreeMap<PathBuf, PathBuf>,
    nodes: std::collections::HashSet<PathBuf>,
}

#[cfg(unix)]
impl PhysicalInputLayout {
    /// Resolve an existing absolute input, remembering the filesystem entries
    /// required to resolve its original spelling inside a worker's root.
    fn resolve(&mut self, path: &Path) -> Result<PathBuf> {
        if !path.is_absolute() {
            bail!(
                "Physical archive input must be absolute: {}",
                path.display()
            );
        }
        // Let the OS validate existence, trailing slashes, and symlink loops,
        // and check that the collected topology agrees with its resolution.
        let expected = path.canonicalize()?;
        let resolved = self.resolve_components(path, 0)?;
        if resolved != expected {
            bail!(
                "Input path changed during archive planning: {}",
                path.display()
            );
        }
        Ok(resolved)
    }

    fn resolve_components(&mut self, path: &Path, depth: usize) -> Result<PathBuf> {
        if depth > 40 {
            bail!("Too many input symlink traversals: {}", path.display());
        }
        let mut current = PathBuf::from("/");
        for component in path.components() {
            match component {
                Component::RootDir => current = PathBuf::from("/"),
                Component::CurDir => {}
                Component::ParentDir => {
                    // The kernel must enter this directory before processing
                    // .., including when the preceding component was a link.
                    if current != Path::new("/") {
                        self.directories.insert(current.clone());
                    }
                    current.pop();
                }
                Component::Normal(name) => {
                    let candidate = current.join(name);
                    if self.nodes.contains(&candidate) {
                        current = candidate;
                        continue;
                    }
                    let target = if let Some(target) = self.links.get(&candidate) {
                        Some(target.clone())
                    } else if fs::symlink_metadata(&candidate)?.is_symlink() {
                        let target = candidate.read_link()?;
                        self.links.insert(candidate.clone(), target.clone());
                        Some(target)
                    } else {
                        self.nodes.insert(candidate.clone());
                        None
                    };
                    current = if let Some(target) = target {
                        self.resolve_components(&current.join(target), depth + 1)?
                    } else {
                        candidate
                    };
                }
                Component::Prefix(_) => bail!("Unexpected prefix in Unix archive input"),
            }
        }
        Ok(current)
    }

    fn add_directory(&mut self, path: &Path) -> Result<PathBuf> {
        let resolved = self.resolve(path)?;
        if !resolved.is_dir() {
            bail!(
                "Physical archive directory is not a directory: {}",
                path.display()
            );
        }
        if resolved != Path::new("/") {
            self.directories.insert(resolved.clone());
        }
        Ok(resolved)
    }
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn physical_native_tree_preserves_aliases_and_parent_traversal() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    for dir in [
        "project",
        "actual/deep",
        "actual/policy",
        "actual/empty",
        "project/policy",
    ] {
        fs::create_dir_all(root.join(dir))?;
    }
    let policy = root.join("actual/policy");
    fs::write(policy.join("actual.toml"), b"actual policy")?;
    fs::write(root.join("project/policy/clippy.toml"), b"wrong policy")?;
    symlink("actual.toml", policy.join("clippy.toml"))?;
    symlink("../actual/deep", root.join("project/hop"))?;
    symlink("hop", root.join("project/link"))?;
    symlink("../actual/empty", root.join("project/empty"))?;
    let lexical = root.join("project/link/../policy");
    let file = lexical.join("clippy.toml");

    let mut inputs = CompilerInputs::new(crate::dist::PathTransformer::new());
    inputs.directory(&lexical)?;
    inputs.directory(&root.join("project/empty"))?;
    inputs.file(&file, None)?;
    inputs.file(&policy.join("actual.toml"), None)?;
    let store = crate::build_runtime::NativeStore::open(&root.join("store"))?;
    let tree = inputs
        .into_native_mapping(|_| false)?
        .prepare()?
        .import(&store)?;
    let view = tree.materialize(&root)?;
    let in_archive =
        |path: &Path| -> Result<PathBuf> { Ok(view.root().join(path.strip_prefix("/")?)) };
    assert_eq!(fs::read(in_archive(&file)?)?, b"actual policy");
    assert!(in_archive(&root.join("project/empty"))?.is_dir());
    assert!(in_archive(&root.join("actual/deep"))?.is_dir());
    assert_eq!(
        fs::read_link(in_archive(&root.join("project/link"))?)?,
        Path::new("hop")
    );
    assert_eq!(
        fs::read_link(in_archive(&root.join("project/hop"))?)?,
        Path::new("../actual/deep")
    );
    assert_eq!(
        fs::read_link(in_archive(&policy.join("clippy.toml"))?)?,
        Path::new("actual.toml")
    );
    assert!(!in_archive(&root.join("project/policy/clippy.toml"))?.exists());
    Ok(())
}

#[cfg(all(test, unix))]
#[test]
fn physical_input_rejects_missing_traversal_and_symlink_loops() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir()?;
    let root = temp.path();
    fs::write(root.join("file"), b"data")?;
    symlink("loop", root.join("loop"))?;
    let mut paths = InputArchivePaths::new(crate::dist::PathTransformer::new());
    assert!(paths.file(&root.join("missing/../file")).is_err());
    assert!(paths.directory(&root.join("loop")).is_err());
    assert!(paths.directory(&root.join("file")).is_err());
    Ok(())
}

/// Simplify a path to remove relative components while preserving meaningful symlink paths.
///
/// Resolving every symlink can make an archived path disappear in favor of its canonical path,
/// so this rejects cases where simplification would be ambiguous.
///
/// # Errors
///
/// Returns an error when path simplification encounters unsupported symlink traversal.
pub fn simplify_path(path: &Path) -> Result<PathBuf> {
    SimplifyPath {
        resolved_symlinks: None,
    }
    .simplify(path)
}

struct SimplifyPath<'a> {
    pub resolved_symlinks: Option<&'a mut std::collections::BTreeMap<PathBuf, PathBuf>>,
}

impl SimplifyPath<'_> {
    /// Simplify `path`, recording resolved symlinks when configured.
    ///
    /// # Errors
    ///
    /// Returns an error when filesystem access fails or symlink traversal is unsupported.
    pub fn simplify(&mut self, path: &Path) -> Result<PathBuf> {
        let mut final_path = PathBuf::new();
        for component in path.components() {
            match component {
                c @ (Component::RootDir | Component::Prefix(_) | Component::Normal(_)) => {
                    final_path.push(c);
                    if self.resolved_symlinks.is_some() && final_path.is_symlink() {
                        let parent = final_path.parent().ok_or_else(|| {
                            anyhow!("symlink path has no parent: {}", final_path.display())
                        })?;
                        let link_target = final_path.read_link()?;
                        let new_final_path = self.simplify(&parent.join(&link_target))?;
                        let old_final_path =
                            std::mem::replace(&mut final_path, new_final_path.clone());
                        if let Some(resolved_symlinks) = self.resolved_symlinks.as_deref_mut() {
                            resolved_symlinks.insert(old_final_path, new_final_path);
                        }
                    }
                }
                Component::ParentDir => {
                    // If the path is doing funny symlink traversals, just give up.
                    //
                    // This case should only occur if `resolved_symlinks` is `None`.
                    if final_path.is_symlink() {
                        bail!("Cannot handle symlinks in parent paths")
                    }
                    final_path.pop();
                }
                Component::CurDir => {}
            }
        }
        Ok(final_path)
    }
}
