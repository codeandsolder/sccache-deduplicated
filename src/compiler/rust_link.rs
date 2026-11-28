//! Rust native-link capture. This is a stage primitive, not a replacement
//! for rustc's linker selection or the compiler's ordinary output contract.
use crate::errors::{Context, Result, bail};
use crate::util::Digest;
use anyhow::ensure;
use fs_err as fs;
use fs_err::os::unix::fs::OpenOptionsExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use walkdir::WalkDir;

const RELAY_DIRECTORY: &str = ".sccache-link-relay";
const CONFIG_FILE: &str = "capture.bin";
const INVOCATION_FILE: &str = "invocation.bin";
const VERSION: u32 = 1;

/// Compiler environments and link arguments preserve native OS strings.
pub type LinkEnvironment = BTreeMap<OsString, OsString>;

/// A private writable compiler root and the logical path at which its
/// contents must be restored for native linking.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotRoot {
    pub logical: OsString,
    pub source: OsString,
}

/// Caller-provided resource budget, applied to the entire snapshot of each
/// native invocation. No assumptions about codegen-unit counts or suffixes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct CaptureLimits {
    pub files: u64,
    pub bytes: u64,
    pub invocations: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub roots: Vec<SnapshotRoot>,
    pub destination: OsString,
    pub compiler_environment: LinkEnvironment,
    pub limits: CaptureLimits,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkInvocation {
    version: u32,
    args: Vec<OsString>,
    cwd: OsString,
    compiler_environment_key: String,
    environment_delta: Vec<(OsString, Option<OsString>)>,
    roots: Vec<OsString>,
}

fn environment_key(environment: &LinkEnvironment) -> String {
    let mut digest = Digest::new();
    digest.delimiter(b"rust-native-link-environment-v1");
    for (key, value) in environment {
        digest.delimiter(key.as_encoded_bytes());
        digest.delimiter(value.as_encoded_bytes());
    }
    digest.finish()
}

fn environment_delta(
    baseline: &LinkEnvironment,
    actual: LinkEnvironment,
) -> Vec<(OsString, Option<OsString>)> {
    let mut delta = baseline
        .keys()
        .filter(|key| !actual.contains_key(*key))
        .map(|key| (key.clone(), None))
        .collect::<Vec<_>>();
    delta.extend(actual.into_iter().filter_map(|(key, value)| {
        (baseline.get(&key) != Some(&value)).then_some((key, Some(value)))
    }));
    delta
}

impl CaptureConfig {
    /// Install a relay under the selected linker's original basename so
    /// rustc's filename-based linker flavor inference is not changed.
    /// The capture destination and source roots are interpreted by the
    /// compiler's namespace, not the installer.
    ///
    /// # Errors
    /// Invalid configuration or filesystem setup failure.
    pub fn install(
        &self,
        executable: &Path,
        relay_parent: &Path,
        linker_basename: &OsStr,
    ) -> Result<PathBuf> {
        let mut components = Path::new(linker_basename).components();
        ensure!(
            matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none(),
            "linker basename must be one path component"
        );
        self.validate()?;
        let relay = relay_parent.join(RELAY_DIRECTORY);
        std::fs::DirBuilder::new().mode(0o700).create(&relay)?;
        let config = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(relay.join(CONFIG_FILE))?;
        bincode::serialize_into(config, self)?;
        let path = relay.join(linker_basename);
        std::os::unix::fs::symlink(executable, &path)?;
        Ok(path)
    }

    fn validate(&self) -> Result<()> {
        ensure!(!self.roots.is_empty(), "capture has no generated roots");
        ensure!(
            Path::new(&self.destination).is_absolute(),
            "capture destination must be absolute"
        );
        let mut roots = std::collections::BTreeSet::new();
        for root in &self.roots {
            ensure!(
                Path::new(&root.logical).is_absolute() && Path::new(&root.source).is_absolute(),
                "capture roots must be absolute"
            );
            ensure!(
                roots.insert(&root.logical),
                "duplicate logical capture root"
            );
        }
        ensure!(
            self.limits.files > 0 && self.limits.bytes > 0 && self.limits.invocations > 0,
            "capture limits must be positive"
        );
        Ok(())
    }

    fn capture(self, args: Vec<OsString>) -> Result<()> {
        self.validate()?;
        let destination = fs::canonicalize(&self.destination)?;
        for root in &self.roots {
            let source = fs::canonicalize(&root.source)?;
            ensure!(
                !destination.starts_with(&source),
                "capture destination overlaps generated inputs"
            );
        }
        let invocation_dir = reserve_invocation(&destination, self.limits.invocations)?;
        let invocation = LinkInvocation {
            version: VERSION,
            args,
            cwd: std::env::current_dir()?.into_os_string(),
            compiler_environment_key: environment_key(&self.compiler_environment),
            environment_delta: environment_delta(
                &self.compiler_environment,
                std::env::vars_os().collect(),
            ),
            roots: self.roots.iter().map(|root| root.logical.clone()).collect(),
        };
        let mut budget = Budget::new(self.limits);
        for (index, root) in self.roots.iter().enumerate() {
            snapshot_root(
                Path::new(&root.source),
                &invocation_dir.join(root_archive(index)),
                &mut budget,
            )?;
        }

        // This is the commit marker. A compiler failure or interruption can
        // leave staging directories but never advertises a complete bundle.
        fs::write(
            invocation_dir.join(INVOCATION_FILE),
            bincode::serialize(&invocation)?,
        )?;
        Ok(())
    }
}

fn reserve_invocation(destination: &Path, limit: u32) -> Result<PathBuf> {
    for index in 0..limit {
        let path = destination.join(format!("invocation-{index:010}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    bail!("native linker invocation count exceeded")
}

fn root_archive(index: usize) -> String {
    format!("root-{index}.tar")
}

struct Budget {
    files: u64,
    bytes: u64,
}

impl Budget {
    const fn new(limits: CaptureLimits) -> Self {
        Self {
            files: limits.files,
            bytes: limits.bytes,
        }
    }

    fn consume(&mut self, bytes: u64) -> Result<()> {
        self.files = self
            .files
            .checked_sub(1)
            .context("generated file count exceeded")?;
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .context("generated data size exceeded")?;
        Ok(())
    }
}

fn snapshot_root(root: &Path, archive: &Path, budget: &mut Budget) -> Result<()> {
    let mut builder = tar::Builder::new(fs::File::create(archive)?);
    builder.follow_symlinks(false);
    for entry in WalkDir::new(root).min_depth(1).sort_by_file_name() {
        let entry = entry?;
        let path = entry.path();
        let relative = path.strip_prefix(root)?;
        let metadata = fs::symlink_metadata(path)?;
        let file_type = metadata.file_type();
        ensure!(
            file_type.is_file() || file_type.is_dir() || file_type.is_symlink(),
            "unsupported generated filesystem object {}",
            path.display()
        );
        budget.consume(if file_type.is_file() {
            metadata.len()
        } else {
            0
        })?;
        builder.append_path_with_name(path, relative)?;
    }
    builder.finish()?;
    Ok(())
}

fn restore_root(archive: &Path, destination: &Path, budget: &mut Budget) -> Result<()> {
    ensure!(
        fs::read_dir(destination)?.next().is_none(),
        "link staging directory must be empty"
    );
    let mut file = fs::File::open(archive)?;
    let mut reader = tar::Archive::new(&mut file);
    for entry in reader.entries()? {
        let entry = entry?;
        let kind = entry.header().entry_type();
        ensure!(
            kind.is_file() || kind.is_gnu_sparse() || kind.is_dir() || kind.is_symlink(),
            "invalid generated snapshot entry type {kind:?} for {}",
            entry.path()?.display()
        );
        ensure!(
            entry
                .path()?
                .components()
                .all(|part| matches!(part, Component::Normal(_) | Component::CurDir)),
            "invalid generated snapshot path"
        );
        // tar resolves GNU sparse and PAX size fields to the actual logical
        // size, not the stored extent length. Charge the full restored size.
        budget.consume(entry.size())?;
    }
    file.seek(SeekFrom::Start(0))?;
    tar::Archive::new(file).unpack(destination)?;
    Ok(())
}

impl LinkInvocation {
    /// Load the committed invocation manifest. The caller owns the archive
    /// directory and must mount restored roots at their original logical paths.
    ///
    /// # Errors
    /// Missing, malformed or unsupported invocation manifest.
    pub fn load(directory: &Path) -> Result<Self> {
        let invocation: Self =
            bincode::deserialize_from(fs::File::open(directory.join(INVOCATION_FILE))?)?;
        ensure!(
            invocation.version == VERSION,
            "unsupported native link manifest version"
        );
        Ok(invocation)
    }

    /// Restore each generated root into a distinct empty private directory.
    /// External libraries and paths not in the snapshot remain caller-owned.
    ///
    /// # Errors
    /// Incorrect root mapping, invalid snapshot, exceeded budget or I/O error.
    pub fn restore(
        &self,
        directory: &Path,
        destinations: &BTreeMap<OsString, PathBuf>,
        limits: CaptureLimits,
    ) -> Result<()> {
        ensure!(
            self.roots.len() == destinations.len(),
            "link snapshot root mapping is incomplete"
        );
        let mut budget = Budget::new(limits);
        for (index, root) in self.roots.iter().enumerate() {
            let destination = destinations
                .get(root)
                .context("missing link snapshot root")?;
            restore_root(
                &directory.join(root_archive(index)),
                destination,
                &mut budget,
            )?;
        }
        Ok(())
    }

    /// Construct the exact native linker invocation. The compiler environment
    /// is part of the codegen identity: a different baseline requires
    /// regenerating the plan instead of applying stale environment overrides.
    /// Argument bytes are not interpreted or rewritten.
    ///
    /// # Errors
    /// The current compiler environment does not match the captured baseline.
    pub fn command(&self, linker: &Path, environment: &LinkEnvironment) -> Result<Command> {
        ensure!(
            environment_key(environment) == self.compiler_environment_key,
            "native link compiler environment changed"
        );
        let mut command = Command::new(linker);
        command
            .args(&self.args)
            .current_dir(&self.cwd)
            .env_clear()
            .envs(environment);
        for (key, value) in &self.environment_delta {
            if let Some(value) = value {
                command.env(key, value);
            } else {
                command.env_remove(key);
            }
        }
        Ok(command)
    }

    /// Execute native linking using the current namespace's actual linker.
    ///
    /// # Errors
    /// The environment differs from capture or the linker could not be run.
    pub fn replay(&self, linker: &Path, environment: &LinkEnvironment) -> Result<Output> {
        Ok(self.command(linker, environment)?.output()?)
    }
}

/// A compiler-owned split-link invocation.
///
/// The link stage retains the complete compiler option list. The codegen
/// stage omits typed native-linker-only arguments; all other argument bytes
/// and ordering remain exact. Both use identical logical paths.
pub struct RustLinkStages {
    arguments: ParsedLinkArguments,
    codegen_directory: PathBuf,
    output_roots: Vec<PathBuf>,
}

pub(super) struct ParsedLinkArguments {
    pub original: Vec<OsString>,
    pub codegen: Vec<OsString>,
    pub input: usize,
}

impl RustLinkStages {
    /// Parse the actual source operand and expand compiler response files once.
    ///
    /// # Errors
    /// The input is ambiguous, not a linked compilation, or already a stage.
    pub fn new(arguments: &[OsString], cwd: &Path) -> Result<Self> {
        Self::from_expanded(
            super::rust_response::expand(arguments, cwd)?,
            cwd,
            resolve_output_directory,
        )
    }

    /// Construct stages from already expanded compiler arguments in a
    /// caller-defined logical filesystem layout. The resolver must resolve
    /// the exact output directory through the actual physical path mapping,
    /// then return its canonical logical spelling.
    /// # Errors
    /// Returns an error for an ambiguous source or output layout.
    pub fn from_expanded(
        arguments: Vec<OsString>,
        cwd: &Path,
        resolve_directory: impl FnMut(&Path, &Path) -> Result<PathBuf>,
    ) -> Result<Self> {
        super::rust::native_link_stage_input(arguments, cwd, resolve_directory)
    }

    pub(super) fn from_parsed(
        arguments: ParsedLinkArguments,
        cwd: &Path,
        out_dir: Option<&Path>,
        output_file: Option<&Path>,
        explicit_outputs: &[PathBuf],
        mut resolve_directory: impl FnMut(&Path, &Path) -> Result<PathBuf>,
    ) -> Result<Self> {
        ensure!(cwd.is_absolute(), "compiler cwd must be absolute");
        let directory = output_file.map_or_else(
            || out_dir.unwrap_or(cwd),
            |path| path.parent().unwrap_or_else(|| Path::new("")),
        );
        let codegen_directory = resolve_directory(cwd, directory)?;
        let mut roots = vec![codegen_directory.clone()];
        for path in explicit_outputs {
            roots.push(resolve_directory(
                cwd,
                path.parent().unwrap_or_else(|| Path::new("")),
            )?);
        }
        // Parent roots already contain any nested output directory. Keep
        // overlays disjoint, including when two paths resolve through aliases.
        for root in &roots {
            ensure!(
                root.is_absolute()
                    && root != Path::new("/")
                    && root
                        .components()
                        .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
                "invalid logical output directory"
            );
        }
        roots.sort_unstable();
        let mut output_roots: Vec<PathBuf> = Vec::new();
        for root in roots {
            if !output_roots.iter().any(|parent| root.starts_with(parent)) {
                output_roots.push(root);
            }
        }
        Ok(Self {
            arguments,
            codegen_directory,
            output_roots,
        })
    }

    /// The compiler's actual output directory for .rlink and generated
    /// codegen objects; -o takes precedence over --out-dir.
    #[must_use = "the codegen directory locates the generated link artifact"]
    pub fn codegen_directory(&self) -> &Path {
        &self.codegen_directory
    }

    /// Disjoint writable roots needed by both stages, including explicitly
    /// placed emit files. Mount writable overlays only at these directories.
    #[must_use = "these roots define the generated output tree contract"]
    pub fn output_roots(&self) -> &[PathBuf] {
        &self.output_roots
    }

    /// Expanded codegen arguments. Use the shared rustc response-file
    /// preparation when launching, so literal leading @ operands survive.
    #[must_use = "these arguments execute the codegen stage"]
    pub fn codegen_arguments(&self) -> Vec<OsString> {
        let mut arguments = Vec::with_capacity(self.arguments.codegen.len() + 2);
        arguments.extend([OsString::from("-Z"), OsString::from("no-link")]);
        arguments.extend(self.arguments.codegen.iter().cloned());
        arguments
    }

    /// Expanded link arguments, with the .rlink artifact at its original
    /// logical path and all current linker options retained.
    #[must_use = "these arguments execute the compiler's native link stage"]
    pub fn link_arguments(&self, artifact: &Path) -> Vec<OsString> {
        let mut arguments = Vec::with_capacity(self.arguments.original.len() + 2);
        // Prefix the stage option: a trailing -- must not turn it into a
        // source operand.
        arguments.extend([OsString::from("-Z"), OsString::from("link-only")]);
        arguments.extend(self.arguments.original.iter().cloned());
        artifact
            .as_os_str()
            .clone_into(&mut arguments[self.arguments.input + 2]);
        arguments
    }

    /// Locate the compiler-produced .rlink in the generated output delta.
    /// Neither the crate name, the codegen-unit count nor file naming is
    /// guessed. The returned path refers to the original logical namespace.
    ///
    /// # Errors
    /// The output does not contain exactly one regular .rlink artifact.
    pub fn link_artifact(generated: &Path, logical: &Path) -> Result<PathBuf> {
        ensure!(
            logical.is_absolute(),
            "logical output path must be absolute"
        );
        let mut artifact = None;
        for entry in WalkDir::new(generated).min_depth(1).follow_links(false) {
            let entry = entry?;
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "rlink")
            {
                ensure!(entry.file_type().is_file(), "invalid .rlink artifact type");
                let relative = entry.path().strip_prefix(generated)?;
                ensure!(
                    artifact.replace(logical.join(relative)).is_none(),
                    "multiple .rlink artifacts"
                );
            }
        }
        artifact.context("compiler did not generate a .rlink artifact")
    }
}

// Resolve the existing prefix through actual symlinks, then append any
// not-yet-created suffix. Never erase unresolved parent traversal.
fn resolve_output_directory(cwd: &Path, directory: &Path) -> Result<PathBuf> {
    let path = super::canonical_paths::physical_operand(cwd, directory)
        .context("cannot preserve output directory traversal")?;
    let mut existing = path.as_path();
    loop {
        match fs::canonicalize(existing) {
            Ok(resolved) => {
                ensure!(resolved.is_dir(), "output ancestor is not a directory");
                let result = resolved.join(path.strip_prefix(existing)?);
                ensure!(
                    result != Path::new("/"),
                    "root cannot be a generated output directory"
                );
                return Ok(result);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A dangling symlink is not a directory we can create.
                ensure!(
                    !existing.is_symlink(),
                    "unresolved output directory symlink"
                );
                existing = existing
                    .parent()
                    .context("output directory has no existing ancestor")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Private generated output tree over the original logical compiler output
/// directory.
///
/// The lower directory remains visible for input dependencies and
/// is never mutated by either compilation stage. The generated delta is the
/// artifact: it contains no unchanged dependency files from the lower tree.
pub struct PrivateOutputTree {
    root: tempfile::TempDir,
    upper: PathBuf,
    work: PathBuf,
}

impl PrivateOutputTree {
    /// Allocate a private overlay upper/work pair under the supplied staging
    /// parent, keeping both directories on the same filesystem.
    ///
    /// # Errors
    /// The staging directories cannot be created.
    pub fn new(parent: &Path) -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("rust-output-stage-")
            .tempdir_in(parent)?;
        let upper = root.path().join("upper");
        let work = root.path().join("work");
        fs::create_dir(&upper)?;
        fs::create_dir(&work)?;
        Ok(Self { root, upper, work })
    }

    /// Reserve the upper directory as the destination of an incoming native
    /// CAS tree. Delivery publishes the verified tree atomically at this
    /// absent path. The overlay then uses exactly those files in place,
    /// without an intermediate archive, copy, or second cache.
    /// # Errors
    /// Returns an error if the stage has already been populated.
    pub fn prepare_delivery(&self) -> Result<&Path> {
        fs::remove_dir(&self.upper)?;
        Ok(&self.upper)
    }

    /// Build the Bubblewrap overlay operation preserving the original path.
    /// The returned arguments must precede the sandbox command separator.
    ///
    /// # Errors
    /// A source or destination path is unsuitable for private staging.
    pub fn overlay_arguments(&self, lower: &Path, logical: &Path) -> Result<Vec<OsString>> {
        ensure!(
            lower.is_absolute() && logical.is_absolute(),
            "stage paths must be absolute"
        );
        let lower = fs::canonicalize(lower)?;
        ensure!(lower.is_dir(), "output stage lower is not a directory");
        ensure!(
            !self.root.path().starts_with(&lower) && !lower.starts_with(self.root.path()),
            "stage storage overlaps the output tree"
        );
        Ok(vec![
            "--overlay-src".into(),
            lower.into_os_string(),
            "--overlay".into(),
            self.upper.clone().into_os_string(),
            self.work.clone().into_os_string(),
            logical.as_os_str().to_owned(),
        ])
    }

    /// The files generated by the compiler, excluding unchanged lower inputs.
    #[must_use = "the generated root is needed for artifact collection"]
    pub fn generated_root(&self) -> &Path {
        &self.upper
    }

    /// Serialize the generated tree. The compiler must have exited and its
    /// mount namespace must have been destroyed before this operation.
    ///
    /// # Errors
    /// Unsupported filesystem object, exceeded limits or I/O failure.
    pub fn archive(&self, destination: &Path, limits: CaptureLimits) -> Result<()> {
        snapshot_root(&self.upper, destination, &mut Budget::new(limits))
    }

    /// Restore a cached generated tree into this new, private upper directory.
    ///
    /// # Errors
    /// Invalid snapshot, nonempty destination, exceeded limits or I/O failure.
    pub fn restore(&self, archive: &Path, limits: CaptureLimits) -> Result<()> {
        restore_root(archive, &self.upper, &mut Budget::new(limits))
    }
}

/// Local namespace of an ordinary Rust native link.
///
/// Linking must use these mounts rather than the worker's
/// sparse input filesystem.
#[cfg(feature = "dist-client")]
#[derive(Debug, Clone)]
pub struct NativeLinkLayout {
    pub(crate) dep_info: Option<PathBuf>,
    pub(crate) environment: Vec<(OsString, OsString)>,
}

#[cfg(feature = "dist-client")]
impl NativeLinkLayout {
    pub(crate) fn new(dep_info: Option<PathBuf>, environment: Vec<(OsString, OsString)>) -> Self {
        Self {
            dep_info,
            environment,
        }
    }
}

/// Logical stage topology and private final-result delivery destinations.
pub struct NativeLinkWorkspace {
    stages: RustLinkStages,
    roots: BTreeMap<PathBuf, NativeLinkRoot>,
}

struct NativeLinkRoot {
    physical: PathBuf,
    tree: PrivateOutputTree,
}

impl NativeLinkWorkspace {
    /// Reserve private, absent delivery paths for every logical output root.
    /// # Errors
    /// Returns an error for an unavailable or overlapping physical layout,
    /// or a staging directory that could not be created.
    pub fn new(
        stages: RustLinkStages,
        scratch: &Path,
        mut physical_path: impl FnMut(&Path) -> Result<PathBuf>,
    ) -> Result<Self> {
        let mut roots: BTreeMap<PathBuf, NativeLinkRoot> = BTreeMap::new();
        for logical in stages.output_roots() {
            let physical = fs::canonicalize(physical_path(logical)?)?;
            ensure!(physical.is_dir(), "native link lower is not a directory");
            ensure!(
                roots
                    .values()
                    .all(|root| !root.physical.starts_with(&physical)
                        && !physical.starts_with(&root.physical)),
                "physical output roots overlap"
            );
            let tree = PrivateOutputTree::new(scratch)?;
            tree.overlay_arguments(&physical, logical)?;
            tree.prepare_delivery()?;
            roots.insert(logical.clone(), NativeLinkRoot { physical, tree });
        }
        Ok(Self { stages, roots })
    }

    /// Exact codegen arguments in the declared logical layout.
    #[must_use = "the worker must execute this stage instead of final linking"]
    pub fn codegen_arguments(&self) -> Vec<OsString> {
        self.stages.codegen_arguments()
    }

    /// Logical path, caller physical lower directory, and absent private
    /// destination for every generated tree.
    #[must_use = "the outputs describe the directory delivery contract"]
    pub fn outputs(&self) -> impl Iterator<Item = (&Path, &Path, &Path)> {
        self.roots.iter().map(|(logical, root)| {
            (
                logical.as_path(),
                root.physical.as_path(),
                root.tree.generated_root(),
            )
        })
    }

    pub(crate) fn link_arguments(&self, artifact: &Path) -> Vec<OsString> {
        self.stages.link_arguments(artifact)
    }

    pub(crate) fn codegen_directory(&self) -> &Path {
        self.stages.codegen_directory()
    }

    /// Install the surviving outputs of the successful link stage.
    ///
    /// The compiler has cleaned its own temporary files. Skip
    /// only the exact internal .rlink and the independently generated local
    /// dependency file, not classes of names or filename suffixes.
    /// # Errors
    /// Invalid output topology, missing required outputs, or publication I/O
    /// failure. No paths outside the declared output roots are published.
    #[cfg(feature = "dist-client")]
    pub(crate) fn publish(
        &self,
        artifact: &Path,
        expected: &[crate::cache::FileObjectSource],
        cwd: &Path,
        dep_info: Option<&Path>,
    ) -> Result<()> {
        use std::collections::BTreeSet;

        let mut entries = Vec::new();
        let mut seen = BTreeSet::new();
        for (logical, root) in &self.roots {
            for entry in WalkDir::new(root.tree.generated_root())
                .min_depth(1)
                .follow_links(false)
            {
                let entry = entry?;
                let relative = entry.path().strip_prefix(root.tree.generated_root())?;
                let destination = root.physical.join(relative);
                if logical.join(relative) == artifact || dep_info == Some(destination.as_path()) {
                    continue;
                }
                let kind = entry.file_type();
                ensure!(
                    kind.is_dir() || kind.is_file() || kind.is_symlink(),
                    "unsupported generated filesystem object: {}",
                    entry.path().display()
                );
                // Validate every existing lower ancestor without following
                // links: the final rename must remain in the output root.
                let mut parent = destination.parent().context("missing output parent")?;
                while parent.starts_with(&root.physical) {
                    match fs::symlink_metadata(parent) {
                        Ok(metadata) => ensure!(
                            metadata.is_dir(),
                            "unsafe output parent {}",
                            parent.display()
                        ),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                    if parent == root.physical {
                        break;
                    }
                    parent = parent.parent().context("missing output ancestor")?;
                }
                if let Ok(metadata) = fs::symlink_metadata(&destination) {
                    ensure!(
                        metadata.is_dir() == kind.is_dir(),
                        "output kind conflicts with existing path {}",
                        destination.display()
                    );
                }
                if !kind.is_dir() {
                    seen.insert(destination.clone());
                }
                entries.push((entry.into_path(), destination, kind));
            }
        }
        for output in expected {
            let path = cwd.join(&output.path);
            let parent = resolve_output_directory(
                cwd,
                path.parent().context("missing declared output parent")?,
            )?;
            let destination =
                parent.join(path.file_name().context("missing declared output name")?);
            ensure!(
                output.optional || seen.contains(&destination),
                "native link did not produce {}",
                destination.display()
            );
        }
        // WalkDir is parent-first. A directory from an overlay can represent
        // existing lower topology; never replace the lower directory wholesale.
        for (_, destination, kind) in &entries {
            if kind.is_dir() && !destination.exists() {
                fs::create_dir(destination)?;
            }
        }
        for (source, destination, kind) in &entries {
            if !kind.is_dir() {
                publish_leaf(source, destination)?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "dist-client")]
fn publish_leaf(source: &Path, destination: &Path) -> Result<()> {
    // fs_err adds useful path context but wraps the underlying OS error.
    // Inspect the original errno before adding that context.
    match std::fs::rename(source, destination) {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "publish generated output {} to {}",
                    source.display(),
                    destination.display()
                )
            });
        }
    }
    // Cross-filesystem delivery still publishes each verified leaf by
    // atomic rename. Copy only when the source cannot be renamed.
    let parent = destination.parent().context("missing publication parent")?;
    let stage = tempfile::Builder::new()
        .prefix(".rust-link-publish-")
        .tempdir_in(parent)?;
    let temporary = stage.path().join("output");
    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_symlink() {
        std::os::unix::fs::symlink(fs::read_link(source)?, &temporary)?;
    } else {
        fs::copy(source, &temporary)?;
        // Preserve compiler output timestamps across the bind-mount boundary.
        fs::File::open(&temporary)?.set_times(
            std::fs::FileTimes::new()
                .set_modified(metadata.modified()?)
                .set_accessed(metadata.accessed()?),
        )?;
    }
    fs::rename(temporary, destination)?;
    Ok(())
}

/// The normal sccache executable also acts as an explicitly installed relay.
/// Its name inside the reserved directory is the original linker basename.
pub(crate) fn capture_if_relay() -> Option<Result<()>> {
    let mut args = std::env::args_os();
    let invoked = PathBuf::from(args.next()?);
    let parent = invoked.parent()?;
    if parent.file_name()? != RELAY_DIRECTORY {
        return None;
    }
    Some((|| {
        let config: CaptureConfig =
            bincode::deserialize_from(fs::File::open(parent.join(CONFIG_FILE))?)?;
        config.capture(args.collect())
    })())
}
