//! Rust native-link capture. This is a stage primitive, not a replacement
//! for rustc's linker selection or the compiler's ordinary output contract.
use crate::errors::{Context, Result};
use anyhow::ensure;
use fs_err as fs;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
#[cfg(feature = "dist-client")]
use walkdir::WalkDir;

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

/// The original caller's logical-to-physical output layout and environment.
#[cfg(feature = "dist-client")]
#[derive(Debug, Clone)]
pub struct NativeLinkLayout {
    pub(crate) dep_info: Option<PathBuf>,
    pub(crate) environment: Vec<(OsString, OsString)>,
    pub(crate) codegen_only: std::collections::BTreeSet<PathBuf>,
}

#[cfg(feature = "dist-client")]
impl NativeLinkLayout {
    pub(crate) fn new(
        dep_info: Option<PathBuf>,
        environment: Vec<(OsString, OsString)>,
        codegen_only: std::collections::BTreeSet<PathBuf>,
    ) -> Self {
        Self {
            dep_info,
            environment,
            codegen_only,
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
    _scratch: tempfile::TempDir,
    delivery: PathBuf,
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
            let staging = tempfile::Builder::new()
                .prefix("rust-output-stage-")
                .tempdir_in(scratch)?;
            ensure!(
                !staging.path().starts_with(&physical) && !physical.starts_with(staging.path()),
                "stage storage overlaps the output tree"
            );
            let delivery = staging.path().join("result");
            roots.insert(
                logical.clone(),
                NativeLinkRoot {
                    physical,
                    _scratch: staging,
                    delivery,
                },
            );
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
                root.delivery.as_path(),
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
            for entry in WalkDir::new(root.delivery.as_path())
                .min_depth(1)
                .follow_links(false)
            {
                let entry = entry?;
                let relative = entry.path().strip_prefix(root.delivery.as_path())?;
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
