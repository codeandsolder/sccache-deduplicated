//! Run a declared native action and retain independently readable output
//! descriptors. The worker uploads the captured bytes directly; no result
//! archive, local CAS publication, or intermediary copy is required.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt},
    },
    path::{Path, PathBuf},
    process::{Child, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use rustix::{
    fs::{Mode, OFlags, ResolveFlags, Stat, openat2},
    io::Errno,
};

use crate::{
    Artifact, BlobRef, BuildPath, ContentId, ExecutionSpec, MaterializedTree, NativeStore,
    OutputKind, ResultManifest, TreeEntry, TreeLease, TreeManifest, TreePath,
    sandbox::{MountAccess, SandboxInvocation, SandboxPath, SandboxPlan},
};

/// Worker-local policy, not part of the client-controlled action.
///
/// The deployment-provided platform digest must match the declared execution
/// contract. Time and storage limits reject execution instead of changing the
/// identity of successful outputs.
pub struct ExecutionPolicy {
    pub platform: ContentId,
    pub bubblewrap: PathBuf,
    pub scratch: PathBuf,
    pub timeout: Duration,
    pub max_result_bytes: u64,
}

/// An isolated process's captured output and diagnostics.
///
/// Failed processes retain diagnostics for delivery but cannot produce a
/// successful result manifest. All readers use positional reads of regular
/// files opened before releasing the private build directory.
pub struct CapturedExecution {
    status: ExitStatus,
    manifest: ResultManifest,
    files: BTreeMap<ContentId, File>,
}

impl CapturedExecution {
    #[must_use = "the status distinguishes successful from failed execution"]
    pub const fn status(&self) -> ExitStatus {
        self.status
    }

    /// Obtain a publication manifest only for a successful process.
    #[must_use = "failed execution must not populate the action cache"]
    pub fn successful_result(&self) -> Option<&ResultManifest> {
        self.status.success().then_some(&self.manifest)
    }

    #[must_use = "the references identify the captured process diagnostics"]
    pub const fn diagnostics(&self) -> (Option<BlobRef>, Option<BlobRef>) {
        (self.manifest.stdout, self.manifest.stderr)
    }

    /// Open a fresh independent stream of captured content.
    ///
    /// # Errors
    /// Returns an error for an undeclared blob or descriptor failure.
    pub fn open_blob(&self, id: ContentId) -> Result<impl Read + Send + 'static> {
        let file = self
            .files
            .get(&id)
            .context("uncaptured result blob")?
            .try_clone()?;
        Ok(PositionalReader { file, offset: 0 })
    }
}

struct PositionalReader {
    file: File,
    offset: u64,
}

impl Read for PositionalReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read_at(buffer, self.offset)?;
        self.offset = self
            .offset
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("result read offset overflow"))?;
        Ok(count)
    }
}

struct OutputLocation {
    directory: File,
    relative: PathBuf,
    baseline: Option<GeneratedBaseline>,
}

impl OutputLocation {
    fn open(&self, kind: OutputKind, required: bool) -> Result<Option<File>> {
        let flags = OFlags::RDONLY
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK
            | if kind.is_tree() {
                OFlags::DIRECTORY
            } else {
                OFlags::empty()
            };
        if self.relative.as_os_str().is_empty() {
            return Ok(Some(self.directory.try_clone()?));
        }
        match openat2(
            &self.directory,
            &self.relative,
            flags,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        ) {
            Ok(fd) => Ok(Some(File::from(fd))),
            Err(Errno::NOENT) if !required => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

/// The existing immutable inputs inside a generated-output directory.
/// Capture their actual private-view metadata without reading their bytes.
/// An identical input is not a generated artifact and must not be sent back.
struct GeneratedBaseline {
    tree: TreeManifest,
    files: BTreeMap<TreePath, Stat>,
}

impl GeneratedBaseline {
    fn capture(directory: &File, relative: &Path, input: &TreeManifest) -> Result<Self> {
        let mut files = BTreeMap::new();
        let tree = crate::source::capture_tree(directory, |path, _, stat| {
            let logical = relative.join(host_path(path.as_bytes()));
            let key = TreePath::new(logical.as_os_str().as_bytes().to_vec())?;
            let entry = input
                .entries
                .get(&key)
                .context("generated root contains an undeclared input")?;
            let entry = if let TreeEntry::Hardlink(target) = entry {
                input
                    .entries
                    .get(target)
                    .context("missing input hardlink target")?
            } else {
                entry
            };
            let TreeEntry::File { blob, .. } = entry else {
                anyhow::bail!("generated root input is not a regular file");
            };
            ensure!(
                u64::try_from(stat.st_size)? == blob.size,
                "materialized input size changed"
            );
            files.insert(path.clone(), *stat);
            Ok(*blob)
        })?;
        Ok(Self { tree, files })
    }

    fn existing_file(&self, path: &TreePath, stat: &Stat) -> Result<Option<BlobRef>> {
        if let Some(before) = self.files.get(path) {
            crate::source::unchanged(before, stat)
                .context("generated output modified an input file")?;
            let Some(TreeEntry::File { blob, .. }) = self.tree.entries.get(path) else {
                anyhow::bail!("generated baseline file missing");
            };
            Ok(Some(*blob))
        } else {
            ensure!(
                !self.tree.entries.contains_key(path),
                "generated output replaced an input"
            );
            Ok(None)
        }
    }

    fn additions(&self, mut actual: TreeManifest) -> Result<TreeManifest> {
        ensure!(
            actual.root.mode == self.tree.root.mode,
            "generated output changed input root permissions"
        );
        for (path, before) in &self.tree.entries {
            let after = actual
                .entries
                .get(path)
                .context("generated output removed an input")?;
            let unchanged = match (before, after) {
                (TreeEntry::Directory(before), TreeEntry::Directory(after)) => {
                    before.mode == after.mode
                }
                _ => before == after,
            };
            ensure!(
                unchanged,
                "generated output changed an input: {:?}",
                path.as_bytes()
            );
        }

        // Existing directories are included only when needed as parents of
        // generated entries. No unchanged regular files, links, or unrelated
        // input directories are copied into the result.
        let mut parents = BTreeSet::new();
        for path in actual
            .entries
            .keys()
            .filter(|path| !self.tree.entries.contains_key(*path))
        {
            for (index, _) in path
                .as_bytes()
                .iter()
                .enumerate()
                .filter(|(_, byte)| **byte == b'/')
            {
                parents.insert(TreePath::new(path.as_bytes()[..index].to_vec())?);
            }
        }
        actual
            .entries
            .retain(|path, _| !self.tree.entries.contains_key(path) || parents.contains(path));
        // This also rejects aliases to inputs outside the generated tree.
        actual.validate()?;
        Ok(actual)
    }
}

struct PreparedBuild {
    plan: SandboxPlan,
    outputs: BTreeMap<String, OutputLocation>,
    // One independently cloned view per namespace location, even when two
    // locations reference the same tree ID.
    _views: BTreeMap<BuildPath, MaterializedTree>,
}

fn host_path(bytes: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(bytes))
}

fn backing<'a, T>(
    locations: &'a BTreeMap<BuildPath, T>,
    path: &BuildPath,
) -> Result<(&'a BuildPath, &'a T)> {
    locations
        .iter()
        .filter(|(point, _)| path.within(point.as_bytes()))
        .max_by_key(|(point, _)| point.as_bytes().len())
        .context("missing native backing tree")
}

fn relative<'a>(path: &'a BuildPath, mount: &BuildPath) -> Result<&'a Path> {
    host_path(path.as_bytes())
        .strip_prefix(host_path(mount.as_bytes()))
        .context("native path lies outside its backing tree")
}

fn require_directory(tree: &TreeLease, path: &Path) -> Result<()> {
    if !path.as_os_str().is_empty() {
        let relative = TreePath::new(path.as_os_str().as_bytes().to_vec())?;
        ensure!(
            matches!(
                tree.manifest().entries.get(&relative),
                Some(TreeEntry::Directory(_))
            ),
            "native directory is not declared: {}",
            path.display()
        );
    }
    Ok(())
}

fn output_parent(path: &BuildPath) -> Result<BuildPath> {
    let parent = host_path(path.as_bytes())
        .parent()
        .context("output parent missing")?;
    BuildPath::new(parent.as_os_str().as_bytes().to_vec())
}

fn writable_locations(
    spec: &ExecutionSpec,
    leases: &BTreeMap<BuildPath, TreeLease>,
) -> Result<BTreeSet<BuildPath>> {
    let tmp = BuildPath::new(b"/tmp".to_vec())?;
    let mut writable = BTreeSet::from([tmp]);
    for output in spec.outputs.values() {
        let (mount, tree) = backing(leases, &output.path)?;
        let path = relative(&output.path, mount)?;
        let existing = if path.as_os_str().is_empty() {
            ensure!(
                output.kind.is_tree(),
                "file output cannot replace a mount root"
            );
            true
        } else {
            let parent = path
                .parent()
                .context("output cannot replace a mount root")?;
            require_directory(tree, parent)?;
            tree.manifest()
                .entries
                .contains_key(&TreePath::new(path.as_os_str().as_bytes().to_vec())?)
        };
        if existing {
            ensure!(
                output.kind.is_tree(),
                "declared file output already exists in immutable input"
            );
            require_directory(tree, path)?;
            writable.insert(output.path.clone());
        } else {
            writable.insert(output_parent(&output.path)?);
        }
    }
    // Remove redundant nested bindings only within the same backing tree.
    let mut result = BTreeSet::new();
    for path in &writable {
        let (mount, _) = backing(leases, path)?;
        if !result.iter().any(|parent: &BuildPath| {
            path.within(parent.as_bytes()) && parent.within(mount.as_bytes())
        }) {
            result.insert(path.clone());
        }
    }
    Ok(result)
}

impl PreparedBuild {
    fn prepare(spec: &ExecutionSpec, store: &NativeStore, scratch: &Path) -> Result<Self> {
        let root_point = BuildPath::new(b"/".to_vec())?;
        let mut leases: BTreeMap<BuildPath, TreeLease> = spec
            .mounts
            .iter()
            .map(|(path, &id)| {
                Ok((
                    path.clone(),
                    store
                        .lookup_tree(id)?
                        .context("native input tree unavailable")?,
                ))
            })
            .collect::<Result<_>>()?;
        leases.insert(root_point.clone(), store.lease_recipe(&spec.root.recipe)?);
        let root = leases.get(&root_point).context("native root unavailable")?;
        spec.root.verify(root.id())?;
        // Never mount through a symlink or a nonexistent parent in the root.
        for path in spec.mounts.keys().map(BuildPath::as_bytes).chain([
            b"/tmp".as_slice(),
            b"/proc",
            b"/dev",
        ]) {
            require_directory(root, host_path(&path[1..]))?;
        }
        let writable = writable_locations(spec, &leases)?;
        let mut views: BTreeMap<BuildPath, MaterializedTree> = leases
            .iter()
            .map(|(path, lease)| Ok((path.clone(), lease.materialize(scratch)?)))
            .collect::<Result<_>>()?;
        for path in &writable {
            let (point, _) = backing(&leases, path)?;
            views
                .get_mut(point)
                .context("native view missing")?
                .mark_writable(relative(path, point)?);
        }
        let access = |path: &BuildPath| {
            if writable.contains(path) {
                MountAccess::Writable
            } else {
                MountAccess::ReadOnly
            }
        };
        let root = views.get(&root_point).context("native root view missing")?;
        let mut plan = SandboxPlan::new(root.root(), access(&root_point))?;
        for (path, view) in &views {
            if path != &root_point {
                plan.bind(
                    view.root(),
                    SandboxPath::new(host_path(path.as_bytes()))?,
                    access(path),
                )?;
            }
        }
        for path in &writable {
            // The mount root itself already has the correct access mode.
            if views.contains_key(path) {
                continue;
            }
            let (point, view) = backing(&views, path)?;
            plan.bind(
                &view.root().join(relative(path, point)?),
                SandboxPath::new(host_path(path.as_bytes()))?,
                MountAccess::Writable,
            )?;
        }
        let mut outputs = BTreeMap::new();
        for (name, output) in &spec.outputs {
            let (point, view) = backing(&views, &output.path)?;
            let mut location = OutputLocation {
                directory: File::open(view.root())?,
                relative: relative(&output.path, point)?.to_owned(),
                baseline: None,
            };
            if output.kind == OutputKind::GeneratedTree
                && let Some(directory) = location.open(output.kind, false)?
            {
                let manifest = leases
                    .get(point)
                    .context("generated output input tree missing")?
                    .manifest();
                location.baseline = Some(GeneratedBaseline::capture(
                    &directory,
                    &location.relative,
                    manifest,
                )?);
            }
            outputs.insert(name.clone(), location);
        }
        Ok(Self {
            plan,
            outputs,
            _views: views,
        })
    }
}

struct RunningChild(Child);

impl Drop for RunningChild {
    fn drop(&mut self) {
        // Reap on timeout, callback failure, or any other early return.
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

impl RunningChild {
    fn wait(
        &mut self,
        timeout: Duration,
        mut progress: impl FnMut() -> Result<()>,
    ) -> Result<ExitStatus> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            ensure!(start.elapsed() < timeout, "native execution timed out");
            progress()?;
            thread::sleep(Duration::from_millis(50).min(timeout.saturating_sub(start.elapsed())));
        }
    }
}

/// Execute one immutable declared build on a worker.
///
/// The progress callback is invoked while the process runs and may renew its
/// scheduler lease or cancel execution. It must return promptly. Output
/// capture uses opened regular files under the private backing views, not
/// paths supplied by the child. The caller controls the lifetime and quota
/// of the scratch filesystem.
///
/// # Errors
/// Returns an error for an invalid specification, incompatible platform,
/// preparation/capture error, cancellation, or timeout.
pub fn execute(
    spec: &ExecutionSpec,
    store: &NativeStore,
    policy: &ExecutionPolicy,
    progress: impl FnMut() -> Result<()>,
) -> Result<CapturedExecution> {
    spec.validate()?;
    ensure!(
        spec.platform == policy.platform,
        "native execution platform mismatch"
    );
    ensure!(
        !policy.timeout.is_zero() && policy.max_result_bytes > 0,
        "invalid execution limits"
    );
    let build = PreparedBuild::prepare(spec, store, &policy.scratch)?;
    let invocation = SandboxInvocation::from_spec(&spec.command)?;
    let stdout = tempfile::tempfile_in(&policy.scratch)?;
    let stderr = tempfile::tempfile_in(&policy.scratch)?;
    let status = RunningChild(
        build
            .plan
            .command(&policy.bubblewrap, &invocation)?
            .stdin(Stdio::null())
            .stdout(stdout.try_clone()?)
            .stderr(stderr.try_clone()?)
            .spawn()?,
    )
    .wait(policy.timeout, progress)?;
    let mut capture = Capture {
        files: BTreeMap::new(),
        remaining: policy.max_result_bytes,
    };
    let stdout = capture.diagnostic(stdout)?;
    let stderr = capture.diagnostic(stderr)?;
    let outputs = if status.success() {
        capture.outputs(&build.outputs, spec)?
    } else {
        BTreeMap::new()
    };
    Ok(CapturedExecution {
        status,
        manifest: ResultManifest {
            outputs,
            stdout,
            stderr,
        },
        files: capture.files,
    })
}

struct Capture {
    files: BTreeMap<ContentId, File>,
    remaining: u64,
}

impl Capture {
    fn diagnostic(&mut self, file: File) -> Result<Option<BlobRef>> {
        if file.metadata()?.len() == 0 {
            Ok(None)
        } else {
            self.file(file).map(Some)
        }
    }

    fn file(&mut self, mut file: File) -> Result<BlobRef> {
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "native output is not a regular file");
        let size = metadata.len();
        ensure!(size <= self.remaining, "native result byte limit exceeded");
        file.seek(SeekFrom::Start(0))?;
        let mut hash = blake3::Hasher::new();
        hash.update_reader((&mut file).take(size.checked_add(1).context("result size overflow")?))?;
        ensure!(
            file.stream_position()? == size && file.metadata()?.len() == size,
            "native output changed while hashing"
        );
        self.remaining -= size;
        let id = ContentId(*hash.finalize().as_bytes());
        self.files.entry(id).or_insert(file);
        Ok(BlobRef { id, size })
    }

    fn outputs(
        &mut self,
        locations: &BTreeMap<String, OutputLocation>,
        spec: &ExecutionSpec,
    ) -> Result<BTreeMap<String, Artifact>> {
        let mut outputs = BTreeMap::new();
        for (name, output) in &spec.outputs {
            let location = locations
                .get(name)
                .context("declared output location missing")?;
            let Some(file) = location
                .open(output.kind, output.required)
                .with_context(|| format!("open declared output {name}"))?
            else {
                continue;
            };
            let artifact = match output.kind {
                OutputKind::File => {
                    let mode = file.metadata()?.mode() & 0o777;
                    Artifact::File {
                        blob: self.file(file)?,
                        mode: Some(mode),
                    }
                }
                OutputKind::Tree | OutputKind::GeneratedTree => {
                    let tree = crate::source::capture_tree(&file, |path, file, stat| {
                        if let Some(baseline) = &location.baseline
                            && let Some(blob) = baseline.existing_file(path, stat)?
                        {
                            return Ok(blob);
                        }
                        let reference = self.file(file.try_clone()?)?;
                        crate::source::unchanged(stat, &rustix::fs::fstat(&file)?)?;
                        Ok(reference)
                    })?;
                    match output.kind {
                        OutputKind::GeneratedTree => {
                            Artifact::GeneratedTree(if let Some(baseline) = &location.baseline {
                                baseline.additions(tree)?
                            } else {
                                tree
                            })
                        }
                        _ => Artifact::Tree(tree),
                    }
                }
            };
            outputs.insert(name.clone(), artifact);
        }
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests;
