//! Run a declared native action and retain independently readable output
//! descriptors. Captured outputs are hashed once and stored in the worker's
//! selected physical format: plain on ZFS, indexed Zstd elsewhere. Transfers
//! may encode the plain ZFS bytes temporarily to save network bandwidth.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::{ffi::OsStrExt, fs::MetadataExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, ExitStatus, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use rustix::{
    event::{PollFd, PollFlags, poll},
    fs::{Mode, OFlags, ResolveFlags, Stat, openat2},
    io::Errno,
    process::{Pid, PidfdFlags, pidfd_open},
    time::Timespec,
};

use crate::{
    Artifact, BlobEncoding, BlobRef, BuildPath, ContentId, ExecutionSpec, MountedTree, NativeStore,
    OutputKind, ResultManifest, StageBudget, StagedBlob, TreeEntry, TreeId, TreeLease,
    TreeManifest, TreePath,
    sandbox::{MountAccess, SandboxInvocation, SandboxPath, SandboxPlan},
    store::CapturedStage,
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
    timings: ExecutionTimings,
    manifest: ResultManifest,
    files: BTreeMap<ContentId, Arc<File>>,
    staged: BTreeMap<ContentId, CapturedStage>,
    encoding: BlobEncoding,
}

/// Wall-clock phase durations of a native action. Process time includes
/// namespace setup and child execution; it is not pure compiler CPU time.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecutionTimings {
    pub preparation: Duration,
    pub process: Duration,
    pub capture: Duration,
}

impl CapturedExecution {
    #[must_use]
    pub const fn timings(&self) -> ExecutionTimings {
        self.timings
    }

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

    /// Return failure diagnostics for transport without publishing a cache hit.
    /// # Errors
    /// Returns an error for a successful execution or a diagnostic read failure.
    pub fn failure_result(&self) -> Result<crate::wire::NativeRunResult> {
        ensure!(!self.status.success(), "expected failed execution");
        let diagnostic = |reference: Option<BlobRef>| -> Result<Vec<u8>> {
            let mut bytes = Vec::new();
            if let Some(reference) = reference {
                self.open_blob(reference.id)?.read_to_end(&mut bytes)?;
                ensure!(
                    u64::try_from(bytes.len())? == reference.size,
                    "failed diagnostic length mismatch"
                );
            }
            Ok(bytes)
        };
        Ok(crate::wire::NativeRunResult::Failed {
            code: self.status.code(),
            signal: self.status.signal(),
            stdout: diagnostic(self.manifest.stdout)?,
            stderr: diagnostic(self.manifest.stderr)?,
        })
    }

    /// Open a fresh independent stream of captured content.
    ///
    /// # Errors
    /// Returns an error for an undeclared blob or descriptor failure.
    pub fn open_blob(&self, id: ContentId) -> Result<impl Read + Send + 'static> {
        crate::BlobReader::open(self.open_file(id)?, self.encoding)
    }

    #[must_use = "result transport must advertise the physical encoding actually captured"]
    pub const fn physical_encoding(&self) -> BlobEncoding {
        self.encoding
    }

    /// Open the immutable physical CAS representation without decoding it,
    /// suitable for verified scheduler upload without another compression.
    ///
    /// # Errors
    /// Returns an error for undeclared content or descriptor failure.
    pub fn open_file(&self, id: ContentId) -> Result<File> {
        let mut file = self
            .files
            .get(&id)
            .context("uncaptured result blob")?
            .try_clone()?;
        file.rewind()?;
        Ok(file)
    }

    /// Return the original captured inodes required for local publication,
    /// syncing them on the asynchronous disk executor when available.
    /// Already resident outputs need no writeback.
    ///
    /// # Errors
    /// Returns an error if a requested capture is missing or cannot be synced.
    pub async fn seal_staged(&mut self, missing: &[BlobRef]) -> Result<Vec<StagedBlob>> {
        let mut pending = std::mem::take(&mut self.staged);
        let selected = missing
            .iter()
            .map(|blob| {
                let stage = pending
                    .remove(&blob.id)
                    .context("missing staged compiler output")?;
                ensure!(
                    stage.reference() == *blob,
                    "staged compiler output length mismatch"
                );
                Ok(stage)
            })
            .collect::<Result<Vec<_>>>()?;
        drop(pending);
        let mut selected = selected.into_iter();
        let mut active = tokio::task::JoinSet::new();
        // Keep per-result fanout bounded; the disk executor separately
        // controls global in-flight operations across all publishers.
        for stage in selected.by_ref().take(32) {
            active.spawn(stage.seal());
        }
        let mut sealed = Vec::with_capacity(missing.len());
        while let Some(stage) = active.join_next().await {
            sealed.push(stage??);
            if let Some(stage) = selected.next() {
                active.spawn(stage.seal());
            }
        }
        Ok(sealed)
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
    _views: BTreeMap<BuildPath, MountedTree>,
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
    leases: &BTreeMap<BuildPath, Arc<TreeLease>>,
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

fn capture_locations(
    spec: &ExecutionSpec,
    views: &BTreeMap<BuildPath, MountedTree>,
    writable: &BTreeSet<BuildPath>,
) -> Result<BTreeMap<String, OutputLocation>> {
    let mut outputs = BTreeMap::new();
    for (name, output) in &spec.outputs {
        // Capture from the *writable bind's* backing directory, not the
        // underlying immutable FUSE tree hidden by that bind.
        let parent = writable
            .iter()
            .filter(|path| output.path.within(path.as_bytes()))
            .max_by_key(|path| path.as_bytes().len())
            .context("output is not in a declared writable mount")?;
        let (point, view) = backing(views, parent)?;
        let mut location = OutputLocation {
            directory: File::open(view.writable_path(relative(parent, point)?)?)?,
            relative: relative(&output.path, parent)?.to_owned(),
            baseline: None,
        };
        if output.kind == OutputKind::GeneratedTree
            && let Some(directory) = location.open(output.kind, false)?
        {
            location.baseline = Some(GeneratedBaseline::capture(
                &directory,
                relative(&output.path, point)?,
                view.manifest(),
            )?);
        }
        outputs.insert(name.clone(), location);
    }
    Ok(outputs)
}

/// Mount every declared backing input, permitting target-file overlays only
/// where no writable directory or more-specific immutable mount can hide it.
fn mount_input_views(
    spec: &ExecutionSpec,
    store: &NativeStore,
    scratch: &Path,
    leases: BTreeMap<BuildPath, Arc<TreeLease>>,
    writable: &BTreeSet<BuildPath>,
) -> Result<BTreeMap<BuildPath, MountedTree>> {
    let protected_system = [
        BuildPath::new(b"/proc".to_vec())?,
        BuildPath::new(b"/dev".to_vec())?,
    ];
    let views: BTreeMap<BuildPath, MountedTree> = leases
        .into_iter()
        .map(|(point, lease)| {
            // A private output mount or nested explicit input mount
            // shadows its backing root. Do not insert file overlays
            // within those regions or split an inode group there.
            let protected = writable
                .iter()
                .filter(|path| path.within(point.as_bytes()))
                .chain(
                    spec.mounts
                        .keys()
                        .filter(|path| **path != point && path.within(point.as_bytes())),
                )
                .chain(
                    protected_system
                        .iter()
                        .filter(|path| path.within(point.as_bytes())),
                )
                .map(|path| relative(path, &point).map(Path::to_owned))
                .collect::<Result<Vec<_>>>()?;
            Ok((
                point,
                store.mount_tree_protected(lease, scratch, &protected)?,
            ))
        })
        .collect::<Result<_>>()?;
    Ok(views)
}

/// Bind target-specific immutable regular files after the larger input
/// mounts. The immutable base and exact target content stay pinned by views.
fn bind_file_overlays(
    plan: &mut SandboxPlan,
    views: &BTreeMap<BuildPath, MountedTree>,
) -> Result<()> {
    for (point, view) in views {
        if let Some(stats) = view.overlay_stats() {
            log::debug!(
                "native CAS action mount {} reused base with {} block clones and {} bytes copied",
                host_path(point.as_bytes()).display(),
                stats.cloned_files,
                stats.copied_bytes,
            );
        }
        for (path, physical) in view.overlay_bindings() {
            let destination = host_path(point.as_bytes()).join(OsStr::from_bytes(path.as_bytes()));
            plan.bind(
                physical,
                SandboxPath::new(&destination)?,
                MountAccess::ReadOnly,
            )?;
        }
    }
    Ok(())
}

impl PreparedBuild {
    fn prepare(
        spec: &ExecutionSpec,
        store: &NativeStore,
        scratch: &Path,
        inputs: &[Arc<TreeLease>],
    ) -> Result<Self> {
        let inputs = admitted_inputs(spec, store, inputs)?;
        let root_point = BuildPath::new(b"/".to_vec())?;
        let mut leases: BTreeMap<BuildPath, Arc<TreeLease>> = spec
            .mounts
            .iter()
            .map(|(path, id)| {
                Ok((
                    path.clone(),
                    Arc::clone(inputs.get(id).context("native input tree unavailable")?),
                ))
            })
            .collect::<Result<_>>()?;
        leases.insert(
            root_point.clone(),
            store.resident_recipe(&spec.root, &inputs)?,
        );
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
        // Reuse immutable native-ZFS CoW tree views (or compressed FUSE
        // mounts on non-ZFS). Only output parents need private scratch.
        let mut views = mount_input_views(spec, store, scratch, leases, &writable)?;
        for path in &writable {
            let (point, _) = backing(&views, path)?;
            let point = point.clone();
            let relative = relative(path, &point)?.to_owned();
            views
                .get_mut(&point)
                .context("native input view missing")?
                .mark_writable(&relative)?;
        }
        let root = views.get(&root_point).context("native root view missing")?;
        let root_writable = writable.contains(&root_point);
        let root_source = if root_writable {
            root.writable_path(Path::new(""))?.to_owned()
        } else {
            root.root().to_owned()
        };
        let mut plan = SandboxPlan::new(
            &root_source,
            if root_writable {
                MountAccess::Writable
            } else {
                MountAccess::ReadOnly
            },
        )?;
        for (path, view) in &views {
            if path != &root_point {
                let is_writable = writable.contains(path);
                let source = if is_writable {
                    view.writable_path(Path::new(""))?.to_owned()
                } else {
                    view.root().to_owned()
                };
                plan.bind(
                    &source,
                    SandboxPath::new(host_path(path.as_bytes()))?,
                    if is_writable {
                        MountAccess::Writable
                    } else {
                        MountAccess::ReadOnly
                    },
                )?;
            }
        }
        for path in &writable {
            // A writable view root is bound above; nested paths override the
            // immutable source with a private writable directory.
            if views.contains_key(path) {
                continue;
            }
            let (point, view) = backing(&views, path)?;
            plan.bind(
                view.writable_path(relative(path, point)?)?,
                SandboxPath::new(host_path(path.as_bytes()))?,
                MountAccess::Writable,
            )?;
        }
        bind_file_overlays(&mut plan, &views)?;
        let outputs = capture_locations(spec, &views, &writable)?;
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
        // The unreaped child PID cannot be recycled. pidfd readiness wakes
        // immediately on exit instead of occupying a compiler slot for the
        // remainder of a 50 ms polling interval.
        let pidfd = pidfd_open(Pid::from_child(&self.0), PidfdFlags::empty())?;
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            ensure!(start.elapsed() < timeout, "native execution timed out");
            progress()?;
            let remaining = timeout.saturating_sub(start.elapsed());
            ensure!(!remaining.is_zero(), "native execution timed out");
            let interval = Timespec::try_from(remaining.min(Duration::from_millis(50)))?;
            let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
            match poll(&mut fds, Some(&interval)) {
                Ok(_) | Err(Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn admitted_inputs(
    spec: &ExecutionSpec,
    store: &NativeStore,
    inputs: &[Arc<TreeLease>],
) -> Result<BTreeMap<TreeId, Arc<TreeLease>>> {
    let required: BTreeSet<_> = spec
        .root
        .recipe
        .layers
        .iter()
        .map(|layer| layer.tree)
        .chain(spec.mounts.values().copied())
        .collect();
    let mut admitted = BTreeMap::new();
    for lease in inputs {
        ensure!(
            lease.belongs_to(store) && lease.is_indexed(),
            "native input lease is not an indexed tree from this store"
        );
        ensure!(
            required.contains(&lease.id()),
            "unexpected native input lease"
        );
        admitted
            .entry(lease.id())
            .or_insert_with(|| Arc::clone(lease));
    }
    ensure!(
        admitted.len() == required.len(),
        "native input closure incomplete"
    );
    Ok(admitted)
}

/// Acquire all declared input leases for direct execution. Distributed
/// workers pass their already admitted leases to execution instead.
/// # Errors
/// Returns an error for an invalid specification or missing input tree.
pub fn acquire_execution_inputs(
    spec: &ExecutionSpec,
    store: &NativeStore,
) -> Result<Vec<Arc<TreeLease>>> {
    spec.action_request()?
        .input_trees
        .into_iter()
        .map(|id| {
            store
                .lookup_resident_tree(id)?
                .context("native input tree unavailable")
        })
        .collect()
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
    inputs: &[Arc<TreeLease>],
    budget: Option<StageBudget>,
    mut progress: impl FnMut() -> Result<()>,
) -> Result<CapturedExecution> {
    spec.validate()?;
    ensure!(
        budget
            .as_ref()
            .is_none_or(|budget| budget.belongs_to(store)),
        "capture budget belongs to another store"
    );
    ensure!(
        spec.platform == policy.platform,
        "native execution platform mismatch"
    );
    ensure!(
        !policy.timeout.is_zero() && policy.max_result_bytes > 0,
        "invalid execution limits"
    );
    let started = Instant::now();
    progress()?;
    let build = PreparedBuild::prepare(spec, store, &policy.scratch, inputs)?;
    let invocation = SandboxInvocation::from_spec(&spec.command)?;
    let stdout = tempfile::tempfile_in(&policy.scratch)?;
    let stderr = tempfile::tempfile_in(&policy.scratch)?;
    progress()?;
    let preparation = started.elapsed();
    ensure!(
        preparation < policy.timeout,
        "native execution preparation timed out"
    );
    let running = Instant::now();
    let mut child = RunningChild(
        build
            .plan
            .command(&policy.bubblewrap, &invocation)?
            .stdin(Stdio::null())
            .stdout(stdout.try_clone()?)
            .stderr(stderr.try_clone()?)
            .spawn()?,
    );
    let status = child.wait(
        policy.timeout.saturating_sub(started.elapsed()),
        &mut progress,
    )?;
    let process = running.elapsed();
    progress()?;
    let mut capture = Capture {
        files: BTreeMap::new(),
        staged: BTreeMap::new(),
        budget,
        remaining: policy.max_result_bytes,
        scratch: policy.scratch.clone(),
        encoding: store.physical_encoding(),
    };
    let stdout = capture.diagnostic(stdout)?;
    let stderr = capture.diagnostic(stderr)?;
    let outputs = if status.success() {
        capture.outputs(&build.outputs, spec)?
    } else {
        BTreeMap::new()
    };
    let timings = ExecutionTimings {
        preparation,
        process,
        capture: running.elapsed().saturating_sub(process),
    };
    log::debug!(
        "native execution phases: preparation={:?} process={:?} capture={:?}",
        timings.preparation,
        timings.process,
        timings.capture
    );
    Ok(CapturedExecution {
        status,
        timings,
        manifest: ResultManifest {
            outputs,
            stdout,
            stderr,
        },
        files: capture.files,
        staged: capture.staged,
        encoding: store.physical_encoding(),
    })
}

struct Capture {
    files: BTreeMap<ContentId, Arc<File>>,
    staged: BTreeMap<ContentId, CapturedStage>,
    budget: Option<StageBudget>,
    remaining: u64,
    scratch: PathBuf,
    encoding: BlobEncoding,
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
        let (reference, physical) = if let Some(budget) = &mut self.budget {
            let stage = budget.stage_capture(size, &mut file)?;
            let reference = stage.reference();
            let physical = stage.file();
            self.staged.entry(reference.id).or_insert(stage);
            (reference, physical)
        } else {
            let mut physical = tempfile::tempfile_in(&self.scratch)?;
            let reference = match self.encoding {
                BlobEncoding::Raw => {
                    crate::encode_native_raw_blob(&mut file, &mut physical, Some(size))?
                }
                BlobEncoding::ZstdChunks => {
                    crate::encode_native_blob(&mut file, &mut physical, Some(size))?
                }
            };
            physical.rewind()?;
            (reference, Arc::new(physical))
        };
        ensure!(
            reference.size == size
                && file.stream_position()? == size
                && file.metadata()?.len() == size,
            "native output changed during compression and hashing"
        );
        self.remaining -= size;
        self.files.entry(reference.id).or_insert(physical);
        Ok(reference)
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
