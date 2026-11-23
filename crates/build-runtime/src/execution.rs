//! Run a declared native action and retain independently readable output
//! descriptors. Each captured output is compressed and hashed once. The
//! worker uploads that representation directly, without an intermediary archive.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::{ffi::OsStrExt, fs::MetadataExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use rustix::{
    fs::{Mode, OFlags, ResolveFlags, openat2},
    io::Errno,
};

use crate::{
    Artifact, BlobRef, BuildPath, ContentId, ExecutionSpec, MountedTree, NativeStore,
    ResultManifest, TreeEntry, TreeLease, TreePath,
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
        crate::BlobReader::open(self.open_file(id)?, crate::BlobEncoding::ZstdChunks)
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
}

struct OutputLocation {
    directory: File,
    relative: PathBuf,
}

struct PreparedBuild {
    plan: SandboxPlan,
    outputs: BTreeMap<String, OutputLocation>,
    // One independently cloned view per namespace location, even when two
    // locations reference the same tree ID.
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
    leases: &BTreeMap<BuildPath, TreeLease>,
) -> Result<BTreeSet<BuildPath>> {
    let tmp = BuildPath::new(b"/tmp".to_vec())?;
    let mut writable = BTreeSet::from([tmp]);
    for output in spec.outputs.values() {
        let (mount, tree) = backing(leases, &output.path)?;
        let path = relative(&output.path, mount)?;
        let parent = path
            .parent()
            .context("output cannot replace a mount root")?;
        require_directory(tree, parent)?;
        ensure!(
            !tree
                .manifest()
                .entries
                .contains_key(&TreePath::new(path.as_os_str().as_bytes().to_vec())?),
            "declared output already exists in the immutable input: {}",
            host_path(output.path.as_bytes()).display()
        );
        writable.insert(output_parent(&output.path)?);
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
        outputs.insert(
            name.clone(),
            OutputLocation {
                directory: File::open(view.writable_path(relative(parent, point)?)?)?,
                relative: relative(&output.path, parent)?.to_owned(),
            },
        );
    }
    Ok(outputs)
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
        // Each immutable input remains encoded in CAS. Mount a read-only tree
        // and construct writable scratch only for explicitly declared output
        // parents. The mounted lease pins its backing blobs through execution.
        let mut views: BTreeMap<BuildPath, MountedTree> = leases
            .into_iter()
            .map(|(path, lease)| Ok((path, store.mount_tree(lease, scratch)?)))
            .collect::<Result<_>>()?;
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
            root.writable_path(Path::new(""))?
        } else {
            root.root()
        };
        let mut plan = SandboxPlan::new(
            root_source,
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
                    view.writable_path(Path::new(""))?
                } else {
                    view.root()
                };
                plan.bind(
                    source,
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
        scratch: policy.scratch.clone(),
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
    scratch: PathBuf,
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
        let mut physical = tempfile::tempfile_in(&self.scratch)?;
        let reference = crate::encode_native_blob(&mut file, &mut physical, Some(size))?;
        ensure!(
            reference.size == size
                && file.stream_position()? == size
                && file.metadata()?.len() == size,
            "native output changed during compression and hashing"
        );
        physical.rewind()?;
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
            let file = match openat2(
                &location.directory,
                &location.relative,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            ) {
                Ok(fd) => File::from(fd),
                Err(Errno::NOENT) if !output.required => continue,
                Err(error) => {
                    return Err(error).with_context(|| format!("open declared output {name}"));
                }
            };
            let mode = file.metadata()?.mode() & 0o777;
            let blob = self.file(file)?;
            outputs.insert(
                name.clone(),
                Artifact {
                    blob,
                    mode: Some(mode),
                },
            );
        }
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests;
