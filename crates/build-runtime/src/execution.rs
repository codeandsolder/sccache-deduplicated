//! Run a declared native action and retain independently readable output
//! descriptors. The worker uploads the captured bytes directly; no result
//! archive, local CAS publication, or intermediary copy is required.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::{self, File},
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
    fs::{Mode, OFlags, ResolveFlags, openat2},
    io::Errno,
};
use tempfile::TempDir;

use crate::{
    Artifact, BlobRef, ContentId, ExecutionSpec, MaterializedTree, NativeStore, ResultManifest,
    TreeEntry, TreePath,
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

struct PreparedBuild {
    plan: SandboxPlan,
    outputs: TempDir,
    // Keep all private input materializations alive until the process exits.
    _trees: BTreeMap<crate::TreeId, MaterializedTree>,
}

impl PreparedBuild {
    fn prepare(spec: &ExecutionSpec, store: &NativeStore, scratch: &Path) -> Result<Self> {
        let request = spec.action_request()?;
        let root = store
            .lookup_tree(spec.root)?
            .context("native root unavailable")?;
        // Mount destinations are declared real directories in the immutable
        // root; never resolve an untrusted symlink on the host.
        for path in spec.mounts.keys().map(crate::BuildPath::as_bytes).chain([
            b"/out".as_slice(),
            b"/tmp",
            b"/proc",
            b"/dev",
        ]) {
            let relative = TreePath::new(path[1..].to_vec())?;
            ensure!(
                matches!(
                    root.manifest().entries.get(&relative),
                    Some(TreeEntry::Directory(_))
                ),
                "native mount destination is not a declared directory"
            );
        }
        let mut trees = BTreeMap::new();
        for id in request.input_trees {
            let lease = store
                .lookup_tree(id)?
                .context("native input tree unavailable")?;
            trees.insert(id, lease.materialize(scratch)?);
        }
        let root_view = trees.get(&spec.root).context("materialized root missing")?;
        let mut plan = SandboxPlan::new(root_view.root(), MountAccess::ReadOnly)?;
        for (path, tree) in &spec.mounts {
            let view = trees.get(tree).context("materialized input missing")?;
            plan.bind(
                view.root(),
                SandboxPath::new(Path::new(OsStr::from_bytes(path.as_bytes())))?,
                MountAccess::ReadOnly,
            )?;
        }
        let outputs = tempfile::Builder::new()
            .prefix("native-outputs-")
            .tempdir_in(scratch)?;
        for declared in spec.outputs.values() {
            let path = outputs
                .path()
                .join(OsStr::from_bytes(declared.path.as_bytes()));
            fs::create_dir_all(path.parent().context("output parent missing")?)?;
        }
        plan.bind(
            outputs.path(),
            SandboxPath::new(Path::new("/out"))?,
            MountAccess::Writable,
        )?;
        plan.tmpfs(SandboxPath::new(Path::new("/tmp"))?)?;
        Ok(Self {
            plan,
            outputs,
            _trees: trees,
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
/// capture uses opened regular files under the private output directory, not
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
        directory: &TempDir,
        spec: &ExecutionSpec,
    ) -> Result<BTreeMap<String, Artifact>> {
        let root = File::open(directory.path())?;
        let mut outputs = BTreeMap::new();
        for (name, output) in &spec.outputs {
            let file = match openat2(
                &root,
                Path::new(OsStr::from_bytes(output.path.as_bytes())),
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
