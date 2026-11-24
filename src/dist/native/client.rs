//! Native action admission, missing-input negotiation and verified delivery.
//! The compiler frontend owns discovery; this layer needs no client cache.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Take, Write},
    net::SocketAddr,
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{ExitStatus, Output},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use tempfile::NamedTempFile;

use super::{LocalExecutor, NativeCacheClient, copy_verified, retryable_transport_error};
use crate::build_runtime::{
    ActionMode, BlobRef, CapturedExecution, ExecutionSpec, PreparedTree, ResultManifest, TreeId,
    TreeManifest,
    wire::{InputDemand, NativeAdmission, NativeRunResult, NativeStatus, ScheduleReply, Ticket},
};

/// Explicit client admission and delivery bounds.
pub struct NativeBuildPolicy {
    pub mode: ActionMode,
    pub timeout: Duration,
    pub renewal_interval: Duration,
    pub max_result_bytes: u64,
}

/// Distinguish a result reuse from a new worker execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NativeBuildSource {
    Hit,
    Local,
    Worker(SocketAddr),
}

/// Native compiler response after all declared results have been delivered.
pub struct NativeBuildResult {
    pub source: NativeBuildSource,
    pub output: Output,
}

/// An input reader that can be abandoned on a direct upload, or drained
/// exactly to its frame boundary when the caller supplied it over IPC.
#[derive(Clone)]
pub(super) struct InputBlob {
    reader: Arc<Mutex<Take<Box<dyn Read + Send>>>>,
    framed: bool,
}

impl InputBlob {
    pub(super) fn new(reader: Box<dyn Read + Send>, size: u64, framed: bool) -> Self {
        Self {
            reader: Arc::new(Mutex::new(reader.take(size))),
            framed,
        }
    }

    fn discard_unread(&self) -> Result<()> {
        if self.framed {
            let mut reader = self
                .reader
                .lock()
                .map_err(|_| anyhow::anyhow!("native input reader poisoned"))?;
            io::copy(&mut *reader, &mut io::sink())?;
            ensure!(reader.limit() == 0, "truncated native IPC input frame");
        }
        Ok(())
    }
}

impl Read for InputBlob {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader
            .lock()
            .map_err(|_| io::Error::other("native input reader poisoned"))?
            .read(buffer)
    }
}

pub(super) trait InputProvider {
    fn manifest(&mut self, tree: TreeId) -> Result<TreeManifest>;
    fn open_blob(&mut self, tree: TreeId, blob: BlobRef) -> Result<Option<InputBlob>>;
}

pub(super) struct LocalInputs<'a>(BTreeMap<TreeId, &'a PreparedTree>);

impl<'a> LocalInputs<'a> {
    pub(super) fn new(spec: &ExecutionSpec, inputs: &'a [PreparedTree]) -> Result<Self> {
        let inputs = inputs
            .iter()
            .map(|tree| (tree.id(), tree))
            .collect::<BTreeMap<_, _>>();
        ensure!(
            inputs.keys().copied().collect::<BTreeSet<_>>() == spec.action_request()?.input_trees,
            "prepared native inputs differ from the action declaration"
        );
        Ok(Self(inputs))
    }

    pub(super) fn tree(&self, id: TreeId) -> Result<&PreparedTree> {
        self.0
            .get(&id)
            .copied()
            .context("scheduler requested undeclared input tree")
    }

    pub(super) fn open_source(
        &self,
        tree: TreeId,
        blob: BlobRef,
    ) -> Result<Option<Box<dyn Read + Send>>> {
        match self.tree(tree)?.open_blob(blob.id) {
            Ok(reader) => Ok(Some(reader)),
            Err(error) => {
                debug!("native origin cannot supply {blob:?}: {error:#}");
                Ok(None)
            }
        }
    }
}

impl InputProvider for LocalInputs<'_> {
    fn manifest(&mut self, tree: TreeId) -> Result<TreeManifest> {
        Ok(self.tree(tree)?.manifest().clone())
    }

    fn open_blob(&mut self, tree: TreeId, blob: BlobRef) -> Result<Option<InputBlob>> {
        Ok(self
            .open_source(tree, blob)?
            .map(|reader| InputBlob::new(reader, blob.size, false)))
    }
}

pub(super) struct Pin<'a> {
    client: &'a NativeCacheClient,
    pub(super) ticket: Ticket,
}

impl Drop for Pin<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.client.close(self.ticket) {
            debug!("native session could not be closed: {error:#}");
        }
    }
}

/// An action is either ready for verified delivery under a live result
/// lease, or returned compiler failure diagnostics without a cache entry.
pub(super) enum Outcome<'a> {
    Ready {
        delivery: Delivery<'a>,
        source: NativeBuildSource,
        manifest: ResultManifest,
    },
    Failed {
        source: NativeBuildSource,
        failure: NativeRunResult,
    },
}

type BlobDownload<'a> = dyn FnMut(BlobRef, &mut dyn Write) -> Result<()> + 'a;

pub(super) enum Delivery<'a> {
    Scheduler(Pin<'a>),
    Local(Box<CapturedExecution>),
}

impl Delivery<'_> {
    pub(super) fn with_download<T>(
        &self,
        renewal_interval: Duration,
        operation: impl FnOnce(&mut BlobDownload<'_>) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Scheduler(pin) => {
                pin.client
                    .with_renewal(pin.ticket, renewal_interval, |check| {
                        let result = operation(&mut |blob, output| {
                            check()?;
                            pin.client.download(pin.ticket, blob, output)
                        })?;
                        check()?;
                        Ok(result)
                    })
            }
            Self::Local(captured) => operation(&mut |blob, output| {
                copy_verified(captured.open_blob(blob.id)?, blob, output)
            }),
        }
    }
}

impl NativeCacheClient {
    /// Admit an exact native action, supply only absent inputs, and execute
    /// in the configured exact sandbox when needed. Remote results are read
    /// from the scheduler; local results use captured descriptors directly.
    /// No result is repackaged into the legacy cache.
    ///
    /// # Errors
    /// Returns an error for incomplete inputs, invalid destinations, admission,
    /// scheduling, transfer or output installation failures.
    pub fn run_action(
        &self,
        spec: &ExecutionSpec,
        inputs: &[PreparedTree],
        destinations: &BTreeMap<String, PathBuf>,
        policy: &NativeBuildPolicy,
        local: Option<&LocalExecutor>,
    ) -> Result<NativeBuildResult> {
        let mut inputs = LocalInputs::new(spec, inputs)?;
        let destinations = verify_destinations(spec, destinations)?;
        match self.acquire_action(spec, &mut inputs, policy, local)? {
            Outcome::Ready {
                delivery,
                source,
                manifest,
            } => {
                let staged = delivery.with_download(policy.renewal_interval, |download| {
                    fetch_result(
                        spec,
                        &manifest,
                        &destinations,
                        policy.max_result_bytes,
                        download,
                    )
                })?;
                let output = staged.install()?;
                Ok(NativeBuildResult { source, output })
            }
            Outcome::Failed { source, failure } => Ok(NativeBuildResult {
                source,
                output: failed_output(failure)?,
            }),
        }
    }

    pub(super) fn acquire_action(
        &self,
        spec: &ExecutionSpec,
        inputs: &mut impl InputProvider,
        policy: &NativeBuildPolicy,
        local: Option<&LocalExecutor>,
    ) -> Result<Outcome<'_>> {
        validate_policy(policy)?;
        let request = spec.action_request()?;
        let start = Instant::now();
        let mut declared = BTreeMap::new();

        loop {
            ensure!(
                start.elapsed() < policy.timeout,
                "native admission timed out"
            );
            match self.admit(spec, policy.mode, &declared)? {
                NativeAdmission::Hit { ticket, manifest } => {
                    let pin = Pin {
                        client: self,
                        ticket,
                    };
                    return Ok(Outcome::Ready {
                        delivery: Delivery::Scheduler(pin),
                        source: NativeBuildSource::Hit,
                        manifest,
                    });
                }
                NativeAdmission::InFlight => {
                    // No speculative duplicate compilation.
                    thread::sleep(
                        Duration::from_millis(50)
                            .min(policy.timeout.saturating_sub(start.elapsed())),
                    );
                }
                NativeAdmission::MissingInputs { trees } => {
                    ensure!(!trees.is_empty(), "empty native missing-input response");
                    for id in trees {
                        ensure!(
                            start.elapsed() < policy.timeout,
                            "native input preparation timed out"
                        );
                        ensure!(
                            request.input_trees.contains(&id),
                            "scheduler requested undeclared input tree"
                        );
                        let manifest = inputs.manifest(id)?;
                        ensure!(manifest.id()? == id, "input provider supplied wrong tree");
                        ensure!(
                            declared.insert(id, manifest).is_none(),
                            "scheduler did not accept declared input"
                        );
                    }
                }
                NativeAdmission::Compile { ticket } => {
                    let pin = Pin {
                        client: self,
                        ticket,
                    };
                    return self.run_admitted(pin, spec, inputs, policy, start, local);
                }
            }
        }
    }

    fn run_admitted<'a>(
        &self,
        pin: Pin<'a>,
        spec: &ExecutionSpec,
        inputs: &mut impl InputProvider,
        policy: &NativeBuildPolicy,
        start: Instant,
        local: Option<&LocalExecutor>,
    ) -> Result<Outcome<'a>> {
        if let Some(local) = local.filter(|executor| executor.prefers_local()) {
            return self.run_local(pin, spec, inputs, policy, start, local);
        }
        let allocation = match self.schedule(pin.ticket, spec.clone())? {
            ScheduleReply::Assigned(allocation) => allocation,
            ScheduleReply::Unavailable { message } => {
                if let Some(local) = local {
                    return self.run_local(pin, spec, inputs, policy, start, local);
                }
                bail!("native worker unavailable: {message}");
            }
        };
        let source = NativeBuildSource::Worker(allocation.address);
        let request = spec.action_request()?;
        let remaining = policy.timeout.saturating_sub(start.elapsed());
        // Keep the origin connection live while the worker acquires inputs.
        // Only the worker RPC needs a separate thread; the original provider
        // (including the namespace stream) remains owned by this thread.
        let result = thread::scope(|scope| {
            let worker =
                scope.spawn(|| Self::run_worker(&allocation, remaining, policy.max_result_bytes));
            let supply = (|| -> Result<()> {
                let mut idle = Duration::from_millis(10);
                while !worker.is_finished() {
                    ensure!(
                        start.elapsed() < policy.timeout,
                        "native worker deadline exceeded"
                    );
                    let demands = match self.input_demands(pin.ticket) {
                        Ok(demands) => demands,
                        Err(error) if retryable_transport_error(&error) => {
                            debug!("retrying native input demand poll: {error:#}");
                            thread::sleep(idle);
                            idle = (idle * 2).min(Duration::from_millis(200));
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    if demands.is_empty() {
                        thread::sleep(idle);
                        idle = (idle * 2).min(Duration::from_millis(200));
                        continue;
                    }
                    idle = Duration::from_millis(10);
                    for demand in demands {
                        ensure!(
                            request.input_trees.contains(&demand.tree),
                            "scheduler requested undeclared tree"
                        );
                        self.supply_demand(pin.ticket, demand, inputs, start, policy)?;
                    }
                    // A nonempty batch is followed immediately by another poll.
                }
                Ok(())
            })();
            // A worker may become ready through a concurrent provider while
            // its previous origin request is still in transit. Preserve an
            // already terminal result instead of cancelling it.
            let terminal = supply.is_err()
                && (worker.is_finished()
                    || matches!(
                        self.status(pin.ticket),
                        Ok(NativeStatus::Ready(_) | NativeStatus::Failed)
                    ));
            if supply.is_err() && !terminal {
                let _ = self.close(pin.ticket);
            }
            let result = worker
                .join()
                .map_err(|_| anyhow::anyhow!("native worker request panicked"))?;
            if !terminal {
                supply?;
            }
            result
        })?;
        match result {
            NativeRunResult::Stored => {
                let NativeStatus::Ready(manifest) = self.status(pin.ticket)? else {
                    bail!("native worker did not publish its result");
                };
                Ok(Outcome::Ready {
                    delivery: Delivery::Scheduler(pin),
                    source,
                    manifest,
                })
            }
            failure @ NativeRunResult::Failed { .. } => Ok(Outcome::Failed { source, failure }),
            NativeRunResult::JobNotFound => bail!("native worker lost its assigned job"),
        }
    }
    fn supply_demand(
        &self,
        ticket: Ticket,
        demand: InputDemand,
        inputs: &mut impl InputProvider,
        start: Instant,
        policy: &NativeBuildPolicy,
    ) -> Result<()> {
        if let Some(reader) = inputs.open_blob(demand.tree, demand.blob)? {
            match self.backfill_input(ticket, demand.blob, reader.clone()) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    // An interrupted HTTP request may have consumed only a
                    // prefix of the IPC frame. Realign before another demand.
                    reader.discard_unread()?;
                    let status = error
                        .downcast_ref::<reqwest::Error>()
                        .and_then(reqwest::Error::status);
                    if retryable_transport_error(&error)
                        || status == Some(reqwest::StatusCode::CONFLICT)
                    {
                        debug!("retrying native input upload after polling: {error:#}");
                        thread::sleep(Duration::from_millis(50));
                        return Ok(());
                    }
                    if status != Some(reqwest::StatusCode::UNPROCESSABLE_ENTITY) {
                        return Err(error);
                    }
                    // Only a verified content mismatch makes this locator
                    // unsuitable; ordinary I/O and claim failures are retried.
                    debug!("native input upload rejected: {error:#}");
                }
            }
        }
        loop {
            ensure!(
                start.elapsed() < policy.timeout,
                "native source decline deadline exceeded"
            );
            match self.input_unavailable(ticket, demand) {
                Ok(()) => return Ok(()),
                Err(error) if retryable_transport_error(&error) => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn run_local<'a>(
        &self,
        pin: Pin<'a>,
        spec: &ExecutionSpec,
        inputs: &mut impl InputProvider,
        policy: &NativeBuildPolicy,
        start: Instant,
        local: &LocalExecutor,
    ) -> Result<Outcome<'a>> {
        let captured = local.execute(self, pin.ticket, spec, inputs, policy, start)?;
        drop(pin);
        let source = NativeBuildSource::Local;
        if let Some(manifest) = captured.successful_result() {
            Ok(Outcome::Ready {
                manifest: manifest.clone(),
                source,
                delivery: Delivery::Local(Box::new(captured)),
            })
        } else {
            Ok(Outcome::Failed {
                source,
                failure: captured.failure_result()?,
            })
        }
    }
}

pub(super) fn validate_policy(policy: &NativeBuildPolicy) -> Result<()> {
    ensure!(
        !policy.timeout.is_zero()
            && !policy.renewal_interval.is_zero()
            && policy.max_result_bytes > 0
            && policy.max_result_bytes < u64::MAX,
        "invalid native client bounds"
    );
    Ok(())
}

pub(super) fn failed_output(failure: NativeRunResult) -> Result<Output> {
    let NativeRunResult::Failed {
        code,
        signal,
        stdout,
        stderr,
    } = failure
    else {
        bail!("expected native compiler failure");
    };
    let status = match (code, signal) {
        (Some(code @ 1..=255), None) => crate::util::exit_status_from_code(code),
        (None, Some(signal @ 1..=64)) => ExitStatus::from_raw(signal),
        _ => bail!("invalid native compiler exit status"),
    };
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

pub(super) fn validate_manifest(
    spec: &ExecutionSpec,
    manifest: &ResultManifest,
    max_result_bytes: u64,
) -> Result<()> {
    spec.action_request()?.validate_result(manifest)?;
    let total = manifest.blobs()?.values().try_fold(0_u64, |total, &size| {
        total
            .checked_add(size)
            .context("native result length overflow")
    })?;
    ensure!(
        total <= max_result_bytes,
        "native result exceeds client limits"
    );
    Ok(())
}

/// Result installation is shared by direct HTTP and namespace callers.
/// All content is verified before any destination is exposed.
pub(super) fn fetch_result(
    spec: &ExecutionSpec,
    manifest: &ResultManifest,
    destinations: &BTreeMap<String, PathBuf>,
    max_result_bytes: u64,
    mut download: impl FnMut(BlobRef, &mut dyn Write) -> Result<()>,
) -> Result<StagedResult> {
    validate_manifest(spec, manifest, max_result_bytes)?;
    let mut diagnostic = |blob: Option<BlobRef>| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        if let Some(blob) = blob {
            download(blob, &mut bytes)?;
        }
        Ok(bytes)
    };
    let stdout = diagnostic(manifest.stdout)?;
    let stderr = diagnostic(manifest.stderr)?;
    let mut staged = Vec::new();
    for (name, artifact) in &manifest.outputs {
        let path = destinations.get(name).context("unexpected native output")?;
        let parent = path.parent().context("native output has no parent")?;
        let mut temp = NamedTempFile::new_in(parent)?;
        download(artifact.blob, &mut temp)?;
        if let Some(mode) = artifact.mode {
            temp.as_file()
                .set_permissions(fs::Permissions::from_mode(mode))?;
        }
        staged.push((temp, path.clone()));
    }
    Ok(StagedResult {
        stdout,
        stderr,
        files: staged,
    })
}

pub(super) struct StagedResult {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    files: Vec<(NamedTempFile, PathBuf)>,
}

impl StagedResult {
    pub(super) fn install(self) -> Result<Output> {
        // File-wise atomic publication, not an atomic multi-file rename.
        for (temp, path) in self.files {
            temp.persist(path)?;
        }
        Ok(Output {
            status: crate::util::exit_status_from_code(0),
            stdout: self.stdout,
            stderr: self.stderr,
        })
    }
}

pub(super) fn verify_destinations(
    spec: &ExecutionSpec,
    destinations: &BTreeMap<String, PathBuf>,
) -> Result<BTreeMap<String, PathBuf>> {
    ensure!(
        destinations.keys().eq(spec.outputs.keys()),
        "native output destination contract differs"
    );
    let mut seen = BTreeSet::new();
    let mut verified = BTreeMap::new();
    for (name, path) in destinations {
        ensure!(
            path.is_absolute() && path != Path::new("/dev/null"),
            "invalid native output destination"
        );
        let parent = path
            .parent()
            .context("output parent missing")?
            .canonicalize()?;
        let filename = path.file_name().context("output file name missing")?;
        let path = parent.join(filename);
        ensure!(
            seen.insert(path.clone()),
            "multiple native outputs select the same destination"
        );
        verified.insert(name.clone(), path);
    }
    Ok(verified)
}

#[cfg(test)]
mod input_blob_tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn aborted_framed_input_drains_exactly_the_remaining_payload() -> Result<()> {
        let source = InputBlob::new(Box::new(Cursor::new(b"firstnext")), 5, true);
        let mut uploader = source.clone();
        let mut prefix = [0; 2];
        uploader.read_exact(&mut prefix)?;
        assert_eq!(&prefix, b"fi");
        source.discard_unread()?;
        assert_eq!(uploader.read(&mut prefix)?, 0);
        let mut reader = source.reader.lock().unwrap();
        let mut next = Vec::new();
        reader.get_mut().read_to_end(&mut next)?;
        assert_eq!(next, b"next");
        Ok(())
    }
}
