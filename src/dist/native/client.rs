//! Native action admission, missing-input negotiation and verified delivery.
//! The compiler frontend owns discovery; this layer needs no client cache.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::SocketAddr,
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{ExitStatus, Output},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use tempfile::NamedTempFile;

use super::{LocalExecutor, NativeCacheClient, copy_verified, renewal::Renewals};
use crate::build_runtime::{
    ActionMode, BlobRef, CapturedExecution, ExecutionSpec, PreparedTree, ResultManifest, TreeId,
    TreeLease, TreeManifest,
    wire::{NativeAdmission, NativeRunResult, NativeStatus, ScheduleReply, Ticket},
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

pub(super) trait InputProvider {
    fn manifest(&mut self, tree: TreeId) -> Result<TreeManifest>;
    fn open_blob(&mut self, tree: TreeId, blob: BlobRef) -> Result<Box<dyn Read + Send>>;
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
}

impl InputProvider for LocalInputs<'_> {
    fn manifest(&mut self, tree: TreeId) -> Result<TreeManifest> {
        Ok(self.tree(tree)?.manifest().clone())
    }

    fn open_blob(&mut self, tree: TreeId, blob: BlobRef) -> Result<Box<dyn Read + Send>> {
        self.tree(tree)?.open_blob(blob.id)
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
        let mut pins: BTreeMap<TreeId, Pin<'_>> = BTreeMap::new();
        let mut local_pins: BTreeMap<TreeId, TreeLease> = BTreeMap::new();
        let renewals = Renewals::start(self.clone(), policy.renewal_interval)?;

        loop {
            renewals.check()?;
            ensure!(
                start.elapsed() < policy.timeout,
                "native admission timed out"
            );
            match self.admit(spec, policy.mode)? {
                NativeAdmission::Hit { ticket, manifest } => {
                    let pin = Pin {
                        client: self,
                        ticket,
                    };
                    renewals.finish()?;
                    drop(pins);
                    return Ok(Outcome::Ready {
                        delivery: Delivery::Scheduler(pin),
                        source: NativeBuildSource::Hit,
                        manifest,
                    });
                }
                NativeAdmission::InFlight => {
                    // No speculative duplicate compilation. Input pins are
                    // not needed while another admitted action owns its closure.
                    renewals.clear()?;
                    pins.clear();
                    local_pins.clear();
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
                        if let Some(pin) = pins.remove(&id) {
                            renewals.remove(pin.ticket)?;
                            drop(pin);
                        }
                        let ticket = if let Some(local) =
                            local.filter(|executor| executor.prefers_local())
                        {
                            let tree = match local_pins.entry(id) {
                                std::collections::btree_map::Entry::Occupied(entry) => {
                                    entry.into_mut()
                                }
                                std::collections::btree_map::Entry::Vacant(entry) => entry.insert(
                                    local.prepare_input(id, inputs, &mut || renewals.check())?,
                                ),
                            };
                            self.push_tree(
                                tree.manifest(),
                                |content| tree.open_file(content),
                                policy.renewal_interval,
                            )?
                        } else {
                            let manifest = inputs.manifest(id)?;
                            ensure!(manifest.id()? == id, "input provider supplied wrong tree");
                            let blobs = manifest.blobs()?;
                            self.push_tree(
                                &manifest,
                                |content| {
                                    let size =
                                        *blobs.get(&content).context("undeclared content")?;
                                    inputs.open_blob(id, BlobRef { id: content, size })
                                },
                                policy.renewal_interval,
                            )?
                        };
                        renewals.add(ticket)?;
                        pins.insert(
                            id,
                            Pin {
                                client: self,
                                ticket,
                            },
                        );
                    }
                }
                NativeAdmission::Compile { ticket } => {
                    let pin = Pin {
                        client: self,
                        ticket,
                    };
                    renewals.finish()?;
                    drop(pins);
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
        let remaining = policy.timeout.saturating_sub(start.elapsed());
        match Self::run_worker(&allocation, remaining, policy.max_result_bytes)? {
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
