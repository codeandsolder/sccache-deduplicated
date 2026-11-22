//! Native action admission, missing-input negotiation and verified delivery.
//! The compiler frontend owns discovery; this layer needs no client cache.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::SocketAddr,
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{ExitStatus, Output},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use tempfile::NamedTempFile;

use super::NativeCacheClient;
use crate::build_runtime::{
    BlobRef, ExecutionSpec, PreparedTree, ResultManifest, TreeId,
    wire::{NativeAdmission, NativeRunResult, NativeStatus, ScheduleReply, Ticket},
};

/// Explicit client admission and delivery bounds.
pub struct NativeBuildPolicy {
    pub timeout: Duration,
    pub renewal_interval: Duration,
    pub max_result_bytes: u64,
}

/// Distinguish a result reuse from a new worker execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeBuildSource {
    Hit,
    Worker(SocketAddr),
}

/// Native compiler response after all declared results have been delivered.
pub struct NativeBuildResult {
    pub source: NativeBuildSource,
    pub output: Output,
}

struct Pin<'a> {
    client: &'a NativeCacheClient,
    ticket: Ticket,
}

impl Drop for Pin<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.client.close(self.ticket) {
            debug!("native session could not be closed: {error:#}");
        }
    }
}

impl NativeCacheClient {
    /// Admit an exact native action, supply only absent inputs, and execute
    /// on a compatible worker when needed. On success, results are read
    /// directly from the scheduler and installed at the supplied local paths.
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
    ) -> Result<NativeBuildResult> {
        ensure!(
            !policy.timeout.is_zero()
                && !policy.renewal_interval.is_zero()
                && policy.max_result_bytes > 0
                && policy.max_result_bytes < u64::MAX,
            "invalid native client bounds"
        );
        let request = spec.action_request()?;
        let inputs = inputs
            .iter()
            .map(|tree| (tree.id(), tree))
            .collect::<BTreeMap<_, _>>();
        ensure!(
            inputs.keys().copied().collect::<BTreeSet<_>>() == request.input_trees,
            "prepared native inputs differ from the action declaration"
        );
        let destinations = verify_destinations(spec, destinations)?;
        let start = Instant::now();
        let mut pins: BTreeMap<TreeId, Pin<'_>> = BTreeMap::new();

        loop {
            ensure!(
                start.elapsed() < policy.timeout,
                "native admission timed out"
            );
            match self.admit(spec)? {
                NativeAdmission::Hit { ticket, manifest } => {
                    let pin = Pin {
                        client: self,
                        ticket,
                    };
                    drop(pins);
                    let output = self.deliver(&pin, spec, &manifest, &destinations, policy)?;
                    return Ok(NativeBuildResult {
                        source: NativeBuildSource::Hit,
                        output,
                    });
                }
                NativeAdmission::InFlight => {
                    // No speculative duplicate compilation. Input pins are
                    // not needed while another admitted action owns its closure.
                    pins.clear();
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
                        let tree = inputs
                            .get(&id)
                            .context("scheduler requested undeclared input tree")?;
                        pins.remove(&id);
                        let ticket = self.push_tree(
                            tree.manifest(),
                            |id| tree.open_blob(id),
                            policy.renewal_interval,
                        )?;
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
                    drop(pins);
                    return self.run_admitted(&pin, spec, &destinations, policy, start);
                }
            }
        }
    }

    fn run_admitted(
        &self,
        pin: &Pin<'_>,
        spec: &ExecutionSpec,
        destinations: &BTreeMap<String, PathBuf>,
        policy: &NativeBuildPolicy,
        start: Instant,
    ) -> Result<NativeBuildResult> {
        let allocation = match self.schedule(pin.ticket, spec.clone())? {
            ScheduleReply::Assigned(allocation) => allocation,
            ScheduleReply::Unavailable { message } => bail!("native worker unavailable: {message}"),
        };
        let source = NativeBuildSource::Worker(allocation.address);
        let remaining = policy.timeout.saturating_sub(start.elapsed());
        match Self::run_worker(&allocation, remaining, policy.max_result_bytes)? {
            NativeRunResult::Stored => {
                let NativeStatus::Ready(manifest) = self.status(pin.ticket)? else {
                    bail!("native worker did not publish its result");
                };
                Ok(NativeBuildResult {
                    source,
                    output: self.deliver(pin, spec, &manifest, destinations, policy)?,
                })
            }
            NativeRunResult::Failed {
                code,
                signal,
                stdout,
                stderr,
            } => {
                let status = match (code, signal) {
                    (Some(code @ 1..=255), None) => crate::util::exit_status_from_code(code),
                    (None, Some(signal @ 1..=64)) => ExitStatus::from_raw(signal),
                    _ => bail!("invalid native compiler exit status"),
                };
                Ok(NativeBuildResult {
                    source,
                    output: Output {
                        status,
                        stdout,
                        stderr,
                    },
                })
            }
            NativeRunResult::JobNotFound => bail!("native worker lost its assigned job"),
        }
    }

    fn deliver(
        &self,
        pin: &Pin<'_>,
        spec: &ExecutionSpec,
        manifest: &ResultManifest,
        destinations: &BTreeMap<String, PathBuf>,
        policy: &NativeBuildPolicy,
    ) -> Result<Output> {
        spec.action_request()?.validate_result(manifest)?;
        let total = manifest.blobs()?.values().try_fold(0_u64, |total, &size| {
            total
                .checked_add(size)
                .context("native result length overflow")
        })?;
        ensure!(
            total <= policy.max_result_bytes,
            "native result exceeds client limits"
        );

        self.with_renewal(pin.ticket, policy.renewal_interval, |check| {
            let diagnostic = |blob: Option<BlobRef>| -> Result<Vec<u8>> {
                let mut bytes = Vec::new();
                if let Some(blob) = blob {
                    self.download(pin.ticket, blob, &mut bytes)?;
                }
                Ok(bytes)
            };
            let stdout = diagnostic(manifest.stdout)?;
            let stderr = diagnostic(manifest.stderr)?;
            let mut staged = Vec::new();
            // Nothing becomes visible until every result has been verified.
            for (name, artifact) in &manifest.outputs {
                check()?;
                let path = destinations.get(name).context("unexpected native output")?;
                let parent = path.parent().context("native output has no parent")?;
                let mut temp = NamedTempFile::new_in(parent)?;
                self.download(pin.ticket, artifact.blob, &mut temp)?;
                if let Some(mode) = artifact.mode {
                    temp.as_file()
                        .set_permissions(fs::Permissions::from_mode(mode))?;
                }
                staged.push((temp, path));
            }
            check()?;
            // File-wise atomic publication, not an atomic multi-file rename.
            // A frontend may retry the compile on an installation error.
            for (temp, path) in staged {
                temp.persist(path)?;
            }
            Ok(Output {
                status: crate::util::exit_status_from_code(0),
                stdout,
                stderr,
            })
        })
    }
}

fn verify_destinations(
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
