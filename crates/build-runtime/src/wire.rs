//! Native cache wire messages, shared by clients and workers.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    ActionFingerprint, BlobRef, ContentId, ExecutionRoot, OutputKind, ResultManifest, TreeId,
    TreeManifest, identity::typed_digest,
};

/// A short-lived, unguessable capability. Never log its bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ticket(pub [u8; 32]);

impl std::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ticket([redacted])")
    }
}

/// Identity of the authenticated party permitted to publish a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Publisher {
    Client,
    Worker { peer: crate::PeerId, job: u64 },
}

/// A client request for a complete *native* action, not a legacy cache key.
/// The output contract is an additional mandatory fingerprint component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRequest {
    pub(crate) fingerprint: ActionFingerprint,
    pub(crate) root: ExecutionRoot,
    pub input_trees: BTreeSet<TreeId>,
    pub required_outputs: BTreeMap<String, OutputKind>,
    pub optional_outputs: BTreeMap<String, OutputKind>,
}

impl ActionRequest {
    /// Include the declared artifact contract in the semantic identity.
    ///
    /// # Errors
    /// Returns an error for invalid names or an ambiguous output declaration.
    pub fn action_fingerprint(&self) -> Result<ActionFingerprint> {
        ensure!(!self.fingerprint.schema.is_empty(), "empty action schema");
        ensure!(
            self.required_outputs
                .keys()
                .all(|name| !self.optional_outputs.contains_key(name)),
            "ambiguous output contract"
        );
        ensure!(
            self.required_outputs
                .keys()
                .chain(self.optional_outputs.keys())
                .all(|name| !name.is_empty() && !name.contains('\0')),
            "invalid output name"
        );
        let mut fingerprint = self.fingerprint.clone();
        let digest = ContentId(typed_digest(
            b"sccache-output-contract-v2\0",
            &(&self.required_outputs, &self.optional_outputs),
        )?);
        ensure!(
            fingerprint
                .components
                .insert("native/output-contract".into(), digest)
                .is_none(),
            "reserved output-contract component"
        );
        self.root.recipe.validate()?;
        ensure!(
            self.root
                .recipe
                .layers
                .iter()
                .all(|layer| self.input_trees.contains(&layer.tree)),
            "native root recipe references an undeclared input"
        );
        ensure!(
            fingerprint
                .components
                .insert("root/tree".into(), ContentId(self.root.id.0))
                .is_none(),
            "reserved root component"
        );
        Ok(fingerprint)
    }

    /// Verify a successful result's outputs against the original declaration.
    ///
    /// # Errors
    /// Returns an error for missing required outputs or unexpected artifacts.
    pub fn validate_result(&self, result: &ResultManifest) -> Result<()> {
        ensure!(
            self.required_outputs
                .keys()
                .all(|name| result.outputs.contains_key(name)),
            "missing required output"
        );
        for (name, artifact) in &result.outputs {
            let expected = self
                .required_outputs
                .get(name)
                .or_else(|| self.optional_outputs.get(name));
            ensure!(
                expected == Some(&artifact.kind()),
                "unexpected output name or kind"
            );
            artifact.validate()?;
        }
        Ok(())
    }
}

/// Result of requesting a native action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeAdmission {
    Hit {
        ticket: Ticket,
        manifest: ResultManifest,
    },
    InFlight,
    MissingInputs {
        trees: BTreeSet<TreeId>,
    },
    Compile {
        ticket: Ticket,
    },
}

/// State of an admitted action as observed by its client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeStatus {
    Compiling,
    Ready(ResultManifest),
    Failed,
}

/// One requested input blob, routed to its original declared tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputDemand {
    pub tree: TreeId,
    pub blob: BlobRef,
}

/// Origin polling ends as soon as the executor has pinned every input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputPoll {
    Waiting,
    Demand(InputDemand),
    Complete,
}

/// Negotiated result manifest and missing content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeginResult {
    pub missing: Vec<BlobRef>,
}

/// Fixed header of an upload. Physical bytes follow in the declared encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadHeader {
    pub ticket: Ticket,
    pub blob: BlobRef,
    /// Byte representation of the verified `BlobEncoding` enum.
    pub encoding: u8,
}

/// Reservation for publishing one immutable input or package tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeOffer {
    pub ticket: Ticket,
    pub id: TreeId,
    pub missing: Vec<BlobRef>,
}

/// A pinned tree and the manifest needed to provision it on a worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeRead {
    pub ticket: Ticket,
    pub manifest: TreeManifest,
}

/// Scheduler-issued capability to run exactly one native assignment over the
/// worker's existing authenticated HTTPS service.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerAllocation {
    pub peer: crate::PeerId,
    pub routes: sccache_peer_identity::RouteSet,
    pub job: u64,
    pub auth: String,
}

impl std::fmt::Debug for WorkerAllocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerAllocation")
            .field("peer", &self.peer)
            .field("routes", &self.routes)
            .field("job", &self.job)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleReply {
    Assigned(WorkerAllocation),
    Unavailable { message: String },
}

/// Encoded body goodput measured on a concrete scheduler-relative route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePathRate {
    pub path: crate::NetworkPath,
    pub bytes_per_second: u64,
}

/// Fresh, authenticated cache-route body goodput, in worker-relative
/// directions. Absence is not a zero-rate link.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePathRates {
    pub download: Option<CachePathRate>,
    pub upload: Option<CachePathRate>,
}

impl CachePathRates {
    #[must_use = "untrusted rate measurements must be validated"]
    pub fn valid(self) -> bool {
        [self.download, self.upload]
            .into_iter()
            .flatten()
            .all(|rate| {
                rate.path.valid()
                    && (64 * 1024..=1_000_000_000_000).contains(&rate.bytes_per_second)
            })
    }
}

/// Coherent snapshot of a worker's measured transfer and compiler service.
/// Revision is monotonic within the authenticated worker incarnation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerTiming {
    pub revision: u64,
    pub transfer: crate::PackageTransferCost,
    /// Zero denotes an unobserved execution prior.
    pub execution_nanoseconds: u64,
    pub result: crate::ResultTransferEstimate,
}

impl WorkerTiming {
    #[must_use = "worker timing is advisory and must be validated"]
    pub fn valid(self) -> bool {
        self.transfer.validate().is_ok()
            && self.execution_nanoseconds <= 3_600_000_000_000
            && self.result.valid()
    }

    #[must_use = "unknown compiler service uses the configured initial prior"]
    pub const fn execution_estimate(self) -> u64 {
        if self.execution_nanoseconds == 0 {
            1_000_000_000
        } else {
            self.execution_nanoseconds
        }
    }

    /// Ignore stale snapshots from the same worker incarnation.
    pub fn adopt(&mut self, other: Self) {
        if other.revision > self.revision && other.valid() {
            *self = other;
        }
    }
}

/// Real service times and actual negotiated output traffic for a successful
/// worker action. Advisory only; never changes the action identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionObservation {
    pub worker_timing: Option<WorkerTiming>,
    /// Warm staging service, excluding worker queue and grace-capacity waits.
    pub warm_staging_nanoseconds: Option<u64>,
    /// Warm local retention and result negotiation, excluding new local writes and grace waits.
    pub publication_setup_nanoseconds: Option<u64>,
    pub execution_nanoseconds: u64,
    pub upload_bytes: u64,
    pub upload_requests: u64,
    pub upload_nanoseconds: u64,
}

impl ActionObservation {
    #[must_use = "untrusted timing samples must be validated"]
    pub fn valid(self) -> bool {
        (1..=3_600_000_000_000).contains(&self.execution_nanoseconds)
            && self.worker_timing.is_none_or(WorkerTiming::valid)
            && self
                .warm_staging_nanoseconds
                .is_none_or(|ns| ns <= 60_000_000_000)
            && self
                .publication_setup_nanoseconds
                .is_none_or(|ns| ns <= 60_000_000_000)
            && self.upload_bytes <= 1 << 40
            && self.upload_requests <= 1_000_000
            && self.upload_nanoseconds <= 3_600_000_000_000
            && (self.upload_requests != 0 || self.upload_bytes == 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeJobPhase {
    Assigned,
    Queued,
    Staging,
    Ready,
    Executing,
    AwaitingPublication,
    Publishing,
    Terminal,
}

impl NativeJobPhase {
    #[must_use = "active jobs retain a scheduler assignment"]
    pub const fn active(self) -> bool {
        !matches!(self, Self::Assigned | Self::Terminal)
    }

    #[must_use = "only pre-publication work competes for compiler admission"]
    pub const fn needs_compiler(self) -> bool {
        matches!(
            self,
            Self::Assigned | Self::Queued | Self::Staging | Self::Ready | Self::Executing
        )
    }

    #[must_use = "verified inputs may be reused by other assignments"]
    pub const fn inputs_ready(self) -> bool {
        matches!(
            self,
            Self::Ready | Self::Executing | Self::AwaitingPublication | Self::Publishing
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeRunRequest {
    Poll,
    Acknowledge,
}

/// Successful output bytes are retrieved from the scheduler. Failed
/// compilations retain replayable diagnostics until acknowledgement or expiry,
/// without creating a cache hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeRunResult {
    Pending(NativeJobPhase),
    Unavailable,
    Acknowledged,
    Stored,
    Failed {
        code: Option<i32>,
        signal: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    JobNotFound,
}
