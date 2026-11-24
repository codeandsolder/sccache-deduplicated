//! Native cache wire messages, shared by clients and workers.

use std::{collections::BTreeSet, net::SocketAddr};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    ActionFingerprint, BlobRef, ContentId, ExecutionRoot, ResultManifest, TreeId, TreeManifest,
    identity::typed_digest,
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
    Worker { address: SocketAddr, job: u64 },
}

/// A client request for a complete *native* action, not a legacy cache key.
/// The output contract is an additional mandatory fingerprint component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRequest {
    pub(crate) fingerprint: ActionFingerprint,
    pub(crate) root: ExecutionRoot,
    pub input_trees: BTreeSet<TreeId>,
    pub required_outputs: BTreeSet<String>,
    pub optional_outputs: BTreeSet<String>,
}

impl ActionRequest {
    /// Include the declared artifact contract in the semantic identity.
    ///
    /// # Errors
    /// Returns an error for invalid names or an ambiguous output declaration.
    pub fn action_fingerprint(&self) -> Result<ActionFingerprint> {
        ensure!(!self.fingerprint.schema.is_empty(), "empty action schema");
        ensure!(
            self.required_outputs.is_disjoint(&self.optional_outputs),
            "ambiguous output contract"
        );
        ensure!(
            self.required_outputs
                .iter()
                .chain(&self.optional_outputs)
                .all(|name| !name.is_empty() && !name.contains('\0')),
            "invalid output name"
        );
        let mut fingerprint = self.fingerprint.clone();
        let digest = ContentId(typed_digest(
            b"sccache-output-contract-v1\0",
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
                .iter()
                .all(|name| result.outputs.contains_key(name)),
            "missing required output"
        );
        ensure!(
            result
                .outputs
                .keys()
                .all(|name| self.required_outputs.contains(name)
                    || self.optional_outputs.contains(name)),
            "unexpected output"
        );
        for artifact in result.outputs.values() {
            ensure!(
                artifact.mode.is_none_or(|mode| mode & !0o777 == 0),
                "unsupported output mode"
            );
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

/// Fixed header of an upload. Follow it with the exact raw blob bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadHeader {
    pub ticket: Ticket,
    pub blob: BlobRef,
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
    pub address: std::net::SocketAddr,
    pub job: u64,
    pub auth: String,
    pub certificate: Vec<u8>,
}

impl std::fmt::Debug for WorkerAllocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerAllocation")
            .field("address", &self.address)
            .field("job", &self.job)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleReply {
    Assigned(WorkerAllocation),
    Unavailable { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeJobPhase {
    Queued,
    Staging,
    Ready,
    Executing,
    Publishing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeRunRequest {
    Poll,
    Acknowledge,
}

/// Successful output bytes are retrieved from the scheduler. Failed
/// compilations deliver their diagnostics once, without creating a cache hit.
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
