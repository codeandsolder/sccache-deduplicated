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
    /// Returns an error for missing required outputs, unexpected artifacts, invalid metadata,
    /// or conflicting content lengths anywhere in the result.
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
        }
        result.blobs()?;
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
    /// A worker has negotiated immutable successful output; durable commit is pending.
    Negotiated(ResultManifest),
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

/// Authorization for an exact peer-to-peer content transfer. Scheduler
/// recovery and member delivery use the same transport but distinct grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobRecipient {
    Scheduler,
    Client(crate::PeerId),
    Worker(crate::PeerId),
}

/// A source for one exact content identity. The grant is never logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobSource {
    pub peer: crate::PeerId,
    pub routes: sccache_peer_identity::RouteSet,
    pub token: String,
}

impl std::fmt::Debug for BlobSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobSource")
            .field("peer", &self.peer)
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

/// A receiver-specific offer. Scheduler residency is an observation, not
/// permission to assume a subsequent transfer will succeed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobSourcePlan {
    pub blob: BlobRef,
    pub scheduler_present: bool,
    pub sources: Vec<BlobSource>,
}

pub const MAX_SOURCE_BATCH: usize = 32;
pub const MAX_BLOB_SOURCES: usize = 4;

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

/// Effective verified logical delivery from a worker, including decoding
/// and staging. Path endpoints are ordered source, receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerDownloadRate {
    pub source: crate::PeerId,
    pub path: crate::NetworkPath,
    pub logical_bytes_per_second: u64,
    pub wire_per_mille: u64,
}

pub const MAX_PEER_DOWNLOAD_RATES: usize = 32;

impl PeerDownloadRate {
    #[must_use = "untrusted delivery telemetry must be validated"]
    pub fn valid(self) -> bool {
        self.path.valid()
            && (64 * 1024..=1_000_000_000_000).contains(&self.logical_bytes_per_second)
            && (1..=1100).contains(&self.wire_per_mille)
    }
}

/// Validate a bounded snapshot, canonically sorted by source principal.
#[must_use = "untrusted delivery telemetry must be validated"]
pub fn peer_download_rates_valid(rates: &[PeerDownloadRate]) -> bool {
    rates.len() <= MAX_PEER_DOWNLOAD_RATES
        && rates.iter().all(|rate| rate.valid())
        && rates.windows(2).all(|pair| pair[0].source < pair[1].source)
}

/// Aggregate interface pressure, including other applications, sampled
/// on the endpoint itself. Nominal capacity is only set for a known
/// physical full-duplex Ethernet link.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceDirection {
    pub total_bytes_per_second: u64,
    pub external_bytes_per_second: u64,
    pub active_streams: u32,
}

impl InterfaceDirection {
    const fn valid(self) -> bool {
        self.external_bytes_per_second <= self.total_bytes_per_second
            && self.total_bytes_per_second <= 1_000_000_000_000
            && self.active_streams <= 4096
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceTraffic {
    pub index: u32,
    pub addresses: Vec<std::net::IpAddr>,
    pub nominal_capacity: Option<u64>,
    pub send: InterfaceDirection,
    pub receive: InterfaceDirection,
}

/// An endpoint-local directional path. The local address belongs to the
/// reporting host; remote is the authenticated connection's other endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EndpointFlow {
    pub path: crate::NetworkPath,
    pub direction: crate::Direction,
}

impl EndpointFlow {
    const fn valid(self) -> bool {
        self.path.valid() && !self.path.local.is_loopback() && !self.path.remote.is_loopback()
    }
}

/// Observed effective aggregate service under simultaneous real task traffic.
/// This is not a physical topology assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointOverlap {
    pub flows: [EndpointFlow; 2],
    pub bytes_per_second: u64,
}

impl EndpointOverlap {
    fn valid(self) -> bool {
        self.flows[0] < self.flows[1]
            && self.flows.iter().all(|flow| flow.valid())
            && (128 * 1024..=2_000_000_000_000).contains(&self.bytes_per_second)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceReport {
    pub interfaces: Vec<InterfaceTraffic>,
    pub overlaps: Vec<EndpointOverlap>,
}

impl InterfaceReport {
    #[must_use = "untrusted interface telemetry must be validated"]
    pub fn valid(&self) -> bool {
        let mut addresses = BTreeSet::new();
        self.interfaces.len() <= 16
            && self
                .interfaces
                .windows(2)
                .all(|pair| pair[0].index < pair[1].index)
            && self.interfaces.iter().all(|interface| {
                interface.index != 0
                    && !interface.addresses.is_empty()
                    && interface.addresses.len() <= 8
                    && interface.addresses.windows(2).all(|pair| pair[0] < pair[1])
                    && interface.addresses.iter().all(|&address| {
                        sccache_peer_identity::RouteSet::eligible(std::net::SocketAddr::new(
                            address, 1,
                        )) && addresses.insert(address)
                    })
                    && interface
                        .nominal_capacity
                        .is_none_or(|rate| (125_000..=1_000_000_000_000).contains(&rate))
                    && interface.send.valid()
                    && interface.receive.valid()
            })
            && self.overlaps.len() <= 64
            && self
                .overlaps
                .windows(2)
                .all(|pair| pair[0].flows < pair[1].flows)
            && self.overlaps.iter().all(|overlap| {
                overlap.valid()
                    && overlap
                        .flows
                        .iter()
                        .all(|flow| self.at(flow.path.local).is_some())
            })
    }

    /// Effective aggregate service learned for exactly this pair of flows.
    #[must_use = "the observed constraint is scoped to the reported endpoint"]
    pub fn shared_rate(&self, a: EndpointFlow, b: EndpointFlow) -> Option<u64> {
        let mut flows = [a, b];
        flows.sort_unstable();
        self.overlaps
            .binary_search_by_key(&flows, |overlap| overlap.flows)
            .ok()
            .map(|index| self.overlaps[index].bytes_per_second)
    }

    #[must_use = "the interface is used for endpoint capacity estimates"]
    pub fn at(&self, address: std::net::IpAddr) -> Option<&InterfaceTraffic> {
        self.interfaces
            .iter()
            .find(|interface| interface.addresses.binary_search(&address).is_ok())
    }
}

impl InterfaceTraffic {
    /// Available wire service on an explicitly known full-duplex wired
    /// interface. Virtual or wireless routes have no invented ceiling.
    #[must_use = "available capacity constrains the transfer forecast"]
    pub fn available(&self, direction: crate::Direction) -> Option<u64> {
        let capacity = self.nominal_capacity?;
        let load = match direction {
            crate::Direction::Send => self.send,
            crate::Direction::Receive => self.receive,
        };
        Some(
            capacity
                .saturating_sub(load.external_bytes_per_second)
                .max(capacity / 8)
                .max(1),
        )
    }
}

/// Fresh receiver-side service estimates for result delivery. The client
/// principal is established by the scheduler's authenticated connection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientDeliveryRates {
    pub scheduler: Option<CachePathRate>,
    pub peers: Vec<PeerDownloadRate>,
    pub interfaces: InterfaceReport,
}

impl ClientDeliveryRates {
    #[must_use = "untrusted receiver telemetry must be validated"]
    pub fn valid(&self) -> bool {
        CachePathRates {
            download: self.scheduler,
            upload: None,
        }
        .valid()
            && peer_download_rates_valid(&self.peers)
            && self.interfaces.valid()
    }
}

/// Scheduler-derived delivery profile, distinct from the action identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliverySelection {
    pub profile: ContentId,
    pub outputs: BTreeSet<String>,
}

impl DeliverySelection {
    /// The command-family hash and exact selected names form a stable profile.
    ///
    /// # Errors
    /// Returns an error for undeclared output names or encoding failure.
    pub fn new(spec: &crate::ExecutionSpec, outputs: BTreeSet<String>) -> Result<Self> {
        ensure!(
            outputs.iter().all(|name| spec.outputs.contains_key(name)),
            "undeclared selected output"
        );
        let profile = ContentId(typed_digest(
            b"sccache-delivery-profile-v1\0",
            &(spec.placement_class()?, &outputs),
        )?);
        Ok(Self { profile, outputs })
    }
}

/// Successfully staged unique content, split by the actual delivery source.
/// Counts exclude failed attempts and repeated reads of the same content.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientDeliveryObservation {
    /// Unique logical closure selected by the receiver, including local reuse.
    pub selected_bytes: u64,
    pub direct_bytes: u64,
    pub scheduler_bytes: u64,
    pub unique_blobs: u64,
    pub staging_nanoseconds: u64,
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

/// Successful output bytes are available under the result lease. Failed
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

#[cfg(test)]
mod endpoint_report_tests {
    use super::*;
    use crate::Direction;

    #[test]
    fn endpoint_report_is_bounded_and_scopes_overlap_to_exact_paths() -> Result<()> {
        let first = EndpointFlow {
            path: "192.0.2.1,192.0.2.2".parse()?,
            direction: Direction::Send,
        };
        let second = EndpointFlow {
            path: "198.51.100.1,198.51.100.2".parse()?,
            direction: Direction::Receive,
        };
        let interface = |index, address| InterfaceTraffic {
            index,
            addresses: vec![address],
            nominal_capacity: None,
            send: InterfaceDirection::default(),
            receive: InterfaceDirection::default(),
        };
        let mut report = InterfaceReport {
            interfaces: vec![
                interface(1, first.path.local),
                interface(2, second.path.local),
            ],
            overlaps: vec![EndpointOverlap {
                flows: [first, second],
                bytes_per_second: 100 << 20,
            }],
        };
        assert!(report.valid());
        assert_eq!(report.shared_rate(second, first), Some(100 << 20));
        assert_eq!(
            report.shared_rate(
                first,
                EndpointFlow {
                    direction: Direction::Send,
                    ..second
                }
            ),
            None
        );
        report.overlaps[0].flows.reverse();
        assert!(!report.valid());
        report.overlaps[0].flows.reverse();
        report.interfaces.pop();
        assert!(!report.valid());
        Ok(())
    }
}
