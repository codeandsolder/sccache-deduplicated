//! Native build storage: action identities, result manifests and immutable files.
//!
//! The scheduler owns the index, while the filesystem handles physical storage.
//! The storage API works with ordinary files so ZFS can compress and clone them
//! without an application-specific compressed filesystem.

#![deny(rust_2018_idioms)]

pub mod analytics;
mod identity;
mod installation;
mod network;
pub use network::{
    ConcurrentCapacity, Direction, DirectionSnapshot, MeteredReader, NetworkCheckpoint,
    NetworkMeter, NetworkPath, NetworkSnapshot, Peer, PeerCapacity, ResultTransferEstimate,
    SharedCapacity, TransferDemand, TransferMeter, transfer_seconds,
};
mod package;
mod placement_class;
pub use installation::{InstallationManifest, InstallationRecipe, InstalledComponent};
pub use package::{
    ArchiveLength, PackageArchive, PackageCatalog, PackageCompression, PackageDeliveryLimits,
    PackageIdentity, PackageReceipt, PackageSource, PackageTransferCost,
};
mod recipe;
mod residency;
pub use residency::BlobResidency;
mod space_policy;
pub use space_policy::SpacePolicy;
mod spec;
pub use recipe::{TreeLayer, TreeRecipe};
pub use spec::{
    BuildPath, CommandSpec, CompilerResultIdentity, ExecutionRoot, ExecutionSpec, OutputSpec,
};
mod tree;
pub mod wire;
pub use identity::{
    ActionFingerprint, ActionKey, ActionMode, Artifact, BlobRef, ContentId, OutputKind, ResultId,
    ResultManifest,
};
pub use tree::{TreeEntry, TreeId, TreeManifest, TreeMetadata, TreePath, TreeTimestamp};

#[cfg(feature = "store")]
mod blob_codec;
#[cfg(feature = "store")]
pub use blob_codec::{
    BlobEncoding, BlobReader, BlobWireEncoder, encode as encode_native_blob,
    encode_raw as encode_native_raw_blob, transfer as transfer_native_blob,
};

#[cfg(all(unix, feature = "async-io"))]
mod disk;
#[cfg(all(unix, feature = "async-io"))]
pub use disk::{initialize_async_disk, read_file_at};

#[cfg(all(unix, feature = "store"))]
mod coordinator;
#[cfg(all(unix, feature = "store"))]
mod session;
#[cfg(all(unix, feature = "store"))]
pub use session::{
    AdmissionStats, DeliveryReceipt, ManifestStatus, NativeContentPending, NativeDownload,
    NativeInputRejected, NativeServiceBusy, NativeSessions, NativeUpload, PeerInputClaim,
    RecoveryStatus, SchedulePreparation, ScheduleReservation, SessionLimits, SessionStatus,
    TicketStatus,
};
#[cfg(all(unix, feature = "store"))]
mod store;
#[cfg(all(unix, feature = "store"))]
pub use coordinator::{Admission, BuildCoordinator, CompilePermit};
#[cfg(all(unix, feature = "store"))]
pub use store::{
    CacheAnalyticsSampler, CacheStats, ComponentAudit, Eviction, GarbageCollected,
    NativeIndexAudit, NativeStore, PackageArchiveLease, PackageDecoder, PackageImport,
    PackageImportLimits, PackagePolicy, PackagePreparation, PackageSlot, PhysicalStager, Published,
    ResultLease, SchemaInventory, SpaceReport, SpaceStatus, StageBudget, StageSpaceExhausted,
    StageSpaceTooLarge, StagedBlob, TreeLease, UploadReservation, VerifiedPackage,
    decode_package_process,
};

#[cfg(all(target_os = "linux", feature = "store"))]
mod execution;
#[cfg(all(target_os = "linux", feature = "mapping"))]
pub mod sandbox;
#[cfg(all(target_os = "linux", feature = "store"))]
pub use execution::{
    CapturedExecution, ExecutionPhase, ExecutionPolicy, ExecutionTimings, acquire_execution_inputs,
    execute,
};

#[cfg(all(target_os = "linux", feature = "store"))]
pub use store::{MountedTree, ResidentInputs};
#[cfg(all(target_os = "linux", feature = "mapping"))]
mod tree_fs;
#[cfg(all(target_os = "linux", feature = "mapping"))]
pub use tree_fs::{MaterializationStats, MaterializedTree, materialize_tree};

#[cfg(all(target_os = "linux", feature = "mapping"))]
mod mapped;
#[cfg(all(target_os = "linux", feature = "mapping"))]
mod source;
#[cfg(all(target_os = "linux", feature = "mapping"))]
pub use mapped::{
    DescriptorDigestProvider, DescriptorMemo, InstallationCatalog, InstallationReport,
    MappedMetadata, MappedTree, PreparedTree, ReferenceBlobProvider, ReferenceResolver,
    SourceDigestCache, hash_descriptor,
};

// Cluster principals are independent of socket endpoints and TLS implementation.
pub use sccache_peer_identity::PeerId;

#[cfg(all(target_os = "linux", feature = "store"))]
pub mod intermediate_fs;
