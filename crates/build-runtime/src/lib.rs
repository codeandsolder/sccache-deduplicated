//! Native build storage: action identities, result manifests and immutable files.
//!
//! The scheduler owns the index, while the filesystem handles physical storage.
//! The storage API works with ordinary files so ZFS can compress and clone them
//! without an application-specific compressed filesystem.

#![deny(rust_2018_idioms)]

mod identity;
mod installation;
mod network;
pub use network::{
    ConcurrentCapacity, Direction, DirectionSnapshot, MeteredReader, NetworkCheckpoint,
    NetworkMeter, NetworkSnapshot, Peer, PeerCapacity, ResultTransferEstimate, SharedCapacity,
    TransferDemand, transfer_seconds,
};
mod package;
pub use installation::{InstallationManifest, InstallationRecipe, InstalledComponent};
pub use package::{
    ArchiveLength, PackageArchive, PackageCompression, PackageIdentity, PackageReceipt,
    PackageSource, PackageTransferCost,
};
mod recipe;
mod residency;
pub use residency::BlobResidency;
mod space_policy;
pub use space_policy::SpacePolicy;
mod spec;
pub use recipe::{TreeLayer, TreeRecipe};
pub use spec::{BuildPath, CommandSpec, ExecutionRoot, ExecutionSpec, OutputSpec};
mod tree;
pub mod wire;
pub use identity::{
    ActionFingerprint, ActionKey, ActionMode, Artifact, BlobRef, ContentId, ResultId,
    ResultManifest,
};
pub use tree::{TreeEntry, TreeId, TreeManifest, TreeMetadata, TreePath, TreeTimestamp};

#[cfg(all(unix, feature = "store"))]
mod coordinator;
#[cfg(all(unix, feature = "store"))]
mod session;
#[cfg(all(unix, feature = "store"))]
pub use session::{NativeServiceBusy, NativeSessions, SessionLimits};
#[cfg(all(unix, feature = "store"))]
mod store;
#[cfg(all(unix, feature = "store"))]
pub use coordinator::{Admission, BuildCoordinator, CompilePermit};
#[cfg(all(unix, feature = "store"))]
pub use store::{
    CacheStats, ComponentAudit, Eviction, GarbageCollected, NativeIndexAudit, NativeStore,
    PackageArchiveLease, PackageDecoder, PackageImportLimits, PackagePolicy, PackageSlot,
    Published, ResultLease, SchemaInventory, SpaceReport, StageBudget, StagedBlob, TreeLease,
    UploadReservation, VerifiedPackage, decode_package_process,
};

#[cfg(all(target_os = "linux", feature = "store"))]
mod execution;
#[cfg(target_os = "linux")]
pub mod sandbox;
#[cfg(all(target_os = "linux", feature = "store"))]
pub use execution::{CapturedExecution, ExecutionPolicy, execute};

#[cfg(all(target_os = "linux", feature = "store"))]
pub use store::{MaterializationStats, MaterializedTree};

#[cfg(all(target_os = "linux", feature = "mapping"))]
mod mapped;
#[cfg(all(target_os = "linux", feature = "mapping"))]
mod source;
#[cfg(all(target_os = "linux", feature = "mapping"))]
pub use mapped::{
    InstallationCatalog, InstallationReport, MappedMetadata, MappedTree, PreparedTree,
    SourceDigestCache,
};
