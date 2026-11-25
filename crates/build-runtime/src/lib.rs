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
pub use spec::{BuildPath, CommandSpec, ExecutionRoot, ExecutionSpec, OutputSpec};
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
    BlobEncoding, BlobReader, encode as encode_native_blob, encode_raw as encode_native_raw_blob,
    transfer as transfer_native_blob,
};

#[cfg(all(unix, feature = "store"))]
mod coordinator;
#[cfg(all(unix, feature = "store"))]
mod session;
#[cfg(all(unix, feature = "store"))]
pub use session::{
    NativeContentPending, NativeInputRejected, NativeServiceBusy, NativeSessions, PeerInputClaim,
    SessionLimits,
};
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
pub use store::MountedTree;
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
    InstallationCatalog, InstallationReport, MappedMetadata, MappedTree, PreparedTree,
    SourceDigestCache,
};

// Cluster principals are independent of socket endpoints and TLS implementation.
pub use sccache_peer_identity::PeerId;
