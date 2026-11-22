//! Native build storage: action identities, result manifests and immutable files.
//!
//! The scheduler owns the index, while the filesystem handles physical storage.
//! The storage API works with ordinary files so ZFS can compress and clone them
//! without an application-specific compressed filesystem.

#![deny(rust_2018_idioms)]

mod identity;
mod recipe;
mod spec;
pub use recipe::{TreeLayer, TreeRecipe};
pub use spec::{BuildPath, CommandSpec, ExecutionSpec, OutputSpec};
mod tree;
pub mod wire;
pub use identity::{
    ActionFingerprint, ActionKey, Artifact, BlobRef, ContentId, ResultId, ResultManifest,
};
pub use tree::{TreeEntry, TreeId, TreeManifest, TreeMetadata, TreePath, TreeTimestamp};

#[cfg(all(unix, feature = "store"))]
mod coordinator;
#[cfg(all(unix, feature = "store"))]
mod session;
#[cfg(all(unix, feature = "store"))]
pub use session::{NativeSessions, SessionLimits};
#[cfg(all(unix, feature = "store"))]
mod store;
#[cfg(all(unix, feature = "store"))]
pub use coordinator::{Admission, BuildCoordinator, CompilePermit};
#[cfg(all(unix, feature = "store"))]
pub use store::{
    CacheStats, ComponentAudit, Eviction, GarbageCollected, NativeStore, PackageCompression,
    PackagePolicy, PackageSource, Published, ResultLease, SpacePolicy, SpaceReport, StagedBlob,
    TreeLease, UploadReservation,
};

#[cfg(all(target_os = "linux", feature = "store"))]
mod execution;
#[cfg(target_os = "linux")]
pub mod sandbox;
#[cfg(all(target_os = "linux", feature = "store"))]
pub use execution::{CapturedExecution, ExecutionPolicy, execute};

#[cfg(all(target_os = "linux", feature = "store"))]
pub use store::{MaterializationStats, MaterializedTree};
