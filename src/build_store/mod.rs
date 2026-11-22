//! Native build storage: action identities, result manifests and immutable files.
//!
//! The scheduler owns the index, while the filesystem handles physical storage.
//! The storage API works with ordinary files so ZFS can compress and clone them
//! without an application-specific compressed filesystem.

mod identity;
pub use identity::{
    ActionFingerprint, ActionKey, Artifact, BlobRef, ContentId, ResultId, ResultManifest,
};

#[cfg(all(unix, feature = "native-store"))]
mod store;
#[cfg(all(unix, feature = "native-store"))]
pub use store::{CacheStats, Eviction, NativeStore, Published, ResultLease, StagedBlob};
