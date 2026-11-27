//! Independent Rust workspace planning. The on-disk manifest and lock formats
//! are interchange formats; this crate does not link to or invoke Cargo.
mod fingerprint;
pub mod impact;
mod options;
mod planner;
pub mod settings;
pub use options::{BuildMode, PlanOptions};
pub use planner::Planner;
pub use settings::{Settings, Toolchain};
mod manifest;
mod metadata;
mod platform;
mod profile;
mod registry;
mod resolve;
mod script;
mod solve;
mod source;
pub use profile::Profile;
pub use registry::{IndexNotFound, Registries, Registry};
pub use script::{LinkDirective, LinkScope, ScriptOutput};

pub use fingerprint::{content_file, content_tree};
pub use manifest::{Dependency, DependencyKind, Manifest, Package, Target, TargetKind, Workspace};
pub use metadata::workspace_metadata;
pub use platform::Platform;
pub use resolve::{BuildDomain, Edge, Graph, ResolveOptions, Unit};
pub use source::{LockMismatch, LockedPackage, Lockfile, Sources};
