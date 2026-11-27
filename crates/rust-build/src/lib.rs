//! Independent Rust workspace planning. The on-disk manifest and lock formats
//! are interchange formats; this crate does not link to or invoke Cargo.
mod fingerprint;
mod manifest;
mod platform;
mod profile;
mod resolve;
mod script;
mod source;
pub use profile::Profile;
pub use script::{LinkDirective, LinkScope, ScriptOutput};

pub use fingerprint::{content_file, content_tree};
pub use manifest::{Dependency, DependencyKind, Manifest, Package, Target, TargetKind, Workspace};
pub use platform::Platform;
pub use resolve::{BuildDomain, Edge, Graph, ResolveOptions, Unit};
pub use source::{LockedPackage, Lockfile, Sources};
