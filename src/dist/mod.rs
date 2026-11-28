// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::compiler;
#[cfg(feature = "dist-server")]
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "dist-server")]
use crate::errors::{Error, Result};

#[cfg(feature = "dist-client")]
pub mod client_auth;
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
pub mod cluster;
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
mod cluster_routes;
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
pub mod execution_queue;
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
pub mod http;
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
pub mod native;
#[cfg(test)]
mod test;

// TODO: paths (particularly outputs, which are accessed by an unsandboxed program)
// should be some pre-sanitised AbsPath type

pub use self::path_transform::PathTransformer;

#[cfg(feature = "dist-client")]
pub mod pkg;
#[cfg(not(feature = "dist-client"))]
mod pkg {
    pub trait ToolchainPackager {}
    pub trait InputsPackager {}
}

mod path_transform {
    use std::collections::HashMap;
    #[cfg(windows)]
    use std::path::{Component, Components, Prefix, PrefixComponent};
    use std::path::{Path, PathBuf};

    #[cfg(windows)]
    fn take_prefix<'a>(components: &'a mut Components<'_>) -> Option<PrefixComponent<'a>> {
        let prefix = components.next()?;
        let pc = match prefix {
            Component::Prefix(pc) => pc,
            _ => return None,
        };
        let root = components.next()?;
        if root != Component::RootDir {
            return None;
        }
        Some(pc)
    }

    #[cfg(windows)]
    fn transform_prefix_component(pc: PrefixComponent<'_>) -> Option<String> {
        match pc.kind() {
            // Transforming these to the same place means these may flip-flop
            // in the tracking map, but they're equivalent so not really an
            // issue
            Prefix::Disk(diskchar) | Prefix::VerbatimDisk(diskchar) => {
                assert!(diskchar.is_ascii_alphabetic());
                let diskchar = diskchar.to_ascii_uppercase();
                Some(format!("/prefix/disk-{}", char::from(diskchar)))
            }
            Prefix::Verbatim(_)
            | Prefix::VerbatimUNC(_, _)
            | Prefix::DeviceNS(_)
            | Prefix::UNC(_, _) => None,
        }
    }

    #[derive(Debug)]
    pub struct PathTransformer {
        dist_to_local_path: HashMap<String, PathBuf>,
        root_mappings: Vec<(PathBuf, String)>,
    }

    impl Default for PathTransformer {
        fn default() -> Self {
            Self::new()
        }
    }

    impl PathTransformer {
        #[must_use = "the returned path transformer records paths for the distributed compilation"]
        pub fn new() -> Self {
            Self {
                dist_to_local_path: HashMap::new(),
                root_mappings: Vec::new(),
            }
        }

        pub fn add_root_mapping(&mut self, local_root: PathBuf, dist_root: &str) {
            debug_assert!(local_root.is_absolute());
            debug_assert!(dist_root.starts_with('/'));
            let root = dist_root.trim_end_matches('/');
            let root = if root.is_empty() { "/" } else { root };
            self.root_mappings.push((local_root, root.to_owned()));
            self.root_mappings
                .sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        }

        pub fn as_dist_abs(&mut self, p: &Path) -> Option<String> {
            if !p.is_absolute() {
                return None;
            }
            self.as_dist(p)
        }

        pub fn as_dist(&mut self, p: &Path) -> Option<String> {
            let mapping = self
                .root_mappings
                .iter()
                .find_map(|(local, dist)| p.strip_prefix(local).ok().map(|suffix| (dist, suffix)));
            let dist_path = if let Some((root, suffix)) = mapping {
                let suffix = suffix.to_str()?;
                #[cfg(windows)]
                let suffix = suffix.replace('\\', "/");
                if suffix.is_empty() {
                    root.clone()
                } else {
                    format!("{}/{suffix}", root.trim_end_matches('/'))
                }
            } else {
                Self::encode_unmapped(p)?
            };
            self.dist_to_local_path
                .insert(dist_path.clone(), p.to_owned());
            Some(dist_path)
        }

        #[cfg(unix)]
        fn encode_unmapped(p: &Path) -> Option<String> {
            Some(p.to_str()?.to_owned())
        }

        #[cfg(windows)]
        fn encode_unmapped(p: &Path) -> Option<String> {
            let mut components = p.components();

            // Extract the prefix (e.g. "C:/") if present
            let maybe_dist_prefix = if p.is_absolute() {
                let pc = take_prefix(&mut components)?;
                Some(transform_prefix_component(pc)?)
            } else {
                None
            };

            // Reconstruct the path (minus the prefix) as a Linux path
            let mut dist_suffix = String::new();
            for component in components {
                let part = match component {
                    Component::Prefix(_) | Component::RootDir => {
                        // On Windows there is such a thing as a path like C:file.txt
                        // It's not clear to me what the semantics of such a path are,
                        // so give up.
                        error!("unexpected part in path {:?}", p);
                        return None;
                    }
                    Component::Normal(osstr) => osstr.to_str()?,
                    // TODO: should be forbidden
                    Component::CurDir => ".",
                    Component::ParentDir => "..",
                };
                if !dist_suffix.is_empty() {
                    dist_suffix.push('/');
                }
                dist_suffix.push_str(part);
            }

            let dist_path = if let Some(mut dist_prefix) = maybe_dist_prefix {
                dist_prefix.push('/');
                dist_prefix.push_str(&dist_suffix);
                dist_prefix
            } else {
                dist_suffix
            };
            Some(dist_path)
        }
        #[cfg(windows)]
        pub fn disk_mappings(&self) -> impl Iterator<Item = (PathBuf, String)> {
            let mut normal_mappings = HashMap::new();
            let mut verbatim_mappings = HashMap::new();
            for local_path in self.dist_to_local_path.values() {
                if !local_path.is_absolute() {
                    continue;
                }
                let mut components = local_path.components();
                let Some(local_prefix) = take_prefix(&mut components) else {
                    continue;
                };
                let local_prefix_component = Component::Prefix(local_prefix);
                let local_prefix_path: &Path = local_prefix_component.as_ref();
                let mappings = if let Prefix::VerbatimDisk(_) = local_prefix.kind() {
                    &mut verbatim_mappings
                } else {
                    &mut normal_mappings
                };
                if mappings.contains_key(local_prefix_path) {
                    continue;
                }
                let Some(dist_prefix) = transform_prefix_component(local_prefix) else {
                    continue;
                };
                mappings.insert(local_prefix_path.to_owned(), dist_prefix);
            }
            // Prioritise normal mappings for the same disk, as verbatim mappings can
            // look odd to users
            normal_mappings.into_iter().chain(verbatim_mappings)
        }

        pub fn path_mappings(&self) -> impl Iterator<Item = (PathBuf, String)> + '_ {
            let mappings = self.root_mappings.iter().cloned();
            #[cfg(windows)]
            let mappings = mappings.chain(self.disk_mappings());
            mappings
        }

        /// Transform a distributed path back to its local path.
        ///
        /// # Errors
        ///
        /// Returns an error for an embedded NUL, or on Windows when no local mapping exists.
        pub fn to_local(&self, p: &str) -> crate::errors::Result<PathBuf> {
            if p.as_bytes().contains(&0) {
                return Err(crate::errors::anyhow!(
                    "distributed path contains an embedded NUL"
                ));
            }
            if let Some(local) = self.dist_to_local_path.get(p) {
                return Ok(local.clone());
            }
            #[cfg(windows)]
            return Err(crate::errors::anyhow!("unknown distributed path: {p}"));
            #[cfg(unix)]
            Ok(self.decode_unmapped(p))
        }

        #[cfg(unix)]
        fn decode_unmapped(&self, p: &str) -> PathBuf {
            let path = Path::new(p);
            if let Some((local, suffix, _)) = self
                .root_mappings
                .iter()
                .filter_map(|(local, dist)| {
                    let root = Path::new(dist);
                    path.strip_prefix(root)
                        .ok()
                        .map(|suffix| (local, suffix, root.components().count()))
                })
                .min_by_key(|(_, _, depth)| std::cmp::Reverse(*depth))
            {
                return local.join(suffix);
            }
            path.to_owned()
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_root_mapping() {
        let mut pt = PathTransformer::new();
        pt.add_root_mapping(PathBuf::from("C:/physical/project"), "/build");
        pt.add_root_mapping(PathBuf::from("C:/physical/project-target"), "/target");
        assert_eq!(
            pt.as_dist(Path::new("C:/physical/project/src/lib.rs"))
                .unwrap(),
            "/build/src/lib.rs"
        );
        assert_eq!(
            pt.as_dist(Path::new("C:/physical/project-target/debug/x.rlib"))
                .unwrap(),
            "/target/debug/x.rlib"
        );
        assert_eq!(
            pt.to_local("/build/src/lib.rs").unwrap(),
            PathBuf::from("C:/physical/project/src/lib.rs")
        );
        let mappings = pt.path_mappings().collect::<Vec<_>>();
        assert!(mappings.contains(&(PathBuf::from("C:/physical/project"), "/build".to_owned())));
    }

    #[cfg(windows)]
    #[test]
    fn test_basic() {
        let mut pt = PathTransformer::new();
        assert_eq!(pt.as_dist(Path::new("C:/a")).unwrap(), "/prefix/disk-C/a");
        assert_eq!(
            pt.as_dist(Path::new(r#"C:\a\b.c"#)).unwrap(),
            "/prefix/disk-C/a/b.c"
        );
        assert_eq!(
            pt.as_dist(Path::new("X:/other.c")).unwrap(),
            "/prefix/disk-X/other.c"
        );
        let mut disk_mappings: Vec<_> = pt.disk_mappings().collect();
        disk_mappings.sort();
        assert_eq!(
            disk_mappings,
            &[
                (Path::new("C:").into(), "/prefix/disk-C".into()),
                (Path::new("X:").into(), "/prefix/disk-X".into()),
            ]
        );
        assert_eq!(pt.to_local("/prefix/disk-C/a").unwrap(), Path::new("C:/a"));
        assert_eq!(
            pt.to_local("/prefix/disk-C/a/b.c").unwrap(),
            Path::new("C:/a/b.c")
        );
        assert_eq!(
            pt.to_local("/prefix/disk-X/other.c").unwrap(),
            Path::new("X:/other.c")
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_relative_paths() {
        let mut pt = PathTransformer::new();
        assert_eq!(pt.as_dist(Path::new("a/b")).unwrap(), "a/b");
        assert_eq!(pt.as_dist(Path::new(r#"a\b"#)).unwrap(), "a/b");
        assert_eq!(pt.to_local("a/b").unwrap(), Path::new("a/b"));
    }

    #[cfg(windows)]
    #[test]
    fn test_verbatim_disks() {
        let mut pt = PathTransformer::new();
        assert_eq!(
            pt.as_dist(Path::new("X:/other.c")).unwrap(),
            "/prefix/disk-X/other.c"
        );
        pt.as_dist(Path::new(r#"\\?\X:\out\other.o"#));
        assert_eq!(
            pt.to_local("/prefix/disk-X/other.c").unwrap(),
            Path::new("X:/other.c")
        );
        assert_eq!(
            pt.to_local("/prefix/disk-X/out/other.o").unwrap(),
            Path::new(r#"\\?\X:\out\other.o"#)
        );
        let disk_mappings: Vec<_> = pt.disk_mappings().collect();
        // Verbatim disks should come last
        assert_eq!(
            disk_mappings,
            &[
                (Path::new("X:").into(), "/prefix/disk-X".into()),
                (Path::new(r#"\\?\X:"#).into(), "/prefix/disk-X".into()),
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_slash_directions() {
        let mut pt = PathTransformer::new();
        assert_eq!(pt.as_dist(Path::new("C:/a")).unwrap(), "/prefix/disk-C/a");
        assert_eq!(pt.as_dist(Path::new("C:\\a")).unwrap(), "/prefix/disk-C/a");
        assert_eq!(pt.to_local("/prefix/disk-C/a").unwrap(), Path::new("C:/a"));
        assert_eq!(pt.disk_mappings().count(), 1);
    }
    #[cfg(unix)]
    #[test]
    fn test_root_mapping() -> crate::errors::Result<()> {
        let mut pt = PathTransformer::new();
        pt.add_root_mapping(PathBuf::from("/physical/project"), "/build");
        assert_eq!(
            pt.as_dist(Path::new("/physical/project/src/lib.rs"))
                .as_deref(),
            Some("/build/src/lib.rs")
        );
        assert_eq!(
            pt.to_local("/build/src/lib.rs")?,
            PathBuf::from("/physical/project/src/lib.rs")
        );
        Ok(())
    }

    #[test]
    fn nested_mapping_precedence_and_root() -> crate::errors::Result<()> {
        let mut transformer = PathTransformer::new();
        #[cfg(windows)]
        let local = Path::new("C:/physical/project");
        #[cfg(unix)]
        let local = Path::new("/physical/project");

        transformer.add_root_mapping(local.join("nested"), "/special/");
        transformer.add_root_mapping(local.to_owned(), "/mapped");
        assert_eq!(
            transformer
                .as_dist_abs(&local.join("nested/file"))
                .as_deref(),
            Some("/special/file")
        );
        assert_eq!(
            transformer.to_local("/special/file")?,
            local.join("nested/file")
        );
        assert_eq!(transformer.as_dist_abs(Path::new("relative")), None);
        transformer.add_root_mapping(local.join("root"), "/");
        assert_eq!(
            transformer.as_dist_abs(&local.join("root")).as_deref(),
            Some("/")
        );
        assert_eq!(
            transformer.as_dist_abs(&local.join("root/file")).as_deref(),
            Some("/file")
        );
        assert!(transformer.to_local("bad\0path").is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn reverse_mapping_uses_distributed_precedence() -> crate::errors::Result<()> {
        let mut transformer = PathTransformer::new();
        transformer.add_root_mapping(PathBuf::from("/physical/deep/project"), "/mapped");
        transformer.add_root_mapping(PathBuf::from("/other"), "/mapped/nested");
        assert_eq!(
            transformer.to_local("/mapped/nested/file")?,
            PathBuf::from("/other/file")
        );
        Ok(())
    }
}

#[must_use = "conversion failure indicates a non-Unicode argument"]
pub fn osstrings_to_strings(osstrings: &[OsString]) -> Option<Vec<String>> {
    osstrings
        .iter()
        .map(|arg| arg.clone().into_string().ok())
        .collect::<Option<_>>()
}

#[must_use = "conversion failure indicates a non-Unicode environment entry"]
pub fn osstring_tuples_to_strings(
    osstring_tuples: &[(OsString, OsString)],
) -> Option<Vec<(String, String)>> {
    osstring_tuples
        .iter()
        .map(|(k, v)| Some((k.clone().into_string().ok()?, v.clone().into_string().ok()?)))
        .collect::<Option<_>>()
}

#[must_use = "the converted argument vector is returned rather than mutated in place"]
pub fn strings_to_osstrings(strings: &[String]) -> Vec<OsString> {
    strings
        .iter()
        .map(|arg| std::ffi::OsStr::new(arg).to_os_string())
        .collect::<Vec<_>>()
}

// TODO: TryFrom
#[must_use = "the result determines whether the compile command is representable on a worker"]
pub fn try_compile_command_to_dist(
    command: compiler::SingleCompileCommand,
) -> Option<CompileCommand> {
    let compiler::SingleCompileCommand {
        executable,
        arguments,
        env_vars,
        cwd,
    } = command;
    Some(CompileCommand {
        umask: crate::util::current_umask(),
        executable: executable.into_os_string().into_string().ok()?,
        arguments: arguments
            .into_iter()
            .map(|arg| arg.into_string().ok())
            .collect::<Option<_>>()?,
        env_vars: env_vars
            .into_iter()
            .map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect::<Option<_>>()?,
        cwd: cwd.into_os_string().into_string().ok()?,
    })
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobId(pub u64);
impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for JobId {
    type Err = <u64 as FromStr>::Err;
    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        u64::from_str(s).map(JobId)
    }
}
pub use sccache_peer_identity::PeerId as ServerId;
#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerNonce(u64);
impl ServerNonce {
    #[must_use = "the generated nonce must identify this worker incarnation"]
    pub fn new() -> Self {
        Self(rand::random())
    }
}

impl Default for ServerNonce {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum JobState {
    Pending,
    Ready,
    Started,
    Complete,
}
impl fmt::Display for JobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Started => "started",
            Self::Complete => "complete",
        }
        .fmt(f)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileCommand {
    pub umask: Option<u32>,
    pub executable: String,
    pub arguments: Vec<String>,
    pub env_vars: Vec<(String, String)>,
    pub cwd: String,
}
impl fmt::Debug for CompileCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let env_var_names: Vec<_> = self.env_vars.iter().map(|(name, _)| name).collect();
        f.debug_struct("CompileCommand")
            .field("executable", &self.executable)
            .field("umask", &self.umask)
            .field("argument_count", &self.arguments.len())
            .field("env_var_names", &env_var_names)
            .field("cwd", &self.cwd)
            .finish()
    }
}

// AllocJob

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobAlloc {
    pub auth: String,
    pub job_id: JobId,
    pub server_id: ServerId,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AllocJobResult {
    Success { job_alloc: JobAlloc },
    Fail { msg: String },
}

// AssignJob

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignJobResult {
    pub state: JobState,
}

// JobState

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum UpdateJobStateResult {
    Success,
    Fail { msg: String },
}

// HeartbeatServer

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatServerResult {
    pub is_new: bool,
    // Includes accepted jobs and assignment RPC reservations.
    pub assigned_job_ids: Vec<JobId>,
}

// Status

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerStatusResult {
    pub num_servers: usize,
    pub num_cpus: usize,
    pub in_progress: usize,
    pub max_jobs: usize,
    pub available_jobs: usize,
}

#[cfg(feature = "dist-server")]
type ExtResult<T, E> = ::std::result::Result<T, E>;

/// Native assignment contains the exact declaration admitted by the cache.
#[cfg(feature = "dist-server")]
#[derive(Clone, Serialize, Deserialize)]
pub struct NativeAssignment {
    pub trace: Option<crate::latency_trace::TraceContext>,
    pub ticket: crate::build_runtime::wire::Ticket,
    pub spec: crate::build_runtime::ExecutionSpec,
    pub input_blobs: NativeInputBlobs,
    /// Scheduler's advisory logical result-size forecast, never a hard limit.
    pub estimated_result_bytes: Option<u64>,
    /// Scheduler-local authenticated requester and advisory delivery telemetry.
    #[serde(skip)]
    pub receiver: Option<(ServerId, crate::build_runtime::wire::ClientDeliveryRates)>,
    #[serde(skip)]
    pub delivery_profile: Option<crate::build_runtime::ContentId>,
}

#[cfg(feature = "dist-server")]
#[async_trait]
pub trait SchedulerOutgoing: Send + Sync {
    // To Server
    /// # Errors
    /// The worker could not be contacted or rejected the assignment.
    async fn do_assign_job(
        &self,
        server_id: ServerId,
        job_id: JobId,
        assignment: NativeAssignment,
        auth: String,
    ) -> Result<AssignJobResult>;
}

#[cfg(feature = "dist-server")]
#[async_trait]
pub trait ServerOutgoing: Send + Sync {
    // To Scheduler
    /// # Errors
    /// The scheduler could not accept or acknowledge the state update.
    async fn do_update_job_state(
        &self,
        job_id: JobId,
        state: JobState,
    ) -> Result<UpdateJobStateResult>;
}

// Trait to handle the creation and verification of job authorization tokens
#[cfg(feature = "dist-server")]
pub trait JobAuthorizer: Send {
    /// # Errors
    /// The job capability could not be signed.
    fn generate_token(&self, job_id: JobId) -> Result<String>;
    /// # Errors
    /// The supplied capability is invalid for the job.
    fn verify_token(&self, job_id: JobId, token: &str) -> Result<()>;
    /// # Errors
    /// The exact-content capability could not be signed.
    fn generate_blob_token(
        &self,
        blob: crate::build_runtime::BlobRef,
        recipient: crate::build_runtime::wire::BlobRecipient,
    ) -> Result<String>;
    /// # Errors
    /// The supplied capability is invalid for the requested content and recipient.
    fn verify_blob_token(
        &self,
        blob: crate::build_runtime::BlobRef,
        recipient: crate::build_runtime::wire::BlobRecipient,
        token: &str,
    ) -> Result<()>;
}

/// A narrowly scoped peer-source capability; never log its token.
#[cfg(feature = "dist-server")]
pub struct NativeBlobSource {
    pub server: ServerId,
    pub token: String,
}

/// Scheduler-owned union of the verified input blobs in an admitted action.
#[cfg(feature = "dist-server")]
pub type NativeInputBlobs = std::collections::BTreeMap<crate::build_runtime::ContentId, u64>;

/// Verified progress for one worker reservation; durations are relative to
/// the heartbeat snapshot, not synchronized wall clocks.
#[cfg(feature = "dist-server")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeJobProgress {
    pub phase: crate::build_runtime::wire::NativeJobPhase,
    pub phase_nanoseconds: u64,
    pub remaining_input_bytes: u64,
    pub remaining_input_blobs: u64,
}

/// Bounded snapshot of the worker-owned pipeline, including terminal
/// responses still occupying reservation capacity.
#[cfg(feature = "dist-server")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeQueueSnapshot {
    pub capacity: u32,
    pub compiler_slots: u32,
    pub compiler_active: u32,
    pub staging_slots: u32,
    pub publication_slots: u32,
    pub jobs: std::collections::BTreeMap<JobId, NativeJobProgress>,
}

#[cfg(feature = "dist-server")]
impl NativeQueueSnapshot {
    pub const MAX_CAPACITY: u32 = 65_536;

    #[must_use = "invalid telemetry must not drive scheduling"]
    pub fn valid(&self) -> bool {
        (1..=Self::MAX_CAPACITY).contains(&self.capacity)
            && (1..=Self::MAX_CAPACITY).contains(&self.compiler_slots)
            && self.compiler_active <= self.compiler_slots
            && (1..=self.capacity).contains(&self.staging_slots)
            && (1..=self.capacity).contains(&self.publication_slots)
            && self.jobs.len() <= self.capacity as usize
            && self.jobs.values().all(|job| {
                !job.phase.inputs_ready()
                    || (job.remaining_input_bytes == 0 && job.remaining_input_blobs == 0)
            })
    }

    #[must_use = "the dispatcher must have room for an additional reservation"]
    pub fn has_capacity(&self, assigned: impl Iterator<Item = JobId>) -> bool {
        self.available_reservations(assigned) != 0
    }

    #[must_use = "unobserved reservations and terminal replies also consume local capacity"]
    pub fn available_reservations(&self, assigned: impl Iterator<Item = JobId>) -> usize {
        let unobserved = assigned.filter(|id| !self.jobs.contains_key(id)).count();
        (self.capacity as usize).saturating_sub(self.jobs.len().saturating_add(unobserved))
    }

    #[must_use = "compiler admission excludes publication-only reservations"]
    pub fn compiler_demand(&self, assigned: impl Iterator<Item = JobId>) -> usize {
        let local = self
            .jobs
            .values()
            .filter(|job| job.phase.needs_compiler())
            .count();
        // Unknown scheduler reservations include legacy jobs and native
        // assignments made since the snapshot. Orphaned local reservations
        // still compete until their cancellation has drained.
        local.saturating_add(assigned.filter(|id| !self.jobs.contains_key(id)).count())
    }
}

#[cfg(feature = "dist-server")]
impl Default for NativeQueueSnapshot {
    fn default() -> Self {
        Self {
            capacity: Self::MAX_CAPACITY,
            compiler_slots: Self::MAX_CAPACITY,
            compiler_active: 0,
            staging_slots: Self::MAX_CAPACITY,
            publication_slots: Self::MAX_CAPACITY,
            jobs: std::collections::BTreeMap::new(),
        }
    }
}

/// Advisory worker telemetry, never part of action identity or verification.
#[cfg(feature = "dist-server")]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativePlacement {
    pub cache_analytics: Option<crate::build_runtime::analytics::CacheSiteSummary>,
    pub package_limits: Option<crate::build_runtime::PackageDeliveryLimits>,
    pub residency: Option<crate::build_runtime::BlobResidency>,
    pub timing: crate::build_runtime::wire::WorkerTiming,
    pub cache_path_rates: crate::build_runtime::wire::CachePathRates,
    pub peer_download_rates: Vec<crate::build_runtime::wire::PeerDownloadRate>,
    pub interfaces: crate::build_runtime::wire::InterfaceReport,
    pub queue: NativeQueueSnapshot,
}

/// Authenticated native action lifecycle observations, emitted only after
/// the corresponding session operation has succeeded.
#[cfg(feature = "dist-server")]
pub enum NativeLifecycleEvent<'a> {
    Delivered(crate::build_runtime::DeliveryReceipt),
    InputsStaged,
    Negotiated,
    Committed {
        manifest: &'a crate::build_runtime::ResultManifest,
        retained_after_begin: std::time::Duration,
        observation: Option<crate::build_runtime::wire::ActionObservation>,
    },
}

/// Worker build engines advertised atomically with its scheduler heartbeat.
#[cfg(feature = "dist-server")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerCapabilities {
    pub native_platform: Option<crate::build_runtime::ContentId>,
    pub native_placement: Option<NativePlacement>,
}

#[cfg(feature = "dist-server")]
#[async_trait]
pub trait SchedulerIncoming: Send + Sync + 'static {
    /// Allocate a native action from the shared worker capacity pool.
    ///
    /// # Errors
    /// Returns an error if allocation or assignment fails.
    async fn handle_alloc_native_job(
        self: std::sync::Arc<Self>,
        requester: &dyn SchedulerOutgoing,
        assignment: NativeAssignment,
        network: &crate::build_runtime::NetworkSnapshot,
        packages: std::sync::Arc<crate::build_runtime::PackageCatalog>,
    ) -> ExtResult<AllocJobResult, Error>;
    /// Select likely sources for a missing exact blob without allocating a job.
    /// # Errors
    /// The scheduler could not access worker state or sign a source capability.
    fn native_blob_sources(
        &self,
        blob: crate::build_runtime::BlobRef,
        requester: Option<ServerId>,
        recipient: crate::build_runtime::wire::BlobRecipient,
        producer: Option<ServerId>,
        recovery_network: Option<&crate::build_runtime::NetworkSnapshot>,
    ) -> ExtResult<Vec<NativeBlobSource>, Error>;
    /// Record advisory producer residency for the current worker epoch.
    fn observe_native_lifecycle(
        &self,
        server_id: ServerId,
        job: JobId,
        event: NativeLifecycleEvent<'_>,
    );
    // From Server
    /// # Errors
    /// Worker state could not be validated or updated.
    fn handle_heartbeat_server(
        &self,
        server_id: ServerId,
        server_nonce: ServerNonce,
        cpu_capacity: f64,
        active_job_ids: &[JobId],
        job_authorizer: Box<dyn JobAuthorizer>,
        capabilities: WorkerCapabilities,
    ) -> ExtResult<HeartbeatServerResult, Error>;
    // From Server, best-effort observability metadata.
    /// # Errors
    /// Worker metadata could not be updated.
    fn handle_update_worker_name(
        &self,
        _server_id: ServerId,
        _server_nonce: ServerNonce,
        _worker_name: String,
    ) -> ExtResult<(), Error> {
        Ok(())
    }
    // From Client, best-effort observability metadata.
    /// # Errors
    /// Worker metadata could not be read.
    fn handle_get_worker_name(&self, _server_id: ServerId) -> ExtResult<Option<String>, Error> {
        Ok(None)
    }
    // From Server
    /// # Errors
    /// The job is unknown or its state transition is invalid.
    fn handle_update_job_state(
        &self,
        job_id: JobId,
        server_id: ServerId,
        job_state: JobState,
    ) -> ExtResult<UpdateJobStateResult, Error>;
    // From anyone
    /// # Errors
    /// Scheduler state could not be read.
    fn handle_status(&self) -> ExtResult<SchedulerStatusResult, Error>;
    #[cfg(feature = "scheduler-dashboard")]
    /// # Errors
    /// Scheduler status could not be collected.
    fn handle_dashboard_snapshot(&self) -> ExtResult<sccache_dashboard::Snapshot, Error>;
    #[cfg(feature = "scheduler-dashboard")]
    /// # Errors
    /// The dashboard wake channel could not be registered.
    fn install_dashboard_waker(
        &self,
        sender: std::sync::mpsc::SyncSender<()>,
    ) -> ExtResult<(), Error>;
    // Additive maintenance metadata. Existing scheduler implementations remain
    // non-draining unless they explicitly opt into a drain source.
    fn handle_is_draining(&self) -> bool {
        false
    }
}

#[cfg(feature = "dist-server")]
pub trait ServerIncoming: Send + Sync {
    /// Compiler slots in use, excluding jobs waiting for input or a slot.
    fn executing_jobs(&self) -> usize;
    fn capabilities(&self) -> WorkerCapabilities;
    fn native_metadata_limit(&self) -> Option<usize>;
    /// Open an exact local CAS blob for an authenticated scheduler request.
    /// # Errors
    /// The local content store could not read the exact blob.
    fn handle_native_blob(
        &self,
        blob: crate::build_runtime::BlobRef,
    ) -> ExtResult<Option<(std::fs::File, crate::build_runtime::BlobEncoding)>, Error>;
    /// Accept an immutable native action assignment.
    ///
    /// # Errors
    /// Returns an error for incompatible platforms or duplicate assignments.
    fn handle_assign_native_job(
        &self,
        requester: std::sync::Arc<dyn ServerOutgoing>,
        job_id: JobId,
        assignment: NativeAssignment,
    ) -> ExtResult<AssignJobResult, Error>;
    /// Observe an already dispatched native action without blocking for compilation.
    ///
    /// # Errors
    /// Returns an error if execution, scheduler reporting or publication fails.
    fn handle_run_native_job(
        &self,
        job_id: JobId,
        request: crate::build_runtime::wire::NativeRunRequest,
    ) -> ExtResult<crate::build_runtime::wire::NativeRunResult, Error>;
    // Reconcile scheduler-side reservations against local unclaimed jobs.
    // The cutoff predates the heartbeat request; later assignments must survive.
    /// # Errors
    /// Worker reservations could not be reconciled.
    fn handle_reconcile_assignments(
        &self,
        assigned_job_ids: &[JobId],
        heartbeat_started_at: std::time::Instant,
    ) -> ExtResult<usize, Error>;
}
