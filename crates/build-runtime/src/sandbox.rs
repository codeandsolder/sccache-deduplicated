//! Linux execution policy shared by local build orchestration and workers.
//!
//! Host paths are materialization details. The command's component digests
//! and the logical mount layout can be included in an action fingerprint;
//! content identities of mounted trees must be supplied separately.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::{BuildPath, CommandSpec, ContentId, identity::typed_digest};

/// Canonical absolute path in the isolated mount namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SandboxPath(PathBuf);

impl SandboxPath {
    /// Reject ambiguous or escaping paths before constructing a mount.
    ///
    /// # Errors
    /// Returns an error for a relative path, parent traversal or a NUL byte.
    pub fn new(path: &Path) -> Result<Self> {
        ensure!(path.is_absolute(), "sandbox path must be absolute");
        ensure!(
            !path.as_os_str().as_bytes().contains(&0)
                && path.components().all(|component| matches!(
                    component,
                    Component::RootDir | Component::Normal(_)
                )),
            "invalid sandbox path: {}",
            path.display()
        );
        Ok(Self(path.components().collect()))
    }

    #[must_use = "the path identifies the sandbox location"]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Write permissions of a mount in the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MountAccess {
    ReadOnly,
    Writable,
}

impl MountAccess {
    const fn argument(self) -> &'static str {
        match self {
            Self::ReadOnly => "--ro-bind",
            Self::Writable => "--bind",
        }
    }
}

#[derive(Debug)]
enum Mount {
    Bind {
        source: PathBuf,
        access: MountAccess,
    },
    Tmpfs,
}

#[derive(Serialize)]
enum MountKind {
    Bind(MountAccess),
    Tmpfs,
}

impl Mount {
    const fn kind(&self) -> MountKind {
        match self {
            Self::Bind { access, .. } => MountKind::Bind(*access),
            Self::Tmpfs => MountKind::Tmpfs,
        }
    }

    fn append(&self, command: &mut Command, destination: &SandboxPath) {
        match self {
            Self::Bind { source, access } => {
                command
                    .arg(access.argument())
                    .arg(source)
                    .arg(destination.as_path());
            }
            Self::Tmpfs => {
                command.arg("--tmpfs").arg(destination.as_path());
            }
        }
    }
}

/// Materialized root and explicit bindings for a single isolated invocation.
///
/// The caller owns the lifetime of the materialized root and mounted files.
/// Use a separate writable output/scratch directory for immutable roots.
/// The ordinary worker overlay is a writable root over immutable toolchain
/// files; it does not need a separate execution-policy implementation.
#[derive(Debug)]
pub struct SandboxPlan {
    root: PathBuf,
    root_access: MountAccess,
    mounts: BTreeMap<SandboxPath, Mount>,
}

impl SandboxPlan {
    /// Construct an isolated mount plan for an existing prepared root.
    ///
    /// # Errors
    /// Returns an error if the root is unavailable, not a directory, or is
    /// the host filesystem root.
    pub fn new(root: &Path, root_access: MountAccess) -> Result<Self> {
        let root = canonical_source(root)?;
        ensure!(root.is_dir(), "sandbox root must be a directory");
        Ok(Self {
            root,
            root_access,
            mounts: BTreeMap::new(),
        })
    }

    /// Bind an additional materialized file or tree at a logical path.
    ///
    /// # Errors
    /// Returns an error for an invalid source or conflicting destination.
    pub fn bind(
        &mut self,
        source: &Path,
        destination: SandboxPath,
        access: MountAccess,
    ) -> Result<()> {
        self.insert_mount(
            destination,
            Mount::Bind {
                source: canonical_source(source)?,
                access,
            },
        )
    }

    /// Add private scratch storage at a logical path.
    ///
    /// # Errors
    /// Returns an error for conflicting or reserved destinations.
    pub fn tmpfs(&mut self, destination: SandboxPath) -> Result<()> {
        self.insert_mount(destination, Mount::Tmpfs)
    }

    fn insert_mount(&mut self, destination: SandboxPath, mount: Mount) -> Result<()> {
        let path = destination.as_path();
        ensure!(
            path != Path::new("/") && !path.starts_with("/proc") && !path.starts_with("/dev"),
            "sandbox mount destination is reserved: {}",
            path.display()
        );
        match self.mounts.entry(destination) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(mount);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                anyhow::bail!(
                    "duplicate sandbox mount: {}",
                    entry.key().as_path().display()
                )
            }
        }
    }

    /// Hash mount destinations and permissions, but not host source paths.
    /// The caller must additionally identify all bound content and initial
    /// writable state before using a cache key.
    ///
    /// # Errors
    /// Returns an error if encoding the layout fails.
    pub fn layout_fingerprint(&self) -> Result<ContentId> {
        let mounts: Vec<_> = self
            .mounts
            .iter()
            .map(|(path, mount)| (path.as_path().as_os_str().as_bytes(), mount.kind()))
            .collect();
        Ok(ContentId(typed_digest(
            b"sccache-linux-sandbox-v1\0",
            &(self.root_access, mounts),
        )?))
    }

    /// Build an isolated Bubblewrap command from this plan.
    ///
    /// Both the launcher and the process inside the namespace start with an
    /// empty inherited environment. Network and nested user namespaces are
    /// disabled. Bind mounts are ordered so parents precede children.
    ///
    /// # Errors
    /// Returns an error if the Bubblewrap launcher is not an absolute path.
    pub fn command(&self, bubblewrap: &Path, invocation: &SandboxInvocation) -> Result<Command> {
        ensure!(
            bubblewrap.is_absolute(),
            "bubblewrap launcher must be absolute"
        );
        let mut command = Command::new(bubblewrap);
        let mask = rustix::fs::Mode::from_bits_truncate(invocation.umask);
        // SAFETY: umask is an async-signal-safe syscall; the child alone
        // changes its creation mask before exec, never the worker process.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut command, move || {
                rustix::process::umask(mask);
                Ok(())
            });
        }
        command.env_clear().args([
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--unshare-user",
            "--unshare-cgroup",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-uts",
            "--disable-userns",
            "--uid",
            "1000",
            "--gid",
            "1000",
            "--hostname",
            "sccache-build",
        ]);
        command
            .arg(self.root_access.argument())
            .arg(&self.root)
            .arg("/");
        for (destination, mount) in &self.mounts {
            mount.append(&mut command, destination);
        }
        // Mount after the root so the root cannot hide these namespaces.
        command
            .args(["--proc", "/proc", "--dev", "/dev"])
            .arg("--chdir")
            .arg(invocation.cwd.as_path())
            .arg("--clearenv");
        for (name, value) in &invocation.environment {
            command.arg("--setenv").arg(name).arg(value);
        }
        command
            .arg("--")
            .arg(&invocation.executable)
            .args(&invocation.arguments);
        Ok(command)
    }
}

fn canonical_source(source: &Path) -> Result<PathBuf> {
    ensure!(source.is_absolute(), "sandbox bind source must be absolute");
    let source = fs::canonicalize(source)
        .with_context(|| format!("resolve sandbox bind source {}", source.display()))?;
    ensure!(
        source != Path::new("/"),
        "refusing to expose the host filesystem root"
    );
    let metadata = fs::metadata(&source)?;
    ensure!(
        metadata.is_file() || metadata.is_dir(),
        "sandbox bind source must be a file or directory"
    );
    Ok(source)
}

/// Explicit process inputs. Unlike the old distributed string transport, this
/// retains names and values as native OS bytes, including non-UTF-8 data and
/// the distinction between absence and an empty value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxInvocation {
    umask: u32,
    executable: OsString,
    arguments: Vec<OsString>,
    cwd: SandboxPath,
    environment: BTreeMap<OsString, OsString>,
}

impl SandboxInvocation {
    /// Validate the command and construct its complete explicit environment.
    ///
    /// # Errors
    /// Returns an error for malformed process arguments, duplicate/invalid
    /// environment names, or an invalid working directory.
    pub fn new(
        executable: OsString,
        arguments: Vec<OsString>,
        cwd: &Path,
        environment: impl IntoIterator<Item = (OsString, OsString)>,
        umask: u32,
    ) -> Result<Self> {
        ensure!(
            !executable.is_empty() && valid_os(&executable),
            "invalid sandbox executable"
        );
        ensure!(
            arguments.iter().all(|arg| valid_os(arg)),
            "sandbox argument contains NUL"
        );
        ensure!(umask <= 0o777, "invalid sandbox umask");
        let mut explicit = BTreeMap::new();
        for (name, value) in environment {
            ensure!(
                !name.is_empty() && valid_os(&name) && !name.as_bytes().contains(&b'='),
                "invalid environment variable name"
            );
            ensure!(valid_os(&value), "environment value contains NUL");
            ensure!(
                explicit.insert(name, value).is_none(),
                "duplicate environment variable"
            );
        }
        Ok(Self {
            umask,
            executable,
            arguments,
            cwd: SandboxPath::new(cwd)?,
            environment: explicit,
        })
    }

    /// Construct the actual invocation from the portable action declaration.
    ///
    /// # Errors
    /// Returns an error if the declaration is invalid.
    pub fn from_spec(spec: &CommandSpec) -> Result<Self> {
        spec.validate()?;
        Self::new(
            OsStr::from_bytes(spec.executable.as_bytes()).to_os_string(),
            spec.arguments
                .iter()
                .map(|arg| OsStr::from_bytes(arg).to_os_string())
                .collect(),
            Path::new(OsStr::from_bytes(spec.cwd.as_bytes())),
            spec.environment.iter().map(|(key, value)| {
                (
                    OsStr::from_bytes(key).to_os_string(),
                    OsStr::from_bytes(value).to_os_string(),
                )
            }),
            spec.umask,
        )
    }

    /// Per-component digests for exact command and environment differences.
    ///
    /// # Errors
    /// Returns an error for invalid or unencodable process inputs.
    pub fn input_components(&self) -> Result<BTreeMap<String, ContentId>> {
        CommandSpec {
            umask: self.umask,
            executable: BuildPath::new(self.executable.as_bytes().to_vec())?,
            arguments: self
                .arguments
                .iter()
                .map(|arg| arg.as_bytes().to_vec())
                .collect(),
            cwd: BuildPath::new(self.cwd.as_path().as_os_str().as_bytes().to_vec())?,
            environment: self
                .environment
                .iter()
                .map(|(key, value)| (key.as_bytes().to_vec(), value.as_bytes().to_vec()))
                .collect(),
        }
        .input_components()
    }
}

fn valid_os(value: &OsStr) -> bool {
    !value.as_bytes().contains(&0)
}

#[cfg(test)]
mod tests;
