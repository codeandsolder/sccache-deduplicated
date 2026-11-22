//! Rust native-link capture. This is a stage primitive, not a replacement
//! for rustc's linker selection or the compiler's ordinary output contract.
use crate::errors::{Context, Result, bail};
use crate::util::Digest;
use anyhow::ensure;
use fs_err as fs;
use fs_err::os::unix::fs::OpenOptionsExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use walkdir::WalkDir;

const RELAY_DIRECTORY: &str = ".sccache-link-relay";
const CONFIG_FILE: &str = "capture.bin";
const INVOCATION_FILE: &str = "invocation.bin";
const VERSION: u32 = 1;

/// Compiler environments and link arguments preserve native OS strings.
pub type LinkEnvironment = BTreeMap<OsString, OsString>;

/// A private writable compiler root and the logical path at which its
/// contents must be restored for native linking.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotRoot {
    pub logical: OsString,
    pub source: OsString,
}

/// Caller-provided resource budget, applied to the entire snapshot of each
/// native invocation. No assumptions about codegen-unit counts or suffixes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct CaptureLimits {
    pub files: u64,
    pub bytes: u64,
    pub invocations: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub roots: Vec<SnapshotRoot>,
    pub destination: OsString,
    pub compiler_environment: LinkEnvironment,
    pub limits: CaptureLimits,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkInvocation {
    version: u32,
    args: Vec<OsString>,
    cwd: OsString,
    compiler_environment_key: String,
    environment_delta: Vec<(OsString, Option<OsString>)>,
    roots: Vec<OsString>,
}

fn environment_key(environment: &LinkEnvironment) -> String {
    let mut digest = Digest::new();
    digest.delimiter(b"rust-native-link-environment-v1");
    for (key, value) in environment {
        digest.delimiter(key.as_encoded_bytes());
        digest.delimiter(value.as_encoded_bytes());
    }
    digest.finish()
}

fn environment_delta(
    baseline: &LinkEnvironment,
    actual: LinkEnvironment,
) -> Vec<(OsString, Option<OsString>)> {
    let mut delta = baseline
        .keys()
        .filter(|key| !actual.contains_key(*key))
        .map(|key| (key.clone(), None))
        .collect::<Vec<_>>();
    delta.extend(actual.into_iter().filter_map(|(key, value)| {
        (baseline.get(&key) != Some(&value)).then_some((key, Some(value)))
    }));
    delta
}

impl CaptureConfig {
    /// Install a relay under the selected linker's original basename so
    /// rustc's filename-based linker flavor inference is not changed.
    /// The capture destination and source roots are interpreted by the
    /// compiler's namespace, not the installer.
    ///
    /// # Errors
    /// Invalid configuration or filesystem setup failure.
    pub fn install(
        &self,
        executable: &Path,
        relay_parent: &Path,
        linker_basename: &OsStr,
    ) -> Result<PathBuf> {
        let mut components = Path::new(linker_basename).components();
        ensure!(
            matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none(),
            "linker basename must be one path component"
        );
        self.validate()?;
        let relay = relay_parent.join(RELAY_DIRECTORY);
        std::fs::DirBuilder::new().mode(0o700).create(&relay)?;
        let config = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(relay.join(CONFIG_FILE))?;
        bincode::serialize_into(config, self)?;
        let path = relay.join(linker_basename);
        std::os::unix::fs::symlink(executable, &path)?;
        Ok(path)
    }

    fn validate(&self) -> Result<()> {
        ensure!(!self.roots.is_empty(), "capture has no generated roots");
        ensure!(
            Path::new(&self.destination).is_absolute(),
            "capture destination must be absolute"
        );
        let mut roots = std::collections::BTreeSet::new();
        for root in &self.roots {
            ensure!(
                Path::new(&root.logical).is_absolute() && Path::new(&root.source).is_absolute(),
                "capture roots must be absolute"
            );
            ensure!(
                roots.insert(&root.logical),
                "duplicate logical capture root"
            );
        }
        ensure!(
            self.limits.files > 0 && self.limits.bytes > 0 && self.limits.invocations > 0,
            "capture limits must be positive"
        );
        Ok(())
    }

    fn capture(self, args: Vec<OsString>) -> Result<()> {
        self.validate()?;
        let destination = fs::canonicalize(&self.destination)?;
        for root in &self.roots {
            let source = fs::canonicalize(&root.source)?;
            ensure!(
                !destination.starts_with(&source),
                "capture destination overlaps generated inputs"
            );
        }
        let invocation_dir = reserve_invocation(&destination, self.limits.invocations)?;
        let invocation = LinkInvocation {
            version: VERSION,
            args,
            cwd: std::env::current_dir()?.into_os_string(),
            compiler_environment_key: environment_key(&self.compiler_environment),
            environment_delta: environment_delta(
                &self.compiler_environment,
                std::env::vars_os().collect(),
            ),
            roots: self.roots.iter().map(|root| root.logical.clone()).collect(),
        };
        let mut budget = Budget::new(self.limits);
        for (index, root) in self.roots.iter().enumerate() {
            snapshot_root(
                Path::new(&root.source),
                &invocation_dir.join(root_archive(index)),
                &mut budget,
            )?;
        }

        // This is the commit marker. A compiler failure or interruption can
        // leave staging directories but never advertises a complete bundle.
        fs::write(
            invocation_dir.join(INVOCATION_FILE),
            bincode::serialize(&invocation)?,
        )?;
        Ok(())
    }
}

fn reserve_invocation(destination: &Path, limit: u32) -> Result<PathBuf> {
    for index in 0..limit {
        let path = destination.join(format!("invocation-{index:010}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    bail!("native linker invocation count exceeded")
}

fn root_archive(index: usize) -> String {
    format!("root-{index}.tar")
}

struct Budget {
    files: u64,
    bytes: u64,
}

impl Budget {
    const fn new(limits: CaptureLimits) -> Self {
        Self {
            files: limits.files,
            bytes: limits.bytes,
        }
    }

    fn consume(&mut self, bytes: u64) -> Result<()> {
        self.files = self
            .files
            .checked_sub(1)
            .context("generated file count exceeded")?;
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .context("generated data size exceeded")?;
        Ok(())
    }
}

fn snapshot_root(root: &Path, archive: &Path, budget: &mut Budget) -> Result<()> {
    let mut builder = tar::Builder::new(fs::File::create(archive)?);
    builder.follow_symlinks(false);
    for entry in WalkDir::new(root).min_depth(1).sort_by_file_name() {
        let entry = entry?;
        let path = entry.path();
        let relative = path.strip_prefix(root)?;
        let metadata = fs::symlink_metadata(path)?;
        let file_type = metadata.file_type();
        ensure!(
            file_type.is_file() || file_type.is_dir() || file_type.is_symlink(),
            "unsupported generated filesystem object {}",
            path.display()
        );
        budget.consume(if file_type.is_file() {
            metadata.len()
        } else {
            0
        })?;
        builder.append_path_with_name(path, relative)?;
    }
    builder.finish()?;
    Ok(())
}

fn restore_root(archive: &Path, destination: &Path, budget: &mut Budget) -> Result<()> {
    ensure!(
        fs::read_dir(destination)?.next().is_none(),
        "link staging directory must be empty"
    );
    let mut file = fs::File::open(archive)?;
    let mut reader = tar::Archive::new(&mut file);
    for entry in reader.entries()? {
        let entry = entry?;
        let kind = entry.header().entry_type();
        ensure!(
            kind.is_file() || kind.is_dir() || kind.is_symlink(),
            "invalid generated snapshot entry type"
        );
        ensure!(
            entry
                .path()?
                .components()
                .all(|part| matches!(part, Component::Normal(_) | Component::CurDir)),
            "invalid generated snapshot path"
        );
        budget.consume(entry.size())?;
    }
    file.seek(SeekFrom::Start(0))?;
    tar::Archive::new(file).unpack(destination)?;
    Ok(())
}

impl LinkInvocation {
    /// Load the committed invocation manifest. The caller owns the archive
    /// directory and must mount restored roots at their original logical paths.
    ///
    /// # Errors
    /// Missing, malformed or unsupported invocation manifest.
    pub fn load(directory: &Path) -> Result<Self> {
        let invocation: Self =
            bincode::deserialize_from(fs::File::open(directory.join(INVOCATION_FILE))?)?;
        ensure!(
            invocation.version == VERSION,
            "unsupported native link manifest version"
        );
        Ok(invocation)
    }

    /// Restore each generated root into a distinct empty private directory.
    /// External libraries and paths not in the snapshot remain caller-owned.
    ///
    /// # Errors
    /// Incorrect root mapping, invalid snapshot, exceeded budget or I/O error.
    pub fn restore(
        &self,
        directory: &Path,
        destinations: &BTreeMap<OsString, PathBuf>,
        limits: CaptureLimits,
    ) -> Result<()> {
        ensure!(
            self.roots.len() == destinations.len(),
            "link snapshot root mapping is incomplete"
        );
        let mut budget = Budget::new(limits);
        for (index, root) in self.roots.iter().enumerate() {
            let destination = destinations
                .get(root)
                .context("missing link snapshot root")?;
            restore_root(
                &directory.join(root_archive(index)),
                destination,
                &mut budget,
            )?;
        }
        Ok(())
    }

    /// Construct the exact native linker invocation. The compiler environment
    /// is part of the codegen identity: a different baseline requires
    /// regenerating the plan instead of applying stale environment overrides.
    /// Argument bytes are not interpreted or rewritten.
    ///
    /// # Errors
    /// The current compiler environment does not match the captured baseline.
    pub fn command(&self, linker: &Path, environment: &LinkEnvironment) -> Result<Command> {
        ensure!(
            environment_key(environment) == self.compiler_environment_key,
            "native link compiler environment changed"
        );
        let mut command = Command::new(linker);
        command
            .args(&self.args)
            .current_dir(&self.cwd)
            .env_clear()
            .envs(environment);
        for (key, value) in &self.environment_delta {
            if let Some(value) = value {
                command.env(key, value);
            } else {
                command.env_remove(key);
            }
        }
        Ok(command)
    }

    /// Execute native linking using the current namespace's actual linker.
    ///
    /// # Errors
    /// The environment differs from capture or the linker could not be run.
    pub fn replay(&self, linker: &Path, environment: &LinkEnvironment) -> Result<Output> {
        Ok(self.command(linker, environment)?.output()?)
    }
}

/// Private generated output tree over the original logical compiler output
/// directory. The lower directory remains visible for input dependencies and
/// is never mutated by either compilation stage. The generated delta is the
/// artifact: it contains no unchanged dependency files from the lower tree.
pub struct PrivateOutputTree {
    root: tempfile::TempDir,
    upper: PathBuf,
    work: PathBuf,
}

impl PrivateOutputTree {
    /// Allocate a private overlay upper/work pair under the supplied staging
    /// parent, keeping both directories on the same filesystem.
    ///
    /// # Errors
    /// The staging directories cannot be created.
    pub fn new(parent: &Path) -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("rust-output-stage-")
            .tempdir_in(parent)?;
        let upper = root.path().join("upper");
        let work = root.path().join("work");
        fs::create_dir(&upper)?;
        fs::create_dir(&work)?;
        Ok(Self { root, upper, work })
    }

    /// Build the Bubblewrap overlay operation preserving the original path.
    /// The returned arguments must precede the sandbox command separator.
    ///
    /// # Errors
    /// A source or destination path is unsuitable for private staging.
    pub fn overlay_arguments(&self, lower: &Path, logical: &Path) -> Result<Vec<OsString>> {
        ensure!(
            lower.is_absolute() && logical.is_absolute(),
            "stage paths must be absolute"
        );
        let lower = fs::canonicalize(lower)?;
        ensure!(lower.is_dir(), "output stage lower is not a directory");
        ensure!(
            !self.root.path().starts_with(&lower) && !lower.starts_with(self.root.path()),
            "stage storage overlaps the output tree"
        );
        Ok(vec![
            "--overlay-src".into(),
            lower.into_os_string(),
            "--overlay".into(),
            self.upper.clone().into_os_string(),
            self.work.clone().into_os_string(),
            logical.as_os_str().to_owned(),
        ])
    }

    /// The files generated by the compiler, excluding unchanged lower inputs.
    #[must_use = "the generated root is needed for artifact collection"]
    pub fn generated_root(&self) -> &Path {
        &self.upper
    }

    /// Serialize the generated tree. The compiler must have exited and its
    /// mount namespace must have been destroyed before this operation.
    ///
    /// # Errors
    /// Unsupported filesystem object, exceeded limits or I/O failure.
    pub fn archive(&self, destination: &Path, limits: CaptureLimits) -> Result<()> {
        snapshot_root(&self.upper, destination, &mut Budget::new(limits))
    }

    /// Restore a cached generated tree into this new, private upper directory.
    ///
    /// # Errors
    /// Invalid snapshot, nonempty destination, exceeded limits or I/O failure.
    pub fn restore(&self, archive: &Path, limits: CaptureLimits) -> Result<()> {
        restore_root(archive, &self.upper, &mut Budget::new(limits))
    }
}

/// The normal sccache executable also acts as an explicitly installed relay.
/// Its name inside the reserved directory is the original linker basename.
pub(crate) fn capture_if_relay() -> Option<Result<()>> {
    let mut args = std::env::args_os();
    let invoked = PathBuf::from(args.next()?);
    let parent = invoked.parent()?;
    if parent.file_name()? != RELAY_DIRECTORY {
        return None;
    }
    Some((|| {
        let config: CaptureConfig =
            bincode::deserialize_from(fs::File::open(parent.join(CONFIG_FILE))?)?;
        config.capture(args.collect())
    })())
}
