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

use crate::cache::FileObjectSource;
#[cfg(target_os = "linux")]
use crate::compiler::CompileCommandImpl;
use crate::compiler::args::*;
use crate::compiler::canonical_paths::CanonicalRustPaths;
use crate::compiler::{
    CCompileCommand, Cacheable, ColorMode, Compilation, CompileCommand, Compiler,
    CompilerArguments, CompilerHasher, CompilerKind, CompilerProxy, GenerateHashKeyContext,
    HashResult, Language, SingleCompileCommand, c::ArtifactDescriptor,
};
#[cfg(feature = "dist-client")]
use crate::compiler::{DistPackagers, OutputsRewriter};
#[cfg(feature = "dist-client")]
use crate::dist::pkg;
#[cfg(feature = "dist-client")]
use crate::lru_disk_cache::{LruCache, Meter};
use crate::mock_command::{CommandCreatorSync, RunCommand};
use crate::util::{Digest, fmt_duration_as_secs, hash_all, hash_all_archives, run_input_output};
use crate::util::{HashToDigest, OsStrExt};
use crate::{counted_array, dist};
use async_trait::async_trait;
use filetime::FileTime;
use fs_err as fs;
use log::Level::Trace;
#[cfg(feature = "dist-client")]
use semver::Version;
use serde::Serialize;
#[cfg(feature = "dist-client")]
use std::borrow::Borrow;
use std::borrow::Cow;
#[cfg(feature = "dist-client")]
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::env::consts::DLL_EXTENSION;
#[cfg(feature = "dist-client")]
use std::env::consts::DLL_PREFIX;
use std::env::consts::EXE_EXTENSION;
use std::ffi::OsString;
use std::fmt;
use std::fs::OpenOptions;
use std::future::Future;
use std::hash::Hash;
#[cfg(feature = "dist-client")]
use std::io;
use std::io::{BufReader, Read, Write};
use std::iter;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process;
#[cfg(feature = "dist-client")]
use std::sync::Arc;
use std::sync::LazyLock;
#[cfg(feature = "dist-client")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time;

use crate::errors::*;

#[cfg(feature = "dist-client")]
const RLIB_PREFIX: &str = "lib";
#[cfg(feature = "dist-client")]
const RLIB_EXTENSION: &str = "rlib";

#[cfg(feature = "dist-client")]
const RMETA_EXTENSION: &str = "rmeta";

/// Directory in the sysroot containing binary to which rustc is linked.
const BINS_DIR: &str = "bin";

/// Directory in the sysroot containing shared libraries to which rustc is linked.
#[cfg(not(windows))]
const LIBS_DIR: &str = "lib";

/// Directory in the sysroot containing shared libraries to which rustc is linked.
#[cfg(windows)]
const LIBS_DIR: &str = "bin";

/// A struct on which to hang a `Compiler` impl.
#[derive(Debug, Clone)]
pub struct Rust {
    /// The path to the rustc executable.
    executable: PathBuf,
    /// The host triple for this rustc.
    host: String,
    /// The verbose version for this rustc.
    ///
    /// Hash calculation will take this version into consideration to prevent
    /// cached object broken after version bump.
    ///
    /// Looks like the following:
    ///
    /// ```shell
    /// :) rustc -vV
    /// rustc 1.66.1 (90743e729 2023-01-10)
    /// binary: rustc
    /// commit-hash: 90743e7298aca107ddaa0c202a4d3604e29bfeb6
    /// commit-date: 2023-01-10
    /// host: x86_64-unknown-linux-gnu
    /// release: 1.66.1
    /// LLVM version: 15.0.2
    /// ```
    version: String,
    /// The path to the rustc sysroot.
    sysroot: PathBuf,
    /// The digests of all the shared libraries in rustc's $sysroot/lib (or /bin on Windows).
    compiler_shlibs_digests: Vec<String>,
    /// A shared, caching reader for rlib dependencies
    #[cfg(feature = "dist-client")]
    rlib_dep_reader: Option<Arc<RlibDepReader>>,
}

/// A struct on which to hang a `CompilerHasher` impl.
#[derive(Debug, Clone)]
pub struct RustHasher {
    /// The path to the rustc executable, not the rustup proxy.
    executable: PathBuf,
    /// The host triple for this rustc.
    host: String,
    /// The version for this rustc.
    version: String,
    /// The path to the rustc sysroot.
    sysroot: PathBuf,
    /// The digests of all the shared libraries in rustc's $sysroot/lib (or /bin on Windows).
    compiler_shlibs_digests: Vec<String>,
    /// A shared, caching reader for rlib dependencies
    #[cfg(feature = "dist-client")]
    rlib_dep_reader: Option<Arc<RlibDepReader>>,
    /// Parsed arguments from the rustc invocation
    parsed_args: ParsedArguments,
    // Normally resolved lazily only for invocations that actually request
    // target-cpu=native. Tests may inject a profile to avoid spawning rustc.
    native_profile: Option<String>,
}

/// a lookup proxy for determining the actual compiler used per file or directory
#[derive(Debug, Clone)]
pub struct RustupProxy {
    proxy_executable: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedArguments {
    /// The full commandline, with all parsed arguments
    arguments: Vec<Argument<ArgData>>,
    /// The location of compiler outputs.
    output_dir: PathBuf,
    /// Paths to extern crates used in the compile.
    externs: Vec<PathBuf>,
    /// The directories searched for rlibs
    crate_link_paths: Vec<PathBuf>,
    /// Static libraries linked to in the compile.
    staticlibs: Vec<PathBuf>,
    /// The crate name passed to --crate-name.
    crate_name: String,
    /// The crate types that will be generated
    crate_types: CrateTypes,
    /// If dependency info is being emitted, the name of the dep info file.
    dep_info: Option<PathBuf>,
    /// If profile info is being emitted, the path of the profile.
    ///
    /// This could be filled while `-Cprofile-use` been enabled.
    ///
    /// We need to add the profile into our outputs to enable distributed compilation.
    /// We don't need to track `profile-generate` since it's users work to make sure
    /// the `profdata` been generated from profraw files.
    ///
    /// For more information, see <https://doc.rust-lang.org/rustc/profile-guided-optimization.html>
    profile: Option<PathBuf>,
    /// If `-Z profile` has been enabled, we will use a GCC-compatible, gcov-based
    /// coverage implementation.
    ///
    /// This is not supported in latest stable rust anymore, but we still keep it here
    /// for the old nightly rustc.
    ///
    /// We need to add the profile into our outputs to enable distributed compilation.
    ///
    /// For more information, see <https://doc.rust-lang.org/rustc/instrument-coverage.html>
    gcno: Option<PathBuf>,
    /// rustc says that emits .rlib for --emit=metadata
    /// <https://github.com/rust-lang/rust/issues/54852>
    emit: HashSet<String>,
    /// The value of any `--color` option passed on the commandline.
    color_mode: ColorMode,
    /// Whether `--json` was passed to this invocation.
    has_json: bool,
    /// A `--target` parameter that specifies a path to a JSON file.
    target_json: Option<PathBuf>,
}

/// A struct on which to hang a `Compilation` impl.
#[derive(Debug, Clone)]
pub struct RustCompilation {
    /// The path to the rustc executable, not the rustup proxy.
    executable: PathBuf,
    /// The host triple for this rustc.
    host: String,
    /// The sysroot for this rustc
    sysroot: PathBuf,
    /// A shared, caching reader for rlib dependencies
    #[cfg(feature = "dist-client")]
    rlib_dep_reader: Option<Arc<RlibDepReader>>,
    /// All arguments passed to rustc
    arguments: Vec<Argument<ArgData>>,
    /// The compiler inputs.
    inputs: Vec<PathBuf>,
    /// The compiler outputs.
    outputs: HashMap<String, ArtifactDescriptor>,
    /// The directories searched for rlibs
    crate_link_paths: Vec<PathBuf>,
    /// The crate name being compiled.
    crate_name: String,
    /// The crate types that will be generated
    crate_types: CrateTypes,
    /// If dependency info is being emitted, the name of the dep info file.
    dep_info: Option<PathBuf>,
    /// The current working directory
    cwd: PathBuf,
    /// The environment variables
    env_vars: Vec<(OsString, OsString)>,
    /// Environment variables rustc reported as explicit source dependencies.
    /// These values are observable through `env!`/`option_env!` and must not be
    /// rewritten before compilation.
    env_dep_names: HashSet<OsString>,
    allow_dist: bool,
    canonical_paths: Option<CanonicalRustPaths>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct CanonicalRustCompileCommand {
    toolchain_executable: PathBuf,
    runner_arguments: Vec<OsString>,
    env_vars: Vec<(OsString, OsString)>,
    cwd: PathBuf,
}

#[cfg(target_os = "linux")]
#[async_trait]
impl CompileCommandImpl for CanonicalRustCompileCommand {
    fn get_executable(&self) -> PathBuf {
        self.toolchain_executable.clone()
    }

    fn get_arguments(&self) -> Vec<OsString> {
        self.runner_arguments.clone()
    }

    fn get_env_vars(&self) -> Vec<(OsString, OsString)> {
        self.env_vars.clone()
    }

    fn get_cwd(&self) -> PathBuf {
        self.cwd.clone()
    }

    async fn execute<T>(
        &self,
        _: &crate::server::SccacheService<T>,
        creator: &T,
    ) -> Result<process::Output>
    where
        T: CommandCreatorSync,
    {
        let mut cmd = creator.clone().new_command_sync("/usr/bin/bwrap");
        cmd.args(&self.runner_arguments)
            .env_clear()
            .envs(self.env_vars.clone())
            .current_dir("/");
        cmd.share_jobserver();
        run_input_output(cmd, None).await
    }
}

// The selection of crate types for this compilation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateTypes {
    rlib: bool,
    staticlib: bool,
}

/// Emit types that we will cache.
static ALLOWED_EMIT: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ["link", "metadata", "dep-info"].iter().copied().collect());

/// Version number for cache key.
const CACHE_VERSION: &[u8] = b"7";

struct RustDepInfoRequest<'a, T> {
    creator: &'a T,
    crate_name: &'a str,
    executable: &'a Path,
    arguments: &'a [OsString],
    cwd: &'a Path,
    env_vars: &'a [(OsString, OsString)],
    pool: &'a tokio::runtime::Handle,
    dep_info_copy: Option<&'a Path>,
}

/// Get absolute paths for all source files and env-deps listed in rustc's dep-info output.
async fn get_source_files_and_env_deps<T>(
    request: RustDepInfoRequest<'_, T>,
) -> Result<(Vec<PathBuf>, Vec<(OsString, OsString)>)>
where
    T: CommandCreatorSync,
{
    let RustDepInfoRequest {
        creator,
        crate_name,
        executable,
        arguments,
        cwd,
        env_vars,
        pool,
        dep_info_copy,
    } = request;
    let start = time::Instant::now();
    // Get the full list of source files from rustc's dep-info.
    let temp_dir = tempfile::Builder::new()
        .prefix("sccache")
        .tempdir()
        .context("Failed to create temp dir")?;
    let dep_file = temp_dir.path().join("deps.d");
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.args(arguments)
        .args(&["--emit", "dep-info"])
        .arg("-o")
        .arg(&dep_file)
        .env_clear()
        .envs(env_vars.to_vec())
        .current_dir(cwd);
    trace!("[{crate_name}]: get dep-info: {cmd:?}");
    // Output of command is in file under dep_file, so we ignore stdout&stderr
    let _dep_info = run_input_output(cmd, None).await?;
    if let Some(copy_to) = dep_info_copy {
        if let Some(parent) = copy_to.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&dep_file, copy_to)?;
    }
    // Parse the dep-info file, then hash the contents of those files.
    let cwd = cwd.to_owned();
    let name2 = crate_name.to_owned();
    let parsed = pool
        .spawn_blocking(move || {
            parse_dep_file(&dep_file, &cwd)
                .with_context(|| format!("Failed to parse dep info for {name2}"))
        })
        .await?;

    parsed.map(move |(files, env_deps)| {
        trace!(
            "[{crate_name}]: got {} source files and {} env-deps from dep-info in {}",
            files.len(),
            env_deps.len(),
            fmt_duration_as_secs(&start.elapsed())
        );
        // Just to make sure we capture temp_dir.
        drop(temp_dir);
        (files, env_deps)
    })
}

/// Parse dependency info from `file` and return a Vec of files mentioned.
/// Treat paths as relative to `cwd`.
fn parse_dep_file<T, U>(file: T, cwd: U) -> Result<(Vec<PathBuf>, Vec<(OsString, OsString)>)>
where
    T: AsRef<Path>,
    U: AsRef<Path>,
{
    let mut f = fs::File::open(file.as_ref())?;
    let mut deps = String::new();
    f.read_to_string(&mut deps)?;
    Ok((parse_dep_info(&deps, cwd), parse_env_dep_info(&deps)))
}

fn parse_dep_info<T>(dep_info: &str, cwd: T) -> Vec<PathBuf>
where
    T: AsRef<Path>,
{
    let cwd = cwd.as_ref();
    // Just parse the first line, which should have the dep-info file and all
    // source files.
    let line = match dep_info.lines().next() {
        None => return vec![],
        Some(l) => l,
    };
    let pos = match line.find(": ") {
        None => return vec![],
        Some(p) => p,
    };

    let mut deps = Vec::new();
    let mut current_dep = String::new();

    let mut iter = line[pos + 2..].chars().peekable();

    loop {
        match iter.next() {
            Some('\\') => {
                if iter.peek() == Some(&' ') {
                    current_dep.push(' ');
                    iter.next();
                } else {
                    current_dep.push('\\');
                }
            }
            Some(' ') => {
                deps.push(current_dep);
                current_dep = String::new();
            }
            Some(c) => current_dep.push(c),
            None => {
                if !current_dep.is_empty() {
                    deps.push(current_dep);
                }

                break;
            }
        }
    }

    let mut deps = deps.iter().map(|s| cwd.join(s)).collect::<Vec<_>>();
    deps.sort();
    deps
}

fn parse_env_dep_info(dep_info: &str) -> Vec<(OsString, OsString)> {
    let mut env_deps = Vec::new();
    for line in dep_info.lines() {
        if let Some(env_dep) = line.strip_prefix("# env-dep:") {
            let mut split = env_dep.splitn(2, '=');
            match (split.next(), split.next()) {
                (Some(var), Some(val)) => env_deps.push((var.into(), val.into())),
                _ => env_deps.push((env_dep.into(), "".into())),
            }
        }
    }
    env_deps
}

/// Run `rustc --print file-names` to get the outputs of compilation.
async fn get_compiler_outputs<T>(
    creator: &T,
    executable: &Path,
    arguments: Vec<OsString>,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
) -> Result<Vec<String>>
where
    T: Clone + CommandCreatorSync,
{
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.args(&arguments)
        .args(&["--print", "file-names"])
        .env_clear()
        .envs(env_vars.to_vec())
        .current_dir(cwd);
    if log_enabled!(Trace) {
        trace!("get_compiler_outputs: {cmd:?}");
    }
    let outputs = run_input_output(cmd, None).await?;

    let outstr = String::from_utf8(outputs.stdout).context("Error parsing rustc output")?;
    if log_enabled!(Trace) {
        trace!("get_compiler_outputs: {outstr:?}");
    }
    Ok(outstr.lines().map(std::borrow::ToOwned::to_owned).collect())
}

fn hashes_in_canonical_path_order(
    paths: &[PathBuf],
    hashes: Vec<String>,
    canonical: Option<&CanonicalRustPaths>,
) -> Vec<String> {
    let mut pairs = paths
        .iter()
        .cloned()
        .zip(hashes)
        .map(|(path, hash)| {
            let identity =
                canonical.map_or_else(|| path.clone(), |canonical| canonical.to_canonical(&path));
            (identity, hash)
        })
        .collect::<Vec<_>>();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));    pairs.into_iter().map(|(_, hash)| hash).collect()
}

const RUST_SHADOW_LOG_ENV: &str = "SCCACHE_RUST_SHADOW_LOG";

static RUST_SHADOW_LOG_LOCK: LazyLock<std::sync::Mutex<()>> =
    LazyLock::new(|| std::sync::Mutex::new(()));
static WARNED_RUST_SHADOW_LOG: AtomicBool = AtomicBool::new(false);

#[derive(Serialize)]
struct RustShadowInput {
    raw_path: String,
    key_path: String,
    digest: String,
}

#[derive(Serialize)]
struct RustShadowEnvValue {
    raw_text: Option<String>,
    raw_blake3: String,
    key_text: Option<String>,
    key_blake3: String,
}

#[derive(Serialize)]
struct RustShadowEnv {
    name: String,
    value: RustShadowEnvValue,
}

#[derive(Serialize)]
struct RustShadowRoots {
    build_root: String,
    target_root: String,
    cargo_home: Option<String>,
    rust_root: String,
}

#[derive(Serialize)]
struct RustShadowOutput {
    cache_object_key: String,
    raw_path: String,
    key_path: String,
    optional: bool,
}

#[derive(Serialize)]
struct RustShadowRecord {
    schema: u32,
    timestamp_unix_ms: u64,
    normalization_policy: String,
    cache_key: String,
    weak_toolchain_key: String,
    cache_version: String,
    crate_name: String,
    crate_types: String,
    host: String,
    target: String,
    compiler_version: String,
    compiler_shlibs_digests: Vec<String>,
    cache_control: String,
    may_dist: bool,
    allow_dist: bool,
    native_requested: bool,
    resolved_native_profile: Option<String>,
    canonical_enabled: bool,
    canonical_roots: Option<RustShadowRoots>,
    cwd_raw: String,
    cwd_key: String,
    sysroot_raw: String,
    sysroot_key: String,
    arguments_raw: Vec<String>,
    arguments_canonical: Vec<String>,
    arguments_hashed_blob: String,
    source_inputs: Vec<RustShadowInput>,
    extern_inputs: Vec<RustShadowInput>,
    staticlib_inputs: Vec<RustShadowInput>,
    target_json_inputs: Vec<RustShadowInput>,
    dep_env: Vec<RustShadowEnv>,
    cargo_env: Vec<RustShadowEnv>,
    outputs: Vec<RustShadowOutput>,
}

fn cargo_manifest_input(env_vars: &[(OsString, OsString)], cwd: &Path) -> Option<PathBuf> {
    let resolve = |value: &OsString| {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            path
        } else {
            cwd.join(path)
        }
    };

    if let Some(manifest) = env_vars
        .iter()
        .find_map(|(name, value)| (name == "CARGO_MANIFEST_PATH").then(|| resolve(value)))
        && manifest.is_file()
    {
        return Some(manifest);
    }

    let manifest_dir = env_vars
        .iter()
        .find_map(|(name, value)| (name == "CARGO_MANIFEST_DIR").then(|| resolve(value)))?;
    let manifest = manifest_dir.join("Cargo.toml");
    manifest.is_file().then_some(manifest)
}

fn rust_cache_hashes_cargo_env(name: &std::ffi::OsStr) -> bool {
    name.starts_with("CARGO_")
        && name != "CARGO_MAKEFLAGS"
        && !name.starts_with("CARGO_REGISTRIES_")
        && name != "CARGO_BUILD_JOBS"
        && name != "CARGO_ENCODED_RUSTFLAGS"
}

fn rust_shadow_plain_env(name: &std::ffi::OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(
            "CARGO"
                | "CARGO_HOME"
                | "CARGO_INSTALL_ROOT"
                | "CARGO_MANIFEST_DIR"
                | "CARGO_MANIFEST_PATH"
                | "CARGO_TARGET_DIR"
                | "CARGO_TARGET_TMPDIR"
                | "OUT_DIR"
                | "PWD"
                | "RUSTC"
                | "RUSTDOC"
                | "TMPDIR"
                | "TMP"
                | "TEMP"
                | "TEMPDIR"
        )
    ) || name
        .to_str()
        .is_some_and(|name| name.starts_with("CARGO_BIN_EXE_"))
}

fn rust_shadow_digest(value: &std::ffi::OsStr) -> String {
    blake3::hash(value.as_encoded_bytes()).to_hex().to_string()
}

fn rust_shadow_env_value(
    name: &std::ffi::OsStr,
    raw: &std::ffi::OsStr,
    canonical: Option<&CanonicalRustPaths>,
) -> RustShadowEnvValue {
    let key = canonical.map_or_else(
        || raw.to_owned(),
        |canonical| canonical.env_value_to_canonical(name, raw),
    );
    let show_text = rust_shadow_plain_env(name);
    RustShadowEnvValue {
        raw_text: show_text.then(|| raw.to_string_lossy().into_owned()),
        raw_blake3: rust_shadow_digest(raw),
        key_text: show_text.then(|| key.to_string_lossy().into_owned()),
        key_blake3: rust_shadow_digest(&key),
    }
}

fn rust_shadow_inputs(
    paths: &[PathBuf],
    hashes: &[String],
    canonical: Option<&CanonicalRustPaths>,
) -> Vec<RustShadowInput> {
    paths
        .iter()
        .zip(hashes)
        .map(|(path, digest)| RustShadowInput {
            raw_path: path.to_string_lossy().into_owned(),
            key_path: canonical
                .map_or_else(|| path.clone(), |canonical| canonical.to_canonical(path))
                .to_string_lossy()
                .into_owned(),
            digest: digest.clone(),
        })
        .collect()
}

fn rust_shadow_args(args: &[(OsString, Option<OsString>)]) -> Vec<String> {
    args.iter()
        .flat_map(|(arg, value)| std::iter::once(arg).chain(value.as_ref()))
        .map(|value| value.to_string_lossy().into_owned())
        .collect()
}

fn rust_shadow_roots(canonical: Option<&CanonicalRustPaths>) -> Option<RustShadowRoots> {
    canonical.map(|canonical| RustShadowRoots {
        build_root: canonical.build_root.to_string_lossy().into_owned(),
        target_root: canonical.target_root.to_string_lossy().into_owned(),
        cargo_home: canonical
            .cargo_home
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        rust_root: canonical.rust_root.to_string_lossy().into_owned(),
    })
}

fn append_rust_shadow_record(path: &Path, record: &RustShadowRecord) {
    let mut encoded = match serde_json::to_vec(record) {
        Ok(encoded) => encoded,
        Err(error) => {
            if !WARNED_RUST_SHADOW_LOG.swap(true, Ordering::Relaxed) {
                warn!("failed to serialize Rust shadow-key telemetry: {error}");
            }
            return;
        }
    };
    encoded.push(b'\n');

    let _guard = RUST_SHADOW_LOG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        if !WARNED_RUST_SHADOW_LOG.swap(true, Ordering::Relaxed) {
            warn!(
                "failed to create Rust shadow-key telemetry directory {}: {error}",
                parent.display()
            );
        }
        return;
    }

    let result = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| {
            let written = file.write(&encoded)?;
            if written == encoded.len() {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    format!(
                        "short Rust shadow telemetry append: {written}/{} bytes",
                        encoded.len()
                    ),
                ))
            }
        });

    if let Err(error) = result
        && !WARNED_RUST_SHADOW_LOG.swap(true, Ordering::Relaxed)
    {
        warn!(
            "failed to append Rust shadow-key telemetry {}: {error}",
            path.display()
        );
    }
}

static NATIVE_PROFILE_CACHE: LazyLock<std::sync::Mutex<HashMap<(PathBuf, String), String>>> =
    LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

static WARNED_DIST_NATIVE_PORTABLE: AtomicBool = AtomicBool::new(false);

fn native_target_requested(arguments: &[Argument<ArgData>]) -> bool {
    arguments.iter().any(|arg| {
        matches!(
            arg.get_data(),
            Some(CodeGen(ArgCodegen {
                opt,
                value: Some(value)
            })) if opt == "target-cpu" && value == "native"
        )
    })
}

fn compilation_target(arguments: &[Argument<ArgData>], host: &str) -> String {
    for arg in arguments.iter().rev() {
        match arg.get_data() {
            Some(Target(ArgTarget::Name(target))) => return target.clone(),
            Some(Target(ArgTarget::Path(_) | ArgTarget::Unsure(_))) => {
                return "custom-target".to_owned();
            }
            _ => {}
        }
    }
    host.to_owned()
}

fn rewrite_native_target_cpu(arguments: &mut [Argument<ArgData>], cpu: &str) {
    for arg in arguments {
        if let Argument::WithValue(_, CodeGen(ArgCodegen { opt, value }), _) = arg
            && opt == "target-cpu"
            && value.as_deref() == Some("native")
        {
            *value = Some(cpu.to_owned());
        }
    }
}

fn remove_dep_info_emit(arguments: &mut [Argument<ArgData>]) {
    for arg in arguments {
        if let Argument::WithValue(_, Emit(value), _) = arg {
            let filtered = value
                .split(',')
                .filter(|item| *item != "dep-info")
                .collect::<Vec<_>>()
                .join(",");
            *value = filtered;
        }
    }
}

fn parse_native_profile(llvm_ir: &str) -> Result<String> {
    let marker = "\"target-cpu\"=\"";
    let start = llvm_ir
        .find(marker)
        .context("native probe LLVM IR did not contain target-cpu")?
        + marker.len();
    let cpu_end = llvm_ir[start..]
        .find('"')
        .context("native probe target-cpu was unterminated")?
        + start;
    let cpu = &llvm_ir[start..cpu_end];

    let feature_marker = "\"target-features\"=\"";
    let features = llvm_ir[cpu_end..]
        .find(feature_marker)
        .and_then(|offset| {
            let start = cpu_end + offset + feature_marker.len();
            llvm_ir[start..]
                .find('"')
                .map(|end| &llvm_ir[start..start + end])
        })
        .unwrap_or("");

    Ok(format!("{cpu}|{features}"))
}

async fn cached_native_profile<T>(
    creator: T,
    executable: &Path,
    rustc_verbose_version: &str,
    env_vars: &[(OsString, OsString)],
) -> Result<String>
where
    T: CommandCreatorSync,
{
    let key = (executable.to_owned(), rustc_verbose_version.to_owned());
    if let Some(profile) = NATIVE_PROFILE_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
        .cloned()
    {
        return Ok(profile);
    }

    let profile = probe_native_profile(creator, executable, env_vars).await?;
    let mut cache = NATIVE_PROFILE_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(cache.entry(key).or_insert_with(|| profile.clone()).clone())
}

async fn probe_native_profile<T>(
    mut creator: T,
    executable: &Path,
    env_vars: &[(OsString, OsString)],
) -> Result<String>
where
    T: CommandCreatorSync,
{
    let temp_dir = tempfile::Builder::new()
        .prefix("sccache-native")
        .tempdir()
        .context("Failed to create native-profile temp dir")?;
    let mut cmd = creator.new_command_sync(executable);
    cmd.args(&[
        "-",
        "--crate-name",
        "sccache_native_probe",
        "--crate-type",
        "lib",
        "--emit=llvm-ir=-",
        "-C",
        "target-cpu=native",
    ])
    .env_clear()
    .envs(env_vars.to_vec())
    .current_dir(temp_dir.path());

    let source =
        b"pub fn sccache_native_probe(x:u64)->u64{x.wrapping_mul(17).rotate_left(9)}\n".to_vec();
    let output = run_input_output(cmd, Some(source)).await?;
    let llvm_ir = String::from_utf8(output.stdout).context("native probe LLVM IR was not UTF-8")?;
    parse_native_profile(&llvm_ir)
}

#[cfg(target_os = "linux")]
fn canonical_bwrap_arguments(
    canonical: &CanonicalRustPaths,
    executable: &Path,
    arguments: &[Argument<ArgData>],
    cwd: &Path,
) -> Vec<OsString> {
    let arguments = arguments
        .iter()
        .flat_map(|arg| arg.iter_os_strings())
        .collect::<Vec<_>>();
    canonical.bwrap_arguments(executable, &arguments, cwd)
}

impl Rust {
    /// Create a new Rust compiler instance, calculating the hashes of
    /// all the shared libraries in its sysroot.
    pub async fn new<T>(
        mut creator: T,
        executable: PathBuf,
        env_vars: &[(OsString, OsString)],
        rustc_verbose_version: &str,
        dist_archive: Option<PathBuf>,
        pool: tokio::runtime::Handle,
    ) -> Result<Self>
    where
        T: CommandCreatorSync,
    {
        // Taken from Cargo
        let host = rustc_verbose_version
            .lines()
            .find(|l| l.starts_with("host: "))
            .map(|l| &l[6..])
            .context("rustc verbose version didn't have a line for `host:`")?
            .to_string();

        // it's fine to use the `executable` directly no matter if proxied or not
        let mut cmd = creator.new_command_sync(&executable);
        cmd.stdout(process::Stdio::piped())
            .stderr(process::Stdio::null())
            .arg("--print=sysroot")
            .env_clear()
            .envs(env_vars.to_vec());
        let sysroot_and_libs = async move {
            let output = run_input_output(cmd, None).await?;
            //debug!("output.and_then: {}", output);
            let outstr = String::from_utf8(output.stdout).context("Error parsing sysroot")?;
            let sysroot = PathBuf::from(outstr.trim_end());
            let libs_path = sysroot.join(LIBS_DIR);
            let mut libs = fs::read_dir(&libs_path)
                .with_context(|| format!("Failed to list rustc sysroot: `{libs_path:?}`"))?
                .filter_map(|e| {
                    e.ok().and_then(|e| {
                        e.file_type().ok().and_then(|t| {
                            let p = e.path();
                            if (t.is_file() || t.is_symlink() && p.is_file())
                                && p.extension().is_some_and(|e| e == DLL_EXTENSION)
                            {
                                Some(p)
                            } else {
                                None
                            }
                        })
                    })
                })
                .collect::<Vec<_>>();
            if let Some(path) = dist_archive {
                trace!("Hashing {path:?} along with rustc libs.");
                libs.push(path);
            }
            libs.sort();
            Result::Ok((sysroot, libs))
        };

        #[cfg(feature = "dist-client")]
        {
            use futures::TryFutureExt;
            let rlib_dep_reader = {
                let executable = executable.clone();
                let env_vars = env_vars.to_owned();
                pool.spawn_blocking(move || RlibDepReader::new_with_check(executable, &env_vars))
                    .map_err(anyhow::Error::from)
            };

            let ((sysroot, libs), rlib_dep_reader) =
                futures::future::try_join(sysroot_and_libs, rlib_dep_reader).await?;

            let rlib_dep_reader = match rlib_dep_reader {
                Ok(r) => Some(Arc::new(r)),
                Err(e) => {
                    warn!(
                        "Failed to initialise RlibDepDecoder, distributed compiles will be inefficient: {e}"
                    );
                    None
                }
            };
            hash_all(&libs, &pool).await.map(move |digests| Self {
                executable,
                host,
                version: rustc_verbose_version.to_string(),
                sysroot,                compiler_shlibs_digests: digests,
                rlib_dep_reader,
            })
        }

        #[cfg(not(feature = "dist-client"))]
        {
            let (sysroot, libs) = sysroot_and_libs.await?;
            hash_all(&libs, &pool).await.map(move |digests| Rust {
                executable,
                host,
                version: rustc_verbose_version.to_string(),
                sysroot,
                compiler_shlibs_digests: digests,
            })
        }
    }
}

impl<T> Compiler<T> for Rust
where
    T: CommandCreatorSync,
{
    fn kind(&self) -> CompilerKind {
        CompilerKind::Rust
    }
    #[cfg(feature = "dist-client")]
    fn get_toolchain_packager(&self) -> Box<dyn pkg::ToolchainPackager> {
        Box::new(RustToolchainPackager {
            sysroot: self.sysroot.clone(),
            canonical: false,
        })
    }
    /// Parse `arguments` as rustc command-line arguments, determine if
    /// we can cache the result of compilation. This is only intended to
    /// cover a subset of rustc invocations, primarily focused on those
    /// that will occur when cargo invokes rustc.
    ///
    /// Caveats:
    /// * We don't support compilation from stdin.
    /// * We require --emit.
    /// * We only support `link` and `dep-info` in --emit (and don't support *just* 'dep-info')
    /// * We require `--out-dir`.
    /// * We don't support `-o file`.
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
        _env_vars: &[(OsString, OsString)],
    ) -> CompilerArguments<Box<dyn CompilerHasher<T> + 'static>> {
        match parse_arguments(arguments, cwd) {
            CompilerArguments::Ok(args) => CompilerArguments::Ok(Box::new(RustHasher {
                executable: self.executable.clone(), // if rustup exists, this must already contain the true resolved compiler path
                host: self.host.clone(),
                version: self.version.clone(),
                sysroot: self.sysroot.clone(),
                compiler_shlibs_digests: self.compiler_shlibs_digests.clone(),
                #[cfg(feature = "dist-client")]
                rlib_dep_reader: self.rlib_dep_reader.clone(),
                parsed_args: args,
                native_profile: None,
            })),
            CompilerArguments::NotCompilation => CompilerArguments::NotCompilation,
            CompilerArguments::CannotCache(why, extra_info) => {
                CompilerArguments::CannotCache(why, extra_info)
            }
        }
    }

    fn box_clone(&self) -> Box<dyn Compiler<T>> {
        Box::new((*self).clone())
    }
}

impl<T> CompilerProxy<T> for RustupProxy
where
    T: CommandCreatorSync,
{
    fn resolve_proxied_executable(
        &self,
        mut creator: T,
        cwd: PathBuf,
        env: &[(OsString, OsString)],
    ) -> Pin<Box<dyn Future<Output = Result<(PathBuf, FileTime)>> + Send>> {
        let mut child = creator.new_command_sync(&self.proxy_executable);
        child
            .current_dir(&cwd)
            .env_clear()
            .envs(env.to_vec())
            .args(&["which", "rustc"]);

        Box::pin(async move {
            let output = run_input_output(child, None)
                .await
                .context("Failed to execute rustup which rustc")?;

            let stdout = String::from_utf8(output.stdout)
                .context("Failed to parse output of rustup which rustc")?;

            let proxied_compiler = PathBuf::from(stdout.trim());
            trace!("proxy: rustup which rustc produced: {proxied_compiler:?}");
            // TODO: Delegate FS access to a thread pool if possible
            let attr = fs::metadata(proxied_compiler.as_path())
                .context("Failed to obtain metadata of the resolved, true rustc")?;

            if attr.is_file() {
                Ok(FileTime::from_last_modification_time(&attr))
            } else {
                Err(anyhow!(
                    "proxy: rustup resolved compiler is not of type file"
                ))
            }
            .map(move |filetime| (proxied_compiler, filetime))
        })
    }

    fn box_clone(&self) -> Box<dyn CompilerProxy<T>> {
        Box::new((*self).clone())
    }
}

impl RustupProxy {
    pub fn new<P>(proxy_executable: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let proxy_executable = proxy_executable.as_ref().to_owned();
        Ok(Self { proxy_executable })
    }

    pub async fn find_proxy_executable<T>(
        compiler_executable: &Path,
        proxy_name: &str,
        mut creator: T,
        env: &[(OsString, OsString)],
    ) -> Result<Result<Option<Self>>>
    where
        T: CommandCreatorSync,
    {
        enum ProxyPath {
            Candidate(PathBuf),
            ToBeDiscovered,
            None,
        }

        // verification if rustc is a proxy or not
        //
        // the process is multistaged
        //
        // if it is determined that rustc is a proxy,
        // then check if there is a rustup binary next to rustc
        // if not then check if which() knows about a rustup and use that.
        //
        // The produced candidate is then tested if it is a rustup.
        //
        //
        // The test for rustc being a proxy or not is done as follows
        // and follow firefox rustc detection closely:
        //
        // https://searchfox.org/mozilla-central/rev/c79c0d65a183d9d38676855f455a5c6a7f7dadd3/build/moz.configure/rust.configure#23-80
        //
        // which boils down to
        //
        // `rustc +stable` returns retcode 0 if it is the rustup proxy
        // `rustc +stable` returns retcode 1 (!=0) if it is installed via i.e. rpm packages

        // verify rustc is proxy
        let mut child = creator.new_command_sync(compiler_executable);
        child.env_clear().envs(env.to_vec()).args(&["+stable"]);
        let state = run_input_output(child, None).await.map(move |output| {
            if output.status.success() {
                trace!("proxy: Found a compiler proxy managed by rustup");
                ProxyPath::ToBeDiscovered
            } else {
                trace!("proxy: Found a regular compiler");
                ProxyPath::None
            }
        });

        let state = match state {
            Ok(candidate @ ProxyPath::Candidate(_)) => Ok(candidate),
            Ok(ProxyPath::ToBeDiscovered) => {
                // simple check: is there a rustup in the same parent dir as rustc?
                // that would be the preferred one
                Ok(match compiler_executable.parent().map(Path::to_owned) {
                    Some(parent) => {
                        let proxy_candidate = parent.join(proxy_name);
                        if proxy_candidate.exists() {
                            trace!(
                                "proxy: Found a compiler proxy at {}",
                                proxy_candidate.display()
                            );
                            ProxyPath::Candidate(proxy_candidate)
                        } else {
                            ProxyPath::ToBeDiscovered
                        }
                    }
                    None => ProxyPath::ToBeDiscovered,
                })
            }
            x => x,
        };
        let state = match state {
            Ok(ProxyPath::ToBeDiscovered) => {
                // still no rustup found, use which crate to find one
                match which::which(proxy_name) {
                    Ok(proxy_candidate) => {
                        warn!(
                            "proxy: rustup found, but not where it was expected (next to rustc {})",
                            compiler_executable.display()
                        );
                        Ok(ProxyPath::Candidate(proxy_candidate))
                    }
                    Err(e) => {
                        trace!("proxy: rustup is not present: {e}");
                        Ok(ProxyPath::ToBeDiscovered)
                    }
                }
            }
            x => x,
        };

        match state {
            Err(e) => Err(e),
            Ok(ProxyPath::ToBeDiscovered) => Ok(Err(anyhow!(
                "Failed to discover a rustup executable, but rustc behaves like a proxy"
            ))),
            Ok(ProxyPath::None) => Ok(Ok(None)),
            Ok(ProxyPath::Candidate(proxy_executable)) => {
                // verify the candidate is a rustup
                let mut child = creator.new_command_sync(&proxy_executable);
                child.env_clear().envs(env.to_vec()).args(&["--version"]);
                let rustup_candidate_check = run_input_output(child, None).await?;

                let stdout = String::from_utf8(rustup_candidate_check.stdout)
                    .map_err(|_e| anyhow!("Response of `rustup --version` is not valid UTF-8"))?;
                Ok(if stdout.trim().starts_with("rustup ") {
                    trace!("PROXY rustup --version produced: {stdout}");
                    Self::new(&proxy_executable).map(Some)
                } else {
                    Err(anyhow!("Unexpected output or `rustup --version`"))
                })
            }
        }
    }
}

macro_rules! make_os_string {
    ($( $v:expr ),*) => {{
        let mut s = OsString::new();
        $(
            s.push($v);
        )*
        s
    }};
}

#[derive(Clone, Debug, PartialEq)]
struct ArgCrateTypes {
    rlib: bool,
    staticlib: bool,
    others: HashSet<String>,
}
impl FromArg for ArgCrateTypes {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let arg = String::process(arg)?;
        let mut crate_types = Self {
            rlib: false,
            staticlib: false,
            others: HashSet::new(),
        };
        for ty in arg.split(',') {
            match ty {
                // It is assumed that "lib" always refers to "rlib", which
                // is true right now but may not be in the future
                "lib" | "rlib" => crate_types.rlib = true,
                "staticlib" => crate_types.staticlib = true,
                other => {
                    crate_types.others.insert(other.to_owned());
                }
            }
        }
        Ok(crate_types)
    }
}
impl IntoArg for ArgCrateTypes {
    fn into_arg_os_string(self) -> OsString {
        let Self {
            rlib,
            staticlib,
            others,
        } = self;
        let mut types: Vec<_> = others
            .iter()
            .map(String::as_str)
            .chain(if rlib { Some("rlib") } else { None })
            .chain(if staticlib { Some("staticlib") } else { None })
            .collect();
        types.sort_unstable();
        let types_string = types.join(",");
        types_string.into()
    }
    fn into_arg_string(self, _transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let Self {
            rlib,
            staticlib,
            others,
        } = self;
        let mut types: Vec<_> = others
            .iter()
            .map(String::as_str)
            .chain(if rlib { Some("rlib") } else { None })
            .chain(if staticlib { Some("staticlib") } else { None })
            .collect();
        types.sort_unstable();
        let types_string = types.join(",");
        Ok(types_string)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgLinkLibrary {
    kind: String,
    name: String,
}
impl FromArg for ArgLinkLibrary {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let (kind, name) = match split_os_string_arg(arg, "=")? {
            (kind, Some(name)) => (kind, name),
            // If no kind is specified, the default is dylib.
            (name, None) => ("dylib".to_owned(), name),
        };
        Ok(Self { kind, name })
    }
}
impl IntoArg for ArgLinkLibrary {
    fn into_arg_os_string(self) -> OsString {
        let Self { kind, name } = self;
        make_os_string!(kind, "=", name)
    }
    fn into_arg_string(self, _transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let Self { kind, name } = self;
        Ok(format!("{kind}={name}"))
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgLinkPath {
    kind: String,
    path: PathBuf,
}
impl FromArg for ArgLinkPath {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let (kind, path) = match split_os_string_arg(arg, "=")? {
            (kind, Some(path)) => (kind, path),
            // If no kind is specified, the path is used to search for all kinds
            (path, None) => ("all".to_owned(), path),
        };
        Ok(Self {
            kind,
            path: path.into(),
        })
    }
}
impl IntoArg for ArgLinkPath {
    fn into_arg_os_string(self) -> OsString {
        let Self { kind, path } = self;
        make_os_string!(kind, "=", path)
    }
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let Self { kind, path } = self;
        Ok(format!("{kind}={}", path.into_arg_string(transformer)?))
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgCodegen {
    opt: String,
    value: Option<String>,
}
impl FromArg for ArgCodegen {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let (opt, value) = split_os_string_arg(arg, "=")?;
        Ok(Self { opt, value })
    }
}
impl IntoArg for ArgCodegen {
    fn into_arg_os_string(self) -> OsString {
        let Self { opt, value } = self;
        if let Some(value) = value {
            make_os_string!(opt, "=", value)
        } else {
            make_os_string!(opt)
        }
    }
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let Self { opt, value } = self;
        Ok(if let Some(value) = value {
            format!("{opt}={}", value.into_arg_string(transformer)?)
        } else {
            opt
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgUnstable {
    opt: String,
    value: Option<String>,
}
impl FromArg for ArgUnstable {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let (opt, value) = split_os_string_arg(arg, "=")?;
        Ok(Self { opt, value })
    }
}
impl IntoArg for ArgUnstable {
    fn into_arg_os_string(self) -> OsString {
        let Self { opt, value } = self;
        if let Some(value) = value {
            make_os_string!(opt, "=", value)
        } else {
            make_os_string!(opt)
        }
    }
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let Self { opt, value } = self;
        Ok(if let Some(value) = value {
            format!("{opt}={}", value.into_arg_string(transformer)?)
        } else {
            opt
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgExtern {
    name: String,
    path: PathBuf,
}
impl FromArg for ArgExtern {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        if let (name, Some(path)) = split_os_string_arg(arg, "=")? {
            Ok(Self {
                name,
                path: path.into(),
            })
        } else {
            Err(ArgParseError::Other("no path for extern"))
        }
    }
}
impl IntoArg for ArgExtern {
    fn into_arg_os_string(self) -> OsString {
        let Self { name, path } = self;
        make_os_string!(name, "=", path)
    }
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let Self { name, path } = self;
        Ok(format!("{name}={}", path.into_arg_string(transformer)?))
    }
}

#[derive(Clone, Debug, PartialEq)]
enum ArgTarget {
    Name(String),
    Path(PathBuf),
    Unsure(OsString),
}
impl FromArg for ArgTarget {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        // Is it obviously a json file path?
        if Path::new(&arg).extension().is_some_and(|ext| ext == "json") {
            return Ok(Self::Path(arg.into()));
        }
        // Time for clever detection - if we append .json (even if it's clearly
        // a directory, i.e. resulting in /my/dir/.json), does the path exist?
        let mut path = arg.clone();
        path.push(".json");
        if Path::new(&path).is_file() {
            // Unfortunately, we're now not sure what will happen without having
            // a list of all the built-in targets handy, as they don't get .json
            // auto-added for target json discovery
            return Ok(Self::Unsure(arg));
        }
        // The file doesn't exist so it can't be a path, safe to assume it's a name
        Ok(Self::Name(
            arg.into_string().map_err(ArgParseError::InvalidUnicode)?,
        ))
    }
}
impl IntoArg for ArgTarget {
    fn into_arg_os_string(self) -> OsString {
        match self {
            Self::Name(s) => s.into(),
            Self::Path(p) => p.into(),
            Self::Unsure(s) => s,
        }
    }
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {        Ok(match self {
            Self::Name(s) => s,
            Self::Path(p) => p.into_arg_string(transformer)?,
            Self::Unsure(s) => s.into_arg_string(transformer)?,
        })
    }
}

ArgData! {
    TooHardFlag,
    TooHardPath(PathBuf),
    NotCompilationFlag,
    NotCompilation(OsString),
    LinkLibrary(ArgLinkLibrary),
    LinkPath(ArgLinkPath),
    Emit(String),
    Extern(ArgExtern),
    Color(String),
    Json(String),
    CrateName(String),
    CrateType(ArgCrateTypes),
    OutDir(PathBuf),
    CodeGen(ArgCodegen),
    PassThrough(OsString),
    Target(ArgTarget),
    Unstable(ArgUnstable),
}

use self::ArgData::*;

use super::CacheControl;

// These are taken from https://github.com/rust-lang/rust/blob/b671c32ddc8c36d50866428d83b7716233356721/src/librustc/session/config.rs#L1186
counted_array!(static ARGS: [ArgInfo<ArgData>; _] = [
    flag!("-", TooHardFlag),
    take_arg!("--allow", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--cap-lints", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--cfg", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--check-cfg", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--codegen", ArgCodegen, CanBeSeparated(b'='), CodeGen),
    take_arg!("--color", String, CanBeSeparated(b'='), Color),
    take_arg!("--crate-name", String, CanBeSeparated(b'='), CrateName),
    take_arg!("--crate-type", ArgCrateTypes, CanBeSeparated(b'='), CrateType),
    take_arg!("--deny", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--diagnostic-width", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--emit", String, CanBeSeparated(b'='), Emit),
    take_arg!("--error-format", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--explain", OsString, CanBeSeparated(b'='), NotCompilation),
    take_arg!("--extern", ArgExtern, CanBeSeparated(b'='), Extern),
    take_arg!("--forbid", OsString, CanBeSeparated(b'='), PassThrough),
    flag!("--help", NotCompilationFlag),
    take_arg!("--json", String, CanBeSeparated(b'='), Json),
    take_arg!("--out-dir", PathBuf, CanBeSeparated(b'='), OutDir),
    take_arg!("--pretty", OsString, CanBeSeparated(b'='), NotCompilation),
    take_arg!("--print", OsString, CanBeSeparated(b'='), NotCompilation),
    take_arg!("--remap-path-prefix", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--sysroot", PathBuf, CanBeSeparated(b'='), TooHardPath),
    take_arg!("--target", ArgTarget, CanBeSeparated(b'='), Target),
    take_arg!("--unpretty", OsString, CanBeSeparated(b'='), NotCompilation),
    flag!("--version", NotCompilationFlag),
    take_arg!("--warn", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("-A", OsString, CanBeSeparated, PassThrough),
    take_arg!("-C", ArgCodegen, CanBeSeparated, CodeGen),
    take_arg!("-D", OsString, CanBeSeparated, PassThrough),
    take_arg!("-F", OsString, CanBeSeparated, PassThrough),
    take_arg!("-L", ArgLinkPath, CanBeSeparated, LinkPath),
    flag!("-V", NotCompilationFlag),
    take_arg!("-W", OsString, CanBeSeparated, PassThrough),
    take_arg!("-Z", ArgUnstable, CanBeSeparated, Unstable),
    take_arg!("-l", ArgLinkLibrary, CanBeSeparated, LinkLibrary),
    take_arg!("-o", PathBuf, CanBeSeparated, TooHardPath),
]);

/// Split the contents of a rustc `@response` file into arguments.
///
/// rustc reads response files by splitting on newlines, trimming whitespace,
/// and skipping empty lines.  It does not support quoting or backslash escaping
/// (unlike GCC), and does not recursively expand `@file` directives found
/// inside a response file.
///
/// Rustc reference: <https://github.com/rust-lang/rust/blob/main/compiler/rustc_driver_impl/src/args.rs>
fn split_rust_response_file_args(contents: &str) -> Vec<OsString> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(OsString::from)
        .collect()
}

pub struct ExpandResponseFile<'a> {
    cwd: &'a Path,
    stack: Vec<OsString>,
}

impl<'a> ExpandResponseFile<'a> {
    pub fn new(cwd: &'a Path, args: &[OsString]) -> Self {
        ExpandResponseFile {
            stack: args
                .iter()
                .rev()
                .map(std::borrow::ToOwned::to_owned)
                .collect(),
            cwd,
        }
    }
}

impl Iterator for ExpandResponseFile<'_> {
    type Item = OsString;

    fn next(&mut self) -> Option<OsString> {
        loop {
            let arg = self.stack.pop()?;
            let file = match arg.split_prefix("@") {
                Some(arg) => self.cwd.join(arg),
                None => return Some(arg),
            };

            let mut contents = String::new();
            let res = fs_err::File::open(&file)
                .and_then(|f| BufReader::new(f).read_to_string(&mut contents));
            if let Err(e) = res {
                debug!("failed to read @-file `{}`: {e}", file.display());
                return Some(arg);
            }
            let new_args = split_rust_response_file_args(&contents);
            self.stack.extend(new_args.into_iter().rev());
        }
    }
}

fn parse_arguments(arguments: &[OsString], cwd: &Path) -> CompilerArguments<ParsedArguments> {
    let mut args = vec![];

    let mut emit: Option<HashSet<String>> = None;
    let mut input = None;
    let mut output_dir = None;
    let mut crate_name = None;
    let mut crate_types = CrateTypes {
        rlib: false,
        staticlib: false,
    };
    let mut extra_filename = None;
    let mut externs = vec![];
    let mut crate_link_paths = vec![];
    let mut static_lib_names = vec![];
    let mut static_link_paths: Vec<PathBuf> = vec![];
    let mut color_mode = ColorMode::Auto;
    let mut has_json = false;
    let mut profile = None;
    let mut gcno = false;
    let mut target_json = None;

    // Custom iterator to expand `@` arguments which stand for reading a file
    // and interpreting it as a list of more arguments.
    let it = ExpandResponseFile::new(cwd, arguments);

    for (idx, arg) in ArgsIter::new(it, &ARGS[..]).enumerate() {
        let arg = try_or_cannot_cache!(arg, "argument parse");
        match arg.get_data() {
            Some(TooHardFlag | TooHardPath(_)) => {
                cannot_cache!(
                    "unsupported compiler option",
                    arg.flag_str()
                        .map_or_else(|| format!("{arg:?}"), str::to_owned)
                )
            }
            Some(NotCompilationFlag | NotCompilation(_)) => {
                return CompilerArguments::NotCompilation;
            }
            Some(LinkLibrary(ArgLinkLibrary { kind, name })) => {
                if kind == "static" {
                    static_lib_names.push(name.to_owned());
                }
            }
            Some(LinkPath(ArgLinkPath { kind, path })) => {
                // "crate" is not typically necessary as cargo will normally
                // emit explicit --extern arguments
                if kind == "crate" || kind == "dependency" || kind == "all" {
                    crate_link_paths.push(cwd.join(path));
                }
                if kind == "native" || kind == "all" {
                    static_link_paths.push(cwd.join(path));
                }
            }
            Some(Emit(value)) => {
                if emit.is_some() {
                    // We don't support passing --emit more than once.
                    cannot_cache!("more than one --emit");
                }
                emit = Some(value.split(',').map(str::to_owned).collect());
            }
            Some(CrateType(ArgCrateTypes {
                rlib,
                staticlib,
                others,
            })) => {
                // We can't cache non-rlib/staticlib crates, because rustc invokes the
                // system linker to link them, and we don't know about all the linker inputs.
                if !others.is_empty() {
                    let mut others: Vec<&str> = others.iter().map(String::as_str).collect();
                    others.sort_unstable();
                    let others_string = others.join(",");
                    cannot_cache!("crate-type", others_string)
                }
                crate_types.rlib |= rlib;
                crate_types.staticlib |= staticlib;
            }
            Some(CrateName(value)) => crate_name = Some(value.clone()),
            Some(OutDir(value)) => output_dir = Some(value.clone()),
            Some(Extern(ArgExtern { path, .. })) => externs.push(path.clone()),
            Some(CodeGen(ArgCodegen { opt, value })) => {
                match (opt.as_ref(), value) {
                    ("extra-filename", Some(value)) => extra_filename = Some(value.to_owned()),
                    ("extra-filename", None) => cannot_cache!("extra-filename"),
                    ("profile-use", Some(v)) => profile = Some(v.clone()),
                    // Incremental compilation makes a mess of sccache's entire world
                    // view. It produces additional compiler outputs that we don't cache,
                    // and just letting rustc do its work in incremental mode is likely
                    // to be faster than trying to fetch a result from cache anyway, so
                    // don't bother caching compiles where it's enabled currently.
                    // Longer-term we would like to figure out better integration between
                    // sccache and rustc in the incremental scenario:
                    // https://github.com/mozilla/sccache/issues/236
                    ("incremental", _) => cannot_cache!("incremental"),
                    (_, _) => (),
                }
            }
            Some(Unstable(ArgUnstable { opt, value })) => match value.as_deref() {
                Some("y" | "yes" | "on") | None if opt == "profile" => {
                    gcno = true;
                }
                _ => (),
            },
            Some(Color(value)) => {
                // We'll just assume the last specified value wins.
                color_mode = match value.as_ref() {
                    "always" => ColorMode::On,
                    "never" => ColorMode::Off,
                    _ => ColorMode::Auto,
                };
            }
            Some(Json(_)) => {
                has_json = true;
            }
            Some(PassThrough(_)) => (),
            Some(Target(target)) => match target {
                ArgTarget::Path(json_path) => target_json = Some(json_path.to_owned()),
                ArgTarget::Unsure(_) => cannot_cache!("target unsure"),
                ArgTarget::Name(_) => (),
            },
            None => {
                match arg {
                    Argument::Raw(ref val) => {
                        if idx == 0
                            && let Some(value) = val.to_str()
                            && value == "rustc"
                        {
                            // If the first argument is rustc, it's likely called via clippy-driver,
                            // so it's not actually an input file, which means we should discount it.
                            continue;
                        }
                        if input.is_some() {
                            // Can't cache compilations with multiple inputs.
                            cannot_cache!(
                                "multiple input files",
                                format!("prev = {input:?}, next = {arg:?}")
                            );
                        }
                        input = Some(val.clone());
                    }
                    Argument::UnknownFlag(_) => {}
                    _ => {
                        cannot_cache!("unexpected Rust argument variant", format!("{arg:?}"));
                    }
                }
            }
        }
        // We'll drop --color arguments, we're going to pass --color=always and the client will
        // strip colors if necessary.
        match arg.get_data() {
            Some(Color(_)) => {}
            _ => args.push(arg.normalize(NormalizedDisposition::Separated)),
        }
    }

    // Unwrap required values.
    macro_rules! req {
        ($x:ident) => {
            let $x = if let Some($x) = $x {
                $x
            } else {
                debug!("Can't cache compilation, missing `{}`", stringify!($x));
                cannot_cache!(concat!("missing ", stringify!($x)));
            };
        };
    }
    // We don't actually save the input value, but there needs to be one.
    req!(input);
    drop(input);
    req!(output_dir);
    req!(emit);
    req!(crate_name);
    // We won't cache invocations that are not producing
    // binary output.
    if !emit.is_empty() && !emit.contains("link") && !emit.contains("metadata") {
        return CompilerArguments::NotCompilation;
    }
    // If it's not an rlib and not a staticlib then crate-type wasn't passed,
    // so it will usually be inferred as a binary, though the `#![crate_type`
    // annotation may dictate otherwise - either way, we don't know what to do.
    if crate_types
        == (CrateTypes {
            rlib: false,
            staticlib: false,
        })
    {
        cannot_cache!("crate-type", "No crate-type passed".to_owned())
    }
    // We won't cache invocations that are outputting anything but
    // linker output and dep-info.
    if emit.iter().any(|e| !ALLOWED_EMIT.contains(e.as_str())) {
        cannot_cache!("unsupported --emit");
    }

    // Figure out the dep-info filename, if emitting dep-info.
    let dep_info = if emit.contains("dep-info") {
        let mut dep_info = crate_name.clone();
        if let Some(extra_filename) = extra_filename.clone() {
            dep_info.push_str(&extra_filename[..]);
        }
        dep_info.push_str(".d");
        Some(dep_info)
    } else {
        None
    };

    // Ignore profile is `link` is not in emit which means we are running `cargo check`.
    let profile = if emit.contains("link") { profile } else { None };

    // Figure out the gcno filename, if producing gcno files with `-Zprofile`.
    let gcno = if gcno && emit.contains("link") {
        let mut gcno = crate_name.clone();
        if let Some(extra_filename) = extra_filename {
            gcno.push_str(&extra_filename[..]);
        }
        gcno.push_str(".gcno");
        Some(gcno)
    } else {
        None
    };

    // Locate all static libs specified on the commandline.
    let staticlibs = static_lib_names
        .into_iter()
        .filter_map(|name| {
            for path in &static_link_paths {
                for f in &[
                    format_args!("lib{name}.a"),
                    format_args!("{name}.lib"),
                    format_args!("{name}.a"),
                ] {
                    let lib_path = path.join(fmt::format(*f));
                    if lib_path.exists() {
                        return Some(lib_path);
                    }
                }
            }
            // rustc will just error if there's a missing static library, so don't worry about
            // it too much.
            None
        })
        .collect();
    // We'll figure out the source files and outputs later in
    // `generate_hash_key` where we can run rustc.
    // Cargo doesn't deterministically order --externs, and we need the hash inputs in a
    // deterministic order.
    externs.sort();
    CompilerArguments::Ok(ParsedArguments {
        arguments: args,
        output_dir,
        crate_types,
        externs,
        crate_link_paths,
        staticlibs,
        crate_name,
        dep_info: dep_info.map(std::convert::Into::into),
        profile: profile.map(std::convert::Into::into),
        gcno: gcno.map(std::convert::Into::into),
        emit,
        color_mode,
        has_json,
        target_json,
    })
}

#[async_trait]
impl<T> CompilerHasher<T> for RustHasher
where
    T: CommandCreatorSync,
{
    async fn generate_hash_key(
        &mut self,
        context: GenerateHashKeyContext<'_, T>,
    ) -> Result<HashResult<T>> {
        let GenerateHashKeyContext {
            creator,
            cwd,
            env_vars,
            may_dist,
            pool,
            cache_control,
            ..
        } = context;
        trace!("[{}]: generate_hash_key", self.parsed_args.crate_name);

        let shadow_log_path = std::env::var_os(RUST_SHADOW_LOG_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let mut effective_arguments = self.parsed_args.arguments.clone();
        let native_requested = native_target_requested(&effective_arguments);
        let target = compilation_target(&effective_arguments, &self.host);
        let mut allow_dist = true;
        let mut effective_cache_control = cache_control;
        let mut resolved_native_profile = None;
        if native_requested && may_dist {
            if target.starts_with("x86_64-") {
                rewrite_native_target_cpu(&mut effective_arguments, "x86-64-v2");
                resolved_native_profile = Some("x86-64-v2".to_owned());
                if !WARNED_DIST_NATIVE_PORTABLE.swap(true, Ordering::Relaxed) {
                    warn!(
                        "distributed Rust compile requested -C target-cpu=native; using x86-64-v2 for deterministic heterogeneous-worker codegen (performance may be reduced)"
                    );
                }
            } else {
                allow_dist = false;
                warn!(
                    "distributed Rust compile requested -C target-cpu=native for {target}; compiling locally because no portable native policy is defined for this target"
                );
            }
        }

        if native_requested && (!may_dist || !allow_dist) {
            let profile = if let Some(profile) = self.native_profile.as_ref() {
                profile.clone()
            } else {
                match cached_native_profile(
                    (*creator).clone(),
                    &self.executable,
                    &self.version,
                    &env_vars,
                )
                .await
                {
                    Ok(profile) => profile,
                    Err(error) => {
                        warn!(
                            "Failed to resolve rustc native CPU profile; bypassing cache: {error:#}"
                        );
                        effective_cache_control = CacheControl::ForceNoCache;
                        format!("unresolved:{}", self.host)
                    }
                }
            };
            resolved_native_profile = Some(profile);
        }

        let canonical_paths = CanonicalRustPaths::from_env(&env_vars, &cwd, &self.sysroot);
        if canonical_paths.is_some() {
            remove_dep_info_emit(&mut effective_arguments);
        }

        // TODO: this doesn't produce correct arguments if they should be concatenated - should use iter_os_strings
        let os_string_arguments: Vec<(OsString, Option<OsString>)> = effective_arguments
            .iter()
            .map(|arg| {
                (
                    arg.to_os_string(),
                    arg.get_data().cloned().map(IntoArg::into_arg_os_string),
                )
            })
            .collect();
        // `filtered_arguments` omits --emit and --out-dir arguments.
        // It's used for invoking rustc with `--emit=dep-info` to get the list of
        // source files for this crate.
        let hash_os_string_arguments = os_string_arguments
            .iter()
            .map(|(arg, val)| {
                if let Some(canonical) = canonical_paths.as_ref() {
                    (
                        canonical.normalize_os_value(arg),
                        val.as_ref().map(|val| canonical.normalize_os_value(val)),
                    )
                } else {
                    (arg.clone(), val.clone())
                }
            })
            .collect::<Vec<_>>();
