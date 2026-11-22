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
#[cfg(feature = "dist-client")]
use crate::compiler::DistPackagers;
use crate::compiler::args::{
    ArgDisposition, ArgInfo, ArgParseError, ArgParseResult, ArgToStringResult, ArgsIter, Argument,
    FromArg, IntoArg, NormalizedDisposition, PathTransformerFn, split_os_string_arg,
};
use crate::compiler::canonical_paths::CanonicalRustPaths;
use crate::compiler::{
    CCompileCommand, Cacheable, ColorMode, Compilation, CompileCommand, Compiler,
    CompilerArguments, CompilerHasher, CompilerKind, CompilerProxy, GenerateHashKeyContext,
    HashResult, Language, SingleCompileCommand, c::ArtifactDescriptor,
};
#[cfg(feature = "dist-client")]
use crate::dist::pkg;
#[cfg(feature = "dist-client")]
use crate::lru_disk_cache::{LruCache, Meter};
use crate::mock_command::{CommandCreatorSync, RunCommand};
use crate::util::{Digest, fmt_duration_as_secs, hash_all, hash_all_archives, run_input_output};
use crate::util::{HashToDigest, OsStrExt};
use crate::{counted_array, dist};
use async_trait::async_trait;
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
use std::collections::{BTreeSet, HashMap, HashSet};
use std::env::consts::DLL_EXTENSION;
#[cfg(feature = "dist-client")]
use std::env::consts::DLL_PREFIX;
use std::env::consts::EXE_EXTENSION;
#[cfg(feature = "dist-client")]
use std::env::consts::EXE_SUFFIX;
use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::future::Future;
use std::hash::Hash;
#[cfg(feature = "dist-client")]
use std::io::{self, Seek};
use std::io::{Read, Write};
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
use std::time::{self, SystemTime};
use walkdir::WalkDir;

use crate::errors::{Context, Result, anyhow, bail};

#[cfg(feature = "dist-client")]
const RLIB_PREFIX: &str = "lib";
#[cfg(feature = "dist-client")]
const RLIB_EXTENSION: &str = "rlib";

#[cfg(feature = "dist-client")]
const RMETA_EXTENSION: &str = "rmeta";

/// Resolve an environment path relative to the compiler cwd, preserving its
/// lexical spelling until the archive layout has recorded its traversal.
fn absolute_env_path(env_vars: &[(OsString, OsString)], name: &str, cwd: &Path) -> Option<PathBuf> {
    let value = env_vars
        .iter()
        .rev()
        .find_map(|(key, value)| (key == name).then_some(value))?;
    if value.is_empty() {
        return None;
    }
    Some(cwd.join(value))
}

/// Clippy tracks the resolved policy file, while the environment dependency
/// tracks the literal directory spelling. Keep those two identities separate.
fn clippy_config_dir(
    executable: &Path,
    env_vars: &[(OsString, OsString)],
    cwd: &Path,
) -> Option<PathBuf> {
    is_clippy_driver(executable)
        .then(|| absolute_env_path(env_vars, "CLIPPY_CONF_DIR", cwd))
        .flatten()
        .map(|path| path.canonicalize().unwrap_or(path))
}

/// Both supported Clippy policy filenames affect diagnostics and cache reuse.
fn clippy_config_inputs(directory: &Path) -> Vec<PathBuf> {
    ["clippy.toml", ".clippy.toml"]
        .into_iter()
        .map(|name| directory.join(name))
        .filter(|file| file.is_file())
        .collect()
}

/// Directory in the sysroot containing binary to which rustc is linked.
const BINS_DIR: &str = "bin";

#[cfg(feature = "dist-client")]
fn rust_dist_cargo_executable(sysroot: &Path) -> Option<PathBuf> {
    let bin = sysroot.join(BINS_DIR);
    let real_cargo = bin.join(format!("cargo.real{EXE_SUFFIX}"));
    if real_cargo.is_file() {
        return Some(real_cargo);
    }
    let cargo = bin.join(format!("cargo{EXE_SUFFIX}"));
    cargo.is_file().then_some(cargo)
}

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
    /// The custom dist toolchain archive for this rustc, if configured.
    dist_archive: Option<PathBuf>,
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
    /// The custom dist toolchain archive for this rustc, if configured.
    dist_archive: Option<PathBuf>,
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
    /// Requested output kinds.
    emit: HashSet<String>,
    /// Metadata-only invocations produce this file regardless of crate type.
    metadata_only_output: Option<String>,
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
    /// Whether only dependency metadata (not native objects) is needed.
    #[cfg(feature = "dist-client")]
    can_trim_rlibs: bool,
    /// The current working directory
    cwd: PathBuf,
    /// The environment variables
    env_vars: Vec<(OsString, OsString)>,
    /// Environment variables rustc reported as explicit source dependencies.
    /// These values are observable through `env!`/`option_env!` and must not be
    /// rewritten before compilation.
    env_dep_names: HashSet<OsString>,
    allow_dist: bool,
    #[cfg(feature = "dist-client")]
    dlltool_files: Vec<PathBuf>,
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
    cdylib: bool,
}

/// Emit types that we will cache.
static ALLOWED_EMIT: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ["link", "metadata", "dep-info"].iter().copied().collect());

/// Version number for cache key.
const CACHE_VERSION: &[u8] = b"8";

struct RustDepInfoRequest<'a, T> {
    creator: &'a T,
    crate_name: &'a str,
    executable: &'a Path,
    arguments: &'a [OsString],
    cwd: &'a Path,
    env_vars: &'a [(OsString, OsString)],
    pool: &'a tokio::runtime::Handle,
}

/// Run `rustc --emit=dep-info` to discover source files and env-deps.
///
/// The raw dep-info is retained so the caller can derive the real compilation's
/// dep-info locally instead of restoring one from a cache entry or build server.
async fn get_source_files_and_env_deps<T>(
    request: RustDepInfoRequest<'_, T>,
) -> Result<(Vec<PathBuf>, Vec<(OsString, OsString)>, String)>
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
    } = request;
    let start = time::Instant::now();
    let temp_dir = tempfile::Builder::new()
        .prefix("sccache")
        .tempdir()
        .context("Failed to create temp dir")?;
    let dep_file = temp_dir.path().join("deps.d");
    let mut spawn_arguments = arguments.to_vec();
    spawn_arguments.extend([
        OsString::from("--emit"),
        OsString::from("dep-info"),
        OsString::from("-o"),
        dep_file.as_os_str().to_owned(),
    ]);
    let prepared = super::rust_response::prepare(executable, &spawn_arguments)?;
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.args(&prepared.args)
        .env_clear()
        .envs(env_vars.to_vec())
        .current_dir(cwd);
    trace!("[{crate_name}]: get dep-info: {cmd:?}");
    let _dep_info = run_input_output(cmd, None).await?;

    let cwd = cwd.to_owned();
    let name = crate_name.to_owned();
    let parsed = pool
        .spawn_blocking(move || {
            parse_dep_file(&dep_file, &cwd)
                .with_context(|| format!("Failed to parse dep info for {name}"))
        })
        .await?;

    parsed.map(move |(files, env_deps, dep_info)| {
        trace!(
            "[{crate_name}]: got {} source files and {} env-deps from dep-info in {}",
            files.len(),
            env_deps.len(),
            fmt_duration_as_secs(&start.elapsed())
        );
        drop(temp_dir);
        (files, env_deps, dep_info)
    })
}

type ParsedDepFile = (Vec<PathBuf>, Vec<(OsString, OsString)>, String);
type CpuCacheKey = (PathBuf, String, String);
type CpuProfileCache = std::sync::Mutex<HashMap<CpuCacheKey, String>>;
type CpuCfgFeatureCache = std::sync::Mutex<HashMap<CpuCacheKey, BTreeSet<String>>>;

/// Parse dependency info from `file`, returning source paths, env-deps and raw text.
fn parse_dep_file<T, U>(file: T, cwd: U) -> Result<ParsedDepFile>
where
    T: AsRef<Path>,
    U: AsRef<Path>,
{
    let mut f = fs::File::open(file.as_ref())?;
    let mut deps = String::new();
    f.read_to_string(&mut deps)?;
    Ok((parse_dep_info(&deps, cwd), parse_env_dep_info(&deps), deps))
}

/// Return make-style prerequisite spellings from rustc dep-info.
///
/// Normal dep-info starts with `<target>: <prerequisites>`. With
/// `-Zdep-info-omit-d-target`, rustc emits only leading phony prerequisite rules.
fn dep_info_prerequisites(dep_info: &str) -> Result<Vec<String>> {
    const MAX_LEN: usize = 200;

    if dep_info.trim().is_empty() {
        bail!("dep-info written by rustc is empty");
    }
    let first = dep_info.lines().next().unwrap_or_default();
    if let Some((_, prerequisites)) = first.split_once(": ") {
        return Ok(split_make_prerequisite_spellings(prerequisites));
    }
    if first.ends_with(':') {
        return Ok(dep_info
            .lines()
            .map_while(|line| line.strip_suffix(':'))
            .map(str::to_owned)
            .collect());
    }

    let first_line = match first.char_indices().nth(MAX_LEN) {
        Some((i, _)) => format!("{}...", &first[..i]),
        None => first.to_owned(),
    };
    bail!(
        "dep-info does not start with a `<target>: <prerequisites>` rule or phony prerequisite rules; its first line is {first_line:?}"
    )
}

/// Split make-style prerequisites without losing their escaping.
fn split_make_prerequisite_spellings(prerequisites: &str) -> Vec<String> {
    let mut deps = Vec::new();
    let mut current = String::new();
    let mut iter = prerequisites.chars();
    loop {
        match iter.next() {
            Some('\\') => {
                current.push('\\');
                if let Some(next) = iter.next() {
                    current.push(next);
                }
            }
            Some(' ') if !current.is_empty() => deps.push(std::mem::take(&mut current)),
            Some(' ') => {}
            Some(c) => current.push(c),
            None => {
                if !current.is_empty() {
                    deps.push(current);
                }
                break;
            }
        }
    }
    deps
}

fn decode_make_prerequisite(spelling: &str) -> String {
    let mut path = String::new();
    let mut iter = spelling.chars().peekable();
    while let Some(c) = iter.next() {
        if c == '\\' && iter.peek() == Some(&' ') {
            path.push(' ');
            iter.next();
        } else {
            path.push(c);
        }
    }
    path
}

fn parse_dep_info<T>(dep_info: &str, cwd: T) -> Vec<PathBuf>
where
    T: AsRef<Path>,
{
    let cwd = cwd.as_ref();
    let Ok(deps) = dep_info_prerequisites(dep_info) else {
        return vec![];
    };
    let mut deps = deps
        .into_iter()
        .map(|s| cwd.join(decode_make_prerequisite(&s)))
        .collect::<Vec<_>>();
    deps.sort();
    deps
}

fn parse_env_dep_info(dep_info: &str) -> Vec<(OsString, OsString)> {
    let mut env_deps = Vec::new();
    for line in dep_info.lines() {
        if let Some(env_dep) = line.strip_prefix("# env-dep:") {
            let mut split = env_dep.splitn(2, '=');
            match (split.next(), split.next()) {
                (Some(var), Some(val)) => {
                    env_deps.push((unescape_dep_env(var).into(), unescape_dep_env(val).into()));
                }
                _ => env_deps.push((unescape_dep_env(env_dep).into(), "".into())),
            }
        }
    }
    env_deps
}

/// Undo rustc's escaping of `\`, newlines and carriage returns
/// in env-dep names and values.
fn unescape_dep_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some(c) => out.push(c),
            None => out.push('\\'),
        }
    }
    out
}

/// Derive the real compilation's dep-info from the dep-info-only prepass.
///
/// The prepass target is temporary and must never be cached or copied verbatim.
/// This replaces it with one rule per real output while preserving rustc's phony
/// prerequisite and env-dep records. Extra prerequisites are added to every rule.
fn dep_info_with_targets<'a>(
    dep_info: &str,
    targets: impl IntoIterator<Item = &'a Path>,
    extra_prerequisites: impl IntoIterator<Item = &'a Path>,
) -> Result<String> {
    let prerequisites = dep_info_prerequisites(dep_info)?;
    let first = dep_info.lines().next().unwrap_or_default();
    let rest = if first.contains(": ") {
        dep_info.split_once('\n').map_or("", |(_, rest)| rest)
    } else {
        dep_info
    };

    let extra_prerequisites = extra_prerequisites
        .into_iter()
        .map(|p| p.to_string_lossy().replace(' ', "\\ "))
        .collect::<Vec<_>>();
    let prerequisites = extra_prerequisites
        .iter()
        .map(String::as_str)
        .chain(prerequisites.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");

    let mut out = String::new();
    for target in targets {
        out.push_str(&target.to_string_lossy());
        out.push_str(": ");
        out.push_str(&prerequisites);
        out.push_str("\n\n");
    }
    for prerequisite in &extra_prerequisites {
        out.push_str(prerequisite);
        out.push_str(":\n");
    }
    out.push_str(rest.strip_prefix('\n').unwrap_or(rest));
    Ok(out)
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
    let start = time::Instant::now();
    let mut arguments = arguments;
    arguments.extend([OsString::from("--print"), OsString::from("file-names")]);
    let prepared = super::rust_response::prepare(executable, &arguments)?;
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.args(&prepared.args)
        .env_clear()
        .envs(env_vars.to_vec())
        .current_dir(cwd);
    if log_enabled!(Trace) {
        trace!("get_compiler_outputs: {cmd:?}");
    }
    let outputs = run_input_output(cmd, None).await?;

    let outstr = String::from_utf8(outputs.stdout).context("Error parsing rustc output")?;
    if log_enabled!(Trace) {
        trace!(
            "get_compiler_outputs in {}: {outstr:?}",
            fmt_duration_as_secs(&start.elapsed())
        );
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
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs.into_iter().map(|(_, hash)| hash).collect()
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

#[expect(
    clippy::struct_excessive_bools,
    reason = "shadow telemetry keeps independent boolean fields explicit because their serialized names are part of the diagnostic schema"
)]
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

fn cargo_manifest_tree_inputs(manifest: &Path, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let manifest_dir = manifest
        .parent()
        .context("Cargo manifest has no parent directory")?;

    // A proc macro runs inside rustc and may open arbitrary package data relative
    // to CARGO_MANIFEST_DIR without using proc_macro::tracked_path::path(). Such
    // reads are invisible to rustc dep-info (wayland-scanner's wayland.xml is a
    // real-world example), so include the package tree conservatively in both the
    // cache key and distributed input archive.
    //
    // Do not recurse into Cargo's output tree if the package itself is the
    // workspace root. Those files are compiler outputs, not source inputs, and
    // including them would make the cache key self-referential.
    let target_root = output_dir
        .ancestors()
        .find(|ancestor| {
            ancestor.join("CACHEDIR.TAG").is_file() || ancestor.join(".rustc_info.json").is_file()
        })
        .map(Path::to_owned);

    let mut inputs = Vec::new();
    let walker = WalkDir::new(manifest_dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            let path = entry.path();
            if target_root
                .as_ref()
                .is_some_and(|target| path == target || path.starts_with(target))
            {
                return false;
            }
            !matches!(
                entry.file_name().to_str(),
                Some(".git" | ".hg" | ".svn" | ".jj")
            )
        });

    for entry in walker {
        let entry = entry.with_context(|| {
            format!(
                "Failed to walk Cargo manifest directory {}",
                manifest_dir.display()
            )
        })?;
        if entry.path().is_file() {
            inputs.push(entry.into_path());
        }
    }
    inputs.sort();
    Ok(inputs)
}

fn rust_cache_hashes_cargo_env(name: &std::ffi::OsStr) -> bool {
    name.starts_with("CARGO_")
        && name != "CARGO_MAKEFLAGS"
        && !name.starts_with("CARGO_REGISTRIES_")
        && name != "CARGO_BUILD_JOBS"
        && name != "CARGO_ENCODED_RUSTFLAGS"
}

fn rust_cargo_env_for_hash(
    env: &[(OsString, OsString)],
    canonical: Option<&CanonicalRustPaths>,
) -> Vec<(OsString, OsString)> {
    let mut hashed = env
        .iter()
        .filter(|(name, _)| rust_cache_hashes_cargo_env(name))
        .filter(|(name, _)| {
            canonical.is_none() || !matches!(name.to_str(), Some("CARGO_HOME" | "CARGO_TARGET_DIR"))
        })
        .map(|(name, value)| {
            let value = canonical.map_or_else(
                || value.clone(),
                |canonical| canonical.env_value_to_canonical(name, value),
            );
            (name.clone(), value)
        })
        .collect::<Vec<_>>();

    if let Some(canonical) = canonical {
        if let Some(cargo_home) = canonical.cargo_home.as_ref() {
            hashed.push((
                OsString::from("CARGO_HOME"),
                canonical.env_value_to_canonical(
                    std::ffi::OsStr::new("CARGO_HOME"),
                    cargo_home.as_os_str(),
                ),
            ));
        }
        hashed.push((
            OsString::from("CARGO_TARGET_DIR"),
            canonical.env_value_to_canonical(
                std::ffi::OsStr::new("CARGO_TARGET_DIR"),
                canonical.target_root.as_os_str(),
            ),
        ));
    }

    hashed.sort();
    hashed
}

fn is_clippy_driver(executable: &Path) -> bool {
    executable
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| name.eq_ignore_ascii_case("clippy-driver"))
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

fn rust_shadow_root(canonical: &CanonicalRustPaths) -> RustShadowRoots {
    RustShadowRoots {
        build_root: canonical.build_root.to_string_lossy().into_owned(),
        target_root: canonical.target_root.to_string_lossy().into_owned(),
        cargo_home: canonical
            .cargo_home
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        rust_root: canonical.rust_root.to_string_lossy().into_owned(),
    }
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

static CPU_PROFILE_CACHE: LazyLock<CpuProfileCache> =
    LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

static CPU_CFG_FEATURE_CACHE: LazyLock<CpuCfgFeatureCache> =
    LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

fn native_target_requested(arguments: &[Argument<ArgData>]) -> bool {
    arguments.iter().rev().find_map(|arg| match arg.get_data() {
        Some(CodeGen(ArgCodegen { opt, value })) if opt == "target-cpu" => {
            Some(value.as_deref() == Some("native"))
        }
        _ => None,
    }) == Some(true)
}

fn native_tune_requested(arguments: &[Argument<ArgData>]) -> bool {
    arguments.iter().rev().find_map(|arg| match arg.get_data() {
        Some(Unstable(ArgUnstable { opt, value })) if opt == "tune-cpu" => {
            Some(value.as_deref() == Some("native"))
        }
        _ => None,
    }) == Some(true)
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

// Bump this whenever RustToolchainPackager changes which files it archives or
// where they appear. The weak map persists across sccache upgrades, so the
// package format must participate in the weak key independently of compile
// cache versioning.
const RUST_DIST_TOOLCHAIN_PACKAGE_SCHEMA: &[u8] = b"rust-dist-toolchain-package-v3";

fn dist_toolchain_weak_key_with_schema(
    compiler_shlibs_digests: &[String],
    package_schema: &[u8],
    target: &str,
    target_std_manifest_digest: Option<&str>,
    noncanonical_sysroot: Option<&Path>,
) -> String {
    // Clippy policy, manifest inputs, proc macros and --emit affect the
    // compilation cache key, not the contents of the packaged sysroot.
    let mut weak = Digest::new();
    weak.delimiter(package_schema);
    for digest in compiler_shlibs_digests {
        weak.delimiter(digest.as_bytes());
    }
    weak.delimiter(b"rust-dist-toolchain-target-v1");
    if let Some(sysroot) = noncanonical_sysroot {
        weak.delimiter(b"noncanonical-sysroot-v1");
        weak.delimiter(sysroot.as_os_str().as_encoded_bytes());
    }
    weak.delimiter(target.as_bytes());
    match target_std_manifest_digest {
        Some(digest) => {
            weak.delimiter(b"target-std-present");
            weak.delimiter(digest.as_bytes());
        }
        None => weak.delimiter(b"target-std-missing"),
    }
    weak.finish()
}

fn dist_toolchain_weak_key(
    compiler_shlibs_digests: &[String],
    target: &str,
    target_std_manifest_digest: Option<&str>,
    noncanonical_sysroot: Option<&Path>,
) -> String {
    dist_toolchain_weak_key_with_schema(
        compiler_shlibs_digests,
        RUST_DIST_TOOLCHAIN_PACKAGE_SCHEMA,
        target,
        target_std_manifest_digest,
        noncanonical_sysroot,
    )
}

fn rewrite_native_target_cpu(
    arguments: &mut Vec<Argument<ArgData>>,
    baseline_cpu: &str,
    feature_delta: &str,
) {
    let first_user_target_feature = arguments.iter().position(|arg| {
        matches!(
            arg.get_data(),
            Some(CodeGen(ArgCodegen { opt, .. })) if opt == "target-feature"
        )
    });
    let mut last_rewritten_cpu = None;
    for (index, arg) in arguments.iter_mut().enumerate() {
        if let Argument::WithValue(_, CodeGen(ArgCodegen { opt, value }), _) = arg
            && opt == "target-cpu"
            && value.as_deref() == Some("native")
        {
            *value = Some(baseline_cpu.to_owned());
            last_rewritten_cpu = Some(index);
        }
    }

    if !feature_delta.is_empty() {
        // rustc accumulates target-feature options in command-line order, while
        // target-cpu does not reset an earlier feature override. Put our
        // synthesized baseline before every original target-feature option so
        // the caller's +/- overrides always retain final authority.
        let insert_at = first_user_target_feature
            .unwrap_or_else(|| last_rewritten_cpu.map_or(0, |index| index + 1));
        arguments.insert(
            insert_at,
            Argument::WithValue(
                "-C",
                CodeGen(ArgCodegen {
                    opt: "target-feature".to_owned(),
                    value: Some(feature_delta.to_owned()),
                }),
                ArgDisposition::Separated,
            ),
        );
    }
}

fn rewrite_native_tune_cpu(arguments: &mut [Argument<ArgData>], cpu: &str) {
    for arg in arguments {
        if let Argument::WithValue(_, Unstable(ArgUnstable { opt, value }), _) = arg
            && opt == "tune-cpu"
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

async fn cached_cpu_profile<T>(
    creator: T,
    executable: &Path,
    rustc_verbose_version: &str,
    env_vars: &[(OsString, OsString)],
    cpu: Option<&str>,
) -> Result<String>
where
    T: CommandCreatorSync,
{
    let cpu_key = cpu.unwrap_or("<default>").to_owned();
    let key = (
        executable.to_owned(),
        rustc_verbose_version.to_owned(),
        cpu_key,
    );
    let cached_profile = {
        let cache = CPU_PROFILE_CACHE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.get(&key).cloned()
    };
    if let Some(profile) = cached_profile {
        return Ok(profile);
    }

    let profile = probe_cpu_profile(creator, executable, env_vars, cpu).await?;
    let mut cache = CPU_PROFILE_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(cache.entry(key).or_insert_with(|| profile.clone()).clone())
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
    cached_cpu_profile(
        creator,
        executable,
        rustc_verbose_version,
        env_vars,
        Some("native"),
    )
    .await
}

fn parse_cfg_target_features(cfg: &str) -> BTreeSet<String> {
    cfg.lines()
        .filter_map(|line| {
            line.strip_prefix("target_feature=\"")
                .and_then(|feature| feature.strip_suffix('"'))
                .map(str::to_owned)
        })
        .collect()
}

async fn cached_cpu_cfg_features<T>(
    mut creator: T,
    executable: &Path,
    rustc_verbose_version: &str,
    env_vars: &[(OsString, OsString)],
    cpu: Option<&str>,
) -> Result<BTreeSet<String>>
where
    T: CommandCreatorSync,
{
    let key = (
        executable.to_owned(),
        rustc_verbose_version.to_owned(),
        cpu.unwrap_or("<default>").to_owned(),
    );
    let cached_features = {
        let cache = CPU_CFG_FEATURE_CACHE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.get(&key).cloned()
    };
    if let Some(features) = cached_features {
        return Ok(features);
    }

    let mut cmd = creator.new_command_sync(executable);
    cmd.args(&["--print", "cfg"]);
    if let Some(cpu) = cpu {
        cmd.args(&["-C"]).arg(format!("target-cpu={cpu}"));
    }
    cmd.env_clear().envs(env_vars.to_vec());
    let output = run_input_output(cmd, None).await?;
    let cfg = String::from_utf8(output.stdout).context("rustc --print cfg was not UTF-8")?;
    let features = parse_cfg_target_features(&cfg);

    let mut cache = CPU_CFG_FEATURE_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(cache.entry(key).or_insert_with(|| features.clone()).clone())
}

fn explicit_native_feature_delta(
    native_features: &BTreeSet<String>,
    baseline_features: &BTreeSet<String>,
) -> String {
    native_features
        .iter()
        .map(|feature| format!("+{feature}"))
        .chain(
            baseline_features
                .difference(native_features)
                .map(|feature| format!("-{feature}")),
        )
        .collect::<Vec<_>>()
        .join(",")
}

fn native_profile_parts(profile: &str) -> Option<(&str, &str)> {
    let (cpu, features) = profile.split_once('|')?;
    (!cpu.is_empty()).then_some((cpu, features))
}

async fn probe_cpu_profile<T>(
    mut creator: T,
    executable: &Path,
    env_vars: &[(OsString, OsString)],
    cpu: Option<&str>,
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
    ]);
    if let Some(cpu) = cpu {
        cmd.args(&["-C"]).arg(format!("target-cpu={cpu}"));
    }
    cmd.env_clear()
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
        let hashed_archive = dist_archive.clone();
        let sysroot_and_libs = async move {
            let output = run_input_output(cmd, None).await?;
            //debug!("output.and_then: {}", output);
            let outstr = String::from_utf8(output.stdout).context("Error parsing sysroot")?;
            let sysroot = PathBuf::from(outstr.trim_end());
            let libs_path = sysroot.join(LIBS_DIR);
            let mut libs = fs::read_dir(&libs_path)
                .with_context(|| {
                    format!(
                        "Failed to list rustc sysroot: `{}`",
                        crate::util::debug_display(&libs_path)
                    )
                })?
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
            if let Some(path) = hashed_archive {
                trace!(
                    "Hashing {} along with rustc libs.",
                    crate::util::debug_display(&path)
                );
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
                sysroot,
                compiler_shlibs_digests: digests,
                dist_archive,
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
                dist_archive,
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
            host: None,
            target: None,
            dlltool_files: Vec::new(),
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
                dist_archive: self.dist_archive.clone(),
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
    ) -> Pin<Box<dyn Future<Output = Result<(PathBuf, SystemTime)>> + Send>> {
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
            trace!(
                "proxy: rustup which rustc produced: {}",
                crate::util::debug_display(&proxied_compiler)
            );
            // TODO: Delegate FS access to a thread pool if possible
            let attr = fs::metadata(proxied_compiler.as_path())
                .context("Failed to obtain metadata of the resolved, true rustc")?;

            if attr.is_file() {
                attr.modified()
                    .context("Failed to read the resolved rustc modification time")
            } else {
                Err(anyhow!(
                    "proxy: rustup resolved compiler is not of type file"
                ))
            }
            .map(move |mtime| (proxied_compiler, mtime))
        })
    }

    fn box_clone(&self) -> Box<dyn CompilerProxy<T>> {
        Box::new((*self).clone())
    }
}

impl RustupProxy {
    pub fn new<P>(proxy_executable: P) -> Self
    where
        P: AsRef<Path>,
    {
        let proxy_executable = proxy_executable.as_ref().to_owned();
        Self { proxy_executable }
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
                Ok(compiler_executable.parent().map(Path::to_owned).map_or(
                    ProxyPath::ToBeDiscovered,
                    |parent| {
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
                    },
                ))
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
                    Ok(Some(Self::new(&proxy_executable)))
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
    cdylib: bool,
    others: HashSet<String>,
}
impl FromArg for ArgCrateTypes {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let arg = String::process(arg)?;
        let mut crate_types = Self {
            rlib: false,
            staticlib: false,
            cdylib: false,
            others: HashSet::new(),
        };
        for ty in arg.split(',') {
            match ty {
                // It is assumed that "lib" always refers to "rlib", which
                // is true right now but may not be in the future
                "lib" | "rlib" => crate_types.rlib = true,
                "staticlib" => crate_types.staticlib = true,
                "cdylib" => crate_types.cdylib = true,
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
            cdylib,
            others,
        } = self;
        let mut types: Vec<_> = others
            .iter()
            .map(String::as_str)
            .chain(if rlib { Some("rlib") } else { None })
            .chain(if staticlib { Some("staticlib") } else { None })
            .chain(if cdylib { Some("cdylib") } else { None })
            .collect();
        types.sort_unstable();
        let types_string = types.join(",");
        types_string.into()
    }
    fn into_arg_string(self, _transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let Self {
            rlib,
            staticlib,
            cdylib,
            others,
        } = self;
        let mut types: Vec<_> = others
            .iter()
            .map(String::as_str)
            .chain(if rlib { Some("rlib") } else { None })
            .chain(if staticlib { Some("staticlib") } else { None })
            .chain(if cdylib { Some("cdylib") } else { None })
            .collect();
        types.sort_unstable();
        let types_string = types.join(",");
        Ok(types_string)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgLinkLibrary {
    kind: Option<String>,
    name: String,
}
impl FromArg for ArgLinkLibrary {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let (kind, name) = match split_os_string_arg(arg, "=")? {
            (kind, Some(name)) => (Some(kind), name),
            (name, None) => (None, name),
        };
        Ok(Self { kind, name })
    }
}
impl IntoArg for ArgLinkLibrary {
    fn into_arg_os_string(self) -> OsString {
        let Self { kind, name } = self;
        if let Some(kind) = kind {
            make_os_string!(kind, "=", name)
        } else {
            make_os_string!(name)
        }
    }
    fn into_arg_string(self, _transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let Self { kind, name } = self;
        if let Some(kind) = kind {
            Ok(format!("{kind}={name}"))
        } else {
            Ok(name)
        }
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
        Ok(match value {
            Some(value) if opt == "profile-use" => {
                format!(
                    "{opt}={}",
                    PathBuf::from(value).into_arg_string(transformer)?
                )
            }
            Some(value) => format!("{opt}={value}"),
            None => opt,
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
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        Ok(match self {
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

use self::ArgData::{
    CodeGen, Color, CrateName, CrateType, Emit, Extern, Json, LinkLibrary, LinkPath,
    NotCompilation, NotCompilationFlag, OutDir, PassThrough, Target, TooHardFlag, TooHardPath,
    Unstable,
};

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
    take_arg!("--edition", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--emit", String, CanBeSeparated(b'='), Emit),
    take_arg!("--error-format", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--explain", OsString, CanBeSeparated(b'='), NotCompilation),
    take_arg!("--extern", ArgExtern, CanBeSeparated(b'='), Extern),
    take_arg!("--forbid", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--force-warn", OsString, CanBeSeparated(b'='), PassThrough),
    flag!("--help", NotCompilationFlag),
    take_arg!("--json", String, CanBeSeparated(b'='), Json),
    take_arg!("--out-dir", PathBuf, CanBeSeparated(b'='), OutDir),
    take_arg!("--pretty", OsString, CanBeSeparated(b'='), NotCompilation),
    take_arg!("--print", OsString, CanBeSeparated(b'='), NotCompilation),
    take_arg!("--remap-path-prefix", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--remap-path-scope", OsString, CanBeSeparated(b'='), PassThrough),
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
    flag!("-Vv", NotCompilationFlag),
    take_arg!("-W", OsString, CanBeSeparated, PassThrough),
    take_arg!("-Z", ArgUnstable, CanBeSeparated, Unstable),
    flag!("-h", NotCompilationFlag),
    take_arg!("-l", ArgLinkLibrary, CanBeSeparated, LinkLibrary),
    take_arg!("-o", PathBuf, CanBeSeparated, TooHardPath),
    flag!("-vV", NotCompilationFlag),
]);

#[expect(
    clippy::too_many_lines,
    reason = "single-pass argument parser keeps interdependent flag state and ordering visible; splitting would require a state bag threaded through helpers"
)]
fn parse_arguments(arguments: &[OsString], cwd: &Path) -> CompilerArguments<ParsedArguments> {
    let mut args = vec![];

    let mut emit: Option<HashSet<String>> = None;
    let mut input = None;
    let mut output_dir = None;
    let mut crate_name = None;
    let mut crate_types = CrateTypes {
        rlib: false,
        staticlib: false,
        cdylib: false,
    };
    let mut other_crate_types = HashSet::new();
    let mut test_harness = false;
    let mut target_name: Option<String> = None;
    let mut has_opaque_linker_args = false;
    let mut extra_filename = None;
    let mut externs = vec![];
    let mut crate_link_paths = vec![];
    let mut static_lib_names = vec![];
    let mut static_link_paths: Vec<PathBuf> = vec![];
    let mut color_mode = ColorMode::Auto;
    let mut has_json = false;
    let mut gcno = false;
    let mut target_json = None;

    // Custom iterator to expand `@` arguments which stand for reading a file
    // and interpreting it as a list of more arguments.
    let it = try_or_cannot_cache!(
        super::rust_response::expand(arguments, cwd),
        "Rust response file"
    )
    .into_iter();
    let parsed: Vec<_> = ArgsIter::new(it, &ARGS[..]).collect();
    // Cargo commonly puts the stdin input before --print=file-names.
    // Query classification must not depend on the order of otherwise
    // unsupported compilation options. Parse rather than scan strings:
    // "--print" can itself be the value of another argument.
    if parsed.iter().any(|arg| {
        arg.as_ref()
            .is_ok_and(|arg| matches!(arg.get_data(), Some(NotCompilationFlag | NotCompilation(_))))
    }) {
        return CompilerArguments::NotCompilation;
    }

    for (idx, arg) in parsed.into_iter().enumerate() {
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
                // The kind may be inherited from a source #[link] attribute.
                let (kind, modifiers) = kind.as_deref().map_or(("static", ""), |kind| {
                    kind.split_once(':').unwrap_or((kind, ""))
                });
                if kind == "static" {
                    let name = name
                        .split_once(':')
                        .map_or(name.as_str(), |(_, rename)| rename);
                    let bundle = !modifiers.split(',').any(|m| m == "-bundle");
                    let verbatim = modifiers.split(',').any(|m| m == "+verbatim");
                    static_lib_names.push((name.to_owned(), bundle, verbatim));
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
                cdylib,
                others,
            })) => {
                other_crate_types.extend(others.iter().cloned());
                crate_types.rlib |= rlib;
                crate_types.staticlib |= staticlib;
                crate_types.cdylib |= cdylib;
            }
            Some(CrateName(value)) => crate_name = Some(value.clone()),
            Some(OutDir(value)) => output_dir = Some(value.clone()),
            Some(Extern(ArgExtern { path, .. })) => externs.push(path.clone()),
            Some(CodeGen(ArgCodegen { opt, value })) => {
                match (opt.as_ref(), value) {
                    ("extra-filename", Some(value)) => extra_filename = Some(value.to_owned()),
                    ("extra-filename", None) => cannot_cache!("extra-filename"),
                    ("linker" | "link-arg" | "link-args", _) => {
                        has_opaque_linker_args = true;
                    }
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
                _ if matches!(opt.as_ref(), "no-link" | "link-only") => {
                    // An explicit stage invocation has a different output
                    // contract from an ordinary --emit=link compilation.
                    cannot_cache!("explicit Rust link stage", opt.clone());
                }
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
                ArgTarget::Name(name) => target_name = Some(name.clone()),
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
                    Argument::UnknownFlag(ref flag) => {
                        test_harness |= flag == "--test";
                    }
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
            let Some($x) = $x else {
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
    if emit.iter().any(|e| !ALLOWED_EMIT.contains(e.as_str())) {
        cannot_cache!("unsupported --emit");
    }
    let metadata_only = emit.contains("metadata") && !emit.contains("link");
    if !metadata_only {
        // General linked Rust artifacts remain non-cacheable: their native
        // linker inputs are opaque. A test harness always links an executable,
        // irrespective of an explicit crate type.
        if !other_crate_types.is_empty() {
            let mut others: Vec<_> = other_crate_types.into_iter().collect();
            others.sort_unstable();
            cannot_cache!("crate-type", others.join(","))
        }
        if test_harness {
            cannot_cache!("crate-type", "test harness".to_owned())
        }
        if crate_types
            == (CrateTypes {
                rlib: false,
                staticlib: false,
                cdylib: false,
            })
        {
            cannot_cache!("crate-type", "No crate-type passed".to_owned())
        }
        // wasm32-wasip2's component linker ships inside the Rust sysroot.
        if crate_types.cdylib
            && (target_name.as_deref() != Some("wasm32-wasip2")
                || crate_types.rlib
                || crate_types.staticlib
                || has_opaque_linker_args)
        {
            cannot_cache!("crate-type", "cdylib".to_owned())
        }
    }
    // --print file-names reports the *linked* output even for --emit=metadata.
    // Rust metadata instead uses lib<crate-name><extra-filename>.rmeta, even
    // for executable targets where the file is an empty Cargo marker.
    let metadata_only_output = metadata_only.then(|| {
        format!(
            "lib{crate_name}{}.rmeta",
            extra_filename.as_deref().unwrap_or_default()
        )
    });

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
        .filter(|(_, bundle, _)| *bundle || crate_types.cdylib)
        .flat_map(|(name, _, verbatim)| {
            // Search target-dependent filename alternatives instead of
            // assuming the compiler uses the host archive convention.
            let names = if verbatim {
                vec![name]
            } else {
                vec![
                    format!("lib{name}.a"),
                    format!("{name}.lib"),
                    format!("{name}.a"),
                ]
            };
            static_link_paths.iter().flat_map(move |path| {
                names
                    .iter()
                    .map(|name| path.join(name))
                    .filter(|path| path.is_file())
                    .collect::<Vec<_>>()
            })
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
        gcno: gcno.map(std::convert::Into::into),
        emit,
        metadata_only_output,
        color_mode,
        has_json,
        target_json,
    })
}

/// Resolve typed path operands in the physical namespace. The same arguments
/// feed hashing, the local sandbox and the worker; in particular, a relative
/// output directory can otherwise land under /build instead of /target.
fn relocate_rust_operands(
    arguments: &mut [Argument<ArgData>],
    canonical: &CanonicalRustPaths,
    cwd: &Path,
) -> Option<()> {
    use super::canonical_paths::physical_operand;

    let relocate_path = |path: &mut PathBuf| {
        if path.is_absolute()
            && !path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            return Some(());
        }
        let physical = physical_operand(cwd, path)?;
        if !canonical.root_is_known(&physical) {
            return None;
        }
        // Preserve the existing absolute spelling unless normalization is
        // necessary. Relative operands must be mapped independently of cwd.
        *path = physical;
        Some(())
    };

    for argument in arguments {
        let path = match argument {
            Argument::WithValue(
                _,
                OutDir(path)
                | Extern(ArgExtern { path, .. })
                | LinkPath(ArgLinkPath { path, .. })
                | Target(ArgTarget::Path(path)),
                _,
            ) => path,
            Argument::WithValue(
                _,
                CodeGen(ArgCodegen {
                    opt,
                    value: Some(value),
                }),
                _,
            ) if opt == "profile-use" => {
                let mut path = PathBuf::from(&*value);
                relocate_path(&mut path)?;
                *value = path.into_os_string().into_string().ok()?;
                continue;
            }
            // Source spelling is observable through file!(). Keep a relative
            // source operand only if it still reaches the mapped input.
            Argument::Raw(input) => {
                let path = Path::new(input);
                if path.is_relative() {
                    let physical = physical_operand(cwd, path)?;
                    let mapped = canonical.to_canonical(&physical);
                    let virtual_path = canonical.canonical_cwd(cwd).join(path);
                    let mut normalized = PathBuf::new();
                    for component in virtual_path.components() {
                        match component {
                            std::path::Component::ParentDir => {
                                normalized.pop();
                            }
                            std::path::Component::CurDir => {}
                            other => normalized.push(other),
                        }
                    }
                    if normalized != mapped {
                        return None;
                    }
                }
                continue;
            }
            _ => continue,
        };
        relocate_path(path)?;
    }
    Some(())
}

#[cfg(target_os = "linux")]
pub fn relocate_raw_rust_operands(
    arguments: &[OsString],
    canonical: &CanonicalRustPaths,
    cwd: &Path,
) -> Option<Vec<OsString>> {
    let mut parsed = ArgsIter::new(
        super::rust_response::expand(arguments, cwd)
            .ok()?
            .into_iter(),
        &ARGS[..],
    )
    .collect::<std::result::Result<Vec<_>, _>>()
    .ok()?;
    relocate_rust_operands(&mut parsed, canonical, cwd)?;
    // An IPC fallback retains the original emit and color settings, unlike
    // the cacheable compile where dep-info has already been generated.
    Some(
        parsed
            .iter()
            .flat_map(|arg| arg.iter_os_strings())
            .collect(),
    )
}

/// Identify the source operand using the same typed argument grammar as
/// compiler hashing. Retain the expanded argv itself, not a reserialization:
/// linker options, repeated options, and option spellings remain exact.
#[cfg(target_os = "linux")]
pub(super) fn native_link_stage_input(
    arguments: &[OsString],
    cwd: &Path,
) -> Result<super::rust_link::RustLinkStages> {
    use anyhow::ensure;
    use std::cell::Cell;

    let expanded = super::rust_response::expand(arguments, cwd)?;
    let consumed = Cell::new(0);
    let mut input = None;
    let mut after_separator = false;
    let mut emit = None;
    let mut out_dir = None;
    let mut output_file = None;
    let mut explicit_outputs = Vec::new();
    for argument in ArgsIter::new(
        expanded
            .iter()
            .cloned()
            .inspect(|_| consumed.set(consumed.get() + 1)),
        &ARGS[..],
    )
    .with_double_dashes()
    {
        let argument = argument?;
        match &argument {
            Argument::Raw(value) if value == "--" && !after_separator => after_separator = true,
            Argument::Raw(_) => {
                ensure!(
                    input.replace(consumed.get() - 1).is_none(),
                    "multiple Rust source operands"
                );
            }
            _ => match argument.get_data() {
                Some(Unstable(option))
                    if matches!(option.opt.as_str(), "no-link" | "link-only") =>
                {
                    bail!("Rust invocation already specifies a link stage");
                }
                Some(NotCompilationFlag | NotCompilation(_)) => bail!("not a Rust compilation"),
                Some(OutDir(path)) => out_dir = Some(path.clone()),
                Some(TooHardPath(path)) if argument.flag_str() == Some("-o") => {
                    output_file = Some(path.clone());
                }
                Some(Emit(value)) => {
                    explicit_outputs.extend(value.split(',').filter_map(|kind| {
                        let (_, path) = kind.split_once('=')?;
                        (path != "-").then(|| PathBuf::from(path))
                    }));
                    ensure!(
                        emit.replace(
                            value
                                .split(',')
                                .any(|kind| kind == "link" || kind.starts_with("link="))
                        )
                        .is_none(),
                        "multiple Rust emit options"
                    );
                }
                _ => {}
            },
        }
    }
    ensure!(
        emit.unwrap_or(true),
        "Rust invocation does not emit a linked artifact"
    );
    super::rust_link::RustLinkStages::from_parsed(
        expanded,
        input.context("missing Rust source operand")?,
        cwd,
        out_dir.as_deref(),
        output_file.as_deref(),
        &explicit_outputs,
    )
}

#[async_trait]
impl<T> CompilerHasher<T> for RustHasher
where
    T: CommandCreatorSync,
{
    #[expect(
        clippy::too_many_lines,
        reason = "Rust cache-key construction is an ordered cache-key ABI; keeping every hashed input in one pipeline makes omissions and reordering auditable"
    )]
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
        let needs_literal_argfile = effective_arguments
            .iter()
            .flat_map(|arg| arg.iter_os_strings())
            .any(|arg| arg.starts_with("@"));
        let native_target = native_target_requested(&effective_arguments);
        let native_tune = native_tune_requested(&effective_arguments);
        let native_requested = native_target || native_tune;
        let target = compilation_target(&effective_arguments, &self.host);
        // Worker and bubblewrap argv are currently raw. Keep literal @
        // operands in the local response-file-aware path.
        let mut allow_dist = !needs_literal_argfile;
        let mut effective_cache_control = cache_control;
        let dlltool_result = if self.parsed_args.metadata_only_output.is_some() {
            Ok(None)
        } else {
            let explicit =
                effective_arguments
                    .iter()
                    .rev()
                    .find_map(|argument| match argument.get_data() {
                        Some(CodeGen(ArgCodegen { opt, value })) if opt == "dlltool" => {
                            value.as_deref()
                        }
                        _ => None,
                    });
            let target_json = self
                .parsed_args
                .target_json
                .as_ref()
                .map(|path| cwd.join(path));
            super::rust_dlltool::discover(
                &target,
                target_json.as_deref(),
                explicit,
                &env_vars,
                &cwd,
                pool,
            )
            .await
        };
        let dlltool_unresolved = dlltool_result.is_err();
        let dlltool_plan = match dlltool_result {
            Ok(plan) => plan,
            Err(error) => {
                warn!(
                    "Rust codegen auxiliary dependency discovery failed; bypassing cache: {error:#}"
                );
                effective_cache_control = CacheControl::ForceNoCache;
                allow_dist = false;
                None
            }
        };

        let resolved_native_profile = if native_requested {
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
                            "Failed to resolve rustc native CPU profile; bypassing cache and distributed compilation: {error:#}"
                        );
                        effective_cache_control = CacheControl::ForceNoCache;
                        allow_dist = false;
                        format!("unresolved:{}", self.host)
                    }
                }
            };
            Some(profile)
        } else {
            None
        };

        if native_requested && may_dist && allow_dist {
            if target != self.host {
                allow_dist = false;
                warn!(
                    "distributed Rust native CPU request targets {target}; compiling locally because native resolution is only proven for host target {}",
                    self.host
                );
            } else if let Some(profile) = resolved_native_profile.as_ref()
                && let Some((cpu, _llvm_features)) = native_profile_parts(profile)
            {
                if native_target {
                    let native_features = cached_cpu_cfg_features(
                        (*creator).clone(),
                        &self.executable,
                        &self.version,
                        &env_vars,
                        Some("native"),
                    )
                    .await;
                    let baseline_profile = cached_cpu_profile(
                        (*creator).clone(),
                        &self.executable,
                        &self.version,
                        &env_vars,
                        None,
                    )
                    .await;
                    match (native_features, baseline_profile) {
                        (Ok(native_features), Ok(baseline_profile)) => {
                            if let Some((baseline_cpu, _)) = native_profile_parts(&baseline_profile)
                            {
                                match cached_cpu_cfg_features(
                                    (*creator).clone(),
                                    &self.executable,
                                    &self.version,
                                    &env_vars,
                                    Some(baseline_cpu),
                                )
                                .await
                                {
                                    Ok(baseline_features) => {
                                        // Do not send the resolved CPU model itself: a VM or
                                        // firmware can mask individual ISA features while LLVM
                                        // still names the physical CPU model. Instead start from
                                        // rustc's deterministic target baseline and explicitly
                                        // reproduce every rustc-recognized host feature. LLVM-only
                                        // model features remain disabled rather than guessed.
                                        let feature_delta = explicit_native_feature_delta(
                                            &native_features,
                                            &baseline_features,
                                        );
                                        rewrite_native_target_cpu(
                                            &mut effective_arguments,
                                            baseline_cpu,
                                            &feature_delta,
                                        );
                                    }
                                    Err(error) => {
                                        allow_dist = false;
                                        warn!(
                                            "Failed to resolve rustc baseline target features for {baseline_cpu}; compiling native request locally: {error:#}"
                                        );
                                    }
                                }
                            } else {
                                allow_dist = false;
                                warn!(
                                    "rustc default CPU profile did not contain an explicit CPU name; compiling native request locally"
                                );
                            }
                        }
                        (Err(error), _) | (_, Err(error)) => {
                            allow_dist = false;
                            warn!(
                                "Failed to resolve a safe explicit rustc native feature set for {cpu}; compiling locally: {error:#}"
                            );
                        }
                    }
                }
                if allow_dist && native_tune {
                    // `tune-cpu` changes scheduling choices rather than the ISA.
                    // The native profile already gives us rustc/LLVM's local CPU
                    // name, so use that exact explicit tuning model remotely.
                    rewrite_native_tune_cpu(&mut effective_arguments, cpu);
                }
            } else {
                allow_dist = false;
                warn!(
                    "rustc native CPU profile did not contain an explicit CPU name; compiling locally"
                );
            }
        }

        let output_dir = cwd.join(&self.parsed_args.output_dir);
        let canonical_output_dir =
            super::canonical_paths::physical_operand(&cwd, &self.parsed_args.output_dir);
        let cargo_target = self
            .parsed_args
            .arguments
            .iter()
            .rev()
            .find_map(|argument| match argument.get_data() {
                Some(Target(ArgTarget::Name(name))) => Some(OsStr::new(name)),
                Some(Target(ArgTarget::Path(path))) => Some(path.as_os_str()),
                Some(Target(ArgTarget::Unsure(name))) => Some(name.as_os_str()),
                _ => None,
            });
        let mut canonical_paths = canonical_output_dir
            .as_ref()
            .filter(|_| !needs_literal_argfile)
            .and_then(|output_dir| {
                CanonicalRustPaths::from_env_with_output_dir(
                    &env_vars,
                    &cwd,
                    &self.sysroot,
                    Some(output_dir),
                    cargo_target,
                )
            });
        if dlltool_unresolved
            || canonical_paths.as_ref().is_some_and(|canonical| {
                dlltool_plan
                    .as_ref()
                    .is_some_and(|plan| !plan.canonical_visible(canonical))
            })
        {
            canonical_paths = None;
        }
        if let Some(canonical) = canonical_paths.as_ref() {
            // The sandbox mounts /build read-only and both output roots writable.
            // Validate the paths we already know before the dep-info pre-pass so
            // a bad mapping cannot make that discovery step mutate/fail under a
            // location that canonical execution could not safely use anyway.
            let mapped_output =
                canonical.to_canonical(canonical_output_dir.as_deref().unwrap_or(&output_dir));
            let writable_output = mapped_output.starts_with(Path::new("/target"))
                || (canonical.intermediate_root.is_some()
                    && mapped_output.starts_with(Path::new("/intermediate")));
            let invalid_known_path = if !canonical.root_is_known(&cwd) {
                Some(&cwd)
            } else if !writable_output {
                Some(&output_dir)
            } else {
                None
            };
            if let Some(path) = invalid_known_path {
                warn!(
                    "canonical Rust path mapping does not safely cover {}; falling back to ordinary sccache for this compilation",
                    path.display()
                );
                canonical_paths = None;
            }
        }

        // Keep the original argument set until canonical path eligibility has been
        // validated against the inputs discovered by rustc's dep-info pre-pass.
        // Canonical mode suppresses dep-info from the real compile, while an
        // ordinary fallback must preserve the caller's original --emit request.
        let prepass_os_string_arguments: Vec<(OsString, Option<OsString>)> = effective_arguments
            .iter()
            .map(|arg| {
                (
                    arg.to_os_string(),
                    arg.get_data().cloned().map(IntoArg::into_arg_os_string),
                )
            })
            .collect();

        // `filtered_arguments` omits --emit and --out-dir arguments. It is used
        // for invoking rustc with `--emit=dep-info` to discover the complete set
        // of source inputs before deciding whether canonical mode is safe.
        let filtered_arguments = prepass_os_string_arguments
            .iter()
            .filter_map(|(arg, val)| {
                if arg == "--emit" || arg == "--out-dir" {
                    None
                } else {
                    Some((arg, val))
                }
            })
            .flat_map(|(arg, val)| std::iter::once(arg).chain(val))
            .cloned()
            .collect::<Vec<_>>();
        // Find all the source files and hash them.
        let cargo_manifest = cargo_manifest_input(&env_vars, &cwd);
        let has_dynamic_extern = self
            .parsed_args
            .externs
            .iter()
            .any(|path| path.extension().is_some_and(|ext| ext == DLL_EXTENSION));
        let output_dir = if self.parsed_args.output_dir.is_absolute() {
            self.parsed_args.output_dir.clone()
        } else {
            cwd.join(&self.parsed_args.output_dir)
        };
        let cargo_manifest_tree_inputs = if has_dynamic_extern {
            cargo_manifest
                .as_deref()
                .map(|manifest| cargo_manifest_tree_inputs(manifest, &output_dir))
                .transpose()?
        } else {
            None
        };
        let source_hashes_pool = pool.clone();
        let source_files_and_hashes_and_env_deps = async {
            let (mut source_files, env_deps, dep_info_text) =
                get_source_files_and_env_deps(RustDepInfoRequest {
                    creator,
                    crate_name: &self.parsed_args.crate_name,
                    executable: &self.executable,
                    arguments: &filtered_arguments,
                    cwd: &cwd,
                    env_vars: &env_vars,
                    pool,
                })
                .await?;
            if let Some(config_dir) = clippy_config_dir(&self.executable, &env_vars, &cwd) {
                source_files.extend(clippy_config_inputs(&config_dir));
            }
            // Cargo.toml is always a compiler input: proc macros and env macros can read
            // package metadata even when rustc dep-info does not list the manifest itself.
            if let Some(manifest) = cargo_manifest.as_ref()
                && !source_files.contains(manifest)
            {
                source_files.push(manifest.clone());
            }
            // A dynamic extern can be a proc macro loaded into rustc. Such a macro can read
            // arbitrary package data through CARGO_MANIFEST_DIR without tracked_path(), so
            // include the package tree conservatively for those compilations.
            if let Some(manifest_inputs) = cargo_manifest_tree_inputs.as_ref() {
                source_files.extend(manifest_inputs.iter().cloned());
            }
            source_files.sort();
            source_files.dedup();
            let source_hashes = hash_all(&source_files, &source_hashes_pool).await?;
            Ok((source_files, source_hashes, env_deps, dep_info_text))
        };

        // Hash the contents of the externs listed on the commandline.
        trace!(
            "[{}]: hashing {} externs",
            self.parsed_args.crate_name,
            self.parsed_args.externs.len()
        );
        let abs_externs = self
            .parsed_args
            .externs
            .iter()
            .map(|e| cwd.join(e))
            .collect::<Vec<_>>();
        let extern_hashes = hash_all(&abs_externs, pool);
        // Hash the contents of the staticlibs listed on the commandline.
        trace!(
            "[{}]: hashing {} staticlibs",
            self.parsed_args.crate_name,
            self.parsed_args.staticlibs.len()
        );
        let abs_staticlibs = self
            .parsed_args
            .staticlibs
            .iter()
            .map(|s| cwd.join(s))
            .collect::<Vec<_>>();
        let staticlib_hashes = hash_all_archives(&abs_staticlibs, pool);

        // Hash the content of the specified target json file, if any.
        let mut target_json_files = Vec::new();
        if let Some(path) = &self.parsed_args.target_json {
            trace!(
                "[{}]: hashing target json file {}",
                self.parsed_args.crate_name,
                path.display()
            );
            let abs_target_json = cwd.join(path);
            target_json_files.push(abs_target_json);
        }

        let target_json_hash = hash_all(&target_json_files, pool);

        // Output filenames depend on crate type, target and naming flags, not
        // the canonical layout selected after source discovery. Query the compiler
        // in the original namespace with the physical pre-pass arguments.
        let outputs = async {
            if let Some(metadata) = &self.parsed_args.metadata_only_output {
                return Ok(vec![metadata.clone()]);
            }
            let arguments = prepass_os_string_arguments
                .iter()
                .flat_map(|(arg, val)| iter::once(arg).chain(val.as_ref()))
                .cloned()
                .collect();
            get_compiler_outputs(creator, &self.executable, arguments, &cwd, &env_vars).await
        };

        // Perform all hashing operations on the files.
        let (
            (source_files, source_hashes, mut env_deps, dep_info_text),
            extern_hashes,
            staticlib_hashes,
            target_json_hash,
            mut outputs,
        ) = futures::try_join!(
            source_files_and_hashes_and_env_deps,
            extern_hashes,
            staticlib_hashes,
            target_json_hash,
            outputs
        )?;

        if let Some(canonical) = canonical_paths.as_ref()
            && let Some(path) = source_files
                .iter()
                .chain(abs_externs.iter())
                .chain(abs_staticlibs.iter())
                .chain(target_json_files.iter())
                // An rmeta can implicitly load a host proc macro through -L
                // dependency, even when no direct --extern names that macro.
                // A split layout must cover these search directories too.
                .chain(self.parsed_args.crate_link_paths.iter())
                .find(|path| !canonical.root_is_known(path))
        {
            warn!(
                "canonical Rust path mapping does not cover {}; falling back to ordinary sccache for this compilation",
                path.display()
            );
            canonical_paths = None;
        }

        let env_dep_names = env_deps
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<HashSet<_>>();
        let observes_relocated_environment = canonical_paths.as_ref().is_some_and(|canonical| {
            let mapped = canonical.env_to_canonical(&env_vars);
            env_dep_names.iter().any(|name| {
                let original = env_vars.iter().rev().find(|(key, _)| key == name);
                let rewritten = mapped.iter().rev().find(|(key, _)| key == name);
                original != rewritten
            })
        });
        if observes_relocated_environment {
            // An observed absolute path is program data, and may also be used
            // by include!/include_str! during compilation. Preserve both the
            // value and the input layout rather than rewriting the value or
            // forcing compilation onto this host. The ordinary distributed
            // layout packages inputs at their physical Unix paths.
            debug!(
                "Rust source observes a relocated environment value; using the physical input layout"
            );
            canonical_paths = None;
        }

        if let Some(canonical) = canonical_paths.as_ref() {
            let mut relocated = effective_arguments.clone();
            if relocate_rust_operands(&mut relocated, canonical, &cwd).is_some() {
                remove_dep_info_emit(&mut relocated);
                effective_arguments = relocated;
            } else {
                debug!(
                    "Relative Rust operand cannot safely be relocated; using physical input layout"
                );
                canonical_paths = None;
            }
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
        let hash_os_string_arguments = os_string_arguments
            .iter()
            .map(|(arg, val)| {
                canonical_paths.as_ref().map_or_else(
                    || (arg.clone(), val.clone()),
                    |canonical| {
                        (
                            canonical.normalize_os_value(arg),
                            val.as_ref().map(|val| canonical.normalize_os_value(val)),
                        )
                    },
                )
            })
            .collect::<Vec<_>>();

        let shadow_inputs = shadow_log_path.as_ref().map(|_| {
            (
                rust_shadow_inputs(&source_files, &source_hashes, canonical_paths.as_ref()),
                rust_shadow_inputs(&abs_externs, &extern_hashes, canonical_paths.as_ref()),
                rust_shadow_inputs(&abs_staticlibs, &staticlib_hashes, canonical_paths.as_ref()),
                rust_shadow_inputs(
                    &target_json_files,
                    &target_json_hash,
                    canonical_paths.as_ref(),
                ),
            )
        });

        let source_hashes =
            hashes_in_canonical_path_order(&source_files, source_hashes, canonical_paths.as_ref());
        let extern_hashes =
            hashes_in_canonical_path_order(&abs_externs, extern_hashes, canonical_paths.as_ref());
        let staticlib_hashes = hashes_in_canonical_path_order(
            &abs_staticlibs,
            staticlib_hashes,
            canonical_paths.as_ref(),
        );

        // If you change any of the inputs to the hash, you should change `CACHE_VERSION`.
        let mut m = Digest::new();
        // Hash inputs:
        // 1. A version
        m.update(CACHE_VERSION);
        if effective_arguments.iter().any(|arg| {
            matches!(arg.get_data(), Some(LinkLibrary(ArgLinkLibrary { kind, name }))
                if kind.as_deref().is_none_or(|kind| kind.starts_with("static:"))
                    || name.contains(':'))
        }) {
            m.delimiter(b"native-library-inputs-v1");
        }
        if is_clippy_driver(&self.executable) {
            // Separate correctly executed Clippy from old rustc-substituted results.
            m.update(b"clippy-driver-correct-execution-v1");
        }
        if clippy_config_dir(&self.executable, &env_vars, &cwd).is_some() {
            // Never reuse earlier entries that omitted external Clippy policy files.
            m.update(b"clippy-config-inputs-v1");
        }
        if cargo_manifest.is_some() {
            // Keep the manifest-input schema scoped to Cargo builds so unrelated Rust cache
            // entries remain reusable while old Cargo entries cannot collide with this key.
            m.update(b"cargo-manifest-input-v1");
            if has_dynamic_extern {
                // Dynamic externs may be proc macros that perform untracked reads relative to
                // CARGO_MANIFEST_DIR. Their package-tree inputs use a distinct key schema.
                m.update(b"proc-macro-manifest-tree-v1");
            }
        }
        if self.parsed_args.metadata_only_output.is_some() && !self.parsed_args.crate_types.rlib {
            m.update(b"rust-metadata-output-v1");
        }
        // 2. compiler_shlibs_digests
        for d in &self.compiler_shlibs_digests {
            m.update(d.as_bytes());
        }
        if canonical_paths.is_some() {
            m.update(b"canonical-rust-layout-v2");
        }
        // Dist toolchain archives recursively contain the Rust sysroot, including
        // installed cross-target standard libraries. Key the weak toolchain cache
        // by both the effective target and rustup's target-std manifest so a
        // host-only archive cannot be reused for a later cross-target compile,
        // and installing a previously-missing target invalidates a failed/stale
        // archive without perturbing the normal compilation cache key.
        let target_std_manifest = self
            .sysroot
            .join(LIBS_DIR)
            .join("rustlib")
            .join(format!("manifest-rust-std-{target}"));
        let target_std_manifest_digest = if target_std_manifest.is_file() {
            Some(Digest::file(target_std_manifest, pool).await?)
        } else {
            None
        };
        let weak_toolchain_key = dist_toolchain_weak_key(
            &self.compiler_shlibs_digests,
            &target,
            target_std_manifest_digest.as_deref(),
            canonical_paths.is_none().then_some(self.sysroot.as_path()),
        );
        // The same selected auxiliary closure participates in both result
        // identity and the weak-to-strong archive mapping. Changing the
        // assembler, DLL generator, or any loaded library cannot reuse an
        // old compiled import library or an old toolchain package.
        let weak_toolchain_key = if let Some(plan) = &dlltool_plan {
            m.delimiter(b"rust-dlltool-closure-v1");
            m.delimiter(plan.identity.as_bytes());
            let mut weak = Digest::new();
            weak.delimiter(weak_toolchain_key.as_bytes());
            weak.delimiter(plan.identity.as_bytes());
            weak.finish()
        } else {
            weak_toolchain_key
        };
        // 3. The full commandline (self.arguments)
        // TODO: there will be full paths here, it would be nice to
        // normalize them so we can get cross-machine cache hits.
        // A few argument types are not passed in a deterministic order
        // by cargo: --extern, -L, --cfg. We'll filter those out, sort them,
        // and append them to the rest of the arguments.
        let args = {
            let (mut sortables, rest): (Vec<_>, Vec<_>) = hash_os_string_arguments
                .iter()
                // We exclude a few arguments from the hash:
                //   -L, --extern, --out-dir, --diagnostic-width
                // These contain paths which aren't relevant to the output, and the compiler inputs
                // in those paths (rlibs and static libs used in the compilation) are used as hash
                // inputs below.
                .filter(|&(arg, _)| {
                    !(arg == "--extern"
                        || arg == "-L"
                        || arg == "--check-cfg"
                        || arg == "--out-dir"
                        || arg == "--diagnostic-width")
                })
                // We also exclude `--target` if it specifies a path to a .json file. The file content
                // is used as hash input below.
                // If `--target` specifies a string, it continues to be hashed as part of the arguments.
                .filter(|&(arg, _)| self.parsed_args.target_json.is_none() || arg != "--target")
                // A few argument types were not passed in a deterministic order
                // by older versions of cargo: --extern, -L, --cfg. We'll filter the rest of those
                // out, sort them, and append them to the rest of the arguments.
                .partition(|&(arg, _)| arg == "--cfg");
            sortables.sort();
            rest.into_iter()
                .chain(sortables)
                .flat_map(|(arg, val)| iter::once(arg).chain(val.as_ref()))
                .fold(OsString::new(), |mut a, b| {
                    a.push(b);
                    a
                })
        };
        args.hash(&mut HashToDigest { digest: &mut m });
        if native_requested {
            // Keep the resolved host profile in the cache identity even when
            // `native` was rewritten to a proven-equivalent explicit CPU for
            // distributed execution. This prevents cross-host cache aliasing if
            // LLVM exposes host details not represented in rustc cfg features.
            if let Some(profile) = resolved_native_profile.as_ref() {
                profile.hash(&mut HashToDigest { digest: &mut m });
            } else {
                effective_cache_control = CacheControl::ForceNoCache;
            }
        }
        // 4. The digest of all source files (this includes src file from cmdline).
        // 5. The digest of all files listed on the commandline (self.externs).
        // 6. The digest of all static libraries listed on the commandline (self.staticlibs).
        // 7. The digest of the content of the target json file specified via `--target` (if any).
        for h in source_hashes
            .iter()
            .chain(extern_hashes.iter())
            .chain(staticlib_hashes.iter())
            .chain(target_json_hash.iter())
        {
            m.update(h.as_bytes());
        }
        // 8. Environment variables: Hash all environment variables listed in the rustc dep-info
        //    output. Additionally also has all environment variables starting with `CARGO_`,
        //    since those are not listed in dep-info but affect cacheability.
        env_deps.sort();
        if canonical_paths.is_none() && !env_deps.is_empty() {
            // Earlier physical-layout distributed builds could rewrite explicit
            // observations. Do not reuse those entries. Keep normal canonical
            // keys stable (including observed CARGO_PKG_VERSION metadata).
            m.update(b"observed-rust-environment-v2");
        }
        for (var, val) in &env_deps {
            var.hash(&mut HashToDigest { digest: &mut m });
            m.update(b"=");
            val.hash(&mut HashToDigest { digest: &mut m });
            // dep-info spells unset and empty differently but the parser
            // represents both as empty strings. Hash actual membership and
            // values wherever the old text representation is insufficient.
            let actual = env_vars
                .iter()
                .rev()
                .find(|(name, _)| name == var)
                .map(|(_, value)| value);
            if canonical_paths.is_none() || val.is_empty() || actual != Some(val) {
                m.update(b"exact-env-dependency-v1");
                actual.hash(&mut HashToDigest { digest: &mut m });
            }
        }
        let mut env_vars: Vec<_> = env_vars
            .iter()
            // Filter out RUSTC_COLOR since we control color usage with command line flags.
            // rustc reports an error when both are present.
            .filter(|(k, _)| k != "RUSTC_COLOR" || env_dep_names.contains(k))
            .cloned()
            .collect();
        env_vars.sort();
        // In canonical mode, hash Cargo's semantic defaults rather than whether
        // CARGO_HOME/CARGO_TARGET_DIR happened to be explicitly exported by the
        // invoking Cargo wrapper. Their physical roots are already represented by
        // CanonicalRustPaths, and direct env!/option_env! observations remain in
        // env_deps above and are therefore still hashed exactly as observed.
        for (var, val) in rust_cargo_env_for_hash(&env_vars, canonical_paths.as_ref()) {
            var.hash(&mut HashToDigest { digest: &mut m });
            m.update(b"=");
            val.hash(&mut HashToDigest { digest: &mut m });
        }
        if is_clippy_driver(&self.executable) {
            if canonical_paths.is_some() {
                m.delimiter(b"canonical-clippy-env-v1");
            }
            // Clippy lint flags arrive through CLIPPY_ARGS, not rustc argv.
            // Hash the environment seen by the canonical compiler, rather
            // than the physical spelling of the relocated policy directory.
            // Explicit env!/option_env! observations remain separately hashed
            // above, and the actual policy files are hashed as source inputs.
            for (var, val) in env_vars.iter().filter(|(k, _)| k.starts_with("CLIPPY_")) {
                let value = canonical_paths.as_ref().map_or_else(
                    || val.clone(),
                    |paths| paths.env_value_to_canonical(var, val),
                );
                var.hash(&mut HashToDigest { digest: &mut m });
                m.update(b"=");
                value.hash(&mut HashToDigest { digest: &mut m });
            }
        }
        // 9. The cwd of the compile. This will wind up in the rlib.
        let hash_cwd = canonical_paths
            .as_ref()
            .map_or_else(|| cwd.clone(), |canonical| canonical.canonical_cwd(&cwd));
        hash_cwd.hash(&mut HashToDigest { digest: &mut m });
        // 10. The version of the compiler.
        self.version.hash(&mut HashToDigest { digest: &mut m });

        if self.parsed_args.emit.contains("metadata")
            && self.parsed_args.metadata_only_output.is_none()
        {
            // --print file-names only reports the linked outputs.
            let metadata = outputs
                .iter()
                .filter_map(|name| name.strip_suffix(".rlib"))
                .map(|stem| format!("{stem}.rmeta"))
                .collect::<Vec<_>>();
            for name in metadata {
                if !outputs.contains(&name) {
                    outputs.push(name);
                }
            }
        }

        // Write dep-info from the local prepass rather than restoring it from a
        // cache entry or distributed build server. A cached dep-info can name paths
        // from another checkout or machine and is not a portable compiler artifact.
        if let Some(dep_info_name) = &self.parsed_args.dep_info {
            let dep_info = self.parsed_args.output_dir.join(dep_info_name);
            let targets = std::iter::once(dep_info.clone())
                .chain(outputs.iter().map(|o| self.parsed_args.output_dir.join(o)))
                .collect::<Vec<_>>();
            let text = dep_info_with_targets(
                &dep_info_text,
                targets.iter().map(PathBuf::as_path),
                self.dist_archive.as_deref(),
            )
            .with_context(|| {
                format!(
                    "Failed to derive dep-info for {}",
                    self.parsed_args.crate_name
                )
            })?;
            let path = cwd.join(&dep_info);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, text)
                .with_context(|| format!("Failed to write dep-info to {}", path.display()))?;
        }

        // Convert output files into a map of basename -> full
        // path, and remove some unneeded / non-existing ones,
        // see https://github.com/rust-lang/rust/pull/68799.
        let artifact_dir = if canonical_paths.is_some() {
            canonical_output_dir
                .as_deref()
                .unwrap_or(&self.parsed_args.output_dir)
        } else {
            &self.parsed_args.output_dir
        };
        let mut outputs = outputs
            .into_iter()
            .map(|o| {
                let p = artifact_dir.join(&o);
                (
                    o,
                    ArtifactDescriptor {
                        path: p,
                        optional: false,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        if let Some(gcno) = &self.parsed_args.gcno {
            let p = artifact_dir.join(gcno);
            outputs.insert(
                gcno.to_string_lossy().into_owned(),
                ArtifactDescriptor {
                    path: p,
                    optional: true,
                },
            );
        }
        let mut arguments = effective_arguments;
        // Request color output unless json was requested. The client will strip colors if needed.
        if !self.parsed_args.has_json
            && !env_dep_names.contains(std::ffi::OsStr::new("RUSTC_COLOR"))
        {
            arguments.push(Argument::WithValue(
                "--color",
                ArgData::Color("always".into()),
                ArgDisposition::Separated,
            ));
        }

        let inputs = source_files
            .iter()
            .chain(abs_externs.iter())
            .chain(abs_staticlibs.iter())
            .chain(target_json_files.iter())
            .cloned()
            .collect();

        let key = m.finish();

        if let Some(shadow_log_path) = shadow_log_path.as_ref() {
            let canonical = canonical_paths.as_ref();

            let dep_env = env_deps
                .iter()
                .map(|(name, value)| RustShadowEnv {
                    name: name.to_string_lossy().into_owned(),
                    // Explicit env-deps are hashed exactly as observed.
                    value: rust_shadow_env_value(name, value, None),
                })
                .collect::<Vec<_>>();

            let cargo_env = env_vars
                .iter()
                .filter(|(name, _)| rust_cache_hashes_cargo_env(name))
                .map(|(name, value)| RustShadowEnv {
                    name: name.to_string_lossy().into_owned(),
                    value: rust_shadow_env_value(name, value, canonical),
                })
                .collect::<Vec<_>>();

            let mut shadow_outputs = outputs
                .iter()
                .map(|(cache_object_key, output)| RustShadowOutput {
                    cache_object_key: cache_object_key.clone(),
                    raw_path: output.path.to_string_lossy().into_owned(),
                    key_path: canonical
                        .map_or_else(
                            || output.path.clone(),
                            |canonical| canonical.to_canonical(&output.path),
                        )
                        .to_string_lossy()
                        .into_owned(),
                    optional: output.optional,
                })
                .collect::<Vec<_>>();
            shadow_outputs.sort_by(|a, b| a.cache_object_key.cmp(&b.cache_object_key));

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let timestamp_unix_ms = u64::try_from(now.as_millis()).unwrap_or(u64::MAX);

            if let Some((
                shadow_source_inputs,
                shadow_extern_inputs,
                shadow_staticlib_inputs,
                shadow_target_json_inputs,
            )) = shadow_inputs
            {
                let record = RustShadowRecord {
                    schema: 1,
                    timestamp_unix_ms,
                    normalization_policy: if canonical.is_some() {
                        "canonical-rust-layout-v2".to_owned()
                    } else {
                        "legacy-rust-v6".to_owned()
                    },
                    cache_key: key.clone(),
                    weak_toolchain_key: weak_toolchain_key.clone(),
                    cache_version: String::from_utf8_lossy(CACHE_VERSION).into_owned(),
                    crate_name: self.parsed_args.crate_name.clone(),
                    crate_types: format!("{:?}", self.parsed_args.crate_types),
                    host: self.host.clone(),
                    target: target.clone(),
                    compiler_version: self.version.clone(),
                    compiler_shlibs_digests: self.compiler_shlibs_digests.clone(),
                    cache_control: format!("{effective_cache_control:?}"),
                    may_dist,
                    allow_dist,
                    native_requested,
                    resolved_native_profile: resolved_native_profile.clone(),
                    canonical_enabled: canonical.is_some(),
                    canonical_roots: canonical.map(rust_shadow_root),
                    cwd_raw: cwd.to_string_lossy().into_owned(),
                    cwd_key: canonical
                        .map_or_else(|| cwd.clone(), |canonical| canonical.canonical_cwd(&cwd))
                        .to_string_lossy()
                        .into_owned(),
                    sysroot_raw: self.sysroot.to_string_lossy().into_owned(),
                    sysroot_key: canonical
                        .map_or_else(
                            || self.sysroot.clone(),
                            |canonical| canonical.to_canonical(&self.sysroot),
                        )
                        .to_string_lossy()
                        .into_owned(),
                    arguments_raw: rust_shadow_args(&os_string_arguments),
                    arguments_canonical: rust_shadow_args(&hash_os_string_arguments),
                    arguments_hashed_blob: args.to_string_lossy().into_owned(),
                    source_inputs: shadow_source_inputs,
                    extern_inputs: shadow_extern_inputs,
                    staticlib_inputs: shadow_staticlib_inputs,
                    target_json_inputs: shadow_target_json_inputs,
                    dep_env,
                    cargo_env,
                    outputs: shadow_outputs,
                };
                append_rust_shadow_record(shadow_log_path, &record);
            } else if !WARNED_RUST_SHADOW_LOG.swap(true, Ordering::Relaxed) {
                warn!("Rust shadow logging enabled without an input snapshot; skipping record");
            }
        }

        Ok(HashResult {
            key,
            compilation: Box::new(RustCompilation {
                executable: self.executable.clone(),
                host: self.host.clone(),
                sysroot: self.sysroot.clone(),
                arguments,
                inputs,
                outputs,
                crate_link_paths: self.parsed_args.crate_link_paths.clone(),
                crate_name: self.parsed_args.crate_name.clone(),
                #[cfg(feature = "dist-client")]
                can_trim_rlibs: self.parsed_args.metadata_only_output.is_some()
                    || matches!(
                        self.parsed_args.crate_types,
                        CrateTypes {
                            rlib: true,
                            staticlib: false,
                            cdylib: false,
                        }
                    ),
                cwd,
                env_vars,
                env_dep_names,
                allow_dist,
                #[cfg(feature = "dist-client")]
                dlltool_files: dlltool_plan.map_or_else(Vec::new, |plan| plan.files),
                canonical_paths,
                #[cfg(feature = "dist-client")]
                rlib_dep_reader: self.rlib_dep_reader.clone(),
            }),
            weak_toolchain_key,
            cache_control: effective_cache_control,
        })
    }

    fn color_mode(&self) -> ColorMode {
        self.parsed_args.color_mode
    }

    fn output_pretty(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.parsed_args.crate_name)
    }

    fn box_clone(&self) -> Box<dyn CompilerHasher<T>> {
        Box::new((*self).clone())
    }

    fn language(&self) -> Language {
        Language::Rust
    }
}

impl<T: CommandCreatorSync> Compilation<T> for RustCompilation {
    #[expect(
        clippy::too_many_lines,
        reason = "local, canonical, and distributed Rust command construction share one argument transformation pipeline and ownership flow"
    )]
    fn generate_compile_commands(
        &self,
        path_transformer: &mut dist::PathTransformer,
        _rewrite_includes_only: bool,
    ) -> Result<(
        Box<dyn CompileCommand<T>>,
        Option<dist::CompileCommand>,
        Cacheable,
    )> {
        let Self {
            ref executable,
            ref arguments,
            ref crate_name,
            ref cwd,
            ref env_vars,
            ref env_dep_names,
            ref host,
            ref sysroot,
            allow_dist,
            ref canonical_paths,
            ..
        } = *self;

        #[cfg(not(target_os = "linux"))]
        let _ = env_dep_names;

        // Ignore unused variables
        #[cfg(not(feature = "dist-client"))]
        {
            let _ = path_transformer;
            let _ = host;
            let _ = sysroot;
            let _ = allow_dist;
        }

        trace!("[{crate_name}]: compile");

        if let Some(canonical) = canonical_paths {
            canonical.add_to_transformer(path_transformer);
        }

        let command: Box<dyn CompileCommand<T>> = canonical_paths.as_ref().map_or_else(
            || {
                Ok::<_, anyhow::Error>(CCompileCommand::boxed(SingleCompileCommand {
                    executable: executable.to_owned(),
                    arguments: arguments
                        .iter()
                        .flat_map(|arg| arg.iter_os_strings())
                        .collect(),
                    env_vars: env_vars.to_owned(),
                    cwd: cwd.to_owned(),
                    share_jobserver: true,
                }))
            },
            |canonical| {
                #[cfg(target_os = "linux")]
                {
                    let sysroot_compiler = sysroot
                        .join(BINS_DIR)
                        .join(executable.file_name().context("compiler has no filename")?);
                    Ok(CCompileCommand::boxed(CanonicalRustCompileCommand {
                        toolchain_executable: executable.to_owned(),
                        runner_arguments: canonical_bwrap_arguments(
                            canonical,
                            &sysroot_compiler,
                            arguments,
                            cwd,
                        ),
                        env_vars: canonical.env_to_canonical_preserving(env_vars, env_dep_names),
                        cwd: canonical.canonical_cwd(cwd),
                    }))
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = canonical;
                    bail!("experimental canonical Rust paths currently require Linux bubblewrap")
                }
            },
        )?;

        #[cfg(not(feature = "dist-client"))]
        let dist_command = None;
        #[cfg(feature = "dist-client")]
        let dist_command = (|| {
            if !allow_dist {
                return None;
            }
            macro_rules! try_string_arg {
                ($e:expr) => {
                    match $e {
                        Ok(s) => s,
                        Err(e) => {
                            debug!("Conversion failed for distributed compile argument: {}", e);
                            return None;
                        }
                    }
                };
            }

            // Dependency files are derived from the local source-discovery
            // pass. Never make a worker write them to the client's --out-dir,
            // which need not exist in the worker sandbox.
            let mut worker_arguments = arguments.clone();
            remove_dep_info_emit(&mut worker_arguments);
            let mut dist_arguments = vec![];
            let mut saw_target = false;

            // flat_map would be nice but the lifetimes don't work out
            for argument in &worker_arguments {
                let path_transformer_fn = &mut |p: &Path| path_transformer.as_dist(p);
                if let Argument::Raw(input_path) = argument {
                    // Need to explicitly handle the input argument as it's not parsed as a path
                    let input_path = Path::new(input_path).to_owned();
                    dist_arguments.push(try_string_arg!(
                        input_path.into_arg_string(path_transformer_fn)
                    ));
                } else {
                    if let Some(Target(_)) = argument.get_data() {
                        saw_target = true;
                    }
                    for string_arg in argument.iter_strings(path_transformer_fn) {
                        dist_arguments.push(try_string_arg!(string_arg));
                    }
                }
            }

            // We can't rely on the packaged toolchain necessarily having the same default target triple
            // as us (typically host triple), so make sure to always explicitly specify a target.
            if let Some(canonical) = canonical_paths {
                for value in &mut dist_arguments {
                    *value = canonical
                        .normalize_os_value(std::ffi::OsStr::new(value))
                        .into_string()
                        .ok()?;
                }
            }

            if !saw_target {
                dist_arguments.push(format!("--target={host}"));
            }

            let mut changed_out_dir: Option<PathBuf> = None;
            let env_vars = if let Some(canonical) = canonical_paths {
                dist::osstring_tuples_to_strings(
                    &canonical.env_to_canonical_preserving(env_vars, env_dep_names),
                )?
            } else {
                let mut env_vars = dist::osstring_tuples_to_strings(env_vars)?;
                for (k, v) in &mut env_vars {
                    match k.as_str() {
                        "OUT_DIR" => {
                            let dist_out_dir = path_transformer.as_dist(Path::new(v))?;
                            if dist_out_dir != *v {
                                changed_out_dir = Some(v.to_owned().into());
                            }
                            *v = dist_out_dir;
                        }
                        "TMPDIR"
                            if !cfg!(unix) || !env_dep_names.contains(std::ffi::OsStr::new(k)) =>
                        {
                            v.clear();
                        }
                        "CARGO" => {
                            // Cargo can export a site wrapper or rustup proxy that is outside
                            // the packaged sysroot. Prefer the Cargo binary in the automatic
                            // package when present. If it is absent, leave the value untouched
                            // for now: a configured custom toolchain may replace it after
                            // toolchain selection. The automatic path is rejected later if no
                            // suitable custom override is selected.
                            if let Some(cargo) = rust_dist_cargo_executable(sysroot) {
                                *v = path_transformer.as_dist(&cargo)?;
                            }
                        }
                        "CARGO_MANIFEST_DIR" => {
                            *v = path_transformer.as_dist(Path::new(v))?;
                        }
                        // Unix physical-layout archives preserve both the
                        // original spelling and the filesystem topology. On
                        // other platforms retain the existing path transform.
                        #[cfg(not(unix))]
                        "CLIPPY_CONF_DIR" if is_clippy_driver(executable) => {
                            let local_dir = clippy_config_dir(executable, &self.env_vars, cwd)?;
                            *v = path_transformer.as_dist(&local_dir)?;
                        }
                        _ => (),
                    }
                }
                env_vars
            };

            if canonical_paths.is_none()
                && let Some(out_dir) = changed_out_dir
                && self.inputs.iter().any(|input| input.starts_with(&out_dir))
            {
                return None;
            }

            // Add any necessary path transforms - although we haven't packaged up inputs yet, we've
            // probably seen all drives (e.g. on Windows), so let's just transform those rather than
            // trying to do every single path.
            let mut remapped_disks = HashSet::new();
            for (local_path, dist_path) in get_path_mappings(path_transformer) {
                if canonical_paths.is_some()
                    && matches!(
                        dist_path.as_str(),
                        "/build" | "/target" | "/cargo" | "/rust"
                    )
                {
                    continue;
                }
                let local_path = local_path.to_str()?;
                // "The from=to parameter is scanned from right to left, so from may contain '=', but to may not."
                if local_path.contains('=') {
                    return None;
                }
                if remapped_disks.contains(&dist_path) {
                    continue;
                }
                dist_arguments.push(format!("--remap-path-prefix={dist_path}={local_path}"));
                remapped_disks.insert(dist_path);
            }

            let sysroot_executable = sysroot.join(BINS_DIR).join(executable.file_name()?);

            Some(dist::CompileCommand {
                executable: path_transformer.as_dist(&sysroot_executable)?,
                arguments: dist_arguments,
                env_vars,
                cwd: path_transformer.as_dist_abs(cwd)?,
            })
        })();

        Ok((command, dist_command, Cacheable::Yes))
    }

    #[cfg(feature = "dist-client")]
    fn dist_environment_dependencies(&self) -> Vec<(OsString, Option<OsString>)> {
        self.env_dep_names
            .iter()
            .map(|name| {
                let value = self
                    .env_vars
                    .iter()
                    .rev()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.clone());
                (name.clone(), value)
            })
            .collect()
    }

    #[cfg(feature = "dist-client")]
    fn dist_command_uses_cargo(&self) -> bool {
        self.env_vars
            .iter()
            .any(|(key, _)| key == std::ffi::OsStr::new("CARGO"))
    }

    #[cfg(feature = "dist-client")]
    fn automatic_dist_toolchain_is_ready(&self) -> bool {
        let uses_cargo = self
            .env_vars
            .iter()
            .any(|(key, _)| key == std::ffi::OsStr::new("CARGO"));
        !uses_cargo || rust_dist_cargo_executable(&self.sysroot).is_some()
    }

    #[cfg(feature = "dist-client")]
    fn into_dist_packagers(
        self: Box<Self>,
        path_transformer: dist::PathTransformer,
    ) -> Result<DistPackagers> {
        let Self {
            inputs,
            crate_link_paths,
            sysroot,
            can_trim_rlibs,
            rlib_dep_reader,
            env_vars,
            env_dep_names,
            canonical_paths,
            dlltool_files,
            host,
            arguments,
            executable,
            cwd,
            ..
        } = *{ self };
        let mut input_dirs = Vec::new();
        if cfg!(unix) && canonical_paths.is_none() {
            // These are directory-valued compiler inputs, not arbitrary
            // environment strings. Archive only their path topology, not the
            // contents of unrelated directories.
            input_dirs.push(cwd.clone());
            for name in [
                "OUT_DIR",
                "CARGO_MANIFEST_DIR",
                "CARGO_HOME",
                "CARGO_TARGET_DIR",
                "RUSTUP_HOME",
                "TMPDIR",
                "TMP",
                "TEMP",
                "TEMPDIR",
                "HOME",
            ] {
                if env_dep_names.contains(std::ffi::OsStr::new(name))
                    && let Some(path) = absolute_env_path(&env_vars, name, &cwd)
                    && path.is_dir()
                {
                    input_dirs.push(path);
                }
            }
            if is_clippy_driver(&executable)
                && let Some(path) = absolute_env_path(&env_vars, "CLIPPY_CONF_DIR", &cwd)
            {
                input_dirs.push(path);
            }
        } else if let Some(path) = clippy_config_dir(&executable, &env_vars, &cwd) {
            input_dirs.push(path);
        }
        trace!("Dist inputs: inputs={inputs:?} crate_link_paths={crate_link_paths:?}");

        let inputs_packager = Box::new(RustInputsPackager {
            env_vars,
            input_dirs,
            crate_link_paths,
            can_trim_rlibs,
            inputs,
            path_transformer,
            rlib_dep_reader,
        });
        let canonical = canonical_paths.is_some();
        let target = compilation_target(&arguments, &host);
        let toolchain_packager = Box::new(RustToolchainPackager {
            sysroot,
            canonical,
            host: Some(host),
            target: Some(target),
            dlltool_files,
        });

        Ok((inputs_packager, toolchain_packager))
    }

    fn outputs<'a>(&'a self) -> Box<dyn Iterator<Item = FileObjectSource> + 'a> {
        Box::new(self.outputs.iter().map(|(k, v)| FileObjectSource {
            key: k.clone(),
            path: v.path.clone(),
            optional: v.optional,
        }))
    }
}

// TODO: we do end up with slashes facing the wrong way, but Windows is agnostic so it's
// mostly ok. We currently don't get mappings for every single path because it means we need to
// figure out all prefixes and send them over the wire.
#[cfg(feature = "dist-client")]
fn get_path_mappings(
    path_transformer: &dist::PathTransformer,
) -> impl Iterator<Item = (PathBuf, String)> {
    path_transformer.path_mappings()
}

#[cfg(feature = "dist-client")]
struct RustInputsPackager {
    env_vars: Vec<(OsString, OsString)>,
    input_dirs: Vec<PathBuf>,
    crate_link_paths: Vec<PathBuf>,
    can_trim_rlibs: bool,
    inputs: Vec<PathBuf>,
    path_transformer: dist::PathTransformer,
    rlib_dep_reader: Option<Arc<RlibDepReader>>,
}

#[cfg(feature = "dist-client")]
fn can_trim_this(input_path: &Path) -> bool {
    trace!(
        "can_trim_this: input_path={}",
        crate::util::debug_display(input_path)
    );
    // A dependency that also emits a linkable artifact is handed to its
    // dependents as a whole rlib rather than as metadata, so trimming it to
    // metadata strands the remote compile.
    // https://bugzilla.mozilla.org/show_bug.cgi?id=1760743
    input_path.extension().is_some_and(|e| e == RLIB_EXTENSION)
        && !has_link_artifact_sibling(input_path)
}

/// Whether `rlib` sits beside a staticlib, cdylib or dylib built from the same crate.
#[cfg(feature = "dist-client")]
fn has_link_artifact_sibling(rlib: &Path) -> bool {
    const LINK_EXTENSIONS: &[&str] = &["a", "so", "dylib", "dll", "wasm"];
    let (Some(dir), Some(stem)) = (rlib.parent(), rlib.file_stem().and_then(|s| s.to_str())) else {
        return false;
    };
    // Only some of the artifacts carry the `lib` prefix the rlib has.
    let unprefixed = stem.strip_prefix("lib").unwrap_or(stem);
    LINK_EXTENSIONS.iter().any(|ext| {
        dir.join(format!("{stem}.{ext}")).exists()
            || dir.join(format!("{unprefixed}.{ext}")).exists()
    })
}

#[test]
#[cfg(feature = "dist-client")]
fn test_can_trim_this() {
    use crate::test::utils::create_file;
    let tempdir = tempfile::Builder::new()
        .prefix("sccache_test")
        .tempdir()
        .unwrap();
    let tempdir = tempdir.path();

    // With only one rlib file we should be fine
    let rlib_file = create_file(tempdir, "libtest.rlib", |_f| Ok(())).unwrap();
    assert!(can_trim_this(&rlib_file));

    // Adding an ar from a staticlib (i.e., crate-type = ["staticlib", "rlib"]
    // we need to refuse to allow trimming
    let _ar_file = create_file(tempdir, "libtest.a", |_f| Ok(())).unwrap();
    assert!(!can_trim_this(&rlib_file));

    // Same for a cdylib, whose artifact shares the rlib's stem
    let tempdir = tempfile::Builder::new()
        .prefix("sccache_test")
        .tempdir()
        .unwrap();
    let tempdir = tempdir.path();
    let rlib_file = create_file(tempdir, "libtest.rlib", |_f| Ok(())).unwrap();
    assert!(can_trim_this(&rlib_file));
    let _so_file = create_file(tempdir, "libtest.so", |_f| Ok(())).unwrap();
    assert!(!can_trim_this(&rlib_file));

    // A wasm cdylib is the same case, minus the `lib` prefix
    let tempdir = tempfile::Builder::new()
        .prefix("sccache_test")
        .tempdir()
        .unwrap();
    let tempdir = tempdir.path();
    let rlib_file = create_file(tempdir, "libtest.rlib", |_f| Ok(())).unwrap();
    assert!(can_trim_this(&rlib_file));
    let _wasm_file = create_file(tempdir, "test.wasm", |_f| Ok(())).unwrap();
    assert!(!can_trim_this(&rlib_file));
}

/// Extract the crate name and extension from a library file path in a crate
/// link directory.
///
/// Filenames are normally `lib<crate>-<metadata-hash>.<ext>`, but cdylib and
/// staticlib outputs can have no metadata hash (e.g. `libcrc_fast.rmeta` from a
/// crate with `crate-type = ["lib", "cdylib", "staticlib"]`). In that case
/// `rsplitn(2, '-')` yields a single element, so the whole filename is the
/// libname.
#[cfg(feature = "dist-client")]
fn crate_name_and_ext_from_lib_path(path: &Path) -> Option<(&str, &str)> {
    let ext = path.extension()?.to_str()?;
    // file_stem strips the extension, giving e.g. `libcrc_fast` from
    // `libcrc_fast.rmeta`. rsplitn on the stem then correctly handles both
    // `libfoo-HASH` (normal) and `libcrc_fast` (cdylib, no hash) cases.
    let stem = path.file_stem()?.to_str()?;
    let mut rev_name_split = stem.rsplitn(2, '-');
    let _extra_filename_and_ext = rev_name_split.next();
    let libname = rev_name_split.next().unwrap_or(stem);
    if libname.starts_with(DLL_PREFIX) && ext == DLL_EXTENSION {
        Some((&libname[DLL_PREFIX.len()..], ext))
    } else if libname.starts_with(RLIB_PREFIX) && (ext == RLIB_EXTENSION || ext == RMETA_EXTENSION)
    {
        Some((&libname[RLIB_PREFIX.len()..], ext))
    } else {
        None
    }
}

#[test]
#[cfg(feature = "dist-client")]
fn test_crate_name_and_ext_from_lib_path() {
    use std::path::Path;

    // Normal rlib with metadata hash suffix
    let p = Path::new("libfoo-abc123.rlib");
    assert_eq!(crate_name_and_ext_from_lib_path(p), Some(("foo", "rlib")));

    // Normal rmeta with metadata hash suffix
    let p = Path::new("libfoo-abc123.rmeta");
    assert_eq!(crate_name_and_ext_from_lib_path(p), Some(("foo", "rmeta")));

    // cdylib output with no metadata hash suffix (crate-type includes cdylib)
    let p = Path::new("libcrc_fast.rmeta");
    assert_eq!(
        crate_name_and_ext_from_lib_path(p),
        Some(("crc_fast", "rmeta"))
    );

    // cdylib output with no metadata hash suffix, rlib variant
    let p = Path::new("libcrc_fast.rlib");
    assert_eq!(
        crate_name_and_ext_from_lib_path(p),
        Some(("crc_fast", "rlib"))
    );

    // Dynamic library with metadata hash.
    let filename = format!("{DLL_PREFIX}foo-abc123.{DLL_EXTENSION}");
    let p = Path::new(&filename);
    assert_eq!(
        crate_name_and_ext_from_lib_path(p),
        Some(("foo", DLL_EXTENSION))
    );

    // Dynamic library without metadata hash (cdylib).
    let filename = format!("{DLL_PREFIX}crc_fast.{DLL_EXTENSION}");
    let p = Path::new(&filename);
    assert_eq!(
        crate_name_and_ext_from_lib_path(p),
        Some(("crc_fast", DLL_EXTENSION))
    );

    // Not a library file
    let p = Path::new("foo.txt");
    assert_eq!(crate_name_and_ext_from_lib_path(p), None);

    // Path with multiple dashes in crate name
    let p = Path::new("libxai_file_utils-abc123.rmeta");
    assert_eq!(
        crate_name_and_ext_from_lib_path(p),
        Some(("xai_file_utils", "rmeta"))
    );
}

#[test]
#[cfg(feature = "dist-client")]
fn test_lexical_parent_traversal_dirs() {
    let path = Path::new(
        "/cargo/libc/src/new/glibc/sysdeps/nptl/bits/../../x86/nptl/bits/struct_mutex.rs",
    );
    assert_eq!(
        pkg::lexical_parent_traversal_dirs(path),
        vec![
            PathBuf::from("/cargo/libc/src/new/glibc/sysdeps/nptl/bits"),
            PathBuf::from("/cargo/libc/src/new/glibc/sysdeps/nptl"),
        ]
    );

    assert_eq!(
        pkg::lexical_parent_traversal_dirs(Path::new("/cargo/libc/src/lib.rs")),
        [] as [std::path::PathBuf; 0]
    );
}

#[test]
#[cfg(feature = "dist-client")]
fn test_rust_inputs_packager_preserves_manifest_at_canonical_path() -> Result<()> {
    use crate::dist::pkg::InputsPackager;

    let tempdir = tempfile::Builder::new()
        .prefix("sccache_manifest_dist")
        .tempdir()?;
    let crate_dir = tempdir
        .path()
        .join("registry")
        .join("src")
        .join("fast_image_resize-6.1.0");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir)?;

    let lib_rs = src_dir.join("lib.rs");
    let manifest = crate_dir.join("Cargo.toml");
    let protocol = crate_dir.join("wayland.xml");
    fs::write(&lib_rs, b"pub fn marker() {}\n")?;
    fs::write(
        &manifest,
        br#"[package]
name = "fast_image_resize"
version = "6.1.0"
"#,
    )?;
    fs::write(&protocol, b"<protocol name=\"wayland\"/>\n")?;

    let mut path_transformer = dist::PathTransformer::new();
    path_transformer.add_root_mapping(tempdir.path().to_owned(), "/cargo");

    let inputs = cargo_manifest_tree_inputs(&manifest, &tempdir.path().join("target/debug"))?;
    assert!(inputs.contains(&lib_rs));
    assert!(inputs.contains(&manifest));
    assert!(inputs.contains(&protocol));

    let packager = RustInputsPackager {
        env_vars: vec![(
            OsString::from("CARGO_PKG_NAME"),
            OsString::from("fast_image_resize"),
        )],
        crate_link_paths: vec![],
        can_trim_rlibs: true,
        inputs,
        path_transformer,
        rlib_dep_reader: None,
        input_dirs: vec![],
    };

    let mut package = Vec::new();
    Box::new(packager).write_inputs(&mut package)?;

    let mut archive = tar::Archive::new(std::io::Cursor::new(package));
    let mut paths = Vec::new();
    for entry in archive.entries()? {
        let entry = entry?;
        paths.push(entry.path()?.into_owned());
    }

    assert!(paths.contains(&PathBuf::from(
        "cargo/registry/src/fast_image_resize-6.1.0/src/lib.rs"
    )));
    assert!(paths.contains(&PathBuf::from(
        "cargo/registry/src/fast_image_resize-6.1.0/Cargo.toml"
    )));
    assert!(paths.contains(&PathBuf::from(
        "cargo/registry/src/fast_image_resize-6.1.0/wayland.xml"
    )));
    Ok(())
}

#[test]
#[cfg(feature = "dist-client")]
fn test_dist_archive_includes_clippy_config_files_and_empty_directory() -> Result<()> {
    use crate::dist::pkg::InputsPackager;
    let temp = tempfile::tempdir()?;
    let policy = temp.path().join("policy");
    fs::create_dir_all(&policy)?;
    fs::write(policy.join("clippy.toml"), b"disallowed-names = []\n")?;
    fs::write(
        policy.join(".clippy.toml"),
        b"avoid-breaking-exported-api = true\n",
    )?;

    for empty in [false, true] {
        if empty {
            for name in ["clippy.toml", ".clippy.toml"] {
                fs::remove_file(policy.join(name))?;
            }
            assert!(clippy_config_inputs(&policy).is_empty());
        }
        let mut transformer = dist::PathTransformer::new();
        transformer.add_root_mapping(policy.clone(), "/clippy-config");
        let packager = RustInputsPackager {
            env_vars: vec![],
            input_dirs: vec![policy.clone()],
            crate_link_paths: vec![],
            can_trim_rlibs: true,
            inputs: if empty {
                vec![]
            } else {
                clippy_config_inputs(&policy)
            },
            path_transformer: transformer,
            rlib_dep_reader: None,
        };
        let mut bytes = Vec::new();
        Box::new(packager).write_inputs(&mut bytes)?;
        let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
        let paths = archive
            .entries()?
            .map(|entry| Ok(entry?.path()?.into_owned()))
            .collect::<Result<Vec<_>>>()?;
        assert!(paths.iter().any(|p| p == Path::new("clippy-config")));
        if !empty {
            for name in ["clippy.toml", ".clippy.toml"] {
                assert!(paths.contains(&PathBuf::from("clippy-config").join(name)));
            }
        }
    }
    Ok(())
}

/// Dependency metadata inspection is a transfer-size optimization, not a
/// prerequisite for compiling in the worker. If any input cannot be inspected,
/// the complete search directory candidate set must be preserved.
#[cfg(feature = "dist-client")]
fn rust_dependency_names(
    inputs: &[PathBuf],
    env_vars: &[(OsString, OsString)],
    reader: Option<&RlibDepReader>,
) -> Option<HashSet<String>> {
    let reader = reader?;
    if !env_vars.iter().any(|(key, _)| key == "CARGO_PKG_NAME") {
        return None;
    }
    let mut names = HashSet::new();
    for input in inputs {
        if !input.extension().is_some_and(|extension| {
            extension == RLIB_EXTENSION
                || extension == RMETA_EXTENSION
                || extension == DLL_EXTENSION
        }) {
            continue;
        }
        match reader.discover_rlib_deps(env_vars, input) {
            Ok(dependencies) => names.extend(dependencies),
            Err(error) => {
                debug!(
                    "Unable to inspect Rust dependencies of {}: {error:#}; including all search-path candidates",
                    input.display()
                );
                return None;
            }
        }
    }
    trace!("Identified dependency crate names: {names:?}");
    Some(names)
}

#[cfg(feature = "dist-client")]
fn rust_dependency_candidates(
    crate_link_paths: &[PathBuf],
    names: Option<&HashSet<String>>,
) -> Result<Vec<PathBuf>> {
    let mut candidates = Vec::new();
    for directory in crate_link_paths {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("Failed to read Rust crate search directory"),
        };
        for entry in entries {
            let path = entry?.path();
            let Some((name, extension)) = crate_name_and_ext_from_lib_path(&path) else {
                continue;
            };
            if names.is_some_and(|names| !names.contains(name)) || !path.is_file() {
                continue;
            }
            if !super::CAN_DIST_DYLIBS && extension == DLL_EXTENSION {
                bail!("Cannot distribute dylib input {}", path.display());
            }
            candidates.push(path);
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    Ok(candidates)
}

#[test]
#[cfg(feature = "dist-client")]
fn test_dist_dependency_inspection_failure_keeps_all_candidates() -> Result<()> {
    use crate::dist::pkg::InputsPackager as _;
    let tmp = tempfile::tempdir()?;
    let deps = tmp.path().join("deps");
    fs::create_dir(&deps)?;
    let explicit = deps.join("libdirect-abc.rlib");
    let transitive = deps.join("libtransitive-def.rmeta");
    let metadata = b"metadata payload";
    let plain_archive = {
        let mut bytes = Vec::new();
        ar::Builder::new(&mut bytes)
            .append(&ar::Header::new(b"object.o".to_vec(), 3), &b"obj"[..])?;
        bytes
    };
    fs::write(&explicit, &plain_archive)?;
    fs::write(&transitive, metadata)?;
    fs::write(deps.join("unrelated.txt"), b"not a crate")?;
    // Metadata reader unavailable for this individual input, even though
    // discovery was enabled when the server initialized the compiler.
    let reader = Arc::new(RlibDepReader {
        cache: Mutex::new(LruCache::with_meter(1024, DepsSize)),
        executable: tmp.path().join("missing-rustc"),
        ls_arg: "ls=root".into(),
    });
    let env_vars = vec![("CARGO_PKG_NAME".into(), "test".into())];
    let inputs = vec![explicit];
    let mut transformer = dist::PathTransformer::new();
    transformer.add_root_mapping(tmp.path().to_owned(), "/target");
    let packager = RustInputsPackager {
        env_vars,
        input_dirs: vec![],
        crate_link_paths: vec![deps],
        can_trim_rlibs: true,
        inputs,
        path_transformer: transformer,
        rlib_dep_reader: Some(reader),
    };
    let mut bytes = Vec::new();
    Box::new(packager).write_inputs(&mut bytes)?;
    let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
    let mut packaged = HashMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        assert!(packaged.insert(path, bytes).is_none());
    }
    assert_eq!(packaged.len(), 2);
    assert_eq!(
        packaged[Path::new("target/deps/libdirect-abc.rlib")],
        plain_archive
    );
    assert_eq!(
        packaged[Path::new("target/deps/libtransitive-def.rmeta")],
        metadata
    );
    Ok(())
}

#[test]
#[cfg(feature = "dist-client")]
fn test_dist_rlib_trimming_preserves_recognized_metadata() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("libtest.rlib");
    {
        let file = fs::File::create(&path)?;
        let mut builder = ar::Builder::new(file);
        builder.append(&ar::Header::new(b"code.o".to_vec(), 4), &b"code"[..])?;
        builder.append(
            &ar::Header::new(b"rust.metadata.bin".to_vec(), 4),
            &b"meta"[..],
        )?;
    }
    let payload = rlib_metadata_archive(&mut fs::File::open(&path)?)?
        .context("expected to trim recognized metadata")?;
    let mut trimmed = ar::Archive::new(std::io::Cursor::new(payload));
    {
        let mut entry = trimmed.next_entry().context("missing metadata member")??;
        assert_eq!(entry.header().identifier(), b"rust.metadata.bin");
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        assert_eq!(data, b"meta");
    }
    assert!(trimmed.next_entry().is_none());
    Ok(())
}

#[cfg(feature = "dist-client")]
impl pkg::InputsPackager for RustInputsPackager {
    fn write_inputs(self: Box<Self>, wtr: &mut dyn io::Write) -> Result<()> {
        debug!("Packaging compile inputs for compile");
        let Self {
            crate_link_paths,
            can_trim_rlibs,
            inputs,
            path_transformer,
            rlib_dep_reader,
            env_vars,
            input_dirs,
        } = *{ self };

        let dependency_names =
            rust_dependency_names(&inputs, &env_vars, rlib_dep_reader.as_deref());
        let crate_libraries =
            rust_dependency_candidates(&crate_link_paths, dependency_names.as_ref())?;

        let mut paths = pkg::InputArchivePaths::new(path_transformer);
        let mut all_tar_inputs = Vec::with_capacity(inputs.len() + crate_libraries.len());
        for input_path in inputs.into_iter().chain(crate_libraries) {
            if !super::CAN_DIST_DYLIBS
                && input_path
                    .extension()
                    .is_some_and(|ext| ext == DLL_EXTENSION)
            {
                bail!(
                    "Cannot distribute dylib input {} on this platform",
                    input_path.display()
                );
            }
            all_tar_inputs.push(paths.file(&input_path)?);
        }
        // The explicit externs and implicit search directories can refer to
        // the same file, including via symlink aliases.
        all_tar_inputs.sort_unstable();
        all_tar_inputs.dedup();
        for directory in input_dirs {
            paths.directory(&directory)?;
        }

        let mut builder = tar::Builder::new(wtr);

        for (input_path, dist_input_path) in &all_tar_inputs {
            let mut file_header = pkg::make_tar_header(input_path, dist_input_path)?;
            let mut file = fs::File::open(input_path)?;
            if can_trim_rlibs && can_trim_this(input_path) {
                match rlib_metadata_archive(&mut file) {
                    Ok(Some(metadata_ar)) => {
                        file_header.set_size(metadata_ar.len() as u64);
                        file_header.set_cksum();
                        builder.append(&file_header, metadata_ar.as_slice())?;
                        continue;
                    }
                    Ok(None) => debug!(
                        "No recognized metadata member in {}; transferring full rlib",
                        input_path.display()
                    ),
                    Err(error) => debug!(
                        "Unable to trim {}: {error:#}; transferring full rlib",
                        input_path.display()
                    ),
                }
                file.rewind()?;
            }
            file_header.set_cksum();
            builder.append(&file_header, file)?;
        }

        paths.append_support_entries(&mut builder)?;
        // Finish archive
        builder.into_inner()?;
        Ok(())
    }
}

#[cfg(feature = "dist-client")]
fn rlib_metadata_archive(file: &mut fs::File) -> Result<Option<Vec<u8>>> {
    let mut archive = ar::Archive::new(file);
    while let Some(entry) = archive.next_entry() {
        let mut entry = entry?;
        if entry.header().identifier() == b"rust.metadata.bin" {
            let mut metadata = Vec::new();
            {
                let mut builder = ar::Builder::new(&mut metadata);
                builder.append(&entry.header().clone(), &mut entry)?;
            }
            return Ok(Some(metadata));
        }
    }
    Ok(None)
}

#[cfg(feature = "dist-client")]
struct RustToolchainPackager {
    sysroot: PathBuf,
    dlltool_files: Vec<PathBuf>,
    canonical: bool,
    // Compiler-wide callers have no target; preserve full-package semantics.
    host: Option<String>,
    target: Option<String>,
}

// Keep the runtime and unknown rustlib extensions. Only remove directories
// explicitly identified as standard libraries for other installed targets.
#[cfg(all(feature = "dist-client", target_os = "linux"))]
fn rustlib_entries_for_target(rustlib: &Path, host: &str, target: &str) -> Result<Vec<PathBuf>> {
    let mut selected = Vec::new();
    for entry in fs::read_dir(rustlib)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_str();

        if matches!(name_str, Some("src" | "etc")) {
            continue;
        }

        let is_other_target = name_str
            .and_then(|name| {
                name.strip_prefix("manifest-rust-std-").or_else(|| {
                    (path.is_dir() && rustlib.join(format!("manifest-rust-std-{name}")).is_file())
                        .then_some(name)
                })
            })
            .is_some_and(|triple| triple != host && triple != target);
        if is_other_target {
            continue;
        }
        selected.push(path);
    }
    selected.sort();
    Ok(selected)
}

#[cfg(all(test, feature = "dist-client", target_os = "linux"))]
#[test]
fn test_rustlib_entries_keep_host_requested_target_and_unknown_extensions() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let rustlib = temp.path();
    let host = "x86_64-unknown-linux-gnu";
    let target = "wasm32-wasip2";
    let unused = "aarch64-unknown-linux-musl";
    for dir in [host, target, unused, "src", "etc", "custom-extension"] {
        fs::create_dir_all(rustlib.join(dir))?;
        fs::write(rustlib.join(dir).join("file"), b"important")?;
    }
    for triple in [host, target, unused] {
        fs::write(
            rustlib.join(format!("manifest-rust-std-{triple}")),
            b"installed",
        )?;
    }
    fs::write(rustlib.join("components"), b"rustc")?;
    let selected = rustlib_entries_for_target(rustlib, host, target)?;
    let names: HashSet<_> = selected
        .iter()
        .filter_map(|path| path.file_name().and_then(std::ffi::OsStr::to_str))
        .collect();
    for keep in [
        host,
        target,
        "custom-extension",
        "components",
        "manifest-rust-std-x86_64-unknown-linux-gnu",
        "manifest-rust-std-wasm32-wasip2",
    ] {
        assert!(
            names.contains(keep),
            "required rustlib entry missing: {keep}"
        );
    }
    for skip in [
        unused,
        "src",
        "etc",
        "manifest-rust-std-aarch64-unknown-linux-musl",
    ] {
        assert!(
            !names.contains(skip),
            "unneeded rustlib entry retained: {skip}"
        );
    }
    Ok(())
}

#[cfg(all(
    test,
    feature = "dist-client",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn test_dist_toolchain_archive_contains_only_required_installed_targets() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let sysroot = temp.path().join("sysroot");
    let bin = sysroot.join(BINS_DIR);
    let lib = sysroot.join(LIBS_DIR);
    let rustlib = lib.join("rustlib");
    fs::create_dir_all(&bin)?;
    let host = "x86_64-unknown-linux-gnu";
    let target = "wasm32-wasip2";
    let unused = "aarch64-unknown-linux-musl";
    for triple in [host, target, unused] {
        let folder = rustlib.join(triple).join("lib");
        fs::create_dir_all(&folder)?;
        fs::write(folder.join("libstd.rlib"), triple.as_bytes())?;
        fs::write(
            rustlib.join(format!("manifest-rust-std-{triple}")),
            b"installed",
        )?;
    }
    fs::write(lib.join("other_runtime"), b"needed")?;
    fs::copy("/bin/true", bin.join("rustc"))?;
    fs::copy("/bin/true", bin.join("clippy-driver"))?;
    let archive_path = temp.path().join("toolchain.tar.gz");
    let writer = fs::File::create(&archive_path)?;
    let packager = RustToolchainPackager {
        sysroot,
        canonical: true,
        host: Some(host.to_owned()),
        target: Some(target.to_owned()),
        dlltool_files: Vec::new(),
    };
    pkg::ToolchainPackager::write_pkg(Box::new(packager), writer)?;
    let reader = fs::File::open(archive_path)?;
    let mut archive = tar::Archive::new(crate::compression::deflate::InflateReader::gzip(reader)?);
    let paths = archive
        .entries()?
        .map(|entry| -> Result<PathBuf> { Ok(entry?.path()?.into_owned()) })
        .collect::<Result<Vec<_>>>()?;
    let includes = |fragment: &str| {
        paths
            .iter()
            .any(|path| path.to_string_lossy().ends_with(fragment))
    };
    assert!(includes("rust/bin/clippy-driver"));
    assert!(includes("rust/lib/other_runtime"));
    assert!(includes(&format!(
        "rust/lib/rustlib/{host}/lib/libstd.rlib"
    )));
    assert!(includes(&format!(
        "rust/lib/rustlib/{target}/lib/libstd.rlib"
    )));
    assert!(!includes(&format!(
        "rust/lib/rustlib/{unused}/lib/libstd.rlib"
    )));
    Ok(())
}

#[cfg(feature = "dist-client")]
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl pkg::ToolchainPackager for RustToolchainPackager {
    fn prepare_namespace(self: Box<Self>) -> Result<(String, Box<dyn pkg::ToolchainPackager>)> {
        self.package_builder()?.prepare_namespace()
    }

    fn write_pkg(self: Box<Self>, f: fs::File) -> Result<()> {
        self.package_builder()?.write_compressed_tar(f)
    }
}

#[cfg(all(
    feature = "dist-client",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl RustToolchainPackager {
    fn package_builder(self) -> Result<pkg::ToolchainPackageBuilder> {
        info!(
            "Packaging Rust compiler for sysroot {}",
            self.sysroot.display()
        );
        let Self {
            sysroot,
            canonical,
            host,
            target,
            dlltool_files,
        } = self;

        let mut package_builder = pkg::ToolchainPackageBuilder::new();
        if canonical {
            package_builder.add_root_mapping(sysroot.clone(), PathBuf::from("/rust"));
        }
        package_builder.add_common()?;

        for dependency in dlltool_files {
            package_builder.add_file(dependency)?;
        }

        let bins_path = sysroot.join(BINS_DIR);
        let sysroot_executable = bins_path.join("rustc").with_extension(EXE_EXTENSION);
        package_builder.add_executable_and_deps(sysroot_executable)?;

        package_builder.add_dir_contents(&bins_path)?;
        if BINS_DIR != LIBS_DIR {
            let libs_path = sysroot.join(LIBS_DIR);
            let rustlib = libs_path.join("rustlib");
            if let (Some(host), Some(target)) = (host.as_deref(), target.as_deref())
                && target != "custom-target"
                && rustlib.join(host).is_dir()
                && rustlib.join(target).is_dir()
            {
                for entry in fs::read_dir(&libs_path)? {
                    let entry = entry?;
                    let path = entry.path();
                    let entries = if path == rustlib {
                        rustlib_entries_for_target(&rustlib, host, target)?
                    } else {
                        vec![path]
                    };
                    for path in entries {
                        if path.is_dir() {
                            package_builder.add_dir_contents(&path)?;
                        } else if path.is_file() {
                            package_builder.add_file(path)?;
                        }
                    }
                }
            } else {
                // Unknown/custom target, incomplete sysroot, or compiler-wide
                // packaging: preserve all potentially required runtimes.
                package_builder.add_dir_contents(&libs_path)?;
            }
        }

        Ok(package_builder)
    }
}

#[cfg(feature = "dist-client")]
#[derive(Debug)]
struct RlibDepsDetail {
    deps: Vec<String>,
    mtime: time::SystemTime,
}

#[cfg(feature = "dist-client")]
struct DepsSize;
#[cfg(feature = "dist-client")]
impl Meter<PathBuf, RlibDepsDetail> for DepsSize {
    type Measure = usize;
    fn measure<Q: ?Sized>(&self, _k: &Q, v: &RlibDepsDetail) -> usize
    where
        PathBuf: Borrow<Q>,
    {
        use std::mem;

        // TODO: unfortunately there is exactly nothing you can do with the k given the
        // current trait bounds. Just use some kind of sane value;
        //let k_size = mem::size_of::<PathBuf>() + k.capacity();
        let k_size = 3 * 8 + 100;

        let crate_names_size: usize = v.deps.iter().map(std::string::String::capacity).sum();
        let v_size: usize = mem::size_of::<RlibDepsDetail>() + // Systemtime and vec itself
            v.deps.capacity() * mem::size_of::<String>() + // Each string in the vec
            crate_names_size; // Contents of all strings

        k_size + v_size
    }
}

#[cfg(feature = "dist-client")]
#[derive(Debug)]
struct RlibDepReader {
    cache: Mutex<LruCache<PathBuf, RlibDepsDetail, RandomState, DepsSize>>,
    executable: PathBuf,
    ls_arg: String,
}

#[cfg(feature = "dist-client")]
impl RlibDepReader {
    fn new_with_check(executable: PathBuf, env_vars: &[(OsString, OsString)]) -> Result<Self> {
        const CACHE_SIZE: u64 = 3 * 1024 * 1024;

        let temp_dir = tempfile::Builder::new()
            .prefix("sccache-rlibreader")
            .tempdir()
            .context("Could not create temporary directory for rlib output")?;
        let temp_rlib = temp_dir.path().join("x.rlib");

        let mut cmd = process::Command::new(&executable);
        cmd.arg("--crate-type=rlib")
            .arg("-o")
            .arg(&temp_rlib)
            .arg("-")
            .env_clear()
            .envs(env_vars.to_vec());

        let process::Output {
            status,
            stdout,
            stderr,
        } = cmd
            .stdin(process::Stdio::piped())
            .output()
            .context("could not execute Rust dependency probe")?;

        if !stdout.is_empty() {
            bail!(
                "rustc stdout non-empty when compiling a minimal rlib: {:?}",
                String::from_utf8_lossy(&stdout)
            )
        }
        if !stderr.is_empty() {
            bail!(
                "rustc stderr non-empty when compiling a minimal rlib: {:?}",
                String::from_utf8_lossy(&stderr)
            )
        }
        if !status.success() {
            bail!(
                "Failed to compile a minimal rlib with {}",
                executable.display()
            )
        }

        // The goal of this cache is to avoid repeated lookups when building a single project. Let's budget 3MB.
        // Allowing for a 100 byte path, 50 dependencies per rlib and 20 characters per crate name, this roughly
        // approximates to `path_size + path + vec_size + num_deps * (systemtime_size + string_size + crate_name_len)`
        //                 `   3*8    +  100 +   3*8    +    50    * (      8         +     3*8     +       20      )`
        //                 `2748` bytes per crate
        // Allowing for possible overhead of up to double (for unused space in allocated memory), this means we
        // can cache information from about 570 rlibs - easily enough for a single project.
        let cache = LruCache::with_meter(CACHE_SIZE, DepsSize);
        let rustc_version = Self::get_rustc_version(&executable, env_vars)?;

        let rlib_dep_reader = Self {
            cache: Mutex::new(cache),
            executable,
            ls_arg: Self::get_correct_ls_arg(&rustc_version),
        };
        if let Err(e) = rlib_dep_reader.discover_rlib_deps(env_vars, &temp_rlib) {
            bail!("Failed to read deps from minimal rlib: {e}")
        }

        Ok(rlib_dep_reader)
    }

    fn get_rustc_version(
        executable: &PathBuf,
        env_vars: &[(OsString, OsString)],
    ) -> Result<Version> {
        let mut cmd = process::Command::new(executable);
        cmd.arg("--version").env_clear().envs(env_vars.to_vec());

        let process::Output {
            status,
            stdout,
            stderr,
        } = cmd
            .stdin(process::Stdio::piped())
            .output()
            .context("could not execute Rust dependency probe")?;

        if !status.success() {
            bail!("Failed to get rustc version with {}", executable.display())
        }
        if stdout.is_empty() {
            bail!("rustc stdout empty when parsing version")
        }
        if !stderr.is_empty() {
            bail!(
                "rustc stderr non-empty when parsing version: {:?}",
                String::from_utf8_lossy(&stderr)
            )
        }

        Self::parse_rustc_version(&stdout)
    }

    fn parse_rustc_version(stdout: &[u8]) -> Result<Version> {
        let stdout_string = String::from_utf8_lossy(stdout);
        let rustc_version: Vec<&str> = stdout_string.split_whitespace().collect();
        if rustc_version[0] != "rustc" {
            bail!(
                "Expected rustc string in rustc version with {:?}",
                String::from_utf8_lossy(stdout)
            )
        }

        Ok(Version::parse(rustc_version[1])?)
    }

    fn get_correct_ls_arg(version: &Version) -> String {
        if version.major <= 1 && version.minor <= 74 {
            String::from("ls")
        } else {
            String::from("ls=root")
        }
    }

    fn discover_rlib_deps(
        &self,
        env_vars: &[(OsString, OsString)],
        rlib: &Path,
    ) -> Result<Vec<String>> {
        let rlib_mtime = fs::metadata(rlib)
            .and_then(|m| m.modified())
            .context("Unable to get rlib modified time")?;

        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| anyhow!("rlib dependency cache mutex poisoned"))?;
            if let Some(deps_detail) = cache.get(rlib)
                && rlib_mtime == deps_detail.mtime
            {
                return Ok(deps_detail.deps.clone());
            }
        }

        trace!("Discovering dependencies of {}", rlib.display());

        let mut cmd = process::Command::new(&self.executable);
        cmd.args(["-Z", &self.ls_arg])
            .arg(rlib)
            .env_clear()
            .envs(env_vars.to_vec())
            .env("RUSTC_BOOTSTRAP", "1"); // TODO: this is fairly naughty

        let process::Output {
            status,
            stdout,
            stderr,
        } = cmd
            .stdin(process::Stdio::piped())
            .output()
            .context("could not execute Rust dependency probe")?;

        if !status.success() {
            bail!(format!("Failed to list deps of {}", rlib.display()))
        }
        if !stderr.is_empty() {
            bail!(
                "rustc -Z ls stderr non-empty: {:?}",
                String::from_utf8_lossy(&stderr)
            )
        }

        let stdout = String::from_utf8(stdout).context("Error parsing rustc -Z ls output")?;
        let deps: Vec<_> = parse_rustc_z_ls(&stdout).map(|deps| {
            deps.into_iter()
                .map(std::borrow::ToOwned::to_owned)
                .collect()
        })?;

        {
            // This will behave poorly if the rlib is changing under our feet, but in that case rustc
            // will also do the wrong thing, so the user has bigger issues to deal with.
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| anyhow!("rlib dependency cache mutex poisoned"))?;
            cache.insert(
                rlib.to_owned(),
                RlibDepsDetail {
                    deps: deps.clone(),
                    mtime: rlib_mtime,
                },
            );
        }
        Ok(deps)
    }
}

// Parse output like the following:
//
// ```
// =External Dependencies=
// 1 std-08a5bd1ca58a28ee
// 2 core-ed31c38c1a60e6f9
// 3 compiler_builtins-6bd92a903b271497
// 4 alloc-5184f4fa2c87f835
// 5 alloc_system-7a70df28ae5ce6c3
// 6 libc-fb97b8e8c331f065
// 7 unwind-3fec89e45492b583
// 8 alloc_jemalloc-3e9fce05c4bf31e5
// 9 panic_unwind-376f1801255ba526
// 10 bitflags-f482823cbc05f4d7
// 11 cfg_if-cf72e166fff77ced
// ```
#[cfg(feature = "dist-client")]
fn parse_rustc_z_ls(stdout: &str) -> Result<Vec<&str>> {
    let mut lines = stdout.lines();
    loop {
        match lines.next() {
            Some("=External Dependencies=") => break,
            Some(_s) => {}
            None => bail!("No output from rustc -Z ls"),
        }
    }

    let mut dep_names = vec![];

    for line in &mut lines {
        if line.is_empty() {
            break;
        }

        let mut line_splits = line.splitn(2, ' ');
        let num: usize = line_splits
            .next()
            .context("Zero strings from line split")?
            .parse()
            .context("Could not parse number from rustc -Z ls")?;
        let libstring = line_splits
            .next()
            .context("No lib string on line from rustc -Z ls")?;
        // The libstring may contain additional metadata after the crate name
        // (e.g., "crc_fast hash 05bce6... host_hash None kind Unconditional public"
        // when the crate has no -HASH suffix). Take only the first
        // whitespace-delimited token so rsplitn(-) below operates on just
        // the crate name, not the entire trailing metadata.
        let libstring = libstring
            .split_whitespace()
            .next()
            .context("No lib string on line from rustc -Z ls")?;
        if num != dep_names.len() + 1 {
            bail!("Unexpected numbering of {libstring} in rustc -Z ls output")
        }

        let mut libstring_splits = libstring.rsplitn(2, '-');
        // Most things get printed as ${LIBNAME}-${HASH} but for some things
        // (native code-only libraries?), ${LIBNAME} is all you get.
        let libname = {
            let maybe_hash = libstring_splits
                .next()
                .context("Nothing in lib string from `rustc -Z ls`")?;
            libstring_splits.next().map_or(maybe_hash, |name| name)
        };

        dep_names.push(libname);
    }

    for line in lines {
        if !line.is_empty() {
            bail!("Trailing non-blank lines in rustc -Z ls output")
        }
    }

    Ok(dep_names)
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::compiler::*;
    use crate::mock_command::*;
    use crate::test::mock_storage::MockStorage;
    use crate::test::utils::*;
    use fs::File;
    use itertools::Itertools;
    use std::ffi::OsStr;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use test_case::test_case;

    #[test]
    fn test_parse_native_profile() {
        let ir =
            r#"attributes #0 = { "target-cpu"="znver2" "target-features"="+sse2,+avx2,-avx512f" }"#;
        assert_eq!(
            parse_native_profile(ir).unwrap(),
            "znver2|+sse2,+avx2,-avx512f"
        );
    }

    #[test]
    fn test_parse_cfg_target_features() {
        let cfg = "target_arch=\"x86_64\"\ntarget_feature=\"sse2\"\ntarget_feature=\"avx2\"\n";
        assert_eq!(
            parse_cfg_target_features(cfg),
            BTreeSet::from(["avx2".to_owned(), "sse2".to_owned()])
        );
    }

    #[test]
    fn test_explicit_native_feature_delta() {
        let native = BTreeSet::from(["avx2".to_owned(), "sse2".to_owned()]);
        let baseline = BTreeSet::from(["sse2".to_owned(), "sse3".to_owned()]);
        assert_eq!(
            explicit_native_feature_delta(&native, &baseline),
            "+avx2,+sse2,-sse3"
        );
    }

    #[test]
    fn test_rewrite_native_target_cpu() {
        let mut args = vec![Argument::WithValue(
            "-C",
            CodeGen(ArgCodegen {
                opt: "target-cpu".into(),
                value: Some("native".into()),
            }),
            ArgDisposition::Separated,
        )];
        assert!(native_target_requested(&args));
        rewrite_native_target_cpu(&mut args, "x86-64", "+avx2,+sse2");
        assert!(!native_target_requested(&args));
        assert_eq!(
            args[0].iter_os_strings().collect::<Vec<_>>(),
            vec![OsString::from("-C"), OsString::from("target-cpu=x86-64")]
        );
        assert_eq!(
            args[1].iter_os_strings().collect::<Vec<_>>(),
            vec![
                OsString::from("-C"),
                OsString::from("target-feature=+avx2,+sse2")
            ]
        );
    }

    #[test]
    fn test_rewrite_native_target_cpu_preserves_user_feature_override_order() {
        let target_feature = |value: &str| {
            Argument::WithValue(
                "-C",
                CodeGen(ArgCodegen {
                    opt: "target-feature".into(),
                    value: Some(value.into()),
                }),
                ArgDisposition::Separated,
            )
        };
        let target_cpu_native = || {
            Argument::WithValue(
                "-C",
                CodeGen(ArgCodegen {
                    opt: "target-cpu".into(),
                    value: Some("native".into()),
                }),
                ArgDisposition::Separated,
            )
        };

        for mut args in [
            vec![target_feature("-avx2"), target_cpu_native()],
            vec![target_cpu_native(), target_feature("-avx2")],
        ] {
            rewrite_native_target_cpu(&mut args, "x86-64", "+avx2,+sse2");
            let features = args
                .iter()
                .filter_map(|arg| match arg.get_data() {
                    Some(CodeGen(ArgCodegen { opt, value })) if opt == "target-feature" => {
                        value.clone()
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(features, ["+avx2,+sse2", "-avx2"]);
        }
    }

    #[test]
    fn test_native_tune_requested() {
        let args = vec![Argument::WithValue(
            "-Z",
            Unstable(ArgUnstable {
                opt: "tune-cpu".into(),
                value: Some("native".into()),
            }),
            ArgDisposition::Separated,
        )];
        assert!(native_tune_requested(&args));
        assert!(!native_target_requested(&args));
    }

    #[test]
    fn test_native_cpu_detection_uses_last_value() {
        let codegen = |value: &str| {
            Argument::WithValue(
                "-C",
                CodeGen(ArgCodegen {
                    opt: "target-cpu".into(),
                    value: Some(value.into()),
                }),
                ArgDisposition::Separated,
            )
        };
        assert!(!native_target_requested(&[
            codegen("native"),
            codegen("znver2")
        ]));
        assert!(native_target_requested(&[
            codegen("znver2"),
            codegen("native")
        ]));

        let tune = |value: &str| {
            Argument::WithValue(
                "-Z",
                Unstable(ArgUnstable {
                    opt: "tune-cpu".into(),
                    value: Some(value.into()),
                }),
                ArgDisposition::Separated,
            )
        };
        assert!(!native_tune_requested(&[tune("native"), tune("znver2")]));
        assert!(native_tune_requested(&[tune("znver2"), tune("native")]));
    }

    fn _parse_arguments(arguments: &[String]) -> CompilerArguments<ParsedArguments> {
        let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        parse_arguments(&arguments, ".".as_ref())
    }

    macro_rules! parses {
        ( $( $s:expr ),* ) => {
            match _parse_arguments(&[ $( $s.to_string(), )* ]) {
                CompilerArguments::Ok(a) => a,
                o => panic!("Got unexpected parse result: {:?}", o),
            }
        }
    }

    macro_rules! fails {
        ( $( $s:expr ),* ) => {
            match _parse_arguments(&[ $( $s.to_string(), )* ]) {
                CompilerArguments::Ok(_) => panic!("Should not have parsed ok: `{}`", stringify!($( $s, )*)),

                o => o,
            }
        }
    }

    const TEST_RUSTC_VERSION: &str = r"
rustc 1.66.1 (90743e729 2023-01-10)
binary: rustc
commit-hash: 90743e7298aca107ddaa0c202a4d3604e29bfeb6
commit-date: 2023-01-10
host: x86_64-unknown-linux-gnu
release: 1.66.1
LLVM version: 15.0.2
";

    #[test]
    fn test_parse_arguments_simple() {
        let h = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib"
        );
        assert_eq!(h.output_dir.to_str(), Some("out"));
        assert!(h.dep_info.is_none());
        assert_eq!(h.externs, [] as [std::path::PathBuf; 0]);
        let h = parses!(
            "--emit=link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        assert_eq!(h.output_dir.to_str(), Some("out"));
        assert!(h.dep_info.is_none());
        let h = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir=out",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        assert_eq!(h.output_dir.to_str(), Some("out"));
        assert_eq!(
            parses!(
                "--emit",
                "link",
                "-C",
                "opt-level=1",
                "foo.rs",
                "--out-dir",
                "out",
                "--crate-name",
                "foo",
                "--crate-type",
                "lib"
            ),
            parses!(
                "--emit=link",
                "-Copt-level=1",
                "foo.rs",
                "--out-dir=out",
                "--crate-name=foo",
                "--crate-type=lib"
            )
        );
        let h = parses!(
            "--emit",
            "link,dep-info",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "my_crate",
            "--crate-type",
            "lib",
            "-C",
            "extra-filename=-abcxyz"
        );
        assert_eq!(h.output_dir.to_str(), Some("out"));
        assert_eq!(h.dep_info.unwrap().to_str().unwrap(), "my_crate-abcxyz.d");
        fails!(
            "--emit",
            "link",
            "--out-dir",
            "out",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        fails!(
            "--emit",
            "link",
            "foo.rs",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        fails!(
            "--emit",
            "asm",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        fails!(
            "--emit",
            "asm,link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        fails!(
            "--emit",
            "asm,link,dep-info",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        fails!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name=foo"
        );
        fails!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-type=lib"
        );
        // From an actual cargo compilation, with some args shortened:
        let h = parses!(
            "--crate-name",
            "foo",
            "src/lib.rs",
            "--crate-type",
            "lib",
            "--emit=dep-info,link",
            "-C",
            "debuginfo=2",
            "-C",
            "metadata=d6ae26f5bcfb7733",
            "-C",
            "extra-filename=-d6ae26f5bcfb7733",
            "--out-dir",
            "/foo/target/debug/deps",
            "-L",
            "dependency=/foo/target/debug/deps",
            "--extern",
            "libc=/foo/target/debug/deps/liblibc-89a24418d48d484a.rlib",
            "--extern",
            "log=/foo/target/debug/deps/liblog-2f7366be74992849.rlib"
        );
        assert_eq!(h.output_dir.to_str(), Some("/foo/target/debug/deps"));
        assert_eq!(h.crate_name, "foo");
        assert_eq!(
            h.dep_info.unwrap().to_str().unwrap(),
            "foo-d6ae26f5bcfb7733.d"
        );
        assert_eq!(
            h.externs,
            ovec![
                "/foo/target/debug/deps/liblibc-89a24418d48d484a.rlib",
                "/foo/target/debug/deps/liblog-2f7366be74992849.rlib"
            ]
        );
    }

    #[test]
    fn rust_queries_are_not_rejected_compilations() {
        for args in [
            &[
                "-",
                "--crate-name",
                "___",
                "--print=file-names",
                "--crate-type",
                "bin",
            ][..],
            &["--sysroot", "/some/sysroot", "--print", "target-libdir"],
            &["--print=cfg", "-"],
            &["-vV"],
            &["-Vv"],
            &["-h"],
        ] {
            let args = args.iter().map(OsString::from).collect::<Vec<_>>();
            assert_eq!(
                parse_arguments(&args, Path::new(".")),
                CompilerArguments::NotCompilation
            );
        }
        // Do not interpret strings consumed by another option as queries.
        assert!(matches!(
            fails!("-", "--cfg", "--print", "--emit=metadata"),
            CompilerArguments::CannotCache("unsupported compiler option", _)
        ));
    }

    #[test]
    fn test_parse_arguments_non_cacheable_crate_type_details() {
        let bin = fails!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "bin"
        );
        assert_eq!(
            bin,
            CompilerArguments::CannotCache("crate-type", Some("bin".to_string()))
        );

        let proc_macro = fails!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "proc-macro"
        );
        assert_eq!(
            proc_macro,
            CompilerArguments::CannotCache("crate-type", Some("proc-macro".to_string()))
        );

        let multiple = fails!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "proc-macro,bin"
        );
        assert_eq!(
            multiple,
            CompilerArguments::CannotCache("crate-type", Some("bin,proc-macro".to_string()))
        );

        let missing = fails!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
        assert_eq!(
            missing,
            CompilerArguments::CannotCache("crate-type", Some("No crate-type passed".to_string()))
        );
    }

    #[test]
    fn test_metadata_only_all_crate_types_and_test_harness() {
        for crate_type in [
            None,
            Some("bin"),
            Some("lib"),
            Some("proc-macro"),
            Some("dylib"),
            Some("cdylib"),
            Some("staticlib"),
            Some("rlib,staticlib,cdylib"),
        ] {
            for test_harness in [false, true] {
                let mut args = vec![
                    "--crate-name",
                    "foo",
                    "--out-dir",
                    "out",
                    "-C",
                    "extra-filename=-abc",
                    "foo.rs",
                ];
                if let Some(ty) = crate_type {
                    args.extend(["--crate-type", ty]);
                }
                if test_harness {
                    args.push("--test");
                }
                args.extend(["--emit", "dep-info,metadata"]);
                let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
                let CompilerArguments::Ok(parsed) = parse_arguments(&args, Path::new(".")) else {
                    panic!("metadata-only compile rejected: {args:?}");
                };
                assert_eq!(
                    parsed.metadata_only_output.as_deref(),
                    Some("libfoo-abc.rmeta")
                );
            }
        }
        assert_eq!(
            fails!(
                "--test",
                "--crate-type",
                "lib",
                "--emit",
                "link",
                "--out-dir",
                "out",
                "--crate-name",
                "foo",
                "foo.rs"
            ),
            CompilerArguments::CannotCache("crate-type", Some("test harness".to_owned()))
        );
    }

    #[test]
    fn test_parse_arguments_wasip2_cdylib_is_cacheable() {
        let parsed = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "cdylib",
            "--target",
            "wasm32-wasip2"
        );
        assert!(parsed.crate_types.cdylib);
        assert!(!parsed.crate_types.rlib);
        assert!(!parsed.crate_types.staticlib);
    }

    #[test]
    fn test_parse_arguments_cdylib_stays_noncachable_outside_wasip2() {
        let native = fails!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "cdylib"
        );
        assert_eq!(
            native,
            CompilerArguments::CannotCache("crate-type", Some("cdylib".to_string()))
        );

        let custom_linker = fails!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "cdylib",
            "--target",
            "wasm32-wasip2",
            "-C",
            "linker=/tmp/custom-linker"
        );
        assert_eq!(
            custom_linker,
            CompilerArguments::CannotCache("crate-type", Some("cdylib".to_string()))
        );
    }

    #[test]
    fn explicit_rust_link_stages_do_not_use_completed_library_cache() {
        for option in ["no-link", "link-only", "no-link=yes", "link-only=yes"] {
            let result = fails!(
                "--emit=link",
                "foo.rs",
                "--out-dir",
                "out",
                "--crate-name",
                "foo",
                "--crate-type",
                "rlib",
                "-Z",
                option
            );
            assert_eq!(
                result,
                CompilerArguments::CannotCache(
                    "explicit Rust link stage",
                    Some(option.split('=').next().unwrap().to_owned())
                )
            );
        }
    }

    #[test]
    fn test_parse_arguments_incremental() {
        parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib"
        );
        let r = fails!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "-C",
            "incremental=/foo"
        );
        assert_eq!(r, CompilerArguments::CannotCache("incremental", None));
    }

    #[test]
    fn test_parse_arguments_dep_info_no_extra_filename() {
        let h = parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "src/lib.rs",
            "--emit=dep-info,link",
            "--out-dir",
            "/out"
        );
        assert_eq!(h.dep_info, Some("foo.d".into()));
    }

    #[test]
    fn test_parse_arguments_native_libs() {
        parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib,staticlib",
            "--emit",
            "link",
            "-l",
            "bar",
            "foo.rs",
            "--out-dir",
            "out"
        );
        parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib,staticlib",
            "--emit",
            "link",
            "-l",
            "static=bar",
            "foo.rs",
            "--out-dir",
            "out"
        );
        parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib,staticlib",
            "--emit",
            "link",
            "-l",
            "dylib=bar",
            "foo.rs",
            "--out-dir",
            "out"
        );
    }

    /// `-l` reaches rustc as it was given. In particular a library without a kind must not
    /// become `dylib`: rustc picks the kind per target (e.g. static with `crt-static`).
    #[test_case("bar" ; "without kind")]
    #[test_case("static=bar" ; "static")]
    #[test_case("static:-bundle=bar" ; "static with modifiers")]
    #[test_case("dylib=bar" ; "dylib")]
    fn test_parse_arguments_link_library_is_passed_unchanged(lib: &str) {
        let h = parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--emit",
            "link",
            "-l",
            lib,
            "foo.rs",
            "--out-dir",
            "out"
        );
        let arguments: Vec<OsString> = h
            .arguments
            .iter()
            .flat_map(|arg| arg.iter_os_strings())
            .collect();
        let position = arguments.iter().position(|arg| arg == "-l").unwrap();
        assert_eq!(arguments[position + 1], lib);
    }

    #[test_case("static", true ; "without modifiers")]
    #[test_case("static:+bundle", true ; "with bundle")]
    #[test_case("static:+whole-archive", true ; "with whole-archive")]
    #[test_case("static:-bundle", false ; "without bundle")]
    #[test_case("static:+whole-archive,-bundle", false ; "with whole-archive, without bundle")]
    #[test_case("static:-bundle,+whole-archive", false ; "without bundle, with whole-archive")]
    #[test_case("dylib", false ; "dylib, without modifiers")]
    #[test_case("dylib:+as-needed", false ; "dylib, with as-needed")]
    fn test_parse_arguments_static_lib_with_link_modifiers(kind: &str, hashed: bool) {
        let f = TestFixture::new();
        let lib = f.touch("libbar.a").unwrap();
        let h = parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--emit",
            "link",
            "-L",
            format!("native={}", lib.parent().unwrap().display()),
            "-l",
            format!("{kind}=bar"),
            "foo.rs",
            "--out-dir",
            "out"
        );
        let expected = if hashed { vec![lib] } else { vec![] };
        assert_eq!(h.staticlibs, expected);
    }

    #[test_case("static=original:renamed", "librenamed.a"; "renamed")]
    #[test_case("static:+verbatim=archive.custom", "archive.custom"; "verbatim")]
    #[test_case("static:+verbatim=original:renamed.custom", "renamed.custom"; "renamed verbatim")]
    #[test_case("renamed", "librenamed.a"; "implicit kind")]
    fn test_parse_arguments_static_library_names(spec: &str, file: &str) {
        let f = TestFixture::new();
        let lib = f.touch(file).unwrap();
        let h = parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--emit",
            "link",
            "-L",
            format!("native={}", lib.parent().unwrap().display()),
            "-l",
            spec,
            "foo.rs",
            "--out-dir",
            "out"
        );
        assert_eq!(h.staticlibs, [lib]);
    }

    #[test]
    fn test_static_library_without_bundle_for_component_link() {
        let f = TestFixture::new();
        let lib = f.touch("libbar.a").unwrap();
        let h = parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "cdylib",
            "--target",
            "wasm32-wasip2",
            "--emit",
            "link",
            "-L",
            format!("native={}", lib.parent().unwrap().display()),
            "-l",
            "static:-bundle=bar",
            "foo.rs",
            "--out-dir",
            "out"
        );
        assert_eq!(h.staticlibs, [lib]);
    }

    #[test]
    fn test_parse_arguments_non_rlib_crate() {
        parses!(
            "--crate-type",
            "rlib",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
        parses!(
            "--crate-type",
            "lib",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
        parses!(
            "--crate-type",
            "staticlib",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
        parses!(
            "--crate-type",
            "rlib,staticlib",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
        fails!(
            "--crate-type",
            "bin",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
        fails!(
            "--crate-type",
            "rlib,dylib",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
    }

    #[test]
    fn test_parse_arguments_color() {
        let h = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib"
        );
        assert_eq!(h.color_mode, ColorMode::Auto);
        let h = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--color=always"
        );
        assert_eq!(h.color_mode, ColorMode::On);
        let h = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--color=never"
        );
        assert_eq!(h.color_mode, ColorMode::Off);
        let h = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--color=auto"
        );
        assert_eq!(h.color_mode, ColorMode::Auto);
    }

    #[test]
    fn test_parse_arguments_multiple_inputs() {
        fails!(
            "huh.rs",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib"
        );

        // Having `rustc` as the first argument is indicative of clippy
        parses!(
            "rustc",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib"
        );
    }

    #[test]
    fn test_get_compiler_outputs() {
        let creator = new_creator();
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "foo\nbar\nbaz", "")),
        );
        let outputs = get_compiler_outputs(
            &creator,
            "rustc".as_ref(),
            ovec!("a", "b"),
            "cwd".as_ref(),
            &[],
        )
        .wait()
        .unwrap();
        assert_eq!(outputs, &["foo", "bar", "baz"]);
    }

    #[test]
    fn test_get_compiler_outputs_fail() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "error")));
        assert!(
            get_compiler_outputs(
                &creator,
                "rustc".as_ref(),
                ovec!("a", "b"),
                "cwd".as_ref(),
                &[]
            )
            .wait()
            .is_err()
        );
    }

    #[test]
    fn test_parse_dep_info() {
        let deps = "foo: baz.rs abc.rs bar.rs

baz.rs:

abc.rs:

bar.rs:
";
        assert_eq!(
            pathvec!["abc.rs", "bar.rs", "baz.rs"],
            parse_dep_info(deps, "")
        );
    }

    #[test]
    fn test_parse_env_dep_info_unescapes() {
        let deps = "# env-dep:OUT_DIR=C:\\\\dir\\\\out\n# env-dep:X=a\\nb\\rc=d\n# env-dep:Y\n";
        assert_eq!(
            parse_env_dep_info(deps),
            [
                ("OUT_DIR".into(), r"C:\dir\out".into()),
                ("X".into(), "a\nb\rc=d".into()),
                ("Y".into(), "".into()),
            ]
        );
    }

    #[test]
    fn test_parse_dep_info_omit_d_target() {
        let deps = "src/lib.rs:\nsrc/a\\ b.rs:\n\n# env-dep:FOO=bar\n";
        assert_eq!(
            pathvec!["src/a b.rs", "src/lib.rs"],
            parse_dep_info(deps, "")
        );
    }

    #[test]
    fn test_dep_info_with_targets() {
        let deps = "/tmp/x/deps.d: src/lib.rs src/../LICENSE\n\nsrc/lib.rs:\nsrc/../LICENSE:\n\n# env-dep:FOO=bar\n# env-dep:BAZ\n";
        let targets = [
            Path::new("out/foo-abc.d"),
            Path::new("out/libfoo-abc.rlib"),
            Path::new("out/libfoo-abc.rmeta"),
        ];
        assert_eq!(
            dep_info_with_targets(deps, targets, []).unwrap(),
            "out/foo-abc.d: src/lib.rs src/../LICENSE\n\nout/libfoo-abc.rlib: src/lib.rs src/../LICENSE\n\nout/libfoo-abc.rmeta: src/lib.rs src/../LICENSE\n\nsrc/lib.rs:\nsrc/../LICENSE:\n\n# env-dep:FOO=bar\n# env-dep:BAZ\n"
        );
    }

    #[test]
    fn test_dep_info_with_targets_extra_prerequisite() {
        let deps = "/tmp/x/deps.d: src/lib.rs\n\nsrc/lib.rs:\n";
        assert_eq!(
            dep_info_with_targets(
                deps,
                [Path::new("out/foo.d"), Path::new("out/libfoo.rlib")],
                [Path::new("/toolchains/my rust.tar.gz")],
            )
            .unwrap(),
            "out/foo.d: /toolchains/my\\ rust.tar.gz src/lib.rs\n\nout/libfoo.rlib: /toolchains/my\\ rust.tar.gz src/lib.rs\n\n/toolchains/my\\ rust.tar.gz:\nsrc/lib.rs:\n"
        );
    }

    #[test]
    fn test_dep_info_with_targets_omit_d_target() {
        let deps = "src/lib.rs:\nsrc/a\\ b.rs:\n\n# env-dep:FOO=bar\n";
        assert_eq!(
            dep_info_with_targets(deps, [Path::new("foo.d"), Path::new("libfoo.rlib")], [])
                .unwrap(),
            "foo.d: src/lib.rs src/a\\ b.rs\n\nlibfoo.rlib: src/lib.rs src/a\\ b.rs\n\nsrc/lib.rs:\nsrc/a\\ b.rs:\n\n# env-dep:FOO=bar\n"
        );
    }

    #[test]
    fn test_dep_info_with_targets_reports_bad_input() {
        assert!(dep_info_with_targets("", [Path::new("foo.d")], []).is_err());
        let err = dep_info_with_targets("# env-dep:FOO\n", [Path::new("foo.d")], []).unwrap_err();
        assert!(err.to_string().contains("first line"), "{err:#}");
    }

    #[test]
    fn test_parse_dep_info_with_escaped_spaces() {
        let deps = r"foo: baz.rs abc\ def.rs

baz.rs:

abc def.rs:
";
        assert_eq!(pathvec!["abc def.rs", "baz.rs"], parse_dep_info(deps, ""));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_parse_dep_info_cwd() {
        let deps = "foo: baz.rs abc.rs bar.rs

baz.rs:

abc.rs:

bar.rs:
";
        assert_eq!(
            pathvec!["foo/abc.rs", "foo/bar.rs", "foo/baz.rs"],
            parse_dep_info(deps, "foo/")
        );

        assert_eq!(
            pathvec!["/foo/bar/abc.rs", "/foo/bar/bar.rs", "/foo/bar/baz.rs"],
            parse_dep_info(deps, "/foo/bar/")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn test_parse_dep_info_abs_paths() {
        let deps = "/foo/foo: /foo/baz.rs /foo/abc.rs /foo/bar.rs

/foo/baz.rs:

/foo/abc.rs:

/foo/bar.rs:
";
        assert_eq!(
            pathvec!["/foo/abc.rs", "/foo/bar.rs", "/foo/baz.rs"],
            parse_dep_info(deps, "/bar/")
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_parse_dep_info_cwd() {
        let deps = "foo: baz.rs abc.rs bar.rs

baz.rs:

abc.rs:

bar.rs:
";
        assert_eq!(
            pathvec!["foo/abc.rs", "foo/bar.rs", "foo/baz.rs"],
            parse_dep_info(deps, "foo/")
        );

        assert_eq!(
            pathvec![
                "c:/foo/bar/abc.rs",
                "c:/foo/bar/bar.rs",
                "c:/foo/bar/baz.rs"
            ],
            parse_dep_info(deps, "c:/foo/bar/")
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_parse_dep_info_abs_paths() {
        let deps = "c:/foo/foo: c:/foo/baz.rs c:/foo/abc.rs c:/foo/bar.rs

c:/foo/baz.rs: c:/foo/bar.rs
c:/foo/abc.rs:
c:/foo/bar.rs:
";
        assert_eq!(
            pathvec!["c:/foo/abc.rs", "c:/foo/bar.rs", "c:/foo/baz.rs"],
            parse_dep_info(deps, "c:/bar/")
        );
    }

    #[cfg(feature = "dist-client")]
    #[test]
    fn test_parse_rustc_z_ls_pre_1_55() {
        let output = "=External Dependencies=
1 lucet_runtime
2 lucet_runtime_internals-1ff6232b6940e924
3 lucet_runtime_macros-c18e1952b835769e


";
        let res = parse_rustc_z_ls(output);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.len(), 3);
        assert_eq!(res[0], "lucet_runtime");
        assert_eq!(res[1], "lucet_runtime_internals");
        assert_eq!(res[2], "lucet_runtime_macros");
    }

    #[cfg(feature = "dist-client")]
    #[test]
    fn test_parse_rustc_z_ls_post_1_55() {
        // This was introduced in rust 1.55 by
        // https://github.com/rust-lang/rust/commit/cef3ab75b12155e0582dd8b7710b7b901215fdd6
        let output = "Crate info:
name lucet_runtime
hash 6c42566fc9757bba stable_crate_id StableCrateId(11157525371370257329)
proc_macro false
=External Dependencies=
1 lucet_runtime
2 lucet_runtime_internals-1ff6232b6940e924
3 lucet_runtime_macros-c18e1952b835769e


";
        let res = parse_rustc_z_ls(output);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.len(), 3);
        assert_eq!(res[0], "lucet_runtime");
        assert_eq!(res[1], "lucet_runtime_internals");
        assert_eq!(res[2], "lucet_runtime_macros");
    }

    #[cfg(feature = "dist-client")]
    #[test]
    fn test_parse_rustc_z_ls_modern_no_hash_suffix() {
        // Modern rustc (1.75+) prints extended metadata per dep line:
        //   N libname[-hash] hash HASH host_hash ... kind ... public
        // Crates without a -HASH suffix (e.g. crc_fast, a proc-macro-style
        // library built with a deterministic hash) appear as:
        //   N crc_fast hash 05bce6... host_hash None kind Unconditional public
        // The parser must extract just "crc_fast", not the entire trailing
        // metadata, so that RustInputsPackager can match it against rmeta
        // files in crate_link_paths.
        let output = "Crate info:
name xai_file_utils
hash 42fac6f0 stable_crate_id StableCrateId(12206970385906972588)
=External Dependencies=
1 std-453218b5e9634890 hash c76be37888b32288681053863554e618 host_hash None kind Unconditional public
2 core-5f5c0031517c19c4 hash 4e0d60221dfd8f9efa10e2a33c921b61 host_hash None kind Unconditional public
3 crc_fast hash 05bce60290e56777e3ae6d3ddcc01e6c host_hash None kind Unconditional public
4 crc-8c7d86e779319534 hash 49e85fac7c830ee1def0dd1674e740b0 host_hash None kind Unconditional public
5 aws_sdk_s3-c49a342c963fe6e9 hash 119191ef3d4a8059aee3abebc4c4b5bf host_hash None kind Unconditional public

";
        let res = parse_rustc_z_ls(output);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.len(), 5);
        assert_eq!(res[0], "std");
        assert_eq!(res[1], "core");
        assert_eq!(res[2], "crc_fast");
        assert_eq!(res[3], "crc");
        assert_eq!(res[4], "aws_sdk_s3");
    }

    #[cfg(feature = "dist-client")]
    #[test]
    fn test_rlib_dep_reader_call() {
        // Use the compiler Cargo/CI selected, not a rustup proxy that could
        // install a different toolchain while this test is executing.
        let rustc_path = std::env::var_os("RUSTC")
            .or_else(|| option_env!("RUSTC").map(OsString::from))
            .map(PathBuf::from)
            .or_else(|| which::which("rustc").ok())
            .expect("rustc not found");
        let mut env_vars: Vec<_> = [
            "RUSTUP_HOME",
            "RUSTUP_TOOLCHAIN",
            "HOME",
            "USERPROFILE",
            "PATH",
        ]
        .into_iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (name.into(), value)))
        .collect();
        env_vars.push(("RUSTUP_AUTO_INSTALL".into(), "0".into()));

        let rlib_dep_reader = RlibDepReader::new_with_check(rustc_path, &env_vars);
        rlib_dep_reader.expect("selected rustc must support rlib dependency reading");
    }

    #[cfg(feature = "dist-client")]
    #[test]
    fn test_rlib_dep_reader_parse_rustc_version() {
        let v0 = RlibDepReader::parse_rustc_version(b"rustc 1.2.3 aaaa");
        assert!(v0.is_ok());
        let v0 = v0.unwrap();
        assert_eq!(v0.major, 1);
        assert_eq!(v0.minor, 2);
        assert_eq!(v0.patch, 3);

        assert!(RlibDepReader::parse_rustc_version(b"rutc 1.2.3 aaaa").is_err());
        assert!(RlibDepReader::parse_rustc_version(b"1.2.3").is_err());
    }

    #[cfg(feature = "dist-client")]
    #[test]
    fn test_rlib_dep_reader_get_correct_ls_arg() {
        assert_eq!(
            RlibDepReader::get_correct_ls_arg(&Version::new(0, 73, 0)),
            "ls"
        );
        assert_eq!(
            RlibDepReader::get_correct_ls_arg(&Version::new(1, 73, 0)),
            "ls"
        );
        assert_eq!(
            RlibDepReader::get_correct_ls_arg(&Version::new(1, 73, 1)),
            "ls"
        );
        assert_eq!(
            RlibDepReader::get_correct_ls_arg(&Version::new(1, 74, 0)),
            "ls"
        );
        assert_eq!(
            RlibDepReader::get_correct_ls_arg(&Version::new(1, 74, 1)),
            "ls"
        );
        assert_eq!(
            RlibDepReader::get_correct_ls_arg(&Version::new(1, 75, 0)),
            "ls=root"
        );
        assert_eq!(
            RlibDepReader::get_correct_ls_arg(&Version::new(2, 73, 0)),
            "ls=root"
        );
        assert_eq!(
            RlibDepReader::get_correct_ls_arg(&Version::new(2, 74, 0)),
            "ls=root"
        );
    }

    fn mock_dep_info(creator: &Arc<Mutex<MockCommandCreator>>, dep_srcs: &[&str]) {
        // Mock the `rustc --emit=dep-info` process by writing
        // a dep-info file.
        let mut sorted_deps = dep_srcs
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<String>>();
        sorted_deps.sort();
        next_command_calls(creator, move |args| {
            let mut dep_info_path = None;
            let mut it = args.iter();
            while let Some(a) = it.next() {
                if a == "-o" {
                    dep_info_path = it.next();
                    break;
                }
            }
            let dep_info_path = dep_info_path.unwrap();
            let mut f = File::create(dep_info_path)?;
            writeln!(f, "blah: {}", sorted_deps.iter().join(" "))?;
            for d in &sorted_deps {
                writeln!(f, "{d}:")?;
            }
            Ok(MockChild::new(exit_status(0), "", ""))
        });
    }

    fn mock_file_names(creator: &Arc<Mutex<MockCommandCreator>>, filenames: &[&str]) {
        // Mock the `rustc --print=file-names` process output.
        let stdout = filenames.iter().join("\n");
        next_command_calls(creator, move |args| {
            assert!(
                args.windows(2)
                    .any(|pair| pair[0] == "--print" && pair[1] == "file-names")
            );
            Ok(MockChild::new(exit_status(0), &stdout, ""))
        });
    }

    #[test]
    fn test_metadata_only_output_is_materialized_and_has_local_dep_info() -> Result<()> {
        for crate_type in ["bin", "lib", "staticlib", "cdylib", "proc-macro", "dylib"] {
            let f = TestFixture::new();
            f.touch("foo.rs")?;
            let args = [
                "--crate-name",
                "foo",
                "--crate-type",
                crate_type,
                "--out-dir",
                "out",
                "--emit",
                "metadata,dep-info",
                "-C",
                "extra-filename=-abc",
                "foo.rs",
            ]
            .map(OsString::from);
            let CompilerArguments::Ok(parsed_args) = parse_arguments(&args, f.tempdir.path())
            else {
                bail!("could not parse metadata compile for {crate_type}");
            };
            let mut hasher = RustHasher {
                executable: "rustc".into(),
                host: "x86_64-unknown-linux-gnu".into(),
                version: TEST_RUSTC_VERSION.to_string(),
                sysroot: f.tempdir.path().join("sysroot"),
                compiler_shlibs_digests: vec![],
                dist_archive: None,
                #[cfg(feature = "dist-client")]
                rlib_dep_reader: None,
                native_profile: Some("test-native".into()),
                parsed_args,
            };
            let creator = new_creator();
            // Exactly one compiler call: source dependency discovery. The
            // --print file-names query describes linked outputs, not metadata.
            mock_dep_info(&creator, &["foo.rs"]);
            let runtime = single_threaded_runtime();
            let pool = runtime.handle().clone();
            let result = hasher
                .generate_hash_key(GenerateHashKeyContext {
                    creator: &creator,
                    cwd: f.tempdir.path().to_owned(),
                    env_vars: vec![],
                    may_dist: true,
                    pool: &pool,
                    rewrite_includes_only: false,
                    storage: Arc::new(MockStorage::new(None, false)),
                    cache_control: CacheControl::Default,
                })
                .wait()?;
            let outputs = result.compilation.outputs().collect::<Vec<_>>();
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].key, "libfoo-abc.rmeta");
            assert_eq!(outputs[0].path, Path::new("out/libfoo-abc.rmeta"));
            assert!(!outputs[0].optional);
            let dep_info = fs::read_to_string(f.tempdir.path().join("out/foo-abc.d"))?;
            assert!(dep_info.contains("out/libfoo-abc.rmeta: foo.rs"));
            #[cfg(feature = "dist-client")]
            {
                let mut transformer = dist::PathTransformer::new();
                let (_, command, _) = result
                    .compilation
                    .generate_compile_commands(&mut transformer, false)?;
                let command = command.context("metadata-only command should be distributable")?;
                assert!(
                    command
                        .arguments
                        .windows(2)
                        .any(|pair| pair == ["--emit", "metadata"])
                );
            }
        }
        Ok(())
    }

    #[test]
    fn test_generate_hash_key_writes_local_dep_info() {
        let f = TestFixture::new();
        f.touch("foo.rs").unwrap();
        fs::create_dir(f.tempdir.path().join("out")).unwrap();

        let emit = ["dep-info", "link", "metadata"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let mut hasher = Box::new(RustHasher {
            executable: "rustc".into(),
            host: "x86-64-unknown-unknown-unknown".to_owned(),
            version: TEST_RUSTC_VERSION.to_string(),
            sysroot: f.tempdir.path().join("sysroot"),
            compiler_shlibs_digests: vec![],
            dist_archive: Some("/toolchains/rust.tar.gz".into()),
            #[cfg(feature = "dist-client")]
            rlib_dep_reader: None,
            native_profile: Some("test-native".into()),
            parsed_args: ParsedArguments {
                arguments: vec![],
                output_dir: "out".into(),
                externs: vec![],
                crate_link_paths: vec![],
                staticlibs: vec![],
                crate_name: "foo".into(),
                crate_types: CrateTypes {
                    rlib: true,
                    staticlib: false,
                    cdylib: false,
                },
                dep_info: Some("foo-abc.d".into()),
                emit,
                metadata_only_output: None,
                color_mode: ColorMode::Auto,
                has_json: false,
                gcno: None,
                target_json: None,
            },
        });
        let creator = new_creator();
        mock_dep_info(&creator, &["foo.rs"]);
        mock_file_names(&creator, &["libfoo-abc.rlib"]);
        let runtime = single_threaded_runtime();
        let pool = runtime.handle().clone();
        let res = hasher
            .generate_hash_key(GenerateHashKeyContext {
                creator: &creator,
                cwd: f.tempdir.path().to_owned(),
                env_vars: vec![],
                may_dist: false,
                pool: &pool,
                rewrite_includes_only: false,
                storage: Arc::new(MockStorage::new(None, false)),
                cache_control: CacheControl::Default,
            })
            .wait()
            .unwrap();

        let mut outputs = res.compilation.outputs().map(|o| o.key).collect::<Vec<_>>();
        outputs.sort();
        assert_eq!(outputs, ["libfoo-abc.rlib", "libfoo-abc.rmeta"]);

        let dep_info = fs::read_to_string(f.tempdir.path().join("out/foo-abc.d")).unwrap();
        assert_eq!(
            dep_info,
            "out/foo-abc.d: /toolchains/rust.tar.gz foo.rs\n\nout/libfoo-abc.rlib: /toolchains/rust.tar.gz foo.rs\n\nout/libfoo-abc.rmeta: /toolchains/rust.tar.gz foo.rs\n\n/toolchains/rust.tar.gz:\nfoo.rs:\n"
        );
        assert!(!dep_info.contains("deps.d"));
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_generate_hash_key(preprocessor_cache_mode: bool) {
        use ar::{Builder, Header};
        drop(env_logger::try_init());
        let f = TestFixture::new();
        const FAKE_DIGEST: &str = "abcd1234";
        const BAZ_O_SIZE: u64 = 1024;
        // We'll just use empty files for each of these.
        for s in &["foo.rs", "bar.rs", "bar.rlib"] {
            f.touch(s).unwrap();
        }
        // libbaz.a needs to be a valid archive.
        create_file(f.tempdir.path(), "libbaz.a", |f| {
            let mut builder = Builder::new(f);
            let hdr = Header::new(b"baz.o".to_vec(), BAZ_O_SIZE);
            builder.append(&hdr, io::repeat(0).take(BAZ_O_SIZE))?;
            Ok(())
        })
        .unwrap();
        let mut m = Digest::new();
        m.update(b"baz.o");
        m.update(&vec![0; BAZ_O_SIZE as usize]);
        let libbaz_a_digest = m.finish();

        let mut emit = HashSet::new();
        emit.insert("link".to_string());
        emit.insert("metadata".to_string());
        let mut hasher = Box::new(RustHasher {
            executable: "rustc".into(),
            host: "x86-64-unknown-unknown-unknown".to_owned(),
            version: TEST_RUSTC_VERSION.to_string(),
            sysroot: f.tempdir.path().join("sysroot"),
            compiler_shlibs_digests: vec![FAKE_DIGEST.to_owned()],
            dist_archive: None,
            #[cfg(feature = "dist-client")]
            rlib_dep_reader: None,
            native_profile: Some("test-native".into()),
            parsed_args: ParsedArguments {
                arguments: vec![
                    Argument::Raw("a".into()),
                    Argument::WithValue(
                        "--cfg",
                        ArgData::PassThrough("xyz".into()),
                        ArgDisposition::Separated,
                    ),
                    Argument::Raw("b".into()),
                    Argument::WithValue(
                        "--cfg",
                        ArgData::PassThrough("abc".into()),
                        ArgDisposition::Separated,
                    ),
                ],
                output_dir: "foo/".into(),
                externs: vec!["bar.rlib".into()],
                crate_link_paths: vec![],
                staticlibs: vec![f.tempdir.path().join("libbaz.a")],
                crate_name: "foo".into(),
                crate_types: CrateTypes {
                    rlib: true,
                    staticlib: false,
                    cdylib: false,
                },
                dep_info: None,
                emit,
                metadata_only_output: None,
                color_mode: ColorMode::Auto,
                has_json: false,
                gcno: None,
                target_json: None,
            },
        });
        let creator = new_creator();
        mock_dep_info(&creator, &["foo.rs", "bar.rs"]);
        mock_file_names(&creator, &["foo.rlib", "foo.a"]);
        let runtime = single_threaded_runtime();
        let pool = runtime.handle().clone();
        let res = hasher
            .generate_hash_key(GenerateHashKeyContext {
                creator: &creator,
                cwd: f.tempdir.path().to_owned(),
                env_vars: [
                    (OsString::from("CARGO_PKG_NAME"), OsString::from("foo")),
                    (OsString::from("FOO"), OsString::from("bar")),
                    (OsString::from("CARGO_BLAH"), OsString::from("abc")),
                    (
                        OsString::from("CARGO_REGISTRIES_A_TOKEN"),
                        OsString::from("ignored"),
                    ),
                    (
                        OsString::from("CARGO_BUILD_JOBS"),
                        OsString::from("ignored"),
                    ),
                ]
                .to_vec(),
                may_dist: false,
                pool: &pool,
                rewrite_includes_only: false,
                storage: Arc::new(MockStorage::new(None, preprocessor_cache_mode)),
                cache_control: CacheControl::Default,
            })
            .wait()
            .unwrap();
        let m = Digest::new();
        let empty_digest = m.finish();

        let mut m = Digest::new();
        // Version.
        m.update(CACHE_VERSION);
        // sysroot shlibs digests.
        m.update(FAKE_DIGEST.as_bytes());
        // Arguments, with cfgs sorted at the end.
        OsStr::new("ab--cfgabc--cfgxyz").hash(&mut HashToDigest { digest: &mut m });
        // bar.rs (source file, from dep-info)
        m.update(empty_digest.as_bytes());
        // foo.rs (source file, from dep-info)
        m.update(empty_digest.as_bytes());
        // bar.rlib (extern crate, from externs)
        m.update(empty_digest.as_bytes());
        // libbaz.a (static library, from staticlibs), containing a single
        // file, baz.o, consisting of 1024 bytes of zeroes.
        m.update(libbaz_a_digest.as_bytes());
        // Env vars
        OsStr::new("CARGO_BLAH").hash(&mut HashToDigest { digest: &mut m });
        m.update(b"=");
        OsStr::new("abc").hash(&mut HashToDigest { digest: &mut m });
        OsStr::new("CARGO_PKG_NAME").hash(&mut HashToDigest { digest: &mut m });
        m.update(b"=");
        OsStr::new("foo").hash(&mut HashToDigest { digest: &mut m });
        f.tempdir.path().hash(&mut HashToDigest { digest: &mut m });
        TEST_RUSTC_VERSION.hash(&mut HashToDigest { digest: &mut m });
        let digest = m.finish();
        assert_eq!(res.key, digest);
        let mut out = res.compilation.outputs().map(|k| k.key).collect::<Vec<_>>();
        out.sort();
        assert_eq!(out, vec!["foo.a", "foo.rlib", "foo.rmeta"]);
    }

    #[test]
    fn test_profile_use_path_transforms_for_worker() {
        let arg = ArgCodegen {
            opt: "profile-use".into(),
            value: Some("/profiles/merged.profdata".into()),
        };
        let transformed = arg
            .into_arg_string(&mut |path| {
                assert_eq!(path, Path::new("/profiles/merged.profdata"));
                Some("/worker/profiles/merged.profdata".into())
            })
            .unwrap();
        assert_eq!(transformed, "profile-use=/worker/profiles/merged.profdata");
    }

    #[test]
    fn test_generate_hash_key_profile_use() {
        // The profile is an input: rustc lists it in its dep-info, which is how its
        // contents reach the key. As an output it was rewritten on every cache hit, and
        // the new mtime made cargo rebuild every crate that had read it.
        let f = TestFixture::new();
        f.touch("foo.rs").unwrap();
        let key_and_outputs = |profile: &[u8]| {
            create_file(f.tempdir.path(), "merged.profdata", |mut f| {
                f.write_all(profile)
            })
            .unwrap();
            let parsed_args = parses!(
                "--emit",
                "link",
                "foo.rs",
                "--out-dir",
                "out",
                "--crate-name",
                "foo",
                "--crate-type",
                "lib",
                "-C",
                "profile-use=merged.profdata"
            );
            let mut hasher = Box::new(RustHasher {
                executable: "rustc".into(),
                host: "x86-64-unknown-unknown-unknown".to_owned(),
                version: TEST_RUSTC_VERSION.to_string(),
                sysroot: f.tempdir.path().join("sysroot"),
                compiler_shlibs_digests: vec![],
                dist_archive: None,
                #[cfg(feature = "dist-client")]
                rlib_dep_reader: None,
                native_profile: Some("test-native".into()),
                parsed_args,
            });
            let creator = new_creator();
            mock_dep_info(&creator, &["foo.rs", "merged.profdata"]);
            mock_file_names(&creator, &["libfoo.rlib"]);
            let runtime = single_threaded_runtime();
            let pool = runtime.handle().clone();
            let res = hasher
                .generate_hash_key(GenerateHashKeyContext {
                    creator: &creator,
                    cwd: f.tempdir.path().to_owned(),
                    env_vars: vec![],
                    may_dist: false,
                    pool: &pool,
                    rewrite_includes_only: false,
                    storage: Arc::new(MockStorage::new(None, false)),
                    cache_control: CacheControl::Default,
                })
                .wait()
                .unwrap();
            let outputs = res.compilation.outputs().map(|k| k.key).collect::<Vec<_>>();
            (res.key, outputs)
        };

        let (key, outputs) = key_and_outputs(b"one profile");
        assert_eq!(outputs, ["libfoo.rlib"]);
        assert_eq!(key, key_and_outputs(b"one profile").0);
        assert_ne!(key, key_and_outputs(b"another profile").0);
    }

    fn hash_key<F>(
        f: &TestFixture,
        args: &[&'static str],
        env_vars: &[(OsString, OsString)],
        pre_func: F,
        preprocessor_cache_mode: bool,
    ) -> String
    where
        F: Fn(&Path) -> Result<()>,
    {
        hash_keys_for_compiler(
            f,
            args,
            env_vars,
            pre_func,
            preprocessor_cache_mode,
            "rustc",
        )
        .0
    }

    fn hash_keys_for_compiler<F>(
        f: &TestFixture,
        args: &[&'static str],
        env_vars: &[(OsString, OsString)],
        pre_func: F,
        preprocessor_cache_mode: bool,
        executable: &str,
    ) -> (String, String)
    where
        F: Fn(&Path) -> Result<()>,
    {
        let oargs = args.iter().map(OsString::from).collect::<Vec<OsString>>();
        let parsed_args = match parse_arguments(&oargs, f.tempdir.path()) {
            CompilerArguments::Ok(parsed_args) => parsed_args,
            o => panic!("Got unexpected parse result: {o:?}"),
        };
        // Just use empty files for sources.
        {
            let src = &"foo.rs";
            let s = format!("Failed to create {src}");
            f.touch(src).expect(&s);
        }
        // as well as externs
        for e in &parsed_args.externs {
            let s = format!("Failed to create {e:?}");
            f.touch(e.to_str().unwrap()).expect(&s);
        }
        pre_func(f.tempdir.path()).expect("Failed to execute pre_func");
        let mut hasher = Box::new(RustHasher {
            executable: executable.into(),
            host: "x86-64-unknown-unknown-unknown".to_owned(),
            version: TEST_RUSTC_VERSION.to_string(),
            sysroot: f.tempdir.path().join("sysroot"),
            compiler_shlibs_digests: vec![],
            dist_archive: None,
            #[cfg(feature = "dist-client")]
            rlib_dep_reader: None,
            native_profile: Some("test-native".into()),
            parsed_args,
        });

        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle().clone();

        mock_dep_info(&creator, &["foo.rs"]);
        if hasher.parsed_args.metadata_only_output.is_none() {
            mock_file_names(&creator, &["foo.rlib"]);
        }
        let result = hasher
            .generate_hash_key(GenerateHashKeyContext {
                creator: &creator,
                cwd: f.tempdir.path().to_owned(),
                env_vars: env_vars.to_owned(),
                may_dist: false,
                pool: &pool,
                rewrite_includes_only: false,
                storage: Arc::new(MockStorage::new(None, preprocessor_cache_mode)),
                cache_control: CacheControl::Default,
            })
            .wait()
            .unwrap();
        (result.key, result.weak_toolchain_key)
    }

    #[test]
    fn test_external_clippy_config_file_contents_change_cache_key() -> Result<()> {
        let f = TestFixture::new();
        let policy = f.tempdir.path().join("policy");
        fs::create_dir_all(&policy)?;
        let file = policy.join("clippy.toml");
        fs::write(&file, b"disallowed-names = [\"bad_one\"]\n")?;
        let env = vec![(OsString::from("CLIPPY_CONF_DIR"), policy.into_os_string())];
        let args = [
            "--emit",
            "metadata",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
        ];
        let first = hash_keys_for_compiler(&f, &args, &env, |_| Ok(()), false, "clippy-driver").0;
        fs::write(&file, b"disallowed-names = [\"bad_two\"]\n")?;
        let second = hash_keys_for_compiler(&f, &args, &env, |_| Ok(()), false, "clippy-driver").0;
        assert_ne!(
            first, second,
            "changing the external Clippy policy must invalidate cache"
        );
        Ok(())
    }

    #[test]
    fn test_canonical_clippy_policy_location_does_not_change_cache_key() -> Result<()> {
        let a = TestFixture::new();
        let b = TestFixture::new();
        let args = [
            "--emit",
            "metadata",
            "foo.rs",
            "--out-dir",
            "target/out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
        ];
        let policy_env = |fixture: &TestFixture| {
            let root = fixture.tempdir.path();
            vec![
                ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
                (
                    "SCCACHE_CANONICAL_BUILD_ROOT".into(),
                    root.as_os_str().to_owned(),
                ),
                (
                    "CARGO_TARGET_DIR".into(),
                    root.join("target").into_os_string(),
                ),
                (
                    "CLIPPY_CONF_DIR".into(),
                    root.join("policy").into_os_string(),
                ),
                (
                    "CLIPPY_ARGS".into(),
                    "-Dclippy::unwrap_used__CLIPPY_HACKERY__".into(),
                ),
            ]
        };
        let policy = |fixture: &TestFixture, contents: &[u8]| -> Result<()> {
            let dir = fixture.tempdir.path().join("policy");
            fs::create_dir_all(&dir)?;
            fs::write(dir.join("clippy.toml"), contents)?;
            Ok(())
        };
        policy(&a, b"disallowed-names = [\"bad_one\"]\n")?;
        policy(&b, b"disallowed-names = [\"bad_one\"]\n")?;
        let env_a = policy_env(&a);
        let env_b = policy_env(&b);
        let key = |fixture: &TestFixture, env: &[(OsString, OsString)]| {
            hash_key_for_compiler(fixture, &args, env, |_| Ok(()), false, "clippy-driver")
        };
        let first = key(&a, &env_a);
        assert_eq!(first, key(&b, &env_b));
        policy(&b, b"disallowed-names = [\"bad_two\"]\n")?;
        assert_ne!(first, key(&b, &env_b));
        Ok(())
    }

    #[test]
    fn test_clippy_lint_flags_change_the_cache_key() {
        let f = TestFixture::new();
        let args = [
            "--emit",
            "metadata",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
        ];
        let deny = vec![(
            "CLIPPY_ARGS".into(),
            "-Dclippy::unwrap_used__CLIPPY_HACKERY__".into(),
        )];
        let allow = vec![(
            "CLIPPY_ARGS".into(),
            "-Aclippy::unwrap_used__CLIPPY_HACKERY__".into(),
        )];
        let deny_key =
            hash_keys_for_compiler(&f, &args, &deny, |_| Ok(()), false, "clippy-driver").0;
        let allow_key =
            hash_keys_for_compiler(&f, &args, &allow, |_| Ok(()), false, "clippy-driver").0;
        let rustc_key = hash_keys_for_compiler(&f, &args, &deny, |_| Ok(()), false, "rustc").0;
        assert_ne!(
            deny_key, allow_key,
            "different Clippy lint levels must not reuse diagnostics"
        );
        assert_ne!(
            deny_key, rustc_key,
            "Clippy results must not reuse rustc cache entries"
        );
    }

    #[test]
    #[cfg(feature = "dist-client")]
    fn test_noncanonical_distributed_clippy_staticlib_omits_dep_info() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let cwd = temp.path().join("source");
        let output_dir = temp.path().join("external-target/debug/build/ffi/out");
        fs::create_dir_all(&cwd)?;
        let sysroot = temp.path().join("sysroot");
        let clippy = sysroot.join(BINS_DIR).join("clippy-driver");

        for (requested, worker_emit) in [
            ("dep-info,metadata", "metadata"),
            ("metadata,dep-info", "metadata"),
            ("dep-info,link", "link"),
            ("link,dep-info", "link"),
        ] {
            let requested_arguments = [
                "rustc",
                "--crate-name",
                "model_alb_xspice_ffi",
                "--crate-type",
                "staticlib",
                "--emit",
                requested,
                "--out-dir",
                output_dir.to_str().context("non-UTF8 target path")?,
                "src/lib.rs",
            ]
            .map(OsString::from);
            let parsed = match parse_arguments(&requested_arguments, &cwd) {
                CompilerArguments::Ok(parsed) => parsed,
                other => bail!("unexpected parse result: {other:?}"),
            };
            let compilation = RustCompilation {
                executable: clippy.clone(),
                host: "x86_64-unknown-linux-gnu".into(),
                sysroot: sysroot.clone(),
                rlib_dep_reader: None,
                arguments: parsed.arguments,
                inputs: vec![cwd.join("src/lib.rs")],
                outputs: HashMap::new(),
                crate_link_paths: vec![],
                crate_name: "model_alb_xspice_ffi".into(),
                #[cfg(feature = "dist-client")]
                can_trim_rlibs: true,
                cwd: cwd.clone(),
                env_vars: Vec::new(),
                env_dep_names: HashSet::new(),
                allow_dist: true,
                #[cfg(feature = "dist-client")]
                dlltool_files: Vec::new(),
                canonical_paths: None,
            };
            let mut transformer = dist::PathTransformer::new();
            let (local, distributed, _) = <RustCompilation as Compilation<
                ProcessCommandCreator,
            >>::generate_compile_commands(
                &compilation, &mut transformer, false
            )?;
            let local_arguments = local.get_arguments();
            assert!(
                local_arguments
                    .windows(2)
                    .any(|pair| { pair[0] == "--emit" && pair[1] == requested }),
                "local compiler must retain the caller's --emit request: {requested}"
            );
            let distributed = distributed.context("missing distributed Clippy command")?;
            assert!(
                distributed
                    .arguments
                    .windows(2)
                    .any(|pair| { pair[0] == "--emit" && pair[1] == worker_emit }),
                "worker must omit locally synthesized dep-info: {requested}"
            );
            assert!(
                !distributed
                    .arguments
                    .iter()
                    .any(|arg| arg.contains("dep-info")),
                "worker must not write a client-local .d output"
            );
            assert!(
                distributed.arguments.windows(2).any(|pair| {
                    pair[0] == "--out-dir" && pair[1] == output_dir.to_string_lossy()
                }),
                "preserve the independent client output directory in legacy mode"
            );
        }
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_cached_clippy_uses_driver_for_canonical_and_distributed_compilation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let build = temp.path().join("project");
        let sysroot = temp.path().join("toolchain");
        let bin = sysroot.join(BINS_DIR);
        fs::create_dir_all(&bin)?;
        fs::create_dir_all(&build)?;
        fs::write(
            build.join("Cargo.toml"),
            "[package]\nname='foo'\nversion='0.0.0'\n",
        )?;
        let policy = temp.path().join("external-policy");
        fs::create_dir_all(&policy)?;
        fs::write(policy.join("clippy.toml"), b"disallowed-names = []\n")?;
        let clippy = bin.join(format!("clippy-driver{}", std::env::consts::EXE_SUFFIX));
        let rustc = bin.join(format!("rustc{}", std::env::consts::EXE_SUFFIX));
        fs::write(&clippy, b"clippy-driver")?;
        fs::write(&rustc, b"rustc")?;
        let parsed = match parse_arguments(
            &[
                "rustc".into(),
                "foo.rs".into(),
                "--emit".into(),
                "metadata".into(),
                "--crate-name".into(),
                "foo".into(),
                "--crate-type".into(),
                "lib".into(),
                "--out-dir".into(),
                "out".into(),
            ],
            &build,
        ) {
            CompilerArguments::Ok(parsed) => parsed,
            other => bail!("unexpected parse result: {other:?}"),
        };
        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            (
                "SCCACHE_CANONICAL_BUILD_ROOT".into(),
                build.as_os_str().to_owned(),
            ),
            (
                "SCCACHE_CANONICAL_TARGET_ROOT".into(),
                build.join("target").into_os_string(),
            ),
            ("CLIPPY_CONF_DIR".into(), policy.clone().into_os_string()),
        ];
        let canonical = CanonicalRustPaths::from_env(&env, &build, &sysroot)
            .context("canonical Rust paths are unavailable")?;
        let compilation = RustCompilation {
            executable: clippy,
            host: "x86_64-unknown-linux-gnu".into(),
            sysroot,
            #[cfg(feature = "dist-client")]
            rlib_dep_reader: None,
            arguments: parsed.arguments,
            inputs: vec![build.join("foo.rs")],
            outputs: HashMap::new(),
            crate_link_paths: vec![],
            crate_name: "foo".into(),
            #[cfg(feature = "dist-client")]
            can_trim_rlibs: true,
            cwd: build,
            env_vars: env,
            env_dep_names: HashSet::new(),
            allow_dist: true,
            #[cfg(feature = "dist-client")]
            dlltool_files: Vec::new(),
            canonical_paths: Some(canonical),
        };
        let mut transformer = dist::PathTransformer::new();
        let (local, dist_command, _) =
            <RustCompilation as Compilation<ProcessCommandCreator>>::generate_compile_commands(
                &compilation,
                &mut transformer,
                false,
            )?;
        let local_args = local.get_arguments();
        assert!(
            local_args
                .iter()
                .any(|arg| arg == "/rust/bin/clippy-driver")
        );
        assert!(!local_args.iter().any(|arg| arg == "/rust/bin/rustc"));
        #[cfg(feature = "dist-client")]
        {
            let distributed = dist_command.context("distributed Clippy command not generated")?;
            assert_eq!(distributed.executable, "/rust/bin/clippy-driver");
            assert_eq!(
                distributed.env_vars.iter().find_map(|(name, value)| {
                    (name == "CLIPPY_CONF_DIR").then_some(value.trim_end_matches('/'))
                }),
                Some("/clippy-config")
            );

            // Physical Unix archives reconstruct the input path relative to
            // the original cwd, so the observed relative value is unchanged.
            let mut noncanonical = compilation.clone();
            noncanonical.canonical_paths = None;
            let (_, config_value) = noncanonical
                .env_vars
                .iter_mut()
                .find(|(name, _)| name == "CLIPPY_CONF_DIR")
                .context("expected Clippy config variable")?;
            *config_value = OsString::from("../external-policy");
            let mut legacy_transformer = dist::PathTransformer::new();
            let (_, legacy_dist, _) =
                <RustCompilation as Compilation<ProcessCommandCreator>>::generate_compile_commands(
                    &noncanonical,
                    &mut legacy_transformer,
                    false,
                )?;
            let legacy_dist = legacy_dist.context("noncanonical distributed command missing")?;
            assert_eq!(
                legacy_dist.env_vars.iter().find_map(|(name, value)| {
                    (name == "CLIPPY_CONF_DIR").then_some(value.as_str())
                }),
                if cfg!(unix) {
                    Some("../external-policy")
                } else {
                    Some(policy.to_str().context("non-UTF8 policy path")?)
                }
            );
        }
        #[cfg(not(feature = "dist-client"))]
        assert!(dist_command.is_none());
        Ok(())
    }

    #[test]
    fn test_dist_native_resolves_to_equivalent_explicit_cpu() -> Result<()> {
        let f = TestFixture::new();
        f.touch("foo.rs")?;

        let raw = [
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "-C",
            "target-cpu=native",
        ];
        let oargs = raw.iter().map(OsString::from).collect::<Vec<_>>();
        let parsed_args = match parse_arguments(&oargs, f.tempdir.path()) {
            CompilerArguments::Ok(parsed_args) => parsed_args,
            other => bail!("unexpected parse result: {other:?}"),
        };

        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle().clone();

        let run = |profile: Option<&str>, may_dist: bool| -> Result<_> {
            let mut hasher = RustHasher {
                executable: "rustc".into(),
                host: "x86_64-unknown-linux-gnu".to_owned(),
                version: TEST_RUSTC_VERSION.to_string(),
                sysroot: f.tempdir.path().join("sysroot"),
                compiler_shlibs_digests: vec![],
                dist_archive: None,
                #[cfg(feature = "dist-client")]
                rlib_dep_reader: None,
                native_profile: profile.map(str::to_owned),
                parsed_args: parsed_args.clone(),
            };
            if profile.is_none() {
                next_command(&creator, Err(anyhow!("native profile probe failed")));
            } else if may_dist {
                let native_cfg = "target_feature=\"sse2\"\ntarget_feature=\"avx2\"\n";
                next_command(&creator, Ok(MockChild::new(exit_status(0), native_cfg, "")));
                let baseline_ir = r#"attributes #0 = { "target-cpu"="x86-64" }"#;
                next_command(
                    &creator,
                    Ok(MockChild::new(exit_status(0), baseline_ir, "")),
                );
                let baseline_cfg = "target_feature=\"sse2\"\n";
                next_command(
                    &creator,
                    Ok(MockChild::new(exit_status(0), baseline_cfg, "")),
                );
            }
            mock_dep_info(&creator, &["foo.rs"]);
            mock_file_names(&creator, &["foo.rlib"]);
            hasher
                .generate_hash_key(GenerateHashKeyContext {
                    creator: &creator,
                    cwd: f.tempdir.path().to_owned(),
                    env_vars: vec![],
                    may_dist,
                    pool: &pool,
                    rewrite_includes_only: false,
                    storage: Arc::new(MockStorage::new(None, false)),
                    cache_control: CacheControl::Default,
                })
                .wait()
        };

        let local_znver2 = run(Some("znver2|+avx2"), false)?;
        let local_znver5 = run(Some("znver5|+avx512f"), false)?;
        assert_ne!(local_znver2.key, local_znver5.key);
        assert_eq!(local_znver2.cache_control, CacheControl::Default);
        assert_eq!(local_znver5.cache_control, CacheControl::Default);

        let dist_znver2 = run(Some("znver2|+avx2"), true)?;
        assert_eq!(dist_znver2.cache_control, CacheControl::Default);

        let unresolved_native = run(None, false)?;
        assert_eq!(
            unresolved_native.cache_control,
            CacheControl::ForceNoCache,
            "unresolved native CPU identity must bypass cache lookup and storage"
        );

        let mut transformer = dist::PathTransformer::new();
        let (local_command, dist_command, _) = dist_znver2
            .compilation
            .generate_compile_commands(&mut transformer, false)?;

        let local_args = local_command.get_arguments();
        assert!(local_args.iter().any(|arg| arg == "target-cpu=x86-64"));

        #[cfg(feature = "dist-client")]
        {
            let Some(dist_command) = dist_command else {
                bail!("distributed native compilation did not produce a distributed command");
            };
            let dist_args = dist_command.arguments;
            assert!(dist_args.iter().any(|arg| arg == "target-cpu=x86-64"));
            assert!(
                dist_args
                    .iter()
                    .any(|arg| arg == "target-feature=+avx2,+sse2")
            );
            assert!(!dist_args.iter().any(|arg| arg == "target-cpu=native"));
        }

        Ok(())
    }

    #[test]
    #[cfg(feature = "dist-client")]
    fn test_rust_dist_cargo_executable_falls_back_to_cargo() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let bin = temp.path().join(BINS_DIR);
        fs::create_dir_all(&bin)?;
        let cargo = bin.join(format!("cargo{EXE_SUFFIX}"));
        fs::write(&cargo, b"cargo")?;
        assert_eq!(rust_dist_cargo_executable(temp.path()), Some(cargo));
        Ok(())
    }

    #[test]
    #[cfg(feature = "dist-client")]
    fn test_noncanonical_dist_rewrites_cargo_to_packaged_sysroot_binary() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let sysroot = temp.path().join("sysroot");
        let cargo = sysroot.join(BINS_DIR).join(format!("cargo{EXE_SUFFIX}"));
        let real_cargo = sysroot
            .join(BINS_DIR)
            .join(format!("cargo.real{EXE_SUFFIX}"));
        fs::create_dir_all(cargo.parent().context("Cargo path has no parent")?)?;
        fs::write(&cargo, b"site-wrapper")?;
        fs::write(&real_cargo, b"cargo")?;
        assert_ne!(cargo, real_cargo);

        let parsed = match parse_arguments(
            &[
                OsString::from("foo.rs"),
                OsString::from("--emit"),
                OsString::from("link"),
                OsString::from("--crate-name"),
                OsString::from("foo"),
                OsString::from("--crate-type"),
                OsString::from("lib"),
                OsString::from("--out-dir"),
                OsString::from("out"),
            ],
            temp.path(),
        ) {
            CompilerArguments::Ok(parsed) => parsed,
            other => bail!("unexpected parse result: {other:?}"),
        };

        let compilation = RustCompilation {
            executable: sysroot.join(BINS_DIR).join("rustc"),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            sysroot: sysroot.clone(),
            rlib_dep_reader: None,
            arguments: parsed.arguments,
            inputs: vec![temp.path().join("foo.rs")],
            outputs: HashMap::new(),
            crate_link_paths: vec![],
            crate_name: "foo".to_owned(),
            #[cfg(feature = "dist-client")]
            can_trim_rlibs: true,
            cwd: temp.path().to_owned(),
            env_vars: vec![(
                OsString::from("CARGO"),
                OsString::from("/usr/local/libexec/cargo-site-wrapper"),
            )],
            env_dep_names: HashSet::new(),
            allow_dist: true,
            #[cfg(feature = "dist-client")]
            dlltool_files: Vec::new(),
            canonical_paths: None,
        };

        let mut transformer = dist::PathTransformer::new();
        let (_, dist_command, _) =
            <RustCompilation as Compilation<ProcessCommandCreator>>::generate_compile_commands(
                &compilation,
                &mut transformer,
                false,
            )?;
        let dist_command = dist_command.context("distributed command unexpectedly disabled")?;
        let cargo_value = dist_command
            .env_vars
            .iter()
            .find_map(|(name, value)| (name == "CARGO").then_some(value));
        let expected_cargo = transformer
            .as_dist(&real_cargo)
            .context("sysroot real Cargo path is not distributable")?;
        assert_eq!(
            cargo_value.map(String::as_str),
            Some(expected_cargo.as_str())
        );
        Ok(())
    }

    #[test]
    #[cfg(feature = "dist-client")]
    fn test_noncanonical_dist_without_packaged_cargo_defers_toolchain_decision() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let sysroot = temp.path().join("sysroot");
        fs::create_dir_all(sysroot.join(BINS_DIR))?;

        let parsed = match parse_arguments(
            &[
                OsString::from("foo.rs"),
                OsString::from("--emit"),
                OsString::from("link"),
                OsString::from("--crate-name"),
                OsString::from("foo"),
                OsString::from("--crate-type"),
                OsString::from("lib"),
                OsString::from("--out-dir"),
                OsString::from("out"),
            ],
            temp.path(),
        ) {
            CompilerArguments::Ok(parsed) => parsed,
            other => bail!("unexpected parse result: {other:?}"),
        };

        let compilation = RustCompilation {
            executable: sysroot.join(BINS_DIR).join("rustc"),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            sysroot,
            rlib_dep_reader: None,
            arguments: parsed.arguments,
            inputs: vec![temp.path().join("foo.rs")],
            outputs: HashMap::new(),
            crate_link_paths: vec![],
            crate_name: "foo".to_owned(),
            #[cfg(feature = "dist-client")]
            can_trim_rlibs: true,
            cwd: temp.path().to_owned(),
            env_vars: vec![(
                OsString::from("CARGO"),
                OsString::from("/usr/local/libexec/cargo-site-wrapper"),
            )],
            env_dep_names: HashSet::new(),
            allow_dist: true,
            #[cfg(feature = "dist-client")]
            dlltool_files: Vec::new(),
            canonical_paths: None,
        };

        let mut transformer = dist::PathTransformer::new();
        let (_, dist_command, _) =
            <RustCompilation as Compilation<ProcessCommandCreator>>::generate_compile_commands(
                &compilation,
                &mut transformer,
                false,
            )?;
        assert!(dist_command.is_some());
        assert!(
            <RustCompilation as Compilation<ProcessCommandCreator>>::dist_command_uses_cargo(
                &compilation,
            )
        );
        assert!(
            !<RustCompilation as Compilation<ProcessCommandCreator>>::automatic_dist_toolchain_is_ready(
                &compilation,
            )
        );
        Ok(())
    }

    #[test]
    fn test_canonical_env_dep_preserves_physical_value_and_key() {
        fn run(f: &TestFixture) -> (String, OsString) {
            create_file(f.tempdir.path(), "Cargo.toml", |mut file| {
                file.write_all(b"[package]\nname='foo'\nversion='0.0.0'\n")
            })
            .unwrap();
            f.touch("foo.rs").unwrap();

            let args = [
                "--emit",
                "link",
                "foo.rs",
                "--out-dir",
                "out",
                "--crate-name",
                "foo",
                "--crate-type",
                "lib",
            ];
            let oargs = args.iter().map(OsString::from).collect::<Vec<_>>();
            let parsed_args = match parse_arguments(&oargs, f.tempdir.path()) {
                CompilerArguments::Ok(parsed_args) => parsed_args,
                other => panic!("Got unexpected parse result: {other:?}"),
            };
            let mut hasher = Box::new(RustHasher {
                executable: "rustc".into(),
                host: "x86-64-unknown-unknown-unknown".to_owned(),
                version: TEST_RUSTC_VERSION.to_string(),
                sysroot: f.tempdir.path().join("sysroot"),
                compiler_shlibs_digests: vec![],
                dist_archive: None,
                #[cfg(feature = "dist-client")]
                rlib_dep_reader: None,
                native_profile: Some("test-native".into()),
                parsed_args,
            });

            let manifest = f.tempdir.path().to_owned();
            let env = vec![
                (
                    OsString::from("SCCACHE_EXPERIMENTAL_CANONICAL_RUST"),
                    OsString::from("1"),
                ),
                (
                    OsString::from("SCCACHE_CANONICAL_BUILD_ROOT"),
                    manifest.clone().into_os_string(),
                ),
                (
                    OsString::from("CARGO_MANIFEST_DIR"),
                    manifest.clone().into_os_string(),
                ),
            ];
            let creator = new_creator();
            let runtime = single_threaded_runtime();
            let pool = runtime.handle().clone();
            let manifest_for_dep = manifest.clone();

            next_command_calls(&creator, move |args| {
                let mut dep_info_path = None;
                let mut it = args.iter();
                while let Some(arg) = it.next() {
                    if arg == "-o" {
                        dep_info_path = it.next();
                        break;
                    }
                }
                let mut file = File::create(dep_info_path.unwrap())?;
                writeln!(file, "blah: foo.rs")?;
                writeln!(file, "foo.rs:")?;
                writeln!(
                    file,
                    "# env-dep:CARGO_MANIFEST_DIR={}",
                    manifest_for_dep.display()
                )?;
                Ok(MockChild::new(exit_status(0), "", ""))
            });
            mock_file_names(&creator, &["foo.rlib"]);

            let result = hasher
                .generate_hash_key(GenerateHashKeyContext {
                    creator: &creator,
                    cwd: manifest,
                    env_vars: env,
                    may_dist: true,
                    pool: &pool,
                    rewrite_includes_only: false,
                    storage: Arc::new(MockStorage::new(None, false)),
                    cache_control: CacheControl::Default,
                })
                .wait()
                .unwrap();

            let mut transformer = dist::PathTransformer::new();
            let (command, distributed, _) = result
                .compilation
                .generate_compile_commands(&mut transformer, false)
                .unwrap();
            let manifest_env = command
                .get_env_vars()
                .into_iter()
                .find(|(name, _)| name == "CARGO_MANIFEST_DIR")
                .map(|(_, value)| value)
                .unwrap();

            #[cfg(all(feature = "dist-client", unix))]
            {
                let distributed =
                    distributed.expect("observed path must not force local compilation");
                assert_eq!(distributed.cwd, f.tempdir.path().to_str().unwrap());
                assert_eq!(
                    distributed
                        .env_vars
                        .iter()
                        .find_map(|(name, value)| (name == "CARGO_MANIFEST_DIR")
                            .then_some(value.as_str())),
                    f.tempdir.path().to_str()
                );
                assert_eq!(
                    transformer
                        .as_dist(&f.tempdir.path().join("foo.rs"))
                        .as_deref(),
                    f.tempdir.path().join("foo.rs").to_str()
                );
            }
            #[cfg(not(all(feature = "dist-client", unix)))]
            let _ = distributed;
            (result.key, manifest_env)
        }

        let a = TestFixture::new();
        let b = TestFixture::new();
        let (key_a, manifest_a) = run(&a);
        let (key_b, manifest_b) = run(&b);

        assert_eq!(manifest_a, a.tempdir.path().as_os_str());
        assert_eq!(manifest_b, b.tempdir.path().as_os_str());
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_canonical_unknown_source_falls_back_without_failing() -> Result<()> {
        let f = TestFixture::new();
        f.touch("foo.rs")?;
        let external = tempfile::tempdir()?;
        let external_source = external.path().join("shared.rs");
        fs::write(&external_source, b"pub const SHARED: u8 = 1;\n")?;

        let raw = [
            "--emit",
            "link,dep-info",
            "foo.rs",
            "--out-dir",
            "target/out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
        ];
        let oargs = raw.iter().map(OsString::from).collect::<Vec<_>>();
        let parsed_args = match parse_arguments(&oargs, f.tempdir.path()) {
            CompilerArguments::Ok(parsed_args) => parsed_args,
            other => bail!("unexpected parse result: {other:?}"),
        };

        let creator = new_creator();
        mock_dep_info(
            &creator,
            &[
                "foo.rs",
                external_source.to_str().context("non-UTF-8 temp path")?,
            ],
        );
        mock_file_names(&creator, &["foo.rlib"]);
        let runtime = single_threaded_runtime();
        let pool = runtime.handle().clone();
        let mut hasher = RustHasher {
            executable: "rustc".into(),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            version: TEST_RUSTC_VERSION.to_string(),
            sysroot: f.tempdir.path().join("sysroot"),
            compiler_shlibs_digests: vec![],
            dist_archive: None,
            #[cfg(feature = "dist-client")]
            rlib_dep_reader: None,
            native_profile: Some("test-native".into()),
            parsed_args,
        };
        let env = vec![
            (
                OsString::from("SCCACHE_EXPERIMENTAL_CANONICAL_RUST"),
                OsString::from("1"),
            ),
            (
                OsString::from("SCCACHE_CANONICAL_BUILD_ROOT"),
                f.tempdir.path().as_os_str().to_owned(),
            ),
            (
                OsString::from("SCCACHE_CANONICAL_TARGET_ROOT"),
                f.tempdir.path().join("target").into_os_string(),
            ),
        ];

        let result = hasher
            .generate_hash_key(GenerateHashKeyContext {
                creator: &creator,
                cwd: f.tempdir.path().to_owned(),
                env_vars: env,
                may_dist: false,
                pool: &pool,
                rewrite_includes_only: false,
                storage: Arc::new(MockStorage::new(None, false)),
                cache_control: CacheControl::Default,
            })
            .wait()?;

        let mut transformer = dist::PathTransformer::new();
        let (command, _, _) = result
            .compilation
            .generate_compile_commands(&mut transformer, false)?;
        let arguments = command.get_arguments();

        assert!(
            !arguments.iter().any(|arg| arg == "--die-with-parent"),
            "fallback unexpectedly kept canonical bubblewrap execution"
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair[0] == "--emit" && pair[1] == "link,dep-info"),
            "ordinary fallback did not preserve the caller's dep-info emission"
        );

        Ok(())
    }

    #[test]
    fn test_canonical_output_outside_target_falls_back_without_failing() -> Result<()> {
        let f = TestFixture::new();
        f.touch("foo.rs")?;

        let raw = [
            "--emit",
            "link,dep-info",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
        ];
        let oargs = raw.iter().map(OsString::from).collect::<Vec<_>>();
        let parsed_args = match parse_arguments(&oargs, f.tempdir.path()) {
            CompilerArguments::Ok(parsed_args) => parsed_args,
            other => bail!("unexpected parse result: {other:?}"),
        };

        let creator = new_creator();
        mock_dep_info(&creator, &["foo.rs"]);
        mock_file_names(&creator, &["foo.rlib"]);
        let runtime = single_threaded_runtime();
        let pool = runtime.handle().clone();
        let mut hasher = RustHasher {
            executable: "rustc".into(),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            version: TEST_RUSTC_VERSION.to_string(),
            sysroot: f.tempdir.path().join("sysroot"),
            compiler_shlibs_digests: vec![],
            dist_archive: None,
            #[cfg(feature = "dist-client")]
            rlib_dep_reader: None,
            native_profile: Some("test-native".into()),
            parsed_args,
        };
        let env = vec![
            (
                OsString::from("SCCACHE_EXPERIMENTAL_CANONICAL_RUST"),
                OsString::from("1"),
            ),
            (
                OsString::from("SCCACHE_CANONICAL_BUILD_ROOT"),
                f.tempdir.path().as_os_str().to_owned(),
            ),
            (
                OsString::from("SCCACHE_CANONICAL_TARGET_ROOT"),
                f.tempdir.path().join("target").into_os_string(),
            ),
        ];

        let result = hasher
            .generate_hash_key(GenerateHashKeyContext {
                creator: &creator,
                cwd: f.tempdir.path().to_owned(),
                env_vars: env,
                may_dist: false,
                pool: &pool,
                rewrite_includes_only: false,
                storage: Arc::new(MockStorage::new(None, false)),
                cache_control: CacheControl::Default,
            })
            .wait()?;

        let mut transformer = dist::PathTransformer::new();
        let (command, _, _) = result
            .compilation
            .generate_compile_commands(&mut transformer, false)?;
        let arguments = command.get_arguments();
        assert!(
            !arguments.iter().any(|arg| arg == "--die-with-parent"),
            "output under read-only /build unexpectedly kept canonical execution"
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair[0] == "--emit" && pair[1] == "link,dep-info"),
            "ordinary fallback did not preserve the caller's dep-info emission"
        );

        Ok(())
    }

    #[test]
    fn test_canonical_hash_equal_across_physical_roots() {
        fn mk_manifest(tempdir: &Path) -> Result<()> {
            create_file(tempdir, "Cargo.toml", |mut f| {
                f.write_all(b"[package]\nname='foo'\nversion='0.0.0'\n")
            })?;
            Ok(())
        }

        let args = [
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "target/out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
        ];
        let a = TestFixture::new();
        let b = TestFixture::new();
        let env_a = vec![
            (
                OsString::from("SCCACHE_EXPERIMENTAL_CANONICAL_RUST"),
                OsString::from("1"),
            ),
            (
                OsString::from("CARGO_TARGET_DIR"),
                a.tempdir.path().join("target").into_os_string(),
            ),
            (
                OsString::from("CARGO_HOME"),
                PathBuf::from("/tmp/sccache-canonical-explicit-home/.cargo").into_os_string(),
            ),
            (
                OsString::from("CARGO_MANIFEST_DIR"),
                a.tempdir.path().as_os_str().to_owned(),
            ),
        ];
        let env_b = vec![
            (
                OsString::from("SCCACHE_EXPERIMENTAL_CANONICAL_RUST"),
                OsString::from("1"),
            ),
            (
                OsString::from("HOME"),
                PathBuf::from("/tmp/sccache-canonical-implicit-home").into_os_string(),
            ),
            (
                OsString::from("CARGO_MANIFEST_DIR"),
                b.tempdir.path().as_os_str().to_owned(),
            ),
        ];

        assert_eq!(
            hash_key(&a, &args, &env_a, mk_manifest, false),
            hash_key(&b, &args, &env_b, mk_manifest, false)
        );
    }

    #[test]
    fn test_cargo_manifest_path_overrides_manifest_dir() -> Result<()> {
        let f = TestFixture::new();
        let default_manifest = f.tempdir.path().join("Cargo.toml");
        let explicit_manifest = f.tempdir.path().join("Explicit.toml");
        fs::write(&default_manifest, b"default")?;
        fs::write(&explicit_manifest, b"explicit")?;

        let env = vec![
            (
                OsString::from("CARGO_MANIFEST_DIR"),
                f.tempdir.path().as_os_str().to_owned(),
            ),
            (
                OsString::from("CARGO_MANIFEST_PATH"),
                explicit_manifest.as_os_str().to_owned(),
            ),
        ];

        assert_eq!(
            cargo_manifest_input(&env, f.tempdir.path()),
            Some(explicit_manifest)
        );
        Ok(())
    }

    #[test]
    fn test_cargo_manifest_contents_affect_hash_key() -> Result<()> {
        let f = TestFixture::new();
        let args = [
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
        ];
        let env = vec![(
            OsString::from("CARGO_MANIFEST_DIR"),
            f.tempdir.path().as_os_str().to_owned(),
        )];

        let first = hash_key(
            &f,
            &args,
            &env,
            |root| {
                fs::write(
                    root.join("Cargo.toml"),
                    b"[package]
name='foo'
version='1.0.0'
",
                )?;
                Ok(())
            },
            false,
        );
        let second = hash_key(
            &f,
            &args,
            &env,
            |root| {
                fs::write(
                    root.join("Cargo.toml"),
                    b"[package]
name='foo'
version='2.0.0'
",
                )?;
                Ok(())
            },
            false,
        );

        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn test_cargo_manifest_sidecar_contents_affect_hash_key() -> Result<()> {
        let f = TestFixture::new();
        let proc_macro_extern = if cfg!(windows) {
            "macro_dep=macro_dep.dll"
        } else if cfg!(target_os = "macos") {
            "macro_dep=libmacro_dep.dylib"
        } else {
            "macro_dep=libmacro_dep.so"
        };
        let args = [
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--extern",
            proc_macro_extern,
        ];
        let env = vec![(
            OsString::from("CARGO_MANIFEST_DIR"),
            f.tempdir.path().as_os_str().to_owned(),
        )];

        let make_inputs = |protocol: &'static [u8]| {
            move |root: &Path| {
                fs::write(
                    root.join("Cargo.toml"),
                    b"[package]\nname='foo'\nversion='1.0.0'\n",
                )?;
                fs::write(root.join("wayland.xml"), protocol)?;
                Ok(())
            }
        };

        let first = hash_key(&f, &args, &env, make_inputs(b"<protocol name='a'/>"), false);
        let second = hash_key(&f, &args, &env, make_inputs(b"<protocol name='b'/>"), false);

        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn test_cargo_manifest_tree_inputs_excludes_target_and_vcs_metadata() -> Result<()> {
        let f = TestFixture::new();
        let root = f.tempdir.path();
        let manifest = root.join("Cargo.toml");
        let protocol = root.join("protocols/wayland.xml");
        let target = root.join("target");
        fs::create_dir_all(protocol.parent().context("protocol has no parent")?)?;
        fs::create_dir_all(target.join("debug"))?;
        fs::create_dir_all(root.join(".git/objects"))?;
        fs::write(&manifest, b"[package]\nname='foo'\nversion='1.0.0'\n")?;
        fs::write(&protocol, b"<protocol/>")?;
        fs::write(
            target.join("CACHEDIR.TAG"),
            b"Signature: 8a477f597d28d172789f06886806bc55\n",
        )?;
        fs::write(target.join("debug/generated"), b"output")?;
        fs::write(root.join(".git/objects/object"), b"git")?;

        let inputs = cargo_manifest_tree_inputs(&manifest, &target.join("debug/deps"))?;
        assert!(inputs.contains(&manifest));
        assert!(inputs.contains(&protocol));
        assert!(!inputs.iter().any(|path| path.starts_with(&target)));
        assert!(
            !inputs
                .iter()
                .any(|path| path.starts_with(root.join(".git")))
        );
        Ok(())
    }

    fn nothing(_path: &Path) -> Result<()> {
        Ok(())
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_equal_hashes_externs(preprocessor_cache_mode: bool) {
        // Put some content in the extern rlibs so we can verify that the content hashes are
        // used in the right order.
        fn mk_files(tempdir: &Path) -> Result<()> {
            create_file(tempdir, "a.rlib", |mut f| f.write_all(b"this is a.rlib"))?;
            create_file(tempdir, "b.rlib", |mut f| f.write_all(b"this is b.rlib"))?;
            Ok(())
        }
        let f = TestFixture::new();
        assert_eq!(
            hash_key(
                &f,
                &[
                    "--emit",
                    "link",
                    "foo.rs",
                    "--extern",
                    "a=a.rlib",
                    "--out-dir",
                    "out",
                    "--crate-name",
                    "foo",
                    "--crate-type",
                    "lib",
                    "--extern",
                    "b=b.rlib"
                ],
                &[],
                mk_files,
                preprocessor_cache_mode,
            ),
            hash_key(
                &f,
                &[
                    "--extern",
                    "b=b.rlib",
                    "--emit",
                    "link",
                    "--extern",
                    "a=a.rlib",
                    "foo.rs",
                    "--out-dir",
                    "out",
                    "--crate-name",
                    "foo",
                    "--crate-type",
                    "lib"
                ],
                &[],
                mk_files,
                preprocessor_cache_mode,
            )
        );
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_equal_hashes_link_paths(preprocessor_cache_mode: bool) {
        let f = TestFixture::new();
        assert_eq!(
            hash_key(
                &f,
                &[
                    "--emit",
                    "link",
                    "-L",
                    "x=x",
                    "foo.rs",
                    "--out-dir",
                    "out",
                    "--crate-name",
                    "foo",
                    "--crate-type",
                    "lib",
                    "-L",
                    "y=y"
                ],
                &[],
                nothing,
                preprocessor_cache_mode,
            ),
            hash_key(
                &f,
                &[
                    "-L",
                    "y=y",
                    "--emit",
                    "link",
                    "-L",
                    "x=x",
                    "foo.rs",
                    "--out-dir",
                    "out",
                    "--crate-name",
                    "foo",
                    "--crate-type",
                    "lib"
                ],
                &[],
                nothing,
                preprocessor_cache_mode,
            )
        );
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_equal_hashes_ignored_args(preprocessor_cache_mode: bool) {
        let f = TestFixture::new();
        assert_eq!(
            hash_key(
                &f,
                &[
                    "--emit",
                    "link",
                    "-L",
                    "x=x",
                    "foo.rs",
                    "--out-dir",
                    "out",
                    "--diagnostic-width=1",
                    "--extern",
                    "a=1",
                    "--crate-name",
                    "foo",
                    "--crate-type",
                    "lib",
                    "-L",
                    "y=y"
                ],
                &[],
                nothing,
                preprocessor_cache_mode,
            ),
            hash_key(
                &f,
                &[
                    "-L",
                    "y=a",
                    "--emit",
                    "link",
                    "-L",
                    "x=b",
                    "foo.rs",
                    "--extern",
                    "a=2",
                    "--out-dir",
                    "out2",
                    "--crate-name",
                    "foo",
                    "--crate-type",
                    "lib"
                ],
                &[],
                nothing,
                preprocessor_cache_mode,
            )
        );
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_equal_hashes_ignored_check_cfg_arg(preprocessor_cache_mode: bool) {
        let f = TestFixture::new();
        assert_eq!(
            hash_key(
                &f,
                &[
                    "--emit",
                    "link",
                    "-L",
                    "x=x",
                    "foo.rs",
                    "--out-dir",
                    "out",
                    "--crate-name",
                    "foo",
                    "--crate-type",
                    "lib",
                ],
                &[],
                nothing,
                preprocessor_cache_mode,
            ),
            hash_key(
                &f,
                &[
                    "--emit",
                    "link",
                    "-L",
                    "x=x",
                    "foo.rs",
                    "--out-dir",
                    "out",
                    "--crate-name",
                    "foo",
                    "--crate-type",
                    "lib",
                    "--check-cfg",
                    "cfg(verbose)",
                ],
                &[],
                nothing,
                preprocessor_cache_mode,
            )
        );
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_equal_hashes_cfg_features(preprocessor_cache_mode: bool) {
        let f = TestFixture::new();
        assert_eq!(
            hash_key(
                &f,
                &[
                    "--emit",
                    "link",
                    "--cfg",
                    "feature=a",
                    "foo.rs",
                    "--out-dir",
                    "out",
                    "--crate-name",
                    "foo",
                    "--crate-type",
                    "lib",
                    "--cfg",
                    "feature=b"
                ],
                &[],
                nothing,
                preprocessor_cache_mode,
            ),
            hash_key(
                &f,
                &[
                    "--cfg",
                    "feature=b",
                    "--emit",
                    "link",
                    "--cfg",
                    "feature=a",
                    "foo.rs",
                    "--out-dir",
                    "out",
                    "--crate-name",
                    "foo",
                    "--crate-type",
                    "lib"
                ],
                &[],
                nothing,
                preprocessor_cache_mode,
            )
        );
    }

    #[test]
    fn test_parse_unstable_profile_flag() {
        let h = parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "./src/lib.rs",
            "--emit=dep-info,link",
            "--out-dir",
            "/out",
            "-Zprofile"
        );

        assert_eq!(h.gcno, Some("foo.gcno".into()));

        let h = parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "./src/lib.rs",
            "--emit=dep-info,link",
            "-C",
            "extra-filename=-a1b6419f8321841f",
            "--out-dir",
            "/out",
            "-Zprofile"
        );

        assert_eq!(h.gcno, Some("foo-a1b6419f8321841f.gcno".into()));
    }

    #[test]
    fn test_parse_remap_path_prefix() {
        let h = parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "./src/lib.rs",
            "--emit=dep-info,link",
            "--out-dir",
            "/out",
            "--remap-path-prefix",
            "/home/test=~",
            "--remap-path-prefix",
            "/root=~"
        );
        assert!(h.arguments.contains(&Argument::WithValue(
            "--remap-path-prefix",
            ArgData::PassThrough(OsString::from("/home/test=~")),
            ArgDisposition::Separated
        )));
        assert!(h.arguments.contains(&Argument::WithValue(
            "--remap-path-prefix",
            ArgData::PassThrough(OsString::from("/root=~")),
            ArgDisposition::Separated
        )));
    }

    #[test]
    fn test_parse_target() {
        // Parse a --target argument that is a string (not a path to a .json file).
        let h = parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "./src/lib.rs",
            "--emit=dep-info,link",
            "--out-dir",
            "/out",
            "--target",
            "string"
        );
        assert!(h.arguments.contains(&Argument::WithValue(
            "--target",
            ArgData::Target(ArgTarget::Name("string".to_owned())),
            ArgDisposition::Separated
        )));
        assert!(h.target_json.is_none());

        // Parse a --target argument that is a path.
        let h = parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "./src/lib.rs",
            "--emit=dep-info,link",
            "--out-dir",
            "/out",
            "--target",
            "/path/to/target.json"
        );
        assert!(h.arguments.contains(&Argument::WithValue(
            "--target",
            ArgData::Target(ArgTarget::Path(PathBuf::from("/path/to/target.json"))),
            ArgDisposition::Separated
        )));
        assert_eq!(h.target_json, Some(PathBuf::from("/path/to/target.json")));
    }

    #[test]
    fn dist_toolchain_weak_key_tracks_target_std_manifest_and_physical_layout() {
        let base = ["same-rustc".to_owned()];

        let host = dist_toolchain_weak_key(
            &base,
            "x86_64-unknown-linux-gnu",
            Some("host-std-digest"),
            None,
        );
        let wasm = dist_toolchain_weak_key(&base, "wasm32-wasip2", Some("wasm-std-digest"), None);
        let wasm_missing = dist_toolchain_weak_key(&base, "wasm32-wasip2", None, None);
        let wasm_repeated =
            dist_toolchain_weak_key(&base, "wasm32-wasip2", Some("wasm-std-digest"), None);

        assert_ne!(host, wasm);
        assert_ne!(wasm_missing, wasm);
        assert_eq!(wasm, wasm_repeated);

        let previous_package_schema = dist_toolchain_weak_key_with_schema(
            &base,
            b"rust-dist-toolchain-package-v2",
            "x86_64-unknown-linux-gnu",
            Some("host-std-digest"),
            None,
        );
        assert_ne!(host, previous_package_schema);

        let root_toolchain = dist_toolchain_weak_key(
            &base,
            "x86_64-unknown-linux-gnu",
            Some("host-std-digest"),
            Some(Path::new("/root/.rustup/toolchains/1.99.0")),
        );
        let user_toolchain = dist_toolchain_weak_key(
            &base,
            "x86_64-unknown-linux-gnu",
            Some("host-std-digest"),
            Some(Path::new("/home/user/.rustup/toolchains/1.99.0")),
        );
        assert_ne!(root_toolchain, user_toolchain);
        assert_ne!(root_toolchain, host);
        assert_ne!(
            host,
            dist_toolchain_weak_key(
                &["different-rustc".to_owned()],
                "x86_64-unknown-linux-gnu",
                Some("host-std-digest"),
                None,
            )
        );
    }

    #[test]
    fn dist_toolchain_key_is_independent_of_compilation_policy() -> Result<()> {
        let f = TestFixture::new();
        let args = [
            "--emit",
            "metadata",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
        ];
        let policy = f.tempdir.path().join("policy");
        fs::create_dir_all(&policy)?;
        fs::write(
            policy.join("clippy.toml"),
            b"disallowed-names = [\"test\"]\n",
        )?;
        let env = vec![(OsString::from("CLIPPY_CONF_DIR"), policy.into_os_string())];
        let (rustc_key, rustc_toolchain) =
            hash_keys_for_compiler(&f, &args, &[], |_| Ok(()), false, "rustc");
        let (clippy_key, clippy_toolchain) =
            hash_keys_for_compiler(&f, &args, &env, |_| Ok(()), false, "clippy-driver");
        assert_ne!(rustc_key, clippy_key);
        assert_eq!(rustc_toolchain, clippy_toolchain);
        Ok(())
    }

    #[test]
    fn test_parse_arguments_response_file() {
        let td = tempfile::Builder::new()
            .prefix("sccache")
            .tempdir()
            .unwrap();
        File::create(td.path().join("args"))
            .unwrap()
            .write_all(b"--emit\nlink,dep-info\nfoo.rs\n--out-dir\nout\n--crate-name\nfoo\n--crate-type\nlib\n")
            .unwrap();
        let arg = format!("@{}", td.path().join("args").display());
        let args: Vec<OsString> = vec![OsString::from(arg)];
        let result = parse_arguments(&args, td.path());
        let parsed = match result {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {o:?}"),
        };
        assert_eq!(parsed.output_dir.to_str(), Some("out"));
        assert!(parsed.dep_info.is_some());
        assert_eq!(parsed.externs, [] as [std::path::PathBuf; 0]);
    }

    #[test]
    fn test_parse_arguments_response_file_missing() {
        // Do not generate a cache key from arguments rustc cannot expand.
        let cwd = Path::new("/nonexistent");
        let args: Vec<OsString> = vec![OsString::from("@missing_file")];
        let result = parse_arguments(&args, cwd);
        assert!(matches!(result, CompilerArguments::CannotCache(..)));
    }
}
