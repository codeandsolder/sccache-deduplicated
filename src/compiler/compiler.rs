// Copyright 2016 Mozilla Foundation
// SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use crate::cache::{FileObjectSource, Storage};
use crate::compiler::args::{
    ArgDisposition, ArgInfo, ArgToStringResult, ArgsIter, Argument, FromArg, IntoArg,
    NormalizedDisposition, PathTransformerFn,
};
use crate::compiler::c::{CCompiler, CCompilerKind};
use crate::compiler::cicc::Cicc;
use crate::compiler::clang::Clang;
use crate::compiler::cudafe::CudaFE;
use crate::compiler::diab::Diab;
use crate::compiler::gcc::Gcc;
use crate::compiler::msvc;
use crate::compiler::msvc::Msvc;
use crate::compiler::nvcc::Nvcc;
use crate::compiler::nvcc::NvccHostCompiler;
use crate::compiler::nvhpc::Nvhpc;
use crate::compiler::ptxas::Ptxas;
use crate::compiler::rust::{Rust, RustupProxy};
use crate::compiler::tasking_vx::TaskingVX;
#[cfg(feature = "dist-client")]
use crate::dist::pkg;
#[cfg(test)]
use crate::mock_command::exit_status;
use crate::mock_command::{CommandChild, CommandCreatorSync, RunCommand};
use crate::server;
use crate::server::activity::{self, Phase};
use crate::util::{
    Digest, fmt_duration_as_secs, resolve_compiler_avoiding_wrapper, run_input_output,
};
use crate::{counted_array, dist};
use async_trait::async_trait;
use fs::File;
use fs_err as fs;
use futures::TryFutureExt;
use itertools::Itertools as _;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::future::Future;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{self, Stdio};
use std::str;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tempfile::TempDir;

#[cfg(test)]
use crate::errors::anyhow;
use crate::errors::{Context, ProcessError, Result, bail};

/// Can dylibs (shared libraries or proc macros) be distributed on this platform?
#[cfg(all(
    feature = "dist-client",
    any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        target_os = "freebsd"
    )
))]
pub const CAN_DIST_DYLIBS: bool = true;
#[cfg(all(
    feature = "dist-client",
    not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        target_os = "freebsd"
    ))
))]
pub const CAN_DIST_DYLIBS: bool = false;

pub trait CompileCommand<T>: Send + Sync + 'static
where
    T: CommandCreatorSync,
{
    fn get_executable(&self) -> PathBuf;
    fn get_arguments(&self) -> Vec<OsString>;
    fn get_env_vars(&self) -> Vec<(OsString, OsString)>;
    fn get_cwd(&self) -> PathBuf;
}

#[derive(Debug)]
pub struct CCompileCommand<I>
where
    I: CompileCommandImpl,
{
    cmd: I,
}

impl<I> CCompileCommand<I>
where
    I: CompileCommandImpl,
{
    pub fn boxed<T>(cmd: I) -> Box<dyn CompileCommand<T>>
    where
        T: CommandCreatorSync,
    {
        Box::new(Self { cmd }) as Box<dyn CompileCommand<T>>
    }
}

impl<T, I> CompileCommand<T> for CCompileCommand<I>
where
    T: CommandCreatorSync,
    I: CompileCommandImpl,
{
    fn get_executable(&self) -> PathBuf {
        self.cmd.get_executable()
    }
    fn get_arguments(&self) -> Vec<OsString> {
        self.cmd.get_arguments()
    }
    fn get_env_vars(&self) -> Vec<(OsString, OsString)> {
        self.cmd.get_env_vars()
    }
    fn get_cwd(&self) -> PathBuf {
        self.cmd.get_cwd()
    }
}

pub trait CompileCommandImpl: Send + Sync + 'static {
    fn get_executable(&self) -> PathBuf;
    fn get_arguments(&self) -> Vec<OsString>;
    fn get_env_vars(&self) -> Vec<(OsString, OsString)>;
    fn get_cwd(&self) -> PathBuf;
}

#[derive(Debug)]
pub struct SingleCompileCommand {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub env_vars: Vec<(OsString, OsString)>,
    pub cwd: PathBuf,
}

impl CompileCommandImpl for SingleCompileCommand {
    fn get_executable(&self) -> PathBuf {
        self.executable.clone()
    }
    fn get_arguments(&self) -> Vec<OsString> {
        self.arguments.clone()
    }
    fn get_env_vars(&self) -> Vec<(OsString, OsString)> {
        self.env_vars.clone()
    }
    fn get_cwd(&self) -> PathBuf {
        self.cwd.clone()
    }
}

/// Supported compilers.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CompilerKind {
    /// A C compiler.
    C(CCompilerKind),
    /// A Rust compiler.
    Rust,
}

// Used for tests
// Need to be consistent with `Language`
#[cfg(test)]
const EXPECTED_LANGUAGE_COUNT: usize = 21;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Language {
    AssemblerToPreprocess,
    Assembler,
    C,
    Cxx,
    GenericHeader,
    CHeader,
    CPreprocessed,
    CxxHeader,
    CxxPreprocessed,
    ObjectiveC,
    ObjectiveCHeader,
    ObjectiveCPreprocessed,
    ObjectiveCxx,
    ObjectiveCxxPreprocessed,
    ObjectiveCxxHeader,
    Cuda,
    CudaFE,
    Ptx,
    Cubin,
    Rust,
    Hip,
    CxxModule,
}

impl Language {
    pub fn from_file_name(file: &Path) -> Option<Self> {
        match file.extension().and_then(|e| e.to_str()) {
            // gcc: https://gcc.gnu.org/onlinedocs/gcc/Overall-Options.html
            Some("s") => Some(Self::Assembler),
            Some("S" | "sx") => Some(Self::AssemblerToPreprocess),
            Some("c") => Some(Self::C),
            // Could be C or C++
            Some("h") => Some(Self::GenericHeader),
            Some("i") => Some(Self::CPreprocessed),
            Some("C" | "cc" | "cp" | "cpp" | "CPP" | "cxx" | "c++") => Some(Self::Cxx),
            Some("ii") => Some(Self::CxxPreprocessed),
            Some("H" | "hh" | "hp" | "hpp" | "HPP" | "hxx" | "h++" | "tcc") => {
                Some(Self::CxxHeader)
            }
            Some("cppm" | "ixx") => Some(Self::CxxModule),
            Some("m") => Some(Self::ObjectiveC),
            Some("mi") => Some(Self::ObjectiveCPreprocessed),
            Some("M" | "mm") => Some(Self::ObjectiveCxx),
            Some("mii") => Some(Self::ObjectiveCxxPreprocessed),
            Some("cu") => Some(Self::Cuda),
            Some("ptx") => Some(Self::Ptx),
            Some("cubin") => Some(Self::Cubin),
            // TODO cy
            Some("rs") => Some(Self::Rust),
            Some("hip") => Some(Self::Hip),
            e => {
                trace!("Unknown source extension: {}", e.unwrap_or("(None)"));
                None
            }
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AssemblerToPreprocess => "assemblerToPreprocess",
            Self::Assembler => "assembler",
            Self::C => "c",
            Self::CHeader => "cHeader",
            Self::CPreprocessed => "cPreprocessed",
            Self::Cxx => "c++",
            Self::CxxHeader => "c++Header",
            Self::CxxPreprocessed => "c++Preprocessed",
            Self::GenericHeader => "c/c++",
            Self::ObjectiveC | Self::ObjectiveCHeader => "objc",
            Self::ObjectiveCPreprocessed => "objcPreprocessed",
            Self::ObjectiveCxx | Self::ObjectiveCxxHeader => "objc++",
            Self::ObjectiveCxxPreprocessed => "objc++Preprocessed",
            Self::Cuda | Self::CudaFE => "cuda",
            Self::Ptx => "ptx",
            Self::Cubin => "cubin",
            Self::Rust => "rust",
            Self::Hip => "hip",
            Self::CxxModule => "c++-module",
        }
    }

    pub const fn needs_c_preprocessing(self) -> bool {
        !matches!(
            self,
            Self::Assembler
                | Self::CPreprocessed
                | Self::CxxPreprocessed
                | Self::ObjectiveCPreprocessed
                | Self::ObjectiveCxxPreprocessed
                | Self::Rust
        )
    }

    pub const fn is_c_like_header(self) -> bool {
        matches!(
            self,
            Self::CHeader
                | Self::CxxHeader
                | Self::ObjectiveCHeader
                | Self::ObjectiveCxxHeader
                | Self::GenericHeader
        )
    }

    pub const fn to_c_preprocessed_language(self) -> Option<Self> {
        match self {
            Self::AssemblerToPreprocess => Some(Self::Assembler),
            Self::C => Some(Self::CPreprocessed),
            Self::Cxx => Some(Self::CxxPreprocessed),
            Self::ObjectiveC => Some(Self::ObjectiveCPreprocessed),
            Self::ObjectiveCxx => Some(Self::ObjectiveCxxPreprocessed),
            _ => None,
        }
    }

    /// Common implementation for GCC and Clang language argument mapping
    const fn to_compiler_arg(self, cuda_arg: &'static str) -> Option<&'static str> {
        match self {
            Self::AssemblerToPreprocess => Some("assembler-with-cpp"),
            Self::Assembler => Some("assembler"),
            Self::C => Some("c"),
            Self::CHeader => Some("c-header"),
            Self::CPreprocessed => Some("cpp-output"),
            Self::Cxx => Some("c++"),
            Self::CxxHeader => Some("c++-header"),
            Self::CxxPreprocessed => Some("c++-cpp-output"),
            Self::ObjectiveC => Some("objective-c"),
            Self::ObjectiveCHeader => Some("objective-c-header"),
            Self::ObjectiveCPreprocessed => Some("objective-c-cpp-output"),
            Self::ObjectiveCxx => Some("objective-c++"),
            Self::ObjectiveCxxHeader => Some("objective-c++-header"),
            Self::ObjectiveCxxPreprocessed => Some("objective-c++-cpp-output"),
            Self::Cuda => Some(cuda_arg),
            Self::CudaFE | Self::Ptx | Self::Cubin | Self::Rust | Self::GenericHeader => None,
            // Let the compiler decide
            Self::Hip => Some("hip"),
            // Let the compiler decide
            Self::CxxModule => Some("c++-module"),
        }
    }

    /// Returns the GCC-specific language argument for the `-x` flag
    /// <https://gcc.gnu.org/onlinedocs/gcc/Overall-Options.html>
    pub const fn to_gcc_arg(self) -> Option<&'static str> {
        self.to_compiler_arg("cu")
    }

    /// Returns the Clang-specific language argument for the `-x` flag
    /// <https://github.com/llvm/llvm-project/blob/main/clang/include/clang/Driver/Types.def>
    pub const fn to_clang_arg(self) -> Option<&'static str> {
        self.to_compiler_arg("cuda")
    }
}

impl CompilerKind {
    pub fn lang_kind(lang: Language) -> String {
        match lang {
            Language::AssemblerToPreprocess | Language::Assembler => "Assembler",
            Language::C
            | Language::CHeader
            | Language::CPreprocessed
            | Language::Cxx
            | Language::CxxHeader
            | Language::CxxModule
            | Language::CxxPreprocessed
            | Language::GenericHeader
            | Language::ObjectiveC
            | Language::ObjectiveCHeader
            | Language::ObjectiveCPreprocessed
            | Language::ObjectiveCxx
            | Language::ObjectiveCxxHeader
            | Language::ObjectiveCxxPreprocessed => "C/C++",
            Language::Cuda => "CUDA",
            Language::CudaFE => "CUDA (Device code)",
            Language::Ptx => "PTX",
            Language::Cubin => "CUBIN",
            Language::Rust => "Rust",
            Language::Hip => "HIP",
        }
        .to_string()
    }
    pub fn lang_comp_kind(&self, lang: Language) -> String {
        let textual_lang = lang.as_str().to_owned();
        match self {
            Self::C(CCompilerKind::Clang) => textual_lang + " [clang]",
            Self::C(CCompilerKind::Diab) => textual_lang + " [diab]",
            Self::C(CCompilerKind::Gcc) => textual_lang + " [gcc]",
            Self::C(CCompilerKind::Msvc) => textual_lang + " [msvc]",
            Self::C(CCompilerKind::Nvcc) => textual_lang + " [nvcc]",
            Self::C(CCompilerKind::CudaFE) => textual_lang + " [cudafe++]",
            Self::C(CCompilerKind::Cicc) => textual_lang + " [cicc]",
            Self::C(CCompilerKind::Ptxas) => textual_lang + " [ptxas]",
            Self::C(CCompilerKind::Nvhpc) => textual_lang + " [nvhpc]",
            Self::C(CCompilerKind::TaskingVX) => textual_lang + " [taskingvx]",
            Self::Rust => textual_lang,
        }
    }
}

/// Select the remote execution representation before compiler-specific
/// argument rewriting. Native workers preserve the declared path topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompileTransport {
    Archive { rewrite_includes_only: bool },
    Native,
}

impl CompileTransport {
    #[must_use = "this controls compiler preprocessing"]
    pub const fn rewrite_includes_only(self) -> bool {
        matches!(
            self,
            Self::Archive {
                rewrite_includes_only: true
            }
        )
    }
}

pub type GenerateCompileCommandsResult<T> = Result<(
    Box<dyn CompileCommand<T>>,
    Option<dist::CompileCommand>,
    Cacheable,
)>;

pub type CompilerProxyFuture =
    Pin<Box<dyn Future<Output = Result<(PathBuf, SystemTime)>> + Send + 'static>>;

#[cfg(feature = "dist-client")]
pub type DistPackagers = (
    Box<dyn pkg::InputsPackager>,
    Box<dyn pkg::ToolchainPackager>,
);

/// Which execution/cache contract the caller intends to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilerCachePolicy {
    FinishedArtifact,
    Native,
}

/// An interface to a compiler for argument parsing.
pub trait Compiler<T>: Send + Sync + 'static
where
    T: CommandCreatorSync,
{
    /// Return the kind of compiler.
    fn kind(&self) -> CompilerKind;
    /// Determine whether `arguments` are supported by this compiler.
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        policy: CompilerCachePolicy,
    ) -> CompilerArguments<Box<dyn CompilerHasher<T> + 'static>>;
    fn box_clone(&self) -> Box<dyn Compiler<T>>;
}

impl<T: CommandCreatorSync> Clone for Box<dyn Compiler<T>> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait CompilerProxy<T>: Send + Sync + 'static
where
    T: CommandCreatorSync + Sized,
{
    /// Maps the executable to be used in `cwd` to the true, proxied compiler.
    ///
    /// Returns the absolute path to the true compiler and the timestamp of
    /// timestamp of the true compiler. Iff the resolution fails,
    /// the returned future resolves to an error with more information.
    fn resolve_proxied_executable(
        &self,
        creator: T,
        cwd: PathBuf,
        env_vars: &[(OsString, OsString)],
    ) -> CompilerProxyFuture;

    /// Create a clone of `Self` and puts it in a `Box`
    fn box_clone(&self) -> Box<dyn CompilerProxy<T>>;
}

impl<T: CommandCreatorSync> Clone for Box<dyn CompilerProxy<T>> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub struct GenerateHashKeyContext<'a, T> {
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    pub native: Option<Arc<super::native::NativeCompilerClient>>,
    pub creator: &'a T,
    pub cwd: PathBuf,
    pub env_vars: Vec<(OsString, OsString)>,
    pub may_dist: bool,
    pub pool: &'a tokio::runtime::Handle,
    pub rewrite_includes_only: bool,
    pub storage: Arc<dyn Storage>,
    pub cache_control: CacheControl,
}

pub struct CacheCompileContext<'a, T: CommandCreatorSync> {
    pub service: &'a server::SccacheService<T>,
    pub creator: T,
    pub storage: Arc<dyn Storage>,
    pub arguments: Vec<OsString>,
    pub cwd: PathBuf,
    pub env_vars: Vec<(OsString, OsString)>,
    pub cache_control: CacheControl,
    pub pool: tokio::runtime::Handle,
}

/// An interface to a compiler for hash key generation, the result of
/// argument parsing.
#[async_trait]
pub trait CompilerHasher<T>: fmt::Debug + Send + 'static
where
    T: CommandCreatorSync,
{
    /// Given information about a compiler command, generate a hash key
    /// that can be used for cache lookups, as well as any additional
    /// information that can be reused for compilation if necessary.
    async fn generate_hash_key(
        &mut self,
        context: GenerateHashKeyContext<'_, T>,
    ) -> Result<HashResult<T>>;

    /// Return the state of any `--color` option passed to the compiler.
    fn color_mode(&self) -> ColorMode;

    /// Discover a compiler's inputs and submit a native CAS action. There is
    /// no alternate archive or client execution contract.
    async fn get_cached_or_compile(
        &mut self,
        context: CacheCompileContext<'_, T>,
    ) -> Result<(CompileResult, process::Output)> {
        #[cfg(not(all(feature = "dist-client", target_os = "linux")))]
        {
            let _ = context;
            bail!("Native distributed compilation requires a Linux distributed client");
        }
        #[cfg(all(feature = "dist-client", target_os = "linux"))]
        {
            let CacheCompileContext {
                service,
                creator,
                storage,
                arguments,
                cwd,
                env_vars,
                cache_control,
                pool,
            } = context;
            let native = service.native_compiler().context(
                "Native scheduler configuration required; compilation cannot run locally",
            )?;
            let out_pretty = self.output_pretty().into_owned();
            debug!("[{out_pretty}]: native compilation: {arguments:?}");
            let start = Instant::now();
            activity::phase(Phase::HashInputs);
            let result = self
                .generate_hash_key(GenerateHashKeyContext {
                    native: Some(Arc::clone(&native)),
                    creator: &creator,
                    cwd: cwd.clone(),
                    env_vars,
                    may_dist: true,
                    pool: &pool,
                    rewrite_includes_only: false,
                    storage,
                    cache_control,
                })
                .await;
            debug!(
                "[{out_pretty}]: generate_hash_key took {}",
                fmt_duration_as_secs(&start.elapsed())
            );
            let HashResult {
                key,
                compilation,
                cache_control,
                ..
            } = match result {
                Ok(result) => result,
                Err(error) => {
                    return match error.downcast::<ProcessError>() {
                        Ok(ProcessError(output)) => Ok((CompileResult::Error, output)),
                        Err(error) => Err(error),
                    };
                }
            };
            super::native::compile(
                native,
                creator,
                cwd,
                compilation,
                (cache_control, &key),
                &pool,
            )
            .await
        }
    }

    /// A descriptive string about the file that we're going to be producing.
    ///
    /// This is primarily intended for debug logging and such, not for actual
    /// artifact generation.
    fn output_pretty(&self) -> Cow<'_, str>;

    fn box_clone(&self) -> Box<dyn CompilerHasher<T>>;

    fn language(&self) -> Language;
}

#[cfg(feature = "dist-client")]
pub(super) fn validate_dist_environment_dependencies(
    command: &dist::CompileCommand,
    dependencies: &[(OsString, Option<OsString>)],
) -> Result<()> {
    for (name, expected) in dependencies {
        let actual = command
            .env_vars
            .iter()
            .rev()
            .find(|(key, _)| OsStr::new(key) == name.as_os_str())
            .map(|(_, value)| OsStr::new(value));
        if actual != expected.as_deref() {
            // Don't print potentially sensitive values from the environment.
            bail!(
                "distributed toolchain cannot preserve observed environment variable {}",
                name.to_string_lossy()
            );
        }
    }
    Ok(())
}

impl<T: CommandCreatorSync> Clone for Box<dyn CompilerHasher<T>> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

/// An interface to a compiler for actually invoking compilation.
pub trait Compilation<T>: Send
where
    T: CommandCreatorSync,
{
    /// Given information about a compiler command, generate a command that can
    /// execute the compiler.
    fn generate_compile_commands(
        &self,
        path_transformer: &mut dist::PathTransformer,
        transport: CompileTransport,
    ) -> GenerateCompileCommandsResult<T>;

    /// Compiler-specific result identity policy for the native CAS.
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    fn native_result_policy(&self) -> super::ResultIdentityPolicy {
        super::ResultIdentityPolicy::Exact
    }

    /// The original Rust native link stage's local namespace, if this
    /// compilation uses an independently cacheable codegen action.
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    fn native_link_layout(&self) -> Option<&super::rust_link::NativeLinkLayout> {
        None
    }

    /// Exact environment observations that the final distributed command must preserve.
    #[cfg(feature = "dist-client")]
    fn dist_environment_dependencies(&self) -> Vec<(OsString, Option<OsString>)> {
        Vec::new()
    }

    /// Whether a custom distributed toolchain must provide a Cargo executable for this command.
    #[cfg(feature = "dist-client")]
    fn dist_command_uses_cargo(&self) -> bool {
        false
    }

    /// Whether the automatically packaged toolchain contains everything this command needs.
    #[cfg(feature = "dist-client")]
    fn automatic_dist_toolchain_is_ready(&self) -> bool {
        true
    }

    /// Create a function that will create the inputs used to perform a distributed compilation
    #[cfg(feature = "dist-client")]
    fn into_dist_packagers(
        self: Box<Self>,
        _path_transformer: dist::PathTransformer,
    ) -> Result<DistPackagers>;

    /// Returns an iterator over the results of this compilation.
    ///
    /// Each item is a descriptive (and unique) name of the output paired with
    /// the path where it'll show up.
    fn outputs<'a>(&'a self) -> Box<dyn Iterator<Item = FileObjectSource> + 'a>;
}

/// Result of generating a hash from a compiler command.
pub struct HashResult<T>
where
    T: CommandCreatorSync,
{
    /// The hash key of the inputs.
    pub key: String,
    /// An object to use for the actual compilation, if necessary.
    pub compilation: Box<dyn Compilation<T> + 'static>,
    /// A weak key that may be used to identify the toolchain.
    pub weak_toolchain_key: String,
    /// Effective cache policy after compiler-specific safety checks.
    pub cache_control: CacheControl,
}

/// Possible results of parsing compiler arguments.
#[derive(Debug, PartialEq, Eq)]
pub enum CompilerArguments<T> {
    /// Commandline can be handled.
    Ok(T),
    /// Cannot cache this compilation.
    CannotCache(&'static str, Option<String>),
    /// This commandline is not a compile.
    NotCompilation,
}

macro_rules! cannot_cache {
    ($why:expr) => {
        return CompilerArguments::CannotCache($why, None)
    };
    ($why:expr, $extra_info:expr) => {
        return CompilerArguments::CannotCache($why, Some($extra_info))
    };
}

macro_rules! try_or_cannot_cache {
    ($arg:expr, $why:expr) => {{
        match $arg {
            Ok(arg) => arg,
            Err(e) => cannot_cache!($why, e.to_string()),
        }
    }};
}

/// Result of a scheduler-owned compilation.
#[derive(Debug, PartialEq, Eq)]
pub enum CompileResult {
    /// Input discovery failed.
    Error,
    /// Native action results, in dependency order.
    Native(Vec<crate::protocol::NativeCompileReport>, Duration),
}

/// The state of `--color` options passed to a compiler.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ColorMode {
    Off,
    On,
    #[default]
    Auto,
}

/// Can this result be stored in cache?
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Cacheable {
    Yes,
    No,
}

/// Control of caching behavior.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CacheControl {
    /// Default caching behavior.
    Default,
    /// Do not cache the results of the compilation.
    ForceNoCache,
    /// Ignore existing cache entries, force recompilation.
    ForceRecache,
}

/// Creates a future that will write `contents` to `path` inside of a temporary
/// directory.
///
/// The future will resolve to the temporary directory and an absolute path
/// inside that temporary directory with a file that has the same filename as
/// `path` contains the `contents` specified.
///
/// Note that when the `TempDir` is dropped it will delete all of its contents
/// including the path returned.
pub async fn write_temp_file(
    pool: &tokio::runtime::Handle,
    path: &Path,
    contents: Vec<u8>,
) -> Result<(TempDir, PathBuf)> {
    let path = path.to_owned();
    pool.spawn_blocking(move || {
        let dir = tempfile::Builder::new().prefix("sccache").tempdir()?;
        let src = dir.path().join(path);
        let mut file = File::create(&src)?;
        file.write_all(&contents)?;
        Ok::<_, anyhow::Error>((dir, src))
    })
    .await?
    .context("failed to write temporary file")
}

/// Returns true if the given path looks like a program known to have
/// a rustc compatible interface.
fn is_rustc_like<P: AsRef<Path>>(p: P) -> bool {
    matches!(
        p.as_ref()
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .as_deref(),
        Some("rustc" | "clippy-driver")
    )
}

/// Returns true if the given path looks like cudafe++
fn is_nvidia_cudafe<P: AsRef<Path>>(p: P) -> bool {
    matches!(
        p.as_ref()
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .as_deref(),
        Some("cudafe++")
    )
}

/// Returns true if the given path looks like cicc
fn is_nvidia_cicc<P: AsRef<Path>>(p: P) -> bool {
    matches!(
        p.as_ref()
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .as_deref(),
        Some("cicc")
    )
}

/// Returns true if the given path looks like ptxas
fn is_nvidia_ptxas<P: AsRef<Path>>(p: P) -> bool {
    matches!(
        p.as_ref()
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .as_deref(),
        Some("ptxas")
    )
}

/// Returns true if the given path looks like a c compiler program
///
/// This does not check c compilers, it only report programs that are definitely not rustc
fn is_known_c_compiler<P: AsRef<Path>>(p: P) -> bool {
    matches!(
        p.as_ref()
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .as_deref(),
        Some(
            "cc" | "c++"
                | "gcc"
                | "g++"
                | "clang"
                | "clang++"
                | "clang-cl"
                | "cl"
                | "nvc"
                | "nvc++"
                | "nvcc"
        )
    )
}

/// Installed compiler inputs needed during discovery. Native compilation
/// shares the content memo with its subsequent executable-tree preparation.
#[derive(Clone, Default)]
pub struct CompilerDiscovery {
    pub dist_archive: Option<PathBuf>,
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    pub native_digests: Option<Arc<crate::build_runtime::SourceDigestCache>>,
}

impl CompilerDiscovery {
    /// Hash one installed tool with the same verified content memo used
    /// by native toolchain capture. Legacy discovery keeps its digest format.
    pub async fn hash_toolchain_file(
        &self,
        path: &Path,
        pool: &tokio::runtime::Handle,
    ) -> Result<String> {
        #[cfg(all(feature = "dist-client", target_os = "linux"))]
        if let Some(cache) = &self.native_digests {
            let path = path.to_owned();
            let cache = Arc::clone(cache);
            return pool
                .spawn_blocking(move || {
                    let blob = cache.file_digest(&path)?;
                    Ok(crate::util::hex(&blob.id.0))
                })
                .await?;
        }
        Digest::file(path, pool).await
    }

    pub async fn hash_toolchain_files(
        &self,
        files: &[PathBuf],
        pool: &tokio::runtime::Handle,
    ) -> Result<Vec<String>> {
        futures::future::try_join_all(
            files
                .iter()
                .map(|path| self.hash_toolchain_file(path, pool)),
        )
        .await
    }
}

/// If `executable` is a known compiler, return `Some(Box<Compiler>)`.
async fn detect_compiler<T>(
    creator: T,
    executable: &Path,
    cwd: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
    pool: &tokio::runtime::Handle,
    discovery: CompilerDiscovery,
) -> Result<(Box<dyn Compiler<T>>, Option<Box<dyn CompilerProxy<T>>>)>
where
    T: CommandCreatorSync,
{
    trace!("detect_compiler: {}", executable.display());
    // First, see if this looks like rustc.

    let maybe_rustc_executable = if is_rustc_like(executable) {
        Some(executable.to_path_buf())
    } else if env.iter().any(|(k, _)| k == OsStr::new("CARGO")) {
        // If not, detect the scenario where cargo is configured to wrap rustc with something other than sccache.
        // This happens when sccache is used as a `RUSTC_WRAPPER` and another tool is used as a
        // `RUSTC_WORKSPACE_WRAPPER`. In that case rustc will be the first argument rather than the command.
        //
        // The check for the `CARGO` env acts as a guardrail against false positives.
        // https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-reads
        args.iter()
            .next()
            .filter(|arg1| is_rustc_like(arg1))
            .map(PathBuf::from)
    } else {
        None
    };

    let pool = pool.clone();

    let rustc_executable = if let Some(ref rustc_executable) = maybe_rustc_executable {
        rustc_executable
    } else if is_nvidia_cudafe(executable) {
        debug!("Found cudafe++");
        return CCompiler::new(
            CudaFE {
                // TODO: Use nvcc --version
                version: Some(String::new()),
            },
            executable.to_owned(),
            &pool,
            &discovery,
        )
        .await
        .map(|c| (Box::new(c) as Box<dyn Compiler<T>>, None));
    } else if is_nvidia_cicc(executable) {
        debug!("Found cicc");
        return CCompiler::new(
            Cicc {
                // TODO: Use nvcc --version
                version: Some(String::new()),
            },
            executable.to_owned(),
            &pool,
            &discovery,
        )
        .await
        .map(|c| (Box::new(c) as Box<dyn Compiler<T>>, None));
    } else if is_nvidia_ptxas(executable) {
        debug!("Found ptxas");
        return CCompiler::new(
            Ptxas {
                // TODO: Use nvcc --version
                version: Some(String::new()),
            },
            executable.to_owned(),
            &pool,
            &discovery,
        )
        .await
        .map(|c| (Box::new(c) as Box<dyn Compiler<T>>, None));
    } else if is_known_c_compiler(executable) {
        let cc = detect_c_compiler(
            creator,
            executable,
            args,
            cwd,
            env.to_vec(),
            pool,
            &discovery,
        )
        .await;
        return cc.map(|c| (c, None));
    } else {
        // Even if it does not look like rustc like it might still be rustc driver
        // so we do full check
        executable
    };

    match resolve_rust_compiler(
        creator.clone(),
        executable,
        rustc_executable.to_path_buf(),
        env,
        cwd.to_path_buf(),
        discovery.clone(),
        pool.clone(),
    )
    .await
    {
        Ok(res) => Ok(res),
        Err(e) => {
            // in case we attempted to test for rustc while it didn't look like it, fallback to c compiler detection one lat time
            if maybe_rustc_executable.is_none() {
                let executable = executable.to_path_buf();
                let cc = detect_c_compiler(
                    creator,
                    executable,
                    args,
                    cwd,
                    env.to_vec(),
                    pool,
                    &discovery,
                )
                .await;
                cc.map(|c| (c, None))
            } else {
                Err(e)
            }
        }
    }
}

/// Tries to verify that provided executable is really rust compiler
/// or rust driver
async fn resolve_rust_compiler<T>(
    creator: T,
    executable: &Path,
    rustc_executable: PathBuf,
    env: &[(OsString, OsString)],
    cwd: PathBuf,
    discovery: CompilerDiscovery,
    pool: tokio::runtime::Handle,
) -> Result<(Box<dyn Compiler<T>>, Option<Box<dyn CompilerProxy<T>>>)>
where
    T: CommandCreatorSync,
{
    let mut child = creator.clone().new_command_sync(executable);
    // We're wrapping rustc if the executable doesn't match the detected rustc_executable. In this case the wrapper
    // expects rustc as the first argument.
    if rustc_executable != executable {
        child.arg(&rustc_executable);
    }

    child.env_clear().envs(env.to_vec()).args(&["-vV"]);

    let rustc_vv = run_input_output(child, None).await.map(|output| {
        if let Ok(stdout) = String::from_utf8(output.stdout.clone())
            && stdout.starts_with("rustc ")
        {
            return Ok(stdout);
        }
        Err(ProcessError(output))
    })?;

    // rustc -vV verification status
    match rustc_vv {
        Ok(rustc_verbose_version) => {
            let rustc_executable2 = rustc_executable.clone();

            let proxy = RustupProxy::find_proxy_executable::<T>(
                &rustc_executable2,
                "rustup",
                creator.clone(),
                env,
            );
            let creator1 = creator.clone();
            let res = proxy.and_then(move |proxy| async move {
                match proxy {
                    Ok(Some(proxy)) => {
                        trace!("Found rustup proxy executable");
                        // take the pathbuf for rustc as resolved by the proxy
                        match proxy.resolve_proxied_executable(creator1, cwd, env).await {
                            Ok((resolved_path, _time)) => {
                                trace!(
                                    "Resolved path with rustup proxy {}",
                                    crate::util::debug_display(&resolved_path)
                                );
                                Ok((Some(proxy), resolved_path))
                            }
                            Err(e) => {
                                trace!("Could not resolve compiler with rustup proxy: {e}");
                                Ok((None, rustc_executable))
                            }
                        }
                    }
                    Ok(None) => {
                        trace!("Did not find rustup");
                        Ok((None, rustc_executable))
                    }
                    Err(e) => {
                        trace!("Did not find rustup due to {e}, compiling without proxy");
                        Ok((None, rustc_executable))
                    }
                }
            });

            let (proxy, resolved_rustc) = res.await.map_or_else(
                |_e| {
                    trace!("Compiling rust without proxy");
                    (None, rustc_executable2)
                },
                |(proxy, resolved_compiler_executable)| {
                    (
                        proxy
                            .map(Box::new)
                            .map(|x: Box<RustupProxy>| x as Box<dyn CompilerProxy<T>>),
                        resolved_compiler_executable,
                    )
                },
            );

            debug!(
                "Using rustc at path: {}",
                crate::util::debug_display(&resolved_rustc)
            );

            Rust::new(
                creator,
                resolved_rustc,
                env,
                &rustc_verbose_version,
                discovery,
                pool,
            )
            .await
            .map(|c| {
                (
                    Box::new(c) as Box<dyn Compiler<T>>,
                    proxy as Option<Box<dyn CompilerProxy<T>>>,
                )
            })
        }
        Err(e) => Err(e).context("Failed to launch subprocess for compiler determination"),
    }
}

ArgData! {
    PassThrough(OsString),
}
use self::ArgData::PassThrough as Detect_PassThrough;

// Establish a set of compiler flags that are required for
// valid execution of the compiler even in preprocessor mode.
// If the requested compiler invocatiomn has any of these arguments
// propagate them when doing our compiler vendor detection
//
// Current known required flags:
// ccbin/compiler-bindir needed for nvcc
//  This flag specifies the host compiler to use otherwise
//  gcc is expected to exist on the PATH. So if gcc doesn't exist
//  compiler detection fails if we don't pass along the ccbin arg
counted_array!(static ARGS: [ArgInfo<ArgData>; _] = [
    take_arg!("--compiler-bindir", OsString, CanBeSeparated(b'='), Detect_PassThrough),
    take_arg!("-ccbin", OsString, CanBeSeparated(b'='), Detect_PassThrough),
]);

/// Ask `executable` for the version of the assembler it would run.
///
/// Going through the compiler rather than looking for `as` ourselves means the
/// answer accounts for the search paths the compiler was built with.
async fn assembler_version<T>(
    creator: &T,
    executable: &Path,
    extra_args: &[&str],
    env: &[(OsString, OsString)],
) -> Option<String>
where
    T: CommandCreatorSync,
{
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(env.iter().map(|s| (&s.0, &s.1)))
        .args(extra_args)
        .arg("-Wa,--version")
        // Empty input from stdin and the object to stdout, so that asking for a
        // version leaves nothing behind. The assembler prints its version and
        // exits without assembling, so the object never materializes.
        .arg("-x")
        .arg("assembler")
        .arg("-c")
        .arg("-")
        .arg("-o")
        .arg("-");
    trace!("assembler_version: {cmd:?}");
    let output = cmd.spawn().await.ok()?.wait_with_output().await.ok()?;

    if !output.status.success() {
        debug!(
            "Failed to get the assembler version: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    // The rest of what `--version` prints is copyright boilerplate.
    let version = str::from_utf8(&output.stdout)
        .ok()?
        .lines()
        .next()?
        .trim()
        .to_owned();
    if version.is_empty() {
        return None;
    }
    Some(version)
}

/// Ask `executable` where the assembler it would run lives.
async fn assembler_path<T>(
    creator: &T,
    executable: &Path,
    extra_args: &[&str],
    cwd: &Path,
    env: &[(OsString, OsString)],
) -> Option<PathBuf>
where
    T: CommandCreatorSync,
{
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(env.iter().map(|s| (&s.0, &s.1)))
        .args(extra_args)
        .arg("-print-prog-name=as");
    trace!("assembler_path: {cmd:?}");
    let output = cmd.spawn().await.ok()?.wait_with_output().await.ok()?;

    if !output.status.success() {
        return None;
    }
    let name = str::from_utf8(&output.stdout).ok()?.trim();
    if name.is_empty() {
        return None;
    }
    // GCC answers with a bare name when it leaves finding the assembler to
    // $PATH, and clang does the same when there is nothing to find, so finish
    // the search the way the compiler will: against the client's $PATH.
    let paths = env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.clone())
        .or_else(|| env::var_os("PATH"));
    which::which_in(name, paths, cwd).ok()
}

/// Identify the assembler `executable` hands the compilation off to.
///
/// GCC never assembles by itself, and clang doesn't either when its integrated
/// assembler is disabled, so without this the object file depends on a program
/// that nothing in the cache key accounts for. The assembler gets identified the
/// same way the compiler is, by both its contents and the version it reports:
/// the contents catch a rebuild that didn't bump the version, the version speaks
/// for wrappers like Apple's `as`, where the binary we find isn't what ends up
/// doing the work.
async fn detect_assembler<T>(
    creator: &T,
    executable: &Path,
    extra_args: &[&str],
    cwd: &Path,
    env: &[(OsString, OsString)],
    pool: &tokio::runtime::Handle,
    discovery: &CompilerDiscovery,
) -> Option<String>
where
    T: CommandCreatorSync,
{
    let version = assembler_version(creator, executable, extra_args, env).await;
    let path = assembler_path(creator, executable, extra_args, cwd, env).await;
    let contents = match &path {
        Some(path) => discovery
            .hash_toolchain_file(path, pool)
            .await
            .map_err(|e| debug!("Failed to hash assembler {}: {e}", path.display()))
            .ok(),
        None => None,
    };
    if version.is_none() && contents.is_none() {
        return None;
    }
    debug!("Found assembler {version:?} at {path:?}");

    let mut m = Digest::new();
    m.update(version.unwrap_or_default().as_bytes());
    m.update(contents.unwrap_or_default().as_bytes());
    Some(m.finish())
}

#[expect(
    clippy::too_many_lines,
    reason = "compiler detection is an ordered probe sequence; keeping priority and fallback rules contiguous prevents accidental reordering"
)]
async fn detect_c_compiler<T, P>(
    creator: T,
    executable: P,
    arguments: &[OsString],
    cwd: &Path,
    env: Vec<(OsString, OsString)>,
    pool: tokio::runtime::Handle,
    discovery: &CompilerDiscovery,
) -> Result<Box<dyn Compiler<T>>>
where
    T: CommandCreatorSync,
    P: AsRef<Path>,
{
    trace!("detect_c_compiler");

    // NVCC needs to be first as msvc, clang, or gcc could
    // be the underlying host compiler for nvcc
    // Both clang and clang-cl define _MSC_VER on Windows, so we first
    // check for MSVC, then check whether _MT is defined, which is the
    // difference between clang and clang-cl.
    // NVHPC needs a custom version line since `__VERSION__` evaluates
    // to the EDG version.
    //
    // We prefix the information we need with `compiler_id` and `compiler_version`
    // so that we can support compilers that insert pre-amble code even in `-E` mode
    let test = b"
#if defined(__NVCC__) && defined(__NVCOMPILER)
compiler_id=nvcc-nvhpc
compiler_version=__CUDACC_VER_MAJOR__.__CUDACC_VER_MINOR__.__CUDACC_VER_BUILD__
#elif defined(__NVCC__) && defined(_MSC_VER)
compiler_id=nvcc-msvc
compiler_version=__CUDACC_VER_MAJOR__.__CUDACC_VER_MINOR__.__CUDACC_VER_BUILD__
#elif defined(__NVCC__)
compiler_id=nvcc
compiler_version=__CUDACC_VER_MAJOR__.__CUDACC_VER_MINOR__.__CUDACC_VER_BUILD__
#elif defined(_MSC_VER) && !defined(__clang__)
compiler_id=msvc
#elif defined(_MSC_VER) && defined(_MT)
compiler_id=msvc-clang
#elif defined(__NVCOMPILER)
compiler_id=nvhpc
compiler_version=__NVCOMPILER_MAJOR__.__NVCOMPILER_MINOR__.__NVCOMPILER_PATCHLEVEL__
#elif defined(__clang__) && defined(__cplusplus) && defined(__apple_build_version__)
compiler_id=apple-clang++
#elif defined(__clang__) && defined(__cplusplus)
compiler_id=clang++
#elif defined(__clang__) && defined(__apple_build_version__)
compiler_id=apple-clang
#elif defined(__clang__)
compiler_id=clang
#elif defined(__GNUC__) && defined(__cplusplus)
compiler_id=g++
#elif defined(__GNUC__)
compiler_id=gcc
#elif defined(__DCC__)
compiler_id=diab
#elif defined(__CTC__)
compiler_id=tasking_vx
#else
compiler_id=unknown
#endif
compiler_version=__VERSION__
"
    .to_vec();
    let (tempdir, src) = write_temp_file(&pool, "testfile.c".as_ref(), test).await?;

    // Resolve compiler avoiding ccache wrappers to prevent double-caching.
    let executable = executable.as_ref();
    let resolved_executable = resolve_compiler_avoiding_wrapper(executable, &env);

    let mut cmd = creator.clone().new_command_sync(&resolved_executable);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(env.iter().map(|s| (&s.0, &s.1)));

    // Iterate over all the arguments for compilation and extract
    // any that are required for any valid execution of the compiler.
    // Allowing our compiler vendor detection to always properly execute
    for arg in ArgsIter::new(arguments.iter().cloned(), &ARGS[..]) {
        let arg = arg.unwrap_or_else(|_| Argument::Raw(OsString::from("")));
        if let Some(Detect_PassThrough(_)) = arg.get_data() {
            let required_arg = arg.normalize(NormalizedDisposition::Concatenated);
            cmd.args(&required_arg.iter_os_strings().collect_vec());
        }
    }

    cmd.arg("-E").arg(src);
    trace!("compiler {cmd:?}");
    let child = cmd.spawn().await?;
    let output = child
        .wait_with_output()
        .await
        .context("failed to read child output")?;

    drop(tempdir);

    let Ok(stdout) = str::from_utf8(&output.stdout) else {
        bail!("Failed to parse output")
    };
    let mut lines = stdout.lines().filter_map(|line| {
        let line = line.trim();
        line.strip_prefix("compiler_id=")
            .or_else(|| line.strip_prefix("compiler_version="))
    });
    if let Some(kind) = lines.next() {
        let executable = resolved_executable;
        let version = lines
            .next()
            // In case the compiler didn't expand the macro.
            .filter(|&line| line != "__VERSION__")
            .map(str::to_owned);
        match kind {
            "clang" | "clang++" | "apple-clang" | "apple-clang++" => {
                debug!("Found {kind}");
                let assembler_digest = detect_assembler(
                    &creator,
                    &executable,
                    &["-fno-integrated-as"],
                    cwd,
                    &env,
                    &pool,
                    discovery,
                )
                .await;
                return CCompiler::new(
                    Clang {
                        clangplusplus: kind.ends_with("++"),
                        is_appleclang: kind.starts_with("apple-"),
                        version: version.clone(),
                        assembler_digest,
                    },
                    executable,
                    &pool,
                    discovery,
                )
                .await
                .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            "diab" => {
                debug!("Found diab");
                return CCompiler::new(
                    Diab {
                        version: version.clone(),
                    },
                    executable,
                    &pool,
                    discovery,
                )
                .await
                .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            "gcc" | "g++" => {
                debug!("Found {kind}");
                let assembler_digest =
                    detect_assembler(&creator, &executable, &[], cwd, &env, &pool, discovery).await;
                return CCompiler::new(
                    Gcc {
                        gplusplus: kind == "g++",
                        version: version.clone(),
                        assembler_digest,
                    },
                    executable,
                    &pool,
                    discovery,
                )
                .await
                .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            "msvc" | "msvc-clang" => {
                let is_clang = kind == "msvc-clang";
                debug!("Found MSVC (is clang: {is_clang})");
                let prefix = msvc::detect_showincludes_prefix(
                    &creator,
                    executable.as_ref(),
                    is_clang,
                    env,
                    &pool,
                )
                .await?;
                trace!("showIncludes prefix: '{prefix}'");

                return CCompiler::new(
                    Msvc {
                        includes_prefix: prefix,
                        is_clang,
                        version: version.clone(),
                    },
                    executable,
                    &pool,
                    discovery,
                )
                .await
                .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            "nvcc" | "nvcc-msvc" | "nvcc-nvhpc" => {
                let host_compiler = match kind {
                    "nvcc-nvhpc" => NvccHostCompiler::Nvhpc,
                    "nvcc-msvc" => NvccHostCompiler::Msvc,
                    "nvcc" | &_ => NvccHostCompiler::Gcc,
                };
                let host_compiler_version = lines
                    .next()
                    // In case the compiler didn't expand the macro.
                    .filter(|&line| line != "__VERSION__")
                    .map(str::to_owned);

                return CCompiler::new(
                    Nvcc {
                        host_compiler,
                        host_compiler_version,
                        version,
                    },
                    executable,
                    &pool,
                    discovery,
                )
                .await
                .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            "nvhpc" => {
                debug!("Found NVHPC");
                return CCompiler::new(
                    Nvhpc {
                        nvcplusplus: kind == "nvc++",
                        version: version.clone(),
                    },
                    executable,
                    &pool,
                    discovery,
                )
                .await
                .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            "tasking_vx" => {
                debug!("Found Tasking VX");
                return CCompiler::new(TaskingVX, executable, &pool, discovery)
                    .await
                    .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            _ => (),
        }
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    debug!("nothing useful in detection output {stdout:?}");
    debug!("compiler status: {}", output.status);
    debug!("compiler stderr:\n{stderr}");

    bail!(stderr.into_owned())
}

/// If `executable` is a known compiler, return a `Box<Compiler>` containing information about it.
pub async fn get_compiler_info<T>(
    creator: T,
    executable: &Path,
    cwd: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
    pool: &tokio::runtime::Handle,
    discovery: CompilerDiscovery,
) -> Result<(Box<dyn Compiler<T>>, Option<Box<dyn CompilerProxy<T>>>)>
where
    T: CommandCreatorSync,
{
    let pool = pool.clone();
    detect_compiler(creator, executable, cwd, args, env, &pool, discovery).await
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mock_command::*;
    use crate::test::mock_storage::MockStorage;
    use crate::test::utils::*;
    use std::sync::Arc;
    use test_case::test_case;

    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    #[test]
    fn native_toolchain_digest_matches_legacy_encoding() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let library = dir.path().join("library.so");
        fs::write(&library, b"library contents")?;
        let alias = dir.path().join("libalias.so");
        std::os::unix::fs::symlink(&library, &alias)?;
        let files = vec![library.clone(), alias];
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let discovery = CompilerDiscovery {
            dist_archive: None,
            native_digests: Some(Arc::new(crate::build_runtime::SourceDigestCache::default())),
        };
        for contents in [
            b"library contents".as_slice(),
            b"changed contents".as_slice(),
        ] {
            fs::write(&library, contents)?;
            let original = runtime.block_on(crate::util::hash_all(&files, pool))?;
            let native = runtime.block_on(discovery.hash_toolchain_files(&files, pool))?;
            assert_eq!(native, original);
        }
        Ok(())
    }

    #[test]
    fn test_c_preprocessing_consistent() -> Result<()> {
        // Must contain all possible values from `Language`.
        // Cannot use `enum_iterator` because it adds macro to the real enum,
        // and we don't want to add additional dependencies.
        let languages = vec![
            Language::AssemblerToPreprocess,
            Language::Assembler,
            Language::C,
            Language::Cxx,
            Language::GenericHeader,
            Language::CHeader,
            Language::CPreprocessed,
            Language::CxxHeader,
            Language::CxxPreprocessed,
            Language::ObjectiveC,
            Language::ObjectiveCHeader,
            Language::ObjectiveCPreprocessed,
            Language::ObjectiveCxx,
            Language::ObjectiveCxxPreprocessed,
            Language::ObjectiveCxxHeader,
            Language::Cuda,
            Language::CudaFE,
            Language::Ptx,
            Language::Cubin,
            Language::Rust,
            Language::Hip,
        ];

        assert_eq!(
            languages.len(),
            EXPECTED_LANGUAGE_COUNT,
            "update the list of supported languages"
        );

        for lang in languages {
            let maybe_processed = lang.to_c_preprocessed_language();

            if let Some(processed) = maybe_processed {
                assert!(
                    !processed.needs_c_preprocessing(),
                    "{processed:?} should not need preprocessing - it is a result of {lang:?} processing"
                );
            }

            if !lang.needs_c_preprocessing() {
                assert!(
                    maybe_processed.is_none(),
                    "{lang:?} should not be processed, but it produces the {maybe_processed:?} as a C preprocessing result"
                );

                assert!(
                    !lang.is_c_like_header(),
                    "{lang:?} should not be processed, but it is a C-like header and can be used as preprocessor input"
                );
            }
        }
        Ok(())
    }

    #[test_case("gcc: error: unrecognized command-line option '-vV'; did you mean '-v'?", "\n\ncompiler_id=gcc", CCompilerKind::Gcc, true; "gcc")]
    #[test_case("clang: error: unknown argument: '-vV'", "compiler_id=clang\n", CCompilerKind::Clang, true; "clang")]
    #[test_case("no -vV", "compiler_id=nvcc\n", CCompilerKind::Nvcc, false; "nvcc")]
    #[test_case("no -vV", "compiler_id=nvhpc\n", CCompilerKind::Nvhpc, false; "nvhpc")]
    #[test_case("no -vV", "\ncompiler_id=diab\n", CCompilerKind::Diab, false; "diab")]
    fn test_detect_c_kind(
        stderr: &str,
        probe: &str,
        expected: CCompilerKind,
        assembler: bool,
    ) -> Result<()> {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", stderr)));
        next_command(&creator, Ok(MockChild::new(exit_status(0), probe, "")));
        if assembler {
            next_assembler(&creator, "GNU assembler (GNU Binutils) 2.42", "");
        }
        let c = detect_compiler(
            creator,
            &f.bins[0],
            f.tempdir.path(),
            &[],
            &[],
            runtime.handle(),
            CompilerDiscovery::default(),
        )
        .wait()?
        .0;
        assert_eq!(CompilerKind::C(expected), c.kind());
        Ok(())
    }

    #[test]
    fn test_detect_compiler_assembler_probes() -> Result<()> {
        let f = TestFixture::new();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        for (kind, integrated_as) in [("gcc", false), ("clang", true)] {
            let compiler = f.mk_bin(kind)?;
            let creator = new_creator();
            next_command(
                &creator,
                Ok(MockChild::new(
                    exit_status(0),
                    format!("compiler_id={kind}"),
                    "",
                )),
            );
            for (probe, output) in [
                ("-Wa,--version", "GNU assembler (GNU Binutils) 2.42"),
                ("-print-prog-name=as", "as"),
            ] {
                next_command_calls(&creator, move |args| {
                    assert!(args.iter().any(|arg| arg == probe), "{args:?}");
                    // Clang answers for its own integrated assembler unless that
                    // one is turned off; gcc has none to turn off.
                    assert_eq!(
                        integrated_as,
                        args.iter().any(|arg| arg == "-fno-integrated-as"),
                        "{args:?}"
                    );
                    Ok(MockChild::new(exit_status(0), output, ""))
                });
            }
            detect_compiler(
                creator,
                &compiler,
                f.tempdir.path(),
                &[],
                &[],
                pool,
                CompilerDiscovery::default(),
            )
            .wait()?;
        }
        Ok(())
    }

    #[test]
    fn test_detect_compiler_must_be_clang() -> Result<()> {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let clang = f.mk_bin("clang")?;
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=clang\n", "")),
        );
        next_assembler(&creator, "GNU assembler (GNU Binutils) 2.42", "");
        let c = detect_compiler(
            creator,
            &clang,
            f.tempdir.path(),
            &[],
            &[],
            pool,
            CompilerDiscovery::default(),
        )
        .wait()?
        .0;
        assert_eq!(CompilerKind::C(CCompilerKind::Clang), c.kind());
        Ok(())
    }

    #[test]
    fn test_detect_compiler_vv_clang() -> Result<()> {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "clang: 13\n", "")),
        );
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=clang\n", "")),
        );
        next_assembler(&creator, "GNU assembler (GNU Binutils) 2.42", "");
        let c = detect_compiler(
            creator,
            &f.bins[0],
            f.tempdir.path(),
            &[],
            &[],
            pool,
            CompilerDiscovery::default(),
        )
        .wait()?
        .0;
        assert_eq!(CompilerKind::C(CCompilerKind::Clang), c.kind());
        Ok(())
    }

    #[test]
    fn test_detect_compiler_kind_msvc() -> Result<()> {
        drop(env_logger::try_init());
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let f = TestFixture::new();
        let srcfile = f.touch("test.h")?;
        let mut s = srcfile
            .to_str()
            .ok_or_else(|| anyhow!("test header path is not UTF-8"))?;
        if s.starts_with("\\\\?\\") {
            s = &s[4..];
        }
        let prefix = String::from("blah: ");
        let stderr = format!("{prefix}{s}\r\n");
        // Compiler detection output
        next_command(
            &creator,
            Ok(MockChild::new(
                exit_status(1),
                "",
                "msvc-error: unknown argument: '-vV'",
            )),
        );
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "\ncompiler_id=msvc\n", "")),
        );
        // showincludes prefix detection output
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), String::new(), stderr)),
        );
        let c = detect_compiler(
            creator,
            &f.bins[0],
            f.tempdir.path(),
            &[],
            &[],
            pool,
            CompilerDiscovery::default(),
        )
        .wait()?
        .0;
        assert_eq!(CompilerKind::C(CCompilerKind::Msvc), c.kind());
        Ok(())
    }

    #[test]
    fn test_detect_compiler_kind_rustc() -> Result<()> {
        let f = TestFixture::new();
        // Windows uses bin, everything else uses lib. Just create both.
        fs::create_dir(f.tempdir.path().join("lib"))?;
        fs::create_dir(f.tempdir.path().join("bin"))?;
        let rustc = f.mk_bin("rustc.exe")?;
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        populate_rustc_command_mock(&creator, &f)?;
        let c = detect_compiler(
            creator,
            &rustc,
            f.tempdir.path(),
            &[],
            &[],
            pool,
            CompilerDiscovery::default(),
        )
        .wait()?
        .0;
        assert_eq!(CompilerKind::Rust, c.kind());
        Ok(())
    }

    #[test]
    fn test_is_rustc_like() -> Result<()> {
        assert!(is_rustc_like("rustc"));
        assert!(is_rustc_like("rustc.exe"));
        assert!(is_rustc_like("/path/to/rustc.exe"));
        assert!(is_rustc_like("/path/to/rustc"));
        assert!(is_rustc_like("/PATH/TO/RUSTC.EXE"));
        assert!(is_rustc_like("/Path/To/RustC.Exe"));
        assert!(is_rustc_like("/path/to/clippy-driver"));
        assert!(is_rustc_like("/path/to/clippy-driver.exe"));
        assert!(is_rustc_like("/PATH/TO/CLIPPY-DRIVER.EXE"));
        assert!(is_rustc_like("/Path/To/Clippy-Driver.Exe"));
        assert!(!is_rustc_like("rust"));
        assert!(!is_rustc_like("RUST"));
        Ok(())
    }

    fn populate_rustc_command_mock(
        creator: &Arc<std::sync::Mutex<MockCommandCreator>>,
        f: &TestFixture,
    ) -> Result<()> {
        // rustc --vV
        next_command(
            creator,
            Ok(MockChild::new(
                exit_status(0),
                "\
rustc 1.27.0 (3eda71b00 2018-06-19)
binary: rustc
commit-hash: 3eda71b00ad48d7bf4eef4c443e7f611fd061418
commit-date: 2018-06-19
host: x86_64-unknown-linux-gnu
release: 1.27.0
LLVM version: 6.0",
                "",
            )),
        );
        // rustc --print=sysroot
        let sysroot = f
            .tempdir
            .path()
            .to_str()
            .ok_or_else(|| anyhow!("temporary rustc sysroot path is not UTF-8"))?;
        next_command(creator, Ok(MockChild::new(exit_status(0), sysroot, "")));
        next_command(creator, Ok(MockChild::new(exit_status(0), sysroot, "")));
        next_command(creator, Ok(MockChild::new(exit_status(0), sysroot, "")));
        Ok(())
    }

    #[test]
    fn test_detect_compiler_kind_rustc_workspace_wrapper() -> Result<()> {
        let f = TestFixture::new();
        // Windows uses bin, everything else uses lib. Just create both.
        fs::create_dir(f.tempdir.path().join("lib"))?;
        fs::create_dir(f.tempdir.path().join("bin"))?;
        let rustc = f.mk_bin("rustc-workspace-wrapper")?;
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        populate_rustc_command_mock(&creator, &f)?;
        let c = detect_compiler(
            creator,
            &rustc,
            f.tempdir.path(),
            // Specifying an extension tests the ignoring
            &[OsString::from("rustc.exe")],
            &[(OsString::from("CARGO"), OsString::from("CARGO"))],
            pool,
            CompilerDiscovery::default(),
        )
        .wait()?
        .0;
        assert_eq!(CompilerKind::Rust, c.kind());

        // Test we don't detect rustc if the first arg is not rustc
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "no -vV")));
        populate_rustc_command_mock(&creator, &f)?;
        assert!(
            detect_compiler(
                creator,
                &rustc,
                f.tempdir.path(),
                &[OsString::from("not-rustc")],
                &[(OsString::from("CARGO"), OsString::from("CARGO"))],
                pool,
                CompilerDiscovery::default(),
            )
            .wait()
            .is_err()
        );

        // Test we detect rustc if the CARGO env is not defined
        let creator = new_creator();
        populate_rustc_command_mock(&creator, &f)?;
        assert!(
            detect_compiler(
                creator,
                &rustc,
                f.tempdir.path(),
                &[OsString::from("rustc")],
                &[],
                pool,
                CompilerDiscovery::default(),
            )
            .wait()
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn test_detect_compiler_kind_unknown() -> Result<()> {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "no -vV")));
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "something", "")),
        );
        assert!(
            detect_compiler(
                creator,
                "/foo/bar".as_ref(),
                f.tempdir.path(),
                &[],
                &[],
                pool,
                CompilerDiscovery::default()
            )
            .wait()
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn test_detect_compiler_kind_process_fail() -> Result<()> {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "no -vV")));
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        assert!(
            detect_compiler(
                creator,
                "/foo/bar".as_ref(),
                f.tempdir.path(),
                &[],
                &[],
                pool,
                CompilerDiscovery::default()
            )
            .wait()
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn test_compiler_version_affects_hash() -> Result<()> {
        let f = TestFixture::new();
        let clang = f.mk_bin("clang")?;
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let cwd = f.tempdir.path();
        // Write a dummy input file so the preprocessor cache mode can work
        std::fs::write(f.tempdir.path().join("foo.c"), "whatever")?;

        let results = [11, 12]
            .iter()
            .map(|version| -> Result<_> {
                let output = format!("compiler_id=clang\ncompiler_version=\"{version}.0.0\"");
                next_command(&creator, Ok(MockChild::new(exit_status(0), output, "")));
                next_assembler(&creator, "GNU assembler (GNU Binutils) 2.42", "");
                let c = detect_compiler(
                    creator.clone(),
                    &clang,
                    f.tempdir.path(),
                    &[],
                    &[],
                    pool,
                    CompilerDiscovery::default(),
                )
                .wait()?
                .0;
                next_command(
                    &creator,
                    Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
                );
                let mut hasher = match c.parse_arguments(
                    &arguments,
                    ".".as_ref(),
                    &[],
                    CompilerCachePolicy::FinishedArtifact,
                ) {
                    CompilerArguments::Ok(h) => h,
                    o => bail!("Bad result from parse_arguments: {o:?}"),
                };
                hasher
                    .generate_hash_key(GenerateHashKeyContext {
                        #[cfg(all(feature = "dist-client", target_os = "linux"))]
                        native: None,
                        creator: &creator,
                        cwd: cwd.to_path_buf(),
                        env_vars: vec![],
                        may_dist: false,
                        pool,
                        rewrite_includes_only: false,
                        storage: Arc::new(MockStorage::new()),
                        cache_control: CacheControl::Default,
                    })
                    .wait()
            })
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(results.len(), 2);
        assert_ne!(results[0].key, results[1].key);
        Ok(())
    }

    #[test]
    fn test_assembler_affects_hash() -> Result<()> {
        let f = TestFixture::new();
        let clang = f.mk_bin("clang")?;
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let cwd = f.tempdir.path();
        // Write a dummy input file so the preprocessor cache mode can work
        std::fs::write(f.tempdir.path().join("foo.c"), "whatever")?;

        let key = |version: &str, path: &str, arguments: &[OsString]| -> Result<_> {
            next_command(
                &creator,
                Ok(MockChild::new(
                    exit_status(0),
                    "compiler_id=clang\ncompiler_version=\"16.0.0\"",
                    "",
                )),
            );
            next_assembler(&creator, version, path);
            let c = detect_compiler(
                creator.clone(),
                &clang,
                f.tempdir.path(),
                &[],
                &[],
                pool,
                CompilerDiscovery::default(),
            )
            .wait()?
            .0;
            next_command(
                &creator,
                Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
            );
            let mut hasher = match c.parse_arguments(
                arguments,
                ".".as_ref(),
                &[],
                CompilerCachePolicy::FinishedArtifact,
            ) {
                CompilerArguments::Ok(h) => h,
                o => bail!("Bad result from parse_arguments: {o:?}"),
            };
            Ok(hasher
                .generate_hash_key(GenerateHashKeyContext {
                    #[cfg(all(feature = "dist-client", target_os = "linux"))]
                    native: None,
                    creator: &creator,
                    cwd: cwd.to_path_buf(),
                    env_vars: vec![],
                    may_dist: false,
                    pool,
                    rewrite_includes_only: false,
                    storage: Arc::new(MockStorage::new()),
                    cache_control: CacheControl::Default,
                })
                .wait()?
                .key)
        };

        // Two assemblers reporting the same version, one of them a rebuild.
        let mk_as = |name, contents: &'static str| -> Result<String> {
            let path = mk_bin_contents(f.tempdir.path(), name, |mut f| {
                f.write_all(contents.as_bytes())
            })?;
            Ok(path
                .to_str()
                .ok_or_else(|| anyhow!("assembler test path is not UTF-8"))?
                .to_owned())
        };
        let as1 = mk_as("as1", "assembler")?;
        let as2 = mk_as("as2", "assembler, rebuilt")?;
        let (as1, as2) = (as1.as_str(), as2.as_str());
        let version = "GNU assembler (GNU Binutils) 2.42";

        let external = ovec!["-c", "foo.c", "-o", "foo.o", "-fno-integrated-as"];
        assert_ne!(
            key(version, as1, &external)?,
            key("GNU assembler (GNU Binutils) 2.44", as1, &external)?
        );
        assert_ne!(key(version, as1, &external)?, key(version, as2, &external)?);

        // With the integrated assembler, which is the default, no external
        // assembler runs and none of this is our business.
        let integrated = ovec!["-c", "foo.c", "-o", "foo.o"];
        assert_eq!(
            key(version, as1, &integrated)?,
            key("GNU assembler (GNU Binutils) 2.44", as2, &integrated)?
        );
        Ok(())
    }

    #[test]
    fn test_assembler_incbin_payload_affects_hash() -> Result<()> {
        let f = TestFixture::new();
        let clang = f.mk_bin("clang")?;
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let cwd = f.tempdir.path();
        std::fs::write(cwd.join("foo.S"), ".incbin \"blob.bin\"\n")?;

        next_command(
            &creator,
            Ok(MockChild::new(
                exit_status(0),
                "compiler_id=clang\ncompiler_version=\"16.0.0\"",
                "",
            )),
        );
        next_assembler(&creator, "GNU assembler (GNU Binutils) 2.42", "");
        let compiler = detect_compiler(
            creator.clone(),
            &clang,
            cwd,
            &[],
            &[],
            pool,
            CompilerDiscovery::default(),
        )
        .wait()?
        .0;
        let arguments = ovec!["-c", "foo.S", "-o", "foo.o"];

        let key_for = |payload: &[u8]| -> Result<String> {
            std::fs::write(cwd.join("blob.bin"), payload)?;
            next_command(
                &creator,
                Ok(MockChild::new(exit_status(0), ".incbin \"blob.bin\"\n", "")),
            );
            let mut hasher = match compiler.parse_arguments(
                &arguments,
                cwd,
                &[],
                CompilerCachePolicy::FinishedArtifact,
            ) {
                CompilerArguments::Ok(hasher) => hasher,
                other => bail!("Bad result from parse_arguments: {other:?}"),
            };
            Ok(hasher
                .generate_hash_key(GenerateHashKeyContext {
                    #[cfg(all(feature = "dist-client", target_os = "linux"))]
                    native: None,
                    creator: &creator,
                    cwd: cwd.to_path_buf(),
                    env_vars: vec![],
                    may_dist: true,
                    pool,
                    rewrite_includes_only: false,
                    storage: Arc::new(MockStorage::new()),
                    cache_control: CacheControl::Default,
                })
                .wait()?
                .key)
        };

        let first = key_for(b"payload-one")?;
        let second = key_for(b"payload-two")?;
        assert_ne!(first, second);
        Ok(())
    }

    #[test_case("-fPIC", "-fno-pic", false; "common args")]
    #[test_case("-DHELLO", "-DHI", true; "preprocessor args")]
    fn test_argument_hash_equivalence(first: &str, second: &str, equivalent: bool) -> Result<()> {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let output = "compiler_id=clang\ncompiler_version=\"16.0.0\"";
        let arguments = [
            ovec!["-c", "foo.c", "-o", "foo.o", first],
            ovec!["-c", "foo.c", "-o", "foo.o", second],
            ovec!["-c", "foo.c", "-o", "foo.o"],
        ];
        let cwd = f.tempdir.path();
        // Write a dummy input file so the preprocessor cache mode can work
        std::fs::write(f.tempdir.path().join("foo.c"), "whatever")?;

        let results = arguments
            .iter()
            .map(|argument| -> Result<_> {
                next_command(
                    &creator,
                    Ok(MockChild::new(
                        exit_status(1),
                        "",
                        "clang: error: unknown argument: '-vV'",
                    )),
                );
                next_command(&creator, Ok(MockChild::new(exit_status(0), output, "")));
                next_assembler(&creator, "GNU assembler (GNU Binutils) 2.42", "");
                let c = detect_compiler(
                    creator.clone(),
                    &f.bins[0],
                    f.tempdir.path(),
                    &[],
                    &[],
                    pool,
                    CompilerDiscovery::default(),
                )
                .wait()?
                .0;
                next_command(
                    &creator,
                    Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
                );
                let mut hasher = match c.parse_arguments(
                    argument,
                    ".".as_ref(),
                    &[],
                    CompilerCachePolicy::FinishedArtifact,
                ) {
                    CompilerArguments::Ok(h) => h,
                    o => bail!("Bad result from parse_arguments: {o:?}"),
                };
                hasher
                    .generate_hash_key(GenerateHashKeyContext {
                        #[cfg(all(feature = "dist-client", target_os = "linux"))]
                        native: None,
                        creator: &creator,
                        cwd: cwd.to_path_buf(),
                        env_vars: vec![],
                        may_dist: false,
                        pool,
                        rewrite_includes_only: false,
                        storage: Arc::new(MockStorage::new()),
                        cache_control: CacheControl::Default,
                    })
                    .wait()
            })
            .collect::<Result<Vec<_>>>()?;

        assert_eq!(results.len(), 3);
        for (left, right) in [(0, 1), (1, 2), (0, 2)] {
            assert_eq!(results[left].key == results[right].key, equivalent);
        }
        Ok(())
    }

    #[test]
    fn test_preprocessed_file_works_without_preprocessor_call() -> Result<()> {
        let f = TestFixture::new();
        let clang = f.mk_bin("clang")?;
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let output = "compiler_id=clang\ncompiler_version=\"16.0.0\"";
        let cwd = f.tempdir.path();

        let results = ["foo.c", "foo.i"]
            .iter()
            .map(|file| -> Result<_> {
                let arguments = ovec!["-c", file, "-o", "foo.o"];

                // Write a dummy input file so the preprocessor cache mode can work
                std::fs::write(f.tempdir.path().join(file), "int foo(void) { return 0; }")?;

                next_command(&creator, Ok(MockChild::new(exit_status(0), output, "")));
                next_assembler(&creator, "GNU assembler (GNU Binutils) 2.42", "");
                let c = detect_compiler(
                    creator.clone(),
                    &clang,
                    f.tempdir.path(),
                    &[],
                    &[],
                    pool,
                    CompilerDiscovery::default(),
                )
                .wait()?
                .0;

                // Only run the preprocessor on the non-preprocessed file
                if !file.ends_with('i') {
                    next_command(
                        &creator,
                        Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
                    );
                }
                let mut hasher = match c.parse_arguments(
                    &arguments,
                    ".".as_ref(),
                    &[],
                    CompilerCachePolicy::FinishedArtifact,
                ) {
                    CompilerArguments::Ok(h) => h,
                    o => bail!("Bad result from parse_arguments: {o:?}"),
                };
                hasher
                    .generate_hash_key(GenerateHashKeyContext {
                        #[cfg(all(feature = "dist-client", target_os = "linux"))]
                        native: None,
                        creator: &creator,
                        cwd: cwd.to_path_buf(),
                        env_vars: vec![],
                        may_dist: false,
                        pool,
                        rewrite_includes_only: false,
                        storage: Arc::new(MockStorage::new()),
                        cache_control: CacheControl::Default,
                    })
                    .wait()
            })
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(results.len(), 2);
        assert_ne!(results[0].key, results[1].key);
        Ok(())
    }

    #[test]
    fn test_get_compiler_info() -> Result<()> {
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let f = TestFixture::new();
        // Pretend to be GCC.
        let gcc = f.mk_bin("gcc")?;
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=gcc", "")),
        );
        next_assembler(&creator, "GNU assembler (GNU Binutils) 2.42", "");
        let c = get_compiler_info(
            creator,
            &gcc,
            f.tempdir.path(),
            &[],
            &[],
            pool,
            CompilerDiscovery::default(),
        )
        .wait()?
        .0;
        // digest of an empty file.
        assert_eq!(CompilerKind::C(CCompilerKind::Gcc), c.kind());
        Ok(())
    }

    #[test]
    fn missing_native_configuration_never_starts_compiler() -> Result<()> {
        let creator = new_creator();
        let fixture = TestFixture::new();
        let gcc = fixture.mk_bin("gcc")?;
        let runtime = single_threaded_runtime();
        let pool = runtime.handle().clone();
        let cwd = fixture.tempdir.path();
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=gcc", "")),
        );
        next_assembler(&creator, "GNU assembler (GNU Binutils) 2.42", "");
        let compiler = get_compiler_info(
            creator.clone(),
            &gcc,
            cwd,
            &[],
            &[],
            &pool,
            CompilerDiscovery::default(),
        )
        .wait()?
        .0;
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let CompilerArguments::Ok(mut hasher) =
            compiler.parse_arguments(&arguments, cwd, &[], CompilerCachePolicy::Native)
        else {
            bail!("test compiler was not recognized");
        };
        let storage = Arc::new(MockStorage::new());
        let service = server::SccacheService::mock_with_storage(storage.clone(), pool.clone());
        // No compiler process is queued after discovery.
        let error = runtime
            .block_on(hasher.get_cached_or_compile(CacheCompileContext {
                service: &service,
                creator,
                storage,
                arguments,
                cwd: cwd.to_owned(),
                env_vars: vec![],
                cache_control: CacheControl::Default,
                pool,
            }))
            .expect_err("compile must require native configuration");
        assert!(format!("{error:#}").contains("Native"));
        assert!(!cwd.join("foo.o").exists());
        Ok(())
    }
}

#[cfg(all(test, feature = "dist-client"))]
mod native_environment_tests {
    use super::validate_dist_environment_dependencies;
    use crate::dist::CompileCommand;
    use crate::errors::Result;

    #[test]
    fn observed_environment_must_survive_native_planning() -> Result<()> {
        let mut command = CompileCommand {
            umask: Some(0o022),
            executable: "/automatic/rustc".into(),
            arguments: vec![],
            env_vars: vec![
                ("CARGO".into(), "/automatic/cargo".into()),
                ("EMPTY".into(), String::new()),
            ],
            cwd: "/build".into(),
        };
        let dependencies = [
            ("CARGO".into(), Some("/automatic/cargo".into())),
            ("EMPTY".into(), Some("".into())),
            ("MISSING".into(), None),
        ];
        validate_dist_environment_dependencies(&command, &dependencies)?;
        command.env_vars[0].1 = "/different/cargo".into();
        assert!(validate_dist_environment_dependencies(&command, &dependencies).is_err());
        command.env_vars[0].1 = "/automatic/cargo".into();
        command.env_vars.retain(|(key, _)| key != "EMPTY");
        assert!(validate_dist_environment_dependencies(&command, &dependencies).is_err());
        command.env_vars.push(("EMPTY".into(), "".into()));
        command.env_vars.push(("MISSING".into(), "".into()));
        assert!(validate_dist_environment_dependencies(&command, &dependencies).is_err());
        Ok(())
    }
}
