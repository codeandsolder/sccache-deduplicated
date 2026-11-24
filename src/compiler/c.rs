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
#[cfg(feature = "dist-client")]
use crate::compiler::DistPackagers;
use crate::compiler::preprocessor_cache::{
    PreprocessorCacheKey, preprocessor_cache_entry_hash_key,
};
use crate::compiler::{
    CCompileCommand, Cacheable, ColorMode, Compilation, CompileCommand, CompileCommandImpl,
    CompileTransport, Compiler, CompilerArguments, CompilerHasher, CompilerKind,
    GenerateHashKeyContext, HashResult, Language, SingleCompileCommand,
};
use crate::config::PreprocessorCacheModeConfig;
use crate::dist;
#[cfg(feature = "dist-client")]
use crate::dist::pkg;
use crate::mock_command::{CommandCreatorSync, RunCommand};
use crate::util::{
    Digest, MetadataCtimeExt, TimeMacroFinder, Timestamp, decode_path, encode_path, hash_all,
    run_input_output, strip_basedirs, strip_basedirs_from_arg,
};
use async_trait::async_trait;
use fs_err as fs;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::LazyLock;

use crate::errors::{Context, ProcessError, Result, bail};
use anyhow::ensure;

use super::CacheControl;
use super::canonical_native::NativeCargoPaths;
use super::preprocessor_cache::PreprocessorCacheEntry;

/// A generic implementation of the `Compiler` trait for C/C++ compilers.
#[derive(Clone)]
pub struct CCompiler<I>
where
    I: CCompilerImpl,
{
    executable: PathBuf,
    executable_digest: String,
    compiler: I,
}

/// A generic implementation of the `CompilerHasher` trait for C/C++ compilers.
#[derive(Debug, Clone)]
pub struct CCompilerHasher<I>
where
    I: CCompilerImpl,
{
    parsed_args: ParsedArguments,
    executable: PathBuf,
    executable_digest: String,
    compiler: I,
}

/// Artifact produced by a C/C++ compiler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactDescriptor {
    /// Path to the artifact.
    pub path: PathBuf,
    /// Whether the artifact is an optional object file.
    pub optional: bool,
}

/// The results of parsing a compiler commandline.
#[expect(
    clippy::struct_excessive_bools,
    reason = "parsed compiler flags are independent command-line facts; packing them would obscure names and parser state"
)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParsedArguments {
    /// The input source file.
    pub input: PathBuf,
    /// Whether to prepend the input with `--`
    pub double_dash_input: bool,
    /// The type of language used in the input source file.
    pub language: Language,
    /// The flag required to compile for the given language
    pub compilation_flag: OsString,
    /// The file in which to generate dependencies.
    pub depfile: Option<PathBuf>,
    /// Output files and whether it's optional, keyed by a simple name, like "obj".
    pub outputs: HashMap<&'static str, ArtifactDescriptor>,
    /// Commandline arguments for dependency generation.
    pub dependency_args: Vec<OsString>,
    /// Commandline arguments for the preprocessor (not including `common_args`).
    pub preprocessor_args: Vec<OsString>,
    /// Commandline arguments for the preprocessor or the compiler.
    pub common_args: Vec<OsString>,
    /// Commandline arguments for the compiler that specify the architecture given
    pub arch_args: Vec<OsString>,
    /// Commandline arguments for the preprocessor or the compiler that don't affect the computed hash.
    pub unhashed_args: Vec<OsString>,
    /// Extra unhashed files that need to be sent along with dist compiles.
    pub extra_dist_files: Vec<PathBuf>,
    /// Extra files that need to have their contents hashed.
    pub extra_hash_files: Vec<PathBuf>,
    /// Whether the compiler runs a separate assembler to produce the object file.
    pub uses_external_assembler: bool,
    /// Whether or not the `-showIncludes` argument is passed on MSVC
    pub msvc_show_includes: bool,
    /// Whether the MSVC input was given with `/Tc` or `/Tp`
    pub msvc_explicit_language: bool,
    /// Whether the compilation is generating profiling or coverage data.
    pub profile_generate: bool,
    /// The color mode.
    pub color_mode: ColorMode,
    /// arguments are incompatible with `rewrite_includes_only`
    pub suppress_rewrite_includes_only: bool,
    /// Arguments are incompatible with preprocessor cache mode
    pub too_hard_for_preprocessor_cache_mode: Option<OsString>,
}

#[cfg(test)]
impl ParsedArguments {
    pub(super) fn test_compile(input: &str, output: &str, language: Language) -> Self {
        Self {
            input: input.into(),
            double_dash_input: false,
            language,
            compilation_flag: "-c".into(),
            depfile: None,
            outputs: HashMap::from([(
                "obj",
                ArtifactDescriptor {
                    path: output.into(),
                    optional: false,
                },
            )]),
            dependency_args: vec![],
            preprocessor_args: vec![],
            common_args: vec![],
            arch_args: vec![],
            unhashed_args: vec![],
            extra_dist_files: vec![],
            extra_hash_files: vec![],
            uses_external_assembler: false,
            msvc_show_includes: false,
            msvc_explicit_language: false,
            profile_generate: false,
            color_mode: ColorMode::Auto,
            suppress_rewrite_includes_only: false,
            too_hard_for_preprocessor_cache_mode: None,
        }
    }
}

pub fn is_native_codegen_arg(arg: &OsStr) -> bool {
    matches!(
        arg.to_str(),
        Some("-march=native" | "-mcpu=native" | "-mtune=native")
    )
}

fn native_codegen_args(parsed_args: &ParsedArguments) -> Vec<OsString> {
    parsed_args
        .common_args
        .iter()
        .filter(|arg| is_native_codegen_arg(arg))
        .cloned()
        .collect()
}

/// Compiler-specific lowering of the final target state on the machine
/// that received the compile request, independent of its chosen worker.
#[derive(Debug, Clone)]
pub struct NativeCodegenResolution {
    fingerprint: String,
    #[cfg(feature = "dist-client")]
    /// Exact compiler-observed target state, not merely a CPU model name.
    /// Apply after the original non-native options so user overrides survive
    /// Clang's driver-to-cc1 argument reordering.
    explicit_args: Vec<OsString>,
}

impl NativeCodegenResolution {
    #[cfg(feature = "dist-client")]
    pub fn rewrite_arguments(&self, args: Vec<OsString>) -> Vec<OsString> {
        let mut resolved = args
            .into_iter()
            .filter(|arg| !is_native_codegen_arg(arg))
            .collect::<Vec<_>>();
        resolved.extend_from_slice(&self.explicit_args);
        resolved
    }
}

fn is_native_driver_frontend(arg: &str) -> bool {
    let executable = arg.rsplit(['/', '\\']).next().unwrap_or(arg);
    matches!(
        executable.strip_suffix(".exe").unwrap_or(executable),
        "-cc1" | "cc1" | "cc1plus" | "cc1obj" | "cc1objplus"
    )
}

fn native_driver_args(driver_line: &str) -> Result<Vec<String>> {
    let args = shlex::split(driver_line).context("unparseable compiler native expansion")?;
    if !args.iter().any(|arg| is_native_driver_frontend(arg)) {
        bail!("native probe did not identify GCC/Clang compiler frontend");
    }
    if args
        .iter()
        .any(|arg| arg == "native" || arg.ends_with("=native"))
    {
        bail!("compiler left native CPU selection unresolved");
    }
    Ok(args)
}

/// Lower the *whole effective target state*, including the caller's explicit
/// feature and tuning overrides. Per-switch expansion is not sufficient:
/// Clang forwards -Xclang feature settings after its ordinary -m switches,
/// even when those were placed earlier in the original command.
fn native_driver_replacement(
    driver_line: &str,
    kind: CCompilerKind,
    native_args: &[OsString],
) -> Result<Vec<OsString>> {
    let args = native_driver_args(driver_line)?;
    let mut flags = Vec::<OsString>::new();
    match kind {
        CCompilerKind::Gcc => {
            for (index, arg) in args.iter().enumerate() {
                if arg.starts_with("-m") {
                    flags.push(OsString::from(arg));
                } else if arg == "--param" {
                    let value = args
                        .get(index + 1)
                        .context("GCC native expansion had a dangling --param")?;
                    flags.push(OsString::from("--param"));
                    flags.push(OsString::from(value));
                }
            }
            if native_args.iter().any(|arg| arg == "-march=native")
                && !flags
                    .iter()
                    .any(|arg| arg.to_string_lossy().starts_with("-march="))
            {
                bail!("GCC native expansion did not resolve -march");
            }
            if native_args
                .iter()
                .any(|arg| arg == "-mtune=native" || arg == "-mcpu=native")
                && !flags
                    .iter()
                    .any(|arg| arg.to_string_lossy().starts_with("-mtune="))
            {
                bail!("GCC native expansion did not resolve tuning");
            }
        }
        CCompilerKind::Clang => {
            let cpu = args
                .windows(2)
                .find_map(|pair| (pair[0] == "-target-cpu").then_some(pair[1].as_str()))
                .context("Clang native expansion did not resolve the requested CPU")?;
            ensure!(
                !cpu.is_empty() && cpu != "native",
                "Clang native CPU model unresolved"
            );
            let cpu_option = if native_args.iter().any(|arg| arg == "-mcpu=native") {
                "-mcpu"
            } else {
                "-march"
            };
            flags.push(OsString::from(format!("{cpu_option}={cpu}")));
            if let Some(tune) = args
                .windows(2)
                .find_map(|pair| (pair[0] == "-tune-cpu").then_some(pair[1].as_str()))
            {
                ensure!(
                    !tune.is_empty() && tune != "native",
                    "Clang tune CPU unresolved"
                );
                flags.push(OsString::from(format!("-mtune={tune}")));
            }
            // cc1 target-feature overrides include VM-masked features and all
            // explicit -mno-* settings. Feed the final state to cc1 last.
            for pair in args.windows(2) {
                if pair[0] == "-target-feature" {
                    ensure!(
                        pair[1].starts_with('+') || pair[1].starts_with('-'),
                        "malformed Clang native feature {}",
                        pair[1]
                    );
                    flags.extend([
                        OsString::from("-Xclang"),
                        OsString::from("-target-feature"),
                        OsString::from("-Xclang"),
                        OsString::from(&pair[1]),
                    ]);
                }
            }
        }
        _ => bail!("unsupported compiler family for native CPU resolution: {kind:?}"),
    }
    Ok(flags)
}

/// The compiler driver must resolve the ISA in the *requested language*.
/// Probing C for C++ can change frontend options (or reject C++-only flags)
/// and then fingerprint a state different from the actual compilation.
/// For assembly/other modes with no C frontend, use a C frontend solely to
/// determine CPU codegen flags, not the syntax of the source.
const fn native_probe_language(language: Language) -> &'static str {
    match language {
        Language::Cxx | Language::CxxHeader | Language::CxxPreprocessed | Language::CxxModule => {
            "c++"
        }
        Language::ObjectiveCxx
        | Language::ObjectiveCxxHeader
        | Language::ObjectiveCxxPreprocessed => "objective-c++",
        Language::ObjectiveC | Language::ObjectiveCHeader | Language::ObjectiveCPreprocessed => {
            "objective-c"
        }
        _ => "c",
    }
}

async fn native_codegen_resolution<T>(
    creator: &T,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
    kind: CCompilerKind,
) -> Result<Option<NativeCodegenResolution>>
where
    T: CommandCreatorSync,
{
    let native_args = native_codegen_args(parsed_args);
    if native_args.is_empty() {
        return Ok(None);
    }

    // Probe once using the entire ordered target-relevant driver argument
    // sequence, including any named CPU and feature masks interleaved with
    // native. The observed cc1 target state is the authoritative expansion.
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-###")
        .arg("-E")
        .arg("-x")
        .arg(native_probe_language(parsed_args.language))
        .arg("-")
        .args(&parsed_args.common_args)
        .args(&parsed_args.arch_args)
        .env_clear()
        .envs(env_vars.to_vec())
        .current_dir(cwd);
    let output = run_input_output(cmd, Some(Vec::new())).await?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let driver_line = stderr
        .lines()
        .find(|line| {
            shlex::split(line)
                .is_some_and(|args| args.iter().any(|arg| is_native_driver_frontend(arg)))
        })
        .context("compiler did not expose a native CPU frontend expansion")?;
    let flags = native_driver_replacement(driver_line, kind, &native_args)?;
    // Preserve the requesting compiler's full observed frontend state in the
    // native-only cache supplement. The working directory can affect emitted
    // debug metadata without changing preprocessed bytes (notably Clang -g),
    // so hashing only the CPU switches could alias materially different objects.
    let mut digest = Digest::new();
    digest.update(b"sccache-native-target-resolution-v4\0");
    digest.update(driver_line.as_bytes());
    #[cfg(not(feature = "dist-client"))]
    let _ = flags;
    Ok(Some(NativeCodegenResolution {
        fingerprint: digest.finish(),
        #[cfg(feature = "dist-client")]
        explicit_args: flags,
    }))
}

impl ParsedArguments {
    pub fn output_pretty(&self) -> Cow<'_, str> {
        self.outputs
            .get("obj")
            .and_then(|o| o.path.file_name())
            .map_or(Cow::Borrowed("Unknown filename"), |s| s.to_string_lossy())
    }
}

/// A generic implementation of the `Compilation` trait for C/C++ compilers.
struct CCompilation<I: CCompilerImpl> {
    parsed_args: ParsedArguments,
    is_locally_preprocessed: bool,
    allow_dist: bool,
    native_resolution: Option<NativeCodegenResolution>,
    #[cfg(feature = "dist-client")]
    preprocessed_input: Vec<u8>,
    executable: PathBuf,
    compiler: I,
    cwd: PathBuf,
    env_vars: Vec<(OsString, OsString)>,
}

/// Supported C compilers.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CCompilerKind {
    /// GCC
    Gcc,
    /// clang
    Clang,
    /// Diab
    Diab,
    /// Microsoft Visual C++
    Msvc,
    /// NVIDIA CUDA compiler
    Nvcc,
    /// NVIDIA CUDA front-end
    CudaFE,
    /// NVIDIA CUDA optimizer and PTX generator
    Cicc,
    /// NVIDIA CUDA PTX assembler
    Ptxas,
    /// NVIDIA hpc c, c++ compiler
    Nvhpc,
    /// Tasking VX
    TaskingVX,
}

pub struct CPreprocessContext<'a, T> {
    pub creator: &'a T,
    pub executable: &'a Path,
    pub parsed_args: &'a ParsedArguments,
    pub cwd: &'a Path,
    pub env_vars: &'a [(OsString, OsString)],
    pub may_dist: bool,
    pub rewrite_includes_only: bool,
    pub preprocessor_cache_mode: bool,
}

pub struct CCompileContext<'a> {
    pub path_transformer: &'a mut dist::PathTransformer,
    pub executable: &'a Path,
    pub parsed_args: &'a ParsedArguments,
    pub cwd: &'a Path,
    pub env_vars: &'a [(OsString, OsString)],
    pub rewrite_includes_only: bool,
    pub native_resolution: Option<&'a NativeCodegenResolution>,
}

impl CCompileContext<'_> {
    pub(super) fn local_command(&self, arguments: Vec<OsString>) -> SingleCompileCommand {
        SingleCompileCommand {
            executable: self.executable.to_owned(),
            arguments,
            env_vars: self.env_vars.to_owned(),
            cwd: self.cwd.to_owned(),
            share_jobserver: false,
        }
    }
}

pub type CCompileCommands<C> = Result<(C, Option<dist::CompileCommand>, Cacheable)>;

/// Construct a local-only frontend command using the shared -o convention.
pub(super) fn local_dash_o_compile_commands(
    context: &CCompileContext<'_>,
) -> CCompileCommands<SingleCompileCommand> {
    trace!("compile");
    let parsed = context.parsed_args;
    let output = parsed
        .outputs
        .get("obj")
        .context("Missing object file output")?;
    let mut arguments = vec![
        parsed.compilation_flag.clone(),
        parsed.input.clone().into(),
        "-o".into(),
        output.path.as_os_str().into(),
    ];
    arguments.extend_from_slice(&parsed.preprocessor_args);
    arguments.extend_from_slice(&parsed.unhashed_args);
    arguments.extend_from_slice(&parsed.common_args);
    Ok((context.local_command(arguments), None, Cacheable::Yes))
}

/// An interface to a specific C compiler.
#[async_trait]
pub trait CCompilerImpl: Clone + fmt::Debug + Send + Sync + 'static {
    type LocalCommand: CompileCommandImpl;
    /// Return the kind of compiler.
    fn kind(&self) -> CCompilerKind;
    /// Return true iff this is g++ or clang++.
    fn plusplus(&self) -> bool;
    /// Return the compiler version reported by the compiler executable.
    fn version(&self) -> Option<String>;
    /// Return the identity of the assembler the compiler would run, when it
    /// runs one at all.
    fn assembler_digest(&self) -> Option<String> {
        None
    }
    /// Determine whether `arguments` are supported by this compiler.
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
    ) -> CompilerArguments<ParsedArguments>;
    /// Run the C preprocessor with the specified set of arguments.
    async fn preprocess<T>(&self, context: CPreprocessContext<'_, T>) -> Result<process::Output>
    where
        T: CommandCreatorSync;
    /// Generate a command that can be used to invoke the C compiler to perform
    /// the compilation.
    fn generate_compile_commands(
        &self,
        context: CCompileContext<'_>,
    ) -> CCompileCommands<Self::LocalCommand>;
}

impl<I> CCompiler<I>
where
    I: CCompilerImpl,
{
    pub async fn new(
        compiler: I,
        executable: PathBuf,
        pool: &tokio::runtime::Handle,
    ) -> Result<Self> {
        let digest = Digest::file(executable.clone(), pool).await?;

        Ok(Self {
            executable,
            executable_digest: {
                if let Some(version) = compiler.version() {
                    let mut m = Digest::new();
                    m.update(digest.as_bytes());
                    m.update(version.as_bytes());
                    m.finish()
                } else {
                    digest
                }
            },
            compiler,
        })
    }

    fn extract_rocm_arg(args: &ParsedArguments, flag: &str) -> Option<PathBuf> {
        args.common_args.iter().find_map(|arg| match arg.to_str() {
            Some(sarg) if sarg.starts_with(flag) => {
                Some(PathBuf::from(sarg[arg.len()..].to_string()))
            }
            _ => None,
        })
    }

    fn extract_rocm_env(env_vars: &[(OsString, OsString)], name: &str) -> Option<PathBuf> {
        env_vars.iter().find_map(|(k, v)| match v.to_str() {
            Some(path) if k == name => Some(PathBuf::from(path.to_string())),
            _ => None,
        })
    }

    // See https://clang.llvm.org/docs/HIPSupport.html for details regarding the
    // order in which the environment variables and command-line arguments control the
    // directory to search for bitcode libraries.
    fn search_hip_device_libs(
        args: &ParsedArguments,
        env_vars: &[(OsString, OsString)],
    ) -> Vec<PathBuf> {
        let rocm_path_arg: Option<PathBuf> = Self::extract_rocm_arg(args, "--rocm-path=");
        let hip_device_lib_path_arg: Option<PathBuf> =
            Self::extract_rocm_arg(args, "--hip-device-lib-path=");
        let rocm_path_env: Option<PathBuf> = Self::extract_rocm_env(env_vars, "ROCM_PATH");
        let hip_device_lib_path_env: Option<PathBuf> =
            Self::extract_rocm_env(env_vars, "HIP_DEVICE_LIB_PATH");

        let hip_device_lib_path: PathBuf = hip_device_lib_path_arg
            .or(hip_device_lib_path_env)
            .or_else(|| rocm_path_arg.map(|path| path.join("amdgcn").join("bitcode")))
            .or_else(|| rocm_path_env.map(|path| path.join("amdgcn").join("bitcode")))
            // This is the default location in official AMD packages and containers.
            .unwrap_or_else(|| PathBuf::from("/opt/rocm/amdgcn/bitcode"));

        hip_device_lib_path
            .read_dir()
            .ok()
            .map(|f| {
                let mut device_libs = f
                    .flatten()
                    .filter(|f| f.path().extension().is_some_and(|ext| ext == "bc"))
                    .map(|f| f.path())
                    .collect::<Vec<_>>();
                device_libs.sort_unstable();
                device_libs
            })
            .unwrap_or_default()
    }
}

impl<T: CommandCreatorSync, I: CCompilerImpl> Compiler<T> for CCompiler<I> {
    fn kind(&self) -> CompilerKind {
        CompilerKind::C(self.compiler.kind())
    }
    #[cfg(feature = "dist-client")]
    fn get_toolchain_packager(&self) -> Box<dyn pkg::ToolchainPackager> {
        Box::new(CToolchainPackager {
            executable: self.executable.clone(),
            kind: self.compiler.kind(),
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
            env_vars: Vec::new(),
        })
    }
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        _policy: super::CompilerCachePolicy,
    ) -> CompilerArguments<Box<dyn CompilerHasher<T> + 'static>> {
        match self.compiler.parse_arguments(arguments, cwd, env_vars) {
            CompilerArguments::Ok(mut args) => {
                // Handle SCCACHE_EXTRAFILES
                for (k, v) in env_vars {
                    if k.as_os_str() == OsStr::new("SCCACHE_EXTRAFILES") {
                        args.extra_hash_files.extend(std::env::split_paths(&v));
                    }
                }

                // Handle cache invalidation for the ROCm device bitcode libraries. Every HIP
                // object links in some LLVM bitcode libraries (.bc files), so in some sense
                // every HIP object compilation has an direct dependency on those bitcode
                // libraries.
                //
                // The bitcode libraries are unlikely to change **except** when a ROCm version
                // changes, so for correctness we should take these bitcode libraries into
                // account by adding them to `extra_hash_files`.
                //
                // In reality, not every available bitcode library is needed, but that is
                // too much to handle on our side so we just hash every bitcode library we find.
                if args.language == Language::Hip {
                    args.extra_hash_files
                        .extend(Self::search_hip_device_libs(&args, env_vars));
                }

                CompilerArguments::Ok(Box::new(CCompilerHasher {
                    parsed_args: args,
                    executable: self.executable.clone(),
                    executable_digest: self.executable_digest.clone(),
                    compiler: self.compiler.clone(),
                }))
            }
            CompilerArguments::CannotCache(why, extra_info) => {
                CompilerArguments::CannotCache(why, extra_info)
            }
            CompilerArguments::NotCompilation => CompilerArguments::NotCompilation,
        }
    }

    fn box_clone(&self) -> Box<dyn Compiler<T>> {
        Box::new((*self).clone())
    }
}

#[async_trait]
impl<T, I> CompilerHasher<T> for CCompilerHasher<I>
where
    T: CommandCreatorSync,
    I: CCompilerImpl,
{
    #[expect(
        clippy::too_many_lines,
        reason = "cache-key construction is an ordered pipeline; keeping hashing and preprocessing decisions contiguous makes key changes auditable"
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
            rewrite_includes_only,
            storage,
            cache_control,
        } = context;
        let start_of_compilation = std::time::SystemTime::now();
        let mut parsed_args = self.parsed_args.clone();
        let canonical_native = NativeCargoPaths::discover(
            &env_vars,
            self.compiler.kind(),
            self.compiler.version().as_deref(),
            &parsed_args,
        );
        if let Some(paths) = &canonical_native {
            parsed_args.common_args.extend(paths.compiler_options());
            // The native canonical key must see the expanded macro values,
            // including filename builtins. Send that exact preprocessed stream
            // to the worker rather than a second, directive-only interpretation.
            parsed_args.suppress_rewrite_includes_only = true;
        }

        let mut extra_hashes = hash_all(&parsed_args.extra_hash_files, &pool.clone()).await?;
        let native_resolution = native_codegen_resolution(
            creator,
            &self.executable,
            &self.parsed_args,
            &cwd,
            &env_vars,
            self.compiler.kind(),
        )
        .await;
        let mut cache_control = cache_control;
        if let Ok(Some(resolution)) = &native_resolution {
            extra_hashes.push(resolution.fingerprint.clone());
        } else if let Err(error) = &native_resolution {
            warn!(
                "Failed to resolve native C/C++ codegen identity; bypassing cache for this compile: {error:#}"
            );
            cache_control = CacheControl::ForceNoCache;
        }
        let native_resolution = native_resolution.ok().flatten();
        // The assembler that turns the compiler's output into the object file is
        // as much a part of the result as the compiler itself.
        let assembler_digest = if parsed_args.uses_external_assembler {
            self.compiler.assembler_digest()
        } else {
            None
        };
        // Create an argument vector containing both preprocessor and arch args, to
        // use in creating a hash key
        let mut preprocessor_and_arch_args = parsed_args.preprocessor_args.clone();
        preprocessor_and_arch_args.extend(parsed_args.arch_args.clone());
        // common_args is used in preprocessing too
        preprocessor_and_arch_args.extend(parsed_args.common_args.clone());

        let absolute_input_path: Cow<'_, _> = if parsed_args.input.is_absolute() {
            Cow::Borrowed(&parsed_args.input)
        } else {
            Cow::Owned(cwd.join(&parsed_args.input))
        };

        // Try to look for a cached preprocessing step for this compilation
        // request.
        let preprocessor_cache_mode_config = storage.preprocessor_cache_mode_config();
        let too_hard_for_preprocessor_cache_mode =
            parsed_args.too_hard_for_preprocessor_cache_mode.is_some();
        if let Some(arg) = &parsed_args.too_hard_for_preprocessor_cache_mode {
            debug!(
                "generate_hash_key: Cannot use preprocessor cache because of {}",
                crate::util::debug_display(arg)
            );
        }

        let needs_preprocessing = parsed_args.language.needs_c_preprocessing();

        let use_preprocessor_cache_mode = if needs_preprocessing {
            let can_use_preprocessor_cache_mode = preprocessor_cache_mode_config
                .use_preprocessor_cache_mode
                && !too_hard_for_preprocessor_cache_mode
                && canonical_native.is_none();

            let mut use_preprocessor_cache_mode = can_use_preprocessor_cache_mode;

            // Allow overrides from the env
            for (key, val) in &env_vars {
                if key == "SCCACHE_DIRECT" {
                    if let Some(val) = val.to_str() {
                        use_preprocessor_cache_mode = match val.to_lowercase().as_str() {
                            "false" | "off" | "0" => false,
                            _ => can_use_preprocessor_cache_mode,
                        };
                    }
                    break;
                }
            }

            if can_use_preprocessor_cache_mode && !use_preprocessor_cache_mode {
                debug!(
                    "generate_hash_key: Disabling preprocessor cache because SCCACHE_DIRECT=false"
                );
            }

            use_preprocessor_cache_mode
        } else {
            debug!(
                "generate_hash_key: Disabling preprocessor cache because {} language doesn't need C preprocessing",
                parsed_args.language.as_str()
            );
            false
        };

        let mut preprocessor_key = if use_preprocessor_cache_mode {
            preprocessor_cache_entry_hash_key(PreprocessorCacheKey {
                compiler_digest: &self.executable_digest,
                language: parsed_args.language,
                arguments: &preprocessor_and_arch_args,
                extra_hashes: &extra_hashes,
                assembler_digest: assembler_digest.as_deref(),
                env_vars: &env_vars,
                input_file: &absolute_input_path,
                plusplus: self.compiler.plusplus(),
                config: preprocessor_cache_mode_config,
                basedirs: storage.basedirs(),
            })?
        } else {
            None
        };

        let (preprocessor_output, include_files) = if needs_preprocessing {
            if let Some(preprocessor_key) = &preprocessor_key
                && cache_control == CacheControl::Default
                && let Some(mut seekable) = storage
                    .get_preprocessor_cache_entry(preprocessor_key)
                    .await
                    .unwrap_or_else(|error| {
                        debug!("Preprocessor cache lookup failed for {preprocessor_key}: {error}");
                        None
                    })
                && let Some(preprocessor_cache_entry) =
                    read_preprocessor_cache_entry(&mut seekable, preprocessor_key)
            {
                if let Some(key) =
                    preprocessor_cache_entry.lookup_result_digest(preprocessor_cache_mode_config)
                {
                    debug!("Preprocessor cache hit: {preprocessor_key}");
                    // A compiler binary may be a symlink to another and
                    // so has the same digest, but that means
                    // the toolchain will not contain the correct path
                    // to invoke the compiler! Add the compiler
                    // executable path to try and prevent this
                    let weak_toolchain_key = format!(
                        "{}-{}",
                        self.executable.to_string_lossy(),
                        self.executable_digest
                    );
                    return Ok(HashResult {
                        key,
                        compilation: Box::new(CCompilation {
                            parsed_args: parsed_args.clone(),
                            is_locally_preprocessed: false,
                            allow_dist: true,
                            native_resolution: native_resolution.clone(),
                            #[cfg(feature = "dist-client")]
                            preprocessed_input: PREPROCESSING_SKIPPED_COMPILE_POISON.to_vec(),
                            executable: self.executable.clone(),
                            compiler: self.compiler.to_owned(),
                            cwd: cwd.clone(),
                            env_vars: env_vars.clone(),
                        }),
                        weak_toolchain_key,
                        cache_control,
                    });
                }
                debug!("Preprocessor cache miss: {preprocessor_key}");
            }

            let result = self
                .compiler
                .preprocess(CPreprocessContext {
                    creator,
                    executable: &self.executable,
                    parsed_args: &parsed_args,
                    cwd: &cwd,
                    env_vars: &env_vars,
                    may_dist: may_dist || canonical_native.is_some(),
                    rewrite_includes_only,
                    preprocessor_cache_mode: use_preprocessor_cache_mode,
                })
                .await;
            let out_pretty = parsed_args.output_pretty().into_owned();
            let result = result.map_err(|e| {
                debug!("[{out_pretty}]: preprocessor failed: {e:?}");
                e
            });

            let outputs = parsed_args.outputs.clone();
            let args_cwd = cwd.clone();

            let mut preprocessor_result = result.or_else(move |err| {
                // Errors remove all traces of potential output.
                debug!("removing files {outputs:?}");

                let v: std::result::Result<(), std::io::Error> =
                    outputs.values().try_for_each(|output| {
                        let mut path = args_cwd.clone();
                        path.push(&output.path);
                        match fs::metadata(&path) {
                            // File exists, remove it.
                            Ok(_) => fs::remove_file(&path),
                            _ => Ok(()),
                        }
                    });
                if v.is_err() {
                    warn!("Could not remove files after preprocessing failed!");
                }

                match err.downcast::<ProcessError>() {
                    Ok(ProcessError(output)) => {
                        debug!(
                            "[{out_pretty}]: preprocessor returned error status {:?}",
                            output.status.code()
                        );
                        // Drop the stdout since it's the preprocessor output,
                        // just hand back stderr and the exit status.
                        bail!(ProcessError(process::Output {
                            stdout: vec!(),
                            ..output
                        }))
                    }
                    Err(err) => Err(err),
                }
            })?;

            // Remember include files needed in this preprocessing step
            let mut include_files = HashMap::new();
            if preprocessor_key.is_some() {
                // TODO how to propagate stats and which stats?
                if !process_preprocessed_file(
                    &absolute_input_path,
                    &cwd,
                    &mut preprocessor_result.stdout,
                    &mut include_files,
                    preprocessor_cache_mode_config,
                    start_of_compilation,
                    &StandardFsAbstraction,
                )? {
                    debug!("Disabling preprocessor cache mode");
                    preprocessor_key = None;
                }
            }

            trace!(
                "[{}]: Preprocessor output is {} bytes",
                parsed_args.output_pretty(),
                preprocessor_result.stdout.len()
            );

            (preprocessor_result.stdout, include_files)
        } else {
            // No preprocessing is supported - input is already preprocessed
            (
                std::fs::read(absolute_input_path.as_path())?,
                HashMap::new(),
            )
        };

        let mut allow_dist = true;
        let has_assembler_external_input = if matches!(
            parsed_args.language,
            Language::Assembler | Language::AssemblerToPreprocess
        ) {
            contains_assembler_file_directive(&preprocessor_output)
        } else {
            contains_inline_assembler_file_directive(&preprocessor_output)
        };
        if matches!(
            self.compiler.kind(),
            CCompilerKind::Gcc | CCompilerKind::Clang
        ) && has_assembler_external_input
        {
            // GCC/Clang do not report assembler .include/.incbin inputs in -M/-MD
            // dependencies. For actual assembly inputs, discover the literal file
            // graph ourselves so its contents participate in the object key and the
            // same files are available to distributed workers. Other languages can
            // contain assembler directives inside inline-asm strings; decoding those
            // through the front-end is intentionally left to the compiler, so keep
            // such compilations local and uncached rather than risking stale objects.
            if matches!(
                parsed_args.language,
                Language::Assembler | Language::AssemblerToPreprocess
            ) {
                match assembler_file_dependencies(&preprocessor_output, &cwd, &parsed_args) {
                    AssemblerDependencyScan::Complete(paths) => {
                        let paths: Vec<_> = paths
                            .into_iter()
                            .filter(|path| !parsed_args.extra_hash_files.contains(path))
                            .collect();
                        extra_hashes.extend(hash_all(&paths, &pool.clone()).await?);
                        parsed_args.extra_hash_files.extend(paths);
                    }
                    AssemblerDependencyScan::Incomplete(reason) => {
                        debug!("assembler external-input scan incomplete: {reason}");
                        cache_control = CacheControl::ForceNoCache;
                        allow_dist = false;
                    }
                }
            } else {
                debug!(
                    "assembler file directive outside an assembly input; disabling cache and dist"
                );
                cache_control = CacheControl::ForceNoCache;
                allow_dist = false;
            }
            // Assembler-owned files are invisible to the C preprocessor. Never
            // store a preprocessor-cache result that could bypass this scan.
            preprocessor_key = None;
        }

        // Create an argument vector containing both common and arch args, to
        // use in creating a hash key
        let mut common_and_arch_args = self.parsed_args.common_args.clone();
        common_and_arch_args.extend(self.parsed_args.arch_args.clone());

        // Hash the same remapped filename identity that the compiler uses for
        // debug information. Do not strip arbitrary source literals or flags.
        let key_input = if let Some(paths) = &canonical_native {
            let normalized = paths.preprocessed_key_bytes(&preprocessor_output);
            extra_hashes.push(paths.context_digest(&self.parsed_args, &cwd, &normalized));
            normalized
        } else {
            Cow::Borrowed(preprocessor_output.as_slice())
        };
        let basedirs = if canonical_native.is_some() {
            &[][..]
        } else {
            storage.basedirs()
        };

        let debug_compilation_dir = matches!(
            self.compiler.kind(),
            CCompilerKind::Gcc | CCompilerKind::Clang
        )
        .then(|| effective_debug_compilation_dir(&cwd, &common_and_arch_args))
        .flatten()
        .map(|directory| {
            // Cargo's canonical source path identity is realized by injected
            // compiler prefix maps. Those maps rewrite DW_AT_comp_dir too;
            // hash the *emitted* directory, not the physical OUT_DIR/CWD.
            canonical_native.as_ref().map_or_else(
                || directory.clone(),
                |paths| paths.map_bytes(&directory).into_owned(),
            )
        });
        let key = HashKeyParams::new(
            &self.executable_digest,
            parsed_args.language,
            &common_and_arch_args,
            &key_input,
        )
        .with_extra_hashes(&extra_hashes)
        .with_env_vars(&env_vars)
        .with_plusplus(self.compiler.plusplus())
        .with_basedirs(basedirs)
        .with_assembler_digest(assembler_digest.as_deref())
        .with_input_file_name(hashed_input_file_name(
            self.parsed_args.language,
            &self.parsed_args.input,
        ))
        .with_debug_compilation_dir(debug_compilation_dir.as_deref())
        .compute();

        // Cache the preprocessing step
        if let Some(preprocessor_key) = preprocessor_key
            && !include_files.is_empty()
        {
            let mut preprocessor_cache_entry = PreprocessorCacheEntry::new();
            let mut files: Vec<_> = include_files
                .into_iter()
                .map(|(path, digest)| (digest, path))
                .collect();
            files.sort_unstable_by(|a, b| a.1.cmp(&b.1));
            preprocessor_cache_entry.add_result(start_of_compilation, &key, files);

            if let Err(e) = storage
                .put_preprocessor_cache_entry(&preprocessor_key, preprocessor_cache_entry)
                .await
            {
                debug!("Failed to update preprocessor cache: {e}");
            }
        }

        // A compiler binary may be a symlink to another and so has the same digest, but that means
        // the toolchain will not contain the correct path to invoke the compiler! Add the compiler
        // executable path to try and prevent this
        let weak_toolchain_key = format!(
            "{}-{}",
            self.executable.to_string_lossy(),
            self.executable_digest
        );
        Ok(HashResult {
            key,
            compilation: Box::new(CCompilation {
                parsed_args,
                is_locally_preprocessed: true,
                allow_dist,
                native_resolution,
                #[cfg(feature = "dist-client")]
                preprocessed_input: preprocessor_output,
                executable: self.executable.clone(),
                compiler: self.compiler.clone(),
                cwd,
                env_vars,
            }),
            weak_toolchain_key,
            cache_control,
        })
    }

    fn color_mode(&self) -> ColorMode {
        self.parsed_args.color_mode
    }

    fn output_pretty(&self) -> Cow<'_, str> {
        self.parsed_args.output_pretty()
    }

    fn box_clone(&self) -> Box<dyn CompilerHasher<T>> {
        Box::new((*self).clone())
    }

    fn language(&self) -> Language {
        self.parsed_args.language
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AssemblerDependencyScan {
    Complete(Vec<PathBuf>),
    Incomplete(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AssemblerFileDirective {
    Include,
    Incbin,
}

#[derive(Debug, PartialEq, Eq)]
enum AssemblerDependency {
    File(AssemblerFileDirective, PathBuf),
    Unparsable,
}

#[derive(Debug, PartialEq, Eq)]
enum AssemblerFileOperand {
    Name(Vec<u8>),
    Unparsable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AssemblerOperandQuoting {
    Plain,
    Escaped,
}

const ASSEMBLER_OPERAND_MAX_LEN: usize = 4096;

const fn skip_assembler_whitespace(bytes: &[u8]) -> (&[u8], bool) {
    let mut rest = bytes;
    let mut skipped = false;
    loop {
        rest = match rest {
            [b' ' | b'\t', tail @ ..]
            | [b'\\', b't' | b'n' | b'r' | b'f' | b'v' | b' ', tail @ ..] => tail,
            _ => return (rest, skipped),
        };
        skipped = true;
    }
}

fn parse_assembler_file_operand(after_directive: &[u8]) -> Option<(AssemblerFileOperand, usize)> {
    if after_directive
        .first()
        .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'$'))
    {
        return None;
    }

    let (rest, skipped_whitespace) = skip_assembler_whitespace(after_directive);
    let (quoting, body) = if let Some(body) = rest.strip_prefix(b"\\\"") {
        (AssemblerOperandQuoting::Escaped, body)
    } else if let Some(body) = rest.strip_prefix(b"\"") {
        (AssemblerOperandQuoting::Plain, body)
    } else if skipped_whitespace {
        return Some((AssemblerFileOperand::Unparsable, 0));
    } else {
        return None;
    };

    let terminator: &[u8] = match quoting {
        AssemblerOperandQuoting::Plain => b"\"",
        AssemblerOperandQuoting::Escaped => b"\\\"",
    };
    let window = &body[..body.len().min(ASSEMBLER_OPERAND_MAX_LEN)];
    let mut end = None;
    let mut i = 0;
    while i < window.len() {
        if window[i..].starts_with(terminator) {
            end = Some(i);
            break;
        }
        if matches!(window[i], b'"' | b'\\' | b'\n' | b'\r') {
            break;
        }
        i += 1;
    }

    Some(match end {
        Some(0) | None => (AssemblerFileOperand::Unparsable, 0),
        Some(end) => {
            let spanned = after_directive.len() - body.len() + end + terminator.len();
            (AssemblerFileOperand::Name(window[..end].to_vec()), spanned)
        }
    })
}

fn assembler_dependency_at(slice: &[u8]) -> Option<(AssemblerDependency, usize)> {
    let (directive, directive_len, after_directive) =
        if let Some(rest) = slice.strip_prefix(INCBIN_DIRECTIVE) {
            (AssemblerFileDirective::Incbin, INCBIN_DIRECTIVE.len(), rest)
        } else {
            let rest = slice.strip_prefix(INCLUDE_DIRECTIVE)?;
            (
                AssemblerFileDirective::Include,
                INCLUDE_DIRECTIVE.len(),
                rest,
            )
        };

    Some(match parse_assembler_file_operand(after_directive)? {
        (AssemblerFileOperand::Name(name), spanned) => {
            let Ok(path) = decode_path(&name) else {
                return Some((AssemblerDependency::Unparsable, directive_len));
            };
            (
                AssemblerDependency::File(directive, path),
                directive_len + spanned,
            )
        }
        (AssemblerFileOperand::Unparsable, _) => (AssemblerDependency::Unparsable, directive_len),
    })
}

/// Return true when a recognized assembler directive may begin at `pos`.
///
/// A preceding identifier character makes `.include`/`.incbin` a member or
/// symbol suffix, not an assembler statement. Everything else remains eligible:
/// line starts, whitespace, statement separators, labels, and C-string escape
/// sequences used by inline assembly.
fn starts_assembler_statement(bytes: &[u8], pos: usize) -> bool {
    let before = &bytes[..pos];
    let identifier_start = before
        .iter()
        .rposition(|c| !(c.is_ascii_alphanumeric() || matches!(c, b'_' | b'$')))
        .map_or(0, |end| end + 1);
    if identifier_start == before.len() {
        return true;
    }

    identifier_start > 0 && before[identifier_start - 1] == b'\\'
}

fn assembler_dependencies_in(bytes: &[u8]) -> Vec<AssemblerDependency> {
    let mut dependencies = Vec::new();
    let mut offset = 0;
    while let Some(pos) = memchr::memchr(b'.', &bytes[offset..]) {
        let start = offset + pos;
        match assembler_dependency_at(&bytes[start..]) {
            Some((dependency, spanned)) if starts_assembler_statement(bytes, start) => {
                dependencies.push(dependency);
                offset = start + spanned;
            }
            _ => offset = start + 1,
        }
    }
    dependencies
}

fn contains_assembler_file_directive(bytes: &[u8]) -> bool {
    !assembler_dependencies_in(bytes).is_empty()
}

const fn is_c_identifier_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_c_space_and_comments(bytes: &[u8], mut pos: usize) -> usize {
    loop {
        while bytes.get(pos).is_some_and(u8::is_ascii_whitespace) {
            pos += 1;
        }
        if bytes.get(pos..pos + 2) == Some(b"/*") {
            pos += 2;
            while pos + 1 < bytes.len() && bytes.get(pos..pos + 2) != Some(b"*/") {
                pos += 1;
            }
            pos = (pos + 2).min(bytes.len());
            continue;
        }
        if bytes.get(pos..pos + 2) == Some(b"//") {
            pos += 2;
            while bytes.get(pos).is_some_and(|byte| *byte != b'\n') {
                pos += 1;
            }
            continue;
        }
        return pos;
    }
}

fn skip_c_quoted(bytes: &[u8], mut pos: usize, quote: u8) -> usize {
    debug_assert_eq!(bytes.get(pos), Some(&quote));
    pos += 1;
    while let Some(&byte) = bytes.get(pos) {
        if byte == b'\\' {
            pos = (pos + 2).min(bytes.len());
        } else {
            pos += 1;
            if byte == quote {
                break;
            }
        }
    }
    pos
}

fn matching_c_paren(bytes: &[u8], open: usize) -> Option<usize> {
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 1usize;
    let mut pos = open + 1;
    while pos < bytes.len() {
        match bytes[pos] {
            b'"' | b'\'' => pos = skip_c_quoted(bytes, pos, bytes[pos]),
            b'/' if bytes.get(pos + 1) == Some(&b'*') || bytes.get(pos + 1) == Some(&b'/') => {
                pos = skip_c_space_and_comments(bytes, pos);
            }
            b'(' => {
                depth += 1;
                pos += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(pos);
                }
                pos += 1;
            }
            _ => pos += 1,
        }
    }
    None
}

/// Detect assembler file directives only inside GNU C/C++ inline-asm statements.
///
/// Searching arbitrary C strings causes false positives for ordinary text such as
/// `".include %s"`. GNU inline asm is syntactically anchored by `asm`, `__asm` or
/// `__asm__`, optionally followed by the standard qualifiers, and a parenthesized
/// operand list. Restrict the expensive/correctness fallback to those regions.
fn contains_inline_assembler_file_directive(bytes: &[u8]) -> bool {
    inline_assembly_matches(bytes, contains_assembler_file_directive)
}

/// A GNU inline-assembly operand can contain assembler directives as well as
/// instructions. Inspect its operand rather than searching unrelated C++ text.
pub(super) fn inline_assembly_matches(bytes: &[u8], predicate: impl Fn(&[u8]) -> bool) -> bool {
    let mut pos = 0;
    while pos < bytes.len() {
        match bytes[pos] {
            b'"' | b'\'' => {
                pos = skip_c_quoted(bytes, pos, bytes[pos]);
            }
            b'/' if bytes.get(pos + 1) == Some(&b'*') || bytes.get(pos + 1) == Some(&b'/') => {
                pos = skip_c_space_and_comments(bytes, pos);
            }
            byte if byte == b'_' || byte.is_ascii_alphabetic() => {
                let start = pos;
                pos += 1;
                while bytes
                    .get(pos)
                    .is_some_and(|byte| is_c_identifier_char(*byte))
                {
                    pos += 1;
                }
                let ident = &bytes[start..pos];
                if !matches!(ident, b"asm" | b"__asm" | b"__asm__") {
                    continue;
                }

                let mut cursor = skip_c_space_and_comments(bytes, pos);
                loop {
                    let qualifier_start = cursor;
                    while bytes
                        .get(cursor)
                        .is_some_and(|byte| is_c_identifier_char(*byte))
                    {
                        cursor += 1;
                    }
                    let qualifier = &bytes[qualifier_start..cursor];
                    if matches!(
                        qualifier,
                        b"volatile" | b"__volatile" | b"__volatile__" | b"inline" | b"goto"
                    ) {
                        cursor = skip_c_space_and_comments(bytes, cursor);
                    } else {
                        cursor = qualifier_start;
                        break;
                    }
                }
                if bytes.get(cursor) != Some(&b'(') {
                    continue;
                }
                let Some(close) = matching_c_paren(bytes, cursor) else {
                    // Malformed C is the compiler's problem; it cannot yield a valid
                    // stale cache entry, so there is no external-input dependency to track.
                    continue;
                };
                if predicate(&bytes[cursor + 1..close]) {
                    return true;
                }
                pos = close + 1;
            }
            _ => pos += 1,
        }
    }
    false
}

/// Return GCC/Clang `-I` directories in assembler search order.
///
/// GCC argument parsing normalizes the two-token spelling (`-I dir`) to a
/// single `-Idir` argument before this point.
fn absolutize_assembler_include_dir(path: PathBuf, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

fn preprocessor_assembler_include_dirs(parsed_args: &ParsedArguments, cwd: &Path) -> Vec<PathBuf> {
    parsed_args
        .preprocessor_args
        .iter()
        .filter_map(|arg| {
            arg.as_encoded_bytes()
                .strip_prefix(b"-I")
                .filter(|path| !path.is_empty())
                .and_then(|path| decode_path(path).ok())
        })
        .map(|path| absolutize_assembler_include_dir(path, cwd))
        .collect()
}

fn driver_assembler_include_dirs(
    parsed_args: &ParsedArguments,
    cwd: &Path,
) -> Result<Vec<PathBuf>> {
    let mut assembler_args = Vec::<Vec<u8>>::new();
    let mut i = 0;
    while i < parsed_args.common_args.len() {
        let arg = parsed_args.common_args[i].as_encoded_bytes();
        if let Some(rest) = arg.strip_prefix(b"-Wa,") {
            assembler_args.extend(rest.split(|byte| *byte == b',').map(<[u8]>::to_vec));
        } else if arg == b"-Xassembler" {
            i += 1;
            let value = parsed_args
                .common_args
                .get(i)
                .context("-Xassembler is missing its argument")?;
            assembler_args.push(value.as_encoded_bytes().to_vec());
        }
        i += 1;
    }

    let mut include_dirs = Vec::new();
    let mut i = 0;
    while i < assembler_args.len() {
        let arg = &assembler_args[i];
        let path = if arg == b"-I" {
            i += 1;
            let value = assembler_args
                .get(i)
                .context("assembler -I is missing its directory")?;
            decode_path(value).context("assembler -I directory is not a valid path")?
        } else if let Some(value) = arg.strip_prefix(b"-I").filter(|value| !value.is_empty()) {
            decode_path(value).context("assembler -I directory is not a valid path")?
        } else {
            i += 1;
            continue;
        };
        include_dirs.push(absolutize_assembler_include_dir(path, cwd));
        i += 1;
    }

    Ok(include_dirs)
}

pub(super) fn assembler_include_dirs(parsed_args: &ParsedArguments, cwd: &Path) -> Vec<PathBuf> {
    let mut include_dirs = preprocessor_assembler_include_dirs(parsed_args, cwd);
    if let Ok(driver_dirs) = driver_assembler_include_dirs(parsed_args, cwd) {
        include_dirs.extend(driver_dirs);
    }
    include_dirs
}

fn assembler_dependency_include_dirs(
    parsed_args: &ParsedArguments,
    cwd: &Path,
) -> std::result::Result<Vec<PathBuf>, String> {
    let preprocessor_dirs = preprocessor_assembler_include_dirs(parsed_args, cwd);
    let driver_dirs =
        driver_assembler_include_dirs(parsed_args, cwd).map_err(|error| error.to_string())?;

    // ParsedArguments keeps preprocessor and pass-through arguments in separate
    // vectors, so their original interleaving is no longer recoverable. If both
    // forms contribute assembler search paths, choosing either concatenation could
    // resolve a duplicate file name differently from the compiler. Preserve
    // correctness by keeping such a translation unit local and uncached.
    if !preprocessor_dirs.is_empty() && !driver_dirs.is_empty() {
        return Err(
            "assembler include path mixes -I with -Wa/-Xassembler -I; original search order is unavailable"
                .to_owned(),
        );
    }

    Ok(if driver_dirs.is_empty() {
        preprocessor_dirs
    } else {
        driver_dirs
    })
}

fn resolve_assembler_file(path: &Path, cwd: &Path, include_dirs: &[PathBuf]) -> Option<PathBuf> {
    if path.is_absolute() {
        return path.is_file().then(|| path.to_path_buf());
    }
    let direct = cwd.join(path);
    if direct.is_file() {
        return Some(direct);
    }
    include_dirs
        .iter()
        .map(|dir| dir.join(path))
        .find(|candidate| candidate.is_file())
}

fn assembler_file_dependencies(
    bytes: &[u8],
    cwd: &Path,
    parsed_args: &ParsedArguments,
) -> AssemblerDependencyScan {
    let include_dirs = match assembler_dependency_include_dirs(parsed_args, cwd) {
        Ok(include_dirs) => include_dirs,
        Err(reason) => return AssemblerDependencyScan::Incomplete(reason),
    };
    let mut pending = vec![(None, bytes.to_vec())];
    let mut visited_includes = HashSet::new();
    let mut dependencies = Vec::new();
    let mut seen_dependencies = HashSet::new();

    while let Some((source, contents)) = pending.pop() {
        for dependency in assembler_dependencies_in(&contents) {
            let (directive, filename) = match dependency {
                AssemblerDependency::File(directive, filename) => (directive, filename),
                AssemblerDependency::Unparsable => {
                    return AssemblerDependencyScan::Incomplete(format!(
                        "assembler directive has a non-literal or unsupported file operand in {}",
                        source.as_deref().map_or_else(
                            || "preprocessed input".to_owned(),
                            |p: &Path| p.display().to_string()
                        )
                    ));
                }
            };
            let Some(path) = resolve_assembler_file(&filename, cwd, &include_dirs) else {
                return AssemblerDependencyScan::Incomplete(format!(
                    "cannot resolve assembler file {} referenced from {}",
                    filename.display(),
                    source.as_deref().map_or_else(
                        || "preprocessed input".to_owned(),
                        |p: &Path| p.display().to_string()
                    )
                ));
            };
            if seen_dependencies.insert(path.clone()) {
                dependencies.push(path.clone());
            }
            if directive == AssemblerFileDirective::Include && visited_includes.insert(path.clone())
            {
                match fs::read(&path) {
                    Ok(contents) => pending.push((Some(path), contents)),
                    Err(error) => {
                        return AssemblerDependencyScan::Incomplete(format!(
                            "cannot read assembler include {}: {error}",
                            path.display()
                        ));
                    }
                }
            }
        }
    }

    AssemblerDependencyScan::Complete(dependencies)
}

const PRAGMA_GCC_PCH_PREPROCESS: &[u8] = b"pragma GCC pch_preprocess";
const HASH_31_COMMAND_LINE_NEWLINE: &[u8] = b"# 31 \"<command-line>\"\n";
const HASH_32_COMMAND_LINE_2_NEWLINE: &[u8] = b"# 32 \"<command-line>\" 2\n";
const INCBIN_DIRECTIVE: &[u8] = b".incbin";
const INCLUDE_DIRECTIVE: &[u8] = b".include";
const COMPRESSED_CLANG_OFFLOAD_BUNDLE_MAGIC: &[u8] = b"CCOB";

/// An entry that cannot be read, such as one truncated by a crash, is a miss
/// rather than a failed compilation: the miss path overwrites it.
fn read_preprocessor_cache_entry(
    mut entry: impl io::Read,
    key: &str,
) -> Option<PreprocessorCacheEntry> {
    let mut buf = vec![];
    let result = entry
        .read_to_end(&mut buf)
        .map_err(Into::into)
        .and_then(|_| PreprocessorCacheEntry::read(&buf));
    match result {
        Ok(entry) => Some(entry),
        Err(e) => {
            debug!("Ignoring unreadable preprocessor cache entry {key}: {e}");
            None
        }
    }
}

/// Remember the include files in the preprocessor output if it can be cached.
/// Returns `false` if preprocessor cache mode should be disabled.
fn process_preprocessed_file(
    input_file: &Path,
    cwd: &Path,
    bytes: &mut [u8],
    included_files: &mut HashMap<PathBuf, String>,
    config: PreprocessorCacheModeConfig,
    time_of_compilation: std::time::SystemTime,
    fs_impl: &impl PreprocessorFSAbstraction,
) -> Result<bool> {
    if bytes.starts_with(COMPRESSED_CLANG_OFFLOAD_BUNDLE_MAGIC) {
        debug!("Found compressed Clang offload bundle in preprocessor output");
        return Ok(false);
    }

    let mut start = 0;
    let mut hash_start = 0;
    let total_len = bytes.len();
    let mut digest = Digest::new();
    let mut normalized_include_paths: HashMap<Vec<u8>, Option<Vec<u8>>> = HashMap::new();
    // There must be at least 7 characters (# 1 "x") left to potentially find an
    // include file path.
    while start < total_len.saturating_sub(7) {
        let mut slice = &bytes[start..];
        // Check if we look at a line containing the file name of an included file.
        // At least the following formats exist (where N is a positive integer):
        //
        // GCC:
        //
        //   # N "file"
        //   # N "file" N
        //   #pragma GCC pch_preprocess "file"
        //
        // HP's compiler:
        //
        //   #line N "file"
        //
        // AIX's compiler:
        //
        //   #line N "file"
        //   #line N
        //
        // Note that there may be other lines starting with '#' left after
        // preprocessing as well, for instance "#    pragma".
        if slice[0] == b'#'
        // GCC:
        && ((slice[1] == b' ' && slice[2] >= b'0' && slice[2] <= b'9')
            // GCC precompiled header:
            || slice[1..].starts_with(PRAGMA_GCC_PCH_PREPROCESS)
            // HP/AIX:
            || slice[1..].starts_with(b"line "))
        && (start == 0 || bytes[start - 1] == b'\n')
        {
            match process_preprocessor_line(
                PreprocessorLineContext {
                    input_file,
                    cwd,
                    included_files,
                    config,
                    time_of_compilation,
                    bytes,
                    digest: &mut digest,
                    normalized_include_paths: &mut normalized_include_paths,
                    fs_impl,
                },
                start,
                hash_start,
            )? {
                ControlFlow::Continue((s, h)) => {
                    start = s;
                    hash_start = h;
                }
                ControlFlow::Break((s, h, continue_preprocessor_cache_mode)) => {
                    if !continue_preprocessor_cache_mode {
                        return Ok(false);
                    }
                    start = s;
                    hash_start = h;
                }
            }
        } else if slice.starts_with(b"___________") && (start == 0 || bytes[start - 1] == b'\n') {
            // Unfortunately the distcc-pump wrapper outputs standard output lines:
            // __________Using distcc-pump from /usr/bin
            // __________Using # distcc servers in pump mode
            // __________Shutting down distcc-pump include server
            digest.update(&bytes[hash_start..start]);
            while start < total_len && slice[0] != b'\n' {
                start += 1;
                if start < total_len {
                    slice = &bytes[start..];
                }
            }
            slice = &bytes[start..];
            if slice[0] == b'\n' {
                start += 1;
            }
            hash_start = start;
        } else {
            start += 1;
        }
    }
    digest.update(&bytes[hash_start..]);

    Ok(true)
}

/// What to do after handling a preprocessor number line.
/// The `Break` variant is `(start, hash_start, continue_preprocessor_cache_mode)`.
/// The `Continue` variant is `(start, hash_start)`.
type PreprocessedLineAction = ControlFlow<(usize, usize, bool), (usize, usize)>;

struct PreprocessorLineContext<'a, F> {
    input_file: &'a Path,
    cwd: &'a Path,
    included_files: &'a mut HashMap<PathBuf, String>,
    config: PreprocessorCacheModeConfig,
    time_of_compilation: std::time::SystemTime,
    bytes: &'a mut [u8],
    digest: &'a mut Digest,
    normalized_include_paths: &'a mut HashMap<Vec<u8>, Option<Vec<u8>>>,
    fs_impl: &'a F,
}

fn process_preprocessor_line<F>(
    context: PreprocessorLineContext<'_, F>,
    mut start: usize,
    mut hash_start: usize,
) -> Result<PreprocessedLineAction>
where
    F: PreprocessorFSAbstraction,
{
    let PreprocessorLineContext {
        input_file,
        cwd,
        included_files,
        config,
        time_of_compilation,
        bytes,
        digest,
        normalized_include_paths,
        fs_impl,
    } = context;
    let total_len = bytes.len();
    let mut slice = &bytes[start..];
    // Workarounds for preprocessor linemarker bugs in GCC version 6.
    if slice.get(2) == Some(&b'3') {
        if slice.starts_with(HASH_31_COMMAND_LINE_NEWLINE) {
            // Bogus extra line with #31, after the regular #1:
            // Ignore the whole line, and continue parsing.
            digest.update(&bytes[hash_start..start]);
            while start < hash_start && slice[0] != b'\n' {
                start += 1;
            }
            start += 1;
            hash_start = start;
            return Ok(ControlFlow::Break((start, hash_start, true)));
        } else if slice.starts_with(HASH_32_COMMAND_LINE_2_NEWLINE) {
            // Bogus wrong line with #32, instead of regular #1:
            // Replace the line number with the usual one.
            digest.update(&bytes[hash_start..start]);
            start += 1;
            bytes[start..=start + 2].copy_from_slice(b"# 1");
            hash_start = start;
            slice = &bytes[start..];
        }
    }
    while start < total_len && slice[0] != b'"' && slice[0] != b'\n' {
        start += 1;
        if start < total_len {
            slice = &bytes[start..];
        }
    }
    slice = &bytes[start..];
    if start < total_len && slice[0] == b'\n' {
        // a newline before the quotation mark -> no match
        return Ok(ControlFlow::Break((start, hash_start, true)));
    }
    start += 1;
    if start >= total_len {
        bail!("Failed to parse included file path");
    }
    // `start` points to the beginning of an include file path
    digest.update(&bytes[hash_start..start]);
    hash_start = start;
    slice = &bytes[start..];
    while start < total_len && slice[0] != b'"' {
        start += 1;
        if start < total_len {
            slice = &bytes[start..];
        }
    }
    if start == hash_start {
        // Skip empty file name.
        return Ok(ControlFlow::Break((start, hash_start, true)));
    }
    // Look for preprocessor flags, after the "filename".
    let mut system = false;
    let mut pointer = start + 1;
    while pointer < total_len && bytes[pointer] != b'\n' {
        if bytes[pointer] == b'3' {
            // System header.
            system = true;
        }
        pointer += 1;
    }

    // `hash_start` and `start` span the include file path.
    let include_path = &bytes[hash_start..start];
    // We need to normalize the path now since it's part of the
    // hash and since we need to deduplicate the include files.
    // We cache the results since they are often quite a bit repeated.
    let include_path: &[u8] = if let Some(opt) = normalized_include_paths.get(include_path) {
        opt.as_ref().map_or(include_path, |normalized| normalized)
    } else {
        let path_buf = decode_path(include_path)?;
        let normalized = normalize_path(&path_buf);
        if normalized == path_buf {
            // `None` is a marker that the normalization is the same
            normalized_include_paths.insert(include_path.to_owned(), None);
            include_path
        } else {
            let mut encoded = Vec::with_capacity(include_path.len());
            encode_path(&mut encoded, &normalized)?;
            let normalized = normalized_include_paths
                .entry(include_path.to_owned())
                .or_insert_with(|| Some(encoded));
            normalized.as_deref().unwrap_or(include_path)
        }
    };

    if !remember_include_file(RememberIncludeContext {
        path: include_path,
        input_file,
        cwd,
        included_files,
        digest,
        system,
        config,
        time_of_compilation,
        fs_impl,
    })? {
        return Ok(ControlFlow::Break((start, hash_start, false)));
    }
    // Everything of interest between hash_start and start has been hashed now.
    hash_start = start;
    Ok(ControlFlow::Continue((start, hash_start)))
}

/// Copied from cargo.
///
/// Normalize a path, removing things like `.` and `..`.
///
/// CAUTION: This does not resolve symlinks (unlike
/// [`std::fs::canonicalize`]).
pub fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().copied() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(prefix) => ret.push(prefix.as_os_str()),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}

/// Limited abstraction of `std::fs::Metadata`, allowing us to create fake
/// values during testing.
#[derive(Debug, Eq, PartialEq, Clone)]
struct PreprocessorFileMetadata {
    is_dir: bool,
    is_file: bool,
    modified: Option<Timestamp>,
    ctime_or_creation: Option<Timestamp>,
}

impl From<std::fs::Metadata> for PreprocessorFileMetadata {
    fn from(meta: std::fs::Metadata) -> Self {
        Self {
            is_dir: meta.is_dir(),
            is_file: meta.is_file(),
            modified: meta.modified().ok().map(Into::into),
            ctime_or_creation: meta.ctime_or_creation().ok(),
        }
    }
}

/// An abstraction to filesystem access for use during the preprocessor
/// caching phase, to make testing easier.
///
/// This may help non-local preprocessor caching in the future, if it ends up
/// being viable.
trait PreprocessorFSAbstraction {
    fn metadata(&self, path: impl AsRef<Path>) -> io::Result<PreprocessorFileMetadata> {
        std::fs::metadata(path).map(Into::into)
    }

    fn open(&self, path: impl AsRef<Path>) -> io::Result<Box<dyn std::io::Read>> {
        Ok(Box::new(std::fs::File::open(path)?))
    }
}

/// Provides filesystem access with the expected standard library functions.
struct StandardFsAbstraction;

impl PreprocessorFSAbstraction for StandardFsAbstraction {}

struct RememberIncludeContext<'a, F> {
    path: &'a [u8],
    input_file: &'a Path,
    cwd: &'a Path,
    included_files: &'a mut HashMap<PathBuf, String>,
    digest: &'a mut Digest,
    system: bool,
    config: PreprocessorCacheModeConfig,
    time_of_compilation: std::time::SystemTime,
    fs_impl: &'a F,
}

// Returns false if the include file was "too new" (meaning modified during or
// after the start of the compilation) and therefore should disable
// the preprocessor cache mode, otherwise true.
fn remember_include_file<F>(context: RememberIncludeContext<'_, F>) -> Result<bool>
where
    F: PreprocessorFSAbstraction,
{
    let RememberIncludeContext {
        mut path,
        input_file,
        cwd,
        included_files,
        digest,
        system,
        config,
        time_of_compilation,
        fs_impl,
    } = context;
    // TODO if precompiled header.
    if path.len() >= 2 && path[0] == b'<' && path[path.len() - 1] == b'>' {
        // Typically <built-in> or <command-line>.
        digest.update(path);
        return Ok(true);
    }

    if system && config.skip_system_headers {
        // Don't remember this system header, only hash its path.
        digest.update(path);
        return Ok(true);
    }

    let original_path = path;
    // Canonicalize path for comparison; Clang uses ./header.h.
    #[cfg(windows)]
    {
        if path.starts_with(br".\") || path.starts_with(b"./") {
            path = &path[2..];
        }
    }
    #[cfg(not(windows))]
    {
        if path.starts_with(b"./") {
            path = &path[2..];
        }
    }
    let mut path = decode_path(path).context("failed to decode path")?;
    if path.is_relative() {
        path = cwd.join(path);
    }
    if path != cwd || config.hash_working_directory {
        digest.update(original_path);
    }

    if included_files.contains_key(&path) {
        // Already known include file
        return Ok(true);
    }

    if path == input_file {
        // Don't remember the input file.
        return Ok(true);
    }
    let meta = match fs_impl.metadata(&path) {
        Ok(meta) => meta,
        Err(e) => {
            debug!("Failed to stat include file {}: {e}", path.display());
            return Ok(false);
        }
    };
    if meta.is_dir {
        // Ignore directory, typically $PWD.
        return Ok(true);
    }
    if !meta.is_file {
        // Device, pipe, socket or other strange creature.
        debug!("Non-regular include file {}", path.display());
        return Ok(false);
    }

    // TODO add an option to ignore some header files?
    if include_is_too_new(&path, &meta, time_of_compilation) {
        return Ok(false);
    }

    // Let's hash the include file content.
    let file = match fs_impl.open(&path) {
        Ok(file) => file,
        Err(e) => {
            debug!("Failed to open header file {}: {e}", path.display());
            return Ok(false);
        }
    };

    let (file_digest, finder) = if config.ignore_time_macros {
        match Digest::reader_sync(file) {
            Ok(file_digest) => (file_digest, TimeMacroFinder::new()),
            Err(e) => {
                debug!("Failed to read header file {}: {e}", path.display());
                return Ok(false);
            }
        }
    } else {
        match Digest::reader_sync_time_macros(file) {
            Ok((file_digest, finder)) => (file_digest, finder),
            Err(e) => {
                debug!("Failed to read header file {}: {e}", path.display());
                return Ok(false);
            }
        }
    };

    if finder.found_time_macros() {
        debug!("Time macro in header file {}", path.display());
        return Ok(false);
    }

    included_files.insert(path, file_digest);

    Ok(true)
}

/// Opt out of preprocessor cache mode because of a race condition.
///
/// The race condition consists of these events:
///
/// - the preprocessor is run
/// - an include file is modified by someone
/// - the new include file is hashed by sccache
/// - the real compiler is run on the preprocessor's output, which contains
///   data from the old header file
/// - the wrong object file is stored in the cache.
fn include_is_too_new(
    path: &Path,
    meta: &PreprocessorFileMetadata,
    time_of_compilation: std::time::SystemTime,
) -> bool {
    // The comparison using >= is intentional, due to a possible race between
    // starting compilation and writing the include file.
    if let Some(mtime) = meta.modified
        && mtime >= time_of_compilation.into()
    {
        debug!("Include file {} is too new", path.display());
        return true;
    }

    // The same >= logic as above applies to the change time of the file.
    if let Some(ctime) = meta.ctime_or_creation
        && ctime >= time_of_compilation.into()
    {
        debug!("Include file {} is too new", path.display());
        return true;
    }

    false
}

// Used as "preprocessed code" when no preprocessing was done so that compilation fails. That should never
// happen though because, where necessary, the situation is detected and preprocessing is *then* done to
// salvage the situation. Previously, an empty u8 vector was used, which is unfortunately a valid C and C++
// compilation unit and caused errors that only surfaced when linking: the symbols expected from the
// compilation unit were of course not produced.
#[cfg(feature = "dist-client")]
const PREPROCESSING_SKIPPED_COMPILE_POISON: &[u8] = b"([{SCCACHE -*-* INVALID_C_CPP_CODE([{\"";

impl<T: CommandCreatorSync, I: CCompilerImpl> Compilation<T> for CCompilation<I> {
    fn generate_compile_commands(
        &self,
        path_transformer: &mut dist::PathTransformer,
        transport: CompileTransport,
    ) -> Result<(
        Box<dyn CompileCommand<T>>,
        Option<dist::CompileCommand>,
        Cacheable,
    )> {
        let (command, mut dist_command, cacheable) =
            self.compiler.generate_compile_commands(CCompileContext {
                path_transformer,
                executable: &self.executable,
                parsed_args: &self.parsed_args,
                cwd: &self.cwd,
                env_vars: &self.env_vars,
                rewrite_includes_only: transport.rewrite_includes_only(),
                native_resolution: self.native_resolution.as_ref(),
            })?;
        if !self.allow_dist {
            dist_command = None;
        }
        Ok((CCompileCommand::boxed(command), dist_command, cacheable))
    }

    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    fn automatic_dist_toolchain_is_ready(&self) -> bool {
        use std::io::Read as _;

        // A script's transitive execution environment is not automatically
        // discoverable by ELF dependency analysis. A custom archive may
        // still explicitly provide the wrapper and its dependencies.
        let mut magic = [0; 2];
        !fs::File::open(&self.executable)
            .and_then(|mut file| file.read_exact(&mut magic))
            .is_ok_and(|()| magic == *b"#!")
    }

    #[cfg(feature = "dist-client")]
    fn into_dist_packagers(
        self: Box<Self>,
        path_transformer: dist::PathTransformer,
    ) -> Result<DistPackagers> {
        let Self {
            parsed_args,
            cwd,
            preprocessed_input,
            executable,
            compiler,
            env_vars,
            ..
        } = *self;
        trace!(
            "Dist inputs: {}",
            crate::util::debug_display(&parsed_args.input)
        );

        let input_path = cwd.join(&parsed_args.input);
        let inputs_packager = Box::new(CInputsPackager {
            input_path,
            preprocessed_input,
            path_transformer,
            extra_dist_files: parsed_args.extra_dist_files,
            extra_hash_files: parsed_args.extra_hash_files,
        });
        let toolchain_packager = Box::new(CToolchainPackager {
            executable,
            kind: compiler.kind(),
            cwd,
            env_vars,
        });
        Ok((inputs_packager, toolchain_packager))
    }

    fn is_locally_preprocessed(&self) -> bool {
        self.is_locally_preprocessed
    }

    fn outputs<'a>(&'a self) -> Box<dyn Iterator<Item = FileObjectSource> + 'a> {
        Box::new(
            self.parsed_args
                .outputs
                .iter()
                .map(|(k, output)| FileObjectSource {
                    key: k.to_string(),
                    path: output.path.clone(),
                    optional: output.optional,
                }),
        )
    }
}

#[cfg(feature = "dist-client")]
struct CInputsPackager {
    input_path: PathBuf,
    path_transformer: dist::PathTransformer,
    preprocessed_input: Vec<u8>,
    extra_dist_files: Vec<PathBuf>,
    extra_hash_files: Vec<PathBuf>,
}

#[cfg(feature = "dist-client")]
impl pkg::InputsPackager for CInputsPackager {
    fn write_inputs(self: Box<Self>, wtr: &mut dyn io::Write) -> Result<()> {
        (*self).discover()?.write_archive(wtr, |_, _| Ok(None))
    }

    #[cfg(target_os = "linux")]
    fn native_mapping(self: Box<Self>) -> Result<crate::build_runtime::MappedTree> {
        (*self).discover()?.into_native_mapping()
    }
}

#[cfg(feature = "dist-client")]
impl CInputsPackager {
    fn discover(self) -> Result<pkg::CompilerInputs> {
        let Self {
            input_path,
            path_transformer,
            preprocessed_input,
            extra_dist_files,
            extra_hash_files,
        } = self;
        let mut inputs = pkg::CompilerInputs::new(path_transformer);
        inputs.file(&input_path, Some(preprocessed_input))?;
        for input_path in extra_hash_files.iter().chain(&extra_dist_files) {
            if !super::CAN_DIST_DYLIBS
                && input_path
                    .extension()
                    .is_some_and(|ext| ext == std::env::consts::DLL_EXTENSION)
            {
                bail!("Cannot distribute dylib input {}", input_path.display());
            }
            inputs.file(input_path, None)?;
        }
        Ok(inputs)
    }
}

#[cfg(feature = "dist-client")]
struct CToolchainPackager {
    executable: PathBuf,
    kind: CCompilerKind,
    cwd: PathBuf,
    env_vars: Vec<(OsString, OsString)>,
}

#[cfg(all(
    feature = "dist-client",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn gcc_program_search_fingerprint(
    search_output: &[u8],
    cwd: &Path,
    path_env: Option<&OsStr>,
) -> Result<String> {
    use std::os::unix::ffi::OsStrExt;

    fn record_path(digest: &mut Digest, path: &Path) -> Result<bool> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;

        digest.delimiter(path.as_os_str().as_bytes());
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                digest.update(b"absent");
                return Ok(false);
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Could not inspect GCC helper {}", path.display()));
            }
        };
        digest.update(b"present");
        for field in [
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mode().into(),
            metadata.mtime().cast_unsigned(),
            metadata.mtime_nsec().cast_unsigned(),
            metadata.ctime().cast_unsigned(),
            metadata.ctime_nsec().cast_unsigned(),
        ] {
            digest.update(&field.to_le_bytes());
        }
        Ok(metadata.is_dir())
    }

    let program_line = search_output
        .split(|&byte| byte == b'\n')
        .find_map(|line| line.strip_prefix(b"programs: "))
        .context("GCC -print-search-dirs omitted program search paths")?;
    let installation_directory = search_output
        .split(|&byte| byte == b'\n')
        .find_map(|line| line.strip_prefix(b"install: "));
    let mut digest = Digest::new();
    digest.delimiter(b"gcc-toolchain-helper-search-v2");
    for bytes in program_line
        .split(|&byte| byte == b':')
        .chain(installation_directory)
    {
        let bytes = bytes.strip_prefix(b"=").unwrap_or(bytes);
        if bytes.is_empty() {
            continue;
        }
        let directory = PathBuf::from(OsStr::from_bytes(bytes));
        let directory = if directory.is_absolute() {
            directory
        } else {
            cwd.join(directory)
        };
        if !record_path(&mut digest, &directory)? {
            continue;
        }
        let mut entries = fs::read_dir(&directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()?;
        entries.sort_unstable();
        for entry in entries {
            record_path(&mut digest, &entry)?;
        }
    }
    // GCC may fall back to PATH after its own program search directories.
    // Include all known helper names without enumerating an entire /usr/bin.
    if let Some(path_env) = path_env {
        for dir in std::env::split_paths(path_env) {
            let dir = if dir.is_absolute() {
                dir
            } else {
                cwd.join(dir)
            };
            for helper in [
                "as",
                "objcopy",
                "ld",
                "cc1",
                "cc1plus",
                "collect2",
                "lto-wrapper",
                "lto1",
            ] {
                record_path(&mut digest, &dir.join(helper))?;
            }
        }
    }
    Ok(digest.finish())
}

#[cfg(all(
    test,
    feature = "dist-client",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn gcc_program_search_fingerprint_tracks_helper_changes() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("gcc-tools");
    fs::create_dir(&dir)?;
    let search = format!(
        "install: ignored\nprograms: ={}\nlibraries: ignored\n",
        dir.display()
    );
    let fingerprint = || gcc_program_search_fingerprint(search.as_bytes(), temp.path(), None);

    let initial = fingerprint()?;
    assert_eq!(initial, fingerprint()?);
    fs::write(dir.join("as"), b"assembler version 1")?;
    let with_assembler = fingerprint()?;
    assert_ne!(initial, with_assembler);
    fs::write(dir.join("as"), b"assembler version 2 with new size")?;
    let with_new_assembler = fingerprint()?;
    assert_ne!(with_assembler, with_new_assembler);
    fs::write(dir.join("ld"), b"linker")?;
    assert_ne!(with_new_assembler, fingerprint()?);
    Ok(())
}

#[cfg(all(
    test,
    feature = "dist-client",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn real_cross_gcc_package_preserves_executable_helper_search_path() -> Result<()> {
    use std::os::unix::ffi::OsStringExt;

    let Some(executable) = std::env::var_os("SCCACHE_TEST_CROSS_GCC") else {
        return Ok(());
    };
    let executable = PathBuf::from(executable);
    let output = process::Command::new(&executable)
        .arg("-print-prog-name=as")
        .output()?;
    if !output.status.success() {
        bail!("GCC failed while identifying its assembler");
    }
    let assembler = PathBuf::from(OsString::from_vec(output.stdout.trim_ascii_end().to_vec()));
    assert!(assembler.is_absolute() && assembler.is_file());

    let temp = tempfile::tempdir()?;
    let archive_path = temp.path().join("toolchain.tar.gz");
    let packager = CToolchainPackager {
        executable,
        kind: CCompilerKind::Gcc,
        cwd: temp.path().to_owned(),
        env_vars: Vec::new(),
    };
    let cache_key = pkg::ToolchainPackager::cache_key_extension(&packager)?;
    assert_eq!(
        cache_key,
        pkg::ToolchainPackager::cache_key_extension(&packager)?,
        "unchanged GCC helper dependencies must have a stable cache key"
    );
    pkg::ToolchainPackager::write_pkg(Box::new(packager), fs::File::create(&archive_path)?)?;

    let root = temp.path().join("unpacked");
    crate::compression::deflate::unpack_gzip(fs::File::open(archive_path)?, &root)?;
    assert!(
        root.join(assembler.strip_prefix("/")?).is_file(),
        "packaged GCC assembler must resolve using the driver's original path"
    );
    Ok(())
}

#[cfg(feature = "dist-client")]
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl pkg::DiscoverToolchain for CToolchainPackager {
    fn key_extension(&self) -> Result<Option<String>> {
        // The compiler binary can be unchanged while its assembler, linker,
        // internal phases or search directories are being installed or updated.
        // One GCC driver query and metadata checks are cheaper than repackaging
        // on every distributed compile.
        if self.kind != CCompilerKind::Gcc {
            return Ok(Some("c-toolchain-lexical-paths-v2".to_owned()));
        }
        let output = process::Command::new(&self.executable)
            .arg("-print-search-dirs")
            .current_dir(&self.cwd)
            .envs(self.env_vars.iter().cloned())
            .output()
            .with_context(|| format!("Could not inspect GCC {}", self.executable.display()))?;
        if !output.status.success() {
            bail!("GCC failed while reporting toolchain search directories");
        }
        let path_env = self
            .env_vars
            .iter()
            .find(|(key, _)| key.as_os_str() == OsStr::new("PATH"))
            .map(|(_, value)| value.clone())
            .or_else(|| std::env::var_os("PATH"));
        Ok(Some(gcc_program_search_fingerprint(
            &output.stdout,
            &self.cwd,
            path_env.as_deref(),
        )?))
    }

    fn package_builder(self) -> Result<pkg::ToolchainPackageBuilder> {
        use std::os::unix::ffi::OsStringExt;

        info!("Generating toolchain {}", self.executable.display());
        let mut package_builder = pkg::ToolchainPackageBuilder::new();
        package_builder.add_common()?;
        package_builder.add_executable_and_deps(self.executable.clone())?;

        // Helper to use -print-file-name and -print-prog-name to look up
        // files by path.
        let named_file = |kind: &str, name: &str| -> Option<PathBuf> {
            let mut output = process::Command::new(&self.executable)
                .arg(format!("-print-{kind}-name={name}"))
                .current_dir(&self.cwd)
                .envs(self.env_vars.iter().cloned())
                .output()
                .ok()?;
            debug!(
                "find named {kind} {name} output:\n{}\n===\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            if !output.status.success() {
                debug!("exit failure");
                return None;
            }

            // Remove the trailing newline (if present)
            if output.stdout.last() == Some(&b'\n') {
                output.stdout.pop();
            }

            // Create our PathBuf from the raw bytes.  Assume that relative
            // paths can be found via PATH.
            let path: PathBuf = OsString::from_vec(output.stdout).into();
            if path.is_absolute() {
                Some(path)
            } else {
                let paths = self
                    .env_vars
                    .iter()
                    .find(|(key, _)| key.as_os_str() == OsStr::new("PATH"))
                    .map(|(_, value)| value.clone())
                    .or_else(|| std::env::var_os("PATH"))
                    .unwrap_or_default();
                which::which_in(path, Some(paths), &self.cwd).ok()
            }
        };

        // Helper to add a named file/program by to the package.
        // We ignore the case where the file doesn't exist, as we don't need it.
        let add_named_prog =
            |builder: &mut pkg::ToolchainPackageBuilder, name: &str| -> Result<()> {
                if let Some(path) = named_file("prog", name) {
                    builder.add_executable_and_deps(path)?;
                }
                Ok(())
            };
        let add_named_file =
            |builder: &mut pkg::ToolchainPackageBuilder, name: &str| -> Result<()> {
                if let Some(path) = named_file("file", name) {
                    builder.add_file(path)?;
                }
                Ok(())
            };

        // Add basic |as| and |objcopy| programs.
        add_named_prog(&mut package_builder, "as")?;
        add_named_prog(&mut package_builder, "objcopy")?;

        // Linker configuration.
        if Path::new("/etc/ld.so.conf").is_file() {
            package_builder.add_file("/etc/ld.so.conf".into())?;
        }
        let ld_conf_dir = Path::new("/etc/ld.so.conf.d");
        if ld_conf_dir.is_dir() {
            package_builder.add_dir_contents(ld_conf_dir)?;
        }

        // Compiler-specific handling
        match self.kind {
            CCompilerKind::Clang => {
                // Clang uses internal header files, so add them.
                if let Some(limits_h) = named_file("file", "include/limits.h") {
                    info!("limits_h = {}", limits_h.display());
                    let include_dir = limits_h
                        .parent()
                        .context("clang builtin limits.h path has no parent directory")?;
                    package_builder.add_dir_contents(include_dir)?;
                }
            }

            CCompilerKind::Gcc => {
                // Various external programs / files which may be needed by gcc
                add_named_prog(&mut package_builder, "ld")?;
                add_named_prog(&mut package_builder, "collect2")?;
                add_named_prog(&mut package_builder, "lto-wrapper")?;
                add_named_prog(&mut package_builder, "lto1")?;
                add_named_prog(&mut package_builder, "cc1")?;
                add_named_prog(&mut package_builder, "cc1plus")?;
                add_named_file(&mut package_builder, "specs")?;
                add_named_file(&mut package_builder, "liblto_plugin.so")?;
            }

            CCompilerKind::Cicc
            | CCompilerKind::CudaFE
            | CCompilerKind::Ptxas
            | CCompilerKind::Nvcc => {}

            CCompilerKind::Nvhpc => {
                // Various programs called by the nvc nvc++ front end.
                add_named_file(&mut package_builder, "cpp1")?;
                add_named_file(&mut package_builder, "cpp2")?;
                add_named_file(&mut package_builder, "opt")?;
                add_named_prog(&mut package_builder, "llc")?;
                add_named_prog(&mut package_builder, "acclnk")?;
            }

            CCompilerKind::Diab | CCompilerKind::Msvc | CCompilerKind::TaskingVX => {
                bail!(
                    "distributed toolchain packaging is not implemented for {:?}",
                    self.kind
                );
            }
        }

        // Bundle into a compressed tarfile.
        Ok(package_builder)
    }
}

pub(super) const INPUT_FILE_NAME_DOMAIN: &[u8] = b"c-input-file-name-v1";

/// The file name of `input` to put in the hash key, if any.
///
/// The inputs of nvcc's device-code steps are its own temporaries, named after
/// the source, and identical device code from different sources is meant to be
/// shared.
/// The exact directory emitted as debug compilation metadata, after the
/// compiler's last matching prefix-map rule. Worktrees may safely share C/C++
/// objects without debug information or when their debug directories map to
/// the same path, but not when emitted `DW_AT_comp_dir` would differ.
///
/// The original (not previously transformed) path is tested against each
/// mapping, with the last match winning; both GCC and Clang use this order.
/// These switches select a debugging information level on GCC/Clang.
/// Modifiers such as `-gcolumn-info`, `-gz`, and `-gstrict-dwarf` do not
/// enable it by themselves; treating every `-g*` option as an enabler would
/// unnecessarily partition cache entries for ordinary optimized builds.
fn enables_debug_information(arg: &[u8]) -> bool {
    matches!(
        arg,
        b"-g" | b"-ggdb" | b"-gline-tables-only" | b"-gmlt" | b"-gmodules" | b"-gcodeview"
    ) || matches!(
        arg,
        b"-g1" | b"-g2" | b"-g3" | b"-ggdb1" | b"-ggdb2" | b"-ggdb3"
    ) || arg.starts_with(b"-gdwarf-")
}

fn effective_debug_compilation_dir(cwd: &Path, args: &[OsString]) -> Option<Vec<u8>> {
    let mut debug_enabled = false;
    let mut clang_debug_forced = false;
    let mut clang_frontend_next = false;
    let mut explicit_directory = None;
    let mut maps = Vec::new();
    let mut args = args.iter().map(|arg| arg.as_encoded_bytes());
    while let Some(arg) = args.next() {
        // `-Xclang -debug-info-kind=limited` enables DWARF without `-g`.
        // It is forwarded directly to Clang's frontend, independently of the
        // driver's -g option order. Do not confuse it with a regular option.
        if arg == b"-Xclang" {
            clang_frontend_next = true;
            continue;
        }
        if std::mem::take(&mut clang_frontend_next) {
            if let Some(kind) = arg.strip_prefix(b"-debug-info-kind=") {
                clang_debug_forced = kind != b"none";
            }
            if let Some(path) = arg.strip_prefix(b"-fdebug-compilation-dir=") {
                explicit_directory = Some(path.to_vec());
            }
            // Frontend options can also contain normal debug prefix mappings.
            // Apply them through the same last-match rule below.
        }
        if matches!(arg, b"-g0" | b"-ggdb0") {
            debug_enabled = false;
        } else if enables_debug_information(arg) {
            debug_enabled = true;
        }
        if let Some(path) = arg.strip_prefix(b"-fdebug-compilation-dir=") {
            explicit_directory = Some(path.to_vec());
        } else if arg == b"-fdebug-compilation-dir" {
            explicit_directory = args.next().map(<[u8]>::to_vec);
        }
        for option in [b"-fdebug-prefix-map=".as_slice(), b"-ffile-prefix-map="] {
            if let Some(mapping) = arg.strip_prefix(option)
                && let Some(separator) = mapping.iter().position(|&byte| byte == b'=')
            {
                maps.push((
                    mapping[..separator].to_vec(),
                    mapping[separator + 1..].to_vec(),
                ));
            }
        }
    }
    if !(debug_enabled || clang_debug_forced) {
        return None;
    }
    let original =
        explicit_directory.unwrap_or_else(|| cwd.as_os_str().as_encoded_bytes().to_vec());
    let mut effective = original.clone();
    for (from, to) in maps {
        if original.starts_with(&from) {
            effective = to;
            effective.extend_from_slice(&original[from.len()..]);
        }
    }
    Some(effective)
}

pub(super) fn hashed_input_file_name(language: Language, input: &Path) -> Option<&OsStr> {
    match language {
        Language::CudaFE | Language::Ptx | Language::Cubin => None,
        _ => input.file_name(),
    }
}

/// The cache is versioned by the inputs to `HashKeyParams::compute`.
pub const CACHE_VERSION: &[u8] = b"15";

/// Environment variables that are factored into the cache key.
static CACHED_ENV_VARS: LazyLock<HashSet<&'static OsStr>> = LazyLock::new(|| {
    [
        // SCCACHE_C_CUSTOM_CACHE_BUSTER has no particular meaning behind it,
        // serving as a way for the user to factor custom data into the hash.
        // One can set it to different values for different invocations
        // to prevent cache reuse between them.
        "SCCACHE_C_CUSTOM_CACHE_BUSTER",
        "MACOSX_DEPLOYMENT_TARGET",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "TVOS_DEPLOYMENT_TARGET",
        "WATCHOS_DEPLOYMENT_TARGET",
        "SDKROOT",
        "CCC_OVERRIDE_OPTIONS",
    ]
    .iter()
    .map(OsStr::new)
    .collect()
});

/// Feed normalized compiler arguments into the digest with unambiguous boundaries.
///
/// C compiler argv may contain non-UTF-8 bytes, including 0xff on Unix.
/// A one-byte separator therefore aliases a single argument containing that
/// byte with two distinct arguments. Frame both count and byte lengths.
pub fn hash_arguments(m: &mut Digest, arguments: &[OsString], basedirs: &[Vec<u8>]) {
    m.delimiter(b"c-argv-v1");
    m.update(&(arguments.len() as u128).to_le_bytes());
    for arg in arguments {
        let normalized = strip_basedirs_from_arg(arg.as_encoded_bytes(), basedirs);
        hash_length_prefixed(m, &normalized);
    }
}

/// Distinguish length and payload even when arbitrary, non-UTF8 bytes occur.
pub(super) fn hash_length_prefixed(m: &mut Digest, bytes: &[u8]) {
    m.update(&(bytes.len() as u128).to_le_bytes());
    m.update(bytes);
}

/// Preserve the identity and cardinality of auxiliary inputs separately from
/// the optional external assembler. They may coincidentally have equal digests.
pub(super) fn hash_auxiliary_inputs(
    m: &mut Digest,
    extra_hashes: &[String],
    assembler_digest: Option<&str>,
) {
    m.delimiter(b"c-auxiliary-inputs-v1");
    m.update(&(extra_hashes.len() as u128).to_le_bytes());
    for hash in extra_hashes {
        hash_length_prefixed(m, hash.as_bytes());
    }
    if let Some(digest) = assembler_digest {
        m.update(&[1]);
        hash_length_prefixed(m, digest.as_bytes());
    } else {
        m.update(&[0]);
    }
}

/// A source filename is embedded in some C objects but not in others.
/// Keep presence distinct from the next hash field, even for empty names.
pub(super) fn hash_input_file_name_marker(m: &mut Digest, present: bool) {
    m.delimiter(INPUT_FILE_NAME_DOMAIN);
    m.update(&[u8::from(present)]);
}

/// Hash only the declared compiler environment dependencies, preserving
/// ordering, duplicates, field boundaries and arbitrary OS string bytes.
pub(super) fn hash_cached_env_vars(
    m: &mut Digest,
    env_vars: &[(OsString, OsString)],
    dependencies: &HashSet<&'static OsStr>,
) {
    m.delimiter(b"c-cached-env-v1");
    let count = env_vars
        .iter()
        .filter(|(name, _)| dependencies.contains(name.as_os_str()))
        .count();
    m.update(&(count as u128).to_le_bytes());
    for (name, value) in env_vars {
        if dependencies.contains(name.as_os_str()) {
            hash_length_prefixed(m, name.as_encoded_bytes());
            hash_length_prefixed(m, value.as_encoded_bytes());
        }
    }
}

/// Parameters for computing a hash key for C/C++ compilation caching.
///
/// Construct with required fields via [`HashKeyParams::new`], then add optional
/// fields with builder methods.
///
/// # Example
/// ```ignore
/// let hash = HashKeyParams::new(
///     "abc123",          // compiler_digest
///     Language::C,        // language
///     &args,             // arguments
///     output             // preprocessor_output
/// )
/// .with_extra_hashes(&extra)
/// .with_plusplus(true)
/// .compute();
/// ```
#[derive(Debug, Clone)]
pub struct HashKeyParams<'a> {
    compiler_digest: &'a str,
    language: Language,
    arguments: &'a [OsString],
    extra_hashes: &'a [String],
    env_vars: &'a [(OsString, OsString)],
    preprocessor_output: &'a [u8],
    plusplus: bool,
    basedirs: &'a [Vec<u8>],
    assembler_digest: Option<&'a str>,
    input_file_name: Option<&'a OsStr>,
    debug_compilation_dir: Option<&'a [u8]>,
}

impl<'a> HashKeyParams<'a> {
    /// Creates a new hash key parameter set with required fields.
    ///
    /// Optional fields have default values and can be set via `with_*` methods.
    ///
    /// # Arguments
    /// * `compiler_digest` - Hash of the compiler executable
    /// * `language` - Source language being compiled
    /// * `arguments` - Compiler arguments
    /// * `preprocessor_output` - Preprocessed source to hash
    pub const fn new(
        compiler_digest: &'a str,
        language: Language,
        arguments: &'a [OsString],
        preprocessor_output: &'a [u8],
    ) -> Self {
        Self {
            compiler_digest,
            language,
            arguments,
            preprocessor_output,
            extra_hashes: &[],
            env_vars: &[],
            plusplus: false,
            basedirs: &[],
            assembler_digest: None,
            input_file_name: None,
            debug_compilation_dir: None,
        }
    }

    /// Sets additional hash data to include in the cache key.
    pub const fn with_extra_hashes(mut self, extra_hashes: &'a [String]) -> Self {
        self.extra_hashes = extra_hashes;
        self
    }

    /// Sets the environment variables to consider for caching.
    pub const fn with_env_vars(mut self, env_vars: &'a [(OsString, OsString)]) -> Self {
        self.env_vars = env_vars;
        self
    }

    /// Sets whether this is a C++ compiler (affects clang/clang++ distinction).
    pub const fn with_plusplus(mut self, plusplus: bool) -> Self {
        self.plusplus = plusplus;
        self
    }

    /// Sets the base directories for path normalization.
    pub const fn with_basedirs(mut self, basedirs: &'a [Vec<u8>]) -> Self {
        self.basedirs = basedirs;
        self
    }

    /// Sets the identity of the assembler the compiler will run, if any.
    pub const fn with_assembler_digest(mut self, assembler_digest: Option<&'a str>) -> Self {
        self.assembler_digest = assembler_digest;
        self
    }

    /// Sets the file name, without its directory, of the source being compiled.
    pub const fn with_input_file_name(mut self, input_file_name: Option<&'a OsStr>) -> Self {
        self.input_file_name = input_file_name;
        self
    }

    /// Adds the effective debug compilation directory when debug metadata
    /// includes one. Omitting it preserves nondebug cache identity.
    pub const fn with_debug_compilation_dir(mut self, directory: Option<&'a [u8]>) -> Self {
        self.debug_compilation_dir = directory;
        self
    }

    /// Computes the hash key based on the configured parameters.
    ///
    /// If `basedirs` are provided, paths in the preprocessor output will be normalized by
    /// stripping the longest matching basedir prefix. This enables cache hits across different
    /// absolute paths (similar to ccache's `CCACHE_BASEDIR`).
    ///
    /// # Note
    /// If you change any of the inputs to the hash, you should change `CACHE_VERSION`.
    pub fn compute(&self) -> String {
        let mut m = Digest::new();
        m.update(self.compiler_digest.as_bytes());
        // clang and clang++ have different behavior despite being byte-for-byte identical binaries, so
        // we have to incorporate that into the hash as well.
        m.update(&[u8::from(self.plusplus)]);
        m.update(CACHE_VERSION);
        m.update(self.language.as_str().as_bytes());
        hash_arguments(&mut m, self.arguments, self.basedirs);
        hash_auxiliary_inputs(&mut m, self.extra_hashes, self.assembler_digest);
        // The compiler writes the source's file name into the object (the
        // STT_FILE symbol on ELF), and -P leaves it out of the preprocessed
        // output, so two sources that preprocess the same would share an
        // object naming only one of them. The directory is left out: the
        // symbol does not record it, and keeping it would cost cache hits
        // across checkouts.
        hash_input_file_name_marker(&mut m, self.input_file_name.is_some());
        if let Some(input_file_name) = self.input_file_name {
            hash_length_prefixed(&mut m, input_file_name.as_encoded_bytes());
        }

        hash_cached_env_vars(&mut m, self.env_vars, &CACHED_ENV_VARS);

        // Version only the debug-dependent keys: objects without debug data
        // retain their existing cache identity, while old unsafe debug hits
        // cannot alias the additional domain and directory payload.
        if let Some(dir) = self.debug_compilation_dir {
            m.delimiter(b"c-effective-debug-compdir-v1");
            hash_length_prefixed(&mut m, dir);
        }

        // Strip basedirs from preprocessor output if configured
        let preprocessor_output_to_hash = strip_basedirs(self.preprocessor_output, self.basedirs);

        m.update(&preprocessor_output_to_hash);
        m.finish()
    }
}

#[cfg(test)]
mod test {
    use std::{collections::VecDeque, sync::Mutex};

    use super::*;
    use crate::mock_command::*;
    use crate::test::utils::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn cargo_native_paths_reuse_real_compiler_keys_and_preserve_depfiles() -> Result<()> {
        use crate::compiler::gcc::Gcc;
        use crate::test::mock_storage::MockStorage;
        use std::sync::Arc;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()?;
        let compiler_path = which::which("g++")?;
        let version = std::process::Command::new(&compiler_path)
            .arg("-dumpfullversion")
            .output()?;
        let version = String::from_utf8(version.stdout)?.trim().to_owned();
        let compiler = Gcc {
            gplusplus: true,
            version: Some(version),
            assembler_digest: Some("same-assembler".into()),
        };
        let creator = <ProcessCommandCreator as CommandCreatorSync>::new(
            &crate::jobserver::Client::new_num(2),
        );
        let storage = Arc::new(MockStorage::new(None, true));
        let work = tempfile::tempdir()?;

        for (name, source) in [
            (
                "test.cc",
                b"extern \"C\" const char *name() { return __FILE__; }\nextern \"C\" const char *base() { return __BASE_FILE__; }\n".as_slice(),
            ),
            (
                "test.S",
                b".text\n.globl native_cargo_test\nnative_cargo_test:\n ret\n".as_slice(),
            ),
        ] {
            let mut first = None;
            for (session, fingerprint) in [("first", "package-a"), ("second", "package-b")] {
                let tree = work.path().join(session);
                let out = tree.join("debug/build").join(fingerprint).join("out");
                let cwd = out.join("cmake");
                std::fs::create_dir_all(&cwd)?;
                std::fs::write(tree.join("CACHEDIR.TAG"), b"")?;
                let input = out.join(name);
                std::fs::write(&input, source)?;
                let object = cwd.join("result.o");
                let depfile = cwd.join("result.d");
                let env: Vec<_> = std::env::vars_os()
                    .filter(|(key, _)| key != "OUT_DIR" && key != "SCCACHE_CANONICAL_TARGET_ROOT")
                    .chain([
                        ("OUT_DIR".into(), out.into_os_string()),
                        ("SCCACHE_CANONICAL_TARGET_ROOT".into(), work.path().join("target").into_os_string()),
                    ])
                    .collect();
                let arguments = vec![
                    "-g".into(),
                    "-O2".into(),
                    "-MMD".into(),
                    "-MF".into(),
                    depfile.as_os_str().into(),
                    "-c".into(),
                    input.as_os_str().into(),
                    "-o".into(),
                    object.as_os_str().into(),
                ];
                let CompilerArguments::Ok(parsed_args) =
                    compiler.parse_arguments(&arguments, &cwd, &env)
                else {
                    bail!("real compiler invocation was rejected");
                };
                let mut hasher = CCompilerHasher {
                    parsed_args,
                    executable: compiler_path.clone(),
                    executable_digest: "same-compiler".into(),
                    compiler: compiler.clone(),
                };
                let hash = runtime.block_on(
                    <CCompilerHasher<Gcc> as CompilerHasher<ProcessCommandCreator>>::generate_hash_key(
                        &mut hasher,
                        GenerateHashKeyContext {
                            creator: &creator,
                            cwd: cwd.clone(),
                            env_vars: env,
                            may_dist: true,
                            pool: runtime.handle(),
                            rewrite_includes_only: false,
                            storage: storage.clone(),
                            cache_control: CacheControl::Default,
                        },
                    ),
                )?;
                assert!(hash.compilation.is_locally_preprocessed());
                let deps = std::fs::read_to_string(&depfile)?;
                assert!(deps.contains(input.to_str().context("UTF-8 input")?));
                assert!(!deps.contains("/__sccache/"));
                let (command, remote, _) =
                    hash.compilation.generate_compile_commands(&mut dist::PathTransformer::new(), CompileTransport::Archive { rewrite_includes_only: false })?;
                #[cfg(feature = "dist-client")]
                assert!(remote.context("distributed command")?.arguments.iter().any(|arg| arg.starts_with("-ffile-prefix-map=")));
                #[cfg(not(feature = "dist-client"))]
                let _ = remote;
                assert!(command.get_arguments().iter().any(|arg| arg.as_encoded_bytes().starts_with(b"-ffile-prefix-map=")));
                let output = std::process::Command::new(command.get_executable())
                    .args(command.get_arguments())
                    .env_clear()
                    .envs(command.get_env_vars())
                    .current_dir(command.get_cwd())
                    .output()?;
                assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
                let bytes = std::fs::read(&object)?;
                if let Some((expected_key, expected_object)) = &first {
                    assert_eq!(&hash.key, expected_key, "cache key differed for {name}");
                    assert_eq!(&bytes, expected_object, "object differed for {name}");
                } else {
                    first = Some((hash.key, bytes));
                }
            }
        }
        Ok(())
    }

    fn native_parsed_arguments() -> ParsedArguments {
        ParsedArguments {
            input: "foo.c".into(),
            double_dash_input: false,
            language: Language::C,
            compilation_flag: "-c".into(),
            depfile: None,
            outputs: HashMap::new(),
            dependency_args: vec![],
            preprocessor_args: vec![],
            common_args: ovec!["-march=native"],
            arch_args: vec![],
            unhashed_args: vec![],
            extra_dist_files: vec![],
            extra_hash_files: vec![],
            uses_external_assembler: false,
            msvc_show_includes: false,
            msvc_explicit_language: false,
            profile_generate: false,
            color_mode: ColorMode::Auto,
            suppress_rewrite_includes_only: false,
            too_hard_for_preprocessor_cache_mode: None,
        }
    }

    fn assembler_parsed_arguments(preprocessor_args: Vec<OsString>) -> ParsedArguments {
        let mut args = native_parsed_arguments();
        args.language = Language::AssemblerToPreprocess;
        args.common_args.clear();
        args.preprocessor_args = preprocessor_args;
        args
    }

    #[test]
    #[cfg(feature = "dist-client")]
    fn test_dist_input_packager_preserves_parent_path_resolution() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("arch/arm64/kvm")).unwrap();
        std::fs::create_dir_all(root.join("virt/kvm")).unwrap();
        std::fs::write(
            root.join("virt/kvm/eventfd.c"),
            b"int f(void) { return 0; }\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("asm/a/b")).unwrap();
        std::fs::write(root.join("asm/blob.bin"), b"blob").unwrap();

        let input_path = root.join("arch/arm64/kvm/../../../virt/kvm/eventfd.c");
        let extra_input_path = root.join("asm/a/b/../../blob.bin");
        let mut path_transformer = dist::PathTransformer::new();
        path_transformer.add_root_mapping(root.to_owned(), "/work");
        let packager = CInputsPackager {
            input_path,
            path_transformer,
            preprocessed_input: b"int f(void) { return 0; }\n".to_vec(),
            extra_dist_files: Vec::new(),
            extra_hash_files: vec![extra_input_path],
        };
        let mut package = Vec::new();
        pkg::InputsPackager::write_inputs(Box::new(packager), &mut package).unwrap();

        let mut archive = tar::Archive::new(std::io::Cursor::new(&package));
        let paths: std::collections::BTreeSet<_> = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned())
            .collect();
        assert_eq!(
            paths,
            std::collections::BTreeSet::from([
                PathBuf::from("work/arch"),
                PathBuf::from("work/arch/arm64"),
                PathBuf::from("work/arch/arm64/kvm"),
                PathBuf::from("work/virt/kvm/eventfd.c"),
                PathBuf::from("work/asm/a"),
                PathBuf::from("work/asm/a/b"),
                PathBuf::from("work/asm/blob.bin"),
            ])
        );
        assert!(paths.iter().all(|path| {
            !path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        }));

        let worker_root = tempfile::tempdir().unwrap();
        let mut archive = tar::Archive::new(std::io::Cursor::new(package));
        archive.unpack(worker_root.path()).unwrap();
        let worker_input = worker_root
            .path()
            .join("work/arch/arm64/kvm/../../../virt/kvm/eventfd.c");
        assert_eq!(
            std::fs::read(worker_input).unwrap(),
            b"int f(void) { return 0; }\n"
        );
        let worker_extra = worker_root.path().join("work/asm/a/b/../../blob.bin");
        assert_eq!(std::fs::read(worker_extra).unwrap(), b"blob");
    }

    #[cfg(all(feature = "dist-client", feature = "native-store", target_os = "linux"))]
    #[test]
    fn native_c_input_mapping_preserves_generated_content_and_lexical_paths() -> Result<()> {
        use crate::build_runtime::NativeStore;
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("source");
        std::fs::create_dir_all(root.join("empty/deep"))?;
        std::fs::write(root.join("source.c"), b"#include \"header.h\"")?;
        std::fs::write(root.join("data.bin"), b"binary dependency")?;
        let mut transformer = dist::PathTransformer::new();
        transformer.add_root_mapping(root.clone(), "/work");
        let packager = CInputsPackager {
            input_path: root.join("empty/deep/../../source.c"),
            path_transformer: transformer,
            preprocessed_input: b"int f(void) { return 42; }".to_vec(),
            extra_dist_files: vec![root.join("empty/../data.bin")],
            extra_hash_files: Vec::new(),
        };
        let store = NativeStore::open(&temp.path().join("store"))?;
        let tree = pkg::InputsPackager::native_mapping(Box::new(packager))?
            .prepare()?
            .import(&store)?;
        let view = tree.materialize(temp.path())?;
        assert_eq!(
            std::fs::read(view.root().join("work/empty/deep/../../source.c"))?,
            b"int f(void) { return 42; }"
        );
        assert_eq!(
            std::fs::read(view.root().join("work/empty/../data.bin"))?,
            b"binary dependency"
        );
        Ok(())
    }

    #[test]
    fn test_assembler_dependency_statement_boundaries() {
        assert!(assembler_dependencies_in(b"opts.include = 1;\n").is_empty());
        assert!(assembler_dependencies_in(b"x = y.incbin + 1;\n").is_empty());
        assert!(assembler_dependencies_in(b"cfg->opts.incbin(path);\n").is_empty());
        assert!(assembler_dependencies_in(b".incbinary \"blob.bin\"\n").is_empty());

        assert_eq!(
            assembler_dependencies_in(b"nop;.incbin \"blob.bin\"\n"),
            vec![AssemblerDependency::File(
                AssemblerFileDirective::Incbin,
                PathBuf::from("blob.bin")
            )]
        );
        assert_eq!(
            assembler_dependencies_in(b"payload:.incbin \"blob.bin\"\n"),
            vec![AssemblerDependency::File(
                AssemblerFileDirective::Incbin,
                PathBuf::from("blob.bin")
            )]
        );
        assert_eq!(
            assembler_dependencies_in(b"__asm__(\".incbin \\\"blob.bin\\\"\");\n"),
            vec![AssemblerDependency::File(
                AssemblerFileDirective::Incbin,
                PathBuf::from("blob.bin")
            )]
        );
        for line_break in [b"\\n".as_slice(), b"\\012".as_slice(), b"\\x0a".as_slice()] {
            let mut source = b"\"nop".to_vec();
            source.extend_from_slice(line_break);
            source.extend_from_slice(b".incbin \\\"blob.bin\\\"\"");
            assert_eq!(
                assembler_dependencies_in(&source),
                vec![AssemblerDependency::File(
                    AssemblerFileDirective::Incbin,
                    PathBuf::from("blob.bin")
                )]
            );
        }
    }

    #[test]
    fn test_inline_assembler_dependency_classifier_ignores_ordinary_c_strings() {
        assert!(!contains_inline_assembler_file_directive(
            b"const char *fmt = \".include %s\";"
        ));
        assert!(!contains_inline_assembler_file_directive(
            b"log(\".incbin \\\"blob.bin\\\"\");"
        ));
        assert!(!contains_inline_assembler_file_directive(
            b"struct opts { int include; }; opts.include = 1;"
        ));

        assert!(contains_inline_assembler_file_directive(
            b"__asm__(\".incbin \\\"blob.bin\\\"\");"
        ));
        assert!(contains_inline_assembler_file_directive(
            b"asm volatile (\"nop\\n.incbin \\\"blob.bin\\\"\" : : : \"memory\");"
        ));
        assert!(contains_inline_assembler_file_directive(
            b"__asm__ goto (\".include \\\"inner.s\\\"\" : : : : target);"
        ));
    }

    #[test]
    fn test_assembler_dependency_unparsable_is_not_silently_ignored() {
        for source in [
            b".incbin BLOB_PATH\n".as_slice(),
            b".include MACRO_PATH\n".as_slice(),
            b".incbin \"\"\n".as_slice(),
            b".incbin \"unterminated\n".as_slice(),
        ] {
            assert_eq!(
                assembler_dependencies_in(source),
                vec![AssemblerDependency::Unparsable]
            );
        }
    }

    #[test]
    fn test_assembler_dependency_scan_resolves_cwd_include_path_and_nested_include() {
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().join("cwd");
        let include = temp.path().join("include");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&include).unwrap();

        std::fs::write(cwd.join("same.bin"), b"cwd").unwrap();
        std::fs::write(include.join("same.bin"), b"include").unwrap();
        std::fs::write(include.join("nested.bin"), b"nested").unwrap();
        std::fs::write(include.join("inner.s"), b"\t.incbin \"nested.bin\"\n").unwrap();

        let args =
            assembler_parsed_arguments(vec![OsString::from(format!("-I{}", include.display()))]);
        assert_eq!(
            assembler_file_dependencies(
                b"\t.incbin \"same.bin\"\n\t.include \"inner.s\"\n",
                &cwd,
                &args,
            ),
            AssemblerDependencyScan::Complete(vec![
                cwd.join("same.bin"),
                include.join("inner.s"),
                include.join("nested.bin"),
            ])
        );
    }

    #[test]
    fn test_assembler_dependency_include_dirs_support_driver_forms_and_reject_mixed_order() {
        let cwd = Path::new("/work");
        let mut args = assembler_parsed_arguments(Vec::new());
        args.common_args = ovec!["-Wa,-I,wa", "-Xassembler", "-Ixa"];
        assert_eq!(
            assembler_dependency_include_dirs(&args, cwd).unwrap(),
            vec![cwd.join("wa"), cwd.join("xa")]
        );

        args.preprocessor_args = ovec!["-Icpp"];
        assert!(assembler_dependency_include_dirs(&args, cwd).is_err());
    }

    #[test]
    fn test_assembler_dependency_scan_rejects_unresolved_or_dynamic_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let args = assembler_parsed_arguments(Vec::new());

        assert!(matches!(
            assembler_file_dependencies(b".incbin \"missing.bin\"\n", temp.path(), &args),
            AssemblerDependencyScan::Incomplete(_)
        ));
        assert!(matches!(
            assembler_file_dependencies(b".incbin BLOB_PATH\n", temp.path(), &args),
            AssemblerDependencyScan::Incomplete(_)
        ));
    }

    #[test]
    fn test_native_driver_replacement_preserves_complete_cpu_state() -> Result<()> {
        let native = ovec!["-march=native", "-mtune=native"];
        let gcc = native_driver_replacement(
            "/usr/lib/gcc/cc1 -march=znver2 -mavx2 -mno-avx512f -mno-xsaves -mtune=znver2 --param l1-cache-size=32",
            CCompilerKind::Gcc,
            &native,
        )?;
        assert_eq!(
            gcc,
            ovec![
                "-march=znver2",
                "-mavx2",
                "-mno-avx512f",
                "-mno-xsaves",
                "-mtune=znver2",
                "--param",
                "l1-cache-size=32",
            ]
        );
        let gcc_tune = native_driver_replacement(
            "/usr/lib/gcc/cc1 -mtune=znver2 -march=x86-64",
            CCompilerKind::Gcc,
            &[OsString::from("-mtune=native")],
        )?;
        assert_eq!(gcc_tune, ovec!["-mtune=znver2", "-march=x86-64"]);
        let clang = native_driver_replacement(
            "\"/usr/bin/clang\" \"-cc1\" \"-target-cpu\" \"znver2\" \"-tune-cpu\" \"znver2\" \"-target-feature\" \"+avx2\" \"-target-feature\" \"-xsaves\"",
            CCompilerKind::Clang,
            &native,
        )?;
        assert_eq!(
            clang,
            ovec![
                "-march=znver2",
                "-mtune=znver2",
                "-Xclang",
                "-target-feature",
                "-Xclang",
                "+avx2",
                "-Xclang",
                "-target-feature",
                "-Xclang",
                "-xsaves",
            ]
        );
        assert!(
            native_driver_replacement(
                "/usr/lib/gcc/cc1 -march=native",
                CCompilerKind::Gcc,
                &native,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    #[cfg(feature = "dist-client")]
    fn test_native_codegen_is_lowered_for_worker_not_local_compiler() -> Result<()> {
        let mut parsed_args = native_parsed_arguments();
        parsed_args.common_args = ovec!["-march=native", "-mno-avx2", "-mtune=native"];
        parsed_args.outputs.insert(
            "obj",
            ArtifactDescriptor {
                path: "foo.o".into(),
                optional: false,
            },
        );
        let resolution = NativeCodegenResolution {
            fingerprint: "test-native".to_owned(),
            explicit_args: ovec!["-march=znver2", "-mno-avx2", "-mno-xsaves", "-mtune=znver2"],
        };
        let mut transformer = dist::PathTransformer::new();
        let (local, remote, _) = crate::compiler::gcc::generate_compile_commands(
            CCompileContext {
                path_transformer: &mut transformer,
                executable: Path::new("/usr/bin/gcc"),
                parsed_args: &parsed_args,
                cwd: Path::new("/work"),
                env_vars: &[],
                rewrite_includes_only: false,
                native_resolution: Some(&resolution),
            },
            CCompilerKind::Gcc,
            crate::compiler::gcc::language_to_gcc_arg,
        )?;
        assert!(local.arguments.contains(&OsString::from("-march=native")));
        let remote_args = remote
            .context("expected explicit distributed native target")?
            .arguments;
        let arch = remote_args
            .iter()
            .position(|arg| arg == "-march=znver2")
            .context("resolved CPU missing")?;
        assert_eq!(
            &remote_args[arch..arch + 4],
            ["-march=znver2", "-mno-avx2", "-mno-xsaves", "-mtune=znver2"]
        );
        assert!(!remote_args.iter().any(|arg| arg.ends_with("=native")));
        Ok(())
    }

    #[test]
    #[cfg(feature = "dist-client")]
    fn test_clang_native_codegen_is_lowered_for_worker() -> Result<()> {
        let mut parsed_args = native_parsed_arguments();
        parsed_args.outputs.insert(
            "obj",
            ArtifactDescriptor {
                path: "foo.o".into(),
                optional: false,
            },
        );
        let resolution = NativeCodegenResolution {
            fingerprint: "clang-native".to_owned(),
            explicit_args: ovec![
                "-march=znver2",
                "-Xclang",
                "-target-feature",
                "-Xclang",
                "-xsaves"
            ],
        };
        let mut transformer = dist::PathTransformer::new();
        let (local, remote, _) = crate::compiler::gcc::generate_compile_commands(
            CCompileContext {
                path_transformer: &mut transformer,
                executable: Path::new("/usr/bin/clang"),
                parsed_args: &parsed_args,
                cwd: Path::new("/work"),
                env_vars: &[],
                rewrite_includes_only: false,
                native_resolution: Some(&resolution),
            },
            CCompilerKind::Clang,
            crate::compiler::clang::language_to_clang_arg,
        )?;
        assert!(local.arguments.contains(&OsString::from("-march=native")));
        let arguments = remote
            .context("expected distributed native Clang job")?
            .arguments;
        assert!(arguments.iter().any(|arg| arg == "-march=znver2"));
        assert!(
            arguments
                .windows(4)
                .any(|args| { args == ["-Xclang", "-target-feature", "-Xclang", "-xsaves"] })
        );
        assert!(!arguments.iter().any(|arg| arg.ends_with("=native")));
        Ok(())
    }

    #[test]
    fn test_native_codegen_probe_respects_cxx_language_and_options() -> Result<()> {
        let mut parsed = native_parsed_arguments();
        parsed.language = Language::Cxx;
        parsed.common_args.push(OsString::from("-std=c++20"));
        let creator = new_creator();
        next_command_calls(&creator, |args| {
            assert!(args.windows(2).any(|pair| pair == ["-x", "c++"]));
            assert!(args.iter().any(|arg| arg == "-std=c++20"));
            assert!(args.iter().any(|arg| arg == "-march=native"));
            Ok(MockChild::new(
                exit_status(0),
                "",
                "/usr/lib/gcc/cc1plus -march=znver2 -mtune=znver2 -std=c++20",
            ))
        });
        let result = single_threaded_runtime().block_on(native_codegen_resolution(
            &creator,
            Path::new("/usr/bin/g++"),
            &parsed,
            Path::new("/project"),
            &[],
            CCompilerKind::Gcc,
        ))?;
        assert!(result.is_some());
        assert_eq!(native_probe_language(Language::CxxModule), "c++");
        assert_eq!(
            native_probe_language(Language::ObjectiveCxx),
            "objective-c++"
        );
        assert_eq!(native_probe_language(Language::ObjectiveC), "objective-c");
        assert_eq!(native_probe_language(Language::AssemblerToPreprocess), "c");
        assert!(native_driver_args(" cc1obj -march=znver2 -mtune=znver2").is_ok());
        assert!(native_driver_args(" cc1objplus -march=znver2 -mtune=znver2").is_ok());
        assert!(is_native_driver_frontend(r"C:\gcc\libexec\cc1plus.exe"));
        Ok(())
    }

    #[test]
    fn test_native_codegen_fingerprint_tracks_effective_cpu_state() {
        fn fingerprint(driver_line: &str) -> String {
            let creator = new_creator();
            next_command(
                &creator,
                Ok(MockChild::new(exit_status(0), "", driver_line)),
            );
            single_threaded_runtime()
                .block_on(native_codegen_resolution(
                    &creator,
                    Path::new("/usr/bin/cc"),
                    &native_parsed_arguments(),
                    Path::new("/project"),
                    &[],
                    CCompilerKind::Gcc,
                ))
                .unwrap()
                .unwrap()
                .fingerprint
        }

        let znver2 = fingerprint(r"/usr/lib/gcc/cc1 -march=znver2 -mtune=znver2");
        let znver2_again = fingerprint(r"/usr/lib/gcc/cc1 -march=znver2 -mtune=znver2");
        let skylake = fingerprint(r"/usr/lib/gcc/cc1 -march=skylake -mtune=skylake");

        assert_eq!(znver2, znver2_again);
        assert_ne!(znver2, skylake);
        // Debug compilation directories can affect emitted DW_AT_comp_dir even
        // when preprocessing output and CPU ISA are otherwise identical.
        assert_ne!(
            znver2,
            fingerprint(
                "/usr/lib/gcc/cc1 -march=znver2 -mtune=znver2 -fdebug-compilation-dir=/other/worktree"
            )
        );
        // Conversely, an effective ISA change must never alias the cache.
        assert_ne!(
            znver2,
            fingerprint("/usr/lib/gcc/cc1 -march=znver2 -mtune=znver2 -mno-avx2")
        );
    }

    #[test]
    fn test_native_codegen_fingerprint_rejects_unresolved_driver() {
        for driver_line in [
            r"/usr/lib/gcc/cc1 -march=native",
            r"/usr/bin/clang -cc1 -target-cpu native",
        ] {
            let creator = new_creator();
            next_command(
                &creator,
                Ok(MockChild::new(exit_status(0), "", driver_line)),
            );
            let result = single_threaded_runtime().block_on(native_codegen_resolution(
                &creator,
                Path::new("/usr/bin/cc"),
                &native_parsed_arguments(),
                Path::new("/project"),
                &[],
                CCompilerKind::Gcc,
            ));
            assert!(
                result.is_err(),
                "unresolved driver line must not be cacheable: {driver_line}"
            );
        }
    }

    #[test]
    fn debug_compilation_directory_respects_effective_debug_options_and_prefix_maps() {
        let cwd = Path::new("/build/a");
        let effective = |args: Vec<OsString>| effective_debug_compilation_dir(cwd, &args);
        assert_eq!(effective(ovec![]), None);
        assert_eq!(effective(ovec!["-g", "-g0"]), None);
        assert_eq!(effective(ovec!["-ggdb0"]), None);
        assert_eq!(effective(ovec!["-gsplit-dwarf"]), None);
        for option in [
            "-gstrict-dwarf",
            "-gcolumn-info",
            "-gz",
            "-gpubnames",
            "-grecord-gcc-switches",
            "-gcc-toolchain=/path",
        ] {
            assert_eq!(
                effective(ovec![option]),
                None,
                "{option} alone must not emit DWARF"
            );
        }
        assert_eq!(effective(ovec!["-gdwarf-5"]), Some(b"/build/a".to_vec()));
        assert_eq!(effective(ovec!["-gmodules"]), Some(b"/build/a".to_vec()));
        assert_eq!(
            effective(ovec!["-Xclang", "-debug-info-kind=limited"]),
            Some(b"/build/a".to_vec())
        );
        assert_eq!(
            effective(ovec!["-Xclang", "-debug-info-kind=line-tables-only"]),
            Some(b"/build/a".to_vec())
        );
        assert_eq!(effective(ovec!["-Xclang", "-debug-info-kind=none"]), None);
        assert_eq!(
            effective(ovec![
                "-Xclang",
                "-debug-info-kind=limited",
                "-Xclang",
                "-debug-info-kind=none"
            ]),
            None
        );
        assert_eq!(
            effective(ovec![
                "-Xclang",
                "-debug-info-kind=limited",
                "-Xclang",
                "-fdebug-compilation-dir=/fixed"
            ]),
            Some(b"/fixed".to_vec())
        );
        assert_eq!(
            effective(ovec![
                "-g",
                "-Xclang",
                "-fdebug-prefix-map=/build/a=/mapped"
            ]),
            Some(b"/mapped".to_vec())
        );
        assert_eq!(
            effective(ovec!["-Xclang", "-debug-info-kind=limited", "-g0"]),
            Some(b"/build/a".to_vec())
        );
        assert_eq!(effective(ovec!["-g0", "-g"]), Some(b"/build/a".to_vec()));
        assert_eq!(
            effective(ovec!["-gline-tables-only"]),
            Some(b"/build/a".to_vec())
        );
        assert_eq!(
            effective(ovec!["-g", "-fdebug-compilation-dir=/stable"]),
            Some(b"/stable".to_vec())
        );
        assert_eq!(
            effective(ovec!["-g", "-fdebug-compilation-dir", "."]),
            Some(b".".to_vec())
        );
        assert_eq!(
            effective(ovec!["-g", "-fdebug-prefix-map=/build/a=/stable"]),
            Some(b"/stable".to_vec())
        );
        assert_eq!(
            effective(ovec!["-g", "-ffile-prefix-map=/build/a=/stable"]),
            Some(b"/stable".to_vec())
        );
        assert_eq!(
            effective(ovec!["-g", "-fdebug-prefix-map=/build=/virtual"]),
            Some(b"/virtual/a".to_vec())
        );
        assert_eq!(
            effective(ovec![
                "-g",
                "-fdebug-prefix-map=/build=/one",
                "-fdebug-prefix-map=/build/a=/two"
            ]),
            Some(b"/two".to_vec())
        );
        assert_eq!(
            effective(ovec![
                "-g",
                "-fdebug-prefix-map=/build/a=/two",
                "-fdebug-prefix-map=/build=/one"
            ]),
            Some(b"/one/a".to_vec())
        );
    }

    #[test]
    fn gcc_and_clang_parsers_retain_debug_path_options_for_cache_identity() {
        let arguments = ovec![
            "-g",
            "-fdebug-prefix-map=/build/a=/virtual",
            "-c",
            "probe.c",
            "-o",
            "probe.o"
        ];
        for (kind, parsed_result) in [
            (
                CCompilerKind::Gcc,
                crate::compiler::gcc::parse_arguments(
                    &arguments,
                    Path::new("/build/a"),
                    &crate::compiler::gcc::ARGS[..],
                    false,
                    CCompilerKind::Gcc,
                ),
            ),
            (
                CCompilerKind::Clang,
                crate::compiler::gcc::parse_arguments(
                    &arguments,
                    Path::new("/build/a"),
                    (
                        &crate::compiler::gcc::ARGS[..],
                        &crate::compiler::clang::ARGS[..],
                    ),
                    false,
                    CCompilerKind::Clang,
                ),
            ),
        ] {
            let parsed = match parsed_result {
                CompilerArguments::Ok(args) => args,
                other => panic!("{kind:?} failed to recognize a debug-path mapping: {other:?}"),
            };
            let mut flags = parsed.common_args;
            flags.extend(parsed.arch_args);
            assert_eq!(
                effective_debug_compilation_dir(Path::new("/build/a"), &flags),
                Some(b"/virtual".to_vec()),
            );
        }
    }

    #[test]
    fn debug_compilation_directory_changes_only_debug_dependent_cache_keys() {
        let args = ovec!["-g"];
        let key = |directory: Option<&[u8]>| {
            HashKeyParams::new("cc", Language::C, &args, b"same-preprocessed-source")
                .with_debug_compilation_dir(directory)
                .compute()
        };
        assert_ne!(key(Some(b"/build/a")), key(Some(b"/build/b")));
        assert_eq!(key(Some(b"/virtual")), key(Some(b"/virtual")));
        assert_eq!(
            key(None),
            HashKeyParams::new("cc", Language::C, &args, b"same-preprocessed-source").compute(),
        );
    }

    #[test]
    fn test_same_content() {
        let args = ovec!["a", "b", "c"];
        let h1 = HashKeyParams::new("abcd", Language::C, &args, b"hello world").compute();
        let h2 = HashKeyParams::new("abcd", Language::C, &args, b"hello world").compute();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_plusplus_differs() {
        let args = ovec!["a", "b", "c"];
        let h1 = HashKeyParams::new("abcd", Language::C, &args, b"hello world").compute();
        let h2 = HashKeyParams::new("abcd", Language::C, &args, b"hello world")
            .with_plusplus(true)
            .compute();
        assert_neq!(h1, h2);
    }

    #[test]
    fn test_assembler_digest_differs() {
        let args = ovec!["a", "b", "c"];
        let h1 = HashKeyParams::new("abcd", Language::C, &args, b"hello world").compute();
        let h2 = HashKeyParams::new("abcd", Language::C, &args, b"hello world")
            .with_assembler_digest(Some("abcd"))
            .compute();
        let h3 = HashKeyParams::new("abcd", Language::C, &args, b"hello world")
            .with_assembler_digest(Some("efgh"))
            .compute();
        assert_neq!(h1, h2);
        assert_neq!(h2, h3);
        // Not knowing the assembler must keep the key the compiler alone would give,
        // so that caches predating assembler tracking stay usable.
        let h4 = HashKeyParams::new("abcd", Language::C, &args, b"hello world")
            .with_assembler_digest(None)
            .compute();
        assert_eq!(h1, h4);
    }

    #[test]
    fn test_input_file_name_differs() {
        let args = ovec!["a", "b", "c"];
        let hash_for = |input: &str| {
            HashKeyParams::new("abcd", Language::C, &args, b"")
                .with_input_file_name(Path::new(input).file_name())
                .compute()
        };
        assert_neq!(hash_for("alpha.c"), hash_for("beta.c"));
        assert_eq!(hash_for("alpha.c"), hash_for("src/alpha.c"));
        assert_eq!(hash_for("/a/alpha.c"), hash_for("/b/alpha.c"));
    }

    #[test]
    fn test_device_code_input_file_name_ignored() {
        let args = ovec!["a", "b", "c"];
        let hash_for = |language: Language, input: &str| {
            HashKeyParams::new("abcd", language, &args, b"device code")
                .with_input_file_name(hashed_input_file_name(language, Path::new(input)))
                .compute()
        };
        // nvcc names the inputs of its device-code steps after the source, so
        // two sources with the same device code must still share these entries.
        assert_eq!(
            hash_for(Language::CudaFE, "alpha.cpp1.ii"),
            hash_for(Language::CudaFE, "beta.cpp1.ii")
        );
        assert_eq!(
            hash_for(Language::Ptx, "alpha.cpp1.ii"),
            hash_for(Language::Ptx, "beta.cpp1.ii")
        );
        assert_eq!(
            hash_for(Language::Cubin, "alpha.ptx"),
            hash_for(Language::Cubin, "beta.ptx")
        );
        // Everything else keeps the file name in the key.
        assert_neq!(
            hash_for(Language::C, "alpha.c"),
            hash_for(Language::C, "beta.c")
        );
        assert_neq!(
            hash_for(Language::Cuda, "alpha.cu"),
            hash_for(Language::Cuda, "beta.cu")
        );
    }

    #[test]
    fn test_header_differs() {
        let args = ovec!["a", "b", "c"];
        let h1 = HashKeyParams::new("abcd", Language::C, &args, b"hello world").compute();
        let h2 = HashKeyParams::new("abcd", Language::CHeader, &args, b"hello world").compute();
        assert_neq!(h1, h2);
    }

    #[test]
    fn test_plusplus_header_differs() {
        let args = ovec!["a", "b", "c"];
        let h1 = HashKeyParams::new("abcd", Language::Cxx, &args, b"hello world")
            .with_plusplus(true)
            .compute();
        let h2 = HashKeyParams::new("abcd", Language::CxxHeader, &args, b"hello world")
            .with_plusplus(true)
            .compute();
        assert_neq!(h1, h2);
    }

    #[test]
    fn test_hash_key_executable_contents_differs() {
        let args = ovec!["a", "b", "c"];
        let h1 = HashKeyParams::new("abcd", Language::C, &args, b"hello world").compute();
        let h2 = HashKeyParams::new("wxyz", Language::C, &args, b"hello world").compute();
        assert_neq!(h1, h2);
    }

    #[test]
    fn test_hash_key_args_differs() {
        let abc = ovec!["a", "b", "c"];
        let xyz = ovec!["x", "y", "z"];
        let ab = ovec!["a", "b"];
        let a = ovec!["a"];

        let h_abc = HashKeyParams::new("abcd", Language::C, &abc, b"hello world").compute();
        let h_xyz = HashKeyParams::new("abcd", Language::C, &xyz, b"hello world").compute();
        let h_ab = HashKeyParams::new("abcd", Language::C, &ab, b"hello world").compute();
        let h_a = HashKeyParams::new("abcd", Language::C, &a, b"hello world").compute();

        assert_neq!(h_abc, h_xyz);
        assert_neq!(h_abc, h_ab);
        assert_neq!(h_abc, h_a);
    }

    #[test]
    fn test_destination_cpu_flags_partition_c_cache() {
        let key = |args: &[&str]| {
            let arguments: Vec<_> = args.iter().map(OsString::from).collect();
            HashKeyParams::new(
                "gcc-toolchain-digest",
                Language::C,
                &arguments,
                b"same preprocessed C source",
            )
            .compute()
        };
        let v2 = key(&["-O3", "-march=x86-64-v2"]);
        let v4 = key(&["-O3", "-march=x86-64-v4"]);
        assert_ne!(v2, v4, "effective GCC -march must partition C cache");
        assert_eq!(v2, key(&["-O3", "-march=x86-64-v2"]));
    }

    #[cfg(unix)]
    #[test]
    fn test_hash_key_non_unicode_argument_boundaries() {
        use std::os::unix::ffi::OsStringExt as _;

        let merged = [OsString::from_vec(b"-DVALUE=a\xff-DOTHER=b".to_vec())];
        let split = [OsString::from("-DVALUE=a"), OsString::from("-DOTHER=b")];
        let old_hash = |args: &[OsString]| {
            let mut digest = Digest::new();
            for arg in args {
                digest.update(arg.as_encoded_bytes());
                digest.update(&[0xff]);
            }
            digest.finish()
        };
        assert_eq!(old_hash(&merged), old_hash(&split));

        let key = |args: &[OsString]| {
            HashKeyParams::new("compiler", Language::C, args, b"same preprocessed content")
                .compute()
        };
        assert_ne!(key(&merged), key(&split));
    }

    #[test]
    fn test_hash_key_separates_auxiliary_hashes_from_external_assembler() {
        let compiler_args = [OsString::from("-c")];
        let digest = "1234567890abcdef".repeat(4);
        let hashes = [digest.clone()];
        // The former raw-concatenation scheme cannot tell these apart:
        // a single extra input and the same digest for the assembler.
        let mut old_extra = Digest::new();
        old_extra.update(digest.as_bytes());
        let mut old_assembler = Digest::new();
        old_assembler.update(digest.as_bytes());
        assert_eq!(old_extra.finish(), old_assembler.finish());

        let extra = HashKeyParams::new("compiler", Language::C, &compiler_args, b"input")
            .with_extra_hashes(&hashes)
            .compute();
        let assembler = HashKeyParams::new("compiler", Language::C, &compiler_args, b"input")
            .with_assembler_digest(Some(&digest))
            .compute();
        assert_ne!(extra, assembler);
    }

    #[cfg(unix)]
    #[test]
    fn test_hash_key_environment_field_boundaries() {
        use std::os::unix::ffi::OsStringExt as _;

        let name = OsString::from("SCCACHE_C_CUSTOM_CACHE_BUSTER");
        let other = OsString::from("MACOSX_DEPLOYMENT_TARGET");
        let collapsed = [(
            name.clone(),
            OsString::from_vec(b"a\xffMACOSX_DEPLOYMENT_TARGET\xff=b".to_vec()),
        )];
        let split = [(name, OsString::from("a")), (other, OsString::from("b"))];
        let args = [OsString::from("-c")];
        let key = |env: &[(OsString, OsString)]| {
            HashKeyParams::new("compiler", Language::C, &args, b"input")
                .with_env_vars(env)
                .compute()
        };
        assert_ne!(key(&collapsed), key(&split));
    }

    #[test]
    fn test_hash_key_preprocessed_content_differs() {
        let args = ovec!["a", "b", "c"];
        let h1 = HashKeyParams::new("abcd", Language::C, &args, b"hello world").compute();
        let h2 = HashKeyParams::new("abcd", Language::C, &args, b"goodbye").compute();
        assert_neq!(h1, h2);
    }

    #[test]
    fn test_hash_key_env_var_differs() {
        let args = ovec!["a", "b", "c"];
        for var in CACHED_ENV_VARS.iter() {
            let h1 = HashKeyParams::new("abcd", Language::C, &args, b"hello world").compute();

            let vars1 = vec![(OsString::from(var), OsString::from("something"))];
            let h2 = HashKeyParams::new("abcd", Language::C, &args, b"hello world")
                .with_env_vars(&vars1)
                .compute();

            let vars2 = vec![(OsString::from(var), OsString::from("something else"))];
            let h3 = HashKeyParams::new("abcd", Language::C, &args, b"hello world")
                .with_env_vars(&vars2)
                .compute();

            assert_neq!(h1, h2);
            assert_neq!(h2, h3);
        }
    }

    #[test]
    fn test_extra_hash_data() {
        let args = ovec!["a", "b", "c"];
        let extra_data = stringvec!["hello", "world"];

        let h1 = HashKeyParams::new("abcd", Language::C, &args, b"hello world")
            .with_extra_hashes(&extra_data)
            .compute();
        let h2 = HashKeyParams::new("abcd", Language::C, &args, b"hello world").compute();

        assert_neq!(h1, h2);
    }

    #[test]
    fn test_hash_key_basedirs() {
        let args = ovec!["a", "b", "c"];
        let preprocessed1 = b"# 1 \"/home/user1/project/src/main.c\"\nint main() { return 0; }";
        let preprocessed2 = b"# 1 \"/home/user2/project/src/main.c\"\nint main() { return 0; }";
        let basedirs = [
            b"/home/user1/project".to_vec(),
            b"/home/user2/project".to_vec(),
        ];

        // Helper to compute with basedirs
        let hash_with_basedirs = |output: &[u8], dirs: &[Vec<u8>]| {
            HashKeyParams::new("abcd", Language::C, &args, output)
                .with_basedirs(dirs)
                .compute()
        };

        // Test 1: Same hash with different absolute paths when basedir is used
        let h1 = hash_with_basedirs(preprocessed1, &basedirs);
        let h2 = hash_with_basedirs(preprocessed2, &basedirs);
        assert_eq!(h1, h2);

        // Test 2: Same hash with single basedir that matches each
        assert_eq!(
            hash_with_basedirs(preprocessed1, &basedirs[..1]),
            hash_with_basedirs(preprocessed2, &basedirs[1..])
        );

        // Test 3: Different hashes without basedir
        assert_neq!(
            HashKeyParams::new("abcd", Language::C, &args, preprocessed1).compute(),
            HashKeyParams::new("abcd", Language::C, &args, preprocessed2).compute()
        );

        // Test 4: Works for C++ files too
        let preprocessed_cpp1 =
            b"# 1 \"/home/user1/project/src/main.cpp\"\nint main() { return 0; }";
        let preprocessed_cpp2 =
            b"# 1 \"/home/user2/project/src/main.cpp\"\nint main() { return 0; }";
        let h_cpp1 = HashKeyParams::new("abcd", Language::Cxx, &args, preprocessed_cpp1)
            .with_plusplus(true)
            .with_basedirs(&basedirs)
            .compute();
        let h_cpp2 = HashKeyParams::new("abcd", Language::Cxx, &args, preprocessed_cpp2)
            .with_plusplus(true)
            .with_basedirs(&basedirs)
            .compute();
        assert_eq!(h_cpp1, h_cpp2);

        // Test 5: Doesn't work with trailing slash in basedir, they must be normalized in config
        let basedir_slash = b"/home/user1/project/".to_vec();
        let h_slash = hash_with_basedirs(preprocessed1, std::slice::from_ref(&basedir_slash));
        assert_neq!(h1, h_slash);

        // Test 6: Multiple basedirs - longest match wins
        let multi_basedirs = vec![
            b"/home/user1".to_vec(),
            b"/home/user1/project".to_vec(), // This should match (longest)
        ];
        assert_eq!(h1, hash_with_basedirs(preprocessed1, &multi_basedirs));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_hash_key_basedirs_windows_escaped_backslashes() {
        // On Windows, paths in preprocessor output are C string literals with
        // escaped backslashes (e.g. MSVC: #line 1 "D:\\dir\\file.c", clang:
        // # 1 "D:\\dir\\file.c"). The same source compiled from two different
        // directories must produce the same hash when both are basedirs.
        let args = ovec!["a", "b", "c"];
        let preprocessed1 =
            b"#line 1 \"D:\\\\dev\\\\user1\\\\project\\\\src\\\\main.c\"\nint main() { return 0; }";
        let preprocessed2 =
            b"#line 1 \"E:\\\\work\\\\user2\\\\checkout\\\\src\\\\main.c\"\nint main() { return 0; }";
        // As normalized by Config: lowercase, forward slashes, trailing slash
        let basedirs = [
            b"d:/dev/user1/project/".to_vec(),
            b"e:/work/user2/checkout/".to_vec(),
        ];

        let hash_with_basedirs = |output: &[u8], dirs: &[Vec<u8>]| {
            HashKeyParams::new("abcd", Language::C, &args, output)
                .with_basedirs(dirs)
                .compute()
        };

        // Same hash with different absolute (escaped backslash) paths
        let h1 = hash_with_basedirs(preprocessed1, &basedirs);
        let h2 = hash_with_basedirs(preprocessed2, &basedirs);
        assert_eq!(h1, h2);

        // Different hashes without basedirs
        assert_neq!(
            HashKeyParams::new("abcd", Language::C, &args, preprocessed1).compute(),
            HashKeyParams::new("abcd", Language::C, &args, preprocessed2).compute()
        );
    }

    #[test]
    fn test_language_from_file_name() {
        fn t(extension: &str, expected: Language) {
            let path_str = format!("input.{extension}");
            let path = Path::new(&path_str);
            let actual = Language::from_file_name(path);
            assert_eq!(actual, Some(expected));
        }

        t("s", Language::Assembler);
        t("S", Language::AssemblerToPreprocess);
        t("sx", Language::AssemblerToPreprocess);

        t("c", Language::C);

        t("i", Language::CPreprocessed);

        t("C", Language::Cxx);
        t("cc", Language::Cxx);
        t("cp", Language::Cxx);
        t("cpp", Language::Cxx);
        t("CPP", Language::Cxx);
        t("cxx", Language::Cxx);
        t("c++", Language::Cxx);

        t("ii", Language::CxxPreprocessed);

        t("h", Language::GenericHeader);

        t("hh", Language::CxxHeader);
        t("H", Language::CxxHeader);
        t("hp", Language::CxxHeader);
        t("hxx", Language::CxxHeader);
        t("hpp", Language::CxxHeader);
        t("HPP", Language::CxxHeader);
        t("h++", Language::CxxHeader);
        t("tcc", Language::CxxHeader);

        t("m", Language::ObjectiveC);

        t("mi", Language::ObjectiveCPreprocessed);

        t("M", Language::ObjectiveCxx);
        t("mm", Language::ObjectiveCxx);

        t("mii", Language::ObjectiveCxxPreprocessed);

        t("cu", Language::Cuda);
        t("hip", Language::Hip);
    }

    #[test]
    fn test_language_from_file_name_none() {
        fn t(extension: &str) {
            let path_str = format!("input.{extension}");
            let path = Path::new(&path_str);
            let actual = Language::from_file_name(path);
            let expected = None;
            assert_eq!(actual, expected);
        }

        // gcc parses file-extensions as case-sensitive
        t("Cp");
        t("Cpp");
        t("Hp");
        t("Hpp");
        t("Mm");
        t("Cu");
    }

    #[test]
    fn test_process_preprocessed_file() {
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init()
            .ok();
        let input_file = Path::new("tests/test.c");
        let path = Path::new(file!())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        // This should be portable since the only headers present in this
        // output are system headers, which aren't interacted with
        // on the filesystem if configured.
        let path = path.join("tests/test.c.gcc-13.2.0-preproc");
        let mut bytes = std::fs::read(path).unwrap();
        let original_bytes = bytes.clone();
        let mut include_files = HashMap::new();

        let config = PreprocessorCacheModeConfig {
            use_preprocessor_cache_mode: true,
            skip_system_headers: true,
            ..Default::default()
        };
        let success = process_preprocessed_file(
            input_file,
            Path::new(""),
            &mut bytes,
            &mut include_files,
            config,
            std::time::SystemTime::now(),
            &StandardFsAbstraction,
        )
        .unwrap();
        assert_eq!(&bytes, &original_bytes);
        assert!(success);
        assert_eq!(include_files.len(), 0);
    }

    #[test]
    fn test_process_preprocessed_file_disables_cache_for_compressed_offload_bundle() {
        let input_file = Path::new("tests/test.hip");
        let mut bytes = b"CCOB\0\0\0\0\n# 1karg compressed payload".to_vec();
        let original_bytes = bytes.clone();
        let mut include_files = HashMap::new();

        let config = PreprocessorCacheModeConfig {
            use_preprocessor_cache_mode: true,
            ..Default::default()
        };
        let success = process_preprocessed_file(
            input_file,
            Path::new(""),
            &mut bytes,
            &mut include_files,
            config,
            std::time::SystemTime::now(),
            &PanicFs,
        )
        .unwrap();

        assert_eq!(bytes, original_bytes);
        assert!(!success);
        assert!(include_files.is_empty());
    }

    #[test]
    fn test_process_preprocessed_file_line_directive() {
        let header = PathBuf::from("tests/test.h");
        let fs_impl = TestFs {
            metadata_results: Mutex::new(
                [(
                    header.clone(),
                    PreprocessorFileMetadata {
                        is_dir: false,
                        is_file: true,
                        modified: Some(Timestamp::new(12_341_234, 0)),
                        ctime_or_creation: None,
                    },
                )]
                .into_iter()
                .collect(),
            ),
            open_results: Mutex::new(
                [(
                    header.clone(),
                    Box::new(&b"contents"[..]) as Box<dyn std::io::Read>,
                )]
                .into_iter()
                .collect(),
            ),
        };
        let mut bytes = br#"#line 1 "tests/test.h"
int value;
"#
        .to_vec();
        let mut include_files = HashMap::new();

        let success = process_preprocessed_file(
            Path::new("tests/test.c"),
            Path::new(""),
            &mut bytes,
            &mut include_files,
            PreprocessorCacheModeConfig::activated(),
            std::time::SystemTime::now(),
            &fs_impl,
        )
        .unwrap();

        assert!(success);
        assert_eq!(
            include_files.get(&header).map(String::as_str),
            Some("a93900c371d997927c5bc568ea538bed59ae5c960021dcfe7b0b369da5267528")
        );
    }

    /// A filesystem interface that only panics to test that we don't access it.
    struct PanicFs;

    impl PreprocessorFSAbstraction for PanicFs {
        fn metadata(&self, path: impl AsRef<Path>) -> io::Result<PreprocessorFileMetadata> {
            panic!("called metadata at {}", path.as_ref().display());
        }

        fn open(&self, path: impl AsRef<Path>) -> io::Result<Box<dyn std::io::Read>> {
            panic!("called open at {}", path.as_ref().display());
        }
    }

    /// A filesystem interface that gives back expected values.
    struct TestFs {
        metadata_results: Mutex<VecDeque<(PathBuf, PreprocessorFileMetadata)>>,
        open_results: Mutex<VecDeque<(PathBuf, Box<dyn std::io::Read>)>>,
    }

    impl PreprocessorFSAbstraction for TestFs {
        fn metadata(&self, path: impl AsRef<Path>) -> io::Result<PreprocessorFileMetadata> {
            let (expected_path, meta) = self
                .metadata_results
                .lock()
                .unwrap()
                .pop_front()
                .expect("not enough 'metadata' results");
            assert_eq!(expected_path, path.as_ref(), "{}", path.as_ref().display());
            Ok(meta)
        }

        fn open(&self, path: impl AsRef<Path>) -> io::Result<Box<dyn std::io::Read>> {
            let (expected_path, impls_read) = self
                .open_results
                .lock()
                .unwrap()
                .pop_front()
                .expect("not enough 'open' results");
            assert_eq!(expected_path, path.as_ref(), "{}", path.as_ref().display());
            Ok(impls_read)
        }
    }

    // Short-circuit the parameters we don't need to change during tests
    fn do_single_preprocessor_line_call(
        line: &[u8],
        include_files: &mut HashMap<PathBuf, String>,
        fs_impl: &impl PreprocessorFSAbstraction,
        skip_system_headers: bool,
    ) -> PreprocessedLineAction {
        let input_file = Path::new("tests/test.c");

        let config = PreprocessorCacheModeConfig {
            use_preprocessor_cache_mode: true,
            skip_system_headers,
            ..Default::default()
        };

        let mut bytes = line.to_vec();
        let mut digest = Digest::new();
        let mut normalized_include_paths = HashMap::new();
        process_preprocessor_line(
            PreprocessorLineContext {
                input_file,
                cwd: Path::new(""),
                included_files: include_files,
                config,
                time_of_compilation: std::time::SystemTime::now(),
                bytes: &mut bytes,
                digest: &mut digest,
                normalized_include_paths: &mut normalized_include_paths,
                fs_impl,
            },
            0,
            0,
        )
        .unwrap()
    }

    /// Test cases where we don't access the filesystem
    #[test]
    fn test_process_preprocessor_line_simple() {
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init()
            .ok();

        let mut include_files = HashMap::new();
        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 0 "tests/test.c""#,
                &mut include_files,
                &PanicFs,
                true,
            ),
            ControlFlow::Continue((20, 20)),
        );
        assert_eq!(include_files.len(), 0);

        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 0 "<built-in>""#,
                &mut include_files,
                &PanicFs,
                true,
            ),
            ControlFlow::Continue((18, 18)),
        );
        assert_eq!(include_files.len(), 0);

        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 0 "<command-line>""#,
                &mut include_files,
                &PanicFs,
                true,
            ),
            ControlFlow::Continue((22, 22)),
        );
        assert_eq!(include_files.len(), 0);

        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 0 "<command-line>" 2"#,
                &mut include_files,
                &PanicFs,
                true,
            ),
            ControlFlow::Continue((22, 22)),
        );
        assert_eq!(include_files.len(), 0);

        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 1 "tests/test.c""#,
                &mut include_files,
                &PanicFs,
                true,
            ),
            ControlFlow::Continue((20, 20)),
        );
        assert_eq!(include_files.len(), 0);

        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 1 "/usr/include/stdc-predef.h" 1 3 4"#,
                &mut include_files,
                &PanicFs,
                true,
            ),
            ControlFlow::Continue((34, 34)),
        );
        assert_eq!(include_files.len(), 0);
    }

    /// Test cases where we test our tests...
    #[test]
    fn test_test_helpers() {
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init()
            .ok();

        // Test PanicFs
        let res = std::panic::catch_unwind(|| {
            let mut include_files = HashMap::new();
            assert_eq!(
                do_single_preprocessor_line_call(
                    br#"// # 1 "/usr/include/stdc-predef.h" 1 3 4"#,
                    &mut include_files,
                    &PanicFs,
                    false,
                ),
                ControlFlow::Continue((34, 34)),
            );
        });
        assert_eq!(
            res.unwrap_err().downcast_ref::<String>().unwrap(),
            "called metadata at /usr/include/stdc-predef.h"
        );

        // Test TestFs's safeguard
        let res = std::panic::catch_unwind(|| {
            let mut include_files = HashMap::new();
            let fs_impl = TestFs {
                metadata_results: Mutex::new(VecDeque::new()),
                open_results: Mutex::new(VecDeque::new()),
            };
            assert_eq!(
                do_single_preprocessor_line_call(
                    br#"// # 33 "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h" 3 4"#,
                    &mut include_files,
                    &fs_impl,
                    false,
                ),
                ControlFlow::Continue((34, 34)),
            );
        });
        assert_eq!(
            res.unwrap_err().downcast_ref::<String>().unwrap(),
            "not enough 'metadata' results"
        );
    }

    /// Test cases where we test filesystem access
    #[test]
    fn test_process_preprocessor_line_fs_access() {
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init()
            .ok();

        // Test "too new" include file
        let mut include_files = HashMap::new();
        let fs_impl = TestFs {
            metadata_results: Mutex::new(
                [(
                    PathBuf::from("/usr/include/x86_64-linux-gnu/bits/libc-header-start.h"),
                    PreprocessorFileMetadata {
                        is_dir: false,
                        is_file: true,
                        modified: Some(Timestamp::new(i64::MAX - 1, 0)),
                        ctime_or_creation: None,
                    },
                )]
                .into_iter()
                .collect(),
            ),
            open_results: Mutex::new(VecDeque::new()),
        };
        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 33 "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h" 3 4"#,
                &mut include_files,
                &fs_impl,
                false,
            ),
            // preprocessor cache mode is disabled
            ControlFlow::Break((63, 9, false)),
        );

        // Test invalid include file is actually a dir
        let mut include_files = HashMap::new();
        let fs_impl = TestFs {
            metadata_results: Mutex::new(
                [(
                    PathBuf::from("/usr/include/x86_64-linux-gnu/bits/libc-header-start.h"),
                    PreprocessorFileMetadata {
                        is_dir: true,
                        is_file: false,
                        modified: Some(Timestamp::new(12_341_234, 0)),
                        ctime_or_creation: None,
                    },
                )]
                .into_iter()
                .collect(),
            ),
            open_results: Mutex::new(VecDeque::new()),
        };
        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 33 "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h" 3 4"#,
                &mut include_files,
                &fs_impl,
                false,
            ),
            // preprocessor cache mode is *not* disabled,
            ControlFlow::Continue((63, 63)),
        );
        assert_eq!(include_files.len(), 0);

        // Test correct include file
        let mut include_files = HashMap::new();
        let fs_impl = TestFs {
            metadata_results: Mutex::new(
                [(
                    PathBuf::from("/usr/include/x86_64-linux-gnu/bits/libc-header-start.h"),
                    PreprocessorFileMetadata {
                        is_dir: false,
                        is_file: true,
                        modified: Some(Timestamp::new(12_341_234, 0)),
                        ctime_or_creation: None,
                    },
                )]
                .into_iter()
                .collect(),
            ),
            open_results: Mutex::new(
                [(
                    PathBuf::from("/usr/include/x86_64-linux-gnu/bits/libc-header-start.h"),
                    Box::new(&b"contents"[..]) as Box<dyn std::io::Read>,
                )]
                .into_iter()
                .collect(),
            ),
        };
        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 33 "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h" 3 4"#,
                &mut include_files,
                &fs_impl,
                false,
            ),
            ControlFlow::Continue((63, 63)),
        );
        assert_eq!(include_files.len(), 1);
        assert_eq!(
            include_files
                .get(Path::new(
                    "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h",
                ))
                .unwrap(),
            // hash of `b"contents"`
            "a93900c371d997927c5bc568ea538bed59ae5c960021dcfe7b0b369da5267528",
        );
    }
}
