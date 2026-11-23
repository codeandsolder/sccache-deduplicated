// Copyright 2016 Mozilla Foundation
// SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use crate::compiler::args::{
    ArgDisposition, ArgInfo, ArgToStringResult, ArgsIter, Argument, FromArg, IntoArg,
    PathTransformerFn, SearchableArgInfo,
};
use crate::compiler::c::{ArtifactDescriptor, CCompileContext, CCompilerKind, ParsedArguments};
use crate::compiler::{
    CCompileCommand, Cacheable, ColorMode, CompileCommand, CompilerArguments, Language,
    SingleCompileCommand,
};
use crate::{counted_array, dist};

use crate::mock_command::CommandCreatorSync;

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process;

use crate::errors::{Result, anyhow};

/// A unit struct on which to implement `CCompilerImpl`.
#[derive(Clone, Debug)]
pub struct Cicc {
    pub version: Option<String>,
}

pub const CICC_INPUT_SUFFIX: &str = ".cpp1.ii";
pub const PTXAS_INPUT_SUFFIX: &str = ".ptx";

pub fn is_cicc_input(arg: impl AsRef<OsStr>) -> bool {
    arg.as_ref().to_string_lossy().ends_with(CICC_INPUT_SUFFIX)
}

pub fn is_ptxas_input(arg: impl AsRef<OsStr>) -> bool {
    arg.as_ref().to_string_lossy().ends_with(PTXAS_INPUT_SUFFIX)
}

// Three CUDA compiler frontends share the same CCompilerImpl lifecycle.
// Only their compiler kind, input syntax and output style differ. Keep the
// complete lifecycle in one place rather than duplicating trait impls.
macro_rules! impl_cuda_stage_compiler {
    ($stage:ident, $kind:expr, $language:expr, $args:expr, $offset:expr, $style:expr $(,)?) => {
        #[async_trait::async_trait]
        impl crate::compiler::c::CCompilerImpl for $stage {
            fn kind(&self) -> crate::compiler::c::CCompilerKind {
                $kind
            }
            fn plusplus(&self) -> bool {
                true
            }
            fn version(&self) -> Option<String> {
                self.version.clone()
            }
            fn parse_arguments(
                &self,
                arguments: &[std::ffi::OsString],
                cwd: &std::path::Path,
                _env_vars: &[(std::ffi::OsString, std::ffi::OsString)],
            ) -> crate::compiler::CompilerArguments<crate::compiler::c::ParsedArguments> {
                crate::compiler::cicc::parse_arguments(arguments, cwd, $language, $args, $offset)
            }
            async fn preprocess<T>(
                &self,
                context: crate::compiler::c::CPreprocessContext<'_, T>,
            ) -> crate::errors::Result<std::process::Output>
            where
                T: crate::mock_command::CommandCreatorSync,
            {
                crate::compiler::cicc::preprocess(context.cwd, context.parsed_args)
            }
            fn generate_compile_commands<T>(
                &self,
                context: crate::compiler::c::CCompileContext<'_>,
            ) -> crate::errors::Result<crate::compiler::cicc::CudaStageCompileCommands<T>>
            where
                T: crate::mock_command::CommandCreatorSync,
            {
                crate::compiler::cicc::boxed_compile_commands(context, $style)
            }
        }
    };
}
impl_cuda_stage_compiler!(
    Cicc,
    CCompilerKind::Cicc,
    Language::Ptx,
    &ARGS[..],
    3,
    OutputStyle::ObjectFile,
);

#[expect(
    clippy::too_many_lines,
    reason = "single-pass argument parser keeps interdependent flag state and ordering visible; splitting would require a state bag threaded through helpers"
)]
pub fn parse_arguments<S>(
    arguments: &[OsString],
    cwd: &Path,
    language: Language,
    arg_info: S,
    input_arg_offset_from_end: usize,
) -> CompilerArguments<ParsedArguments>
where
    S: SearchableArgInfo<ArgData>,
{
    let input_loc = match language {
        Language::Ptx => arguments.iter().position(is_cicc_input),
        Language::Cubin => arguments.iter().position(is_ptxas_input),
        _ => None,
    }
    // The expected trailing position is a fallback, not a precondition:
    // explicit PTX/CICC inputs may occur even in shorter argument lists.
    // `unwrap_or` would evaluate a potentially underflowing subtraction
    // even when an input suffix had already been located.
    .or_else(|| arguments.len().checked_sub(input_arg_offset_from_end));
    let Some((input_loc, input)) =
        input_loc.and_then(|index| arguments.get(index).map(|input| (index, input)))
    else {
        return CompilerArguments::CannotCache("missing compiler input", None);
    };

    // Borrow the source and parse the remaining options directly instead of
    // allocating a temporary Vec and cloning every option twice.
    let args = arguments[..input_loc]
        .iter()
        .chain(arguments[input_loc + 1..].iter())
        .cloned();
    let mut take_next = false;
    let mut outputs = HashMap::new();
    let mut extra_dist_files = vec![];
    let mut gen_module_id_file = false;
    let mut module_id_file_name = Option::<PathBuf>::None;

    let mut common_args = vec![];
    let mut unhashed_args = vec![];

    for arg in ArgsIter::new(args, arg_info) {
        let arg = match arg {
            Ok(arg) => arg,
            Err(error) => {
                return CompilerArguments::CannotCache("argument parse", Some(error.to_string()));
            }
        };
        let args = match arg.get_data() {
            Some(PassThrough(_)) => {
                take_next = false;
                &mut common_args
            }
            Some(Output(o)) => {
                take_next = false;
                let path = cwd.join(o);
                outputs.insert(
                    "obj",
                    ArtifactDescriptor {
                        path,
                        optional: false,
                    },
                );
                continue;
            }
            Some(GenModuleIdFileFlag) => {
                take_next = false;
                gen_module_id_file = true;
                &mut common_args
            }
            Some(ModuleIdFileName(o)) => {
                take_next = false;
                module_id_file_name = Some(cwd.join(o));
                &mut common_args
            }
            Some(UnhashedPassThrough(_)) => {
                take_next = false;
                &mut unhashed_args
            }
            Some(UnhashedOutput(o)) => {
                take_next = false;
                let path = cwd.join(o);
                if let Some(flag) = arg.flag_str() {
                    outputs.insert(
                        flag,
                        ArtifactDescriptor {
                            path,
                            optional: false,
                        },
                    );
                }
                &mut unhashed_args
            }
            None => match arg {
                Argument::Raw(ref operand) => {
                    if take_next {
                        take_next = false;
                        &mut common_args
                    } else {
                        // Device compilation handles exactly one positional
                        // input. Dropping another would change both the
                        // executed argv and the input-dependent cache key.
                        return CompilerArguments::CannotCache(
                            "unexpected positional compiler argument",
                            Some(operand.to_string_lossy().into_owned()),
                        );
                    }
                }
                Argument::UnknownFlag(ref p) => {
                    let s = p.to_string_lossy();
                    take_next = s.starts_with('-');
                    &mut common_args
                }
                _ => unreachable!(),
            },
        };
        args.extend(arg.iter_os_strings());
    }

    if let Some(module_id_path) = module_id_file_name {
        if gen_module_id_file {
            outputs.insert(
                "--module_id_file_name",
                ArtifactDescriptor {
                    path: module_id_path,
                    optional: true,
                },
            );
        } else {
            extra_dist_files.push(module_id_path);
        }
    }

    if !outputs.contains_key("obj") {
        return CompilerArguments::CannotCache("missing compiler output", None);
    }

    CompilerArguments::Ok(ParsedArguments {
        input: input.clone().into(),
        outputs,
        double_dash_input: false,
        language,
        compilation_flag: OsString::new(),
        depfile: None,
        dependency_args: vec![],
        preprocessor_args: vec![],
        common_args,
        arch_args: vec![],
        unhashed_args,
        extra_dist_files: extra_dist_files.clone(),
        extra_hash_files: extra_dist_files,
        uses_external_assembler: false,
        msvc_show_includes: false,
        profile_generate: false,
        color_mode: ColorMode::Off,
        suppress_rewrite_includes_only: false,
        too_hard_for_preprocessor_cache_mode: None,
    })
}

pub fn preprocess(cwd: &Path, parsed_args: &ParsedArguments) -> Result<process::Output> {
    // cicc and ptxas expect input to be an absolute path
    let input = if parsed_args.input.is_absolute() {
        parsed_args.input.clone()
    } else {
        cwd.join(&parsed_args.input)
    };
    std::fs::read(input)
        .map_err(anyhow::Error::new)
        .map(|s| process::Output {
            status: process::ExitStatus::default(),
            stdout: s,
            stderr: vec![],
        })
}

/// Output operands used by the CUDA device compilation stages.
/// The two forms differ only in the order and spelling of the last three arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputStyle {
    ObjectFile,
    ModuleIdFile,
}

impl OutputStyle {
    fn local_args(self, input: &Path, output: &Path) -> [OsString; 3] {
        match self {
            Self::ObjectFile => [
                input.as_os_str().to_owned(),
                "-o".into(),
                output.as_os_str().to_owned(),
            ],
            Self::ModuleIdFile => [
                "--module_id_file_name".into(),
                output.as_os_str().to_owned(),
                input.as_os_str().to_owned(),
            ],
        }
    }

    #[cfg(feature = "dist-client")]
    fn dist_args(
        self,
        transformer: &mut dist::PathTransformer,
        input: &Path,
        output: &Path,
    ) -> Option<[String; 3]> {
        match self {
            Self::ObjectFile => Some([
                transformer.as_dist(input)?,
                "-o".into(),
                transformer.as_dist(output)?,
            ]),
            Self::ModuleIdFile => Some([
                "--module_id_file_name".into(),
                transformer.as_dist(output)?,
                transformer.as_dist(input)?,
            ]),
        }
    }
}

/// Common `CCompilerImpl` result for all three CUDA device compiler stages.
pub(super) type CudaStageCompileCommands<T> = (
    Box<dyn CompileCommand<T>>,
    Option<dist::CompileCommand>,
    Cacheable,
);
/// Box a CUDA device compiler command using the frontend-specific output style.
/// The three stage adapters share path transformation and command ownership.
pub(super) fn boxed_compile_commands<T: CommandCreatorSync>(
    context: CCompileContext<'_>,
    output_style: OutputStyle,
) -> Result<CudaStageCompileCommands<T>> {
    let CCompileContext {
        path_transformer,
        executable,
        parsed_args,
        cwd,
        env_vars,
        ..
    } = context;
    generate_compile_commands(
        path_transformer,
        executable,
        parsed_args,
        cwd,
        env_vars,
        output_style,
    )
    .map(|(command, dist_command, cacheable)| {
        (CCompileCommand::boxed(command), dist_command, cacheable)
    })
}
pub fn generate_compile_commands(
    path_transformer: &mut dist::PathTransformer,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
    output_style: OutputStyle,
) -> Result<(
    SingleCompileCommand,
    Option<dist::CompileCommand>,
    Cacheable,
)> {
    // Unused arguments
    #[cfg(not(feature = "dist-client"))]
    {
        let _ = path_transformer;
    }

    let lang_str = &parsed_args.language.as_str();
    let out_file = match parsed_args.outputs.get("obj") {
        Some(obj) => &obj.path,
        None => return Err(anyhow!("Missing {lang_str:?} file output")),
    };

    let mut arguments: Vec<OsString> = vec![];
    arguments.extend_from_slice(&parsed_args.common_args);
    arguments.extend_from_slice(&parsed_args.unhashed_args);
    arguments.extend(output_style.local_args(&parsed_args.input, out_file));

    if log_enabled!(log::Level::Trace) {
        trace!(
            "[{}]: {} command: {:?}",
            out_file
                .file_name()
                .unwrap_or(out_file.as_os_str())
                .to_string_lossy(),
            executable
                .file_name()
                .unwrap_or(executable.as_os_str())
                .to_string_lossy(),
            [
                &[format!("cd {} &&", cwd.to_string_lossy())],
                &[executable.to_str().unwrap_or_default().to_string()][..],
                &dist::osstrings_to_strings(&arguments).unwrap_or_default()[..]
            ]
            .concat()
            .join(" ")
        );
    }

    let command = SingleCompileCommand {
        executable: executable.to_owned(),
        arguments,
        env_vars: env_vars.to_owned(),
        cwd: cwd.to_owned(),
        share_jobserver: false,
    };

    #[cfg(not(feature = "dist-client"))]
    let dist_command = None;
    #[cfg(feature = "dist-client")]
    let dist_command = (|| {
        let mut arguments: Vec<String> = vec![];
        arguments.extend(dist::osstrings_to_strings(&parsed_args.common_args)?);
        arguments.extend(dist::osstrings_to_strings(&parsed_args.unhashed_args)?);
        arguments.extend(output_style.dist_args(path_transformer, &parsed_args.input, out_file)?);
        Some(dist::CompileCommand {
            executable: path_transformer.as_dist(&executable.canonicalize().ok()?)?,
            arguments,
            env_vars: dist::osstring_tuples_to_strings(env_vars)?,
            cwd: path_transformer.as_dist_abs(cwd)?,
        })
    })();

    Ok((command, dist_command, Cacheable::Yes))
}

ArgData! { pub
    Output(PathBuf),
    PassThrough(OsString),
    GenModuleIdFileFlag,
    ModuleIdFileName(PathBuf),
    UnhashedPassThrough(OsString),
    UnhashedOutput(PathBuf),
}

use self::ArgData::{
    GenModuleIdFileFlag, ModuleIdFileName, Output, PassThrough, UnhashedOutput, UnhashedPassThrough,
};

counted_array!(pub static ARGS: [ArgInfo<ArgData>; _] = [
    take_arg!("--gen_c_file_name", PathBuf, Separated, UnhashedOutput),
    take_arg!("--gen_device_file_name", PathBuf, Separated, UnhashedOutput),
    flag!("--gen_module_id_file", GenModuleIdFileFlag),
    take_arg!("--include_file_name", OsString, Separated, PassThrough),
    take_arg!("--module_id_file_name", PathBuf, Separated, ModuleIdFileName),
    take_arg!("--stub_file_name", PathBuf, Separated, UnhashedOutput),
    take_arg!("-o", PathBuf, Separated, Output),
]);

#[cfg(test)]
mod test {
    use super::*;
    use crate::compiler::ptxas;

    fn os_strings(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn cuda_stage_trait_dispatch_keeps_compiler_specific_semantics() {
        use crate::compiler::c::CCompilerImpl;
        use crate::compiler::cudafe::CudaFE;
        use crate::compiler::ptxas::Ptxas;

        fn verify<C: CCompilerImpl>(
            compiler: &C,
            kind: CCompilerKind,
            language: Language,
            arguments: &[&str],
            input: &str,
            output: &str,
        ) {
            assert_eq!(compiler.kind(), kind);
            assert!(compiler.plusplus());
            assert_eq!(compiler.version().as_deref(), Some("device stage"));
            let parsed = compiler.parse_arguments(&os_strings(arguments), Path::new("."), &[]);
            let CompilerArguments::Ok(parsed) = parsed else {
                panic!("stage {kind:?} rejected valid arguments: {parsed:?}");
            };
            assert_eq!(parsed.language, language);
            assert_eq!(parsed.input, PathBuf::from(input));
            let expected_output = Path::new(".").join(output);
            assert_eq!(
                parsed
                    .outputs
                    .get("obj")
                    .map(|descriptor| descriptor.path.as_path()),
                Some(expected_output.as_path()),
            );
        }

        verify(
            &Cicc {
                version: Some("device stage".into()),
            },
            CCompilerKind::Cicc,
            Language::Ptx,
            &["kernel.cpp1.ii", "-o", "kernel.ptx"],
            "kernel.cpp1.ii",
            "kernel.ptx",
        );
        verify(
            &CudaFE {
                version: Some("device stage".into()),
            },
            CCompilerKind::CudaFE,
            Language::CudaFE,
            &[
                "--module_id_file_name",
                "kernel.module_id",
                "kernel.cpp1.ii",
            ],
            "kernel.cpp1.ii",
            "kernel.module_id",
        );
        verify(
            &Ptxas {
                version: Some("device stage".into()),
            },
            CCompilerKind::Ptxas,
            Language::Cubin,
            &["kernel.ptx", "-o=kernel.cubin"],
            "kernel.ptx",
            "kernel.cubin",
        );
    }

    #[test]
    fn cuda_output_styles_preserve_argument_order() {
        let input = Path::new("kernel.cpp1.ii");
        let output = Path::new("kernel.ptx");
        assert_eq!(
            OutputStyle::ObjectFile.local_args(input, output),
            ["kernel.cpp1.ii", "-o", "kernel.ptx"].map(OsString::from)
        );
        assert_eq!(
            OutputStyle::ModuleIdFile.local_args(input, output),
            ["--module_id_file_name", "kernel.ptx", "kernel.cpp1.ii"].map(OsString::from)
        );
    }

    #[cfg(feature = "dist-client")]
    #[test]
    fn cuda_output_styles_preserve_distributed_argument_order() {
        let root = std::env::current_dir().expect("current directory");
        let input = root.join("kernel.cpp1.ii");
        let output = root.join("kernel.ptx");
        let mut transformer = dist::PathTransformer::new();
        transformer.add_root_mapping(root, "/build");
        assert_eq!(
            OutputStyle::ObjectFile.dist_args(&mut transformer, &input, &output),
            Some([
                "/build/kernel.cpp1.ii".to_owned(),
                "-o".to_owned(),
                "/build/kernel.ptx".to_owned(),
            ])
        );
        assert_eq!(
            OutputStyle::ModuleIdFile.dist_args(&mut transformer, &input, &output),
            Some([
                "--module_id_file_name".to_owned(),
                "/build/kernel.ptx".to_owned(),
                "/build/kernel.cpp1.ii".to_owned(),
            ])
        );
    }

    #[test]
    fn test_parse_cicc_input_before_simt_only() {
        let args = os_strings(&[
            "--device-c",
            "-arch",
            "compute_80",
            "--module_id_file_name",
            "kernel.module_id",
            "kernel.cpp1.ii",
            "--simt-only",
            "-o",
            "kernel.ptx",
        ]);

        let parsed = match parse_arguments(&args, ".".as_ref(), Language::Ptx, &ARGS[..], 3) {
            CompilerArguments::Ok(parsed) => parsed,
            other => panic!("Got unexpected parse result: {other:?}"),
        };

        assert_eq!(PathBuf::from("kernel.cpp1.ii"), parsed.input);
        assert_eq!(
            Some(&ArtifactDescriptor {
                path: PathBuf::from(".").join("kernel.ptx"),
                optional: false
            }),
            parsed.outputs.get("obj")
        );
    }

    #[test]
    fn test_parse_ptxas_input_by_ptx_extension() {
        for output_args in [
            vec!["-o", "kernel.cubin"],
            vec!["-o=kernel.cubin"],
            vec!["--output-file", "kernel.cubin"],
            vec!["--output-file=kernel.cubin"],
        ] {
            let mut args = os_strings(&["-arch=sm_80", "kernel.ptx", "--some-new-flag"]);
            args.extend(os_strings(&output_args));

            let parsed =
                match parse_arguments(&args, ".".as_ref(), Language::Cubin, &ptxas::ARGS[..], 3) {
                    CompilerArguments::Ok(parsed) => parsed,
                    other => panic!("Got unexpected parse result: {other:?}"),
                };

            assert_eq!(PathBuf::from("kernel.ptx"), parsed.input);
            assert_eq!(
                Some(&ArtifactDescriptor {
                    path: PathBuf::from(".").join("kernel.cubin"),
                    optional: false
                }),
                parsed.outputs.get("obj")
            );
        }
    }

    #[test]
    fn truncated_cuda_arguments_never_select_invalid_input() {
        for (arguments, language, arg_info, offset) in [
            (os_strings(&[]), Language::Ptx, &ARGS[..], 3),
            (os_strings(&["-arch"]), Language::Cubin, &ptxas::ARGS[..], 3),
            (
                os_strings(&["--output-file=kernel.cubin", "not-a-source"]),
                Language::Cubin,
                &ptxas::ARGS[..],
                3,
            ),
            (os_strings(&[]), Language::CudaFE, &ARGS[..], 1),
        ] {
            let parsed = parse_arguments(&arguments, Path::new("."), language, arg_info, offset);
            assert!(
                matches!(parsed, CompilerArguments::CannotCache(_, _)),
                "truncated argument list unexpectedly cacheable: {arguments:?} -> {parsed:?}"
            );
        }
    }

    #[test]
    fn suffix_selected_before_fallback_even_for_short_invocations() {
        // The input suffix is authoritative; a fixed-position fallback must
        // not be evaluated eagerly when the source is already known.
        let arguments = os_strings(&["kernel.ptx", "-o=kernel.cubin"]);
        let parsed = parse_arguments(
            &arguments,
            Path::new("."),
            Language::Cubin,
            &ptxas::ARGS[..],
            3,
        );
        let CompilerArguments::Ok(parsed) = parsed else {
            panic!("short valid PTX invocation was rejected: {parsed:?}");
        };
        assert_eq!(parsed.input, PathBuf::from("kernel.ptx"));
        assert_eq!(
            parsed
                .outputs
                .get("obj")
                .map(|output| output.path.as_path()),
            Some(Path::new("./kernel.cubin"))
        );
    }

    #[test]
    fn malformed_cuda_flags_and_missing_outputs_are_not_cacheable() {
        let trailing_missing_value =
            os_strings(&["kernel.ptx", "--output-file=kernel.cubin", "-arch"]);
        assert!(matches!(
            parse_arguments(
                &trailing_missing_value,
                Path::new("."),
                Language::Cubin,
                &ptxas::ARGS[..],
                3
            ),
            CompilerArguments::CannotCache("argument parse", Some(_))
        ));

        for (arguments, language, arg_info, offset) in [
            (
                os_strings(&["kernel.ptx"]),
                Language::Cubin,
                &ptxas::ARGS[..],
                3,
            ),
            (
                os_strings(&["kernel.cpp1.ii", "--gen_module_id_file"]),
                Language::Ptx,
                &ARGS[..],
                3,
            ),
        ] {
            assert!(matches!(
                parse_arguments(&arguments, Path::new("."), language, arg_info, offset),
                CompilerArguments::CannotCache("missing compiler output", None)
            ));
        }
    }

    #[test]
    fn additional_positional_cuda_inputs_cannot_disappear_from_cache_keys() {
        for (arguments, language, arg_info) in [
            (
                os_strings(&["kernel.ptx", "second.ptx", "-o=kernel.cubin"]),
                Language::Cubin,
                &ptxas::ARGS[..],
            ),
            (
                os_strings(&["extra-file", "kernel.ptx", "-o=kernel.cubin"]),
                Language::Cubin,
                &ptxas::ARGS[..],
            ),
            (
                os_strings(&["kernel.cpp1.ii", "other.cpp1.ii", "-o", "kernel.ptx"]),
                Language::Ptx,
                &ARGS[..],
            ),
        ] {
            assert!(
                matches!(
                    parse_arguments(&arguments, Path::new("."), language, arg_info, 3),
                    CompilerArguments::CannotCache(
                        "unexpected positional compiler argument",
                        Some(_)
                    )
                ),
                "extra source was silently discarded: {arguments:?}"
            );
        }

        // An unknown flag's following value is not an extra source: the
        // frontend must preserve both tokens in its pass-through argument list.
        let arguments = os_strings(&[
            "--vendor-flag",
            "vendor-option-value",
            "kernel.ptx",
            "-o=kernel.cubin",
        ]);
        let parsed = parse_arguments(
            &arguments,
            Path::new("."),
            Language::Cubin,
            &ptxas::ARGS[..],
            3,
        );
        let CompilerArguments::Ok(parsed) = parsed else {
            panic!("flag value incorrectly classified as a second input: {parsed:?}");
        };
        assert_eq!(
            parsed.common_args,
            os_strings(&["--vendor-flag", "vendor-option-value"])
        );
    }
}
