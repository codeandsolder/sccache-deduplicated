// Copyright 2018 Mozilla Foundation
// Copyright 2018 Felix Obenhuber <felix@obenhuber.de>
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
    NormalizedDisposition, PathTransformerFn, SearchableArgInfo,
};
use crate::compiler::c::{
    ArtifactDescriptor, CCompileCommands, CCompileContext, CCompilerImpl, CCompilerKind,
    CPreprocessContext, ParsedArguments,
};
use crate::compiler::response_files::ResponseFileExpansion;
use crate::compiler::{ColorMode, CompilerArguments, Language, SingleCompileCommand};
use crate::counted_array;
use crate::errors::Result;
use crate::mock_command::{CommandCreatorSync, RunCommand};
use crate::util::{OsStrExt, run_input_output};
use async_trait::async_trait;
use log::Level::Trace;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process;

#[derive(Clone, Debug)]
pub struct Diab {
    pub version: Option<String>,
}

#[async_trait]
impl CCompilerImpl for Diab {
    type LocalCommand = SingleCompileCommand;

    fn kind(&self) -> CCompilerKind {
        CCompilerKind::Diab
    }
    fn plusplus(&self) -> bool {
        false
    }
    fn version(&self) -> Option<String> {
        self.version.clone()
    }
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
        _env_vars: &[(OsString, OsString)],
    ) -> CompilerArguments<ParsedArguments> {
        parse_arguments(arguments, cwd, &ARGS[..])
    }

    async fn preprocess<T>(&self, context: CPreprocessContext<'_, T>) -> Result<process::Output>
    where
        T: CommandCreatorSync,
    {
        let CPreprocessContext {
            creator,
            executable,
            parsed_args,
            cwd,
            env_vars,
            may_dist,
            ..
        } = context;
        preprocess(creator, executable, parsed_args, cwd, env_vars, may_dist).await
    }

    fn generate_compile_commands(
        &self,
        context: CCompileContext<'_>,
    ) -> CCompileCommands<Self::LocalCommand> {
        crate::compiler::c::local_dash_o_compile_commands(context)
    }
}

ArgData! { pub
    DoCompilation,
    Output(PathBuf),
    PassThrough(OsString),
    PreprocessorArgument(OsString),
    PreprocessorArgumentPath(PathBuf),
    DepArgumentFlag,
    DepArgument(OsString),
    DepArgumentPath(PathBuf),
    TooHardFlag,
    TooHard(OsString),
}

use self::ArgData::{
    DepArgument, DepArgumentFlag, DepArgumentPath, DoCompilation, Output, PassThrough,
    PreprocessorArgument, PreprocessorArgumentPath, TooHard, TooHardFlag,
};

counted_array!(pub static ARGS: [ArgInfo<ArgData>; _] = [
    flag!("-", TooHardFlag),
    flag!("-##", TooHardFlag),
    flag!("-###", TooHardFlag),
    take_arg!("-@", OsString, Concatenated, TooHard),
    take_arg!("-D", OsString, CanBeSeparated, PreprocessorArgument),
    flag!("-E", TooHardFlag),
    take_arg!("-I", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-L", OsString, Separated, PassThrough),
    flag!("-P", TooHardFlag),
    flag!("-S", TooHardFlag),
    take_arg!("-U", OsString, CanBeSeparated, PreprocessorArgument),
    flag!("-V", TooHardFlag),
    flag!("-VV", TooHardFlag),
    take_arg!("-W", OsString, Separated, PassThrough),
    flag!("-Xmake-dependency", DepArgumentFlag),
    flag!(
        "-Xmake-dependency-canonicalize-path-off",
        DepArgumentFlag
    ),
    take_arg!(
        "-Xmake-dependency-savefile",
        PathBuf,
        Concatenated(b'='),
        DepArgumentPath
    ),
    take_arg!(
        "-Xmake-dependency-target",
        OsString,
        Concatenated(b'='),
        DepArgument
    ),
    flag!("-c", DoCompilation),
    take_arg!(
        "-include",
        PathBuf,
        CanBeSeparated,
        PreprocessorArgumentPath
    ),
    take_arg!("-l", OsString, Separated, PassThrough),
    take_arg!("-o", PathBuf, Separated, Output),
    take_arg!("-t", OsString, Separated, PassThrough),
]);

/// Parse `arguments`, determining whether it is supported.
///
/// If any of the entries in `arguments` result in a compilation that
/// cannot be cached, return `CompilerArguments::CannotCache`.
/// If the commandline described by `arguments` is not compilation,
/// return `CompilerArguments::NotCompilation`.
/// Otherwise, return `CompilerArguments::Ok(ParsedArguments)`, with
/// the `ParsedArguments` struct containing information parsed from
/// `arguments`.
#[expect(
    clippy::too_many_lines,
    reason = "single-pass argument parser keeps interdependent flag state and ordering visible; splitting would require a state bag threaded through helpers"
)]
pub fn parse_arguments<S>(
    arguments: &[OsString],
    cwd: &Path,
    arg_info: S,
) -> CompilerArguments<ParsedArguments>
where
    S: SearchableArgInfo<ArgData>,
{
    let mut common_args = vec![];
    let mut compilation = false;
    let mut compilation_flag = OsString::new();
    let mut input_arg = None;
    let mut multiple_input = false;
    let mut output_arg = None;
    let mut preprocessor_args = vec![];
    let mut dependency_args = vec![];

    // Custom iterator to expand `@` arguments which stand for reading a file
    // and interpreting it as a list of more arguments.
    let it = ExpandAtArgs::new(cwd, arguments);

    for arg in ArgsIter::new(it, arg_info) {
        let arg = try_or_cannot_cache!(arg, "argument parse");
        // Check if the value part of this argument begins with '@'. If so, we either
        // failed to expand it, or it was a concatenated argument - either way, bail.
        // We refuse to cache concatenated arguments (like "-include@foo") because they're a
        // mess. See https://github.com/mozilla/sccache/issues/150#issuecomment-318586953
        match arg {
            Argument::WithValue(
                _,
                ref v,
                ArgDisposition::Separated
                | ArgDisposition::CanBeConcatenated(_)
                | ArgDisposition::CanBeSeparated(_),
            ) => {
                if v.clone().into_arg_os_string().starts_with("@") {
                    cannot_cache!("@");
                }
            }
            // Empirically, concatenated arguments appear not to interpret '@' as
            // an include directive, so just continue.
            Argument::WithValue(_, _, ArgDisposition::Concatenated(_))
            | Argument::Raw(_)
            | Argument::UnknownFlag(_)
            | Argument::Flag(_, _) => {}
        }

        match arg.get_data() {
            Some(TooHardFlag | TooHard(_)) => {
                let Some(flag) = arg.flag_str() else {
                    cannot_cache!("unsupported compiler option");
                };
                cannot_cache!(flag)
            }

            Some(
                DepArgument(_)
                | DepArgumentFlag
                | DepArgumentPath(_)
                | PreprocessorArgument(_)
                | PreprocessorArgumentPath(_)
                | PassThrough(_),
            ) => {}

            Some(DoCompilation) => {
                compilation = true;
                let Some(flag) = arg.flag_str() else {
                    cannot_cache!("compilation flag missing");
                };
                compilation_flag = OsString::from(flag);
            }
            Some(Output(p)) => output_arg = Some(p.clone()),
            None => match arg {
                Argument::Raw(ref val) => {
                    if input_arg.is_some() {
                        multiple_input = true;
                    }
                    input_arg = Some(val.clone());
                }
                Argument::UnknownFlag(_) => {}
                _ => unreachable!(),
            },
        }
        let args = match arg.get_data() {
            Some(PassThrough(_)) => &mut common_args,
            Some(DepArgument(_) | DepArgumentFlag | DepArgumentPath(_)) => &mut dependency_args,
            Some(PreprocessorArgument(_) | PreprocessorArgumentPath(_)) => &mut preprocessor_args,
            Some(DoCompilation | Output(_)) => continue,
            Some(TooHardFlag | TooHard(_)) => unreachable!(),
            None => match arg {
                Argument::Raw(_) => continue,
                Argument::UnknownFlag(_) => &mut common_args,
                _ => unreachable!(),
            },
        };
        // Normalize attributes such as "-I foo", "-D FOO=bar", as
        // "-Ifoo", "-DFOO=bar", etc. and "-includefoo", "idirafterbar" as
        // "-include foo", "-idirafter bar", etc.
        let norm = match arg.flag_str() {
            Some(s) if s.len() == 2 => NormalizedDisposition::Concatenated,
            _ => NormalizedDisposition::Separated,
        };
        args.extend(arg.normalize(norm).iter_os_strings());
    }

    // We only support compilation.
    if !compilation {
        return CompilerArguments::NotCompilation;
    }
    // Can't cache compilations with multiple inputs.
    if multiple_input {
        cannot_cache!("multiple input files");
    }
    let Some(input) = input_arg else {
        cannot_cache!("no input file")
    };
    let Some(language) = Language::from_file_name(Path::new(&input)) else {
        cannot_cache!("unknown source language")
    };

    let output = output_arg.unwrap_or_else(|| Path::new(&input).with_extension("o"));

    let mut outputs = HashMap::new();
    outputs.insert(
        "obj",
        ArtifactDescriptor {
            path: output,
            optional: false,
        },
    );

    CompilerArguments::Ok(ParsedArguments {
        input: input.into(),
        double_dash_input: false,
        language,
        compilation_flag,
        depfile: None,
        outputs,
        dependency_args,
        preprocessor_args,
        common_args,
        arch_args: vec![],
        unhashed_args: vec![],
        extra_dist_files: vec![],
        extra_hash_files: vec![],
        uses_external_assembler: false,
        msvc_show_includes: false,
        profile_generate: false,
        // FIXME: Implement me.
        color_mode: ColorMode::Auto,
        suppress_rewrite_includes_only: false,
        too_hard_for_preprocessor_cache_mode: None,
    })
}

pub async fn preprocess<T>(
    creator: &T,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
    _may_dist: bool,
) -> Result<process::Output>
where
    T: CommandCreatorSync,
{
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-E")
        .arg(&parsed_args.input)
        .args(&parsed_args.dependency_args)
        .args(&parsed_args.preprocessor_args)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.to_vec())
        .current_dir(cwd);

    if log_enabled!(Trace) {
        trace!("preprocess: {cmd:?}");
    }
    run_input_output(cmd, None).await
}

pub struct ExpandAtArgs<'a> {
    cwd: &'a Path,
    expansion: ResponseFileExpansion,
}

impl<'a> ExpandAtArgs<'a> {
    pub fn new(cwd: &'a Path, args: &[OsString]) -> Self {
        Self {
            cwd,
            expansion: ResponseFileExpansion::new(args),
        }
    }
}

impl Iterator for ExpandAtArgs<'_> {
    type Item = OsString;

    fn next(&mut self) -> Option<OsString> {
        loop {
            let arg = self.expansion.next_argument()?;

            // Just return non @ arguments
            if !arg.starts_with("-@") {
                return Some(arg);
            }

            let Some(value) = arg.split_prefix("-@") else {
                return Some(arg);
            };

            // Return options that produce additional output and are not cacheable
            if value.starts_with("E") || value.starts_with("O") || value.starts_with("@") {
                return Some(arg);
            }

            // According to diab [1], @file means:
            // Read command line options from either a file or an environment
            // variable. When -@name is encountered on the command line, the
            // driver first looks for an environment variable with the given
            // name and substitutes its value. If an environment variable is
            // not found then the driver tries to open a file with given name
            // and substitutes the contents of the file. If neither an
            // environment variable or a file can be found, an error message
            // is issued and the driver terminates.
            //
            // [1]: http://www.vxdev.com/docs/vx55man/diab5.0ppc/c-invoke.htm#3000619
            //
            // The environment variable feature is *not* supported by sccache
            // since this would raise the need for the clients environment
            // and not just env::var. This is technically possible, but
            // considered as a unneeded edge case for now.

            let file = self.cwd.join(&value);
            if !self.expansion.expand(&file, |contents| {
                if contents.contains('"') || contents.contains('\'') {
                    return None;
                }
                Some(contents.split_whitespace().map(OsString::from).collect())
            }) {
                // If the file cannot be expanded, let the compiler parse it
                // itself and mark the request as uncacheable.
                return Some(arg);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{ARGS, Diab, Language, OsString, ParsedArguments, parse_arguments};
    use crate::compiler::c::{ArtifactDescriptor, CCompileContext, CCompilerImpl};
    use crate::compiler::*;
    use crate::dist;
    use crate::test::utils::*;
    use fs::File;
    use fs_err as fs;
    use std::io::Write;

    fn parse_arguments_(arguments: Vec<String>) -> CompilerArguments<ParsedArguments> {
        let args = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        parse_arguments(&args, ".".as_ref(), &ARGS[..])
    }

    #[test_case::test_case(true; "explicit output")]
    #[test_case::test_case(false; "default output")]
    fn test_parse_arguments_simple(explicit_output: bool) {
        let mut args = stringvec!["-c", "foo.c"];
        if explicit_output {
            args.extend(stringvec!["-o", "foo.o"]);
        }
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments_(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {o:?}"),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false
                }
            )
        );
        assert_eq!(preprocessor_args, [] as [std::ffi::OsString; 0]);
        assert_eq!(common_args, [] as [std::ffi::OsString; 0]);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_extra() {
        let args = stringvec!["-c", "foo.cc", "-fabc", "-o", "foo.o", "-mxyz"];
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments_(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {o:?}"),
        };
        assert_eq!(Some("foo.cc"), input.to_str());
        assert_eq!(Language::Cxx, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false
                }
            )
        );
        assert_eq!(preprocessor_args, [] as [std::ffi::OsString; 0]);
        assert_eq!(ovec!["-fabc", "-mxyz"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_values() {
        let args = stringvec![
            "-c", "foo.cxx", "-fabc", "-I", "include", "-o", "foo.o", "-include", "file"
        ];
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments_(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {o:?}"),
        };
        assert_eq!(Some("foo.cxx"), input.to_str());
        assert_eq!(Language::Cxx, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false
                }
            )
        );
        assert_eq!(ovec!["-Iinclude", "-include", "file"], preprocessor_args);
        assert_eq!(ovec!["-fabc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_preprocessor_args() {
        let args = stringvec![
            "-c",
            "foo.c",
            "-fabc",
            "-Xmake-dependency",
            "-Xmake-dependency-canonicalize-path-off",
            "-Xmake-dependency-savefile=bar",
            "-Xmake-dependency-target=foo",
            "-o",
            "foo.o"
        ];
        let ParsedArguments {
            input,
            language,
            outputs,
            dependency_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments_(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {o:?}"),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false
                }
            )
        );
        assert_eq!(
            ovec![
                "-Xmake-dependency",
                "-Xmake-dependency-canonicalize-path-off",
                "-Xmake-dependency-savefile=bar",
                "-Xmake-dependency-target=foo"
            ],
            dependency_args
        );
        assert_eq!(ovec!["-fabc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_empty_args() {
        assert_eq!(CompilerArguments::NotCompilation, parse_arguments_(vec![]));
    }

    #[test]
    fn test_parse_arguments_not_compile() {
        assert_eq!(
            CompilerArguments::NotCompilation,
            parse_arguments_(stringvec!["-o", "foo"])
        );
    }

    #[test]
    fn test_parse_arguments_too_many_inputs() {
        assert_eq!(
            CompilerArguments::CannotCache("multiple input files", None),
            parse_arguments_(stringvec!["-c", "foo.c", "-o", "foo.o", "bar.c"])
        );
    }

    #[test]
    fn test_parse_arguments_link() {
        assert_eq!(
            CompilerArguments::NotCompilation,
            parse_arguments_(stringvec!["-shared", "foo.o", "-o", "foo.so", "bar.o"])
        );
    }

    #[test]
    fn test_parse_dry_run() {
        assert_eq!(
            CompilerArguments::CannotCache("-##", None),
            parse_arguments_(stringvec!["-##", "-c", "foo.c"])
        );

        assert_eq!(
            CompilerArguments::CannotCache("-###", None),
            parse_arguments_(stringvec!["-###", "-c", "foo.c"])
        );
    }

    #[test]
    fn test_at_signs() {
        let cannot_cache = CompilerArguments::CannotCache("-@", None);
        assert_eq!(parse_arguments_(vec!["-@@foo".into()]), cannot_cache);
        assert_eq!(parse_arguments_(vec!["-@E=foo".into()]), cannot_cache);
        assert_eq!(parse_arguments_(vec!["-@E+foo".into()]), cannot_cache);
        assert_eq!(parse_arguments_(vec!["-@O=foo".into()]), cannot_cache);
        assert_eq!(parse_arguments_(vec!["-@O+foo".into()]), cannot_cache);
    }

    #[test]
    fn recursive_response_files_fall_back_without_hanging() -> crate::errors::Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("self.rsp"), b"-@self.rsp")?;
        let args = [OsString::from("-@self.rsp")];
        assert_eq!(
            super::ExpandAtArgs::new(temp.path(), &args).collect::<Vec<_>>(),
            args
        );
        assert_eq!(
            parse_arguments(&args, temp.path(), &ARGS[..]),
            CompilerArguments::CannotCache("-@", None)
        );

        fs::write(temp.path().join("first.rsp"), b"-@second.rsp")?;
        fs::write(temp.path().join("second.rsp"), b"-@first.rsp")?;
        assert_eq!(
            super::ExpandAtArgs::new(temp.path(), &[OsString::from("-@first.rsp")])
                .collect::<Vec<_>>(),
            [OsString::from("-@first.rsp")]
        );
        Ok(())
    }

    #[test]
    fn nested_and_repeated_response_files_remain_supported() -> crate::errors::Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("leaf.rsp"), b"-DVALUE=1")?;
        fs::write(temp.path().join("outer.rsp"), b"-@leaf.rsp -c source.c")?;
        assert_eq!(
            super::ExpandAtArgs::new(
                temp.path(),
                &[OsString::from("-@outer.rsp"), OsString::from("-@leaf.rsp"),],
            )
            .collect::<Vec<_>>(),
            [
                OsString::from("-DVALUE=1"),
                OsString::from("-c"),
                OsString::from("source.c"),
                OsString::from("-DVALUE=1"),
            ]
        );
        fs::write(temp.path().join("empty.rsp"), b"")?;
        assert_eq!(
            super::ExpandAtArgs::new(
                temp.path(),
                &[OsString::from("-@empty.rsp"), OsString::from("tail")],
            )
            .collect::<Vec<_>>(),
            [OsString::from("tail")]
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn response_file_symlink_cycles_are_detected() -> crate::errors::Result<()> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("actual.rsp"), b"-@alias.rsp")?;
        symlink("actual.rsp", temp.path().join("alias.rsp"))?;
        assert_eq!(
            super::ExpandAtArgs::new(temp.path(), &[OsString::from("-@actual.rsp")])
                .collect::<Vec<_>>(),
            [OsString::from("-@alias.rsp")]
        );
        Ok(())
    }

    #[test]
    fn test_at_signs_file_not_readable() {
        let td = tempfile::Builder::new()
            .prefix("sccache")
            .tempdir()
            .unwrap();
        let arg = format!("-@{}", td.path().join("foo").display());
        // File foo doesn't exist.
        assert_eq!(
            parse_arguments_(vec![arg]),
            CompilerArguments::CannotCache("-@", None)
        );
    }

    #[test]
    fn test_at_signs_file() {
        let td = tempfile::Builder::new()
            .prefix("sccache")
            .tempdir()
            .unwrap();
        File::create(td.path().join("foo"))
            .unwrap()
            .write_all(b"-c foo.c -o foo.o")
            .unwrap();
        let arg = format!("-@{}", td.path().join("foo").display());
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments_(vec![arg]) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {o:?}"),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false
                }
            )
        );
        assert_eq!(preprocessor_args, [] as [std::ffi::OsString; 0]);
        assert_eq!(common_args, [] as [std::ffi::OsString; 0]);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_compile_simple() -> crate::errors::Result<()> {
        let f = TestFixture::new();
        let parsed_args = ParsedArguments::test_compile("foo.c", "foo.o", Language::C);
        let compiler = &f.bins[0];
        let mut path_transformer = dist::PathTransformer::new();
        let (command, _, cacheable) = Diab { version: None }
            .generate_compile_commands(CCompileContext {
                path_transformer: &mut path_transformer,
                executable: compiler,
                parsed_args: &parsed_args,
                cwd: f.tempdir.path(),
                env_vars: &[],
                rewrite_includes_only: false,
            })
            .unwrap();
        assert_compile_command_executes(&command)?;
        assert_eq!(Cacheable::Yes, cacheable);
        Ok(())
    }
}
