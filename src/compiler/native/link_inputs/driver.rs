//! Expand a captured rustc invocation through the real compiler driver's
//! non-executing -### mode. It is not safe to guess GCC's startup objects,
//! multilib directory, or selected linker from the Rust target triple.
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};

use super::{LinkInputs, closure};
use crate::compiler::native::link_capture::CapturedInvocation;

pub(super) struct DriverPlan {
    pub arguments: Vec<OsString>,
    pub tools: BTreeSet<PathBuf>,
    pub default_search: Vec<PathBuf>,
    pub response_files: BTreeSet<PathBuf>,
}

fn linker_program(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    name == "collect2"
        || name == "ld"
        || name == "ld.bfd"
        || name == "ld.gold"
        || name == "ld.lld"
        || name == "mold"
        || name == "rust-lld"
        || name.ends_with("-ld")
        || name.ends_with("-ld.bfd")
        || name.ends_with("-ld.gold")
        || name.ends_with("-ld.lld")
}

fn dry_link_command(stderr: &[u8]) -> Result<(PathBuf, Vec<OsString>)> {
    let mut commands = Vec::new();
    for line in stderr.split(|byte| *byte == b'\n') {
        if !line.first().is_some_and(u8::is_ascii_whitespace) {
            continue;
        }
        let words = closure::response_words(line)?;
        let Some((program, arguments)) = words.split_first() else {
            continue;
        };
        if linker_program(Path::new(program)) {
            commands.push((PathBuf::from(program), arguments.to_vec()));
        }
    }
    ensure!(
        commands.len() == 1,
        "driver dry run did not identify one linker command"
    );
    commands.pop().context("missing driver link command")
}

// Translate absolute paths and attached path operands for the actual driver
// query. Leave linker option payloads intact: the dry run only forwards
// them and does not execute the linker.
fn translate_argument(
    arg: &OsStr,
    translate: &impl Fn(&Path) -> Result<PathBuf>,
) -> Result<OsString> {
    let bytes = arg.as_bytes();
    if bytes.starts_with(b"/") {
        return Ok(translate(Path::new(arg))?.into_os_string());
    }
    for prefix in [
        b"-B".as_slice(),
        b"-L",
        b"--sysroot=",
        b"--gcc-toolchain=",
        b"-plugin-opt=",
        b"--plugin-opt=",
    ] {
        if let Some(path) = bytes
            .strip_prefix(prefix)
            .filter(|path| path.starts_with(b"/"))
        {
            let path = translate(Path::new(OsStr::from_bytes(path)))?;
            return Ok(OsString::from_vec(
                [prefix, path.as_os_str().as_bytes()].concat(),
            ));
        }
    }
    Ok(arg.to_owned())
}

fn selected_linker_suffix(args: &[OsString]) -> Option<OsString> {
    args.iter()
        .rev()
        .find_map(|arg| arg.as_bytes().strip_prefix(b"-fuse-ld="))
        .map(|name| {
            if name.starts_with(b"/") {
                OsString::from_vec(name.to_vec())
            } else {
                OsString::from_vec([b"ld.".as_slice(), name].concat())
            }
        })
}

fn driver_search_arguments(args: &[OsString]) -> Vec<OsString> {
    let mut result = Vec::new();
    let mut pending = false;
    for arg in args {
        let bytes = arg.as_bytes();
        if pending {
            result.push(arg.clone());
            pending = false;
        } else if matches!(
            bytes,
            b"-B" | b"--sysroot" | b"-isysroot" | b"--gcc-toolchain"
        ) {
            result.push(arg.clone());
            pending = true;
        } else if [
            b"-B".as_slice(),
            b"--sysroot=",
            b"-isysroot",
            b"--gcc-toolchain=",
            b"-fuse-ld=",
            b"-m",
        ]
        .iter()
        .any(|prefix| bytes.starts_with(prefix))
        {
            result.push(arg.clone());
        }
    }
    result
}

fn environment(
    input: &LinkInputs,
    capture: &CapturedInvocation,
) -> Result<BTreeMap<OsString, OsString>> {
    let mut result = capture.environment.clone();
    for key in ["PATH", "COMPILER_PATH", "LIBRARY_PATH", "LD_LIBRARY_PATH"] {
        if let Some(value) = result.get_mut(OsStr::new(key)) {
            let paths = std::env::split_paths(value)
                .map(|path| {
                    if path.is_absolute() {
                        input.physical(&path)
                    } else {
                        Ok(path)
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            *value = std::env::join_paths(paths)?;
        }
    }
    if let Some(value) = result.get_mut(OsStr::new("GCC_EXEC_PREFIX"))
        && Path::new(value).is_absolute()
    {
        *value = input.physical(Path::new(value))?.into_os_string();
    }
    Ok(result)
}

impl DriverPlan {
    pub(super) fn discover(input: &LinkInputs, capture: &CapturedInvocation) -> Result<Self> {
        let (options, spec) = input.target_spec()?;
        let flavor = options
            .flavor
            .as_deref()
            .or_else(|| {
                spec.get("linker-flavor")
                    .and_then(serde_json::Value::as_str)
            })
            .context("target does not declare linker flavor")?;
        let linker_name = options.linker.as_deref().or_else(|| {
            spec.get("linker")
                .and_then(serde_json::Value::as_str)
                .map(OsStr::new)
        });
        let environment = environment(input, capture)?;
        let cwd = input.physical(&capture.cwd)?;
        let mut response_data = BTreeMap::new();
        for (index, bytes) in &capture.responses {
            let arg = capture
                .arguments
                .get(*index)
                .context("response capture index out of bounds")?;
            let path = arg
                .as_bytes()
                .strip_prefix(b"@")
                .context("response capture argument mismatch")?;
            response_data.insert(capture.cwd.join(OsStr::from_bytes(path)), bytes);
        }
        let mut expanded = Vec::new();
        let mut response_files = BTreeSet::new();
        closure::expand_response(
            capture.arguments.clone(),
            &mut |path| {
                let logical = capture.cwd.join(path);
                if let Some(bytes) = response_data.get(&logical) {
                    Ok((*bytes).clone())
                } else {
                    Ok(std::fs::read(input.physical(&logical)?)?)
                }
            },
            &mut BTreeSet::new(),
            &mut response_files,
            &mut expanded,
        )?;
        response_files = response_files
            .into_iter()
            .map(|path| capture.cwd.join(path))
            .collect();

        let mut tools = BTreeSet::new();
        let (linker, arguments) = if flavor.ends_with("-cc") {
            let driver = input.locate(linker_name.unwrap_or_else(|| OsStr::new("cc")))?;
            tools.insert(driver.clone());
            let arguments = expanded
                .iter()
                .map(|arg| translate_argument(arg, &|path| input.physical(path)))
                .collect::<Result<Vec<_>>>()?;
            let output = Command::new(&driver)
                .current_dir(&cwd)
                .env_clear()
                .envs(&environment)
                .arg("-###")
                .args(&arguments)
                .output()?;
            ensure!(
                output.status.success(),
                "link driver planning failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let (program, command) = dry_link_command(&output.stderr)?;
            let program = input.locate(program.as_os_str())?;
            tools.insert(program.clone());
            let linker = if program.file_name() == Some(OsStr::new("collect2")) {
                let name =
                    selected_linker_suffix(&arguments).unwrap_or_else(|| OsString::from("ld"));
                if Path::new(&name).is_absolute() {
                    PathBuf::from(name)
                } else {
                    let mut query = OsString::from("-print-prog-name=");
                    query.push(&name);
                    let output = Command::new(&driver)
                        .current_dir(&cwd)
                        .env_clear()
                        .envs(&environment)
                        .args(driver_search_arguments(&arguments))
                        .arg(query)
                        .output()?;
                    ensure!(output.status.success(), "linker executable query failed");
                    let name = std::str::from_utf8(&output.stdout)?.trim();
                    input.locate(OsStr::new(name))?
                }
            } else {
                program
            };
            let logical = |path: &Path| -> Result<PathBuf> {
                let mut mapping = crate::dist::PathTransformer::new();
                for (physical, logical) in input.transformer.path_mappings() {
                    mapping.add_root_mapping(physical, &logical);
                }
                Ok(PathBuf::from(
                    mapping
                        .as_dist_abs(path)
                        .context("driver path has no native mapping")?,
                ))
            };
            let arguments = command
                .iter()
                .map(|arg| translate_argument(arg, &logical))
                .collect::<Result<Vec<_>>>()?;
            (linker, arguments)
        } else {
            let linker = if let Some(name) = linker_name {
                input.locate(name)?
            } else if flavor.contains("lld") || flavor.starts_with("wasm") {
                let target = options
                    .target
                    .as_deref()
                    .and_then(OsStr::to_str)
                    .or_else(|| spec.get("llvm-target").and_then(serde_json::Value::as_str))
                    .context("target linker path unavailable")?;
                let sysroot = input
                    .compiler
                    .parent()
                    .and_then(Path::parent)
                    .context("compiler sysroot unavailable")?;
                sysroot
                    .join("lib/rustlib")
                    .join(target)
                    .join("bin/rust-lld")
            } else {
                input.locate(OsStr::new("ld"))?
            };
            (linker, expanded)
        };
        tools.insert(linker.clone());

        let version = Command::new(&linker)
            .current_dir(&cwd)
            .env_clear()
            .envs(&environment)
            .arg("--version")
            .output()?;
        ensure!(version.status.success(), "query selected linker version");
        let default_search = if version.stdout.starts_with(b"GNU ld") {
            // GNU ld's default script reflects the selected emulation and
            // sysroot; neither is necessarily the compiler's host default.
            let mut command = Command::new(&linker);
            command
                .current_dir(&cwd)
                .env_clear()
                .envs(&environment)
                .arg("--verbose");
            let mut args = arguments.iter();
            while let Some(arg) = args.next() {
                if arg == "-m" || arg == "--sysroot" {
                    let value = args
                        .next()
                        .context("missing linker emulation/sysroot operand")?;
                    command
                        .arg(arg)
                        .arg(translate_argument(value, &|path| input.physical(path))?);
                } else if arg.as_bytes().starts_with(b"--sysroot=") {
                    command.arg(translate_argument(arg, &|path| input.physical(path))?);
                }
            }
            let output = command.output()?;
            ensure!(output.status.success(), "query GNU ld search directories");
            closure::default_search_paths(&output.stdout)?
        } else {
            // ELF lld uses the explicit search paths supplied by its driver.
            Vec::new()
        };
        Ok(Self {
            arguments,
            tools,
            default_search,
            response_files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_uses_command_not_driver_diagnostics() -> Result<()> {
        let (program, args) = dry_link_command(b"COLLECT_GCC=/usr/bin/cc\nCOLLECT_GCC_OPTIONS='-o' 'a b'\n /usr/lib/gcc/collect2 \"--hash-style=gnu\" -o \"a b\" -L\"/path with spaces\" -lc\n")?;
        assert_eq!(program, Path::new("/usr/lib/gcc/collect2"));
        assert_eq!(
            args,
            [
                "--hash-style=gnu",
                "-o",
                "a b",
                "-L/path with spaces",
                "-lc"
            ]
        );
        Ok(())
    }
}
