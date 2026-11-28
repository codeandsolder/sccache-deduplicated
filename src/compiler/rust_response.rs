//! rustc argument files, using the compiler's newline-delimited UTF-8 format.
//! Expansion is not recursive; arguments inside a file are pushed verbatim.
use crate::errors::{Context, Result, bail};
use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::path::Path;

pub(super) fn plain_arguments(contents: &str) -> impl Iterator<Item = OsString> + '_ {
    contents.lines().map(OsString::from)
}

pub(super) fn expand(arguments: &[OsString], cwd: &Path) -> Result<Vec<OsString>> {
    let mut expanded = Vec::new();
    let mut shell_argfiles = false;
    let mut unstable_next = false;
    let mut push = |arg: OsString, shell_argfiles: &mut bool| {
        let option = if unstable_next {
            unstable_next = false;
            arg.to_str()
        } else if arg == "-Z" {
            unstable_next = true;
            None
        } else {
            arg.to_str().and_then(|arg| arg.strip_prefix("-Z"))
        };
        if option == Some("shell-argfiles") {
            *shell_argfiles = true;
        }
        expanded.push(arg);
    };
    for argument in arguments {
        let Some(text) = argument.to_str() else {
            bail!("rustc arguments must be Unicode");
        };
        let Some(file) = text.strip_prefix('@') else {
            push(argument.clone(), &mut shell_argfiles);
            continue;
        };
        let (file, shell) = match file.strip_prefix("shell:") {
            Some(path) if shell_argfiles => (path, true),
            _ => (file, false),
        };
        let contents = std::fs::read_to_string(cwd.join(file))
            .with_context(|| format!("Failed to read Rust argument file {file}"))?;
        if shell {
            let args = shlex::split(&contents).context("Invalid shell-style Rust argument file")?;
            for arg in args {
                push(arg.into(), &mut shell_argfiles);
            }
        } else {
            for arg in plain_arguments(&contents) {
                push(arg, &mut shell_argfiles);
            }
        }
    }
    Ok(expanded)
}

/// Prepared expanded compiler argv. The directory owns the response files for
/// the entire compiler invocation, including its asynchronous wait.
pub(super) struct PreparedArguments<'a> {
    pub(super) args: Cow<'a, [OsString]>,
    directory: Option<tempfile::TempDir>,
}

impl PreparedArguments<'_> {
    pub(super) fn scratch_path(&self) -> Option<&Path> {
        self.directory.as_ref().map(tempfile::TempDir::path)
    }
}

fn windows_command_line_bound(executable: &Path, args: &[OsString]) -> usize {
    // Windows quotes/backslash escaping can double an argument's UTF-16
    // length. Include delimiters, argv[0] quoting and the terminal NUL.
    // Saturate instead of overflowing for untrusted argument lists.
    let bound = |arg: &OsStr| {
        arg.to_string_lossy()
            .encode_utf16()
            .count()
            .saturating_mul(2)
            .saturating_add(3)
    };
    args.iter().fold(
        bound(executable.as_os_str()).saturating_add(1),
        |length, arg| length.saturating_add(bound(arg)),
    )
}

pub(super) fn prepare<'a>(
    executable: &Path,
    arguments: &'a [OsString],
) -> Result<PreparedArguments<'a>> {
    prepare_for_platform(executable, arguments, cfg!(windows))
}

fn prepare_for_platform<'a>(
    executable: &Path,
    arguments: &'a [OsString],
    windows: bool,
) -> Result<PreparedArguments<'a>> {
    const WINDOWS_LIMIT: usize = 32_767;
    let needs_file = arguments
        .iter()
        .any(|arg| arg.to_str().is_some_and(|arg| arg.starts_with('@')))
        || (windows && windows_command_line_bound(executable, arguments) >= WINDOWS_LIMIT);
    if !needs_file {
        return Ok(PreparedArguments {
            args: Cow::Borrowed(arguments),
            directory: None,
        });
    }
    let directory = tempfile::Builder::new()
        .prefix("sccache-rust-args")
        .tempdir()?;
    let mut prepared = Vec::new();
    let mut contents = String::new();
    let mut index = 0_usize;
    let mut flush = |contents: &mut String, prepared: &mut Vec<OsString>| -> Result<()> {
        if !contents.is_empty() {
            let path = directory.path().join(format!("{index}.args"));
            index += 1;
            std::fs::write(&path, contents.as_bytes())?;
            let mut at = OsString::from("@");
            at.push(path);
            prepared.push(at);
            contents.clear();
        }
        Ok(())
    };
    // Use files for maximal contiguous sequences that the plain format can
    // losslessly encode, leaving exceptional operands on the command line.
    // A literal leading @ must always remain inside a file.
    for argument in arguments {
        let text = argument.to_str().context("Rust argument must be Unicode")?;
        if text.contains('\n') || text.ends_with('\r') {
            if text.starts_with('@') {
                bail!(
                    "Cannot encode literal @ argument containing a newline in a Rust argument file"
                );
            }
            flush(&mut contents, &mut prepared)?;
            prepared.push(argument.clone());
        } else {
            contents.push_str(text);
            contents.push('\n');
        }
    }
    flush(&mut contents, &mut prepared)?;
    if windows && windows_command_line_bound(executable, &prepared) >= WINDOWS_LIMIT {
        bail!("Rust argument list cannot fit the Windows command line even using response files");
    }
    Ok(PreparedArguments {
        args: Cow::Owned(prepared),
        directory: Some(directory),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_file_roundtrip_preserves_arguments_and_file_lifetime() -> Result<()> {
        let arguments = [
            OsString::from(""),
            "  leading and trailing  ".into(),
            "--cfg=message=\"quotes and spaces\"".into(),
            "C:\\żółć folder\\src.rs".into(),
            "@literal".into(),
            "embedded\nnewline".into(),
            "ends-in-cr\r".into(),
            "last".into(),
        ];
        let prepared = prepare_for_platform(Path::new("rustc.exe"), &arguments, true)?;
        let directory = prepared
            .directory
            .as_ref()
            .context("missing argument directory")?
            .path()
            .to_owned();
        assert_eq!(expand(&prepared.args, Path::new("."))?, arguments);
        drop(prepared);
        assert!(!directory.exists());
        Ok(())
    }

    #[test]
    fn long_windows_command_uses_file_even_without_literal_at() -> Result<()> {
        let arguments = (0..600)
            .map(|index| OsString::from(format!("--cfg=very_long_flag_{index}_{}", "a".repeat(80))))
            .collect::<Vec<_>>();
        let prepared = prepare_for_platform(Path::new("rustc.exe"), &arguments, true)?;
        assert_eq!(prepared.args.len(), 1);
        assert_eq!(expand(&prepared.args, Path::new("."))?, arguments);
        Ok(())
    }

    #[test]
    fn expansion_is_not_recursive_and_matches_rustc_shell_option_order() -> Result<()> {
        let temp = tempfile::tempdir()?;
        std::fs::write(
            temp.path().join("plain"),
            "  padded  \n\n@missing\n-Z\nshell-argfiles\n",
        )?;
        std::fs::write(
            temp.path().join("shell-args"),
            "'two words' \"quotes\" @not-expanded",
        )?;
        let args = ["@plain".into(), "@shell:shell-args".into()];
        assert_eq!(
            expand(&args, temp.path())?,
            [
                "  padded  ",
                "",
                "@missing",
                "-Z",
                "shell-argfiles",
                "two words",
                "quotes",
                "@not-expanded"
            ]
            .map(OsString::from)
        );
        assert!(expand(&["@missing".into()], temp.path()).is_err());
        Ok(())
    }
}
