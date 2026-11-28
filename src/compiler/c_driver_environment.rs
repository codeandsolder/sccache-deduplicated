//! Driver environment is relevant only where the actual compiler consumes it.
//! Keep target-specific driver settings out of unrelated compilation keys.
use std::ffi::{OsStr, OsString};
use std::path::Path;

use super::c::{CCompilerKind, ParsedArguments};
use crate::errors::{Context, Result};
use crate::mock_command::{CommandCreatorSync, RunCommand};
use crate::util::run_input_output;

pub(super) const DARWIN_ENVIRONMENT: &[&str] = &[
    "SDKROOT",
    "MACOSX_DEPLOYMENT_TARGET",
    "IPHONEOS_DEPLOYMENT_TARGET",
    "TVOS_DEPLOYMENT_TARGET",
    "WATCHOS_DEPLOYMENT_TARGET",
    "DRIVERKIT_DEPLOYMENT_TARGET",
    "XROS_DEPLOYMENT_TARGET",
    "RC_DEBUG_OPTIONS",
    "RC_DEBUG_PREFIX_MAP",
];

pub(super) fn darwin_variable(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| DARWIN_ENVIRONMENT.contains(&name))
}

fn darwin_target(triple: &str) -> bool {
    // GCC reports its configured triple. Clang normalizes its effective
    // driver target, including `CCC_OVERRIDE_OPTIONS`. Darwin OS names can
    // carry a version suffix, and the vendor is not necessarily "apple".
    triple.split('-').any(|component| {
        [
            "darwin",
            "macos",
            "ios",
            "tvos",
            "watchos",
            "xros",
            "driverkit",
        ]
        .iter()
        .any(|os| {
            component.strip_prefix(os).is_some_and(|suffix| {
                suffix.is_empty()
                    || suffix.as_bytes().first().is_some_and(u8::is_ascii_digit)
                    || (*os == "macos" && suffix.starts_with("x"))
            })
        })
    })
}

fn reduce_environment(
    kind: CCompilerKind,
    darwin: bool,
    environment: &mut Vec<(OsString, OsString)>,
) {
    environment.retain(|(name, _)| {
        (kind != CCompilerKind::Gcc || name != "CCC_OVERRIDE_OPTIONS")
            && (darwin || !darwin_variable(name))
    });
}

/// Query only when a Darwin-specific setting is present. The ordinary
/// Linux compile has no additional process launch. Use the same reduced
/// environment for preprocessing, key generation, and worker execution.
pub(super) async fn normalize<T: CommandCreatorSync>(
    creator: &T,
    executable: &Path,
    kind: CCompilerKind,
    parsed: &ParsedArguments,
    cwd: &Path,
    mut environment: Vec<(OsString, OsString)>,
) -> Result<Vec<(OsString, OsString)>> {
    let query = match kind {
        CCompilerKind::Gcc => "-dumpmachine",
        CCompilerKind::Clang => "-print-target-triple",
        _ => return Ok(environment),
    };
    if environment.iter().any(|(name, _)| darwin_variable(name)) {
        let mut command = creator.clone().new_command_sync(executable);
        command
            .args(&parsed.preprocessor_args)
            .args(&parsed.common_args)
            .args(&parsed.arch_args)
            .arg(query)
            .current_dir(cwd)
            .env_clear()
            .envs(environment.clone());
        let output = run_input_output(command, None).await?;
        let triple = std::str::from_utf8(&output.stdout)
            .context("compiler target was not UTF-8")?
            .trim();
        anyhow::ensure!(
            !triple.is_empty() && triple.split_whitespace().count() == 1,
            "compiler did not report one target triple"
        );
        reduce_environment(kind, darwin_target(triple), &mut environment);
    } else {
        reduce_environment(kind, false, &mut environment);
    }
    Ok(environment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_environment_follows_the_selected_target() {
        for target in [
            "x86_64-pc-linux-gnu",
            "aarch64-unknown-linux-musl",
            "x86_64-w64-mingw32",
            "wasm32-unknown-unknown",
        ] {
            assert!(!darwin_target(target));
        }
        for target in [
            "arm64-apple-darwin",
            "x86_64-apple-macosx14.0",
            "arm64-apple-ios17.0-simulator",
            "arm64-apple-xros2.0",
            "aarch64-unknown-driverkit23.0",
        ] {
            assert!(darwin_target(target));
        }
        let environment = [
            ("SDKROOT", "/sdk"),
            ("XROS_DEPLOYMENT_TARGET", "2.0"),
            ("CCC_OVERRIDE_OPTIONS", "^--target=x86_64-linux-gnu"),
            ("SOURCE_DATE_EPOCH", "1"),
        ]
        .map(|(key, value)| (key.into(), value.into()))
        .to_vec();
        let mut gcc = environment.clone();
        reduce_environment(CCompilerKind::Gcc, false, &mut gcc);
        assert_eq!(gcc, [("SOURCE_DATE_EPOCH".into(), "1".into())]);
        let mut clang = environment.clone();
        reduce_environment(CCompilerKind::Clang, false, &mut clang);
        assert_eq!(clang, environment[2..]);
        let mut darwin = environment.clone();
        reduce_environment(CCompilerKind::Clang, true, &mut darwin);
        assert_eq!(darwin, environment);
    }
}
