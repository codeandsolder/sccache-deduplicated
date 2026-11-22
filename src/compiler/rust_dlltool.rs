//! The Windows GNU import-library generator is a Rust codegen dependency,
//! even when the requested artifact is an rlib rather than a linked binary.

use crate::errors::{Context, Result};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub(super) struct DlltoolPlan {
    pub files: Vec<PathBuf>,
    pub identity: String,
}

impl DlltoolPlan {
    // Canonical Rust mounts system directories and declared project roots.
    // Other tool locations use the physical compiler namespace, retaining
    // the actual invocation spelling and auxiliary dependency topology.
    pub(super) fn canonical_visible(
        &self,
        canonical: &super::canonical_paths::CanonicalRustPaths,
    ) -> bool {
        self.files.iter().all(|path| {
            ["/usr", "/bin", "/lib", "/lib64", "/etc"]
                .iter()
                .any(|root| path.starts_with(root))
                && canonical.to_canonical(path) == *path
        })
    }
}

// rustc_codegen_ssa::common::is_using_dlltool requires windows, gnu and
// an unspecified ABI, excluding e.g. windows-gnullvm. Custom JSON targets
// specify those exact fields, independently of their filename.
fn target_arch(target: &str, target_json: Option<&Path>) -> Result<Option<String>> {
    if let Some(json) = target_json {
        let spec: serde_json::Value = serde_json::from_reader(fs_err::File::open(json)?)?;
        let field = |name: &str| {
            spec.get(name)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
        };
        return if field("os") == "windows" && field("env") == "gnu" && field("abi").is_empty() {
            Ok(Some(
                spec.get("arch")
                    .and_then(serde_json::Value::as_str)
                    .context("Windows GNU target has no architecture")?
                    .to_owned(),
            ))
        } else {
            Ok(None)
        };
    }
    Ok(target
        .ends_with("-windows-gnu")
        .then(|| target.split('-').next().unwrap_or_default().to_owned()))
}

pub(super) async fn discover(
    target: &str,
    target_json: Option<&Path>,
    explicit: Option<&str>,
    environment: &[(OsString, OsString)],
    cwd: &Path,
    pool: &tokio::runtime::Handle,
) -> Result<Option<DlltoolPlan>> {
    let Some(arch) = target_arch(target, target_json)? else {
        return Ok(None);
    };
    #[cfg(target_os = "linux")]
    {
        let explicit = explicit.map(str::to_owned);
        let environment = environment.to_owned();
        let cwd = cwd.to_owned();
        pool.spawn_blocking(move || linux::discover(&arch, explicit.as_deref(), &environment, &cwd))
            .await?
            .map(Some)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (arch, explicit, environment, cwd, pool);
        crate::errors::bail!("Windows GNU auxiliary tool discovery is not supported on this host");
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{DlltoolPlan, OsString, Path, PathBuf};
    use crate::{
        errors::{Context, Result, bail},
        util::Digest,
    };
    use anyhow::ensure;
    use std::{
        collections::BTreeSet,
        ffi::OsStr,
        os::unix::{fs::MetadataExt, process::CommandExt},
        process,
    };

    // Rust's default selection returns the first *file* on PATH, whereas an
    // explicit bare name is subject to process executable search. Do not
    // canonicalize argv[0]: GNU dlltool derives its assembler from that name.
    fn selected_tool(
        arch: &str,
        explicit: Option<&str>,
        path: &OsStr,
        cwd: &Path,
    ) -> Result<(PathBuf, PathBuf)> {
        if let Some(explicit) = explicit {
            let invocation = PathBuf::from(explicit);
            let executable = resolve_executable(&invocation, path, cwd)?;
            return Ok((invocation, executable));
        }
        let name = match arch {
            "x86_64" => "x86_64-w64-mingw32-dlltool",
            "x86" | "i386" | "i486" | "i586" | "i686" => "i686-w64-mingw32-dlltool",
            "aarch64" => "aarch64-w64-mingw32-dlltool",
            _ => "dlltool",
        };
        for directory in std::env::split_paths(path) {
            let candidate = directory.join(name);
            if cwd.join(&candidate).is_file() {
                // rustc runs the tool in a generated output directory, not
                // the initial compiler cwd. A relative candidate is ambiguous.
                ensure!(candidate.is_absolute(), "relative default dlltool path");
                return Ok((candidate.clone(), candidate));
            }
        }
        bail!("missing Windows GNU import library generator {name}")
    }

    fn resolve_executable(invocation: &Path, path: &OsStr, cwd: &Path) -> Result<PathBuf> {
        if invocation.is_absolute() {
            ensure!(
                invocation.is_file(),
                "missing tool {}",
                invocation.display()
            );
            return Ok(invocation.to_owned());
        }
        ensure!(
            invocation.components().count() == 1
                && invocation.file_name() == Some(invocation.as_os_str()),
            "relative auxiliary tool path"
        );
        ensure!(
            std::env::split_paths(path).all(|directory| directory.is_absolute()),
            "relative PATH entries depend on the compiler's private working directory"
        );
        Ok(which::which_in(invocation, Some(path), cwd)?)
    }

    // GNU binutils dlltool.c: deduce_name("as"). An absolute invocation tries
    // the prefixed sibling, then the unprefixed sibling, then the PATH name.
    // A bare prefixed invocation directly searches PATH for the prefixed name.
    fn assembler_name(invocation: &Path) -> Result<PathBuf> {
        let basename = invocation
            .file_name()
            .and_then(OsStr::to_str)
            .context("invalid dlltool basename")?;
        let prefixed = basename
            .rsplit_once('-')
            .map(|(prefix, _)| format!("{prefix}-as"));
        if !invocation.is_absolute() {
            return Ok(prefixed.map_or_else(|| PathBuf::from("as"), PathBuf::from));
        }
        let parent = invocation.parent().context("missing dlltool parent")?;
        if let Some(name) = prefixed {
            let candidate = parent.join(name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        let candidate = parent.join("as");
        Ok(if candidate.exists() {
            candidate
        } else {
            PathBuf::from("as")
        })
    }

    pub(super) fn discover(
        arch: &str,
        explicit: Option<&str>,
        environment: &[(OsString, OsString)],
        cwd: &Path,
    ) -> Result<DlltoolPlan> {
        let env = |name: &str| {
            environment
                .iter()
                .rev()
                .find_map(|(key, value)| (key == name).then_some(value.as_os_str()))
        };
        let path = env("PATH").unwrap_or_default();
        let (invocation, dlltool) = selected_tool(arch, explicit, path, cwd)?;
        // Relative loader search paths have the same private-cwd problem.
        if let Some(paths) = env("LD_LIBRARY_PATH") {
            ensure!(
                std::env::split_paths(paths).all(|path| path.is_absolute()),
                "relative loader search path"
            );
        }
        let version = process::Command::new(&dlltool)
            .arg0(invocation.as_os_str())
            .arg("--version")
            .current_dir(cwd)
            .env_clear()
            .envs(environment.iter().cloned())
            .output()?;
        // Only GNU's proven assembler selection contract is modeled here.
        // Arbitrary wrappers/other implementations require a complete
        // execution dependency contract, not a guessed sibling executable.
        ensure!(
            version.status.success()
                && version.stdout.starts_with(b"GNU ")
                && version
                    .stdout
                    .windows(b"GNU Binutils".len())
                    .any(|bytes| bytes == b"GNU Binutils"),
            "unrecognized DLL import library tool"
        );
        let assembler = resolve_executable(&assembler_name(&invocation)?, path, cwd)?;
        let mut files = BTreeSet::new();
        for executable in [&dlltool, &assembler] {
            files.insert(executable.clone());
            files.extend(super::super::dynamic_dependencies::find_ldd_libraries(
                executable,
                Some(environment),
            )?);
        }
        let mut identity = Digest::new();
        identity.delimiter(b"rust-dlltool-codegen-closure-v1");
        identity.delimiter(invocation.as_os_str().as_encoded_bytes());
        for (name, value) in environment
            .iter()
            .filter(|(name, _)| name.as_encoded_bytes().starts_with(b"LD_"))
        {
            identity.delimiter(name.as_encoded_bytes());
            identity.delimiter(value.as_encoded_bytes());
        }
        for file in &files {
            identity.delimiter(file.as_os_str().as_encoded_bytes());
            identity.delimiter(file.canonicalize()?.as_os_str().as_encoded_bytes());
            identity.update(&file.metadata()?.mode().to_le_bytes());
            identity.delimiter(Digest::reader_sync(fs_err::File::open(file)?)?.as_bytes());
        }
        Ok(DlltoolPlan {
            files: files.into_iter().collect(),
            identity: identity.finish(),
        })
    }

    #[test]
    fn assembler_resolution_preserves_invocation_spelling() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let dlltool = root.join("x86_64-w64-mingw32-dlltool");
        let prefixed = root.join("x86_64-w64-mingw32-as");
        let plain = root.join("as");
        fs_err::write(&plain, b"plain")?;
        assert_eq!(assembler_name(&dlltool)?, plain);
        fs_err::write(&prefixed, b"cross")?;
        assert_eq!(assembler_name(&dlltool)?, prefixed);
        assert_eq!(
            assembler_name(Path::new("x86_64-w64-mingw32-dlltool"))?,
            Path::new("x86_64-w64-mingw32-as")
        );
        assert_eq!(assembler_name(Path::new("dlltool"))?, Path::new("as"));
        Ok(())
    }
}

#[test]
fn windows_gnu_target_selection_matches_rustc() -> Result<()> {
    assert_eq!(
        target_arch("i686-pc-windows-gnu", None)?.as_deref(),
        Some("i686")
    );
    assert!(target_arch("x86_64-pc-windows-gnullvm", None)?.is_none());
    assert!(target_arch("x86_64-pc-windows-msvc", None)?.is_none());
    let target = tempfile::NamedTempFile::new()?;
    fs_err::write(
        target.path(),
        br#"{"arch":"aarch64","os":"windows","env":"gnu"}"#,
    )?;
    assert_eq!(
        target_arch("custom-target", Some(target.path()))?.as_deref(),
        Some("aarch64")
    );
    fs_err::write(
        target.path(),
        br#"{"arch":"aarch64","os":"windows","env":"gnu","abi":"llvm"}"#,
    )?;
    assert!(target_arch("custom-target", Some(target.path()))?.is_none());
    Ok(())
}
