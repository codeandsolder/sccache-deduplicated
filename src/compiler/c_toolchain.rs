//! Package-owned C compiler search environment. Ask the actual ELF
//! interpreter which dependencies it selects, then reconstruct a search
//! contract that selects those same files without the host's ld.so.cache.
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process,
};

use anyhow::ensure;
use object::{
    Object,
    read::{ReadCache, elf::ProgramHeader},
};

use crate::{
    dist::pkg::ToolchainPackageBuilder,
    errors::{Context, Result},
};

struct LoaderProbe {
    executable: PathBuf,
    interpreter: Option<PathBuf>,
}

type Selection = BTreeMap<Vec<u8>, PathBuf>;

impl LoaderProbe {
    fn open(executable: PathBuf) -> Result<Self> {
        let cache = ReadCache::new(fs_err::File::open(&executable)?);
        let file = object::File::parse(&cache)?;
        let interpreter = match &file {
            object::File::Elf32(elf) => elf
                .elf_program_headers()
                .iter()
                .find(|header| header.p_type(elf.endian()) == object::elf::PT_INTERP)
                .map(|header| header.data(elf.endian(), &cache)),
            object::File::Elf64(elf) => elf
                .elf_program_headers()
                .iter()
                .find(|header| header.p_type(elf.endian()) == object::elf::PT_INTERP)
                .map(|header| header.data(elf.endian(), &cache)),
            _ => anyhow::bail!("non-ELF compiler helper {}", executable.display()),
        };
        let interpreter = interpreter
            .map(|data| -> Result<_> {
                let bytes =
                    data.map_err(|()| anyhow::anyhow!("invalid ELF interpreter segment"))?;
                let path = PathBuf::from(OsStr::from_bytes(
                    bytes
                        .strip_suffix(b"\0")
                        .context("unterminated ELF interpreter")?,
                ));
                ensure!(path.is_absolute(), "nonabsolute ELF interpreter");
                Ok(path)
            })
            .transpose()?;
        if interpreter.is_none() {
            ensure!(
                file.imports()?.next().is_none(),
                "ELF helper without interpreter has unresolved imports"
            );
        }
        Ok(Self {
            executable,
            interpreter,
        })
    }

    fn resolve(
        &self,
        environment: &[(OsString, OsString)],
        cwd: &Path,
        loader_path: Option<&OsStr>,
        host_cache: bool,
    ) -> Result<Selection> {
        let Some(interpreter) = &self.interpreter else {
            return Ok(Selection::new());
        };
        let mut command = process::Command::new(interpreter);
        command.current_dir(cwd).env_clear().envs(
            environment
                .iter()
                .filter(|(name, _)| name != "LD_LIBRARY_PATH")
                .cloned(),
        );
        if let Some(path) = loader_path {
            command.env("LD_LIBRARY_PATH", path);
        }
        // Glibc's cache is host-specific and deliberately absent from the
        // sandbox. Musl has no ld.so.cache; its selected nonstandard dirs
        // are supplied by the constructed search list.
        let musl = interpreter
            .file_name()
            .is_some_and(|name| name.as_encoded_bytes().starts_with(b"ld-musl-"));
        if !host_cache && !musl {
            command.arg("--inhibit-cache");
        }
        let output = command
            .arg("--list")
            .arg(&self.executable)
            .stdin(process::Stdio::piped())
            .output()?;
        ensure!(
            output.status.success(),
            "loader could not resolve {}: {}",
            self.executable.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        let mut selected = parse_selection(&output.stdout, cwd)?;
        selected.insert(b"\0interpreter".to_vec(), interpreter.clone());
        Ok(selected)
    }
}

fn parse_selection(output: &[u8], cwd: &Path) -> Result<Selection> {
    let mut result = BTreeMap::new();
    for line in output.split(|&byte| byte == b'\n') {
        let line = line.trim_ascii();
        let Some(end) = line.windows(2).rposition(|part| part == b" (") else {
            ensure!(
                !line.ends_with(b"=> not found"),
                "unresolved ELF dependency"
            );
            continue;
        };
        let entry = &line[..end];
        let (name, path) = if let Some(split) = entry.windows(3).position(|part| part == b" =>") {
            (&entry[..split], entry[split + 3..].trim_ascii())
        } else if entry.starts_with(b"/") {
            (entry, entry)
        } else {
            // Linux's virtual DSO has no package file.
            continue;
        };
        if path.is_empty() {
            continue;
        }
        let path = cwd.join(Path::new(OsStr::from_bytes(path)));
        ensure!(
            path.is_file(),
            "loader returned unavailable dependency {}",
            path.display()
        );
        result.insert(name.to_vec(), path);
    }
    Ok(result)
}

fn resolve(
    probes: &[LoaderProbe],
    environment: &[(OsString, OsString)],
    cwd: &Path,
    path: Option<&OsStr>,
    host_cache: bool,
) -> Result<Vec<Selection>> {
    probes
        .iter()
        .map(|probe| probe.resolve(environment, cwd, path, host_cache))
        .collect()
}

fn canonical_selection(selections: &[Selection]) -> Result<Vec<Selection>> {
    selections
        .iter()
        .map(|selection| {
            selection
                .iter()
                .map(|(name, path)| Ok((name.clone(), path.canonicalize()?)))
                .collect()
        })
        .collect()
}

/// Build an explicit search list from the dependencies actually selected,
/// then verify the entire transitive resolution. The common case needs no
/// library-path override at all. Never examine unrelated build directories.
fn search_contract(
    probes: &[LoaderProbe],
    environment: &[(OsString, OsString)],
    cwd: &Path,
) -> Result<(Option<Vec<u8>>, Vec<Selection>)> {
    let caller = environment
        .iter()
        .rev()
        .find(|(name, _)| name == "LD_LIBRARY_PATH")
        .map(|(_, value)| value.as_os_str());
    let expected = resolve(probes, environment, cwd, caller, true)?;
    let canonical = canonical_selection(&expected)?;
    let equivalent = |path: Option<&OsStr>| -> Option<Vec<Selection>> {
        let actual = resolve(probes, environment, cwd, path, false).ok()?;
        (canonical_selection(&actual).ok()? == canonical).then_some(actual)
    };
    if let Some(selected) = equivalent(None) {
        return Ok((None, selected));
    }

    // Only directories of selected dependency files can be relevant. The
    // loader's configured directories are represented explicitly, rather
    // than shipping a host-global cache or a Cargo-specific blacklist.
    let mut selected_dirs = BTreeSet::new();
    for selection in &expected {
        for path in selection.values() {
            selected_dirs.insert(path.parent().context("library has no parent")?.to_owned());
        }
    }
    let mut entries = selected_dirs
        .into_iter()
        .map(|path| path.as_os_str().as_bytes().to_vec())
        .collect::<Vec<_>>();
    // Preserve selection precedence if different helper libraries have
    // colliding names. Explicit caller search is considered only when the
    // deterministic resolved directory set cannot reproduce the closure.
    let joined = |entries: &[Vec<u8>]| entries.join(&b':');
    if equivalent(Some(OsStr::from_bytes(&joined(&entries)))).is_none() {
        let mut priority = caller.map_or_else(Vec::new, |path| {
            path.as_bytes()
                .split(|&byte| matches!(byte, b':' | b';'))
                .map(<[u8]>::to_vec)
                .collect()
        });
        priority.append(&mut entries);
        entries = priority;
    }
    // Remove redundant entries by comparing the actual loader output for
    // every selected executable, not by guessing from directory existence.
    let mut index = entries.len();
    while index != 0 {
        index -= 1;
        let removed = entries.remove(index);
        let candidate = joined(&entries);
        if equivalent((!entries.is_empty()).then(|| OsStr::from_bytes(&candidate))).is_none() {
            entries.insert(index, removed);
        }
    }
    let path = joined(&entries);
    let selected = equivalent(Some(OsStr::from_bytes(&path)))
        .context("could not reconstruct caller ELF selection without host loader cache")?;
    Ok((Some(path), selected))
}

/// Resolve the actual loader-selected files in requested-library-name order.
/// Result identity can use this without constructing a delivery package.
pub(super) fn selected_loader_files(
    executable: &Path,
    environment: &[(OsString, OsString)],
    cwd: &Path,
) -> Result<Vec<PathBuf>> {
    let path = environment
        .iter()
        .rev()
        .find(|(name, _)| name == "LD_LIBRARY_PATH")
        .map(|(_, value)| value.as_os_str());
    Ok(LoaderProbe::open(executable.to_owned())?
        .resolve(environment, cwd, path, true)?
        .into_values()
        .collect())
}

/// The native platform supplies the core language and OS runtime. All other
/// selected libraries are compiler dependencies, even when a distribution
/// installs them in the system library directory. Private overrides remain
/// compiler inputs regardless of their library names.
fn is_compiler_code_library(path: &Path, private_root: Option<&Path>) -> bool {
    if private_root.is_some_and(|root| path.starts_with(root)) {
        return true;
    }
    if path.starts_with("/usr/local")
        || !["/usr/lib", "/lib", "/lib64", "/usr/lib64"]
            .iter()
            .any(|root| path.starts_with(root))
    {
        return true;
    }
    !path.file_name().is_some_and(|name| {
        [
            b"ld-linux-".as_slice(),
            b"ld-musl-",
            b"libc.so.",
            b"libm.so.",
            b"libpthread.so.",
            b"librt.so.",
            b"libdl.so.",
            b"libgcc_s.so.",
            b"libstdc++.so.",
            b"libresolv.so.",
        ]
        .iter()
        .any(|prefix| name.as_bytes().starts_with(prefix))
    })
}

/// Resolve only actually loaded compiler code. Ignore unrelated installed
/// libraries, path aliases, and the fixed platform's ordinary system runtime.
pub(super) fn selected_compiler_libraries(
    executable: &Path,
    environment: &[(OsString, OsString)],
    cwd: &Path,
    private_root: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let mut seen = BTreeSet::new();
    let mut selected = Vec::new();
    for path in selected_loader_files(executable, environment, cwd)? {
        let path = path.canonicalize()?;
        if is_compiler_code_library(&path, private_root) && seen.insert(path.clone()) {
            selected.push(path);
        }
    }
    Ok(selected)
}

pub(super) fn prepare_loader_search(
    builder: &mut ToolchainPackageBuilder,
    executables: &[PathBuf],
    environment: &[(OsString, OsString)],
    cwd: &Path,
) -> Result<Option<Vec<u8>>> {
    ensure!(
        !environment.iter().any(|(name, value)| {
            matches!(name.to_str(), Some("LD_PRELOAD" | "LD_AUDIT")) && !value.is_empty()
        }),
        "arbitrary loader extensions require local compilation"
    );
    let probes = executables
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(LoaderProbe::open)
        .collect::<Result<Vec<_>>>()?;
    let (libraries, selected) = search_contract(&probes, environment, cwd)?;
    for (probe, closure) in probes.iter().zip(selected) {
        if let Some(name) = probe.interpreter.as_ref().and_then(|path| path.file_name())
            && let Some(prefix) = name.as_bytes().strip_suffix(b".so.1")
            && prefix.starts_with(b"ld-musl-")
        {
            let config = Path::new("/etc")
                .join(OsStr::from_bytes(prefix))
                .with_extension("path");
            if config.is_file() {
                builder.add_file(config)?;
            }
        }
        let libraries = closure.into_values().collect::<Vec<_>>();
        builder.add_resolved_executable(&probe.executable, &libraries)?;
    }
    Ok(libraries)
}

pub(super) fn prepare_search(
    builder: &mut ToolchainPackageBuilder,
    executables: &[PathBuf],
    helpers: &[(OsString, PathBuf)],
    environment: &[(OsString, OsString)],
    cwd: &Path,
) -> Result<()> {
    let libraries = prepare_loader_search(builder, executables, environment, cwd)?;
    for (name, path) in helpers {
        builder.add_native_helper(name, path)?;
        builder.add_native_helper(path.file_name().context("helper has no basename")?, path)?;
    }
    builder.set_native_search(Some(b"/__sccache/toolchain/bin".to_vec()), libraries);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn selected_compiler_code_includes_distribution_and_private_libraries() {
        for path in [
            "/usr/lib/libclang-cpp.so.23.1",
            "/usr/lib/libLLVM.so.23.1",
            "/usr/lib/libisl.so.23",
            "/usr/lib/libmpc.so.3",
            "/usr/lib/libcustom.so",
            "/usr/lib/libzstd.so.1",
            "/usr/local/lib/libcustom.so",
            "/opt/compiler/lib/libcustom.so",
        ] {
            assert!(is_compiler_code_library(Path::new(path), None), "{path}");
        }
        assert!(!is_compiler_code_library(
            Path::new("/usr/lib/libc.so.6"),
            None
        ));
        assert!(!is_compiler_code_library(
            Path::new("/usr/lib/libstdc++.so.6"),
            None
        ));
        assert!(is_compiler_code_library(
            Path::new("/usr/lib/custom/libcode.so"),
            Some(Path::new("/usr/lib/custom"))
        ));
    }

    #[test]
    fn loader_selection_parser_preserves_requested_names() -> Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("libprobe.so"), b"fixture")?;
        let selection = parse_selection(
            b"linux-vdso.so.1 (0x123)\nlibprobe.so => libprobe.so (0x456)\n",
            temp.path(),
        )?;
        assert_eq!(
            selection[b"libprobe.so".as_slice()],
            temp.path().join("libprobe.so")
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires a real ELF C compiler"]
    fn custom_shared_library_selection_survives_search_reconstruction() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        let compiler = which::which("cc")?;
        for (directory, value) in [("one", 11), ("two", 22)] {
            let dir = root.join(directory);
            fs::create_dir(&dir)?;
            let source = dir.join("probe.c");
            fs::write(&source, format!("int probe(void) {{ return {value}; }}"))?;
            let output = process::Command::new(&compiler)
                .args(["-shared", "-fPIC", "-Wl,-soname,libprobe.so"])
                .arg(&source)
                .arg("-o")
                .arg(dir.join("libprobe.so"))
                .output()?;
            ensure!(
                output.status.success(),
                "fixture library failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let source = root.join("main.c");
        let executable = root.join("probe");
        fs::write(
            &source,
            "int probe(void); int main(void) { return probe(); }",
        )?;
        let output = process::Command::new(&compiler)
            .arg(&source)
            .arg(format!("-L{}", root.join("one").display()))
            .arg("-lprobe")
            .arg("-o")
            .arg(&executable)
            .output()?;
        ensure!(
            output.status.success(),
            "fixture executable failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let probes = [LoaderProbe::open(executable.clone())?];
        for (directory, value) in [("one", 11), ("two", 22)] {
            let lib = root.join(directory);
            let caller = format!("{}:{}", root.join("unused").display(), lib.display());
            let environment = [("LD_LIBRARY_PATH".into(), caller.into())];
            let (path, selected) = search_contract(&probes, &environment, root)?;
            let path = path.context("selected custom library lost its search path")?;
            assert_eq!(path, lib.as_os_str().as_bytes());
            assert_eq!(
                selected[0][b"libprobe.so".as_slice()],
                lib.join("libprobe.so")
            );
            let status = process::Command::new(&executable)
                .env_clear()
                .env("LD_LIBRARY_PATH", OsStr::from_bytes(&path))
                .status()?;
            assert_eq!(status.code(), Some(value));
        }
        Ok(())
    }
}
