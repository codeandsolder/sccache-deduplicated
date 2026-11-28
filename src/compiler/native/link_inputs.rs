//! Discover native linker dependencies separately from codegen. All
//! discovered paths are represented in the immutable task input tree.
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};

use crate::{
    build_runtime::{PreparedTree, SourceDigestCache},
    dist::{PathTransformer, pkg},
};

pub(super) struct LinkInputs {
    compiler: PathBuf,
    cwd: PathBuf,
    environment: Vec<(OsString, OsString)>,
    transformer: PathTransformer,
    arguments: Vec<OsString>,
}

impl LinkInputs {
    pub(super) fn new(
        compiler: PathBuf,
        cwd: PathBuf,
        environment: Vec<(OsString, OsString)>,
        transformer: &PathTransformer,
        arguments: Vec<OsString>,
    ) -> Self {
        let mut mapping = PathTransformer::new();
        for (physical, logical) in transformer.path_mappings() {
            mapping.add_root_mapping(physical, &logical);
        }
        Self {
            compiler,
            cwd,
            environment,
            transformer: mapping,
            arguments,
        }
    }

    fn query(&self, executable: &Path, args: &[&OsStr]) -> Result<String> {
        let output = Command::new(executable)
            .args(args)
            .current_dir(&self.cwd)
            .env_clear()
            .envs(self.environment.iter().cloned())
            .output()
            .with_context(|| format!("query linker toolchain {}", executable.display()))?;
        ensure!(
            output.status.success(),
            "linker toolchain query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?)
    }

    fn locate(&self, name: &OsStr) -> Result<PathBuf> {
        let path = Path::new(name);
        if path.is_absolute() {
            return self.physical(path);
        }
        if path.components().count() > 1 {
            return Ok(self.cwd.join(path));
        }
        let paths = self
            .environment
            .iter()
            .find(|(key, _)| key == "PATH")
            .map(|(_, value)| value);
        which::which_in(path, paths, &self.cwd)
            .with_context(|| format!("linker executable {} unavailable", path.display()))
    }

    fn physical(&self, logical: &Path) -> Result<PathBuf> {
        if logical.is_absolute() {
            Ok(self
                .transformer
                .to_local(logical.to_str().context("non-UTF8 logical linker input")?)?)
        } else {
            Ok(self.cwd.join(logical))
        }
    }

    fn target_spec(&self) -> Result<(super::super::rust::NativeLinkDiscovery, serde_json::Value)> {
        let options = super::super::rust::native_link_discovery(&self.arguments)?;
        let mut query = vec![
            OsString::from("-Z"),
            OsString::from("unstable-options"),
            OsString::from("--print"),
            OsString::from("target-spec-json"),
        ];
        if let Some(target) = &options.target {
            query.push("--target".into());
            let target = Path::new(target);
            query.push(if target.extension().is_some_and(|ext| ext == "json") {
                self.physical(target)?.into_os_string()
            } else {
                target.as_os_str().to_owned()
            });
        }
        let spec: serde_json::Value = serde_json::from_str(&self.query(
            &self.compiler,
            &query.iter().map(OsString::as_os_str).collect::<Vec<_>>(),
        )?)?;
        Ok((options, spec))
    }

    #[cfg(test)]
    pub(super) fn relay_basename(&self) -> Result<Option<OsString>> {
        let (options, spec) = self.target_spec()?;
        if !options.external_linker {
            return Ok(None);
        }
        let flavor = options
            .flavor
            .as_deref()
            .or_else(|| {
                spec.get("linker-flavor")
                    .and_then(serde_json::Value::as_str)
            })
            .context("target does not declare linker flavor")?;
        let name = options
            .linker
            .as_deref()
            .or_else(|| {
                spec.get("linker")
                    .and_then(serde_json::Value::as_str)
                    .map(OsStr::new)
            })
            .unwrap_or_else(|| {
                if flavor.ends_with("-cc") {
                    OsStr::new("cc")
                } else if flavor.contains("lld") || flavor.starts_with("wasm") {
                    OsStr::new("rust-lld")
                } else {
                    OsStr::new("ld")
                }
            });
        Ok(Some(
            Path::new(name)
                .file_name()
                .context("linker has no basename")?
                .to_owned(),
        ))
    }

    pub(super) fn prepare(
        &self,
        cache: &SourceDigestCache,
        client: Option<&super::NativeCompilerClient>,
    ) -> Result<Vec<PreparedTree>> {
        let (options, spec) = self.target_spec()?;
        let flavor = options
            .flavor
            .as_deref()
            .or_else(|| {
                spec.get("linker-flavor")
                    .and_then(serde_json::Value::as_str)
            })
            .context("target does not declare linker flavor")?;
        // The target may specify an explicit driver. Do not select one based
        // on the worker's installation or environment.
        let linker_name = options.linker.as_deref().or_else(|| {
            spec.get("linker")
                .and_then(serde_json::Value::as_str)
                .map(OsStr::new)
        });
        let mut tools = pkg::ToolchainPackageBuilder::new();
        for (physical, logical) in self.transformer.path_mappings() {
            tools.add_root_mapping(physical, PathBuf::from(logical));
        }
        tools.add_common()?;
        let mut search = BTreeSet::new();
        if flavor.ends_with("-cc") {
            let driver = self.locate(linker_name.unwrap_or_else(|| OsStr::new("cc")))?;
            tools.add_executable_and_deps(driver.clone())?;
            let dirs = self.query(&driver, &[OsStr::new("-print-search-dirs")])?;
            let libraries = dirs
                .lines()
                .find_map(|line| line.strip_prefix("libraries: "))
                .context("link driver did not declare library search directories")?;
            for dir in libraries
                .trim_start_matches('=')
                .split(':')
                .filter(|dir| !dir.is_empty())
            {
                let path = self.cwd.join(dir);
                if path.is_dir() {
                    search.insert(path);
                }
            }
            for helper in ["ld", "collect2", "lto-wrapper", "lto1", "as", "objcopy"] {
                let query = format!("-print-prog-name={helper}");
                let value = self.query(&driver, &[OsStr::new(&query)])?;
                let name = Path::new(value.trim());
                // Drivers report the bare name for an uninstalled optional
                // helper. Required ld must be present.
                if name.is_absolute() || helper == "ld" || name.as_os_str() != OsStr::new(helper) {
                    let executable = self.locate(name.as_os_str())?;
                    tools.add_executable_and_deps(executable)?;
                }
            }
            for file in ["specs", "liblto_plugin.so"] {
                let query = format!("-print-file-name={file}");
                let value = self.query(&driver, &[OsStr::new(&query)])?;
                let path = Path::new(value.trim());
                if path.is_absolute() {
                    tools.add_file(path.to_owned())?;
                }
            }
        } else if let Some(name) = linker_name {
            if name != "rust-lld" {
                tools.add_executable_and_deps(self.locate(name)?)?;
            }
        } else {
            ensure!(
                flavor.contains("lld") || flavor.starts_with("wasm"),
                "automatic linker inventory unavailable for target flavor {flavor}"
            );
        }

        // Capture every library candidate in the driver's declared search
        // directories, including startup objects and linker scripts with
        // library filenames. This preserves lookup precedence without
        // assuming an installed library version.
        for directory in search {
            tools.add_dir(directory.clone())?;
            for entry in std::fs::read_dir(&directory)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if (name.ends_with(".a")
                    || name.ends_with(".o")
                    || name.ends_with(".so")
                    || name.contains(".so."))
                    && entry.path().is_file()
                {
                    tools.add_file(entry.path())?;
                }
            }
        }

        let mut mapping = PathTransformer::new();
        for (physical, logical) in self.transformer.path_mappings() {
            mapping.add_root_mapping(physical, &logical);
        }
        let mut inputs = pkg::CompilerInputs::new(mapping);
        let mut roots = options.search_paths;
        let mut explicit = BTreeSet::new();
        let mut pending = options.link_arguments;
        let mut visited_responses = BTreeSet::new();
        while let Some(argument) = pending.pop() {
            if let Some(response) = argument.strip_prefix('@') {
                let path = self.physical(Path::new(response))?;
                if visited_responses.insert(path.clone()) {
                    inputs.file(&path, None)?;
                    let contents = std::fs::read_to_string(&path)?;
                    pending
                        .extend(shlex::split(&contents).context("invalid linker response file")?);
                }
            } else if let Some(arguments) = argument.strip_prefix("-Wl,") {
                pending.extend(arguments.split(',').map(str::to_owned));
            } else if let Some(directory) = argument
                .strip_prefix("-L")
                .filter(|value| !value.is_empty())
            {
                roots.push(PathBuf::from(directory));
            } else if !argument.starts_with('-') {
                let path = self.physical(Path::new(&argument))?;
                if path.is_file() {
                    explicit.insert(path);
                }
            } else if let Some((_, value)) = argument.split_once('=') {
                let path = self.physical(Path::new(value))?;
                if path.is_file() {
                    explicit.insert(path);
                }
            }
        }
        for directory in roots {
            let directory = self.physical(&directory)?;
            if !directory.is_dir() {
                continue;
            }
            inputs.directory(&directory)?;
            for entry in std::fs::read_dir(&directory)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if (name.ends_with(".a")
                    || name.ends_with(".o")
                    || name.ends_with(".so")
                    || name.contains(".so."))
                    && entry.path().is_file()
                {
                    explicit.insert(entry.path());
                }
            }
        }
        for path in explicit {
            inputs.file(&path, None)?;
        }
        let mapped = inputs.into_native_mapping(|logical| {
            logical.starts_with("/target") || logical.starts_with("/intermediate")
        })?;
        let inputs = if let Some(client) = client {
            mapped.prepare_with_references(&|file, _| client.reference(file))?
        } else {
            mapped.prepare()?
        };
        Ok(vec![
            tools.into_native_mapping()?.prepare_with_cache(cache)?,
            inputs,
        ])
    }
}
