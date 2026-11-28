//! Discover native linker dependencies separately from codegen. All
//! discovered paths are represented in the immutable task input tree.
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};
mod closure;
mod driver;
mod elf;

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

    pub(super) fn relay(&self) -> Result<Option<(OsString, usize)>> {
        let options = super::super::rust::native_link_discovery(&self.arguments)?;
        if options.external_linkers == 0 {
            return Ok(None);
        }
        let (_, spec) = self.target_spec()?;
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
        Ok(Some((
            Path::new(name)
                .file_name()
                .context("linker has no basename")?
                .to_owned(),
            options.external_linkers,
        )))
    }

    /// Native archives consumed by rustc itself (including staticlib output)
    /// are not necessarily operands of an external linker. Resolve only
    /// explicitly named libraries, in search order, using the target format.
    pub(super) fn prepare_declared(
        &self,
        client: Option<&super::NativeCompilerClient>,
    ) -> Result<Vec<PreparedTree>> {
        let options = super::super::rust::native_link_discovery(&self.arguments)?;
        if options.static_libraries.is_empty() || options.native_paths.is_empty() {
            return Ok(Vec::new());
        }
        let (_, spec) = self.target_spec()?;
        let prefix = spec
            .get("staticlib-prefix")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("lib");
        let suffix = spec
            .get("staticlib-suffix")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(".a");
        let mut files = BTreeSet::new();
        for (name, verbatim) in options.static_libraries {
            let names = if verbatim {
                vec![name]
            } else {
                vec![format!("{prefix}{name}{suffix}"), format!("lib{name}.a")]
            };
            // An absent candidate is not an input. Rustc or the actual
            // linker may find an installed library in the declared sysroot.
            'search: for directory in &options.native_paths {
                for name in &names {
                    let candidate = self.physical(&directory.join(name))?;
                    match std::fs::metadata(&candidate) {
                        Ok(metadata) if metadata.is_file() => {
                            files.insert(candidate);
                            break 'search;
                        }
                        Ok(_) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                            ) => {}
                        Err(error) => {
                            return Err(error).with_context(|| {
                                format!("resolve declared native library {}", candidate.display())
                            });
                        }
                    }
                }
            }
        }
        if files.is_empty() {
            return Ok(Vec::new());
        }
        let closure = closure::LinkClosure::discover(
            files.into_iter().map(PathBuf::into_os_string).collect(),
            &self.cwd,
            closure::LinkerSearch::default(),
            &|path| Ok(path.to_owned()),
            &|_| false,
        )?;
        let mut inputs = pkg::ToolchainPackageBuilder::new();
        for (physical, logical) in self.transformer.path_mappings() {
            inputs.add_root_mapping(physical, PathBuf::from(logical));
        }
        for file in closure.files {
            inputs.add_file(file)?;
        }
        let mapped = inputs.into_native_mapping()?;
        Ok(vec![if let Some(client) = client {
            mapped.prepare_with_references(&|file, _| client.reference(file))?
        } else {
            mapped.prepare()?
        }])
    }

    pub(super) fn prepare_captured(
        &self,
        capture: &super::link_capture::CapturedInvocation,
        generated_paths: &BTreeSet<PathBuf>,
        cache: &SourceDigestCache,
        client: Option<&super::NativeCompilerClient>,
    ) -> Result<Vec<PreparedTree>> {
        let driver = driver::DriverPlan::discover(self, capture)?;
        // Captured generated paths are created by rustc itself in the final
        // action. All other paths have to be resolved in the caller's view.
        let generated = |path: &Path| generated_paths.contains(path);
        let closure = closure::LinkClosure::discover(
            driver.arguments,
            &capture.cwd,
            driver.search,
            &|path| self.physical(path),
            &generated,
        )?;
        let mut tools = pkg::ToolchainPackageBuilder::new();
        for (physical, logical) in self.transformer.path_mappings() {
            tools.add_root_mapping(physical, PathBuf::from(logical));
        }
        tools.add_common()?;
        for tool in driver.tools {
            tools.add_executable_and_deps(tool)?;
        }
        // Use the physical-path-aware package builder for both tools and
        // data; system library aliases such as /lib -> /usr/lib must retain
        // the same symlink topology as the compiler toolchain.
        let mut inputs = pkg::ToolchainPackageBuilder::new();
        for (physical, logical) in self.transformer.path_mappings() {
            inputs.add_root_mapping(physical, PathBuf::from(logical));
        }
        for directory in closure.directories {
            let physical = self.physical(&directory)?;
            if physical.is_dir() {
                inputs.add_dir(physical)?;
            }
        }
        for file in closure.files.into_iter().chain(driver.response_files) {
            if !generated(&file) {
                inputs.add_file(self.physical(&file)?)?;
            }
        }
        let mapped = inputs.into_native_mapping()?;
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
