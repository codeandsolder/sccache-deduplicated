use anyhow::{Context, Result, bail, ensure};
use sccache_rust_build::Platform;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use toml::{Table, Value};

#[derive(Debug)]
pub struct Toolchain {
    pub rustc: PathBuf,
    pub clippy: Option<PathBuf>,
    pub rustdoc: Option<PathBuf>,
    pub host: Platform,
    pub target: Platform,
    pub version: String,
    pub explicit_target: Option<OsString>,
}

fn output(command: &mut Command) -> Result<String> {
    let result = command.output()?;
    ensure!(
        result.status.success(),
        "{}: {}",
        command.get_program().to_string_lossy(),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?.trim_end().to_owned())
}

fn tool(name: &str, explicit: Option<&Path>, cwd: &Path) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(which::which_in(path, std::env::var_os("PATH"), cwd)?);
    }
    // rustup selects the toolchain named by rust-toolchain.toml, without
    // running Cargo or relying on a compiler proxy's timestamp.
    let path = output(
        Command::new("rustup")
            .current_dir(cwd)
            .args(["which", name]),
    );
    match path {
        Ok(path) => Ok(PathBuf::from(path)),
        Err(_) => Ok(which::which_in(name, std::env::var_os("PATH"), cwd)?),
    }
}

impl Toolchain {
    pub fn discover(
        cwd: &Path,
        rustc: Option<&Path>,
        target: Option<&OsStr>,
        clippy: bool,
        docs: bool,
    ) -> Result<Self> {
        let rustc = tool("rustc", rustc, cwd)?;
        let version = output(Command::new(&rustc).current_dir(cwd).arg("-vV"))?;
        let host = version
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .context("rustc has no host triple")?
            .to_owned();
        let host_cfg = output(
            Command::new(&rustc)
                .current_dir(cwd)
                .args(["--print", "cfg"]),
        )?;
        let host = Platform::parse(host, &host_cfg)?;
        let target_platform = if let Some(target) = target {
            let target_cfg = output(
                Command::new(&rustc)
                    .current_dir(cwd)
                    .args(["--print", "cfg", "--target"])
                    .arg(target),
            )?;
            let triple = Path::new(target)
                .file_stem()
                .and_then(OsStr::to_str)
                .context("target name is not UTF-8")?;
            Platform::parse(triple.into(), &target_cfg)?
        } else {
            host.clone()
        };
        let companion = |name: &str| -> Result<PathBuf> {
            let path = rustc.with_file_name(name);
            if path.is_file() {
                Ok(path)
            } else {
                tool(name, None, cwd)
            }
        };
        let clippy = clippy.then(|| companion("clippy-driver")).transpose()?;
        let rustdoc = docs.then(|| companion("rustdoc")).transpose()?;
        Ok(Self {
            rustc,
            clippy,
            rustdoc,
            host,
            target: target_platform,
            version,
            explicit_target: target.map(OsStr::to_owned),
        })
    }

    pub fn filenames(&self, crate_types: &[String], host: bool, test: bool) -> Result<Vec<String>> {
        let mut command = Command::new(&self.rustc);
        command
            .args([
                "--print=file-names",
                "--crate-name",
                "sccache_probe",
                "--crate-type",
            ])
            .arg(crate_types.join(","));
        command.args(["-C", "extra-filename=-sccache_tag"]);
        if test {
            command.arg("--test");
        }
        if !host && let Some(target) = &self.explicit_target {
            command.arg("--target").arg(target);
        }
        command.arg("-").stdin(std::process::Stdio::null());
        Ok(output(&mut command)?.lines().map(str::to_owned).collect())
    }
}

#[derive(Default, Debug)]
pub struct Settings {
    pub environment: BTreeMap<OsString, OsString>,
    pub document: Table,
}

fn merge(parent: &mut Table, child: Table) {
    for (name, value) in child {
        if let Some(Value::Table(existing)) = parent.get_mut(&name)
            && let Value::Table(child) = &value
        {
            merge(existing, child.clone());
        } else {
            parent.insert(name, value);
        }
    }
}

fn flags(value: &Value) -> Result<Vec<OsString>> {
    match value {
        Value::Array(values) => values
            .iter()
            .map(|value| {
                Ok(OsString::from(
                    value.as_str().context("rustflags entry not string")?,
                ))
            })
            .collect(),
        Value::String(value) => Ok(value.split_whitespace().map(OsString::from).collect()),
        _ => bail!("invalid rustflags"),
    }
}

impl Settings {
    pub fn load(cwd: &Path, import_root: Option<&Path>) -> Result<Self> {
        let mut result = Self {
            environment: std::env::vars_os().collect(),
            document: Table::new(),
        };
        let paths = import_root.into_iter().map(Path::to_path_buf).chain(
            cwd.ancestors()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .map(|p| p.join(".cargo")),
        );
        for dir in paths {
            let path = dir.join("config.toml");
            let path = if path.exists() {
                path
            } else {
                dir.join("config")
            };
            if !path.is_file() {
                continue;
            }
            let table: Table = toml::from_str(&fs::read_to_string(&path)?)
                .with_context(|| format!("parse {}", path.display()))?;
            if let Some(env) = table.get("env").and_then(Value::as_table) {
                for (key, value) in env {
                    let (value, force, relative) = match value {
                        Value::String(v) => (v.as_str(), false, false),
                        Value::Table(t) => (
                            t.get("value")
                                .and_then(Value::as_str)
                                .context("invalid configured env value")?,
                            t.get("force").and_then(Value::as_bool).unwrap_or(false),
                            t.get("relative").and_then(Value::as_bool).unwrap_or(false),
                        ),
                        _ => bail!("invalid env configuration for {key}"),
                    };
                    if force || !result.environment.contains_key(OsStr::new(key)) {
                        let value = if relative {
                            dir.parent()
                                .context("config has no parent")?
                                .join(value)
                                .into_os_string()
                        } else {
                            value.into()
                        };
                        result.environment.insert(key.into(), value);
                    }
                }
            }
            merge(&mut result.document, table);
        }
        // Never inherit another tool's jobserver or incremental policy.
        for key in [
            "CARGO_MAKEFLAGS",
            "MAKEFLAGS",
            "MFLAGS",
            "CARGO_INCREMENTAL",
            "CARGO_BUILD_INCREMENTAL",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
        ] {
            if matches!(key, "RUSTFLAGS" | "CARGO_ENCODED_RUSTFLAGS") {
                continue;
            }
            result.environment.remove(OsStr::new(key));
        }
        Ok(result)
    }

    pub fn target(&self) -> Option<&str> {
        self.document
            .get("build")
            .and_then(Value::as_table)
            .and_then(|v| v.get("target"))
            .and_then(Value::as_str)
    }

    pub fn rustflags(
        &self,
        platform: &Platform,
        host: bool,
        explicit_target: bool,
    ) -> Result<Vec<OsString>> {
        if host && explicit_target {
            return Ok(Vec::new());
        }
        if let Some(value) = self.environment.get(OsStr::new("CARGO_ENCODED_RUSTFLAGS")) {
            return Ok(value
                .to_string_lossy()
                .split('\u{1f}')
                .filter(|v| !v.is_empty())
                .map(OsString::from)
                .collect());
        }
        if let Some(value) = self.environment.get(OsStr::new("RUSTFLAGS")) {
            return Ok(value
                .to_string_lossy()
                .split_whitespace()
                .map(OsString::from)
                .collect());
        }
        let mut result = Vec::new();
        if let Some(targets) = self.document.get("target").and_then(Value::as_table) {
            for (selector, value) in targets {
                if platform.matches(selector)?
                    && let Some(value) = value.as_table().and_then(|t| t.get("rustflags"))
                {
                    result.extend(flags(value)?);
                }
            }
        }
        if result.is_empty()
            && let Some(value) = self
                .document
                .get("build")
                .and_then(Value::as_table)
                .and_then(|t| t.get("rustflags"))
        {
            result = flags(value)?;
        }
        Ok(result)
    }

    pub fn linker(&self, platform: &Platform) -> Result<Option<OsString>> {
        let Some(targets) = self.document.get("target").and_then(Value::as_table) else {
            return Ok(None);
        };
        if let Some(value) = targets
            .get(&platform.triple)
            .and_then(Value::as_table)
            .and_then(|t| t.get("linker"))
        {
            return Ok(Some(
                value.as_str().context("linker is not a string")?.into(),
            ));
        }
        let mut selected = None;
        for (selector, value) in targets {
            if selector.starts_with("cfg(")
                && platform.matches(selector)?
                && let Some(value) = value.as_table().and_then(|t| t.get("linker"))
            {
                ensure!(selected.is_none(), "multiple matching cfg linkers");
                selected = Some(value.as_str().context("linker is not a string")?.into());
            }
        }
        Ok(selected)
    }
}
