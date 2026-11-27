//! Build-script output is an ordered protocol; link arguments must not be
//! sorted or deduplicated because the native linker's order is significant.
use crate::TargetKind;
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub enum LinkScope {
    All,
    Binary(String),
    Kind(TargetKind),
    Cdylib,
}

#[derive(Debug, Default, Clone)]
pub struct ScriptOutput {
    pub env: BTreeMap<String, String>,
    pub metadata: BTreeMap<String, String>,
    pub cfg: Vec<String>,
    pub check_cfg: Vec<String>,
    pub links: Vec<LinkDirective>,
    pub warnings: Vec<String>,
    pub tracked_paths: Vec<PathBuf>,
    pub tracked_env: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum LinkDirective {
    Search(String),
    Library(String),
    Argument(LinkScope, String),
}

impl ScriptOutput {
    pub fn read(path: &Path) -> Result<Self> {
        Self::parse(
            &fs::read(path)
                .with_context(|| format!("read build script output {}", path.display()))?,
        )
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut output = Self::default();
        for line in bytes.split(|b| *b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let (line, modern) = if let Some(line) = line.strip_prefix(b"cargo::") {
                (line, true)
            } else if let Some(line) = line.strip_prefix(b"cargo:") {
                (line, false)
            } else {
                continue;
            };
            let line = std::str::from_utf8(line).context("invalid UTF-8 build script directive")?;
            let (key, value) = line
                .split_once('=')
                .context("build script directive lacks '='")?;
            match key {
                "rustc-env" | "metadata" => {
                    let (name, value) = value
                        .split_once('=')
                        .context("build script key/value directive lacks '='")?;
                    ensure!(
                        !name.is_empty() && !name.contains('\0'),
                        "invalid build script variable"
                    );
                    if key == "rustc-env" {
                        output.env.insert(name.into(), value.into());
                    } else {
                        output.metadata.insert(name.into(), value.into());
                    }
                }
                "rustc-cfg" => output.cfg.push(value.into()),
                "rustc-check-cfg" => output.check_cfg.push(value.into()),
                "rustc-link-search" => output.links.push(LinkDirective::Search(value.into())),
                "rustc-link-lib" => output.links.push(LinkDirective::Library(value.into())),
                "rustc-link-arg" => output
                    .links
                    .push(LinkDirective::Argument(LinkScope::All, value.into())),
                "rustc-link-arg-bin" => {
                    let (name, arg) = value
                        .split_once('=')
                        .context("missing link argument for binary")?;
                    output.links.push(LinkDirective::Argument(
                        LinkScope::Binary(name.into()),
                        arg.into(),
                    ));
                }
                "rustc-link-arg-bins" => output.links.push(LinkDirective::Argument(
                    LinkScope::Kind(TargetKind::Binary),
                    value.into(),
                )),
                "rustc-link-arg-tests" => output.links.push(LinkDirective::Argument(
                    LinkScope::Kind(TargetKind::Test),
                    value.into(),
                )),
                "rustc-link-arg-examples" => output.links.push(LinkDirective::Argument(
                    LinkScope::Kind(TargetKind::Example),
                    value.into(),
                )),
                "rustc-link-arg-benches" => output.links.push(LinkDirective::Argument(
                    LinkScope::Kind(TargetKind::Bench),
                    value.into(),
                )),
                "rustc-link-arg-cdylib" | "rustc-cdylib-link-arg" => output
                    .links
                    .push(LinkDirective::Argument(LinkScope::Cdylib, value.into())),
                "rustc-flags" => {
                    let mut flags = value.split_whitespace();
                    while let Some(flag) = flags.next() {
                        let (key, value) = if flag == "-l" || flag == "-L" {
                            (flag, flags.next().context("missing rustc-flags value")?)
                        } else {
                            ensure!(
                                flag.len() > 2 && flag.is_char_boundary(2),
                                "invalid rustc-flags"
                            );
                            flag.split_at(2)
                        };
                        match key {
                            "-l" => output.links.push(LinkDirective::Library(value.into())),
                            "-L" => output.links.push(LinkDirective::Search(value.into())),
                            _ => bail!("unsupported rustc-flags option {key}"),
                        }
                    }
                }
                "warning" => output.warnings.push(value.into()),
                "error" => bail!("build script: {value}"),
                "rerun-if-changed" => output.tracked_paths.push(PathBuf::from(value)),
                "rerun-if-env-changed" => output.tracked_env.push(value.into()),
                _ if !modern => {
                    output.metadata.insert(key.into(), value.into());
                }
                _ => bail!("unknown build script directive {key}"),
            }
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directives_keep_link_order_and_metadata() -> Result<()> {
        let output = ScriptOutput::parse(b"ordinary output\ncargo:root=/some/path\ncargo::metadata=token=a=b\ncargo::rustc-link-lib=foo\ncargo:rustc-link-search=native=/a\ncargo::rustc-link-lib=bar\ncargo::rustc-env=TOKEN=x=y\n")?;
        assert_eq!(output.metadata["token"], "a=b");
        assert_eq!(output.env["TOKEN"], "x=y");
        assert!(
            matches!(&output.links[..],[LinkDirective::Library(a),LinkDirective::Search(b),LinkDirective::Library(c)] if a=="foo" && b=="native=/a" && c=="bar")
        );
        assert!(ScriptOutput::parse(b"cargo::error=broken").is_err());
        Ok(())
    }
}
