//! Registry identities are independent of their acquisition endpoints.
//! The lockfile identifies the source; a configured scheduler upstream
//! provides immutable, checksum-verified archives.
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use toml::{Table, Value};

pub const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[derive(Debug, Clone)]
pub struct Registry {
    pub source: String,
    pub index: String,
    pub upstream: String,
    pub archive_template: String,
    pub offline_index: Option<PathBuf>,
    pub archive_base: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Registries {
    entries: BTreeMap<String, Registry>,
    aliases: BTreeMap<String, String>,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

pub(crate) fn prefix(name: &str) -> Result<String> {
    ensure!(valid_name(name), "invalid registry package name {name:?}");
    Ok(match name.len() {
        1 => "1".into(),
        2 => "2".into(),
        3 => format!("3/{}", &name[..1]),
        _ => format!("{}/{}", &name[..2], &name[2..4]),
    })
}

pub(crate) fn index_path(name: &str) -> Result<String> {
    let name = name.to_ascii_lowercase();
    Ok(format!("{}/{name}", prefix(&name)?))
}

/// Keep Cargo.lock source identifiers, not endpoint/mirror names.
pub(crate) fn registry_source(index: &str) -> Result<String> {
    let (kind, address) = if let Some(address) = index.strip_prefix("sparse+") {
        ("sparse+", address)
    } else {
        (
            "registry+",
            index.strip_prefix("registry+").unwrap_or(index),
        )
    };
    let address = url::Url::parse(address)?;
    ensure!(
        matches!(address.scheme(), "https" | "http" | "file" | "ssh" | "git")
            && address.username().is_empty()
            && address.password().is_none()
            && address.query().is_none()
            && address.fragment().is_none(),
        "invalid registry index URL"
    );
    if matches!(
        address.as_str().trim_end_matches('/'),
        "https://github.com/rust-lang/crates.io-index" | "https://index.crates.io"
    ) {
        return Ok(CRATES_IO.to_owned());
    }
    if kind == "sparse+" {
        ensure!(
            matches!(address.scheme(), "http" | "https" | "file"),
            "sparse index must be HTTP(S) or local"
        );
        ensure!(
            address.path().ends_with('/'),
            "sparse index URL must end in '/'"
        );
    }
    Ok(format!("{kind}{address}"))
}

impl Default for Registries {
    fn default() -> Self {
        let crates = Registry {
            source: CRATES_IO.into(),
            index: "sparse+https://index.crates.io/".into(),
            upstream: "crates".into(),
            archive_template: "crates/{crate}/{crate}-{version}.crate".into(),
            offline_index: None,
            archive_base: Some("https://static.crates.io/".into()),
        };
        Self {
            entries: BTreeMap::from([(CRATES_IO.to_owned(), crates)]),
            aliases: BTreeMap::from([("crates-io".into(), CRATES_IO.into())]),
        }
    }
}

fn string<'a>(table: &'a Table, key: &str) -> Result<Option<&'a str>> {
    table
        .get(key)
        .map(|v| {
            v.as_str()
                .with_context(|| format!("{key} must be a string"))
        })
        .transpose()
}

impl Registries {
    /// Alternate registries use the ecosystem index identifier but explicitly
    /// name an allowed scheduler package repository and relative path template.
    /// No client-provided archive host is accepted by the scheduler.
    pub fn from_settings(document: &Table) -> Result<Self> {
        let mut result = Self::default();
        if let Some(registries) = document.get("registries").and_then(Value::as_table) {
            for (name, value) in registries {
                ensure!(valid_name(name), "invalid registry name {name}");
                let values = value
                    .as_table()
                    .context("registry configuration must be a table")?;
                let Some(index) = string(values, "index")? else {
                    continue;
                };
                let source = registry_source(index)?;
                let existing = result.entries.get(&source);
                let upstream = string(values, "sccache-upstream")?
                    .map(str::to_owned)
                    .or_else(|| existing.map(|r| r.upstream.clone()))
                    .unwrap_or_else(|| name.clone());
                let archive_template = string(values, "sccache-archive-path")?
                    .map(str::to_owned)
                    .or_else(|| existing.map(|r| r.archive_template.clone()))
                    .unwrap_or_default();
                let archive_base = string(values, "sccache-archive-base")?
                    .map(str::to_owned)
                    .or_else(|| existing.and_then(|r| r.archive_base.clone()));
                let offline_index = string(values, "sccache-index-cache")?.map(PathBuf::from);
                if let Some(path) = &offline_index {
                    ensure!(path.is_absolute(), "sccache-index-cache must be absolute");
                }
                let registry = Registry {
                    source: source.clone(),
                    index: index.to_owned(),
                    upstream,
                    archive_template,
                    archive_base,
                    offline_index,
                };
                result.aliases.insert(name.clone(), source.clone());
                result.entries.insert(source, registry);
            }
        }
        Ok(result)
    }

    pub fn get(&self, name: Option<&str>) -> Result<&Registry> {
        let name = name.unwrap_or("crates-io");
        if let Some(source) = self.aliases.get(name) {
            return self
                .entries
                .get(source)
                .context("registry alias lacks source");
        }
        let source = registry_source(name)?;
        self.entries
            .get(&source)
            .with_context(|| format!("registry {name:?} is not configured"))
    }

    pub fn matches(&self, requested: &Registry, source: &str) -> bool {
        registry_source(source).is_ok_and(|source| source == requested.source)
    }
}

impl Registry {
    pub fn archive_path(&self, name: &str, version: &str, checksum: &str) -> Result<String> {
        ensure!(
            !self.archive_template.is_empty(),
            "registry {} needs sccache-archive-path",
            self.source
        );
        ensure!(
            checksum.len() == 64 && checksum.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid registry archive checksum"
        );
        let path = self
            .archive_template
            .replace("{crate}", name)
            .replace("{version}", version)
            .replace("{prefix}", &prefix(name)?)
            .replace("{lowerprefix}", &prefix(&name.to_ascii_lowercase())?)
            .replace("{sha256-checksum}", checksum);
        ensure!(
            !path.is_empty()
                && path.split('/').all(|segment| !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|b| b.is_ascii_alphanumeric()
                        || matches!(b, b'-' | b'_' | b'.' | b'+' | b'~' | b'@'))),
            "invalid registry archive relative path"
        );
        Ok(path)
    }

    pub fn archive_url(&self, name: &str, version: &str, checksum: &str) -> Result<String> {
        let mut base = url::Url::parse(
            self.archive_base
                .as_deref()
                .context("registry has no direct archive base")?,
        )?;
        ensure!(
            base.path().ends_with('/') && base.query().is_none() && base.fragment().is_none(),
            "invalid archive base"
        );
        base.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("invalid archive URL"))?
            .pop_if_empty()
            .extend(self.archive_path(name, version, checksum)?.split('/'));
        Ok(base.to_string())
    }

    pub(crate) fn sparse_url(&self, name: &str) -> Result<Option<String>> {
        let Some(index) = self.index.strip_prefix("sparse+") else {
            return Ok(None);
        };
        let mut index = url::Url::parse(index)?;
        index
            .path_segments_mut()
            .map_err(|()| anyhow::anyhow!("invalid sparse index URL"))?
            .pop_if_empty()
            .extend(index_path(name)?.split('/'));
        Ok(Some(index.to_string()))
    }

    pub(crate) fn offline_entry(
        &self,
        import: Option<&Path>,
        name: &str,
    ) -> Result<Option<Vec<u8>>> {
        let relative = index_path(name)?;
        if let Some(root) = &self.offline_index {
            for path in [root.join(".cache").join(&relative), root.join(&relative)] {
                if path.is_file() {
                    return Ok(Some(fs::read(path)?));
                }
            }
            return Ok(None);
        }
        if self.source != CRATES_IO {
            bail!(
                "registry {} needs an explicit offline index cache",
                self.source
            );
        }
        let Some(import) = import else {
            return Ok(None);
        };
        let index = import.join("registry/index");
        if !index.is_dir() {
            return Ok(None);
        }
        let mut found = None;
        for entry in fs::read_dir(index)? {
            let entry = entry?;
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with("index.crates.io-")
            {
                continue;
            }
            let path = entry.path().join(".cache").join(&relative);
            if path.is_file() {
                let bytes = fs::read(path)?;
                ensure!(
                    found.as_ref().is_none_or(|old| old == &bytes),
                    "conflicting offline crates.io indexes for {name}"
                );
                found = Some(bytes);
            }
        }
        Ok(found)
    }
}

/// A missing sparse index object is different from a network failure.
#[derive(Debug)]
pub struct IndexNotFound;
impl std::fmt::Display for IndexNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("registry index entry not found")
    }
}
impl std::error::Error for IndexNotFound {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_identity_is_not_the_scheduler_endpoint() -> Result<()> {
        let config: Table = toml::from_str(
            r#"
[registries.private]
index = "sparse+https://registry.example/index/"
sccache-upstream = "private-mirror"
sccache-archive-path = "objects/{lowerprefix}/{crate}/{version}/{sha256-checksum}.crate"
"#,
        )?;
        let registries = Registries::from_settings(&config)?;
        let registry = registries.get(Some("private"))?;
        assert_eq!(registry.source, "sparse+https://registry.example/index/");
        assert_eq!(registry.upstream, "private-mirror");
        assert_eq!(
            registry.sparse_url("My-Crate")?.as_deref(),
            Some("https://registry.example/index/my/-c/my-crate")
        );
        let checksum = "ab".repeat(32);
        assert_eq!(
            registry.archive_path("My-Crate", "1.2.3", &checksum)?,
            format!("objects/my/-c/My-Crate/1.2.3/{checksum}.crate")
        );
        assert_eq!(
            registries
                .get(Some("sparse+https://index.crates.io/"))?
                .source,
            CRATES_IO
        );
        assert!(registry.archive_path("../bad", "1", &checksum).is_err());
        assert!(!registries.matches(registry, CRATES_IO));
        Ok(())
    }
}
