use anyhow::{Context, Result, bail, ensure};
use std::collections::{BTreeMap, BTreeSet};

/// Rustc's actual cfg set, not a guessed mapping from target triples.
#[derive(Debug, Clone)]
pub struct Platform {
    pub triple: String,
    flags: BTreeSet<String>,
    values: BTreeMap<String, BTreeSet<String>>,
}

impl Platform {
    pub fn parse(triple: String, cfg: &str) -> Result<Self> {
        let mut result = Self {
            triple,
            flags: BTreeSet::new(),
            values: BTreeMap::new(),
        };
        for line in cfg.lines().filter(|l| !l.is_empty()) {
            if let Some((key, value)) = line.split_once('=') {
                let value = quoted(value)?;
                result
                    .values
                    .entry(key.to_owned())
                    .or_default()
                    .insert(value);
            } else {
                ensure!(
                    line.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                    "invalid rustc cfg {line:?}"
                );
                result.flags.insert(line.to_owned());
            }
        }
        Ok(result)
    }

    pub fn matches(&self, selector: &str) -> Result<bool> {
        if let Some(expression) = selector
            .strip_prefix("cfg(")
            .and_then(|s| s.strip_suffix(')'))
        {
            let mut parser = Parser {
                rest: expression,
                platform: self,
            };
            let result = parser.expression()?;
            ensure!(
                parser.rest.trim().is_empty(),
                "trailing target cfg tokens: {selector}"
            );
            Ok(result)
        } else {
            Ok(self.triple == selector)
        }
    }

    pub fn environment(&self) -> BTreeMap<String, String> {
        self.flags
            .iter()
            .map(|name| (format!("CARGO_CFG_{}", name.to_uppercase()), String::new()))
            .chain(self.values.iter().map(|(key, values)| {
                (
                    format!("CARGO_CFG_{}", key.to_uppercase()),
                    values.iter().cloned().collect::<Vec<_>>().join(","),
                )
            }))
            .collect()
    }
}

fn quoted(value: &str) -> Result<String> {
    let literal = format!("value = {value}");
    let parsed: toml::Table = toml::from_str(&literal)?;
    Ok(parsed
        .get("value")
        .and_then(toml::Value::as_str)
        .context("cfg value is not a string")?
        .to_owned())
}

struct Parser<'a> {
    rest: &'a str,
    platform: &'a Platform,
}

impl Parser<'_> {
    fn take(&mut self, token: char) -> bool {
        self.rest = self.rest.trim_start();
        if let Some(rest) = self.rest.strip_prefix(token) {
            self.rest = rest;
            true
        } else {
            false
        }
    }

    fn expression(&mut self) -> Result<bool> {
        self.rest = self.rest.trim_start();
        let end = self
            .rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(self.rest.len());
        ensure!(end > 0, "expected target cfg identifier");
        let (name, rest) = self.rest.split_at(end);
        self.rest = rest;
        if self.take('(') {
            let mut values = Vec::new();
            while !self.take(')') {
                values.push(self.expression()?);
                if self.take(')') {
                    break;
                }
                ensure!(self.take(','), "expected comma in target cfg");
            }
            return match name {
                "all" => Ok(values.into_iter().all(|v| v)),
                "any" => Ok(values.into_iter().any(|v| v)),
                "not" if values.len() == 1 => Ok(!values[0]),
                _ => bail!("invalid cfg operator {name}"),
            };
        }
        if self.take('=') {
            self.rest = self.rest.trim_start();
            ensure!(self.rest.starts_with('"'), "expected quoted cfg value");
            let mut escaped = false;
            let end = self
                .rest
                .char_indices()
                .skip(1)
                .find_map(|(i, c)| {
                    if escaped {
                        escaped = false;
                        None
                    } else if c == '\\' {
                        escaped = true;
                        None
                    } else if c == '"' {
                        Some(i + 1)
                    } else {
                        None
                    }
                })
                .context("unterminated target cfg string")?;
            let (literal, rest) = self.rest.split_at(end);
            self.rest = rest;
            let value = quoted(literal)?;
            Ok(self
                .platform
                .values
                .get(name)
                .is_some_and(|values| values.contains(&value)))
        } else {
            Ok(self.platform.flags.contains(name))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_and_multivalued_cfg() -> Result<()> {
        let p = Platform::parse(
            "x86_64-unknown-linux-gnu".into(),
            "unix\ntarget_os=\"linux\"\ntarget_feature=\"sse\"\ntarget_feature=\"sse2\"\n",
        )?;
        assert!(p.matches(
            "cfg(all(unix, any(target_os = \"linux\", windows), not(target_feature=\"avx\")))"
        )?);
        assert!(p.matches("cfg(target_feature = \"sse2\")")?);
        assert!(!p.matches("cfg(any())")?);
        assert!(p.matches("cfg(all())")?);
        assert!(p.matches("cfg(all(unix,))")?);
        assert!(p.matches("cfg(not(unix,windows))").is_err());
        assert_eq!(p.environment()["CARGO_CFG_TARGET_FEATURE"], "sse,sse2");
        Ok(())
    }
}
