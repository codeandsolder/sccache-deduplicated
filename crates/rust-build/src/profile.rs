use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeMap;
use toml::{Table, Value};

#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    pub options: BTreeMap<String, String>,
}

fn table<'a>(value: Option<&'a Value>, name: &str) -> Result<Option<&'a Table>> {
    value
        .map(|v| {
            v.as_table()
                .with_context(|| format!("invalid {name} table"))
        })
        .transpose()
}

fn scalar(value: &Value) -> Result<String> {
    match value {
        Value::String(v) => Ok(v.clone()),
        Value::Integer(v) => Ok(v.to_string()),
        Value::Boolean(v) => Ok(v.to_string()),
        _ => bail!("invalid profile scalar {value}"),
    }
}

impl Profile {
    pub fn load(
        document: &Table,
        name: &str,
        package: &str,
        host: bool,
        external: bool,
    ) -> Result<Self> {
        let profiles = table(document.get("profile"), "profile")?;
        let mut chain = Vec::new();
        let mut current = name;
        loop {
            ensure!(!chain.contains(&current), "profile inheritance cycle");
            chain.push(current);
            if matches!(current, "dev" | "release") {
                break;
            }
            let default = match current {
                "test" => "dev",
                "bench" => "release",
                _ => "",
            };
            current = profiles
                .and_then(|p| p.get(current))
                .and_then(Value::as_table)
                .and_then(|p| p.get("inherits"))
                .and_then(Value::as_str)
                .unwrap_or(default);
            ensure!(!current.is_empty(), "custom profile requires inherits");
        }
        let release = current == "release";
        let mut options = BTreeMap::from([
            ("opt-level".into(), if release { "3" } else { "0" }.into()),
            ("debug".into(), if release { "0" } else { "2" }.into()),
            ("debug-assertions".into(), (!release).to_string()),
            ("overflow-checks".into(), (!release).to_string()),
            (
                "codegen-units".into(),
                if release { "16" } else { "256" }.into(),
            ),
        ]);
        if let Some(profiles) = profiles {
            for &name in chain.iter().rev() {
                let Some(profile) = table(profiles.get(name), "profile")? else {
                    continue;
                };
                apply(&mut options, profile)?;
            }
            // Host build dependencies have independent defaults and overrides.
            if host {
                options.insert("opt-level".into(), "0".into());
                options.insert("debug".into(), "0".into());
                options.insert("codegen-units".into(), "256".into());
                options.remove("lto");
                options.remove("panic");
                for &name in chain.iter().rev() {
                    if let Some(overrides) = profiles
                        .get(name)
                        .and_then(Value::as_table)
                        .and_then(|p| p.get("build-override"))
                    {
                        apply(
                            &mut options,
                            overrides.as_table().context("invalid build-override")?,
                        )?;
                    }
                }
            }
            // Inherited wildcard overrides precede inherited specific ones.
            // A child wildcard must not override a more specific parent rule.
            for selector in [external.then_some("*"), Some(package)]
                .into_iter()
                .flatten()
            {
                for &name in chain.iter().rev() {
                    if let Some(packages) = profiles
                        .get(name)
                        .and_then(Value::as_table)
                        .and_then(|p| p.get("package"))
                        .and_then(Value::as_table)
                        && let Some(overrides) = table(packages.get(selector), "package override")?
                    {
                        apply(&mut options, overrides)?;
                    }
                }
            }
        } else if host {
            options.insert("opt-level".into(), "0".into());
            options.insert("debug".into(), "0".into());
            options.insert("codegen-units".into(), "256".into());
        }
        // Incremental outputs are deliberately replaced by the content cache.
        options.remove("incremental");
        Ok(Self {
            name: name.into(),
            options,
        })
    }

    pub fn arguments(&self, test: bool) -> Vec<String> {
        let mut args = Vec::new();
        for (key, value) in &self.options {
            let (key, value) = match key.as_str() {
                "debug" => (
                    "debuginfo",
                    match value.as_str() {
                        "true" | "full" => "2",
                        "false" | "none" => "0",
                        "limited" => "1",
                        v => v,
                    },
                ),
                // LTO depends on the consuming action graph, not just the
                // profile of this package.
                "lto" => continue,
                "strip" if value == "false" => continue,
                "strip" if value == "true" => ("strip", "symbols"),
                "panic" if test => continue,
                "debug-assertions" | "overflow-checks" | "rpath" => (
                    key.as_str(),
                    if value == "true" {
                        "yes"
                    } else if value == "false" {
                        "no"
                    } else {
                        value
                    },
                ),
                _ => (key.as_str(), value.as_str()),
            };
            args.extend(["-C".into(), format!("{key}={value}")]);
        }
        args
    }
}

fn apply(options: &mut BTreeMap<String, String>, table: &Table) -> Result<()> {
    for (key, value) in table {
        match key.as_str() {
            "inherits" | "package" | "build-override" | "incremental" => {}
            "opt-level" | "debug" | "debug-assertions" | "overflow-checks" | "lto"
            | "codegen-units" | "panic" | "strip" | "rpath" | "split-debuginfo" => {
                options.insert(key.clone(), scalar(value)?);
            }
            _ => bail!("unsupported profile setting {key}"),
        }
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn inherited_profile_package_overrides_follow_specificity() -> Result<()> {
    let document: Table = toml::from_str(
        r#"
[profile.release]
lto = "thin"
[profile.release.package."*"]
opt-level = 1
[profile.release.package.foo]
opt-level = 2
[profile.custom]
inherits = "release"
[profile.custom.package."*"]
opt-level = 3
[profile.custom.package.foo]
debug = true
"#,
    )?;
    let profile = Profile::load(&document, "custom", "foo", false, true)?;
    assert_eq!(profile.options["opt-level"], "2");
    assert_eq!(profile.options["debug"], "true");
    assert_eq!(profile.options["lto"], "thin");
    assert!(
        !profile
            .arguments(false)
            .iter()
            .any(|arg| arg.starts_with("lto="))
    );
    Ok(())
}
