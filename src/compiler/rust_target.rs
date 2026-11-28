//! Resolve the target tuple and selected custom specification, never the
//! contents of all directories searched by rustc.
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use super::canonical_paths::{CanonicalRustPaths, physical_operand};
use crate::errors::{Context, Result};
use crate::mock_command::{CommandCreatorSync, RunCommand};
use crate::util::run_input_output;

const TARGET_PATH: &str = "RUST_TARGET_PATH";
type TargetListKey = (PathBuf, Vec<String>);
type TargetListCache = HashMap<TargetListKey, Arc<BTreeSet<String>>>;
static TARGET_LISTS: LazyLock<Mutex<TargetListCache>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) fn tuple_from_path(path: &Path) -> Result<String> {
    path.file_stem()
        .and_then(OsStr::to_str)
        .map(str::to_owned)
        .context("custom Rust target has no UTF-8 file stem")
}

/// The search path is the original operand (possibly relative to cwd). For
/// an installed target spec, rustc falls back to its selected target libdir.
pub(super) struct NamedTargetSpec {
    pub path: PathBuf,
    search_dir: Option<PathBuf>,
}

fn search_path_spec(
    target: &str,
    cwd: &Path,
    environment: &[(OsString, OsString)],
) -> Option<NamedTargetSpec> {
    let search = environment
        .iter()
        .rev()
        .find(|(name, _)| name == TARGET_PATH)
        .map_or_else(|| OsStr::new(""), |(_, value)| value.as_os_str());
    let name = format!("{target}.json");
    std::env::split_paths(search).find_map(|dir| {
        let path = cwd.join(&dir).join(&name);
        path.is_file().then_some(NamedTargetSpec {
            path,
            search_dir: Some(dir),
        })
    })
}

pub(super) struct TargetQuery<'a, T> {
    pub creator: &'a T,
    pub executable: &'a Path,
    pub target: &'a str,
    pub compiler_digests: &'a [String],
    pub cwd: &'a Path,
    pub environment: &'a [(OsString, OsString)],
    pub unstable_options: bool,
}

impl<T: CommandCreatorSync> TargetQuery<'_, T> {
    async fn print(&self, arguments: &[&str]) -> Result<String> {
        let mut command = self.creator.clone().new_command_sync(self.executable);
        command
            .args(arguments)
            .env_clear()
            .envs(self.environment.to_vec())
            .current_dir(self.cwd);
        let output = run_input_output(command, None).await?;
        String::from_utf8(output.stdout).context("invalid rustc target discovery output")
    }

    async fn builtin_targets(&self) -> Result<Arc<BTreeSet<String>>> {
        let key = (self.executable.to_owned(), self.compiler_digests.to_vec());
        let cached = TARGET_LISTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .cloned();
        if let Some(cached) = cached {
            return Ok(cached);
        }
        let output = self.print(&["--print", "target-list"]).await?;
        let targets = Arc::new(output.lines().map(str::to_owned).collect::<BTreeSet<_>>());
        anyhow::ensure!(!targets.is_empty(), "rustc reported no built-in targets");
        let mut cache = TARGET_LISTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(cache.entry(key).or_insert(targets).clone())
    }

    /// Built-in names take precedence even over an existing same-named JSON
    /// file. A custom name is then resolved through the actual ordered search
    /// paths or rustc's own configured target-library location.
    pub async fn discover(self) -> Result<Option<NamedTargetSpec>> {
        if self.builtin_targets().await?.contains(self.target) {
            return Ok(None);
        }
        if let Some(spec) = search_path_spec(self.target, self.cwd, self.environment) {
            return Ok(Some(spec));
        }
        let mut arguments = vec!["--print", "target-libdir", "--target", self.target];
        if self.unstable_options {
            arguments.push("-Zunstable-options");
        }
        let output = self.print(&arguments).await?;
        let libdir = Path::new(output.trim_end());
        let path = libdir
            .parent()
            .context("rustc target libdir has no parent")?
            .join("target.json");
        anyhow::ensure!(
            path.is_file(),
            "rustc selected custom target specification is unavailable: {}",
            path.display()
        );
        Ok(Some(NamedTargetSpec {
            path,
            search_dir: None,
        }))
    }
}

/// Only an unobserved, actually selected external search path needs rewriting.
/// Preserve tracked environment values exactly; installed specs keep rustc's
/// ordinary search contract. Built-in and explicit JSON targets need no search.
pub(super) fn normalize_search_environment(
    environment: &mut Vec<(OsString, OsString)>,
    observed: &HashSet<OsString>,
    named: Option<&NamedTargetSpec>,
) {
    if observed.contains(OsStr::new(TARGET_PATH)) {
        return;
    }
    match named {
        Some(NamedTargetSpec {
            search_dir: Some(dir),
            ..
        }) => {
            environment.retain(|(name, _)| name != TARGET_PATH);
            environment.push((TARGET_PATH.into(), dir.as_os_str().to_owned()));
            environment.sort_by(|a, b| a.0.cmp(&b.0));
        }
        None => environment.retain(|(name, _)| name != TARGET_PATH),
        Some(_) => {}
    }
}

impl NamedTargetSpec {
    pub fn canonical_visible(
        &self,
        paths: &CanonicalRustPaths,
        cwd: &Path,
        observed: &HashSet<OsString>,
    ) -> bool {
        let Some(dir) = &self.search_dir else {
            return true;
        };
        let Some(physical_dir) = physical_operand(cwd, dir) else {
            return false;
        };
        let Some(physical_file) = physical_operand(cwd, &self.path) else {
            return false;
        };
        let Ok(relative) = physical_file.strip_prefix(&physical_dir) else {
            return false;
        };
        // Canonical mount mapping does not preserve arbitrary symlink
        // topology. Physical input layout does, including absolute aliases.
        if physical_file.canonicalize().ok().as_ref() != Some(&physical_file) {
            return false;
        }
        let logical_dir = if dir.is_relative() || observed.contains(OsStr::new(TARGET_PATH)) {
            paths.canonical_cwd(cwd).join(dir)
        } else {
            paths.to_canonical(&physical_dir)
        };
        super::c::normalize_path(&logical_dir.join(relative)) == paths.to_canonical(&physical_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_target_search_uses_invocation_cwd_and_order() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let cwd = temp.path();
        for dir in ["one", "two"] {
            fs_err::create_dir(cwd.join(dir))?;
            fs_err::write(cwd.join(dir).join("custom.json"), dir)?;
        }
        let env = vec![(TARGET_PATH.into(), std::env::join_paths(["two", "one"])?)];
        let spec = search_path_spec("custom", cwd, &env).context("missing spec")?;
        assert_eq!(spec.path, cwd.join("two/custom.json"));
        let mut execution = env.clone();
        normalize_search_environment(&mut execution, &HashSet::new(), Some(&spec));
        assert_eq!(execution, vec![(TARGET_PATH.into(), "two".into())]);
        let mut observed = env.clone();
        normalize_search_environment(
            &mut observed,
            &HashSet::from([TARGET_PATH.into()]),
            Some(&spec),
        );
        assert_eq!(observed, env);
        let mut irrelevant = env;
        normalize_search_environment(&mut irrelevant, &HashSet::new(), None);
        assert!(irrelevant.is_empty());
        fs_err::write(cwd.join("custom.json"), "cwd")?;
        assert_eq!(
            search_path_spec("custom", cwd, &[])
                .context("missing cwd spec")?
                .path,
            cwd.join("custom.json")
        );
        Ok(())
    }
}
