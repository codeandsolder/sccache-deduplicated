//! Coverage filenames must identify the producing source tree, even when
//! several compiles use the same canonical /build sandbox mount.
use crate::{Graph, Workspace};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Component, Path, PathBuf},
};

const SOURCE_PREFIX: &str = "/sccache-coverage/source";
const GENERATED_PREFIX: &str = "/sccache-coverage/generated";

#[derive(Debug, Clone)]
struct Source {
    root: PathBuf,
    repository: bool,
}

/// The path map associated with one planned collection. Source identifiers
/// derive from logical package sources, not transient extraction paths.
#[derive(Debug, Clone)]
pub struct CoverageSources {
    packages: Vec<PathBuf>,
    sources: BTreeMap<PathBuf, Source>,
    generated: PathBuf,
}

fn relative(from: &Path, to: &Path) -> PathBuf {
    let common = from.ancestors().find(|ancestor| to.starts_with(ancestor));
    let Some(common) = common else {
        return to.to_owned();
    };
    let mut result = PathBuf::new();
    if let Ok(rest) = from.strip_prefix(common) {
        for _ in rest.components() {
            result.push("..");
        }
    }
    if let Ok(rest) = to.strip_prefix(common) {
        result.push(rest);
    }
    result
}

fn repo_key(root: &Path, path: &Path) -> Result<Option<String>> {
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                resolved.pop();
            }
            Component::CurDir => {}
            other => resolved.push(other),
        }
    }
    let Ok(relative) = resolved.strip_prefix(root) else {
        return Ok(None);
    };
    let name = relative
        .to_str()
        .context("coverage source path is not UTF-8")?;
    ensure!(!name.is_empty(), "coverage filename is a directory root");
    Ok(Some(if cfg!(windows) {
        name.replace('\\', "/")
    } else {
        name.to_owned()
    }))
}

impl CoverageSources {
    pub fn new(graph: &Graph, workspace: &Workspace, generated: PathBuf) -> Result<Self> {
        ensure!(
            graph.source_roots.len() == graph.packages.len()
                && graph.sources.len() == graph.packages.len(),
            "incomplete source inventory"
        );
        let mut packages = Vec::new();
        let mut sources = BTreeMap::<PathBuf, Source>::new();
        for (index, package) in graph.packages.iter().enumerate() {
            let root = &graph.source_roots[index];
            let logical = match graph.sources[index].as_deref() {
                Some(source) if source.starts_with("git+") => serde_json::to_vec(&("git", source))?,
                Some(source) => serde_json::to_vec(&(
                    "registry",
                    source,
                    &package.package.name,
                    &package.package.version,
                ))?,
                None => serde_json::to_vec(&(
                    "local",
                    relative(&workspace.root, root)
                        .as_os_str()
                        .as_encoded_bytes(),
                ))?,
            };
            let prefix = Path::new(SOURCE_PREFIX).join(blake3::hash(&logical).to_hex().as_str());
            let repository = graph.sources[index].is_none();
            if let Some(old) = sources.get(&prefix) {
                ensure!(
                    old.root == *root && old.repository == repository,
                    "coverage source identity collision"
                );
            } else {
                sources.insert(
                    prefix.clone(),
                    Source {
                        root: root.clone(),
                        repository,
                    },
                );
            }
            packages.push(prefix);
        }
        Ok(Self {
            packages,
            sources,
            generated,
        })
    }

    /// The compiler gets the original source path. Existing canonical-path
    /// translation rewrites the FROM side to the matching sandbox mount.
    /// Coverage-only remapping leaves file!(), diagnostics and debug paths
    /// unchanged. Specific source roots must follow the generated-root map,
    /// since rustc applies the last matching prefix.
    pub fn flags(&self, package: usize, user_flags: &[OsString]) -> Result<Vec<OsString>> {
        ensure!(
            !user_flags.iter().any(|flag| {
                let flag = flag.as_encoded_bytes();
                flag.starts_with(b"--remap-path-prefix")
                    || flag.starts_with(b"--remap-path-scope")
                    || flag.starts_with(b"remap-cwd-prefix")
                    || flag.starts_with(b"-Zremap-cwd-prefix")
            }),
            "coverage mode requires control of coverage path remapping"
        );
        let prefix = self
            .packages
            .get(package)
            .context("unknown coverage source")?;
        let root = &self.sources[prefix].root;
        fn mapping(from: &Path, to: &Path) -> OsString {
            let mut value = OsString::from("--remap-path-prefix=");
            value.push(from);
            value.push("=");
            value.push(to);
            value
        }
        Ok(vec![
            mapping(&self.generated, Path::new(GENERATED_PREFIX)),
            mapping(root, prefix),
            "--remap-path-scope=coverage".into(),
        ])
    }

    /// Map exact LLVM filenames to Git-root coordinates. Generated files
    /// have a distinct synthetic namespace; their content must be covered by
    /// the static input invalidation contract before a baseline can skip work.
    pub fn key(&self, file: &Path, git_root: &Path) -> Result<Option<String>> {
        for (prefix, source) in &self.sources {
            if let Ok(suffix) = file.strip_prefix(prefix) {
                if !source.repository {
                    return Ok(None);
                }
                return repo_key(git_root, &source.root.join(suffix))?
                    .map(Some)
                    .context("local coverage source escapes Git root");
            }
        }
        // A registry checkout inside the intermediate tree is still a
        // registry source, not a generated local file. Choose the most
        // specific physical source root before the broader scratch mapping.
        if let Some(source) = self
            .sources
            .values()
            .filter(|source| file.starts_with(&source.root))
            .max_by_key(|source| source.root.components().count())
            && (source.root.starts_with(&self.generated) || !file.starts_with(&self.generated))
        {
            if !source.repository {
                return Ok(None);
            }
            return repo_key(git_root, file)?
                .map(Some)
                .context("local coverage source escapes Git root");
        }
        if let Ok(suffix) = file
            .strip_prefix(GENERATED_PREFIX)
            .or_else(|_| file.strip_prefix(&self.generated))
        {
            let suffix = suffix
                .to_str()
                .context("generated coverage path is not UTF-8")?;
            ensure!(
                !suffix.is_empty() && !suffix.split('/').any(|part| part == ".."),
                "invalid generated coverage path"
            );
            return Ok(Some(format!("@generated/{suffix}")));
        }
        if file.starts_with("/rustc") || file.starts_with("/rust") {
            return Ok(None);
        }
        if let Some(key) = repo_key(git_root, file)? {
            return Ok(Some(key));
        }
        anyhow::bail!("unmapped LLVM coverage source {}", file.display())
    }

    pub fn sentinel(
        &self,
        source: &Path,
        git_root: &Path,
    ) -> Result<Option<super::coverage::HitRange>> {
        self.key(source, git_root)
            .map(|key| key.map(super::coverage::HitRange::sentinel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Manifest, Package};
    use semver::Version;
    use std::collections::BTreeMap;
    #[test]
    fn identical_sandbox_names_in_different_trees_remain_distinct() -> Result<()> {
        let root = PathBuf::from("/repo/workspace");
        let sibling = PathBuf::from("/repo/shared");
        let manifest = |root: PathBuf, name: &str| Manifest {
            root,
            package: Package {
                name: name.into(),
                version: Version::new(1, 0, 0),
                edition: "2024".into(),
                links: None,
                metadata: BTreeMap::new(),
            },
            dependencies: vec![],
            features: BTreeMap::new(),
            targets: vec![],
            lint_arguments: vec![],
            metadata: None,
        };
        let graph = Graph {
            packages: vec![
                manifest(root.clone(), "app"),
                manifest(sibling.clone(), "shared"),
            ],
            sources: vec![None, None],
            source_roots: vec![root.clone(), sibling.clone()],
            units: vec![],
            roots: vec![],
        };
        let workspace = Workspace {
            root: root.clone(),
            members: vec![],
            defaults: vec![],
            document: toml::Table::new(),
        };
        let map = CoverageSources::new(&graph, &workspace, PathBuf::from("/lease"))?;
        assert_ne!(map.packages[0], map.packages[1]);
        assert_eq!(
            map.key(&map.packages[0].join("src/lib.rs"), Path::new("/repo"))?
                .as_deref(),
            Some("workspace/src/lib.rs")
        );
        assert_eq!(
            map.key(&map.packages[1].join("src/lib.rs"), Path::new("/repo"))?
                .as_deref(),
            Some("shared/src/lib.rs")
        );
        assert!(
            map.key(Path::new("/build/src/lib.rs"), Path::new("/repo"))
                .is_err()
        );
        assert_eq!(
            map.key(
                Path::new("/sccache-coverage/generated/scripts/123/out.rs"),
                Path::new("/repo")
            )?
            .as_deref(),
            Some("@generated/scripts/123/out.rs")
        );
        let flags = map.flags(0, &[])?;
        assert_eq!(
            flags[2],
            std::ffi::OsStr::new("--remap-path-scope=coverage")
        );
        assert!(
            map.flags(0, &[OsString::from("--remap-path-prefix=/foo=/bar")])
                .is_err()
        );
        Ok(())
    }
}
