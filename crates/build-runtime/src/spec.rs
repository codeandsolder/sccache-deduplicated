//! Portable declaration of a native build. Host materialization paths never
//! enter this identity; the worker constructs its command from these bytes.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    ActionFingerprint, ContentId, TreeId, TreePath, TreeRecipe, identity::typed_digest,
    wire::ActionRequest,
};

/// Exact canonical absolute POSIX path, including non-UTF-8 names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BuildPath(Vec<u8>);

impl BuildPath {
    /// Construct a canonical absolute path.
    ///
    /// # Errors
    /// Returns an error for noncanonical or relative paths.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let path = Self(bytes);
        path.validate()?;
        Ok(path)
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.0.starts_with(b"/"), "build path must be absolute");
        if self.0 != b"/" {
            TreePath::new(self.0[1..].to_vec())?;
        }
        Ok(())
    }

    #[must_use = "these bytes identify the logical build path"]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn within(&self, parent: &[u8]) -> bool {
        parent == b"/"
            || self.0 == parent
            || self
                .0
                .strip_prefix(parent)
                .is_some_and(|suffix| suffix.starts_with(b"/"))
    }
}

/// Exact process inputs. Environment values are included in the action
/// fingerprint but not persisted in the scheduler's action index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpec {
    pub executable: BuildPath,
    pub arguments: Vec<Vec<u8>>,
    pub cwd: BuildPath,
    pub environment: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl CommandSpec {
    /// Validate all command bytes, even after wire deserialization.
    ///
    /// # Errors
    /// Returns an error if paths, arguments or environment are invalid.
    pub fn validate(&self) -> Result<()> {
        self.executable.validate()?;
        self.cwd.validate()?;
        ensure!(self.executable.0 != b"/", "root is not an executable");
        ensure!(
            self.arguments.iter().all(|argument| !argument.contains(&0)),
            "argument contains NUL"
        );
        for (name, value) in &self.environment {
            ensure!(
                !name.is_empty() && !name.contains(&0) && !name.contains(&b'='),
                "invalid environment name"
            );
            ensure!(!value.contains(&0), "environment value contains NUL");
        }
        Ok(())
    }

    /// Auditable semantic command components.
    ///
    /// # Errors
    /// Returns an error for invalid or unencodable inputs.
    pub fn input_components(&self) -> Result<BTreeMap<String, ContentId>> {
        self.validate()?;
        let mut components = BTreeMap::from([
            (
                "command/executable".into(),
                ContentId::of(self.executable.as_bytes()),
            ),
            (
                "command/arguments".into(),
                ContentId(typed_digest(b"sccache-sandbox-argv-v1\0", &self.arguments)?),
            ),
            ("command/cwd".into(), ContentId::of(self.cwd.as_bytes())),
        ]);
        for (name, value) in &self.environment {
            components.insert(
                format!("environment/{}", name.escape_ascii()),
                ContentId::of(value),
            );
        }
        Ok(components)
    }
}

/// One named output at its exact absolute sandbox path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputSpec {
    pub path: BuildPath,
    pub required: bool,
}

/// All declared inputs to a Linux native build.
///
/// Platform is a versioned execution-contract digest supplied by deployment
/// policy, checked against the worker before execution. It must distinguish
/// incompatible kernel/CPU/runtime assumptions; an arbitrary digest does not
/// establish reproducibility. The immutable root and mounts identify the
/// actual files, and scratch, output and namespace policy are schema-fixed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSpec {
    pub platform: ContentId,
    pub root: TreeRecipe,
    pub mounts: BTreeMap<BuildPath, TreeId>,
    pub command: CommandSpec,
    pub outputs: BTreeMap<String, OutputSpec>,
}

impl ExecutionSpec {
    /// Validate the complete declaration.
    ///
    /// # Errors
    /// Returns an error for invalid topology or process/output declarations.
    pub fn validate(&self) -> Result<()> {
        self.command.validate()?;
        self.root.validate()?;
        for target in self.mounts.keys() {
            target.validate()?;
            ensure!(
                target.0 != b"/"
                    && ![b"/proc".as_slice(), b"/dev", b"/tmp"]
                        .iter()
                        .any(|reserved| target.within(reserved)),
                "reserved build mount"
            );
            ensure!(
                !self
                    .mounts
                    .keys()
                    .any(|other| other != target && target.within(other.as_bytes())),
                "overlapping build mounts"
            );
        }
        let mut paths = BTreeSet::new();
        for (name, output) in &self.outputs {
            ensure!(
                !name.is_empty() && !name.contains('\0'),
                "invalid output name"
            );
            output.path.validate()?;
            ensure!(
                output.path.as_bytes() != b"/"
                    && ![b"/proc".as_slice(), b"/dev"]
                        .iter()
                        .any(|reserved| output.path.within(reserved))
                    && !self
                        .mounts
                        .keys()
                        .any(|mount| mount.within(output.path.as_bytes())),
                "output conflicts with a reserved or mounted path"
            );
            ensure!(
                paths.insert(output.path.as_bytes()),
                "duplicate output path"
            );
        }
        for &path in &paths {
            for (index, _) in path.iter().enumerate().filter(|(_, byte)| **byte == b'/') {
                ensure!(!paths.contains(&path[..index]), "overlapping output paths");
            }
        }
        Ok(())
    }

    /// Derive the cache request from the exact declaration that will execute.
    ///
    /// # Errors
    /// Returns an error for an invalid or unencodable specification.
    pub fn action_request(&self) -> Result<ActionRequest> {
        self.validate()?;
        let mut components = self.command.input_components()?;
        components.insert("platform".into(), self.platform);
        components.insert("root/recipe".into(), self.root.fingerprint()?);
        let mut trees: BTreeSet<_> = self.root.layers.iter().map(|layer| layer.tree).collect();
        for (mount, tree) in &self.mounts {
            components.insert(
                format!("mount/{}", mount.as_bytes().escape_ascii()),
                ContentId(tree.0),
            );
            trees.insert(*tree);
        }
        let mut required_outputs = BTreeSet::new();
        let mut optional_outputs = BTreeSet::new();
        for (name, output) in &self.outputs {
            components.insert(
                format!("output/path/{name}"),
                ContentId::of(output.path.as_bytes()),
            );
            if output.required {
                required_outputs.insert(name.clone());
            } else {
                optional_outputs.insert(name.clone());
            }
        }
        Ok(ActionRequest {
            fingerprint: ActionFingerprint {
                schema: "native-linux-bwrap-v3".into(),
                components,
            },
            input_trees: trees,
            required_outputs,
            optional_outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TreeMetadata, TreeTimestamp};
    use anyhow::Context;

    fn spec() -> Result<ExecutionSpec> {
        Ok(ExecutionSpec {
            platform: ContentId::of(b"platform"),
            root: TreeRecipe::union(
                TreeMetadata {
                    mode: 0o755,
                    modified: TreeTimestamp {
                        seconds: 1,
                        nanoseconds: 0,
                    },
                },
                [TreeId([1; 32])],
            ),
            mounts: BTreeMap::from([(BuildPath::new(b"/src".to_vec())?, TreeId([2; 32]))]),
            command: CommandSpec {
                executable: BuildPath::new(b"/bin/tool".to_vec())?,
                arguments: vec![b"-c".to_vec(), vec![255]],
                cwd: BuildPath::new(b"/src".to_vec())?,
                environment: BTreeMap::from([(b"LANG".to_vec(), Vec::new())]),
            },
            outputs: BTreeMap::from([(
                "object".into(),
                OutputSpec {
                    path: BuildPath::new(b"/out/object.o".to_vec())?,
                    required: true,
                },
            )]),
        })
    }

    #[test]
    fn exact_execution_declaration_controls_the_key() -> Result<()> {
        let original = spec()?;
        let key = |spec: &ExecutionSpec| spec.action_request()?.action_fingerprint()?.key();
        let first = key(&original)?;
        let mut changed = original.clone();
        changed.command.environment.clear();
        assert_ne!(first, key(&changed)?);
        changed = original.clone();
        changed.root.layers[0].tree = TreeId([3; 32]);
        assert_ne!(first, key(&changed)?);
        changed = original.clone();
        changed.root.layers.push(crate::TreeLayer {
            tree: TreeId([4; 32]),
            source: None,
            destination: Some(TreePath::new(b"layer".to_vec())?),
        });
        assert_ne!(first, key(&changed)?);
        assert!(
            changed
                .action_request()?
                .input_trees
                .contains(&TreeId([4; 32]))
        );

        changed = original.clone();
        changed.platform = ContentId::of(b"other platform");
        assert_ne!(first, key(&changed)?);
        changed = original.clone();
        changed
            .outputs
            .get_mut("object")
            .context("test output")?
            .required = false;
        assert_ne!(first, key(&changed)?);
        changed = original.clone();
        changed.mounts.clear();
        changed
            .mounts
            .insert(BuildPath::new(b"/other".to_vec())?, TreeId([2; 32]));
        assert_ne!(first, key(&changed)?);
        Ok(())
    }

    #[test]
    fn rejects_noncanonical_paths_and_aliasing_outputs() -> Result<()> {
        for path in [
            b"relative".as_slice(),
            b"/../file",
            b"/a//b",
            b"/a/.",
            b"/a/",
            b"/a\0b",
        ] {
            assert!(BuildPath::new(path.to_vec()).is_err());
        }
        let mut invalid = spec()?;
        invalid
            .mounts
            .insert(BuildPath::new(b"/src/nested".to_vec())?, TreeId([3; 32]));
        assert!(invalid.action_request().is_err());
        invalid = spec()?;
        invalid
            .mounts
            .insert(BuildPath::new(b"/tmp/nested".to_vec())?, TreeId([3; 32]));
        assert!(invalid.action_request().is_err());
        invalid = spec()?;
        invalid.outputs.insert(
            "other".into(),
            OutputSpec {
                path: BuildPath::new(b"/out/object.o/nested".to_vec())?,
                required: false,
            },
        );
        assert!(invalid.action_request().is_err());
        invalid = spec()?;
        invalid.command.executable = BuildPath(b"/bin/../tool".to_vec());
        assert!(invalid.action_request().is_err());
        Ok(())
    }
}
