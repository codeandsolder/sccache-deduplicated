//! Portable declaration of a native build. Host materialization paths never
//! enter this identity; the worker constructs its command from these bytes.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    ActionFingerprint, ContentId, OutputKind, TreeId, TreeManifest, TreePath, TreeRecipe,
    identity::typed_digest, wire::ActionRequest,
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
    pub umask: u32,
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
        ensure!(self.umask <= 0o777, "invalid command umask");
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
            (
                "command/umask".into(),
                ContentId::of(&self.umask.to_le_bytes()),
            ),
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
    pub kind: OutputKind,
}

/// Canonical root filesystem identity and its independently replaceable delivery recipe.
///
/// Compilation identity depends on the composed filesystem, not on how its
/// verified input trees were split, ordered or obtained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRoot {
    pub id: TreeId,
    pub recipe: TreeRecipe,
}

impl ExecutionRoot {
    /// Resolve a recipe against the exact manifests that will be supplied.
    ///
    /// # Errors
    /// Returns an error if composition or hashing fails.
    pub fn resolve(recipe: TreeRecipe, packages: &BTreeMap<TreeId, &TreeManifest>) -> Result<Self> {
        let id = recipe.compose(packages)?.id()?;
        Ok(Self { id, recipe })
    }

    /// Check the declared identity against independently resolved content.
    ///
    /// # Errors
    /// Returns an error for a different composed filesystem.
    pub fn verify(&self, id: TreeId) -> Result<()> {
        ensure!(self.id == id, "native composed root digest mismatch");
        Ok(())
    }
}

/// Compiler-front-end identity of a reusable result.
///
/// The authenticated client supplies the compiler's semantic input digest; the exact execution plan
/// remains independently verified. The packaged toolchain is also an input
/// because an identical driver may load different auxiliary programs/libraries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerResultIdentity {
    pub semantic: ContentId,
    pub toolchain: TreeId,
    /// Additional compiler-visible inputs not covered by the front-end digest.
    pub input_closure: Option<TreeId>,
    pub environment: ContentId,
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
    pub compiler_result: Option<CompilerResultIdentity>,
    /// Root-relative destinations of recipe layers whose files belong to this
    /// action's generated output tree. Other input files remain immutable.
    pub working_inputs: BTreeSet<TreePath>,
    /// Existing directories made privately writable but never captured as results.
    pub scratch: BTreeSet<BuildPath>,
    pub platform: ContentId,
    pub root: ExecutionRoot,
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
        self.root.recipe.validate()?;
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
        for path in &self.scratch {
            path.validate()?;
            ensure!(
                path.as_bytes() != b"/"
                    && ![b"/proc".as_slice(), b"/dev"]
                        .iter().any(|reserved| path.within(reserved))
                    && !self.mounts.keys().any(|mount| path.within(mount.as_bytes()) || mount.within(path.as_bytes())),
                "scratch directory conflicts with reserved or mounted path"
            );
        }
        ensure!(
            self.scratch.is_empty() || self.compiler_result.is_none(),
            "private scratch requires exact action identity"
        );
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
                        .any(|mount| mount.within(output.path.as_bytes())
                            && (mount != &output.path || !output.kind.is_tree())),
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
        if !self.working_inputs.is_empty() {
            ensure!(
                self.compiler_result.is_none(),
                "working inputs require exact action identity"
            );
            for path in &self.working_inputs {
                let mut absolute = vec![b'/'];
                absolute.extend_from_slice(path.as_bytes());
                let absolute = BuildPath::new(absolute)?;
                ensure!(
                    self.root
                        .recipe
                        .layers
                        .iter()
                        .filter(|layer| layer.destination.as_ref() == Some(path))
                        .count()
                        == 1,
                    "working input must name exactly one root recipe layer"
                );
                ensure!(
                    self.outputs
                        .values()
                        .any(|output| output.kind == OutputKind::GeneratedTree
                            && absolute.within(output.path.as_bytes()))
                        || self
                            .scratch
                            .iter()
                            .any(|path| absolute.within(path.as_bytes())),
                    "working input must lie in a generated output tree or private scratch"
                );
                ensure!(
                    !self
                        .mounts
                        .keys()
                        .any(|mount| absolute.within(mount.as_bytes())
                            || mount.within(absolute.as_bytes())),
                    "working input conflicts with a mounted tree"
                );
            }
            ensure!(
                self.root.recipe.layers.iter().any(|layer| !layer
                    .destination
                    .as_ref()
                    .is_some_and(|path| self.working_inputs.contains(path))),
                "working inputs require an immutable root"
            );
        }
        Ok(())
    }

    /// Derive both exact execution and reusable result identity from the declaration.
    ///
    /// # Errors
    /// Returns an error for an invalid or unencodable specification.
    pub fn action_request(&self) -> Result<ActionRequest> {
        self.validate()?;
        let mut components = self.command.input_components()?;
        components.insert("platform".into(), self.platform);
        if !self.scratch.is_empty() {
            components.insert(
                "output/private-scratch".into(),
                ContentId(typed_digest(b"native-private-scratch-v1\0", &self.scratch)?),
            );
        }
        if !self.working_inputs.is_empty() {
            let layers = self
                .working_inputs
                .iter()
                .map(|path| {
                    self.root
                        .recipe
                        .layers
                        .iter()
                        .find(|layer| layer.destination.as_ref() == Some(path))
                        .ok_or_else(|| anyhow::anyhow!("missing working layer"))
                })
                .collect::<Result<Vec<_>>>()?;
            components.insert(
                "output/working-inputs".into(),
                ContentId(typed_digest(b"native-working-inputs-v1\0", &layers)?),
            );
        }
        let mut trees: BTreeSet<_> = self
            .root
            .recipe
            .layers
            .iter()
            .map(|layer| layer.tree)
            .collect();
        for (mount, tree) in &self.mounts {
            components.insert(
                format!("mount/{}", mount.as_bytes().escape_ascii()),
                ContentId(tree.0),
            );
            trees.insert(*tree);
        }
        let mut required_outputs = BTreeMap::new();
        let mut optional_outputs = BTreeMap::new();
        for (name, output) in &self.outputs {
            components.insert(
                format!("output/path/{name}"),
                ContentId::of(output.path.as_bytes()),
            );
            if output.required {
                required_outputs.insert(name.clone(), output.kind);
            } else {
                optional_outputs.insert(name.clone(), output.kind);
            }
        }
        let result_fingerprint = self.compiler_result.map(|identity| {
            let mut components = BTreeMap::from([
                ("compiler/semantic".into(), identity.semantic),
                ("compiler/toolchain".into(), ContentId(identity.toolchain.0)),
                ("compiler/environment".into(), identity.environment),
                ("platform".into(), self.platform),
                (
                    "command/umask".into(),
                    ContentId::of(&self.command.umask.to_le_bytes()),
                ),
            ]);
            if let Some(tree) = identity.input_closure {
                components.insert("compiler/input-closure".into(), ContentId(tree.0));
            }
            // Generated trees may contain embedded paths (e.g. Rust rlink).
            // Preserve their logical output root even when file output names
            // are relocatable according to the compiler frontend.
            for (name, output) in &self.outputs {
                if output.kind == OutputKind::GeneratedTree {
                    components.insert(
                        format!("output/path/{name}"),
                        ContentId::of(output.path.as_bytes()),
                    );
                }
            }
            ActionFingerprint {
                schema: "native-compiler-result-v1".into(),
                components,
            }
        });
        if let Some(identity) = self.compiler_result {
            ensure!(
                self.mounts.is_empty(),
                "compiler identity does not describe additional mounts"
            );
            ensure!(
                self.root
                    .recipe
                    .layers
                    .iter()
                    .any(|layer| layer.tree == identity.toolchain),
                "compiler result identity references an undeclared toolchain"
            );
        }
        Ok(ActionRequest {
            result_fingerprint,
            fingerprint: ActionFingerprint {
                schema: "native-linux-bwrap-v4".into(),
                components,
            },
            root: self.root.clone(),
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
            compiler_result: None,
            working_inputs: Default::default(),
            scratch: Default::default(),
            platform: ContentId::of(b"platform"),
            root: ExecutionRoot {
                id: TreeId([1; 32]),
                recipe: TreeRecipe::union(
                    TreeMetadata {
                        mode: 0o755,
                        modified: TreeTimestamp {
                            seconds: 1,
                            nanoseconds: 0,
                        },
                    },
                    [TreeId([1; 32])],
                ),
            },
            mounts: BTreeMap::from([(BuildPath::new(b"/src".to_vec())?, TreeId([2; 32]))]),
            command: CommandSpec {
                umask: 0o022,
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
                    kind: crate::OutputKind::File,
                },
            )]),
        })
    }

    #[test]
    fn private_scratch_is_keyed_and_not_an_output() -> Result<()> {
        let base = spec()?;
        let mut scratch = base.clone();
        scratch
            .scratch
            .insert(BuildPath::new(b"/tmp/build".to_vec())?);
        let request = scratch.action_request()?;
        assert_eq!(
            request.required_outputs,
            base.action_request()?.required_outputs
        );
        assert_ne!(
            request.action_fingerprint()?.key()?,
            base.action_request()?.action_fingerprint()?.key()?
        );
        scratch
            .scratch
            .insert(BuildPath::new(b"/src/nested".to_vec())?);
        assert!(scratch.validate().is_err());
        Ok(())
    }

    #[test]
    fn exact_execution_declaration_controls_the_key() -> Result<()> {
        let original = spec()?;
        let key = |spec: &ExecutionSpec| spec.action_request()?.action_fingerprint()?.key();
        let first = key(&original)?;
        let mut changed = original.clone();
        changed.command.umask = 0o077;
        assert_ne!(first, key(&changed)?);
        changed.command.umask = 0o1000;
        assert!(changed.validate().is_err());
        changed = original.clone();
        changed.command.environment.clear();
        assert_ne!(first, key(&changed)?);
        changed = original.clone();
        changed.root.id = TreeId([3; 32]);
        assert_ne!(first, key(&changed)?);
        changed = original.clone();
        changed.root.recipe.layers.push(crate::TreeLayer {
            tree: TreeId([4; 32]),
            source: None,
            destination: Some(TreePath::new(b"layer".to_vec())?),
        });
        assert_eq!(first, key(&changed)?);
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
        changed
            .outputs
            .get_mut("object")
            .context("test output")?
            .kind = OutputKind::Tree;
        assert_ne!(first, key(&changed)?);
        changed = original;
        changed.mounts.clear();
        changed
            .mounts
            .insert(BuildPath::new(b"/other".to_vec())?, TreeId([2; 32]));
        assert_ne!(first, key(&changed)?);
        Ok(())
    }

    #[test]
    fn compiler_result_identity_is_independent_of_exact_execution() -> Result<()> {
        let mut original = spec()?;
        original.mounts.clear();
        let toolchain = original.root.recipe.layers[0].tree;
        let identity = CompilerResultIdentity {
            semantic: ContentId::of(b"compiler semantic inputs"),
            toolchain,
            input_closure: Some(TreeId([8; 32])),
            environment: ContentId::of(b"compiler environment"),
        };
        original.compiler_result = Some(identity);
        let request = original.action_request()?;
        let key = request.action_fingerprint()?.key()?;
        let mut changed = original.clone();
        changed
            .command
            .environment
            .insert(b"CI_RUN_ID".to_vec(), b"new".to_vec());
        changed.command.cwd = BuildPath::new(b"/different-checkout".to_vec())?;
        changed.root.id = TreeId([9; 32]);
        let changed_request = changed.action_request()?;
        assert_ne!(request, changed_request);
        assert_eq!(key, changed_request.action_fingerprint()?.key()?);

        for different in [
            CompilerResultIdentity {
                semantic: ContentId::of(b"changed input"),
                ..identity
            },
            CompilerResultIdentity {
                input_closure: Some(TreeId([10; 32])),
                ..identity
            },
            CompilerResultIdentity {
                environment: ContentId::of(b"changed compiler environment"),
                ..identity
            },
        ] {
            changed.compiler_result = Some(different);
            assert_ne!(key, changed.action_request()?.action_fingerprint()?.key()?);
        }
        changed.compiler_result = Some(identity);
        changed.command.umask = 0o077;
        assert_ne!(key, changed.action_request()?.action_fingerprint()?.key()?);
        changed.command.umask = original.command.umask;
        changed.platform = ContentId::of(b"changed platform");
        assert_ne!(key, changed.action_request()?.action_fingerprint()?.key()?);
        changed.platform = original.platform;
        changed
            .outputs
            .get_mut("object")
            .context("test output")?
            .required = false;
        assert_ne!(key, changed.action_request()?.action_fingerprint()?.key()?);
        changed.compiler_result = Some(CompilerResultIdentity {
            toolchain: TreeId([12; 32]),
            ..identity
        });
        assert!(changed.action_request().is_err());
        Ok(())
    }

    #[test]
    fn composed_filesystem_identity_is_independent_of_transport_layout() -> Result<()> {
        use crate::{BlobRef, TreeEntry};
        let mut action = spec()?;
        let metadata = action.root.recipe.directories;
        let path = TreePath::new(b"file".to_vec())?;
        let file = TreeManifest {
            root: metadata,
            entries: BTreeMap::from([(
                path.clone(),
                TreeEntry::File {
                    blob: BlobRef {
                        id: ContentId::of(b"contents"),
                        size: 8,
                    },
                    metadata,
                },
            )]),
        };
        let empty = TreeManifest {
            root: metadata,
            entries: BTreeMap::new(),
        };
        let file_id = file.id()?;
        let empty_id = empty.id()?;
        let packages = BTreeMap::from([(file_id, &file), (empty_id, &empty)]);
        let key = |spec: &ExecutionSpec| spec.action_request()?.action_fingerprint()?.key();
        action.root = ExecutionRoot::resolve(TreeRecipe::union(metadata, [file_id]), &packages)?;
        let original = key(&action)?;
        action.root =
            ExecutionRoot::resolve(TreeRecipe::union(metadata, [empty_id, file_id]), &packages)?;
        assert_eq!(key(&action)?, original);
        action.root =
            ExecutionRoot::resolve(TreeRecipe::union(metadata, [file_id, empty_id]), &packages)?;
        assert_eq!(key(&action)?, original);

        let mut modified = file.clone();
        let TreeEntry::File { metadata, .. } =
            modified.entries.get_mut(&path).context("missing file")?
        else {
            anyhow::bail!("not a file");
        };
        metadata.mode = 0o644;
        let changed_id = modified.id()?;
        action.root = ExecutionRoot::resolve(
            TreeRecipe::union(action.root.recipe.directories, [changed_id]),
            &BTreeMap::from([(changed_id, &modified)]),
        )?;
        assert_ne!(key(&action)?, original);
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
                kind: crate::OutputKind::File,
            },
        );
        assert!(invalid.action_request().is_err());
        invalid = spec()?;
        invalid.command.executable = BuildPath(b"/bin/../tool".to_vec());
        assert!(invalid.action_request().is_err());
        Ok(())
    }
}
