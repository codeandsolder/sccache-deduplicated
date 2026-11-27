//! Versioned frontend-to-executor contract. Plans describe logical actions,
//! not cache keys: compiler inputs can change after prerequisite actions run.

use std::collections::BTreeSet;
#[cfg(unix)]
use std::path::Path;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{BuildGraph, BuildPath};

pub const BUILD_PLAN_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildPlan {
    pub version: u32,
    pub nodes: Vec<PlanNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanNode {
    pub label: String,
    /// Indices into this plan, never identifiers in the global action cache.
    pub dependencies: Vec<usize>,
    /// Relative cost estimate for ordering ready requests. Not a CPU quota.
    pub estimated_cost: u64,
    pub directories: Vec<BuildPath>,
    pub required_outputs: Vec<BuildPath>,
    pub action: PlanAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PlanAction {
    /// Resolve this action through the live frontend after prerequisites
    /// finish. An offline plan must not contain deferred actions.
    Deferred,
    /// A logical dependency with no process (for example an overridden
    /// build script whose outputs are already supplied by configuration).
    Noop,
    /// Use the normal sccache compiler frontend and admission path.
    Compile { command: PlanCommand },
    /// A process with effects not covered by a compiler cache key. Execute
    /// locally; no result cache entry is inferred from this declaration.
    Process {
        command: PlanCommand,
        stdout: Option<BuildPath>,
        stderr: Option<BuildPath>,
    },
    /// Materialize a final output from a completed predecessor.
    Publish {
        source: BuildPath,
        destination: BuildPath,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanCommand {
    pub executable: BuildPath,
    pub cwd: BuildPath,
    pub arguments: Vec<Vec<u8>>,
    /// Overlay on the invoking environment, or on an empty environment when
    /// inheritance is false. Byte arrays preserve non-UTF-8 POSIX strings.
    pub inherit_environment: bool,
    pub environment: Vec<EnvironmentChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentChange {
    pub name: Vec<u8>,
    /// None removes a variable.
    pub value: Option<Vec<u8>>,
}

impl PlanCommand {
    fn validate(&self) -> Result<()> {
        self.executable.validate()?;
        self.cwd.validate()?;
        ensure!(
            self.executable.as_bytes() != b"/",
            "root is not an executable"
        );
        ensure!(
            self.arguments.iter().all(|arg| !arg.contains(&0)),
            "NUL in plan argument"
        );
        let mut names = BTreeSet::new();
        for change in &self.environment {
            ensure!(
                !change.name.is_empty()
                    && !change.name.contains(&0)
                    && !change.name.contains(&b'='),
                "invalid plan environment name"
            );
            ensure!(names.insert(&change.name), "duplicate environment change");
            ensure!(
                change
                    .value
                    .as_ref()
                    .is_none_or(|value| !value.contains(&0)),
                "NUL in plan environment value"
            );
        }
        Ok(())
    }
}

impl BuildPlan {
    /// Validate all nodes before any side effects. Graph readiness is rebuilt
    /// from this plan; it is deliberately not stored in persistent cache state.
    ///
    /// # Errors
    /// Returns an error for an unsupported version, invalid action or graph.
    pub fn graph(&self) -> Result<BuildGraph> {
        ensure!(
            self.version == BUILD_PLAN_VERSION,
            "unsupported build plan version {}",
            self.version
        );
        let mut outputs = BTreeSet::new();
        for (index, node) in self.nodes.iter().enumerate() {
            ensure!(!node.label.is_empty(), "empty label for node {index}");
            for path in &node.directories {
                path.validate()?;
            }
            for output in &node.required_outputs {
                output.validate()?;
                ensure!(output.as_bytes() != b"/", "root cannot be an output");
                ensure!(
                    outputs.insert(output),
                    "duplicate declared output: {output:?}"
                );
            }
            node.validate_action(&node.action)?;
        }
        let dependencies: Vec<_> = self
            .nodes
            .iter()
            .map(|node| node.dependencies.clone())
            .collect();
        let costs: Vec<_> = self.nodes.iter().map(|node| node.estimated_cost).collect();
        BuildGraph::new(&dependencies, &costs)
    }

    /// The plan protocol is independent of the transport. This method makes
    /// the POSIX nature of paths explicit at the executor boundary.
    #[cfg(unix)]
    #[must_use]
    pub fn path(path: &BuildPath) -> &Path {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _};
        Path::new(OsStr::from_bytes(path.as_bytes()))
    }
}

impl PlanNode {
    /// Validate a resolved action before execution. Deferred commands are
    /// deliberately checked again after the frontend supplies them.
    ///
    /// # Errors
    /// Returns an error for an invalid command or undeclared output.
    pub fn validate_action(&self, action: &PlanAction) -> Result<()> {
        match action {
            PlanAction::Deferred | PlanAction::Noop => {}
            PlanAction::Compile { command } => command.validate()?,
            PlanAction::Process {
                command,
                stdout,
                stderr,
            } => {
                command.validate()?;
                for path in stdout.iter().chain(stderr) {
                    ensure!(
                        self.required_outputs.contains(path),
                        "captured stream must be a declared output"
                    );
                }
            }
            PlanAction::Publish {
                source,
                destination,
            } => {
                source.validate()?;
                ensure!(
                    source != destination,
                    "publication source equals destination"
                );
                ensure!(
                    self.required_outputs.contains(destination),
                    "publication destination must be a declared output"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(bytes: &[u8]) -> Result<BuildPath> {
        BuildPath::new(bytes.to_vec())
    }

    #[test]
    fn versioned_plan_roundtrip_and_validation() -> Result<()> {
        let mut plan = BuildPlan {
            version: BUILD_PLAN_VERSION,
            nodes: vec![PlanNode {
                label: "compile".into(),
                dependencies: vec![],
                estimated_cost: 1,
                directories: vec![],
                required_outputs: vec![path(b"/output")?],
                action: PlanAction::Compile {
                    command: PlanCommand {
                        executable: path(b"/tool/rustc")?,
                        cwd: path(b"/source")?,
                        arguments: vec![vec![0xff]],
                        inherit_environment: true,
                        environment: vec![EnvironmentChange {
                            name: b"REMOVED".to_vec(),
                            value: None,
                        }],
                    },
                },
            }],
        };
        let encoded = serde_json::to_vec(&plan)?;
        let decoded: BuildPlan = serde_json::from_slice(&encoded)?;
        assert_eq!(encoded, serde_json::to_vec(&decoded)?);
        assert!(decoded.graph().is_ok());
        plan.version += 1;
        assert!(plan.graph().is_err());
        Ok(())
    }
}
