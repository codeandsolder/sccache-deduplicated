//! Capture rustc's actual native linker command as a scheduler-owned action.
//! The relay records arguments but never invokes a real linker. A planning
//! result is separate from the final link result and cannot publish binaries.
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, ensure};

use crate::{
    build_runtime::{
        BuildPath, MappedTree, OutputKind, OutputSpec, SourceDigestCache, TreeMetadata, TreePath,
    },
    dist::pkg,
};

use super::CompilerPlan;

const CAPTURE_ROOT: &str = "/__sccache_link_capture";
const CAPTURE_OUTPUT: &str = "/__sccache_link_capture/out";
const OUTPUT_NAME: &str = "link-invocation";

// The shell is itself part of the task's immutable CAS toolchain. The relay
// returns success to prevent rustc from retrying a different linker. Rustc may
// subsequently try to process a nonexistent executable (e.g. packed DWARF).
// The outer wrapper accepts only a complete, single invocation capture.
const RELAY: &str = r#"set -eu
base=/__sccache_link_capture/out
n=0
while :; do
    out="$base/invocation-$n"
    if /usr/bin/mkdir "$out" 2>/dev/null; then break; fi
    test -d "$out" || exit 1
    n=$((n + 1))
done
printf '%s\0' "$#" "$@" > "$out/argv"
pwd -P > "$out/cwd"
/usr/bin/env -0 > "$out/environment"
i=0
search_next=0
: > "$out/existing-paths"
for arg do
    case "$arg" in
        @*) file=${arg#@}
            if [ -f "$file" ]; then
                /usr/bin/cat -- "$file" > "$out/response-$i"
                printf '%s\0' "$file" >> "$out/existing-paths"
            fi ;;
    esac
    if [ -f "$arg" ]; then
        printf '%s\0' "$arg" >> "$out/existing-paths"
    fi
    # Only generated native libraries in rustc's private writable search
    # directories need existence capture. All declared project and installed
    # libraries are resolved by exact name against the origin's inputs.
    directory=
    if [ "$search_next" = 1 ]; then
        directory=$arg
        search_next=0
    else
        case "$arg" in
            -L) search_next=1 ;;
            -L?*) directory=${arg#-L} ;;
        esac
    fi
    if [ -n "$directory" ] && [ -d "$directory" ]; then
        directory=$(cd -P -- "$directory" && pwd -P)
        if private_search "$directory"; then
            for file in "$directory"/*; do
                if [ -f "$file" ]; then
                    printf '%s\0' "$file" >> "$out/existing-paths"
                fi
            done
        fi
    fi
    i=$((i + 1))
done
: > "$out/complete"
"#;

const WRAPPER: &str = r#"
expected=$1
shift
if "$@"; then :; fi
out=/__sccache_link_capture/out
n=0
for dir in "$out"/invocation-*; do
    test -f "$dir/complete" && test -s "$dir/argv" || exit 1
    n=$((n + 1))
done
test "$n" -eq "$expected"
"#;

pub(super) struct LinkCapture {
    destination: PathBuf,
    expected: usize,
}

pub(super) struct CapturedInvocation {
    pub arguments: Vec<OsString>,
    pub cwd: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub responses: BTreeMap<usize, Vec<u8>>,
    pub existing_paths: BTreeSet<PathBuf>,
}

impl LinkCapture {
    pub(super) fn configure(
        mut plan: CompilerPlan,
        basename: &OsStr,
        expected: usize,
        scratch: &Path,
        cache: &SourceDigestCache,
    ) -> Result<(Self, CompilerPlan)> {
        let mut components = Path::new(basename).components();
        ensure!(
            matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none(),
            "invalid linker relay basename"
        );
        ensure!(expected > 0, "capture must expect at least one invocation");
        let relay = Path::new(CAPTURE_ROOT).join("bin").join(basename);
        let directories = pkg::native_directory_metadata()?;
        let relative =
            |path: &Path| TreePath::new(path.strip_prefix("/")?.as_os_str().as_bytes().to_vec());
        let mut mapping = MappedTree::new(directories);
        mapping.add_directory(relative(Path::new(CAPTURE_OUTPUT))?)?;
        // A search root can only be enumerated if it is inside a private
        // generated output or scratch tree. The shell patterns quote all
        // path bytes; only the trailing descendant wildcard is active.
        let mut private = BTreeSet::from([PathBuf::from("/tmp")]);
        for output in plan.spec.outputs.values() {
            let path = Path::new(OsStr::from_bytes(output.path.as_bytes()));
            private.insert(if output.kind.is_tree() {
                path.to_owned()
            } else {
                path.parent().context("output has no parent")?.to_owned()
            });
        }
        private.extend(
            plan.spec
                .scratch
                .iter()
                .map(|path| PathBuf::from(OsStr::from_bytes(path.as_bytes()))),
        );
        let mut script = b"#!/bin/sh\nprivate_search() {\n    case \"$1\" in\n".to_vec();
        for root in private {
            ensure!(
                root.is_absolute() && root != Path::new("/"),
                "invalid private link root"
            );
            script.extend_from_slice(b"        '");
            for &byte in root.as_os_str().as_bytes() {
                if byte == b'\'' {
                    script.extend_from_slice(b"'\\''");
                } else {
                    script.push(byte);
                }
            }
            script.extend_from_slice(b"/'*) return 0 ;;\n");
        }
        script.extend_from_slice(b"    esac\n    return 1\n}\n");
        script.extend_from_slice(RELAY.as_bytes());
        mapping.add_bytes(
            relative(&relay)?,
            script,
            TreeMetadata {
                mode: 0o755,
                modified: directories.modified,
            },
        )?;
        let mut tools = pkg::ToolchainPackageBuilder::new();
        for path in ["/bin/sh", "/usr/bin/env", "/usr/bin/cat", "/usr/bin/mkdir"] {
            tools.add_executable_and_deps(PathBuf::from(path))?;
        }
        plan.extend_inputs(vec![
            mapping.prepare()?,
            tools.into_native_mapping()?.prepare_with_cache(cache)?,
        ])?;

        let compiler = plan.spec.command.executable.as_bytes().to_vec();
        let mut compiler_arguments = std::mem::take(&mut plan.spec.command.arguments);
        let mut linker = b"-Clinker=".to_vec();
        linker.extend_from_slice(relay.as_os_str().as_bytes());
        let index = compiler_arguments
            .iter()
            .position(|arg| arg == b"--")
            .unwrap_or(compiler_arguments.len());
        compiler_arguments.insert(index, linker);
        let mut arguments = vec![
            b"-c".to_vec(),
            WRAPPER.as_bytes().to_vec(),
            b"link-capture".to_vec(),
            expected.to_string().into_bytes(),
            compiler,
        ];
        arguments.extend(compiler_arguments);
        plan.spec.command.executable = BuildPath::new(b"/bin/sh".to_vec())?;
        plan.spec.command.arguments = arguments;
        // Original output directories are private scratch, not publication
        // targets. Capture must not upload another copy of codegen artifacts.
        for output in std::mem::take(&mut plan.spec.outputs).into_values() {
            let path = Path::new(OsStr::from_bytes(output.path.as_bytes()));
            let root = if output.kind.is_tree() {
                path
            } else {
                path.parent().context("output has no parent")?
            };
            plan.spec
                .scratch
                .insert(BuildPath::new(root.as_os_str().as_bytes().to_vec())?);
        }
        plan.spec.outputs.insert(
            OUTPUT_NAME.into(),
            OutputSpec {
                path: BuildPath::new(CAPTURE_OUTPUT.as_bytes().to_vec())?,
                required: true,
                kind: OutputKind::GeneratedTree,
            },
        );
        let destination = scratch.join("link-invocation");
        plan.destinations = BTreeMap::from([(OUTPUT_NAME.into(), destination.clone())]);
        plan.spec.validate()?;
        Ok((
            Self {
                destination,
                expected,
            },
            plan,
        ))
    }

    pub(super) fn read(&self) -> Result<Vec<CapturedInvocation>> {
        ensure!(
            std::fs::read_dir(&self.destination)?.count() == self.expected,
            "link capture invocation count mismatch"
        );
        (0..self.expected)
            .map(|index| {
                CapturedInvocation::read(&self.destination.join(format!("invocation-{index}")))
            })
            .collect()
    }
}

fn nul_fields(bytes: &[u8]) -> Result<Vec<&[u8]>> {
    ensure!(bytes.last() == Some(&0), "incomplete linker capture");
    Ok(bytes[..bytes.len() - 1].split(|byte| *byte == 0).collect())
}

impl CapturedInvocation {
    fn read(path: &Path) -> Result<Self> {
        ensure!(
            path.join("complete").is_file() && !path.join("duplicate").exists(),
            "linker capture is incomplete or ambiguous"
        );
        let raw = std::fs::read(path.join("argv"))?;
        let fields = nul_fields(&raw)?;
        let (count, arguments) = fields
            .split_first()
            .context("missing linker argument count")?;
        let count = std::str::from_utf8(count)?.parse::<usize>()?;
        ensure!(count == arguments.len(), "linker argument count mismatch");
        let arguments = arguments
            .iter()
            .map(|arg| OsString::from_vec(arg.to_vec()))
            .collect::<Vec<_>>();
        let mut cwd = std::fs::read(path.join("cwd"))?;
        ensure!(cwd.pop() == Some(b'\n'), "incomplete linker cwd");
        let cwd = PathBuf::from(OsString::from_vec(cwd));
        ensure!(cwd.is_absolute(), "linker cwd is not absolute");
        let raw = std::fs::read(path.join("environment"))?;
        let mut environment = BTreeMap::new();
        if !raw.is_empty() {
            for field in nul_fields(&raw)? {
                let split = field
                    .iter()
                    .position(|byte| *byte == b'=')
                    .context("invalid linker environment")?;
                let key = OsString::from_vec(field[..split].to_vec());
                ensure!(
                    !key.is_empty()
                        && environment
                            .insert(key, OsString::from_vec(field[split + 1..].to_vec()))
                            .is_none(),
                    "duplicate or empty linker environment name"
                );
            }
        }
        let mut responses = BTreeMap::new();
        for (index, arg) in arguments.iter().enumerate() {
            if !arg.as_bytes().starts_with(b"@") {
                continue;
            }
            match std::fs::read(path.join(format!("response-{index}"))) {
                Ok(bytes) => {
                    responses.insert(index, bytes);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let raw = std::fs::read(path.join("existing-paths"))?;
        let existing_paths = if raw.is_empty() {
            BTreeSet::new()
        } else {
            nul_fields(&raw)?
                .into_iter()
                .map(|name| cwd.join(OsStr::from_bytes(name)))
                .collect()
        };
        Ok(Self {
            arguments,
            cwd,
            environment,
            responses,
            existing_paths,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_invocation_preserves_argument_boundaries_and_response_bytes() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path();
        std::fs::write(path.join("complete"), b"")?;
        std::fs::write(path.join("argv"), b"4\0-L\0/path with spaces\0\0@foo.rsp\0")?;
        std::fs::write(path.join("cwd"), b"/work\n")?;
        std::fs::write(path.join("environment"), b"PATH=/bin:/usr/bin\0VAR=a=b\0")?;
        std::fs::write(path.join("response-3"), b"\"a b\" -lm\n")?;
        std::fs::write(path.join("existing-paths"), b"relative.o\0/absolute.o\0")?;
        let capture = CapturedInvocation::read(path)?;
        assert_eq!(
            capture.arguments,
            ["-L", "/path with spaces", "", "@foo.rsp"]
        );
        assert_eq!(capture.cwd, Path::new("/work"));
        assert_eq!(capture.environment[OsStr::new("VAR")], "a=b");
        assert_eq!(capture.responses[&3], b"\"a b\" -lm\n");
        assert_eq!(
            capture.existing_paths,
            [
                PathBuf::from("/work/relative.o"),
                PathBuf::from("/absolute.o")
            ]
            .into_iter()
            .collect()
        );
        std::fs::write(path.join("duplicate"), b"")?;
        assert!(CapturedInvocation::read(path).is_err());
        Ok(())
    }
}
