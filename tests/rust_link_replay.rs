#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use fs_err as fs;
use sccache::rust_link::RustLinkStages;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type LinkEnvironment = BTreeMap<OsString, OsString>;

struct PrivateOutputTree {
    _root: tempfile::TempDir,
    upper: PathBuf,
    work: PathBuf,
}

impl PrivateOutputTree {
    fn new(parent: &Path) -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("test-output-stage-")
            .tempdir_in(parent)?;
        let upper = root.path().join("upper");
        let work = root.path().join("work");
        fs::create_dir(&upper)?;
        fs::create_dir(&work)?;
        Ok(Self {
            _root: root,
            upper,
            work,
        })
    }

    fn overlay_arguments(&self, lower: &Path, logical: &Path) -> Result<Vec<OsString>> {
        Ok(vec![
            "--overlay-src".into(),
            lower.canonicalize()?.into_os_string(),
            "--overlay".into(),
            self.upper.clone().into_os_string(),
            self.work.clone().into_os_string(),
            logical.as_os_str().to_owned(),
        ])
    }

    fn generated_root(&self) -> &Path {
        &self.upper
    }

    // Test-only transfer between two independent overlays. The actual
    // scheduler transfers content-addressed trees, not a local tar archive.
    fn transfer_to(&self, destination: &Self) -> Result<()> {
        fs::remove_dir(&destination.upper)?;
        fs::rename(&self.upper, &destination.upper)?;
        Ok(())
    }
}

struct Namespace<'a> {
    source: &'a Path,
    output: &'a Path,
    source_mount: &'a Path,
    output_mount: &'a Path,
}

impl Namespace<'_> {
    fn run(&self, command: &Command, output_tree: Option<&PrivateOutputTree>) -> Result<Output> {
        let mut sandbox = Command::new("bwrap");
        sandbox
            .args(["--bind", "/", "/", "--bind"])
            .arg(self.source)
            .arg(self.source_mount);
        if let Some(tree) = output_tree {
            sandbox.args(tree.overlay_arguments(self.output, self.output_mount)?);
        } else {
            sandbox
                .arg("--bind")
                .arg(self.output)
                .arg(self.output_mount);
        }
        sandbox
            .arg("--chdir")
            .arg(command.get_current_dir().context("missing command cwd")?)
            .arg("--")
            .arg(command.get_program())
            .args(command.get_args());
        sandbox.env_clear().envs(
            command
                .get_envs()
                .filter_map(|(key, value)| value.map(|value| (key, value))),
        );
        let output = sandbox.output()?;
        ensure!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    }
}

fn native_library(root: &Path, value: u32, name: &str) -> Result<()> {
    fs::write(
        root.join("native.c"),
        format!("unsigned native_value(void) {{ return {value}; }}"),
    )?;
    let output = Command::new("gcc")
        .current_dir(root)
        .args(["-c", "native.c", "-o", "native.o"])
        .output()?;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("ar")
        .current_dir(root)
        .args(["rcs", name, "native.o"])
        .output()?;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_file(root.join("native.o"))?;
    fs::remove_file(root.join("native.c"))?;
    Ok(())
}

fn compiler() -> Result<PathBuf> {
    let output = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()?;
    ensure!(output.status.success(), "could not locate rustc");
    Ok(PathBuf::from(std::str::from_utf8(&output.stdout)?.trim()).join("bin/rustc"))
}

#[test]
fn rustc_native_split_link_preserves_logical_output_tree_and_live_inputs() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let source_mount = root.join("source-mount");
    let output_mount = root.join("output-mount");
    let source_a = root.join("source-a");
    let source_b = root.join("source-b");
    let output_a = root.join("output-a");
    let output_b = root.join("output-b");
    for path in [
        &source_mount,
        &output_mount,
        &source_a,
        &source_b,
        &output_a,
        &output_b,
    ] {
        fs::create_dir(path)?;
    }
    let source = r#"unsafe extern "C" { fn native_value() -> u32; }
fn main() { println!("{}", unsafe { native_value() }); }"#;
    fs::write(source_a.join("probe.rs"), source)?;
    fs::write(
        source_b.join("probe.rs"),
        "compile_error!(\"must not run source again\");",
    )?;
    native_library(&source_a, 17, "libnative.a")?;
    native_library(&source_b, 42, "libnative.a")?;
    fs::write(output_a.join("lower-input"), b"first dependency")?;
    fs::write(output_b.join("lower-input"), b"second dependency")?;
    let environment: LinkEnvironment = std::env::vars_os().collect();
    let rustc = compiler()?;
    let mut compile = Command::new(&rustc);
    let common = [
        "--crate-name",
        "probe",
        "--crate-type",
        "bin",
        "--edition=2024",
        "--emit=metadata,link,dep-info",
        "--error-format=json",
        "--json=artifacts",
        "-C",
        "codegen-units=4",
        "-C",
        "extra-filename=-stage",
        "-L",
        "native=.",
        "-l",
        "static=native",
    ];
    let mut arguments = common.map(OsString::from).to_vec();
    arguments.extend([
        "--out-dir".into(),
        output_mount.clone().into_os_string(),
        "probe.rs".into(),
    ]);
    let stages = RustLinkStages::new(&arguments, &source_mount)?;
    compile
        .current_dir(&source_mount)
        .env_clear()
        .envs(&environment)
        .args(stages.codegen_arguments());
    let first = Namespace {
        source: &source_a,
        output: &output_a,
        source_mount: &source_mount,
        output_mount: &output_mount,
    };
    let first_tree = PrivateOutputTree::new(&root)?;
    let generated = first.run(&compile, Some(&first_tree))?;
    assert!(!first_tree.generated_root().join("probe-stage").exists());
    assert!(
        first_tree
            .generated_root()
            .join("probe-stage.rlink")
            .is_file()
    );
    assert!(!first_tree.generated_root().join("lower-input").exists());
    assert_eq!(fs::read_dir(&output_a)?.count(), 1);

    let artifact = RustLinkStages::link_artifact(first_tree.generated_root(), &output_mount)?;
    let second_tree = PrivateOutputTree::new(&root)?;
    first_tree.transfer_to(&second_tree)?;
    let second = Namespace {
        source: &source_b,
        output: &output_b,
        ..first
    };
    let mut link = Command::new(&rustc);
    link.current_dir(&source_mount)
        .env_clear()
        .envs(&environment)
        .args(stages.link_arguments(&artifact));
    let linked = second.run(&link, Some(&second_tree))?;
    let output = Command::new(second_tree.generated_root().join("probe-stage")).output()?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"42\n");
    assert_eq!(fs::read_dir(&output_b)?.count(), 1);
    // Rustc's own stage diagnostics distinguish the two emitted artifacts
    // and use the original logical output directory, not the staging path.
    let mut emitted = Vec::new();
    for diagnostics in [&generated.stderr, &linked.stderr] {
        for line in String::from_utf8_lossy(diagnostics).lines() {
            let value: serde_json::Value = serde_json::from_str(line)?;
            if let Some(artifact) = value.get("artifact").and_then(serde_json::Value::as_str) {
                assert!(Path::new(artifact).starts_with(&output_mount));
                emitted.push(
                    value["emit"]
                        .as_str()
                        .context("missing emit kind")?
                        .to_owned(),
                );
            }
        }
    }
    assert_eq!(emitted, ["dep-info", "metadata", "link"]);
    Ok(())
}

#[test]
fn split_link_argument_plan_preserves_expanded_option_bytes() -> Result<()> {
    let root = tempfile::tempdir()?;
    let original = [
        "--crate-name",
        "probe",
        "--emit=link,dep-info",
        "-C",
        "link-arg=@native.rsp",
        "-Clink-args=-Wl,--as-needed",
        "--codegen=link-arg=-lm",
        "--cfg",
        "message=\"two words\"",
        "--out-dir",
        "output directory",
        "--edition",
        "2024",
        "--force-warn",
        "unused",
        "--remap-path-scope",
        "all",
        "--",
        "-source.rs",
    ]
    .map(OsString::from);
    let response = root.path().join("args.txt");
    fs::write(
        &response,
        original
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join("\n"),
    )?;
    let mut at = OsString::from("@");
    at.push(response);
    let stages = RustLinkStages::new(&[at], root.path())?;
    let codegen = stages.codegen_arguments();
    assert_eq!(codegen[..2], ["-Z", "no-link"]);
    let expected = original[..3]
        .iter()
        .chain(&original[7..])
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(codegen[2..], expected);
    let artifact = root.path().join("probe.rlink");
    let link = stages.link_arguments(&artifact);
    assert_eq!(link[..2], ["-Z", "link-only"]);
    assert_eq!(link[2..link.len() - 1], original[..original.len() - 1]);
    assert_eq!(
        link.last().context("missing link operand")?,
        artifact.as_os_str()
    );
    assert!(RustLinkStages::new(&["-Zno-link".into(), "a.rs".into()], root.path()).is_err());
    assert!(RustLinkStages::new(&["--emit=metadata".into(), "a.rs".into()], root.path()).is_err());
    assert!(RustLinkStages::new(&["a.rs".into(), "b.rs".into()], root.path()).is_err());
    Ok(())
}

/// The generated result is a tree, not a guessed list of objects: LTO can
/// introduce codegen units from any dependency, and packed debuginfo adds .dwo.
#[test]
fn native_split_link_covers_library_types_lto_and_post_link_debug_output() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let src_mount = root.join("source");
    let out_mount = root.join("output");
    let src = root.join("actual-source");
    let out = root.join("lower-output");
    let invalid = root.join("invalid-source");
    for path in [&src_mount, &out_mount, &src, &out, &invalid] {
        fs::create_dir(path)?;
    }
    fs::write(
        invalid.join("probe.rs"),
        "compile_error!(\"codegen rerun in link stage\");",
    )?;
    let rustc = compiler()?;
    let environment: LinkEnvironment = std::env::vars_os().collect();
    let bin = "fn main(){println!(\"linked\");}";
    let library = "#[unsafe(no_mangle)] pub extern \"C\" fn answer()->u32{42}";
    let proc_macro = "extern crate proc_macro; #[proc_macro] pub fn identity(x:proc_macro::TokenStream)->proc_macro::TokenStream{x}";
    let test = "#[test] fn works(){assert_eq!(2+2,4);}";
    let cases: &[(&[&str], &str, &[&str])] = &[
        (&["--crate-type=bin"], bin, &["probe-stage"]),
        (
            &["--crate-type=proc-macro"],
            proc_macro,
            &["libprobe-stage.so"],
        ),
        (&["--crate-type=cdylib"], library, &["libprobe-stage.so"]),
        (&["--crate-type=dylib"], library, &["libprobe-stage.so"]),
        (&["--crate-type=staticlib"], library, &["libprobe-stage.a"]),
        (&["--crate-type=rlib"], library, &["libprobe-stage.rlib"]),
        (
            &["--crate-type=rlib,cdylib"],
            library,
            &["libprobe-stage.rlib", "libprobe-stage.so"],
        ),
        (&["--test", "--crate-type=lib"], test, &["probe-stage"]),
        (&["--crate-type=bin", "-Clto=thin"], bin, &["probe-stage"]),
        (&["--crate-type=bin", "-Clto=fat"], bin, &["probe-stage"]),
        (
            &[
                "--crate-type=bin",
                "-Cdebuginfo=2",
                "-Csplit-debuginfo=packed",
            ],
            bin,
            &["probe-stage", "probe-stage.dwp"],
        ),
    ];
    let first = Namespace {
        source: &src,
        output: &out,
        source_mount: &src_mount,
        output_mount: &out_mount,
    };
    let second = Namespace {
        source: &invalid,
        ..first
    };
    for (flags, source, expected) in cases {
        fs::write(src.join("probe.rs"), source)?;
        let mut arguments = flags.iter().map(OsString::from).collect::<Vec<_>>();
        arguments.extend(
            [
                "--crate-name=probe",
                "--edition=2024",
                "-Cextra-filename=-stage",
                "-Ccodegen-units=4",
                "--emit=link,dep-info",
                "--out-dir",
            ]
            .map(OsString::from),
        );
        arguments.extend([out_mount.clone().into_os_string(), "probe.rs".into()]);
        let stages = RustLinkStages::new(&arguments, &src)?;
        let codegen = PrivateOutputTree::new(&root)?;
        let mut command = Command::new(&rustc);
        command
            .current_dir(&src_mount)
            .env_clear()
            .envs(&environment)
            .args(stages.codegen_arguments());
        first
            .run(&command, Some(&codegen))
            .with_context(|| format!("codegen {flags:?}"))?;
        for output in *expected {
            assert!(
                !codegen.generated_root().join(output).exists(),
                "completed link output during codegen: {flags:?}"
            );
        }
        let artifact = RustLinkStages::link_artifact(codegen.generated_root(), &out_mount)?;
        let replay = PrivateOutputTree::new(&root)?;
        codegen.transfer_to(&replay)?;
        let mut command = Command::new(&rustc);
        command
            .current_dir(&src_mount)
            .env_clear()
            .envs(&environment)
            .args(stages.link_arguments(&artifact));
        second
            .run(&command, Some(&replay))
            .with_context(|| format!("link {flags:?}"))?;
        for name in *expected {
            let output = replay.generated_root().join(name);
            assert!(
                output.is_file() && output.metadata()?.len() > 0,
                "missing output {name}: {flags:?}"
            );
            if *name == "probe-stage" {
                let result = Command::new(output).output()?;
                ensure!(
                    result.status.success(),
                    "linked executable failed: {flags:?}"
                );
            }
        }
        assert_eq!(fs::read_dir(&out)?.count(), 0);
    }
    Ok(())
}

#[test]
fn split_link_output_layout_covers_default_override_and_explicit_emit_paths() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let cwd = root.join("source");
    let out = cwd.join("out");
    let elsewhere = cwd.join("elsewhere");
    let stage = root.join("stage");
    for directory in [&cwd, &out, &elsewhere, &stage] {
        fs::create_dir(directory)?;
    }
    fs::write(cwd.join("probe.rs"), "fn main() { println!(\"linked\"); }")?;
    let rustc = compiler()?;
    let cases: &[(&[&str], &Path, &[&Path])] = &[
        (&[], &cwd, &[&cwd]),
        (&["--out-dir", "out"], &out, &[&out]),
        (&["-o", "elsewhere/chosen"], &elsewhere, &[&elsewhere]),
        (
            &["--out-dir", "out", "-o", "elsewhere/chosen"],
            &elsewhere,
            &[&elsewhere],
        ),
        (
            &[
                "--out-dir",
                "out",
                "--emit=link=elsewhere/chosen,dep-info=elsewhere/chosen.d,metadata=elsewhere/chosen.rmeta",
            ],
            &out,
            &[&elsewhere, &out],
        ),
    ];
    for (flags, codegen_directory, expected_roots) in cases {
        let mut arguments = [
            "--crate-type=bin",
            "--crate-name=probe",
            "--edition=2024",
            "-Cextra-filename=-tag",
        ]
        .map(OsString::from)
        .to_vec();
        arguments.extend(flags.iter().map(OsString::from));
        arguments.push("probe.rs".into());
        let plan = RustLinkStages::new(&arguments, &cwd)?;
        assert_eq!(plan.codegen_directory(), *codegen_directory);
        assert_eq!(plan.output_roots(), *expected_roots);
        let roots = plan
            .output_roots()
            .iter()
            .map(|logical| Ok((logical, PrivateOutputTree::new(&stage)?)))
            .collect::<Result<Vec<_>>>()?;
        let execute = |args: Vec<OsString>| -> Result<()> {
            let mut command = Command::new("bwrap");
            command.args(["--bind", "/", "/"]);
            for (logical, tree) in &roots {
                command.args(tree.overlay_arguments(logical, logical)?);
            }
            let output = command
                .arg("--chdir")
                .arg(&cwd)
                .arg("--")
                .arg(&rustc)
                .args(args)
                .output()?;
            ensure!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            Ok(())
        };
        execute(plan.codegen_arguments())?;
        let (logical, tree) = roots
            .iter()
            .find(|(logical, _)| plan.codegen_directory().starts_with(logical))
            .context("missing codegen root")?;
        let artifact = RustLinkStages::link_artifact(
            &tree
                .generated_root()
                .join(plan.codegen_directory().strip_prefix(logical)?),
            plan.codegen_directory(),
        )?;
        execute(plan.link_arguments(&artifact))?;
        let expected = if flags.iter().any(|arg| arg.contains("elsewhere/chosen")) {
            elsewhere.join("chosen")
        } else {
            codegen_directory.join("probe-tag")
        };
        let (logical, tree) = roots
            .iter()
            .find(|(logical, _)| expected.starts_with(logical))
            .context("missing final output root")?;
        let binary = tree.generated_root().join(expected.strip_prefix(logical)?);
        let output = Command::new(binary).output()?;
        assert!(output.status.success());
        assert_eq!(output.stdout, b"linked\n");
        assert!(!expected.exists(), "link changed the lower tree");
    }
    Ok(())
}
