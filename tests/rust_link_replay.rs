#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use fs_err as fs;
use sccache::rust_link::{
    CaptureConfig, CaptureLimits, LinkEnvironment, LinkInvocation, SnapshotRoot,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const LIMITS: CaptureLimits = CaptureLimits {
    files: 4096,
    bytes: 256 * 1024 * 1024,
    invocations: 8,
};

struct Namespace<'a> {
    source: &'a Path,
    output: &'a Path,
    source_mount: &'a Path,
    output_mount: &'a Path,
}

impl Namespace<'_> {
    fn run(&self, command: &Command) -> Result<Output> {
        let mut sandbox = Command::new("bwrap");
        sandbox
            .args(["--bind", "/", "/", "--bind"])
            .arg(self.source)
            .arg(self.source_mount)
            .arg("--bind")
            .arg(self.output)
            .arg(self.output_mount)
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
fn real_rust_codegen_replays_native_libraries_and_response_files_across_namespaces() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let source_mount = root.join("source-mount");
    let output_mount = root.join("output-mount");
    let source_a = root.join("source-a");
    let source_b = root.join("source-b");
    let output_a = root.join("output-a");
    let output_b = root.join("output-b");
    let capture = root.join("capture");

    for path in [
        &source_mount,
        &output_mount,
        &source_a,
        &source_b,
        &output_a,
        &output_b,
        &capture,
    ] {
        fs::create_dir(path)?;
    }
    let source = r#"unsafe extern "C" { fn native_value() -> u32; }
fn main() { println!("{}", unsafe { native_value() }); }"#;
    fs::write(source_a.join("probe.rs"), source)?;
    fs::write(
        source_b.join("probe.rs"),
        "compile_error!(\"Rust must not be run again\");",
    )?;
    native_library(&source_a, 17, "libnative.a")?;
    native_library(&source_b, 42, "libalternate.a")?;
    fs::write(source_a.join("native.rsp"), "libnative.a\n")?;
    fs::write(source_b.join("native.rsp"), "libalternate.a\n")?;

    let environment: LinkEnvironment = std::env::vars_os().collect();
    let config = CaptureConfig {
        roots: vec![SnapshotRoot {
            logical: output_mount.clone().into_os_string(),
            source: output_mount.clone().into_os_string(),
        }],
        destination: capture.clone().into_os_string(),
        compiler_environment: environment.clone(),
        limits: LIMITS,
    };
    let relay = config.install(
        Path::new(env!("CARGO_BIN_EXE_sccache")),
        &root,
        "cc".as_ref(),
    )?;
    let mut compile = Command::new(compiler()?);
    compile
        .current_dir(&source_mount)
        .env_clear()
        .envs(&environment)
        .args([
            "--crate-name",
            "probe",
            "--edition=2024",
            "--crate-type",
            "bin",
            "-C",
            "codegen-units=4",
            "--emit=link,dep-info",
            "--out-dir",
        ])
        .arg(&output_mount)
        .arg("-C")
        .arg(format!("linker={}", relay.display()))
        .args(["-C", "link-arg=@native.rsp", "probe.rs"]);
    let codegen = Namespace {
        source: &source_a,
        output: &output_a,
        source_mount: &source_mount,
        output_mount: &output_mount,
    };
    codegen.run(&compile)?;
    // Rustc reports codegen success, but the relay has never linked a binary.
    assert!(!output_a.join("probe").exists());

    let invocation_dir = capture.join("invocation-0000000000");
    let invocation = LinkInvocation::load(&invocation_dir)?;
    let destinations = BTreeMap::from([(output_mount.clone().into_os_string(), output_b.clone())]);
    invocation.restore(&invocation_dir, &destinations, LIMITS)?;
    let linker = which::which("cc")?;
    let replay = invocation.command(&linker, &environment)?;
    let client = Namespace {
        source: &source_b,
        output: &output_b,
        source_mount: &source_mount,
        output_mount: &output_mount,
    };
    client.run(&replay)?;
    let output = Command::new(output_b.join("probe")).output()?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"42\n");

    // Same captured objects and argv, a second live response-file and archive.
    let original = Namespace {
        source: &source_a,
        ..client
    };
    original.run(&replay)?;
    let output = Command::new(output_b.join("probe")).output()?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"17\n");

    let mut changed = environment;
    changed.insert(OsString::from("LC_ALL"), OsString::from("changed"));
    assert!(invocation.command(&linker, &changed).is_err());
    Ok(())
}
