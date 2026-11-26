#![cfg(all(feature = "dist-client", feature = "dist-server"))]

extern crate assert_cmd;
extern crate log;
extern crate sccache;
extern crate serde_json;

use crate::harness::{
    cargo_command, clear_cache_local_daemon, get_stats, init_cargo, sccache_command,
    start_local_daemon, stop_local_daemon, write_json_cfg, write_source,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use anyhow::ensure;
use assert_cmd::prelude::*;
use sccache::dist::{
    AssignJobResult, CompileCommand, InputsReader, JobId, JobState, OutputRequest, RunJobResult,
    ServerIncoming, ServerOutgoing, SubmitToolchainResult, Toolchain, ToolchainReader,
};
use std::env;
use std::ffi::OsStr;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Output;

use sccache::errors::*;

pub mod harness;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "dist/transport_stall.rs"]
mod transport_stall;

/// One worker per compatible group, with independent client-result caches.
/// Keeping the worker alive also retains verified extracted toolchains. The
/// namespace and toolchain lifecycle tests below still create cold workers.
#[cfg(unix)]
struct RustDistFixture {
    system: harness::DistSystem,
    root: tempfile::TempDir,
}

#[cfg(unix)]
struct RustDistCase {
    root: tempfile::TempDir,
    config: std::path::PathBuf,
    cached_config: std::path::PathBuf,
}

#[cfg(unix)]
impl RustDistFixture {
    fn new(environment: &[(&str, &str)]) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let mut system = harness::DistSystem::new(&harness::sccache_dist_path(), root.path());
        system.add_scheduler();
        let _worker = system.add_server(environment);
        Ok(Self { system, root })
    }

    fn case(&self) -> Result<RustDistCase> {
        let root = tempfile::tempdir()?;
        let path = root.path();
        let mut cfg = harness::sccache_client_cfg(path, false);
        cfg.dist.scheduler_url = Some(self.system.scheduler_url());
        cfg.dist.cluster = Some(self.system.cluster_config());
        cfg.dist.cache_dir = self.root.path().join("client-toolchains");
        let config = path.join("sccache-cfg.json");
        let cached_config = path.join("sccache-cached-cfg");
        write_json_cfg(path, "sccache-cfg.json", &cfg);
        let _ = stop_local_daemon();
        start_local_daemon(&config, &cached_config);
        Ok(RustDistCase {
            root,
            config,
            cached_config,
        })
    }
}

#[cfg(unix)]
impl Drop for RustDistCase {
    fn drop(&mut self) {
        let _ = stop_local_daemon();
    }
}

fn basic_compile(tmpdir: &Path, sccache_cfg_path: &Path, sccache_cached_cfg_path: &Path) {
    let envs: Vec<(_, &OsStr)> = vec![
        ("RUST_BACKTRACE", "1".as_ref()),
        ("SCCACHE_LOG", "debug".as_ref()),
        ("SCCACHE_CONF", sccache_cfg_path.as_ref()),
        ("SCCACHE_CACHED_CONF", sccache_cached_cfg_path.as_ref()),
    ];
    let source_file = "x.c";
    let obj_file = "x.o";
    write_source(
        tmpdir,
        source_file,
        "#if !defined(SCCACHE_TEST_DEFINE)\n#error SCCACHE_TEST_DEFINE is not defined\n#endif\nint x() { return 5; }",
    );
    sccache_command()
        .args([
            std::env::var("CC")
                .unwrap_or_else(|_| "gcc".to_string())
                .as_str(),
            "-c",
            "-DSCCACHE_TEST_DEFINE",
        ])
        .arg(tmpdir.join(source_file))
        .arg("-o")
        .arg(tmpdir.join(obj_file))
        .envs(envs)
        .assert()
        .success();
}

fn rust_compile(tmpdir: &Path, sccache_cfg_path: &Path, sccache_cached_cfg_path: &Path) -> Output {
    let sccache_path = env!("CARGO_BIN_EXE_sccache");
    let envs: Vec<(_, &OsStr)> = vec![
        ("RUSTC_WRAPPER", sccache_path.as_ref()),
        ("CARGO_TARGET_DIR", "target".as_ref()),
        ("RUST_BACKTRACE", "1".as_ref()),
        ("SCCACHE_LOG", "debug".as_ref()),
        ("SCCACHE_CONF", sccache_cfg_path.as_ref()),
        ("SCCACHE_CACHED_CONF", sccache_cached_cfg_path.as_ref()),
    ];
    let cargo_name = "sccache-dist-test";
    let cargo_path = init_cargo(tmpdir, cargo_name);

    let manifest_file = "Cargo.toml";
    let source_file = "src/main.rs";

    write_source(
        &cargo_path,
        manifest_file,
        r#"[package]
        name = "sccache-dist-test"
        version = "0.1.0"
        edition = "2021"
        [dependencies]
        # Pinned: the point of this test is that distributed compilation works,
        # not that it keeps up with whatever libc published most recently.
        libc = "=0.2.169""#,
    );
    write_source(
        &cargo_path,
        source_file,
        r#"fn main() {
        println!("Hello, world!");
}"#,
    );

    cargo_command()
        .current_dir(cargo_path)
        .args(["build", "--release"])
        .envs(envs)
        .output()
        .unwrap()
}

pub fn dist_test_sccache_client_cfg(
    tmpdir: &Path,
    system: &harness::DistSystem,
) -> sccache::config::FileConfig {
    let mut sccache_cfg = harness::sccache_client_cfg(tmpdir, false);
    sccache_cfg.cache.disk.as_mut().unwrap().size = 0;
    sccache_cfg.dist.scheduler_url = Some(system.scheduler_url());
    sccache_cfg.dist.cluster = Some(system.cluster_config());
    sccache_cfg
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_basic() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    system.add_server(&[]);

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, &system);
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    let _ = stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    get_stats(|info| {
        assert_eq!(1, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

/// GCC and Clang embed the effective compilation directory in DWARF even
/// when their preprocessed C inputs are otherwise identical. The worker must
/// compile both distinct debug contexts, then restore each from its own key.
#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(
    not(feature = "dist-tests"),
    ignore = "requires isolated Docker distribution harness"
)]
fn test_dist_c_debug_compilation_directory_is_cache_identity() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let mut system = harness::DistSystem::new(&harness::sccache_dist_path(), root);
    system.add_scheduler();
    system.add_server(&[]);
    let mut config = dist_test_sccache_client_cfg(root, &system);
    config
        .cache
        .disk
        .as_mut()
        .context("missing disk cache")?
        .size = 128 * 1024 * 1024;
    let config_path = root.join("sccache-cfg.json");
    write_json_cfg(root, "sccache-cfg.json", &config);
    let cached_config = root.join("sccache-cached-cfg");
    let _ = stop_local_daemon();
    start_local_daemon(&config_path, &cached_config);

    for compiler in ["gcc", "clang"] {
        let compiler_path = which::which(compiler)?;
        let mut objects = Vec::new();
        for directory in ["a", "b"] {
            let cwd = root.join(compiler).join(directory);
            std::fs::create_dir_all(&cwd)?;
            write_source(&cwd, "probe.c", "int multiply(int x) { return x * 7; }\n");
            let output = cwd.join("probe.o");
            let compile = || -> Result<Vec<u8>> {
                let result = sccache_command()
                    .arg(&compiler_path)
                    .args(["-g", "-O2", "-c", "probe.c", "-o", "probe.o"])
                    .current_dir(&cwd)
                    .env("SCCACHE_CONF", &config_path)
                    .env("SCCACHE_CACHED_CONF", &cached_config)
                    .output()?;
                assert!(
                    result.status.success(),
                    "{compiler} {directory}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                Ok(std::fs::read(&output)?)
            };
            let cold = compile()?;
            std::fs::remove_file(&output)?;
            assert_eq!(
                cold,
                compile()?,
                "cached object differs for {compiler}/{directory}"
            );
            objects.push(cold);
        }
        assert_ne!(
            objects[0], objects[1],
            "{compiler} debug objects aliased across different working directories"
        );
    }
    get_stats(|info| {
        assert_eq!(4, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(8, info.stats.compile_requests);
        assert_eq!(4, info.stats.cache_hits.all());
        assert_eq!(4, info.stats.cache_misses.all());
    });
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_cpu_target_sources(root: &Path) {
    write_source(
        root,
        "native_target.c",
        r#"
unsigned native_target_has_avx2(void) {
#if defined(__AVX2__)
    return 1;
#else
    return 0;
#endif
}
unsigned long native_target(unsigned long x, unsigned long y) {
    return (x * 17UL + y) ^ (y >> 7);
}
"#,
    );
    write_source(
        root,
        "specific_target.c",
        r#"
#include <immintrin.h>
#if !defined(__AVX512F__)
#error explicit x86-64-v4 target must enable AVX-512 codegen
#endif
void specific_target(int *dst, const int *a, const int *b) {
    __m512i va = _mm512_loadu_si512((const void *)a);
    __m512i vb = _mm512_loadu_si512((const void *)b);
    _mm512_storeu_si512((void *)dst, _mm512_add_epi32(va, vb));
}
"#,
    );
    write_source(
        root,
        "native_target.cpp",
        r#"
extern "C" unsigned native_target_cpp_has_avx2(void) {
#if defined(__AVX2__)
    return 1;
#else
    return 0;
#endif
}
template<unsigned N> constexpr unsigned scale(unsigned x) { return x * N; }
static_assert(scale<3>(7) == 21);
extern "C" unsigned long native_target_cpp(unsigned long x, unsigned long y) {
    return (x * 17UL + y) ^ (y >> 7);
}
"#,
    );
    write_source(
        root,
        "specific_target.cpp",
        r#"
#include <immintrin.h>
#if !defined(__AVX512F__)
#error explicit x86-64-v4 must enable AVX-512 in C++ too
#endif
static_assert(2 * 3 == 6);
extern "C" void specific_target_cpp(int *dst, const int *a, const int *b) {
    __m512i va = _mm512_loadu_si512((const void *)a);
    __m512i vb = _mm512_loadu_si512((const void *)b);
    _mm512_storeu_si512((void *)dst, _mm512_add_epi32(va, vb));
}
"#,
    );
}

/// GCC/Clang C and C++ jobs targeting native and explicit v4 must match the
/// initiating compiler's exact codegen even on a different worker CPU, and
/// every repeat must hit cache.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[cfg_attr(
    not(feature = "dist-tests"),
    ignore = "requires isolated Docker distribution harness"
)]
fn test_dist_c_native_target_codegen_and_cache() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let mut system = harness::DistSystem::new(&harness::sccache_dist_path(), root);
    system.add_scheduler();
    system.add_server(&[]);
    let mut config = dist_test_sccache_client_cfg(root, &system);
    // Unlike the minimal distribution smoke test, retain objects for the
    // repeat-request cache verification.
    config
        .cache
        .disk
        .as_mut()
        .context("missing test disk cache")?
        .size = 128 * 1024 * 1024;
    let config_path = root.join("sccache-cfg.json");
    write_json_cfg(root, "sccache-cfg.json", &config);
    let cached_config = root.join("sccache-cached-cfg");
    let _ = stop_local_daemon();
    start_local_daemon(&config_path, &cached_config);

    write_cpu_target_sources(root);
    let mut replay_pairs = Vec::new();
    for (index, compiler) in ["gcc", "clang", "g++", "clang++"].into_iter().enumerate() {
        let compiler_path = which::which(compiler)?;
        let is_cxx = compiler.ends_with("++");
        for (case, flags, source) in [
            (
                "native",
                &["-O2", "-march=native", "-mno-avx2", "-mtune=native"][..],
                if is_cxx {
                    "native_target.cpp"
                } else {
                    "native_target.c"
                },
            ),
            (
                "v4",
                &["-O2", "-march=x86-64-v4"][..],
                if is_cxx {
                    "specific_target.cpp"
                } else {
                    "specific_target.c"
                },
            ),
        ] {
            let output = root.join(format!("{case}-{index}.o"));
            let compile_object = || {
                let mut command = sccache_command();
                command.arg(&compiler_path).args(flags);
                if is_cxx {
                    command.arg("-std=c++20");
                }
                let result = command
                    .arg("-c")
                    .arg(root.join(source))
                    .arg("-o")
                    .arg(&output)
                    .env("SCCACHE_CONF", &config_path)
                    .env("SCCACHE_CACHED_CONF", &cached_config)
                    .output()?;
                ensure!(
                    result.status.success(),
                    "{} {case} compilation failed: {}",
                    compiler_path.display(),
                    String::from_utf8_lossy(&result.stderr)
                );
                Ok::<_, anyhow::Error>(std::fs::read(&output)?)
            };
            let first = compile_object()?;
            ensure!(!first.is_empty(), "distributed compile produced no object");
            // Native is whatever the *requesting compiler* considers its CPU.
            // Different hosted runner CPUs, compiler versions, or ISA feature
            // dependencies can affect whether -mno-avx2 disables __AVX2__.
            // Comparing the complete object against the initiating compiler's
            // actual direct invocation tests equivalence without guessing that
            // feature state or weakening the requirement for exact codegen.
            let reference_output = root.join(format!("reference-{case}-{index}.o"));
            let mut reference = std::process::Command::new(&compiler_path);
            reference.args(flags);
            if is_cxx {
                reference.arg("-std=c++20");
            }
            let reference_result = reference
                .arg("-c")
                .arg(root.join(source))
                .arg("-o")
                .arg(&reference_output)
                .output()?;
            ensure!(
                reference_result.status.success(),
                "{} direct {case} reference failed: {}",
                compiler_path.display(),
                String::from_utf8_lossy(&reference_result.stderr)
            );
            assert_eq!(
                first,
                std::fs::read(reference_output)?,
                "{} {case} distributed codegen differs from requesting compiler",
                compiler_path.display()
            );
            replay_pairs.push((compile_object()?, first));
        }
    }
    for (actual, expected) in replay_pairs {
        assert_eq!(actual, expected);
    }
    get_stats(|info| {
        assert_eq!(8, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(16, info.stats.compile_requests);
        assert_eq!(8, info.stats.cache_hits.all());
        assert_eq!(8, info.stats.cache_misses.all());
    });
    Ok(())
}

/// The daemon sees deliberately different sources at the exact paths used by
/// the caller. Cold misses must execute on a worker, not on the host.
#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_namespace_broker() -> Result<()> {
    use std::fs;

    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let mut system = harness::DistSystem::new(&harness::sccache_dist_path(), &root);
    system.add_scheduler();
    let _worker = system.add_server(&[]);
    let mut cfg = harness::sccache_client_cfg(&root, false);
    cfg.dist.scheduler_url = Some(system.scheduler_url());
    cfg.dist.cluster = Some(system.cluster_config());
    let config = root.join("sccache-cfg.json");
    write_json_cfg(&root, "sccache-cfg.json", &cfg);
    let cached_config = root.join("sccache-cached-cfg");
    let _ = stop_local_daemon();
    start_local_daemon(&config, &cached_config);

    let visible = root.join("visible");
    let private = root.join("private");
    fs::create_dir(&visible)?;
    fs::create_dir(&private)?;
    fs::write(visible.join("probe.c"), "#error wrong host source")?;
    fs::write(
        visible.join("probe.rs"),
        "compile_error!(\"wrong host source\");",
    )?;
    fs::write(
        private.join("probe.c"),
        "int namespace_probe(void) { return 42; }",
    )?;
    fs::write(
        private.join("probe.rs"),
        "pub fn namespace_probe() -> u32 { 42 }",
    )?;
    fs::write(private.join("config.json"), "{}")?;
    let hidden_config = root.join("hidden-config");
    fs::write(&hidden_config, "{}")?;
    let script = r#"
set -eu
: <>/dev/null
"$2" --version >/dev/null
"$3" --version >/dev/null
"$1" "$2" -c probe.c -o probe.o
"$1" "$3" --crate-name probe --crate-type rlib --edition=2021 --emit=metadata,dep-info --out-dir . probe.rs
cp probe.o initial.o
cp libprobe.rmeta initial.rmeta
rm probe.o libprobe.rmeta
"$1" "$2" -c probe.c -o probe.o
"$1" "$3" --crate-name probe --crate-type rlib --edition=2021 --emit=metadata,dep-info --out-dir . probe.rs
cmp initial.o probe.o
cmp initial.rmeta libprobe.rmeta
"#;
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let gcc = which::which("gcc")?;
    let mut command = harness::prune_command(std::process::Command::new("bwrap"));
    let output = command
        .args(["--bind", "/", "/", "--dev-bind", "/dev", "/dev", "--bind"])
        .arg(&private)
        .arg(&visible)
        .arg("--ro-bind")
        .arg(&hidden_config)
        .arg(&config)
        .arg("--tmpfs")
        .arg(root.join("client-cache"))
        .arg("--tmpfs")
        .arg(root.join("client-dist-cache"))
        .arg("--chdir")
        .arg(&visible)
        .args(["--", "/bin/sh", "-c", script, "namespace-test"])
        .arg(env!("CARGO_BIN_EXE_sccache"))
        .arg(gcc)
        .arg(rustc)
        .env("SCCACHE_CLIENT_SIDE", "1")
        .env("SCCACHE_CONF", visible.join("config.json"))
        .env("SCCACHE_CACHED_CONF", visible.join("cached-config"))
        .env_remove("SCCACHE_ERROR_LOG")
        .env("SCCACHE_LOG", "sccache=debug")
        .env_remove("CARGO_INCREMENTAL")
        .env_remove("CARGO_BUILD_INCREMENTAL")
        .env("CARGO_PKG_NAME", "probe")
        .output()?;
    eprintln!(
        "namespace compiler stdout:\n{}\nnamespace compiler stderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success());
    assert!(private.join("probe.o").is_file());
    assert!(private.join("libprobe.rmeta").is_file());
    assert!(!visible.join("probe.o").exists());
    assert!(!visible.join("libprobe.rmeta").exists());
    get_stats(|info| {
        assert_eq!(2, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(2, info.stats.cache_hits.all());
        assert_eq!(2, info.stats.cache_misses.all());
        assert_eq!(0, info.stats.dist_errors);
    });
    Ok(())
}

/// Actual compiler scripts: only an explicitly attested transparent launcher
/// shares the real GCC cache identity and remote toolchain. An arbitrary
/// script that changes flags must retain its own local compilation semantics.
#[cfg(unix)]
#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_c_compiler_aliases() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let gcc = which::which("gcc")?;
    let transparent = root.join("cc");
    let modifying = root.join("other-cc");
    let script = format!("#!/bin/sh\nexec '{}' \"$@\"\n", gcc.display());
    let modified = format!(
        "#!/bin/sh\nexec '{}' -DWRAPPER_VALUE=42 \"$@\"\n",
        gcc.display()
    );
    for (file, contents) in [(&transparent, &script), (&modifying, &modified)] {
        std::fs::write(file, contents)?;
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755))?;
    }
    let mut system = harness::DistSystem::new(&harness::sccache_dist_path(), &root);
    system.add_scheduler();
    let _worker = system.add_server(&[]);
    let mut cfg = harness::sccache_client_cfg(&root, false);
    cfg.dist.scheduler_url = Some(system.scheduler_url());
    cfg.dist.cluster = Some(system.cluster_config());
    cfg.compiler_aliases.0.insert(
        transparent.clone(),
        sccache::config::CompilerAlias {
            compiler: gcc.clone(),
            blake3: blake3::hash(script.as_bytes()).to_hex().to_string(),
        },
    );
    let config = root.join("sccache-cfg.json");
    write_json_cfg(&root, "sccache-cfg.json", &cfg);
    let cached_config = root.join("sccache-cached-cfg");
    let _ = stop_local_daemon();
    start_local_daemon(&config, &cached_config);
    let source = root.join("probe.c");
    let object = root.join("probe.o");
    std::fs::write(
        &source,
        "#ifndef WRAPPER_VALUE\n#define WRAPPER_VALUE 11\n#endif\nint marker(void) { return WRAPPER_VALUE; }\n",
    )?;
    let compile = |compiler: &Path| -> Result<Output> {
        Ok(sccache_command()
            .arg(compiler)
            .arg("-c")
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .env("SCCACHE_CONF", &config)
            .env("SCCACHE_CACHED_CONF", &cached_config)
            .current_dir(&root)
            .output()?)
    };
    let first = compile(&transparent)?;
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let ordinary = std::fs::read(&object)?;
    std::fs::remove_file(&object)?;
    let direct = compile(&gcc)?;
    assert!(
        direct.status.success(),
        "{}",
        String::from_utf8_lossy(&direct.stderr)
    );
    assert_eq!(ordinary, std::fs::read(&object)?);
    std::fs::remove_file(&object)?;
    let altered = compile(&modifying)?;
    assert!(
        altered.status.success(),
        "{}",
        String::from_utf8_lossy(&altered.stderr)
    );
    assert_ne!(ordinary, std::fs::read(&object)?);
    std::fs::remove_file(&object)?;
    // A changed formerly transparent wrapper must never reuse the alias.
    std::fs::write(&transparent, modified)?;
    let changed = compile(&transparent)?;
    assert!(!changed.status.success());
    assert!(String::from_utf8_lossy(&changed.stderr).contains("alias digest mismatch"));
    assert!(!object.exists());
    get_stats(|info| {
        assert_eq!(1, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(1, info.stats.cache_hits.all());
        assert_eq!(2, info.stats.cache_misses.all());
        assert_eq!(0, info.stats.dist_errors);
    });
    Ok(())
}

// A successful assembler diagnostic may intentionally leave the object
// absent or retain an existing file. Neither result can be cached as an object.
#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_c_success_without_object() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let mut system = harness::DistSystem::new(&harness::sccache_dist_path(), &root);
    system.add_scheduler();
    let _worker = system.add_server(&[]);
    let mut cfg = harness::sccache_client_cfg(&root, false);
    cfg.dist.scheduler_url = Some(system.scheduler_url());
    cfg.dist.cluster = Some(system.cluster_config());
    let config = root.join("sccache-cfg.json");
    write_json_cfg(&root, "sccache-cfg.json", &cfg);
    let cached_config = root.join("sccache-cached-cfg");
    let _ = stop_local_daemon();
    start_local_daemon(&config, &cached_config);

    let source = root.join("probe.S");
    let object = root.join("probe.o");
    std::fs::write(&source, ".text\n.globl probe\nprobe:\nret\n")?;
    let compile = |diagnostic: bool| -> Result<Output> {
        let mut command = sccache_command();
        command
            .arg("gcc")
            .args(["-c", "-x", "assembler-with-cpp"])
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .env("SCCACHE_CONF", &config)
            .env("SCCACHE_CACHED_CONF", &cached_config)
            .current_dir(&root);
        if diagnostic {
            command.arg("-Wa,--version");
        }
        Ok(command.output()?)
    };
    let first = compile(true)?;
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(String::from_utf8_lossy(&first.stdout).contains("GNU assembler"));
    assert!(!object.exists());
    std::fs::write(&object, b"previous object")?;
    let second = compile(true)?;
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(second.stdout, first.stdout);
    assert_eq!(std::fs::read(&object)?, b"previous object");
    let ordinary = compile(false)?;
    assert!(
        ordinary.status.success(),
        "{}",
        String::from_utf8_lossy(&ordinary.stderr)
    );
    let expected = std::fs::read(&object)?;
    assert_ne!(expected, b"previous object");
    std::fs::remove_file(&object)?;
    assert!(compile(false)?.status.success());
    assert_eq!(std::fs::read(&object)?, expected);
    get_stats(|info| {
        assert_eq!(3, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(1, info.stats.cache_hits.all());
        assert_eq!(2, info.stats.non_cacheable_compilations);
        assert_eq!(0, info.stats.dist_errors);
    });
    Ok(())
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_restartedserver() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    let server_handle = system.add_server(&[]);

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, &system);
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    let _ = stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    system.restart_server(&server_handle);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    get_stats(|info| {
        assert_eq!(2, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(2, info.stats.compile_requests);
        assert_eq!(2, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(2, info.stats.cache_misses.all());
    });
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_nobuilder() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, &system);
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    let _ = stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    get_stats(|info| {
        assert_eq!(0, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(1, info.stats.dist_errors);
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

struct FailingServer;
impl ServerIncoming for FailingServer {
    fn executing_jobs(&self) -> usize {
        0
    }
    fn native_metadata_limit(&self) -> Option<usize> {
        None
    }

    fn handle_native_blob(
        &self,
        _blob: sccache::build_runtime::BlobRef,
    ) -> Result<Option<(std::fs::File, sccache::build_runtime::BlobEncoding)>> {
        Ok(None)
    }

    fn capabilities(&self) -> sccache::dist::WorkerCapabilities {
        sccache::dist::WorkerCapabilities::ARCHIVE
    }
    fn handle_assign_native_job(
        &self,
        _requester: std::sync::Arc<dyn ServerOutgoing>,
        _job_id: JobId,
        _assignment: sccache::dist::NativeAssignment,
    ) -> Result<AssignJobResult> {
        anyhow::bail!("mock does not accept native assignments")
    }
    fn handle_run_native_job(
        &self,
        _job_id: JobId,
        _request: sccache::build_runtime::wire::NativeRunRequest,
    ) -> Result<sccache::build_runtime::wire::NativeRunResult> {
        anyhow::bail!("mock does not execute native assignments")
    }
    fn handle_reconcile_assignments(
        &self,
        _assigned_job_ids: &[JobId],
        _heartbeat_started_at: std::time::Instant,
    ) -> Result<usize> {
        // This mock stores no pending assignments.
        Ok(0)
    }

    fn handle_assign_job(&self, _job_id: JobId, _tc: Toolchain) -> Result<AssignJobResult> {
        let need_toolchain = false;
        let state = JobState::Ready;
        Ok(AssignJobResult {
            need_toolchain,
            state,
        })
    }
    fn handle_submit_toolchain(
        &self,
        _requester: &dyn ServerOutgoing,
        _job_id: JobId,
        _tc_rdr: ToolchainReader,
    ) -> Result<SubmitToolchainResult> {
        panic!("should not have submitted toolchain")
    }
    fn handle_run_job(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        _command: CompileCommand,
        _outputs: OutputRequest,
        _inputs_rdr: InputsReader,
    ) -> Result<RunJobResult> {
        requester
            .do_update_job_state(job_id, JobState::Started)
            .context("Updating job state failed")?;
        bail!("internal build failure")
    }
}

#[test]
fn failing_server_process() -> Result<()> {
    let Some(server_addr) = env::var_os(harness::CUSTOM_SERVER_ADDR_ENV) else {
        return Ok(());
    };
    let server_addr: SocketAddr = server_addr
        .to_string_lossy()
        .parse()
        .context("custom server address should be valid")?;
    let scheduler_url = env::var(harness::CUSTOM_SERVER_SCHEDULER_ENV)
        .context("custom server scheduler URL should be provided")?;
    let token = env::var(harness::CUSTOM_SERVER_TOKEN_ENV)
        .context("custom server token should be provided")?;
    let server = sccache::dist::http::Server::new(
        server_addr,
        Some(SocketAddr::from(([0, 0, 0, 0], server_addr.port()))),
        sccache::dist::cluster::open_peer(
            serde_json::from_str(&env::var(harness::CUSTOM_SERVER_CLUSTER_ENV)?)?,
            &url::Url::parse(&scheduler_url)?,
            sccache_cluster_identity::Role::Worker,
            move || Ok(token.clone()),
        )?,
        None,
        FailingServer,
    )
    .context("custom failing server should initialize")?;
    env_logger::try_init().ok();
    server
        .start()
        .context("custom failing server should run")
        .map(|never| match never {})
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_failingserver() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    system.add_custom_server_process("failing_server_process");

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, &system);
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    let _ = stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    get_stats(|info| {
        assert_eq!(0, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(1, info.stats.dist_errors);
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_cargo_build() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    let _server_handle = system.add_server(&[]);

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, &system);
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    let _ = stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    rust_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path)
        .assert()
        .success();
    get_stats(|info| {
        assert_eq!(1, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(8, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

// The physical layout must preserve both observable strings and the paths
// consumed by include_str! during compilation, not just the cache key.
#[test]
#[cfg(unix)]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_rust_observed_environment() -> Result<()> {
    let fixture = RustDistFixture::new(&[("SCCACHE_OBSERVED_MISSING", "worker-only")])?;
    let case = fixture.case()?;
    let root = case.root.path();
    let cfg_path = &case.config;
    let cached_cfg = &case.cached_config;

    let project = init_cargo(root, "observed_env");
    write_source(
        &project,
        "Cargo.toml",
        "[package]\nname = \"observed_env\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_source(&project, "payload.txt", "physical input");
    write_source(
        &project,
        "src/lib.rs",
        r#"
pub const ROOT: &str = env!("CARGO_MANIFEST_DIR");
pub const PAYLOAD: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/payload.txt"));
pub const EMPTY: Option<&str> = option_env!("SCCACHE_OBSERVED_EMPTY");
pub const MISSING: Option<&str> = option_env!("SCCACHE_OBSERVED_MISSING");
"#,
    );
    write_source(
        &project,
        "src/main.rs",
        r#"
fn main() {
    assert_eq!(std::path::Path::new(observed_env::ROOT), std::env::current_dir().unwrap());
    assert_eq!(observed_env::PAYLOAD, "physical input");
    assert_eq!(observed_env::EMPTY, Some(""));
    assert_eq!(observed_env::MISSING, None);
}
"#,
    );
    cargo_command()
        .current_dir(&project)
        .args(["run", "--quiet"])
        .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_sccache"))
        .env("SCCACHE_CONF", &cfg_path)
        .env("SCCACHE_CACHED_CONF", &cached_cfg)
        .env("SCCACHE_EXPERIMENTAL_CANONICAL_RUST", "1")
        .env("SCCACHE_CANONICAL_BUILD_ROOT", &project)
        .env("CARGO_TARGET_DIR", project.join("target"))
        .env("SCCACHE_OBSERVED_EMPTY", "")
        .env_remove("SCCACHE_OBSERVED_MISSING")
        .assert()
        .success();
    get_stats(|info| {
        assert_eq!(1, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
    });
    Ok(())
}

/// The policy directory is tracked by Clippy itself and can also be observed
/// by user source. The worker must resolve the original spelling, not a
/// rewritten environment value, with the exact policy contents.
#[cfg(unix)]
fn rust_clippy_observed_paths(fixture: &RustDistFixture) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::symlink;
    let case = fixture.case()?;
    let root = case.root.path().canonicalize()?;
    let cfg_path = &case.config;
    let cached_cfg = &case.cached_config;

    let project = root.join("source");
    let target = root.join("target");
    let policy = root.join("policy");
    let other_policy = root.join("other/policy");
    for path in [
        &project,
        &target,
        &policy,
        &other_policy,
        &root.join("other/traversal"),
        &root.join("scripts"),
        &root.join("tempdir"),
        &project.join("policy"),
    ] {
        fs::create_dir_all(path)?;
    }
    let allow = "disallowed-names = []\n";
    let deny = "disallowed-names = [\"policy_denied_name\"]\n";
    fs::write(policy.join("clippy.toml"), allow)?;
    fs::write(other_policy.join("actual.toml"), allow)?;
    symlink("actual.toml", other_policy.join("clippy.toml"))?;
    // Flattening the link/.. pair would select source/policy (the decoy),
    // whereas the kernel enters other/traversal and then selects other/policy.
    fs::write(project.join("policy/clippy.toml"), deny)?;
    symlink("../other/traversal", project.join("hop"))?;
    symlink("hop", project.join("link"))?;
    symlink(&policy, root.join("absolute-alias"))?;

    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let sysroot = std::process::Command::new(&rustc)
        .args(["--print", "sysroot"])
        .output()?;
    assert!(sysroot.status.success());
    let clippy = Path::new(std::str::from_utf8(&sysroot.stdout)?.trim()).join("bin/clippy-driver");
    assert!(clippy.is_file(), "Install the toolchain's Clippy component");
    let tmpdir = root.join("scripts/../tempdir");
    let cases = [
        ("normalized", policy.clone()),
        ("lexical", root.join("scripts/../policy")),
        ("relative", Path::new("../policy").to_owned()),
        ("symlink_parent", Path::new("link/../policy").to_owned()),
        ("absolute_alias", root.join("absolute-alias")),
    ];
    for (name, spelling) in &cases {
        let source = project.join(format!("{name}.rs"));
        let metadata = target.join(format!("lib{name}.rmeta"));
        let observed = spelling.to_str().context("non-UTF8 config path")?;
        let observed_tmp = tmpdir.to_str().context("non-UTF8 temporary path")?;
        fs::write(
            &source,
            format!(
                r#"
pub const OBSERVED: &str = env!("CLIPPY_CONF_DIR");
pub const TEMP: &str = env!("TMPDIR");
pub const POLICY: &str = include_str!(concat!(env!("CLIPPY_CONF_DIR"), "/clippy.toml"));
const fn equal(a: &[u8], b: &[u8]) -> bool {{
    if a.len() != b.len() {{ return false; }}
    let mut i = 0;
    while i < a.len() {{
        if a[i] != b[i] {{ return false; }}
        i += 1;
    }}
    true
}}
const _: () = assert!(equal(OBSERVED.as_bytes(), {observed:?}.as_bytes()));
const _: () = assert!(equal(TEMP.as_bytes(), {observed_tmp:?}.as_bytes()));
pub fn marker() -> u32 {{ let policy_denied_name = 11; policy_denied_name + 1 }}
"#
            ),
        )?;
        let compile = || {
            let mut command = sccache_command();
            for (key, _) in env::vars_os() {
                if key.to_string_lossy().starts_with("CARGO") || key == "OUT_DIR" {
                    command.env_remove(key);
                }
            }
            command
                .current_dir(&project)
                .arg(&clippy)
                .args([
                    "rustc",
                    "--edition=2024",
                    "--crate-name",
                    name,
                    "--crate-type",
                    "lib",
                    "--emit=metadata,dep-info",
                    "-Wclippy::disallowed_names",
                ])
                .arg("--out-dir")
                .arg(&target)
                .arg(&source)
                .env("CLIPPY_CONF_DIR", spelling)
                .env_remove("CLIPPY_ARGS")
                .env("TMPDIR", &tmpdir)
                .env("SCCACHE_CONF", cfg_path)
                .env("SCCACHE_CACHED_CONF", cached_cfg)
                .env("SCCACHE_EXPERIMENTAL_CANONICAL_RUST", "1")
                .env("SCCACHE_CANONICAL_BUILD_ROOT", &project)
                .env("SCCACHE_CANONICAL_TARGET_ROOT", &target);
            command
        };
        let first = compile().output()?;
        assert!(
            first.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&first.stderr)
                .contains("use of a disallowed/placeholder name")
        );
        let initial = fs::read(&metadata)?;
        assert!(!initial.is_empty());
        fs::remove_file(&metadata)?;
        let cached = compile().output()?;
        assert!(cached.status.success());
        assert_eq!(cached.stderr, first.stderr);
        assert_eq!(fs::read(&metadata)?, initial);

        // Changing only the resolved policy must invalidate the cache, run
        // on the worker, and enforce the new lint rather than reuse success.
        let resolved = project.join(spelling).canonicalize()?.join("clippy.toml");
        fs::write(&resolved, deny)?;
        fs::remove_file(&metadata)?;
        let result = compile().output()?;
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("use of a disallowed/placeholder name"),
            "{name}: unexpected diagnostic: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_ne!(
            fs::read(&metadata)?,
            initial,
            "changed policy must change embedded metadata"
        );
        fs::write(&resolved, allow)?;
    }
    let count = cases.len();
    let expected_hits = u64::try_from(count)?;
    get_stats(move |info| {
        assert_eq!(count * 2, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(expected_hits, info.stats.cache_hits.all());
        assert_eq!(0, info.stats.dist_errors);
    });
    Ok(())
}

// MinGW's raw-dylib import library is generated during rlib compilation.
#[cfg(target_os = "linux")]
fn rust_windows_gnu_dlltool(fixture: &RustDistFixture) -> Result<()> {
    use std::io::Write;
    let case = fixture.case()?;
    let root = case.root.path();
    let cfg_path = &case.config;
    let cached_cfg = &case.cached_config;

    let tools = root.join("auxiliary tools");
    std::fs::create_dir(&tools)?;
    let dlltool = tools.join("x86_64-w64-mingw32-dlltool");
    let assembler = tools.join("x86_64-w64-mingw32-as");
    std::fs::copy(which::which("x86_64-w64-mingw32-dlltool")?, &dlltool)?;
    std::fs::copy(which::which("x86_64-w64-mingw32-as")?, &assembler)?;
    write_source(
        root,
        "raw.rs",
        r#"
#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" { fn GetTickCount() -> u32; }
pub fn ticks() -> u32 { unsafe { GetTickCount() } }
"#,
    );
    let compiler = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = root.join("libraw.rlib");
    let compile = |explicit: bool| {
        let mut command = sccache_command();
        for (key, _) in env::vars_os() {
            if key.to_string_lossy().starts_with("CARGO") || key == "OUT_DIR" {
                command.env_remove(key);
            }
        }
        command.current_dir(root).arg(&compiler).args([
            "--edition=2024",
            "--crate-name=raw",
            "--crate-type=rlib",
            "--target=x86_64-pc-windows-gnu",
            "--emit=link,dep-info",
            "--out-dir",
            ".",
        ]);
        if explicit {
            command
                .arg("-C")
                .arg(format!("dlltool={}", dlltool.display()));
        }
        command
            .arg("raw.rs")
            .env("SCCACHE_CONF", cfg_path)
            .env("SCCACHE_CACHED_CONF", cached_cfg)
            .assert()
            .success();
    };
    for explicit in [false, true] {
        compile(explicit);
        let expected = std::fs::read(&output)?;
        assert!(expected.starts_with(b"!<arch>\n"));
        std::fs::remove_file(&output)?;
        compile(explicit);
        assert_eq!(std::fs::read(&output)?, expected);
    }
    // A byte-identical result from a changed tool still needs a new key.
    // Trailing data does not change ELF execution.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&assembler)?
        .write_all(b"identity mutation")?;
    std::fs::remove_file(&output)?;
    compile(true);
    get_stats(|info| {
        assert_eq!(3, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(2, info.stats.cache_hits.all());
        assert_eq!(0, info.stats.dist_errors);
    });
    Ok(())
}

// Check the real worker and cache restoration, including zero-length rmeta
// marker files required by Cargo for executable and test targets.
#[cfg(unix)]
fn rust_metadata_outputs(fixture: &RustDistFixture) -> Result<()> {
    let case = fixture.case()?;
    let root = case.root.path();
    let cfg_path = &case.config;
    let cached_cfg = &case.cached_config;

    let source = root.join("source");
    std::fs::create_dir(&source)?;
    let output = root.join("output");
    std::fs::create_dir(&output)?;
    write_source(&source, "common.rs", "pub fn marker() {} fn main() {}");
    write_source(
        &source,
        "macro.rs",
        r#"
extern crate proc_macro;
use proc_macro::TokenStream;
#[proc_macro] pub fn identity(input: TokenStream) -> TokenStream { input }
"#,
    );
    let compiler = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let cases: &[(&str, &[&str])] = &[
        ("executable", &["--crate-type", "bin"]),
        ("implicit", &[]),
        ("unit_test", &["--test"]),
        ("lib_test", &["--crate-type", "lib", "--test"]),
        ("rlib", &["--crate-type", "rlib"]),
        ("dylib", &["--crate-type", "dylib"]),
        ("staticlib", &["--crate-type", "staticlib"]),
        ("cdylib", &["--crate-type", "cdylib"]),
        ("proc_macro", &["--crate-type", "proc-macro"]),
    ];
    for (name, flags) in cases {
        let src = if *name == "proc_macro" {
            "macro.rs"
        } else {
            "common.rs"
        };
        let metadata = output.join(format!("lib{name}-regression.rmeta"));
        let dep_info = output.join(format!("{name}-regression.d"));
        let compile = || {
            let mut command = sccache_command();
            for (key, _) in env::vars_os() {
                if key.to_string_lossy().starts_with("CARGO") || key == "OUT_DIR" {
                    command.env_remove(key);
                }
            }
            command
                .current_dir(&source)
                .arg(&compiler)
                .args([
                    "--crate-name",
                    name,
                    "--emit",
                    "metadata,dep-info",
                    "-C",
                    "extra-filename=-regression",
                ])
                .args(*flags)
                .arg("--out-dir")
                .arg(&output)
                .arg(src)
                .env("SCCACHE_CONF", cfg_path)
                .env("SCCACHE_CACHED_CONF", cached_cfg)
                .env("SCCACHE_EXPERIMENTAL_CANONICAL_RUST", "1")
                .env("SCCACHE_CANONICAL_BUILD_ROOT", &source)
                .env("SCCACHE_CANONICAL_TARGET_ROOT", &output)
                .assert()
                .success();
        };
        compile();
        let expected = std::fs::read(&metadata)?;
        let deps = std::fs::read(&dep_info)?;
        std::fs::remove_file(&metadata)?;
        std::fs::remove_file(&dep_info)?;
        compile();
        assert_eq!(std::fs::read(metadata)?, expected, "{name}");
        assert_eq!(std::fs::read(dep_info)?, deps, "{name}");
    }
    let expected = cases.len();
    get_stats(move |info| {
        assert_eq!(expected, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(
            u64::try_from(expected).unwrap(),
            info.stats.cache_hits.all()
        );
        assert_eq!(0, info.stats.dist_errors);
    });
    Ok(())
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_cargo_makeflags() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    let _server_handle = system.add_server(&[]);

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, &system);
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    let _ = stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    let compile_output = rust_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    assert!(
        !String::from_utf8_lossy(&compile_output.stderr)
            .contains("warning: failed to connect to jobserver from environment variable")
    );

    get_stats(|info| {
        assert_eq!(1, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(8, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_preprocesspr_cache_bug_2173() {
    // Bug 2173: preprocessor cache hit but main cache miss - because using the preprocessor cache
    // means not doing regular preprocessing, there was no preprocessed translation unit to send
    // out for distributed compilation, so an empty u8 array was compiled - which "worked", but
    // the object file *was* the result of compiling an empty file.
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    let _server_handle = system.add_server(&[]);

    let mut sccache_cfg = dist_test_sccache_client_cfg(tmpdir, &system);
    let disk_cache = sccache_cfg.cache.disk.as_mut().unwrap();
    disk_cache
        .preprocessor_cache_mode
        .use_preprocessor_cache_mode = true;
    disk_cache.size = 10_000_000; // enough for one tiny object file
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    let _ = stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);

    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);
    let obj_file = "x.o";
    let obj_path = tmpdir.join(obj_file);
    let data_a = std::fs::read(&obj_path).unwrap();

    let cache_path = sccache_cfg.cache.disk.unwrap().dir;

    // Don't touch the preprocessor cache - and check that it exists
    assert!(
        cache_path.join("preprocessor").is_dir(),
        "The preprocessor cache should exist"
    );

    // Delete the main cache to ensure a cache miss - potential dirs are "0".."f".
    let main_cache_dirs = "0123456789abcdef";
    let delete_count = main_cache_dirs.chars().fold(0, |res, dir| {
        res + (std::fs::remove_dir_all(cache_path.join(String::from(dir))).is_ok() as u32)
    });
    assert_eq!(delete_count, 1, "Did the disk cache format change?");

    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    // Check that this gave the same result (i.e. that it didn't compile a completely empty file).
    // It would be nice to check directly that the object file contains the symbol for the x() function
    // from basic_compile(), but that seems pretty involved and this happens to work...
    let data_b = std::fs::read(&obj_path).unwrap();

    assert_eq!(data_a, data_b);
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_toolchain() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    let server_handle = system.add_server(&[]);
    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, &system);
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");
    let _ = stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    assert!(
        stop_local_daemon(),
        "failed to stop local daemon before cache clear"
    );
    assert!(
        clear_cache_local_daemon(tmpdir),
        "failed to clear local daemon cache"
    );

    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    assert_eq!(system.count_toolchains_on_server(&server_handle), 1);

    get_stats(|info| {
        assert_eq!(1, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

// rustc must resolve a transitive metadata dependency through -L dependency
// even when the client command explicitly names only the immediate extern.
#[cfg(unix)]
fn dist_rust_dependency_chain(fixture: &RustDistFixture, relative: Option<&str>) -> Result<()> {
    let case = fixture.case()?;
    let root = case.root.path();
    let cfg_path = &case.config;
    let cached_cfg = &case.cached_config;

    let source = root.join("source");
    let target = if relative == Some("out") {
        source.join("out")
    } else {
        root.join("target")
    };
    let operand = relative.map_or(target.as_path(), Path::new);
    let extension = if relative.is_some() { "rlib" } else { "rmeta" };
    let emit = if relative.is_some() {
        "--emit=link,dep-info"
    } else {
        "--emit=metadata,dep-info"
    };
    std::fs::create_dir(&source)?;
    std::fs::create_dir(&target)?;
    write_source(
        &source,
        "first.rs",
        "pub struct Value; impl Value { pub fn get(&self) -> u32 { 42 } }",
    );
    write_source(
        &source,
        "second.rs",
        "pub fn value() -> first::Value { first::Value }",
    );
    write_source(
        &source,
        "third.rs",
        "pub fn result() -> u32 { second::value().get() }",
    );
    let compiler = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    for name in ["first", "second", "third"] {
        let metadata = target.join(format!("lib{name}-regression.{extension}"));
        let predecessor = match name {
            "second" => Some("first"),
            "third" => Some("second"),
            _ => None,
        };
        let compile = || {
            let mut command = sccache_command();
            for (key, _) in env::vars_os() {
                if key.to_string_lossy().starts_with("CARGO") || key == "OUT_DIR" {
                    command.env_remove(key);
                }
            }
            command
                .current_dir(&source)
                .arg(&compiler)
                .args([
                    "--edition=2021",
                    "--crate-name",
                    name,
                    "--crate-type",
                    "rlib",
                    emit,
                    "-C",
                    "extra-filename=-regression",
                ])
                .arg("--out-dir")
                .arg(operand)
                .arg("-L")
                .arg(format!("dependency={}", operand.display()))
                .arg(format!("{name}.rs"))
                .env("CARGO_PKG_NAME", name)
                .env("SCCACHE_CONF", cfg_path)
                .env("SCCACHE_CACHED_CONF", cached_cfg)
                .env("SCCACHE_EXPERIMENTAL_CANONICAL_RUST", "1")
                .env("SCCACHE_CANONICAL_BUILD_ROOT", &source)
                .env("SCCACHE_CANONICAL_TARGET_ROOT", &target);
            if let Some(dep) = predecessor {
                command.arg("--extern").arg(format!(
                    "{dep}={}",
                    operand
                        .join(format!("lib{dep}-regression.{extension}"))
                        .display()
                ));
            }
            command.assert().success();
        };
        compile();
        let initial = std::fs::read(&metadata)?;
        assert!(!initial.is_empty());
        let dep_info = std::fs::read_to_string(target.join(format!("{name}-regression.d")))?;
        assert!(dep_info.contains(
            &format!("{}:", operand.join(format!("lib{name}-regression.{extension}")).display())
        ));
        std::fs::remove_file(&metadata)?;
        compile();
        assert_eq!(std::fs::read(&metadata)?, initial);
    }
    get_stats(|info| {
        assert_eq!(3, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(3, info.stats.cache_hits.all());
        assert_eq!(0, info.stats.dist_errors);
    });
    Ok(())
}

/// Cargo's real split build root contains target metadata and sibling host
/// proc macro artifacts. Compile a consumer of a re-exported proc macro
/// through a transitive metadata dependency in two independent build roots.
#[cfg(target_os = "linux")]
fn rust_cargo_split_root_proc_macro(fixture: &RustDistFixture) -> Result<()> {
    let case = fixture.case()?;
    let root = case.root.path();
    let cfg_path = &case.config;
    let cached_cfg = &case.cached_config;

    let project = root.join("consumer");
    for (name, manifest, source) in [
        (
            "",
            "[package]\nname='consumer'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nsecond={path='second'}\n",
            "#[second::identity]\npub fn answer() -> second::Value { second::Value }",
        ),
        (
            "second",
            "[package]\nname='second'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nfirst={path='../first'}\n",
            "pub use first::{identity, Value};",
        ),
        (
            "first",
            "[package]\nname='first'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nmacro_dep={path='../macro_dep'}\n",
            "pub use macro_dep::identity; pub struct Value;",
        ),
        (
            "macro_dep",
            "[package]\nname='macro_dep'\nversion='0.1.0'\nedition='2024'\n[lib]\nproc-macro=true\n",
            "extern crate proc_macro; #[proc_macro_attribute] pub fn identity(_: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream { item }",
        ),
    ] {
        let dir = project.join(name);
        std::fs::create_dir_all(dir.join("src"))?;
        write_source(&dir, "Cargo.toml", manifest);
        write_source(&dir, "src/lib.rs", source);
    }
    let compiler = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = std::process::Command::new(&compiler).arg("-vV").output()?;
    assert!(version.status.success());
    let version = String::from_utf8(version.stdout)?;
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("rustc did not report its host triple")?;

    for session in ["one", "two"] {
        let target = root.join(session).join("target");
        let intermediate = root.join(session).join("intermediate");
        cargo_command()
            .current_dir(&project)
            .args(["check", "--offline", "--target", host, "--config"])
            .arg(format!("build.build-dir='{}'", intermediate.display()))
            .arg("--target-dir")
            .arg(&target)
            .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_sccache"))
            .env("SCCACHE_CONF", cfg_path)
            .env("SCCACHE_CACHED_CONF", cached_cfg)
            .env("SCCACHE_EXPERIMENTAL_CANONICAL_RUST", "1")
            .env("SCCACHE_CANONICAL_TARGET_ROOT", &target)
            .env("CARGO_BUILD_EPHEMERAL_INTERMEDIATES", "false")
            .env("CARGO_INCREMENTAL", "0")
            .assert()
            .success();
        assert!(intermediate.join("CACHEDIR.TAG").is_file());
        assert!(intermediate.join(host).join("CACHEDIR.TAG").is_file());
    }
    get_stats(|info| {
        assert!(info.stats.dist_compiles.values().sum::<usize>() >= 3);
        assert!(info.stats.cache_hits.all() >= 3);
        assert_eq!(info.stats.dist_errors, 0);
    });
    Ok(())
}

// Each case is named in the log so CI timings remain attributable even
// though the expensive worker/toolchain setup is shared.
#[test]
#[cfg(unix)]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_rust_warm_regressions() -> Result<()> {
    let fixture = RustDistFixture::new(&[])?;
    fn timed(name: &str, case: impl FnOnce() -> Result<()>) -> Result<()> {
        let start = std::time::Instant::now();
        let result = case().with_context(|| format!("distributed regression: {name}"));
        eprintln!("{name}: {:.2?}", start.elapsed());
        result
    }
    #[cfg(target_os = "linux")]
    timed("cargo split-root proc macro", || {
        rust_cargo_split_root_proc_macro(&fixture)
    })?;
    timed("Clippy observed paths", || {
        rust_clippy_observed_paths(&fixture)
    })?;
    for (name, relative) in [
        ("dependency chain absolute", None),
        ("dependency chain relative nested", Some("out")),
        ("dependency chain relative sibling", Some("../target")),
    ] {
        timed(name, || dist_rust_dependency_chain(&fixture, relative))?;
    }
    timed("metadata outputs", || rust_metadata_outputs(&fixture))?;
    #[cfg(target_os = "linux")]
    timed("Windows GNU dlltool", || rust_windows_gnu_dlltool(&fixture))?;
    Ok(())
}
