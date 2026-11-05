use anyhow::{Context, Result};
use assert_cmd::assert::OutputAssertExt;
use chrono::Local;
use fs_err as fs;
use log::trace;
use std::convert::Infallible;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::LazyLock;

pub static CRATE_DIR: LazyLock<PathBuf> =
    LazyLock::new(|| Path::new(file!()).parent().unwrap().join("../test-crate"));
pub static CARGO: LazyLock<OsString> = LazyLock::new(|| std::env::var_os("CARGO").unwrap());
pub static SCCACHE_BIN: LazyLock<&Path> =
    LazyLock::new(|| Path::new(env!("CARGO_BIN_EXE_sccache")));

/// Use the test-owned server endpoint, not an inherited CI compiler-cache daemon.
///
/// The canonical CI compiler cache can use a separate TCP port or Unix socket.
/// System tests deliberately start and stop their own daemon and must never
/// accidentally stop that externally managed compiler cache.
#[must_use]
pub fn test_sccache_command() -> Command {
    let mut cmd = Command::new(SCCACHE_BIN.as_os_str());
    cmd.env_remove("SCCACHE_SERVER_PORT")
        .env_remove("SCCACHE_SERVER_UDS");
    cmd
}

/// Test Cargo invocations compile through the test-built sccache binary,
/// not an inherited CI compiler-cache endpoint.
#[must_use]
pub fn test_cargo_command() -> Command {
    let mut cmd = Command::new(CARGO.as_os_str());
    cmd.env_remove("SCCACHE_SERVER_PORT")
        .env_remove("SCCACHE_SERVER_UDS");
    cmd
}

/// Ensures the logger is only initialized once. Panics if initialization fails.
static LOGGER: LazyLock<Result<(), Infallible>> = LazyLock::new(|| {
    env_logger::Builder::new()
        .format(|f, record| {
            writeln!(
                f,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                record.level(),
                record.args()
            )
        })
        .parse_env("RUST_LOG")
        .init();
    Ok(())
});

/// Used as a test setup fixture. The drop implementation cleans up after a _successful_ test.
/// We catch the panic to ensure that the drop runs and the `TempDir` is cleaned up.
pub struct SccacheTest<'a> {
    /// Tempdir used for Sccache cache and cargo output. It is kept in the struct only to have the
    /// destructor run when `SccacheTest` goes out of scope, but is never used otherwise.
    pub tempdir: tempfile::TempDir,
    pub env: Vec<(&'a str, std::ffi::OsString)>,
}

impl SccacheTest<'_> {
    pub fn new(additional_envs: Option<&[(&'static str, std::ffi::OsString)]>) -> Result<Self> {
        assert!(LOGGER.is_ok());

        // Create a temp directory to use for the disk cache.
        let tempdir = tempfile::Builder::new()
            .prefix("sccache_test_rust_cargo")
            .tempdir()
            .context("Failed to create tempdir")?;
        let cache_dir = tempdir.path().join("cache");
        fs::create_dir(&cache_dir)?;
        let cargo_dir = tempdir.path().join("cargo");
        fs::create_dir(&cargo_dir)?;

        // Ensure there's no existing sccache server running.
        stop_sccache()?;

        trace!("sccache --start-server");

        test_sccache_command()
            .arg("--start-server")
            .env("SCCACHE_DIR", &cache_dir)
            .assert()
            .try_success()
            .context("Failed to start sccache server")?;

        let mut env = vec![
            ("CARGO_TARGET_DIR", cargo_dir.as_os_str().to_owned()),
            ("RUSTC_WRAPPER", SCCACHE_BIN.as_os_str().to_owned()),
            // Explicitly disable incremental compilation because sccache is unable to cache it at
            // the time of writing.
            ("CARGO_INCREMENTAL", OsString::from("0")),
            ("TEST_ENV_VAR", OsString::from("1")),
        ];

        if let Some(vec) = additional_envs {
            env.extend_from_slice(vec);
        }

        Ok(SccacheTest {
            tempdir,
            env: env.clone(),
        })
    }

    /// Show the statistics for sccache. This will be called at the end of a test and making this
    /// an associated function will ensure that the struct lives until the end of the test.
    pub fn show_stats(&self) -> Result<assert_cmd::assert::Assert> {
        trace!("sccache --show-stats");

        test_sccache_command()
            .args(["--show-stats", "--stats-format=json"])
            .assert()
            .try_success()
            .map_err(Into::into)
    }

    pub fn show_text_stats(&self, advanced: bool) -> Result<assert_cmd::assert::Assert> {
        let cmd = if advanced {
            "--show-adv-stats"
        } else {
            "--show-stats"
        };

        trace!("sccache {cmd}");

        test_sccache_command()
            .args([cmd, "--stats-format=text"])
            .assert()
            .try_success()
            .map_err(Into::into)
    }
}

impl Drop for SccacheTest<'_> {
    fn drop(&mut self) {
        if let Err(error) = stop_sccache() {
            eprintln!("failed to stop sccache test server during cleanup: {error:#}");
        }
    }
}

pub fn stop_sccache() -> Result<()> {
    trace!("sccache --stop-server");

    test_sccache_command()
        .arg("--stop-server")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to stop sccache server")?;
    Ok(())
}

pub fn cargo_clean(test_info: &SccacheTest) -> Result<()> {
    test_cargo_command()
        .args(["clean"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_success()?;
    Ok(())
}
