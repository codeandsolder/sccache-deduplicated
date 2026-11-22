//! Real scheduler and native-only worker subprocesses on loopback.
//! No Docker, root, production daemon, or archive cache is involved.
#![cfg(all(target_os = "linux", feature = "dist-server", feature = "dist-client"))]

use std::{
    collections::BTreeMap,
    fs::{self, File},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use sccache::{
    build_runtime::{
        ActionMode, BuildPath, CommandSpec, ComponentAudit, ContentId, ExecutionRoot,
        ExecutionSpec, InstallationManifest, MappedMetadata, MappedTree, NativeStore, OutputSpec,
        SpacePolicy, TreeLayer, TreePath, TreeRecipe,
        wire::{NativeAdmission, NativeRunResult, NativeStatus, ScheduleReply},
    },
    config::{
        Config, DistAuth, HTTPUrl, NativeClientConfig, NativeExecutionPreference,
        NativeLocalConfig, scheduler, server,
    },
    dist::{
        SchedulerStatusResult,
        native::{LocalExecutor, NativeBuildPolicy, NativeBuildSource, NativeCacheClient},
        pkg::ToolchainPackageBuilder,
    },
};

const CLIENT_TOKEN: &str = "native-integration-client";
const WORKER_TOKEN: &str = "native-integration-worker";
const PLATFORM: &str = "native-integration-platform-v1";

fn package_limits(retain_original: bool) -> sccache::build_runtime::PackageImportLimits {
    sccache::build_runtime::PackageImportLimits {
        retain_original,
        max_concurrent_imports: 2,
        max_archive_bytes: 1 << 30,
        max_entries: 100_000,
        max_expanded_bytes: 4 << 30,
        max_tar_bytes: 5 << 30,
        max_metadata_bytes: 64 << 20,
        decoder_memory_bytes: 512 << 20,
        decoder_timeout_secs: 120,
    }
}

fn space() -> SpacePolicy {
    SpacePolicy {
        min_available_bytes: 1024 * 1024,
        target_available_bytes: 2 * 1024 * 1024,
        max_evictions_per_pass: 8,
        gc_batch: 128,
    }
}

fn local_config(root: &Path, preference: NativeExecutionPreference) -> NativeLocalConfig {
    NativeLocalConfig {
        preference,
        max_jobs: 2,
        directory: root.join("local-input-store"),
        scratch: root.join("local-scratch"),
        bubblewrap: "/usr/bin/bwrap".into(),
        space: space(),
    }
}

struct Process {
    child: Child,
    log: PathBuf,
}

impl Process {
    fn start(root: &Path, role: &str, config: &impl serde::Serialize) -> Result<Self> {
        let file = root.join(format!("{role}.json"));
        fs::write(&file, serde_json::to_vec(config)?)?;
        let log = root.join(format!("{role}.log"));
        let output = File::create(&log)?;
        let child = Command::new(env!("CARGO_BIN_EXE_sccache-dist"))
            .args([role, "--config"])
            .arg(file)
            // Existing foreground control of the subprocess under test.
            .env("SCCACHE_NO_DAEMON", "1")
            .env("SCCACHE_LOG", "info")
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(output)
            .spawn()?;
        Ok(Self { child, log })
    }

    fn check(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            anyhow::bail!(
                "native subprocess exited {status}: {}",
                fs::read_to_string(&self.log)?
            );
        }
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!(
                "{}: {}",
                self.log.display(),
                fs::read_to_string(&self.log).unwrap_or_default()
            );
        }
    }
}

fn wait_for<T>(mut ready: impl FnMut() -> Result<Option<T>>) -> Result<T> {
    let start = Instant::now();
    loop {
        if let Some(result) = ready()? {
            return Ok(result);
        }
        ensure!(
            start.elapsed() < Duration::from_secs(20),
            "native subprocess readiness timed out"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn addresses() -> Result<[SocketAddr; 3]> {
    let listeners = (0..3)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<Vec<_>>>()?;
    let addresses = listeners
        .iter()
        .map(TcpListener::local_addr)
        .collect::<std::io::Result<Vec<_>>>()?;
    addresses
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong listener count"))
}

fn fetch_status(
    http: &reqwest::blocking::Client,
    scheduler: &reqwest::Url,
) -> Result<SchedulerStatusResult> {
    Ok(http
        .get(scheduler.join("/api/v1/scheduler/status")?)
        .header("Accept", "application/json")
        .send()?
        .error_for_status()?
        .json()?)
}

struct Fleet {
    worker: Process,
    scheduler: Process,
    worker_directory: PathBuf,
    scheduler_directory: PathBuf,
    worker_address: SocketAddr,
    cache_url: reqwest::Url,
    scheduler_url: reqwest::Url,
    http: reqwest::blocking::Client,
}

impl Fleet {
    fn start(
        root: &Path,
        package_upstreams: BTreeMap<String, scheduler::PackageUpstream>,
    ) -> Result<Self> {
        let [scheduler_address, cache_address, worker_address] = addresses()?;
        let scheduler_url = reqwest::Url::parse(&format!("http://{scheduler_address}/"))?;
        let cache_url = reqwest::Url::parse(&format!("http://{cache_address}/"))?;
        let scheduler_directory = root.join("scheduler-store");
        let worker_directory = root.join("worker-store");
        let mut scheduler_process = Process::start(
            root,
            "scheduler",
            &scheduler::Config {
                public_addr: scheduler_address,
                client_auth: scheduler::ClientAuth::Token {
                    token: CLIENT_TOKEN.into(),
                },
                server_auth: scheduler::ServerAuth::Token {
                    token: WORKER_TOKEN.into(),
                },
                maintenance_drain_file: None,
                job_slack: scheduler::JobSlackConfig {
                    static_jobs: 0,
                    percent: 0.0,
                },
                native_cache: Some(scheduler::NativeCacheConfig {
                    public_addr: cache_address,
                    directory: scheduler_directory.clone(),
                    space: space(),
                    idle_timeout_secs: 120,
                    max_sessions: 64,
                    max_result_bytes: 64 * 1024 * 1024,
                    max_result_blobs: 128,
                    max_tree_bytes: 4 * 1024 * 1024 * 1024,
                    max_tree_blobs: 32_768,
                    max_concurrent_uploads: 2,
                    max_total_uploads: 4,
                    http_threads: 8,
                    max_metadata_bytes: 64 * 1024 * 1024,
                    package_import: Some(package_limits(true)),
                    package_upstreams,
                }),
            },
        )?;
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;
        let status = || fetch_status(&http, &scheduler_url);
        wait_for(|| {
            scheduler_process.check()?;
            Ok(status().ok())
        })?;
        let mut worker_process = Process::start(
            root,
            "server",
            &server::Config {
                builder: server::BuilderType::Native,
                cache_dir: None,
                public_addr: worker_address,
                bind_address: None,
                scheduler_url: HTTPUrl::from_url(scheduler_url.clone()),
                scheduler_auth: server::SchedulerAuth::Token {
                    token: WORKER_TOKEN.into(),
                },
                toolchain_cache_size: 0,
                toolchain_archive_sources: Vec::new(),
                native_worker: Some(server::NativeWorkerConfig {
                    cache_url: HTTPUrl::from_url(cache_url.clone()),
                    directory: worker_directory.clone(),
                    space: space(),
                    scratch: root.join("scratch"),
                    bubblewrap: "/usr/bin/bwrap".into(),
                    platform_contract: PLATFORM.into(),
                    renewal_interval_secs: 1,
                    request_timeout_secs: 60,
                    execution_timeout_secs: 120,
                    max_result_bytes: 64 * 1024 * 1024,
                    max_metadata_bytes: 64 * 1024 * 1024,
                    package_import: Some(package_limits(false)),
                }),
            },
        )?;
        wait_for(|| {
            scheduler_process.check()?;
            worker_process.check()?;
            Ok(status()
                .ok()
                .filter(|status| status.num_servers == 1 && status.available_jobs > 0))
        })?;
        Ok(Self {
            worker: worker_process,
            scheduler: scheduler_process,
            worker_directory,
            scheduler_directory,
            worker_address,
            cache_url,
            scheduler_url,
            http,
        })
    }

    fn status(&self) -> Result<SchedulerStatusResult> {
        fetch_status(&self.http, &self.scheduler_url)
    }

    fn finish(
        self,
    ) -> Result<(
        sccache::build_runtime::CacheStats,
        sccache::build_runtime::CacheStats,
    )> {
        let Self {
            worker,
            scheduler,
            worker_directory,
            scheduler_directory,
            ..
        } = self;
        drop(worker);
        drop(scheduler);
        Ok((
            NativeStore::open(&scheduler_directory)?.stats()?,
            NativeStore::open(&worker_directory)?.stats()?,
        ))
    }
}

fn rust_installer_fixture(component: &str, file: &str, contents: &[u8]) -> Result<Vec<u8>> {
    let mut archive = tar::Builder::new(Vec::new());
    let components = format!("{component}\n");
    let manifest = format!("file:{file}\n");
    for (path, bytes) in [
        ("release/rust-installer-version".to_owned(), &b"3\n"[..]),
        ("release/components".to_owned(), components.as_bytes()),
        (
            format!("release/{component}/manifest.in"),
            manifest.as_bytes(),
        ),
        (format!("release/{component}/{file}"), contents),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o755);
        header.set_size(u64::try_from(bytes.len())?);
        header.set_cksum();
        archive.append_data(&mut header, path, bytes)?;
    }
    Ok(archive.into_inner()?)
}

fn provisioning_config(root: &Path, endpoint: &reqwest::Url) -> Result<PathBuf> {
    let config = sccache::config::FileConfig {
        dist: sccache::config::DistConfig {
            auth: DistAuth::Token {
                token: CLIENT_TOKEN.into(),
            },
            native: Some(NativeClientConfig {
                endpoint: HTTPUrl::from_url(endpoint.clone()),
                platform_contract: PLATFORM.into(),
                request_timeout_secs: 30,
                build_timeout_secs: 30,
                renewal_interval_secs: 1,
                max_metadata_bytes: 1024 * 1024,
                max_result_bytes: 1024 * 1024,
                local_execution: None,
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    let config_path = root.join("provision.json");
    fs::write(&config_path, serde_json::to_vec(&config)?)?;
    Ok(config_path)
}

struct OriginalUpstream {
    origin: reqwest::Url,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    peak: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    stop: std::sync::mpsc::Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl OriginalUpstream {
    fn start(archives: std::collections::BTreeMap<String, Vec<u8>>) -> Result<Self> {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let requests = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&requests);
        let archives = archives
            .into_iter()
            .map(|(path, bytes)| (path, Arc::<[u8]>::from(bytes)))
            .collect::<std::collections::BTreeMap<_, _>>();
        let peak = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::clone(&peak);
        let active = AtomicUsize::new(0);
        let server = rouille::Server::new("127.0.0.1:0", move |request| {
            if request.method() != "GET" || request.header("Authorization").is_some() {
                return rouille::Response::empty_404();
            }
            let Some(bytes) = archives.get(&request.url()) else {
                return rouille::Response::empty_404();
            };
            count.fetch_add(1, Ordering::Relaxed);
            let concurrent = active.fetch_add(1, Ordering::SeqCst) + 1;
            maximum.fetch_max(concurrent, Ordering::SeqCst);
            // Allow independent acquisitions to overlap.
            thread::sleep(Duration::from_millis(800));
            active.fetch_sub(1, Ordering::SeqCst);
            let mut response = rouille::Response::from_data("application/octet-stream", Vec::new());
            // Intentionally omit Content-Length.
            response.data =
                rouille::ResponseBody::from_reader(std::io::Cursor::new(Arc::clone(bytes)));
            response
        })
        .map_err(|error| anyhow::anyhow!("{error}"))?
        .pool_size(2);
        let origin = reqwest::Url::parse(&format!("http://{}/", server.server_addr()))?;
        let (worker, stop) = server.stoppable();
        Ok(Self {
            origin,
            requests,
            peak,
            stop,
            thread: Some(worker),
        })
    }

    fn count(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Drop for OriginalUpstream {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn sync_rustup_command(root: &Path, config: &Path, catalog: &Path, recipe: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sccache-dist"));
    command
        .args(["native-sync-rust", "--root"])
        .arg(root)
        .arg("--client-config")
        .arg(config)
        .arg("--output")
        .arg(catalog)
        .arg("--recipe-output")
        .arg(recipe);
    command
}

fn json_output(output: std::process::Output) -> Result<serde_json::Value> {
    ensure!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
#[ignore = "requires actual scheduler, worker subprocesses and xz"]
fn rustup_sync_acquires_once_and_reuses_portable_recipe_and_catalog() -> Result<()> {
    use sccache::build_runtime::{InstallationRecipe, PackageCompression, PackageIdentity};
    use sha2::{Digest, Sha256};

    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let sysroot = root.join("sysroot");
    let rustlib = sysroot.join("lib/rustlib");
    fs::create_dir_all(&rustlib)?;
    let mut archives = std::collections::BTreeMap::new();
    let mut components = String::new();
    let mut installed = String::from("config_version = \"1\"\n");
    let mut channel = String::from("manifest-version = \"2\"\ndate = \"2026-11-22\"\n");
    let mut archive_bytes = 0;
    for (component, file, contents) in [
        ("compiler", "bin/rustc", &b"original compiler bytes"[..]),
        ("runtime", "lib/libexample", &b"original runtime bytes"[..]),
    ] {
        use std::fmt::Write as _;
        let archive = root.join(format!("{component}.tar"));
        fs::write(&archive, rust_installer_fixture(component, file, contents)?)?;
        let compressed = Command::new("xz").arg("-c").arg(&archive).output()?;
        ensure!(compressed.status.success(), "fixture xz compression failed");
        let identity = PackageIdentity {
            sha256: Sha256::digest(&compressed.stdout).into(),
            compression: PackageCompression::Xz,
        };
        archive_bytes += compressed.stdout.len();
        let path = format!("/dist/2026-11-22/{component}-nightly-host.tar.xz");
        writeln!(components, "{component}-host")?;
        writeln!(
            installed,
            "[[components]]\npkg = \"{component}\"\ntarget = \"host\""
        )?;
        writeln!(
            channel,
            "[pkg.{component}.target.host]\navailable = true\nxz_url = \"https://other-mirror.example{path}\"\nxz_hash = \"{}\"",
            identity.checksum_hex()
        )?;
        archives.insert(path, compressed.stdout);
        let destination = sysroot.join(file);
        fs::create_dir_all(destination.parent().context("fixture parent")?)?;
        fs::write(destination, contents)?;
        fs::write(
            rustlib.join(format!("manifest-{component}-host")),
            format!("file:{file}\n"),
        )?;
    }
    fs::write(rustlib.join("components"), components)?;
    fs::write(rustlib.join("multirust-config.toml"), installed)?;
    fs::write(rustlib.join("multirust-channel-manifest.toml"), channel)?;
    let upstream = OriginalUpstream::start(archives)?;
    let fleet = Fleet::start(
        root,
        BTreeMap::from([(
            "rust".into(),
            scheduler::PackageUpstream {
                origin: upstream.origin.clone(),
                timeout_secs: 10,
            },
        )]),
    )?;
    let config = provisioning_config(root, &fleet.cache_url)?;
    let catalog = root.join("installation.catalog");
    let recipe = root.join("installation.recipe");
    let catalog2 = root.join("installation-second.catalog");
    let recipe2 = root.join("installation-second.recipe");
    let first = sync_rustup_command(&sysroot, &config, &catalog, &recipe)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let second = sync_rustup_command(&sysroot, &config, &catalog2, &recipe2)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let first = json_output(first.wait_with_output()?)?;
    let second = json_output(second.wait_with_output()?)?;
    for field in ["acquired_packages", "reused_packages"] {
        assert_eq!(
            first["packages"][field].as_u64().unwrap_or(0)
                + second["packages"][field].as_u64().unwrap_or(0),
            2
        );
    }
    assert_eq!(
        first["packages"]["downloaded_archive_bytes"]
            .as_u64()
            .unwrap_or(0)
            + second["packages"]["downloaded_archive_bytes"]
                .as_u64()
                .unwrap_or(0),
        u64::try_from(archive_bytes)?
    );
    assert_eq!(upstream.count(), 2);
    assert_eq!(upstream.peak.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(fs::read(&recipe)?, fs::read(&recipe2)?);
    let installation = InstallationRecipe::read(File::open(&recipe)?)?;
    assert_eq!(
        installation.components["compiler-host"].component,
        "compiler"
    );
    assert_eq!(installation.tree_recipe()?.layers.len(), 2);
    assert_eq!(first["attestation"]["verified_files"], 2);
    assert_eq!(second["attestation"]["verified_files"], 2);
    let warm = json_output(sync_rustup_command(&sysroot, &config, &catalog, &recipe).output()?)?;
    assert_eq!(warm["packages"]["downloaded_archive_bytes"], 0);
    assert_eq!(warm["packages"]["reused_packages"], 2);
    assert_eq!(warm["attestation"]["reused_files"], 2);
    assert_eq!(upstream.count(), 2);
    let (scheduler, worker) = fleet.finish()?;
    assert_eq!(scheduler.blobs, 9);
    assert_eq!(scheduler.trees, 4);
    assert_eq!(worker.blobs, 0);
    drop(upstream);

    // Offline reattestation needs neither scheduler nor upstream, and a
    // changed installed file cannot inherit the original content identity.
    fs::write(sysroot.join("bin/rustc"), b"modified compiler bytes")?;
    let report = json_output(
        Command::new(env!("CARGO_BIN_EXE_sccache-dist"))
            .args(["native-attest-installation", "--root"])
            .arg(&sysroot)
            .arg("--recipe")
            .arg(&recipe)
            .arg("--output")
            .arg(&catalog)
            .output()?,
    )?;
    assert_eq!(report["reused_files"], 1);
    assert_eq!(report["differing_files"], 1);
    Ok(())
}

#[test]
#[ignore = "requires actual scheduler and worker subprocesses"]
fn live_original_package_provisioning_reuses_verified_content() -> Result<()> {
    use sccache::build_runtime::{PackageCompression, PackageIdentity, PackageSource};
    use sha2::{Digest, Sha256};

    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let fleet = Fleet::start(root, BTreeMap::new())?;
    let bytes = rust_installer_fixture("compiler", "bin/rustc", b"original compiler bytes")?;
    let archive = root.join("package.tar");
    fs::write(&archive, &bytes)?;
    let source = PackageSource {
        identity: PackageIdentity {
            sha256: Sha256::digest(&bytes).into(),
            compression: PackageCompression::Tar,
        },
        size: u64::try_from(bytes.len())?,
    };
    let client = NativeCacheClient::new(
        fleet.cache_url.clone(),
        CLIENT_TOKEN.into(),
        Duration::from_secs(30),
        1024 * 1024,
    )?;
    assert!(client.lookup_rust_package(source.identity)?.is_none());
    let mut wrong = source;
    wrong.identity.sha256[0] ^= 1;
    assert!(
        client
            .import_rust_package(wrong, File::open(&archive)?)
            .is_err()
    );
    assert!(client.lookup_rust_package(wrong.identity)?.is_none());
    let worker = NativeCacheClient::new(
        fleet.cache_url.clone(),
        WORKER_TOKEN.into(),
        Duration::from_secs(5),
        1024 * 1024,
    )?
    .for_worker(sccache::dist::JobId(123));
    assert!(worker.lookup_rust_package(source.identity).is_err());
    let config_path = provisioning_config(root, &fleet.cache_url)?;
    let manifest_path = root.join("package.manifest");
    let sha256 = source.identity.checksum_hex();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sccache-dist"));
        command
            .args(["native-provision-rust", "--client-config"])
            .arg(&config_path)
            .args([
                "--sha256",
                &sha256,
                "--size",
                &source.size.to_string(),
                "--compression",
                "tar",
                "--manifest-output",
            ])
            .arg(&manifest_path);
        command
    };
    let cold = command().arg("--archive").arg(&archive).output()?;
    ensure!(
        cold.status.success(),
        "cold provisioning failed: {}",
        String::from_utf8_lossy(&cold.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&cold.stdout)?;
    assert_eq!(report["reused_original_package"], false);
    let installed = InstallationManifest::read(File::open(&manifest_path)?)?;
    assert_eq!(installed.source, source);
    assert_eq!(installed.files()?.len(), 1);
    let warm = command().output()?;
    ensure!(
        warm.status.success(),
        "warm provisioning failed: {}",
        String::from_utf8_lossy(&warm.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&warm.stdout)?;
    assert_eq!(report["reused_original_package"], true);
    let resolved = client
        .lookup_rust_package(source.identity)?
        .ok_or_else(|| anyhow::anyhow!("verified package lost"))?;
    assert_eq!(resolved.components, installed.components);
    assert_eq!(resolved.package, installed.package);
    let raw = client
        .lookup_package(source.identity)?
        .context("original package absent")?;
    assert_eq!(raw.source, source);
    assert_eq!(raw.tree, installed.package);
    assert!(worker.lookup_package(source.identity).is_err());

    // A different tree with one of the package payloads needs no upload.
    let mut tree = installed.components["compiler"].clone();
    let path = TreePath::new(b"bin/rustc".to_vec())?;
    let entry = tree
        .entries
        .remove(&path)
        .ok_or_else(|| anyhow::anyhow!("installed compiler missing"))?;
    tree.entries
        .insert(TreePath::new(b"bin/renamed".to_vec())?, entry);
    let offer = client.offer_tree(&tree)?;
    assert!(offer.missing.is_empty());
    assert_eq!(client.commit_tree(offer.ticket)?, tree.id()?);
    client.close(offer.ticket)?;
    assert_eq!(fleet.status()?.num_servers, 1);
    let (scheduler, _) = fleet.finish()?;
    assert_eq!(scheduler.blobs, 5);
    assert_eq!(scheduler.trees, 3);
    Ok(())
}

#[test]
#[ignore = "requires Linux native scheduler and worker processes"]
fn named_system_upstream_provisions_original_without_client_upload() -> Result<()> {
    use sccache::build_runtime::{PackageCompression, PackageIdentity};
    use sccache::dist::native::PackageLocator;
    use sha2::{Digest, Sha256};

    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let bytes = zstd::stream::encode_all(
        rust_installer_fixture("compiler", "bin/tool", b"system compiler payload")?.as_slice(),
        1,
    )?;
    let identity = PackageIdentity {
        sha256: Sha256::digest(&bytes).into(),
        compression: PackageCompression::Zstd,
    };
    let size = u64::try_from(bytes.len())?;
    let path = "core/gcc-16.2.1+r23-x86_64_v3.pkg.tar.zst";
    let upstream = OriginalUpstream::start(BTreeMap::from([(format!("/repo/{path}"), bytes)]))?;
    let fleet = Fleet::start(
        root,
        BTreeMap::from([(
            "distro".into(),
            scheduler::PackageUpstream {
                origin: upstream.origin.join("repo/")?,
                timeout_secs: 10,
            },
        )]),
    )?;
    let client = NativeCacheClient::new(
        fleet.cache_url.clone(),
        CLIENT_TOKEN.into(),
        Duration::from_secs(30),
        1024 * 1024,
    )?;
    let locator = PackageLocator {
        identity,
        expected_size: Some(size),
        upstream: "distro".into(),
        path: path.into(),
    };
    assert!(
        client
            .acquire_package(&PackageLocator {
                upstream: "unknown".into(),
                ..locator.clone()
            })
            .is_err()
    );
    assert!(
        client
            .acquire_package(&PackageLocator {
                expected_size: Some(size - 1),
                ..locator.clone()
            })
            .is_err()
    );
    assert!(client.lookup_package(identity)?.is_none());
    let config = provisioning_config(root, &fleet.cache_url)?;
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sccache-dist"));
        command
            .args(["native-provision-package", "--client-config"])
            .arg(&config)
            .args([
                "--sha256",
                &identity.checksum_hex(),
                "--compression",
                "zstd",
                "--upstream",
                "distro",
                "--path",
                path,
            ]);
        command
    };
    let cold = command().output()?;
    ensure!(
        cold.status.success(),
        "{}",
        String::from_utf8_lossy(&cold.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&cold.stdout)?;
    assert_eq!(report["reused_original_package"], false);
    let receipt = client
        .lookup_package(identity)?
        .context("original package missing")?;
    assert_eq!(receipt.source.size, size);
    let warm = client.acquire_package(&locator)?;
    assert!(warm.reused);
    assert_eq!(warm.package, receipt);
    assert_eq!(upstream.count(), 2);
    let warm = command().output()?;
    ensure!(
        warm.status.success(),
        "{}",
        String::from_utf8_lossy(&warm.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&warm.stdout)?["reused_original_package"],
        true
    );
    assert_eq!(upstream.count(), 2);
    fleet.finish()?;
    Ok(())
}

fn provision_compressed_fixture(
    client: &NativeCacheClient,
    root: &Path,
    component: &str,
    data: &[u8],
    compression: sccache::build_runtime::PackageCompression,
) -> Result<sccache::build_runtime::PackageReceipt> {
    use sccache::build_runtime::{PackageCompression, PackageIdentity, PackageSource};
    use sha2::{Digest, Sha256};
    let bytes = match compression {
        PackageCompression::Xz => {
            let original = root.join(format!("{component}.tar"));
            fs::write(
                &original,
                rust_installer_fixture(component, "lib/payload", data)?,
            )?;
            let compressed = Command::new("xz").arg("-c").arg(&original).output()?;
            ensure!(compressed.status.success(), "fixture compression failed");
            compressed.stdout
        }
        PackageCompression::Zstd => {
            let mut tar = tar::Builder::new(Vec::new());
            for (path, bytes) in [
                (".PKGINFO", b"pkgname = include\n".as_slice()),
                ("usr/include/payload", data),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_mode(0o644);
                header.set_size(u64::try_from(bytes.len())?);
                header.set_cksum();
                tar.append_data(&mut header, path, bytes)?;
            }
            zstd::stream::encode_all(tar.into_inner()?.as_slice(), 1)?
        }
        _ => anyhow::bail!("unexpected fixture compression"),
    };
    let package = PackageSource {
        identity: PackageIdentity {
            sha256: Sha256::digest(&bytes).into(),
            compression,
        },
        size: u64::try_from(bytes.len())?,
    };
    let archive = root.join(format!("{component}.archive"));
    fs::write(&archive, bytes)?;
    assert!(client.lookup_package(package.identity)?.is_none());
    let receipt = client.import_package(package, File::open(&archive)?)?;
    assert_eq!(receipt.source, package);
    assert_eq!(client.lookup_package(package.identity)?, Some(receipt));
    assert!(package.size < u64::try_from(data.len())? / 100);
    Ok(receipt)
}

#[test]
#[ignore = "requires Linux Bubblewrap, GNU assembler and ldd"]
fn native_worker_https_executes_real_assembler_and_reuses_result() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let fleet = Fleet::start(root, BTreeMap::new())?;
    let worker_address = fleet.worker_address;
    let cache_url = fleet.cache_url.clone();
    let client = NativeCacheClient::new(
        cache_url,
        CLIENT_TOKEN.into(),
        Duration::from_secs(10),
        1024 * 1024,
    )?;
    let source_dir = root.join("source");
    fs::create_dir(&source_dir)?;
    let input = source_dir.join("input.s");
    // Two independent missing source blobs have smaller original archives.
    // Both are required by the same tree and can be reconstructed concurrently.
    let mut assembly = b".text\n.globl entry\nentry:\n.include \"input.inc\"\n".to_vec();
    let mut include = b".byte 1, 2, 3, 4\n".to_vec();
    for _ in 0..32768 {
        assembly.extend_from_slice(b"# repeated original assembly content\n");
        include.extend_from_slice(b"# repeated original include content\n");
    }
    fs::write(&input, &assembly)?;
    let include_path = source_dir.join("input.inc");
    fs::write(&include_path, &include)?;
    let packages = [
        provision_compressed_fixture(
            &client,
            root,
            "assembly",
            &assembly,
            sccache::build_runtime::PackageCompression::Xz,
        )?,
        provision_compressed_fixture(
            &client,
            root,
            "include",
            &include,
            sccache::build_runtime::PackageCompression::Zstd,
        )?,
    ];
    let reference = root.join("reference.o");
    ensure!(
        Command::new("/usr/bin/as")
            .current_dir(&source_dir)
            .arg("-o")
            .arg(&reference)
            .arg(&input)
            .status()?
            .success(),
        "local assembler failed"
    );
    let mut discovery = ToolchainPackageBuilder::new();
    discovery.add_executable_and_deps("/usr/bin/as".into())?;
    let root_tree = discovery.into_native_mapping()?.prepare()?;
    let mut mapping = MappedTree::new(root_tree.manifest().root);
    mapping.add_file(
        TreePath::new(b"input.s".to_vec())?,
        input.clone(),
        MappedMetadata::Preserve,
    )?;
    mapping.add_file(
        TreePath::new(b"input.inc".to_vec())?,
        include_path,
        MappedMetadata::Preserve,
    )?;
    let source_tree = mapping.prepare()?;
    let spec = ExecutionSpec {
        platform: ContentId::of(PLATFORM.as_bytes()),
        root: ExecutionRoot::resolve(
            TreeRecipe {
                directories: root_tree.manifest().root,
                layers: vec![
                    TreeLayer {
                        tree: root_tree.id(),
                        source: None,
                        destination: None,
                    },
                    TreeLayer {
                        tree: source_tree.id(),
                        source: None,
                        destination: Some(TreePath::new(b"src".to_vec())?),
                    },
                ],
            },
            &BTreeMap::from([
                (root_tree.id(), root_tree.manifest()),
                (source_tree.id(), source_tree.manifest()),
            ]),
        )?,
        mounts: BTreeMap::new(),
        command: CommandSpec {
            executable: BuildPath::new(b"/usr/bin/as".to_vec())?,
            arguments: [b"-o".as_slice(), b"object.o", b"/src/input.s"]
                .map(<[u8]>::to_vec)
                .to_vec(),
            cwd: BuildPath::new(b"/src".to_vec())?,
            environment: BTreeMap::new(),
        },
        outputs: BTreeMap::from([(
            "object".into(),
            OutputSpec {
                path: BuildPath::new(b"/src/object.o".to_vec())?,
                required: true,
            },
        )]),
    };
    assert_eq!(
        client.admit(&spec, ActionMode::Reuse)?,
        NativeAdmission::MissingInputs {
            trees: [root_tree.id(), source_tree.id()].into_iter().collect()
        },
    );
    let root_pin = client.push_tree(
        root_tree.manifest(),
        |id| root_tree.open_blob(id),
        Duration::from_secs(1),
    )?;
    let source_pin = client.push_tree(
        source_tree.manifest(),
        |_| -> Result<File> { anyhow::bail!("preseeded original must not upload its payload") },
        Duration::from_secs(1),
    )?;
    let NativeAdmission::Compile { ticket } = client.admit(&spec, ActionMode::Reuse)? else {
        anyhow::bail!("expected native miss");
    };
    client.close(root_pin)?;
    client.close(source_pin)?;
    let ScheduleReply::Assigned(allocation) = client.schedule(ticket, spec.clone())? else {
        anyhow::bail!("worker not allocated");
    };
    assert_eq!(allocation.address, worker_address);
    assert_eq!(
        client.schedule(ticket, spec.clone())?,
        ScheduleReply::Assigned(allocation.clone())
    );
    assert_eq!(
        NativeCacheClient::run_worker(&allocation, Duration::from_secs(30), 1024 * 1024)?,
        NativeRunResult::Stored
    );
    let NativeStatus::Ready(manifest) = client.status(ticket)? else {
        anyhow::bail!("result not published");
    };
    let mut bytes = Vec::new();
    client.download(ticket, manifest.outputs["object"].blob, &mut bytes)?;
    assert_eq!(bytes, fs::read(&reference)?);
    client.close(ticket)?;
    let warm_pin = client.push_tree(
        source_tree.manifest(),
        |_| -> Result<File> { anyhow::bail!("warm tree must not reopen input content") },
        Duration::from_secs(1),
    )?;
    client.close(warm_pin)?;
    let NativeAdmission::Hit {
        ticket: hit,
        manifest: cached,
    } = client.admit(&spec, ActionMode::Reuse)?
    else {
        anyhow::bail!("expected cache hit");
    };
    assert_eq!(cached, manifest);
    client.close(hit)?;

    // A different transport recipe with exactly the same resolved tree must
    // hit the existing result without uploading the flattened tree.
    let mut flattened = spec.clone();
    flattened.root.recipe = TreeRecipe::union(spec.root.recipe.directories, [spec.root.id]);
    let NativeAdmission::Hit {
        ticket: flattened_hit,
        manifest: cached,
    } = client.admit(&flattened, ActionMode::Reuse)?
    else {
        anyhow::bail!("equivalent flattened root missed the cache");
    };
    assert_eq!(cached, manifest);
    client.close(flattened_hit)?;
    let mut reordered = spec.clone();
    reordered.root.recipe.layers.reverse();
    let NativeAdmission::Hit {
        ticket: reordered_hit,
        manifest: cached,
    } = client.admit(&reordered, ActionMode::Reuse)?
    else {
        anyhow::bail!("equivalent reordered root missed the cache");
    };
    assert_eq!(cached, manifest);
    client.close(reordered_hit)?;

    // A forged root cannot obtain a publication permit even when all
    // transport trees are already available to the scheduler.
    let mut forged = spec.clone();
    forged.root.id = sccache::build_runtime::TreeId([0xA5; 32]);
    assert!(client.admit(&forged, ActionMode::Reuse).is_err());
    assert_eq!(fleet.status()?.in_progress, 0);

    let inputs = [root_tree, source_tree];
    let policy = NativeBuildPolicy {
        mode: ActionMode::Reuse,
        timeout: Duration::from_secs(30),
        renewal_interval: Duration::from_secs(1),
        max_result_bytes: 16 * 1024 * 1024,
    };
    let delivered = root.join("delivered.o");
    let destinations = BTreeMap::from([("object".into(), delivered.clone())]);
    let hit = client.run_action(&spec, &inputs, &destinations, &policy, None)?;
    assert_eq!(hit.source, NativeBuildSource::Hit);
    assert!(hit.output.status.success());
    assert_eq!(fs::read(&delivered)?, fs::read(&reference)?);

    let mut second = spec.clone();
    second.command.arguments.insert(0, b"--64".to_vec());
    fs::remove_file(&delivered)?;
    let miss = client.run_action(&second, &inputs, &destinations, &policy, None)?;
    assert_eq!(miss.source, NativeBuildSource::Worker(worker_address));
    assert!(miss.output.status.success());
    assert_eq!(fs::read(&delivered)?, fs::read(&reference)?);
    let hit = client.run_action(&second, &inputs, &destinations, &policy, None)?;
    assert_eq!(hit.source, NativeBuildSource::Hit);

    // The exact sandbox on the client host can publish and refresh the same
    // action as the remote worker; its successful result needs no download.
    let local = LocalExecutor::new(
        local_config(root, NativeExecutionPreference::Local),
        spec.platform,
    );
    let refresh = NativeBuildPolicy {
        mode: ActionMode::Refresh,
        ..policy
    };
    let result = client.run_action(&second, &inputs, &destinations, &refresh, Some(&local))?;
    assert_eq!(result.source, NativeBuildSource::Local);
    assert!(result.output.status.success());
    assert_eq!(fs::read(&delivered)?, fs::read(&reference)?);
    assert_eq!(
        client
            .run_action(&second, &inputs, &destinations, &policy, None)?
            .source,
        NativeBuildSource::Hit
    );
    drop(local);

    let mut local_only = second.clone();
    local_only.platform = ContentId::of(b"no compatible remote worker");
    let local = LocalExecutor::new(
        local_config(root, NativeExecutionPreference::RemoteFirst),
        local_only.platform,
    );
    let result = client.run_action(&local_only, &inputs, &destinations, &policy, Some(&local))?;
    assert_eq!(result.source, NativeBuildSource::Local);
    assert!(result.output.status.success());
    assert_eq!(fs::read(&delivered)?, fs::read(&reference)?);
    assert_eq!(
        client
            .run_action(&local_only, &inputs, &destinations, &policy, None)?
            .source,
        NativeBuildSource::Hit
    );
    assert_eq!(fleet.status()?.in_progress, 0);
    drop(local);
    let local_store = NativeStore::open(&root.join("local-input-store"))?;
    assert_eq!(local_store.stats()?.actions, 0);
    assert_eq!(local_store.stats()?.trees, 2);
    drop(local_store);

    // A real compiler failure must be reported but never become a hit.
    let mut invalid = spec;
    invalid
        .command
        .arguments
        .push(b"--invalid-native-test-flag".to_vec());
    let NativeAdmission::Compile { ticket } = client.admit(&invalid, ActionMode::Reuse)? else {
        anyhow::bail!("expected failed-action miss");
    };
    let ScheduleReply::Assigned(allocation) = client.schedule(ticket, invalid.clone())? else {
        anyhow::bail!("worker unavailable");
    };
    let NativeRunResult::Failed { code, stderr, .. } =
        NativeCacheClient::run_worker(&allocation, Duration::from_secs(30), 1024 * 1024)?
    else {
        anyhow::bail!("expected compiler failure");
    };
    assert_ne!(code, Some(0));
    assert!(!stderr.is_empty());
    assert_eq!(client.status(ticket)?, NativeStatus::Failed);
    client.close(ticket)?;
    let failed = client.run_action(&invalid, &inputs, &destinations, &policy, None)?;
    assert_eq!(failed.source, NativeBuildSource::Worker(worker_address));
    assert!(!failed.output.status.success());
    assert!(!failed.output.stderr.is_empty());
    let worker_directory = fleet.worker_directory.clone();
    let (scheduler_stats, worker_stats) = fleet.finish()?;
    let store = NativeStore::open(&worker_directory)?;
    let policy = sccache::build_runtime::PackagePolicy::normalized_archive(
        100000,
        1 << 32,
        5 << 30,
        1 << 26,
    )?;
    for receipt in packages {
        let reconstructed = store
            .lookup_package(receipt.source.identity, policy)?
            .context("worker did not reconstruct original archive")?;
        assert_eq!(reconstructed.tree().id(), receipt.tree);
        assert_eq!(reconstructed.source(), receipt.source);
        let missing = reconstructed
            .tree()
            .manifest()
            .blobs()?
            .into_iter()
            .map(|(id, size)| sccache::build_runtime::BlobRef { id, size })
            .collect::<Vec<_>>();
        assert!(
            store
                .plan_package_downloads(&missing, 8, u64::MAX)?
                .is_empty(),
            "worker retained redundant archive"
        );
    }
    assert_eq!(worker_stats.actions, 0);
    assert_eq!(scheduler_stats.actions, 3);
    assert_eq!(scheduler_stats.results, 1);
    assert_eq!(worker_stats.trees, 4);
    assert_eq!(scheduler_stats.trees, 4);
    Ok(())
}

/// A test-owned in-process service, not a separately launched managed
/// sccache daemon. It listens exclusively on a temporary Unix socket.
struct LocalService {
    socket: PathBuf,
    caller_config: PathBuf,
    cached_config: PathBuf,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

impl LocalService {
    fn start(
        root: &Path,
        fleet: &Fleet,
        local_execution: Option<NativeLocalConfig>,
    ) -> Result<Self> {
        let socket = root.join("client.sock");
        let caller_config = root.join("caller.toml");
        let cached_config = root.join("caller-cached.toml");
        fs::write(&caller_config, "client_side_mode = true\n")?;
        let mut config = Config::default();
        config.dist.scheduler_url = Some(HTTPUrl::from_url(fleet.scheduler_url.clone()));
        config.dist.auth = DistAuth::Token {
            token: CLIENT_TOKEN.into(),
        };
        config.dist.native = Some(NativeClientConfig {
            endpoint: HTTPUrl::from_url(fleet.cache_url.clone()),
            platform_contract: PLATFORM.into(),
            request_timeout_secs: 60,
            build_timeout_secs: 180,
            renewal_interval_secs: 1,
            max_metadata_bytes: 64 * 1024 * 1024,
            max_result_bytes: 64 * 1024 * 1024,
            local_execution,
        });
        config.fallback_cache.dir = root.join("unexpected-archive-cache");
        config.dist.cache_dir = root.join("unexpected-toolchain-cache");
        let address = sccache::server::SocketAddr::parse_uds(
            socket
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 socket path"))?,
        )?;
        let thread = thread::spawn(move || sccache::server::start_server(&config, &address));
        let mut service = Self {
            socket,
            caller_config,
            cached_config,
            thread: Some(thread),
        };
        wait_for(|| {
            if service
                .thread
                .as_ref()
                .is_some_and(thread::JoinHandle::is_finished)
            {
                service.join()?;
                anyhow::bail!("test sccache service exited during start");
            }
            Ok(std::os::unix::net::UnixStream::connect(&service.socket)
                .ok()
                .map(|_| ()))
        })?;
        Ok(service)
    }

    fn command(&self, executable: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(executable);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("SCCACHE_SERVER_UDS", &self.socket)
            .env("SCCACHE_CONF", &self.caller_config)
            .env("SCCACHE_CACHED_CONF", &self.cached_config)
            .env("SCCACHE_NO_AUTO_START_SERVER", "1")
            .env("SCCACHE_LOG", "sccache=debug");
        command
    }

    fn stats(&self) -> Result<sccache::server::ServerStats> {
        let output = self
            .command(env!("CARGO_BIN_EXE_sccache"))
            .args(["--show-stats", "--stats-format=json"])
            .output()?;
        ensure!(
            output.status.success(),
            "test stats request failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let info: sccache::server::ServerInfo = serde_json::from_slice(&output.stdout)?;
        Ok(info.stats)
    }

    fn join(&mut self) -> Result<()> {
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("test sccache service panicked"))??;
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        if self.thread.is_some() {
            let output = self
                .command(env!("CARGO_BIN_EXE_sccache"))
                .arg("--stop-server")
                .output()?;
            ensure!(
                output.status.success(),
                "test stop failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            self.join()?;
        }
        Ok(())
    }
}

impl Drop for LocalService {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn compiler_script() -> &'static str {
    r#"
set -eu
mkdir -p build
"$2" -c probe.c -o build/probe.o -MMD -MF build/probe-c.d
"$3" --crate-name probe --crate-type rlib --edition=2024 --emit=link,dep-info --out-dir build probe.rs
cp build/probe.o gcc-reference.o
cp build/libprobe.rlib rust-reference.rlib
for i in 1 2 ${4:+3 4}; do
    if [ "$i" = 3 ]; then export SCCACHE_RECACHE=1; else unset SCCACHE_RECACHE; fi
    rm -f build/probe.o build/libprobe.rlib build/probe.d build/probe-c.d
    "$1" "$2" -c probe.c -o build/probe.o -MMD -MF build/probe-c.d
    "$1" "$3" --crate-name probe --crate-type rlib --edition=2024 --emit=link,dep-info --out-dir build probe.rs
    cmp gcc-reference.o build/probe.o
    cmp rust-reference.rlib build/libprobe.rlib
    test -s build/probe-c.d
    test -s build/probe.d
done
"#
}

/// Exercise the real catalog command and configured namespace caller using
/// package-content metadata for the installed compiler executable. The
/// upstream installer projection has independent archive tests.
fn compiler_catalog_fixture(root: &Path, rustc: &Path) -> Result<PathBuf> {
    let sysroot = rustc
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow::anyhow!("missing compiler sysroot"))?;
    let directories = sccache::build_runtime::TreeMetadata {
        mode: 0o755,
        modified: sccache::build_runtime::TreeTimestamp {
            seconds: 0,
            nanoseconds: 0,
        },
    };
    let mut mapping = MappedTree::new(directories);
    mapping.add_file(
        TreePath::new(b"bin/rustc".to_vec())?,
        rustc.canonicalize()?,
        MappedMetadata::Normalize(directories.modified),
    )?;
    let prepared = mapping.prepare()?;
    let manifest = InstallationManifest {
        source: sccache::build_runtime::PackageSource {
            identity: sccache::build_runtime::PackageIdentity {
                sha256: [0; 32],
                compression: sccache::build_runtime::PackageCompression::Tar,
            },
            size: 0,
        },
        package: prepared.id(),
        components: BTreeMap::from([("test-compiler".into(), prepared.manifest().clone())]),
    };
    let path = root.join("fixture-package.manifest");
    manifest.write(File::create(&path)?)?;
    let catalog = root.join("fixture-installation.catalog");
    let output = Command::new(env!("CARGO_BIN_EXE_sccache-dist"))
        .args(["native-attest-installation", "--root"])
        .arg(sysroot)
        .arg("--manifest")
        .arg(path)
        .arg("--output")
        .arg(&catalog)
        .output()?;
    ensure!(
        output.status.success(),
        "catalog verification failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["verified_files"], 1);
    assert_eq!(report["differing_files"], 0);
    Ok(catalog)
}

fn namespace_compilers(
    service: &LocalService,
    private: &Path,
    visible: &Path,
    rustc: &Path,
    refresh: bool,
) -> Result<std::process::Output> {
    Ok(service
        .command("/usr/bin/bwrap")
        .args([
            "--unshare-net",
            "--bind",
            "/",
            "/",
            "--dev-bind",
            "/dev",
            "/dev",
            "--bind",
        ])
        .arg(private)
        .arg(visible)
        .arg("--chdir")
        .arg(visible)
        .args([
            "--",
            "/bin/sh",
            "-c",
            compiler_script(),
            "namespace-test",
            env!("CARGO_BIN_EXE_sccache"),
            "/usr/bin/gcc",
        ])
        .arg(rustc)
        .arg(if refresh { "refresh" } else { "" })
        .output()?)
}

fn write_compiler_sources(root: &Path) -> Result<()> {
    fs::create_dir(root)?;
    fs::write(
        root.join("probe.c"),
        b"int namespace_probe(void) { return 42; }\n",
    )?;
    fs::write(
        root.join("probe.rs"),
        b"pub fn namespace_probe() -> u32 { 42 }\n",
    )?;
    Ok(())
}

fn run_environment_audit(
    service: &LocalService,
    directory: &Path,
    rustc: &Path,
    config: &Path,
) -> Result<()> {
    fs::write(
        directory.join("audit.rs"),
        b"pub const OBSERVED: &str = env!(\"NATIVE_AUDIT_OBSERVED\");\n",
    )?;
    let compile = |unused: &str, observed: &str| -> Result<Vec<u8>> {
        let output = service
            .command(env!("CARGO_BIN_EXE_sccache"))
            .arg(rustc)
            .args([
                "--crate-name",
                "audit",
                "--crate-type",
                "rlib",
                "--edition=2024",
                "--emit=link,dep-info",
                "--out-dir",
                "build",
                "audit.rs",
            ])
            .current_dir(directory)
            .env("SCCACHE_CONF", config)
            .env("CARGO_NATIVE_AUDIT_UNUSED", unused)
            .env("NATIVE_AUDIT_OBSERVED", observed)
            .output()?;
        ensure!(
            output.status.success(),
            "environment audit compile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(fs::read(directory.join("build/libaudit.rlib"))?)
    };
    let first = compile("first", "first")?;
    assert_eq!(compile("second", "first")?, first);
    assert_ne!(compile("first", "second")?, first);
    Ok(())
}

fn audit_index(index: &Path, component: &str) -> Result<ComponentAudit> {
    let output = Command::new(env!("CARGO_BIN_EXE_sccache-dist"))
        .args(["native-audit", "--index"])
        .arg(index)
        .args(["--schema", "native-linux-bwrap-v4", "--without", component])
        .output()?;
    ensure!(
        output.status.success(),
        "native audit command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    Ok(serde_json::from_value(report["comparison"].clone())?)
}

#[test]
#[ignore = "requires Linux Bubblewrap, GCC, Rust toolchain and ldd"]
fn native_compiler_cli_direct_and_networkless_namespace() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let fleet = Fleet::start(&root, BTreeMap::new())?;
    let mut service = LocalService::start(&root, &fleet, None)?;
    let rustc = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()?;
    ensure!(rustc.status.success(), "could not discover test sysroot");
    let rustc = PathBuf::from(String::from_utf8(rustc.stdout)?.trim()).join("bin/rustc");
    let direct = root.join("direct");
    write_compiler_sources(&direct)?;
    let direct_config = root.join("direct.toml");
    fs::write(&direct_config, "client_side_mode = false\n")?;
    let start = Instant::now();
    let output = service
        .command("/bin/sh")
        .args([
            "-c",
            compiler_script(),
            "direct-test",
            env!("CARGO_BIN_EXE_sccache"),
            "/usr/bin/gcc",
        ])
        .arg(&rustc)
        .arg("refresh")
        .current_dir(&direct)
        .env("SCCACHE_CONF", &direct_config)
        .output()?;
    eprintln!(
        "direct compiler elapsed {:?}:\n{}",
        start.elapsed(),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        output.status.success(),
        "direct native compiler path failed"
    );
    let stats = service.stats()?;
    assert_eq!(stats.dist_compiles.values().sum::<usize>(), 4);
    assert_eq!(stats.forced_recaches, 2);
    assert_eq!(stats.cache_hits.all(), 4);
    assert_eq!(stats.cache_misses.all(), 4);
    assert_eq!(stats.dist_errors, 0);

    let visible = root.join("visible");
    let private = root.join("private");
    fs::create_dir(&visible)?;
    fs::write(visible.join("probe.c"), b"#error wrong daemon source\n")?;
    fs::write(
        visible.join("probe.rs"),
        b"compile_error!(\"wrong daemon source\");\n",
    )?;
    write_compiler_sources(&private)?;
    let start = Instant::now();
    let output = namespace_compilers(&service, &private, &visible, &rustc, true)?;
    eprintln!(
        "namespace compiler elapsed {:?}:\n{}",
        start.elapsed(),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        output.status.success(),
        "native namespace compiler path failed"
    );
    let stats = service.stats()?;
    assert_eq!(stats.dist_compiles.values().sum::<usize>(), 8);
    assert_eq!(stats.cache_hits.all(), 8);
    assert_eq!(stats.cache_misses.all(), 8);
    assert_eq!(stats.forced_recaches, 4);
    assert_eq!(stats.dist_errors, 0);
    assert!(private.join("build/probe.o").is_file());
    assert!(private.join("build/libprobe.rlib").is_file());
    assert!(!visible.join("build").exists());
    assert!(!root.join("unexpected-archive-cache").exists());
    assert!(!root.join("unexpected-toolchain-cache").exists());

    // Changing only whether the caller can reuse a verified digest must
    // preserve the exact action key, including in a fresh networkless CLI.
    let catalog = compiler_catalog_fixture(&root, &rustc)?;
    fs::write(
        &service.caller_config,
        format!(
            "client_side_mode = true\n[dist]\nnative_installation_catalogs = [{}]\n",
            serde_json::to_string(&catalog)?
        ),
    )?;
    let output = namespace_compilers(&service, &private, &visible, &rustc, false)?;
    let log = String::from_utf8_lossy(&output.stderr);
    ensure!(
        output.status.success(),
        "catalog-backed namespace compilation failed: {log}"
    );
    assert!(
        log.contains("verified installation memo: 1 files"),
        "catalog not used: {log}"
    );
    assert_eq!(
        fs::read(private.join("build/libprobe.rlib"))?,
        fs::read(private.join("rust-reference.rlib"))?
    );
    let stats = service.stats()?;
    assert_eq!(stats.cache_hits.all(), 12);
    assert_eq!(stats.dist_compiles.values().sum::<usize>(), 8);
    run_environment_audit(&service, &direct, &rustc, &direct_config)?;
    let stats = service.stats()?;
    assert_eq!(stats.dist_compiles.values().sum::<usize>(), 11);
    assert_eq!(stats.dist_errors, 0);
    let index = fleet.scheduler_directory.join("index.redb");
    service.stop()?;
    let (scheduler, worker) = fleet.finish()?;
    assert_eq!(scheduler.actions, 7);
    let unused = audit_index(&index, "environment/CARGO_NATIVE_AUDIT_UNUSED")?;
    assert_eq!(unused.equivalent_pairs, 1);
    assert_eq!(unused.conflicting_pairs, 0);
    let observed = audit_index(&index, "environment/NATIVE_AUDIT_OBSERVED")?;
    assert_eq!(observed.equivalent_pairs, 0);
    assert_eq!(observed.conflicting_pairs, 1);
    assert_eq!(unused.examined_actions, 7);
    eprintln!("actual Rust environment audit: {unused:?}; {observed:?}");
    assert_eq!(worker.actions, 0);
    Ok(())
}

#[test]
#[ignore = "requires Linux Bubblewrap, GCC, Rust toolchain and ldd"]
fn native_local_execution_in_networkless_namespace_shares_remote_actions() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let fleet = Fleet::start(&root, BTreeMap::new())?;
    let rustc = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()?;
    ensure!(rustc.status.success(), "could not discover test sysroot");
    let rustc = PathBuf::from(String::from_utf8(rustc.stdout)?.trim()).join("bin/rustc");
    let visible = root.join("visible");
    let private = root.join("private");
    fs::create_dir(&visible)?;
    fs::write(visible.join("probe.c"), b"#error wrong daemon source\n")?;
    fs::write(
        visible.join("probe.rs"),
        b"compile_error!(\"wrong daemon source\");\n",
    )?;
    write_compiler_sources(&private)?;
    let mut service = LocalService::start(
        &root,
        &fleet,
        Some(local_config(&root, NativeExecutionPreference::Local)),
    )?;
    let output = namespace_compilers(&service, &private, &visible, &rustc, true)?;
    ensure!(
        output.status.success(),
        "local namespace compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stats = service.stats()?;
    assert_eq!(stats.dist_compiles.values().sum::<usize>(), 0);
    assert_eq!(stats.cache_misses.all(), 4);
    assert_eq!(stats.cache_hits.all(), 4);
    assert_eq!(stats.forced_recaches, 2);
    assert_eq!(stats.dist_errors, 0);
    service.stop()?;
    drop(service);
    let store = NativeStore::open(&root.join("local-input-store"))?;
    assert_eq!(store.stats()?.actions, 0);
    assert!(store.stats()?.trees >= 2);
    drop(store);
    // Restart only the local daemon with remote execution policy. Both
    // ordinary hits and forced remote refreshes must reuse the same keys.
    let mut service = LocalService::start(&root, &fleet, None)?;
    let output = namespace_compilers(&service, &private, &visible, &rustc, true)?;
    ensure!(
        output.status.success(),
        "remote refresh after local publication failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stats = service.stats()?;
    assert_eq!(stats.dist_compiles.values().sum::<usize>(), 2);
    assert_eq!(stats.cache_misses.all(), 2);
    assert_eq!(stats.cache_hits.all(), 6);
    assert_eq!(stats.forced_recaches, 2);
    assert_eq!(stats.dist_errors, 0);
    assert!(!visible.join("build").exists());
    assert!(!root.join("unexpected-archive-cache").exists());
    service.stop()?;
    let (scheduler, worker) = fleet.finish()?;
    assert_eq!(scheduler.actions, 2);
    assert_eq!(worker.actions, 0);
    Ok(())
}
