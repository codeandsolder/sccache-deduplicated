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
        ActionMode, Artifact, BuildPath, CommandSpec, ContentId, ExecutionRoot, ExecutionSpec,
        InstallationManifest, MappedMetadata, MappedTree, NativeStore, OutputSpec, SpacePolicy,
        TreeLayer, TreePath, TreeRecipe,
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
        max_resident_bytes: u64::MAX,
        target_resident_bytes: u64::MAX,
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
            .env("SCCACHE_LOG", "info,native_placement_replay=trace")
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

fn fetch_status(http: &wreq::Client, scheduler: &url::Url) -> Result<SchedulerStatusResult> {
    sccache::http_client::io_runtime()?.block_on(async {
        Ok(http
            .get(scheduler.join("/api/v1/scheduler/status")?.as_str())
            .header("Accept", "application/json")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    })
}

fn native_worker_config(
    root: &Path,
    cluster: sccache_peer_identity::PeerConfig,
    worker_address: SocketAddr,
    scheduler_url: url::Url,
    cache_url: url::Url,
    platform: &str,
    transfer: sccache::build_runtime::PackageTransferCost,
) -> server::Config {
    server::Config {
        traces: None,
        cluster,
        builder: server::BuilderType::Native,
        cache_dir: None,
        public_addr: worker_address,
        bind_address: None,
        scheduler_url: HTTPUrl::from_url(scheduler_url),
        scheduler_auth: server::SchedulerAuth::Token {
            token: WORKER_TOKEN.into(),
        },
        toolchain_cache_size: 0,
        toolchain_archive_sources: Vec::new(),
        native_worker: Some(server::NativeWorkerConfig {
            cache_url: HTTPUrl::from_url(cache_url),
            directory: Some(root.join("worker-store")),
            space: Some(space()),
            scratch: root.join("scratch"),
            bubblewrap: "/usr/bin/bwrap".into(),
            platform_contract: platform.into(),
            renewal_interval_secs: 1,
            request_timeout_secs: 60,
            execution_timeout_secs: 120,
            max_result_bytes: 64 * 1024 * 1024,
            max_metadata_bytes: 64 * 1024 * 1024,
            artifact_grace_secs: 300,
            artifact_grace_bytes: None,
            max_inflight_jobs: None,
            package_import: Some(package_limits(false)),
            package_transfer: transfer,
        }),
    }
}

struct Fleet {
    worker: Option<Process>,
    scheduler: Process,
    worker_directory: PathBuf,
    scheduler_directory: PathBuf,
    worker_address: SocketAddr,
    worker_id: sccache_peer_identity::PeerId,
    cluster: sccache_peer_identity::PeerConfig,
    worker_cluster: sccache_peer_identity::PeerConfig,
    peer: std::sync::Arc<sccache_cluster_identity::PeerCredentials>,
    status_base: url::Url,
    cache_url: url::Url,
    scheduler_url: url::Url,
    http: wreq::Client,
}

impl Fleet {
    fn start(
        root: &Path,
        package_upstreams: BTreeMap<String, scheduler::PackageUpstream>,
    ) -> Result<Self> {
        Self::start_with_transfer(
            root,
            package_upstreams,
            sccache::build_runtime::PackageTransferCost {
                download_bytes_per_second: 1 << 20,
                archive_download_bytes_per_second: 1 << 20,
                decode_xz_bytes_per_second: 1 << 30,
                decode_zstd_bytes_per_second: 1 << 30,
                per_entry_nanoseconds: 0,
                startup_nanoseconds: 0,
                ..Default::default()
            },
        )
    }

    fn start_with_transfer(
        root: &Path,
        package_upstreams: BTreeMap<String, scheduler::PackageUpstream>,
        transfer: sccache::build_runtime::PackageTransferCost,
    ) -> Result<Self> {
        Self::start_with_mode(root, package_upstreams, transfer, false, None)
    }

    fn start_with_mode(
        root: &Path,
        package_upstreams: BTreeMap<String, scheduler::PackageUpstream>,
        transfer: sccache::build_runtime::PackageTransferCost,
        colocated: bool,
        trace_endpoint: Option<&str>,
    ) -> Result<Self> {
        let [scheduler_address, cache_address, worker_address] = addresses()?;
        let scheduler_url = url::Url::parse(&format!("https://{scheduler_address}/"))?;
        let cache_url = url::Url::parse(&format!("https://{cache_address}/"))?;
        let scheduler_directory = root.join("scheduler-store");
        let worker_directory = if colocated {
            scheduler_directory.clone()
        } else {
            root.join("worker-store")
        };
        let cluster_directory = root.join("cluster");
        fs::create_dir_all(&cluster_directory)?;
        drop(sccache_cluster_identity::scheduler_registry(
            &cluster_directory,
        )?);
        let ca = sccache_cluster_identity::ClusterCa::open(&cluster_directory.join("ca-key.pem"))?;
        let scheduler_id =
            sccache_cluster_identity::Identity::open(&cluster_directory.join("key.pem"))?.id()?;
        let ca_certificate = cluster_directory.join("ca.pem");
        sccache_cluster_identity::publish_trust_anchor(ca.certificate(), &ca_certificate)?;
        let cluster = sccache_peer_identity::PeerConfig {
            directory: root.join("client-identity"),
            ca_certificate,
            scheduler_id,
        };
        let worker_cluster = sccache_peer_identity::PeerConfig {
            directory: root.join("worker-identity"),
            ..cluster.clone()
        };
        let worker_id = sccache_cluster_identity::open_identity(&worker_cluster)?.id()?;
        let mut worker_config = native_worker_config(
            root,
            worker_cluster.clone(),
            worker_address,
            scheduler_url.clone(),
            cache_url.clone(),
            PLATFORM,
            transfer,
        );
        worker_config.traces =
            trace_endpoint.map(|endpoint| trace_config(root, endpoint, "worker"));
        let (local_worker, standalone_worker) = if colocated {
            let native = worker_config
                .native_worker
                .as_mut()
                .context("native config missing")?;
            native.directory = None;
            native.space = None;
            (Some(Box::new(worker_config)), None)
        } else {
            (None, Some(worker_config))
        };
        let mut scheduler_process = Process::start(
            root,
            "scheduler",
            &scheduler::Config {
                traces: trace_endpoint.map(|endpoint| trace_config(root, endpoint, "scheduler")),
                cluster_directory,
                local_worker,
                public_addr: scheduler_address,
                client_auth: scheduler::ClientAuth::Token {
                    token: CLIENT_TOKEN.into(),
                },
                server_auth: scheduler::ServerAuth::Token {
                    token: WORKER_TOKEN.into(),
                },
                maintenance_drain_file: None,
                dashboard: None,
                job_slack: scheduler::JobSlackConfig {
                    static_jobs: 0,
                    percent: 0.0,
                },
                native_cache: Some(scheduler::NativeCacheConfig {
                    public_addr: cache_address,
                    bind_address: Some(cache_address),
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
        let peer = wait_for(|| {
            scheduler_process.check()?;
            Ok(sccache::dist::cluster::open_peer(
                cluster.clone(),
                &scheduler_url,
                sccache_cluster_identity::Role::Client,
                || Ok(CLIENT_TOKEN.to_owned()),
            )
            .ok())
        })?;
        let transport = sccache_cluster_identity::ClusterHttpClient::new(
            peer.current()?.as_ref(),
            scheduler_id,
            sccache_cluster_identity::Role::Scheduler,
            scheduler_address,
        )?;
        let (http, status_base) = (transport.client(), transport.base().clone());
        let status = || fetch_status(&http, &status_base);
        let mut worker_process = standalone_worker
            .as_ref()
            .map(|config| Process::start(root, "server", config))
            .transpose()?;
        wait_for(|| {
            scheduler_process.check()?;
            if let Some(worker) = &mut worker_process {
                worker.check()?;
            }
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
            worker_id,
            cluster,
            worker_cluster,
            peer,
            status_base,
            cache_url,
            scheduler_url,
            http,
        })
    }

    fn start_peer(&self, root: &Path) -> Result<Process> {
        let address = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        let mut peer = Process::start(
            root,
            "server",
            &native_worker_config(
                root,
                sccache_peer_identity::PeerConfig {
                    directory: root.join("worker-identity"),
                    ..self.cluster.clone()
                },
                address,
                self.scheduler_url.clone(),
                self.cache_url.clone(),
                "native-integration-peer-only-platform",
                sccache::build_runtime::PackageTransferCost::default(),
            ),
        )?;
        wait_for(|| {
            peer.check()?;
            Ok(self.status().ok().filter(|status| status.num_servers == 2))
        })?;
        Ok(peer)
    }

    fn status(&self) -> Result<SchedulerStatusResult> {
        fetch_status(&self.http, &self.status_base)
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
        let scheduler_stats = NativeStore::open(&scheduler_directory)?.stats()?;
        let worker_stats = if worker_directory == scheduler_directory {
            scheduler_stats
        } else {
            NativeStore::open(&worker_directory)?.stats()?
        };
        Ok((scheduler_stats, worker_stats))
    }
}

/// This explicit root test is run only in the disposable hosted CI lane.
#[test]
#[ignore = "requires sudo and Linux host namespace capabilities on a disposable CI runner"]
fn shared_daemon_credential_isolation() -> Result<()> {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("contrib/codeandsolder/test-shared-daemon");
    let binary = env!("CARGO_BIN_EXE_sccache");
    let local = Command::new("sudo")
        .args(["-n", "bash"])
        .arg(&script)
        .arg(binary)
        .status()?;
    ensure!(
        local.success(),
        "shared local daemon regression failed: {local}"
    );

    let temporary = tempfile::tempdir()?;
    let fleet = Fleet::start(temporary.path(), BTreeMap::new())?;
    let config = sccache::config::DistConfig {
        cluster: Some(fleet.cluster.clone()),
        scheduler_url: Some(HTTPUrl::from_url(fleet.scheduler_url.clone())),
        auth: DistAuth::Token {
            token: CLIENT_TOKEN.into(),
        },
        native: Some(NativeClientConfig {
            endpoint: HTTPUrl::from_url(fleet.cache_url.clone()),
            platform_contract: PLATFORM.into(),
            request_timeout_secs: 60,
            build_timeout_secs: 180,
            renewal_interval_secs: 1,
            max_metadata_bytes: 64 * 1024 * 1024,
            max_result_bytes: 64 * 1024 * 1024,
            local_execution: None,
        }),
        ..Default::default()
    };
    let path = temporary.path().join("shared-distribution.json");
    fs::write(&path, serde_json::to_vec(&config)?)?;
    let distributed = Command::new("sudo")
        .args(["-n", "bash"])
        .arg(script)
        .arg(binary)
        .arg(path)
        .status()?;
    ensure!(
        distributed.success(),
        "shared native daemon regression failed: {distributed}"
    );
    let (scheduler, worker) = fleet.finish()?;
    ensure!(
        scheduler.actions > 0 && worker.actions > 0,
        "no remote native action persisted"
    );
    Ok(())
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

fn provisioning_config(root: &Path, fleet: &Fleet) -> Result<PathBuf> {
    let config = sccache::config::FileConfig {
        dist: sccache::config::DistConfig {
            cluster: Some(fleet.cluster.clone()),
            scheduler_url: Some(HTTPUrl::from_url(fleet.scheduler_url.clone())),
            auth: DistAuth::Token {
                token: CLIENT_TOKEN.into(),
            },
            native: Some(NativeClientConfig {
                endpoint: HTTPUrl::from_url(fleet.cache_url.clone()),
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
    origin: url::Url,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    peak: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
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
        use axum::{Router, body::Body, response::IntoResponse};
        use http::{Method, StatusCode, header};
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let origin = url::Url::parse(&format!("http://{}/", listener.local_addr()?))?;
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let archives = Arc::new(archives);
        let active = Arc::new(active);
        let admission = Arc::new(tokio::sync::Semaphore::new(2));
        let router = Router::new().fallback(move |request: axum::extract::Request| {
            let archives = Arc::clone(&archives);
            let count = Arc::clone(&count);
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            let admission = Arc::clone(&admission);
            async move {
                if request.method() != Method::GET
                    || request.headers().contains_key(header::AUTHORIZATION)
                {
                    return StatusCode::NOT_FOUND.into_response();
                }
                let Some(bytes) = archives.get(request.uri().path()).cloned() else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                let Ok(_permit) = admission.acquire().await else {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                };
                count.fetch_add(1, Ordering::Relaxed);
                let concurrent = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(concurrent, Ordering::SeqCst);
                // Allow independent acquisitions to overlap.
                tokio::time::sleep(Duration::from_millis(800)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                // An unknown-size stream intentionally omits Content-Length.
                let body = Body::from_stream(futures::stream::once(async move {
                    Ok::<_, std::convert::Infallible>(bytes::Bytes::from_owner(bytes))
                }));
                ([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response()
            }
        });
        let worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("fixture runtime");
            runtime.block_on(async {
                let listener =
                    tokio::net::TcpListener::from_std(listener).expect("fixture listener");
                axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        let _ = shutdown.await;
                    })
                    .await
                    .expect("fixture HTTP server");
            });
        });
        Ok(Self {
            origin,
            requests,
            peak,
            stop: Some(stop),
            thread: Some(worker),
        })
    }

    fn count(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Drop for OriginalUpstream {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
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
    // Installed files must be older than the source digest race window before
    // metadata-only attestation can safely remember them.
    std::thread::sleep(Duration::from_secs(3));
    let config = provisioning_config(root, &fleet)?;
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
        &fleet.cache_url,
        std::sync::Arc::clone(&fleet.peer),
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
    let worker_id = fleet.worker_id;
    let worker = NativeCacheClient::new(
        &fleet.cache_url,
        sccache::dist::cluster::open_peer(
            fleet.worker_cluster.clone(),
            &fleet.scheduler_url,
            sccache_cluster_identity::Role::Worker,
            move || Ok(format!("{worker_id} {WORKER_TOKEN}")),
        )?,
        Duration::from_secs(5),
        1024 * 1024,
    )?
    .for_worker(sccache::dist::JobId(123));
    assert!(worker.lookup_rust_package(source.identity).is_err());
    let config_path = provisioning_config(root, &fleet)?;
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
        &fleet.cache_url,
        std::sync::Arc::clone(&fleet.peer),
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
    let config = provisioning_config(root, &fleet)?;
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

#[test]
#[ignore = "requires pacman with a cached, installed GCC release, plus isolated scheduler and worker"]
fn pacman_discovery_seeds_real_gcc_and_compiles_with_exact_results() -> Result<()> {
    use sccache::build_runtime::{PackageCompression, PackageIdentity};
    if !Path::new("/usr/bin/pacman").is_file() || !Path::new("/usr/bin/gcc").is_file() {
        eprintln!("SKIP: native pacman GCC integration requires pacman and GCC");
        return Ok(());
    }
    let installed = Command::new("/usr/bin/pacman")
        .args(["-Q", "gcc"])
        .output()?;
    ensure!(
        installed.status.success(),
        "test host must provide installed GCC"
    );
    let metadata = Command::new("/usr/bin/pacman")
        .args(["-Sp", "--print-format", "%n|%v|%a|%h|%r|%l", "gcc"])
        .output()?;
    ensure!(
        metadata.status.success(),
        "test requires synchronized GCC release metadata"
    );
    let release = String::from_utf8(metadata.stdout)?;
    let (_, fields) = release
        .split_once('|')
        .context("pacman GCC record missing")?;
    let values: Vec<_> = fields.trim().split('|').collect();
    ensure!(values.len() == 5, "unexpected GCC release record");
    let installed_version = String::from_utf8(installed.stdout)?
        .trim()
        .split_once(' ')
        .context("installed GCC version missing")?
        .1
        .to_owned();
    ensure!(
        values[0] == installed_version,
        "installed GCC differs from sync repository"
    );
    let identity = PackageIdentity::from_sha256_hex(values[2], PackageCompression::Zstd)?;
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let fleet = Fleet::start_with_transfer(
        root,
        BTreeMap::new(),
        sccache::build_runtime::PackageTransferCost::default(),
    )?;
    let worker_store = fleet.worker_directory.clone();
    let config = provisioning_config(root, &fleet)?;
    let discover = || {
        Command::new(env!("CARGO_BIN_EXE_sccache-dist"))
            .args(["native-sync-system", "--client-config"])
            .arg(&config)
            .args([
                "--path",
                "/usr/bin/gcc",
                "--cache-dir",
                "/var/cache/pacman/pkg",
            ])
            .output()
    };
    let first = discover()?;
    ensure!(
        first.status.success(),
        "system sync failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&first.stdout)?;
    assert_eq!(report["provisioned"][0]["name"], "gcc");
    assert_eq!(report["provisioned"][0]["reused"], false);
    assert_eq!(report["provisioned"][0]["transfer"], "local-original");
    let second = discover()?;
    ensure!(
        second.status.success(),
        "warm system sync failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let warm: serde_json::Value = serde_json::from_slice(&second.stdout)?;
    assert_eq!(warm["provisioned"][0]["reused"], true);
    assert_eq!(warm["provisioned"][0]["transfer"], "existing");
    let client = NativeCacheClient::new(
        &fleet.cache_url,
        std::sync::Arc::clone(&fleet.peer),
        Duration::from_secs(60),
        1024 * 1024,
    )?;
    let receipt = client
        .lookup_package(identity)?
        .context("original GCC missing from scheduler")?;
    assert_eq!(receipt.source.identity, identity);

    let mut service = LocalService::start(root, &fleet, None)?;
    let directory = root.join("source");
    fs::create_dir(&directory)?;
    fs::write(
        directory.join("probe.c"),
        b"int native_pacman_probe(int value) { return value * 7 + 2; }\n",
    )?;
    let reference = Command::new("/usr/bin/gcc")
        .args(["-c", "probe.c", "-O2", "-o", "reference.o"])
        .current_dir(&directory)
        .output()?;
    ensure!(reference.status.success(), "local GCC compilation failed");
    let result = service
        .command(env!("CARGO_BIN_EXE_sccache"))
        .arg("/usr/bin/gcc")
        .args(["-c", "probe.c", "-O2", "-o", "native.o"])
        .current_dir(&directory)
        .output()?;
    ensure!(
        result.status.success(),
        "native GCC compilation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(directory.join("native.o"))?,
        fs::read(directory.join("reference.o"))?
    );
    assert_eq!(service.stats()?.dist_compiles.values().sum::<usize>(), 1);
    service.stop()?;
    let (scheduler, worker) = fleet.finish()?;
    assert_eq!(scheduler.actions, 1);
    assert_eq!(worker.actions, 1);
    let store = NativeStore::open(&worker_store)?;
    let policy = sccache::build_runtime::PackagePolicy::normalized_archive(
        100_000,
        4 << 30,
        5 << 30,
        64 << 20,
    )?;
    assert!(
        store.lookup_package(identity, policy)?.is_none(),
        "fast worker link should favor requested raw GCC content over full-package expansion"
    );
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

fn verify_learned_placement_trace(log: &Path, expected_archive_bytes: u64) -> Result<()> {
    let contents = fs::read_to_string(log)?;
    let mut assignments = BTreeMap::new();
    let mut completed = Vec::new();
    let mut delivered = BTreeMap::new();
    for line in contents
        .lines()
        .filter(|line| line.contains("native_placement_replay"))
    {
        let Some(start) = line.find('{') else {
            continue;
        };
        let value: serde_json::Value = serde_json::from_str(&line[start..])?;
        let job = value["job"].as_u64().context("missing trace job ID")?;
        match value["kind"].as_str() {
            Some("assigned") => {
                assert!(assignments.insert(job, value).is_none());
            }
            Some("completed") => completed.push(value),
            Some("delivered") => {
                assert!(delivered.insert(job, value).is_none());
            }
            _ => (),
        }
    }
    assert_eq!(completed.len(), 9);
    let cold = completed.first().context("missing cold completion")?;
    assert!(cold["warm_staging_nanoseconds"].is_null());
    let id = cold["job"].as_u64().context("missing cold job")?;
    let worker = cold["worker"].as_str().context("missing worker address")?;
    let forecast = &assignments.get(&id).context("missing cold allocation")?["candidates"][worker];
    assert_eq!(forecast["archive_bytes"], expected_archive_bytes);
    assert!(
        forecast["input_wire_bytes"]
            .as_u64()
            .context("missing wire forecast")?
            < forecast["missing_input_union_bytes"]
                .as_u64()
                .context("missing logical forecast")?
    );
    let class = completed.get(1).context("no repeated file-output action")?["class"].clone();
    let repeated = completed
        .iter()
        .filter(|value| value["class"] == class)
        .collect::<Vec<_>>();
    assert_eq!(repeated.len(), 5);
    let mut estimate = None;
    let mut peak_result = 0_u64;
    let mut staging_observed = None;
    let mut previous_timing = cold["worker_timing"].clone();
    for value in completed.iter().skip(1) {
        let previous = std::mem::replace(&mut previous_timing, value["worker_timing"].clone());
        let previous_stage = staging_observed;
        if let Some(stage) = value["warm_staging_nanoseconds"].as_u64() {
            staging_observed = Some(previous_stage.map_or(stage, |old: u64| {
                if stage >= old {
                    old + (stage - old).div_ceil(4)
                } else {
                    old - (old - stage).div_ceil(4)
                }
            }));
        }
        if value["class"] != class {
            continue;
        }
        let observed = value["execution_nanoseconds"]
            .as_u64()
            .context("missing real execution time")?;
        let job = value["job"].as_u64().context("missing completion job ID")?;
        let assignment = assignments.get(&job).context("missing allocation trace")?;
        assert_eq!(assignment["worker"], value["worker"]);
        assert_eq!(assignment["class"], value["class"]);
        let worker = value["worker"].as_str().context("missing worker address")?;
        assert_eq!(
            assignment["candidates"][worker]["missing_input_union_bytes"], 0,
            "warm closure must be recognized before the next heartbeat"
        );
        assert_eq!(assignment["candidates"][worker]["input_wire_bytes"], 0);
        assert_eq!(assignment["candidates"][worker]["archive_bytes"], 0);
        let stage = value["warm_staging_nanoseconds"]
            .as_u64()
            .context("warm staging sample missing")?;
        assert!(stage > 0);
        let forecast_phase = &assignment["candidates"][worker]["cost"]["phase"];
        // The exact current worker-wide prior comes from the preceding
        // authenticated commit, not the periodic heartbeat.
        assert_eq!(
            assignment["host_prior"]["execution_nanoseconds"],
            previous["execution_nanoseconds"]
        );
        assert_eq!(
            assignment["host_prior"]["output_bytes"],
            previous["result"]["expected_bytes"]
        );
        let revision = value["worker_timing"]["revision"]
            .as_u64()
            .context("missing timing revision")?;
        assert!(
            revision
                > previous["revision"]
                    .as_u64()
                    .context("missing previous timing revision")?
        );
        if let Some(previous) = previous_stage {
            assert_eq!(forecast_phase["staging_nanoseconds"], previous);
        }
        assert!(
            value["publication_setup_nanoseconds"]
                .as_u64()
                .is_some_and(|ns| ns > 0)
        );
        if estimate.is_some() {
            assert!(
                forecast_phase["publication_nanoseconds"]
                    .as_u64()
                    .is_some_and(|ns| ns > 0)
            );
        }
        assert!(
            value["actual_publication_seconds"]
                .as_f64()
                .is_some_and(|seconds| seconds > 0.0)
        );
        assert!(observed > 0);
        let predicted = value["predicted_cost"]["execution_nanoseconds"]
            .as_u64()
            .context("missing action forecast")?;
        let previous: Option<(u64, usize)> = estimate;
        if let Some((learned, count)) = previous {
            assert_eq!(
                assignment["estimated_result_bytes"],
                peak_result + peak_result.div_ceil(4) + 65_536,
                "result retention forecast must reflect full output, even with zero negotiated upload"
            );
            if count >= 4 {
                assert_eq!(
                    predicted, learned,
                    "the learned command cost should replace the host prior"
                );
            }
            let smoothed = if observed >= learned {
                learned + (observed - learned).div_ceil(4)
            } else {
                learned - (learned - observed).div_ceil(4)
            };
            estimate = Some((smoothed, count + 1));
        } else {
            estimate = Some((observed, 1));
        }
        peak_result = peak_result.max(
            value["result_bytes"]
                .as_u64()
                .context("missing verified result size")?,
        );
    }
    assert!(
        !delivered.is_empty(),
        "automatic remote restoration must report delivery"
    );
    for (&job, receipt) in &delivered {
        let publication = completed
            .iter()
            .find(|value| value["job"].as_u64() == Some(job))
            .context("delivery without commit")?;
        assert_eq!(receipt["worker"], publication["worker"]);
        let bytes = receipt["direct_bytes"]
            .as_u64()
            .context("missing direct bytes")?
            .checked_add(
                receipt["scheduler_bytes"]
                    .as_u64()
                    .context("missing scheduler bytes")?,
            )
            .context("delivery overflow")?;
        let selected = receipt["selected_bytes"]
            .as_u64()
            .context("missing selected bytes")?;
        assert!(bytes <= selected);
        assert!(
            selected
                <= publication["result_bytes"]
                    .as_u64()
                    .context("missing result bytes")?
        );
        assert!(
            receipt["actual_client_completion_seconds"]
                .as_f64()
                .is_some_and(|seconds| seconds > 0.0)
        );
    }
    // Expose actual canary records in --nocapture logs for the report tool.
    for value in assignments
        .values()
        .chain(completed.iter())
        .chain(delivered.values())
    {
        println!("{value}");
    }
    Ok(())
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
        &cache_url,
        std::sync::Arc::clone(&fleet.peer),
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
        compiler_result: None,
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
            umask: 0o022,
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
                kind: sccache_build::OutputKind::File,
            },
        )]),
    };
    assert_eq!(
        client.admit(
            None,
            &spec,
            ActionMode::Reuse,
            &std::collections::BTreeMap::new()
        )?,
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
    let NativeAdmission::Compile { ticket } = client.admit(
        None,
        &spec,
        ActionMode::Reuse,
        &std::collections::BTreeMap::new(),
    )?
    else {
        anyhow::bail!("expected native miss");
    };
    client.close(root_pin)?;
    client.close(source_pin)?;
    let ScheduleReply::Assigned(allocation) = client.schedule(ticket, spec.clone())? else {
        anyhow::bail!("worker not allocated");
    };
    assert_eq!(allocation.routes.primary, worker_address);
    assert_eq!(
        client.schedule(ticket, spec.clone())?,
        ScheduleReply::Assigned(allocation.clone())
    );
    assert_eq!(
        client.run_worker(&allocation, Duration::from_secs(30), 1024 * 1024)?,
        NativeRunResult::Stored
    );
    let NativeStatus::Ready(manifest) = client.status(ticket)? else {
        anyhow::bail!("result not published");
    };
    let mut bytes = Vec::new();
    let Artifact::File { blob, .. } = &manifest.outputs["object"] else {
        anyhow::bail!("expected file output");
    };
    client.download(ticket, *blob, &mut bytes)?;
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
    } = client.admit(
        None,
        &spec,
        ActionMode::Reuse,
        &std::collections::BTreeMap::new(),
    )?
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
    } = client.admit(
        None,
        &flattened,
        ActionMode::Reuse,
        &std::collections::BTreeMap::new(),
    )?
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
    } = client.admit(
        None,
        &reordered,
        ActionMode::Reuse,
        &std::collections::BTreeMap::new(),
    )?
    else {
        anyhow::bail!("equivalent reordered root missed the cache");
    };
    assert_eq!(cached, manifest);
    client.close(reordered_hit)?;

    // A forged root cannot obtain a publication permit even when all
    // transport trees are already available to the scheduler.
    let mut forged = spec.clone();
    forged.root.id = sccache::build_runtime::TreeId([0xA5; 32]);
    assert!(
        client
            .admit(
                None,
                &forged,
                ActionMode::Reuse,
                &std::collections::BTreeMap::new()
            )
            .is_err()
    );
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
    assert_eq!(miss.source, NativeBuildSource::Worker(fleet.worker_id));
    assert!(miss.output.status.success());
    assert_eq!(fs::read(&delivered)?, fs::read(&reference)?);
    let hit = client.run_action(&second, &inputs, &destinations, &policy, None)?;
    assert_eq!(hit.source, NativeBuildSource::Hit);

    // Output selection is a delivery policy, not an execution/cache identity.
    // The assembler produces a separate listing file in addition to its
    // object. An immutable input cannot be declared as a writable file
    // output, so exercise selection using two actual generated outputs.
    let mut selective = spec.clone();
    selective
        .command
        .arguments
        .insert(0, b"-al=listing.txt".to_vec());
    selective.outputs.insert(
        "intermediate".into(),
        OutputSpec {
            path: BuildPath::new(b"/src/listing.txt".to_vec())?,
            required: true,
            kind: sccache_build::OutputKind::File,
        },
    );
    let intermediate = root.join("delivered-listing.txt");
    let first = client
        .run_action(&selective, &inputs, &destinations, &policy, None)
        .context("selective assembler listing compilation")?;
    assert_eq!(first.source, NativeBuildSource::Worker(fleet.worker_id));
    assert!(first.output.status.success());
    assert!(!intermediate.exists());
    let mut all = destinations.clone();
    all.insert("intermediate".into(), intermediate.clone());
    let second_result = client.run_action(&selective, &inputs, &all, &policy, None)?;
    assert_eq!(second_result.source, NativeBuildSource::Hit);
    assert!(second_result.output.status.success());
    assert!(fs::read_to_string(&intermediate)?.contains("repeated original assembly content"));

    // Repeated real executions of the same command family exercise the
    // scheduler's learned service time rather than its worker-wide prior.
    let remote_refresh = NativeBuildPolicy {
        mode: ActionMode::Refresh,
        ..policy
    };
    for _ in 0..4 {
        let result = client.run_action(&second, &inputs, &destinations, &remote_refresh, None)?;
        assert_eq!(result.source, NativeBuildSource::Worker(fleet.worker_id));
        assert!(result.output.status.success());
        assert_eq!(fs::read(&delivered)?, fs::read(&reference)?);
    }

    // The same worker can declare a complete directory result, including
    // live input files at the original logical output root. The scheduler
    // retains leaf content; both miss and hit materialize a private tree.
    let mut directory = spec.clone();
    directory.outputs = BTreeMap::from([(
        "codegen".into(),
        OutputSpec {
            path: BuildPath::new(b"/src".to_vec())?,
            required: true,
            kind: sccache_build::OutputKind::Tree,
        },
    )]);
    let generated = root.join("generated-codegen");
    let tree_destinations = BTreeMap::from([("codegen".into(), generated.clone())]);
    let result = client.run_action(&directory, &inputs, &tree_destinations, &policy, None)?;
    assert_eq!(result.source, NativeBuildSource::Worker(fleet.worker_id));
    assert!(result.output.status.success());
    assert_eq!(fs::read(generated.join("object.o"))?, fs::read(&reference)?);
    let source_bytes = fs::read(generated.join("input.s"))?;
    assert!(
        client
            .run_action(&directory, &inputs, &tree_destinations, &policy, None)
            .is_err()
    );
    fs::remove_dir_all(&generated)?;
    let result = client.run_action(&directory, &inputs, &tree_destinations, &policy, None)?;
    assert_eq!(result.source, NativeBuildSource::Hit);
    assert_eq!(fs::read(generated.join("object.o"))?, fs::read(&reference)?);
    assert_eq!(fs::read(generated.join("input.s"))?, source_bytes);

    directory.outputs.get_mut("codegen").context("output")?.kind =
        sccache_build::OutputKind::GeneratedTree;
    fs::remove_dir_all(&generated)?;
    let result = client.run_action(&directory, &inputs, &tree_destinations, &policy, None)?;
    assert_eq!(result.source, NativeBuildSource::Worker(fleet.worker_id));
    assert_eq!(fs::read(generated.join("object.o"))?, fs::read(&reference)?);
    assert!(!generated.join("input.s").exists());
    fs::remove_dir_all(&generated)?;
    let result = client.run_action(&directory, &inputs, &tree_destinations, &policy, None)?;
    assert_eq!(result.source, NativeBuildSource::Hit);
    assert_eq!(fs::read(generated.join("object.o"))?, fs::read(&reference)?);
    assert_eq!(fs::read_dir(&generated)?.count(), 1);

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
    let NativeAdmission::Compile { ticket } = client.admit(
        None,
        &invalid,
        ActionMode::Reuse,
        &std::collections::BTreeMap::new(),
    )?
    else {
        anyhow::bail!("expected failed-action miss");
    };
    let ScheduleReply::Assigned(allocation) = client.schedule(ticket, invalid.clone())? else {
        anyhow::bail!("worker unavailable");
    };
    let NativeRunResult::Failed { code, stderr, .. } =
        client.run_worker(&allocation, Duration::from_secs(30), 1024 * 1024)?
    else {
        anyhow::bail!("expected compiler failure");
    };
    assert_ne!(code, Some(0));
    assert!(!stderr.is_empty());
    assert_eq!(client.status(ticket)?, NativeStatus::Failed);
    client.close(ticket)?;
    let failed = client.run_action(&invalid, &inputs, &destinations, &policy, None)?;
    assert_eq!(failed.source, NativeBuildSource::Worker(fleet.worker_id));
    assert!(!failed.output.status.success());
    assert!(!failed.output.stderr.is_empty());
    let worker_directory = fleet.worker_directory.clone();
    let scheduler_log = fleet.scheduler.log.clone();
    let (scheduler_stats, worker_stats) = fleet.finish()?;
    verify_learned_placement_trace(
        &scheduler_log,
        packages.iter().map(|package| package.source.size).sum(),
    )?;
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
                .plan_package_downloads(
                    &missing,
                    8,
                    u64::MAX,
                    sccache::build_runtime::PackageTransferCost::default()
                )?
                .is_empty(),
            "worker retained redundant archive"
        );
    }
    // The selected-output compilation is a distinct action with a
    // complete result containing both the object and generated listing.
    assert_eq!(worker_stats.actions, 5);
    assert_eq!(scheduler_stats.actions, 6);
    assert_eq!(scheduler_stats.results, 4);
    assert!(worker_stats.trees >= 4);
    assert_eq!(scheduler_stats.trees, 4);
    Ok(())
}

#[test]
#[ignore = "requires Linux Bubblewrap, GNU assembler and isolated scheduler/worker processes"]
fn native_worker_only_inputs_survive_scheduler_eviction_and_restart() -> Result<()> {
    run_worker_only_inputs(false)
}

#[test]
#[ignore = "requires Linux Bubblewrap, GNU assembler and isolated scheduler/worker processes"]
fn native_peer_only_input_is_delivered_without_scheduler_or_origin_upload() -> Result<()> {
    run_worker_only_inputs(true)
}

fn run_worker_only_inputs(peer_source: bool) -> Result<()> {
    use sccache::build_runtime::BlobRef;

    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let source_dir = root.join("source");
    fs::create_dir(&source_dir)?;
    let assembly = b".text\n.globl entry\nentry:\n.include \"input.inc\"\n";
    let include = b".byte 1, 2, 3, 4\n";
    let input = source_dir.join("input.s");
    let include_path = source_dir.join("input.inc");
    fs::write(&input, assembly)?;
    fs::write(&include_path, include)?;

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

    let present = BlobRef {
        id: ContentId::of(include),
        size: u64::try_from(include.len())?,
    };
    let missing = BlobRef {
        id: ContentId::of(assembly),
        size: u64::try_from(assembly.len())?,
    };
    let mut worker_only = root_tree.manifest().blobs()?;
    worker_only.insert(present.id, present.size);
    {
        let store = NativeStore::open(&root.join("worker-store"))?;
        root_tree.import(&store)?;
        let retention = NativeStore::blob_retention_manifest(present)?;
        store.publish_tree(
            &retention,
            vec![store.stage_expected(present, &include[..])?],
        )?;
        assert!(store.lookup_tree(source_tree.id())?.is_none());
    }
    let peer_root = root.join("peer");
    if peer_source {
        fs::create_dir(&peer_root)?;
        let store = NativeStore::open(&peer_root.join("worker-store"))?;
        let retention = NativeStore::blob_retention_manifest(missing)?;
        store.publish_tree(
            &retention,
            vec![store.stage_expected(missing, &assembly[..])?],
        )?;
        // The only accessible copy is on the non-compiling peer. Any attempt
        // to request this input from the original provider must fail.
        fs::remove_file(&input)?;
    }
    let mut spec = ExecutionSpec {
        compiler_result: None,
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
            umask: 0o022,
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
                kind: sccache_build::OutputKind::File,
            },
        )]),
    };
    let inputs = [root_tree, source_tree];
    let policy = NativeBuildPolicy {
        mode: ActionMode::Reuse,
        timeout: Duration::from_secs(60),
        renewal_interval: Duration::from_secs(1),
        max_result_bytes: 16 * 1024 * 1024,
    };
    let delivered = root.join("delivered.o");
    let destinations = BTreeMap::from([("object".into(), delivered.clone())]);

    let mut action_keys = Vec::new();
    let object = BlobRef {
        id: ContentId::of(&fs::read(&reference)?),
        size: fs::metadata(&reference)?.len(),
    };
    for pass in 0..3 {
        if pass == 1 {
            spec.command.arguments.insert(0, b"--64".to_vec());
        }
        if pass > 0 {
            fs::remove_file(&delivered)?;
        }
        let action = spec.action_request()?.action_fingerprint()?.key()?;
        if pass < 2 {
            action_keys.push(action);
        }
        let fleet = Fleet::start(root, BTreeMap::new())?;
        let peer = if pass == 0 && peer_source {
            Some(fleet.start_peer(&peer_root)?)
        } else {
            None
        };
        let client = NativeCacheClient::new(
            &fleet.cache_url,
            std::sync::Arc::clone(&fleet.peer),
            Duration::from_secs(10),
            1024 * 1024,
        )?;
        let result = client.run_action(&spec, &inputs, &destinations, &policy, None)?;
        assert_eq!(
            result.source,
            if pass == 2 {
                NativeBuildSource::Hit
            } else {
                NativeBuildSource::Worker(fleet.worker_id)
            },
        );
        assert!(result.output.status.success());
        assert_eq!(fs::read(&delivered)?, fs::read(&reference)?);
        drop(peer);
        fleet.finish()?;
        let scheduler = NativeStore::open(&root.join("scheduler-store"))?;
        for (&id, &size) in &worker_only {
            assert!(
                scheduler
                    .open_available_blob(BlobRef { id, size })?
                    .is_none(),
                "worker-resident input was unnecessarily uploaded"
            );
        }
        if pass == 0 && !peer_source {
            assert!(scheduler.open_available_blob(missing)?.is_some());
            let retention = NativeStore::blob_retention_manifest(missing)?.id()?;
            assert!(matches!(
                scheduler.evict_tree(retention)?,
                sccache::build_runtime::Eviction::Removed { .. }
            ));
            scheduler.collect_garbage(128)?;
        }
        assert!(
            scheduler.open_available_blob(missing)?.is_none(),
            "direct peer input must not populate scheduler solely for relay"
        );
        let worker = NativeStore::open(&root.join("worker-store"))?;
        assert!(worker.lookup_tree(inputs[1].id())?.is_some());
        assert!(worker.open_available_blob(object)?.is_some());
        if pass == 1 {
            // Both distinct actions share their output, so evict both to
            // force physical reclamation rather than a scheduler-local hit.
            for &key in &action_keys {
                assert!(matches!(
                    scheduler.evict(key)?,
                    sccache::build_runtime::Eviction::Removed { .. }
                ));
                assert!(scheduler.result_receipt(key)?.is_some());
            }
            scheduler.collect_garbage(128)?;
            assert!(scheduler.open_available_blob(object)?.is_none());
            // A recovered result must work even without the original source.
            if !peer_source {
                fs::remove_file(&input)?;
            }
        }
        if pass == 2 {
            assert!(scheduler.lookup(action)?.is_some());
            assert!(scheduler.open_available_blob(object)?.is_some());
            assert_eq!(worker.stats()?.actions, 2);
        }
    }
    Ok(())
}

/// A test-owned in-process service, not a separately launched managed
/// sccache daemon. It listens exclusively on a temporary Unix socket.
fn trace_config(
    root: &Path,
    endpoint: &str,
    instance: &str,
) -> sccache::latency_trace::TraceConfig {
    sccache::latency_trace::TraceConfig {
        endpoint: endpoint.into(),
        instance: instance.into(),
        spool_directory: root.join(format!("trace-spool-{instance}")),
        max_spool_bytes: 8 * 1024 * 1024,
    }
}

struct TraceCollector {
    endpoint: String,
    receiver: std::sync::mpsc::Receiver<opentelemetry_proto::tonic::trace::v1::Span>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TraceCollector {
    fn start() -> Result<Self> {
        use axum::{Router, body::Bytes, routing::post};
        use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
        use prost::Message as _;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let endpoint = format!("http://{}/v1/traces", listener.local_addr()?);
        let (sender, receiver) = std::sync::mpsc::channel();
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let router = Router::new().route(
            "/v1/traces",
            post(move |body: Bytes| {
                let sender = sender.clone();
                async move {
                    let Ok(request) = ExportTraceServiceRequest::decode(body) else {
                        return http::StatusCode::BAD_REQUEST;
                    };
                    for resource in request.resource_spans {
                        let revision = resource.resource.as_ref().and_then(|resource| {
                            resource.attributes.iter().find(|attr| attr.key == "service.version")
                        }).and_then(|attr| attr.value.as_ref()).and_then(|value| {
                            match &value.value {
                                Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(value)) => Some(value.as_str()),
                                _ => None,
                            }
                        });
                        if revision != Some(sccache::BUILD_REVISION) {
                            return http::StatusCode::BAD_REQUEST;
                        }
                        for span in resource.scope_spans.into_iter().flat_map(|scope| scope.spans) {
                        if sender.send(span).is_err() {
                            return http::StatusCode::SERVICE_UNAVAILABLE;
                        }
                        }
                    }
                    http::StatusCode::OK
                }
            }),
        );
        let worker = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("trace runtime")
                .block_on(async {
                    let listener =
                        tokio::net::TcpListener::from_std(listener).expect("trace listener");
                    axum::serve(listener, router)
                        .with_graceful_shutdown(async {
                            let _ = shutdown.await;
                        })
                        .await
                        .expect("trace HTTP server");
                });
        });
        Ok(Self {
            endpoint,
            receiver,
            stop: Some(stop),
            thread: Some(worker),
        })
    }

    fn collect(
        &self,
        ready: impl Fn(&[opentelemetry_proto::tonic::trace::v1::Span]) -> bool,
    ) -> Result<Vec<opentelemetry_proto::tonic::trace::v1::Span>> {
        let start = Instant::now();
        let mut spans = Vec::new();
        while !ready(&spans) {
            spans.push(
                self.receiver
                    .recv_timeout(Duration::from_secs(20).saturating_sub(start.elapsed()))
                    .with_context(|| {
                        format!(
                            "trace collection timed out: {:?}",
                            spans.iter().map(|span| &span.name).collect::<Vec<_>>()
                        )
                    })?,
            );
        }
        Ok(spans)
    }
}

impl Drop for TraceCollector {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.thread.take() {
            let _ = worker.join();
        }
    }
}

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
        Self::start_configured(root, fleet, local_execution, None)
    }

    fn start_configured(
        root: &Path,
        fleet: &Fleet,
        local_execution: Option<NativeLocalConfig>,
        traces: Option<sccache::latency_trace::TraceConfig>,
    ) -> Result<Self> {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Warn)
            .filter_module("sccache::compiler::native", log::LevelFilter::Debug)
            .try_init();
        let socket = root.join("client.sock");
        let caller_config = root.join("caller.toml");
        let cached_config = root.join("caller-cached.toml");
        fs::write(&caller_config, "client_side_mode = true\n")?;
        let mut config = Config {
            traces,
            ..Default::default()
        };
        config.dist.cluster = Some(fleet.cluster.clone());
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
        // Keep the explicitly isolated test environment, but let an
        // instrumented client (including one launched through bwrap) write
        // coverage into this test's profile bundle.
        if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", profile);
        }
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
        eprintln!("Native integration stats: {:?}", info.stats);
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

#[test]
#[ignore = "requires Linux Bubblewrap, GCC and ldd"]
fn request_traces_follow_real_worker_and_cache_hit() -> Result<()> {
    for binary in [
        env!("CARGO_BIN_EXE_sccache"),
        env!("CARGO_BIN_EXE_sccache-dist"),
    ] {
        let output = Command::new(binary).arg("--version").output()?;
        ensure!(output.status.success(), "version command failed");
        assert!(
            String::from_utf8(output.stdout)?
                .trim()
                .ends_with(sccache::BUILD_VERSION)
        );
    }
    let temp = tempfile::Builder::new()
        .prefix("native-trace-")
        .tempdir_in("/tmp")?;
    let root = temp.path();
    let collector = TraceCollector::start()?;
    let fleet = Fleet::start_with_mode(
        root,
        BTreeMap::new(),
        Default::default(),
        false,
        Some(&collector.endpoint),
    )?;
    let mut service = LocalService::start_configured(
        root,
        &fleet,
        None,
        Some(trace_config(root, &collector.endpoint, "client")),
    )?;
    fs::write(root.join("probe.c"), "int trace_probe(void) { return 42; }")?;
    for _ in 0..2 {
        let output = service
            .command(env!("CARGO_BIN_EXE_sccache"))
            .args(["/usr/bin/gcc", "-c", "probe.c", "-o", "probe.o"])
            .current_dir(root)
            .output()?;
        ensure!(
            output.status.success(),
            "compile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::remove_file(root.join("probe.o"))?;
    }
    let spans = collector.collect(|spans| {
        spans
            .iter()
            .filter(|span| span.name == "compile" && span.parent_span_id.is_empty())
            .count()
            >= 2
            && spans.iter().any(|span| span.name == "worker_job")
            && spans.iter().any(|span| span.name == "allocate_worker")
    })?;
    verify_trace_pair(&spans)?;
    service.stop()?;
    fleet.finish()?;
    Ok(())
}

fn verify_trace_pair(spans: &[opentelemetry_proto::tonic::trace::v1::Span]) -> Result<()> {
    use opentelemetry_proto::tonic::{common::v1::any_value::Value, trace::v1::Span};
    let attr = |span: &Span, key: &str| -> Option<String> {
        span.attributes
            .iter()
            .find(|attr| attr.key == key)
            .and_then(|attr| attr.value.as_ref())
            .and_then(|value| match &value.value {
                Some(Value::StringValue(value)) => Some(value.clone()),
                _ => None,
            })
    };
    let root_for = |outcome: &str| {
        spans.iter().find(|span| {
            span.name == "compile"
                && span.parent_span_id.is_empty()
                && attr(span, "sccache.outcome").as_deref() == Some(outcome)
        })
    };
    let miss = root_for("worker").context("missing worker trace root")?;
    let hit = root_for("hit").context("missing hit trace root")?;
    assert_ne!(miss.trace_id, hit.trace_id);
    let action = attr(miss, "sccache.action_key").context("missing native action identity")?;
    assert_eq!(
        attr(hit, "sccache.action_key").as_deref(),
        Some(action.as_str())
    );
    for name in [
        "allocate_worker",
        "worker_job",
        "prepare_sandbox",
        "compiler_process",
        "capture_outputs",
    ] {
        assert!(
            spans
                .iter()
                .any(|span| span.name == name && span.trace_id == miss.trace_id),
            "missing {name} in miss trace"
        );
        assert!(
            !spans
                .iter()
                .any(|span| span.name == name && span.trace_id == hit.trace_id),
            "unexpected {name} in hit trace"
        );
    }
    for span in spans {
        assert!(span.end_time_unix_nano >= span.start_time_unix_nano);
    }
    Ok(())
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

# The two calls have exactly the same Rust codegen inputs and arguments.
# Change the native archive, response-file contents, and literal linker
# argument. None is a codegen input; the same generated tree must be reused.
for value in 17 42; do
    printf 'unsigned native_value(void) { return %s; }\n' "$value" > native.c
    "$2" -c native.c -o native.o
    /usr/bin/ar rcs libnative.a native.o
    printf '%s\n' "-Wl,--defsym,native_marker=$value" > native.rsp
    rm -f build/linked-stage build/linked-stage.d build/linked-stage.dwp build/liblinked-stage.rmeta
    "$1" "$3" --crate-name linked --crate-type bin --edition=2024 --emit=link,metadata,dep-info --out-dir build -Cextra-filename=-stage -Cdebuginfo=2 -Csplit-debuginfo=packed -Lnative=. -lstatic=native -Clink-arg=@native.rsp "-Clink-arg=-Wl,--defsym,live_marker=$value" linked.rs
    test "$(build/linked-stage)" = "$value"
    test "$(readelf -Ws build/linked-stage | awk '$7 == "ABS" && $8 == "live_marker" { print $2 }')" = "$(printf '%016x' "$value")"
    test -f build/liblinked-stage.rmeta
    test -s build/linked-stage.d
    test -s build/linked-stage.dwp
    test ! -e build/linked-stage.rlink
done
# A test harness is an ordinary executable despite its explicit lib
# crate type. Its actual output must also be independently cacheable.
for i in 1 2; do
    rm -f build/testcase-stage build/testcase-stage.d
    "$1" "$3" --crate-name testcase --crate-type lib --test --edition=2024 --emit=link,dep-info --out-dir build -Cextra-filename=-stage testcase.rs
    build/testcase-stage --quiet
    test ! -e build/testcase-stage.rlink
done
# -Zno-link currently changes the crate metadata hash. The native
# backend must not silently replace a proc macro with an incompatible
# metadata identity, even though its linker invocation can be replayed.
"$3" --crate-name identity --crate-type proc-macro --edition=2024 --emit=link,dep-info --out-dir build -Cextra-filename=-stage identity.rs
"$3" --crate-name intermediate --crate-type rlib --edition=2024 --extern identity=build/libidentity-stage.so intermediate.rs --out-dir build
rm -f build/libidentity-stage.so
"$1" "$3" --crate-name identity --crate-type proc-macro --edition=2024 --emit=link,dep-info --out-dir build -Cextra-filename=-stage identity.rs
"$3" --edition=2024 --extern intermediate=build/libintermediate.rlib -Ldependency=build consumer.rs -o build/consumer
build/consumer
test ! -e build/identity-stage.rlink

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
    fs::write(
        root.join("linked.rs"),
        br#"unsafe extern "C" { fn native_value() -> u32; }
fn main() { println!("{}", unsafe { native_value() }); }"#,
    )?;
    fs::write(root.join("identity.rs"), b"extern crate proc_macro; #[proc_macro] pub fn identity(x:proc_macro::TokenStream)->proc_macro::TokenStream{x}")?;
    fs::write(
        root.join("consumer.rs"),
        b"fn main(){assert_eq!(intermediate::answer(),49);}",
    )?;
    fs::write(
        root.join("intermediate.rs"),
        b"pub fn answer()->i32 {identity::identity!(7 * 7)}",
    )?;
    fs::write(
        root.join("testcase.rs"),
        b"#[test] fn answer(){assert_eq!(7 * 7,49);}",
    )?;
    Ok(())
}

fn action_report(output: &std::process::Output) -> Result<(String, String)> {
    let log = String::from_utf8_lossy(&output.stderr);
    ensure!(output.status.success(), "compiler failed: {log}");
    let mut reports = log
        .lines()
        .filter_map(|line| line.split_once("native_action "));
    let (_, report) = reports.next().context("missing native action report")?;
    ensure!(reports.next().is_none(), "multiple native action reports");
    let mut fields = report.split_whitespace();
    let key = fields.next().context("missing key")?.to_owned();
    let source = fields.next().context("missing source")?.to_owned();
    Ok((key, source))
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
    let compile = |unused: &str, observed: &str| -> Result<((String, String), Vec<u8>)> {
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
            .env("NATIVE_AUDIT_UNUSED", unused)
            .env("SCCACHE_LOG", "sccache::native_action=info")
            .env("NATIVE_AUDIT_OBSERVED", observed)
            .output()?;
        let report = action_report(&output)?;
        Ok((report, fs::read(directory.join("build/libaudit.rlib"))?))
    };
    let ((key, source), first) = compile("first", "first")?;
    assert_eq!(source, "worker");
    let ((same, source), second) = compile("second", "first")?;
    assert_eq!(source, "hit");
    assert_eq!(key, same);
    assert_eq!(first, second);
    let ((changed, source), third) = compile("first", "second")?;
    assert_eq!(source, "worker");
    assert_ne!(key, changed);
    assert_ne!(first, third);
    Ok(())
}

#[test]
#[ignore = "requires Linux Bubblewrap, GCC and ldd"]
fn native_compiler_semantic_reuse_across_ephemeral_inputs() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("native-semantic-")
        .tempdir_in("/tmp")?;
    let root = temp.path().canonicalize()?;
    let fleet = Fleet::start(&root, BTreeMap::new())?;
    let mut service = LocalService::start(&root, &fleet, None)?;
    let config = root.join("direct.toml");
    fs::write(&config, "client_side_mode = false\n")?;
    for (name, input) in [
        ("probe.c", "int semantic_probe(void) { return VALUE; }\n"),
        (
            "probe.S",
            ".data\n.globl semantic_probe\nsemantic_probe: .byte VALUE\n",
        ),
    ] {
        let first = root.join("first");
        let second = root.join("second");
        for (dir, seconds) in [(&first, 1), (&second, 2)] {
            fs::create_dir_all(dir)?;
            let path = dir.join(name);
            fs::write(&path, input)?;
            fs::File::options().write(true).open(path)?.set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(seconds)),
            )?;
        }
        let compile = |dir: &Path, job: &str, value: &str| -> Result<((String, String), Vec<u8>)> {
            let output = service
                .command(env!("CARGO_BIN_EXE_sccache"))
                .args(["/usr/bin/gcc", "-c", name, "-o", "probe.o", value])
                .current_dir(dir)
                .env("SCCACHE_CONF", &config)
                .env("SCCACHE_LOG", "sccache::native_action=info")
                .env("GITHUB_RUN_ID", job)
                .output()?;
            Ok((action_report(&output)?, fs::read(dir.join("probe.o"))?))
        };
        let ((key, source), artifact) = compile(&first, "1", "-DVALUE=42")?;
        assert_eq!(source, "worker");
        let ((same, source), bytes) = compile(&second, "2", "-DVALUE=42")?;
        assert_eq!(source, "hit", "{name}");
        assert_eq!(key, same);
        assert_eq!(artifact, bytes);
        let ((changed, source), bytes) = compile(&second, "3", "-DVALUE=17")?;
        assert_eq!(source, "worker");
        assert_ne!(key, changed);
        assert_ne!(artifact, bytes);
    }
    service.stop()?;
    fleet.finish()?;
    Ok(())
}

#[test]
#[ignore = "requires Linux Bubblewrap, GCC and ldd"]
fn colocated_native_worker_shares_one_store_and_commits_results() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let fleet = Fleet::start_with_mode(root, BTreeMap::new(), Default::default(), true, None)?;
    let mut service = LocalService::start(root, &fleet, None)?;
    let source = root.join("compile");
    fs::create_dir(&source)?;
    fs::write(
        source.join("probe.c"),
        b"int colocated_probe(void) { return 42; }",
    )?;
    let compile = || -> Result<Vec<u8>> {
        let output = service
            .command(env!("CARGO_BIN_EXE_sccache"))
            .args(["/usr/bin/gcc", "-c", "probe.c", "-o", "probe.o"])
            .current_dir(&source)
            .output()?;
        ensure!(
            output.status.success(),
            "colocated compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(fs::read(source.join("probe.o"))?)
    };
    let first = compile()?;
    fs::remove_file(source.join("probe.o"))?;
    assert_eq!(compile()?, first);
    let stats = service.stats()?;
    assert_eq!(stats.cache_hits.all(), 1);
    assert_eq!(stats.cache_misses.all(), 1);
    assert_eq!(stats.dist_compiles.values().sum::<usize>(), 1);
    assert_eq!(stats.dist_errors, 0);
    service.stop()?;
    let (scheduler, worker) = fleet.finish()?;
    assert_eq!(scheduler, worker);
    assert_eq!(scheduler.actions, 1);
    assert!(!root.join("worker-store").exists());
    assert!(root.join("scheduler-store/index.redb").is_file());
    Ok(())
}

#[test]
#[ignore = "requires Linux Bubblewrap, GCC, Rust toolchain and ldd"]
fn native_compiler_cli_direct_and_networkless_namespace() -> Result<()> {
    // /dev/shm is useful for store-only tests, but /dev is reserved in
    // the execution contract and cannot contain real compiler outputs.
    let temp = tempfile::Builder::new()
        .prefix("native-cli-")
        .tempdir_in("/tmp")?;
    let root = temp.path().canonicalize()?;
    let fleet = Fleet::start(&root, BTreeMap::new())?;
    let mut service = LocalService::start(&root, &fleet, None)?;
    let status = service
        .command(env!("CARGO_BIN_EXE_sccache"))
        .arg("--dist-status")
        .output()?;
    ensure!(status.status.success(), "native status command failed");
    let status: sccache::server::DistInfo = serde_json::from_slice(&status.stdout)?;
    let sccache::server::DistInfo::SchedulerStatus(_, status) = status else {
        anyhow::bail!("native scheduler status did not authenticate: {status:?}");
    };
    assert_eq!(status.num_servers, 1);
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
    assert_eq!(stats.dist_compiles.values().sum::<usize>(), 6);
    assert_eq!(stats.forced_recaches, 2);
    assert_eq!(stats.cache_hits.all(), 6);
    assert_eq!(stats.cache_misses.all(), 6);
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
    let namespace_compiles = stats.dist_compiles.values().sum::<usize>();
    assert!((11..=12).contains(&namespace_compiles));
    assert_eq!(stats.cache_hits.all() + stats.cache_misses.all(), 24);
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
    assert_eq!(
        stats.cache_hits.all(),
        32 - u64::try_from(namespace_compiles)?
    );
    assert_eq!(
        stats.dist_compiles.values().sum::<usize>(),
        namespace_compiles
    );
    run_environment_audit(&service, &direct, &rustc, &direct_config)?;
    assert_eq!(service.stats()?.dist_errors, 0);
    service.stop()?;
    let (scheduler, worker) = fleet.finish()?;
    assert_eq!(scheduler.actions, worker.actions);
    Ok(())
}

#[test]
#[ignore = "requires Linux Bubblewrap, GCC, Rust toolchain and ldd"]
fn native_local_execution_in_networkless_namespace_shares_remote_actions() -> Result<()> {
    // /dev/shm is useful for store-only tests, but /dev is reserved in
    // the execution contract and cannot contain real compiler outputs.
    let temp = tempfile::Builder::new()
        .prefix("native-cli-")
        .tempdir_in("/tmp")?;
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
    assert_eq!(stats.cache_misses.all(), 6);
    assert_eq!(stats.cache_hits.all(), 6);
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
    assert_eq!(stats.cache_hits.all(), 10);
    assert_eq!(stats.forced_recaches, 2);
    assert_eq!(stats.dist_errors, 0);
    assert!(!visible.join("build").exists());
    assert!(!root.join("unexpected-archive-cache").exists());
    service.stop()?;
    let (scheduler, worker) = fleet.finish()?;
    // The scheduler owns all four actions, including the two produced locally.
    assert_eq!(scheduler.actions, 4);
    assert_eq!(worker.actions, 2);
    Ok(())
}

/// Exercise the actual launcher, Cargo fingerprints, an intermediate Rust
/// library, the broker, a scheduler cache hit and final executable delivery.
#[test]
#[ignore = "requires a real FUSE mount, stock Cargo and native distributed test fleet"]
fn cargo_leased_intermediates_deliver_a_working_binary() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("native-cargo-")
        .tempdir_in("/tmp")?;
    let root = temp.path().canonicalize()?;
    let fleet = Fleet::start(&root, BTreeMap::new())?;
    let mut service = LocalService::start(&root, &fleet, None)?;
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src"))?;
    fs::create_dir_all(workspace.join("dep/src"))?;
    fs::write(
        workspace.join("Cargo.toml"),
        "[package]\nname = \"leased-app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nleased-dep = { path = \"dep\" }\n",
    )?;
    fs::write(
        workspace.join("dep/Cargo.toml"),
        "[package]\nname = \"leased-dep\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )?;
    fs::write(
        workspace.join("dep/src/lib.rs"),
        "pub fn answer() -> u32 { 42 }\n",
    )?;
    fs::write(
        workspace.join("src/main.rs"),
        "fn main() { println!(\"{}\", leased_dep::answer()); }\n",
    )?;
    let binary = workspace.join("target/debug/leased-app");
    let direct_config = root.join("direct.toml");
    fs::write(&direct_config, "client_side_mode = false\n")?;
    for round in 0..2 {
        let mut command = service.command(env!("CARGO_BIN_EXE_sccache"));
        command
            .current_dir(&workspace)
            .args(["--cargo-final", "--", "build", "--offline", "-j", "2"])
            .env("SCCACHE_CONF", &direct_config)
            .env("SCCACHE_EXPERIMENTAL_CANONICAL_RUST", "1")
            .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_sccache"))
            .env("CARGO_TARGET_DIR", workspace.join("target"))
            .env("TMPDIR", &root);
        // CI installs the pinned toolchain using rustup. Preserve only the
        // toolchain discovery environment, never its compiler-cache socket.
        for key in [
            "PATH",
            "HOME",
            "RUSTUP_HOME",
            "CARGO_HOME",
            "RUSTUP_TOOLCHAIN",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let output = command.output()?;
        ensure!(
            output.status.success(),
            "Cargo leased build {round} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result = Command::new(&binary).output()?;
        assert!(result.status.success());
        assert_eq!(result.stdout, b"42\n");
        // Force Cargo to consult the action cache again with a fresh
        // intermediate tree, keeping the workspace and compiler inputs.
        fs::remove_dir_all(workspace.join("target"))?;
    }
    let stats = service.stats()?;
    assert_eq!(stats.dist_errors, 0);
    assert!(stats.dist_compiles.values().sum::<usize>() >= 2);
    assert!(stats.cache_hits.all() >= 2);
    service.stop()?;
    fleet.finish()?;
    Ok(())
}

/// A dependency-free Cargo graph exercises actual generated inputs and native
/// libraries, rather than assuming every intermediate is a plain Rust rlib.
fn write_mixed_cargo_graph(workspace: &Path) -> Result<()> {
    for directory in ["src", "dep/src", "mac/src"] {
        fs::create_dir_all(workspace.join(directory))?;
    }
    for (path, contents) in [
        (
            "Cargo.toml",
            r#"[package]
name = "leased-mixed-app"
version = "0.1.0"
edition = "2024"
[dependencies]
leased-mixed-dep = { path = "dep" }
"#,
        ),
        (
            "dep/Cargo.toml",
            r#"[package]
name = "leased-mixed-dep"
version = "0.1.0"
edition = "2024"
[dependencies]
leased-mixed-mac = { path = "../mac" }
"#,
        ),
        (
            "mac/Cargo.toml",
            r#"[package]
name = "leased-mixed-mac"
version = "0.1.0"
edition = "2024"
[lib]
proc-macro = true
"#,
        ),
        (
            "mac/src/lib.rs",
            r#"extern crate proc_macro;
#[proc_macro]
pub fn identity(input: proc_macro::TokenStream) -> proc_macro::TokenStream { input }
"#,
        ),
        (
            "dep/native.c",
            "unsigned native_value(void) { return 7; }\n",
        ),
        (
            "dep/build.rs",
            r#"use std::{env, fs, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=native.c");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    assert!(Command::new(env::var_os("RUSTC_WRAPPER").unwrap())
        .args(["/usr/bin/gcc", "-O2", "-c", "native.c", "-o"])
        .arg(out.join("native.o")).status().unwrap().success());
    assert!(Command::new("/usr/bin/ar").arg("crs")
        .arg(out.join("libnative.a")).arg(out.join("native.o"))
        .status().unwrap().success());
    fs::write(out.join("generated.rs"), "const FACTOR: u32 = 6;").unwrap();
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=native");
}
"#,
        ),
        (
            "dep/src/lib.rs",
            r#"include!(concat!(env!("OUT_DIR"), "/generated.rs"));
unsafe extern "C" { fn native_value() -> u32; }
pub fn answer() -> u32 {
    leased_mixed_mac::identity!(FACTOR * unsafe { native_value() })
}
"#,
        ),
        (
            "src/main.rs",
            r#"fn main() { println!("{}", leased_mixed_dep::answer()); }
#[test]
fn actual_native_link() { assert_eq!(leased_mixed_dep::answer(), 42); }
"#,
        ),
    ] {
        fs::write(workspace.join(path), contents)?;
    }
    Ok(())
}

fn run_mixed_cargo(
    service: &LocalService,
    workspace: &Path,
    root: &Path,
    target: &Path,
    mode: &str,
    build_directory: Option<&Path>,
) -> Result<()> {
    for subcommand in ["build", "test"] {
        let mut command = service.command(env!("CARGO_BIN_EXE_sccache"));
        command
            .current_dir(workspace)
            .args([mode, "--", subcommand, "--offline", "-j", "2"])
            .env("SCCACHE_CONF", root.join("direct.toml"))
            .env("SCCACHE_EXPERIMENTAL_CANONICAL_RUST", "1")
            .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_sccache"))
            .env("CARGO_TARGET_DIR", target)
            .env("TMPDIR", root);
        if let Some(directory) = build_directory {
            command.arg("--config").arg(format!(
                "build.build-dir={}",
                serde_json::to_string(directory)?
            ));
        }
        for key in [
            "PATH",
            "HOME",
            "RUSTUP_HOME",
            "CARGO_HOME",
            "RUSTUP_TOOLCHAIN",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let output = command.output()?;
        ensure!(
            output.status.success(),
            "mixed Cargo {mode} {subcommand} failed for {}: {}\n{}",
            target.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if subcommand == "test" {
            ensure!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "native-linked unit test was not executed"
            );
        }
    }
    let result = Command::new(target.join("debug/leased-mixed-app")).output()?;
    assert!(result.status.success());
    assert_eq!(result.stdout, b"42\n");
    Ok(())
}

#[test]
#[ignore = "requires Linux FUSE, stock Cargo, GCC, ar and an isolated distributed test fleet"]
fn cargo_leased_intermediates_support_parallel_mixed_graphs() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("native-mixed-cargo-")
        .tempdir_in("/tmp")?;
    let root = temp.path().canonicalize()?;
    let fleet = Fleet::start(&root, BTreeMap::new())?;
    let mut service = LocalService::start(&root, &fleet, None)?;
    let workspace = root.join("workspace");
    write_mixed_cargo_graph(&workspace)?;
    fs::write(root.join("direct.toml"), "client_side_mode = false\n")?;
    let cold_target = root.join("cold");
    run_mixed_cargo(
        &service,
        &workspace,
        &root,
        &cold_target,
        "--cargo-final",
        None,
    )?;
    let cold = service.stats()?;
    assert_eq!(cold.dist_errors, 0);
    assert!(cold.dist_compiles.values().sum::<usize>() >= 3);
    let warm_left = root.join("warm-left");
    let warm_right = root.join("warm-right");
    thread::scope(|scope| -> Result<()> {
        let left = scope.spawn(|| {
            run_mixed_cargo(
                &service,
                &workspace,
                &root,
                &warm_left,
                "--cargo-final",
                None,
            )
        });
        let right = scope.spawn(|| {
            run_mixed_cargo(
                &service,
                &workspace,
                &root,
                &warm_right,
                "--cargo-final",
                None,
            )
        });
        let left = left
            .join()
            .map_err(|_| anyhow::anyhow!("left Cargo session panicked"))?;
        let right = right
            .join()
            .map_err(|_| anyhow::anyhow!("right Cargo session panicked"))?;
        left?;
        right
    })?;
    let warm = service.stats()?;
    assert_eq!(warm.dist_errors, 0);
    assert!(warm.cache_hits.all() >= cold.cache_hits.all() + 4);
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("sccache-cargo-")
        {
            assert_eq!(
                fs::read_dir(entry.path())?.count(),
                0,
                "expired lease remained"
            );
        }
    }
    // The full-export mode uses ordinary persistent Cargo build directories
    // and must consume the same compiler graph without a FUSE session.
    let all_target = root.join("all");
    let all_intermediates = root.join("all-intermediates");
    run_mixed_cargo(
        &service,
        &workspace,
        &root,
        &all_target,
        "--cargo-all",
        Some(&all_intermediates),
    )?;
    assert!(all_intermediates.is_dir());
    assert_eq!(
        fs::read(all_target.join("debug/leased-mixed-app"))?,
        fs::read(cold_target.join("debug/leased-mixed-app"))?
    );
    let all = service.stats()?;
    assert_eq!(all.dist_errors, 0);
    assert!(all.cache_hits.all() > warm.cache_hits.all());
    service.stop()?;
    fleet.finish()?;
    Ok(())
}
