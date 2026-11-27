use fs_err as fs;
use log::trace;
#[cfg(feature = "dist-server")]
use sccache::config::HTTPUrl;
#[cfg(feature = "dist-server")]
use sccache::dist::{self, SchedulerStatusResult, ServerId};
use sccache::server::ServerInfo;
use std::env;
use std::fs::remove_dir_all;
use std::io::Write;
#[cfg(feature = "dist-server")]
use std::net::{self, SocketAddr};
use std::path::{Path, PathBuf};
#[cfg(feature = "dist-server")]
use std::process::{Child, Output};
use std::process::{Command, Stdio};
use std::str::{self};
#[cfg(feature = "dist-server")]
use std::thread;
#[cfg(feature = "dist-server")]
use std::time::{Duration, Instant};

use assert_cmd::prelude::*;
use predicates::prelude::*;
use serde::Serialize;
#[cfg(feature = "dist-server")]
use uuid::Uuid;

#[cfg(feature = "dist-server")]
const CONTAINER_NAME_PREFIX: &str = "sccache_dist_test";
#[cfg(feature = "dist-server")]
const DIST_IMAGE: &str = "sccache_dist_test_image";
#[cfg(feature = "dist-server")]
const DIST_DOCKERFILE: &str = include_str!("Dockerfile.sccache-dist");
#[cfg(feature = "dist-server")]
const DIST_IMAGE_BWRAP_PATH: &str = "/usr/bin/bwrap";
#[cfg(feature = "dist-server")]
const MAX_STARTUP_WAIT: Duration = Duration::from_secs(5);
const DIST_CACHE_RELPATH: &str = "client-dist-cache";

#[cfg(feature = "dist-server")]
const DIST_SERVER_TOKEN: &str = "THIS IS THE TEST TOKEN";

pub const CUSTOM_SERVER_ADDR_ENV: &str = "SCCACHE_TEST_CUSTOM_SERVER_ADDR";
pub const CUSTOM_SERVER_SCHEDULER_ENV: &str = "SCCACHE_TEST_CUSTOM_SERVER_SCHEDULER";
pub const CUSTOM_SERVER_CLUSTER_ENV: &str = "SCCACHE_TEST_CUSTOM_SERVER_CLUSTER";
pub const CUSTOM_SERVER_TOKEN_ENV: &str = "SCCACHE_TEST_CUSTOM_SERVER_TOKEN";

#[cfg(feature = "dist-server")]
const CONFIGS_CONTAINER_PATH: &str = "/sccache-bits";
#[cfg(feature = "dist-server")]
const BUILD_DIR_CONTAINER_PATH: &str = "/sccache-bits/build-dir";
// Per-fixture endpoints avoid touching the managed build cache or other
// distributed test processes on the host.
#[cfg(all(unix, feature = "dist-server"))]
thread_local! {
    static DIST_DAEMON_SOCKET: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(all(unix, feature = "dist-server"))]
struct DistDaemonSocket;

#[cfg(all(unix, feature = "dist-server"))]
impl DistDaemonSocket {
    fn new(path: PathBuf) -> Self {
        DIST_DAEMON_SOCKET.with(|socket| {
            assert!(socket.borrow().is_none(), "nested distributed test fixture");
            socket.replace(Some(path));
        });
        Self
    }
}

#[cfg(all(unix, feature = "dist-server"))]
impl Drop for DistDaemonSocket {
    fn drop(&mut self) {
        let _ = stop_local_daemon();
        DIST_DAEMON_SOCKET.with(|socket| {
            socket.replace(None);
        });
    }
}

#[cfg(feature = "dist-server")]
fn loopback_listener() -> net::TcpListener {
    net::TcpListener::bind("127.0.0.1:0").unwrap()
}

// A current Rust sysroot plus cross-target runtimes can exceed 1 GiB.
// Keep normal test worker archives and extractions resident across requests.
const TC_CACHE_SIZE: u64 = 4 * 1024 * 1024 * 1024;
#[cfg(feature = "dist-server")]
const EXTRACTED_TC_CACHE_SIZE: u64 = 8 * 1024 * 1024 * 1024;

pub fn start_local_daemon(cfg_path: &Path, cached_cfg_path: &Path) {
    // Don't run this with run() because on Windows `wait_with_output`
    // will hang because the internal server process is not detached.
    if !sccache_command()
        .arg("--start-server")
        // Uncomment following lines to debug locally.
        // .env("SCCACHE_LOG", "sccache=trace")
        // .env("RUST_LOG_STYLE", "never")
        // .env(
        //     "SCCACHE_ERROR_LOG",
        //     env::temp_dir().join("sccache_local_daemon.txt"),
        // )
        .env("SCCACHE_CONF", cfg_path)
        .env("SCCACHE_CACHED_CONF", cached_cfg_path)
        .status()
        .unwrap()
        .success()
    {
        panic!("Failed to start local daemon");
    }
}

#[must_use = "the result indicates whether daemon shutdown succeeded"]
pub fn stop_local_daemon() -> bool {
    trace!("sccache --stop-server");
    sccache_command()
        .arg("--stop-server")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[must_use = "the result indicates whether the cache was cleared"]
pub fn clear_cache_local_daemon(tmpdir: &Path) -> bool {
    trace!("clear local cache daemon");
    let client_build_dir = tmpdir.join(DIST_CACHE_RELPATH);
    assert!(client_build_dir.exists());
    remove_dir_all(client_build_dir).is_ok()
}

pub fn get_stats<F: 'static + Fn(ServerInfo)>(f: F) {
    sccache_command()
        .args(["--show-stats", "--stats-format=json"])
        .assert()
        .success()
        .stdout(predicate::function(move |output: &[u8]| {
            let Ok(text) = str::from_utf8(output) else {
                eprintln!("sccache stats output was not UTF-8: {output:?}");
                return false;
            };
            let Ok(stats) = serde_json::from_str(text) else {
                eprintln!("failed to parse sccache JSON stats: {text}");
                return false;
            };
            eprintln!("get server stats: {stats:?}");
            f(stats);
            true
        }));
}

pub fn zero_stats() {
    trace!("sccache --zero-stats");
    drop(
        sccache_command()
            .arg("--zero-stats")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
}

pub fn write_json_cfg<T: Serialize>(path: &Path, filename: &str, contents: &T) {
    let p = path.join(filename);
    let mut f = fs::File::create(p).unwrap();
    f.write_all(&serde_json::to_vec(contents).unwrap()).unwrap();
}

pub fn write_source(path: &Path, filename: &str, contents: &str) {
    let p = path.join(filename);
    let mut f = fs::File::create(p).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

#[must_use = "the returned path is the initialized test project directory"]
pub fn init_cargo(path: &Path, cargo_name: &str) -> PathBuf {
    let cargo_path = path.join(cargo_name);
    let source_path = "src";
    fs::create_dir_all(cargo_path.join(source_path)).unwrap();
    cargo_path
}

// Prune any environment variables that could adversely affect test execution.
#[must_use = "the returned command contains the filtered environment"]
pub fn prune_command(mut cmd: Command) -> Command {
    use sccache::util::OsStrExt;

    for (var, _) in env::vars_os() {
        if var.starts_with("SCCACHE_") {
            cmd.env_remove(var);
        }
    }
    #[cfg(all(unix, feature = "dist-server"))]
    DIST_DAEMON_SOCKET.with(|socket| {
        if let Some(path) = socket.borrow().as_ref() {
            cmd.env("SCCACHE_SERVER_UDS", path);
        }
    });
    cmd
}

// A packaged integration-test executable and its subject binaries are
// relocatable together. Normal Cargo invocations use Cargo's exact paths.
fn test_binary_path(cargo_path: &str) -> PathBuf {
    let path = Path::new(cargo_path);
    env::current_exe()
        .ok()
        .and_then(|exe| {
            let directory = exe.parent()?;
            let name = path.file_name()?;
            directory
                .join("sccache-test-bundle.sha")
                .is_file()
                .then(|| directory.join(name))
        })
        .unwrap_or_else(|| path.to_owned())
}

#[must_use = "the returned path identifies the test client"]
pub fn sccache_path() -> PathBuf {
    test_binary_path(env!("CARGO_BIN_EXE_sccache"))
}

#[must_use = "the returned command must be executed to invoke the test client"]
pub fn sccache_command() -> Command {
    prune_command(Command::new(sccache_path()))
}

#[must_use = "the returned command must be executed to invoke Cargo"]
pub fn cargo_command() -> Command {
    prune_command(Command::new("cargo"))
}

#[cfg(feature = "dist-server")]
pub fn sccache_dist_path() -> PathBuf {
    test_binary_path(env!("CARGO_BIN_EXE_sccache-dist"))
}

#[must_use = "the returned configuration must be used to configure the test client"]
pub fn sccache_client_cfg(
    tmpdir: &Path,
    preprocessor_cache_mode: bool,
) -> sccache::config::FileConfig {
    let cache_relpath = "client-cache";
    let dist_cache_relpath = DIST_CACHE_RELPATH;
    fs::create_dir(tmpdir.join(cache_relpath)).unwrap();
    fs::create_dir(tmpdir.join(dist_cache_relpath)).unwrap();

    let disk_cache = sccache::config::DiskCacheConfig {
        dir: tmpdir.join(cache_relpath),
        preprocessor_cache_mode: sccache::config::PreprocessorCacheModeConfig {
            use_preprocessor_cache_mode: preprocessor_cache_mode,
            ..Default::default()
        },
        ..Default::default()
    };
    sccache::config::FileConfig {
        cache: sccache::config::CacheConfigs {
            azure: None,
            disk: Some(disk_cache),
            gcs: None,
            gha: None,
            memcached: None,
            redis: None,
            s3: None,
            webdav: None,
            oss: None,
            cos: None,
            multilevel: None,
        },
        dist: sccache::config::DistConfig {
            cluster: None,
            auth: Default::default(), // dangerously_insecure
            scheduler_url: None,
            cache_dir: tmpdir.join(dist_cache_relpath),
            toolchains: vec![],
            toolchain_cache_size: TC_CACHE_SIZE,
            rewrite_includes_only: false, // TODO
            native: None,
            native_installation_catalogs: Vec::new(),
        },
        server_startup_timeout_ms: None,
        basedirs: vec![],
        client_side_mode: false,
        shared_daemon: None,
        compiler_aliases: Default::default(),
        compile_limits: Default::default(),
        traces: None,
    }
}

#[cfg(feature = "dist-server")]
fn sccache_scheduler_cfg(address: SocketAddr) -> sccache::config::scheduler::Config {
    sccache::config::scheduler::Config {
        cluster_directory: Path::new(CONFIGS_CONTAINER_PATH).join("cluster"),
        maintenance_drain_file: None,
        dashboard: None,
        native_cache: None,
        local_worker: None,
        traces: None,
        job_slack: Default::default(),
        public_addr: address,
        client_auth: sccache::config::scheduler::ClientAuth::Insecure,
        server_auth: sccache::config::scheduler::ServerAuth::Token {
            token: DIST_SERVER_TOKEN.to_owned(),
        },
    }
}

#[cfg(feature = "dist-server")]
fn sccache_server_cfg(
    tmpdir: &Path,
    scheduler_url: HTTPUrl,
    server_addr: SocketAddr,
) -> sccache::config::server::Config {
    let relpath = "server-cache";
    let scheduler_id = sccache_cluster_identity::Identity::open(&tmpdir.join("cluster/key.pem"))
        .unwrap()
        .id()
        .unwrap();
    fs::create_dir(tmpdir.join(relpath)).unwrap();

    sccache::config::server::Config {
        cluster: sccache_peer_identity::PeerConfig {
            directory: Path::new(CONFIGS_CONTAINER_PATH)
                .join(format!("worker-{}", server_addr.port())),
            ca_certificate: Path::new(CONFIGS_CONTAINER_PATH).join("cluster/ca.pem"),
            scheduler_id,
        },
        builder: sccache::config::server::BuilderType::Overlay {
            build_dir: BUILD_DIR_CONTAINER_PATH.into(),
            bwrap_path: DIST_IMAGE_BWRAP_PATH.into(),
            extracted_toolchain_cache_size: EXTRACTED_TC_CACHE_SIZE,
        },
        cache_dir: Some(Path::new(CONFIGS_CONTAINER_PATH).join(relpath)),
        public_addr: server_addr,
        bind_address: Some(server_addr),
        scheduler_url,
        scheduler_auth: sccache::config::server::SchedulerAuth::Token {
            token: DIST_SERVER_TOKEN.to_owned(),
        },
        toolchain_cache_size: TC_CACHE_SIZE,
        toolchain_archive_sources: vec![],
        native_worker: None,
        traces: None,
    }
}

// TODO: this is copied from the sccache-dist binary - it's not clear where would be a better place to put the
// code so that it can be included here
#[cfg(feature = "dist-server")]
fn create_server_token(server_id: ServerId, auth_token: &str) -> String {
    format!("{} {}", server_id, auth_token)
}

#[cfg(feature = "dist-server")]
pub enum ServerHandle {
    Container { cid: String, url: HTTPUrl },
    Process { pid: u32, url: HTTPUrl },
}

#[cfg(feature = "dist-server")]
pub struct DistSystem {
    sccache_dist: PathBuf,
    tmpdir: PathBuf,

    scheduler_addr: SocketAddr,
    scheduler_listener: Option<net::TcpListener>,
    #[cfg(unix)]
    daemon_socket: Option<DistDaemonSocket>,
    scheduler_name: Option<String>,
    server_names: Vec<String>,
    server_processes: Vec<Child>,
}

#[cfg(feature = "dist-server")]
impl DistSystem {
    pub fn new(sccache_dist: &Path, tmpdir: &Path) -> Self {
        static IMAGE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        IMAGE.get_or_init(|| {
            // Make sure the docker image is available, building it if necessary.
            // Retry up to 3 times to handle transient apt-get failures in CI.
            let mut last_output = None;
            for attempt in 1..=3 {
                let mut child = Command::new("docker")
                    .args(["build", "-q", "-t", DIST_IMAGE, "-"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(DIST_DOCKERFILE.as_bytes())
                    .unwrap();
                let output = child.wait_with_output().unwrap();
                if output.status.success() {
                    last_output = Some(output);
                    break;
                }
                eprintln!(
                    "docker build attempt {}/3 failed (exit {}), retrying...",
                    attempt, output.status
                );
                last_output = Some(output);
                std::thread::sleep(Duration::from_secs(5 * attempt as u64));
            }
            check_output(&last_output.unwrap());
        });

        let tmpdir = tmpdir.join("distsystem");
        fs::create_dir(&tmpdir).unwrap();
        let cluster = tmpdir.join("cluster");
        fs::create_dir_all(&cluster).unwrap();
        drop(sccache_cluster_identity::scheduler_registry(&cluster).unwrap());
        let ca = sccache_cluster_identity::ClusterCa::open(&cluster.join("ca-key.pem")).unwrap();
        sccache_cluster_identity::Identity::open(&cluster.join("key.pem")).unwrap();
        sccache_cluster_identity::publish_trust_anchor(ca.certificate(), &cluster.join("ca.pem"))
            .unwrap();

        let scheduler_listener = loopback_listener();
        let scheduler_addr = scheduler_listener.local_addr().unwrap();
        #[cfg(unix)]
        let daemon_socket = Some(DistDaemonSocket::new(tmpdir.join("client.sock")));
        Self {
            scheduler_addr,
            scheduler_listener: Some(scheduler_listener),
            #[cfg(unix)]
            daemon_socket,
            sccache_dist: sccache_dist.to_owned(),
            tmpdir,

            scheduler_name: None,
            server_names: vec![],
            server_processes: vec![],
        }
    }

    pub fn add_scheduler(&mut self) {
        let scheduler_cfg_relpath = "scheduler-cfg.json";
        let scheduler_cfg_path = self.tmpdir.join(scheduler_cfg_relpath);
        let scheduler_cfg_container_path =
            Path::new(CONFIGS_CONTAINER_PATH).join(scheduler_cfg_relpath);
        let scheduler_cfg = sccache_scheduler_cfg(self.scheduler_addr);
        fs::File::create(scheduler_cfg_path)
            .unwrap()
            .write_all(&serde_json::to_vec(&scheduler_cfg).unwrap())
            .unwrap();

        // Create the scheduler
        let scheduler_name = make_container_name("scheduler");
        // Reserve until immediately before the service binds.
        drop(self.scheduler_listener.take());
        let output = Command::new("docker")
            .args([
                "run",
                "--name",
                &scheduler_name,
                "-e",
                "SCCACHE_NO_DAEMON=1",
                "-e",
                "SCCACHE_LOG=debug",
                "-e",
                "RUST_BACKTRACE=1",
                "--network",
                "host",
                "-v",
                &format!("{}:/sccache-dist:z", self.sccache_dist.to_str().unwrap()),
                "-v",
                &format!(
                    "{}:{}:z",
                    self.tmpdir.to_str().unwrap(),
                    CONFIGS_CONTAINER_PATH
                ),
                "-d",
                DIST_IMAGE,
                "bash",
                "-c",
                &format!(
                    r#"
                    set -o errexit &&
                    exec /sccache-dist scheduler --config {cfg}
                "#,
                    cfg = scheduler_cfg_container_path.to_str().unwrap()
                ),
            ])
            .output()
            .unwrap();
        self.scheduler_name = Some(scheduler_name);

        check_output(&output);

        let scheduler_url = self.scheduler_url();
        wait_for_http(scheduler_url, Duration::from_millis(100), MAX_STARTUP_WAIT);
        wait_for(
            || {
                let status = self.scheduler_status()?;
                if matches!(
                    status,
                    SchedulerStatusResult {
                        num_servers: 0,
                        num_cpus: _,
                        in_progress: 0,
                        ..
                    }
                ) {
                    Ok(())
                } else {
                    Err(format!("{:?}", status))
                }
            },
            Duration::from_millis(100),
            MAX_STARTUP_WAIT,
        );
    }

    pub fn add_server(&mut self, environment: &[(&str, &str)]) -> ServerHandle {
        let server_cfg_relpath = format!("server-cfg-{}.json", self.server_names.len());
        let server_cfg_path = self.tmpdir.join(&server_cfg_relpath);
        let server_cfg_container_path = Path::new(CONFIGS_CONTAINER_PATH).join(server_cfg_relpath);

        let server_name = make_container_name("server");
        let output = Command::new("docker")
            .args([
                "run",
                // Important for the bubblewrap builder
                "--privileged",
                "--name",
                &server_name,
                "-e",
                "SCCACHE_LOG=debug",
                "-e",
                "RUST_BACKTRACE=1",
                "--network",
                "host",
                "-v",
                &format!("{}:/sccache-dist:z", self.sccache_dist.to_str().unwrap()),
                "-v",
                &format!(
                    "{}:{}:z",
                    self.tmpdir.to_str().unwrap(),
                    CONFIGS_CONTAINER_PATH
                ),
                "-d",
            ])
            .args(
                environment
                    .iter()
                    .flat_map(|(key, value)| ["-e".to_owned(), format!("{key}={value}")]),
            )
            .args([
                DIST_IMAGE,
                "bash",
                "-c",
                &format!(
                    r#"
                    set -o errexit &&
                    while [ ! -f {cfg}.ready ]; do sleep 0.1; done &&
                    exec /sccache-dist server --config {cfg}
                "#,
                    cfg = server_cfg_container_path.to_str().unwrap()
                ),
            ])
            .output()
            .unwrap();
        self.server_names.push(server_name.clone());

        check_output(&output);

        let listener = loopback_listener();
        let server_addr = listener.local_addr().unwrap();
        let server_cfg = sccache_server_cfg(&self.tmpdir, self.scheduler_url(), server_addr);
        fs::File::create(&server_cfg_path)
            .unwrap()
            .write_all(&serde_json::to_vec(&server_cfg).unwrap())
            .unwrap();
        drop(listener);
        fs::File::create(format!("{}.ready", server_cfg_path.to_str().unwrap())).unwrap();

        let url = HTTPUrl::from_url(url::Url::parse(&format!("https://{server_addr}")).unwrap());
        let handle = ServerHandle::Container {
            cid: server_name,
            url,
        };
        self.wait_server_ready(&handle);
        handle
    }

    pub fn add_custom_server_process(&mut self, test_name: &str) -> ServerHandle {
        let listener = loopback_listener();
        let server_addr = listener.local_addr().unwrap();
        let cluster = sccache_peer_identity::PeerConfig {
            directory: self
                .tmpdir
                .join(format!("custom-worker-{}", server_addr.port())),
            ..self.cluster_config()
        };
        let peer_id = sccache_cluster_identity::open_identity(&cluster)
            .unwrap()
            .id()
            .unwrap();
        let token = create_server_token(peer_id, DIST_SERVER_TOKEN);
        let scheduler_url = self.scheduler_url().to_url().to_string();
        drop(listener);
        let child = Command::new(env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(CUSTOM_SERVER_ADDR_ENV, server_addr.to_string())
            .env(CUSTOM_SERVER_SCHEDULER_ENV, scheduler_url)
            .env(CUSTOM_SERVER_TOKEN_ENV, token)
            .env(
                CUSTOM_SERVER_CLUSTER_ENV,
                serde_json::to_string(&cluster).unwrap(),
            )
            .env("SCCACHE_LOG", "sccache=trace")
            .spawn()
            .unwrap();
        let pid = child.id();
        self.server_processes.push(child);

        let url = HTTPUrl::from_url(url::Url::parse(&format!("https://{}", server_addr)).unwrap());
        let handle = ServerHandle::Process { pid, url };
        self.wait_server_ready(&handle);
        handle
    }

    pub fn restart_server(&mut self, handle: &ServerHandle) {
        match handle {
            ServerHandle::Container { cid, url: _ } => {
                let output = Command::new("docker")
                    .args(["restart", cid])
                    .output()
                    .unwrap();
                check_output(&output);
            }
            ServerHandle::Process { pid: _, url: _ } => {
                // TODO: pretty easy, just no need yet
                panic!("restart not yet implemented for pids")
            }
        }
        self.wait_server_ready(handle)
    }
    pub fn count_toolchains_on_server(&mut self, handle: &ServerHandle) -> usize {
        match handle {
            ServerHandle::Container { cid, url: _ } => {
                let output = Command::new("docker")
                    .args([
                        "exec",
                        "-t",
                        cid,
                        "ls",
                        "-1",
                        &format!("{BUILD_DIR_CONTAINER_PATH}/toolchains"),
                    ])
                    .output()
                    .unwrap();
                check_output(&output);
                println!("{output:?}");
                let str_output = String::from_utf8_lossy(&output.stdout);
                str_output.lines().filter(|&part| !part.is_empty()).count()
            }
            ServerHandle::Process { pid: _, url: _ } => {
                panic!("restart not yet implemented for pids")
            }
        }
    }

    pub fn wait_server_ready(&mut self, handle: &ServerHandle) {
        let url = match handle {
            ServerHandle::Container { cid: _, url } | ServerHandle::Process { pid: _, url } => {
                url.clone()
            }
        };
        wait_for_http(url, Duration::from_millis(100), MAX_STARTUP_WAIT);
        wait_for(
            || {
                let status = self.scheduler_status()?;
                if matches!(
                    status,
                    SchedulerStatusResult {
                        num_servers: 1,
                        num_cpus: _,
                        in_progress: 0,
                        ..
                    }
                ) {
                    Ok(())
                } else {
                    Err(format!("{:?}", status))
                }
            },
            Duration::from_millis(100),
            MAX_STARTUP_WAIT,
        );
    }

    pub fn scheduler_url(&self) -> HTTPUrl {
        let url = format!("https://{}", self.scheduler_addr);
        HTTPUrl::from_url(url::Url::parse(&url).unwrap())
    }

    pub fn cluster_config(&self) -> sccache_peer_identity::PeerConfig {
        sccache_peer_identity::PeerConfig {
            directory: self.tmpdir.join("client-identity"),
            ca_certificate: self.tmpdir.join("cluster/ca.pem"),
            scheduler_id: sccache_cluster_identity::Identity::open(
                &self.tmpdir.join("cluster/key.pem"),
            )
            .unwrap()
            .id()
            .unwrap(),
        }
    }

    fn scheduler_status(&self) -> Result<SchedulerStatusResult, String> {
        let config = self.cluster_config();
        let id = config.scheduler_id;
        let peer = sccache::dist::cluster::open_peer(
            config,
            &self.scheduler_url().to_url(),
            sccache_cluster_identity::Role::Client,
            || Ok(sccache::config::INSECURE_DIST_CLIENT_TOKEN.to_owned()),
        )
        .map_err(|error| error.to_string())?;
        let credentials = peer.current().map_err(|error| error.to_string())?;
        let transport = sccache_cluster_identity::ClusterHttpClient::new(
            &credentials,
            id,
            sccache_cluster_identity::Role::Scheduler,
            self.scheduler_addr,
        )
        .map_err(|error| error.to_string())?;
        let url = dist::http::urls::scheduler_status(transport.base())
            .map_err(|error| error.to_string())?;
        let runtime = sccache::http_client::io_runtime().map_err(|error| error.to_string())?;
        let res = runtime
            .block_on(
                transport
                    .client()
                    .get(url.as_str())
                    .timeout(Duration::from_secs(2))
                    .send(),
            )
            .map_err(|error| error.to_string())?;
        if !res.status().is_success() {
            return Err(format!("scheduler status request failed: {}", res.status()));
        }
        let bytes = runtime
            .block_on(res.bytes())
            .map_err(|error| error.to_string())?;
        bincode::deserialize(&bytes).map_err(|error| error.to_string())
    }
}

// If you want containers to hang around (e.g. for debugging), comment out the "rm -f" lines
#[cfg(feature = "dist-server")]
impl Drop for DistSystem {
    fn drop(&mut self) {
        #[cfg(unix)]
        drop(self.daemon_socket.take());
        let mut did_err = false;

        // Panicking halfway through drop would either abort (if it's a double panic) or leave us with
        // resources that aren't yet cleaned up. Instead, do as much as possible then decide what to do
        // at the end - panic (if not already doing so) or let the panic continue
        macro_rules! droperr {
            ($e:expr) => {
                match $e {
                    Ok(()) => (),
                    Err(e) => {
                        did_err = true;
                        eprintln!("Error with {}: {}", stringify!($e), e)
                    }
                }
            };
        }

        let mut logs = vec![];
        let mut outputs = vec![];
        let mut exits = vec![];

        if let Some(scheduler_name) = self.scheduler_name.as_ref() {
            droperr!(
                Command::new("docker")
                    .args(["logs", scheduler_name])
                    .output()
                    .map(|o| logs.push((scheduler_name, o)))
            );
            droperr!(
                Command::new("docker")
                    .args(["kill", scheduler_name])
                    .output()
                    .map(|o| outputs.push((scheduler_name, o)))
            );
            droperr!(
                Command::new("docker")
                    .args(["rm", "-f", scheduler_name])
                    .output()
                    .map(|o| outputs.push((scheduler_name, o)))
            );
        }
        for server_name in self.server_names.iter() {
            droperr!(
                Command::new("docker")
                    .args(["logs", server_name])
                    .output()
                    .map(|o| logs.push((server_name, o)))
            );
            droperr!(
                Command::new("docker")
                    .args(["kill", server_name])
                    .output()
                    .map(|o| outputs.push((server_name, o)))
            );
            droperr!(
                Command::new("docker")
                    .args(["rm", "-f", server_name])
                    .output()
                    .map(|o| outputs.push((server_name, o)))
            );
        }
        for child in &mut self.server_processes {
            match child.try_wait() {
                Ok(Some(status)) => exits.push(status),
                Ok(None) => {
                    droperr!(child.kill());
                    droperr!(child.wait().map(|status| exits.push(status)));
                }
                Err(error) => {
                    did_err = true;
                    eprintln!(
                        "Error checking custom server process {}: {error}",
                        child.id()
                    );
                }
            }
        }

        for (
            container,
            Output {
                status,
                stdout,
                stderr,
            },
        ) in logs
        {
            println!(
                "LOGS == ({}) ==\n> {} <:\n## STDOUT\n{}\n\n## STDERR\n{}\n====",
                status,
                container,
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
        }
        for (
            container,
            Output {
                status,
                stdout,
                stderr,
            },
        ) in outputs
        {
            println!(
                "OUTPUTS == ({}) ==\n> {} <:\n## STDOUT\n{}\n\n## STDERR\n{}\n====",
                status,
                container,
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
        }
        for exit in exits {
            println!("EXIT: {:?}", exit)
        }

        if did_err && !thread::panicking() {
            panic!("Encountered failures during dist system teardown")
        }
    }
}

#[cfg(feature = "dist-server")]
fn make_container_name(tag: &str) -> String {
    format!(
        "{}_{}_{}",
        CONTAINER_NAME_PREFIX,
        tag,
        Uuid::new_v4().hyphenated()
    )
}

#[cfg(feature = "dist-server")]
fn check_output(output: &Output) {
    if !output.status.success() {
        println!(
            "{}\n\n[BEGIN STDOUT]\n===========\n{}\n===========\n[FIN STDOUT]\n\n[BEGIN STDERR]\n===========\n{}\n===========\n[FIN STDERR]\n\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        panic!()
    }
}

#[cfg(feature = "dist-server")]
fn wait_for_http(url: HTTPUrl, interval: Duration, max_wait: Duration) {
    // TODO: after upgrading to reqwest >= 0.9, use 'danger_accept_invalid_certs' and stick with that rather than tcp
    wait_for(
        || {
            let url = url.to_url();
            let url = url.socket_addrs(|| None).unwrap();
            match net::TcpStream::connect(url.as_slice()) {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        },
        interval,
        max_wait,
    )
}

#[cfg(feature = "dist-server")]
fn wait_for<F: Fn() -> Result<(), String>>(f: F, interval: Duration, max_wait: Duration) {
    let start = Instant::now();
    let mut lasterr;
    loop {
        match f() {
            Ok(()) => return,
            Err(e) => lasterr = e,
        }
        if start.elapsed() > max_wait {
            break;
        }
        thread::sleep(interval);
    }
    panic!("wait timed out, last error result: {lasterr}")
}
