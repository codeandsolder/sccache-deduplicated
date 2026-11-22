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
        Artifact, BuildPath, CommandSpec, ComponentAudit, ContentId, ExecutionSpec, MappedMetadata,
        MappedTree, NativeStore, OutputSpec, SpacePolicy, TreeLayer, TreePath, TreeRecipe,
        wire::{NativeAdmission, NativeRunResult, NativeStatus, ScheduleReply},
    },
    config::{Config, DistAuth, HTTPUrl, NativeClientConfig, scheduler, server},
    dist::{
        SchedulerStatusResult,
        native::{NativeBuildPolicy, NativeBuildSource, NativeCacheClient},
        pkg::ToolchainPackageBuilder,
    },
};

const CLIENT_TOKEN: &str = "native-integration-client";
const WORKER_TOKEN: &str = "native-integration-worker";
const PLATFORM: &str = "native-integration-platform-v1";

fn space() -> SpacePolicy {
    SpacePolicy {
        min_available_bytes: 1024 * 1024,
        target_available_bytes: 2 * 1024 * 1024,
        max_evictions_per_pass: 8,
        gc_batch: 128,
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
    fn start(root: &Path) -> Result<Self> {
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

#[test]
#[ignore = "requires Linux Bubblewrap, GNU assembler and ldd"]
fn native_worker_https_executes_real_assembler_and_reuses_result() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let fleet = Fleet::start(root)?;
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
    fs::write(&input, b".text\n.globl entry\nentry:\n.byte 1, 2, 3, 4\n")?;
    let reference = root.join("reference.o");
    ensure!(
        Command::new("/usr/bin/as")
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
    let source_tree = mapping.prepare()?;
    let spec = ExecutionSpec {
        platform: ContentId::of(PLATFORM.as_bytes()),
        root: TreeRecipe {
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
                kind: sccache_build::OutputKind::File,
            },
        )]),
    };
    assert_eq!(
        client.admit(&spec)?,
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
        |id| source_tree.open_blob(id),
        Duration::from_secs(1),
    )?;
    let NativeAdmission::Compile { ticket } = client.admit(&spec)? else {
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
    } = client.admit(&spec)?
    else {
        anyhow::bail!("expected cache hit");
    };
    assert_eq!(cached, manifest);
    client.close(hit)?;
    assert_eq!(fleet.status()?.in_progress, 0);

    let inputs = [root_tree, source_tree];
    let policy = NativeBuildPolicy {
        timeout: Duration::from_secs(30),
        renewal_interval: Duration::from_secs(1),
        max_result_bytes: 16 * 1024 * 1024,
    };
    let delivered = root.join("delivered.o");
    let destinations = BTreeMap::from([("object".into(), delivered.clone())]);
    let hit = client.run_action(&spec, &inputs, &destinations, &policy)?;
    assert_eq!(hit.source, NativeBuildSource::Hit);
    assert!(hit.output.status.success());
    assert_eq!(fs::read(&delivered)?, fs::read(&reference)?);

    let mut second = spec.clone();
    second.command.arguments.insert(0, b"--64".to_vec());
    fs::remove_file(&delivered)?;
    let miss = client.run_action(&second, &inputs, &destinations, &policy)?;
    assert_eq!(miss.source, NativeBuildSource::Worker(worker_address));
    assert!(miss.output.status.success());
    assert_eq!(fs::read(&delivered)?, fs::read(&reference)?);
    let hit = client.run_action(&second, &inputs, &destinations, &policy)?;
    assert_eq!(hit.source, NativeBuildSource::Hit);

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
    let result = client.run_action(&directory, &inputs, &tree_destinations, &policy)?;
    assert_eq!(result.source, NativeBuildSource::Worker(worker_address));
    assert!(result.output.status.success());
    assert_eq!(fs::read(generated.join("object.o"))?, fs::read(&reference)?);
    let source_bytes = fs::read(generated.join("input.s"))?;
    assert!(
        client
            .run_action(&directory, &inputs, &tree_destinations, &policy)
            .is_err()
    );
    fs::remove_dir_all(&generated)?;
    let result = client.run_action(&directory, &inputs, &tree_destinations, &policy)?;
    assert_eq!(result.source, NativeBuildSource::Hit);
    assert_eq!(fs::read(generated.join("object.o"))?, fs::read(&reference)?);
    assert_eq!(fs::read(generated.join("input.s"))?, source_bytes);

    directory.outputs.get_mut("codegen").context("output")?.kind =
        sccache_build::OutputKind::GeneratedTree;
    fs::remove_dir_all(&generated)?;
    let result = client.run_action(&directory, &inputs, &tree_destinations, &policy)?;
    assert_eq!(result.source, NativeBuildSource::Worker(worker_address));
    assert_eq!(fs::read(generated.join("object.o"))?, fs::read(&reference)?);
    assert!(!generated.join("input.s").exists());
    fs::remove_dir_all(&generated)?;
    let result = client.run_action(&directory, &inputs, &tree_destinations, &policy)?;
    assert_eq!(result.source, NativeBuildSource::Hit);
    assert_eq!(fs::read(generated.join("object.o"))?, fs::read(&reference)?);
    assert_eq!(fs::read_dir(&generated)?.count(), 1);

    // A real compiler failure must be reported but never become a hit.
    let mut invalid = spec;
    invalid
        .command
        .arguments
        .push(b"--invalid-native-test-flag".to_vec());
    let NativeAdmission::Compile { ticket } = client.admit(&invalid)? else {
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
    let failed = client.run_action(&invalid, &inputs, &destinations, &policy)?;
    assert_eq!(failed.source, NativeBuildSource::Worker(worker_address));
    assert!(!failed.output.status.success());
    assert!(!failed.output.stderr.is_empty());
    let (scheduler_stats, worker_stats) = fleet.finish()?;
    assert_eq!(worker_stats.actions, 0);
    assert_eq!(scheduler_stats.actions, 4);
    assert_eq!(scheduler_stats.results, 3);
    assert_eq!(worker_stats.trees, 2);
    assert_eq!(scheduler_stats.trees, 2);
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
    fn start(root: &Path, fleet: &Fleet) -> Result<Self> {
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
for i in 1 2; do
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
    let fleet = Fleet::start(&root)?;
    let mut service = LocalService::start(&root, &fleet)?;
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
    let output = service
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
        .arg(&private)
        .arg(&visible)
        .arg("--chdir")
        .arg(&visible)
        .args([
            "--",
            "/bin/sh",
            "-c",
            compiler_script(),
            "namespace-test",
            env!("CARGO_BIN_EXE_sccache"),
            "/usr/bin/gcc",
        ])
        .arg(&rustc)
        .output()?;
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
    assert_eq!(stats.dist_errors, 0);
    assert!(private.join("build/probe.o").is_file());
    assert!(private.join("build/libprobe.rlib").is_file());
    assert!(!visible.join("build").exists());
    assert!(!root.join("unexpected-archive-cache").exists());
    assert!(!root.join("unexpected-toolchain-cache").exists());
    run_environment_audit(&service, &direct, &rustc, &direct_config)?;
    let stats = service.stats()?;
    assert_eq!(stats.dist_compiles.values().sum::<usize>(), 11);
    assert_eq!(stats.dist_errors, 0);
    let index = fleet.scheduler_directory.join("index.redb");
    service.stop()?;
    let (scheduler, worker) = fleet.finish()?;
    assert_eq!(scheduler.actions, 11);
    let unused = audit_index(&index, "environment/CARGO_NATIVE_AUDIT_UNUSED")?;
    assert_eq!(unused.equivalent_pairs, 1);
    assert_eq!(unused.conflicting_pairs, 0);
    let observed = audit_index(&index, "environment/NATIVE_AUDIT_OBSERVED")?;
    assert_eq!(observed.equivalent_pairs, 0);
    assert_eq!(observed.conflicting_pairs, 1);
    assert_eq!(unused.examined_actions, 11);
    eprintln!("actual Rust environment audit: {unused:?}; {observed:?}");
    assert_eq!(worker.actions, 0);
    Ok(())
}
