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

use anyhow::{Result, ensure};
use sccache::{
    build_runtime::{
        BuildPath, CommandSpec, ContentId, ExecutionSpec, NativeStore, OutputSpec, SpacePolicy,
        TreePath,
        wire::{NativeAdmission, NativeRunResult, NativeStatus, ScheduleReply},
    },
    config::{HTTPUrl, scheduler, server},
    dist::{SchedulerStatusResult, native::NativeCacheClient, pkg::ToolchainPackageBuilder},
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

#[test]
#[ignore = "requires Linux Bubblewrap, GNU assembler and ldd"]
fn native_worker_https_executes_real_assembler_and_reuses_result() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
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
                idle_timeout_secs: 30,
                max_sessions: 32,
                max_result_bytes: 16 * 1024 * 1024,
                max_result_blobs: 16,
                max_tree_bytes: 256 * 1024 * 1024,
                max_tree_blobs: 512,
                max_concurrent_uploads: 2,
                max_total_uploads: 4,
                http_threads: 8,
                max_metadata_bytes: 1024 * 1024,
            }),
        },
    )?;
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let status_url = scheduler_url.join("/api/v1/scheduler/status")?;
    let status = || -> Result<SchedulerStatusResult> {
        Ok(http
            .get(status_url.clone())
            .header("Accept", "application/json")
            .send()?
            .error_for_status()?
            .json()?)
    };
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
            scheduler_url: HTTPUrl::from_url(scheduler_url),
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
                request_timeout_secs: 10,
                execution_timeout_secs: 10,
                max_result_bytes: 16 * 1024 * 1024,
                max_metadata_bytes: 1024 * 1024,
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
    let sender = NativeStore::open(&root.join("sender"))?;
    let mut discovery = ToolchainPackageBuilder::new();
    discovery.add_executable_and_deps("/usr/bin/as".into())?;
    let mut mapping = discovery.into_native_mapping()?;
    mapping.add_directory(TreePath::new(b"src".to_vec())?)?;
    let root_tree = mapping.capture(&sender)?;
    let source_tree = sender.capture_tree(&source_dir)?;
    let root_pin = client.push_tree(&root_tree)?;
    let source_pin = client.push_tree(&source_tree)?;
    let spec = ExecutionSpec {
        platform: ContentId::of(PLATFORM.as_bytes()),
        root: root_tree.id(),
        mounts: BTreeMap::from([(BuildPath::new(b"/src".to_vec())?, source_tree.id())]),
        command: CommandSpec {
            executable: BuildPath::new(b"/usr/bin/as".to_vec())?,
            arguments: [b"-o".as_slice(), b"/out/object.o", b"/src/input.s"]
                .map(<[u8]>::to_vec)
                .to_vec(),
            cwd: BuildPath::new(b"/src".to_vec())?,
            environment: BTreeMap::new(),
        },
        outputs: BTreeMap::from([(
            "object".into(),
            OutputSpec {
                path: TreePath::new(b"object.o".to_vec())?,
                required: true,
            },
        )]),
    };
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
    client.download(ticket, manifest.outputs["object"].blob, &mut bytes)?;
    assert_eq!(bytes, fs::read(&reference)?);
    client.close(ticket)?;
    let NativeAdmission::Hit {
        ticket: hit,
        manifest: cached,
    } = client.admit(&spec)?
    else {
        anyhow::bail!("expected cache hit");
    };
    assert_eq!(cached, manifest);
    client.close(hit)?;
    assert_eq!(status()?.in_progress, 0);

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
    assert!(matches!(
        client.admit(&invalid)?,
        NativeAdmission::Compile { .. }
    ));
    drop(worker_process);
    drop(scheduler_process);
    assert_eq!(NativeStore::open(&worker_directory)?.stats()?.actions, 0);
    assert_eq!(NativeStore::open(&scheduler_directory)?.stats()?.actions, 1);
    Ok(())
}
