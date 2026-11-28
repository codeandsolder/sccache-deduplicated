//! Root-owned shared daemon; compiler work is delegated to a private child
//! which enters the peer's filesystem and irreversibly assumes its credentials.
#[cfg(feature = "dist-client")]
mod digests;
mod executor;
mod peer;
pub use peer::Peer;

use super::{Message, SccacheResponse, SccacheService, activity};
use crate::config::{CompilerAliases, Config, SharedDaemonConfig};
use crate::jobserver::Client;
use crate::mock_command::CommandCreatorSync;
use crate::protocol::{Compile, CompileFinished, CompileResponse, Response};
use anyhow::{Context, Result, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fs;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, chown};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HELPER_ARG: &str = "--internal-shared-executor";
const MAX_FRAME: usize = 8 * 1024 * 1024;
const BROKER_FD: libc::c_int = 3;
const MOUNT_FD: libc::c_int = 4;
const ROOT_FD: libc::c_int = 5;
const STDIN_FD: libc::c_int = 6;
const PIDNS_FD: libc::c_int = 8;
const PERMIT_FD: libc::c_int = 9;
#[cfg(feature = "dist-client")]
const DIGEST_FD: libc::c_int = 7;

#[derive(Serialize, Deserialize)]
struct Credentials {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    umask: u32,
    join_mount: bool,
    join_pid: bool,
    parent_pid: u32,
}

#[derive(Serialize, Deserialize)]
struct Job {
    activity_id: String,
    compile: Compile,
    aliases: CompilerAliases,
    // Tagged serde enums are not supported by bincode. These contain
    // administrator-approved toolchain mappings only, never scheduler auth.
    toolchains: Vec<u8>,
    catalogs: Vec<std::path::PathBuf>,
}

#[derive(Serialize, Deserialize)]
enum ExecutorEvent {
    Progress(Box<activity::CompileActivity>),
    Finished(std::result::Result<CompileFinished, String>),
}

pub(super) struct SharedExecutor {
    pub(super) policy: SharedDaemonConfig,
    jobserver: Client,
    executors: tokio::sync::Semaphore,
    aliases: CompilerAliases,
    toolchains: Vec<u8>,
    catalogs: Vec<std::path::PathBuf>,
    #[cfg(feature = "dist-client")]
    digest_memo: Arc<crate::build_runtime::DescriptorMemo>,
}

fn root_owned(metadata: &fs::Metadata) -> bool {
    metadata.uid() == 0 && metadata.mode() & 0o022 == 0
}

pub(super) fn for_listener(
    config: &Config,
    client: &Client,
    addr: &crate::net::SocketAddr,
) -> io::Result<Option<Arc<SharedExecutor>>> {
    if let Some(policy) = config.shared_daemon.clone() {
        if !addr.is_unix_path() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shared daemon requires a pathname Unix socket",
            ));
        }
        Ok(Some(Arc::new(
            SharedExecutor::new(config, policy, client.clone()).map_err(io::Error::other)?,
        )))
    } else {
        Ok(None)
    }
}

pub(super) fn prepare_listener(path: &Path) -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    ensure!(
        // SAFETY: these credential queries have no pointer arguments.
        unsafe { libc::geteuid() == 0 && libc::getuid() == 0 },
        "shared daemon must run as root"
    );
    let executable = fs::metadata("/proc/self/exe")?;
    ensure!(
        executable.is_file() && root_owned(&executable) && executable.mode() & 0o6000 == 0,
        "install a root-owned, non-writable sccache binary before enabling shared mode"
    );
    ensure!(
        path.is_absolute(),
        "shared daemon requires an absolute pathname socket"
    );
    let parent = path
        .parent()
        .context("shared socket has no parent")?
        .canonicalize()?;
    ensure!(
        path.parent() == Some(parent.as_path()),
        "shared socket parent must be canonical"
    );
    for ancestor in parent.ancestors() {
        let metadata = fs::metadata(ancestor)?;
        ensure!(
            metadata.is_dir() && root_owned(&metadata),
            "unsafe shared socket directory: {}",
            ancestor.display()
        );
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_socket() && metadata.uid() == 0,
                "refusing to remove an untrusted shared socket path"
            );
            match UnixStream::connect(path) {
                Ok(_) => return Err(io::Error::from(io::ErrorKind::AddrInUse).into()),
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(path)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub(super) fn secure_listener(path: &Path, policy: &SharedDaemonConfig) -> io::Result<()> {
    chown(path, Some(0), Some(policy.socket_gid))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))
}

fn duplicate_high(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    // SAFETY: fd is live; F_DUPFD_CLOEXEC returns a new descriptor.
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fcntl returned an owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(result) })
}

fn frame<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let body = bincode::serialize(value)?;
    ensure!(
        body.len() <= MAX_FRAME,
        "shared executor frame exceeds limit"
    );
    let mut bytes = Vec::with_capacity(body.len() + 4);
    bytes.extend_from_slice(&u32::try_from(body.len())?.to_be_bytes());
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

fn decode_frame<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}

fn read_sync_frame<T: DeserializeOwned>(input: &mut impl Read) -> Result<T> {
    let mut length = [0_u8; 4];
    input.read_exact(&mut length)?;
    let len = u32::from_be_bytes(length) as usize;
    ensure!(len <= MAX_FRAME, "shared executor input exceeds limit");
    let mut data = vec![0; len];
    input.read_exact(&mut data)?;
    decode_frame(&data)
}

async fn read_result(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    activity: &activity::Activity,
) -> Result<CompileFinished> {
    loop {
        let len = reader.read_u32().await? as usize;
        ensure!(len <= MAX_FRAME, "shared executor result exceeds limit");
        let mut bytes = vec![0; len];
        reader.read_exact(&mut bytes).await?;
        match decode_frame(&bytes)? {
            ExecutorEvent::Progress(sample) => activity.observe_executor(*sample)?,
            ExecutorEvent::Finished(result) => return result.map_err(anyhow::Error::msg),
        }
    }
}

// On cancellation, kill the private process group while the child PID is
// still owned by the caller. No root daemon threads change credentials.
struct GroupGuard(Option<i32>);
impl Drop for GroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            // SAFETY: pid is the positive ID of our private process group;
            // a negative ID targets only that group.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
    }
}

impl SharedExecutor {
    pub(super) fn new(
        config: &Config,
        policy: SharedDaemonConfig,
        jobserver: Client,
    ) -> Result<Self> {
        ensure!(
            !config.client_side_mode
                && config
                    .dist
                    .native
                    .as_ref()
                    .is_none_or(|native| native.local_execution.is_none()),
            "shared daemon requires credential-isolated execution"
        );
        let capacity = policy.max_executors.map_or_else(
            || jobserver.capacity().saturating_mul(3).max(1),
            std::num::NonZeroUsize::get,
        );
        ensure!(
            capacity <= tokio::sync::Semaphore::MAX_PERMITS,
            "shared executor limit exceeds semaphore capacity"
        );
        Ok(Self {
            policy,
            jobserver,
            executors: tokio::sync::Semaphore::new(capacity),
            aliases: config.compiler_aliases.clone(),
            toolchains: serde_json::to_vec(&config.dist.toolchains)?,
            catalogs: config.dist.native_installation_catalogs.clone(),
            #[cfg(feature = "dist-client")]
            digest_memo: Arc::default(),
        })
    }

    pub(super) fn response<C>(
        self: Arc<Self>,
        service: SccacheService<C>,
        peer: Arc<Peer>,
        compile: Compile,
    ) -> SccacheResponse
    where
        C: CommandCreatorSync + Clone + Send + Sync + 'static,
    {
        Message::WithBody(
            Response::Compile(CompileResponse::CompileStarted),
            Box::pin(async move {
                self.execute(service, peer, compile)
                    .await
                    .map(Response::CompileFinished)
            }),
        )
    }

    async fn execute<C>(
        &self,
        service: SccacheService<C>,
        peer: Arc<Peer>,
        compile: Compile,
    ) -> Result<CompileFinished>
    where
        C: CommandCreatorSync + Clone + Send + Sync + 'static,
    {
        // Bound outstanding executors separately from physical compiler work.
        let activity = activity::current().context("missing shared compile activity")?;
        let waiting = activity::ChildActivity::waiting();
        let _slot = self.executors.acquire().await?;
        drop(waiting);
        ensure!(peer::alive(peer.pidfd.as_fd())?, "compile requester exited");
        let (broker, helper) = UnixStream::pair()?;
        let (permit_broker, permit_helper) = UnixStream::pair()?;
        #[cfg(feature = "dist-client")]
        let (digest_broker, digest_helper) = UnixStream::pair()?;
        let descriptors = [
            (duplicate_high(helper.as_fd())?, BROKER_FD),
            (duplicate_high(peer.mount.as_fd())?, MOUNT_FD),
            (duplicate_high(peer.root.as_fd())?, ROOT_FD),
            (duplicate_high(peer.stdin.as_fd())?, STDIN_FD),
            (duplicate_high(permit_helper.as_fd())?, PERMIT_FD),
            (duplicate_high(peer.pid_namespace.as_fd())?, PIDNS_FD),
            #[cfg(feature = "dist-client")]
            (duplicate_high(digest_helper.as_fd())?, DIGEST_FD),
        ];
        let mut command = std::process::Command::new("/proc/self/exe");
        command
            .arg(HELPER_ARG)
            .current_dir("/")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .process_group(0);
        // SAFETY: the closure runs after fork in the child, using only dup2
        // on live descriptors with disjoint source and destination numbers.
        unsafe {
            command.pre_exec(move || {
                for (source, target) in &descriptors {
                    if libc::dup2(source.as_raw_fd(), *target) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = tokio::process::Command::from(command)
            .kill_on_drop(true)
            .spawn()?;
        let pid = i32::try_from(child.id().context("missing executor PID")?)?;
        let mut group = GroupGuard(Some(pid));
        drop(helper);
        drop(permit_helper);
        let permit_task = crate::util::spawn(crate::jobserver::remote::serve(
            permit_broker,
            self.jobserver.clone(),
        ));
        #[cfg(feature = "dist-client")]
        let digest_task = {
            drop(digest_helper);
            let scope = digests::scope(&peer)?;
            let memo = Arc::clone(&self.digest_memo);
            tokio::task::spawn_blocking(move || digests::serve(digest_broker, scope, &memo))
        };
        broker.set_nonblocking(true)?;
        let broker = tokio::net::UnixStream::from_std(broker)?;
        let broker_task = crate::util::spawn(service.bind_with_role(
            broker,
            super::ConnectionRole::PrivateExecutor { uid: peer.uid() },
        ));

        let mut input = child.stdin.take().context("missing executor input")?;
        let job = Job {
            activity_id: activity.snapshot().id,
            compile,
            aliases: self.aliases.clone(),
            toolchains: self.toolchains.clone(),
            catalogs: self.catalogs.clone(),
        };
        input.write_all(&frame(&peer.credentials)?).await?;
        input.write_all(&frame(&job)?).await?;
        input.shutdown().await?;
        drop(input);
        let mut output = child.stdout.take().context("missing executor output")?;
        let result = read_result(&mut output, &activity).await?;
        let status = child.wait().await?;
        group.0 = None;
        // Wait until the private connection has closed, including pending stats.
        broker_task.await??;
        permit_task.await??;
        #[cfg(feature = "dist-client")]
        digest_task.await??;
        ensure!(status.success(), "shared executor exited with {status}");
        Ok(result)
    }
}

pub fn run_if_requested() -> Option<Result<()>> {
    let mut args = std::env::args_os().skip(1);
    if args.next().is_some_and(|arg| arg == HELPER_ARG) {
        Some(executor::run())
    } else {
        None
    }
}
