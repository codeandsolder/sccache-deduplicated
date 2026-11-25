//! The single-threaded trusted entry point drops privileges before decoding
//! the user's compile request or running any compiler-related code.
use super::{
    BROKER_FD, Credentials, ExecutorEvent, Job, MOUNT_FD, PIDNS_FD, ROOT_FD, STDIN_FD, frame,
    read_sync_frame,
};
use crate::cache::IpcStorage;
use crate::client::{ServerConnection, connection_task};
use crate::config::DistConfig;
use crate::jobserver::Client;
use crate::mock_command::ProcessCommandCreator;
use crate::protocol::{CompileFinished, CompileIdentity, CompileResponse, Request};
use crate::server::{SccacheService, WaitUntilZero, activity};
use anyhow::{Context, Result, bail, ensure};
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::sync::Arc;
use std::time::Duration;

fn checked(result: libc::c_int) -> io::Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn inherited(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl validates the inherited descriptor and prevents
    // accidental inheritance by any compiler or linker.
    checked(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
    // SAFETY: the private launcher owns these fixed descriptors.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_pidfd(pid: libc::pid_t) -> Result<OwnedFd> {
    // SAFETY: pid identifies the current process or its verified parent.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("open supervisor pidfd");
    }
    // SAFETY: pidfd_open returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(libc::c_int::try_from(fd)?) })
}

// The private launcher is still single-threaded. setns(CLONE_NEWPID)
// changes only the namespace of subsequently created children.
fn enter_pid_namespace(credentials: &Credentials, namespace: &OwnedFd) -> Result<OwnedFd> {
    let daemon_pid = i32::try_from(credentials.parent_pid)?;
    // SAFETY: only process-local queries and parent-death signal setup.
    unsafe {
        checked(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0))?;
        ensure!(libc::getppid() == daemon_pid, "shared daemon disappeared");
    }
    if !credentials.join_pid {
        return open_pidfd(daemon_pid);
    }
    // SAFETY: this is the current process, prior to fork.
    let supervisor = open_pidfd(unsafe { libc::getpid() })?;
    // SAFETY: a verified peer PID namespace, before any threads or runtime.
    let child = unsafe {
        checked(libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWPID))
            .context("enter requester PID namespace")?;
        libc::fork()
    };
    if child < 0 {
        return Err(io::Error::last_os_error()).context("fork namespace executor");
    }
    if child > 0 {
        supervise_child(child);
    }
    Ok(supervisor)
}

fn supervise_child(child: libc::pid_t) -> ! {
    // SAFETY: the single-threaded supervisor owns this child. Close every
    // inherited pipe/socket copy so only the executor can hold them open.
    // No Rust destructors or stdio operations run in this supervisor.
    unsafe {
        if libc::syscall(libc::SYS_close_range, 0_u32, u32::MAX, 0_u32) < 0 {
            libc::_exit(1);
        }
        let mut status = 0;
        loop {
            if libc::waitpid(child, &raw mut status, 0) == child {
                libc::_exit(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                });
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                libc::_exit(1);
            }
        }
    }
}

fn assume(
    credentials: &Credentials,
    mount: &OwnedFd,
    root: &OwnedFd,
    supervisor: &OwnedFd,
) -> Result<()> {
    // SAFETY: this entry point executes before constructing runtimes or
    // spawning threads. Both namespace descriptors come from the authenticated
    // peer, opened by the root daemon, not from user-controlled pathname data.
    unsafe {
        if credentials.join_mount {
            checked(libc::setns(mount.as_raw_fd(), libc::CLONE_NEWNS))
                .context("enter requester mount namespace")?;
        }
        checked(libc::fchdir(root.as_raw_fd()))?;
        checked(libc::chroot(c".".as_ptr()))?;
        checked(libc::chdir(c"/".as_ptr()))?;
        libc::umask(credentials.umask);
        checked(libc::setgroups(
            credentials.groups.len(),
            credentials.groups.as_ptr(),
        ))?;
        checked(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
        if credentials.uid != 0 {
            const NO_SETUID_FIXUP: libc::c_int = 1 << 2;
            // Do not inherit a service configuration that preserves root
            // capabilities across the UID transition.
            checked(libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0))?;
            let securebits = libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0);
            checked(securebits)?;
            ensure!(
                securebits & NO_SETUID_FIXUP == 0,
                "unsafe inherited securebits"
            );
            checked(libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ))?;
        }
        checked(libc::setresgid(
            credentials.gid,
            credentials.gid,
            credentials.gid,
        ))?;
        checked(libc::setresuid(
            credentials.uid,
            credentials.uid,
            credentials.uid,
        ))?;
        checked(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0))?;
        // Credential changes clear PDEATHSIG; arm it after dropping them.
        checked(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0))?;
        ensure!(
            super::peer::alive(supervisor.as_fd())?,
            "shared executor supervisor disappeared"
        );
    }
    Ok(())
}

async fn compile(
    job: Job,
    broker: UnixStream,
    #[cfg(feature = "dist-client")] digest_provider: crate::build_runtime::DescriptorDigestProvider,
) -> Result<CompileFinished> {
    let Job {
        activity_id: _,
        mut compile,
        aliases,
        toolchains,
        catalogs,
    } = job;
    // Use the attested real executable for both cacheable work and the
    // daemon-owned fallback; a strict launcher must not resubmit the job.
    compile.exe = aliases.resolve(compile.exe.into())?.into_os_string();
    let storage = IpcStorage::connect(ServerConnection::new(Box::new(broker))?).await?;
    let conn = storage.conn();
    let config = DistConfig {
        toolchains: serde_json::from_slice(&toolchains)?,
        native_installation_catalogs: catalogs,
        ..DistConfig::default()
    };
    #[cfg(feature = "dist-client")]
    let dist_client = storage.dist_client(&config, Some(digest_provider));
    #[cfg(not(feature = "dist-client"))]
    let dist_client = {
        drop(config);
        crate::server::DistClientContainer::new_disabled()
    };
    let jobserver = Client::new_num(1);
    let (tx, _rx) = futures::channel::mpsc::channel(1);
    let (_, info) = WaitUntilZero::new();
    let service = SccacheService::<ProcessCommandCreator>::new(
        dist_client,
        Arc::new(storage),
        &jobserver,
        tokio::runtime::Handle::current(),
        tx,
        info,
        aliases,
    );

    let (response, finished) = service.compile_direct(compile.clone()).await?;
    let result = match response {
        CompileResponse::CompileStarted => finished.context("accepted compile has no result"),
        CompileResponse::UnsupportedCompiler(exe) => {
            bail!("Compiler not supported: {}", exe.to_string_lossy())
        }
        CompileResponse::UnhandledCompile => {
            // The client must never execute this fallback. It runs here, in
            // the exact same credential and filesystem context as cache hits.
            activity::phase(activity::Phase::LocalCompile);
            let output = tokio::process::Command::new(&compile.exe)
                .args(&compile.args)
                .env_clear()
                .envs(compile.env_vars)
                .current_dir(&compile.cwd)
                .stdin(std::process::Stdio::inherit())
                .kill_on_drop(true)
                .output()
                .await?;
            Ok(CompileFinished {
                retcode: output.status.code(),
                signal: output.status.signal(),
                stdout: output.stdout,
                stderr: output.stderr,
                ..CompileFinished::default()
            })
        }
    };
    let stats = service.take_stats().await;
    connection_task(conn, move |conn| {
        conn.request(Request::RecordStats(Box::new(stats)))
    })
    .await?;
    result
}

pub(super) fn run() -> Result<()> {
    // SAFETY: geteuid has no preconditions; direct invocation by ordinary users
    // cannot turn this entry point into a privileged process.
    ensure!(
        // SAFETY: these credential queries have no pointer arguments.
        unsafe { libc::geteuid() == 0 && libc::getuid() == 0 },
        "shared executor must be launched by root daemon"
    );
    let broker = inherited(BROKER_FD)?;
    let mount = inherited(MOUNT_FD)?;
    let root = inherited(ROOT_FD)?;
    let pid_namespace = inherited(PIDNS_FD)?;
    let stdin = inherited(STDIN_FD)?;
    #[cfg(feature = "dist-client")]
    let digest = inherited(super::DIGEST_FD)?;
    let mut input = io::stdin().lock();
    let credentials: Credentials = read_sync_frame(&mut input)?;
    let supervisor = enter_pid_namespace(&credentials, &pid_namespace)?;
    drop(pid_namespace);
    assume(&credentials, &mount, &root, &supervisor)?;
    drop(supervisor);
    crate::util::initialize_shared_umask(credentials.umask)?;
    drop(mount);
    drop(root);
    // Only now is the user-provided compiler request decoded.
    let job: Job = read_sync_frame(&mut input)?;
    drop(input);
    // SAFETY: stdin is a live descriptor duplicated from the authenticated peer.
    checked(unsafe { libc::dup2(stdin.as_raw_fd(), libc::STDIN_FILENO) })?;
    drop(stdin);
    std::env::set_current_dir(&job.compile.cwd)?;
    for (key, value) in &job.compile.env_vars {
        // SAFETY: still single threaded, before constructing the runtime and
        // after irreversible privilege drop. Compiler discovery observes the
        // same environment as the requesting user.
        unsafe { std::env::set_var(key, value) };
    }
    let runtime = crate::util::new_client_runtime()?;
    runtime.block_on(report_compile(
        job,
        UnixStream::from(broker),
        &mut io::stdout().lock(),
        #[cfg(feature = "dist-client")]
        super::digests::provider(UnixStream::from(digest)),
    ))
}

async fn report_compile(
    job: Job,
    broker: UnixStream,
    output: &mut impl Write,
    #[cfg(feature = "dist-client")] digest_provider: crate::build_runtime::DescriptorDigestProvider,
) -> Result<()> {
    let activity = Arc::new(activity::Activity::new(
        job.activity_id.clone(),
        &CompileIdentity::from(&job.compile),
        activity::CompileOwner::Daemon,
    ));
    let work = activity::scope(
        &activity,
        compile(
            job,
            broker,
            #[cfg(feature = "dist-client")]
            digest_provider,
        ),
    );
    tokio::pin!(work);
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            result = &mut work => {
                output.write_all(&frame(&ExecutorEvent::Progress(activity.snapshot()))?)?;
                output.write_all(&frame(&ExecutorEvent::Finished(
                    result.map_err(|error| format!("{error:#}")),
                ))?)?;
                output.flush()?;
                return Ok(());
            }
            _ = ticker.tick() => {
                output.write_all(&frame(&ExecutorEvent::Progress(activity.snapshot()))?)?;
                output.flush()?;
            }
        }
    }
}
