//! The single-threaded trusted entry point drops privileges before decoding
//! the user's compile request or running any compiler-related code.
use super::{
    BROKER_FD, Credentials, Job, MAX_FRAME, MOUNT_FD, ROOT_FD, STDIN_FD, decode_frame, frame,
};
use crate::cache::IpcStorage;
use crate::client::{ServerConnection, connection_task};
use crate::config::DistConfig;
use crate::jobserver::Client;
use crate::mock_command::ProcessCommandCreator;
use crate::protocol::{CompileFinished, CompileResponse, Request};
use crate::server::{SccacheService, WaitUntilZero};
use anyhow::{Context, Result, bail, ensure};
use serde::de::DeserializeOwned;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::sync::Arc;

fn read_frame<T: DeserializeOwned>(input: &mut impl Read) -> Result<T> {
    let mut length = [0_u8; 4];
    input.read_exact(&mut length)?;
    let len = u32::from_be_bytes(length) as usize;
    ensure!(len <= MAX_FRAME, "shared executor input exceeds limit");
    let mut data = vec![0; len];
    input.read_exact(&mut data)?;
    decode_frame(&data)
}

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

fn assume(credentials: &Credentials, mount: &OwnedFd, root: &OwnedFd) -> Result<()> {
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
            // Do not inherit a service configuration that preserves root
            // capabilities across the UID transition.
            checked(libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0))?;
            let securebits = libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0);
            checked(securebits)?;
            const NO_SETUID_FIXUP: libc::c_int = 1 << 2;
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
            libc::getppid() == i32::try_from(credentials.parent_pid)?,
            "shared daemon disappeared"
        );
    }
    Ok(())
}

async fn compile(job: Job, broker: UnixStream) -> Result<CompileFinished> {
    let Job {
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
    let dist_client = storage.dist_client(&config);
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
        unsafe { libc::geteuid() == 0 && libc::getuid() == 0 },
        "shared executor must be launched by root daemon"
    );
    let broker = inherited(BROKER_FD)?;
    let mount = inherited(MOUNT_FD)?;
    let root = inherited(ROOT_FD)?;
    let stdin = inherited(STDIN_FD)?;
    let mut input = io::stdin().lock();
    let credentials: Credentials = read_frame(&mut input)?;
    assume(&credentials, &mount, &root)?;
    drop(mount);
    drop(root);
    // Only now is the user-provided compiler request decoded.
    let job: Job = read_frame(&mut input)?;
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
    let result = runtime
        .block_on(compile(job, UnixStream::from(broker)))
        .map_err(|error| format!("{error:#}"));
    io::stdout().lock().write_all(&frame(&result)?)?;
    Ok(())
}
