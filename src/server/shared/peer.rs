//! Snapshot the authenticated Unix peer, not any identity supplied in RPC data.
use super::Credentials;
use anyhow::{Context, Result, ensure};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use tokio::net::UnixStream;

pub struct Peer {
    pub(super) credentials: Credentials,
    pub(super) mount: File,
    pub(super) root: File,
    pub(super) stdin: OwnedFd,
    pub(super) pidfd: OwnedFd,
    pub(super) pid: u32,
}

fn socket_option(
    socket: BorrowedFd<'_>,
    option: libc::c_int,
    output: &mut [u8],
) -> io::Result<usize> {
    let mut len = libc::socklen_t::try_from(output.len()).map_err(io::Error::other)?;
    // SAFETY: output is writable for len bytes and the socket is borrowed.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            output.as_mut_ptr().cast(),
            &raw mut len,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(len as usize)
}

fn peer_pidfd(socket: BorrowedFd<'_>) -> Result<OwnedFd> {
    let mut bytes = [0_u8; size_of::<libc::c_int>()];
    let len = socket_option(socket, libc::SO_PEERPIDFD, &mut bytes)
        .context("shared daemon requires kernel SO_PEERPIDFD (Linux 6.5 or newer)")?;
    ensure!(len == bytes.len(), "invalid kernel peer pidfd size");
    let fd = libc::c_int::from_ne_bytes(bytes);
    ensure!(fd >= 0, "invalid kernel peer pidfd");
    // SAFETY: successful SO_PEERPIDFD returned a new descriptor owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn peer_groups(socket: BorrowedFd<'_>) -> Result<Vec<u32>> {
    // Linux NGROUPS_MAX is 65536. The kernel snapshots groups at connect.
    let mut bytes = vec![0_u8; 65536 * size_of::<libc::gid_t>()];
    let len = socket_option(socket, libc::SO_PEERGROUPS, &mut bytes)?;
    ensure!(
        len <= bytes.len() && len.is_multiple_of(size_of::<libc::gid_t>()),
        "invalid kernel peer group list"
    );
    bytes.truncate(len);
    Ok(bytes
        .as_chunks::<{ size_of::<libc::gid_t>() }>()
        .0
        .iter()
        .map(|bytes| libc::gid_t::from_ne_bytes(*bytes))
        .collect())
}

fn same_identity(a: &File, b: &File) -> io::Result<bool> {
    let a = a.metadata()?;
    let b = b.metadata()?;
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}

pub(super) fn alive(pidfd: BorrowedFd<'_>) -> io::Result<bool> {
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll references one initialized pollfd for this syscall.
    match unsafe { libc::poll(&raw mut poll, 1, 0) } {
        0 => Ok(true),
        -1 => Err(io::Error::last_os_error()),
        _ => Ok(false),
    }
}

pub(super) fn duplicate_fd(pidfd: BorrowedFd<'_>, fd: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: pidfd identifies a live process, and successful pidfd_getfd
    // returns a new owned CLOEXEC descriptor for the specified open file.
    let result = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = libc::c_int::try_from(result).map_err(io::Error::other)?;
    // SAFETY: the syscall returned an owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn stdin_fd(pidfd: BorrowedFd<'_>) -> Result<OwnedFd> {
    match duplicate_fd(pidfd, 0) {
        Ok(fd) => Ok(fd),
        Err(error) if error.raw_os_error() == Some(libc::EBADF) => {
            Ok(File::open("/dev/null")?.into())
        }
        Err(error) => {
            Err(error).context("cannot duplicate peer stdin; shared daemon requires CAP_SYS_PTRACE")
        }
    }
}

fn read_umask(proc: &Path) -> Result<u32> {
    let status = std::fs::read_to_string(proc.join("status"))?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))
        .context("kernel did not report peer umask")?;
    let mask = u32::from_str_radix(value.trim(), 8)?;
    ensure!(mask <= 0o777, "invalid peer umask");
    Ok(mask)
}

impl Peer {
    pub(crate) const fn uid(&self) -> u32 {
        self.credentials.uid
    }
    pub(crate) const fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn capture(
        socket: &UnixStream,
        allowed_uids: &std::collections::BTreeSet<u32>,
    ) -> Result<Self> {
        use std::os::fd::AsFd;
        let identity = socket.peer_cred()?;
        let uid = identity.uid();
        ensure!(
            uid == 0 || allowed_uids.contains(&uid),
            "unauthorized shared daemon UID"
        );
        let pid = u32::try_from(identity.pid().context("peer PID unavailable")?)?;
        ensure!(pid != 0, "peer PID is outside the daemon PID namespace");
        let pidfd = peer_pidfd(socket.as_fd())?;
        ensure!(alive(pidfd.as_fd())?, "peer exited");
        let proc = std::path::PathBuf::from(format!("/proc/{pid}"));
        let user = File::open(proc.join("ns/user"))?;
        let own_user = File::open("/proc/self/ns/user")?;
        ensure!(
            same_identity(&user, &own_user)?,
            "shared executor does not accept remapped user namespaces"
        );
        let mount = File::open(proc.join("ns/mnt"))?;
        let own_mount = File::open("/proc/self/ns/mnt")?;
        let join_mount = !same_identity(&mount, &own_mount)?;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(proc.join("root"))?;
        let credentials = Credentials {
            uid,
            gid: identity.gid(),
            groups: peer_groups(socket.as_fd())?,
            umask: read_umask(&proc)?,
            join_mount,
            parent_pid: std::process::id(),
        };
        let stdin = stdin_fd(pidfd.as_fd())?;
        // If /proc/PID was reused while opening the handles, the original
        // pidfd is now readable. Never use a replacement process's namespace.
        ensure!(
            alive(pidfd.as_fd())?,
            "peer exited while capturing execution context"
        );
        Ok(Self {
            credentials,
            mount,
            root,
            stdin,
            pidfd,
            pid,
        })
    }
}
