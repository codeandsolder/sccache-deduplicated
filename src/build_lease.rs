//! Build-wide artifact lease and scratch filesystem lifecycle.
//! Compiler artifacts remain accessible until their last local reader exits;
//! the distributed action cache is their durable backing store.

use anyhow::{Context, Result, ensure};
use std::{
    env,
    fs::{self, File, OpenOptions, TryLockError},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Command,
};

const PREFIX: &str = "lease-";
const READY: &str = ".ready";

pub(crate) struct ScratchLease {
    path: PathBuf,
    lock: Option<File>,
}

fn open_directory(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

fn scratch_base() -> Result<PathBuf> {
    // SAFETY: geteuid is a side-effect-free query of the calling process.
    let uid = unsafe { libc::geteuid() };
    let base = env::temp_dir().join(format!("sccache-build-{uid}"));
    match fs::DirBuilder::new().mode(0o700).create(&base) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(&base)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid && metadata.mode().trailing_zeros() >= 6,
        "build scratch root must be a private directory owned by the caller"
    );
    Ok(base)
}

/// Reclaim only a published root with no live process holding its lease.
/// A lock on the directory itself also excludes other reapers.
fn reap(path: &Path) -> Result<bool> {
    let file = match open_directory(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Ok(false),
        Err(TryLockError::Error(error)) => return Err(error.into()),
    }
    if !path.join(READY).is_file() {
        return Ok(false);
    }
    let opened = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        named.is_dir() && (named.dev(), named.ino()) == (opened.dev(), opened.ino()),
        "build scratch directory changed during reclamation"
    );
    // A killed launcher closes the FUSE connection but may leave a dead
    // mountpoint. Only reclaim it after the inherited build lease is gone.
    let mount = path.join("intermediates");
    if fs::metadata(&mount).is_err_and(|error| error.raw_os_error() == Some(libc::ENOTCONN)) {
        ensure!(
            Command::new("fusermount3")
                .arg("-u")
                .arg(&mount)
                .status()?
                .success(),
            "could not detach expired build mount"
        );
    }
    fs::remove_dir_all(path)?;
    Ok(true)
}

impl ScratchLease {
    fn create(base: &Path) -> Result<Self> {
        for entry in fs::read_dir(base)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && entry.file_name().as_bytes().starts_with(PREFIX.as_bytes())
                && let Err(error) = reap(&entry.path())
            {
                log::warn!(
                    "could not reclaim build scratch {}: {error:#}",
                    entry.path().display()
                );
            }
        }
        let directory = tempfile::Builder::new().prefix(PREFIX).tempdir_in(base)?;
        let lock = open_directory(directory.path())?;
        lock.lock()?;
        // Publish only after taking the lock. A killed creator before this
        // point cannot have started a build or written any build intermediates.
        File::create_new(directory.path().join(READY))?;
        Ok(Self {
            path: directory.keep(),
            lock: Some(lock),
        })
    }

    #[cfg(feature = "dist-client")]
    fn wait_for_descendants(&mut self) -> Result<()> {
        drop(self.lock.take());
        let file = open_directory(&self.path)?;
        file.lock()?;
        self.lock = Some(file);
        Ok(())
    }

    pub(crate) fn inherit(&self, command: &mut Command) -> Result<()> {
        let fd = self
            .lock
            .as_ref()
            .context("closed build scratch lease")?
            .as_raw_fd();
        // SAFETY: the child hook performs only an async-signal-safe fcntl
        // on a live descriptor inherited from the parent; no allocations.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
    pub(crate) fn root(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchLease {
    fn drop(&mut self) {
        // Closing rather than explicitly unlocking preserves the shared
        // open-file-description lock in any remaining descendant.
        drop(self.lock.take());
        if let Err(error) = reap(&self.path) {
            log::warn!(
                "could not reclaim build scratch {}: {error:#}",
                self.path.display()
            );
        }
    }
}

/// Retain all intermediate artifacts in the existing daemon-owned content
/// store for the duration of a command or a whole native planning session.
#[cfg(feature = "dist-client")]
pub(crate) fn with_build_intermediates<T>(
    execute: impl FnOnce(&ScratchLease, &Path, crate::build_runtime::wire::Ticket) -> Result<T>,
) -> Result<T> {
    // The launcher owns the mount and one connection-owned retention
    // lease. It is not a compiler or another cache daemon.
    // Each active FUSE inode has a backing descriptor. Match the
    // inherited hard limit, rather than the shell's small soft limit.
    // SAFETY: rlimit is initialized by getrlimit before being read.
    unsafe {
        let mut limit = std::mem::zeroed::<libc::rlimit>();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) == -1 {
            return Err(std::io::Error::last_os_error()).context("query descriptor limit");
        }
        limit.rlim_cur = limit.rlim_max;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) == -1 {
            return Err(std::io::Error::last_os_error()).context("raise descriptor limit");
        }
    }
    let mut scratch = ScratchLease::create(&scratch_base()?)?;
    let mount = scratch.path.join("intermediates");
    let backing = scratch.path.join("namespace");
    let spool = scratch.path.join("spool");
    for path in [&mount, &backing, &spool] {
        fs::create_dir(path)?;
    }
    let (token, connection) = crate::dist::native::intermediate::open()?;
    let filesystem = crate::build_runtime::intermediate_fs::mount_intermediates(
        &mount,
        &backing,
        &spool,
        token,
        crate::dist::native::intermediate::content(),
    )
    .context("mount leased build intermediates")?;
    let result = execute(&scratch, &mount, token);
    scratch.wait_for_descendants()?;
    drop(filesystem);
    drop(connection);
    drop(scratch);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_roots_are_unique_and_reclaimed() -> Result<()> {
        let base = tempfile::tempdir()?;
        let first = ScratchLease::create(base.path())?;
        let path = first.path.clone();
        let second = ScratchLease::create(base.path())?;
        assert_ne!(path, second.path);
        assert!(!reap(&path)?);
        drop(first);
        assert!(!path.exists());
        let path = second.path.clone();
        drop(second);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn inherited_lease_prevents_reaping_after_parent_drops() -> Result<()> {
        let base = tempfile::tempdir()?;
        let scratch = ScratchLease::create(base.path())?;
        let path = scratch.path.clone();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "read value"]);
        command.stdin(std::process::Stdio::piped());
        scratch.inherit(&mut command)?;
        let mut child = command.spawn()?;
        drop(scratch);
        assert!(path.exists());
        assert!(!reap(&path)?);
        drop(child.stdin.take());
        child.wait()?;
        assert!(reap(&path)?);
        assert!(!path.exists());
        Ok(())
    }
}
