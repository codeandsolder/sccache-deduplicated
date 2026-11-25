//! Root-confined host path resolution for distributed builds and archive access.

use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

/// Whether ordinary symlinks may be followed inside the supplied root.
#[derive(Clone, Copy)]
pub enum Symlinks {
    WithinRoot,
    Deny,
}

// With RESOLVE_IN_ROOT, Linux may return EAGAIN when concurrent renames
// prevent it from proving that resolution remained inside the root. Retry
// the same constrained operation; never fall back to unrestricted lookup.
const RESOLUTION_ATTEMPTS: usize = 16;

fn retry_resolution<T>(mut resolve: impl FnMut() -> nix::Result<T>) -> nix::Result<T> {
    for _ in 1..RESOLUTION_ATTEMPTS {
        match resolve() {
            Err(Errno::EAGAIN) => {}
            result => return result,
        }
    }
    resolve()
}

/// Open a path relative to a supplied filesystem root, including absolute
/// symlink targets. Magic links are always forbidden.
///
/// # Errors
///
/// Returns the original filesystem error, including EAGAIN if containment
/// cannot be established after a bounded number of attempts.
pub fn open(root: &File, path: &Path, flags: OFlag, symlinks: Symlinks) -> io::Result<OwnedFd> {
    let mut resolve = ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS;
    if matches!(symlinks, Symlinks::Deny) {
        resolve |= ResolveFlag::RESOLVE_NO_SYMLINKS;
    }
    let how = OpenHow::new().flags(flags).resolve(resolve);
    retry_resolution(|| openat2(root, path, how)).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_resolution_races_are_retried() {
        let mut calls = 0;
        let result = retry_resolution(|| {
            calls += 1;
            if calls < 4 {
                Err(Errno::EAGAIN)
            } else {
                Ok(42)
            }
        });
        assert_eq!(result, Ok(42));
        assert_eq!(calls, 4);
    }

    #[test]
    fn persistent_races_and_hard_errors_remain_errors() {
        for (error, expected_calls) in [
            (Errno::EAGAIN, RESOLUTION_ATTEMPTS),
            (Errno::ELOOP, 1),
            (Errno::ENOENT, 1),
            (Errno::EXDEV, 1),
        ] {
            let mut calls = 0;
            let result = retry_resolution::<()>(|| {
                calls += 1;
                Err(error)
            });
            assert_eq!(result, Err(error));
            assert_eq!(calls, expected_calls);
        }
    }

    #[test]
    fn symlink_policy_is_preserved() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        std::fs::write(directory.path().join("file"), b"content")?;
        symlink("/file", directory.path().join("alias"))?;
        let root = File::open(directory.path())?;
        let flags = OFlag::O_RDONLY | OFlag::O_CLOEXEC;
        assert!(open(&root, Path::new("/alias"), flags, Symlinks::WithinRoot).is_ok());
        let denied = open(&root, Path::new("/alias"), flags, Symlinks::Deny).unwrap_err();
        assert_eq!(denied.raw_os_error(), Some(Errno::ELOOP as i32));
        assert!(open(&root, Path::new("/file"), flags, Symlinks::Deny).is_ok());
        Ok(())
    }
}
