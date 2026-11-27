//! A signal may interrupt a syscall before any bytes are transferred.
//! Retry the syscall itself, not the accepted higher-level build request.
use std::io;

pub(crate) fn retry_interrupted<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match operation() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

#[cfg(test)]
#[test]
fn retries_only_interrupted_operations() {
    let mut calls = 0;
    let result = retry_interrupted(|| {
        calls += 1;
        if calls < 3 {
            Err(io::ErrorKind::Interrupted.into())
        } else {
            Ok(7)
        }
    });
    assert_eq!(result.unwrap(), 7);
    let result = retry_interrupted::<()>(|| Err(io::ErrorKind::PermissionDenied.into()));
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
}
