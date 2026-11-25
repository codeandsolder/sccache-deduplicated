//! Metadata-only, cross-executor digest memo. All bytes are read in the
//! credential-isolated executor. The root supervisor inspects only duplicated
//! open file descriptors, never a requester-supplied pathname.
use super::{frame, peer, read_sync_frame};
use crate::build_runtime::{
    BlobRef, ContentId, DescriptorDigestProvider, DescriptorMemo, hash_descriptor,
};
use anyhow::{Context, Result};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::MetadataExt, net::UnixStream},
    },
    sync::{Arc, Mutex},
};

pub(super) fn scope(peer: &peer::Peer) -> Result<ContentId> {
    let mount = peer.mount.metadata()?;
    let root = peer.root.metadata()?;
    let credentials = &peer.credentials;
    Ok(ContentId::of(&bincode::serialize(&(
        credentials.uid,
        credentials.gid,
        &credentials.groups,
        mount.dev(),
        mount.ino(),
        root.dev(),
        root.ino(),
    ))?))
}

pub(super) fn pidfd(pid: libc::pid_t) -> Result<OwnedFd> {
    // SAFETY: the parent owns the newly spawned child's PID until wait, and
    // pidfd_open returns a new owned descriptor for that process.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("open private executor pidfd");
    }
    // SAFETY: the successful syscall returned an owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(libc::c_int::try_from(fd)?) })
}

type Reply<T> = std::result::Result<T, String>;

fn reply<T: serde::Serialize>(stream: &mut UnixStream, result: Result<T>) -> Result<()> {
    stream.write_all(&frame(&result.map_err(|error| format!("{error:#}")))?)?;
    Ok(())
}

pub(super) fn serve(
    mut stream: UnixStream,
    pidfd: &OwnedFd,
    scope: ContentId,
    memo: &DescriptorMemo,
) -> Result<()> {
    let mut hits = 0_u64;
    let mut bytes = 0_u64;
    loop {
        let mut request = [0_u8; 4];
        if stream.read(&mut request[..1])? == 0 {
            break;
        }
        stream.read_exact(&mut request[1..])?;
        let probe = (|| {
            let file = File::from(peer::duplicate_fd(
                pidfd.as_fd(),
                i32::from_be_bytes(request),
            )?);
            let (probe, value) = memo.probe(scope, &file)?;
            Ok::<_, anyhow::Error>((file, probe, value))
        })();
        match probe {
            Ok((file, probe, value)) => {
                reply(&mut stream, Ok(value))?;
                if let Some(blob) = value {
                    hits = hits.saturating_add(1);
                    bytes = bytes.saturating_add(blob.size);
                } else {
                    // Hold the verified descriptor until publication. The
                    // executor hashes that same open file under its own UID.
                    let publication: Option<BlobRef> = read_sync_frame(&mut stream)?;
                    let result =
                        publication.map_or(Ok(()), |blob| memo.remember(probe, &file, blob));
                    reply(&mut stream, result)?;
                }
            }
            Err(error) => reply::<Option<BlobRef>>(&mut stream, Err(error))?,
        }
    }
    debug!("shared toolchain memo: reused {hits} files ({bytes} bytes)");
    Ok(())
}

pub(super) fn provider(stream: UnixStream) -> DescriptorDigestProvider {
    let stream = Mutex::new(Some(stream));
    Arc::new(move |file| {
        let mut guard = stream
            .lock()
            .map_err(|_| anyhow::anyhow!("descriptor memo channel poisoned"))?;
        let Some(stream) = guard.as_mut() else {
            return hash_descriptor(file);
        };
        let lookup = (|| {
            stream.write_all(&file.as_raw_fd().to_be_bytes())?;
            read_sync_frame::<Reply<Option<BlobRef>>>(stream)
        })();
        match lookup {
            Ok(Ok(Some(blob))) => return Ok(blob),
            Ok(Ok(None)) => (),
            Ok(Err(error)) => {
                debug!("shared toolchain memo unavailable for descriptor: {error}");
                return hash_descriptor(file);
            }
            Err(error) => {
                warn!("shared toolchain memo transport unavailable: {error:#}");
                *guard = None;
                return hash_descriptor(file);
            }
        }
        let digest = hash_descriptor(file);
        let publication = digest.as_ref().ok().copied();
        let acknowledgement = (|| {
            stream.write_all(&frame(&publication)?)?;
            read_sync_frame::<Reply<()>>(stream)
        })();
        match acknowledgement {
            Ok(Ok(())) => (),
            Ok(Err(error)) => return Err(anyhow::Error::msg(error)),
            Err(error) => {
                // The bytes were independently verified locally. Losing the
                // metadata-only memo cannot change their action identity.
                warn!("shared toolchain memo publication unavailable: {error:#}");
                *guard = None;
            }
        }
        digest
    })
}
