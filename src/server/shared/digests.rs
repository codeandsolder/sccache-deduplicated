//! Content-authenticated, cross-executor digest memo. All bytes are read in the
//! credential-isolated executor. The root supervisor inspects only duplicated
//! open file descriptors, never a requester-supplied pathname.
use super::{frame, peer, read_sync_frame};
use crate::build_runtime::{
    BlobRef, ContentId, DescriptorDigestProvider, DescriptorMemo, hash_descriptor,
};
use anyhow::{Result, ensure};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use std::{
    fs::File,
    io::{IoSlice, IoSliceMut, Write},
    mem::MaybeUninit,
    os::{
        fd::AsFd,
        unix::{fs::MetadataExt, net::UnixStream},
    },
    sync::{Arc, Mutex},
};

pub(super) fn scope(peer: &peer::Peer) -> Result<ContentId> {
    let mount = peer.mount.metadata()?;
    let root = peer.root.metadata()?;
    let pid = peer.pid_namespace.metadata()?;
    let credentials = &peer.credentials;
    Ok(ContentId::of(&bincode::serialize(&(
        credentials.uid,
        credentials.gid,
        &credentials.groups,
        mount.dev(),
        mount.ino(),
        root.dev(),
        root.ino(),
        pid.dev(),
        pid.ino(),
    ))?))
}

fn send_descriptor(stream: &UnixStream, file: &File) -> Result<()> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let descriptors = [file.as_fd()];
    ensure!(
        control.push(SendAncillaryMessage::ScmRights(&descriptors)),
        "descriptor control buffer full"
    );
    ensure!(
        sendmsg(
            stream,
            &[IoSlice::new(b"M")],
            &mut control,
            SendFlags::NOSIGNAL
        )? == 1,
        "incomplete descriptor message"
    );
    Ok(())
}

fn receive_descriptor(stream: &UnixStream) -> Result<Option<File>> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut marker = [0];
    let msg = recvmsg(
        stream,
        &mut [IoSliceMut::new(&mut marker)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut files = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(descriptors) = message {
            files.extend(descriptors.map(File::from));
        } else {
            anyhow::bail!("unexpected descriptor control message");
        }
    }
    ensure!(
        !msg.flags.contains(ReturnFlags::CTRUNC),
        "truncated descriptor message"
    );
    if msg.bytes == 0 {
        ensure!(files.is_empty(), "unexpected descriptor on EOF");
        return Ok(None);
    }
    ensure!(
        marker == *b"M" && files.len() == 1,
        "invalid descriptor message"
    );
    Ok(files.pop())
}

type Reply<T> = std::result::Result<T, String>;

fn reply<T: serde::Serialize>(stream: &mut UnixStream, result: Result<T>) -> Result<()> {
    stream.write_all(&frame(&result.map_err(|error| format!("{error:#}")))?)?;
    Ok(())
}

pub(super) fn serve(mut stream: UnixStream, scope: ContentId, memo: &DescriptorMemo) -> Result<()> {
    let mut hits = 0_u64;
    let mut bytes = 0_u64;
    while let Some(file) = receive_descriptor(&stream)? {
        let probe = memo
            .probe(scope, &file)
            .map(|(probe, value)| (file, probe, value));
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
                        publication.map_or(Ok(()), |blob| memo.remember(&probe, &file, blob));
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
            send_descriptor(stream, file)?;
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
                // immutable-content memo cannot change their action identity.
                warn!("shared toolchain memo publication unavailable: {error:#}");
                *guard = None;
            }
        }
        digest
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_transfer_preserves_identity_and_closes_on_exec() -> Result<()> {
        let (sender, receiver) = UnixStream::pair()?;
        let file = tempfile::tempfile()?;
        send_descriptor(&sender, &file)?;
        let received = receive_descriptor(&receiver)?.expect("descriptor missing");
        assert_eq!(received.metadata()?.ino(), file.metadata()?.ino());
        assert_eq!(received.metadata()?.dev(), file.metadata()?.dev());
        assert!(rustix::io::fcntl_getfd(&received)?.contains(rustix::io::FdFlags::CLOEXEC));
        drop(sender);
        assert!(receive_descriptor(&receiver)?.is_none());
        Ok(())
    }

    #[test]
    fn descriptor_transfer_rejects_missing_ancillary_data() -> Result<()> {
        let (mut sender, receiver) = UnixStream::pair()?;
        sender.write_all(b"M")?;
        assert!(receive_descriptor(&receiver).is_err());
        Ok(())
    }
}
