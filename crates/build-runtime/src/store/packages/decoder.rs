//! Stream archive members once, with a bounded isolated decoder for service use.

use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
    process::{Command, Stdio},
    sync::{Mutex, mpsc},
    thread,
    time::Duration,
};

use super::PackagePolicy;
use crate::{PackageCompression, identity::encoding};
use anyhow::{Context, Result, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize};

pub(super) const MAX_MEMBER_PATH: usize = 4096;
const FRAME_LIMIT: u64 = 16 * 1024;

#[derive(Serialize, Deserialize)]
pub(super) struct ArchiveEntry {
    pub path: Vec<u8>,
    pub mode: u32,
    pub kind: EntryKind,
}

#[derive(Serialize, Deserialize)]
pub(super) enum EntryKind {
    Directory,
    File(u64),
    Symlink(Vec<u8>),
    Hardlink(Vec<u8>),
}

/// Specify the decoder trust boundary. Only the standalone decoder process
/// should parse untrusted compressed archives on a long-lived server.
#[derive(Clone, Copy)]
pub enum PackageDecoder<'a> {
    InProcess,
    Isolated {
        executable: &'a Path,
        memory_bytes: u64,
        timeout: Duration,
    },
}

impl PackageDecoder<'_> {
    pub(super) fn decode(
        self,
        reader: File,
        compression: PackageCompression,
        policy: PackagePolicy,
        consume: impl FnMut(ArchiveEntry, &mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        match self {
            Self::InProcess => decode(reader, compression, policy.max_tar_bytes, consume),
            Self::Isolated {
                executable,
                memory_bytes,
                timeout,
            } => decode_isolated(
                executable,
                reader,
                compression,
                policy,
                memory_bytes,
                timeout,
                consume,
            ),
        }
    }
}

/// Unlike `Read::take`, reaching the limit cannot masquerade as a valid end
/// of archive. Check one extra byte to distinguish an exact fit from overflow.
struct BoundedTar<R> {
    reader: R,
    remaining: u64,
}

impl<R: Read> Read for BoundedTar<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            return match self.reader.read(&mut [0])? {
                0 => Ok(0),
                _ => Err(io::Error::other("decoded tar byte limit exceeded")),
            };
        }
        let limit =
            usize::try_from(self.remaining.min(buffer.len() as u64)).map_err(io::Error::other)?;
        let count = self.reader.read(&mut buffer[..limit])?;
        self.remaining -= count as u64;
        Ok(count)
    }
}

fn decode(
    reader: impl Read,
    compression: PackageCompression,
    max_tar_bytes: u64,
    consume: impl FnMut(ArchiveEntry, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    match compression {
        PackageCompression::Tar => read_tar(reader, max_tar_bytes, consume),
        PackageCompression::Gzip => read_tar(
            flate2::read::MultiGzDecoder::new(reader),
            max_tar_bytes,
            consume,
        ),
        PackageCompression::Xz => read_tar(
            lzma_rust2::XzReader::new(reader, true),
            max_tar_bytes,
            consume,
        ),
    }
}

fn read_tar(
    reader: impl Read,
    max_tar_bytes: u64,
    mut consume: impl FnMut(ArchiveEntry, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    let mut archive = tar::Archive::new(BoundedTar {
        reader,
        remaining: max_tar_bytes,
    });
    for entry in archive.entries()? {
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        let metadata = ArchiveEntry {
            path: entry.path_bytes().into_owned(),
            mode: entry.header().mode()?,
            kind: if kind.is_dir() {
                EntryKind::Directory
            } else if kind.is_file() || kind.is_gnu_sparse() {
                EntryKind::File(entry.size())
            } else if kind.is_symlink() || kind.is_hard_link() {
                let target = entry
                    .link_name_bytes()
                    .context("missing archive link target")?
                    .into_owned();
                if kind.is_symlink() {
                    EntryKind::Symlink(target)
                } else {
                    EntryKind::Hardlink(target)
                }
            } else {
                anyhow::bail!("unsupported tar member type {kind:?}");
            },
        };
        consume(metadata, &mut entry)?;
    }
    // Validate checksums by reading to actual EOF, including padding.
    let mut reader = archive.into_inner();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        ensure!(
            buffer[..count].iter().all(|&byte| byte == 0),
            "unexpected bytes after tar end"
        );
    }
}

fn write_frame(writer: &mut impl Write, entry: Option<&ArchiveEntry>) -> Result<()> {
    let frame = encoding().with_limit(FRAME_LIMIT).serialize(&entry)?;
    writer.write_all(&u32::try_from(frame.len())?.to_le_bytes())?;
    writer.write_all(&frame)?;
    Ok(())
}

fn read_frame(reader: &mut impl Read) -> Result<Option<ArchiveEntry>> {
    let mut size = [0; 4];
    reader.read_exact(&mut size)?;
    let size = u32::from_le_bytes(size);
    ensure!(
        u64::from(size) <= FRAME_LIMIT,
        "oversized package decoder frame"
    );
    let mut frame = vec![0; usize::try_from(size)?];
    reader.read_exact(&mut frame)?;
    Ok(encoding().with_limit(FRAME_LIMIT).deserialize(&frame)?)
}

fn read_frames(
    reader: &mut impl Read,
    mut consume: impl FnMut(ArchiveEntry, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    while let Some(entry) = read_frame(reader)? {
        consume(entry, reader)?;
    }
    ensure!(
        reader.read(&mut [0])? == 0,
        "unexpected bytes after decoded package"
    );
    Ok(())
}

struct DecoderProcess(Mutex<std::process::Child>);

impl Drop for DecoderProcess {
    fn drop(&mut self) {
        let child = self
            .0
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(child.try_wait(), Ok(Some(_))) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct CancelDeadline(mpsc::Sender<()>);

impl Drop for CancelDeadline {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

fn decode_isolated(
    executable: &Path,
    reader: File,
    compression: PackageCompression,
    policy: PackagePolicy,
    memory_bytes: u64,
    timeout: Duration,
    consume: impl FnMut(ArchiveEntry, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    ensure!(
        memory_bytes > 0 && !timeout.is_zero(),
        "invalid package decoder resource limits"
    );
    let codec = match compression {
        PackageCompression::Tar => "tar",
        PackageCompression::Gzip => "gzip",
        PackageCompression::Xz => "xz",
    };
    let mut child = Command::new(executable)
        .env_clear()
        .arg("native-decode-package")
        .args(["--compression", codec])
        .arg("--max-tar-bytes")
        .arg(policy.max_tar_bytes.to_string())
        .arg("--memory-bytes")
        .arg(memory_bytes.to_string())
        .stdin(Stdio::from(reader))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut output = child
        .stdout
        .take()
        .context("missing package decoder stdout")?;
    let child = DecoderProcess(Mutex::new(child));
    let (finished, wait) = mpsc::channel();
    thread::scope(|scope| {
        let _cancel = CancelDeadline(finished);
        let child_ref = &child.0;
        let deadline = thread::Builder::new()
            .name("package-decode-deadline".into())
            .spawn_scoped(scope, move || {
                if wait.recv_timeout(timeout).is_err()
                    && let Ok(mut child) = child_ref.lock()
                {
                    let _ = child.kill();
                }
            });
        let result = match deadline {
            Ok(_) => read_frames(&mut output, consume),
            Err(error) => Err(error.into()),
        };
        drop(output);
        // Do not hold the lock across a blocking wait: a child that
        // closed stdout but has not exited still needs the deadline kill.
        let status = loop {
            let state = {
                let mut child = child
                    .0
                    .lock()
                    .map_err(|_| anyhow::anyhow!("package child lock poisoned"))?;
                if result.is_err() {
                    let _ = child.kill();
                }
                child.try_wait()
            }?;
            if let Some(status) = state {
                break status;
            }
            thread::sleep(Duration::from_millis(10));
        };
        result?;
        ensure!(status.success(), "isolated package decoder failed");
        Ok(())
    })
}

/// Entrypoint for the standalone archive decoder. The invoking process
/// supplies the verified archive descriptor on stdin and reads framed
/// metadata plus raw payload from stdout. No store is opened here.
///
/// # Errors
/// Returns an error on malformed archives, exceeded limits or failed pipes.
pub fn decode_package_process(
    compression: PackageCompression,
    max_tar_bytes: u64,
    memory_bytes: u64,
) -> Result<()> {
    use rustix::process::{Resource, Rlimit, setrlimit};
    ensure!(
        memory_bytes > 0 && max_tar_bytes > 0,
        "invalid package decoder bounds"
    );
    setrlimit(
        Resource::As,
        Rlimit {
            current: Some(memory_bytes),
            maximum: Some(memory_bytes),
        },
    )?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    let mut output = io::BufWriter::new(io::stdout().lock());
    decode(
        io::stdin().lock(),
        compression,
        max_tar_bytes,
        |entry, data| {
            let size = match &entry.kind {
                EntryKind::File(size) => *size,
                _ => 0,
            };
            write_frame(&mut output, Some(&entry))?;
            ensure!(
                io::copy(&mut data.take(size), &mut output)? == size,
                "truncated decoded package member"
            );
            Ok(())
        },
    )?;
    write_frame(&mut output, None)?;
    output.flush()?;
    Ok(())
}
