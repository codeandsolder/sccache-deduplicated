//! Immutable, seekable compressed CAS payloads. Blob identity always hashes decoded bytes.
//! Original upstream archives can retain their exact source bytes without an envelope.
#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

use anyhow::{Context, Result, ensure};

use crate::{BlobRef, ContentId};

const MAGIC: [u8; 16] = *b"SC-CAS-ZSTD-0002";
const CHUNK: usize = 256 * 1024;
const HEADER: u64 = 32;
const RAW_CHUNK: u32 = 1 << 31;

/// A CAS entry's physical format, recorded in the index independently of its content hash.
/// Original upstream package archives are raw even if they begin with the encoded-file magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlobEncoding {
    Raw = 0,
    ZstdChunks = 1,
}

impl BlobEncoding {
    #[must_use = "the receiver requires the physical encoding to decode transferred CAS bytes"]
    pub const fn http_value(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::ZstdChunks => "zstd-chunks",
        }
    }

    /// Decode the representation descriptor returned by the native CAS server.
    ///
    /// # Errors
    /// Returns an error for unsupported or absent physical formats.
    pub fn from_http_value(value: &str) -> Result<Self> {
        match value {
            "raw" => Ok(Self::Raw),
            "zstd-chunks" => Ok(Self::ZstdChunks),
            _ => anyhow::bail!("unsupported CAS physical format: {value}"),
        }
    }
}

impl TryFrom<u8> for BlobEncoding {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Raw),
            1 => Ok(Self::ZstdChunks),
            _ => anyhow::bail!("unknown CAS physical encoding: {value}"),
        }
    }
}

#[derive(Clone, Copy)]
struct Part {
    offset: u64,
    stored: usize,
    plain: usize,
    compressed: bool,
}

/// An individually addressable raw-content blob; compressed parts are independent
/// Zstandard frames and raw parts avoid expansion for incompressible inputs.
pub struct BlobReader {
    file: File,
    parts: Vec<Part>,
    plain_len: u64,
    encoded: bool,
    position: u64,
    current: Option<(usize, Vec<u8>)>,
}

fn transfer_at(
    length: usize,
    mut offset: u64,
    short: io::ErrorKind,
    mut transfer: impl FnMut(usize, u64) -> io::Result<usize>,
) -> io::Result<()> {
    let mut done = 0;
    while done < length {
        match transfer(done, offset) {
            Ok(0) => return Err(short.into()),
            Ok(n) => {
                done += n;
                offset = offset
                    .checked_add(n as u64)
                    .ok_or(io::ErrorKind::InvalidInput)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<()> {
    transfer_at(
        buffer.len(),
        offset,
        io::ErrorKind::UnexpectedEof,
        |done, offset| {
            #[cfg(unix)]
            {
                file.read_at(&mut buffer[done..], offset)
            }
            #[cfg(windows)]
            {
                file.seek_read(&mut buffer[done..], offset)
            }
            #[cfg(not(any(unix, windows)))]
            {
                let mut cloned = file.try_clone()?;
                cloned.seek(SeekFrom::Start(offset))?;
                cloned.read(&mut buffer[done..])
            }
        },
    )
}

fn write_at(file: &File, bytes: &[u8], offset: u64) -> io::Result<()> {
    transfer_at(
        bytes.len(),
        offset,
        io::ErrorKind::WriteZero,
        |done, offset| {
            #[cfg(unix)]
            {
                file.write_at(&bytes[done..], offset)
            }
            #[cfg(windows)]
            {
                file.seek_write(&bytes[done..], offset)
            }
            #[cfg(not(any(unix, windows)))]
            {
                let mut cloned = file.try_clone()?;
                cloned.seek(SeekFrom::Start(offset))?;
                cloned.write(&bytes[done..])
            }
        },
    )
}

impl BlobReader {
    /// Open a CAS object using its explicit physical encoding from the durable index.
    ///
    /// # Errors
    /// Returns an error if the on-disk file or its chunk directory is malformed.
    pub fn open(file: File, encoding: BlobEncoding) -> Result<Self> {
        let stored_len = file.metadata()?.len();
        if encoding == BlobEncoding::Raw {
            return Ok(Self {
                file,
                parts: Vec::new(),
                plain_len: stored_len,
                encoded: false,
                position: 0,
                current: None,
            });
        }
        ensure!(stored_len >= HEADER, "truncated encoded CAS header");
        let mut marker = [0u8; 16];
        read_at(&file, &mut marker, 0)?;
        ensure!(marker == MAGIC, "invalid encoded CAS marker");
        let mut header = [0u8; 16];
        read_at(&file, &mut header, 16)?;
        let plain_len = u64::from_le_bytes(header[..8].try_into()?);
        let chunk_size = u32::from_le_bytes(header[8..12].try_into()?);
        let count = u32::from_le_bytes(header[12..].try_into()?);
        ensure!(
            stored_len >= HEADER && u64::from(count) <= (stored_len - HEADER) / 9,
            "CAS chunk index exceeds physical payload bounds"
        );
        ensure!(chunk_size as usize == CHUNK, "CAS chunk size mismatch");
        ensure!(
            u64::from(count) == plain_len.div_ceil(CHUNK as u64),
            "CAS chunk count mismatch"
        );
        let mut offset = HEADER;
        let mut parts = Vec::with_capacity(usize::try_from(count)?);
        let mut decoded = 0_u64;
        for _ in 0..count {
            let mut widths = [0_u8; 8];
            read_at(&file, &mut widths, offset)?;
            let word = u32::from_le_bytes(widths[..4].try_into()?);
            let stored = usize::try_from(word & !RAW_CHUNK)?;
            let plain = usize::try_from(u32::from_le_bytes(widths[4..].try_into()?))?;
            let compressed = word & RAW_CHUNK == 0;
            // Logical seeking divides by CHUNK; every chunk except the last
            // must therefore cover exactly CHUNK decoded bytes.
            let remaining = plain_len
                .checked_sub(decoded)
                .context("CAS chunk position exceeds content")?;
            ensure!(
                plain == usize::try_from(remaining.min(CHUNK as u64))?,
                "noncanonical CAS chunk position"
            );
            ensure!(
                stored > 0
                    && stored <= zstd::zstd_safe::compress_bound(CHUNK)
                    && plain > 0
                    && plain <= CHUNK
                    && (compressed || stored == plain),
                "invalid CAS chunk lengths"
            );
            offset = offset.checked_add(8).context("CAS chunk offset overflow")?;
            parts.push(Part {
                offset,
                stored,
                plain,
                compressed,
            });
            offset = offset
                .checked_add(u64::try_from(stored)?)
                .context("CAS chunk size overflow")?;
            decoded = decoded
                .checked_add(u64::try_from(plain)?)
                .context("CAS content size overflow")?;
        }
        ensure!(
            decoded == plain_len && offset == stored_len,
            "CAS payload length mismatch"
        );
        Ok(Self {
            file,
            parts,
            plain_len,
            encoded: true,
            position: 0,
            current: None,
        })
    }

    #[must_use = "the decoded length must be validated against the logical CAS reference"]
    pub const fn len(&self) -> u64 {
        self.plain_len
    }

    #[must_use = "empty logical files are handled without attempting to load a chunk"]
    pub const fn is_empty(&self) -> bool {
        self.plain_len == 0
    }

    #[must_use = "the caller must not expose encoded physical bytes as logical content"]
    pub const fn is_encoded(&self) -> bool {
        self.encoded
    }

    fn chunk(&mut self, idx: usize) -> io::Result<&[u8]> {
        if self
            .current
            .as_ref()
            .is_none_or(|(current, _)| *current != idx)
        {
            let part = self
                .parts
                .get(idx)
                .ok_or_else(|| io::Error::other("invalid chunk index"))?;
            let mut physical = vec![0; part.stored];
            read_at(&self.file, &mut physical, part.offset)?;
            let bytes = if part.compressed {
                zstd::bulk::decompress(&physical, part.plain).map_err(io::Error::other)?
            } else {
                physical
            };
            if bytes.len() != part.plain {
                return Err(io::Error::other("CAS decoded chunk length mismatch"));
            }
            self.current = Some((idx, bytes));
        }
        Ok(&self
            .current
            .as_ref()
            .ok_or_else(|| io::Error::other("missing decoded chunk"))?
            .1)
    }
}

impl Read for BlobReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.plain_len {
            return Ok(0);
        }
        let n = usize::try_from((self.plain_len - self.position).min(buf.len() as u64))
            .map_err(io::Error::other)?;
        if self.parts.is_empty() {
            read_at(&self.file, &mut buf[..n], self.position)?;
            self.position += n as u64;
            return Ok(n);
        }
        let mut written = 0;
        while written < n {
            let idx = usize::try_from(self.position / CHUNK as u64).map_err(io::Error::other)?;
            let offset = usize::try_from(self.position % CHUNK as u64).map_err(io::Error::other)?;
            let chunk = self.chunk(idx)?;
            let count = (n - written).min(chunk.len().saturating_sub(offset));
            if count == 0 {
                return Err(io::Error::other("invalid CAS chunk seek"));
            }
            buf[written..written + count].copy_from_slice(&chunk[offset..offset + count]);
            self.position += count as u64;
            written += count;
        }
        Ok(written)
    }
}

impl Seek for BlobReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::End(n) => i128::from(self.plain_len) + i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
        };
        self.position = u64::try_from(target)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid CAS offset"))?;
        Ok(self.position)
    }
}

/// Store original bytes while hashing them. Native ZFS compression operates
/// below the file API, with no application-level frame overhead.
///
/// # Errors
/// Returns an error if the stream fails or exceeds the stated bound.
pub fn encode_raw(mut reader: impl Read, target: &mut File, bound: Option<u64>) -> Result<BlobRef> {
    let mut digest = blake3::Hasher::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if count == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(count)?)
            .context("raw CAS size overflow")?;
        if let Some(bound) = bound {
            ensure!(size <= bound, "raw CAS input exceeds declared size");
        }
        target.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
    }
    Ok(BlobRef {
        id: ContentId(*digest.finalize().as_bytes()),
        size,
    })
}

fn write_encoded_chunk(file: &mut impl Write, bytes: &[u8]) -> Result<()> {
    let encoded = zstd::bulk::compress(bytes, 1)?;
    let (physical, raw) = if encoded.len() < bytes.len() {
        (encoded.as_slice(), false)
    } else {
        (bytes, true)
    };
    let stored = u32::try_from(physical.len())?;
    file.write_all(&(stored | if raw { RAW_CHUNK } else { 0 }).to_le_bytes())?;
    file.write_all(&u32::try_from(bytes.len())?.to_le_bytes())?;
    file.write_all(physical)?;
    Ok(())
}

fn write_encoded_header(file: &mut File, size: u64, chunks: u32) -> Result<()> {
    write_at(file, &size.to_le_bytes(), 16)?;
    write_at(file, &u32::try_from(CHUNK)?.to_le_bytes(), 24)?;
    write_at(file, &chunks.to_le_bytes(), 28)?;
    Ok(())
}

fn validate_transport_header(header: &[u8; 32], expected: BlobRef) -> Result<u32> {
    ensure!(
        header[..16] == MAGIC,
        "native content stream is not the compressed CAS format"
    );
    let size = u64::from_le_bytes(header[16..24].try_into()?);
    let chunk = u32::from_le_bytes(header[24..28].try_into()?);
    let count = u32::from_le_bytes(header[28..].try_into()?);
    ensure!(
        size == expected.size
            && chunk as usize == CHUNK
            && u64::from(count) == size.div_ceil(CHUNK as u64),
        "invalid native content stream declaration"
    );
    Ok(count)
}

#[derive(Clone, Copy)]
struct ChunkWidths {
    stored: usize,
    plain: usize,
    raw: bool,
}

fn validate_transport_widths(widths: &[u8; 8], remaining: u64) -> Result<ChunkWidths> {
    let word = u32::from_le_bytes(widths[..4].try_into()?);
    let stored = usize::try_from(word & !RAW_CHUNK)?;
    let plain = usize::try_from(u32::from_le_bytes(widths[4..].try_into()?))?;
    let raw = word & RAW_CHUNK != 0;
    ensure!(
        plain == usize::try_from(remaining.min(CHUNK as u64))?,
        "noncanonical transported CAS chunk position"
    );
    ensure!(
        stored > 0
            && stored <= zstd::zstd_safe::compress_bound(CHUNK)
            && plain > 0
            && plain <= CHUNK
            && (!raw || stored == plain),
        "native CAS chunk exceeds bounds"
    );
    Ok(ChunkWidths { stored, plain, raw })
}

fn decode_transport_chunk(data: &[u8], widths: ChunkWidths) -> Result<std::borrow::Cow<'_, [u8]>> {
    let bytes = if widths.raw {
        std::borrow::Cow::Borrowed(data)
    } else {
        std::borrow::Cow::Owned(zstd::bulk::decompress(data, widths.plain)?)
    };
    ensure!(bytes.len() == widths.plain, "invalid native decoded chunk");
    Ok(bytes)
}

#[cfg(unix)]
mod ingest;
#[cfg(unix)]
pub(crate) use ingest::BlobIngest;

/// Write one immutable compressed representation while hashing its logical
/// content. This is one compression pass with bounded buffering.
///
/// # Errors
/// Returns an error for input/output failure, excessive content, or an encoding error.
pub fn encode(mut reader: impl Read, file: &mut File, bound: Option<u64>) -> Result<BlobRef> {
    file.write_all(&MAGIC)?;
    file.write_all(&[0_u8; 16])?;
    let mut hash = blake3::Hasher::new();
    let mut size = 0_u64;
    let mut chunks = 0_u32;
    let mut buffer = vec![0_u8; CHUNK];
    loop {
        let mut used = 0;
        while used < CHUNK {
            match reader.read(&mut buffer[used..]) {
                Ok(0) => break,
                Ok(n) => used += n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        if used == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(used)?)
            .context("CAS size overflow")?;
        if let Some(limit) = bound {
            ensure!(size <= limit, "CAS input exceeds declared size");
        }
        hash.update(&buffer[..used]);
        write_encoded_chunk(file, &buffer[..used])?;
        chunks = chunks.checked_add(1).context("too many CAS chunks")?;
    }
    write_encoded_header(file, size, chunks)?;
    Ok(BlobRef {
        id: ContentId(*hash.finalize().as_bytes()),
        size,
    })
}

/// Read and validate a transported physical CAS payload.
///
/// Both encodings preserve content identity over the decoded bytes and reject
/// streams with incorrect length or digest.
///
/// # Errors
/// Returns an error for invalid content, truncation, or an I/O failure.
pub fn transfer(
    reader: impl Read,
    physical: impl Write,
    plaintext: impl Write,
    expected: BlobRef,
    encoding: BlobEncoding,
) -> Result<()> {
    match encoding {
        BlobEncoding::Raw => transfer_raw(reader, physical, plaintext, expected),
        BlobEncoding::ZstdChunks => transfer_zstd_chunks(reader, physical, plaintext, expected),
    }
}

fn transfer_raw(
    mut reader: impl Read,
    mut physical: impl Write,
    mut plaintext: impl Write,
    expected: BlobRef,
) -> Result<()> {
    let mut digest = blake3::Hasher::new();
    let mut decoded = 0_u64;
    let mut block = vec![0_u8; 64 * 1024];
    loop {
        let n = match reader.read(&mut block) {
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if n == 0 {
            break;
        }
        decoded = decoded
            .checked_add(u64::try_from(n)?)
            .context("raw CAS length overflow")?;
        ensure!(
            decoded <= expected.size,
            "raw CAS exceeds advertised length"
        );
        let contents = &block[..n];
        digest.update(contents);
        physical.write_all(contents)?;
        plaintext.write_all(contents)?;
    }
    ensure!(
        decoded == expected.size && ContentId(*digest.finalize().as_bytes()) == expected.id,
        "raw CAS digest or length mismatch"
    );
    Ok(())
}

fn transfer_zstd_chunks(
    mut reader: impl Read,
    mut physical: impl Write,
    mut plaintext: impl Write,
    expected: BlobRef,
) -> Result<()> {
    let mut header = [0_u8; 32];
    reader.read_exact(&mut header)?;
    let count = validate_transport_header(&header, expected)?;
    physical.write_all(&header)?;
    let size = expected.size;
    let mut decoded = 0_u64;
    let mut hash = blake3::Hasher::new();
    for _ in 0..count {
        let mut widths = [0_u8; 8];
        reader.read_exact(&mut widths)?;
        let remaining = size
            .checked_sub(decoded)
            .context("CAS transfer chunk position overflow")?;
        let parsed = validate_transport_widths(&widths, remaining)?;
        decoded = decoded
            .checked_add(u64::try_from(parsed.plain)?)
            .context("decoded length overflow")?;
        let mut data = vec![0; parsed.stored];
        reader.read_exact(&mut data)?;
        let bytes = decode_transport_chunk(&data, parsed)?;
        hash.update(&bytes);
        plaintext.write_all(&bytes)?;
        physical.write_all(&widths)?;
        physical.write_all(&data)?;
    }
    ensure!(
        decoded == size && ContentId(*hash.finalize().as_bytes()) == expected.id,
        "native CAS decoded digest/size mismatch"
    );
    let mut trailing = [0_u8; 1];
    ensure!(
        reader.read(&mut trailing)? == 0,
        "trailing native CAS content"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positional_io_retries_interruptions_and_rejects_short_transfers() -> Result<()> {
        let mut attempts = 0;
        let mut offsets = Vec::new();
        transfer_at(5, 12, io::ErrorKind::UnexpectedEof, |done, offset| {
            attempts += 1;
            if attempts == 1 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            offsets.push((done, offset));
            Ok((5 - done).min(2))
        })?;
        assert_eq!(offsets, [(0, 12), (2, 14), (4, 16)]);
        for short in [io::ErrorKind::UnexpectedEof, io::ErrorKind::WriteZero] {
            assert_eq!(
                transfer_at(1, 0, short, |_, _| Ok(0)).unwrap_err().kind(),
                short
            );
        }
        Ok(())
    }

    #[test]
    fn verified_random_access_and_raw_blocks() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let p = tmp.path().join("blob");
        let input = (0..620_000u32).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        let mut f = File::create(&p)?;
        let reference = encode(input.as_slice(), &mut f, None)?;
        assert_eq!(reference.id, ContentId::of(&input));
        drop(f);
        let mut decoded = BlobReader::open(File::open(&p)?, BlobEncoding::ZstdChunks)?;
        assert_eq!(decoded.len(), input.len() as u64);
        decoded.seek(SeekFrom::Start(250_000))?;
        let mut subset = vec![0_u8; 50_000];
        decoded.read_exact(&mut subset)?;
        assert_eq!(&subset, &input[250_000..300_000]);
        decoded.seek(SeekFrom::Start(0))?;
        let mut output = Vec::new();
        decoded.read_to_end(&mut output)?;
        assert_eq!(output, input);
        let received = tmp.path().join("received");
        let mut saved = File::create(&received)?;
        transfer(
            File::open(&p)?,
            &mut saved,
            io::sink(),
            reference,
            BlobEncoding::ZstdChunks,
        )?;
        drop(saved);
        assert_eq!(std::fs::read(p)?, std::fs::read(received)?);
        Ok(())
    }

    #[test]
    fn plain_physical_file_has_no_encoded_envelope_even_when_header_sized() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("raw");
        std::fs::write(&path, vec![0xa5; usize::try_from(HEADER)?])?;
        let decoded = BlobReader::open(File::open(&path)?, BlobEncoding::Raw)?;
        assert!(!decoded.is_encoded());
        assert_eq!(decoded.len(), HEADER);
        Ok(())
    }

    #[test]
    fn incompressible_chunks_remain_raw_and_seekable() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let file_path = temporary.path().join("entropy");
        let mut bytes = vec![0_u8; 300_000];
        blake3::Hasher::new().finalize_xof().fill(&mut bytes);
        let mut target = File::create(&file_path)?;
        let reference = encode(bytes.as_slice(), &mut target, None)?;
        drop(target);
        let physical = std::fs::read(&file_path)?;
        let physical_header = u32::from_le_bytes(physical[32..36].try_into()?);
        assert_ne!(
            physical_header & RAW_CHUNK,
            0,
            "incompressible input should not waste CPU on subsequent decoding"
        );
        assert!(physical.len() < bytes.len() + 64);
        let mut decoded = BlobReader::open(File::open(&file_path)?, BlobEncoding::ZstdChunks)?;
        let mut output = Vec::new();
        decoded.read_to_end(&mut output)?;
        assert_eq!(output, bytes);
        let mut copied = File::create(temporary.path().join("wire"))?;
        transfer(
            File::open(file_path)?,
            &mut copied,
            io::sink(),
            reference,
            BlobEncoding::ZstdChunks,
        )?;
        Ok(())
    }

    #[test]
    fn reject_noncanonical_chunk_layout_even_when_total_plaintext_matches() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("tampered");
        let data = vec![0x44_u8; CHUNK + 8000];
        let mut file = File::create(&path)?;
        let reference = encode(data.as_slice(), &mut file, None)?;
        drop(file);
        let mut corrupted = std::fs::read(&path)?;
        let first_stored =
            usize::try_from(u32::from_le_bytes(corrupted[32..36].try_into()?) & !RAW_CHUNK)?;
        let second_header = 40 + first_stored;
        let first = u32::try_from(CHUNK - 10)?;
        let last = 8010_u32;
        corrupted[36..40].copy_from_slice(&first.to_le_bytes());
        corrupted[second_header + 4..second_header + 8].copy_from_slice(&last.to_le_bytes());
        std::fs::write(&path, &corrupted)?;
        assert!(BlobReader::open(File::open(&path)?, BlobEncoding::ZstdChunks).is_err());
        assert!(
            transfer(
                corrupted.as_slice(),
                io::sink(),
                io::sink(),
                reference,
                BlobEncoding::ZstdChunks,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn corruption_and_extra_bytes_rejected() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("blob");
        let mut file = File::create(&path)?;
        let expected = encode(&b"native-immutable-artifact"[..], &mut file, None)?;
        drop(file);
        let mut data = std::fs::read(&path)?;
        data.extend(b"trailing");
        let mut dest = File::create(tmp.path().join("result"))?;
        assert!(
            transfer(
                data.as_slice(),
                &mut dest,
                io::sink(),
                expected,
                BlobEncoding::ZstdChunks
            )
            .is_err()
        );
        data.truncate(data.len() - 8);
        data[35] ^= 0x01;
        assert!(
            transfer(
                data.as_slice(),
                &mut dest,
                io::sink(),
                expected,
                BlobEncoding::ZstdChunks
            )
            .is_err()
        );
        Ok(())
    }
}
