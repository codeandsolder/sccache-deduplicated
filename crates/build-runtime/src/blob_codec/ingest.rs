//! Incremental physical CAS ingestion. The caller owns I/O scheduling; this
//! state machine never waits for input and buffers at most one codec frame.

use super::{
    BlobEncoding, BlobRef, CHUNK, ChunkWidths, ContentId, Result, Write, decode_transport_chunk,
    transport_header, validate_transport_header, validate_transport_widths, write_encoded_chunk,
};
use crate::store::BlobIntegrityError;
use anyhow::{Context, ensure};

#[derive(Clone, Copy)]
enum InputState {
    Raw,
    Header,
    Widths,
    Frame(ChunkWidths),
    Complete,
}

pub struct BlobIngest {
    expected: BlobRef,
    target: BlobEncoding,
    state: InputState,
    pending: Vec<u8>,
    digest: blake3::Hasher,
    decoded: u64,
}

impl BlobIngest {
    pub(crate) fn new(
        file: &mut impl Write,
        expected: BlobRef,
        source: BlobEncoding,
        target: BlobEncoding,
    ) -> Result<Self> {
        if source == BlobEncoding::Raw && target == BlobEncoding::ZstdChunks {
            // The negotiated size fixes the header before the first frame.
            file.write_all(&transport_header(expected.size)?)?;
        }
        Ok(Self {
            expected,
            target,
            state: match source {
                BlobEncoding::Raw => InputState::Raw,
                BlobEncoding::ZstdChunks => InputState::Header,
            },
            pending: Vec::new(),
            digest: blake3::Hasher::new(),
            decoded: 0,
        })
    }

    pub(crate) fn requires_codec_pool(&self) -> bool {
        !matches!(self.state, InputState::Raw) || self.target == BlobEncoding::ZstdChunks
    }

    pub(crate) fn feed(&mut self, file: &mut impl Write, mut input: &[u8]) -> Result<()> {
        if matches!(self.state, InputState::Raw) {
            return self.feed_raw(file, input);
        }
        while !input.is_empty() {
            let need = match self.state {
                InputState::Header => 32,
                InputState::Widths => 8,
                InputState::Frame(widths) => widths.stored,
                InputState::Complete => anyhow::bail!("trailing native CAS content"),
                InputState::Raw => unreachable!("raw ingestion handled separately"),
            };
            let count = input.len().min(need - self.pending.len());
            self.pending.extend_from_slice(&input[..count]);
            input = &input[count..];
            if self.pending.len() == need {
                self.finish_part(file)?;
                self.pending.clear();
            }
        }
        Ok(())
    }

    fn feed_raw(&mut self, file: &mut impl Write, mut bytes: &[u8]) -> Result<()> {
        self.decoded = self
            .decoded
            .checked_add(u64::try_from(bytes.len())?)
            .context("blob length overflow")?;
        ensure!(
            self.decoded <= self.expected.size,
            BlobIntegrityError::Length {
                expected: self.expected.size,
                actual: self.decoded
            }
        );
        self.digest.update(bytes);
        if self.target == BlobEncoding::Raw {
            file.write_all(bytes)?;
            return Ok(());
        }
        while !bytes.is_empty() {
            if self.pending.is_empty() && bytes.len() >= CHUNK {
                write_encoded_chunk(file, &bytes[..CHUNK])?;
                bytes = &bytes[CHUNK..];
            } else {
                let count = bytes.len().min(CHUNK - self.pending.len());
                self.pending.extend_from_slice(&bytes[..count]);
                bytes = &bytes[count..];
                if self.pending.len() == CHUNK {
                    self.flush_raw_chunk(file)?;
                }
            }
        }
        Ok(())
    }

    fn flush_raw_chunk(&mut self, file: &mut impl Write) -> Result<()> {
        if !self.pending.is_empty() {
            write_encoded_chunk(file, &self.pending)?;
            self.pending.clear();
        }
        Ok(())
    }

    fn finish_part(&mut self, file: &mut impl Write) -> Result<()> {
        self.state = match self.state {
            InputState::Header => {
                let count =
                    validate_transport_header(self.pending.as_slice().try_into()?, self.expected)?;
                if self.target == BlobEncoding::ZstdChunks {
                    file.write_all(&self.pending)?;
                }
                if count == 0 {
                    InputState::Complete
                } else {
                    InputState::Widths
                }
            }
            InputState::Widths => {
                let remaining = self
                    .expected
                    .size
                    .checked_sub(self.decoded)
                    .context("CAS transfer chunk position overflow")?;
                let widths =
                    validate_transport_widths(self.pending.as_slice().try_into()?, remaining)?;
                if self.target == BlobEncoding::ZstdChunks {
                    file.write_all(&self.pending)?;
                }
                InputState::Frame(widths)
            }
            InputState::Frame(widths) => {
                let bytes = decode_transport_chunk(&self.pending, widths)?;
                self.digest.update(&bytes);
                self.decoded = self
                    .decoded
                    .checked_add(u64::try_from(bytes.len())?)
                    .context("decoded length overflow")?;
                match self.target {
                    BlobEncoding::Raw => file.write_all(&bytes)?,
                    BlobEncoding::ZstdChunks => file.write_all(&self.pending)?,
                }
                if self.decoded == self.expected.size {
                    InputState::Complete
                } else {
                    InputState::Widths
                }
            }
            _ => unreachable!("only complete framed input parts are processed"),
        };
        Ok(())
    }

    pub(crate) fn finish(mut self, file: &mut impl Write) -> Result<()> {
        ensure!(
            matches!(self.state, InputState::Raw | InputState::Complete),
            "truncated native CAS content"
        );
        ensure!(
            self.decoded == self.expected.size,
            BlobIntegrityError::Length {
                expected: self.expected.size,
                actual: self.decoded
            }
        );
        ensure!(
            ContentId(*self.digest.finalize().as_bytes()) == self.expected.id,
            BlobIntegrityError::Digest
        );
        if matches!(self.state, InputState::Raw) && self.target == BlobEncoding::ZstdChunks {
            self.flush_raw_chunk(file)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::{Read, Seek, SeekFrom},
    };

    fn contents(file: &mut File) -> Result<Vec<u8>> {
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    #[test]
    fn arbitrary_boundaries_preserve_all_physical_encodings() -> Result<()> {
        for size in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 17] {
            let mut raw = vec![0; size];
            blake3::Hasher::new()
                .finalize_xof()
                .fill(&mut raw[..size / 2]);
            let mut encoded = tempfile::tempfile()?;
            let expected = super::super::encode(raw.as_slice(), &mut encoded, None)?;
            let encoded = contents(&mut encoded)?;
            for (source, wire) in [
                (BlobEncoding::Raw, &raw),
                (BlobEncoding::ZstdChunks, &encoded),
            ] {
                for (target, canonical) in [
                    (BlobEncoding::Raw, &raw),
                    (BlobEncoding::ZstdChunks, &encoded),
                ] {
                    let mut staged = tempfile::tempfile()?;
                    let mut ingest = BlobIngest::new(&mut staged, expected, source, target)?;
                    let mut offset = 0;
                    let mut width = 1;
                    while offset < wire.len() {
                        let end = (offset + width).min(wire.len());
                        ingest.feed(&mut staged, &wire[offset..end])?;
                        offset = end;
                        width = (width * 3).min(97_531);
                    }
                    ingest.finish(&mut staged)?;
                    assert_eq!(&contents(&mut staged)?, canonical);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn framed_input_rejects_corruption_truncation_and_trailing_bytes() -> Result<()> {
        let raw = vec![42; CHUNK + 1];
        let mut encoded = tempfile::tempfile()?;
        let expected = super::super::encode(raw.as_slice(), &mut encoded, None)?;
        let encoded = contents(&mut encoded)?;
        for end in [0, 1, 31, 32, 39, encoded.len() - 1] {
            let mut target = tempfile::tempfile()?;
            let mut ingest = BlobIngest::new(
                &mut target,
                expected,
                BlobEncoding::ZstdChunks,
                BlobEncoding::Raw,
            )?;
            ingest.feed(&mut target, &encoded[..end])?;
            assert!(ingest.finish(&mut target).is_err());
        }
        for offset in [0, 16, 24, 28, 32, 36] {
            let mut corrupt = encoded.clone();
            corrupt[offset] ^= 0x80;
            let mut target = tempfile::tempfile()?;
            let mut ingest = BlobIngest::new(
                &mut target,
                expected,
                BlobEncoding::ZstdChunks,
                BlobEncoding::Raw,
            )?;
            let result = ingest
                .feed(&mut target, &corrupt)
                .and_then(|()| ingest.finish(&mut target));
            assert!(result.is_err(), "corruption at offset {offset} accepted");
        }
        let mut target = tempfile::tempfile()?;
        let mut ingest = BlobIngest::new(
            &mut target,
            expected,
            BlobEncoding::ZstdChunks,
            BlobEncoding::Raw,
        )?;
        ingest.feed(&mut target, &encoded)?;
        assert!(ingest.feed(&mut target, &[0]).is_err());
        let mut target = tempfile::tempfile()?;
        let wrong = BlobRef {
            id: ContentId::of(b"wrong"),
            ..expected
        };
        let mut ingest = BlobIngest::new(
            &mut target,
            wrong,
            BlobEncoding::ZstdChunks,
            BlobEncoding::Raw,
        )?;
        ingest.feed(&mut target, &encoded)?;
        assert!(ingest.finish(&mut target).is_err());
        Ok(())
    }
}
