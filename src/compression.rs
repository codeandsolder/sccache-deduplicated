// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Shared, cache-compatible compression for distributed compiler artifacts.

#[cfg(any(feature = "dist-client", feature = "dist-server"))]
pub mod deflate;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, Read};

/// A checksummed Zstandard frame and its uncompressed length.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZstdFrame {
    compressed: Vec<u8>,
    uncompressed_len: u64,
}

impl ZstdFrame {
    /// Compress an output once, in the same format used by the cache's stored ZIP entries.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if reading or compression fails.
    pub fn try_from_reader<R: Read>(mut reader: R, level: i32) -> io::Result<Self> {
        let mut compressed = Vec::new();
        let uncompressed_len = encode(&mut reader, &mut compressed, level)?;
        Ok(Self {
            compressed,
            uncompressed_len,
        })
    }

    #[must_use = "the frame lengths are needed to validate or account for the compressed data"]
    pub const fn lens(&self) -> FrameSize {
        FrameSize {
            actual: self.uncompressed_len,
            compressed: self.compressed.len() as u64,
        }
    }

    /// Materialize and validate the frame, retaining its compressed bytes.
    ///
    /// # Errors
    ///
    /// Returns an I/O error for malformed data, length mismatch, or a failed write.
    pub fn materialize<W: io::Write>(self, writer: &mut W) -> io::Result<VerifiedZstdFrame> {
        let decoder = zstd::stream::read::Decoder::new(self.compressed.as_slice())?;
        let count = io::copy(
            &mut decoder.take(self.uncompressed_len.saturating_add(1)),
            writer,
        )?;
        if count != self.uncompressed_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "distributed output length mismatch: expected {}, wrote {count}",
                    self.uncompressed_len
                ),
            ));
        }
        Ok(VerifiedZstdFrame(self))
    }
}

/// A frame that was decoded successfully, including length and checksum validation.
/// This type is not deserializable: it is only obtained through materialization.
pub struct VerifiedZstdFrame(ZstdFrame);

impl VerifiedZstdFrame {
    #[must_use = "the compressed payload must be consumed by the caller"]
    pub(crate) fn compressed_bytes(&self) -> &[u8] {
        &self.0.compressed
    }
}

pub struct FrameSize {
    pub actual: u64,
    pub compressed: u64,
}
impl fmt::Display for FrameSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Size: {}->{}", self.actual, self.compressed)
    }
}

/// Encode a checksummed Zstandard stream into its final destination.
///
/// # Errors
///
/// Returns an I/O error if reading, compressing, or writing fails.
pub(crate) fn encode<R: Read, W: io::Write>(
    mut reader: R,
    writer: W,
    level: i32,
) -> io::Result<u64> {
    let mut encoder = zstd::stream::write::Encoder::new(writer, level)?;
    encoder.include_checksum(true)?;
    let len = io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;
    Ok(len)
}

/// The cache client's configured Zstandard compression level.
pub(crate) fn cache_level() -> i32 {
    std::env::var("SCCACHE_CACHE_ZSTD_LEVEL")
        .ok()
        .and_then(|level| level.parse::<i32>().ok())
        .unwrap_or(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zstd_frame_materializes_and_retains_exact_wire_bytes() -> io::Result<()> {
        for data in [
            &b""[..],
            &b"short compiler output"[..],
            &vec![b'x'; 512 * 1024][..],
        ] {
            for level in [1, 3, 10] {
                let frame = ZstdFrame::try_from_reader(data, level)?;
                let compressed = frame.compressed.clone();
                let encoded = bincode::serialize(&frame).unwrap();
                let received: ZstdFrame = bincode::deserialize(&encoded).unwrap();
                let mut out = Vec::new();
                let verified = received.materialize(&mut out)?;
                assert_eq!(out, data);
                assert_eq!(verified.compressed_bytes(), compressed);
            }
        }
        Ok(())
    }

    #[test]
    fn zstd_frame_rejects_corrupt_truncated_or_wrong_length_data() -> io::Result<()> {
        let data = vec![b'x'; 256 * 1024];
        let frame = ZstdFrame::try_from_reader(data.as_slice(), 3)?;

        let mut truncated = frame.clone();
        truncated.compressed.pop();
        assert!(truncated.materialize(&mut io::sink()).is_err());

        let mut corrupt = frame.clone();
        *corrupt.compressed.last_mut().unwrap() ^= 1;
        assert!(corrupt.materialize(&mut io::sink()).is_err());

        let mut short = frame.clone();
        short.uncompressed_len -= 1;
        assert!(short.materialize(&mut io::sink()).is_err());

        let mut long = frame;
        long.uncompressed_len += 1;
        assert!(long.materialize(&mut io::sink()).is_err());
        Ok(())
    }
}
