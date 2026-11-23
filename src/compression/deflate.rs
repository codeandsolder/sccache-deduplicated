//! Streaming adapters for the fallible zlib-rs-fast Rust API.
//!
//! Decoders are created on the consuming thread. The opaque codec state is
//! never transferred between threads, and no external Send/Sync claims are
//! needed for the fork's raw-pointer-owning streams.

use std::io::{self, BufRead, BufReader, Read};

use zlib_rs_fast::{Inflate, InflateFlush, Status};

const BUFFER_SIZE: usize = 64 * 1024;

/// The zlib-rs stable stream constructors defer initialization failures until
/// first use. Preserve our fallible I/O constructor contract by checking now.
fn initialize_decoder(window_bits: u8) -> io::Result<Inflate> {
    let decoder = Inflate::new(true, window_bits);
    if let Some(error) = decoder.error_message() {
        return Err(io::Error::other(error));
    }
    Ok(decoder)
}

pub struct InflateReader<R> {
    reader: BufReader<R>,
    decoder: Inflate,
    window_bits: u8,
    member_finished: bool,
}

impl<R: Read> InflateReader<R> {
    fn new(reader: R, window_bits: u8) -> io::Result<Self> {
        let decoder = initialize_decoder(window_bits)?;
        Ok(Self {
            reader: BufReader::with_capacity(BUFFER_SIZE, reader),
            decoder,
            window_bits,
            member_finished: false,
        })
    }

    /// Decode a complete zlib stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the decompressor cannot be initialized.
    pub fn zlib(reader: R) -> io::Result<Self> {
        Self::new(reader, 15)
    }

    /// Decode a gzip archive, including concatenated independently compressed members.
    ///
    /// # Errors
    ///
    /// Returns an error if the decompressor cannot be initialized.
    pub fn gzip(reader: R) -> io::Result<Self> {
        Self::new(reader, 31)
    }
}

impl<R: Read> Read for InflateReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            let input = self.reader.fill_buf()?;
            if self.member_finished {
                if input.is_empty() {
                    return Ok(0);
                }
                if self.window_bits != 31 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes after zlib stream",
                    ));
                }
                self.decoder = initialize_decoder(31)?;
                self.member_finished = false;
            }
            let before_in = self.decoder.total_in();
            let before_out = self.decoder.total_out();
            let status = self
                .decoder
                .decompress(input, output, InflateFlush::NoFlush)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.as_str()))?;
            let consumed =
                usize::try_from(self.decoder.total_in() - before_in).map_err(io::Error::other)?;
            let produced =
                usize::try_from(self.decoder.total_out() - before_out).map_err(io::Error::other)?;
            self.reader.consume(consumed);
            self.member_finished = status == Status::StreamEnd;
            if produced != 0 {
                return Ok(produced);
            }
            if !self.member_finished && consumed == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete or stalled DEFLATE stream",
                ));
            }
        }
    }
}

/// Extract an entire gzip-compressed tar archive and verify its trailing members/checksums.
///
/// # Errors
///
/// Returns an error for malformed data or failed extraction.
pub fn unpack_gzip<R: Read>(reader: R, path: &std::path::Path) -> io::Result<()> {
    let mut archive = tar::Archive::new(InflateReader::gzip(reader)?);
    archive.unpack(path)?;
    io::copy(&mut archive.into_inner(), &mut io::sink())?;
    Ok(())
}

#[cfg(feature = "dist-client")]
mod encode {
    use super::{BUFFER_SIZE, Status};
    use std::io::{self, Write};
    use std::num::NonZeroUsize;
    use zlib_rs_fast::{BatchCodec, BatchJob, Deflate, DeflateConfig, DeflateFlush, ReturnCode};

    pub struct ZlibWriter<W> {
        writer: W,
        encoder: Deflate,
        buffer: Vec<u8>,
    }

    impl<W: Write> ZlibWriter<W> {
        /// Construct a level-1 compressor for per-job input transport.
        ///
        /// # Errors
        ///
        /// Returns an error if codec initialization fails.
        pub fn new(writer: W) -> io::Result<Self> {
            let encoder = Deflate::new(1, true, 15);
            if let Some(error) = encoder.error_message() {
                return Err(io::Error::other(error));
            }
            Ok(Self {
                writer,
                encoder,
                buffer: vec![0; BUFFER_SIZE],
            })
        }

        #[must_use = "the compressor input byte count is returned without modifying it"]
        pub const fn total_in(&self) -> u64 {
            self.encoder.total_in()
        }

        fn step(
            &mut self,
            input: &[u8],
            flush: DeflateFlush,
        ) -> io::Result<(Status, usize, usize)> {
            let before_in = self.encoder.total_in();
            let before_out = self.encoder.total_out();
            let status = self
                .encoder
                .compress(input, &mut self.buffer, flush)
                .map_err(|e| io::Error::other(e.as_str()))?;
            let consumed =
                usize::try_from(self.encoder.total_in() - before_in).map_err(io::Error::other)?;
            let produced =
                usize::try_from(self.encoder.total_out() - before_out).map_err(io::Error::other)?;
            self.writer.write_all(&self.buffer[..produced])?;
            Ok((status, consumed, produced))
        }

        /// Finalize the stream and return the destination.
        ///
        /// # Errors
        ///
        /// Returns an error if compression or writing fails.
        pub fn finish(mut self) -> io::Result<W> {
            loop {
                let (status, _, produced) = self.step(&[], DeflateFlush::Finish)?;
                if status == Status::StreamEnd {
                    return Ok(self.writer);
                }
                if produced == 0 {
                    return Err(io::Error::other("DEFLATE finalization made no progress"));
                }
            }
        }
    }

    impl<W: Write> Write for ZlibWriter<W> {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            if input.is_empty() {
                return Ok(0);
            }
            loop {
                let (_, consumed, produced) = self.step(input, DeflateFlush::NoFlush)?;
                if consumed != 0 {
                    return Ok(consumed);
                }
                if produced == 0 {
                    return Err(io::Error::other("DEFLATE compression made no progress"));
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            loop {
                let (_, _, produced) = self.step(&[], DeflateFlush::SyncFlush)?;
                if produced < self.buffer.len() {
                    return self.writer.flush();
                }
            }
        }
    }

    // Fixed member boundaries make archive bytes independent of CPU count and
    // retain parallel compression while requiring only bounded staging memory.
    const GZIP_MEMBER_SIZE: usize = 1024 * 1024;

    pub struct ParallelGzipWriter<W> {
        writer: W,
        compressor: BatchCodec,
        input: Vec<u8>,
        batch_capacity: usize,
        wrote_member: bool,
    }

    impl<W: Write> ParallelGzipWriter<W> {
        /// Construct a bounded parallel gzip archive encoder.
        ///
        /// # Errors
        ///
        /// Returns an error if the worker pool cannot be initialized.
        pub fn new(writer: W) -> io::Result<Self> {
            let workers = std::thread::available_parallelism()?
                .min(NonZeroUsize::new(8).unwrap_or(NonZeroUsize::MIN));
            let batch_capacity = workers.get() * GZIP_MEMBER_SIZE;
            let compressor = BatchCodec::new(workers).map_err(io::Error::other)?;
            Ok(Self {
                writer,
                compressor,
                input: Vec::with_capacity(batch_capacity),
                batch_capacity,
                wrote_member: false,
            })
        }

        fn write_members(&mut self) -> io::Result<()> {
            if self.input.is_empty() && self.wrote_member {
                return Ok(());
            }
            let config = DeflateConfig {
                level: 6,
                window_bits: 31,
                ..DeflateConfig::default()
            };
            let chunks = if self.input.is_empty() {
                vec![&[][..]]
            } else {
                self.input.chunks(GZIP_MEMBER_SIZE).collect::<Vec<_>>()
            };
            let mut outputs = vec![Vec::new(); chunks.len()];
            let mut jobs: Vec<_> = chunks
                .into_iter()
                .zip(&mut outputs)
                .map(|(input, output)| {
                    BatchJob::with_vec(
                        input,
                        output,
                        zlib_rs_fast::compress_bound(input.len()) + 32,
                    )
                })
                .collect::<Result<_, _>>()
                .map_err(io::Error::other)?;
            let results = self.compressor.compress(&mut jobs, config);
            drop(jobs);
            for result in &results {
                if result.code != ReturnCode::Ok {
                    return Err(io::Error::other(format!(
                        "gzip compression failed: {:?}",
                        result.code
                    )));
                }
            }
            for output in &outputs {
                self.writer.write_all(output)?;
            }
            self.wrote_member = true;
            self.input.clear();
            Ok(())
        }

        /// Finalize all pending gzip members.
        ///
        /// # Errors
        ///
        /// Returns an error if compression or writing fails.
        pub fn finish(mut self) -> io::Result<W> {
            self.write_members()?;
            self.writer.flush()?;
            Ok(self.writer)
        }
    }

    impl<W: Write> Write for ParallelGzipWriter<W> {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let consumed = input.len().min(self.batch_capacity - self.input.len());
            self.input.extend_from_slice(&input[..consumed]);
            if self.input.len() == self.batch_capacity {
                self.write_members()?;
            }
            Ok(consumed)
        }

        fn flush(&mut self) -> io::Result<()> {
            // A flush must expose all bytes, not close the archive. A later
            // write starts another standard gzip member.
            if !self.input.is_empty() {
                self.write_members()?;
            }
            self.writer.flush()
        }
    }
}

#[cfg(feature = "dist-client")]
pub use encode::{ParallelGzipWriter, ZlibWriter};

#[cfg(all(test, feature = "dist-client"))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn invalid_inflate_configuration_is_reported_on_construction() {
        // The upstream stable API holds initialization errors in the stream,
        // and must not silently return a reader that fails only later.
        assert!(InflateReader::new(&b""[..], 3).is_err());
        assert!(InflateReader::new(&b""[..], 15).is_ok());
        assert!(InflateReader::new(&b""[..], 31).is_ok());
    }

    #[test]
    fn zlib_stream_round_trips_and_rejects_truncation() -> io::Result<()> {
        let source = b"distributed inputs repeated contents".repeat(30_000);
        let mut writer = ZlibWriter::new(Vec::new())?;
        for chunk in source.chunks(117) {
            writer.write_all(chunk)?;
        }
        let wire = writer.finish()?;
        let mut decoded = Vec::new();
        InflateReader::zlib(wire.as_slice())?.read_to_end(&mut decoded)?;
        assert_eq!(decoded, source);
        assert!(
            InflateReader::zlib(&wire[..wire.len() - 1])?
                .read_to_end(&mut Vec::new())
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn gzip_empty_stream_and_flush_boundaries() -> io::Result<()> {
        let wire = ParallelGzipWriter::new(Vec::new())?.finish()?;
        assert!(!wire.is_empty());
        let mut decoded = Vec::new();
        InflateReader::gzip(wire.as_slice())?.read_to_end(&mut decoded)?;
        assert!(decoded.is_empty());

        let first = b"first member";
        let second = b"second member";
        let mut writer = ParallelGzipWriter::new(Vec::new())?;
        writer.flush()?;
        writer.write_all(first)?;
        writer.flush()?;
        writer.flush()?;
        writer.write_all(second)?;
        let wire = writer.finish()?;
        InflateReader::gzip(wire.as_slice())?.read_to_end(&mut decoded)?;
        assert_eq!(decoded, [first.as_slice(), second.as_slice()].concat());
        Ok(())
    }

    #[test]
    fn gzip_member_boundaries_and_trailer_validation() -> io::Result<()> {
        let source = b"toolchain content".repeat(300_000);
        let mut writer = ParallelGzipWriter::new(Vec::new())?;
        writer.write_all(&source)?;
        let wire = writer.finish()?;
        let mut decoded = Vec::new();
        InflateReader::gzip(wire.as_slice())?.read_to_end(&mut decoded)?;
        assert_eq!(decoded, source);
        assert!(
            InflateReader::gzip(&wire[..wire.len() - 1])?
                .read_to_end(&mut Vec::new())
                .is_err()
        );
        Ok(())
    }
}
