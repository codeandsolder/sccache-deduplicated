//! Portable identities for original upstream archives.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Compression of the original upstream tar package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PackageCompression {
    Tar,
    Gzip,
    Xz,
    Zstd,
}

impl PackageCompression {
    /// Command-line name of the original archive codec.
    #[must_use = "the name selects the decompressor"]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tar => "tar",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }
}

impl std::str::FromStr for PackageCompression {
    type Err = anyhow::Error;

    fn from_str(name: &str) -> Result<Self> {
        match name {
            "tar" => Ok(Self::Tar),
            "gzip" => Ok(Self::Gzip),
            "xz" => Ok(Self::Xz),
            "zstd" => Ok(Self::Zstd),
            _ => anyhow::bail!("unsupported package compression"),
        }
    }
}

/// Cryptographic identity published by upstream release manifests. Archive
/// length is verified at ingestion but is not needed to resolve this identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageIdentity {
    pub sha256: [u8; 32],
    pub compression: PackageCompression,
}

impl PackageIdentity {
    /// Parse the upstream checksum and archive codec.
    /// # Errors
    /// Returns an error for an invalid hexadecimal checksum.
    pub fn from_sha256_hex(hash: &str, compression: PackageCompression) -> Result<Self> {
        ensure!(
            hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid SHA-256 checksum"
        );
        let mut sha256 = [0; 32];
        for (index, value) in sha256.iter_mut().enumerate() {
            *value = u8::from_str_radix(&hash[index * 2..index * 2 + 2], 16)?;
        }
        Ok(Self {
            sha256,
            compression,
        })
    }

    /// The standard lowercase hexadecimal checksum used by upstream tooling.
    #[must_use = "the checksum names the original package"]
    pub fn checksum_hex(self) -> String {
        use std::fmt::Write as _;
        let mut hash = String::with_capacity(64);
        for byte in self.sha256 {
            let _ = write!(hash, "{byte:02x}");
        }
        hash
    }
}

/// Verified upstream archive identity and compressed length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageSource {
    pub identity: PackageIdentity,
    pub size: u64,
}

/// Verified archive provenance and its normalized content tree. This is
/// transport metadata, not a declaration of any installed filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageReceipt {
    pub source: PackageSource,
    pub tree: crate::TreeId,
}

/// Length expectation for original archive ingestion. A checksum is mandatory
/// even when the upstream HTTP response has no Content-Length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveLength {
    Exact(u64),
    AtMost(u64),
}

impl ArchiveLength {
    #[must_use = "maximum compressed input size"]
    pub const fn maximum(self) -> u64 {
        match self {
            Self::Exact(size) | Self::AtMost(size) => size,
        }
    }

    #[must_use = "whether the observed archive length is acceptable"]
    pub const fn accepts(self, size: u64) -> bool {
        match self {
            Self::Exact(expected) => size == expected,
            Self::AtMost(maximum) => size <= maximum,
        }
    }
}

/// Worker-provided estimates of the wall time spent delivering and
/// expanding an original archive. These are operational costs, not
/// fingerprints or evidence of different build behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageTransferCost {
    /// Effective logical blob bytes delivered and staged per second.
    pub download_bytes_per_second: u64,
    /// Original archive bytes delivered per second, before archive expansion.
    pub archive_download_bytes_per_second: u64,
    /// Approximate setup/staging latency of one original HTTP blob request.
    pub raw_request_nanoseconds: u64,
    /// Maximum simultaneous raw blob fetches across worker jobs.
    pub raw_parallelism: u32,
    pub decode_tar_bytes_per_second: u64,
    pub decode_gzip_bytes_per_second: u64,
    pub decode_xz_bytes_per_second: u64,
    pub decode_zstd_bytes_per_second: u64,
    pub per_entry_nanoseconds: u64,
    pub startup_nanoseconds: u64,
}

impl Default for PackageTransferCost {
    fn default() -> Self {
        const MIB: u64 = 1 << 20;
        Self {
            download_bytes_per_second: 128 * MIB,
            archive_download_bytes_per_second: 128 * MIB,
            raw_request_nanoseconds: 2_000_000,
            // One worker-wide budget: enough concurrent small requests to
            // hide network and filesystem latency even on a busy LAN.
            raw_parallelism: 64,
            decode_tar_bytes_per_second: 512 * MIB,
            decode_gzip_bytes_per_second: 128 * MIB,
            decode_xz_bytes_per_second: 24 * MIB,
            decode_zstd_bytes_per_second: 64 * MIB,
            per_entry_nanoseconds: 20_000,
            startup_nanoseconds: 75_000_000,
        }
    }
}

mod catalog;
#[cfg(all(unix, feature = "store"))]
pub use catalog::Candidate;
pub use catalog::{PackageCatalog, PackageDeliveryLimits};

impl PackageTransferCost {
    /// Reject invalid or nonsensical estimates before scheduler admission.
    /// # Errors
    /// Returns an error for a zero or excessive rate.
    pub fn validate(self) -> Result<()> {
        let rates = [
            self.download_bytes_per_second,
            self.archive_download_bytes_per_second,
            self.decode_tar_bytes_per_second,
            self.decode_gzip_bytes_per_second,
            self.decode_xz_bytes_per_second,
            self.decode_zstd_bytes_per_second,
        ];
        ensure!(
            rates
                .iter()
                .all(|&rate| (1..=1_000_000_000_000).contains(&rate))
                && self.per_entry_nanoseconds <= 1_000_000_000
                && self.startup_nanoseconds <= 60_000_000_000
                && self.raw_request_nanoseconds <= 60_000_000_000
                && (1..=256).contains(&self.raw_parallelism),
            "invalid original-package transfer cost estimate"
        );
        Ok(())
    }

    /// Predict time saved over raw content delivery, accounting for the
    /// complete archive expansion, not only the requested file subset.
    #[must_use = "only a positive saving merits original reconstruction"]
    pub fn predicted_savings_nanoseconds(
        self,
        raw_bytes: u128,
        raw_files: usize,
        archive: PackageArchive,
    ) -> Option<u128> {
        const SECOND: u128 = 1_000_000_000;
        if raw_files == 0 || self.validate().is_err() {
            return None;
        }
        let rate = u128::from(self.download_bytes_per_second);
        let request = u128::from(self.raw_request_nanoseconds);
        let batches = (raw_files as u128).div_ceil(u128::from(self.raw_parallelism));
        let raw_cost = raw_bytes * SECOND / rate + batches * request;
        let archive_cost = u128::from(archive.source.size) * SECOND
            / u128::from(self.archive_download_bytes_per_second)
            + self.archive_processing_nanoseconds(archive);
        raw_cost
            .checked_sub(archive_cost)
            .filter(|&saving| saving > 0)
    }

    /// Full decoder and per-entry service, excluding original wire bytes.
    #[must_use = "forecast must charge complete archive expansion"]
    pub fn archive_processing_nanoseconds(self, archive: PackageArchive) -> u128 {
        const SECOND: u128 = 1_000_000_000;
        let decode_rate = match archive.source.identity.compression {
            PackageCompression::Tar => self.decode_tar_bytes_per_second,
            PackageCompression::Gzip => self.decode_gzip_bytes_per_second,
            PackageCompression::Xz => self.decode_xz_bytes_per_second,
            PackageCompression::Zstd => self.decode_zstd_bytes_per_second,
        };
        u128::from(self.raw_request_nanoseconds)
            + u128::from(archive.expanded_bytes) * SECOND / u128::from(decode_rate.max(1))
            + u128::from(archive.entry_count) * u128::from(self.per_entry_nanoseconds)
            + u128::from(self.startup_nanoseconds)
    }
}

/// Original compressed transport representation of a verified package tree.
/// This is deliberately not part of the build's semantic filesystem identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageArchive {
    pub source: PackageSource,
    pub tree: crate::TreeId,
    pub blob: crate::BlobRef,
    /// All regular-file bytes decoded, including files not needed by this job.
    pub expanded_bytes: u64,
    /// Every archive tree entry contributes to decoder and index overhead.
    pub entry_count: u64,
}

#[cfg(test)]
mod transport_cost_tests {
    use super::*;
    use crate::{BlobRef, ContentId, TreeId};

    #[test]
    fn full_package_expansion_can_outweigh_bandwidth_savings() {
        // A signed GCC system original on Asus: large full package, but the
        // real compiler closure needs only part of it.
        let archive = PackageArchive {
            source: PackageSource {
                identity: PackageIdentity {
                    sha256: [17; 32],
                    compression: PackageCompression::Zstd,
                },
                size: 67_257_103,
            },
            tree: TreeId([31; 32]),
            blob: BlobRef {
                id: ContentId([23; 32]),
                size: 67_257_103,
            },
            expanded_bytes: 242_459_968,
            entry_count: 2855,
        };
        let fast_link = PackageTransferCost::default();
        assert!(
            fast_link
                .predicted_savings_nanoseconds(168_285_404, 285, archive)
                .is_none()
        );
        let slow_link = PackageTransferCost {
            download_bytes_per_second: 20 << 20,
            archive_download_bytes_per_second: 20 << 20,
            ..fast_link
        };
        assert!(
            slow_link
                .predicted_savings_nanoseconds(168_285_404, 285, archive)
                .is_some()
        );
        assert!(
            slow_link
                .predicted_savings_nanoseconds(40_000_000, 12, archive)
                .is_none()
        );
        let changed_decoder = PackageTransferCost {
            decode_zstd_bytes_per_second: 1,
            ..slow_link
        };
        assert!(
            changed_decoder
                .predicted_savings_nanoseconds(168_285_404, 285, archive)
                .is_none()
        );
        let invalid = PackageTransferCost {
            download_bytes_per_second: 0,
            ..slow_link
        };
        assert!(invalid.validate().is_err());
        assert!(
            invalid
                .predicted_savings_nanoseconds(168_285_404, 285, archive)
                .is_none()
        );
        let latency = PackageTransferCost {
            download_bytes_per_second: 1 << 30,
            archive_download_bytes_per_second: 1 << 30,
            raw_request_nanoseconds: 2_000_000,
            raw_parallelism: 1,
            startup_nanoseconds: 0,
            decode_zstd_bytes_per_second: 1 << 30,
            per_entry_nanoseconds: 0,
            ..fast_link
        };
        // Overfetching an original can be faster than many serial HTTP calls.
        assert!(
            latency
                .predicted_savings_nanoseconds(60_000_000, 150, archive)
                .is_some()
        );
        let concurrent = PackageTransferCost {
            raw_parallelism: 16,
            ..latency
        };
        assert!(
            concurrent
                .predicted_savings_nanoseconds(60_000_000, 150, archive)
                .is_none()
        );
    }
}
