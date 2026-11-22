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

/// Original compressed transport representation of a verified package tree.
/// This is deliberately not part of the build's semantic filesystem identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageArchive {
    pub source: PackageSource,
    pub tree: crate::TreeId,
    pub blob: crate::BlobRef,
}
