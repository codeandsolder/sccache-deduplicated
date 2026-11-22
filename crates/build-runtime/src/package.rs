//! Portable identities for original upstream archives.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Compression of the original upstream tar package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PackageCompression {
    Tar,
    Gzip,
    Xz,
}

/// Upstream package identity, independent of the normalized content tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageSource {
    pub sha256: [u8; 32],
    pub size: u64,
    pub compression: PackageCompression,
}

impl PackageSource {
    /// Parse an upstream SHA-256 checksum, with explicit archive length and codec.
    /// # Errors
    /// Returns an error for an invalid hexadecimal checksum.
    pub fn from_sha256_hex(hash: &str, size: u64, compression: PackageCompression) -> Result<Self> {
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
            size,
            compression,
        })
    }
}
