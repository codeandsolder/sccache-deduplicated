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
