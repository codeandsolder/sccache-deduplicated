//! Wire-level peer identity, with no TLS or runtime dependency.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Immutable identity of an enrolled public key, independent of the leaf certificate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Construct an identity from a SHA-256 SubjectPublicKeyInfo digest.
    #[must_use = "the digest identifies the enrolled peer"]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for PeerId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let text = String::deserialize(deserializer)?;
            text.parse().map_err(serde::de::Error::custom)
        } else {
            Ok(Self(<[u8; 32]>::deserialize(deserializer)?))
        }
    }
}

/// Invalid hexadecimal peer identity.
#[derive(Debug)]
pub struct ParsePeerIdError;

impl fmt::Display for ParsePeerIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected a 64-digit hexadecimal peer identity")
    }
}

impl std::error::Error for ParsePeerIdError {}

impl std::str::FromStr for PeerId {
    type Err = ParsePeerIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ParsePeerIdError);
        }
        let mut digest = [0; 32];
        for (byte, encoded) in digest.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            *byte = u8::from_str_radix(
                std::str::from_utf8(encoded).map_err(|_| ParsePeerIdError)?,
                16,
            )
            .map_err(|_| ParsePeerIdError)?;
        }
        Ok(Self(digest))
    }
}

/// A role assigned by the enrollment authority, not the requesting peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Role {
    Scheduler,
    Worker,
    Client,
}

impl Role {
    /// Role name used in certificate subjects and logical service names.
    #[must_use = "the name identifies the authorized role"]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::Worker => "worker",
            Self::Client => "client",
        }
    }

    /// Stable DNS-shaped TLS name. No DNS lookup is required.
    #[must_use = "the returned value is required for TLS identity verification"]
    pub fn tls_name(self, peer: PeerId) -> String {
        let hex = peer.to_string();
        let (left, right) = hex.split_at(32);
        format!("{left}.{right}.{}.sccache.invalid", self.label())
    }
}

/// Explicit trust and local identity storage for a cluster member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub directory: std::path::PathBuf,
    pub ca_certificate: std::path::PathBuf,
    pub scheduler_id: PeerId,
}
