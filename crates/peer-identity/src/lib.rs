//! Wire-level peer identity, with no TLS or runtime dependency.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Immutable identity of an enrolled public key, independent of the leaf certificate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Construct an identity from a SHA-256 `SubjectPublicKeyInfo` digest.
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
        for (byte, encoded) in digest.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
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

/// The configured reliable endpoint and bounded alternate interface addresses.
/// Addresses are routing hints, not authentication credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSet {
    pub primary: std::net::SocketAddr,
    pub alternatives: Vec<std::net::SocketAddr>,
}

impl RouteSet {
    pub const MAX_ALTERNATIVES: usize = 8;

    /// Accept routable unicast addresses. Scope-local IPv6 addresses cannot
    /// be used on another host without its own interface index.
    #[must_use = "eligibility determines whether an address can be advertised"]
    pub const fn eligible(address: std::net::SocketAddr) -> bool {
        use std::net::IpAddr;
        address.port() != 0
            && match address.ip() {
                IpAddr::V4(ip) => {
                    !ip.is_unspecified()
                        && !ip.is_multicast()
                        && !ip.is_broadcast()
                        && !ip.is_link_local()
                }
                IpAddr::V6(ip) => {
                    !ip.is_unspecified()
                        && !ip.is_multicast()
                        && !ip.is_unicast_link_local()
                        && ip.to_ipv4_mapped().is_none()
                        && matches!(address, std::net::SocketAddr::V6(v6) if v6.scope_id() == 0)
                }
            }
    }

    /// Canonicalize discovered addresses; preserve the configured fallback.
    #[must_use = "the canonical route set must be used"]
    pub fn new(
        primary: std::net::SocketAddr,
        candidates: impl IntoIterator<Item = std::net::SocketAddr>,
    ) -> Self {
        let alternatives = candidates
            .into_iter()
            .filter(|&address| {
                address != primary && Self::eligible(address) && !address.ip().is_loopback()
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .take(Self::MAX_ALTERNATIVES)
            .collect();
        Self {
            primary,
            alternatives,
        }
    }

    /// Reject malformed or oversized remote advertisements.
    #[must_use = "remote advertisements must be validated"]
    pub fn valid(&self) -> bool {
        Self::eligible(self.primary)
            && self.alternatives.len() <= Self::MAX_ALTERNATIVES
            && *self == Self::new(self.primary, self.alternatives.iter().copied())
    }

    pub fn iter(&self) -> impl Iterator<Item = std::net::SocketAddr> + '_ {
        std::iter::once(self.primary).chain(self.alternatives.iter().copied())
    }
}
