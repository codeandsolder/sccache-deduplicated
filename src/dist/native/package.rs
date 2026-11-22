//! Trusted release checksums and restricted upstream package locators.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::build_runtime::{InstallationManifest, PackageCompression, PackageIdentity};

/// The client supplies the exact checksum from its release manifest and a
/// path inside the configured Rust distribution origin, never an arbitrary
/// scheduler download URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustPackageLocator {
    pub identity: PackageIdentity,
    pub path: String,
}

impl RustPackageLocator {
    /// Derive an upstream locator from Rust release metadata.
    /// # Errors
    /// Returns an error for an invalid distribution URL or path.
    pub fn from_url(identity: PackageIdentity, url: &str) -> Result<Self> {
        let url = reqwest::Url::parse(url)?;
        ensure!(
            matches!(url.scheme(), "https" | "http")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid Rust package URL"
        );
        let path = url
            .path()
            .split_once("/dist/")
            .context("package URL outside Rust dist directory")?
            .1;
        let locator = Self {
            identity,
            path: format!("/dist/{path}"),
        };
        locator.validate()?;
        Ok(locator)
    }

    /// Check the wire path independently of client-side URL parsing.
    /// # Errors
    /// Returns an error for traversal, URL syntax or incorrect codec suffix.
    pub fn validate(&self) -> Result<()> {
        let path = self
            .path
            .strip_prefix("/dist/")
            .context("package path outside dist directory")?;
        ensure!(
            path.len() <= 1024
                && path.split('/').all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                        })
                }),
            "invalid Rust distribution path"
        );
        let suffix = match self.identity.compression {
            PackageCompression::Tar => ".tar",
            PackageCompression::Gzip => ".tar.gz",
            PackageCompression::Xz => ".tar.xz",
        };
        ensure!(path.ends_with(suffix), "Rust package path codec mismatch");
        Ok(())
    }
}

/// The scheduler reports whether it already owned the verified package.
#[derive(Debug, Serialize, Deserialize)]
pub struct PackageAcquisition {
    pub manifest: InstallationManifest,
    pub reused: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_path_cannot_escape_configured_distribution_origin() -> Result<()> {
        let identity = PackageIdentity {
            sha256: [0; 32],
            compression: PackageCompression::Xz,
        };
        let locator = RustPackageLocator::from_url(
            identity,
            "https://mirror.example/mirror/dist/2026-11-22/rustc-nightly.tar.xz",
        )?;
        assert_eq!(locator.path, "/dist/2026-11-22/rustc-nightly.tar.xz");
        for path in [
            "//host/dist/file.tar.xz",
            "/dist/../file.tar.xz",
            "/dist/%2e%2e/file.tar.xz",
            "/dist/dir//file.tar.xz",
            "/dist/dir\\file.tar.xz",
            "/dist/dir/file.tar.xz?x",
            "/dist/dir/file.tar.gz",
        ] {
            assert!(
                RustPackageLocator {
                    identity,
                    path: path.into()
                }
                .validate()
                .is_err(),
                "{path}"
            );
        }
        Ok(())
    }
}
