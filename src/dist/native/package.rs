//! Trusted release checksums and restricted upstream package locators.

use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
    thread,
};

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

/// Apply independent package acquisitions with bounded concurrency.
/// Stops starting new acquisitions on a fatal error and joins all active work.
///
/// # Errors
/// Returns an acquisition, thread creation or worker panic error.
pub fn map_packages<T: Sync, U: Send>(
    requests: &[T],
    jobs: NonZeroUsize,
    operation: impl Fn(&T) -> Result<U> + Sync,
) -> Result<Vec<U>> {
    if jobs.get() == 1 || requests.len() <= 1 {
        return requests.iter().map(operation).collect();
    }
    let next = AtomicUsize::new(0);
    thread::scope(|scope| {
        let mut workers = Vec::new();
        let mut failure = None;
        for _ in 0..jobs.get().min(requests.len()) {
            let worker = thread::Builder::new().spawn_scoped(scope, || {
                let mut packages = Vec::new();
                while let Some(request) = requests.get(next.fetch_add(1, Ordering::Relaxed)) {
                    match operation(request) {
                        Ok(package) => packages.push(package),
                        Err(error) => {
                            next.store(requests.len(), Ordering::Relaxed);
                            return Err(error);
                        }
                    }
                }
                Ok(packages)
            });
            match worker {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    next.store(requests.len(), Ordering::Relaxed);
                    failure = Some(error.into());
                    break;
                }
            }
        }
        let mut acquired = Vec::new();
        for worker in workers {
            match worker.join() {
                Ok(Ok(packages)) => acquired.extend(packages),
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(_) => {
                    failure.get_or_insert_with(|| {
                        anyhow::anyhow!("package acquisition worker panicked")
                    });
                }
            }
        }
        failure.map_or(Ok(acquired), Err)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_mapping_runs_bounded_parallel_work() -> Result<()> {
        use std::sync::Barrier;
        let barrier = Barrier::new(2);
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let mut result = map_packages(
            &[0, 1, 2, 3, 4, 5],
            NonZeroUsize::MIN.saturating_add(1),
            |value| {
                let concurrent = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(concurrent, Ordering::SeqCst);
                if *value < 2 {
                    barrier.wait();
                }
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(*value)
            },
        )?;
        result.sort_unstable();
        assert_eq!(result, [0, 1, 2, 3, 4, 5]);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        Ok(())
    }

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
