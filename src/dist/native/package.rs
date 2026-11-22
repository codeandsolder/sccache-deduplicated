//! Trusted release checksums and restricted upstream package locators.

use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
    thread,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::build_runtime::PackageIdentity;

/// An original archive checksum and a relative path within a named,
/// administrator-configured repository. Never a caller-supplied download URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageLocator {
    pub identity: PackageIdentity,
    pub expected_size: Option<u64>,
    pub upstream: String,
    pub path: String,
}

impl PackageLocator {
    /// Derive an explicit Rust distribution locator from release metadata.
    /// The manifest URL supplies only the relative distribution path.
    /// # Errors
    /// Returns an error for an invalid distribution URL or path.
    pub fn from_rust_url(identity: PackageIdentity, url: &str) -> Result<Self> {
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
            expected_size: None,
            upstream: "rust".into(),
            path: format!("dist/{path}"),
        };
        locator.validate()?;
        Ok(locator)
    }

    /// Check the wire path independently of client-side URL parsing.
    /// Archive format is determined by the verified bytes and declared
    /// codec, not by a filename extension.
    /// # Errors
    /// Returns an error for invalid repository identifiers or paths.
    pub fn validate(&self) -> Result<()> {
        validate_upstream_name(&self.upstream)?;
        ensure!(
            self.path.len() <= 4096
                && self.path.split('/').all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'-' | b'_' | b'.' | b'+' | b'~' | b'@')
                        })
                }),
            "invalid original package relative path"
        );
        Ok(())
    }

    /// Resolve beneath the configured repository prefix without URL
    /// reference resolution, escapes, redirects or caller-controlled hosts.
    /// # Errors
    /// Returns an error for invalid base or locator.
    pub fn resolve(&self, base: &reqwest::Url) -> Result<reqwest::Url> {
        self.validate()?;
        validate_upstream_base(base)?;
        let mut url = base.clone();
        url.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("upstream URL cannot hold path segments"))?
            .pop_if_empty()
            .extend(self.path.split('/'));
        ensure!(
            url.origin() == base.origin() && url.path().starts_with(base.path()),
            "package locator escaped repository prefix"
        );
        Ok(url)
    }
}

/// Validate an administrator-configured repository identifier.
/// # Errors
/// Returns an error for invalid names.
pub fn validate_upstream_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "invalid package upstream name"
    );
    Ok(())
}

/// Validate a repository base URL, including its immutable path prefix.
/// # Errors
/// Returns an error for unsupported or ambiguous base URLs.
pub fn validate_upstream_base(url: &reqwest::Url) -> Result<()> {
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.path().ends_with('/')
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none(),
        "invalid original package upstream base URL"
    );
    Ok(())
}

/// Whether the scheduler already owned the verified package.
#[derive(Debug, Serialize, Deserialize)]
pub struct PackageAcquisition<T> {
    pub package: T,
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
        use crate::build_runtime::PackageCompression;
        let identity = PackageIdentity {
            sha256: [0; 32],
            compression: PackageCompression::Xz,
        };
        let locator = PackageLocator::from_rust_url(
            identity,
            "https://mirror.example/mirror/dist/2026-11-22/rustc-nightly.tar.xz",
        )?;
        assert_eq!(locator.upstream, "rust");
        assert_eq!(locator.path, "dist/2026-11-22/rustc-nightly.tar.xz");
        let base = reqwest::Url::parse("https://configured.example/repository/")?;
        assert_eq!(
            locator.resolve(&base)?.as_str(),
            "https://configured.example/repository/dist/2026-11-22/rustc-nightly.tar.xz"
        );
        for path in [
            "//host/file.tar.xz",
            "/dist/file.tar.xz",
            "../file.tar.xz",
            "dist/%2e%2e/file.tar.xz",
            "dist/dir//file.tar.xz",
            "dist/dir\\file.tar.xz",
            "dist/dir/file.tar.xz?x",
            "https://host/file.tar.xz",
            "dist/./file.tar.xz",
        ] {
            assert!(
                PackageLocator {
                    identity,
                    expected_size: None,
                    upstream: "rust".into(),
                    path: path.into()
                }
                .resolve(&base)
                .is_err(),
                "{path}"
            );
        }
        let system = PackageLocator {
            identity,
            expected_size: None,
            upstream: "cachyos-v3".into(),
            path: "gcc-16.2.1+r23+gd564253eb6c8-3-x86_64_v3.pkg.tar.zst".into(),
        };
        assert_eq!(
            system.resolve(&base)?.as_str(),
            "https://configured.example/repository/gcc-16.2.1+r23+gd564253eb6c8-3-x86_64_v3.pkg.tar.zst"
        );
        assert!(
            PackageLocator {
                upstream: "../wrong".into(),
                ..system
            }
            .validate()
            .is_err()
        );
        assert!(validate_upstream_base(&reqwest::Url::parse("https://host/repository")?).is_err());
        Ok(())
    }
}
