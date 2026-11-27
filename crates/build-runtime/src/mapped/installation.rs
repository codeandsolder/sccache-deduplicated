//! Verified installation metadata for short-lived compiler clients.
//!
//! A catalog is local trusted metadata, not an action-key input. Every reused
//! digest is bound to a kernel-verified immutable content identity.
//! The normal discovery path still defines the actual recipe and its topology.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use rustix::fs::{Stat, fstat};
use serde::{Deserialize, Serialize};

use super::{
    digest_cache::{VerityIdentity, verity_identity},
    hash_open_source, open_source,
};
use crate::{
    BlobRef, InstallationManifest,
    installation::{read_document, write_document},
};

const CATALOG_MAGIC: &[u8] = b"sccache-installation-catalog-v3\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AttestedFile {
    identity: Option<VerityIdentity>,
    blob: BlobRef,
}

/// Content-verified package digests. The catalog must be
/// produced and stored by the trusted installation owner, not supplied by
/// unrelated cache clients.
#[derive(Debug, Serialize, Deserialize)]
pub struct InstallationCatalog {
    packages: BTreeSet<[u8; 32]>,
    files: BTreeMap<Vec<u8>, AttestedFile>,
}

/// Explicit accounting of verification, including files that were modified
/// or were not present in the installation. Only exact matches are reusable.
#[derive(Debug, Default, Serialize)]
pub struct InstallationReport {
    pub verified_files: u64,
    pub verified_bytes: u64,
    pub reused_files: u64,
    pub reused_bytes: u64,
    pub missing_files: u64,
    pub differing_files: u64,
}

impl InstallationCatalog {
    /// Verify original package file digests against one installed sysroot.
    /// Missing or modified files remain ordinary discovered inputs.
    /// # Errors
    /// Returns an error for invalid manifests, filesystem errors or conflicts.
    pub fn attest(
        root: &Path,
        manifests: &[InstallationManifest],
        previous: Option<&Path>,
    ) -> Result<(Self, InstallationReport)> {
        let root = root.canonicalize()?;
        ensure!(root.is_dir(), "installation root is not a directory");
        let mut catalog = Self {
            packages: BTreeSet::new(),
            files: BTreeMap::new(),
        };
        let mut expected = BTreeMap::new();
        for manifest in manifests {
            manifest.validate()?;
            catalog.packages.insert(manifest.source.identity.sha256);
            for (path, blob) in manifest.files()? {
                if let Some(previous) = expected.insert(path, blob) {
                    ensure!(previous == blob, "conflicting original package contents");
                }
            }
        }
        ensure!(!expected.is_empty(), "no installation files to verify");
        let previous = match previous {
            Some(path) if path.exists() => match Self::load(path) {
                Ok(files) => files,
                Err(error) => {
                    log::warn!("Previous installation catalog unavailable: {error:#}");
                    BTreeMap::new()
                }
            },
            _ => BTreeMap::new(),
        };
        let mut report = InstallationReport::default();
        for (path, blob) in expected {
            let local = root.join(std::ffi::OsStr::from_bytes(path.as_bytes()));
            let resolved = match local.canonicalize() {
                Ok(resolved) => resolved,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    report.missing_files += 1;
                    continue;
                }
                Err(error) => return Err(error).context("resolve installed package file"),
            };
            if !resolved.starts_with(&root) || !resolved.is_file() {
                report.differing_files += 1;
                continue;
            }
            let (file, stat) = open_source(&resolved)?;
            if u64::try_from(stat.st_size)? != blob.size {
                report.differing_files += 1;
                continue;
            }
            let reused = lookup(&previous, &resolved, &file, &stat)? == Some(blob);
            if reused {
                report.reused_files += 1;
                report.reused_bytes += blob.size;
            } else if hash_open_source(&file, &stat)? != blob {
                report.differing_files += 1;
                continue;
            }
            // The catalog records the expected content of all verified files.
            // Only fs-verity identities permit subsequent reuse without reads.
            let record = AttestedFile {
                identity: verity_identity(&file),
                blob,
            };
            let path = resolved.into_os_string().into_vec();
            if let Some(previous) = catalog.files.insert(path, record) {
                ensure!(previous == record, "installation changed while verifying");
            }
            report.verified_files += 1;
            report.verified_bytes += blob.size;
        }
        Ok((catalog, report))
    }

    /// Encode the local attestation. The caller owns atomic publication and
    /// file permissions.
    /// # Errors
    /// Returns an error for encoding or I/O failures.
    pub fn write(&self, writer: impl Write) -> Result<()> {
        write_document(writer, CATALOG_MAGIC, self)
    }

    pub(super) fn load(path: &Path) -> Result<BTreeMap<PathBuf, AttestedFile>> {
        let catalog: Self = read_document(File::open(path)?, CATALOG_MAGIC)?;
        let mut files = BTreeMap::new();
        for (path, record) in catalog.files {
            let path = PathBuf::from(std::ffi::OsString::from_vec(path));
            ensure!(path.is_absolute(), "relative attested installation path");
            files.insert(path, record);
        }
        Ok(files)
    }
}

pub(super) fn lookup(
    attested: &BTreeMap<PathBuf, AttestedFile>,
    path: &Path,
    file: &File,
    version: &Stat,
) -> Result<Option<BlobRef>> {
    let Some(record) = attested.get(path) else {
        return Ok(None);
    };
    let Some(identity) = verity_identity(file) else {
        return Ok(None);
    };
    if record.identity != Some(identity) {
        return Ok(None);
    }
    crate::source::unchanged(version, &fstat(file)?)?;
    ensure!(
        record.blob.size == u64::try_from(version.st_size)?,
        "verified catalog length mismatch"
    );
    Ok(Some(record.blob))
}

#[cfg(all(test, feature = "store"))]
mod tests;
