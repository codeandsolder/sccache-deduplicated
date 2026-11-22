//! Verified installation metadata for short-lived compiler clients.
//!
//! A catalog is local trusted metadata, not an action-key input. Every reused
//! digest is bound to a regular file version checked in the caller namespace.
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

use super::{hash_open_source, open_source};
use crate::{
    BlobRef, InstallationManifest,
    installation::{read_document, write_document},
    source::FileVersion,
};

const CATALOG_MAGIC: &[u8] = b"sccache-installation-catalog-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AttestedFile {
    version: FileVersion,
    blob: BlobRef,
}

impl AttestedFile {
    pub(super) fn lookup(self, stat: &Stat) -> Option<BlobRef> {
        (self.version == FileVersion::from(stat)).then_some(self.blob)
    }
}

/// Host- and boot-specific verified package digests. The catalog must be
/// produced and stored by the trusted installation owner, not supplied by
/// unrelated cache clients.
#[derive(Debug, Serialize, Deserialize)]
pub struct InstallationCatalog {
    boot: Vec<u8>,
    packages: BTreeSet<[u8; 32]>,
    files: BTreeMap<Vec<u8>, AttestedFile>,
}

/// Explicit accounting of verification, including files that were modified
/// or were not present in the installation. Only exact matches are reusable.
#[derive(Debug, Default, Serialize)]
pub struct InstallationReport {
    pub verified_files: u64,
    pub verified_bytes: u64,
    pub missing_files: u64,
    pub differing_files: u64,
}

fn boot_id() -> Result<Vec<u8>> {
    let boot = fs::read("/proc/sys/kernel/random/boot_id")?;
    ensure!(
        boot.len() == 37 && boot.ends_with(b"\n"),
        "invalid Linux boot identity"
    );
    Ok(boot)
}

impl InstallationCatalog {
    /// Verify original package file digests against one installed sysroot.
    /// Missing or modified files remain ordinary discovered inputs.
    /// # Errors
    /// Returns an error for invalid manifests, filesystem errors or conflicts.
    pub fn attest(
        root: &Path,
        manifests: &[InstallationManifest],
    ) -> Result<(Self, InstallationReport)> {
        let root = root.canonicalize()?;
        ensure!(root.is_dir(), "installation root is not a directory");
        let mut catalog = Self {
            boot: boot_id()?,
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
            if u64::try_from(stat.st_size)? != blob.size || hash_open_source(&file, &stat)? != blob
            {
                report.differing_files += 1;
                continue;
            }
            let record = AttestedFile {
                version: FileVersion::from(&stat),
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
        ensure!(
            catalog.boot == boot_id()?,
            "installation catalog belongs to another kernel boot"
        );
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
    let Some(blob) = attested.get(path).and_then(|record| record.lookup(version)) else {
        return Ok(None);
    };
    crate::source::unchanged(version, &fstat(file)?)?;
    Ok(Some(blob))
}

#[cfg(all(test, feature = "store"))]
mod tests;
