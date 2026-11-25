//! Durable enrollment authorization, independent of certificate lifetime.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize};

use super::{PeerId, Role};

const REGISTRY_LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Serialize, Deserialize)]
struct Record {
    role: Role,
    revoked: bool,
}

type Records = BTreeMap<PeerId, Record>;

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(REGISTRY_LIMIT)
        .reject_trailing_bytes()
}

fn publish(path: &Path, records: &mut Records, updated: Records) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let bytes = codec().serialize(&updated)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    // A successful rename is already visible. Keep memory coherent even if
    // the subsequent directory sync fails and durability cannot be confirmed.
    *records = updated;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// One scheduler-owned registry; its persistent tombstones prevent re-enrollment
/// of a revoked key using an otherwise valid bootstrap credential.
pub struct Registry {
    path: PathBuf,
    records: Mutex<Records>,
    _lock: fs::File,
}

impl Registry {
    /// Open durable enrollment records; never recover corrupt data as empty.
    ///
    /// # Errors
    /// Returns an error for unreadable or invalid persisted records.
    pub fn open(path: &Path) -> Result<Self> {
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        lock.try_lock()
            .context("enrollment registry already in use")?;
        let records = match fs::File::open(path) {
            Ok(file) => {
                ensure!(
                    file.metadata()?.len() <= REGISTRY_LIMIT,
                    "enrollment registry too large"
                );
                let mut bytes = Vec::new();
                file.take(REGISTRY_LIMIT + 1).read_to_end(&mut bytes)?;
                ensure!(
                    bytes.len() as u64 <= REGISTRY_LIMIT,
                    "enrollment registry too large"
                );
                codec().deserialize(&bytes)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Records::new(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            path: path.to_owned(),
            records: Mutex::new(records),
            _lock: lock,
        })
    }

    pub(crate) fn register(&self, id: PeerId, role: Role) -> Result<()> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("enrollment registry poisoned"))?;
        if let Some(record) = records.get(&id) {
            ensure!(
                !record.revoked && record.role == role,
                "enrollment key revoked or bound to another role"
            );
            return Ok(());
        }
        let mut updated = records.clone();
        updated.insert(
            id,
            Record {
                role,
                revoked: false,
            },
        );
        let result = publish(&self.path, &mut records, updated);
        drop(records);
        result
    }

    /// Check authorization for a verified TLS principal.
    ///
    /// # Errors
    /// Returns an error if the registry is unavailable.
    pub fn is_active(&self, id: PeerId, role: Role) -> Result<bool> {
        let records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("enrollment registry poisoned"))?;
        Ok(records
            .get(&id)
            .is_some_and(|record| !record.revoked && record.role == role))
    }

    /// Snapshot permanent revocations for authenticated worker distribution.
    ///
    /// # Errors
    /// Returns an error if the registry is unavailable.
    pub fn revoked(&self) -> Result<Vec<PeerId>> {
        let records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("enrollment registry poisoned"))?;
        Ok(records
            .iter()
            .filter_map(|(&id, record)| record.revoked.then_some(id))
            .collect())
    }

    /// Permanently revoke an enrolled key, including future renewal.
    ///
    /// # Errors
    /// Returns an error if the key does not exist or persistence fails.
    pub fn revoke(&self, id: PeerId) -> Result<()> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("enrollment registry poisoned"))?;
        let mut updated = records.clone();
        let record = updated.get_mut(&id).context("unknown enrollment key")?;
        record.revoked = true;
        let result = publish(&self.path, &mut records, updated);
        drop(records);
        result
    }
}
