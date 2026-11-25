//! A build-scoped lease for immutable intermediate artifacts.
use super::{NativeCacheClient, renewal::Renewals};
use crate::build_runtime::{BlobRef, ContentId, ResultManifest, wire::Ticket};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Seek, SeekFrom},
    sync::Mutex,
    time::Duration,
};

pub struct NativeResultSession {
    client: NativeCacheClient,
    group: Ticket,
    renewals: Option<Renewals>,
    blobs: Mutex<BTreeMap<ContentId, u64>>,
}

impl NativeResultSession {
    pub fn open(client: NativeCacheClient, interval: Duration) -> Result<Self> {
        let group = client.open_retention()?;
        let mut session = Self {
            client,
            group,
            renewals: None,
            blobs: Mutex::new(BTreeMap::new()),
        };
        let renewals = Renewals::start_retention(session.client.clone(), interval)?;
        renewals.add(group)?;
        session.renewals = Some(renewals);
        Ok(session)
    }

    fn check(&self) -> Result<()> {
        self.renewals
            .as_ref()
            .context("closed intermediate session")?
            .check()
    }

    pub(super) fn retain(&self, action: Ticket, manifest: &ResultManifest) -> Result<()> {
        self.check()?;
        let blobs = manifest.blobs()?;
        self.client
            .retain_result(self.group, action, manifest.id()?)?;
        let mut retained = self
            .blobs
            .lock()
            .map_err(|_| anyhow::anyhow!("intermediate session poisoned"))?;
        for (id, size) in blobs {
            ensure!(
                retained.get(&id).is_none_or(|old| *old == size),
                "conflicting retained content size"
            );
            retained.insert(id, size);
        }
        Ok(())
    }

    pub fn authorize(&self, blob: BlobRef) -> Result<()> {
        self.check()?;
        ensure!(
            self.blobs
                .lock()
                .map_err(|_| anyhow::anyhow!("intermediate session poisoned"))?
                .get(&blob.id)
                == Some(&blob.size),
            "content not retained by this build"
        );
        Ok(())
    }

    pub fn read(&self, blob: BlobRef) -> Result<File> {
        self.authorize(blob)?;
        let mut file = tempfile::tempfile()?;
        self.client.download_retained(self.group, blob, &mut file)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
}

impl Drop for NativeResultSession {
    fn drop(&mut self) {
        drop(self.renewals.take());
        if let Err(error) = self.client.close_retention(self.group) {
            log::debug!("intermediate lease close: {error:#}");
        }
    }
}

/// Tokens exposed to the local filesystem never contain scheduler authority.
#[derive(Default)]
pub(crate) struct Registry {
    groups: Mutex<BTreeMap<Ticket, (u32, std::sync::Weak<NativeResultSession>)>>,
}

impl Registry {
    pub(crate) fn insert(
        &self,
        uid: u32,
        session: &std::sync::Arc<NativeResultSession>,
    ) -> Result<Ticket> {
        let mut groups = self
            .groups
            .lock()
            .map_err(|_| anyhow::anyhow!("intermediate registry poisoned"))?;
        groups.retain(|_, (_, group)| group.strong_count() > 0);
        loop {
            let token = Ticket(rand::random());
            if let std::collections::btree_map::Entry::Vacant(entry) = groups.entry(token) {
                entry.insert((uid, std::sync::Arc::downgrade(session)));
                return Ok(token);
            }
        }
    }

    pub(crate) fn get(
        &self,
        uid: u32,
        token: Ticket,
    ) -> Result<std::sync::Arc<NativeResultSession>> {
        let groups = self
            .groups
            .lock()
            .map_err(|_| anyhow::anyhow!("intermediate registry poisoned"))?;
        let (owner, group) = groups.get(&token).context("unknown intermediate session")?;
        ensure!(*owner == uid, "intermediate session owner mismatch");
        group.upgrade().context("intermediate session closed")
    }
}
