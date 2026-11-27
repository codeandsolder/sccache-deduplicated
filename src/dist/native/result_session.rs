//! A build-scoped lease for immutable intermediate artifacts.
use super::{NativeCacheClient, renewal::Renewals};
use crate::build_runtime::{BlobRef, ContentId, ResultManifest, wire::Ticket};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, fs::File, sync::Mutex, time::Duration};

pub struct NativeResultSession {
    client: NativeCacheClient,
    group: Ticket,
    renewals: Option<Renewals>,
    interval: Duration,
    blobs: Mutex<BTreeMap<ContentId, u64>>,
}

impl NativeResultSession {
    pub fn open(client: NativeCacheClient, interval: Duration) -> Result<Self> {
        let group = client.open_retention()?;
        let mut session = Self {
            client,
            group,
            renewals: None,
            interval,
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
        self.record_blobs(blobs)
    }

    fn record_blobs(&self, blobs: BTreeMap<ContentId, u64>) -> Result<()> {
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

    pub fn retain_package(
        &self,
        identity: crate::build_runtime::PackageIdentity,
        upstream: String,
        path: String,
        offline: bool,
    ) -> Result<Option<crate::build_runtime::RetainedPackage>> {
        self.check()?;
        let locator = super::PackageLocator {
            identity,
            expected_size: None,
            upstream,
            path,
        };
        let package = self.client.retain_package(self.group, &locator, offline)?;
        if let Some(package) = &package {
            self.record_blobs(package.manifest.blobs()?)?;
        }
        Ok(package)
    }

    pub fn retain_impact_head(
        &self,
        scope: ContentId,
    ) -> Result<Option<crate::build_runtime::wire::ImpactHead>> {
        self.check()?;
        let head = self.client.retain_impact_head(self.group, scope)?;
        if let Some(head) = head {
            self.record_blobs(BTreeMap::from([(head.blob.id, head.blob.size)]))?;
        }
        Ok(head)
    }

    pub fn publish_impact_head(
        &self,
        scope: ContentId,
        expected: Option<crate::build_runtime::TreeId>,
        blob: BlobRef,
        file: File,
    ) -> Result<crate::build_runtime::wire::ImpactUpdate> {
        self.check()?;
        self.client
            .publish_impact_head(self.group, scope, expected, blob, file, self.interval)
    }

    pub fn read(&self, blob: BlobRef) -> Result<File> {
        self.authorize(blob)?;
        self.client.download_retained(self.group, blob)
    }
}

impl Drop for NativeResultSession {
    fn drop(&mut self) {
        let renewals = self.renewals.take();
        let client = self.client.clone();
        let group = self.group;
        let cleanup = move || {
            drop(renewals);
            if let Err(error) = client.close_retention(group) {
                log::debug!("intermediate lease close: {error:#}");
            }
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn_blocking(cleanup);
        } else {
            cleanup();
        }
    }
}

/// Tokens exposed to the local filesystem never contain scheduler authority.
#[derive(Default)]
pub struct Registry {
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
        let group = group.upgrade().context("intermediate session closed");
        drop(groups);
        group
    }
}
