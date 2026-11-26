//! Low-rate shared namespace observations, independent of capacity pruning.
use super::*;
use crate::build_runtime::analytics::{TierCacheReport, record_age_bucket};

impl ManagedRemoteCache {
    /// Read the shared report; at most one client per namespace refreshes it
    /// every half hour. No prune, artifact mutation, or hot-path query occurs.
    ///
    /// # Errors
    /// Returns an error if an observation cannot be read or refreshed.
    pub async fn analytics_report(
        &self,
        allow_refresh: bool,
    ) -> anyhow::Result<Option<TierCacheReport>> {
        const REFRESH_SECS: u64 = 1800;
        const LEASE_SECS: u64 = 300;
        const SCAN_TIMEOUT: Duration = Duration::from_secs(240);
        let path = format!("{}/{}", self.metadata_prefix(), ANALYTICS_REPORT_BASENAME);
        let lease = format!("{}/{}", self.metadata_prefix(), ANALYTICS_LEASE_BASENAME);
        let previous = self.read_analytics_report(&path).await?;
        if !allow_refresh
            || previous.as_ref().is_some_and(|(report, _)| {
                unix_seconds().saturating_sub(report.sampled_at) < REFRESH_SECS
            })
        {
            return Ok(previous.map(|(report, _)| report));
        }
        if self.acquire_lease_at(&lease, LEASE_SECS).await?.is_none() {
            return Ok(previous.map(|(report, _)| report));
        }
        // A prior writer may have finished between the first read and lease acquisition.
        let previous = self.read_analytics_report(&path).await?;
        if previous.as_ref().is_some_and(|(report, _)| {
            unix_seconds().saturating_sub(report.sampled_at) < REFRESH_SECS
        }) {
            return Ok(previous.map(|(report, _)| report));
        }
        let refreshed = tokio::time::timeout(SCAN_TIMEOUT, async {
            let report = self.scan_analytics().await?;
            let body = bincode::serialize(&report)?;
            let write = self.operator.write_with(&path, body);
            let result = if let Some((_, etag)) = &previous {
                write.if_match(etag).await
            } else {
                write.if_not_exists(true).await
            };
            match result {
                Ok(_) => Ok::<_, anyhow::Error>(Some(report)),
                Err(error) if error.kind() == ErrorKind::ConditionNotMatch => Ok(self
                    .read_analytics_report(&path)
                    .await?
                    .map(|(report, _)| report)),
                Err(error) => Err(error.into()),
            }
        })
        .await;
        match refreshed {
            Ok(Ok(report)) => Ok(report),
            Ok(Err(error)) => {
                warn!("managed cache analytics refresh failed: {error:#}");
                Ok(previous.map(|(report, _)| report))
            }
            Err(error) => {
                warn!("managed cache analytics refresh timed out: {error}");
                Ok(previous.map(|(report, _)| report))
            }
        }
    }

    async fn read_analytics_report(
        &self,
        path: &str,
    ) -> anyhow::Result<Option<(TierCacheReport, String)>> {
        let reader = match self.operator.reader(path).await {
            Ok(reader) => reader,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let body = match reader.read(..).await {
            Ok(body) => body.to_bytes(),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let etag = reader
            .metadata()
            .and_then(|metadata| metadata.etag().map(str::to_owned))
            .ok_or_else(|| anyhow::anyhow!("managed cache analytics report has no ETag"))?;
        let report = bincode::deserialize(&body)?;
        Ok(Some((report, etag)))
    }

    async fn scan_analytics(&self) -> anyhow::Result<TierCacheReport> {
        let sampled_at = unix_seconds();
        let metadata_prefix = format!("{}/", self.metadata_prefix());
        let shard_prefix = format!("{metadata_prefix}{METADATA_SHARD_DIR}/");
        let shard_paths = self
            .operator
            .list_with(&shard_prefix)
            .recursive(true)
            .await?
            .into_iter()
            .filter(|entry| entry.metadata().mode() == EntryMode::FILE)
            .map(|entry| entry.path().to_owned())
            .collect();
        let metadata = self.load_metadata_entries(shard_paths).await;
        let mut listing = self.operator.lister_with("").recursive(true).await?;
        let mut report = TierCacheReport {
            sampled_at,
            managed_heat: true,
            ..Default::default()
        };
        while let Some(entry) = listing.next().await {
            let entry = entry?;
            if entry.metadata().mode() != EntryMode::FILE
                || entry.path().starts_with(&metadata_prefix)
                || entry.path() == ".sccache_check"
            {
                continue;
            }
            let key = CacheObjectKey::from_data_path(entry.path());
            let candidate = Candidate {
                path: entry.path().to_owned(),
                key,
                size: entry.metadata().content_length(),
                listed_last_access: entry
                    .metadata()
                    .last_modified()
                    .map_or(0, timestamp_seconds),
                metadata: key.and_then(|key| metadata.get(&key).copied()),
            };
            self.record_analytics(&mut report, candidate);
        }
        Ok(report)
    }

    fn record_analytics(&self, report: &mut TierCacheReport, candidate: Candidate) {
        let now = report.sampled_at;
        let age = candidate
            .metadata
            .map(|metadata| now.saturating_sub(metadata.last_access));
        let heat = candidate.metadata.map(|metadata| {
            decayed_heat_milli(
                metadata.heat_milli,
                metadata.last_access,
                now,
                self.config.heat_half_life_secs,
            )
        });
        let score = self.score_candidate(candidate, now);
        let weight = report
            .distribution
            .record(score.candidate.size, None, 1, heat, age);
        record_age_bucket(
            &mut report.policy_age,
            Some(now.saturating_sub(score.virtual_last_access)),
            &weight,
        );
    }
}
