// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Optional direct metrics delivery from the sccache server.
//!
//! The compile path only updates the server's existing in-memory statistics. A
//! low-frequency sampler snapshots those statistics and lets lurkmoar suppress
//! unchanged samples and handle delivery retries independently of compilation.

use crate::mock_command::CommandCreatorSync;
use crate::server::{DistInfo, PerLanguageCount, SccacheService, ServerInfo, ServerStats};
use lurkmoar::{Client, ClientBuilder, Gauge};
use std::collections::HashMap;
use std::env;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

pub(crate) const CAPABILITY: &str = "direct-metrics";

const URL_ENV: &str = "SCCACHE_METRICS_URL";
const INSTANCE_ENV: &str = "SCCACHE_METRICS_INSTANCE";
const SERVICE_ENV: &str = "SCCACHE_METRICS_SERVICE";
const INTERVAL_ENV: &str = "SCCACHE_METRICS_INTERVAL_MS";
const TIMEOUT_ENV: &str = "SCCACHE_METRICS_TIMEOUT_MS";
const HEARTBEAT_ENV: &str = "SCCACHE_METRICS_HEARTBEAT_MS";
const SPILL_AFTER_ENV: &str = "SCCACHE_METRICS_SPILL_AFTER_SECONDS";
const SPOOL_DIR_ENV: &str = "SCCACHE_METRICS_SPOOL_DIR";
const SPOOL_MAX_ENV: &str = "SCCACHE_METRICS_SPOOL_MAX_BYTES";
const DEFAULT_INTERVAL_MS: u64 = 2_500;
const DEFAULT_TIMEOUT_MS: u64 = 1_000;
const DEFAULT_HEARTBEAT_MS: u64 = 60_000;
const DEFAULT_SPILL_AFTER_SECONDS: u64 = 10;
const DEFAULT_SPOOL_MAX_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SeriesKey {
    name: &'static str,
    labels: Vec<(String, String)>,
}

struct Publisher {
    client: Client,
    gauges: HashMap<SeriesKey, Gauge>,
    force_heartbeat: bool,
}

impl Publisher {
    fn from_env() -> Result<Option<(Self, Duration, Duration)>, String> {
        let Some(url) = env::var_os(URL_ENV) else {
            return Ok(None);
        };
        let url = url
            .into_string()
            .map_err(|_| format!("{URL_ENV} is not valid UTF-8"))?;
        if url.is_empty() {
            return Ok(None);
        }

        let interval = env_duration_ms(INTERVAL_ENV, DEFAULT_INTERVAL_MS, 100)?;
        let timeout = env_duration_ms(TIMEOUT_ENV, DEFAULT_TIMEOUT_MS, 1)?;
        let heartbeat = env_duration_ms(HEARTBEAT_ENV, DEFAULT_HEARTBEAT_MS, 1_000)?;
        let spill_after = env_duration_seconds(SPILL_AFTER_ENV, DEFAULT_SPILL_AFTER_SECONDS, 1)?;
        let instance = metrics_instance()?;
        let mut builder = ClientBuilder::new(url)
            .static_label("job", "sccache")
            .static_label("instance", instance)
            .static_label("resolution", "raw")
            .timeout(timeout)
            .spill_after(spill_after);
        if let Some(service) = optional_nonempty_env(SERVICE_ENV)? {
            builder = builder.static_label("service", service);
        }

        if let Some(directory) = env::var_os(SPOOL_DIR_ENV) {
            let directory = directory
                .into_string()
                .map_err(|_| format!("{SPOOL_DIR_ENV} is not valid UTF-8"))?;
            if !directory.is_empty() {
                let max_bytes = env_u64(SPOOL_MAX_ENV, DEFAULT_SPOOL_MAX_BYTES, 1)?;
                builder = builder.spool(directory, max_bytes);
            }
        }

        let client = builder
            .build()
            .map_err(|error| format!("initialize lurkmoar metrics delivery: {error}"))?;
        Ok(Some((
            Self {
                client,
                gauges: HashMap::new(),
                force_heartbeat: false,
            },
            interval,
            heartbeat,
        )))
    }

    fn set<I, K, V>(&mut self, name: &'static str, value: f64, labels: I) -> Result<(), String>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let labels = labels
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect::<Vec<_>>();
        let key = SeriesKey {
            name,
            labels: labels.clone(),
        };
        let gauge = if let Some(gauge) = self.gauges.get(&key) {
            gauge.clone()
        } else {
            let gauge = self
                .client
                .gauge(name, labels.clone())
                .map_err(|error| format!("create metrics series {name}: {error}"))?;
            let _old = self.gauges.insert(key, gauge.clone());
            gauge
        };
        let changed = gauge
            .set(value)
            .map_err(|error| format!("publish metrics series {name}: {error}"))?;
        if self.force_heartbeat && !changed {
            self.client
                .sample(name, value, labels)
                .map_err(|error| format!("publish metrics heartbeat {name}: {error}"))?;
        }
        Ok(())
    }

    fn set_u64<I, K, V>(&mut self, name: &'static str, value: u64, labels: I) -> Result<(), String>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.set(name, prometheus_u64(value), labels)
    }

    fn update(
        &mut self,
        info: &ServerInfo,
        dist: Option<&DistInfo>,
        force_heartbeat: bool,
    ) -> Result<(), String> {
        self.force_heartbeat = force_heartbeat;
        self.set("sccache_info", 1.0, [("version", info.version.as_str())])?;
        if let Some(value) = info.cache_size {
            self.set_u64("sccache_cache_size_bytes", value, [("kind", "current")])?;
        }
        if let Some(value) = info.max_cache_size {
            self.set_u64("sccache_cache_size_bytes", value, [("kind", "max")])?;
        }
        self.set(
            "sccache_preprocessor_cache_mode",
            if info.use_preprocessor_cache_mode {
                1.0
            } else {
                0.0
            },
            std::iter::empty::<(&str, &str)>(),
        )?;
        self.set_u64(
            "sccache_basedirs",
            usize_to_u64(info.basedirs.len()),
            std::iter::empty::<(&str, &str)>(),
        )?;

        self.update_stats(&info.stats)?;
        if let Some(dist) = dist {
            self.update_dist(dist)?;
        }
        Ok(())
    }

    fn update_stats(&mut self, stats: &ServerStats) -> Result<(), String> {
        self.update_request_stats(stats)?;
        self.update_dynamic_stats(stats)?;
        self.update_multilevel_stats(stats)
    }

    fn update_request_stats(&mut self, stats: &ServerStats) -> Result<(), String> {
        for (result, value) in [
            ("compile", stats.compile_requests),
            ("unsupported_compiler", stats.requests_unsupported_compiler),
            ("not_compile", stats.requests_not_compile),
            ("not_cacheable", stats.requests_not_cacheable),
            ("executed", stats.requests_executed),
        ] {
            self.set_u64("sccache_requests_total", value, [("result", result)])?;
        }

        self.update_per_language("error", &stats.cache_errors)?;
        self.update_per_language("hit", &stats.cache_hits)?;
        self.update_per_language("miss", &stats.cache_misses)?;
        for (event, value) in [
            ("timeout", stats.cache_timeouts),
            ("read_error", stats.cache_read_errors),
            (
                "non_cacheable_compilation",
                stats.non_cacheable_compilations,
            ),
            ("forced_recache", stats.forced_recaches),
            ("write_error", stats.cache_write_errors),
            ("write", stats.cache_writes),
        ] {
            self.set_u64("sccache_cache_events_total", value, [("event", event)])?;
        }

        for (result, value) in [
            ("performed", stats.compilations),
            ("failed", stats.compile_fails),
        ] {
            self.set_u64("sccache_compilations_total", value, [("result", result)])?;
        }
        for (operation, duration) in [
            ("cache_write", stats.cache_write_duration),
            ("cache_read_hit", stats.cache_read_hit_duration),
            ("compile", stats.compiler_write_duration),
        ] {
            self.set(
                "sccache_duration_seconds_total",
                duration.as_secs_f64(),
                [("operation", operation)],
            )?;
        }
        Ok(())
    }

    fn update_dynamic_stats(&mut self, stats: &ServerStats) -> Result<(), String> {
        for (reason, value) in &stats.not_cached {
            self.set_u64(
                "sccache_not_cached_total",
                usize_to_u64(*value),
                [("reason", reason.as_str())],
            )?;
        }
        for (crate_type, value) in &stats.not_cached_crate_types {
            self.set_u64(
                "sccache_not_cached_crate_types_total",
                usize_to_u64(*value),
                [("crate_type", crate_type.as_str())],
            )?;
        }
        for (server, value) in &stats.dist_compiles {
            self.set_u64(
                "sccache_dist_compiles_total",
                usize_to_u64(*value),
                [("server", server.as_str())],
            )?;
        }
        self.set_u64(
            "sccache_dist_events_total",
            stats.dist_errors,
            [("event", "error")],
        )
    }

    fn update_multilevel_stats(&mut self, stats: &ServerStats) -> Result<(), String> {
        let levels = stats
            .multi_level
            .as_ref()
            .map_or(&[][..], |multi_level| multi_level.0.as_slice());
        self.set_u64(
            "sccache_cache_levels",
            usize_to_u64(levels.len()),
            std::iter::empty::<(&str, &str)>(),
        )?;
        for (index, level) in levels.iter().enumerate() {
            let index = index.to_string();
            for (operation, value) in [
                ("hit", level.hits),
                ("miss", level.misses),
                ("write", level.writes),
                ("write_failure", level.write_failures),
                ("backfill_from", level.backfills_from),
                ("backfill_to", level.backfills_to),
            ] {
                self.set_u64(
                    "sccache_cache_level_operations_total",
                    value,
                    [
                        ("level", index.as_str()),
                        ("name", level.name.as_str()),
                        ("operation", operation),
                    ],
                )?;
            }
            for (operation, duration) in
                [("hit", level.hit_duration), ("write", level.write_duration)]
            {
                self.set(
                    "sccache_cache_level_duration_seconds_total",
                    duration.as_secs_f64(),
                    [
                        ("level", index.as_str()),
                        ("name", level.name.as_str()),
                        ("operation", operation),
                    ],
                )?;
            }
        }
        Ok(())
    }

    fn update_per_language(
        &mut self,
        result: &'static str,
        values: &PerLanguageCount,
    ) -> Result<(), String> {
        for (language, value) in values.counts() {
            self.set_u64(
                "sccache_cache_requests_total",
                *value,
                [("result", result), ("language", language.as_str())],
            )?;
        }
        for (compiler_language, value) in values.advanced_counts() {
            self.set_u64(
                "sccache_cache_requests_advanced_total",
                *value,
                [
                    ("result", result),
                    ("compiler_language", compiler_language.as_str()),
                ],
            )?;
        }
        Ok(())
    }

    fn update_dist(&mut self, dist: &DistInfo) -> Result<(), String> {
        #[cfg(feature = "dist-client")]
        let (enabled, connected, scheduler) = match dist {
            DistInfo::Disabled(_) => (false, false, None),
            DistInfo::NotConnected(_, _) => (true, false, None),
            DistInfo::SchedulerStatus(_, status) => (true, true, Some(status)),
        };
        #[cfg(not(feature = "dist-client"))]
        let (enabled, connected) = match dist {
            DistInfo::Disabled(_) => (false, false),
        };
        self.set(
            "sccache_dist_status",
            if enabled { 1.0 } else { 0.0 },
            [("kind", "enabled")],
        )?;
        self.set(
            "sccache_dist_status",
            if connected { 1.0 } else { 0.0 },
            [("kind", "connected")],
        )?;
        #[cfg(feature = "dist-client")]
        if let Some(status) = scheduler {
            self.set_u64(
                "sccache_dist_status",
                usize_to_u64(status.num_servers),
                [("kind", "servers")],
            )?;
            self.set_u64(
                "sccache_dist_status",
                usize_to_u64(status.num_cpus),
                [("kind", "cpus")],
            )?;
            self.set_u64(
                "sccache_dist_status",
                usize_to_u64(status.in_progress),
                [("kind", "in_progress")],
            )?;
        }
        Ok(())
    }
}

pub fn spawn<C>(handle: &Handle, service: SccacheService<C>) -> Option<JoinHandle<()>>
where
    C: CommandCreatorSync + Clone + Send + Sync + 'static,
{
    let (mut publisher, interval_duration, heartbeat_duration) = match Publisher::from_env() {
        Ok(Some(config)) => config,
        Ok(None) => return None,
        Err(error) => {
            warn!("direct metrics disabled: {error}");
            return None;
        }
    };

    Some(handle.spawn(async move {
        let mut interval = tokio::time::interval(interval_duration);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut next_heartbeat = Instant::now();
        let mut dist = None;
        loop {
            interval.tick().await;
            let now = Instant::now();
            let force_heartbeat = now >= next_heartbeat;
            if force_heartbeat {
                next_heartbeat = now + heartbeat_duration;
            }
            let info = match service.get_info().await {
                Ok(info) => info,
                Err(error) => {
                    warn!("direct metrics stats snapshot failed: {error:#}");
                    continue;
                }
            };

            // Scheduler status is a network request. Cache it between heartbeat
            // refreshes instead of turning a 2.5 s local statistics sampler into
            // a permanent scheduler polling loop.
            if force_heartbeat || dist.is_none() {
                match service.get_dist_status().await {
                    Ok(status) => dist = Some(status),
                    Err(error) => warn!("direct metrics dist snapshot failed: {error:#}"),
                }
            }
            if let Err(error) = publisher.update(&info, dist.as_ref(), force_heartbeat) {
                warn!("direct metrics update failed: {error}");
            }
        }
    }))
}

fn optional_nonempty_env(name: &str) -> Result<Option<String>, String> {
    let Some(value) = env::var_os(name) else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| format!("{name} is not valid UTF-8"))?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn metrics_instance() -> Result<String, String> {
    if let Some(value) = optional_nonempty_env(INSTANCE_ENV)? {
        return Ok(value);
    }
    hostname::get()
        .map_err(|error| format!("read hostname for metrics instance label: {error}"))?
        .into_string()
        .map_err(|_| "hostname is not valid UTF-8".to_string())
        .and_then(|value| {
            if value.is_empty() {
                Err("hostname for metrics instance label is empty".to_string())
            } else {
                Ok(value)
            }
        })
}

fn env_duration_ms(name: &str, default: u64, minimum: u64) -> Result<Duration, String> {
    Ok(Duration::from_millis(env_u64(name, default, minimum)?))
}

fn env_duration_seconds(name: &str, default: u64, minimum: u64) -> Result<Duration, String> {
    Ok(Duration::from_secs(env_u64(name, default, minimum)?))
}

fn env_u64(name: &str, default: u64, minimum: u64) -> Result<u64, String> {
    let Some(value) = env::var_os(name) else {
        return Ok(default);
    };
    let value = value
        .into_string()
        .map_err(|_| format!("{name} is not valid UTF-8"))?;
    let parsed = value
        .parse::<u64>()
        .map_err(|error| format!("invalid {name}={value:?}: {error}"))?;
    if parsed < minimum {
        return Err(format!("{name} must be at least {minimum}"));
    }
    Ok(parsed)
}

#[expect(
    clippy::cast_precision_loss,
    reason = "Prometheus stores numeric samples as f64; large integer counters may lose sub-unit precision"
)]
const fn prometheus_u64(value: u64) -> f64 {
    value as f64
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_INTERVAL_MS, env_u64};

    #[test]
    fn missing_numeric_environment_uses_default() {
        assert_eq!(
            env_u64("SCCACHE_TEST_MISSING_METRICS_VALUE", DEFAULT_INTERVAL_MS, 1),
            Ok(DEFAULT_INTERVAL_MS)
        );
    }
}
