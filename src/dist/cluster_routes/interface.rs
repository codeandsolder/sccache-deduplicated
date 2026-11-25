//! Host-wide traffic samples from actual task transfers. Interface counters
//! are observations, not capacity claims. No packets are generated here.
use super::Transfer;
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

/// Contamination classification for a real completed task body.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::dist) enum Quality {
    #[default]
    Unknown = 0,
    Clean = 1,
    Busy = 2,
}

#[derive(Clone, Default)]
pub(in crate::dist) struct Evidence(Arc<AtomicU8>);

impl Evidence {
    pub(in crate::dist) fn quality(&self) -> Quality {
        match self.0.load(Ordering::Relaxed) {
            1 => Quality::Clean,
            2 => Quality::Busy,
            _ => Quality::Unknown,
        }
    }
    #[cfg(target_os = "linux")]
    fn record(&self, quality: Quality) {
        self.0.store(quality as u8, Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(in crate::dist) use linux::{Activity, activity, binding, direct_sources, snapshot};

#[cfg(not(target_os = "linux"))]
pub(in crate::dist) struct Activity;
#[cfg(not(target_os = "linux"))]
impl Activity {
    pub(in crate::dist) const fn bytes(&mut self, _: u64) {}
    pub(in crate::dist) fn evidence(&self) -> Evidence {
        Evidence::default()
    }
}
#[cfg(not(target_os = "linux"))]
pub(in crate::dist) struct Snapshot;
#[cfg(not(target_os = "linux"))]
impl Snapshot {
    pub(in crate::dist) const fn cost(
        &self,
        _: Option<IpAddr>,
        _: Transfer,
        _: Option<u64>,
        predicted: u128,
    ) -> u128 {
        predicted
    }
}
#[cfg(not(target_os = "linux"))]
pub(in crate::dist) const fn snapshot() -> Snapshot {
    Snapshot
}
#[cfg(not(target_os = "linux"))]
pub(in crate::dist) const fn activity(_: Option<IpAddr>, _: Transfer) -> Option<Activity> {
    None
}

#[cfg(target_os = "linux")]
const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

#[cfg(not(target_os = "linux"))]
pub(in crate::dist) fn direct_sources(_: std::net::IpAddr) -> Vec<std::net::IpAddr> {
    Vec::new()
}
#[cfg(not(target_os = "linux"))]
pub(in crate::dist) fn binding(_: std::net::IpAddr) -> Option<String> {
    None
}

/// Account for actual body traffic; small control frames are intentionally
/// excluded from the managed bulk stream reservations.
pub(in crate::dist) struct TrackedReader<R> {
    reader: R,
    activity: Option<Activity>,
}

impl<R> TrackedReader<R> {
    pub(in crate::dist) fn evidence(&self) -> Option<Evidence> {
        self.activity.as_ref().map(Activity::evidence)
    }
    pub(in crate::dist) fn new(reader: R, local: Option<IpAddr>, transfer: Transfer) -> Self {
        Self {
            reader,
            activity: activity(local, transfer),
        }
    }
}

impl<R: std::io::Read> std::io::Read for TrackedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.reader.read(buffer)?;
        if let Some(activity) = &mut self.activity {
            activity.bytes(count as u64);
        }
        if count == 0 && !buffer.is_empty() {
            self.activity.take();
        }
        Ok(count)
    }
}
