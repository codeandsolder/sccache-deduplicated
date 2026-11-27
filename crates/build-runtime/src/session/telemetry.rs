//! Read-only observations; never wait for a session performing I/O.
use std::sync::{
    Arc, Mutex, MutexGuard, TryLockError,
    atomic::{AtomicU64, Ordering},
};
use std::time::Instant;

use anyhow::{Result, anyhow};

use super::{Kind, NativeSessions, Phase};
use crate::{ActionMode, wire::NativeAdmission};

/// Counts completed admission decisions, not compiler completions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmissionStats {
    pub hits: u64,
    pub misses: u64,
    pub refreshes: u64,
    pub in_flight: u64,
    pub missing_inputs: u64,
    pub busy: u64,
    pub errors: u64,
}

#[derive(Default)]
pub(super) struct AdmissionCounters {
    hits: AtomicU64,
    misses: AtomicU64,
    refreshes: AtomicU64,
    in_flight: AtomicU64,
    missing_inputs: AtomicU64,
    busy: AtomicU64,
    errors: AtomicU64,
}

impl AdmissionCounters {
    pub(super) fn record(&self, mode: ActionMode, result: &Result<NativeAdmission>) {
        let counter = match result {
            Ok(NativeAdmission::Hit { .. }) => &self.hits,
            Ok(NativeAdmission::Compile { .. }) if mode == ActionMode::Refresh => &self.refreshes,
            Ok(NativeAdmission::Compile { .. }) => &self.misses,
            Ok(NativeAdmission::InFlight { .. }) => &self.in_flight,
            Ok(NativeAdmission::MissingInputs { .. }) => &self.missing_inputs,
            Err(error) if error.is::<super::NativeServiceBusy>() => &self.busy,
            Err(_) => &self.errors,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> AdmissionStats {
        AdmissionStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            refreshes: self.refreshes.load(Ordering::Relaxed),
            in_flight: self.in_flight.load(Ordering::Relaxed),
            missing_inputs: self.missing_inputs.load(Ordering::Relaxed),
            busy: self.busy.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

impl NativeSessions {
    /// Process-lifetime counters; no storage locks or external telemetry.
    #[must_use = "Admission statistics are a read-only observation."]
    pub fn admission_stats(&self) -> AdmissionStats {
        self.admission_counters.snapshot()
    }
}

/// Registered ticket population. Busy tickets remain counted and their phase
/// is explicitly unknown, rather than being attributed to a guessed phase.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TicketStatus {
    pub registered: usize,
    pub action: usize,
    pub tree: usize,
    pub pending: usize,
    pub publishing: usize,
    pub ready: usize,
    pub failed: usize,
    pub expired: usize,
    pub busy: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestStatus {
    pub entries: usize,
    pub bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryStatus {
    pub queued: usize,
    pub queued_bytes: usize,
    pub ready: usize,
    pub cooldown: usize,
}

/// Best-effort observations of the scheduler's existing service resources.
/// An unavailable sub-observation means its lock was contended at sample time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStatus {
    pub max_sessions: usize,
    pub max_uploads: usize,
    pub active_uploads: usize,
    pub manifest_budget_bytes: usize,
    pub tickets: Option<TicketStatus>,
    pub manifests: Option<ManifestStatus>,
    pub recovery: Option<RecoveryStatus>,
}

pub(super) fn observe<T>(mutex: &Mutex<T>) -> Result<Option<MutexGuard<'_, T>>> {
    match mutex.try_lock() {
        Ok(guard) => Ok(Some(guard)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Poisoned(_)) => Err(anyhow!("native telemetry lock poisoned")),
    }
}

impl NativeSessions {
    /// Observe service capacity without touching ticket expiry, acquiring a
    /// service slot, reaping, or blocking on I/O under another session lock.
    ///
    /// # Errors
    /// Returns an error for a poisoned resource lock.
    pub fn telemetry(&self) -> Result<SessionStatus> {
        let tickets = observe(&self.sessions)?.map(|sessions| {
            // Keep map lock duration independent of individual ticket locks.
            sessions.values().map(Arc::clone).collect::<Vec<_>>()
        });
        let tickets = tickets
            .map(|tickets| -> Result<_> {
                let now = Instant::now();
                let mut status = TicketStatus {
                    registered: tickets.len(),
                    ..Default::default()
                };
                for session in tickets {
                    let Some(session) = observe(&session)? else {
                        status.busy += 1;
                        continue;
                    };
                    match session.kind {
                        Kind::Action => status.action += 1,
                        Kind::Tree => status.tree += 1,
                    }
                    match session.phase {
                        Phase::Pending(_) => status.pending += 1,
                        Phase::Publishing(_) => status.publishing += 1,
                        Phase::Ready(_) => status.ready += 1,
                        Phase::Failed => status.failed += 1,
                    }
                    if session.expires <= now {
                        status.expired += 1;
                    }
                }
                Ok(status)
            })
            .transpose()?;
        let manifests = observe(&self.manifests)?.map(|catalog| ManifestStatus {
            entries: catalog.entries.len(),
            bytes: catalog.bytes,
        });
        let recovery = self.recovery.telemetry()?;
        Ok(SessionStatus {
            max_sessions: self.limits.max_sessions,
            max_uploads: self.limits.max_total_uploads,
            active_uploads: self.active_uploads.load(Ordering::Relaxed),
            manifest_budget_bytes: self.limits.max_manifest_cache_bytes,
            tickets,
            manifests,
            recovery,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Ticket;

    #[test]
    fn retries_and_forced_refresh_are_not_cache_misses() {
        let counters = AdmissionCounters::default();
        for mode in [ActionMode::Reuse, ActionMode::Refresh] {
            counters.record(
                mode,
                &Ok(NativeAdmission::Compile {
                    ticket: Ticket([0; 32]),
                }),
            );
            counters.record(mode, &Ok(NativeAdmission::InFlight { producer: None }));
            counters.record(
                mode,
                &Ok(NativeAdmission::MissingInputs {
                    trees: Default::default(),
                }),
            );
        }
        counters.record(
            ActionMode::Reuse,
            &Err(super::super::NativeServiceBusy.into()),
        );
        counters.record(ActionMode::Reuse, &Err(anyhow!("failed")));
        assert_eq!(
            counters.snapshot(),
            AdmissionStats {
                hits: 0,
                misses: 1,
                refreshes: 1,
                in_flight: 2,
                missing_inputs: 2,
                busy: 1,
                errors: 1,
            }
        );
    }
}
