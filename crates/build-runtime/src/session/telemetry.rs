//! Read-only observations; never wait for a session performing I/O.
use std::sync::{Arc, Mutex, MutexGuard, TryLockError, atomic::Ordering};
use std::time::Instant;

use anyhow::{Result, anyhow};

use super::{Kind, NativeSessions, Phase};

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
                        Phase::Publishing => status.publishing += 1,
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
