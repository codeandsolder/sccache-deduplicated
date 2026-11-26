//! One renewal loop for a set of live tickets. Membership is independent of
//! network I/O so admitting another tree never waits for a renewal request.

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, ensure};

use crate::build_runtime::wire::Ticket;

use super::{NativeCacheClient, retryable_transport_error};

#[derive(Default)]
struct State {
    tickets: BTreeSet<Ticket>,
    failure: Option<String>,
}

pub(super) struct Renewals {
    state: Arc<Mutex<State>>,
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<Result<()>>>,
}

impl Renewals {
    pub(super) fn start(client: NativeCacheClient, interval: Duration) -> Result<Self> {
        Self::spawn(interval, move |ticket, timeout| {
            client.control_with_timeout("renew", &ticket, timeout)
        })
    }

    pub(super) fn start_retention(client: NativeCacheClient, interval: Duration) -> Result<Self> {
        Self::spawn(interval, move |group, timeout| {
            client.control_with_timeout("retain_renew", &group, timeout)
        })
    }

    fn spawn(
        interval: Duration,
        renew: impl Fn(Ticket, Duration) -> Result<()> + Send + 'static,
    ) -> Result<Self> {
        ensure!(
            !interval.is_zero(),
            "native renewal interval must be nonzero"
        );
        let state = Arc::new(Mutex::new(State::default()));
        let (stop, stop_rx) = mpsc::channel();
        let shared = Arc::clone(&state);
        let thread = thread::Builder::new()
            .name("native-lease-renewal".into())
            .spawn(move || {
                while stop_rx.recv_timeout(interval) == Err(mpsc::RecvTimeoutError::Timeout) {
                    let tickets = shared
                        .lock()
                        .map_err(|_| anyhow!("native renewal state poisoned"))?
                        .tickets
                        .clone();
                    // Retry transient failures within one renewal period, in
                    // rounds so one unreachable ticket cannot monopolize the
                    // other members. The server remains authoritative: an
                    // expired or rejected lease is never resurrected here.
                    let deadline = Instant::now()
                        .checked_add(interval)
                        .context("native renewal deadline overflow")?;
                    let mut pending = tickets;
                    let mut delay = Duration::from_millis(25);
                    while !pending.is_empty() {
                        let mut retry = BTreeSet::new();
                        for ticket in pending {
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            let timeout = remaining.min(Duration::from_secs(2));
                            let result = if timeout.is_zero() {
                                Err(anyhow!("native renewal retry budget exhausted"))
                            } else {
                                renew(ticket, timeout)
                            };
                            if let Err(error) = result {
                                let mut state = shared
                                    .lock()
                                    .map_err(|_| anyhow!("native renewal state poisoned"))?;
                                if !state.tickets.contains(&ticket) {
                                    continue;
                                }
                                if retryable_transport_error(&error) && Instant::now() < deadline {
                                    debug!("retrying native lease renewal: {error:#}");
                                    retry.insert(ticket);
                                } else {
                                    state.failure = Some(format!("{error:#}"));
                                    return Ok(());
                                }
                            }
                        }
                        pending = retry;
                        if !pending.is_empty() {
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            if stop_rx.recv_timeout(delay.min(remaining))
                                != Err(mpsc::RecvTimeoutError::Timeout)
                            {
                                return Ok(());
                            }
                            delay = (delay * 2).min(Duration::from_millis(250));
                        }
                    }
                }
                Ok(())
            })?;
        Ok(Self {
            state,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    pub(super) fn add(&self, ticket: Ticket) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("native renewal state poisoned"))?;
        state.tickets.insert(ticket);
        drop(state);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn remove(&self, ticket: Ticket) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("native renewal state poisoned"))?;
        state.tickets.remove(&ticket);
        drop(state);
        Ok(())
    }

    pub(super) fn check(&self) -> Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("native renewal state poisoned"))?;
        if let Some(error) = &state.failure {
            return Err(anyhow!("native scheduler lease renewal failed: {error}"));
        }
        drop(state);
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow!("native renewal loop panicked"))??;
        }
        self.check()
    }

    pub(super) fn finish(mut self) -> Result<()> {
        self.stop()
    }
}

impl Drop for Renewals {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            debug!("native renewal loop ended: {error:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renews_all_members_until_released() -> Result<()> {
        let (observed, events) = mpsc::channel();
        let renewals = Renewals::spawn(Duration::from_millis(100), move |ticket, _| {
            observed.send(ticket)?;
            Ok(())
        })?;
        let first = Ticket([1; 32]);
        let second = Ticket([2; 32]);
        renewals.add(first)?;
        renewals.add(second)?;
        let mut seen = BTreeSet::new();
        while seen.len() != 2 {
            seen.insert(events.recv_timeout(Duration::from_secs(2))?);
        }
        renewals.remove(first)?;
        renewals.remove(second)?;
        renewals.finish()?;
        assert_eq!(seen, BTreeSet::from([first, second]));
        Ok(())
    }

    #[test]
    fn transient_renewal_failure_recovers_without_losing_other_tickets() -> Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        let first = Ticket([1; 32]);
        let second = Ticket([2; 32]);
        let failed = AtomicBool::new(false);
        let (observed, events) = mpsc::channel();
        let renewals = Renewals::spawn(Duration::from_millis(200), move |ticket, _| {
            if ticket == first && !failed.swap(true, Ordering::SeqCst) {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset).into());
            }
            observed.send(ticket)?;
            Ok(())
        })?;
        renewals.add(first)?;
        renewals.add(second)?;
        assert_eq!(events.recv_timeout(Duration::from_secs(2))?, second);
        assert_eq!(events.recv_timeout(Duration::from_secs(2))?, first);
        renewals.check()?;
        renewals.finish()?;
        Ok(())
    }

    #[test]
    fn renewal_error_survives_shutdown() -> Result<()> {
        let (observed, events) = mpsc::channel();
        let renewals = Renewals::spawn(Duration::from_millis(100), move |_, _| {
            observed.send(())?;
            anyhow::bail!("lost lease")
        })?;
        renewals.add(Ticket([3; 32]))?;
        events.recv_timeout(Duration::from_secs(2))?;
        assert!(renewals.finish().is_err());
        Ok(())
    }
}
