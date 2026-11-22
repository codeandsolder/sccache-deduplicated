//! One renewal loop for a set of live tickets. Membership is independent of
//! network I/O so admitting another tree never waits for a renewal request.

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::{Result, anyhow, ensure};

use crate::build_runtime::wire::Ticket;

use super::NativeCacheClient;

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
        Self::spawn(interval, move |ticket| client.renew(ticket))
    }

    fn spawn(
        interval: Duration,
        renew: impl Fn(Ticket) -> Result<()> + Send + 'static,
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
                    for ticket in tickets {
                        if let Err(error) = renew(ticket) {
                            let mut state = shared
                                .lock()
                                .map_err(|_| anyhow!("native renewal state poisoned"))?;
                            // A caller may release ownership while an HTTP
                            // request is in flight. That failure is irrelevant.
                            if state.tickets.contains(&ticket) {
                                state.failure = Some(format!("{error:#}"));
                                return Ok(());
                            }
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

    pub(super) fn remove(&self, ticket: Ticket) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("native renewal state poisoned"))?;
        state.tickets.remove(&ticket);
        drop(state);
        Ok(())
    }

    pub(super) fn clear(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("native renewal state poisoned"))?;
        state.tickets.clear();
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
        let renewals = Renewals::spawn(Duration::from_millis(5), move |ticket| {
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
    fn renewal_error_survives_shutdown() -> Result<()> {
        let (observed, events) = mpsc::channel();
        let renewals = Renewals::spawn(Duration::from_millis(5), move |_| {
            observed.send(())?;
            anyhow::bail!("lost lease")
        })?;
        renewals.add(Ticket([3; 32]))?;
        events.recv_timeout(Duration::from_secs(2))?;
        assert!(renewals.finish().is_err());
        Ok(())
    }
}
