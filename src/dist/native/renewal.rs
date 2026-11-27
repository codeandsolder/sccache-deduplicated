//! One renewal loop for a set of live tickets. Membership is independent of
//! network I/O so admitting another tree never waits for a renewal request.

use std::{
    collections::BTreeSet,
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, ensure};
use futures::{StreamExt, stream};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::build_runtime::wire::Ticket;

use super::{NativeCacheClient, retryable_transport_error};

#[derive(Default)]
struct State {
    tickets: BTreeSet<Ticket>,
    failure: Option<String>,
}

pub(super) struct Renewals {
    state: Arc<Mutex<State>>,
    stop: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl Renewals {
    pub(super) fn start(client: NativeCacheClient, interval: Duration) -> Result<Self> {
        Self::start_operation(client, interval, "renew")
    }

    pub(super) fn start_retention(client: NativeCacheClient, interval: Duration) -> Result<Self> {
        Self::start_operation(client, interval, "retain_renew")
    }

    fn start_operation(
        client: NativeCacheClient,
        interval: Duration,
        operation: &'static str,
    ) -> Result<Self> {
        Self::spawn(interval, move |ticket, timeout| {
            let client = client.clone();
            async move {
                client
                    .control_with_timeout_async(operation, &ticket, timeout)
                    .await
            }
        })
    }

    fn spawn<F, Fut>(interval: Duration, renew: F) -> Result<Self>
    where
        F: Fn(Ticket, Duration) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        ensure!(
            !interval.is_zero(),
            "native renewal interval must be nonzero"
        );
        let state = Arc::new(Mutex::new(State::default()));
        let stop = CancellationToken::new();
        let shared = Arc::clone(&state);
        let cancelled = stop.clone();
        let task = crate::http_client::io_runtime()?.spawn(async move {
            tokio::select! {
                biased;
                result = renewal_loop(&shared, interval, renew) => result,
                () = cancelled.cancelled() => Ok(()),
            }
        });
        Ok(Self {
            state,
            stop,
            task: Some(task),
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

    pub(super) fn finish(self) -> Result<()> {
        crate::http_client::io_runtime()?.block_on(self.finish_async())
    }

    pub(super) async fn finish_async(mut self) -> Result<()> {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.await.context("native renewal task terminated")??;
        }
        self.check()
    }
}

impl Drop for Renewals {
    fn drop(&mut self) {
        // Cancellation interrupts pending transport futures and timers. A
        // destructor never waits for a network deadline or joins a thread.
        self.stop.cancel();
        if let Err(error) = self.check() {
            debug!("native renewal loop ended: {error:#}");
        }
    }
}

// Renewals are deadline-critical. Bound fanout independently of blob I/O;
// the server reserves a dedicated control lane.
const MAX_CONCURRENT_RENEWALS: usize = 64;

async fn renewal_loop<F, Fut>(state: &Mutex<State>, interval: Duration, renew: F) -> Result<()>
where
    F: Fn(Ticket, Duration) -> Fut + Sync,
    Fut: Future<Output = Result<()>>,
{
    let mut next = Instant::now() + interval;
    loop {
        tokio::time::sleep_until(next).await;
        let mut pending = state
            .lock()
            .map_err(|_| anyhow!("native renewal state poisoned"))?
            .tickets
            .clone();
        let deadline = next
            .checked_add(interval)
            .context("native renewal deadline overflow")?;
        let mut delay = Duration::from_millis(25);
        while !pending.is_empty() {
            let mut retry = BTreeSet::new();
            let mut requests = std::pin::pin!(
                stream::iter(pending)
                    .map(|ticket| {
                        let renew = &renew;
                        async move {
                            let timeout = deadline
                                .saturating_duration_since(Instant::now())
                                .min(Duration::from_secs(2));
                            let result = if timeout.is_zero() {
                                Err(anyhow!("native renewal retry budget exhausted"))
                            } else {
                                tokio::time::timeout(timeout, renew(ticket, timeout))
                                    .await
                                    .unwrap_or_else(|_| {
                                        Err(std::io::Error::from(std::io::ErrorKind::TimedOut)
                                            .into())
                                    })
                            };
                            (ticket, result)
                        }
                    })
                    .buffer_unordered(MAX_CONCURRENT_RENEWALS)
            );
            while let Some((ticket, result)) = requests.next().await {
                if let Err(error) = result {
                    let mut state = state
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
                tokio::time::sleep(delay.min(remaining)).await;
                delay = (delay * 2).min(Duration::from_millis(250));
            }
        }
        // Schedule from the original deadline instead of accumulating time
        // spent renewing. Skip missed ticks, but never create a catch-up burst.
        next = (next + interval).max(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn renews_all_members_until_released() -> Result<()> {
        let (observed, events) = mpsc::channel();
        let renewals = Renewals::spawn(Duration::from_millis(100), move |ticket, _| {
            std::future::ready(observed.send(ticket).map_err(Into::into))
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
            std::future::ready(if ticket == first && !failed.swap(true, Ordering::SeqCst) {
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset).into())
            } else {
                observed.send(ticket).map_err(Into::into)
            })
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
    fn stalled_ticket_does_not_hold_up_other_members_or_shutdown() -> Result<()> {
        let first = Ticket([1; 32]);
        let second = Ticket([2; 32]);
        let (observed, events) = mpsc::channel();
        let renewals = Renewals::spawn(Duration::from_secs(2), move |ticket, _| {
            let observed = observed.clone();
            async move {
                observed.send(ticket)?;
                if ticket == first {
                    std::future::pending::<()>().await;
                }
                Ok(())
            }
        })?;
        renewals.add(first)?;
        renewals.add(second)?;
        let mut seen = BTreeSet::new();
        seen.insert(events.recv_timeout(Duration::from_secs(4))?);
        seen.insert(events.recv_timeout(Duration::from_millis(500))?);
        assert_eq!(seen, BTreeSet::from([first, second]));
        let start = std::time::Instant::now();
        renewals.finish()?;
        assert!(start.elapsed() < Duration::from_millis(500));
        Ok(())
    }

    #[test]
    fn renewal_error_survives_shutdown() -> Result<()> {
        let (observed, events) = mpsc::channel();
        let renewals = Renewals::spawn(Duration::from_millis(100), move |_, _| {
            std::future::ready(
                observed
                    .send(())
                    .map_err(anyhow::Error::from)
                    .and(Err(anyhow!("lost lease"))),
            )
        })?;
        renewals.add(Ticket([3; 32]))?;
        events.recv_timeout(Duration::from_secs(2))?;
        assert!(renewals.finish().is_err());
        Ok(())
    }
}
