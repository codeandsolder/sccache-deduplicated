//! A renewal guard owns one scheduler lease. The scheduler alone decides
//! whether the lease is lost; a missed client-side timer is not an expiry.

use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, ensure};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::build_runtime::wire::{LeaseRenewal, Ticket};

use super::{NativeCacheClient, retryable_transport_error};

pub(super) struct Renewal {
    failure: Arc<Mutex<Option<String>>>,
    stop: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl Renewal {
    pub(super) fn start(
        client: NativeCacheClient,
        ticket: Ticket,
        interval: Duration,
    ) -> Result<Self> {
        Self::start_operation(client, ticket, interval, "renew")
    }

    pub(super) fn start_retention(
        client: NativeCacheClient,
        ticket: Ticket,
        interval: Duration,
    ) -> Result<Self> {
        Self::start_operation(client, ticket, interval, "retain_renew")
    }

    fn start_operation(
        client: NativeCacheClient,
        ticket: Ticket,
        interval: Duration,
        operation: &'static str,
    ) -> Result<Self> {
        let timeout = client.timeout.min(Duration::from_secs(10));
        Self::spawn(interval, timeout, move |timeout| {
            let client = client.clone();
            async move {
                client
                    .control_with_timeout_async(operation, &ticket, timeout)
                    .await
            }
        })
    }

    fn spawn<F, Fut>(interval: Duration, timeout: Duration, renew: F) -> Result<Self>
    where
        F: Fn(Duration) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<LeaseRenewal>> + Send + 'static,
    {
        ensure!(
            !interval.is_zero() && !timeout.is_zero(),
            "invalid native renewal timing"
        );
        let failure = Arc::new(Mutex::new(None));
        let stop = CancellationToken::new();
        let shared = Arc::clone(&failure);
        let cancelled = stop.clone();
        let task = crate::http_client::io_runtime()?.spawn(async move {
            tokio::select! {
                biased;
                result = renewal_loop(interval, timeout, renew) => {
                    if let Err(error) = result {
                        *shared.lock().map_err(|_| anyhow!("native renewal state poisoned"))? =
                            Some(format!("{error:#}"));
                    }
                    Ok(())
                },
                () = cancelled.cancelled() => Ok(()),
            }
        });
        Ok(Self {
            failure,
            stop,
            task: Some(task),
        })
    }

    pub(super) fn check(&self) -> Result<()> {
        let failure = self
            .failure
            .lock()
            .map_err(|_| anyhow!("native renewal state poisoned"))?;
        if let Some(error) = &*failure {
            return Err(anyhow!("native scheduler lease renewal failed: {error}"));
        }
        drop(failure);
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

impl Drop for Renewal {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Err(error) = self.check() {
            debug!("native renewal loop ended: {error:#}");
        }
    }
}

fn retryable_renewal_error(error: &anyhow::Error) -> bool {
    if let Some(status) = error
        .downcast_ref::<wreq::Error>()
        .and_then(wreq::Error::status)
    {
        return status.is_server_error() || status == http::StatusCode::TOO_MANY_REQUESTS;
    }
    retryable_transport_error(error)
}

fn describe_rejection(error: anyhow::Error) -> anyhow::Error {
    match error.downcast_ref::<wreq::Error>().and_then(wreq::Error::status) {
        Some(http::StatusCode::GONE) => error.context("scheduler no longer owns this lease (expired or restarted); restart the affected build"),
        Some(http::StatusCode::FORBIDDEN) => error.context("scheduler rejected lease ownership"),
        _ => error.context("scheduler renewal rejected"),
    }
}

async fn renewal_loop<F, Fut>(interval: Duration, timeout: Duration, renew: F) -> Result<()>
where
    F: Fn(Duration) -> Fut,
    Fut: Future<Output = Result<LeaseRenewal>>,
{
    let mut confirmed_until = None;
    let mut delay = Duration::from_millis(100);
    let mut degraded_since = None;
    let mut warned = false;
    loop {
        // Renew immediately on creation, including retention groups. A fresh
        // reply advertises the server's actual idle timeout. Use the send time
        // as a conservative lower bound on confirmed validity, never a proof
        // of expiration (ordinary operations may also extend a lease).
        let sent = Instant::now();
        let attempt_timeout = confirmed_until
            .map(|until: Instant| until.saturating_duration_since(sent))
            .filter(|remaining| !remaining.is_zero())
            .map_or(timeout, |remaining| timeout.min(remaining));
        let result = tokio::time::timeout(attempt_timeout, renew(attempt_timeout))
            .await
            .unwrap_or_else(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "native renewal request timed out",
                )
                .into())
            });
        match result {
            Ok(reply) => {
                let lifetime = reply.valid_for;
                ensure!(
                    !lifetime.is_zero(),
                    "scheduler advertised zero lease lifetime"
                );
                confirmed_until = Some(
                    sent.checked_add(lifetime)
                        .context("native lease lifetime overflow")?,
                );
                if let Some(since) = degraded_since.take() {
                    debug!(
                        "native lease renewal recovered after {:?}",
                        Instant::now() - since
                    );
                }
                warned = false;
                delay = Duration::from_millis(100);
                // The configured interval is an upper bound, not a deadline.
                // Keep at least two thirds of the advertised lifetime for
                // recovery, even when the server has a shorter lease policy.
                let cadence = interval.min(lifetime / 3).max(Duration::from_nanos(1));
                tokio::time::sleep_until(
                    sent.checked_add(cadence)
                        .context("native renewal cadence overflow")?
                        .max(Instant::now()),
                )
                .await;
            }
            Err(error) if retryable_renewal_error(&error) => {
                let since = *degraded_since.get_or_insert(sent);
                let now = Instant::now();
                if !warned
                    && (confirmed_until.is_some_and(|until| now >= until)
                        || now - since >= interval)
                {
                    warn!(
                        "native lease renewal delayed; retrying until the scheduler confirms or rejects the lease: {error:#}"
                    );
                    warned = true;
                } else {
                    debug!("retrying native lease renewal: {error:#}");
                }
                let remaining = confirmed_until
                    .map(|until| until.saturating_duration_since(now))
                    .filter(|remaining| !remaining.is_zero());
                let pause = remaining.map_or(delay, |remaining| delay.min(remaining));
                tokio::time::sleep(pause).await;
                delay = (delay * 2).min(Duration::from_secs(2));
            }
            Err(error) => return Err(describe_rejection(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn reply(seconds: u64) -> LeaseRenewal {
        LeaseRenewal {
            valid_for: Duration::from_secs(seconds),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn outage_longer_than_renewal_interval_recovers() {
        let calls = AtomicUsize::new(0);
        let start = Instant::now();
        let result = renewal_loop(Duration::from_secs(15), Duration::from_secs(10), |_| {
            let call = calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(if call == 0 {
                Ok(reply(120))
            } else if Instant::now() - start < Duration::from_secs(45) {
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset).into())
            } else if Instant::now() - start < Duration::from_secs(60) {
                Ok(reply(120))
            } else {
                Err(anyhow!("authoritative rejection"))
            })
        })
        .await;
        assert!(format!("{:#}", result.unwrap_err()).contains("authoritative rejection"));
        assert!(Instant::now() - start >= Duration::from_secs(60));
        assert!(calls.load(Ordering::Relaxed) > 3);
    }

    #[tokio::test(start_paused = true)]
    async fn initial_renewal_retries_without_a_confirmed_lifetime() {
        let start = Instant::now();
        let recovered = AtomicUsize::new(0);
        let result = renewal_loop(Duration::from_secs(2), Duration::from_secs(5), |_| {
            std::future::ready(if Instant::now() - start < Duration::from_secs(8) {
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset).into())
            } else if recovered.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(reply(30))
            } else {
                Err(anyhow!("terminal"))
            })
        })
        .await;
        assert!(result.is_err());
        assert_eq!(recovered.load(Ordering::Relaxed), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn uncertain_expiry_is_not_fabricated_lease_loss() {
        let start = Instant::now();
        let result = renewal_loop(Duration::from_secs(15), Duration::from_secs(10), |_| {
            std::future::ready(if Instant::now() == start {
                Ok(reply(6))
            } else if Instant::now() - start < Duration::from_secs(20) {
                Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into())
            } else {
                Err(anyhow!("scheduler lost the lease"))
            })
        })
        .await;
        assert!(format!("{:#}", result.unwrap_err()).contains("scheduler lost the lease"));
        assert!(Instant::now() - start >= Duration::from_secs(20));
    }

    #[tokio::test(start_paused = true)]
    async fn cadence_tracks_short_scheduler_lifetime() {
        let start = Instant::now();
        let result = renewal_loop(Duration::from_secs(15), Duration::from_secs(10), |_| {
            std::future::ready(if Instant::now() == start {
                Ok(reply(6))
            } else {
                Err(anyhow!("terminal"))
            })
        })
        .await;
        assert!(result.is_err());
        assert_eq!(Instant::now() - start, Duration::from_secs(2));
    }

    #[test]
    fn stalled_lease_is_independent_and_shutdown_is_nonblocking() -> Result<()> {
        let (observed, events) = std::sync::mpsc::channel();
        let stalled = Renewal::spawn(Duration::from_secs(15), Duration::from_secs(10), |_| {
            std::future::pending()
        })?;
        let healthy = Renewal::spawn(
            Duration::from_secs(15),
            Duration::from_secs(10),
            move |_| std::future::ready(observed.send(()).map(|()| reply(120)).map_err(Into::into)),
        )?;
        events.recv_timeout(Duration::from_secs(2))?;
        let start = std::time::Instant::now();
        stalled.finish()?;
        healthy.finish()?;
        assert!(start.elapsed() < Duration::from_secs(1));
        Ok(())
    }

    #[test]
    fn terminal_error_survives_shutdown() -> Result<()> {
        let guard = Renewal::spawn(Duration::from_secs(15), Duration::from_secs(10), |_| {
            std::future::ready(Err(anyhow!("lost lease")))
        })?;
        let start = std::time::Instant::now();
        while guard.check().is_ok() {
            ensure!(
                start.elapsed() < Duration::from_secs(2),
                "renewal rejection not observed"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(format!("{:#}", guard.finish().unwrap_err()).contains("lost lease"));
        Ok(())
    }
}
