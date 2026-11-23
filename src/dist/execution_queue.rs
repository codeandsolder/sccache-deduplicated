//! Worker-wide compiler admission, independent of input transfers and job reservations.

use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::{Condvar, Mutex, PoisonError},
    time::Duration,
};

use anyhow::{Result, ensure};

#[derive(Default)]
struct State {
    active: usize,
    next: u64,
    waiting: VecDeque<u64>,
}

/// FIFO ready-job admission. The caller retains staged input leases while waiting.
pub struct ExecutionQueue {
    width: NonZeroUsize,
    state: Mutex<State>,
    available: Condvar,
}

impl ExecutionQueue {
    #[must_use = "the queue owns worker execution capacity"]
    pub fn new(width: NonZeroUsize) -> Self {
        Self {
            width,
            state: Mutex::new(State::default()),
            available: Condvar::new(),
        }
    }

    #[must_use = "the count describes occupied compiler slots"]
    pub fn active(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .active
    }

    /// Wait for a compiler slot, removing cancelled waiters before returning.
    ///
    /// # Errors
    /// Returns an error on cancellation, queue exhaustion or identifier exhaustion.
    pub fn acquire(&self, check: impl Fn() -> Result<()>) -> Result<ExecutionPermit<'_>> {
        check()?;
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        ensure!(
            state.waiting.len() < self.width.get().saturating_mul(2),
            "worker ready queue is full"
        );
        let id = state.next;
        state.next = id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("worker queue identifier exhausted"))?;
        state.waiting.push_back(id);
        drop(state);
        let _waiter = Waiter { queue: self, id };
        loop {
            check()?;
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.active < self.width.get() && state.waiting.front() == Some(&id) {
                state.waiting.pop_front();
                state.active += 1;
                drop(state);
                self.available.notify_all();
                return Ok(ExecutionPermit(self));
            }
            drop(
                self.available
                    .wait_timeout(state, Duration::from_millis(100))
                    .unwrap_or_else(PoisonError::into_inner),
            );
        }
    }
}

struct Waiter<'a> {
    queue: &'a ExecutionQueue,
    id: u64,
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        let mut state = self
            .queue
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = state.waiting.iter().position(|id| *id == self.id) {
            state.waiting.remove(index);
            drop(state);
            self.queue.available.notify_all();
        }
    }
}

/// Releases compiler capacity on every exit path.
pub struct ExecutionPermit<'a>(&'a ExecutionQueue);

impl Drop for ExecutionPermit<'_> {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.active -= 1;
        drop(state);
        self.0.available.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::Instant,
    };

    fn wait_for_queued(queue: &ExecutionQueue, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while queue.state.lock().unwrap().waiting.len() != count {
            assert!(
                Instant::now() < deadline,
                "ready queue did not reach expected length"
            );
            thread::yield_now();
        }
    }

    #[test]
    fn staged_waiters_do_not_consume_execution_capacity_and_cancel_cleanly() -> Result<()> {
        let queue = ExecutionQueue::new(NonZeroUsize::MIN);
        let running = queue.acquire(|| Ok(()))?;
        let cancel = AtomicBool::new(false);
        thread::scope(|scope| -> Result<()> {
            let cancelled = scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(5);
                queue
                    .acquire(|| {
                        ensure!(
                            !cancel.load(Ordering::Relaxed) && Instant::now() < deadline,
                            "cancelled"
                        );
                        Ok(())
                    })
                    .map(drop)
            });
            wait_for_queued(&queue, 1);
            let (entered, received) = mpsc::channel();
            let queue_ref = &queue;
            let deadline = Instant::now() + Duration::from_secs(5);
            let next = scope.spawn(move || -> Result<()> {
                let _permit = queue_ref.acquire(|| {
                    ensure!(Instant::now() < deadline, "ready queue deadline elapsed");
                    Ok(())
                })?;
                entered.send(())?;
                Ok(())
            });
            wait_for_queued(&queue, 2);
            assert_eq!(queue.active(), 1);
            assert!(received.try_recv().is_err());
            assert!(queue.acquire(|| Ok(())).is_err());
            cancel.store(true, Ordering::Relaxed);
            assert!(cancelled.join().unwrap().is_err());
            wait_for_queued(&queue, 1);
            drop(running);
            received.recv_timeout(Duration::from_secs(5))?;
            next.join().unwrap()?;
            Ok(())
        })?;
        assert_eq!(queue.active(), 0);
        Ok(())
    }
}
