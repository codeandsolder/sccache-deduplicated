//! Low-priority calibration is invalidated immediately by real work.

use std::{
    io::{self, Read},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

struct State {
    active: usize,
    generation: u64,
    idle_since: Instant,
}

pub struct IdleGate {
    state: Mutex<State>,
}

impl Default for IdleGate {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                active: 0,
                generation: 0,
                idle_since: Instant::now(),
            }),
        }
    }
}

/// Held from assignment/real request admission through its terminal state.
pub struct WorkActivity(Arc<IdleGate>);

impl Drop for WorkActivity {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.active -= 1;
        if state.active == 0 {
            state.idle_since = Instant::now();
        }
    }
}

#[derive(Clone)]
pub struct IdlePermit {
    gate: Arc<IdleGate>,
    generation: u64,
}

impl IdleGate {
    /// A new real-work reservation invalidates all outstanding probe permits.
    #[must_use = "keep the guard alive for the complete work lifetime"]
    pub fn begin(self: &Arc<Self>) -> WorkActivity {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.active += 1;
        state.generation = state.generation.wrapping_add(1);
        drop(state);
        WorkActivity(Arc::clone(self))
    }

    #[must_use = "a probe must have an idle-generation permit"]
    pub fn permit(self: &Arc<Self>, idle: Duration) -> Option<IdlePermit> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.active != 0 || state.idle_since.elapsed() < idle {
            return None;
        }
        let generation = state.generation;
        drop(state);
        Some(IdlePermit {
            gate: Arc::clone(self),
            generation,
        })
    }
}

impl IdlePermit {
    #[must_use = "preempted probes must stop producing or consuming payload"]
    pub fn valid(&self) -> bool {
        let state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.active == 0 && state.generation == self.generation
    }

    /// Wait for coordinated start without delaying real work.
    #[must_use = "false means the probe was preempted"]
    pub fn wait(&self, delay: Duration) -> bool {
        let start = Instant::now();
        while let Some(remaining) = delay.checked_sub(start.elapsed()) {
            if !self.valid() {
                return false;
            }
            std::thread::sleep(remaining.min(Duration::from_millis(50)));
        }
        self.valid()
    }
}

/// In-memory data source with a deterministic pseudo-random stream. Transport
/// compression is disabled for probes; the source never touches the CAS.
pub struct ProbePayload(blake3::OutputReader);

impl ProbePayload {
    #[must_use = "the source generates synthetic payload bytes"]
    pub fn new(seed: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed);
        Self(hasher.finalize_xof())
    }
}

impl Read for ProbePayload {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.fill(buffer);
        Ok(buffer.len())
    }
}

/// Bound byte count, duration and cancellation checks on either side of a
/// probe. Normal budget exhaustion is EOF; real-work preemption is an error.
pub struct ProbeStream<R> {
    reader: R,
    permit: IdlePermit,
    remaining: u64,
    deadline: Instant,
}

impl<R> ProbeStream<R> {
    #[must_use = "the bounded stream enforces calibration policy"]
    pub fn new(reader: R, permit: IdlePermit, bytes: u64, duration: Duration) -> Self {
        let now = Instant::now();
        Self {
            reader,
            permit,
            remaining: bytes,
            deadline: now.checked_add(duration).unwrap_or(now),
        }
    }
}

impl<R: Read> Read for ProbeStream<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.permit.valid() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "calibration preempted",
            ));
        }
        if Instant::now() >= self.deadline || self.remaining == 0 {
            return Ok(0);
        }
        let limit = buffer
            .len()
            .min(64 * 1024)
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let count = self.reader.read(&mut buffer[..limit])?;
        self.remaining -= u64::try_from(count).unwrap_or(self.remaining);
        if !self.permit.valid() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "calibration preempted",
            ));
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_work_preempts_all_old_permits_even_after_it_finishes() -> io::Result<()> {
        let gate = Arc::new(IdleGate::default());
        let a = gate.permit(Duration::ZERO).unwrap();
        let b = gate.permit(Duration::ZERO).unwrap();
        let mut payload = ProbeStream::new(
            ProbePayload::new(b"probe"),
            a.clone(),
            100,
            Duration::from_secs(1),
        );
        let mut buffer = [0; 16];
        payload.read_exact(&mut buffer)?;
        assert_ne!(buffer, [0; 16]);
        let work = gate.begin();
        assert!(gate.permit(Duration::ZERO).is_none());
        assert!(!b.valid());
        assert_eq!(
            payload.read(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        drop(work);
        assert!(!a.valid());
        assert!(gate.permit(Duration::ZERO).is_some());
        Ok(())
    }

    #[test]
    fn bounded_payload_never_exceeds_grant() -> io::Result<()> {
        let gate = Arc::new(IdleGate::default());
        let permit = gate.permit(Duration::ZERO).unwrap();
        let mut payload = ProbeStream::new(
            ProbePayload::new(b"probe"),
            permit,
            12345,
            Duration::from_secs(1),
        );
        assert_eq!(io::copy(&mut payload, &mut io::sink())?, 12345);
        Ok(())
    }
}
