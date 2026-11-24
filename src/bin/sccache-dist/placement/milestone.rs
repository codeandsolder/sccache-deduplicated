//! Authenticated lifecycle events establish monotonic phase lower bounds.
//! A heartbeat captured before an event must not undo it.

use sccache::{
    build_runtime::wire::NativeJobPhase,
    dist::{JobId, NativeJobProgress, NativeQueueSnapshot},
};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Milestone {
    phase: NativeJobPhase,
    reached: Instant,
}

const fn rank(phase: NativeJobPhase) -> u8 {
    match phase {
        NativeJobPhase::Assigned => 0,
        NativeJobPhase::Queued => 1,
        NativeJobPhase::Staging => 2,
        NativeJobPhase::Ready => 3,
        NativeJobPhase::Executing => 4,
        NativeJobPhase::AwaitingPublication => 5,
        NativeJobPhase::Publishing => 6,
        NativeJobPhase::Terminal => 7,
    }
}

impl Milestone {
    pub(crate) const fn reached(phase: NativeJobPhase, now: Instant) -> Self {
        Self {
            phase,
            reached: now,
        }
    }

    pub(crate) fn advance(slot: &mut Option<Self>, phase: NativeJobPhase, now: Instant) {
        if slot.is_none_or(|previous| rank(phase) > rank(previous.phase)) {
            *slot = Some(Self::reached(phase, now));
        }
    }

    pub(crate) fn apply(self, queue: &mut NativeQueueSnapshot, id: JobId, now: Instant) {
        if let Some(progress) = queue.jobs.get(&id) {
            if rank(progress.phase) >= rank(self.phase) {
                return;
            }
            if progress.phase == NativeJobPhase::Executing {
                // The completed execution occupied a slot in this snapshot.
                queue.compiler_active = queue.compiler_active.saturating_sub(1);
            }
        }
        queue.jobs.insert(
            id,
            NativeJobProgress {
                phase: self.phase,
                phase_nanoseconds: u64::try_from(
                    now.saturating_duration_since(self.reached).as_nanos(),
                )
                .unwrap_or(u64::MAX),
                remaining_input_bytes: 0,
                remaining_input_blobs: 0,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn native_milestones_override_delayed_heartbeat_without_rewinding() {
        let now = Instant::now();
        let id = JobId(42);
        let mut state = None;
        Milestone::advance(&mut state, NativeJobPhase::Ready, now);
        let mut queue = NativeQueueSnapshot::default();
        state.unwrap().apply(&mut queue, id, now);
        assert_eq!(queue.jobs[&id].phase, NativeJobPhase::Ready);
        queue.jobs.get_mut(&id).unwrap().phase = NativeJobPhase::Executing;
        queue.compiler_active = 1;
        state.unwrap().apply(&mut queue, id, now);
        assert_eq!(queue.jobs[&id].phase, NativeJobPhase::Executing);
        Milestone::advance(&mut state, NativeJobPhase::Publishing, now);
        Milestone::advance(
            &mut state,
            NativeJobPhase::Ready,
            now + Duration::from_secs(1),
        );
        state
            .unwrap()
            .apply(&mut queue, id, now + Duration::from_secs(2));
        assert_eq!(queue.jobs[&id].phase, NativeJobPhase::Publishing);
        assert_eq!(queue.jobs[&id].phase_nanoseconds, 2_000_000_000);
        assert_eq!(queue.compiler_active, 0);
        assert_eq!(queue.compiler_demand([id].into_iter()), 0);
        assert!(queue.valid());
    }
}
