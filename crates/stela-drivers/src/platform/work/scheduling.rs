//! Cooperative NORMAL/FIFO ordering for the optional retained kernel domain.
//! No native preemption, RR quantum, DEADLINE or alternate NORMAL base is
//! inferred from an integer rank. Original Linux PI commits use a captured
//! actual job handle; default Runtime dispatch stays round-robin.
use super::{ContextId, LeaveReason, WakeHandle, WorkError};
use core::sync::atomic::Ordering;

const NORMAL: u8 = 120;
const MIDDLE: u64 = 1 << 63;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BasePolicy {
    Normal,
    Fifo(u8),
}
impl BasePolicy {
    pub fn priority(self) -> Result<u8, WorkError> {
        match self {
            Self::Normal => Ok(NORMAL),
            Self::Fifo(q @ 1..=99) => Ok(99 - q),
            Self::Fifo(_) => Err(WorkError::Unavailable),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub base: BasePolicy,
    pub effective: u8,
}
impl Snapshot {
    const NORMAL: Self = Self {
        base: BasePolicy::Normal,
        effective: NORMAL,
    };
    fn validate(self) -> Result<(), WorkError> {
        let base = self.base.priority()?;
        if (self.effective > 98 && self.effective != NORMAL) || self.effective > base {
            return Err(WorkError::Unavailable);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Ready,
    Running,
    Blocked,
}
#[derive(Clone, Copy)]
struct Row {
    id: ContextId,
    sequence: u64,
    service: bool,
    rank: Snapshot,
    state: State,
    order: u64,
}
/// Fixed 16 actual continuation records, embedded in the retained Queue.
/// Only its existing IRQ-save lock accesses this state; no task/C pointer,
/// provider callback, allocation or ref release is stored or invoked here.
pub(super) struct Board {
    pub(super) enabled: bool,
    rows: [Option<Row>; 16],
    head: u64,
    tail: u64,
}
impl Board {
    pub(super) fn new() -> Self {
        Self {
            enabled: false,
            rows: [None; 16],
            head: MIDDLE,
            tail: MIDDLE,
        }
    }
    fn index(&self, id: ContextId, sequence: u64) -> Result<usize, WorkError> {
        self.rows
            .iter()
            .position(|row| row.is_some_and(|row| row.id == id && row.sequence == sequence))
            .ok_or(WorkError::Closed)
    }
    fn order(&mut self, head: bool) -> Result<u64, WorkError> {
        if head {
            let value = self.head.checked_sub(1).ok_or(WorkError::Exhausted)?;
            self.head = value;
            Ok(value)
        } else {
            let value = self.tail.checked_add(1).ok_or(WorkError::Exhausted)?;
            self.tail = value;
            Ok(value)
        }
    }
    pub(super) fn insert(
        &mut self,
        id: ContextId,
        sequence: u64,
        service: bool,
    ) -> Result<(), WorkError> {
        if !self.enabled {
            return Ok(());
        }
        if sequence == 0 || self.rows.iter().flatten().any(|row| row.id == id) {
            return Err(WorkError::CorruptContext);
        }
        let slot = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(WorkError::Full)?;
        let order = self.order(false)?;
        self.rows[slot] = Some(Row {
            id,
            sequence,
            service,
            rank: Snapshot::NORMAL,
            state: State::Ready,
            order,
        });
        Ok(())
    }
    pub(super) fn wake(&mut self, id: ContextId, sequence: u64) -> Result<(), WorkError> {
        if !self.enabled {
            return Ok(());
        }
        let slot = self.index(id, sequence)?;
        if self.rows[slot].as_ref().unwrap().state == State::Blocked {
            let order = self.order(false)?;
            let row = self.rows[slot].as_mut().unwrap();
            row.order = order;
            row.state = State::Ready;
        }
        Ok(())
    }
    pub(super) fn running(&mut self, id: ContextId, sequence: u64) -> Result<(), WorkError> {
        if !self.enabled {
            return Ok(());
        }
        let slot = self.index(id, sequence)?;
        let row = self.rows[slot].as_mut().unwrap();
        if row.state != State::Ready {
            return Err(WorkError::CorruptContext);
        }
        row.state = State::Running;
        Ok(())
    }
    pub(super) fn can_suspend(
        &self,
        id: ContextId,
        sequence: u64,
        reason: LeaveReason,
    ) -> Result<(), WorkError> {
        if !self.enabled {
            return Ok(());
        }
        let slot = self.index(id, sequence)?;
        if self.rows[slot].as_ref().unwrap().state != State::Running {
            return Err(WorkError::CorruptContext);
        }
        if reason == LeaveReason::Yield && self.tail == u64::MAX {
            return Err(WorkError::Exhausted);
        }
        Ok(())
    }
    pub(super) fn suspend(
        &mut self,
        id: ContextId,
        sequence: u64,
        reason: LeaveReason,
    ) -> Result<(), WorkError> {
        if !self.enabled {
            return Ok(());
        }
        let slot = self.index(id, sequence)?;
        if self.rows[slot].as_ref().unwrap().state != State::Running {
            return Err(WorkError::CorruptContext);
        }
        let order = if reason == LeaveReason::Yield {
            Some(self.order(false)?)
        } else {
            None
        };
        let row = self.rows[slot].as_mut().unwrap();
        if let Some(order) = order {
            row.order = order;
        }
        row.state = if reason == LeaveReason::Blocked {
            State::Blocked
        } else {
            State::Ready
        };
        Ok(())
    }
    pub(super) fn remove(&mut self, id: ContextId, sequence: u64) -> Result<(), WorkError> {
        if !self.enabled {
            return Ok(());
        }
        let slot = self.index(id, sequence)?;
        let row = self.rows[slot].unwrap();
        if row.rank != Snapshot::NORMAL || row.state != State::Running {
            return Err(WorkError::Busy);
        }
        self.rows[slot] = None;
        Ok(())
    }
    pub(super) fn snapshot(&self, id: ContextId, sequence: u64) -> Result<Snapshot, WorkError> {
        if !self.enabled {
            return Err(WorkError::Unavailable);
        }
        Ok(self.rows[self.index(id, sequence)?].unwrap().rank)
    }
    pub(super) fn update(
        &mut self,
        id: ContextId,
        sequence: u64,
        before: Snapshot,
        after: Snapshot,
        head: bool,
    ) -> Result<(), WorkError> {
        after.validate()?;
        let slot = self.index(id, sequence)?;
        let row = self.rows[slot].unwrap();
        if !self.enabled || row.rank != before {
            return Err(WorkError::InvalidTicket);
        }
        if row.service && after.base != BasePolicy::Normal {
            return Err(WorkError::Unavailable);
        }
        // This is the original RT->RT deboost placement, not explicit yield.
        if head && !(before.effective < after.effective && after.effective < 100) {
            return Err(WorkError::Unavailable);
        }
        let changed = before.effective != after.effective;
        let order = if changed && row.state != State::Blocked {
            Some(self.order(head)?)
        } else {
            None
        };
        let row = self.rows[slot].as_mut().unwrap();
        if let Some(order) = order {
            row.order = order;
        }
        row.rank = after;
        Ok(())
    }
    /// Both candidates are actual eligible Runtime tasks. Equal NORMAL keeps
    /// the caller's round-robin scan order; equal effective RT uses ready order.
    pub(super) fn precedes(
        &self,
        candidate: (ContextId, u64),
        selected: (ContextId, u64),
    ) -> Result<bool, WorkError> {
        let a = self.rows[self.index(candidate.0, candidate.1)?].unwrap();
        let b = self.rows[self.index(selected.0, selected.1)?].unwrap();
        if a.state != State::Ready || b.state != State::Ready {
            return Err(WorkError::CorruptContext);
        }
        Ok(a.rank.effective < b.rank.effective
            || (a.rank.effective == b.rank.effective
                && a.rank.effective < 100
                && a.order < b.order))
    }
    pub(super) fn quiet(&self) -> bool {
        self.rows.iter().all(Option::is_none)
    }
}

/// Immutable actual queue/context/job generation. It contains no Runtime or C
/// task pointer. A stale handle cannot mutate a new job on the reused stack.
#[derive(Clone)]
pub struct SchedulingHandle<const N: usize> {
    pub(super) wake: WakeHandle<N>,
}
impl<const N: usize> SchedulingHandle<N> {
    fn live(&self) -> Result<(), WorkError> {
        self.wake.queue.current_id()?; // actual caller CPU/RSP, same Queue
        if self.wake.closed()? {
            return Err(WorkError::Closed);
        }
        Ok(())
    }
    pub fn snapshot(&self) -> Result<Snapshot, WorkError> {
        self.live()?;
        self.wake
            .queue
            .lock()?
            .state()
            .scheduling
            .snapshot(self.wake.id, self.wake.sequence)
    }
    /// # Safety
    /// The same serialized original Linux task/PI-lock mutation supplies these
    /// exact old/new admitted policies and effective priorities. C commits its
    /// corresponding priority and borrowed donor before releasing that lease.
    /// Retain actual donor/task/waiter lifetimes; rank is not an ownership grant.
    pub unsafe fn update(
        &self,
        before: Snapshot,
        after: Snapshot,
        head: bool,
    ) -> Result<(), WorkError> {
        self.live()?;
        self.wake.queue.lock()?.state().scheduling.update(
            self.wake.id,
            self.wake.sequence,
            before,
            after,
            head,
        )?;
        self.wake.queue.inspection.store(true, Ordering::Release);
        Ok(())
    }
}
