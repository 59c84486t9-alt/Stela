//! Actual process/thread admission over the same Work queue state policy.
//! This owner does not yet construct a hosted continuation Runtime or segment.
use super::{HostedExecution, WorkError};
use crate::platform::work::{Callback, Kind, Lane, NEXT_QUEUE, RetainedOwner, State};
use alloc::sync::Arc;
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    mem::ManuallyDrop,
    sync::atomic::{AtomicBool, Ordering},
};

/// A ticket from this hosted queue. It has no native ticket conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedTicket {
    queue: u64,
    sequence: u64,
}

/// The original host execution/code/storage owner remains kept until explicit
/// producer drain and successful retirement. Closing alone never releases it.
pub struct HostedQueue<const N: usize> {
    id: u64,
    execution: ManuallyDrop<Arc<HostedExecution>>,
    owner: ManuallyDrop<RetainedOwner>,
    state: ManuallyDrop<UnsafeCell<State<N>>>,
    held: AtomicBool,
    retired: AtomicBool,
}
// SAFETY: every state access first verifies the same actual PID/OS thread and
// wins the bounded exclusion flag. Foreign-thread operations touch only shared
// immutable/atomic owners and refuse before state; foreign Drop keeps the graph.
unsafe impl<const N: usize> Send for HostedQueue<N> {}
// SAFETY: same checked thread and unique bounded state borrow as Send above.
unsafe impl<const N: usize> Sync for HostedQueue<N> {}

struct Guard<'a, const N: usize> {
    queue: &'a HostedQueue<N>,
}
impl<const N: usize> Guard<'_, N> {
    fn state(&mut self) -> &mut State<N> {
        // SAFETY: same actual host thread and sole held flag. No callback,
        // wait, switch, allocation or owner release occurs while borrowed.
        unsafe { &mut *self.queue.state.get() }
    }
}
impl<const N: usize> Drop for Guard<'_, N> {
    fn drop(&mut self) {
        self.queue.held.store(false, Ordering::Release);
    }
}
impl<const N: usize> HostedQueue<N> {
    pub fn new(
        execution: Arc<HostedExecution>,
        owner: RetainedOwner,
    ) -> Result<Arc<Self>, WorkError> {
        execution.check_current()?;
        if N == 0 || N > 4096 {
            return Err(WorkError::Unavailable);
        }
        let id = NEXT_QUEUE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| WorkError::Exhausted)?;
        Ok(Arc::new(Self {
            id,
            execution: ManuallyDrop::new(execution),
            owner: ManuallyDrop::new(owner),
            state: ManuallyDrop::new(UnsafeCell::new(State::new())),
            held: AtomicBool::new(false),
            retired: AtomicBool::new(false),
        }))
    }
    fn lock(&self) -> Result<Guard<'_, N>, WorkError> {
        self.execution.check_current()?;
        if self.retired.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        self.held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| WorkError::Busy)?;
        Ok(Guard { queue: self })
    }
    /// Admit work without invoking its callback or allocating. A returned
    /// refusal transfers no callback/context ownership.
    ///
    /// # Safety
    /// Keep the actual callback, context and every reachable code/storage
    /// allocation until completion or retained abandonment. No unload, free or
    /// conflicting mutable access may occur while this queue can still use it.
    /// This contract grants no native current, CPU, IRQ, stack or root role.
    pub unsafe fn execute(
        &self,
        kind: Kind,
        callback: Callback,
        context: *mut c_void,
    ) -> Result<HostedTicket, WorkError> {
        let lane = match kind {
            Kind::General => Lane::General,
            Kind::Notify => Lane::Notify,
        };
        let mut guard = self.lock()?;
        let sequence = guard
            .state()
            .enqueue(lane, callback, context, None, false)?;
        Ok(HostedTicket {
            queue: self.id,
            sequence,
        })
    }
    pub fn completed(&self, ticket: HostedTicket) -> Result<bool, WorkError> {
        let mut guard = self.lock()?;
        if ticket.queue != self.id {
            return Err(WorkError::InvalidTicket);
        }
        guard.state().completed(ticket.sequence)
    }
    pub fn close(&self) -> Result<(), WorkError> {
        self.lock()?.state().closed = true;
        Ok(())
    }
    /// # Safety
    /// All actual producers have stopped and cannot enqueue or access queued
    /// contexts again. This is not a callback/current/tail join inferred from
    /// close. Pending jobs or reservations refuse retirement without release.
    pub unsafe fn retire(&self) -> Result<(), WorkError> {
        let mut guard = self.lock()?;
        let state = guard.state();
        if !state.closed
            || state.jobs.iter().any(Option::is_some)
            || state
                .reservations
                .iter()
                .any(|reservation| *reservation != 0)
        {
            return Err(WorkError::Busy);
        }
        self.retired.store(true, Ordering::Release);
        Ok(())
    }
}
impl<const N: usize> Drop for HostedQueue<N> {
    fn drop(&mut self) {
        if self.execution.check_current().is_ok()
            && self.retired.load(Ordering::Acquire)
            && !self.held.load(Ordering::Acquire)
        {
            // SAFETY: explicit retirement checked no pending graph after real
            // producer drain; this is the original thread and unique last owner.
            unsafe {
                ManuallyDrop::drop(&mut self.state);
                ManuallyDrop::drop(&mut self.owner);
                ManuallyDrop::drop(&mut self.execution);
            }
        }
    }
}

#[cfg(test)]
mod tests;
