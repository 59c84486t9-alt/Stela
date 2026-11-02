//! Bounded synchronization for shared metadata; these values grant no ownership,
//! I/O, operation admission or completion authority.
use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicU8, Ordering},
};
const EMPTY: u8 = 0;
const PUBLISHING: u8 = 1;
const READY: u8 = 2;

/// An observation, distinct from the stored cause type. Publishing is closed and
/// incomplete; observing it neither supplies a cause nor permits retrying effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultState<C> {
    Empty,
    Publishing,
    Ready(C),
}

/// Immutable first-cause publication, independent of an operation's Acting or
/// lock state. Record only an actual failure according to the caller's protocol;
/// a pre-effect Busy/refusal is not automatically a terminal cause.
///
/// One CAS claims publication and one plain Copy write precedes Release READY.
/// Readers never allocate, wait, spin, or inspect an unfinished payload. A writer
/// interrupted after its claim leaves Publishing closed; there is no reset or
/// overwrite. No callback, external check, allocation or panic occurs between
/// the successful claim and publication. This is metadata, never an owner/grant.
pub struct FirstFault<C: Copy + Send + Sync> {
    phase: AtomicU8,
    cause: UnsafeCell<MaybeUninit<C>>,
}
// SAFETY: one successful EMPTY→PUBLISHING CAS uniquely owns the sole payload
// write. Release READY publishes it to Acquire readers, then it is immutable.
// C is Copy/Send/Sync; no payload read occurs until READY and there is no reset.
unsafe impl<C: Copy + Send + Sync> Sync for FirstFault<C> {}
impl<C: Copy + Send + Sync> FirstFault<C> {
    pub const fn new() -> Self {
        Self {
            phase: AtomicU8::new(EMPTY),
            cause: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
    /// Publish the first actual cause. False means another writer claimed the
    /// cell already; inspect observe() if its distinct observation is needed.
    pub fn latch(&self, cause: C) -> bool {
        if self
            .phase
            .compare_exchange(EMPTY, PUBLISHING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        // No user code or fallible work occurs between claim and publication.
        // SAFETY: this successful CAS owns the only write; readers cannot read
        // cause until the following Release publishes READY.
        unsafe { (*self.cause.get()).write(cause) };
        self.phase.store(READY, Ordering::Release);
        true
    }
    pub fn observe(&self) -> FaultState<C> {
        match self.phase.load(Ordering::Acquire) {
            EMPTY => FaultState::Empty,
            READY => {
                // SAFETY: Acquire READY observes the unique complete write;
                // C is Copy and the payload is never changed afterward.
                FaultState::Ready(unsafe { (*self.cause.get()).assume_init_read() })
            }
            _ => FaultState::Publishing,
        }
    }
}
impl<C: Copy + Send + Sync> Default for FirstFault<C> {
    fn default() -> Self {
        Self::new()
    }
}

// Only deterministic in-crate controls can pause a writer. Production latch has
// no callback or exposed claim handle between CAS and its plain Copy publish.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    pub(crate) fn claim<C: Copy + Send + Sync>(cell: &FirstFault<C>) -> bool {
        cell.phase
            .compare_exchange(EMPTY, PUBLISHING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
    /// # Safety
    /// Own the sole successful simulated claim for this exact still-Publishing
    /// cell; no other writer may finish it or access its uninitialized payload.
    pub(crate) unsafe fn finish<C: Copy + Send + Sync>(cell: &FirstFault<C>, cause: C) {
        assert_eq!(cell.phase.load(Ordering::Acquire), PUBLISHING);
        // SAFETY: caller owns this cell's sole successful writer claim; all
        // readers still observe Publishing until the following Release READY.
        unsafe { (*cell.cause.get()).write(cause) };
        cell.phase.store(READY, Ordering::Release);
    }
}
#[cfg(test)]
mod tests;
