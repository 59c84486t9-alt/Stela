//! A value one PE hands to another once, without a lock: what a device's
//! copy outside the devices' lock ([`stela_engine::machine::engine::UnlockedDma`])
//! leaves for the device to take back under the lock.
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

const EMPTY: u8 = 0;
const FULL: u8 = 1;
const TAKEN: u8 = 2;

/// One value, put once and taken once.
pub struct Handoff<T> {
    state: AtomicU8,
    value: UnsafeCell<Option<T>>,
}

// SAFETY: `value` is written once, by the one putter, before the Release
// store of FULL, and read once, by the one taker, after the Acquire load
// that sees FULL; TAKEN keeps it from being read again. The value moves
// between the two PEs, as a device's state already does under the
// devices' lock.
unsafe impl<T> Sync for Handoff<T> {}
// SAFETY: as above.
unsafe impl<T> Send for Handoff<T> {}

impl<T> Handoff<T> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(EMPTY),
            value: UnsafeCell::new(None),
        })
    }

    /// Hand `value` over. A second put is ignored.
    pub fn put(&self, value: T) {
        if self.state.load(Ordering::Relaxed) != EMPTY {
            return;
        }
        // SAFETY: the one putter, before the Release store below.
        unsafe { *self.value.get() = Some(value) };
        self.state.store(FULL, Ordering::Release);
    }

    /// Whether the value was put and not yet taken.
    pub fn ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == FULL
    }

    /// The value, once put; `None` before, and after it was taken.
    pub fn take(&self) -> Option<T> {
        if self.state.load(Ordering::Acquire) != FULL {
            return None;
        }
        self.state.store(TAKEN, Ordering::Relaxed);
        // SAFETY: FULL was stored after the write; TAKEN keeps any later
        // call from reading it again.
        unsafe { (*self.value.get()).take() }
    }

    /// The value, waiting for it at most `spins` spin-loop hints: the
    /// putter runs outside the devices' lock, so a holder of that lock
    /// waits only for its copy to end, and a putter that never runs is
    /// waited for no longer. `None` when it did not come.
    pub fn wait(&self, spins: u64) -> Option<T> {
        let mut left = spins;
        while self.state.load(Ordering::Acquire) == EMPTY && left != 0 {
            core::hint::spin_loop();
            left -= 1;
        }
        self.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_is_taken_once_after_it_is_put_and_waited_for_across_threads() {
        let handoff = Handoff::new();
        assert!(!handoff.ready());
        assert_eq!(handoff.take(), None);
        let putter = Arc::clone(&handoff);
        let thread = std::thread::spawn(move || putter.put(alloc::vec![7u8; 64]));
        let empty = Handoff::<u8>::new();
        assert_eq!(empty.wait(1000), None, "bounded");
        assert_eq!(handoff.wait(u64::MAX), Some(alloc::vec![7u8; 64]));
        thread.join().unwrap();
        assert_eq!(handoff.take(), None);
        handoff.put(alloc::vec![1]);
        assert_eq!(handoff.take(), None, "put once");
    }
}
