pub use alloc_crate::sync::{Arc, Weak};
pub use core::sync::atomic;
use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicU8, Ordering},
};

const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const FULL: u8 = 2;

/// A value set once, by whichever host processor gets there first.
pub struct OnceLock<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: as `std`'s: the value crosses threads, and is shared once set.
unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}

impl<T> OnceLock<T> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub fn get(&self) -> Option<&T> {
        // SAFETY: `FULL` is published after the write, with release ordering.
        (self.state.load(Ordering::Acquire) == FULL)
            .then(|| unsafe { (*self.value.get()).assume_init_ref() })
    }

    pub fn get_or_init(&self, make: impl FnOnce() -> T) -> &T {
        match self
            .state
            .compare_exchange(EMPTY, WRITING, Ordering::Acquire, Ordering::Acquire)
        {
            Ok(_) => {
                // SAFETY: winning the exchange makes this the only writer.
                unsafe { (*self.value.get()).write(make()) };
                self.state.store(FULL, Ordering::Release);
            }
            Err(_) => {
                while self.state.load(Ordering::Acquire) != FULL {
                    core::hint::spin_loop();
                }
            }
        }
        self.get().expect("just set")
    }
}
