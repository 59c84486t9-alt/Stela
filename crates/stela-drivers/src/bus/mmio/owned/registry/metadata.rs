//! Fallible metadata reservation before native effects. triomphe 0.1.16 is
//! pinned with default features disabled for alloc-only hosted/UEFI ownership.
use super::Error;
use core::mem::MaybeUninit;
use triomphe::UniqueArc;

pub(super) fn reserve<T>() -> Result<UniqueArc<MaybeUninit<T>>, Error> {
    #[cfg(test)]
    allocation::reserve()?;
    UniqueArc::try_new_uninit().map_err(|_| Error::Unavailable)
}

#[cfg(test)]
pub(super) mod allocation {
    extern crate std;
    use super::Error;
    use core::cell::Cell;
    std::thread_local! {
        static BUDGET: Cell<Option<usize>> = const { Cell::new(None) };
        static ATTEMPTS: Cell<usize> = const { Cell::new(0) };
    }
    pub(crate) fn reserve() -> Result<(), Error> {
        ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
        BUDGET.with(|budget| match budget.get() {
            Some(0) => Err(Error::Unavailable),
            Some(left) => {
                budget.set(Some(left - 1));
                Ok(())
            }
            None => Ok(()),
        })
    }
    pub(crate) fn budget(value: Option<usize>) {
        BUDGET.with(|budget| budget.set(value));
        ATTEMPTS.with(|attempts| attempts.set(0));
    }
    pub(crate) fn attempts() -> usize {
        ATTEMPTS.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct Dropped(Arc<AtomicUsize>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[test]
    fn reserved_unique_storage_becomes_shared_without_moving_and_releases_once() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut storage = reserve::<Dropped>().unwrap();
        let original = storage.write(Dropped(Arc::clone(&dropped))) as *mut Dropped;
        // SAFETY: write initialized the entire retained value exactly once.
        let unique = unsafe { UniqueArc::assume_init(storage) };
        assert_eq!(&*unique as *const Dropped, original);
        let shared = unique.shareable();
        assert_eq!(&*shared as *const Dropped, original);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let value = shared.clone();
                scope.spawn(move || {
                    for _ in 0..128 {
                        drop(value.clone());
                    }
                });
            }
        });
        assert_eq!(triomphe::Arc::strong_count(&shared), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        std::thread::spawn(move || drop(shared)).join().unwrap();
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
}
