//! Spin locks for ring 0. The loader must exclude interrupt re-entry and
//! migration while a guard is held. Panics abort.
//!
//! A lock is a ticket lock: each processor that waits takes the next ticket
//! and only reads until it is served, so waiters take turns in order and do
//! not bounce the line the holder works on.
use alloc::rc::Rc;
use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU32, Ordering},
};

#[cfg(not(all(target_arch = "x86_64", target_os = "uefi")))]
compile_error!("freestanding metadata locks require the x86-64 ring-0 platform");

pub(crate) struct Mutex<T: ?Sized> {
    /// The next ticket, and the ticket that holds the lock.
    next: AtomicU32,
    serving: AtomicU32,
    value: UnsafeCell<T>,
}
// SAFETY: all accesses use the atomic exclusion, and ownership can cross CPUs
// only for Send payloads. Local interrupt/preemption obligations are above.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
// SAFETY: shared references rely on the same argument as `Send` above.
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            next: AtomicU32::new(0),
            serving: AtomicU32::new(0),
            value: UnsafeCell::new(value),
        }
    }
}

pub(crate) struct MutexGuard<'a, T: ?Sized> {
    owner: &'a Mutex<T>,
    _same_cpu: PhantomData<Rc<()>>,
}

pub(crate) struct PoisonError<T>(core::convert::Infallible, PhantomData<T>);
impl<T> PoisonError<T> {
    pub(crate) fn into_inner(self) -> T {
        match self.0 {}
    }
}
impl<T> core::fmt::Debug for PoisonError<T> {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {}
    }
}

#[derive(Debug)]
pub(crate) struct WouldBlock;

impl<T: ?Sized> Mutex<T> {
    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, T>, PoisonError<MutexGuard<'_, T>>> {
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        while self.serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }
        Ok(MutexGuard {
            owner: self,
            _same_cpu: PhantomData,
        })
    }
    pub(crate) fn try_lock(&self) -> Result<MutexGuard<'_, T>, WouldBlock> {
        let serving = self.serving.load(Ordering::Relaxed);
        if self
            .next
            .compare_exchange(
                serving,
                serving.wrapping_add(1),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return Err(WouldBlock);
        }
        Ok(MutexGuard {
            owner: self,
            _same_cpu: PhantomData,
        })
    }
}
impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock, so no other access to the value exists.
        unsafe { &*self.owner.value.get() }
    }
}
impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the lock, so no other access to the value exists.
        unsafe { &mut *self.owner.value.get() }
    }
}
impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // Only the holder moves `serving`.
        let served = self.owner.serving.load(Ordering::Relaxed);
        self.owner
            .serving
            .store(served.wrapping_add(1), Ordering::Release);
    }
}
impl<T: ?Sized + core::fmt::Debug> core::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.try_lock() {
            Ok(guard) => f.debug_struct("Mutex").field("value", &&*guard).finish(),
            Err(_) => f.write_str("Mutex { locked }"),
        }
    }
}
/// Reads also take exclusive access; the atomic tag cells keep their own
/// ordering.
pub(crate) struct RwLock<T>(Mutex<T>);
impl<T> RwLock<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }
    pub(crate) fn read(&self) -> Result<MutexGuard<'_, T>, PoisonError<MutexGuard<'_, T>>> {
        self.0.lock()
    }
    pub(crate) fn write(&self) -> Result<MutexGuard<'_, T>, PoisonError<MutexGuard<'_, T>>> {
        self.0.lock()
    }
}
impl<T: core::fmt::Debug> core::fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}
