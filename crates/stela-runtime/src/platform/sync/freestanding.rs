//! Spin locks for ring 0. The loader must exclude interrupt re-entry and
//! migration while a guard is held. Panics abort.
use alloc::rc::Rc;
use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
compile_error!("freestanding metadata locks require the x86-64 ring-0 platform");

pub(crate) struct Mutex<T: ?Sized> {
    held: AtomicBool,
    value: UnsafeCell<T>,
}
// SAFETY: all accesses use the atomic exclusion, and ownership can cross CPUs
// only for Send payloads. Local interrupt/preemption obligations are above.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            held: AtomicBool::new(false),
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
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Ok(MutexGuard {
            owner: self,
            _same_cpu: PhantomData,
        })
    }
    pub(crate) fn try_lock(&self) -> Result<MutexGuard<'_, T>, WouldBlock> {
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
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
        unsafe { &*self.owner.value.get() }
    }
}
impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.owner.value.get() }
    }
}
impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.owner.held.store(false, Ordering::Release);
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
/// Reads also acquire exclusive metadata access. The atomic tag cells retain
/// their original publication ordering. Reduced read concurrency is explicit.
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
