//! Permanent nonblocking access to the same canonical global heap.
//!
//! Registration retains a function, never a per-enter borrowed context. Its
//! result must use the existing exact-layout global free path; no unrelated
//! allocator, page catalog, physical mapping or GPU readiness is installed.
use core::{
    alloc::Layout,
    cell::UnsafeCell,
    ffi::c_void,
    mem::MaybeUninit,
    ptr,
    sync::atomic::{AtomicU8, Ordering},
};

const EMPTY: u8 = 0;
const INSTALLING: u8 = 1;
const READY: u8 = 2;

/// The canonical allocator's one-attempt, zeroed allocation operation.
pub type TryAllocateZeroed = unsafe fn(Layout) -> *mut u8;

struct Registry {
    state: AtomicU8,
    callback: UnsafeCell<MaybeUninit<TryAllocateZeroed>>,
}

// SAFETY: the sole successful installer writes before READY release/acquire
// publication. The function is then immutable and never removed. Registration
// requires permanent executable code supporting the admitted caller contexts.
unsafe impl Sync for Registry {}

impl Registry {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            callback: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn install(
        &self,
        callback: TryAllocateZeroed,
    ) -> Result<LinuxHeapRegistration, TryAllocateZeroed> {
        if self
            .state
            .compare_exchange(EMPTY, INSTALLING, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return Err(callback);
        }
        // SAFETY: one writer; no reader observes READY before initialization.
        // Neither initialization nor publication calls the allocator/provider.
        unsafe { (*self.callback.get()).write(callback) };
        self.state.store(READY, Ordering::Release);
        Ok(LinuxHeapRegistration { _private: () })
    }

    fn available(&self) -> bool {
        self.state.load(Ordering::Acquire) == READY
    }

    /// # Safety
    /// The caller meets the registered canonical heap's context contract and
    /// supplies a nonzero layout. The returned pointer retains exact-layout
    /// ownership until its one matching canonical global deallocation.
    unsafe fn allocate(&self, layout: Layout) -> *mut u8 {
        assert!(
            self.available(),
            "Linux nonblocking heap used before registration"
        );
        // SAFETY: acquired permanent publication; this function is never
        // replaced, dropped or retargeted after a capability query.
        let callback = unsafe { *(*self.callback.get()).assume_init_ref() };
        // SAFETY: registration attests the actual canonical owner and callback;
        // this caller preserves that same nonzero layout and context contract.
        unsafe { callback(layout) }
    }
}

static HEAP: Registry = Registry::new();

/// Evidence of permanent callback publication, not native/GPU qualification.
/// Dropping it does not unregister, replace or release the canonical heap.
#[derive(Debug)]
pub struct LinuxHeapRegistration {
    _private: (),
}

/// Publish the actual canonical global heap's nonblocking allocation operation.
/// A second or concurrent installation returns its callback unchanged. There
/// is no replacement or unregister operation and no allocation during install.
///
/// # Safety
/// The callback's code and actual initialized heap/backing/mapping stay valid
/// through every allocation and its matching global deallocation. Success is
/// aligned, zeroed, exclusive storage from the EXACT allocator instance used by
/// `alloc::alloc::dealloc`, with the exact supplied layout. Failure transfers
/// nothing and changes no allocation ownership. The callback supports concurrent
/// admitted callers, including an entered Linux owner's IRQ-disabled/preempt/
/// read-side context, without waiting, spinning, sleeping, reclaiming, growing
/// backing, falling back, reentering Linux or unwinding. It may attempt the real
/// allocator lock once and may return NULL on contention or exhaustion. This
/// admits no native ISR, NMI or fault-handler Linux entry. No allocation may
/// escape into a different image/allocator phase without its real owner.
pub unsafe fn register(
    callback: TryAllocateZeroed,
) -> Result<LinuxHeapRegistration, TryAllocateZeroed> {
    HEAP.install(callback)
}

/// Pure capability query. Missing/in-progress registration is unsupported,
/// never ordinary allocation exhaustion. READY cannot later be withdrawn.
#[unsafe(no_mangle)]
extern "C" fn stela_linux_heap_try_available() -> bool {
    HEAP.available()
}

/// # Safety
/// For a nonzero valid layout the C caller first verifies the permanent heap
/// capability and preserves its actual owner/context/one-free contract. Missing
/// registration is a contract trap, not an ordinary exhausted-heap NULL.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_heap_try_alloc(size: usize, align: usize) -> *mut c_void {
    match Layout::from_size_align(size, align) {
        // SAFETY: the checked layout and caller meet the installed heap contract.
        Ok(layout) if size != 0 => unsafe { HEAP.allocate(layout).cast() },
        _ => ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::AtomicUsize;

    // Negative allocation models test publication/dispatch only. They transfer
    // no storage and do not qualify a positive/nonblocking native allocator.
    static SIZE: AtomicUsize = AtomicUsize::new(0);
    static ALIGN: AtomicUsize = AtomicUsize::new(0);
    unsafe fn exhausted(layout: Layout) -> *mut u8 {
        SIZE.store(layout.size(), Ordering::Relaxed);
        ALIGN.store(layout.align(), Ordering::Relaxed);
        ptr::null_mut()
    }

    #[test]
    fn preserves_exact_backing_layout_and_real_failure() {
        let registry = Registry::new();
        assert!(!registry.available());
        assert!(registry.install(exhausted).is_ok());
        assert!(registry.available());
        // SAFETY: this negative model returns no allocation; layout is valid.
        assert!(unsafe { registry.allocate(Layout::from_size_align(256, 128).unwrap()) }.is_null());
        assert_eq!(SIZE.load(Ordering::Relaxed), 256);
        assert_eq!(ALIGN.load(Ordering::Relaxed), 128);
    }

    static FIRST: AtomicUsize = AtomicUsize::new(0);
    static REJECTED: AtomicUsize = AtomicUsize::new(0);
    unsafe fn first(_: Layout) -> *mut u8 {
        FIRST.fetch_add(1, Ordering::Relaxed);
        ptr::null_mut()
    }
    unsafe fn rejected(_: Layout) -> *mut u8 {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        ptr::null_mut()
    }

    #[test]
    fn receipt_exit_and_rejected_install_cannot_retarget_free_identity() {
        let registry = Registry::new();
        {
            let _receipt = registry.install(first).ok().unwrap();
        }
        let returned = match registry.install(rejected) {
            Ok(_) => panic!("canonical allocator was replaced"),
            Err(callback) => callback,
        };
        let layout = Layout::from_size_align(16, 16).unwrap();
        // SAFETY: both negative models transfer no allocation/owner.
        unsafe {
            assert!(registry.allocate(layout).is_null());
            assert!(returned(layout).is_null());
        }
        assert_eq!(FIRST.load(Ordering::Relaxed), 1);
        assert_eq!(REJECTED.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unfinished_publication_cannot_report_exhaustion_or_read_a_callback() {
        let registry = Registry::new();
        for state in [EMPTY, INSTALLING] {
            registry.state.store(state, Ordering::Relaxed);
            assert!(!registry.available());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // SAFETY: valid layout/negative model context; missing callback
                // must trap before reading uninitialized function storage.
                unsafe { registry.allocate(Layout::from_size_align(16, 16).unwrap()) }
            }));
            assert!(result.is_err());
        }
        assert!(registry.install(first).is_err());
        assert_eq!(registry.state.load(Ordering::Relaxed), INSTALLING);
    }

    unsafe fn no_storage(_: Layout) -> *mut u8 {
        ptr::null_mut()
    }

    #[test]
    fn concurrent_installation_publishes_exactly_one_permanent_owner() {
        let registry = Registry::new();
        let barrier = std::sync::Barrier::new(8);
        let winners = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let registry = &registry;
                let barrier = &barrier;
                let winners = &winners;
                scope.spawn(move || {
                    barrier.wait();
                    if registry.install(no_storage).is_ok() {
                        winners.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(winners.load(Ordering::Relaxed), 1);
        assert!(registry.available());
        // SAFETY: initialized permanent publication; negative model only.
        assert!(unsafe { registry.allocate(Layout::from_size_align(8, 8).unwrap()) }.is_null());
    }
}
