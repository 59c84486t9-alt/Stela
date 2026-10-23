//! Permanent immutable-image ownership for Linux's borrowed constant names.
//!
//! Registration consumes an actual platform capability. It does not establish
//! page permissions or manufacture image authority. The provider is retained
//! permanently because names and caches can survive an individual Linux owner.

use crate::platform::image::NativeReadOnlyImage;
use alloc::sync::Arc;
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    mem::MaybeUninit,
    sync::atomic::{AtomicU8, Ordering},
};

const EMPTY: u8 = 0;
const INSTALLING: u8 = 1;
const READY: u8 = 2;

struct Registry {
    state: AtomicU8,
    image: UnsafeCell<MaybeUninit<Arc<dyn NativeReadOnlyImage>>>,
}

// SAFETY: one successful compare-exchange selects the only writer. READY's
// release/acquire publication precedes every read. The stored Arc is never
// replaced, moved or dropped, and its provider is Send + Sync.
unsafe impl Sync for Registry {}

impl Registry {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            image: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn install(
        &self,
        image: Arc<dyn NativeReadOnlyImage>,
    ) -> Result<LinuxImageRegistration, Arc<dyn NativeReadOnlyImage>> {
        if self
            .state
            .compare_exchange(EMPTY, INSTALLING, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return Err(image);
        }
        // SAFETY: this is the sole writer, and readers cannot observe READY
        // until after initialization. No operation between selection and
        // publication allocates, blocks or calls user/provider code.
        unsafe { (*self.image.get()).write(image) };
        self.state.store(READY, Ordering::Release);
        Ok(LinuxImageRegistration { _private: () })
    }

    fn contains(&self, address: usize) -> bool {
        assert_eq!(
            self.state.load(Ordering::Acquire),
            READY,
            "Linux immutable-image service used before registration"
        );
        // SAFETY: READY acquired the sole writer's initialized Arc. Neither the
        // Arc nor its provider is ever released or replaced by this registry.
        unsafe { (*self.image.get()).assume_init_ref() }.contains(address)
    }
}

// MaybeUninit deliberately has no destructor: even a registry's destruction
// cannot release an image while an escaped constant name may still borrow it.
static IMAGE: Registry = Registry::new();

/// Evidence that the permanent Linux image registry has been installed.
///
/// Dropping this receipt does not unregister or release the image. This is no
/// evidence of a GPU, kobject, root or hardware test having passed.
#[derive(Debug)]
pub struct LinuxImageRegistration {
    _private: (),
}

/// Transfer actual immutable native-image ownership to Linux for the mount's
/// lifetime, before admitting any dependent constant-name lifecycle.
///
/// There is no replacement or unregister operation. A second or concurrent
/// registration returns its unchanged capability to the caller. Registration
/// adds no allocation and never calls the provider. Platform producers must
/// satisfy [`NativeReadOnlyImage`]'s complete safety contract before this call.
///
/// # Safety
/// Before admitting a free-or-borrow lifecycle, the caller must establish and
/// preserve complete name provenance for the mount's lifetime: every admitted
/// literal or borrowed constant name, including its terminating NUL, is covered
/// by this provider. Classification must stay true throughout each borrow and
/// its release. Except for the canonical allocator's NULL/zero-size no-op
/// values, a negative classification used to free a name must separately have
/// live heap-allocation ownership; a negative duplication query can instead
/// copy an ordinary valid stack or mutable string. No later image or literal
/// may enter that lifecycle outside this coverage. A partial image capability
/// by itself does not establish this admission contract. Registration failure
/// returns the capability and installs no new admission obligation.
pub unsafe fn register(
    image: Arc<dyn NativeReadOnlyImage>,
) -> Result<LinuxImageRegistration, Arc<dyn NativeReadOnlyImage>> {
    IMAGE.install(image)
}

/// Classify an address without reading its contents. Missing or unfinished
/// registration traps: it cannot become false and cause a literal to be freed.
/// A false result grants no heap-allocation or free authority.
#[unsafe(no_mangle)]
extern "C" fn stela_linux_is_rodata(address: *const c_void) -> bool {
    IMAGE.contains(address as usize)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::AtomicUsize;

    /// Empty authority tests registry mechanics only. It classifies no native
    /// address and supplies no image, permission or execution-root evidence.
    struct EmptyImage {
        queries: AtomicUsize,
        last_address: AtomicUsize,
        drops: Arc<AtomicUsize>,
    }

    // SAFETY: no address is ever classified as immutable data. Classification
    // uses atomics only and never reads through the supplied address.
    unsafe impl NativeReadOnlyImage for EmptyImage {
        fn contains(&self, address: usize) -> bool {
            self.queries.fetch_add(1, Ordering::Relaxed);
            self.last_address.store(address, Ordering::Relaxed);
            false
        }
    }

    impl Drop for EmptyImage {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn empty_image() -> Arc<EmptyImage> {
        Arc::new(EmptyImage {
            queries: AtomicUsize::new(0),
            last_address: AtomicUsize::new(0),
            drops: Arc::new(AtomicUsize::new(0)),
        })
    }

    #[test]
    fn retains_registered_owner_after_receipt_and_registry_exit() {
        let image = empty_image();
        let weak = Arc::downgrade(&image);
        let drops = image.drops.clone();
        {
            let registry = Registry::new();
            {
                let _receipt = registry.install(image).ok().unwrap();
            }
            assert!(!registry.contains(usize::MAX));
            let retained = weak.upgrade().unwrap();
            assert_eq!(retained.queries.load(Ordering::Relaxed), 1);
            assert_eq!(retained.last_address.load(Ordering::Relaxed), usize::MAX);
        }
        assert!(weak.upgrade().is_some());
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rejects_replacement_without_querying_or_dropping_it() {
        let registry = Registry::new();
        assert!(registry.install(empty_image()).is_ok());
        let rejected = empty_image();
        let expected: Arc<dyn NativeReadOnlyImage> = rejected.clone();
        let drops = rejected.drops.clone();
        let returned = registry.install(rejected.clone()).unwrap_err();
        assert!(Arc::ptr_eq(&returned, &expected));
        assert_eq!(rejected.queries.load(Ordering::Relaxed), 0);
        drop(returned);
        drop(expected);
        drop(rejected);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn absent_and_installing_registrations_cannot_classify_false() {
        let registry = Registry::new();
        for state in [EMPTY, INSTALLING] {
            registry.state.store(state, Ordering::Relaxed);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                registry.contains(0)
            }));
            assert!(result.is_err());
        }
        let rejected = empty_image();
        assert!(registry.install(rejected.clone()).is_err());
        assert_eq!(rejected.queries.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn concurrent_registration_retains_exactly_the_winner() {
        const OWNERS: usize = 8;
        let registry = Registry::new();
        let images: [Arc<EmptyImage>; OWNERS] = core::array::from_fn(|_| empty_image());
        let barrier = std::sync::Barrier::new(OWNERS);
        let winners = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for image in &images {
                let registry = &registry;
                let barrier = &barrier;
                let winners = &winners;
                scope.spawn(move || {
                    barrier.wait();
                    if registry.install(image.clone()).is_ok() {
                        winners.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(winners.load(Ordering::Relaxed), 1);
        assert!(!registry.contains(0));
        assert_eq!(
            images
                .iter()
                .map(|image| image.queries.load(Ordering::Relaxed))
                .sum::<usize>(),
            1
        );
        assert_eq!(
            images
                .iter()
                .filter(|image| Arc::strong_count(image) == 2)
                .count(),
            1
        );
        assert_eq!(
            images
                .iter()
                .filter(|image| Arc::strong_count(image) == 1)
                .count(),
            OWNERS - 1
        );
    }
}
