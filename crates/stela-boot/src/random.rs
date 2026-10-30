//! The boot's seeded cryptographic stream, shared by host device consumers.
use crate::{handoff::Region, layout};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, Ordering, compiler_fence};
use stela_boot_core::random::Source;
use stela_drivers::{
    entropy::{Entropy, EntropyError},
    probe::ServiceError,
};

// This strong reference is held for the boot. Consumers receive their
// own Arc, so a probe's temporary service object need not outlive them.
static SOURCE: AtomicPtr<Source> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize once from the loader's private seed, then erase that copy.
///
/// # Safety
/// `seed` names exactly 32 exclusive bytes kept by the loader, reached
/// through the shared physmap. No other reader borrows those bytes.
pub unsafe fn initialize(seed: Region) -> Result<(), EntropyError> {
    if seed.bytes != 32 || seed.physical == 0 {
        return Err(EntropyError::Unavailable);
    }
    let address = layout::physical(seed.physical) as *mut u8;
    let mut bytes = [0; 32];
    // SAFETY: the caller keeps the complete seed range and gives this
    // function its exclusive consumption and erasure.
    unsafe {
        core::ptr::copy_nonoverlapping(address, bytes.as_mut_ptr(), bytes.len());
        for offset in 0..bytes.len() {
            address.add(offset).write_volatile(0);
        }
    }
    compiler_fence(Ordering::SeqCst);
    let source = Arc::new(Source::from_seed(bytes));
    for byte in &mut bytes {
        // SAFETY: the local seed is exclusively borrowed and no longer used.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    let raw = Arc::into_raw(source).cast_mut();
    match SOURCE.compare_exchange(
        core::ptr::null_mut(),
        raw,
        Ordering::Release,
        Ordering::Relaxed,
    ) {
        Ok(_) => Ok(()),
        Err(_) => {
            // SAFETY: publication failed; this is still the one reference
            // produced by into_raw, with no consumer able to observe it.
            drop(unsafe { Arc::from_raw(raw) });
            Err(EntropyError::Failed)
        }
    }
}

pub fn source() -> Result<Arc<dyn Entropy>, ServiceError> {
    let raw = SOURCE.load(Ordering::Acquire);
    if raw.is_null() {
        return Err(ServiceError::Unavailable);
    }
    // SAFETY: the global strong reference is held permanently, and an
    // acquired publication observes the initialized generator. This extra
    // strong reference belongs to the returned capability.
    unsafe {
        Arc::increment_strong_count(raw);
        Ok(Arc::from_raw(raw))
    }
}

pub fn fill(output: &mut [u8]) -> Result<(), EntropyError> {
    source()
        .map_err(|_| EntropyError::Unavailable)?
        .fill(output)
}
