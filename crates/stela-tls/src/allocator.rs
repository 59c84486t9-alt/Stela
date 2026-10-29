//! Fixed Mbed allocation ABI over Rust's actual global allocator.
#[cfg(test)]
use core::sync::atomic::Ordering;
use core::{
    alloc::Layout,
    ffi::{CStr, c_char, c_int, c_void},
};
#[cfg(test)]
use observation::*;
/// Count and size are ordinary untrusted allocation sizes, checked before use.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_mbedtls_calloc(count: usize, size: usize) -> *mut c_void {
    #[cfg(test)]
    if FAIL_AT.try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
        if n >= 0 { Some(n - 1) } else { None }
    }) == Ok(0)
    {
        return core::ptr::null_mut();
    }
    let Some(bytes) = count
        .checked_mul(size)
        .and_then(|n| n.max(1).checked_add(16))
    else {
        return core::ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(bytes, 16) else {
        return core::ptr::null_mut();
    };
    // SAFETY: checked layout; the actual platform Rust allocator supplies its
    // lifetime/thread/context guarantees, as it does for all Rustls allocations.
    let raw = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    #[cfg(test)]
    OUTSTANDING.fetch_add(1, Ordering::AcqRel);
    // SAFETY: exact live allocation includes aligned size header and payload.
    unsafe {
        raw.cast::<usize>().write(bytes);
        raw.add(16).cast()
    }
}
/// # Safety
/// Pointer is null or the exact live payload returned by this backend's calloc,
/// with no surviving callers/references; its preserved header is not modified.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_mbedtls_free(pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: paired allocator contract supplies the exact initialized header.
    let (raw, bytes) = unsafe {
        let raw = pointer.cast::<u8>().sub(16);
        (raw, raw.cast::<usize>().read())
    };
    #[cfg(test)]
    {
        if pointer as usize == CHECK_ZERO.load(Ordering::Acquire) {
            // SAFETY: matching calloc payload is still live and initialized;
            // Mbed's destructor has wiped its exact object before paired free.
            let zero = unsafe { core::slice::from_raw_parts(pointer.cast::<u8>(), bytes - 16) }
                .iter()
                .all(|x| *x == 0);
            WAS_ZERO.store(zero, Ordering::Release);
        }
        if CHECK_ALL_FREES.load(Ordering::Acquire) {
            // SAFETY: digest/HMAC destructor wipes complete allocated contexts;
            // observing this exact initialized payload precedes deallocation.
            let payload = unsafe { core::slice::from_raw_parts(pointer.cast::<u8>(), bytes - 16) };
            if payload.iter().any(|x| *x != 0) {
                NONZERO_FREES.fetch_add(1, Ordering::AcqRel);
            }
        }
        OUTSTANDING.fetch_sub(1, Ordering::AcqRel);
    }
    // SAFETY: header preserves the identical original layout; no aliases live.
    unsafe {
        alloc::alloc::dealloc(
            raw,
            Layout::from_size_align(bytes, 16).expect("original calloc layout"),
        )
    };
}
/// Namespace the minimal curve-name compatibility symbol so it cannot collide
/// with a different native C archive's generic strcmp implementation.
/// # Safety
/// Both pointers name complete readable NUL-terminated C strings for this call.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_mbedtls_strcmp(a: *const c_char, b: *const c_char) -> c_int {
    // SAFETY: exact live C strings are supplied by the documented ABI caller.
    let (a, b) = unsafe { (CStr::from_ptr(a), CStr::from_ptr(b)) };
    match a.to_bytes().cmp(b.to_bytes()) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}
#[cfg(test)]
pub(crate) mod observation {
    use core::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize};
    use std::sync::Mutex;
    pub(crate) static SERIAL: Mutex<()> = Mutex::new(());
    pub(crate) static OUTSTANDING: AtomicUsize = AtomicUsize::new(0);
    pub(crate) static FAIL_AT: AtomicIsize = AtomicIsize::new(-1);
    pub(crate) static CHECK_ZERO: AtomicUsize = AtomicUsize::new(0);
    pub(crate) static WAS_ZERO: AtomicBool = AtomicBool::new(false);
    pub(crate) static CHECK_ALL_FREES: AtomicBool = AtomicBool::new(false);
    pub(crate) static NONZERO_FREES: AtomicUsize = AtomicUsize::new(0);
}
