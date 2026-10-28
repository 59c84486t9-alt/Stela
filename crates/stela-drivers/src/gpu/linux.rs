//! The platform heap under the native ports' kernel-API
//! (`compat/linux/kernel`), which keeps each object's size and alignment
//! and returns them on free.
use alloc::alloc::{alloc_zeroed, dealloc};
use core::{alloc::Layout, ffi::c_void, ptr};

pub mod heap;
pub mod image;
pub mod pages;
pub mod random;
#[cfg(target_arch = "x86_64")]
pub mod task;

#[unsafe(no_mangle)]
extern "C" fn stela_linux_heap_alloc(size: usize, align: usize) -> *mut c_void {
    match Layout::from_size_align(size, align) {
        // SAFETY: a nonzero layout.
        Ok(layout) if size != 0 => unsafe { alloc_zeroed(layout).cast() },
        _ => ptr::null_mut(),
    }
}

/// # Safety
/// `object` is a live ordinary or registered nonblocking canonical-global
/// heap allocation of `size` and `align`, freed once through that same heap.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_heap_free(object: *mut c_void, size: usize, align: usize) {
    // SAFETY: the caller's contract; the allocation was made with this layout.
    unsafe {
        dealloc(
            object.cast(),
            Layout::from_size_align_unchecked(size, align),
        )
    }
}
