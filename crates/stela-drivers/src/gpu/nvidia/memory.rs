//! Unsized RM metadata allocation over Stela's existing global allocator.
//!
//! The native owner must establish the global heap and obey its execution
//! context rules before calling RM: no interrupt handler, interrupt reentry or
//! allocator reentry. All users must finish before the heap is torn down.
//! These are ordinary CPU pointers, never DMA addresses, physical page pins,
//! MMIO mappings or a promise of physical contiguity/cache policy.
use alloc::alloc::{alloc, dealloc};
use core::{alloc::Layout, ffi::c_void, ptr, ptr::NonNull};

// The official API frees without a byte count. Retain the exact shared-heap
// layout immediately before the payload; no allocation registry or pool.
// Sixteen bytes also covers the native C/C++ fundamental type alignment.
#[repr(align(16))]
struct Header {
    layout: Layout,
}

// Internal result tags mirror stela/memory.h, not NVIDIA's status namespace.
#[repr(u32)]
#[derive(Debug, Eq, PartialEq)]
enum AllocationStatus {
    Success = 0,
    InvalidSize = 1,
    OutOfMemory = 2,
}

fn allocate_with(
    bytes: u64,
    allocate: impl FnOnce(Layout) -> *mut u8,
) -> Result<NonNull<c_void>, AllocationStatus> {
    let size = usize::try_from(bytes)
        .ok()
        .and_then(|size| size.checked_add(size_of::<Header>()))
        .ok_or(AllocationStatus::InvalidSize)?;
    let layout = Layout::from_size_align(size, align_of::<Header>())
        .map_err(|_| AllocationStatus::InvalidSize)?;
    let base = NonNull::new(allocate(layout)).ok_or(AllocationStatus::OutOfMemory)?;
    // SAFETY: the allocator supplied this exclusively owned aligned layout;
    // it contains one header followed by the entire requested payload.
    unsafe {
        base.cast::<Header>().as_ptr().write(Header { layout });
        Ok(base.add(size_of::<Header>()).cast())
    }
}

/// Called only through the native C shim, after the owner's heap/context setup.
///
/// # Safety
/// `out` must be a writable native pointer slot, owned by the C shim.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvidia_alloc(bytes: u64, out: *mut *mut c_void) -> AllocationStatus {
    let result = allocate_with(bytes, |layout| {
        // SAFETY: a nonzero checked layout, forwarded to the common allocator.
        unsafe { alloc(layout) }
    });
    let (pointer, status) = match result {
        Ok(pointer) => (pointer.as_ptr(), AllocationStatus::Success),
        Err(status) => (ptr::null_mut(), status),
    };
    // SAFETY: the C shim checked its caller's native output slot.
    unsafe { out.write(pointer) };
    status
}

unsafe fn free_with(pointer: *mut c_void, release: impl FnOnce(*mut u8, Layout)) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: the C/RM caller returns this allocator's live payload exactly
    // once, without modifying its prefix; all payload users have stopped.
    let base = unsafe { pointer.cast::<u8>().sub(size_of::<Header>()) };
    let header = unsafe { base.cast::<Header>().read() };
    release(base, header.layout);
}

/// # Safety
/// Return only a live `stela_nvidia_alloc` pointer, once, after all uses stop.
/// The same heap and supported owner-established execution context must remain.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvidia_free(pointer: *mut c_void) {
    // SAFETY: the native C/RM caller satisfies the contract above; `free_with`
    // recovers the same pointer/layout originally obtained from this heap.
    unsafe { free_with(pointer, |base, layout| dealloc(base, layout)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn os_alloc_mem(out: *mut *mut c_void, bytes: u64) -> u32;
        fn os_free_mem(pointer: *mut c_void);
    }

    #[test]
    fn vendor_c_allocation_owns_aligned_disjoint_writable_payloads() {
        let sizes = [0, 1, 15, 16, 17, 4095, 4096, 4097, 65537];
        let mut pointers = [ptr::null_mut::<c_void>(); 9];
        for (index, (&size, pointer)) in sizes.iter().zip(&mut pointers).enumerate() {
            // SAFETY: writable output; the native hosted global heap is ready.
            assert_eq!(unsafe { os_alloc_mem(pointer, size) }, 0);
            assert!(!pointer.is_null());
            assert_eq!(*pointer as usize % 16, 0);
            // SAFETY: successful allocation owns exactly `size` writable bytes.
            unsafe { pointer.cast::<u8>().write_bytes(index as u8, size as usize) };
        }
        for (index, (&size, &pointer)) in sizes.iter().zip(&pointers).enumerate().rev() {
            // SAFETY: every payload is still live and held by this test alone.
            let bytes = unsafe { core::slice::from_raw_parts(pointer.cast::<u8>(), size as usize) };
            assert!(bytes.iter().all(|byte| *byte == index as u8));
            // SAFETY: every vendor allocation is returned once, after all use.
            unsafe { os_free_mem(pointer) };
        }
    }

    #[test]
    fn vendor_errors_clear_output_and_null_free_is_valid() {
        // Stable vendor ABI values from the pinned nvstatuscodes.h. These calls
        // execute the C adapter compiled against those actual declarations.
        const NV_ERR_INVALID_ARGUMENT: u32 = 0x1f;
        for bytes in [u64::MAX, isize::MAX as u64] {
            let mut out = ptr::dangling_mut::<c_void>();
            // SAFETY: writable output; invalid sizes fail before allocation.
            assert_eq!(
                unsafe { os_alloc_mem(&mut out, bytes) },
                NV_ERR_INVALID_ARGUMENT
            );
            assert!(out.is_null());
        }
        // SAFETY: null outputs are rejected and null free is explicitly valid.
        unsafe {
            assert_eq!(os_alloc_mem(ptr::null_mut(), 1), NV_ERR_INVALID_ARGUMENT);
            os_free_mem(ptr::null_mut());
        }
    }

    #[test]
    fn allocation_failure_and_exact_shared_heap_release() {
        let mut called = false;
        let failed = allocate_with(37, |_| {
            called = true;
            ptr::null_mut()
        });
        assert!(called);
        assert_eq!(failed, Err(AllocationStatus::OutOfMemory));

        let (mut original_base, mut original_layout) = (ptr::null_mut(), None);
        let pointer = allocate_with(37, |layout| {
            original_layout = Some(layout);
            // SAFETY: the checked nonzero layout is forwarded to the heap.
            original_base = unsafe { alloc(layout) };
            original_base
        })
        .unwrap();
        // SAFETY: this uniquely owned payload was returned by allocate_with.
        unsafe {
            free_with(pointer.as_ptr(), |base, layout| {
                assert_eq!(base, original_base);
                assert_eq!(Some(layout), original_layout);
                dealloc(base, layout);
            });
        }
    }

    #[test]
    fn invalid_sizes_never_call_the_heap() {
        for bytes in [u64::MAX, isize::MAX as u64, isize::MAX as u64 - 16] {
            assert_eq!(
                allocate_with(bytes, |_| panic!("invalid native layout reached the heap")),
                Err(AllocationStatus::InvalidSize)
            );
        }
    }
}
