//! The canonical heap for hosted test binaries: ordinary layouts go to the
//! system allocator and one 64 KiB span serves Linux's nonblocking requests.
//! A single span makes contention, exhaustion and same-backend free
//! observable. Each test binary installs [`TestHeap`] as its global allocator
//! and calls [`register`] before Linux runs.
extern crate std;

use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::alloc::System;

const SPAN: usize = 64 * 1024;

unsafe extern "C" {
    /// Counts an attempt on `route` and refuses it inside a refusing window
    /// (`compat/stela/test.c`): 0 ordinary, 1 nonblocking.
    fn stela_test_allocation_attempt(route: u32) -> bool;
}

/// Page-aligned backing, reached only through the raw storage pointer.
#[repr(align(4096))]
struct Span(
    #[expect(dead_code, reason = "reached only through the raw storage pointer")] [u8; SPAN],
);

struct Raw {
    storage: UnsafeCell<Span>,
    enabled: AtomicBool,
    occupied: AtomicBool,
    size: AtomicUsize,
    align: AtomicUsize,
}

// SAFETY: allocation wins one CAS; its unique live owner excludes concurrent
// read/free/reuse of the raw bytes. No libc allocation/growth/lock fallback.
unsafe impl Sync for Raw {}

static RAW: Raw = Raw {
    storage: UnsafeCell::new(Span([0; SPAN])),
    enabled: AtomicBool::new(false),
    occupied: AtomicBool::new(false),
    size: AtomicUsize::new(0),
    align: AtomicUsize::new(0),
};

impl Raw {
    fn base(&self) -> *mut u8 {
        self.storage.get().cast::<u8>()
    }

    unsafe fn allocate(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the C counter owns fixed atomics and a refusal flag, with
        // no allocator, lock, drop or spin.
        if !unsafe { stela_test_allocation_attempt(1) } {
            return ptr::null_mut();
        }
        if !self.enabled.load(Ordering::Acquire)
            || layout.size() == 0
            || layout.size() > SPAN
            || layout.align() > 4096
        {
            return ptr::null_mut();
        }
        if self
            .occupied
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return ptr::null_mut();
        }
        self.size.store(layout.size(), Ordering::Relaxed);
        self.align.store(layout.align(), Ordering::Relaxed);
        // SAFETY: the sole successful CAS owner holds the entire aligned span.
        unsafe { ptr::write_bytes(self.base(), 0, layout.size()) };
        self.base()
    }

    unsafe fn free(&self, pointer: *mut u8, layout: Layout) {
        if pointer != self.base()
            || !self.occupied.load(Ordering::Relaxed)
            || layout.size() != self.size.load(Ordering::Relaxed)
            || layout.align() != self.align.load(Ordering::Relaxed)
        {
            std::process::abort();
        }
        // SAFETY: the unique exact-layout owner frees once, before reuse.
        unsafe { ptr::write_bytes(pointer, 0xd3, layout.size()) };
        self.occupied.store(false, Ordering::Release);
    }

    fn address_in_storage(&self, pointer: *const u8) -> bool {
        (pointer as usize).wrapping_sub(self.base() as usize) < SPAN
    }
}

/// The global allocator every hosted test binary installs.
pub struct TestHeap;

// SAFETY: all ordinary layouts belong to System; the raw span has exact
// base/layout/live identity and this same allocator's free branch. Raw free
// does not allocate, drop or spin.
unsafe impl GlobalAlloc for TestHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: observe this ordinary attempt once; refusal returns NULL
        // before the System call.
        if !unsafe { stela_test_allocation_attempt(0) } {
            return ptr::null_mut();
        }
        // SAFETY: ordinary valid GlobalAlloc layout, delegated unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as `alloc`.
        if !unsafe { stela_test_allocation_attempt(0) } {
            return ptr::null_mut();
        }
        // SAFETY: same System owner and exact layout.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if RAW.address_in_storage(pointer) {
            // SAFETY: the raw branch checks exact identity and layout.
            unsafe { RAW.free(pointer, layout) };
        } else {
            // SAFETY: an ordinary allocation has this same System owner.
            unsafe { System.dealloc(pointer, layout) };
        }
    }
}

unsafe fn try_allocate(layout: Layout) -> *mut u8 {
    // SAFETY: the registry uses this allocator's raw branch; the matching
    // free goes through the production Rust heap bridge to `TestHeap`.
    unsafe { RAW.allocate(layout) }
}

/// Publish the span as Linux's nonblocking heap. The binary must have
/// installed [`TestHeap`] as its global allocator.
pub fn register() -> bool {
    // SAFETY: the span lives for the whole process, and its frees reach the
    // installed `TestHeap` through `alloc::alloc::dealloc`.
    unsafe { crate::heap::register(try_allocate) }.is_ok()
}

/// Whether a nonblocking allocation still holds the span.
pub fn span_occupied() -> bool {
    RAW.occupied.load(Ordering::Acquire)
}

/// Fixture policy only: false makes the span an ordinary exhausted heap; the
/// registered capability stays installed. Callers exclude concurrent users.
#[unsafe(no_mangle)]
extern "C" fn stela_test_heap_try_enable(enable: bool) {
    if span_occupied() {
        std::process::abort();
    }
    RAW.enabled.store(enable, Ordering::Release);
}

/// Whether `pointer` lies in the live nonblocking allocation. The caller owns
/// that allocation and excludes concurrent free and reuse.
#[unsafe(no_mangle)]
extern "C" fn stela_test_heap_try_contains(pointer: *const c_void) -> bool {
    span_occupied()
        && (pointer as usize).wrapping_sub(RAW.base() as usize) < RAW.size.load(Ordering::Relaxed)
}
