//! CPU fixture only: the common heap and metadata adapter, with a
//! process-owned host buffer. This is never linked into the production driver.
#![no_std]
#![expect(
    dead_code,
    reason = "the fixture uses part of the shared heap and the metadata adapter"
)]
extern crate alloc;

// `cargo xtask gpu` builds this file alone with rustc
// (`xtask/src/gpu/nvidia/lut.rs`), which records the heap source it includes.
// No Cargo edge links the driver to the boot heap.
#[path = "../../../../stela-boot-core/src/heap.rs"]
mod common_heap;
#[path = "../memory.rs"]
mod nvidia_memory;

#[global_allocator]
static HEAP: common_heap::Heap = common_heap::Heap::new();

#[repr(align(4096))]
struct Buffer([u8; 128 * 1024]);
static mut BUFFER: Buffer = Buffer([0; 128 * 1024]);

/// # Safety
/// The separate single-thread CPU fixture calls once before any allocation;
/// no aliases, interrupts, migration or concurrent users reach its buffer.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvkms_test_heap_initialize() {
    // SAFETY: the fixture owns the full aligned static buffer for its lifetime.
    unsafe { HEAP.initialize(core::ptr::addr_of_mut!(BUFFER).cast(), size_of::<Buffer>()) };
}

#[unsafe(no_mangle)]
extern "C" fn stela_nvkms_test_heap_live() -> usize {
    HEAP.usage().live
}

#[panic_handler]
fn fixture_panic(_: &core::panic::PanicInfo) -> ! {
    unsafe extern "C" {
        fn abort() -> !;
    }
    // SAFETY: host C runtime termination for this separate CPU fixture.
    // No NVIDIA fatal, purecall, thunk or production runtime hook is supplied.
    unsafe { abort() }
}
