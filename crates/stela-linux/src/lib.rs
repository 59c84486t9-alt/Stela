//! Shared native Linux kernel services and retained resource ownership.
//! One canonical kernel execution environment serves its explicit device
//! bindings; enabling this crate admits no native device. Its platform heap
//! returns each allocation through the original size and alignment contract.
#![no_std]
extern crate alloc;

#[cfg(feature = "kernel")]
use alloc::alloc::{alloc_zeroed, dealloc};
#[cfg(feature = "kernel")]
use core::{alloc::Layout, ffi::c_void, ptr};

#[cfg(all(feature = "kernel", target_arch = "x86_64"))]
pub mod catalogue;
#[cfg(feature = "kernel")]
pub mod client;
#[cfg(all(feature = "kernel", target_arch = "x86_64"))]
pub mod firmware;
#[cfg(all(feature = "kernel", target_arch = "x86_64"))]
pub mod function;
#[cfg(feature = "kernel")]
pub mod heap;
#[cfg(feature = "kernel")]
pub mod image;
#[cfg(all(feature = "kernel", target_arch = "x86_64"))]
pub mod kernel;
#[cfg(feature = "kernel")]
pub mod owner;
#[cfg(feature = "kernel")]
pub mod pages;
#[cfg(feature = "kernel")]
pub mod random;
#[cfg(all(feature = "kernel", target_arch = "x86_64"))]
pub mod resources;
#[cfg(all(feature = "kernel", target_arch = "x86_64"))]
pub mod service;
#[cfg(all(feature = "kernel", target_arch = "x86_64"))]
pub mod srcu;
#[cfg(all(feature = "kernel", target_arch = "x86_64"))]
pub mod task;
#[cfg(all(feature = "kernel", target_arch = "x86_64"))]
pub mod threads;

#[cfg(feature = "kernel")]
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
#[cfg(feature = "kernel")]
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

/// The native ports' hosted C test programs, which `build.rs` compiles.
#[cfg(all(test, feature = "hosted-test-support"))]
mod c_tests {
    extern crate std;

    // Clippy's build compiles no C, so it lists no programs.
    #[cfg_attr(
        clippy,
        allow(dead_code, reason = "Clippy does not compile C fixtures")
    )]
    fn run(program: &str) {
        let output = std::process::Command::new(program)
            .output()
            .unwrap_or_else(|error| panic!("cannot run {program}: {error}"));
        assert!(
            output.status.success(),
            "{program} failed ({}):\n{}{}",
            output.status,
            std::string::String::from_utf8_lossy(&output.stdout),
            std::string::String::from_utf8_lossy(&output.stderr)
        );
    }

    include!(concat!(env!("OUT_DIR"), "/c_tests.rs"));
}
