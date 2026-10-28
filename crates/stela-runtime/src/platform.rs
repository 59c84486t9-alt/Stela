//! Host services: memory, locks, unwinding and CPU detection. The freestanding
//! build runs in ring 0 with an aborting panic and a loader-provided heap.
#[allow(dead_code, reason = "the MMU-on system engine wires these models")]
pub(crate) mod apple;
pub(crate) mod cpu;
pub(crate) mod dma;
pub mod net;
#[cfg(target_arch = "x86_64")]
pub mod pc;
pub(crate) mod sync;
pub(crate) mod unwind;
pub(crate) mod usb;

#[cfg(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std")))]
pub(crate) mod boot;
