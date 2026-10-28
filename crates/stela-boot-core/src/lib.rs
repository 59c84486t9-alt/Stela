//! The UEFI mount's firmware-independent logic, built for the host (its
//! tests and `stela setup`) and for `x86_64-unknown-uefi` (`stela.efi`).
//! `stela-boot` keeps the firmware calls and the code that needs its
//! allocator, page tables or console.
#![cfg_attr(not(test), no_std)]
extern crate alloc;

pub mod aperture;
pub mod console_lines;
pub mod dmar;
pub mod firmware_state;
pub mod options;
pub mod paging_controls;
pub mod passthrough;
pub mod pe;
pub mod ram;
pub mod record;
pub mod remapping;
pub mod storage;
pub mod topology;
pub mod worker_bindings;
