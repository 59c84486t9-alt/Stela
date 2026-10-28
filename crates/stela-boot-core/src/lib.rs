//! The UEFI mount's firmware-independent logic, built for the host (its
//! tests and `stela setup`) and for `x86_64-unknown-uefi` (`stela.efi`).
//! `stela-boot` keeps the firmware calls and the code that needs its
//! allocator, page tables or console.
#![cfg_attr(not(test), no_std)]
extern crate alloc;

pub mod aperture;
pub mod console_lines;
pub mod dmar;
pub mod early_fault;
pub mod entropy;
pub mod firmware_state;
pub mod guarded_stacks;
pub mod madt;
pub mod memory_budget;
pub mod memory_types;
pub mod options;
pub mod paging_controls;
pub mod passthrough;
pub mod pe;
pub mod pm_timer;
pub mod ram;
pub mod random;
pub mod record;
pub mod remapping;
#[cfg(target_arch = "x86_64")]
pub mod requester;
pub mod storage;
pub mod topology;
#[cfg(target_arch = "x86_64")]
pub mod vtd;
pub mod worker_bindings;
pub mod xstate;
