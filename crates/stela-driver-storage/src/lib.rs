//! Disk controllers, each disk a [`BlockDevice`](crate::block::BlockDevice)
//! with polled completion: NVMe ([`nvme`]), AHCI SATA ([`ahci`]) and
//! virtio-blk ([`virtio`]), SDHCI ([`sdhci`]) and Realtek readers ([`rtsx`]).
//! USB disks are in the `stela-drivers` USB stack (`usb::storage`).
#![no_std]
#[cfg_attr(test, macro_use)]
extern crate alloc;

#[cfg(test)]
use stela_driver_base::test_clock;
use stela_driver_base::{Clock, Deadline, Handoff, block, bus, registers, waiting};
use stela_driver_core::bytes;

pub mod ahci;
mod mmc;
pub mod nvme;
mod pci;
mod retention;
pub use retention::Retained;
pub mod rtsx;
pub mod sdhci;
pub mod virtio;
