//! Disk controllers, each disk a [`BlockDevice`](crate::block::BlockDevice)
//! with polled completion: NVMe ([`nvme`]), AHCI SATA ([`ahci`]) and
//! virtio-blk ([`virtio`]), SDHCI ([`sdhci`]) and Realtek readers ([`rtsx`]).
//! USB disks are in [`usb::storage`](crate::usb::storage).
pub mod ahci;
mod mmc;
pub mod nvme;
mod pci;
pub mod rtsx;
pub mod sdhci;
pub mod virtio;
