//! Disk controllers, each disk a [`BlockDevice`](crate::block::BlockDevice)
//! with polled completion: NVMe ([`nvme`]), AHCI SATA ([`ahci`]) and
//! virtio-blk ([`virtio`]). USB disks are in [`usb::storage`](crate::usb::storage).
pub mod ahci;
pub mod nvme;
pub mod sdhci;
pub mod virtio;
