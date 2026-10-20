//! How the drivers reach their devices: PCI configuration space through
//! ECAM ([`pci`]), uncached register windows (`mmio`), DMA memory
//! ([`dma`]) and the virtio PCI transport ([`virtio`]).
pub mod dma;
pub(crate) mod mmio;
pub mod pci;
pub mod virtio;
