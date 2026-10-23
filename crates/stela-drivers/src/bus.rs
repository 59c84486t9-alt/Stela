//! How the drivers reach their devices: PCI configuration space through
//! ECAM ([`pci`]), uncached register windows (`mmio`), DMA memory
//! ([`dma`]), owned IRQ registrations ([`irq`]), I²C ([`i2c`]), SMBus ([`smbus`]) and the virtio PCI transport
//! ([`virtio`]).
pub mod dma;
pub mod i2c;
pub mod irq;
pub mod lpss;
pub mod mmio;
pub mod pci;
pub mod smbus;
pub mod thunderbolt;
pub mod virtio;
