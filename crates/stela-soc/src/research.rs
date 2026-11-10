//! Unadmitted device protocols kept with their original executable models.
//!
//! This module is compiled only by this crate's unit tests. Board composition
//! has no model admission or dependency on these incomplete protocols. Each
//! is planned work for a board interface `docs/target.md` requires (PCIe,
//! DART, AGX, Type-C, Thunderbolt and audio DMA); its evidence and open
//! requirements are in the matching `docs/research/` record.
pub mod agx_pio;
pub mod dart_gen3;
pub mod hpm_spmi;
pub mod mxwrap;
pub mod nhi;
pub mod pcie;
pub mod sio_dma;
