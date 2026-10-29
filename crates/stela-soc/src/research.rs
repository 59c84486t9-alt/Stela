//! Unadmitted device protocols kept with their original executable models.
//!
//! This module is compiled only by this crate's unit tests. Board composition
//! has no model admission or dependency on these incomplete protocols.
pub mod agx_pio;
pub mod dart_gen3;
pub mod hpm_spmi;
pub mod inline_key;
pub mod mxwrap;
pub mod nhi;
pub mod pcie;
pub mod sio_dma;
