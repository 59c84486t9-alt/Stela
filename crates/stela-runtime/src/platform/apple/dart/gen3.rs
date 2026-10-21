//! Original gen3 protocol components, independently of profile admission.
//!
//! These do not advertise a gen3 MMIO profile. The native identifier,
//! context/security/filter and device/CPU ordering contracts still require
//! qualification; see `docs/research/dart-iommu.md`. In particular an old
//! t8110 register bank cannot substitute for gen3's per-SID fault capture.
pub mod tlbi;
pub mod fault;
pub mod tables;
