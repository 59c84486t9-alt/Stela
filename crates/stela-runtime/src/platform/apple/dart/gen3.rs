//! Original gen3 protocol components, independently of profile admission.
//!
//! These do not advertise a gen3 MMIO profile. The native identifier,
//! context/security/filter and device/CPU ordering contracts still require
//! qualification; see `docs/research/dart-iommu.md`. In particular an old
//! t8110 register bank cannot substitute for gen3's per-SID fault capture.
#[expect(dead_code, reason = "wired when a gen3 DART MMIO profile is admitted")]
pub mod context;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired when a gen3 DART MMIO profile is admitted")
)]
pub mod descriptor;
pub mod fault;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired when a gen3 DART MMIO profile is admitted")
)]
pub mod handoff;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired when a gen3 DART MMIO profile is admitted")
)]
pub mod region;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired when a gen3 DART MMIO profile is admitted")
)]
pub mod streams;
#[expect(dead_code, reason = "wired when a gen3 DART MMIO profile is admitted")]
pub mod tables;
#[expect(dead_code, reason = "wired when a gen3 DART MMIO profile is admitted")]
pub mod tlbi;
