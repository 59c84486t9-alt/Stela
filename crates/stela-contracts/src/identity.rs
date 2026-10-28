//! Identification data for a processor in a declared topology.
/// The identification values one PE does not share with the others; they
/// replace `fixed` entries of the same registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub midr: u64,
    pub mpidr: u64,
    /// The core clock in Hz, where the SoC row has evidence of it; it paces
    /// the cycle counter of Apple's performance monitor (`machine::pmu`).
    pub clock: Option<u64>,
    /// The PE's caches, where the SoC row and DeviceTree describe them;
    /// without them CLIDR_EL1 and CCSIDR_EL1 take the profile's values.
    pub caches: Option<crate::caches::Caches>,
}
