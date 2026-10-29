//! Self-hosted and halting debug state that process entries check.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Default))]
pub struct DebugControls {
    pub halted: bool,
    /// The selected permitted CONSTRAINED UNPREDICTABLE ignore-trap outcome.
    pub ignore_traps_in_debug: bool,
    pub halting_allowed: bool,
    pub edscr_tda: bool,
    pub os_locked: bool,
    pub breakpoint_count: u8,
    pub watchpoint_count: u8,
    /// Raw MDSELR_EL1.BANK; distinct from the effective bank by architecture.
    pub raw_bank: u8,
    /// EffectiveMDSELR_EL1_BANK(), including enable and reserved-value rules.
    pub effective_bank: u8,
}
