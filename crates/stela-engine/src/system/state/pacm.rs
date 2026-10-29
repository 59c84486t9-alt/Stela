//! PSTATE.PACM.
pub const PSTATE_PACM_SHIFT: u32 = 35;
pub const PSTATE_PACM_MASK: u64 = 1 << PSTATE_PACM_SHIFT;

/// Explicit storage subset. Full is not proof of a PE feature or effective enable.
/// Trivial/reserved layouts are not implemented by this initial storage subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacmStateFeature {
    Absent,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pacm {
    Zero,
    One,
}

impl Pacm {
    pub const fn bit(self) -> bool {
        matches!(self, Self::One)
    }
    pub(super) const fn pstate_bits(self) -> u64 {
        if self.bit() { PSTATE_PACM_MASK } else { 0 }
    }
}

pub(super) const fn read(pstate: u64) -> Pacm {
    if pstate & PSTATE_PACM_MASK == 0 {
        Pacm::Zero
    } else {
        Pacm::One
    }
}
