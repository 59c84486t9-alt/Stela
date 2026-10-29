//! Apple core text-protection register generation declarations.
use crate::Chip;

/// The register set a chip implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generation {
    /// M1 to M3: the A group, at EL1 and per cluster at EL2.
    A,
    /// M4 and later: CTRR-C/D and CTXR-A..D per core and per cluster.
    Ctrr3,
}

pub const fn generation(chip: Chip) -> Option<Generation> {
    match chip {
        Chip::AppleM1 | Chip::AppleM2 | Chip::AppleM3 => Some(Generation::A),
        Chip::AppleM4 | Chip::AppleM5 | Chip::AppleM6 => Some(Generation::Ctrr3),
    }
}
