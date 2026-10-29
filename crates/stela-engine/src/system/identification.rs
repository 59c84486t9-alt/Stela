//! Identification-register (ID_*) selectors and their feature classes.

use stela_compiler::aarch64::system::registers::Encoding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    IdAa64Afr0El1,
    IdAa64Afr1El1,
    IdAa64Dfr0El1,
    IdAa64Dfr1El1,
    IdAa64Dfr2El1,
    IdAa64Fpfr0El1,
    IdAa64Isar0El1,
    IdAa64Isar1El1,
    IdAa64Isar2El1,
    IdAa64Isar3El1,
    IdAa64Mmfr0El1,
    IdAa64Mmfr1El1,
    IdAa64Mmfr2El1,
    IdAa64Mmfr3El1,
    IdAa64Mmfr4El1,
    IdAa64Pfr0El1,
    IdAa64Pfr1El1,
    IdAa64Pfr2El1,
    IdAa64Smfr0El1,
    IdAa64Zfr0El1,
    MidrEl1,
    MpidrEl1,
    RevidrEl1,
    AidrEl1,
    CtrEl0,
    DczidEl0,
    ClidrEl1,
    CcsidrEl1,
    Ccsidr2El1,
    CsselrEl1,
}

pub const ALL_REGISTERS: [Register; 30] = [
    Register::IdAa64Afr0El1,
    Register::IdAa64Afr1El1,
    Register::IdAa64Dfr0El1,
    Register::IdAa64Dfr1El1,
    Register::IdAa64Dfr2El1,
    Register::IdAa64Fpfr0El1,
    Register::IdAa64Isar0El1,
    Register::IdAa64Isar1El1,
    Register::IdAa64Isar2El1,
    Register::IdAa64Isar3El1,
    Register::IdAa64Mmfr0El1,
    Register::IdAa64Mmfr1El1,
    Register::IdAa64Mmfr2El1,
    Register::IdAa64Mmfr3El1,
    Register::IdAa64Mmfr4El1,
    Register::IdAa64Pfr0El1,
    Register::IdAa64Pfr1El1,
    Register::IdAa64Pfr2El1,
    Register::IdAa64Smfr0El1,
    Register::IdAa64Zfr0El1,
    Register::MidrEl1,
    Register::MpidrEl1,
    Register::RevidrEl1,
    Register::AidrEl1,
    Register::CtrEl0,
    Register::DczidEl0,
    Register::ClidrEl1,
    Register::CcsidrEl1,
    Register::Ccsidr2El1,
    Register::CsselrEl1,
];

impl Register {
    pub const fn encoding(self) -> Encoding {
        let (op1, crm, op2) = match self {
            Self::IdAa64Afr0El1 => (0, 5, 4),
            Self::IdAa64Afr1El1 => (0, 5, 5),
            Self::IdAa64Dfr0El1 => (0, 5, 0),
            Self::IdAa64Dfr1El1 => (0, 5, 1),
            Self::IdAa64Dfr2El1 => (0, 5, 2),
            Self::IdAa64Fpfr0El1 => (0, 4, 7),
            Self::IdAa64Isar0El1 => (0, 6, 0),
            Self::IdAa64Isar1El1 => (0, 6, 1),
            Self::IdAa64Isar2El1 => (0, 6, 2),
            Self::IdAa64Isar3El1 => (0, 6, 3),
            Self::IdAa64Mmfr0El1 => (0, 7, 0),
            Self::IdAa64Mmfr1El1 => (0, 7, 1),
            Self::IdAa64Mmfr2El1 => (0, 7, 2),
            Self::IdAa64Mmfr3El1 => (0, 7, 3),
            Self::IdAa64Mmfr4El1 => (0, 7, 4),
            Self::IdAa64Pfr0El1 => (0, 4, 0),
            Self::IdAa64Pfr1El1 => (0, 4, 1),
            Self::IdAa64Pfr2El1 => (0, 4, 2),
            Self::IdAa64Smfr0El1 => (0, 4, 5),
            Self::IdAa64Zfr0El1 => (0, 4, 4),
            Self::MidrEl1 => (0, 0, 0),
            Self::MpidrEl1 => (0, 0, 5),
            Self::RevidrEl1 => (0, 0, 6),
            Self::AidrEl1 => (1, 0, 7),
            Self::CtrEl0 => (3, 0, 1),
            Self::DczidEl0 => (3, 0, 7),
            Self::ClidrEl1 => (1, 0, 1),
            Self::CcsidrEl1 => (1, 0, 0),
            Self::Ccsidr2El1 => (1, 0, 2),
            Self::CsselrEl1 => (2, 0, 0),
        };
        Encoding::new(SYSTEM_REGISTER_OP0, op1, IDENTIFICATION_CRN, crm, op2)
    }

    pub fn decode(selector: Encoding) -> Option<Self> {
        ALL_REGISTERS
            .into_iter()
            .find(|register| register.encoding() == selector)
    }

    pub const fn is_aa64_feature(self) -> bool {
        !matches!(
            self,
            Self::MidrEl1
                | Self::MpidrEl1
                | Self::RevidrEl1
                | Self::AidrEl1
                | Self::CtrEl0
                | Self::DczidEl0
                | Self::ClidrEl1
                | Self::CcsidrEl1
                | Self::Ccsidr2El1
                | Self::CsselrEl1
        )
    }
}

pub const SYSTEM_REGISTER_OP0: u8 = 3;
pub const IDENTIFICATION_CRN: u8 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_are_unique_and_decode_back() {
        for (i, r) in ALL_REGISTERS.iter().enumerate() {
            assert_eq!(Register::decode(r.encoding()), Some(*r));
            for other in &ALL_REGISTERS[i + 1..] {
                assert_ne!(r.encoding(), other.encoding());
            }
        }
    }
}
