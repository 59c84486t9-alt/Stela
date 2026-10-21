//! Source instruction features, separate from host capabilities and access flags.

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstructionRequirements {
    bits: u8,
}

impl InstructionRequirements {
    pub const NONE: Self = Self { bits: 0 };
    pub const LSE: Self = Self { bits: 1 };
    pub const RCPC: Self = Self { bits: 2 };
    pub const RCPC2: Self = Self { bits: 4 };
    pub const LOR: Self = Self { bits: 8 };
    const KNOWN: u8 = 15;

    pub const fn valid(self) -> bool {
        self.bits & !Self::KNOWN == 0
    }
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }
    pub const fn contains(self, required: Self) -> bool {
        self.bits & required.bits == required.bits
    }
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }
}
