//! FEAT_CSSC ABS, CNT and CTZ.
use super::{Register, Width, register};

const OPCODE_MASK: u32 = 0xffff_fc00;
const WIDTH_BIT: u32 = 1 << 31;
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const ABSOLUTE: u32 = 0x5ac0_2000;
const POPULATION_COUNT: u32 = 0x5ac0_1c00;
const TRAILING_ZEROS: u32 = 0x5ac0_1800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Absolute,
    PopulationCount,
    TrailingZeros,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub width: Width,
    pub destination: Register,
    pub source: Register,
}

pub fn decode(word: u32) -> Option<Operand> {
    let kind = match word & OPCODE_MASK & !WIDTH_BIT {
        ABSOLUTE => Kind::Absolute,
        POPULATION_COUNT => Kind::PopulationCount,
        TRAILING_ZEROS => Kind::TrailingZeros,
        _ => return None,
    };
    Some(Operand {
        kind,
        width: if word & WIDTH_BIT == 0 {
            Width::W32
        } else {
            Width::X64
        },
        destination: register(word & REGISTER_MASK, false),
        source: register((word >> SOURCE_SHIFT) & REGISTER_MASK, false),
    })
}

#[cfg(test)]
mod tests;
