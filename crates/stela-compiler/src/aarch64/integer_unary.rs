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
mod tests {
    use super::*;

    #[test]
    fn all_register_roles_are_allocated_at_both_widths() {
        for (opcode, kind) in [
            (ABSOLUTE, Kind::Absolute),
            (POPULATION_COUNT, Kind::PopulationCount),
            (TRAILING_ZEROS, Kind::TrailingZeros),
        ] {
            for (width_bit, width) in [(0, Width::W32), (WIDTH_BIT, Width::X64)] {
                for destination in 0..=REGISTER_MASK {
                    for source in 0..=REGISTER_MASK {
                        let word = opcode | width_bit | (source << SOURCE_SHIFT) | destination;
                        assert_eq!(
                            decode(word),
                            Some(Operand {
                                kind,
                                width,
                                destination: register(destination, false),
                                source: register(source, false),
                            })
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn adjacent_historical_and_reserved_opcodes_are_not_claimed() {
        // CLZ, CLS, RBIT, REV, and the unallocated opcode above ABS.
        for word in [
            0x5ac0_1000,
            0x5ac0_1400,
            0x5ac0_0000,
            0x5ac0_0800,
            0x5ac0_2400,
        ] {
            assert!(decode(word).is_none());
            assert!(decode(word | WIDTH_BIT).is_none());
        }
        for fixed_bit in [10, 21, 29, 30] {
            assert!(decode(ABSOLUTE ^ (1 << fixed_bit)).is_none());
        }
    }
}
