//! Arm A64 2026-06 predicated integer bit operations, merging forms.
//! SVE/SME feature availability, streaming mode and enable traps belong to the
//! shared execution boundary. Z31 is an ordinary vector register.
use crate::aarch64::scalable::{ElementSize, Predication};

const OPCODE_MASK: u32 = 0xff3f_e000;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 0b11;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 0b111;
const SOURCE_SHIFT: u32 = 5;
const REGISTER_MASK: u32 = 0b1_1111;
const CLS: u32 = 0x0418_a000;
const CLZ: u32 = 0x0419_a000;
const CNT: u32 = 0x041a_a000;
const RBIT: u32 = 0x0527_8000;
const REVB: u32 = 0x0524_8000;
const REVH: u32 = 0x0525_8000;
const REVW: u32 = 0x0526_8000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    LeadingSignBits,
    LeadingZeros,
    PopulationCount,
    ReverseBits,
    ReverseGroups { group_size: ElementSize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub source: u8,
    pub element_size: ElementSize,
    pub predication: Predication,
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    use ElementSize::{Byte, Halfword, Word};
    use Kind::{LeadingSignBits, LeadingZeros, PopulationCount, ReverseBits, ReverseGroups};
    let kind = match word & OPCODE_MASK {
        CLS => LeadingSignBits,
        CLZ => LeadingZeros,
        CNT => PopulationCount,
        RBIT => ReverseBits,
        REVB => ReverseGroups { group_size: Byte },
        REVH => ReverseGroups {
            group_size: Halfword,
        },
        REVW => ReverseGroups { group_size: Word },
        _ => return None,
    };
    let bytes = 1usize << ((word >> SIZE_SHIFT) & SIZE_MASK);
    let Some(element_size) = ElementSize::from_bytes(bytes) else {
        return Some(Err(()));
    };
    if let ReverseGroups { group_size } = kind
        && element_size <= group_size
    {
        return Some(Err(()));
    }
    Some(Ok(Operand {
        kind,
        destination: (word & REGISTER_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
        element_size,
        predication: Predication::Merging(((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ElementSize::{Byte, Doubleword, Halfword, Word};
    use Kind::{LeadingSignBits, LeadingZeros, PopulationCount, ReverseBits, ReverseGroups};

    const FORMS: [(u32, Kind); 7] = [
        (CLS, LeadingSignBits),
        (CLZ, LeadingZeros),
        (CNT, PopulationCount),
        (RBIT, ReverseBits),
        (REVB, ReverseGroups { group_size: Byte }),
        (
            REVH,
            ReverseGroups {
                group_size: Halfword,
            },
        ),
        (REVW, ReverseGroups { group_size: Word }),
    ];
    const ELEMENTS: [ElementSize; 4] = [Byte, Halfword, Word, Doubleword];

    #[test]
    fn operand_fields_and_reserved_reverse_widths() {
        for (opcode, kind) in FORMS {
            for (size, element_size) in ELEMENTS.into_iter().enumerate() {
                for predicate in 0..=PREDICATE_MASK {
                    for source in 0..=REGISTER_MASK {
                        for destination in 0..=REGISTER_MASK {
                            let word = opcode
                                | (size as u32) << SIZE_SHIFT
                                | predicate << PREDICATE_SHIFT
                                | source << SOURCE_SHIFT
                                | destination;
                            let allocated = !matches!(kind, ReverseGroups { group_size } if element_size <= group_size);
                            if allocated {
                                assert_eq!(
                                    decode(word),
                                    Some(Ok(Operand {
                                        kind,
                                        destination: destination as u8,
                                        source: source as u8,
                                        element_size,
                                        predication: Predication::Merging(predicate as u8),
                                    }))
                                );
                            } else {
                                assert_eq!(decode(word), Some(Err(())));
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn other_families_and_unowned_zeroing_forms_do_not_match() {
        const ZEROING_FORMS: [u32; 7] = [
            0x0408_a000,
            0x0409_a000,
            0x040a_a000,
            0x0527_a000,
            0x0524_a000,
            0x0525_a000,
            0x0526_a000,
        ];
        for word in ZEROING_FORMS {
            for size in 0..=SIZE_MASK {
                assert_eq!(decode(word | size << SIZE_SHIFT), None);
            }
        }
        assert_eq!(decode(0), None);
        assert_eq!(decode(u32::MAX), None);
        for (opcode, _) in FORMS {
            for bit in 0..u32::BITS {
                if OPCODE_MASK & (1 << bit) != 0 {
                    let changed = opcode ^ (1 << bit);
                    if !FORMS.iter().any(|(other, _)| changed == *other) {
                        assert_eq!(decode(changed), None);
                    }
                }
            }
        }
    }
}
