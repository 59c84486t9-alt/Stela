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
