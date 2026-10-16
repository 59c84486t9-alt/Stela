//! Predicate Boolean operations, permutes and predicate-as-counter extraction.

use crate::aarch64::scalable::ElementSize;

const PREDICATE_MASK: u32 = 15;
const VECTOR_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const GOVERNOR_SHIFT: u32 = 10;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const BOOLEAN_MASK: u32 = 0xfff0_c210;
const FLAGS_BIT: u32 = 1 << 22;
const AND: u32 = 0x2500_4000;
const BIC: u32 = 0x2500_4010;
const EOR: u32 = 0x2500_4200;
const NAND: u32 = 0x2580_4210;
const NOR: u32 = 0x2580_4200;
const ORN: u32 = 0x2580_4010;
const ORR: u32 = 0x2580_4000;
const SEL: u32 = 0x2500_4210;
const PERMUTATION_MASK: u32 = 0xff30_fe10;
const ZIP1: u32 = 0x0520_4000;
const ZIP2: u32 = 0x0520_4400;
const TRN1: u32 = 0x0520_5000;
const TRN2: u32 = 0x0520_5400;
const UZP1: u32 = 0x0520_4800;
const UZP2: u32 = 0x0520_4c00;
const REVERSE_MASK: u32 = 0xff3f_fe10;
const REV: u32 = 0x0534_4000;
const UNPACK_MASK: u32 = 0xffff_fe10;
const PUNPKLO: u32 = 0x0530_4000;
const PUNPKHI: u32 = 0x0531_4000;
const PMOV_BYTE_MASK: u32 = 0xffff_fc10;
const PMOV_BYTE: u32 = 0x052a_3800;
const PMOV_HALF_MASK: u32 = 0xfffd_fc10;
const PMOV_HALF: u32 = 0x052c_3800;
const PMOV_SINGLE_MASK: u32 = 0xfff9_fc10;
const PMOV_SINGLE: u32 = 0x0568_3800;
const PMOV_DOUBLE_MASK: u32 = 0xffb9_fc10;
const PMOV_DOUBLE: u32 = 0x05a8_3800;
const PMOV_IMMEDIATE_SHIFT: u32 = 17;
const PMOV_DOUBLE_HIGH_SHIFT: u32 = 22;
const PSEL_MASK: u32 = 0xff20_c210;
const PSEL: u32 = 0x2520_4000;
const PSEL_SIZE_HIGH_SHIFT: u32 = 22;
const PSEL_SIZE_LOW_SHIFT: u32 = 18;
const PSEL_IMMEDIATE_HIGH_SHIFT: u32 = 23;
const PSEL_INDEX_BASE: u8 = 12;
const PEXT_SINGLE_MASK: u32 = 0xff3f_fc10;
const PEXT_SINGLE: u32 = 0x2520_7010;
const PEXT_PAIR_MASK: u32 = 0xff3f_fe10;
const PEXT_PAIR: u32 = 0x2520_7410;
const PEXT_PART_SHIFT: u32 = 8;
const COUNTER_REGISTER_BASE: u8 = 8;
const COUNTER_REGISTER_MASK: u32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boolean {
    And,
    BitClear,
    ExclusiveOr,
    Nand,
    Nor,
    OrNot,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permutation {
    Zip { high: bool },
    Transpose { odd: bool },
    Unzip { odd: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Boolean {
        operation: Boolean,
        flags: bool,
        governor: u8,
        left: u8,
        right: u8,
    },
    Select {
        governor: u8,
        left: u8,
        right: u8,
    },
    Permute {
        operation: Permutation,
        element: ElementSize,
        left: u8,
        right: u8,
    },
    Reverse {
        element: ElementSize,
        source: u8,
    },
    Unpack {
        high: bool,
        source: u8,
    },
    MoveVector {
        element: ElementSize,
        source: u8,
        part: u8,
    },
    SelectIndexed {
        element: ElementSize,
        source: u8,
        selector: u8,
        index_register: u8,
        immediate: u8,
    },
    ExtractCounter {
        element: ElementSize,
        source: u8,
        part: u8,
        pair: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: u8,
    pub kind: Kind,
}

/// Feature and streaming-mode checks belong to the shared SVE decode boundary.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let destination = (word & PREDICATE_MASK) as u8;
    let left = ((word >> SOURCE_SHIFT) & PREDICATE_MASK) as u8;
    let right = ((word >> RIGHT_SHIFT) & PREDICATE_MASK) as u8;
    let governor = ((word >> GOVERNOR_SHIFT) & PREDICATE_MASK) as u8;
    let element = ElementSize::from_bytes(1 << ((word >> SIZE_SHIFT) & SIZE_MASK)).unwrap();
    let boolean = match word & BOOLEAN_MASK & !FLAGS_BIT {
        AND => Some(Boolean::And),
        BIC => Some(Boolean::BitClear),
        EOR => Some(Boolean::ExclusiveOr),
        NAND => Some(Boolean::Nand),
        NOR => Some(Boolean::Nor),
        ORN => Some(Boolean::OrNot),
        ORR => Some(Boolean::Or),
        _ => None,
    };
    let kind = if let Some(operation) = boolean {
        Kind::Boolean {
            operation,
            flags: word & FLAGS_BIT != 0,
            governor,
            left,
            right,
        }
    } else if word & BOOLEAN_MASK == SEL {
        Kind::Select {
            governor,
            left,
            right,
        }
    } else if let Some(operation) = match word & PERMUTATION_MASK {
        ZIP1 => Some(Permutation::Zip { high: false }),
        ZIP2 => Some(Permutation::Zip { high: true }),
        TRN1 => Some(Permutation::Transpose { odd: false }),
        TRN2 => Some(Permutation::Transpose { odd: true }),
        UZP1 => Some(Permutation::Unzip { odd: false }),
        UZP2 => Some(Permutation::Unzip { odd: true }),
        _ => None,
    } {
        Kind::Permute {
            operation,
            element,
            left,
            right,
        }
    } else if word & REVERSE_MASK == REV {
        Kind::Reverse {
            element,
            source: left,
        }
    } else if matches!(word & UNPACK_MASK, PUNPKLO | PUNPKHI) {
        Kind::Unpack {
            high: word & UNPACK_MASK == PUNPKHI,
            source: left,
        }
    } else if let Some((element, part)) = decode_vector_move(word) {
        Kind::MoveVector {
            element,
            source: ((word >> SOURCE_SHIFT) & VECTOR_MASK) as u8,
            part,
        }
    } else if word & PSEL_MASK == PSEL {
        let size_encoding =
            (((word >> PSEL_SIZE_HIGH_SHIFT) & 1) << 3) | ((word >> PSEL_SIZE_LOW_SHIFT) & 7);
        if size_encoding == 0 {
            return Some(Err(()));
        }
        let size = size_encoding.trailing_zeros();
        let immediate =
            ((((word >> PSEL_IMMEDIATE_HIGH_SHIFT) & 1) << 4) | size_encoding) >> (size + 1);
        Kind::SelectIndexed {
            element: ElementSize::from_bytes(1 << size).unwrap(),
            source: governor,
            selector: left,
            index_register: PSEL_INDEX_BASE + ((word >> RIGHT_SHIFT) & SIZE_MASK) as u8,
            immediate: immediate as u8,
        }
    } else if word & PEXT_SINGLE_MASK == PEXT_SINGLE || word & PEXT_PAIR_MASK == PEXT_PAIR {
        let pair = word & PEXT_PAIR_MASK == PEXT_PAIR;
        Kind::ExtractCounter {
            element,
            source: COUNTER_REGISTER_BASE + ((word >> SOURCE_SHIFT) & COUNTER_REGISTER_MASK) as u8,
            part: ((word >> PEXT_PART_SHIFT) & if pair { 1 } else { SIZE_MASK }) as u8,
            pair,
        }
    } else {
        return None;
    };
    Some(Ok(Operand { destination, kind }))
}

fn decode_vector_move(word: u32) -> Option<(ElementSize, u8)> {
    if word & PMOV_BYTE_MASK == PMOV_BYTE {
        Some((ElementSize::Byte, 0))
    } else if word & PMOV_HALF_MASK == PMOV_HALF {
        Some((
            ElementSize::Halfword,
            ((word >> PMOV_IMMEDIATE_SHIFT) & 1) as u8,
        ))
    } else if word & PMOV_SINGLE_MASK == PMOV_SINGLE {
        Some((
            ElementSize::Word,
            ((word >> PMOV_IMMEDIATE_SHIFT) & 3) as u8,
        ))
    } else if word & PMOV_DOUBLE_MASK == PMOV_DOUBLE {
        Some((
            ElementSize::Doubleword,
            (((word >> PMOV_IMMEDIATE_SHIFT) & 3) | (((word >> PMOV_DOUBLE_HIGH_SHIFT) & 1) << 2))
                as u8,
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod field {
        use super::*;

        #[test]
        fn all_move_slices_and_vector_registers_decode() {
            for (opcode, element, slices) in [
                (PMOV_BYTE, ElementSize::Byte, 1),
                (PMOV_HALF, ElementSize::Halfword, 2),
                (PMOV_SINGLE, ElementSize::Word, 4),
                (PMOV_DOUBLE, ElementSize::Doubleword, 8),
            ] {
                for part in 0..slices {
                    for source in 0..=VECTOR_MASK {
                        let slice_bits = if element == ElementSize::Doubleword {
                            ((part & 3) << PMOV_IMMEDIATE_SHIFT)
                                | ((part >> 2) << PMOV_DOUBLE_HIGH_SHIFT)
                        } else {
                            part << PMOV_IMMEDIATE_SHIFT
                        };
                        assert_eq!(
                            decode(opcode | slice_bits | (source << SOURCE_SHIFT) | 15),
                            Some(Ok(Operand {
                                destination: 15,
                                kind: Kind::MoveVector {
                                    element,
                                    source: source as u8,
                                    part: part as u8
                                }
                            }))
                        );
                    }
                }
            }
        }

        #[test]
        fn all_permutation_element_groups_allow_operand_aliases() {
            for opcode in [ZIP1, ZIP2, TRN1, TRN2, UZP1, UZP2] {
                for size in 0..=SIZE_MASK {
                    for register in 0..=PREDICATE_MASK {
                        let word = opcode
                            | (size << SIZE_SHIFT)
                            | register
                            | (register << SOURCE_SHIFT)
                            | (register << RIGHT_SHIFT);
                        assert!(matches!(decode(word), Some(Ok(Operand {
                    destination, kind: Kind::Permute { element, left, right, .. }
                })) if destination == register as u8 && left == destination && right == destination
                    && element.bytes() == 1 << size));
                    }
                }
            }
        }
    }

    #[test]
    fn booleans_preserve_all_predicate_register_roles_and_flags() {
        for opcode in [AND, BIC, EOR, NAND, NOR, ORN, ORR] {
            for flags in [false, true] {
                for register in 0..=PREDICATE_MASK {
                    let word = opcode
                        | if flags { FLAGS_BIT } else { 0 }
                        | register
                        | (register << SOURCE_SHIFT)
                        | (register << RIGHT_SHIFT)
                        | (register << GOVERNOR_SHIFT);
                    let operand = decode(word).unwrap().unwrap();
                    assert_eq!(operand.destination, register as u8);
                    assert!(
                        matches!(operand.kind, Kind::Boolean { flags: actual, governor, left, right, .. }
                    if actual == flags && governor == register as u8 && left == register as u8 && right == register as u8)
                    );
                }
            }
        }
    }

    #[test]
    fn counter_pair_allows_wrapping_destination_and_aliases() {
        let word =
            PEXT_PAIR | (3 << SIZE_SHIFT) | (7 << SOURCE_SHIFT) | (1 << PEXT_PART_SHIFT) | 15;
        assert_eq!(
            decode(word),
            Some(Ok(Operand {
                destination: 15,
                kind: Kind::ExtractCounter {
                    element: ElementSize::Doubleword,
                    source: 15,
                    part: 1,
                    pair: true
                }
            }))
        );
    }

    #[test]
    fn indexed_select_rejects_only_zero_size_encoding() {
        for encoded in 0u32..32 {
            let word = PSEL
                | ((encoded >> 4) << PSEL_IMMEDIATE_HIGH_SHIFT)
                | (((encoded >> 3) & 1) << PSEL_SIZE_HIGH_SHIFT)
                | ((encoded & 7) << PSEL_SIZE_LOW_SHIFT);
            assert_eq!(decode(word).unwrap().is_err(), encoded & 15 == 0);
        }
        assert_eq!(decode(0), None);
    }
}
