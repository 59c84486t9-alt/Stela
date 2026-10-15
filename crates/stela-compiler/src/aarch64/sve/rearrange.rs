//! Streaming SVE lane rearrangement and integer vector generation.
//! No memory or architectural flags are modified. Sources precede destination commits.
use crate::aarch64::scalable::ElementSize;
use crate::aarch64::{Register, Width, logical_mask};

const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const SECOND_SHIFT: u32 = 16;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const EXT_LOW_MASK: u32 = 7;
const EXT_LOW_BITS: u32 = 3;
const SEGMENT_IMMEDIATE_MASK: u32 = 15;
const IMMEDIATE_SIGN_BIT: u8 = 16;
const IMMEDIATE_SIGN_EXTEND: u8 = 0xe0;
const LOGICAL_IMMEDIATE_MASK: u32 = (1 << 13) - 1;
const LOGICAL_N_SHIFT: u32 = 12;
const LOGICAL_ROTATION_SHIFT: u32 = 6;
const LOGICAL_FIELD_MASK: u32 = 63;

const DUPQ_Z_ZI_MASK: u32 = 0xffe0fc00;
const DUPQ_Z_ZI_CLASS: u32 = 0x05202400;
const EXT_Z_ZI_CON_MASK: u32 = 0xffe0e000;
const EXT_Z_ZI_CON_CLASS: u32 = 0x05600000;
const EXT_Z_ZI_DES_MASK: u32 = 0xffe0e000;
const EXT_Z_ZI_DES_CLASS: u32 = 0x05200000;
const EXTQ_Z_ZI_DES_MASK: u32 = 0xfff0fc00;
const EXTQ_Z_ZI_DES_CLASS: u32 = 0x05602400;
const REV_Z_Z_MASK: u32 = 0xff3ffc00;
const REV_Z_Z_CLASS: u32 = 0x05383800;
const REVD_Z_P_Z_M_MASK: u32 = 0xffffe000;
const REVD_Z_P_Z_M_CLASS: u32 = 0x052e8000;
const SPLICE_Z_P_ZZ_CON_MASK: u32 = 0xff3fe000;
const SPLICE_Z_P_ZZ_CON_CLASS: u32 = 0x052d8000;
const SPLICE_Z_P_ZZ_DES_MASK: u32 = 0xff3fe000;
const SPLICE_Z_P_ZZ_DES_CLASS: u32 = 0x052c8000;
const TBL_Z_ZZ_1_MASK: u32 = 0xff20fc00;
const TBL_Z_ZZ_1_CLASS: u32 = 0x05203000;
const TBL_Z_ZZ_2_MASK: u32 = 0xff20fc00;
const TBL_Z_ZZ_2_CLASS: u32 = 0x05202800;
const TBLQ_Z_ZZ_MASK: u32 = 0xff20fc00;
const TBLQ_Z_ZZ_CLASS: u32 = 0x4400f800;
const TBX_Z_ZZ_MASK: u32 = 0xff20fc00;
const TBX_Z_ZZ_CLASS: u32 = 0x05202c00;
const TBXQ_Z_ZZ_MASK: u32 = 0xff20fc00;
const TBXQ_Z_ZZ_CLASS: u32 = 0x05203400;
const TRN1_Z_ZZ_MASK: u32 = 0xff20fc00;
const TRN1_Z_ZZ_CLASS: u32 = 0x05207000;
const TRN2_Z_ZZ_MASK: u32 = 0xff20fc00;
const TRN2_Z_ZZ_CLASS: u32 = 0x05207400;
const UZP1_Z_ZZ_MASK: u32 = 0xff20fc00;
const UZP1_Z_ZZ_CLASS: u32 = 0x05206800;
const UZP2_Z_ZZ_MASK: u32 = 0xff20fc00;
const UZP2_Z_ZZ_CLASS: u32 = 0x05206c00;
const UZPQ1_Z_ZZ_MASK: u32 = 0xff20fc00;
const UZPQ1_Z_ZZ_CLASS: u32 = 0x4400e800;
const UZPQ2_Z_ZZ_MASK: u32 = 0xff20fc00;
const UZPQ2_Z_ZZ_CLASS: u32 = 0x4400ec00;
const ZIP1_Z_ZZ_MASK: u32 = 0xff20fc00;
const ZIP1_Z_ZZ_CLASS: u32 = 0x05206000;
const ZIP2_Z_ZZ_MASK: u32 = 0xff20fc00;
const ZIP2_Z_ZZ_CLASS: u32 = 0x05206400;
const ZIPQ1_Z_ZZ_MASK: u32 = 0xff20fc00;
const ZIPQ1_Z_ZZ_CLASS: u32 = 0x4400e000;
const ZIPQ2_Z_ZZ_MASK: u32 = 0xff20fc00;
const ZIPQ2_Z_ZZ_CLASS: u32 = 0x4400e400;
const DUPM_Z_I_MASK: u32 = 0xfffc0000;
const DUPM_Z_I_CLASS: u32 = 0x05c00000;
const INDEX_Z_II_MASK: u32 = 0xff20fc00;
const INDEX_Z_II_CLASS: u32 = 0x04204000;
const INDEX_Z_IR_MASK: u32 = 0xff20fc00;
const INDEX_Z_IR_CLASS: u32 = 0x04204800;
const INDEX_Z_RI_MASK: u32 = 0xff20fc00;
const INDEX_Z_RI_CLASS: u32 = 0x04204400;
const INDEX_Z_RR_MASK: u32 = 0xff20fc00;
const INDEX_Z_RR_CLASS: u32 = 0x04204c00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterleaveKind {
    Zip,
    Transpose,
    Unzip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexOperand {
    Immediate(i8),
    Register(Register),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Interleave {
        kind: InterleaveKind,
        part: u8,
        segment: bool,
        element_size: ElementSize,
        destination: u8,
        source: u8,
        second: u8,
    },
    Extract {
        destination: u8,
        source: u8,
        second: u8,
        byte_offset: u8,
        segment: bool,
    },
    Splice {
        destination: u8,
        source: u8,
        second: u8,
        governing: u8,
        element_size: ElementSize,
    },
    Table {
        destination: u8,
        source: u8,
        indexes: u8,
        register_count: u8,
        extension: bool,
        segment: bool,
        element_size: ElementSize,
    },
    Reverse {
        destination: u8,
        source: u8,
        element_size: ElementSize,
    },
    ReverseDouble {
        destination: u8,
        source: u8,
        governing: u8,
    },
    DuplicateSegment {
        destination: u8,
        source: u8,
        index: u8,
        element_size: ElementSize,
    },
    DuplicateMask {
        destination: u8,
        mask: u64,
    },
    Index {
        destination: u8,
        start: IndexOperand,
        step: IndexOperand,
        element_size: ElementSize,
    },
}

fn signed_immediate(encoded: u8) -> IndexOperand {
    let extended = if encoded & IMMEDIATE_SIGN_BIT != 0 {
        encoded | IMMEDIATE_SIGN_EXTEND
    } else {
        encoded
    };
    IndexOperand::Immediate(extended as i8)
}

fn index_register(encoded: u8) -> IndexOperand {
    IndexOperand::Register(if u32::from(encoded) == REGISTER_MASK {
        Register::Zero
    } else {
        Register::X(encoded)
    })
}

/// None is another allocation; Err is an allocated class with reserved operands.
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let destination = (word & REGISTER_MASK) as u8;
    let source = ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8;
    let second = ((word >> SECOND_SHIFT) & REGISTER_MASK) as u8;
    let governing = ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8;
    let element_size = match (word >> SIZE_SHIFT) & SIZE_MASK {
        0 => ElementSize::Byte,
        1 => ElementSize::Halfword,
        2 => ElementSize::Word,
        _ => ElementSize::Doubleword,
    };
    let operand = if word & DUPQ_Z_ZI_MASK == DUPQ_Z_ZI_CLASS {
        let tsz = (word >> SECOND_SHIFT) & SEGMENT_IMMEDIATE_MASK;
        if tsz == 0 {
            return Some(Err(()));
        }
        let low_bit = tsz.trailing_zeros();
        let element_size = ElementSize::from_bytes(1 << low_bit).expect("nonzero four-bit tsz");
        let index = (((word >> SECOND_SHIFT) & REGISTER_MASK) >> (low_bit + 1)) as u8;
        Operand::DuplicateSegment {
            destination,
            source,
            index,
            element_size,
        }
    } else if word & EXT_Z_ZI_CON_MASK == EXT_Z_ZI_CON_CLASS {
        Operand::Extract {
            destination,
            source,
            second: (source + 1) & REGISTER_MASK as u8,
            byte_offset: ((((word >> SECOND_SHIFT) & REGISTER_MASK) << EXT_LOW_BITS)
                | ((word >> PREDICATE_SHIFT) & EXT_LOW_MASK)) as u8,
            segment: false,
        }
    } else if word & EXT_Z_ZI_DES_MASK == EXT_Z_ZI_DES_CLASS {
        Operand::Extract {
            destination,
            source: destination,
            second: source,
            byte_offset: ((((word >> SECOND_SHIFT) & REGISTER_MASK) << EXT_LOW_BITS)
                | ((word >> PREDICATE_SHIFT) & EXT_LOW_MASK)) as u8,
            segment: false,
        }
    } else if word & EXTQ_Z_ZI_DES_MASK == EXTQ_Z_ZI_DES_CLASS {
        Operand::Extract {
            destination,
            source: destination,
            second: source,
            byte_offset: ((word >> SECOND_SHIFT) & SEGMENT_IMMEDIATE_MASK) as u8,
            segment: true,
        }
    } else if word & REV_Z_Z_MASK == REV_Z_Z_CLASS {
        Operand::Reverse {
            destination,
            source,
            element_size,
        }
    } else if word & REVD_Z_P_Z_M_MASK == REVD_Z_P_Z_M_CLASS {
        Operand::ReverseDouble {
            destination,
            source,
            governing,
        }
    } else if word & SPLICE_Z_P_ZZ_CON_MASK == SPLICE_Z_P_ZZ_CON_CLASS {
        Operand::Splice {
            destination,
            source,
            second: (source + 1) & REGISTER_MASK as u8,
            governing,
            element_size,
        }
    } else if word & SPLICE_Z_P_ZZ_DES_MASK == SPLICE_Z_P_ZZ_DES_CLASS {
        Operand::Splice {
            destination,
            source: destination,
            second: source,
            governing,
            element_size,
        }
    } else if word & TBL_Z_ZZ_1_MASK == TBL_Z_ZZ_1_CLASS {
        Operand::Table {
            destination,
            source,
            indexes: second,
            register_count: 1,
            extension: false,
            segment: false,
            element_size,
        }
    } else if word & TBL_Z_ZZ_2_MASK == TBL_Z_ZZ_2_CLASS {
        Operand::Table {
            destination,
            source,
            indexes: second,
            register_count: 2,
            extension: false,
            segment: false,
            element_size,
        }
    } else if word & TBLQ_Z_ZZ_MASK == TBLQ_Z_ZZ_CLASS {
        Operand::Table {
            destination,
            source,
            indexes: second,
            register_count: 1,
            extension: false,
            segment: true,
            element_size,
        }
    } else if word & TBX_Z_ZZ_MASK == TBX_Z_ZZ_CLASS {
        Operand::Table {
            destination,
            source,
            indexes: second,
            register_count: 1,
            extension: true,
            segment: false,
            element_size,
        }
    } else if word & TBXQ_Z_ZZ_MASK == TBXQ_Z_ZZ_CLASS {
        Operand::Table {
            destination,
            source,
            indexes: second,
            register_count: 1,
            extension: true,
            segment: true,
            element_size,
        }
    } else if word & TRN1_Z_ZZ_MASK == TRN1_Z_ZZ_CLASS {
        Operand::Interleave {
            kind: InterleaveKind::Transpose,
            part: 0,
            segment: false,
            element_size,
            destination,
            source,
            second,
        }
    } else if word & TRN2_Z_ZZ_MASK == TRN2_Z_ZZ_CLASS {
        Operand::Interleave {
            kind: InterleaveKind::Transpose,
            part: 1,
            segment: false,
            element_size,
            destination,
            source,
            second,
        }
    } else if word & UZP1_Z_ZZ_MASK == UZP1_Z_ZZ_CLASS {
        Operand::Interleave {
            kind: InterleaveKind::Unzip,
            part: 0,
            segment: false,
            element_size,
            destination,
            source,
            second,
        }
    } else if word & UZP2_Z_ZZ_MASK == UZP2_Z_ZZ_CLASS {
        Operand::Interleave {
            kind: InterleaveKind::Unzip,
            part: 1,
            segment: false,
            element_size,
            destination,
            source,
            second,
        }
    } else if word & UZPQ1_Z_ZZ_MASK == UZPQ1_Z_ZZ_CLASS {
        Operand::Interleave {
            kind: InterleaveKind::Unzip,
            part: 0,
            segment: true,
            element_size,
            destination,
            source,
            second,
        }
    } else if word & UZPQ2_Z_ZZ_MASK == UZPQ2_Z_ZZ_CLASS {
        Operand::Interleave {
            kind: InterleaveKind::Unzip,
            part: 1,
            segment: true,
            element_size,
            destination,
            source,
            second,
        }
    } else if word & ZIP1_Z_ZZ_MASK == ZIP1_Z_ZZ_CLASS {
        Operand::Interleave {
            kind: InterleaveKind::Zip,
            part: 0,
            segment: false,
            element_size,
            destination,
            source,
            second,
        }
    } else if word & ZIP2_Z_ZZ_MASK == ZIP2_Z_ZZ_CLASS {
        Operand::Interleave {
            kind: InterleaveKind::Zip,
            part: 1,
            segment: false,
            element_size,
            destination,
            source,
            second,
        }
    } else if word & ZIPQ1_Z_ZZ_MASK == ZIPQ1_Z_ZZ_CLASS {
        Operand::Interleave {
            kind: InterleaveKind::Zip,
            part: 0,
            segment: true,
            element_size,
            destination,
            source,
            second,
        }
    } else if word & ZIPQ2_Z_ZZ_MASK == ZIPQ2_Z_ZZ_CLASS {
        Operand::Interleave {
            kind: InterleaveKind::Zip,
            part: 1,
            segment: true,
            element_size,
            destination,
            source,
            second,
        }
    } else if word & DUPM_Z_I_MASK == DUPM_Z_I_CLASS {
        let immediate = (word >> SOURCE_SHIFT) & LOGICAL_IMMEDIATE_MASK;
        let mask = match logical_mask(
            Width::X64,
            immediate >> LOGICAL_N_SHIFT,
            (immediate >> LOGICAL_ROTATION_SHIFT) & LOGICAL_FIELD_MASK,
            immediate & LOGICAL_FIELD_MASK,
        ) {
            Some(mask) => mask,
            None => return Some(Err(())),
        };
        Operand::DuplicateMask { destination, mask }
    } else if word & INDEX_Z_II_MASK == INDEX_Z_II_CLASS {
        Operand::Index {
            destination,
            start: signed_immediate(source),
            step: signed_immediate(second),
            element_size,
        }
    } else if word & INDEX_Z_IR_MASK == INDEX_Z_IR_CLASS {
        Operand::Index {
            destination,
            start: signed_immediate(source),
            step: index_register(second),
            element_size,
        }
    } else if word & INDEX_Z_RI_MASK == INDEX_Z_RI_CLASS {
        Operand::Index {
            destination,
            start: index_register(source),
            step: signed_immediate(second),
            element_size,
        }
    } else if word & INDEX_Z_RR_MASK == INDEX_Z_RR_CLASS {
        Operand::Index {
            destination,
            start: index_register(source),
            step: index_register(second),
            element_size,
        }
    } else {
        return None;
    };
    Some(Ok(operand))
}

impl Operand {
    /// Exact documented MOVPRFX follower requirements. Other allocations remain
    /// unaudited; a matching typed operand alone cannot authorize a canonical word.
    #[allow(clippy::result_unit_err)]
    pub fn prefix_requirement(
        self,
        original_word: u32,
    ) -> Result<Option<crate::aarch64::sve::prefix::PrefixRequirement>, ()> {
        use crate::aarch64::sve::prefix::PrefixRequirement;

        if decode(original_word) != Some(Ok(self)) {
            return Err(());
        }
        let permitted = match self {
            Self::Extract {
                destination,
                second,
                ..
            } if original_word & EXT_Z_ZI_DES_MASK == EXT_Z_ZI_DES_CLASS
                || original_word & EXTQ_Z_ZI_DES_MASK == EXTQ_Z_ZI_DES_CLASS =>
            {
                Some((destination, second))
            }
            Self::Splice {
                destination,
                second,
                ..
            } if original_word & SPLICE_Z_P_ZZ_DES_MASK == SPLICE_Z_P_ZZ_DES_CLASS => {
                Some((destination, second))
            }
            _ => None,
        };
        Ok(
            permitted.map(|(destination, second)| PrefixRequirement::Vector {
                destination,
                predicated: None,
                // Exclude only the implicit destructive first source. An explicit
                // second source equal to the destination must remain an alias.
                other_vector_sources: 1_u32 << second,
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consecutive_operands_wrap_and_destructive_operands_are_explicit() {
        assert_eq!(
            decode(EXT_Z_ZI_CON_CLASS | (31 << SOURCE_SHIFT) | 4),
            Some(Ok(Operand::Extract {
                destination: 4,
                source: 31,
                second: 0,
                byte_offset: 0,
                segment: false,
            }))
        );
        assert_eq!(
            decode(EXT_Z_ZI_DES_CLASS | (31 << SOURCE_SHIFT) | 4),
            Some(Ok(Operand::Extract {
                destination: 4,
                source: 4,
                second: 31,
                byte_offset: 0,
                segment: false,
            }))
        );
    }

    #[test]
    fn index_register_zero_and_signed_immediate_roles_are_explicit() {
        assert_eq!(
            decode(INDEX_Z_RI_CLASS | (16 << SECOND_SHIFT) | (31 << SOURCE_SHIFT)),
            Some(Ok(Operand::Index {
                destination: 0,
                start: IndexOperand::Register(Register::Zero),
                step: IndexOperand::Immediate(-16),
                element_size: ElementSize::Byte,
            }))
        );
    }

    #[test]
    fn segment_duplicate_rejects_zero_size_and_decodes_all_other_values() {
        for encoded in 0..=REGISTER_MASK {
            let decoded = decode(DUPQ_Z_ZI_CLASS | (encoded << SECOND_SHIFT));
            if encoded & SEGMENT_IMMEDIATE_MASK == 0 {
                assert_eq!(decoded, Some(Err(())));
            } else {
                let Some(Ok(Operand::DuplicateSegment {
                    element_size,
                    index,
                    ..
                })) = decoded
                else {
                    panic!("allocated DUPQ failed");
                };
                assert!(usize::from(index) < 16 / element_size.bytes());
            }
        }
    }

    #[test]
    fn logical_duplicate_uses_the_shared_reserved_mask_boundary() {
        for encoded in 0..=LOGICAL_IMMEDIATE_MASK {
            let expected = logical_mask(
                Width::X64,
                encoded >> LOGICAL_N_SHIFT,
                (encoded >> LOGICAL_ROTATION_SHIFT) & LOGICAL_FIELD_MASK,
                encoded & LOGICAL_FIELD_MASK,
            );
            let decoded = decode(DUPM_Z_I_CLASS | (encoded << SOURCE_SHIFT));
            assert_eq!(
                decoded.map(|result| result.map(|operand| match operand {
                    Operand::DuplicateMask { mask, .. } => mask,
                    _ => panic!("wrong duplicate allocation"),
                })),
                Some(expected.ok_or(()))
            );
        }
    }

    #[test]
    fn reverse_double_requires_the_fixed_quadword_allocation() {
        assert_eq!(
            decode(REVD_Z_P_Z_M_CLASS),
            Some(Ok(Operand::ReverseDouble {
                destination: 0,
                source: 0,
                governing: 0,
            }))
        );
        for size in 1..=SIZE_MASK {
            assert_eq!(decode(REVD_Z_P_Z_M_CLASS | (size << SIZE_SHIFT)), None);
        }
        assert_eq!(decode(REVD_Z_P_Z_M_CLASS | (1 << 13)), None);
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;
    use crate::aarch64::scalable::Predication;
    use crate::aarch64::sve::prefix::{self, DecodedPrefix, PrefixRequirement, PrefixViolation};

    const DESTINATION: u8 = 3;
    const SECOND_SOURCE: u8 = 5;
    const GOVERNING_PREDICATE: u8 = 2;
    const Z_REGISTER_COUNT: u8 = 32;
    const PERMITTED_CLASSES: [u32; 3] = [
        EXT_Z_ZI_DES_CLASS,
        EXTQ_Z_ZI_DES_CLASS,
        SPLICE_Z_P_ZZ_DES_CLASS,
    ];
    const UNAUDITED_CLASSES: [u32; 25] = [
        DUPQ_Z_ZI_CLASS | (1 << SECOND_SHIFT),
        EXT_Z_ZI_CON_CLASS,
        REV_Z_Z_CLASS,
        REVD_Z_P_Z_M_CLASS,
        SPLICE_Z_P_ZZ_CON_CLASS,
        TBL_Z_ZZ_1_CLASS,
        TBL_Z_ZZ_2_CLASS,
        TBLQ_Z_ZZ_CLASS,
        TBX_Z_ZZ_CLASS,
        TBXQ_Z_ZZ_CLASS,
        TRN1_Z_ZZ_CLASS,
        TRN2_Z_ZZ_CLASS,
        UZP1_Z_ZZ_CLASS,
        UZP2_Z_ZZ_CLASS,
        UZPQ1_Z_ZZ_CLASS,
        UZPQ2_Z_ZZ_CLASS,
        ZIP1_Z_ZZ_CLASS,
        ZIP2_Z_ZZ_CLASS,
        ZIPQ1_Z_ZZ_CLASS,
        ZIPQ2_Z_ZZ_CLASS,
        DUPM_Z_I_CLASS,
        INDEX_Z_II_CLASS,
        INDEX_Z_IR_CLASS,
        INDEX_Z_RI_CLASS,
        INDEX_Z_RR_CLASS,
    ];

    fn operand(word: u32) -> Operand {
        decode(word)
            .expect("assigned allocation")
            .expect("valid operands")
    }

    fn prefix(source: u8, predication: Predication) -> DecodedPrefix {
        DecodedPrefix {
            destination: DESTINATION,
            source,
            predication,
            element: Some(ElementSize::Byte),
        }
    }

    #[test]
    fn all_twenty_eight_canonical_policies_are_explicit() {
        for class in PERMITTED_CLASSES {
            let word = class | (u32::from(SECOND_SOURCE) << SOURCE_SHIFT) | u32::from(DESTINATION);
            assert_eq!(
                operand(word).prefix_requirement(word),
                Ok(Some(PrefixRequirement::Vector {
                    destination: DESTINATION,
                    predicated: None,
                    other_vector_sources: 1_u32 << SECOND_SOURCE,
                }))
            );
        }
        for word in UNAUDITED_CLASSES {
            assert_eq!(operand(word).prefix_requirement(word), Ok(None));
        }
    }

    #[test]
    fn every_explicit_second_source_is_preserved_including_destination_aliases() {
        for class in PERMITTED_CLASSES {
            for destination in 0..Z_REGISTER_COUNT {
                for second in 0..Z_REGISTER_COUNT {
                    let word = class | (u32::from(second) << SOURCE_SHIFT) | u32::from(destination);
                    assert_eq!(
                        operand(word).prefix_requirement(word),
                        Ok(Some(PrefixRequirement::Vector {
                            destination,
                            predicated: None,
                            other_vector_sources: 1_u32 << second,
                        }))
                    );
                }
            }
        }
    }

    #[test]
    fn constructive_aliases_do_not_authorize_a_destructive_policy() {
        for (constructive, destructive) in [
            (EXT_Z_ZI_CON_CLASS, EXT_Z_ZI_DES_CLASS),
            (SPLICE_Z_P_ZZ_CON_CLASS, SPLICE_Z_P_ZZ_DES_CLASS),
        ] {
            let first =
                constructive | (u32::from(DESTINATION) << SOURCE_SHIFT) | u32::from(DESTINATION);
            let second =
                destructive | (u32::from(DESTINATION + 1) << SOURCE_SHIFT) | u32::from(DESTINATION);
            assert_eq!(operand(first), operand(second));
            assert_eq!(operand(first).prefix_requirement(first), Ok(None));
            assert!(matches!(
                operand(second).prefix_requirement(second),
                Ok(Some(PrefixRequirement::Vector { .. }))
            ));
        }
    }

    #[test]
    fn mismatched_unallocated_and_reserved_words_are_errors() {
        let word = EXT_Z_ZI_DES_CLASS
            | (u32::from(SECOND_SOURCE) << SOURCE_SHIFT)
            | u32::from(DESTINATION);
        let decoded = operand(word);
        for other in [
            word ^ 1,
            0,
            DUPQ_Z_ZI_CLASS,
            DUPM_Z_I_CLASS | (LOGICAL_IMMEDIATE_MASK << SOURCE_SHIFT),
            REVD_Z_P_Z_M_CLASS | (1 << SIZE_SHIFT),
        ] {
            assert_eq!(decoded.prefix_requirement(other), Err(()));
        }
        let forged = Operand::Extract {
            destination: DESTINATION,
            source: DESTINATION,
            second: Z_REGISTER_COUNT,
            byte_offset: 0,
            segment: false,
        };
        assert_eq!(forged.prefix_requirement(word), Err(()));
    }

    #[test]
    fn permitted_followers_accept_only_unpredicated_prefixes() {
        for class in PERMITTED_CLASSES {
            let word = class | (u32::from(SECOND_SOURCE) << SOURCE_SHIFT) | u32::from(DESTINATION);
            let requirement = operand(word).prefix_requirement(word).unwrap().unwrap();
            for source in 0..Z_REGISTER_COUNT {
                assert_eq!(
                    prefix::validate(prefix(source, Predication::Unpredicated), requirement),
                    Ok(())
                );
            }
            for mode in [
                Predication::Merging(GOVERNING_PREDICATE),
                Predication::Zeroing(GOVERNING_PREDICATE),
            ] {
                assert_eq!(
                    prefix::validate(prefix(SECOND_SOURCE, mode), requirement),
                    Err(PrefixViolation::PredicatedPrefixForbidden)
                );
            }
        }
    }

    #[test]
    fn an_explicit_second_destination_alias_is_rejected_by_the_shared_validator() {
        for class in PERMITTED_CLASSES {
            let word = class | (u32::from(DESTINATION) << SOURCE_SHIFT) | u32::from(DESTINATION);
            let requirement = operand(word).prefix_requirement(word).unwrap().unwrap();
            assert_eq!(
                prefix::validate(
                    prefix(SECOND_SOURCE, Predication::Unpredicated),
                    requirement
                ),
                Err(PrefixViolation::OtherSourceAlias)
            );
        }
    }
}

#[cfg(test)]
mod prefix_boundary_tests {
    use super::*;
    use crate::aarch64::sve::prefix::PrefixRequirement;

    const DESTINATION: u8 = 3;
    const SECOND_SOURCE: u8 = 5;
    const ELEMENTS: [ElementSize; 4] = [
        ElementSize::Byte,
        ElementSize::Halfword,
        ElementSize::Word,
        ElementSize::Doubleword,
    ];

    fn operand(word: u32) -> Operand {
        decode(word)
            .expect("assigned allocation")
            .expect("valid operands")
    }

    #[test]
    fn unaudited_wrapped_tables_and_segment_aliases_remain_unaudited() {
        for class in [
            TBL_Z_ZZ_2_CLASS,
            TBLQ_Z_ZZ_CLASS,
            TBXQ_Z_ZZ_CLASS,
            UZPQ1_Z_ZZ_CLASS,
            UZPQ2_Z_ZZ_CLASS,
            ZIPQ1_Z_ZZ_CLASS,
            ZIPQ2_Z_ZZ_CLASS,
        ] {
            for destination in [0, REGISTER_MASK] {
                for second in [0, REGISTER_MASK] {
                    for size in 0..=SIZE_MASK {
                        let word = class
                            | (size << SIZE_SHIFT)
                            | (REGISTER_MASK << SOURCE_SHIFT)
                            | (second << SECOND_SHIFT)
                            | destination;
                        let decoded = operand(word);
                        if class == TBL_Z_ZZ_2_CLASS {
                            assert!(matches!(
                                decoded,
                                Operand::Table {
                                    source,
                                    register_count: 2,
                                    indexes,
                                    ..
                                } if u32::from(source) == REGISTER_MASK && u32::from(indexes) == second
                            ));
                        }
                        assert_eq!(decoded.prefix_requirement(word), Ok(None));
                    }
                }
            }
        }
    }

    #[test]
    fn reverse_merging_and_splice_predicate_size_boundaries_keep_their_policy() {
        for governing in 0..=PREDICATE_MASK {
            let reverse = REVD_Z_P_Z_M_CLASS
                | (governing << PREDICATE_SHIFT)
                | (u32::from(DESTINATION) << SOURCE_SHIFT)
                | u32::from(DESTINATION);
            assert!(matches!(
                operand(reverse),
                Operand::ReverseDouble { source, destination, governing: predicate }
                    if source == destination && u32::from(predicate) == governing
            ));
            assert_eq!(operand(reverse).prefix_requirement(reverse), Ok(None));
            for (size, element) in ELEMENTS.into_iter().enumerate() {
                let splice = SPLICE_Z_P_ZZ_DES_CLASS
                    | ((size as u32) << SIZE_SHIFT)
                    | (governing << PREDICATE_SHIFT)
                    | (u32::from(SECOND_SOURCE) << SOURCE_SHIFT)
                    | u32::from(DESTINATION);
                let decoded = operand(splice);
                assert!(matches!(
                    decoded,
                    Operand::Splice { governing: predicate, element_size, .. }
                        if u32::from(predicate) == governing && element_size == element
                ));
                assert_eq!(
                    decoded.prefix_requirement(splice),
                    Ok(Some(PrefixRequirement::Vector {
                        destination: DESTINATION,
                        predicated: None,
                        other_vector_sources: 1_u32 << SECOND_SOURCE,
                    }))
                );
            }
        }
    }
}
