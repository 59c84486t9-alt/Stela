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
