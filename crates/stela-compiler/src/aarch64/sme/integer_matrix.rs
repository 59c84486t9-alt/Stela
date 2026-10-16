//! Integer SME outer products and ZA vector arithmetic.
//!
//! Structural decoding is independent of execution controls. The caller checks
//! streaming mode, ZA enablement and the per-operand feature requirements before
//! accessing state. None of these operations change NZCV, FPCR/FPSR, Z/P or RAM.
use crate::aarch64::scalable::ElementSize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Outer(OuterOperation),
    Long(LongOperation),
    AddSub(AddSubOperation),
}

pub fn decode(word: u32) -> Option<Operand> {
    decode_outer(word)
        .map(Operand::Outer)
        .or_else(|| decode_long(word).map(Operand::Long))
        .or_else(|| decode_add_sub(word).map(Operand::AddSub))
}

impl Operand {
    pub fn requires_sme2(self) -> bool {
        match self {
            Self::Long(_) | Self::AddSub(_) => true,
            Self::Outer(OuterOperation {
                kind: OuterKind::BitwiseXnor,
                ..
            }) => true,
            Self::Outer(OuterOperation {
                kind: OuterKind::Multiply { products: 2, .. },
                ..
            }) => true,
            Self::Outer(_) => false,
        }
    }

    pub fn requires_i16i64(self) -> bool {
        match self {
            Self::Outer(op) => op.accumulator_size == ElementSize::Doubleword,
            Self::Long(op) => op.accumulator_size == ElementSize::Doubleword,
            Self::AddSub(op) => op.element_size == ElementSize::Doubleword,
        }
    }
}

#[cfg(test)]
mod tests;

// Private integration proposal: all 26 assigned canonical outer-product forms.
// Feature availability and SME/streaming/ZA gates belong to the shared profile.
// All variable fields accept their complete encoded range; no GPR/ZR/SP operands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OuterKind {
    AddHorizontal,
    AddVertical,
    BitwiseXnor,
    Multiply {
        products: u8,
        signed_n: bool,
        signed_m: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OuterOperation {
    pub kind: OuterKind,
    pub accumulator_size: ElementSize,
    pub subtract: bool,
    pub tile: u8,
    pub predicate_n: u8,
    pub predicate_m: u8,
    pub vector_n: u8,
    pub vector_m: Option<u8>,
}

#[derive(Clone, Copy)]
struct OuterEncoding {
    mask: u32,
    value: u32,
    accumulator_size: ElementSize,
    kind: OuterKind,
    subtract: bool,
}

const OUTER_PREDICATE_N_SHIFT: u32 = 10;
const OUTER_PREDICATE_M_SHIFT: u32 = 13;
const OUTER_VECTOR_N_SHIFT: u32 = 5;
const OUTER_VECTOR_M_SHIFT: u32 = 16;
const OUTER_PREDICATE_REGISTER_MASK: u32 = 7;
const OUTER_VECTOR_REGISTER_MASK: u32 = 31;

use ElementSize::{Doubleword, Word};

const OUTER_SIGNED_SIGNED_2: OuterKind = OuterKind::Multiply {
    products: 2,
    signed_n: true,
    signed_m: true,
};
const OUTER_SIGNED_SIGNED_4: OuterKind = OuterKind::Multiply {
    products: 4,
    signed_n: true,
    signed_m: true,
};
const OUTER_SIGNED_UNSIGNED_4: OuterKind = OuterKind::Multiply {
    products: 4,
    signed_n: true,
    signed_m: false,
};
const OUTER_UNSIGNED_UNSIGNED_2: OuterKind = OuterKind::Multiply {
    products: 2,
    signed_n: false,
    signed_m: false,
};
const OUTER_UNSIGNED_UNSIGNED_4: OuterKind = OuterKind::Multiply {
    products: 4,
    signed_n: false,
    signed_m: false,
};
const OUTER_UNSIGNED_SIGNED_4: OuterKind = OuterKind::Multiply {
    products: 4,
    signed_n: false,
    signed_m: true,
};

const fn outer_encoding(
    mask: u32,
    value: u32,
    accumulator_size: ElementSize,
    kind: OuterKind,
    subtract: bool,
) -> OuterEncoding {
    OuterEncoding {
        mask,
        value,
        accumulator_size,
        kind,
        subtract,
    }
}

const OUTER_ENCODINGS: [OuterEncoding; 26] = [
    outer_encoding(
        0xffff_001c,
        0xc090_0000,
        Word,
        OuterKind::AddHorizontal,
        false,
    ),
    outer_encoding(
        0xffff_0018,
        0xc0d0_0000,
        Doubleword,
        OuterKind::AddHorizontal,
        false,
    ),
    outer_encoding(
        0xffff_001c,
        0xc091_0000,
        Word,
        OuterKind::AddVertical,
        false,
    ),
    outer_encoding(
        0xffff_0018,
        0xc0d1_0000,
        Doubleword,
        OuterKind::AddVertical,
        false,
    ),
    outer_encoding(
        0xffe0_001c,
        0x8080_0008,
        Word,
        OuterKind::BitwiseXnor,
        false,
    ),
    outer_encoding(0xffe0_001c, 0x8080_0018, Word, OuterKind::BitwiseXnor, true),
    outer_encoding(0xffe0_001c, 0xa080_0008, Word, OUTER_SIGNED_SIGNED_2, false),
    outer_encoding(0xffe0_001c, 0xa080_0000, Word, OUTER_SIGNED_SIGNED_4, false),
    outer_encoding(
        0xffe0_0018,
        0xa0c0_0000,
        Doubleword,
        OUTER_SIGNED_SIGNED_4,
        false,
    ),
    outer_encoding(0xffe0_001c, 0xa080_0018, Word, OUTER_SIGNED_SIGNED_2, true),
    outer_encoding(0xffe0_001c, 0xa080_0010, Word, OUTER_SIGNED_SIGNED_4, true),
    outer_encoding(
        0xffe0_0018,
        0xa0c0_0010,
        Doubleword,
        OUTER_SIGNED_SIGNED_4,
        true,
    ),
    outer_encoding(
        0xffe0_001c,
        0xa0a0_0000,
        Word,
        OUTER_SIGNED_UNSIGNED_4,
        false,
    ),
    outer_encoding(
        0xffe0_0018,
        0xa0e0_0000,
        Doubleword,
        OUTER_SIGNED_UNSIGNED_4,
        false,
    ),
    outer_encoding(
        0xffe0_001c,
        0xa0a0_0010,
        Word,
        OUTER_SIGNED_UNSIGNED_4,
        true,
    ),
    outer_encoding(
        0xffe0_0018,
        0xa0e0_0010,
        Doubleword,
        OUTER_SIGNED_UNSIGNED_4,
        true,
    ),
    outer_encoding(
        0xffe0_001c,
        0xa180_0008,
        Word,
        OUTER_UNSIGNED_UNSIGNED_2,
        false,
    ),
    outer_encoding(
        0xffe0_001c,
        0xa1a0_0000,
        Word,
        OUTER_UNSIGNED_UNSIGNED_4,
        false,
    ),
    outer_encoding(
        0xffe0_0018,
        0xa1e0_0000,
        Doubleword,
        OUTER_UNSIGNED_UNSIGNED_4,
        false,
    ),
    outer_encoding(
        0xffe0_001c,
        0xa180_0018,
        Word,
        OUTER_UNSIGNED_UNSIGNED_2,
        true,
    ),
    outer_encoding(
        0xffe0_001c,
        0xa1a0_0010,
        Word,
        OUTER_UNSIGNED_UNSIGNED_4,
        true,
    ),
    outer_encoding(
        0xffe0_0018,
        0xa1e0_0010,
        Doubleword,
        OUTER_UNSIGNED_UNSIGNED_4,
        true,
    ),
    outer_encoding(
        0xffe0_001c,
        0xa180_0000,
        Word,
        OUTER_UNSIGNED_SIGNED_4,
        false,
    ),
    outer_encoding(
        0xffe0_0018,
        0xa1c0_0000,
        Doubleword,
        OUTER_UNSIGNED_SIGNED_4,
        false,
    ),
    outer_encoding(
        0xffe0_001c,
        0xa180_0010,
        Word,
        OUTER_UNSIGNED_SIGNED_4,
        true,
    ),
    outer_encoding(
        0xffe0_0018,
        0xa1c0_0010,
        Doubleword,
        OUTER_UNSIGNED_SIGNED_4,
        true,
    ),
];

fn decode_outer(word: u32) -> Option<OuterOperation> {
    let encoding = OUTER_ENCODINGS
        .iter()
        .find(|encoding| word & encoding.mask == encoding.value)?;
    let vector_m = match encoding.kind {
        OuterKind::AddHorizontal | OuterKind::AddVertical => None,
        OuterKind::BitwiseXnor | OuterKind::Multiply { .. } => {
            Some(((word >> OUTER_VECTOR_M_SHIFT) & OUTER_VECTOR_REGISTER_MASK) as u8)
        }
    };
    let tile_mask = (encoding.accumulator_size.bytes() - 1) as u32;
    Some(OuterOperation {
        kind: encoding.kind,
        accumulator_size: encoding.accumulator_size,
        subtract: encoding.subtract,
        tile: (word & tile_mask) as u8,
        predicate_n: ((word >> OUTER_PREDICATE_N_SHIFT) & OUTER_PREDICATE_REGISTER_MASK) as u8,
        predicate_m: ((word >> OUTER_PREDICATE_M_SHIFT) & OUTER_PREDICATE_REGISTER_MASK) as u8,
        vector_n: ((word >> OUTER_VECTOR_N_SHIFT) & OUTER_VECTOR_REGISTER_MASK) as u8,
        vector_m,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongOperation {
    pub signed_left: bool,
    pub signed_right: bool,
    pub subtract: bool,
    pub source_size: ElementSize,
    pub accumulator_size: ElementSize,
    pub group_size: u8,
    pub factor: u8,
    pub selector: u8,
    pub offset: u8,
    pub source_left: u8,
    pub source_right: u8,
    pub indexed_lane: Option<u8>,
    pub group_right: bool,
    pub wrap_left: bool,
}

#[derive(Clone, Copy)]
struct LongField {
    shift: u32,
    mask: u32,
}
impl LongField {
    const fn read(self, word: u32) -> u8 {
        ((word >> self.shift) & self.mask) as u8
    }
}

const LONG_SELECTOR_BASE: u8 = 8;
const LONG_DOUBLE_FACTOR: u8 = 2;
const LONG_QUAD_FACTOR: u8 = 4;
const LONG_UNSIGNED_FLAG: u32 = 1 << 4;
const LONG_SUBTRACT_FLAG: u32 = 1 << 3;
const LONG_SINGLE_MIXED_FLAG: u32 = 1 << 2;
const LONG_GROUP_MIXED_FLAG: u32 = 1 << 5;
const LONG_KIND_MASK: u32 = LONG_UNSIGNED_FLAG | LONG_SUBTRACT_FLAG;
const LONG_SIGNED_ADD: u32 = 0;
const LONG_SIGNED_SUBTRACT: u32 = LONG_SUBTRACT_FLAG;
const LONG_UNSIGNED_ADD: u32 = LONG_UNSIGNED_FLAG;
const LONG_UNSIGNED_SUBTRACT: u32 = LONG_UNSIGNED_FLAG | LONG_SUBTRACT_FLAG;
const LONG_UNSIGNED_SIGNED_ADD: u32 = LONG_SINGLE_MIXED_FLAG;
const LONG_SIGNED_UNSIGNED_ADD: u32 = LONG_UNSIGNED_FLAG | LONG_SINGLE_MIXED_FLAG;

const LONG_I3H_10_1: LongField = LongField {
    shift: 10,
    mask: 0x1,
};
const LONG_I3H_10_2: LongField = LongField {
    shift: 10,
    mask: 0x3,
};
const LONG_I3H_15_1: LongField = LongField {
    shift: 15,
    mask: 0x1,
};
const LONG_I3L_10_2: LongField = LongField {
    shift: 10,
    mask: 0x3,
};
const LONG_I3L_1_2: LongField = LongField {
    shift: 1,
    mask: 0x3,
};
const LONG_I3L_2_1: LongField = LongField {
    shift: 2,
    mask: 0x1,
};
const LONG_I4H_10_2: LongField = LongField {
    shift: 10,
    mask: 0x3,
};
const LONG_I4H_15_1: LongField = LongField {
    shift: 15,
    mask: 0x1,
};
const LONG_I4L_10_3: LongField = LongField {
    shift: 10,
    mask: 0x7,
};
const LONG_I4L_1_2: LongField = LongField {
    shift: 1,
    mask: 0x3,
};
const LONG_O1_0_1: LongField = LongField {
    shift: 0,
    mask: 0x1,
};
const LONG_OFF2_0_2: LongField = LongField {
    shift: 0,
    mask: 0x3,
};
const LONG_OFF3_0_3: LongField = LongField {
    shift: 0,
    mask: 0x7,
};
const LONG_RV_13_2: LongField = LongField {
    shift: 13,
    mask: 0x3,
};
const LONG_SZ_22_1: LongField = LongField {
    shift: 22,
    mask: 0x1,
};
const LONG_ZM_16_4: LongField = LongField {
    shift: 16,
    mask: 0xf,
};
const LONG_ZM_17_4: LongField = LongField {
    shift: 17,
    mask: 0xf,
};
const LONG_ZM_18_3: LongField = LongField {
    shift: 18,
    mask: 0x7,
};
const LONG_ZN_5_5: LongField = LongField {
    shift: 5,
    mask: 0x1f,
};
const LONG_ZN_6_4: LongField = LongField {
    shift: 6,
    mask: 0xf,
};
const LONG_ZN_7_3: LongField = LongField {
    shift: 7,
    mask: 0x7,
};

const LONG_SMLAL_ZA_ZZI_1_MASK: u32 = 0xfff01000;
const LONG_SMLAL_ZA_ZZI_1_OPCODE: u32 = 0xc1c01000;
const LONG_SMLAL_ZA_ZZI_2XI_MASK: u32 = 0xfff09020;
const LONG_SMLAL_ZA_ZZI_2XI_OPCODE: u32 = 0xc1d01000;
const LONG_SMLAL_ZA_ZZI_4XI_MASK: u32 = 0xfff09060;
const LONG_SMLAL_ZA_ZZI_4XI_OPCODE: u32 = 0xc1d09000;
const LONG_SMLAL_ZA_ZZV_1_MASK: u32 = 0xfff09c00;
const LONG_SMLAL_ZA_ZZV_1_OPCODE: u32 = 0xc1600c00;
const LONG_SMLAL_ZA_ZZV_2X1_MASK: u32 = 0xfff09c04;
const LONG_SMLAL_ZA_ZZV_2X1_OPCODE: u32 = 0xc1600800;
const LONG_SMLAL_ZA_ZZV_4X1_MASK: u32 = 0xfff09c04;
const LONG_SMLAL_ZA_ZZV_4X1_OPCODE: u32 = 0xc1700800;
const LONG_SMLAL_ZA_ZZW_2X2_MASK: u32 = 0xffe19c24;
const LONG_SMLAL_ZA_ZZW_2X2_OPCODE: u32 = 0xc1e00800;
const LONG_SMLAL_ZA_ZZW_4X4_MASK: u32 = 0xffe39c64;
const LONG_SMLAL_ZA_ZZW_4X4_OPCODE: u32 = 0xc1e10800;
const LONG_SMLALL_ZA_ZZI_D_MASK: u32 = 0xfff01000;
const LONG_SMLALL_ZA_ZZI_D_OPCODE: u32 = 0xc1800000;
const LONG_SMLALL_ZA_ZZI_D2XI_MASK: u32 = 0xfff09800;
const LONG_SMLALL_ZA_ZZI_D2XI_OPCODE: u32 = 0xc1900000;
const LONG_SMLALL_ZA_ZZI_D4XI_MASK: u32 = 0xfff09840;
const LONG_SMLALL_ZA_ZZI_D4XI_OPCODE: u32 = 0xc1908000;
const LONG_SMLALL_ZA_ZZI_S_MASK: u32 = 0xfff00000;
const LONG_SMLALL_ZA_ZZI_S_OPCODE: u32 = 0xc1000000;
const LONG_SMLALL_ZA_ZZI_S2XI_MASK: u32 = 0xfff09000;
const LONG_SMLALL_ZA_ZZI_S2XI_OPCODE: u32 = 0xc1100000;
const LONG_SMLALL_ZA_ZZI_S4XI_MASK: u32 = 0xfff09040;
const LONG_SMLALL_ZA_ZZI_S4XI_OPCODE: u32 = 0xc1108000;
const LONG_SMLALL_ZA_ZZV_1_MASK: u32 = 0xffb09c00;
const LONG_SMLALL_ZA_ZZV_1_OPCODE: u32 = 0xc1200400;
const LONG_SMLALL_ZA_ZZV_2X1_MASK: u32 = 0xffb09c02;
const LONG_SMLALL_ZA_ZZV_2X1_OPCODE: u32 = 0xc1200000;
const LONG_SMLALL_ZA_ZZV_4X1_MASK: u32 = 0xffb09c02;
const LONG_SMLALL_ZA_ZZV_4X1_OPCODE: u32 = 0xc1300000;
const LONG_SMLALL_ZA_ZZW_2X2_MASK: u32 = 0xffa19c22;
const LONG_SMLALL_ZA_ZZW_2X2_OPCODE: u32 = 0xc1a00000;
const LONG_SMLALL_ZA_ZZW_4X4_MASK: u32 = 0xffa39c62;
const LONG_SMLALL_ZA_ZZW_4X4_OPCODE: u32 = 0xc1a10000;

fn decode_long(word: u32) -> Option<LongOperation> {
    let (
        wide,
        group_size,
        factor,
        source_left,
        source_right,
        offset,
        indexed_lane,
        group_right,
        wrap_left,
        mixed_flag,
        allow_signed_unsigned,
    ) = if word & LONG_SMLAL_ZA_ZZI_1_MASK == LONG_SMLAL_ZA_ZZI_1_OPCODE {
        (
            false,
            1,
            LONG_DOUBLE_FACTOR,
            LONG_ZN_5_5.read(word),
            LONG_ZM_16_4.read(word),
            (LONG_OFF3_0_3.read(word) << 1),
            Some((LONG_I3H_15_1.read(word) << 2) | LONG_I3L_10_2.read(word)),
            false,
            false,
            0,
            false,
        )
    } else if word & LONG_SMLAL_ZA_ZZI_2XI_MASK == LONG_SMLAL_ZA_ZZI_2XI_OPCODE {
        (
            false,
            2,
            LONG_DOUBLE_FACTOR,
            (LONG_ZN_6_4.read(word) << 1),
            LONG_ZM_16_4.read(word),
            (LONG_OFF2_0_2.read(word) << 1),
            Some((LONG_I3H_10_2.read(word) << 1) | LONG_I3L_2_1.read(word)),
            false,
            false,
            0,
            false,
        )
    } else if word & LONG_SMLAL_ZA_ZZI_4XI_MASK == LONG_SMLAL_ZA_ZZI_4XI_OPCODE {
        (
            false,
            4,
            LONG_DOUBLE_FACTOR,
            (LONG_ZN_7_3.read(word) << 2),
            LONG_ZM_16_4.read(word),
            (LONG_OFF2_0_2.read(word) << 1),
            Some((LONG_I3H_10_2.read(word) << 1) | LONG_I3L_2_1.read(word)),
            false,
            false,
            0,
            false,
        )
    } else if word & LONG_SMLAL_ZA_ZZV_1_MASK == LONG_SMLAL_ZA_ZZV_1_OPCODE {
        (
            false,
            1,
            LONG_DOUBLE_FACTOR,
            LONG_ZN_5_5.read(word),
            LONG_ZM_16_4.read(word),
            (LONG_OFF3_0_3.read(word) << 1),
            None,
            false,
            true,
            0,
            false,
        )
    } else if word & LONG_SMLAL_ZA_ZZV_2X1_MASK == LONG_SMLAL_ZA_ZZV_2X1_OPCODE {
        (
            false,
            2,
            LONG_DOUBLE_FACTOR,
            LONG_ZN_5_5.read(word),
            LONG_ZM_16_4.read(word),
            (LONG_OFF2_0_2.read(word) << 1),
            None,
            false,
            true,
            0,
            false,
        )
    } else if word & LONG_SMLAL_ZA_ZZV_4X1_MASK == LONG_SMLAL_ZA_ZZV_4X1_OPCODE {
        (
            false,
            4,
            LONG_DOUBLE_FACTOR,
            LONG_ZN_5_5.read(word),
            LONG_ZM_16_4.read(word),
            (LONG_OFF2_0_2.read(word) << 1),
            None,
            false,
            true,
            0,
            false,
        )
    } else if word & LONG_SMLAL_ZA_ZZW_2X2_MASK == LONG_SMLAL_ZA_ZZW_2X2_OPCODE {
        (
            false,
            2,
            LONG_DOUBLE_FACTOR,
            (LONG_ZN_6_4.read(word) << 1),
            (LONG_ZM_17_4.read(word) << 1),
            (LONG_OFF2_0_2.read(word) << 1),
            None,
            true,
            false,
            0,
            false,
        )
    } else if word & LONG_SMLAL_ZA_ZZW_4X4_MASK == LONG_SMLAL_ZA_ZZW_4X4_OPCODE {
        (
            false,
            4,
            LONG_DOUBLE_FACTOR,
            (LONG_ZN_7_3.read(word) << 2),
            (LONG_ZM_18_3.read(word) << 2),
            (LONG_OFF2_0_2.read(word) << 1),
            None,
            true,
            false,
            0,
            false,
        )
    } else if word & LONG_SMLALL_ZA_ZZI_D_MASK == LONG_SMLALL_ZA_ZZI_D_OPCODE {
        (
            true,
            1,
            LONG_QUAD_FACTOR,
            LONG_ZN_5_5.read(word),
            LONG_ZM_16_4.read(word),
            (LONG_OFF2_0_2.read(word) << 2),
            Some((LONG_I3H_15_1.read(word) << 2) | LONG_I3L_10_2.read(word)),
            false,
            false,
            LONG_SINGLE_MIXED_FLAG,
            true,
        )
    } else if word & LONG_SMLALL_ZA_ZZI_D2XI_MASK == LONG_SMLALL_ZA_ZZI_D2XI_OPCODE {
        (
            true,
            2,
            LONG_QUAD_FACTOR,
            (LONG_ZN_6_4.read(word) << 1),
            LONG_ZM_16_4.read(word),
            (LONG_O1_0_1.read(word) << 2),
            Some((LONG_I3H_10_1.read(word) << 2) | LONG_I3L_1_2.read(word)),
            false,
            false,
            LONG_GROUP_MIXED_FLAG,
            true,
        )
    } else if word & LONG_SMLALL_ZA_ZZI_D4XI_MASK == LONG_SMLALL_ZA_ZZI_D4XI_OPCODE {
        (
            true,
            4,
            LONG_QUAD_FACTOR,
            (LONG_ZN_7_3.read(word) << 2),
            LONG_ZM_16_4.read(word),
            (LONG_O1_0_1.read(word) << 2),
            Some((LONG_I3H_10_1.read(word) << 2) | LONG_I3L_1_2.read(word)),
            false,
            false,
            LONG_GROUP_MIXED_FLAG,
            true,
        )
    } else if word & LONG_SMLALL_ZA_ZZI_S_MASK == LONG_SMLALL_ZA_ZZI_S_OPCODE {
        (
            false,
            1,
            LONG_QUAD_FACTOR,
            LONG_ZN_5_5.read(word),
            LONG_ZM_16_4.read(word),
            (LONG_OFF2_0_2.read(word) << 2),
            Some((LONG_I4H_15_1.read(word) << 3) | LONG_I4L_10_3.read(word)),
            false,
            false,
            LONG_SINGLE_MIXED_FLAG,
            true,
        )
    } else if word & LONG_SMLALL_ZA_ZZI_S2XI_MASK == LONG_SMLALL_ZA_ZZI_S2XI_OPCODE {
        (
            false,
            2,
            LONG_QUAD_FACTOR,
            (LONG_ZN_6_4.read(word) << 1),
            LONG_ZM_16_4.read(word),
            (LONG_O1_0_1.read(word) << 2),
            Some((LONG_I4H_10_2.read(word) << 2) | LONG_I4L_1_2.read(word)),
            false,
            false,
            LONG_GROUP_MIXED_FLAG,
            true,
        )
    } else if word & LONG_SMLALL_ZA_ZZI_S4XI_MASK == LONG_SMLALL_ZA_ZZI_S4XI_OPCODE {
        (
            false,
            4,
            LONG_QUAD_FACTOR,
            (LONG_ZN_7_3.read(word) << 2),
            LONG_ZM_16_4.read(word),
            (LONG_O1_0_1.read(word) << 2),
            Some((LONG_I4H_10_2.read(word) << 2) | LONG_I4L_1_2.read(word)),
            false,
            false,
            LONG_GROUP_MIXED_FLAG,
            true,
        )
    } else if word & LONG_SMLALL_ZA_ZZV_1_MASK == LONG_SMLALL_ZA_ZZV_1_OPCODE {
        (
            LONG_SZ_22_1.read(word) != 0,
            1,
            LONG_QUAD_FACTOR,
            LONG_ZN_5_5.read(word),
            LONG_ZM_16_4.read(word),
            (LONG_OFF2_0_2.read(word) << 2),
            None,
            false,
            true,
            LONG_SINGLE_MIXED_FLAG,
            false,
        )
    } else if word & LONG_SMLALL_ZA_ZZV_2X1_MASK == LONG_SMLALL_ZA_ZZV_2X1_OPCODE {
        (
            LONG_SZ_22_1.read(word) != 0,
            2,
            LONG_QUAD_FACTOR,
            LONG_ZN_5_5.read(word),
            LONG_ZM_16_4.read(word),
            (LONG_O1_0_1.read(word) << 2),
            None,
            false,
            true,
            LONG_SINGLE_MIXED_FLAG,
            true,
        )
    } else if word & LONG_SMLALL_ZA_ZZV_4X1_MASK == LONG_SMLALL_ZA_ZZV_4X1_OPCODE {
        (
            LONG_SZ_22_1.read(word) != 0,
            4,
            LONG_QUAD_FACTOR,
            LONG_ZN_5_5.read(word),
            LONG_ZM_16_4.read(word),
            (LONG_O1_0_1.read(word) << 2),
            None,
            false,
            true,
            LONG_SINGLE_MIXED_FLAG,
            true,
        )
    } else if word & LONG_SMLALL_ZA_ZZW_2X2_MASK == LONG_SMLALL_ZA_ZZW_2X2_OPCODE {
        (
            LONG_SZ_22_1.read(word) != 0,
            2,
            LONG_QUAD_FACTOR,
            (LONG_ZN_6_4.read(word) << 1),
            (LONG_ZM_17_4.read(word) << 1),
            (LONG_O1_0_1.read(word) << 2),
            None,
            true,
            false,
            LONG_SINGLE_MIXED_FLAG,
            false,
        )
    } else if word & LONG_SMLALL_ZA_ZZW_4X4_MASK == LONG_SMLALL_ZA_ZZW_4X4_OPCODE {
        (
            LONG_SZ_22_1.read(word) != 0,
            4,
            LONG_QUAD_FACTOR,
            (LONG_ZN_7_3.read(word) << 2),
            (LONG_ZM_18_3.read(word) << 2),
            (LONG_O1_0_1.read(word) << 2),
            None,
            true,
            false,
            LONG_SINGLE_MIXED_FLAG,
            false,
        )
    } else {
        return None;
    };
    let mixed = word & mixed_flag != 0;
    let kind = (word & LONG_KIND_MASK) | if mixed { LONG_SINGLE_MIXED_FLAG } else { 0 };
    let (signed_left, signed_right, subtract) = match kind {
        LONG_SIGNED_ADD => (true, true, false),
        LONG_SIGNED_SUBTRACT => (true, true, true),
        LONG_UNSIGNED_ADD => (false, false, false),
        LONG_UNSIGNED_SUBTRACT => (false, false, true),
        LONG_UNSIGNED_SIGNED_ADD if !wide => (false, true, false),
        LONG_SIGNED_UNSIGNED_ADD if !wide && allow_signed_unsigned => (true, false, false),
        _ => return None,
    };
    Some(LongOperation {
        signed_left,
        signed_right,
        subtract,
        source_size: if wide || factor == LONG_DOUBLE_FACTOR {
            ElementSize::Halfword
        } else {
            ElementSize::Byte
        },
        accumulator_size: if wide {
            ElementSize::Doubleword
        } else {
            ElementSize::Word
        },
        group_size,
        factor,
        selector: LONG_SELECTOR_BASE | LONG_RV_13_2.read(word),
        offset,
        source_left,
        source_right,
        indexed_lane,
        group_right,
        wrap_left,
    })
}

const ADD_SUB_SIGN_BIT: u32 = 1 << 3;
const ADD_SUB_SIZE_SHIFT: u32 = 22;
const ADD_SUB_SELECTOR_SHIFT: u32 = 13;
const ADD_SUB_SELECTOR_MASK: u32 = 3;
const ADD_SUB_FIRST_SELECTOR: u8 = 8;
const ADD_SUB_OFFSET_MASK: u32 = 7;
const ADD_SUB_VECTOR_MASK: u32 = 31;
const ADD_SUB_SINGLE_MASK: u32 = 15;
const ADD_SUB_LEFT_SHIFT: u32 = 5;
const ADD_SUB_SINGLE_SHIFT: u32 = 16;
const ADD_SUB_PAIR_GROUP_MASK: u32 = 15;
const ADD_SUB_QUAD_GROUP_MASK: u32 = 7;
const ADD_SUB_PAIR_RIGHT_SHIFT: u32 = 17;
const ADD_SUB_QUAD_RIGHT_SHIFT: u32 = 18;
const ADD_SUB_PAIR_LEFT_SHIFT: u32 = 6;
const ADD_SUB_QUAD_LEFT_SHIFT: u32 = 7;
const ADD_SUB_ACCUMULATE_PAIR_MASK: u32 = 0xffbf_9c30;
const ADD_SUB_ACCUMULATE_QUAD_MASK: u32 = 0xffbf_9c70;
const ADD_SUB_SINGLE_CLASS_MASK: u32 = 0xffb0_9c10;
const ADD_SUB_GROUP_PAIR_MASK: u32 = 0xffa1_9c30;
const ADD_SUB_GROUP_QUAD_MASK: u32 = 0xffa3_9c70;
const ADD_SUB_ACCUMULATE_PAIR: u32 = 0xc1a0_1c10;
const ADD_SUB_ACCUMULATE_QUAD: u32 = 0xc1a1_1c10;
const ADD_SUB_SINGLE_PAIR: u32 = 0xc120_1810;
const ADD_SUB_SINGLE_QUAD: u32 = 0xc130_1810;
const ADD_SUB_GROUP_PAIR: u32 = 0xc1a0_1810;
const ADD_SUB_GROUP_QUAD: u32 = 0xc1a1_1810;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddSubSources {
    AccumulatorGroup { right: u8 },
    GroupSingle { left: u8, right: u8 },
    GroupGroup { left: u8, right: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddSubOperation {
    pub subtract: bool,
    pub element_size: ElementSize,
    pub groups: u8,
    pub selector: u8,
    pub offset: u8,
    pub sources: AddSubSources,
}

fn decode_add_sub(word: u32) -> Option<AddSubOperation> {
    let (groups, sources) = if word & ADD_SUB_ACCUMULATE_PAIR_MASK == ADD_SUB_ACCUMULATE_PAIR {
        (
            2,
            AddSubSources::AccumulatorGroup {
                right: (((word >> ADD_SUB_PAIR_LEFT_SHIFT) & ADD_SUB_PAIR_GROUP_MASK) * 2) as u8,
            },
        )
    } else if word & ADD_SUB_ACCUMULATE_QUAD_MASK == ADD_SUB_ACCUMULATE_QUAD {
        (
            4,
            AddSubSources::AccumulatorGroup {
                right: (((word >> ADD_SUB_QUAD_LEFT_SHIFT) & ADD_SUB_QUAD_GROUP_MASK) * 4) as u8,
            },
        )
    } else if [ADD_SUB_SINGLE_PAIR, ADD_SUB_SINGLE_QUAD]
        .contains(&(word & ADD_SUB_SINGLE_CLASS_MASK))
    {
        (
            if word & ADD_SUB_SINGLE_CLASS_MASK == ADD_SUB_SINGLE_PAIR {
                2
            } else {
                4
            },
            AddSubSources::GroupSingle {
                left: ((word >> ADD_SUB_LEFT_SHIFT) & ADD_SUB_VECTOR_MASK) as u8,
                right: ((word >> ADD_SUB_SINGLE_SHIFT) & ADD_SUB_SINGLE_MASK) as u8,
            },
        )
    } else if word & ADD_SUB_GROUP_PAIR_MASK == ADD_SUB_GROUP_PAIR {
        (
            2,
            AddSubSources::GroupGroup {
                left: (((word >> ADD_SUB_PAIR_LEFT_SHIFT) & ADD_SUB_PAIR_GROUP_MASK) * 2) as u8,
                right: (((word >> ADD_SUB_PAIR_RIGHT_SHIFT) & ADD_SUB_PAIR_GROUP_MASK) * 2) as u8,
            },
        )
    } else if word & ADD_SUB_GROUP_QUAD_MASK == ADD_SUB_GROUP_QUAD {
        (
            4,
            AddSubSources::GroupGroup {
                left: (((word >> ADD_SUB_QUAD_LEFT_SHIFT) & ADD_SUB_QUAD_GROUP_MASK) * 4) as u8,
                right: (((word >> ADD_SUB_QUAD_RIGHT_SHIFT) & ADD_SUB_QUAD_GROUP_MASK) * 4) as u8,
            },
        )
    } else {
        return None;
    };
    Some(AddSubOperation {
        subtract: word & ADD_SUB_SIGN_BIT != 0,
        element_size: if word & (1 << ADD_SUB_SIZE_SHIFT) == 0 {
            ElementSize::Word
        } else {
            ElementSize::Doubleword
        },
        groups,
        selector: ADD_SUB_FIRST_SELECTOR
            + ((word >> ADD_SUB_SELECTOR_SHIFT) & ADD_SUB_SELECTOR_MASK) as u8,
        offset: (word & ADD_SUB_OFFSET_MASK) as u8,
        sources,
    })
}
