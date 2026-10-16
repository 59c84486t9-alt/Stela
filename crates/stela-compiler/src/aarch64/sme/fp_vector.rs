//! SME2 unpredicated floating-point operations on aligned groups of Z vectors.
//!
//! Decoding is independent of execution controls. Callers must check streaming
//! access and the returned feature requirement before executing any effects.
use crate::aarch64::floating::{Format, minmax::MinMaxOperation, rounding::RoundingOperation};

const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const SOURCE_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const REGISTER_MASK: u32 = 31;
const BROADCAST_REGISTER_MASK: u32 = 15;
const PAIR_REGISTER_COUNT: u8 = 2;
const QUARTET_REGISTER_COUNT: u8 = 4;
const GROUP_SELECT: u32 = 1 << 11;
const MINIMUM_SELECT: u32 = 1;
const NUMBER_SELECT: u32 = 1 << 5;
const MINMAX_OPERATION_MASK: u32 = MINIMUM_SELECT | NUMBER_SELECT;
const BROADCAST_PAIR_MASK: u32 = 0xff30_ffe1 & !MINMAX_OPERATION_MASK;
const BROADCAST_QUARTET_MASK: u32 = 0xff30_ffe3 & !MINMAX_OPERATION_MASK;
const GROUP_PAIR_MASK: u32 = 0xff21_ffe1 & !MINMAX_OPERATION_MASK;
const GROUP_QUARTET_MASK: u32 = 0xff23_ffe3 & !MINMAX_OPERATION_MASK;
const CLAMP_PAIR_MASK: u32 = 0xff20_fc01;
const CLAMP_QUARTET_MASK: u32 = 0xff20_fc03;
const MINMAX_BROADCAST_PAIR: u32 = 0xc120_a100;
const MINMAX_BROADCAST_QUARTET: u32 = 0xc120_a900;
const MINMAX_GROUP_PAIR: u32 = 0xc120_b100;
const MINMAX_GROUP_QUARTET: u32 = 0xc120_b900;
const CLAMP_PAIR: u32 = 0xc120_c000;
const CLAMP_QUARTET: u32 = 0xc120_c800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElementFormat {
    Ieee(Format),
    BFloat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    Sme2,
    Sme2SveB16B16,
    SmeF16F16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorGroup {
    pub first: u8,
    pub count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conversion {
    Narrow { interleaved: bool, bfloat: bool },
    Widen { deinterleaved: bool },
    ToInteger { unsigned: bool },
    FromInteger { unsigned: bool },
    Round(RoundingOperation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    MinMax {
        operation: MinMaxOperation,
        right: VectorGroup,
    },
    Clamp {
        lower: u8,
        upper: u8,
    },
    Convert {
        operation: Conversion,
        source: VectorGroup,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: VectorGroup,
    pub format: ElementFormat,
    pub feature: Feature,
}

#[derive(Clone, Copy)]
struct ConversionEncoding {
    mask: u32,
    opcode: u32,
    operation: Conversion,
    count: u8,
}

const NARROW_PAIR_MASK: u32 = 0xffff_fc20;
const WIDEN_PAIR_MASK: u32 = 0xffff_fc01;
const UNARY_PAIR_MASK: u32 = 0xffff_fc21;
const UNARY_QUARTET_MASK: u32 = 0xffff_fc63;
const BFCVT_Z_MZ2: u32 = 0xc160_e000;
const BFCVTN_Z_MZ2: u32 = 0xc160_e020;
const FCVT_MZ2_Z: u32 = 0xc1a0_e000;
const FCVT_Z_MZ2: u32 = 0xc120_e000;
const FCVTL_MZ2_Z: u32 = 0xc1a0_e001;
const FCVTN_Z_MZ2: u32 = 0xc120_e020;
const FCVTZS_MZ_Z_2: u32 = 0xc121_e000;
const FCVTZS_MZ_Z_4: u32 = 0xc131_e000;
const FCVTZU_MZ_Z_2: u32 = 0xc121_e020;
const FCVTZU_MZ_Z_4: u32 = 0xc131_e020;
const FRINTA_MZ_Z_2: u32 = 0xc1ac_e000;
const FRINTA_MZ_Z_4: u32 = 0xc1bc_e000;
const FRINTM_MZ_Z_2: u32 = 0xc1aa_e000;
const FRINTM_MZ_Z_4: u32 = 0xc1ba_e000;
const FRINTN_MZ_Z_2: u32 = 0xc1a8_e000;
const FRINTN_MZ_Z_4: u32 = 0xc1b8_e000;
const FRINTP_MZ_Z_2: u32 = 0xc1a9_e000;
const FRINTP_MZ_Z_4: u32 = 0xc1b9_e000;
const SCVTF_MZ_Z_2: u32 = 0xc122_e000;
const SCVTF_MZ_Z_4: u32 = 0xc132_e000;
const UCVTF_MZ_Z_2: u32 = 0xc122_e020;
const UCVTF_MZ_Z_4: u32 = 0xc132_e020;

const CONVERSIONS: &[ConversionEncoding] = &[
    ConversionEncoding {
        mask: NARROW_PAIR_MASK,
        opcode: BFCVT_Z_MZ2,
        operation: Conversion::Narrow {
            interleaved: false,
            bfloat: true,
        },
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: NARROW_PAIR_MASK,
        opcode: BFCVTN_Z_MZ2,
        operation: Conversion::Narrow {
            interleaved: true,
            bfloat: true,
        },
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: WIDEN_PAIR_MASK,
        opcode: FCVT_MZ2_Z,
        operation: Conversion::Widen {
            deinterleaved: false,
        },
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: NARROW_PAIR_MASK,
        opcode: FCVT_Z_MZ2,
        operation: Conversion::Narrow {
            interleaved: false,
            bfloat: false,
        },
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: WIDEN_PAIR_MASK,
        opcode: FCVTL_MZ2_Z,
        operation: Conversion::Widen {
            deinterleaved: true,
        },
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: NARROW_PAIR_MASK,
        opcode: FCVTN_Z_MZ2,
        operation: Conversion::Narrow {
            interleaved: true,
            bfloat: false,
        },
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_PAIR_MASK,
        opcode: FCVTZS_MZ_Z_2,
        operation: Conversion::ToInteger { unsigned: false },
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_QUARTET_MASK,
        opcode: FCVTZS_MZ_Z_4,
        operation: Conversion::ToInteger { unsigned: false },
        count: QUARTET_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_PAIR_MASK,
        opcode: FCVTZU_MZ_Z_2,
        operation: Conversion::ToInteger { unsigned: true },
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_QUARTET_MASK,
        opcode: FCVTZU_MZ_Z_4,
        operation: Conversion::ToInteger { unsigned: true },
        count: QUARTET_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_PAIR_MASK,
        opcode: FRINTA_MZ_Z_2,
        operation: Conversion::Round(RoundingOperation::NearestAway),
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_QUARTET_MASK,
        opcode: FRINTA_MZ_Z_4,
        operation: Conversion::Round(RoundingOperation::NearestAway),
        count: QUARTET_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_PAIR_MASK,
        opcode: FRINTM_MZ_Z_2,
        operation: Conversion::Round(RoundingOperation::TowardNegative),
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_QUARTET_MASK,
        opcode: FRINTM_MZ_Z_4,
        operation: Conversion::Round(RoundingOperation::TowardNegative),
        count: QUARTET_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_PAIR_MASK,
        opcode: FRINTN_MZ_Z_2,
        operation: Conversion::Round(RoundingOperation::NearestEven),
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_QUARTET_MASK,
        opcode: FRINTN_MZ_Z_4,
        operation: Conversion::Round(RoundingOperation::NearestEven),
        count: QUARTET_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_PAIR_MASK,
        opcode: FRINTP_MZ_Z_2,
        operation: Conversion::Round(RoundingOperation::TowardPositive),
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_QUARTET_MASK,
        opcode: FRINTP_MZ_Z_4,
        operation: Conversion::Round(RoundingOperation::TowardPositive),
        count: QUARTET_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_PAIR_MASK,
        opcode: SCVTF_MZ_Z_2,
        operation: Conversion::FromInteger { unsigned: false },
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_QUARTET_MASK,
        opcode: SCVTF_MZ_Z_4,
        operation: Conversion::FromInteger { unsigned: false },
        count: QUARTET_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_PAIR_MASK,
        opcode: UCVTF_MZ_Z_2,
        operation: Conversion::FromInteger { unsigned: true },
        count: PAIR_REGISTER_COUNT,
    },
    ConversionEncoding {
        mask: UNARY_QUARTET_MASK,
        opcode: UCVTF_MZ_Z_4,
        operation: Conversion::FromInteger { unsigned: true },
        count: QUARTET_REGISTER_COUNT,
    },
];

fn group(first: u8, count: u8) -> VectorGroup {
    VectorGroup { first, count }
}

fn aligned_register(word: u32, shift: u32, count: u8) -> u8 {
    ((word >> shift) & (REGISTER_MASK + 1 - u32::from(count))) as u8
}

fn element_format(word: u32) -> ElementFormat {
    match (word >> SIZE_SHIFT) & SIZE_MASK {
        0 => ElementFormat::BFloat,
        1 => ElementFormat::Ieee(Format::Half),
        2 => ElementFormat::Ieee(Format::Single),
        _ => ElementFormat::Ieee(Format::Double),
    }
}

pub fn decode(word: u32) -> Option<Operand> {
    let minmax_shape = [
        (
            BROADCAST_PAIR_MASK,
            MINMAX_BROADCAST_PAIR,
            PAIR_REGISTER_COUNT,
            false,
        ),
        (
            BROADCAST_QUARTET_MASK,
            MINMAX_BROADCAST_QUARTET,
            QUARTET_REGISTER_COUNT,
            false,
        ),
        (
            GROUP_PAIR_MASK,
            MINMAX_GROUP_PAIR,
            PAIR_REGISTER_COUNT,
            true,
        ),
        (
            GROUP_QUARTET_MASK,
            MINMAX_GROUP_QUARTET,
            QUARTET_REGISTER_COUNT,
            true,
        ),
    ]
    .into_iter()
    .find(|(mask, opcode, _, _)| word & mask == *opcode);
    if let Some((_, _, count, grouped)) = minmax_shape {
        let operation = match word & MINMAX_OPERATION_MASK {
            0 => MinMaxOperation::Maximum,
            MINIMUM_SELECT => MinMaxOperation::Minimum,
            NUMBER_SELECT => MinMaxOperation::MaximumNumber,
            _ => MinMaxOperation::MinimumNumber,
        };
        let right = if grouped {
            group(aligned_register(word, RIGHT_SHIFT, count), count)
        } else {
            group(((word >> RIGHT_SHIFT) & BROADCAST_REGISTER_MASK) as u8, 1)
        };
        let format = element_format(word);
        return Some(Operand {
            kind: Kind::MinMax { operation, right },
            destination: group(aligned_register(word, 0, count), count),
            format,
            feature: if format == ElementFormat::BFloat {
                Feature::Sme2SveB16B16
            } else {
                Feature::Sme2
            },
        });
    }
    if word & CLAMP_PAIR_MASK == CLAMP_PAIR || word & CLAMP_QUARTET_MASK == CLAMP_QUARTET {
        let count = if word & GROUP_SELECT == 0 {
            PAIR_REGISTER_COUNT
        } else {
            QUARTET_REGISTER_COUNT
        };
        let format = element_format(word);
        return Some(Operand {
            kind: Kind::Clamp {
                lower: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
                upper: ((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8,
            },
            destination: group(aligned_register(word, 0, count), count),
            format,
            feature: if format == ElementFormat::BFloat {
                Feature::Sme2SveB16B16
            } else {
                Feature::Sme2
            },
        });
    }
    let encoding = CONVERSIONS
        .iter()
        .find(|entry| word & entry.mask == entry.opcode)?;
    let (destination, source, format, feature) = match encoding.operation {
        Conversion::Narrow { bfloat, .. } => (
            group((word & REGISTER_MASK) as u8, 1),
            group(
                aligned_register(word, SOURCE_SHIFT, PAIR_REGISTER_COUNT),
                PAIR_REGISTER_COUNT,
            ),
            if bfloat {
                ElementFormat::BFloat
            } else {
                ElementFormat::Ieee(Format::Half)
            },
            Feature::Sme2,
        ),
        Conversion::Widen { .. } => (
            group(
                aligned_register(word, 0, PAIR_REGISTER_COUNT),
                PAIR_REGISTER_COUNT,
            ),
            group(((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8, 1),
            ElementFormat::Ieee(Format::Single),
            Feature::SmeF16F16,
        ),
        _ => (
            group(aligned_register(word, 0, encoding.count), encoding.count),
            group(
                aligned_register(word, SOURCE_SHIFT, encoding.count),
                encoding.count,
            ),
            ElementFormat::Ieee(Format::Single),
            Feature::Sme2,
        ),
    };
    Some(Operand {
        kind: Kind::Convert {
            operation: encoding.operation,
            source,
        },
        destination,
        format,
        feature,
    })
}

#[cfg(test)]
mod tests;
