//! SVE integer multiplies. Saturation does not set FPSR.QC.
use crate::aarch64::scalable::{ElementSize, Predication};

const REGISTER_MASK: u32 = 31;
const NARROW_REGISTER_MASK: u32 = 7;
const DOUBLEWORD_INDEX_REGISTER_MASK: u32 = 15;
const SOURCE_SHIFT: u32 = 5;
const MULTIPLIER_SHIFT: u32 = 16;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const IMMEDIATE_MASK: u32 = 255;
const INDEX_LOW_SHIFT: u32 = 19;
const INDEX_HIGH_SHIFT: u32 = 22;
const INDEX_DOUBLEWORD_SHIFT: u32 = 20;
const INDEX_LONG_LOW_SHIFT: u32 = 11;
const INDEX_TWO_BITS: u32 = 3;
const INDEX_ONE_BIT: u32 = 1;
const ROTATION_SHIFT: u32 = 10;
const ROTATION_MASK: u32 = 3;
const QUARTER_TURN_DEGREES: u16 = 90;
const COMPLEX_MASK: u32 = 0xff20f000;
const INDEXED_COMPLEX_MASK: u32 = 0xffe0f000;
const PREDICATED_TERNARY_MASK: u32 = 0xff20e000;
const INDEXED_WORD_MASK: u32 = 0xffe0fc00;
const INDEXED_HALFWORD_MASK: u32 = 0xffa0fc00;
const PREDICATED_BINARY_MASK: u32 = 0xff3fe000;
const VECTOR_MASK: u32 = 0xff20fc00;
const INDEXED_LONG_MASK: u32 = 0xffe0f400;
const CMLA_Z_ZZZ: u32 = 0x44002000;
const CMLA_Z_ZZZI_H: u32 = 0x44a06000;
const CMLA_Z_ZZZI_S: u32 = 0x44e06000;
const MAD_Z_P_ZZZ: u32 = 0x0400c000;
const MLA_Z_P_ZZZ: u32 = 0x04004000;
const MLA_Z_ZZZI_D: u32 = 0x44e00800;
const MLA_Z_ZZZI_H: u32 = 0x44200800;
const MLA_Z_ZZZI_S: u32 = 0x44a00800;
const MLS_Z_P_ZZZ: u32 = 0x04006000;
const MLS_Z_ZZZI_D: u32 = 0x44e00c00;
const MLS_Z_ZZZI_H: u32 = 0x44200c00;
const MLS_Z_ZZZI_S: u32 = 0x44a00c00;
const MSB_Z_P_ZZZ: u32 = 0x0400e000;
const MUL_Z_P_ZZ: u32 = 0x04100000;
const MUL_Z_ZI: u32 = 0x2530c000;
const MUL_Z_ZZ: u32 = 0x04206000;
const MUL_Z_ZZI_D: u32 = 0x44e0f800;
const MUL_Z_ZZI_H: u32 = 0x4420f800;
const MUL_Z_ZZI_S: u32 = 0x44a0f800;
const PMUL_Z_ZZ: u32 = 0x04206400;
const PMULLB_Z_ZZ: u32 = 0x45006800;
const PMULLT_Z_ZZ: u32 = 0x45006c00;
const SMLALB_Z_ZZZ: u32 = 0x44004000;
const SMLALB_Z_ZZZI_D: u32 = 0x44e08000;
const SMLALB_Z_ZZZI_S: u32 = 0x44a08000;
const SMLALT_Z_ZZZ: u32 = 0x44004400;
const SMLALT_Z_ZZZI_D: u32 = 0x44e08400;
const SMLALT_Z_ZZZI_S: u32 = 0x44a08400;
const SMLSLB_Z_ZZZ: u32 = 0x44005000;
const SMLSLB_Z_ZZZI_D: u32 = 0x44e0a000;
const SMLSLB_Z_ZZZI_S: u32 = 0x44a0a000;
const SMLSLT_Z_ZZZ: u32 = 0x44005400;
const SMLSLT_Z_ZZZI_D: u32 = 0x44e0a400;
const SMLSLT_Z_ZZZI_S: u32 = 0x44a0a400;
const SMULH_Z_P_ZZ: u32 = 0x04120000;
const SMULH_Z_ZZ: u32 = 0x04206800;
const SMULLB_Z_ZZ: u32 = 0x45007000;
const SMULLB_Z_ZZI_D: u32 = 0x44e0c000;
const SMULLB_Z_ZZI_S: u32 = 0x44a0c000;
const SMULLT_Z_ZZ: u32 = 0x45007400;
const SMULLT_Z_ZZI_D: u32 = 0x44e0c400;
const SMULLT_Z_ZZI_S: u32 = 0x44a0c400;
const SQDMLALB_Z_ZZZ: u32 = 0x44006000;
const SQDMLALB_Z_ZZZI_D: u32 = 0x44e02000;
const SQDMLALB_Z_ZZZI_S: u32 = 0x44a02000;
const SQDMLALBT_Z_ZZZ: u32 = 0x44000800;
const SQDMLALT_Z_ZZZ: u32 = 0x44006400;
const SQDMLALT_Z_ZZZI_D: u32 = 0x44e02400;
const SQDMLALT_Z_ZZZI_S: u32 = 0x44a02400;
const SQDMLSLB_Z_ZZZ: u32 = 0x44006800;
const SQDMLSLB_Z_ZZZI_D: u32 = 0x44e03000;
const SQDMLSLB_Z_ZZZI_S: u32 = 0x44a03000;
const SQDMLSLBT_Z_ZZZ: u32 = 0x44000c00;
const SQDMLSLT_Z_ZZZ: u32 = 0x44006c00;
const SQDMLSLT_Z_ZZZI_D: u32 = 0x44e03400;
const SQDMLSLT_Z_ZZZI_S: u32 = 0x44a03400;
const SQDMULH_Z_ZZ: u32 = 0x04207000;
const SQDMULH_Z_ZZI_D: u32 = 0x44e0f000;
const SQDMULH_Z_ZZI_H: u32 = 0x4420f000;
const SQDMULH_Z_ZZI_S: u32 = 0x44a0f000;
const SQDMULLB_Z_ZZ: u32 = 0x45006000;
const SQDMULLB_Z_ZZI_D: u32 = 0x44e0e000;
const SQDMULLB_Z_ZZI_S: u32 = 0x44a0e000;
const SQDMULLT_Z_ZZ: u32 = 0x45006400;
const SQDMULLT_Z_ZZI_D: u32 = 0x44e0e400;
const SQDMULLT_Z_ZZI_S: u32 = 0x44a0e400;
const SQRDCMLAH_Z_ZZZ: u32 = 0x44003000;
const SQRDCMLAH_Z_ZZZI_H: u32 = 0x44a07000;
const SQRDCMLAH_Z_ZZZI_S: u32 = 0x44e07000;
const SQRDMLAH_Z_ZZZ: u32 = 0x44007000;
const SQRDMLAH_Z_ZZZI_D: u32 = 0x44e01000;
const SQRDMLAH_Z_ZZZI_H: u32 = 0x44201000;
const SQRDMLAH_Z_ZZZI_S: u32 = 0x44a01000;
const SQRDMLSH_Z_ZZZ: u32 = 0x44007400;
const SQRDMLSH_Z_ZZZI_D: u32 = 0x44e01400;
const SQRDMLSH_Z_ZZZI_H: u32 = 0x44201400;
const SQRDMLSH_Z_ZZZI_S: u32 = 0x44a01400;
const SQRDMULH_Z_ZZ: u32 = 0x04207400;
const SQRDMULH_Z_ZZI_D: u32 = 0x44e0f400;
const SQRDMULH_Z_ZZI_H: u32 = 0x4420f400;
const SQRDMULH_Z_ZZI_S: u32 = 0x44a0f400;
const UMLALB_Z_ZZZ: u32 = 0x44004800;
const UMLALB_Z_ZZZI_D: u32 = 0x44e09000;
const UMLALB_Z_ZZZI_S: u32 = 0x44a09000;
const UMLALT_Z_ZZZ: u32 = 0x44004c00;
const UMLALT_Z_ZZZI_D: u32 = 0x44e09400;
const UMLALT_Z_ZZZI_S: u32 = 0x44a09400;
const UMLSLB_Z_ZZZ: u32 = 0x44005800;
const UMLSLB_Z_ZZZI_D: u32 = 0x44e0b000;
const UMLSLB_Z_ZZZI_S: u32 = 0x44a0b000;
const UMLSLT_Z_ZZZ: u32 = 0x44005c00;
const UMLSLT_Z_ZZZI_D: u32 = 0x44e0b400;
const UMLSLT_Z_ZZZI_S: u32 = 0x44a0b400;
const UMULH_Z_P_ZZ: u32 = 0x04130000;
const UMULH_Z_ZZ: u32 = 0x04206c00;
const UMULLB_Z_ZZ: u32 = 0x45007800;
const UMULLB_Z_ZZI_D: u32 = 0x44e0d000;
const UMULLB_Z_ZZI_S: u32 = 0x44a0d000;
const UMULLT_Z_ZZ: u32 = 0x45007c00;
const UMULLT_Z_ZZI_D: u32 = 0x44e0d400;
const UMULLT_Z_ZZI_S: u32 = 0x44a0d400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accumulate {
    None,
    Add,
    Subtract,
}

/// Bottom/top select alternating narrow lanes; cross selects bottom Zn/top Zm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    Bottom,
    Top,
    Cross,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Multiply,
    Polynomial {
        widening: bool,
        selection: Selection,
    },
    MultiplyHigh {
        signed: bool,
    },
    Accumulate {
        subtract: bool,
    },
    Long {
        signed: bool,
        doubling: bool,
        accumulate: Accumulate,
        selection: Selection,
    },
    DoublingHigh {
        rounding: bool,
    },
    RoundedHighAccumulate {
        subtract: bool,
    },
    Complex {
        rounded: bool,
    },
}

impl Kind {
    pub const fn widening(self) -> bool {
        matches!(
            self,
            Self::Long { .. } | Self::Polynomial { widening: true, .. }
        )
    }
    pub const fn accumulating(self) -> bool {
        matches!(
            self,
            Self::Accumulate { .. }
                | Self::RoundedHighAccumulate { .. }
                | Self::Complex { .. }
                | Self::Long {
                    accumulate: Accumulate::Add | Accumulate::Subtract,
                    ..
                }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Multiplier {
    Vector {
        register: u8,
        segment_lane: Option<u8>,
    },
    Immediate(i8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub source: u8,
    pub multiplier: Multiplier,
    pub accumulator: Option<u8>,
    /// Destination width, including widening forms whose source width is half.
    pub element_size: ElementSize,
    pub predication: Predication,
    pub rotation_degrees: u16,
}

#[derive(Clone, Copy)]
enum Format {
    PredicatedBinary,
    PredicatedAccumulator,
    PredicatedMultiplicand,
    Immediate,
    Vector,
    IndexedHalfword,
    IndexedWord,
    IndexedDoubleword,
    IndexedLongWord,
    IndexedLongDoubleword,
    Complex,
    IndexedComplexHalfword,
    IndexedComplexWord,
}

pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let (kind, format) = classify(word)?;
    let element_size = match format {
        Format::IndexedHalfword | Format::IndexedComplexHalfword => ElementSize::Halfword,
        Format::IndexedWord | Format::IndexedLongWord | Format::IndexedComplexWord => {
            ElementSize::Word
        }
        Format::IndexedDoubleword | Format::IndexedLongDoubleword => ElementSize::Doubleword,
        _ => match (word >> SIZE_SHIFT) & SIZE_MASK {
            0 => ElementSize::Byte,
            1 => ElementSize::Halfword,
            2 => ElementSize::Word,
            _ => ElementSize::Doubleword,
        },
    };
    if kind.widening() && element_size == ElementSize::Byte {
        return Some(Err(()));
    }
    if matches!(kind, Kind::Polynomial { widening: true, .. }) && element_size == ElementSize::Word
    {
        return Some(Err(()));
    }
    let destination = (word & REGISTER_MASK) as u8;
    let source_field = ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8;
    let source = if matches!(
        format,
        Format::PredicatedBinary | Format::PredicatedMultiplicand | Format::Immediate
    ) {
        destination
    } else {
        source_field
    };
    let accumulator = if matches!(format, Format::PredicatedMultiplicand) {
        Some(source_field)
    } else if kind.accumulating() {
        Some(destination)
    } else {
        None
    };
    let predication = if matches!(
        format,
        Format::PredicatedBinary | Format::PredicatedAccumulator | Format::PredicatedMultiplicand
    ) {
        Predication::Merging(((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8)
    } else {
        Predication::Unpredicated
    };
    let multiplier = if matches!(format, Format::Immediate) {
        Multiplier::Immediate(((word >> SOURCE_SHIFT) & IMMEDIATE_MASK) as u8 as i8)
    } else {
        let register_mask = match format {
            Format::IndexedHalfword
            | Format::IndexedWord
            | Format::IndexedLongWord
            | Format::IndexedComplexHalfword => NARROW_REGISTER_MASK,
            Format::IndexedDoubleword
            | Format::IndexedLongDoubleword
            | Format::IndexedComplexWord => DOUBLEWORD_INDEX_REGISTER_MASK,
            _ => REGISTER_MASK,
        };
        let shift = if matches!(format, Format::PredicatedBinary) {
            SOURCE_SHIFT
        } else {
            MULTIPLIER_SHIFT
        };
        let segment_lane = match format {
            Format::IndexedHalfword => Some(
                (((word >> INDEX_HIGH_SHIFT) & INDEX_ONE_BIT) << 2
                    | ((word >> INDEX_LOW_SHIFT) & INDEX_TWO_BITS)) as u8,
            ),
            Format::IndexedWord | Format::IndexedComplexHalfword => {
                Some(((word >> INDEX_LOW_SHIFT) & INDEX_TWO_BITS) as u8)
            }
            Format::IndexedDoubleword | Format::IndexedComplexWord => {
                Some(((word >> INDEX_DOUBLEWORD_SHIFT) & INDEX_ONE_BIT) as u8)
            }
            Format::IndexedLongWord => Some(
                (((word >> INDEX_LOW_SHIFT) & INDEX_TWO_BITS) << 1
                    | ((word >> INDEX_LONG_LOW_SHIFT) & INDEX_ONE_BIT)) as u8,
            ),
            Format::IndexedLongDoubleword => Some(
                (((word >> INDEX_DOUBLEWORD_SHIFT) & INDEX_ONE_BIT) << 1
                    | ((word >> INDEX_LONG_LOW_SHIFT) & INDEX_ONE_BIT)) as u8,
            ),
            _ => None,
        };
        Multiplier::Vector {
            register: ((word >> shift) & register_mask) as u8,
            segment_lane,
        }
    };
    let rotation_degrees = if matches!(kind, Kind::Complex { .. }) {
        ((word >> ROTATION_SHIFT) & ROTATION_MASK) as u16 * QUARTER_TURN_DEGREES
    } else {
        0
    };
    Some(Ok(Operand {
        kind,
        destination,
        source,
        multiplier,
        accumulator,
        element_size,
        predication,
        rotation_degrees,
    }))
}

const CMLA_KIND: Kind = Kind::Complex { rounded: false };
const MAD_KIND: Kind = Kind::Accumulate { subtract: false };
const MLA_KIND: Kind = Kind::Accumulate { subtract: false };
const MLS_KIND: Kind = Kind::Accumulate { subtract: true };
const MSB_KIND: Kind = Kind::Accumulate { subtract: true };
const MUL_KIND: Kind = Kind::Multiply;
const PMUL_KIND: Kind = Kind::Polynomial {
    widening: false,
    selection: Selection::Bottom,
};
const PMULLB_KIND: Kind = Kind::Polynomial {
    widening: true,
    selection: Selection::Bottom,
};
const PMULLT_KIND: Kind = Kind::Polynomial {
    widening: true,
    selection: Selection::Top,
};
const SMLALB_KIND: Kind = Kind::Long {
    signed: true,
    doubling: false,
    accumulate: Accumulate::Add,
    selection: Selection::Bottom,
};
const SMLALT_KIND: Kind = Kind::Long {
    signed: true,
    doubling: false,
    accumulate: Accumulate::Add,
    selection: Selection::Top,
};
const SMLSLB_KIND: Kind = Kind::Long {
    signed: true,
    doubling: false,
    accumulate: Accumulate::Subtract,
    selection: Selection::Bottom,
};
const SMLSLT_KIND: Kind = Kind::Long {
    signed: true,
    doubling: false,
    accumulate: Accumulate::Subtract,
    selection: Selection::Top,
};
const SMULH_KIND: Kind = Kind::MultiplyHigh { signed: true };
const SMULLB_KIND: Kind = Kind::Long {
    signed: true,
    doubling: false,
    accumulate: Accumulate::None,
    selection: Selection::Bottom,
};
const SMULLT_KIND: Kind = Kind::Long {
    signed: true,
    doubling: false,
    accumulate: Accumulate::None,
    selection: Selection::Top,
};
const SQDMLALB_KIND: Kind = Kind::Long {
    signed: true,
    doubling: true,
    accumulate: Accumulate::Add,
    selection: Selection::Bottom,
};
const SQDMLALBT_KIND: Kind = Kind::Long {
    signed: true,
    doubling: true,
    accumulate: Accumulate::Add,
    selection: Selection::Cross,
};
const SQDMLALT_KIND: Kind = Kind::Long {
    signed: true,
    doubling: true,
    accumulate: Accumulate::Add,
    selection: Selection::Top,
};
const SQDMLSLB_KIND: Kind = Kind::Long {
    signed: true,
    doubling: true,
    accumulate: Accumulate::Subtract,
    selection: Selection::Bottom,
};
const SQDMLSLBT_KIND: Kind = Kind::Long {
    signed: true,
    doubling: true,
    accumulate: Accumulate::Subtract,
    selection: Selection::Cross,
};
const SQDMLSLT_KIND: Kind = Kind::Long {
    signed: true,
    doubling: true,
    accumulate: Accumulate::Subtract,
    selection: Selection::Top,
};
const SQDMULH_KIND: Kind = Kind::DoublingHigh { rounding: false };
const SQDMULLB_KIND: Kind = Kind::Long {
    signed: true,
    doubling: true,
    accumulate: Accumulate::None,
    selection: Selection::Bottom,
};
const SQDMULLT_KIND: Kind = Kind::Long {
    signed: true,
    doubling: true,
    accumulate: Accumulate::None,
    selection: Selection::Top,
};
const SQRDCMLAH_KIND: Kind = Kind::Complex { rounded: true };
const SQRDMLAH_KIND: Kind = Kind::RoundedHighAccumulate { subtract: false };
const SQRDMLSH_KIND: Kind = Kind::RoundedHighAccumulate { subtract: true };
const SQRDMULH_KIND: Kind = Kind::DoublingHigh { rounding: true };
const UMLALB_KIND: Kind = Kind::Long {
    signed: false,
    doubling: false,
    accumulate: Accumulate::Add,
    selection: Selection::Bottom,
};
const UMLALT_KIND: Kind = Kind::Long {
    signed: false,
    doubling: false,
    accumulate: Accumulate::Add,
    selection: Selection::Top,
};
const UMLSLB_KIND: Kind = Kind::Long {
    signed: false,
    doubling: false,
    accumulate: Accumulate::Subtract,
    selection: Selection::Bottom,
};
const UMLSLT_KIND: Kind = Kind::Long {
    signed: false,
    doubling: false,
    accumulate: Accumulate::Subtract,
    selection: Selection::Top,
};
const UMULH_KIND: Kind = Kind::MultiplyHigh { signed: false };
const UMULLB_KIND: Kind = Kind::Long {
    signed: false,
    doubling: false,
    accumulate: Accumulate::None,
    selection: Selection::Bottom,
};
const UMULLT_KIND: Kind = Kind::Long {
    signed: false,
    doubling: false,
    accumulate: Accumulate::None,
    selection: Selection::Top,
};

fn classify(word: u32) -> Option<(Kind, Format)> {
    let decoded = match word & COMPLEX_MASK {
        CMLA_Z_ZZZ => Some((CMLA_KIND, Format::Complex)),
        SQRDCMLAH_Z_ZZZ => Some((SQRDCMLAH_KIND, Format::Complex)),
        _ => None,
    };
    if decoded.is_some() {
        return decoded;
    }
    let decoded = match word & INDEXED_COMPLEX_MASK {
        CMLA_Z_ZZZI_H => Some((CMLA_KIND, Format::IndexedComplexHalfword)),
        CMLA_Z_ZZZI_S => Some((CMLA_KIND, Format::IndexedComplexWord)),
        SQRDCMLAH_Z_ZZZI_H => Some((SQRDCMLAH_KIND, Format::IndexedComplexHalfword)),
        SQRDCMLAH_Z_ZZZI_S => Some((SQRDCMLAH_KIND, Format::IndexedComplexWord)),
        _ => None,
    };
    if decoded.is_some() {
        return decoded;
    }
    let decoded = match word & PREDICATED_TERNARY_MASK {
        MAD_Z_P_ZZZ => Some((MAD_KIND, Format::PredicatedMultiplicand)),
        MLA_Z_P_ZZZ => Some((MLA_KIND, Format::PredicatedAccumulator)),
        MLS_Z_P_ZZZ => Some((MLS_KIND, Format::PredicatedAccumulator)),
        MSB_Z_P_ZZZ => Some((MSB_KIND, Format::PredicatedMultiplicand)),
        _ => None,
    };
    if decoded.is_some() {
        return decoded;
    }
    let decoded = match word & INDEXED_WORD_MASK {
        MLA_Z_ZZZI_D => Some((MLA_KIND, Format::IndexedDoubleword)),
        MLA_Z_ZZZI_S => Some((MLA_KIND, Format::IndexedWord)),
        MLS_Z_ZZZI_D => Some((MLS_KIND, Format::IndexedDoubleword)),
        MLS_Z_ZZZI_S => Some((MLS_KIND, Format::IndexedWord)),
        MUL_Z_ZZI_D => Some((MUL_KIND, Format::IndexedDoubleword)),
        MUL_Z_ZZI_S => Some((MUL_KIND, Format::IndexedWord)),
        PMUL_Z_ZZ => Some((PMUL_KIND, Format::Vector)),
        SQDMULH_Z_ZZI_D => Some((SQDMULH_KIND, Format::IndexedDoubleword)),
        SQDMULH_Z_ZZI_S => Some((SQDMULH_KIND, Format::IndexedWord)),
        SQRDMLAH_Z_ZZZI_D => Some((SQRDMLAH_KIND, Format::IndexedDoubleword)),
        SQRDMLAH_Z_ZZZI_S => Some((SQRDMLAH_KIND, Format::IndexedWord)),
        SQRDMLSH_Z_ZZZI_D => Some((SQRDMLSH_KIND, Format::IndexedDoubleword)),
        SQRDMLSH_Z_ZZZI_S => Some((SQRDMLSH_KIND, Format::IndexedWord)),
        SQRDMULH_Z_ZZI_D => Some((SQRDMULH_KIND, Format::IndexedDoubleword)),
        SQRDMULH_Z_ZZI_S => Some((SQRDMULH_KIND, Format::IndexedWord)),
        _ => None,
    };
    if decoded.is_some() {
        return decoded;
    }
    let decoded = match word & INDEXED_HALFWORD_MASK {
        MLA_Z_ZZZI_H => Some((MLA_KIND, Format::IndexedHalfword)),
        MLS_Z_ZZZI_H => Some((MLS_KIND, Format::IndexedHalfword)),
        MUL_Z_ZZI_H => Some((MUL_KIND, Format::IndexedHalfword)),
        SQDMULH_Z_ZZI_H => Some((SQDMULH_KIND, Format::IndexedHalfword)),
        SQRDMLAH_Z_ZZZI_H => Some((SQRDMLAH_KIND, Format::IndexedHalfword)),
        SQRDMLSH_Z_ZZZI_H => Some((SQRDMLSH_KIND, Format::IndexedHalfword)),
        SQRDMULH_Z_ZZI_H => Some((SQRDMULH_KIND, Format::IndexedHalfword)),
        _ => None,
    };
    if decoded.is_some() {
        return decoded;
    }
    let decoded = match word & PREDICATED_BINARY_MASK {
        MUL_Z_P_ZZ => Some((MUL_KIND, Format::PredicatedBinary)),
        MUL_Z_ZI => Some((MUL_KIND, Format::Immediate)),
        SMULH_Z_P_ZZ => Some((SMULH_KIND, Format::PredicatedBinary)),
        UMULH_Z_P_ZZ => Some((UMULH_KIND, Format::PredicatedBinary)),
        _ => None,
    };
    if decoded.is_some() {
        return decoded;
    }
    let decoded = match word & VECTOR_MASK {
        MUL_Z_ZZ => Some((MUL_KIND, Format::Vector)),
        PMULLB_Z_ZZ => Some((PMULLB_KIND, Format::Vector)),
        PMULLT_Z_ZZ => Some((PMULLT_KIND, Format::Vector)),
        SMLALB_Z_ZZZ => Some((SMLALB_KIND, Format::Vector)),
        SMLALT_Z_ZZZ => Some((SMLALT_KIND, Format::Vector)),
        SMLSLB_Z_ZZZ => Some((SMLSLB_KIND, Format::Vector)),
        SMLSLT_Z_ZZZ => Some((SMLSLT_KIND, Format::Vector)),
        SMULH_Z_ZZ => Some((SMULH_KIND, Format::Vector)),
        SMULLB_Z_ZZ => Some((SMULLB_KIND, Format::Vector)),
        SMULLT_Z_ZZ => Some((SMULLT_KIND, Format::Vector)),
        SQDMLALB_Z_ZZZ => Some((SQDMLALB_KIND, Format::Vector)),
        SQDMLALBT_Z_ZZZ => Some((SQDMLALBT_KIND, Format::Vector)),
        SQDMLALT_Z_ZZZ => Some((SQDMLALT_KIND, Format::Vector)),
        SQDMLSLB_Z_ZZZ => Some((SQDMLSLB_KIND, Format::Vector)),
        SQDMLSLBT_Z_ZZZ => Some((SQDMLSLBT_KIND, Format::Vector)),
        SQDMLSLT_Z_ZZZ => Some((SQDMLSLT_KIND, Format::Vector)),
        SQDMULH_Z_ZZ => Some((SQDMULH_KIND, Format::Vector)),
        SQDMULLB_Z_ZZ => Some((SQDMULLB_KIND, Format::Vector)),
        SQDMULLT_Z_ZZ => Some((SQDMULLT_KIND, Format::Vector)),
        SQRDMLAH_Z_ZZZ => Some((SQRDMLAH_KIND, Format::Vector)),
        SQRDMLSH_Z_ZZZ => Some((SQRDMLSH_KIND, Format::Vector)),
        SQRDMULH_Z_ZZ => Some((SQRDMULH_KIND, Format::Vector)),
        UMLALB_Z_ZZZ => Some((UMLALB_KIND, Format::Vector)),
        UMLALT_Z_ZZZ => Some((UMLALT_KIND, Format::Vector)),
        UMLSLB_Z_ZZZ => Some((UMLSLB_KIND, Format::Vector)),
        UMLSLT_Z_ZZZ => Some((UMLSLT_KIND, Format::Vector)),
        UMULH_Z_ZZ => Some((UMULH_KIND, Format::Vector)),
        UMULLB_Z_ZZ => Some((UMULLB_KIND, Format::Vector)),
        UMULLT_Z_ZZ => Some((UMULLT_KIND, Format::Vector)),
        _ => None,
    };
    if decoded.is_some() {
        return decoded;
    }
    let decoded = match word & INDEXED_LONG_MASK {
        SMLALB_Z_ZZZI_D => Some((SMLALB_KIND, Format::IndexedLongDoubleword)),
        SMLALB_Z_ZZZI_S => Some((SMLALB_KIND, Format::IndexedLongWord)),
        SMLALT_Z_ZZZI_D => Some((SMLALT_KIND, Format::IndexedLongDoubleword)),
        SMLALT_Z_ZZZI_S => Some((SMLALT_KIND, Format::IndexedLongWord)),
        SMLSLB_Z_ZZZI_D => Some((SMLSLB_KIND, Format::IndexedLongDoubleword)),
        SMLSLB_Z_ZZZI_S => Some((SMLSLB_KIND, Format::IndexedLongWord)),
        SMLSLT_Z_ZZZI_D => Some((SMLSLT_KIND, Format::IndexedLongDoubleword)),
        SMLSLT_Z_ZZZI_S => Some((SMLSLT_KIND, Format::IndexedLongWord)),
        SMULLB_Z_ZZI_D => Some((SMULLB_KIND, Format::IndexedLongDoubleword)),
        SMULLB_Z_ZZI_S => Some((SMULLB_KIND, Format::IndexedLongWord)),
        SMULLT_Z_ZZI_D => Some((SMULLT_KIND, Format::IndexedLongDoubleword)),
        SMULLT_Z_ZZI_S => Some((SMULLT_KIND, Format::IndexedLongWord)),
        SQDMLALB_Z_ZZZI_D => Some((SQDMLALB_KIND, Format::IndexedLongDoubleword)),
        SQDMLALB_Z_ZZZI_S => Some((SQDMLALB_KIND, Format::IndexedLongWord)),
        SQDMLALT_Z_ZZZI_D => Some((SQDMLALT_KIND, Format::IndexedLongDoubleword)),
        SQDMLALT_Z_ZZZI_S => Some((SQDMLALT_KIND, Format::IndexedLongWord)),
        SQDMLSLB_Z_ZZZI_D => Some((SQDMLSLB_KIND, Format::IndexedLongDoubleword)),
        SQDMLSLB_Z_ZZZI_S => Some((SQDMLSLB_KIND, Format::IndexedLongWord)),
        SQDMLSLT_Z_ZZZI_D => Some((SQDMLSLT_KIND, Format::IndexedLongDoubleword)),
        SQDMLSLT_Z_ZZZI_S => Some((SQDMLSLT_KIND, Format::IndexedLongWord)),
        SQDMULLB_Z_ZZI_D => Some((SQDMULLB_KIND, Format::IndexedLongDoubleword)),
        SQDMULLB_Z_ZZI_S => Some((SQDMULLB_KIND, Format::IndexedLongWord)),
        SQDMULLT_Z_ZZI_D => Some((SQDMULLT_KIND, Format::IndexedLongDoubleword)),
        SQDMULLT_Z_ZZI_S => Some((SQDMULLT_KIND, Format::IndexedLongWord)),
        UMLALB_Z_ZZZI_D => Some((UMLALB_KIND, Format::IndexedLongDoubleword)),
        UMLALB_Z_ZZZI_S => Some((UMLALB_KIND, Format::IndexedLongWord)),
        UMLALT_Z_ZZZI_D => Some((UMLALT_KIND, Format::IndexedLongDoubleword)),
        UMLALT_Z_ZZZI_S => Some((UMLALT_KIND, Format::IndexedLongWord)),
        UMLSLB_Z_ZZZI_D => Some((UMLSLB_KIND, Format::IndexedLongDoubleword)),
        UMLSLB_Z_ZZZI_S => Some((UMLSLB_KIND, Format::IndexedLongWord)),
        UMLSLT_Z_ZZZI_D => Some((UMLSLT_KIND, Format::IndexedLongDoubleword)),
        UMLSLT_Z_ZZZI_S => Some((UMLSLT_KIND, Format::IndexedLongWord)),
        UMULLB_Z_ZZI_D => Some((UMULLB_KIND, Format::IndexedLongDoubleword)),
        UMULLB_Z_ZZI_S => Some((UMULLB_KIND, Format::IndexedLongWord)),
        UMULLT_Z_ZZI_D => Some((UMULLT_KIND, Format::IndexedLongDoubleword)),
        UMULLT_Z_ZZI_S => Some((UMULLT_KIND, Format::IndexedLongWord)),
        _ => None,
    };
    if decoded.is_some() {
        return decoded;
    }
    None
}

impl Operand {
    /// MOVPRFX requirements of the follower word, independent of the normalized
    /// kind. Unlisted encodings are refused.
    #[allow(clippy::result_unit_err)]
    pub fn prefix_requirement(
        self,
        original_word: u32,
    ) -> Result<Option<crate::aarch64::sve::prefix::PrefixRequirement>, ()> {
        use crate::aarch64::sve::prefix::{PredicatedPrefixRequirement, PrefixRequirement};

        if decode(original_word) != Some(Ok(self)) {
            return Err(());
        }
        let source_bit = |register: u8| 1_u32 << register;
        let multiplier_mask = match self.multiplier {
            Multiplier::Vector { register, .. } => source_bit(register),
            Multiplier::Immediate(_) => 0,
        };
        let predicated = match self.predication {
            Predication::Merging(predicate) => Some(PredicatedPrefixRequirement {
                predicate,
                element: self.element_size,
            }),
            Predication::Unpredicated | Predication::Zeroing(_) => None,
        };
        let vector = |predicated, other_vector_sources| PrefixRequirement::Vector {
            destination: self.destination,
            predicated,
            other_vector_sources,
        };
        if matches!(original_word & COMPLEX_MASK, CMLA_Z_ZZZ | SQRDCMLAH_Z_ZZZ) {
            return Ok(Some(vector(
                None,
                source_bit(self.source) | multiplier_mask,
            )));
        }
        if matches!(
            original_word & INDEXED_COMPLEX_MASK,
            CMLA_Z_ZZZI_H | CMLA_Z_ZZZI_S | SQRDCMLAH_Z_ZZZI_H | SQRDCMLAH_Z_ZZZI_S
        ) {
            return Ok(Some(vector(
                None,
                source_bit(self.source) | multiplier_mask,
            )));
        }
        if matches!(
            original_word & PREDICATED_TERNARY_MASK,
            MAD_Z_P_ZZZ | MSB_Z_P_ZZZ
        ) {
            return Ok(Some(vector(
                predicated,
                multiplier_mask | source_bit(self.accumulator.ok_or(())?),
            )));
        }
        if matches!(
            original_word & PREDICATED_TERNARY_MASK,
            MLA_Z_P_ZZZ | MLS_Z_P_ZZZ
        ) {
            return Ok(Some(vector(
                predicated,
                source_bit(self.source) | multiplier_mask,
            )));
        }
        if matches!(
            original_word & INDEXED_WORD_MASK,
            MLA_Z_ZZZI_D
                | MLA_Z_ZZZI_S
                | MLS_Z_ZZZI_D
                | MLS_Z_ZZZI_S
                | SQRDMLAH_Z_ZZZI_D
                | SQRDMLAH_Z_ZZZI_S
                | SQRDMLSH_Z_ZZZI_D
                | SQRDMLSH_Z_ZZZI_S
        ) {
            return Ok(Some(vector(
                None,
                source_bit(self.source) | multiplier_mask,
            )));
        }
        if matches!(
            original_word & INDEXED_HALFWORD_MASK,
            MLA_Z_ZZZI_H | MLS_Z_ZZZI_H | SQRDMLAH_Z_ZZZI_H | SQRDMLSH_Z_ZZZI_H
        ) {
            return Ok(Some(vector(
                None,
                source_bit(self.source) | multiplier_mask,
            )));
        }
        if matches!(
            original_word & PREDICATED_BINARY_MASK,
            MUL_Z_P_ZZ | SMULH_Z_P_ZZ | UMULH_Z_P_ZZ
        ) {
            return Ok(Some(vector(predicated, multiplier_mask)));
        }
        if matches!(original_word & PREDICATED_BINARY_MASK, MUL_Z_ZI) {
            return Ok(Some(vector(None, 0)));
        }
        if matches!(
            original_word & VECTOR_MASK,
            MUL_Z_ZZ
                | PMULLB_Z_ZZ
                | PMULLT_Z_ZZ
                | SMULH_Z_ZZ
                | SMULLB_Z_ZZ
                | SMULLT_Z_ZZ
                | SQDMULH_Z_ZZ
                | SQDMULLB_Z_ZZ
                | SQDMULLT_Z_ZZ
                | SQRDMULH_Z_ZZ
                | UMULH_Z_ZZ
                | UMULLB_Z_ZZ
                | UMULLT_Z_ZZ
        ) {
            return Ok(Some(PrefixRequirement::Forbidden));
        }
        if matches!(
            original_word & INDEXED_WORD_MASK,
            MUL_Z_ZZI_D
                | MUL_Z_ZZI_S
                | PMUL_Z_ZZ
                | SQDMULH_Z_ZZI_D
                | SQDMULH_Z_ZZI_S
                | SQRDMULH_Z_ZZI_D
                | SQRDMULH_Z_ZZI_S
        ) {
            return Ok(Some(PrefixRequirement::Forbidden));
        }
        if matches!(
            original_word & INDEXED_HALFWORD_MASK,
            MUL_Z_ZZI_H | SQDMULH_Z_ZZI_H | SQRDMULH_Z_ZZI_H
        ) {
            return Ok(Some(PrefixRequirement::Forbidden));
        }
        if matches!(
            original_word & VECTOR_MASK,
            SMLALB_Z_ZZZ
                | SMLALT_Z_ZZZ
                | SMLSLB_Z_ZZZ
                | SMLSLT_Z_ZZZ
                | SQDMLALB_Z_ZZZ
                | SQDMLALBT_Z_ZZZ
                | SQDMLALT_Z_ZZZ
                | SQDMLSLB_Z_ZZZ
                | SQDMLSLBT_Z_ZZZ
                | SQDMLSLT_Z_ZZZ
                | SQRDMLAH_Z_ZZZ
                | SQRDMLSH_Z_ZZZ
                | UMLALB_Z_ZZZ
                | UMLALT_Z_ZZZ
                | UMLSLB_Z_ZZZ
                | UMLSLT_Z_ZZZ
        ) {
            return Ok(Some(vector(
                None,
                source_bit(self.source) | multiplier_mask,
            )));
        }
        if matches!(
            original_word & INDEXED_LONG_MASK,
            SMLALB_Z_ZZZI_D
                | SMLALB_Z_ZZZI_S
                | SMLALT_Z_ZZZI_D
                | SMLALT_Z_ZZZI_S
                | SMLSLB_Z_ZZZI_D
                | SMLSLB_Z_ZZZI_S
                | SMLSLT_Z_ZZZI_D
                | SMLSLT_Z_ZZZI_S
                | SQDMLALB_Z_ZZZI_D
                | SQDMLALB_Z_ZZZI_S
                | SQDMLALT_Z_ZZZI_D
                | SQDMLALT_Z_ZZZI_S
                | SQDMLSLB_Z_ZZZI_D
                | SQDMLSLB_Z_ZZZI_S
                | SQDMLSLT_Z_ZZZI_D
                | SQDMLSLT_Z_ZZZI_S
                | UMLALB_Z_ZZZI_D
                | UMLALB_Z_ZZZI_S
                | UMLALT_Z_ZZZI_D
                | UMLALT_Z_ZZZI_S
                | UMLSLB_Z_ZZZI_D
                | UMLSLB_Z_ZZZI_S
                | UMLSLT_Z_ZZZI_D
                | UMLSLT_Z_ZZZI_S
        ) {
            return Ok(Some(vector(
                None,
                source_bit(self.source) | multiplier_mask,
            )));
        }
        if matches!(
            original_word & INDEXED_LONG_MASK,
            SMULLB_Z_ZZI_D
                | SMULLB_Z_ZZI_S
                | SMULLT_Z_ZZI_D
                | SMULLT_Z_ZZI_S
                | SQDMULLB_Z_ZZI_D
                | SQDMULLB_Z_ZZI_S
                | SQDMULLT_Z_ZZI_D
                | SQDMULLT_Z_ZZI_S
                | UMULLB_Z_ZZI_D
                | UMULLB_Z_ZZI_S
                | UMULLT_Z_ZZI_D
                | UMULLT_Z_ZZI_S
        ) {
            return Ok(Some(PrefixRequirement::Forbidden));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicated_mad_keeps_destination_as_multiplicand_and_za_as_accumulator() {
        let destination = 31;
        let multiplier = 23;
        let accumulator = 19;
        let predicate = 7;
        let word = MAD_Z_P_ZZZ
            | (2 << SIZE_SHIFT)
            | (multiplier << MULTIPLIER_SHIFT)
            | (predicate << PREDICATE_SHIFT)
            | (accumulator << SOURCE_SHIFT)
            | destination;
        assert_eq!(
            decode(word),
            Some(Ok(Operand {
                kind: Kind::Accumulate { subtract: false },
                destination: destination as u8,
                source: destination as u8,
                multiplier: Multiplier::Vector {
                    register: multiplier as u8,
                    segment_lane: None
                },
                accumulator: Some(accumulator as u8),
                element_size: ElementSize::Word,
                predication: Predication::Merging(predicate as u8),
                rotation_degrees: 0,
            }))
        );
    }

    #[test]
    fn indexed_halfword_and_long_fields_have_distinct_bit_splits() {
        for index in 0..8 {
            for multiplier in 0..8 {
                let normal = MUL_Z_ZZI_H
                    | ((index >> 2) << INDEX_HIGH_SHIFT)
                    | ((index & INDEX_TWO_BITS) << INDEX_LOW_SHIFT)
                    | (multiplier << MULTIPLIER_SHIFT);
                let long = SMULLT_Z_ZZI_S
                    | ((index >> 1) << INDEX_LOW_SHIFT)
                    | ((index & INDEX_ONE_BIT) << INDEX_LONG_LOW_SHIFT)
                    | (multiplier << MULTIPLIER_SHIFT);
                for (word, element) in [(normal, ElementSize::Halfword), (long, ElementSize::Word)]
                {
                    let operand = decode(word).unwrap().unwrap();
                    assert_eq!(operand.element_size, element);
                    assert_eq!(
                        operand.multiplier,
                        Multiplier::Vector {
                            register: multiplier as u8,
                            segment_lane: Some(index as u8),
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn long_byte_allocations_decline_and_cross_selector_is_explicit() {
        for opcode in [
            SMULLB_Z_ZZ,
            SMULLT_Z_ZZ,
            UMULLB_Z_ZZ,
            UMULLT_Z_ZZ,
            SMLALB_Z_ZZZ,
            SMLALT_Z_ZZZ,
            SQDMLALBT_Z_ZZZ,
            SQDMLSLBT_Z_ZZZ,
            SQDMULLB_Z_ZZ,
            SQDMULLT_Z_ZZ,
        ] {
            assert_eq!(decode(opcode), Some(Err(())));
        }
        let cross = decode(SQDMLALBT_Z_ZZZ | (1 << SIZE_SHIFT))
            .unwrap()
            .unwrap();
        assert_eq!(
            cross.kind,
            Kind::Long {
                signed: true,
                doubling: true,
                accumulate: Accumulate::Add,
                selection: Selection::Cross
            }
        );
    }

    #[test]
    fn signed_immediate_and_complex_rotation_preserve_operand_roles() {
        let immediate = decode(MUL_Z_ZI | (IMMEDIATE_MASK << SOURCE_SHIFT) | REGISTER_MASK)
            .unwrap()
            .unwrap();
        assert_eq!(immediate.multiplier, Multiplier::Immediate(-1));
        assert_eq!(immediate.source, 31);
        for rotation in 0..=ROTATION_MASK {
            let complex = decode(CMLA_Z_ZZZ | (rotation << ROTATION_SHIFT))
                .unwrap()
                .unwrap();
            assert_eq!(
                complex.rotation_degrees,
                rotation as u16 * QUARTER_TURN_DEGREES
            );
            assert_eq!(complex.accumulator, Some(complex.destination));
        }
        assert_eq!(decode(0), None);
    }
}
