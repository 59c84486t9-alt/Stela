//! Scalar and AdvSIMD conversions between H/S/D and integers (FCVT*, SCVTF, UCVTF).
use crate::aarch64::Unsupported;
use crate::aarch64::{
    Register,
    floating::{
        Format,
        integer::{IntegerFormat, IntegerRounding, IntegerWidth},
        precision::PrecisionRounding,
    },
};

use super::arithmetic::Shape;

const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const FORMAT_SHIFT: u32 = 22;
const FORMAT_MASK: u32 = 3;
const FORMAT_SINGLE: u32 = 0;
const FORMAT_DOUBLE: u32 = 1;
const FORMAT_HALF: u32 = 3;
const GENERAL_WIDE: u32 = 1 << 31;
const GENERAL_UNSIGNED: u32 = 1 << 16;
const VECTOR_Q: u32 = 1 << 30;
const SIMD_UNSIGNED: u32 = 1 << 29;
const SIMD_DOUBLE: u32 = 1 << 22;
const SIMD_SCALAR_PREFIX: u32 = 0x50000000;
const SIMD_HALF_ADJUSTMENT: u32 = 0x00580000;
const SCALE_SHIFT: u32 = 10;
const SCALE_MASK: u32 = 63;
const SCALE_BIAS: u32 = 64;
const IMMEDIATE_SHIFT: u32 = 16;
const IMMEDIATE_MASK: u32 = 127;
const IMMEDIATE_SHIFT_CLASS_MINIMUM: u32 = 8;
const IMMEDIATE_HALF_MINIMUM: u32 = 16;
const IMMEDIATE_SINGLE_MINIMUM: u32 = 32;
const IMMEDIATE_DOUBLE_MINIMUM: u32 = 64;

const SCALAR_PRECISION_MASK: u32 = 0xff3e7c00;
const SCALAR_FCVT: u32 = 0x1e224000;
const DESTINATION_FORMAT_SHIFT: u32 = 15;
const VECTOR_PRECISION_MASK: u32 = 0xbfbffc00;
const FCVTL: u32 = 0x0e217800;
const FCVTN: u32 = 0x0e216800;
const VECTOR_ODD_MASK: u32 = 0xbffffc00;
const VECTOR_FCVTXN: u32 = 0x2e616800;
const SCALAR_EXACT_MASK: u32 = 0xfffffc00;
const SCALAR_FCVTXN: u32 = 0x7e616800;
const BFCVT: u32 = 0x1e634000;
const FJCVTZS: u32 = 0x1e7e0000;

const GENERAL_INTEGER_MASK: u32 = 0x7f3efc00;
const GENERAL_SCVTF: u32 = 0x1e220000;
const GENERAL_FCVTNS: u32 = 0x1e200000;
const GENERAL_FCVTAS: u32 = 0x1e240000;
const GENERAL_FCVTPS: u32 = 0x1e280000;
const GENERAL_FCVTMS: u32 = 0x1e300000;
const GENERAL_FCVTZS: u32 = 0x1e380000;
const GENERAL_FIXED_MASK: u32 = 0x7f3e0000;
const GENERAL_FIXED_SCVTF: u32 = 0x1e020000;
const GENERAL_FIXED_FCVTZS: u32 = 0x1e180000;

const SIMD_SCALAR_MASK: u32 = 0xdfbffc00;
const SIMD_VECTOR_MASK: u32 = 0x9fbffc00;
const SIMD_SCALAR_HALF_MASK: u32 = 0xdffffc00;
const SIMD_VECTOR_HALF_MASK: u32 = 0x9ffffc00;
const SIMD_SCVTF: u32 = 0x0e21d800;
const SIMD_FCVTNS: u32 = 0x0e21a800;
const SIMD_FCVTAS: u32 = 0x0e21c800;
const SIMD_FCVTPS: u32 = 0x0ea1a800;
const SIMD_FCVTMS: u32 = 0x0e21b800;
const SIMD_FCVTZS: u32 = 0x0ea1b800;
const SIMD_SCALAR_FIXED_MASK: u32 = 0xdf80fc00;
const SIMD_VECTOR_FIXED_MASK: u32 = 0x9f80fc00;
const SIMD_FIXED_SCVTF: u32 = 0x0f00e400;
const SIMD_FIXED_FCVTZS: u32 = 0x0f00fc00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecisionMode {
    Scalar {
        source: Format,
        destination: Format,
        rounding: PrecisionRounding,
    },
    Widen {
        source: Format,
        upper: bool,
    },
    Narrow {
        destination: Format,
        upper: bool,
        rounding: PrecisionRounding,
    },
}

impl PrecisionMode {
    pub const fn source_format(self) -> Format {
        match self {
            Self::Scalar { source, .. } | Self::Widen { source, .. } => source,
            Self::Narrow { destination, .. } => match destination {
                Format::Half => Format::Single,
                Format::Single => Format::Double,
                Format::Double => unreachable!(),
            },
        }
    }

    pub const fn destination_format(self) -> Format {
        match self {
            Self::Scalar { destination, .. } | Self::Narrow { destination, .. } => destination,
            Self::Widen { source, .. } => match source {
                Format::Half => Format::Single,
                Format::Single => Format::Double,
                Format::Double => unreachable!(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecisionOperand {
    pub mode: PrecisionMode,
    pub destination: u8,
    pub source: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerOperand {
    General {
        register: Register,
        format: IntegerFormat,
    },
    Simd {
        register: u8,
        format: IntegerFormat,
        shape: Shape,
    },
}

impl IntegerOperand {
    pub const fn format(self) -> IntegerFormat {
        match self {
            Self::General { format, .. } | Self::Simd { format, .. } => format,
        }
    }

    pub const fn shape(self) -> Shape {
        match self {
            Self::General { .. } => Shape::Scalar,
            Self::Simd { shape, .. } => shape,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegerConversion {
    pub integer: IntegerOperand,
    pub float: u8,
    pub format: Format,
    pub frac_bits: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Precision(PrecisionOperand),
    FromInteger(IntegerConversion),
    ToInteger {
        operand: IntegerConversion,
        rounding: IntegerRounding,
    },
    JavaScript {
        destination: Register,
        source: u8,
    },
}

#[derive(Clone, Copy)]
enum Direction {
    FromInteger,
    ToInteger(IntegerRounding),
}

impl Direction {
    fn operand(self, operand: IntegerConversion) -> Operand {
        match self {
            Self::FromInteger => Operand::FromInteger(operand),
            Self::ToInteger(rounding) => Operand::ToInteger { operand, rounding },
        }
    }
}

fn vector_register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

fn general_register(value: u8) -> Register {
    if u32::from(value) == REGISTER_MASK {
        Register::Zero
    } else {
        Register::X(value)
    }
}

fn format(field: u32) -> Result<Format, Unsupported> {
    match field {
        FORMAT_SINGLE => Ok(Format::Single),
        FORMAT_DOUBLE => Ok(Format::Double),
        FORMAT_HALF => Ok(Format::Half),
        _ => Err(Unsupported),
    }
}

fn vector_shape(word: u32) -> Shape {
    if word & VECTOR_Q == 0 {
        Shape::Vector64
    } else {
        Shape::Vector128
    }
}

fn integer_width(format: Format) -> IntegerWidth {
    match format {
        Format::Half => IntegerWidth::Bits16,
        Format::Single => IntegerWidth::Bits32,
        Format::Double => IntegerWidth::Bits64,
    }
}

/// None denotes another family, including FPRCVT/FP8. Err denotes a reserved
/// field combination in a recognized classic conversion class. All GPR 31
/// operands are ZR; all SIMD 31 operands are ordinary V31.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    decode_precision(word)
        .or_else(|| decode_general(word))
        .or_else(|| decode_simd(word))
        .or_else(|| {
            (word & SCALAR_EXACT_MASK == FJCVTZS).then(|| {
                Ok(Operand::JavaScript {
                    destination: general_register(vector_register(word, 0)),
                    source: vector_register(word, SOURCE_SHIFT),
                })
            })
        })
}

fn decode_precision(word: u32) -> Option<Result<Operand, Unsupported>> {
    if word & SCALAR_EXACT_MASK == BFCVT {
        return None;
    }
    let mode = if word & SCALAR_PRECISION_MASK == SCALAR_FCVT {
        let source = match format((word >> FORMAT_SHIFT) & FORMAT_MASK) {
            Ok(format) => format,
            Err(Unsupported) => return Some(Err(Unsupported)),
        };
        let destination = match format((word >> DESTINATION_FORMAT_SHIFT) & FORMAT_MASK) {
            Ok(format) => format,
            Err(Unsupported) => return Some(Err(Unsupported)),
        };
        if source == destination {
            return Some(Err(Unsupported));
        }
        PrecisionMode::Scalar {
            source,
            destination,
            rounding: PrecisionRounding::Fpcr,
        }
    } else if word & SCALAR_EXACT_MASK == SCALAR_FCVTXN {
        PrecisionMode::Scalar {
            source: Format::Double,
            destination: Format::Single,
            rounding: PrecisionRounding::ToOdd,
        }
    } else if word & VECTOR_ODD_MASK == VECTOR_FCVTXN {
        PrecisionMode::Narrow {
            destination: Format::Single,
            upper: word & VECTOR_Q != 0,
            rounding: PrecisionRounding::ToOdd,
        }
    } else {
        let small = if word & SIMD_DOUBLE == 0 {
            Format::Half
        } else {
            Format::Single
        };
        match word & VECTOR_PRECISION_MASK {
            FCVTL => PrecisionMode::Widen {
                source: small,
                upper: word & VECTOR_Q != 0,
            },
            FCVTN => PrecisionMode::Narrow {
                destination: small,
                upper: word & VECTOR_Q != 0,
                rounding: PrecisionRounding::Fpcr,
            },
            _ => return None,
        }
    };
    Some(Ok(Operand::Precision(PrecisionOperand {
        mode,
        destination: vector_register(word, 0),
        source: vector_register(word, SOURCE_SHIFT),
    })))
}

fn general_direction(opcode: u32) -> Option<Direction> {
    Some(match opcode {
        GENERAL_SCVTF => Direction::FromInteger,
        GENERAL_FCVTNS => Direction::ToInteger(IntegerRounding::NearestEven),
        GENERAL_FCVTAS => Direction::ToInteger(IntegerRounding::NearestAway),
        GENERAL_FCVTPS => Direction::ToInteger(IntegerRounding::TowardPositive),
        GENERAL_FCVTMS => Direction::ToInteger(IntegerRounding::TowardNegative),
        GENERAL_FCVTZS => Direction::ToInteger(IntegerRounding::TowardZero),
        _ => return None,
    })
}

fn decode_general(word: u32) -> Option<Result<Operand, Unsupported>> {
    let (direction, fixed) = if let Some(direction) = general_direction(word & GENERAL_INTEGER_MASK)
    {
        (direction, false)
    } else {
        match word & GENERAL_FIXED_MASK {
            GENERAL_FIXED_SCVTF => (Direction::FromInteger, true),
            GENERAL_FIXED_FCVTZS => (Direction::ToInteger(IntegerRounding::TowardZero), true),
            _ => return None,
        }
    };
    let format = match format((word >> FORMAT_SHIFT) & FORMAT_MASK) {
        Ok(format) => format,
        Err(Unsupported) => return Some(Err(Unsupported)),
    };
    let wide = word & GENERAL_WIDE != 0;
    let frac_bits = if fixed {
        let scale = (word >> SCALE_SHIFT) & SCALE_MASK;
        if !wide && scale < IMMEDIATE_SINGLE_MINIMUM {
            return Some(Err(Unsupported));
        }
        (SCALE_BIAS - scale) as u8
    } else {
        0
    };
    let destination = vector_register(word, 0);
    let source = vector_register(word, SOURCE_SHIFT);
    let (integer, float) = match direction {
        Direction::FromInteger => (source, destination),
        Direction::ToInteger(_) => (destination, source),
    };
    Some(Ok(direction.operand(IntegerConversion {
        integer: IntegerOperand::General {
            register: general_register(integer),
            format: IntegerFormat {
                width: if wide {
                    IntegerWidth::Bits64
                } else {
                    IntegerWidth::Bits32
                },
                signed: word & GENERAL_UNSIGNED == 0,
            },
        },
        float,
        format,
        frac_bits,
    })))
}

fn simd_direction(opcode: u32) -> Option<Direction> {
    Some(match opcode {
        SIMD_SCVTF => Direction::FromInteger,
        SIMD_FCVTNS => Direction::ToInteger(IntegerRounding::NearestEven),
        SIMD_FCVTAS => Direction::ToInteger(IntegerRounding::NearestAway),
        SIMD_FCVTPS => Direction::ToInteger(IntegerRounding::TowardPositive),
        SIMD_FCVTMS => Direction::ToInteger(IntegerRounding::TowardNegative),
        SIMD_FCVTZS => Direction::ToInteger(IntegerRounding::TowardZero),
        _ => return None,
    })
}

fn decode_simd(word: u32) -> Option<Result<Operand, Unsupported>> {
    for (mask, adjustment, scalar, half) in [
        (SIMD_SCALAR_MASK, SIMD_SCALAR_PREFIX, true, false),
        (SIMD_VECTOR_MASK, 0, false, false),
        (
            SIMD_SCALAR_HALF_MASK,
            SIMD_SCALAR_PREFIX | SIMD_HALF_ADJUSTMENT,
            true,
            true,
        ),
        (SIMD_VECTOR_HALF_MASK, SIMD_HALF_ADJUSTMENT, false, true),
    ] {
        let Some(direction) = simd_direction((word & mask) ^ adjustment) else {
            continue;
        };
        let format = if half {
            Format::Half
        } else if word & SIMD_DOUBLE != 0 {
            Format::Double
        } else {
            Format::Single
        };
        return Some(simd_operand(word, direction, format, scalar, 0));
    }
    for (mask, adjustment, scalar) in [
        (SIMD_SCALAR_FIXED_MASK, SIMD_SCALAR_PREFIX, true),
        (SIMD_VECTOR_FIXED_MASK, 0, false),
    ] {
        let direction = match (word & mask) ^ adjustment {
            SIMD_FIXED_SCVTF => Direction::FromInteger,
            SIMD_FIXED_FCVTZS => Direction::ToInteger(IntegerRounding::TowardZero),
            _ => continue,
        };
        let immediate = (word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK;
        // immh=0000 selects modified immediates before the shift/conversion
        // class. MOVI and FMOV must reach their existing shared decoder.
        if immediate < IMMEDIATE_SHIFT_CLASS_MINIMUM {
            return None;
        }
        let format = match immediate {
            IMMEDIATE_DOUBLE_MINIMUM..=IMMEDIATE_MASK => Format::Double,
            IMMEDIATE_SINGLE_MINIMUM..IMMEDIATE_DOUBLE_MINIMUM => Format::Single,
            IMMEDIATE_HALF_MINIMUM..IMMEDIATE_SINGLE_MINIMUM => Format::Half,
            _ => return Some(Err(Unsupported)),
        };
        let frac_bits = (2 * format.bits() - immediate) as u8;
        return Some(simd_operand(word, direction, format, scalar, frac_bits));
    }
    None
}

fn simd_operand(
    word: u32,
    direction: Direction,
    format: Format,
    scalar: bool,
    frac_bits: u8,
) -> Result<Operand, Unsupported> {
    let shape = if scalar {
        Shape::Scalar
    } else {
        vector_shape(word)
    };
    if format == Format::Double && shape == Shape::Vector64 {
        return Err(Unsupported);
    }
    let destination = vector_register(word, 0);
    let source = vector_register(word, SOURCE_SHIFT);
    let (integer, float) = match direction {
        Direction::FromInteger => (source, destination),
        Direction::ToInteger(_) => (destination, source),
    };
    Ok(direction.operand(IntegerConversion {
        integer: IntegerOperand::Simd {
            register: integer,
            format: IntegerFormat {
                width: integer_width(format),
                signed: word & SIMD_UNSIGNED == 0,
            },
            shape,
        },
        float,
        format,
        frac_bits,
    }))
}

#[cfg(test)]
mod tests;
