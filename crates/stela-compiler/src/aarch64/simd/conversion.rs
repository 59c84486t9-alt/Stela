//! Scalar and AdvSIMD conversions between H/S/D and integers (FCVT*, SCVTF, UCVTF).
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

fn format(field: u32) -> Result<Format, ()> {
    match field {
        FORMAT_SINGLE => Ok(Format::Single),
        FORMAT_DOUBLE => Ok(Format::Double),
        FORMAT_HALF => Ok(Format::Half),
        _ => Err(()),
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
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
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

fn decode_precision(word: u32) -> Option<Result<Operand, ()>> {
    if word & SCALAR_EXACT_MASK == BFCVT {
        return None;
    }
    let mode = if word & SCALAR_PRECISION_MASK == SCALAR_FCVT {
        let source = match format((word >> FORMAT_SHIFT) & FORMAT_MASK) {
            Ok(format) => format,
            Err(()) => return Some(Err(())),
        };
        let destination = match format((word >> DESTINATION_FORMAT_SHIFT) & FORMAT_MASK) {
            Ok(format) => format,
            Err(()) => return Some(Err(())),
        };
        if source == destination {
            return Some(Err(()));
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

fn decode_general(word: u32) -> Option<Result<Operand, ()>> {
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
        Err(()) => return Some(Err(())),
    };
    let wide = word & GENERAL_WIDE != 0;
    let frac_bits = if fixed {
        let scale = (word >> SCALE_SHIFT) & SCALE_MASK;
        if !wide && scale < IMMEDIATE_SINGLE_MINIMUM {
            return Some(Err(()));
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

fn decode_simd(word: u32) -> Option<Result<Operand, ()>> {
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
            _ => return Some(Err(())),
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
) -> Result<Operand, ()> {
    let shape = if scalar {
        Shape::Scalar
    } else {
        vector_shape(word)
    };
    if format == Format::Double && shape == Shape::Vector64 {
        return Err(());
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
mod tests {
    use super::*;

    const FORMAT_RESERVED: u32 = 2;
    const REGISTER_COUNT: u32 = REGISTER_MASK + 1;
    const GENERAL_OPERATIONS: [(u32, Direction); 6] = [
        (GENERAL_SCVTF, Direction::FromInteger),
        (
            GENERAL_FCVTNS,
            Direction::ToInteger(IntegerRounding::NearestEven),
        ),
        (
            GENERAL_FCVTAS,
            Direction::ToInteger(IntegerRounding::NearestAway),
        ),
        (
            GENERAL_FCVTPS,
            Direction::ToInteger(IntegerRounding::TowardPositive),
        ),
        (
            GENERAL_FCVTMS,
            Direction::ToInteger(IntegerRounding::TowardNegative),
        ),
        (
            GENERAL_FCVTZS,
            Direction::ToInteger(IntegerRounding::TowardZero),
        ),
    ];
    const SIMD_OPERATIONS: [(u32, Direction); 6] = [
        (SIMD_SCVTF, Direction::FromInteger),
        (
            SIMD_FCVTNS,
            Direction::ToInteger(IntegerRounding::NearestEven),
        ),
        (
            SIMD_FCVTAS,
            Direction::ToInteger(IntegerRounding::NearestAway),
        ),
        (
            SIMD_FCVTPS,
            Direction::ToInteger(IntegerRounding::TowardPositive),
        ),
        (
            SIMD_FCVTMS,
            Direction::ToInteger(IntegerRounding::TowardNegative),
        ),
        (
            SIMD_FCVTZS,
            Direction::ToInteger(IntegerRounding::TowardZero),
        ),
    ];
    const FORMATS: [(u32, Format); 3] = [
        (FORMAT_SINGLE, Format::Single),
        (FORMAT_DOUBLE, Format::Double),
        (FORMAT_HALF, Format::Half),
    ];

    fn apply_registers(operand: Operand, destination: u8, source: u8) -> Operand {
        match operand {
            Operand::Precision(mut operand) => {
                operand.destination = destination;
                operand.source = source;
                Operand::Precision(operand)
            }
            Operand::JavaScript { .. } => Operand::JavaScript {
                destination: general_register(destination),
                source,
            },
            Operand::FromInteger(mut operand) => {
                operand.float = destination;
                operand.integer = integer_register(operand.integer, source);
                Operand::FromInteger(operand)
            }
            Operand::ToInteger {
                mut operand,
                rounding,
            } => {
                operand.float = source;
                operand.integer = integer_register(operand.integer, destination);
                Operand::ToInteger { operand, rounding }
            }
        }
    }

    fn integer_register(operand: IntegerOperand, register: u8) -> IntegerOperand {
        match operand {
            IntegerOperand::General { format, .. } => IntegerOperand::General {
                register: general_register(register),
                format,
            },
            IntegerOperand::Simd { format, shape, .. } => IntegerOperand::Simd {
                register,
                format,
                shape,
            },
        }
    }

    // Every arrangement covers all source/destination aliases and the V31/ZR roles.
    fn check_registers(word: u32, expected: Operand) {
        for destination in 0..REGISTER_COUNT {
            for source in 0..REGISTER_COUNT {
                let word = word | (source << SOURCE_SHIFT) | destination;
                assert_eq!(
                    decode(word),
                    Some(Ok(apply_registers(
                        expected,
                        destination as u8,
                        source as u8
                    ))),
                    "word={word:08x}"
                );
            }
        }
    }

    fn precision(word: u32, mode: PrecisionMode) {
        check_registers(
            word,
            Operand::Precision(PrecisionOperand {
                mode,
                destination: 0,
                source: 0,
            }),
        );
    }

    #[test]
    fn precision_formats_parts_rounding_and_all_aliases_are_explicit() {
        let mut arrangements = 0;
        for (source_field, source) in FORMATS {
            for (destination_field, destination) in FORMATS {
                let word = SCALAR_FCVT
                    | (source_field << FORMAT_SHIFT)
                    | (destination_field << DESTINATION_FORMAT_SHIFT);
                if source == destination {
                    assert_eq!(decode(word), Some(Err(())));
                } else {
                    precision(
                        word,
                        PrecisionMode::Scalar {
                            source,
                            destination,
                            rounding: PrecisionRounding::Fpcr,
                        },
                    );
                    arrangements += 1;
                }
            }
        }
        for (size, small, large) in [
            (0, Format::Half, Format::Single),
            (SIMD_DOUBLE, Format::Single, Format::Double),
        ] {
            for (q, upper) in [(0, false), (VECTOR_Q, true)] {
                let long = PrecisionMode::Widen {
                    source: small,
                    upper,
                };
                assert_eq!(long.source_format(), small);
                assert_eq!(long.destination_format(), large);
                precision(FCVTL | size | q, long);
                let narrow = PrecisionMode::Narrow {
                    destination: small,
                    upper,
                    rounding: PrecisionRounding::Fpcr,
                };
                assert_eq!(narrow.source_format(), large);
                assert_eq!(narrow.destination_format(), small);
                precision(FCVTN | size | q, narrow);
                arrangements += 2;
            }
        }
        precision(
            SCALAR_FCVTXN,
            PrecisionMode::Scalar {
                source: Format::Double,
                destination: Format::Single,
                rounding: PrecisionRounding::ToOdd,
            },
        );
        for (q, upper) in [(0, false), (VECTOR_Q, true)] {
            precision(
                VECTOR_FCVTXN | q,
                PrecisionMode::Narrow {
                    destination: Format::Single,
                    upper,
                    rounding: PrecisionRounding::ToOdd,
                },
            );
        }
        assert_eq!(arrangements + 3, 17);
    }

    #[test]
    fn general_integer_widths_rounding_scales_and_all_register_roles_are_explicit() {
        let mut unscaled = 0;
        let mut fixed = 0;
        for (unsigned, signed) in [(0, true), (GENERAL_UNSIGNED, false)] {
            for (wide, width, bits) in [
                (0, IntegerWidth::Bits32, 32),
                (GENERAL_WIDE, IntegerWidth::Bits64, 64),
            ] {
                for (format_field, format) in FORMATS {
                    let integer = IntegerOperand::General {
                        register: Register::X(0),
                        format: IntegerFormat { width, signed },
                    };
                    let expected = IntegerConversion {
                        integer,
                        float: 0,
                        format,
                        frac_bits: 0,
                    };
                    assert_eq!(integer.format(), IntegerFormat { width, signed });
                    assert_eq!(integer.shape(), Shape::Scalar);
                    for (opcode, direction) in GENERAL_OPERATIONS {
                        check_registers(
                            opcode | unsigned | wide | (format_field << FORMAT_SHIFT),
                            direction.operand(expected),
                        );
                        unscaled += 1;
                    }
                    for (opcode, direction) in [
                        (GENERAL_FIXED_SCVTF, Direction::FromInteger),
                        (
                            GENERAL_FIXED_FCVTZS,
                            Direction::ToInteger(IntegerRounding::TowardZero),
                        ),
                    ] {
                        for frac_bits in 1..=bits {
                            check_registers(
                                opcode
                                    | unsigned
                                    | wide
                                    | (format_field << FORMAT_SHIFT)
                                    | ((SCALE_BIAS - frac_bits) << SCALE_SHIFT),
                                direction.operand(IntegerConversion {
                                    frac_bits: frac_bits as u8,
                                    ..expected
                                }),
                            );
                            fixed += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(unscaled, 72);
        assert_eq!(fixed, 1152);
    }

    #[test]
    fn simd_integer_widths_rounding_scales_shapes_and_all_aliases_are_explicit() {
        let mut unscaled = 0;
        let mut fixed = 0;
        for (unsigned, signed) in [(0, true), (SIMD_UNSIGNED, false)] {
            for format in [Format::Half, Format::Single, Format::Double] {
                for (shape, prefix) in [
                    (Shape::Scalar, SIMD_SCALAR_PREFIX),
                    (Shape::Vector64, 0),
                    (Shape::Vector128, VECTOR_Q),
                ] {
                    if format == Format::Double && shape == Shape::Vector64 {
                        continue;
                    }
                    let width = integer_width(format);
                    let integer = IntegerOperand::Simd {
                        register: 0,
                        format: IntegerFormat { width, signed },
                        shape,
                    };
                    let expected = IntegerConversion {
                        integer,
                        float: 0,
                        format,
                        frac_bits: 0,
                    };
                    assert_eq!(integer.format(), IntegerFormat { width, signed });
                    assert_eq!(integer.shape(), shape);
                    let size = match format {
                        Format::Half => SIMD_HALF_ADJUSTMENT,
                        Format::Single => 0,
                        Format::Double => SIMD_DOUBLE,
                    };
                    for (opcode, direction) in SIMD_OPERATIONS {
                        check_registers(
                            (opcode ^ size) | unsigned | prefix,
                            direction.operand(expected),
                        );
                        unscaled += 1;
                    }
                    for (opcode, direction) in [
                        (SIMD_FIXED_SCVTF, Direction::FromInteger),
                        (
                            SIMD_FIXED_FCVTZS,
                            Direction::ToInteger(IntegerRounding::TowardZero),
                        ),
                    ] {
                        for frac_bits in 1..=format.bits() {
                            check_registers(
                                opcode
                                    | unsigned
                                    | prefix
                                    | ((2 * format.bits() - frac_bits) << IMMEDIATE_SHIFT),
                                direction.operand(IntegerConversion {
                                    frac_bits: frac_bits as u8,
                                    ..expected
                                }),
                            );
                            fixed += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(unscaled, 96);
        assert_eq!(fixed, 1088);
    }

    #[test]
    fn javascript_destination_uses_zero_register_and_source_uses_v31() {
        check_registers(
            FJCVTZS,
            Operand::JavaScript {
                destination: Register::X(0),
                source: 0,
            },
        );
    }

    #[test]
    fn reserved_formats_scales_and_vector_one_double_are_rejected() {
        for (opcode, _) in GENERAL_OPERATIONS {
            for signed in [0, GENERAL_UNSIGNED] {
                for wide in [0, GENERAL_WIDE] {
                    assert_eq!(
                        decode(opcode | signed | wide | (FORMAT_RESERVED << FORMAT_SHIFT)),
                        Some(Err(()))
                    );
                }
            }
        }
        for opcode in [GENERAL_FIXED_SCVTF, GENERAL_FIXED_FCVTZS] {
            for signed in [0, GENERAL_UNSIGNED] {
                for (field, _) in FORMATS {
                    for scale in 0..IMMEDIATE_SINGLE_MINIMUM {
                        assert_eq!(
                            decode(
                                opcode | signed | (field << FORMAT_SHIFT) | (scale << SCALE_SHIFT)
                            ),
                            Some(Err(()))
                        );
                    }
                }
                for wide in [0, GENERAL_WIDE] {
                    assert_eq!(
                        decode(opcode | signed | wide | (FORMAT_RESERVED << FORMAT_SHIFT)),
                        Some(Err(()))
                    );
                }
            }
        }
        for (opcode, _) in SIMD_OPERATIONS {
            for signed in [0, SIMD_UNSIGNED] {
                assert_eq!(decode(opcode | signed | SIMD_DOUBLE), Some(Err(())));
            }
        }
        for opcode in [SIMD_FIXED_SCVTF, SIMD_FIXED_FCVTZS] {
            for signed in [0, SIMD_UNSIGNED] {
                for prefix in [0, VECTOR_Q, SIMD_SCALAR_PREFIX] {
                    for immediate in 0..IMMEDIATE_SHIFT_CLASS_MINIMUM {
                        assert_eq!(
                            decode(opcode | signed | prefix | (immediate << IMMEDIATE_SHIFT)),
                            None
                        );
                    }
                    for immediate in IMMEDIATE_SHIFT_CLASS_MINIMUM..IMMEDIATE_HALF_MINIMUM {
                        assert_eq!(
                            decode(opcode | signed | prefix | (immediate << IMMEDIATE_SHIFT)),
                            Some(Err(()))
                        );
                    }
                }
                for immediate in IMMEDIATE_DOUBLE_MINIMUM..=IMMEDIATE_MASK {
                    assert_eq!(
                        decode(opcode | signed | (immediate << IMMEDIATE_SHIFT)),
                        Some(Err(()))
                    );
                }
            }
        }
        for destination in 0..=FORMAT_MASK {
            assert_eq!(
                decode(
                    SCALAR_FCVT
                        | (FORMAT_RESERVED << FORMAT_SHIFT)
                        | (destination << DESTINATION_FORMAT_SHIFT)
                ),
                Some(Err(()))
            );
        }
    }

    #[test]
    fn adjacent_features_and_unrelated_families_do_not_gain_support() {
        // Neighboring forms: BFCVT/BFCVTN, both FP8 FCVTN classes, signed and
        // unsigned FPRCVT, FMOV and FRINTN.
        const OTHER_FAMILIES: [u32; 12] = [
            0x1e634000, 0x0ea16800, 0x0e40f400, 0x0e60f400, 0x1e7a0000, 0x1e7b0000, 0x1e6a0000,
            0x1e6b0000, 0x9efc0000, 0x9efd0000, 0x1e204000, 0x1e244000,
        ];
        for word in OTHER_FAMILIES {
            assert_eq!(decode(word), None, "word={word:08x}");
        }
        // FCVTL/N bit23 is fixed zero; FCVTXN size23:22 is fixed01.
        const PRECISION_SIZE_HIGH: u32 = 1 << 23;
        for word in [FCVTL, FCVTN] {
            assert_eq!(decode(word | PRECISION_SIZE_HIGH), None);
        }
        for word in [VECTOR_FCVTXN, SCALAR_FCVTXN] {
            assert_eq!(decode(word ^ SIMD_DOUBLE), None);
            assert_eq!(decode(word | PRECISION_SIZE_HIGH), None);
        }
    }

    #[test]
    fn modified_immediates_keep_their_existing_decoder_and_compiler_paths() {
        use crate::{GuestAddress, Lifter, aarch64, block};

        const MODIFIED_IMMEDIATE: u32 = 0x0f000400;
        const CMODE_SHIFT: u32 = 12;
        const CMODE_COUNT: u32 = 16;
        const HALF_FLOAT: u32 = 1 << 11;
        const IMMEDIATE_HIGH_SHIFT: u32 = 5;
        const IMMEDIATE_HIGH_MASK: u32 = 7;
        const IMMEDIATE_COUNT: u32 = 256;
        const MOVI_CMODE: u32 = 14;
        const FMOV_CMODE: u32 = 15;
        const RETURN_X30: u32 = 0xd65f03c0;
        const OLD_MOVI_TWO_D: u32 = 0x6f00e400;
        const BASE: GuestAddress = GuestAddress(0x1000);

        assert_eq!(decode(OLD_MOVI_TWO_D), None);
        let mut decoded = 0;
        let mut compiled = 0;
        for q in [0, VECTOR_Q] {
            for op in [0, SIMD_UNSIGNED] {
                for half in [0, HALF_FLOAT] {
                    for cmode in 0..CMODE_COUNT {
                        for immediate in 0..IMMEDIATE_COUNT {
                            for destination in [0, REGISTER_MASK] {
                                let word = MODIFIED_IMMEDIATE
                                    | q
                                    | op
                                    | half
                                    | (cmode << CMODE_SHIFT)
                                    | (((immediate >> IMMEDIATE_HIGH_SHIFT) & IMMEDIATE_HIGH_MASK)
                                        << IMMEDIATE_SHIFT)
                                    | ((immediate & REGISTER_MASK) << SOURCE_SHIFT)
                                    | destination;
                                assert_eq!(decode(word), None, "word={word:08x}");
                                let Some(Ok(expected)) = super::super::decode(word) else {
                                    continue;
                                };
                                assert_eq!(
                                    aarch64::Decoder.lift(BASE, word).unwrap().operation,
                                    aarch64::Operation::Simd(expected),
                                    "word={word:08x}"
                                );
                                decoded += 1;
                                // Compile every immediate/Q/register arrangement
                                // in the allocated classes intersecting our masks.
                                if (cmode == MOVI_CMODE && half == 0)
                                    || (cmode == FMOV_CMODE && half == HALF_FLOAT)
                                {
                                    let mut source = word.to_le_bytes().to_vec();
                                    source.extend(RETURN_X30.to_le_bytes());
                                    assert!(
                                        crate::compile(&source, BASE).is_ok(),
                                        "word={word:08x}"
                                    );
                                    assert!(
                                        block::compile(&source, BASE).is_ok(),
                                        "word={word:08x}"
                                    );
                                    compiled += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(decoded > 0);
        assert_eq!(compiled, 3072);
    }
}
