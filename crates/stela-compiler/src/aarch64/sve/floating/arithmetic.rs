//! SVE floating-point arithmetic operands.
use crate::aarch64::{
    floating::{
        BinaryOperation, Format, complex::Rotation, fused::FusedOperation, minmax::MinMaxOperation,
    },
    simd::{estimate, refinement},
};

const REGISTER_MASK: u32 = 31;
const INDEXED_NARROW_REGISTER_MASK: u32 = 7;
const INDEXED_WIDE_REGISTER_MASK: u32 = 15;
const TWO_BIT_INDEX_MASK: u32 = 3;
const SINGLE_BIT_MASK: u32 = 1;
const HALF_INDEX_HIGH_SHIFT: u32 = 2;
const SINGLE_SIZE_ENCODING: u32 = 2;
const SOURCE_SHIFT: u32 = 5;
const SECOND_SOURCE_SHIFT: u32 = 16;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const SIZE_SHIFT: u32 = 22;
const LOGB_SIZE_SHIFT: u32 = 17;
const SIZE_MASK: u32 = 3;
const IMMEDIATE_SHIFT: u32 = 5;
const INDEX_HIGH_SHIFT: u32 = 22;
const INDEX_LOW_SHIFT: u32 = 19;
const INDEX_SINGLE_SHIFT: u32 = 19;
const INDEX_DOUBLE_SHIFT: u32 = 20;
const COMPLEX_ROTATION_SHIFT: u32 = 13;
const COMPLEX_INDEXED_ROTATION_SHIFT: u32 = 10;
const COMPLEX_ADD_ROTATION_SHIFT: u32 = 16;
const HALF_EXPONENT_SHIFT: u32 = 10;
const SINGLE_EXPONENT_SHIFT: u32 = 23;
const DOUBLE_EXPONENT_SHIFT: u32 = 52;
const HALF_EXPONENT_BIAS: u64 = 15;
const SINGLE_EXPONENT_BIAS: u64 = 127;
const DOUBLE_EXPONENT_BIAS: u64 = 1023;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Binary(BinaryOperation),
    Fused(FusedOperation),
    MinMax(MinMaxOperation),
    Absolute,
    Negate,
    SquareRoot,
    Estimate(estimate::Kind),
    Refinement(refinement::Kind),
    Scale,
    Logb,
    Clamp,
    ComplexAdd(Rotation),
    ComplexMultiplyAdd(Rotation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Vector(u8),
    ImmediateBits(u64),
    /// Index repeats independently inside every 128-bit segment.
    Indexed {
        register: u8,
        index: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inputs {
    Unary {
        source: u8,
    },
    Binary {
        left: Source,
        right: Source,
    },
    Fused {
        addend: u8,
        left: u8,
        right: Source,
    },
    /// Output predicates select adjacent pairs, rather than individual input lanes.
    Pairwise {
        left: u8,
        right: u8,
    },
    Reduction {
        source: u8,
    },
    Clamp {
        value: u8,
        lower: u8,
        upper: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultShape {
    Vector,
    ScalarReduction,
    /// Matching lane positions reduce across 128-bit segments into one V register.
    QuadReduction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub format: Format,
    pub destination: u8,
    /// All selected predicated encodings merge inactive destination lanes.
    pub predicate: Option<u8>,
    pub inputs: Inputs,
    pub shape: ResultShape,
}

#[derive(Clone, Copy)]
enum Immediate {
    HalfOrOne,
    HalfOrTwo,
    ZeroOrOne,
}
#[derive(Clone, Copy)]
enum Layout {
    Unary { predicated: bool },
    PredicatedBinary { reverse: bool },
    Immediate { value: Immediate, reverse: bool },
    Binary,
    IndexedBinary(Format),
    Fused { destructive_left: bool },
    IndexedFused(Format),
    Pairwise,
    Reduction(ResultShape),
    Clamp,
    ComplexAdd,
    ComplexFused,
    ComplexIndexed(Format),
    Logb,
    UnsignedEstimate,
}
#[derive(Clone, Copy)]
struct Encoding {
    mask: u32,
    value: u32,
    kind: Kind,
    layout: Layout,
}

mod encodings;
use encodings::ENCODINGS;

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}
fn rotation(value: u32) -> Rotation {
    match value & SIZE_MASK {
        0 => Rotation::Degrees0,
        1 => Rotation::Degrees90,
        2 => Rotation::Degrees180,
        _ => Rotation::Degrees270,
    }
}
fn format(word: u32, shift: u32) -> Option<Format> {
    match (word >> shift) & SIZE_MASK {
        1 => Some(Format::Half),
        2 => Some(Format::Single),
        3 => Some(Format::Double),
        _ => None, // BF16 owns size=00 where allocated; never consume it here.
    }
}
fn indexed(word: u32, format: Format, complex: bool) -> Source {
    let (register_bits, index) = match (format, complex) {
        (Format::Half, false) => (
            INDEXED_NARROW_REGISTER_MASK,
            ((word >> INDEX_HIGH_SHIFT) & SINGLE_BIT_MASK) << HALF_INDEX_HIGH_SHIFT
                | ((word >> INDEX_LOW_SHIFT) & TWO_BIT_INDEX_MASK),
        ),
        (Format::Half, true) | (Format::Single, false) => (
            INDEXED_NARROW_REGISTER_MASK,
            (word >> INDEX_SINGLE_SHIFT) & TWO_BIT_INDEX_MASK,
        ),
        (Format::Single, true) | (Format::Double, false) => (
            INDEXED_WIDE_REGISTER_MASK,
            (word >> INDEX_DOUBLE_SHIFT) & SINGLE_BIT_MASK,
        ),
        (Format::Double, true) => unreachable!("no double indexed complex encoding"),
    };
    Source::Indexed {
        register: ((word >> SECOND_SOURCE_SHIFT) & register_bits) as u8,
        index: index as u8,
    }
}
fn immediate(format: Format, value: Immediate, high: bool) -> Source {
    let (bias, shift) = match format {
        Format::Half => (HALF_EXPONENT_BIAS, HALF_EXPONENT_SHIFT),
        Format::Single => (SINGLE_EXPONENT_BIAS, SINGLE_EXPONENT_SHIFT),
        Format::Double => (DOUBLE_EXPONENT_BIAS, DOUBLE_EXPONENT_SHIFT),
    };
    let exponent = match (value, high) {
        (Immediate::ZeroOrOne, false) => return Source::ImmediateBits(0),
        (Immediate::HalfOrOne, false) | (Immediate::HalfOrTwo, false) => bias - 1,
        (Immediate::HalfOrTwo, true) => bias + 1,
        _ => bias,
    };
    Source::ImmediateBits(exponent << shift)
}

fn matching_encoding(word: u32) -> Option<&'static Encoding> {
    ENCODINGS.iter().find(|e| word & e.mask == e.value)
}

fn core_binary_encoding(encoding: &Encoding) -> bool {
    matches!(
        (encoding.kind, encoding.layout),
        (
            Kind::Binary(
                BinaryOperation::Add | BinaryOperation::Subtract | BinaryOperation::Multiply
            ),
            Layout::Binary | Layout::PredicatedBinary { reverse: false },
        ) | (
            Kind::Binary(BinaryOperation::Divide),
            Layout::PredicatedBinary { reverse: false },
        )
    )
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    decode_encoding(word, matching_encoding(word)?)
}

/// Supported subset: forward predicated ADD/SUB/MUL/DIV and unpredicated
/// ADD/SUB/MUL, for H/S/D. The direction comes from the encoding, since
/// reversed forms with aliased registers decode to identical operands.
#[allow(clippy::result_unit_err)]
pub fn decode_core_binary(word: u32) -> Option<Result<Operand, ()>> {
    let encoding = matching_encoding(word)?;
    if !core_binary_encoding(encoding) {
        return None;
    }
    decode_encoding(word, encoding)
}

/// Arithmetic decoding uses the shared encoding table; FABS/FNEG keep their own
/// decoder and emitter.
#[allow(clippy::result_unit_err)]
pub fn decode_numerical(word: u32) -> Option<Result<Operand, ()>> {
    let encoding = matching_encoding(word)?;
    if matches!(encoding.kind, Kind::Absolute | Kind::Negate) {
        return None;
    }
    decode_encoding(word, encoding)
}

fn decode_encoding(word: u32, encoding: &Encoding) -> Option<Result<Operand, ()>> {
    let format = match encoding.layout {
        Layout::IndexedBinary(f) | Layout::IndexedFused(f) | Layout::ComplexIndexed(f) => f,
        Layout::Logb => format(word, LOGB_SIZE_SHIFT)?,
        Layout::UnsignedEstimate => {
            if (word >> SIZE_SHIFT) & SIZE_MASK != SINGLE_SIZE_ENCODING {
                return Some(Err(()));
            }
            Format::Single
        }
        _ => format(word, SIZE_SHIFT)?,
    };
    let destination = register(word, 0);
    let n = register(word, SOURCE_SHIFT);
    let m = register(word, SECOND_SOURCE_SHIFT);
    let mut kind = encoding.kind;
    let mut shape = ResultShape::Vector;
    let (inputs, predicated) = match encoding.layout {
        Layout::Unary { predicated } => (Inputs::Unary { source: n }, predicated),
        Layout::Logb | Layout::UnsignedEstimate => (Inputs::Unary { source: n }, true),
        Layout::Binary => (
            Inputs::Binary {
                left: Source::Vector(n),
                right: Source::Vector(m),
            },
            false,
        ),
        Layout::PredicatedBinary { reverse } => {
            let (left, right) = if reverse {
                (n, destination)
            } else {
                (destination, n)
            };
            (
                Inputs::Binary {
                    left: Source::Vector(left),
                    right: Source::Vector(right),
                },
                true,
            )
        }
        Layout::Immediate { value, reverse } => {
            let right = immediate(format, value, (word >> IMMEDIATE_SHIFT) & 1 != 0);
            let left = Source::Vector(destination);
            let (left, right) = if reverse {
                (right, left)
            } else {
                (left, right)
            };
            (Inputs::Binary { left, right }, true)
        }
        Layout::IndexedBinary(_) => (
            Inputs::Binary {
                left: Source::Vector(n),
                right: indexed(word, format, false),
            },
            false,
        ),
        Layout::Fused { destructive_left } => {
            let (addend, left, right) = if destructive_left {
                (m, destination, n)
            } else {
                (destination, n, m)
            };
            (
                Inputs::Fused {
                    addend,
                    left,
                    right: Source::Vector(right),
                },
                true,
            )
        }
        Layout::IndexedFused(_) => (
            Inputs::Fused {
                addend: destination,
                left: n,
                right: indexed(word, format, false),
            },
            false,
        ),
        Layout::Pairwise => (
            Inputs::Pairwise {
                left: destination,
                right: n,
            },
            true,
        ),
        Layout::Reduction(result_shape) => {
            shape = result_shape;
            (Inputs::Reduction { source: n }, true)
        }
        Layout::Clamp => (
            Inputs::Clamp {
                value: destination,
                lower: n,
                upper: m,
            },
            false,
        ),
        Layout::ComplexAdd => {
            kind = Kind::ComplexAdd(if (word >> COMPLEX_ADD_ROTATION_SHIFT) & 1 == 0 {
                Rotation::Degrees90
            } else {
                Rotation::Degrees270
            });
            (
                Inputs::Binary {
                    left: Source::Vector(destination),
                    right: Source::Vector(n),
                },
                true,
            )
        }
        Layout::ComplexFused => {
            kind = Kind::ComplexMultiplyAdd(rotation(word >> COMPLEX_ROTATION_SHIFT));
            (
                Inputs::Fused {
                    addend: destination,
                    left: n,
                    right: Source::Vector(m),
                },
                true,
            )
        }
        Layout::ComplexIndexed(_) => {
            kind = Kind::ComplexMultiplyAdd(rotation(word >> COMPLEX_INDEXED_ROTATION_SHIFT));
            (
                Inputs::Fused {
                    addend: destination,
                    left: n,
                    right: indexed(word, format, true),
                },
                false,
            )
        }
    };
    Some(Ok(Operand {
        kind,
        format,
        destination,
        predicate: predicated.then_some(((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8),
        inputs,
        shape,
    }))
}

#[cfg(test)]
mod tests;
