//! Streaming SVE floating arithmetic operands; state and lane execution live separately.
//! Encoding facts are pinned to Arm A64 2026-06. Feature/mode checks belong to the caller.
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

#[path = "arithmetic/encodings.rs"]
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

/// Closed first-admission subset: forward vector-register ADD/SUB/MUL/DIV and
/// unpredicated vector-register ADD/SUB/MUL, with exact H/S/D completion.
/// Canonical direction comes from the original encoding layout because reverse
/// forms become indistinguishable typed operands when their registers alias.
#[allow(clippy::result_unit_err)]
pub fn decode_core_binary(word: u32) -> Option<Result<Operand, ()>> {
    let encoding = matching_encoding(word)?;
    if !core_binary_encoding(encoding) {
        return None;
    }
    decode_encoding(word, encoding)
}

/// Numerical arithmetic admission uses the shared canonical encoding table.
/// Total sign instructions retain their separately published decoder and emitter.
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
mod tests {
    use super::*;

    const SINGLE_SIZE: u32 = SINGLE_SIZE_ENCODING << SIZE_SHIFT;
    const ALL_REGISTERS_AND_PREDICATES: u32 = REGISTER_MASK
        | (REGISTER_MASK << SOURCE_SHIFT)
        | (REGISTER_MASK << SECOND_SOURCE_SHIFT)
        | (PREDICATE_MASK << PREDICATE_SHIFT);
    const FADD_PREDICATED: u32 = 0x6500_8000;
    const FADD_UNPREDICATED: u32 = 0x6500_0000;
    const FMLA_PREDICATED: u32 = 0x6520_0000;
    const FCLAMP: u32 = 0x6420_2400;
    const FSUBR_IMMEDIATE: u32 = 0x651b_8000;
    const FMLA_HALF_INDEXED: u32 = 0x6420_0000;
    const FCMLA_SINGLE_INDEXED: u32 = 0x64e0_1000;
    const FLOGB: u32 = 0x6518_a000;
    const URECPE: u32 = 0x4400_a000;

    #[test]
    fn every_selected_encoding_accepts_register_and_width_boundaries() {
        for encoding in ENCODINGS {
            for poison in [0, ALL_REGISTERS_AND_PREDICATES] {
                let mut word = encoding.value | (poison & !encoding.mask);
                match encoding.layout {
                    Layout::IndexedBinary(_)
                    | Layout::IndexedFused(_)
                    | Layout::ComplexIndexed(_) => {}
                    Layout::Logb => word |= SINGLE_SIZE_ENCODING << LOGB_SIZE_SHIFT,
                    _ => word |= SINGLE_SIZE,
                }
                assert!(decode(word).is_some_and(|v| v.is_ok()), "{word:08x}");
            }
        }
    }

    #[test]
    fn bfloat_encodings_are_left_for_their_owner() {
        for opcode in [FADD_PREDICATED, FADD_UNPREDICATED, FMLA_PREDICATED, FCLAMP] {
            assert_eq!(decode(opcode), None);
        }
    }

    #[test]
    fn reverse_immediate_keeps_the_immediate_as_left_operand() {
        let operand = decode(FSUBR_IMMEDIATE | SINGLE_SIZE).unwrap().unwrap();
        assert_eq!(operand.kind, Kind::Binary(BinaryOperation::Subtract));
        assert_eq!(
            operand.inputs,
            Inputs::Binary {
                left: Source::ImmediateBits(0x3f00_0000),
                right: Source::Vector(0),
            }
        );
        assert_eq!(operand.predicate, Some(0));
    }

    #[test]
    fn indexed_forms_keep_narrow_register_fields_and_segment_indices() {
        let half = FMLA_HALF_INDEXED
            | (1 << INDEX_HIGH_SHIFT)
            | (3 << INDEX_LOW_SHIFT)
            | (7 << SECOND_SOURCE_SHIFT)
            | (31 << SOURCE_SHIFT)
            | 31;
        let operand = decode(half).unwrap().unwrap();
        assert_eq!(operand.format, Format::Half);
        assert_eq!(
            operand.inputs,
            Inputs::Fused {
                addend: 31,
                left: 31,
                right: Source::Indexed {
                    register: 7,
                    index: 7
                },
            }
        );
        let single = FCMLA_SINGLE_INDEXED
            | (1 << INDEX_DOUBLE_SHIFT)
            | (15 << SECOND_SOURCE_SHIFT)
            | (3 << COMPLEX_INDEXED_ROTATION_SHIFT);
        let operand = decode(single).unwrap().unwrap();
        assert_eq!(operand.format, Format::Single);
        assert_eq!(operand.kind, Kind::ComplexMultiplyAdd(Rotation::Degrees270));
        assert_eq!(
            operand.inputs,
            Inputs::Fused {
                addend: 0,
                left: 0,
                right: Source::Indexed {
                    register: 15,
                    index: 1
                },
            }
        );
    }

    #[test]
    fn logb_has_its_distinct_size_position_and_unsigned_estimates_require_words() {
        for (size, expected) in [(1, Format::Half), (2, Format::Single), (3, Format::Double)] {
            let operand = decode(FLOGB | size << LOGB_SIZE_SHIFT).unwrap().unwrap();
            assert_eq!(operand.format, expected);
        }
        for size in 0..=SIZE_MASK {
            let result = decode(URECPE | size << SIZE_SHIFT).unwrap();
            assert_eq!(result.is_ok(), size == SINGLE_SIZE_ENCODING);
        }
    }

    #[test]
    fn multiplicand_destructive_fused_forms_use_za_in_the_high_source_field() {
        const FMAD: u32 = 0x6520_8000;
        let word = FMAD | SINGLE_SIZE | (3 << SECOND_SOURCE_SHIFT) | (2 << SOURCE_SHIFT) | 1;
        let operand = decode(word).unwrap().unwrap();
        assert_eq!(
            operand.inputs,
            Inputs::Fused {
                addend: 3,
                left: 1,
                right: Source::Vector(2),
            }
        );
    }

    #[test]
    fn unrelated_words_do_not_match() {
        for word in [0, u32::MAX, 0xd503_201f, 0x1e20_2800] {
            assert_eq!(decode(word), None);
        }
    }

    #[test]
    fn core_binary_subset_is_seven_classes_with_all_three_widths() {
        const HALF_SIZE: u32 = 1 << SIZE_SHIFT;
        const DOUBLE_SIZE: u32 = 3 << SIZE_SHIFT;
        let selected: Vec<_> = ENCODINGS
            .iter()
            .filter(|e| core_binary_encoding(e))
            .collect();
        assert_eq!(selected.len(), 7);
        for encoding in selected {
            for size in [HALF_SIZE, SINGLE_SIZE, DOUBLE_SIZE] {
                let word = (encoding.value & !(SIZE_MASK << SIZE_SHIFT)) | size;
                assert!(matches!(decode_core_binary(word), Some(Ok(_))));
                assert_eq!(decode_core_binary(word), decode(word));
            }
        }
    }

    #[test]
    fn core_binary_subset_preserves_canonical_direction_under_register_aliases() {
        for operation in [BinaryOperation::Subtract, BinaryOperation::Divide] {
            let selected = |reverse| {
                ENCODINGS.iter().find(|encoding| {
                    encoding.kind == Kind::Binary(operation)
                        && matches!(encoding.layout, Layout::PredicatedBinary { reverse: value } if value == reverse)
                }).expect("both forward and reverse allocations are pinned").value | SINGLE_SIZE
            };
            let forward = selected(false);
            let reverse = selected(true);
            // All registers and Pg are zero: canonical direction is no longer
            // represented by the public typed operand, so class filtering matters.
            assert_eq!(decode(forward), decode(reverse));
            assert!(matches!(decode_core_binary(forward), Some(Ok(_))));
            assert_eq!(decode_core_binary(reverse), None);
        }
    }
}
