//! FMADD/FMSUB/FNMADD/FNMSUB and AdvSIMD FMLA/FMLS.
use crate::aarch64::Unsupported;
use crate::aarch64::floating::{Format, fused::FusedOperation};

use super::arithmetic::Shape;

const SCALAR_MASK: u32 = 0xff208000;
const FMADD: u32 = 0x1f000000;
const FMSUB: u32 = 0x1f008000;
const FNMADD: u32 = 0x1f200000;
const FNMSUB: u32 = 0x1f208000;
const VECTOR_MASK: u32 = 0xbfa0fc00;
const VECTOR_FMLA: u32 = 0x0e20cc00;
const VECTOR_FMLS: u32 = 0x0ea0cc00;
const VECTOR_HALF_MASK: u32 = 0xbfe0fc00;
const VECTOR_HALF_FMLA: u32 = 0x0e400c00;
const VECTOR_HALF_FMLS: u32 = 0x0ec00c00;
const INDEXED_SCALAR_HALF_MASK: u32 = 0xffc0b400;
const INDEXED_SCALAR_HALF: u32 = 0x5f001000;
const INDEXED_SCALAR_MASK: u32 = 0xff80b400;
const INDEXED_SCALAR: u32 = 0x5f801000;
const INDEXED_VECTOR_HALF_MASK: u32 = 0xbfc0b400;
const INDEXED_VECTOR_HALF: u32 = 0x0f001000;
const INDEXED_VECTOR_MASK: u32 = 0xbf80b400;
const INDEXED_VECTOR: u32 = 0x0f801000;
const INDEXED_SUBTRACT: u32 = 1 << 14;
const VECTOR_Q: u32 = 1 << 30;
const VECTOR_DOUBLE: u32 = 1 << 22;
const FORMAT_SHIFT: u32 = 22;
const FORMAT_MASK: u32 = 3;
const FORMAT_SINGLE: u32 = 0;
const FORMAT_DOUBLE: u32 = 1;
const FORMAT_HALF: u32 = 3;
const REGISTER_MASK: u32 = 31;
const INDEXED_HALF_REGISTER_MASK: u32 = 15;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const ADDEND_SHIFT: u32 = 10;
const RIGHT_SHIFT: u32 = 16;
const INDEX_H_SHIFT: u32 = 11;
const INDEX_L_SHIFT: u32 = 21;
const INDEX_M_SHIFT: u32 = 20;
const INDEX_BIT_MASK: u32 = 1;
const HALF_LANE_HIGH_SHIFT: u32 = 2;
const HALF_LANE_LOW_SHIFT: u32 = 1;
const SINGLE_LANE_HIGH_SHIFT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub operation: FusedOperation,
    pub format: Format,
    pub shape: Shape,
    pub destination: u8,
    pub addend: u8,
    pub left: u8,
    pub right: u8,
    pub right_lane: Option<u8>,
}

/// None is another family; Err is reserved scalar ftype, vector 1D or indexed D/L.
/// Register fields denote ordinary V registers; indexed H permits only V0–V15.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    decode_scalar(word)
        .or_else(|| decode_vector(word))
        .or_else(|| decode_indexed(word))
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

fn vector_shape(word: u32) -> Shape {
    if word & VECTOR_Q == 0 {
        Shape::Vector64
    } else {
        Shape::Vector128
    }
}

fn decode_scalar(word: u32) -> Option<Result<Operand, Unsupported>> {
    let operation = match word & SCALAR_MASK {
        FMADD => FusedOperation::Add,
        FMSUB => FusedOperation::Subtract,
        FNMADD => FusedOperation::NegatedAdd,
        FNMSUB => FusedOperation::NegatedSubtract,
        _ => return None,
    };
    let format = match (word >> FORMAT_SHIFT) & FORMAT_MASK {
        FORMAT_SINGLE => Format::Single,
        FORMAT_DOUBLE => Format::Double,
        FORMAT_HALF => Format::Half,
        _ => return Some(Err(Unsupported)),
    };
    Some(Ok(Operand {
        operation,
        format,
        shape: Shape::Scalar,
        destination: register(word, DESTINATION_SHIFT),
        addend: register(word, ADDEND_SHIFT),
        left: register(word, LEFT_SHIFT),
        right: register(word, RIGHT_SHIFT),
        right_lane: None,
    }))
}

fn decode_vector(word: u32) -> Option<Result<Operand, Unsupported>> {
    let half_operation = match word & VECTOR_HALF_MASK {
        VECTOR_HALF_FMLA => Some(FusedOperation::Add),
        VECTOR_HALF_FMLS => Some(FusedOperation::Subtract),
        _ => None,
    };
    let shape = vector_shape(word);
    let (operation, format) = if let Some(operation) = half_operation {
        (operation, Format::Half)
    } else {
        let operation = match word & VECTOR_MASK {
            VECTOR_FMLA => FusedOperation::Add,
            VECTOR_FMLS => FusedOperation::Subtract,
            _ => return None,
        };
        let format = if word & VECTOR_DOUBLE == 0 {
            Format::Single
        } else {
            if shape == Shape::Vector64 {
                return Some(Err(Unsupported));
            }
            Format::Double
        };
        (operation, format)
    };
    let destination = register(word, DESTINATION_SHIFT);
    Some(Ok(Operand {
        operation,
        format,
        shape,
        destination,
        addend: destination,
        left: register(word, LEFT_SHIFT),
        right: register(word, RIGHT_SHIFT),
        right_lane: None,
    }))
}

fn decode_indexed(word: u32) -> Option<Result<Operand, Unsupported>> {
    let (half, shape) = if word & INDEXED_SCALAR_HALF_MASK == INDEXED_SCALAR_HALF {
        (true, Shape::Scalar)
    } else if word & INDEXED_SCALAR_MASK == INDEXED_SCALAR {
        (false, Shape::Scalar)
    } else if word & INDEXED_VECTOR_HALF_MASK == INDEXED_VECTOR_HALF {
        (true, vector_shape(word))
    } else if word & INDEXED_VECTOR_MASK == INDEXED_VECTOR {
        (false, vector_shape(word))
    } else {
        return None;
    };
    let high = (word >> INDEX_H_SHIFT) & INDEX_BIT_MASK;
    let low = (word >> INDEX_L_SHIFT) & INDEX_BIT_MASK;
    let middle = (word >> INDEX_M_SHIFT) & INDEX_BIT_MASK;
    let (format, right, lane) = if half {
        (
            Format::Half,
            ((word >> RIGHT_SHIFT) & INDEXED_HALF_REGISTER_MASK) as u8,
            (high << HALF_LANE_HIGH_SHIFT) | (low << HALF_LANE_LOW_SHIFT) | middle,
        )
    } else if word & VECTOR_DOUBLE == 0 {
        (
            Format::Single,
            register(word, RIGHT_SHIFT),
            (high << SINGLE_LANE_HIGH_SHIFT) | low,
        )
    } else {
        if low != 0 || shape == Shape::Vector64 {
            return Some(Err(Unsupported));
        }
        (Format::Double, register(word, RIGHT_SHIFT), high)
    };
    let operation = if word & INDEXED_SUBTRACT == 0 {
        FusedOperation::Add
    } else {
        FusedOperation::Subtract
    };
    let destination = register(word, DESTINATION_SHIFT);
    Some(Ok(Operand {
        operation,
        format,
        shape,
        destination,
        addend: destination,
        left: register(word, LEFT_SHIFT),
        right,
        right_lane: Some(lane as u8),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORMAT_RESERVED: u32 = 2;
    const INDEXED_REGISTER_HIGH_SHIFT: u32 = 4;
    const SCALAR_OPERATION_MASK: u32 = 0x00208000;
    const INDEXED_HALF_SINGLE_BIT: u32 = 1 << 23;
    const INDEXED_SCALAR_VECTOR_BIT: u32 = 1 << 28;
    const VECTOR_OPERATION_MASK: u32 = 1 << 23;
    const SCALAR_OPERATIONS: [(u32, FusedOperation); 4] = [
        (FMADD, FusedOperation::Add),
        (FMSUB, FusedOperation::Subtract),
        (FNMADD, FusedOperation::NegatedAdd),
        (FNMSUB, FusedOperation::NegatedSubtract),
    ];

    #[test]
    fn scalar_formats_and_all_register_roles_are_explicit() {
        for (encoding, operation) in SCALAR_OPERATIONS {
            for (format_field, format) in [
                (FORMAT_SINGLE, Some(Format::Single)),
                (FORMAT_DOUBLE, Some(Format::Double)),
                (FORMAT_HALF, Some(Format::Half)),
                (FORMAT_RESERVED, None),
            ] {
                for destination in 0..=REGISTER_MASK {
                    for left in 0..=REGISTER_MASK {
                        for right in 0..=REGISTER_MASK {
                            // Every addend value and alias occurs across the field matrix.
                            let addend = destination ^ left ^ right;
                            let word = encoding
                                | (format_field << FORMAT_SHIFT)
                                | (right << RIGHT_SHIFT)
                                | (addend << ADDEND_SHIFT)
                                | (left << LEFT_SHIFT)
                                | destination;
                            let expected = format.map_or(Err(Unsupported), |format| {
                                Ok(Operand {
                                    operation,
                                    format,
                                    shape: Shape::Scalar,
                                    destination: destination as u8,
                                    addend: addend as u8,
                                    left: left as u8,
                                    right: right as u8,
                                    right_lane: None,
                                })
                            });
                            assert_eq!(decode(word), Some(expected));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn vector_formats_shapes_and_registers_are_explicit() {
        for (ordinary, half, operation) in [
            (VECTOR_FMLA, VECTOR_HALF_FMLA, FusedOperation::Add),
            (VECTOR_FMLS, VECTOR_HALF_FMLS, FusedOperation::Subtract),
        ] {
            for (encoding, format, size) in [
                (ordinary, Format::Single, 0),
                (ordinary, Format::Double, VECTOR_DOUBLE),
                (half, Format::Half, 0),
            ] {
                for (q, shape) in [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)] {
                    for destination in 0..=REGISTER_MASK {
                        for left in 0..=REGISTER_MASK {
                            for right in 0..=REGISTER_MASK {
                                let word = encoding
                                    | size
                                    | q
                                    | (right << RIGHT_SHIFT)
                                    | (left << LEFT_SHIFT)
                                    | destination;
                                let expected =
                                    if format == Format::Double && shape == Shape::Vector64 {
                                        Err(Unsupported)
                                    } else {
                                        Ok(Operand {
                                            operation,
                                            format,
                                            shape,
                                            destination: destination as u8,
                                            addend: destination as u8,
                                            left: left as u8,
                                            right: right as u8,
                                            right_lane: None,
                                        })
                                    };
                                assert_eq!(decode(word), Some(expected));
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn indexed_lanes_register_widths_and_reserved_fields_are_explicit() {
        for (scalar, half, encoding) in [
            (true, true, INDEXED_SCALAR_HALF),
            (true, false, INDEXED_SCALAR),
            (false, true, INDEXED_VECTOR_HALF),
            (false, false, INDEXED_VECTOR),
        ] {
            for (subtract, operation) in [
                (0, FusedOperation::Add),
                (INDEXED_SUBTRACT, FusedOperation::Subtract),
            ] {
                for q in [0, VECTOR_Q] {
                    if scalar && q == 0 {
                        continue;
                    }
                    let shape = if scalar {
                        Shape::Scalar
                    } else if q == 0 {
                        Shape::Vector64
                    } else {
                        Shape::Vector128
                    };
                    for double in [0, VECTOR_DOUBLE] {
                        if half && double != 0 {
                            continue;
                        }
                        let format = if half {
                            Format::Half
                        } else if double == 0 {
                            Format::Single
                        } else {
                            Format::Double
                        };
                        for h in 0..=INDEX_BIT_MASK {
                            for l in 0..=INDEX_BIT_MASK {
                                for m in 0..=INDEX_BIT_MASK {
                                    for rm in 0..=INDEXED_HALF_REGISTER_MASK {
                                        for destination in 0..=REGISTER_MASK {
                                            for left in 0..=REGISTER_MASK {
                                                let word = encoding
                                                    | subtract
                                                    | q
                                                    | double
                                                    | (h << INDEX_H_SHIFT)
                                                    | (l << INDEX_L_SHIFT)
                                                    | (m << INDEX_M_SHIFT)
                                                    | (rm << RIGHT_SHIFT)
                                                    | (left << LEFT_SHIFT)
                                                    | destination;
                                                let expected = if format == Format::Double
                                                    && (l != 0 || shape == Shape::Vector64)
                                                {
                                                    Err(Unsupported)
                                                } else {
                                                    Ok(Operand {
                                                        operation,
                                                        format,
                                                        shape,
                                                        destination: destination as u8,
                                                        addend: destination as u8,
                                                        left: left as u8,
                                                        right: if half {
                                                            rm
                                                        } else {
                                                            (m << INDEXED_REGISTER_HIGH_SHIFT) | rm
                                                        }
                                                            as u8,
                                                        right_lane: Some(match format {
                                                            Format::Half => {
                                                                (h << HALF_LANE_HIGH_SHIFT)
                                                                    | (l << HALF_LANE_LOW_SHIFT)
                                                                    | m
                                                            }
                                                            Format::Single => {
                                                                (h << SINGLE_LANE_HIGH_SHIFT) | l
                                                            }
                                                            Format::Double => h,
                                                        }
                                                            as u8),
                                                    })
                                                };
                                                assert_eq!(decode(word), Some(expected));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn fixed_bits_and_neighboring_families_do_not_alias() {
        for (encoding, mask) in [
            (FMADD, SCALAR_MASK & !SCALAR_OPERATION_MASK),
            (VECTOR_FMLA, VECTOR_MASK & !VECTOR_OPERATION_MASK),
            (VECTOR_HALF_FMLA, VECTOR_HALF_MASK & !VECTOR_OPERATION_MASK),
            (INDEXED_SCALAR_HALF, INDEXED_SCALAR_HALF_MASK),
            (INDEXED_SCALAR, INDEXED_SCALAR_MASK),
            (INDEXED_VECTOR_HALF, INDEXED_VECTOR_HALF_MASK),
            (INDEXED_VECTOR, INDEXED_VECTOR_MASK),
        ] {
            for bit in 0..u32::BITS {
                let changed_bit = 1 << bit;
                if mask & changed_bit != 0 {
                    let changed = encoding ^ changed_bit;
                    let indexed = matches!(
                        encoding,
                        INDEXED_SCALAR_HALF | INDEXED_SCALAR | INDEXED_VECTOR_HALF | INDEXED_VECTOR
                    );
                    let scalar_indexed = matches!(encoding, INDEXED_SCALAR_HALF | INDEXED_SCALAR);
                    let crosses_family = indexed
                        && (changed_bit == INDEXED_HALF_SINGLE_BIT
                            || changed_bit == INDEXED_SCALAR_VECTOR_BIT
                            || (scalar_indexed && changed_bit == VECTOR_Q));
                    if crosses_family {
                        // These changes enter another fused encoding or reserved ftype.
                        assert!(decode(changed).is_some(), "{changed:08x}");
                    } else {
                        assert_eq!(decode(changed), None, "{changed:08x}");
                    }
                }
            }
        }
        for neighbor in [
            0x1e200800, // FMUL S
            0x1e208800, // FNMUL S
            0x0e20d400, // FADD vector
            0x2e20dc00, // FMUL vector
            0x0e20ec00, // FMLAL vector
            0x0f800000, // FMLAL indexed
            0x0f809000, // FMUL indexed
            0x2f809000, // FMULX indexed
            0x0f00c000, // SQDMULH indexed
        ] {
            assert_eq!(decode(neighbor), None, "{neighbor:08x}");
        }
    }
}
