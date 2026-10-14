//! Scalar and AdvSIMD FADD/FSUB/FMUL/FDIV from the pinned Arm 2026-06 reference.
use crate::aarch64::floating::{BinaryOperation, Format};

const SCALAR_MASK: u32 = 0xff20fc00;
const FADD: u32 = 0x1e202800;
const FSUB: u32 = 0x1e203800;
const FMUL: u32 = 0x1e200800;
const FDIV: u32 = 0x1e201800;
const VECTOR_MASK: u32 = 0xbfa0fc00;
const VECTOR_FADD: u32 = 0x0e20d400;
const VECTOR_FSUB: u32 = 0x0ea0d400;
const VECTOR_FMUL: u32 = 0x2e20dc00;
const VECTOR_FDIV: u32 = 0x2e20fc00;
const VECTOR_HALF_MASK: u32 = 0xbfe0fc00;
const VECTOR_HALF_FADD: u32 = 0x0e401400;
const VECTOR_HALF_FSUB: u32 = 0x0ec01400;
const VECTOR_HALF_FMUL: u32 = 0x2e401c00;
const VECTOR_HALF_FDIV: u32 = 0x2e403c00;
const VECTOR_Q: u32 = 1 << 30;
const VECTOR_DOUBLE: u32 = 1 << 22;
const VECTOR64_BITS: u32 = 64;
const VECTOR128_BITS: u32 = 128;
const FORMAT_SHIFT: u32 = 22;
const FORMAT_MASK: u32 = 3;
const FORMAT_SINGLE: u32 = 0;
const FORMAT_DOUBLE: u32 = 1;
const FORMAT_HALF: u32 = 3;
const REGISTER_MASK: u32 = 31;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Scalar,
    Vector64,
    Vector128,
}

impl Shape {
    pub const fn lane_count(self, format: Format) -> u32 {
        match self {
            Self::Scalar => 1,
            Self::Vector64 => VECTOR64_BITS / format.bits(),
            Self::Vector128 => VECTOR128_BITS / format.bits(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub operation: BinaryOperation,
    pub format: Format,
    pub shape: Shape,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
}

/// None is another family; Err is reserved scalar ftype or vector 1D.
/// All register fields denote ordinary V registers, including register 31.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let scalar_operation = match word & SCALAR_MASK {
        FADD => Some(BinaryOperation::Add),
        FSUB => Some(BinaryOperation::Subtract),
        FMUL => Some(BinaryOperation::Multiply),
        FDIV => Some(BinaryOperation::Divide),
        _ => None,
    };
    let (operation, format, shape) = if let Some(operation) = scalar_operation {
        let format = match (word >> FORMAT_SHIFT) & FORMAT_MASK {
            FORMAT_SINGLE => Format::Single,
            FORMAT_DOUBLE => Format::Double,
            FORMAT_HALF => Format::Half,
            _ => return Some(Err(())),
        };
        (operation, format, Shape::Scalar)
    } else {
        let half_operation = match word & VECTOR_HALF_MASK {
            VECTOR_HALF_FADD => Some(BinaryOperation::Add),
            VECTOR_HALF_FSUB => Some(BinaryOperation::Subtract),
            VECTOR_HALF_FMUL => Some(BinaryOperation::Multiply),
            VECTOR_HALF_FDIV => Some(BinaryOperation::Divide),
            _ => None,
        };
        let shape = if word & VECTOR_Q == 0 {
            Shape::Vector64
        } else {
            Shape::Vector128
        };
        let (operation, format) = if let Some(operation) = half_operation {
            (operation, Format::Half)
        } else {
            let operation = match word & VECTOR_MASK {
                VECTOR_FADD => BinaryOperation::Add,
                VECTOR_FSUB => BinaryOperation::Subtract,
                VECTOR_FMUL => BinaryOperation::Multiply,
                VECTOR_FDIV => BinaryOperation::Divide,
                _ => return None,
            };
            let format = if word & VECTOR_DOUBLE == 0 {
                Format::Single
            } else {
                if shape == Shape::Vector64 {
                    return Some(Err(()));
                }
                Format::Double
            };
            (operation, format)
        };
        (operation, format, shape)
    };
    Some(Ok(Operand {
        operation,
        format,
        shape,
        destination: (word & REGISTER_MASK) as u8,
        left: ((word >> LEFT_SHIFT) & REGISTER_MASK) as u8,
        right: ((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORMAT_RESERVED: u32 = 2;
    const SCALAR_OPERATION_FIELD_MASK: u32 = 0x3000;
    const VECTOR_OPERATION_FIELD_MASK: u32 = 0x20802800;
    const OPERATIONS: [(u32, BinaryOperation); 4] = [
        (FADD, BinaryOperation::Add),
        (FSUB, BinaryOperation::Subtract),
        (FMUL, BinaryOperation::Multiply),
        (FDIV, BinaryOperation::Divide),
    ];
    const VECTOR_OPERATIONS: [(u32, u32, BinaryOperation); 4] = [
        (VECTOR_FADD, VECTOR_HALF_FADD, BinaryOperation::Add),
        (VECTOR_FSUB, VECTOR_HALF_FSUB, BinaryOperation::Subtract),
        (VECTOR_FMUL, VECTOR_HALF_FMUL, BinaryOperation::Multiply),
        (VECTOR_FDIV, VECTOR_HALF_FDIV, BinaryOperation::Divide),
    ];

    fn instruction(operation: u32, format: u32, destination: u32, left: u32, right: u32) -> u32 {
        operation
            | (format << FORMAT_SHIFT)
            | (left << LEFT_SHIFT)
            | (right << RIGHT_SHIFT)
            | destination
    }

    #[test]
    fn every_operation_format_and_register_combination_is_explicit() {
        for (encoding, operation) in OPERATIONS {
            for format_field in 0..=FORMAT_MASK {
                let format = match format_field {
                    FORMAT_SINGLE => Some(Format::Single),
                    FORMAT_DOUBLE => Some(Format::Double),
                    FORMAT_HALF => Some(Format::Half),
                    FORMAT_RESERVED => None,
                    _ => unreachable!(),
                };
                for destination in 0..=REGISTER_MASK {
                    for left in 0..=REGISTER_MASK {
                        for right in 0..=REGISTER_MASK {
                            let decoded = decode(instruction(
                                encoding,
                                format_field,
                                destination,
                                left,
                                right,
                            ));
                            let expected = format.map_or(Err(()), |format| {
                                Ok(Operand {
                                    operation,
                                    format,
                                    shape: Shape::Scalar,
                                    destination: destination as u8,
                                    left: left as u8,
                                    right: right as u8,
                                })
                            });
                            assert_eq!(decoded, Some(expected));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn every_vector_shape_and_register_combination_is_explicit() {
        for (ordinary, half, operation) in VECTOR_OPERATIONS {
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
                                    | (left << LEFT_SHIFT)
                                    | (right << RIGHT_SHIFT)
                                    | destination;
                                let expected =
                                    if format == Format::Double && shape == Shape::Vector64 {
                                        Err(())
                                    } else {
                                        Ok(Operand {
                                            operation,
                                            format,
                                            shape,
                                            destination: destination as u8,
                                            left: left as u8,
                                            right: right as u8,
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
    fn lane_counts_follow_allocated_scalar_and_vector_shapes() {
        for format in [Format::Half, Format::Single, Format::Double] {
            assert_eq!(Shape::Scalar.lane_count(format), 1);
        }
        for (shape, format, lanes) in [
            (Shape::Vector64, Format::Half, 4),
            (Shape::Vector128, Format::Half, 8),
            (Shape::Vector64, Format::Single, 2),
            (Shape::Vector128, Format::Single, 4),
            (Shape::Vector128, Format::Double, 2),
        ] {
            assert_eq!(shape.lane_count(format), lanes);
        }
    }

    #[test]
    fn altered_fixed_bits_and_neighboring_numerical_families_do_not_match() {
        let fixed_mask = SCALAR_MASK & !SCALAR_OPERATION_FIELD_MASK;
        for (encoding, _) in OPERATIONS {
            for format in 0..=FORMAT_MASK {
                let word = instruction(
                    encoding,
                    format,
                    REGISTER_MASK,
                    REGISTER_MASK,
                    REGISTER_MASK,
                );
                for bit in 0..u32::BITS {
                    let changed_bit = 1 << bit;
                    if fixed_mask & changed_bit != 0 {
                        assert_eq!(decode(word ^ changed_bit), None);
                    }
                }
            }
        }
        for (ordinary, half, _) in VECTOR_OPERATIONS {
            for (encoding, mask) in [(ordinary, VECTOR_MASK), (half, VECTOR_HALF_MASK)] {
                let fixed_mask = mask & !VECTOR_OPERATION_FIELD_MASK;
                for q in [0, VECTOR_Q] {
                    let word = encoding
                        | q
                        | (REGISTER_MASK << LEFT_SHIFT)
                        | (REGISTER_MASK << RIGHT_SHIFT)
                        | REGISTER_MASK;
                    for bit in 0..u32::BITS {
                        let changed_bit = 1 << bit;
                        if fixed_mask & changed_bit != 0 {
                            assert_eq!(decode(word ^ changed_bit), None);
                        }
                    }
                }
            }
        }
        for neighbor in [
            0x1e204800, // FMAX
            0x1e205800, // FMIN
            0x1e206800, // FMAXNM
            0x1e207800, // FMINNM
            0x1e208800, // FNMUL
            0x1e200c00, // FCSEL
            0x1e202000, // FCMP
            0x1f000000, // FMADD
        ] {
            for format in 0..=FORMAT_MASK {
                assert_eq!(
                    decode(instruction(
                        neighbor,
                        format,
                        REGISTER_MASK,
                        REGISTER_MASK,
                        REGISTER_MASK
                    )),
                    None
                );
            }
        }
        const VECTOR_FADDP: u32 = 0x2e20d400;
        const VECTOR_FMULX: u32 = 0x0e20dc00;
        const VECTOR_FABD: u32 = 0x2ea0d400;
        const VECTOR_FMLA: u32 = 0x0e20cc00;
        const VECTOR_FMLS: u32 = 0x0ea0cc00;
        const VECTOR_FMAX: u32 = 0x0e20f400;
        const VECTOR_FMIN: u32 = 0x0ea0f400;
        const VECTOR_FCMEQ: u32 = 0x0e20e400;
        const VECTOR_FCMGE: u32 = 0x2e20e400;
        const INDEXED_FMUL: u32 = 0x0f809000;
        const INDEXED_HALF_FMUL: u32 = 0x0f009000;
        const VECTOR_ADD: u32 = 0x0e208400;
        const VECTOR_SUB: u32 = 0x2e208400;
        for neighbor in [
            VECTOR_FADDP,
            VECTOR_FMULX,
            VECTOR_FABD,
            VECTOR_FMLA,
            VECTOR_FMLS,
            VECTOR_FMAX,
            VECTOR_FMIN,
            VECTOR_FCMEQ,
            VECTOR_FCMGE,
            INDEXED_FMUL,
            INDEXED_HALF_FMUL,
            VECTOR_ADD,
            VECTOR_SUB,
        ] {
            for q in [0, VECTOR_Q] {
                for size in [0, VECTOR_DOUBLE] {
                    assert_eq!(
                        decode(
                            neighbor
                                | q
                                | size
                                | (REGISTER_MASK << LEFT_SHIFT)
                                | (REGISTER_MASK << RIGHT_SHIFT)
                                | REGISTER_MASK
                        ),
                        None
                    );
                }
            }
        }
    }
}
