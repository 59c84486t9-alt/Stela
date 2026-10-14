//! Scalar FADD/FSUB/FMUL/FDIV encodings from the pinned Arm 2026-06 reference.
use crate::aarch64::floating::{BinaryOperation, Format};

const ENCODING_MASK: u32 = 0xff20fc00;
const FADD: u32 = 0x1e202800;
const FSUB: u32 = 0x1e203800;
const FMUL: u32 = 0x1e200800;
const FDIV: u32 = 0x1e201800;
const FORMAT_SHIFT: u32 = 22;
const FORMAT_MASK: u32 = 3;
const FORMAT_SINGLE: u32 = 0;
const FORMAT_DOUBLE: u32 = 1;
const FORMAT_HALF: u32 = 3;
const REGISTER_MASK: u32 = 31;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub operation: BinaryOperation,
    pub format: Format,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
}

/// None is another family; Err is the reserved ftype within these four opcodes.
/// All register fields denote ordinary V registers, including register 31.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let operation = match word & ENCODING_MASK {
        FADD => BinaryOperation::Add,
        FSUB => BinaryOperation::Subtract,
        FMUL => BinaryOperation::Multiply,
        FDIV => BinaryOperation::Divide,
        _ => return None,
    };
    let format = match (word >> FORMAT_SHIFT) & FORMAT_MASK {
        FORMAT_SINGLE => Format::Single,
        FORMAT_DOUBLE => Format::Double,
        FORMAT_HALF => Format::Half,
        _ => return Some(Err(())),
    };
    Some(Ok(Operand {
        operation,
        format,
        destination: (word & REGISTER_MASK) as u8,
        left: ((word >> LEFT_SHIFT) & REGISTER_MASK) as u8,
        right: ((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORMAT_RESERVED: u32 = 2;
    const OPERATION_FIELD_MASK: u32 = 0x3000;
    const OPERATIONS: [(u32, BinaryOperation); 4] = [
        (FADD, BinaryOperation::Add),
        (FSUB, BinaryOperation::Subtract),
        (FMUL, BinaryOperation::Multiply),
        (FDIV, BinaryOperation::Divide),
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
    fn altered_fixed_bits_and_neighboring_numerical_families_do_not_match() {
        let fixed_mask = ENCODING_MASK & !OPERATION_FIELD_MASK;
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
        for neighbor in [
            0x1e204800, // FMAX
            0x1e205800, // FMIN
            0x1e206800, // FMAXNM
            0x1e207800, // FMINNM
            0x1e208800, // FNMUL
            0x1e200c00, // FCSEL
            0x1e202000, // FCMP
            0x1f000000, // FMADD
            0x0e20d400, // FADD vector
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
    }
}
