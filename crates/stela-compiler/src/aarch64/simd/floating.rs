//! FCSEL, FABS and FNEG, including FPCR.AH/NEP behavior.
use crate::aarch64::Unsupported;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignOperation {
    Abs,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Select {
        destination: u8,
        left: u8,
        right: u8,
        lane_bytes: u8,
        condition: u8,
    },
    Sign {
        operation: SignOperation,
        destination: u8,
        source: u8,
        lane_bytes: u8,
        bytes: u8,
        scalar: bool,
    },
}

const SELECT_MASK: u32 = 0xff20_0c00;
const SELECT: u32 = 0x1e20_0c00;
const SCALAR_SIGN_MASK: u32 = 0xff3f_fc00;
const SCALAR_ABS: u32 = 0x1e20_c000;
const SCALAR_NEG: u32 = 0x1e21_4000;
const VECTOR_HALF_MASK: u32 = 0xbfff_fc00;
const VECTOR_HALF_ABS: u32 = 0x0ef8_f800;
const VECTOR_HALF_NEG: u32 = 0x2ef8_f800;
const VECTOR_FLOAT_MASK: u32 = 0xbfbf_fc00;
const VECTOR_FLOAT_ABS: u32 = 0x0ea0_f800;
const VECTOR_FLOAT_NEG: u32 = 0x2ea0_f800;

fn scalar_lane(word: u32) -> Result<u8, Unsupported> {
    match (word >> 22) & 3 {
        0 => Ok(4),
        1 => Ok(8),
        3 => Ok(2),
        _ => Err(Unsupported),
    }
}

pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    let destination = (word & 31) as u8;
    let source = ((word >> 5) & 31) as u8;
    if word & SELECT_MASK == SELECT {
        return Some(scalar_lane(word).map(|lane_bytes| Operand::Select {
            destination,
            left: source,
            right: ((word >> 16) & 31) as u8,
            lane_bytes,
            condition: ((word >> 12) & 15) as u8,
        }));
    }
    let scalar = match word & SCALAR_SIGN_MASK {
        SCALAR_ABS => Some(SignOperation::Abs),
        SCALAR_NEG => Some(SignOperation::Neg),
        _ => None,
    };
    if let Some(operation) = scalar {
        return Some(scalar_lane(word).map(|lane_bytes| Operand::Sign {
            operation,
            destination,
            source,
            lane_bytes,
            bytes: lane_bytes,
            scalar: true,
        }));
    }
    let half = match word & VECTOR_HALF_MASK {
        VECTOR_HALF_ABS => Some(SignOperation::Abs),
        VECTOR_HALF_NEG => Some(SignOperation::Neg),
        _ => None,
    };
    let ordinary = match word & VECTOR_FLOAT_MASK {
        VECTOR_FLOAT_ABS => Some(SignOperation::Abs),
        VECTOR_FLOAT_NEG => Some(SignOperation::Neg),
        _ => None,
    };
    let operation = half.or(ordinary)?;
    let bytes = if word & (1 << 30) == 0 { 8 } else { 16 };
    let lane_bytes = if half.is_some() {
        2
    } else {
        4 << ((word >> 22) & 1)
    };
    if lane_bytes == 8 && bytes == 8 {
        return Some(Err(Unsupported));
    }
    Some(Ok(Operand::Sign {
        operation,
        destination,
        source,
        lane_bytes,
        bytes,
        scalar: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_scalar_types_conditions_and_vector_allocations() {
        for (ftype, bytes) in [(0, 4), (1, 8), (3, 2)] {
            for condition in 0..16 {
                assert_eq!(
                    decode(
                        SELECT | (ftype << 22) | (31 << 16) | (condition << 12) | (29 << 5) | 31
                    ),
                    Some(Ok(Operand::Select {
                        destination: 31,
                        left: 29,
                        right: 31,
                        lane_bytes: bytes,
                        condition: condition as u8,
                    }))
                );
            }
            for (base, operation) in [
                (SCALAR_ABS, SignOperation::Abs),
                (SCALAR_NEG, SignOperation::Neg),
            ] {
                assert_eq!(
                    decode(base | (ftype << 22) | (31 << 5)),
                    Some(Ok(Operand::Sign {
                        operation,
                        destination: 0,
                        source: 31,
                        lane_bytes: bytes,
                        bytes,
                        scalar: true,
                    }))
                );
            }
        }
        for base in [SELECT, SCALAR_ABS, SCALAR_NEG] {
            assert_eq!(decode(base | (2 << 22)), Some(Err(Unsupported)));
        }
        for base in [VECTOR_FLOAT_ABS, VECTOR_FLOAT_NEG] {
            assert_eq!(decode(base | (1 << 22)), Some(Err(Unsupported)));
            assert!(matches!(
                decode(base | (1 << 22) | (1 << 30)),
                Some(Ok(Operand::Sign {
                    lane_bytes: 8,
                    bytes: 16,
                    scalar: false,
                    ..
                }))
            ));
        }
        assert_eq!(decode(0x1e20_4000), None); // FMOV remains in its own family.
        assert_eq!(decode(0x1e20_2800), None); // Numerical FADD is still unsupported.
    }
}
