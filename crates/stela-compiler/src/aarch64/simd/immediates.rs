//! Arm A64 2026-06 modified immediates and FP register/constant bit moves.
//! FEAT_FP/AdvSIMD/FP16 enabled. No numerical FP operations or FPCR-dependent unary.
use super::super::register;
use super::rearrange::{LaneSource, Operand as LaneMove};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstantOperation {
    Move,
    Or,
    BitClear,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Constant {
        destination: u8,
        value: u64,
        bytes: u8,
        operation: ConstantOperation,
    },
    LaneMove(LaneMove),
}
const MODIFIED_MASK: u32 = 0x9ff80400;
const MODIFIED_BASE: u32 = 0x0f000400;
const SCALAR_FLOAT_MASK: u32 = 0xffe01fe0;
const SCALAR_HALF: u32 = 0x1ee01000;
const SCALAR_SINGLE: u32 = 0x1e201000;
const SCALAR_DOUBLE: u32 = 0x1e601000;
const FLOAT_MOVE_MASK: u32 = 0xfffffc00;
const MOVE_HALF: u32 = 0x1ee04000;
const MOVE_SINGLE: u32 = 0x1e204000;
const MOVE_DOUBLE: u32 = 0x1e604000;

fn replicate(value: u64, bytes: u8) -> u64 {
    let mut result = 0;
    for lane in 0..8 / bytes {
        result |= value << (lane * bytes * 8);
    }
    result
}
/// VFPExpandImm constructs sign/exponent/fraction fields, without FP conversion.
fn float_immediate(imm: u8, bytes: u8) -> u64 {
    let exponent_bits = match bytes {
        2 => 5,
        4 => 8,
        8 => 11,
        _ => unreachable!(),
    };
    let fraction_bits = bytes * 8 - exponent_bits - 1;
    let repeated = if imm & 0x40 != 0 {
        (1u64 << (exponent_bits - 3)) - 1
    } else {
        0
    };
    let exponent = (u64::from(imm & 0x40 == 0) << (exponent_bits - 1))
        | (repeated << 2)
        | u64::from((imm >> 4) & 3);
    (u64::from(imm >> 7) << (bytes * 8 - 1))
        | (exponent << fraction_bits)
        | (u64::from(imm & 15) << (fraction_bits - 4))
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let d = (word & 31) as u8;
    let n = ((word >> 5) & 31) as u8;
    let scalar_float = match word & SCALAR_FLOAT_MASK {
        SCALAR_HALF => Some(2),
        SCALAR_SINGLE => Some(4),
        SCALAR_DOUBLE => Some(8),
        _ => None,
    };
    if let Some(bytes) = scalar_float {
        return Some(Ok(Operand::Constant {
            destination: d,
            value: float_immediate(((word >> 13) & 255) as u8, bytes),
            bytes,
            operation: ConstantOperation::Move,
        }));
    }
    let scalar_move = match word & FLOAT_MOVE_MASK {
        MOVE_HALF => Some(2),
        MOVE_SINGLE => Some(4),
        MOVE_DOUBLE => Some(8),
        _ => None,
    };
    if let Some(bytes) = scalar_move {
        return Some(Ok(Operand::LaneMove(LaneMove::Duplicate {
            destination: d,
            source: LaneSource::Vector {
                register: n,
                byte: 0,
            },
            lane_bytes: bytes,
            bytes,
        })));
    }
    // Fixed opcode identities distinguish bit movement from numerical conversion.
    let transfer = match word & FLOAT_MOVE_MASK {
        0x1ee60000 => Some((false, 2, false, false)), // H -> W
        0x9ee60000 => Some((false, 2, false, true)),  // H -> X
        0x1e260000 => Some((false, 4, false, false)), // S -> W
        0x9e660000 => Some((false, 8, false, true)),  // D -> X
        0x9eae0000 => Some((false, 8, true, true)),   // V.D[1] -> X
        0x1ee70000 => Some((true, 2, false, false)),  // W -> H
        0x9ee70000 => Some((true, 2, false, true)),   // X -> H
        0x1e270000 => Some((true, 4, false, false)),  // W -> S
        0x9e670000 => Some((true, 8, false, true)),   // X -> D
        0x9eaf0000 => Some((true, 8, true, true)),    // X -> V.D[1]
        _ => None,
    };
    if let Some((to_vector, bytes, upper, x64)) = transfer {
        let operand = if !to_vector {
            LaneMove::Extract {
                destination: register(u32::from(d), false),
                source: n,
                byte: if upper { 8 } else { 0 },
                lane_bytes: bytes,
                signed: false,
                x64,
            }
        } else if upper {
            LaneMove::Insert {
                destination: d,
                source: LaneSource::General(register(u32::from(n), false)),
                byte: 8,
                lane_bytes: 8,
            }
        } else {
            LaneMove::Duplicate {
                destination: d,
                source: LaneSource::General(register(u32::from(n), false)),
                lane_bytes: bytes,
                bytes,
            }
        };
        return Some(Ok(Operand::LaneMove(operand)));
    }
    if word & MODIFIED_MASK != MODIFIED_BASE {
        return None;
    }
    let q = word & (1 << 30) != 0;
    let op = word & (1 << 29) != 0;
    let half = word & (1 << 11) != 0;
    let cmode = ((word >> 12) & 15) as u8;
    let imm = ((((word >> 16) & 7) << 5) | ((word >> 5) & 31)) as u8;
    let bytes = if q { 16 } else { 8 };
    if half {
        if op || cmode != 15 {
            return Some(Err(()));
        }
        return Some(Ok(Operand::Constant {
            destination: d,
            value: replicate(float_immediate(imm, 2), 2),
            bytes,
            operation: ConstantOperation::Move,
        }));
    }
    if cmode == 14 && op {
        return None;
    } // Existing D/2D MOVI byte-mask lowering.
    if cmode == 15 {
        if op && !q {
            return Some(Err(()));
        }
        let lane = if op { 8 } else { 4 };
        return Some(Ok(Operand::Constant {
            destination: d,
            value: replicate(float_immediate(imm, lane), lane),
            bytes,
            operation: ConstantOperation::Move,
        }));
    }
    let mut value = match cmode {
        0..=7 => replicate(u64::from(imm) << ((cmode >> 1) * 8), 4),
        8..=11 => replicate(u64::from(imm) << (((cmode >> 1) & 1) * 8), 2),
        12 | 13 => {
            let shift = if cmode == 12 { 8 } else { 16 };
            replicate((u64::from(imm) << shift) | ((1u64 << shift) - 1), 4)
        }
        14 => replicate(u64::from(imm), 1),
        _ => unreachable!(),
    };
    let operation = if cmode < 12 && cmode & 1 != 0 {
        if op {
            ConstantOperation::BitClear
        } else {
            ConstantOperation::Or
        }
    } else {
        if op {
            value = !value;
        }
        ConstantOperation::Move
    };
    Some(Ok(Operand::Constant {
        destination: d,
        value,
        bytes,
        operation,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn float_one_constants_have_exact_ieee_width_and_upper_clearing() {
        for (base, bytes, value) in [
            (SCALAR_HALF, 2, 0x3c00),
            (SCALAR_SINGLE, 4, 0x3f800000),
            (SCALAR_DOUBLE, 8, 0x3ff0000000000000),
        ] {
            assert_eq!(
                decode(base | (0x70 << 13) | 31),
                Some(Ok(Operand::Constant {
                    destination: 31,
                    value,
                    bytes,
                    operation: ConstantOperation::Move
                }))
            );
        }
        assert_eq!(decode(0x2f00f400), Some(Err(()))); // vector double requires Q=1
        assert!(decode(0x1ea01000).is_none()); // reserved scalar ftype
        assert!(decode(0x9e260000).is_none()); // numerical conversion is not a bit move
    }
    #[test]
    fn modified_fields_are_not_accidentally_vector_shift_or_polynomial_forms() {
        for cmode in 0..16 {
            for op in 0..2 {
                let word = MODIFIED_BASE | (cmode << 12) | (op << 29);
                if cmode == 14 && op == 1 {
                    assert!(decode(word).is_none());
                } else if cmode == 15 && op == 1 {
                    assert_eq!(decode(word), Some(Err(())));
                } else {
                    assert!(decode(word).unwrap().is_ok());
                }
                let half = decode(word | (1 << 11));
                assert_eq!(half.unwrap().is_ok(), cmode == 15 && op == 0);
            }
        }
        assert!(decode(0x0f080400).is_none()); // SSHR has nonzero immh
    }
}
