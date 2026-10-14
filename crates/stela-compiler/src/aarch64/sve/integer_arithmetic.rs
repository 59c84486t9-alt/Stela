//! Streaming-SVE ordinary integer arithmetic, widening and carry operations.
//! Canonical encodings: hash-pinned Arm A64 2026-06 candidate inventory.
use crate::aarch64::scalable::{ElementSize, Predication};
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const IMMEDIATE_MASK: u32 = 255;
const IMMEDIATE_SHIFT_FLAG: u32 = 1 << 13;
const IMMEDIATE_SHIFT: u32 = 8;
const ROTATION_FLAG: u32 = 1 << 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binary {
    Add,
    Subtract,
    ReverseSubtract,
    Divide { unsigned: bool, reverse: bool },
    Minimum { unsigned: bool },
    Maximum { unsigned: bool },
    Clamp { unsigned: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Vector(u8),
    Immediate(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Binary {
        operation: Binary,
        left: u8,
        right: Source,
    },
    Unary {
        source: u8,
        absolute: bool,
    },
    Widening {
        left: u8,
        right: u8,
        unsigned: bool,
        subtract: bool,
        wide_left: bool,
        left_top: bool,
        right_top: bool,
    },
    Carry {
        source: u8,
        carry: u8,
        subtract: bool,
        top: bool,
    },
    ComplexAdd {
        source: u8,
        rotate_270: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: u8,
    pub element_size: ElementSize,
    pub predication: Predication,
    pub kind: Kind,
}

const PREDICATED_MASK: u32 = 0xff3f_e000;

const CARRY_MASK: u32 = 0xffa0_fc00;

const IMMEDIATE_MASK_OPCODE: u32 = 0xff3f_c000;

const REGISTER_OPCODE_MASK: u32 = 0xff20_fc00;

const COMPLEX_OPCODE_MASK: u32 = 0xff3f_f800;
const ABS_Z_P_Z_M: u32 = 0x0416_a000;
const ADCLB_Z_ZZZ: u32 = 0x4500_d000;
const ADCLT_Z_ZZZ: u32 = 0x4500_d400;
const ADD_Z_P_ZZ: u32 = 0x0400_0000;
const ADD_Z_ZI: u32 = 0x2520_c000;
const ADD_Z_ZZ: u32 = 0x0420_0000;
const CADD_Z_ZZ: u32 = 0x4500_d800;
const NEG_Z_P_Z_M: u32 = 0x0417_a000;
const SADDLB_Z_ZZ: u32 = 0x4500_0000;
const SADDLBT_Z_ZZ: u32 = 0x4500_8000;
const SADDLT_Z_ZZ: u32 = 0x4500_0400;
const SADDWB_Z_ZZ: u32 = 0x4500_4000;
const SADDWT_Z_ZZ: u32 = 0x4500_4400;
const SBCLB_Z_ZZZ: u32 = 0x4580_d000;
const SBCLT_Z_ZZZ: u32 = 0x4580_d400;
const SCLAMP_Z_ZZ: u32 = 0x4400_c000;
const SDIV_Z_P_ZZ: u32 = 0x0414_0000;
const SDIVR_Z_P_ZZ: u32 = 0x0416_0000;
const SMAX_Z_P_ZZ: u32 = 0x0408_0000;
const SMAX_Z_ZI: u32 = 0x2528_c000;
const SMIN_Z_P_ZZ: u32 = 0x040a_0000;
const SMIN_Z_ZI: u32 = 0x252a_c000;
const SSUBLB_Z_ZZ: u32 = 0x4500_1000;
const SSUBLBT_Z_ZZ: u32 = 0x4500_8800;
const SSUBLT_Z_ZZ: u32 = 0x4500_1400;
const SSUBLTB_Z_ZZ: u32 = 0x4500_8c00;
const SSUBWB_Z_ZZ: u32 = 0x4500_5000;
const SSUBWT_Z_ZZ: u32 = 0x4500_5400;
const SUB_Z_P_ZZ: u32 = 0x0401_0000;
const SUB_Z_ZI: u32 = 0x2521_c000;
const SUB_Z_ZZ: u32 = 0x0420_0400;
const SUBR_Z_P_ZZ: u32 = 0x0403_0000;
const SUBR_Z_ZI: u32 = 0x2523_c000;
const UADDLB_Z_ZZ: u32 = 0x4500_0800;
const UADDLT_Z_ZZ: u32 = 0x4500_0c00;
const UADDWB_Z_ZZ: u32 = 0x4500_4800;
const UADDWT_Z_ZZ: u32 = 0x4500_4c00;
const UCLAMP_Z_ZZ: u32 = 0x4400_c400;
const UDIV_Z_P_ZZ: u32 = 0x0415_0000;
const UDIVR_Z_P_ZZ: u32 = 0x0417_0000;
const UMAX_Z_P_ZZ: u32 = 0x0409_0000;
const UMAX_Z_ZI: u32 = 0x2529_c000;
const UMIN_Z_P_ZZ: u32 = 0x040b_0000;
const UMIN_Z_ZI: u32 = 0x252b_c000;
const USUBLB_Z_ZZ: u32 = 0x4500_1800;
const USUBLT_Z_ZZ: u32 = 0x4500_1c00;
const USUBWB_Z_ZZ: u32 = 0x4500_5800;
const USUBWT_Z_ZZ: u32 = 0x4500_5c00;

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let destination = (word & REGISTER_MASK) as u8;
    let source = ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8;
    let right = ((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8;
    let size = (word >> SIZE_SHIFT) & SIZE_MASK;
    let predicate = Predication::Merging(((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8);
    let immediate = ((word >> SOURCE_SHIFT) & IMMEDIATE_MASK) as u8;
    let element_bytes = 1 << size;
    let operand = |bytes, predication, kind| {
        Some(Ok(Operand {
            destination,
            element_size: ElementSize::from_bytes(bytes).unwrap(),
            predication,
            kind,
        }))
    };
    let binary = |operation, left, right| Kind::Binary {
        operation,
        left,
        right,
    };
    let opcode = word & PREDICATED_MASK;
    if matches!(opcode, ABS_Z_P_Z_M | NEG_Z_P_Z_M) {
        return operand(
            element_bytes,
            predicate,
            Kind::Unary {
                source,
                absolute: opcode == ABS_Z_P_Z_M,
            },
        );
    }
    let operation = match opcode {
        ADD_Z_P_ZZ => Some(Binary::Add),
        SUB_Z_P_ZZ => Some(Binary::Subtract),
        SUBR_Z_P_ZZ => Some(Binary::ReverseSubtract),
        SDIV_Z_P_ZZ => Some(Binary::Divide {
            unsigned: false,
            reverse: false,
        }),
        SDIVR_Z_P_ZZ => Some(Binary::Divide {
            unsigned: false,
            reverse: true,
        }),
        UDIV_Z_P_ZZ => Some(Binary::Divide {
            unsigned: true,
            reverse: false,
        }),
        UDIVR_Z_P_ZZ => Some(Binary::Divide {
            unsigned: true,
            reverse: true,
        }),
        SMIN_Z_P_ZZ => Some(Binary::Minimum { unsigned: false }),
        UMIN_Z_P_ZZ => Some(Binary::Minimum { unsigned: true }),
        SMAX_Z_P_ZZ => Some(Binary::Maximum { unsigned: false }),
        UMAX_Z_P_ZZ => Some(Binary::Maximum { unsigned: true }),
        _ => None,
    };
    if let Some(operation) = operation {
        if matches!(operation, Binary::Divide { .. }) && element_bytes < 4 {
            return Some(Err(()));
        }
        return operand(
            element_bytes,
            predicate,
            binary(operation, destination, Source::Vector(source)),
        );
    }
    let immediate_operation = match opcode {
        SMIN_Z_ZI => Some((
            Binary::Minimum { unsigned: false },
            i64::from(immediate as i8),
        )),
        UMIN_Z_ZI => Some((Binary::Minimum { unsigned: true }, i64::from(immediate))),
        SMAX_Z_ZI => Some((
            Binary::Maximum { unsigned: false },
            i64::from(immediate as i8),
        )),
        UMAX_Z_ZI => Some((Binary::Maximum { unsigned: true }, i64::from(immediate))),
        _ => None,
    };
    if let Some((operation, immediate)) = immediate_operation {
        return operand(
            element_bytes,
            Predication::Unpredicated,
            binary(operation, destination, Source::Immediate(immediate)),
        );
    }
    let operation = match word & IMMEDIATE_MASK_OPCODE {
        ADD_Z_ZI => Some(Binary::Add),
        SUB_Z_ZI => Some(Binary::Subtract),
        SUBR_Z_ZI => Some(Binary::ReverseSubtract),
        _ => None,
    };
    if let Some(operation) = operation {
        let shifted = word & IMMEDIATE_SHIFT_FLAG != 0;
        if element_bytes == 1 && shifted {
            return Some(Err(()));
        }
        let value = i64::from(immediate) << if shifted { IMMEDIATE_SHIFT } else { 0 };
        return operand(
            element_bytes,
            Predication::Unpredicated,
            binary(operation, destination, Source::Immediate(value)),
        );
    }
    let carry = match word & CARRY_MASK {
        ADCLB_Z_ZZZ => Some((false, false)),
        ADCLT_Z_ZZZ => Some((false, true)),
        SBCLB_Z_ZZZ => Some((true, false)),
        SBCLT_Z_ZZZ => Some((true, true)),
        _ => None,
    };
    if let Some((subtract, top)) = carry {
        let bytes = 4 << ((word >> SIZE_SHIFT) & 1);
        return operand(
            bytes,
            Predication::Unpredicated,
            Kind::Carry {
                source,
                carry: right,
                subtract,
                top,
            },
        );
    }
    if word & COMPLEX_OPCODE_MASK == CADD_Z_ZZ {
        return operand(
            element_bytes,
            Predication::Unpredicated,
            Kind::ComplexAdd {
                source,
                rotate_270: word & ROTATION_FLAG != 0,
            },
        );
    }
    let opcode = word & REGISTER_OPCODE_MASK;
    let operation = match opcode {
        ADD_Z_ZZ => Some(Binary::Add),
        SUB_Z_ZZ => Some(Binary::Subtract),
        SCLAMP_Z_ZZ => Some(Binary::Clamp { unsigned: false }),
        UCLAMP_Z_ZZ => Some(Binary::Clamp { unsigned: true }),
        _ => None,
    };
    if let Some(operation) = operation {
        return operand(
            element_bytes,
            Predication::Unpredicated,
            binary(operation, source, Source::Vector(right)),
        );
    }
    // Tuple fields describe unsigned, subtraction, wide left, left/top, right/top.
    let widening = match opcode {
        SADDLB_Z_ZZ => Some((false, false, false, false, false)),
        SADDLBT_Z_ZZ => Some((false, false, false, false, true)),
        SADDLT_Z_ZZ => Some((false, false, false, true, true)),
        SADDWB_Z_ZZ => Some((false, false, true, false, false)),
        SADDWT_Z_ZZ => Some((false, false, true, true, true)),
        SSUBLB_Z_ZZ => Some((false, true, false, false, false)),
        SSUBLBT_Z_ZZ => Some((false, true, false, false, true)),
        SSUBLT_Z_ZZ => Some((false, true, false, true, true)),
        SSUBLTB_Z_ZZ => Some((false, true, false, true, false)),
        SSUBWB_Z_ZZ => Some((false, true, true, false, false)),
        SSUBWT_Z_ZZ => Some((false, true, true, true, true)),
        UADDLB_Z_ZZ => Some((true, false, false, false, false)),
        UADDLT_Z_ZZ => Some((true, false, false, true, true)),
        UADDWB_Z_ZZ => Some((true, false, true, false, false)),
        UADDWT_Z_ZZ => Some((true, false, true, true, true)),
        USUBLB_Z_ZZ => Some((true, true, false, false, false)),
        USUBLT_Z_ZZ => Some((true, true, false, true, true)),
        USUBWB_Z_ZZ => Some((true, true, true, false, false)),
        USUBWT_Z_ZZ => Some((true, true, true, true, true)),
        _ => None,
    };
    if let Some((unsigned, subtract, wide_left, left_top, right_top)) = widening {
        if element_bytes == 1 {
            return Some(Err(()));
        }
        return operand(
            element_bytes,
            Predication::Unpredicated,
            Kind::Widening {
                left: source,
                right,
                unsigned,
                subtract,
                wide_left,
                left_top,
                right_top,
            },
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_forms_validate_widths_predicates_and_register_roles() {
        let forms = [
            (ABS_Z_P_Z_M, true, false, false, false),
            (ADCLB_Z_ZZZ, false, true, false, false),
            (ADCLT_Z_ZZZ, false, true, false, false),
            (ADD_Z_P_ZZ, true, false, false, false),
            (ADD_Z_ZI, false, false, false, false),
            (ADD_Z_ZZ, false, false, false, false),
            (CADD_Z_ZZ, false, false, false, false),
            (NEG_Z_P_Z_M, true, false, false, false),
            (SADDLB_Z_ZZ, false, false, true, false),
            (SADDLBT_Z_ZZ, false, false, true, false),
            (SADDLT_Z_ZZ, false, false, true, false),
            (SADDWB_Z_ZZ, false, false, true, false),
            (SADDWT_Z_ZZ, false, false, true, false),
            (SBCLB_Z_ZZZ, false, true, false, false),
            (SBCLT_Z_ZZZ, false, true, false, false),
            (SCLAMP_Z_ZZ, false, false, false, false),
            (SDIV_Z_P_ZZ, true, false, false, true),
            (SDIVR_Z_P_ZZ, true, false, false, true),
            (SMAX_Z_P_ZZ, true, false, false, false),
            (SMAX_Z_ZI, false, false, false, false),
            (SMIN_Z_P_ZZ, true, false, false, false),
            (SMIN_Z_ZI, false, false, false, false),
            (SSUBLB_Z_ZZ, false, false, true, false),
            (SSUBLBT_Z_ZZ, false, false, true, false),
            (SSUBLT_Z_ZZ, false, false, true, false),
            (SSUBLTB_Z_ZZ, false, false, true, false),
            (SSUBWB_Z_ZZ, false, false, true, false),
            (SSUBWT_Z_ZZ, false, false, true, false),
            (SUB_Z_P_ZZ, true, false, false, false),
            (SUB_Z_ZI, false, false, false, false),
            (SUB_Z_ZZ, false, false, false, false),
            (SUBR_Z_P_ZZ, true, false, false, false),
            (SUBR_Z_ZI, false, false, false, false),
            (UADDLB_Z_ZZ, false, false, true, false),
            (UADDLT_Z_ZZ, false, false, true, false),
            (UADDWB_Z_ZZ, false, false, true, false),
            (UADDWT_Z_ZZ, false, false, true, false),
            (UCLAMP_Z_ZZ, false, false, false, false),
            (UDIV_Z_P_ZZ, true, false, false, true),
            (UDIVR_Z_P_ZZ, true, false, false, true),
            (UMAX_Z_P_ZZ, true, false, false, false),
            (UMAX_Z_ZI, false, false, false, false),
            (UMIN_Z_P_ZZ, true, false, false, false),
            (UMIN_Z_ZI, false, false, false, false),
            (USUBLB_Z_ZZ, false, false, true, false),
            (USUBLT_Z_ZZ, false, false, true, false),
            (USUBWB_Z_ZZ, false, false, true, false),
            (USUBWT_Z_ZZ, false, false, true, false),
        ];
        for (opcode, predicated, carry, widening, division) in forms {
            let maximum_size = if carry { 1 } else { SIZE_MASK };
            for size in 0..=maximum_size {
                for destination in 0..=REGISTER_MASK {
                    let word = opcode | (size << SIZE_SHIFT) | destination;
                    let result = decode(word).unwrap();
                    if (widening && size == 0) || (division && size < 2) {
                        assert_eq!(result, Err(()));
                        continue;
                    }
                    let operand = result.unwrap();
                    assert_eq!(operand.destination, destination as u8);
                    assert_eq!(
                        operand.element_size.bytes(),
                        if carry { 4 << size } else { 1 << size }
                    );
                    assert_eq!(
                        operand.predication,
                        if predicated {
                            Predication::Merging(0)
                        } else {
                            Predication::Unpredicated
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn immediate_byte_shift_is_reserved_and_signed_minmax_extend_imm8() {
        for opcode in [ADD_Z_ZI, SUB_Z_ZI, SUBR_Z_ZI] {
            assert_eq!(decode(opcode | IMMEDIATE_SHIFT_FLAG), Some(Err(())));
            assert!(
                decode(opcode | (1 << SIZE_SHIFT) | IMMEDIATE_SHIFT_FLAG)
                    .unwrap()
                    .is_ok()
            );
        }
        for opcode in [SMIN_Z_ZI, SMAX_Z_ZI] {
            let operand = decode(opcode | (IMMEDIATE_MASK << SOURCE_SHIFT))
                .unwrap()
                .unwrap();
            assert!(matches!(
                operand.kind,
                Kind::Binary {
                    right: Source::Immediate(-1),
                    ..
                }
            ));
        }
    }

    #[test]
    fn aliases_include_z31_and_destructive_sources_keep_roles() {
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                let operand = decode(ADD_Z_P_ZZ | (source << SOURCE_SHIFT) | destination)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    operand.kind,
                    Kind::Binary {
                        operation: Binary::Add,
                        left: destination as u8,
                        right: Source::Vector(source as u8)
                    }
                );
                let operand = decode(
                    ADCLT_Z_ZZZ
                        | (source << SOURCE_SHIFT)
                        | (REGISTER_MASK << RIGHT_SHIFT)
                        | destination,
                )
                .unwrap()
                .unwrap();
                assert_eq!(
                    operand.kind,
                    Kind::Carry {
                        source: source as u8,
                        carry: REGISTER_MASK as u8,
                        subtract: false,
                        top: true
                    }
                );
            }
        }
    }
}
