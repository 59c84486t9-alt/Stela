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

impl Operand {
    /// MOVPRFX policy for the exact canonical follower before any destructive
    /// operand normalization. All 48 policies are pinned to Arm A64 2026-06.
    #[allow(clippy::result_unit_err)]
    pub fn prefix_requirement(
        self,
        original_word: u32,
    ) -> Result<Option<crate::aarch64::sve::prefix::PrefixRequirement>, ()> {
        use crate::aarch64::sve::prefix::{PredicatedPrefixRequirement, PrefixRequirement};

        if decode(original_word) != Some(Ok(self)) {
            return Err(());
        }
        let predicated = match self.predication {
            Predication::Merging(predicate) => Some(PredicatedPrefixRequirement {
                predicate,
                // Every predicated form here has equal source/destination sizes.
                element: self.element_size,
            }),
            Predication::Unpredicated | Predication::Zeroing(_) => None,
        };
        let vector = |predicated, other_vector_sources| PrefixRequirement::Vector {
            destination: self.destination,
            predicated,
            other_vector_sources,
        };
        let source_bit = |register: u8| 1_u32 << register;
        let requirement = match self.kind {
            Kind::Unary { source, .. }
                if matches!(original_word & PREDICATED_MASK, ABS_Z_P_Z_M | NEG_Z_P_Z_M) =>
            {
                Some(vector(predicated, source_bit(source)))
            }
            Kind::Binary {
                right: Source::Vector(right),
                ..
            } if matches!(
                original_word & PREDICATED_MASK,
                ADD_Z_P_ZZ
                    | SUB_Z_P_ZZ
                    | SUBR_Z_P_ZZ
                    | SDIV_Z_P_ZZ
                    | SDIVR_Z_P_ZZ
                    | UDIV_Z_P_ZZ
                    | UDIVR_Z_P_ZZ
                    | SMIN_Z_P_ZZ
                    | UMIN_Z_P_ZZ
                    | SMAX_Z_P_ZZ
                    | UMAX_Z_P_ZZ
            ) =>
            {
                Some(vector(predicated, source_bit(right)))
            }
            Kind::Binary {
                right: Source::Immediate(_),
                ..
            } if matches!(
                original_word & PREDICATED_MASK,
                SMIN_Z_ZI | UMIN_Z_ZI | SMAX_Z_ZI | UMAX_Z_ZI
            ) || matches!(
                original_word & IMMEDIATE_MASK_OPCODE,
                ADD_Z_ZI | SUB_Z_ZI | SUBR_Z_ZI
            ) =>
            {
                Some(vector(None, 0))
            }
            Kind::Carry { source, carry, .. }
                if matches!(
                    original_word & CARRY_MASK,
                    ADCLB_Z_ZZZ | ADCLT_Z_ZZZ | SBCLB_Z_ZZZ | SBCLT_Z_ZZZ
                ) =>
            {
                Some(vector(None, source_bit(source) | source_bit(carry)))
            }
            Kind::ComplexAdd { source, .. } if original_word & COMPLEX_OPCODE_MASK == CADD_Z_ZZ => {
                Some(vector(None, source_bit(source)))
            }
            Kind::Binary {
                left,
                right: Source::Vector(right),
                ..
            } if matches!(
                original_word & REGISTER_OPCODE_MASK,
                SCLAMP_Z_ZZ | UCLAMP_Z_ZZ
            ) =>
            {
                Some(vector(None, source_bit(left) | source_bit(right)))
            }
            Kind::Binary { .. }
                if matches!(original_word & REGISTER_OPCODE_MASK, ADD_Z_ZZ | SUB_Z_ZZ) =>
            {
                Some(PrefixRequirement::Forbidden)
            }
            Kind::Widening { .. }
                if matches!(
                    original_word & REGISTER_OPCODE_MASK,
                    SADDLB_Z_ZZ
                        | SADDLBT_Z_ZZ
                        | SADDLT_Z_ZZ
                        | SADDWB_Z_ZZ
                        | SADDWT_Z_ZZ
                        | SSUBLB_Z_ZZ
                        | SSUBLBT_Z_ZZ
                        | SSUBLT_Z_ZZ
                        | SSUBLTB_Z_ZZ
                        | SSUBWB_Z_ZZ
                        | SSUBWT_Z_ZZ
                        | UADDLB_Z_ZZ
                        | UADDLT_Z_ZZ
                        | UADDWB_Z_ZZ
                        | UADDWT_Z_ZZ
                        | USUBLB_Z_ZZ
                        | USUBLT_Z_ZZ
                        | USUBWB_Z_ZZ
                        | USUBWT_Z_ZZ
                ) =>
            {
                Some(PrefixRequirement::Forbidden)
            }
            _ => None,
        };
        Ok(requirement)
    }
}

#[cfg(test)]
mod tests;
