//! FP binary arithmetic: SSE2 for normal values, software fallback otherwise.
use alloc::vec;
use alloc::vec::Vec;
mod half;
use super::super::isa::ShiftOpcode;
use super::numerical::{
    ArithmeticOpcode, Condition, EXPONENT_VECTOR, INPUT_MINIMUM_EXPONENT, LEFT_VECTOR,
    MOVLHPS_XMM1_XMM2, MOVQ_XMM0_XMM0, RESULT_MINIMUM_EXPONENT, RIGHT_VECTOR,
    SINGLE_EXPONENT_BIAS_BITS, ZeroProduct, branch, clear_scalar, commit_inexact, emit_opcode,
    environment, exponent_range, jump, prepare_vector_input_range, prepare_vector_result_range,
    read_numerical_right, read_numerical_vector, reject_other_status, resolve, restore_environment,
    sticky_inexact, sticky_result_check, test_control, vector_exponent_range, zero_product_check,
};
use super::{Host, commit, packed, read_vector, shuffle};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{BinaryOperation, FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, Format},
        simd::arithmetic::{Inputs, Operand, Shape},
    },
    block::ExitKind,
};

const PAIRED_RIGHT: u8 = 6;
const SIGN_MASK_VECTOR: u8 = 2;
const SSE_ESCAPE: u8 = 0x0f;
const REGISTER_DIRECT: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const SHUFPS: u8 = 0xc6;
const UNPCKLPS_XMM0_XMM1: &[u8] = &[0x0f, 0x14, 0xc1];
const MOVHLPS_XMM1_XMM0: &[u8] = &[0x0f, 0x12, 0xc8];
const EVEN_SINGLE_LANES: u8 = 0x88;
const ODD_SINGLE_LANES: u8 = 0xdd;
const FIRST_LANE: u8 = 0;
const REPLICATE_SINGLE_LANE: u8 = 0x55;
const REPLICATE_LOW_DOUBLE: u8 = 0x44;
const REPLICATE_HIGH_DOUBLE: u8 = 0xee;
const SIGN_BITS: u8 = 1;
const MOVD_EAX_XMM0: &[u8] = &[0x66, 0x0f, 0x7e, 0xc0];
const MOVQ_RAX_XMM0: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xc0];
const MOVD_XMM2_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xd0];
const MOVQ_XMM2_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e, 0xd0];
const MOVSS_XMM0_XMM2: &[u8] = &[0xf3, 0x0f, 0x10, 0xc2];
const MOVSD_XMM0_XMM2: &[u8] = &[0xf2, 0x0f, 0x10, 0xc2];
const AND_EAX_IMM32: u8 = 0x25;
const XOR_EAX_IMM32: u8 = 0x35;
const BTR_RAX_IMM8: &[u8] = &[0x48, 0x0f, 0xba, 0xf0];
const BTC_RAX_IMM8: &[u8] = &[0x48, 0x0f, 0xba, 0xf8];

fn arithmetic_opcode(operation: BinaryOperation) -> ArithmeticOpcode {
    match operation {
        BinaryOperation::Add => ArithmeticOpcode::Add,
        BinaryOperation::Subtract | BinaryOperation::AbsoluteDifference => {
            ArithmeticOpcode::Subtract
        }
        BinaryOperation::Multiply
        | BinaryOperation::NegatedMultiply
        | BinaryOperation::MultiplyExtended => ArithmeticOpcode::Multiply,
        BinaryOperation::Divide => ArithmeticOpcode::Divide,
    }
}

fn shuffle_single(code: &mut Vec<u8>, destination: u8, source: u8, lanes: u8) {
    code.extend([
        SSE_ESCAPE,
        SHUFPS,
        REGISTER_DIRECT | (destination << MODRM_REGISTER_SHIFT) | source,
        lanes,
    ]);
}

/// Stage adjacent Vn pairs before adjacent Vm pairs without numerical work.
/// Return the right host register; classifier scratch XMM2/3/4/5 must not alias it.
fn prepare_pairs(code: &mut Vec<u8>, format: Format, shape: Shape) -> u8 {
    match (format, shape) {
        (Format::Single, Shape::Vector64) => {
            // Q0 loads zero both high qwords. The extra packed sums are normal
            // values plus zero, so they cannot add exceptions to active lanes.
            code.extend(UNPCKLPS_XMM0_XMM1);
            code.extend(MOVHLPS_XMM1_XMM0);
            RIGHT_VECTOR
        }
        (Format::Single, Shape::Vector128) => {
            packed(code, Host::MoveAligned, PAIRED_RIGHT, LEFT_VECTOR);
            shuffle_single(code, LEFT_VECTOR, RIGHT_VECTOR, EVEN_SINGLE_LANES);
            shuffle_single(code, PAIRED_RIGHT, RIGHT_VECTOR, ODD_SINGLE_LANES);
            PAIRED_RIGHT
        }
        (Format::Double, Shape::Vector128) => {
            packed(code, Host::MoveAligned, PAIRED_RIGHT, LEFT_VECTOR);
            packed(code, Host::UnpackLowQword, LEFT_VECTOR, RIGHT_VECTOR);
            packed(code, Host::UnpackHighQword, PAIRED_RIGHT, RIGHT_VECTOR);
            PAIRED_RIGHT
        }
        _ => unreachable!("allocated S/D vector pairwise shape"),
    }
}

fn prepare_inputs(code: &mut Vec<u8>, operand: &Operand) -> u8 {
    match operand.inputs {
        Inputs::Elementwise { left, right } => {
            read_numerical_vector(code, operand.shape, left, LEFT_VECTOR);
            read_numerical_vector(code, operand.shape, right, RIGHT_VECTOR);
            RIGHT_VECTOR
        }
        Inputs::Indexed {
            left,
            right,
            right_lane,
        } => {
            read_numerical_vector(code, operand.shape, left, LEFT_VECTOR);
            // Both policies select from the whole Vm. The 128-bit form uses one
            // shuffle; the 64-bit form keeps its shift and broadcast and can
            // still select an upper lane.
            if operand.shape == Shape::Vector128 {
                read_vector(code, right, RIGHT_VECTOR);
                let lanes = match operand.format {
                    Format::Single => right_lane * REPLICATE_SINGLE_LANE,
                    Format::Double if right_lane == FIRST_LANE => REPLICATE_LOW_DOUBLE,
                    Format::Double => REPLICATE_HIGH_DOUBLE,
                    Format::Half => unreachable!("Half has its own mapping policy"),
                };
                shuffle(code, RIGHT_VECTOR, RIGHT_VECTOR, lanes);
            } else {
                read_numerical_right(code, operand.format, operand.shape, right, Some(right_lane));
            }
            RIGHT_VECTOR
        }
        Inputs::Pairwise { left, right } => {
            read_numerical_vector(code, operand.shape, left, LEFT_VECTOR);
            read_numerical_vector(code, operand.shape, right, RIGHT_VECTOR);
            prepare_pairs(code, operand.format, operand.shape)
        }
        Inputs::PairwiseScalar { source } => {
            read_vector(code, source, LEFT_VECTOR);
            packed(code, Host::MoveAligned, RIGHT_VECTOR, LEFT_VECTOR);
            ShiftOpcode::RightBytes.emit(
                code,
                RIGHT_VECTOR,
                (operand.format.bits() / u8::BITS) as u8,
            );
            RIGHT_VECTOR
        }
    }
}

/// FNMUL/FABD transform the rounded result. Only finite normal results reach
/// this point, so AH's NaN sign policy stays on the exact helper path.
fn result_sign(code: &mut Vec<u8>, operand: &Operand) {
    let negate = match operand.operation {
        BinaryOperation::NegatedMultiply => true,
        BinaryOperation::AbsoluteDifference => false,
        _ => return,
    };
    if operand.shape == Shape::Scalar {
        match operand.format {
            Format::Single => {
                code.extend(MOVD_EAX_XMM0);
                code.push(if negate { XOR_EAX_IMM32 } else { AND_EAX_IMM32 });
                let sign = operand.format.sign_mask() as u32;
                code.extend((if negate { sign } else { !sign }).to_le_bytes());
                code.extend(MOVD_XMM2_EAX);
                code.extend(MOVSS_XMM0_XMM2);
            }
            Format::Double => {
                code.extend(MOVQ_RAX_XMM0);
                code.extend(if negate { BTC_RAX_IMM8 } else { BTR_RAX_IMM8 });
                code.push(operand.format.bits() as u8 - SIGN_BITS);
                code.extend(MOVQ_XMM2_RAX);
                code.extend(MOVSD_XMM0_XMM2);
            }
            Format::Half => unreachable!("Half has its own mapping policy"),
        }
    } else {
        packed(code, Host::EqualDword, SIGN_MASK_VECTOR, SIGN_MASK_VECTOR);
        let shift = match (operand.format, negate) {
            (Format::Single, true) => ShiftOpcode::LeftDword,
            (Format::Double, true) => ShiftOpcode::LeftQword,
            (Format::Single, false) => ShiftOpcode::RightDword,
            (Format::Double, false) => ShiftOpcode::RightQword,
            (Format::Half, _) => unreachable!("Half has its own mapping policy"),
        };
        shift.emit(
            code,
            SIGN_MASK_VECTOR,
            if negate {
                operand.format.bits() as u8 - SIGN_BITS
            } else {
                SIGN_BITS
            },
        );
        packed(
            code,
            if negate { Host::Xor } else { Host::And },
            LEFT_VECTOR,
            SIGN_MASK_VECTOR,
        );
    }
}

/// Addition and subtraction results below the minimum normal are exact, so
/// they raise no guest status.
fn exact_tiny(operation: BinaryOperation) -> bool {
    matches!(
        operation,
        BinaryOperation::Add | BinaryOperation::Subtract | BinaryOperation::AbsoluteDifference
    )
}

/// A product whose rounded result is a zero is exact, without status,
/// exactly when an input is a zero; otherwise it underflowed. FMULX's
/// zero times infinity is two, not a zero.
fn zero_product(operation: BinaryOperation) -> bool {
    matches!(
        operation,
        BinaryOperation::Multiply
            | BinaryOperation::NegatedMultiply
            | BinaryOperation::MultiplyExtended
    )
}

/// The left source, whose register the operation overwrote, for the
/// out-of-line zero-product check: still unchanged in the frame.
fn product_left(operand: &Operand) -> u8 {
    match operand.inputs {
        Inputs::Elementwise { left, .. } | Inputs::Indexed { left, .. } => left,
        Inputs::Pairwise { .. } | Inputs::PairwiseScalar { .. } => {
            unreachable!("pairwise forms add")
        }
    }
}

/// The sticky-inexact path (`numerical::sticky_inexact`): the operation in
/// the entry MXCSR, its result classification and the commit, which clears
/// scalar upper bits as NEP is zero there. Products that the classification
/// rejects first take an out-of-line check for exact zeros
/// ([`zero_product`]). Returns the branches to the full path, to the helper
/// and past the full path.
fn sticky_path(code: &mut Vec<u8>, operand: &Operand) -> ([usize; 2], Vec<usize>, usize) {
    let full = sticky_inexact(code);
    let right = prepare_inputs(code, operand);
    emit_opcode(
        code,
        operand.format,
        operand.shape,
        arithmetic_opcode(operand.operation),
        right,
    );
    let rejected = sticky_result_check(
        code,
        operand.format,
        operand.shape,
        LEFT_VECTOR,
        exact_tiny(operand.operation),
    );
    let resume = code.len();
    result_sign(code, operand);
    match operand.shape {
        Shape::Scalar => clear_scalar(code, operand.format, LEFT_VECTOR),
        Shape::Vector64 => code.extend(MOVQ_XMM0_XMM0),
        Shape::Vector128 => {}
    }
    commit(code, operand.destination, LEFT_VECTOR);
    let done = jump(code);
    if !zero_product(operand.operation) {
        return (full, vec![rejected], done);
    }
    let check = code.len();
    resolve(code, rejected, check);
    let helper = zero_product_check(
        code,
        &ZeroProduct {
            format: operand.format,
            shape: operand.shape,
            right,
            left: product_left(operand),
            addend: None,
        },
        resume,
    );
    (full, helper, done)
}

fn emit_scalar(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress) {
    let (full, sticky_helper, sticky_done) = sticky_path(code, operand);
    let full_start = code.len();
    for patch in full {
        resolve(code, patch, full_start);
    }
    let mut helper = sticky_helper;
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    let right = prepare_inputs(code, operand);
    for right in [LEFT_VECTOR, right] {
        exponent_range(code, operand.format, right, INPUT_MINIMUM_EXPONENT);
        helper.push(branch(code, Condition::AboveOrEqual));
    }
    environment(code);
    emit_opcode(
        code,
        operand.format,
        operand.shape,
        arithmetic_opcode(operand.operation),
        right,
    );
    restore_environment(code);
    // Caller environment and stack are restored before every branch from here.
    helper.push(reject_other_status(code));
    exponent_range(code, operand.format, LEFT_VECTOR, RESULT_MINIMUM_EXPONENT);
    let success = branch(code, Condition::Below);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, success, success_start);

    commit_inexact(code);
    result_sign(code, operand);
    if matches!(operand.inputs, Inputs::PairwiseScalar { .. }) {
        clear_scalar(code, operand.format, LEFT_VECTOR);
    } else {
        test_control(code, FPCR_NEP);
        let merge = branch(code, Condition::NotZero);
        clear_scalar(code, operand.format, LEFT_VECTOR);
        let merge_target = code.len();
        resolve(code, merge, merge_target);
    }
    commit(code, operand.destination, LEFT_VECTOR);
    let done = code.len();
    resolve(code, sticky_done, done);
}

fn emit_vector(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress) {
    let (full, sticky_helper, sticky_done) = sticky_path(code, operand);
    let full_start = code.len();
    for patch in full {
        resolve(code, patch, full_start);
    }
    let mut helper = sticky_helper;
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    let right = prepare_inputs(code, operand);
    prepare_vector_input_range(code, operand.format);
    for source in [LEFT_VECTOR, right] {
        vector_exponent_range(code, operand.format, operand.shape, source);
        helper.push(branch(code, Condition::NotZero));
    }
    if operand.shape == Shape::Vector64 && operand.operation == BinaryOperation::Divide {
        // Inactive numerators are zero; 1.0 denominators keep 0/0 from raising
        // host invalid.
        packed(code, Host::EqualDword, EXPONENT_VECTOR, EXPONENT_VECTOR);
        ShiftOpcode::RightDword.emit(
            code,
            EXPONENT_VECTOR,
            u32::BITS as u8 - SINGLE_EXPONENT_BIAS_BITS,
        );
        ShiftOpcode::LeftDword.emit(code, EXPONENT_VECTOR, Format::Single.fraction_bits() as u8);
        code.extend(MOVLHPS_XMM1_XMM2);
    }
    environment(code);
    emit_opcode(
        code,
        operand.format,
        operand.shape,
        arithmetic_opcode(operand.operation),
        right,
    );
    restore_environment(code);
    helper.push(reject_other_status(code));
    prepare_vector_result_range(code);
    vector_exponent_range(code, operand.format, operand.shape, LEFT_VECTOR);
    let success = branch(code, Condition::Zero);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, success, success_start);
    commit_inexact(code);
    result_sign(code, operand);
    if operand.shape == Shape::Vector64 {
        code.extend(MOVQ_XMM0_XMM0);
    }
    commit(code, operand.destination, LEFT_VECTOR);
    let done = code.len();
    resolve(code, sticky_done, done);
}

pub(super) fn always_exits(operand: &Operand) -> bool {
    operand.format == Format::Half
        && matches!(operand.inputs, Inputs::Elementwise { .. })
        && matches!(
            operand.operation,
            BinaryOperation::Add
                | BinaryOperation::Subtract
                | BinaryOperation::Multiply
                | BinaryOperation::Divide
        )
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    if always_exits(operand) {
        super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    } else if operand.format == Format::Half {
        half::emit(code, operand, pc, target);
    } else if operand.shape == Shape::Scalar {
        emit_scalar(code, operand, pc);
    } else {
        emit_vector(code, operand, pc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn numerical_instructions_require_the_block_exit_protocol() {
        const FADD_S: u32 = 0x1e222820;
        const FADD_H: u32 = 0x1ee22820;
        const FADD_2S: u32 = 0x0e22d420;
        const FADD_4H: u32 = 0x0e421420;
        const RET: u32 = 0xd65f03c0;
        for word in [FADD_S, FADD_H, FADD_2S, FADD_4H] {
            let bytes: Vec<u8> = [word, RET]
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect();
            assert!(
                crate::compile(&bytes, GuestAddress(0x1000))
                    .unwrap_err()
                    .0
                    .contains("NumericalRuntimeRequired")
            );
            let block = crate::block::compile(&bytes, GuestAddress(0x1000)).unwrap();
            if [FADD_H, FADD_4H].contains(&word) {
                assert_eq!(block.source_bytes, size_of::<u32>());
                assert_eq!(block.native.source_map, [(GuestAddress(0x1000), 0)]);
            } else {
                assert_eq!(block.native.source_map.len(), 2);
                assert_eq!(block.native.source_map[1].0, GuestAddress(0x1004));
            }
        }
    }
}
