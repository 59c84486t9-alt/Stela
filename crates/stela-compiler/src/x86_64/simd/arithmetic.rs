//! Binary numerical blocks: normal SSE2 path and exact integer-core fallback.
use super::super::isa::ShiftOpcode;
use super::numerical::{
    ArithmeticOpcode, Condition, EXPONENT_VECTOR, INPUT_MINIMUM_EXPONENT, LEFT_VECTOR,
    MOVLHPS_XMM1_XMM2, MOVQ_XMM0_XMM0, RESULT_MINIMUM_EXPONENT, RIGHT_VECTOR,
    SINGLE_EXPONENT_BIAS_BITS, branch, clear_scalar, commit_inexact, emit_opcode, environment,
    exponent_range, prepare_vector_input_range, prepare_vector_result_range, read_numerical_vector,
    reject_other_status, resolve, restore_environment, test_control, vector_exponent_range,
};
use super::{Host, commit, packed, read_vector};
use crate::{
    GuestAddress,
    aarch64::{
        floating::{BinaryOperation, FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, Format},
        simd::arithmetic::{Operand, Shape},
    },
    block::ExitKind,
};

fn arithmetic_opcode(operation: BinaryOperation) -> ArithmeticOpcode {
    match operation {
        BinaryOperation::Add => ArithmeticOpcode::Add,
        BinaryOperation::Subtract => ArithmeticOpcode::Subtract,
        BinaryOperation::Multiply => ArithmeticOpcode::Multiply,
        BinaryOperation::Divide => ArithmeticOpcode::Divide,
    }
}

fn emit_scalar(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress) {
    let mut helper = Vec::new();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    read_vector(code, operand.left, 0);
    read_vector(code, operand.right, 1);
    for right in [0, 1] {
        exponent_range(code, operand.format, right, INPUT_MINIMUM_EXPONENT);
        helper.push(branch(code, Condition::AboveOrEqual));
    }
    environment(code);
    emit_opcode(
        code,
        operand.format,
        operand.shape,
        arithmetic_opcode(operand.operation),
        RIGHT_VECTOR,
    );
    restore_environment(code);
    // Caller environment and stack are restored before every branch from here.
    helper.push(reject_other_status(code));
    exponent_range(code, operand.format, 0, RESULT_MINIMUM_EXPONENT);
    let success = branch(code, Condition::Below);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, success, success_start);

    commit_inexact(code);
    test_control(code, FPCR_NEP);
    let merge = branch(code, Condition::NotZero);
    clear_scalar(code, operand.format, LEFT_VECTOR);
    let merge_target = code.len();
    resolve(code, merge, merge_target);
    commit(code, operand.destination, 0);
}

fn emit_vector(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress) {
    let mut helper = Vec::new();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    read_numerical_vector(code, operand.shape, operand.left, LEFT_VECTOR);
    read_numerical_vector(code, operand.shape, operand.right, RIGHT_VECTOR);
    prepare_vector_input_range(code, operand.format);
    for source in [LEFT_VECTOR, RIGHT_VECTOR] {
        vector_exponent_range(code, operand.format, operand.shape, source);
        helper.push(branch(code, Condition::NotZero));
    }
    if operand.shape == Shape::Vector64 && operand.operation == BinaryOperation::Divide {
        // Inactive numerators are zero. Supply 1.0 denominators to avoid 0/0
        // contributing host invalid status; inactive original bits never execute.
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
        RIGHT_VECTOR,
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
    if operand.shape == Shape::Vector64 {
        code.extend(MOVQ_XMM0_XMM0);
    }
    commit(code, operand.destination, LEFT_VECTOR);
}

pub(in crate::x86_64) fn emit(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress) {
    if operand.format == Format::Half {
        super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    } else if operand.shape == Shape::Scalar {
        emit_scalar(code, operand, pc);
    } else {
        emit_vector(code, operand, pc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
