//! Fused multiply-add: FMA3 when available, otherwise an exact-product SSE2 path.
use super::super::isa::ShiftOpcode;
use super::numerical::{
    ArithmeticOpcode, Condition, FusedOpcode, INPUT_MINIMUM_EXPONENT, RESULT_MINIMUM_EXPONENT,
    branch, clear_scalar, commit_inexact, emit_fma, emit_opcode, environment, exponent_range,
    prepare_vector_input_range, prepare_vector_result_range, read_numerical_right,
    read_numerical_vector, reject_other_status, reject_product_status, resolve,
    restore_environment, restore_environment_with_product, save_product_status, test_control,
    vector_exponent_range,
};
use super::{Host, commit, packed};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, Format, fused::FusedOperation},
        simd::{arithmetic::Shape, fused::Operand},
    },
    block::ExitKind,
};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const SIGN_MASK: u8 = 2;
const ADDEND: u8 = 6;
const ORIGINAL_ADDEND: u8 = 7;
const SSE_ESCAPE: u8 = 0x0f;
const MOV_SCALAR: u8 = 0x10;
const SINGLE_PREFIX: u8 = 0xf3;
const DOUBLE_PREFIX: u8 = 0xf2;
const REGISTER_DIRECT: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;

fn emit_checked_fma(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    let opcode = match operand.operation {
        FusedOperation::Add => FusedOpcode::MultiplyAdd,
        FusedOperation::Subtract => FusedOpcode::NegativeMultiplyAdd,
        FusedOperation::NegatedAdd => FusedOpcode::NegativeMultiplySubtract,
        FusedOperation::NegatedSubtract => FusedOpcode::MultiplySubtract,
    };
    emit_fma(code, operand.format, operand.shape, opcode, target);
}

fn prepare_right(code: &mut Vec<u8>, operand: &Operand) {
    read_numerical_right(
        code,
        operand.format,
        operand.shape,
        operand.right,
        operand.right_lane,
    );
}

fn prepare_negation(code: &mut Vec<u8>, operand: &Operand) -> u8 {
    let merge = if operand.shape == Shape::Scalar && operand.operation.negate_addend() {
        packed(code, Host::MoveAligned, ORIGINAL_ADDEND, ADDEND);
        ORIGINAL_ADDEND
    } else {
        ADDEND
    };
    if operand.operation.negate_addend() || operand.operation.negate_left() {
        packed(code, Host::EqualDword, SIGN_MASK, SIGN_MASK);
        let shift = if operand.format == Format::Single {
            ShiftOpcode::LeftDword
        } else {
            ShiftOpcode::LeftQword
        };
        shift.emit(code, SIGN_MASK, (operand.format.bits() - 1) as u8);
        if operand.operation.negate_left() {
            packed(code, Host::Xor, LEFT, SIGN_MASK);
        }
        if operand.operation.negate_addend() {
            packed(code, Host::Xor, ADDEND, SIGN_MASK);
        }
    }
    merge
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    if operand.format == Format::Half {
        super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
        return;
    }
    let mut helper = Vec::new();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    read_numerical_vector(code, operand.shape, operand.left, LEFT);
    read_numerical_vector(code, operand.shape, operand.addend, ADDEND);
    prepare_right(code, operand);
    if operand.shape != Shape::Scalar {
        prepare_vector_input_range(code, operand.format);
    }
    for source in [LEFT, RIGHT, ADDEND] {
        let condition = if operand.shape == Shape::Scalar {
            exponent_range(code, operand.format, source, INPUT_MINIMUM_EXPONENT);
            Condition::AboveOrEqual
        } else {
            vector_exponent_range(code, operand.format, operand.shape, source);
            Condition::NotZero
        };
        helper.push(branch(code, condition));
    }
    let native_fma = target.supports(TargetCpu::Fma);
    let merge = if native_fma {
        ADDEND
    } else {
        prepare_negation(code, operand)
    };
    environment(code);
    if native_fma {
        emit_checked_fma(code, operand, target);
        restore_environment(code);
    } else {
        emit_opcode(
            code,
            operand.format,
            operand.shape,
            ArithmeticOpcode::Multiply,
            RIGHT,
        );
        save_product_status(code);
        emit_opcode(
            code,
            operand.format,
            operand.shape,
            ArithmeticOpcode::Add,
            ADDEND,
        );
        restore_environment_with_product(code);
        // All host status and stack state are restored before either side exit.
        helper.push(reject_product_status(code));
    }
    helper.push(reject_other_status(code));
    let success_condition = if operand.shape == Shape::Scalar {
        exponent_range(code, operand.format, LEFT, RESULT_MINIMUM_EXPONENT);
        Condition::Below
    } else {
        prepare_vector_result_range(code);
        vector_exponent_range(code, operand.format, operand.shape, LEFT);
        Condition::Zero
    };
    let success = branch(code, success_condition);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, success, success_start);
    commit_inexact(code);
    if operand.shape == Shape::Scalar {
        // Register MOVSS/MOVSD replaces only the result lane of A.
        code.extend([
            if operand.format == Format::Single {
                SINGLE_PREFIX
            } else {
                DOUBLE_PREFIX
            },
            SSE_ESCAPE,
            MOV_SCALAR,
            REGISTER_DIRECT | (merge << MODRM_REGISTER_SHIFT) | LEFT,
        ]);
        test_control(code, FPCR_NEP);
        let merging = branch(code, Condition::NotZero);
        clear_scalar(code, operand.format, merge);
        let commit_start = code.len();
        resolve(code, merging, commit_start);
        commit(code, operand.destination, merge);
    } else {
        if operand.shape == Shape::Vector64 {
            packed(code, Host::MoveQword, LEFT, LEFT);
        }
        commit(code, operand.destination, LEFT);
    }
}
