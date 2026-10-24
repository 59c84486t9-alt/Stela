//! Half-precision arithmetic through exact widened intermediates.
use alloc::vec::Vec;
mod product;

use super::super::super::isa::ShiftOpcode;
use super::super::numerical::{
    ArithmeticOpcode, Condition, VZEROUPPER, branch, emit_opcode_to, prepare_vector_input_range,
    read_numerical_right, read_numerical_vector, test_control, vector_exponent_range,
};
use super::super::{Host, commit, half as lanes, packed, read_vector};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{BinaryOperation, FPCR_EXCEPTION_ENABLE_MASK, Format},
        simd::arithmetic::{Inputs, Operand, Shape},
    },
};

const LEFT_ODD: u8 = 6;
const RIGHT_ODD: u8 = 3;
const EVEN_HALF_WORDS: u8 = 0x88;
const SECOND_HALF_WORD: u8 = 0x55;

fn compact_even_words(code: &mut Vec<u8>, source: u8) {
    packed(code, Host::ShuffleLowWord, source, source);
    code.push(EVEN_HALF_WORDS);
}

/// Normalize adjacent Vn pairs followed by Vm pairs into two Half vectors.
/// Q0 inputs were loaded with MOVQ; only the assembled active words are guarded.
fn prepare_pairs(code: &mut Vec<u8>, shape: Shape) {
    packed(code, Host::MoveAligned, LEFT_ODD, lanes::LEFT);
    if shape == Shape::Vector128 {
        packed(code, Host::MoveAligned, RIGHT_ODD, lanes::RIGHT);
        // Sign extension makes every raw Half field exactly PACKSSDW-safe.
        for source in [lanes::LEFT, lanes::RIGHT] {
            ShiftOpcode::LeftDword.emit(code, source, Format::Half.bits() as u8);
            ShiftOpcode::ArithmeticDword.emit(code, source, Format::Half.bits() as u8);
        }
        packed(code, Host::PackSignedDwordToWord, lanes::LEFT, lanes::RIGHT);
        for source in [LEFT_ODD, RIGHT_ODD] {
            ShiftOpcode::ArithmeticDword.emit(code, source, Format::Half.bits() as u8);
        }
        packed(code, Host::PackSignedDwordToWord, LEFT_ODD, RIGHT_ODD);
        packed(code, Host::MoveAligned, lanes::RIGHT, LEFT_ODD);
        return;
    }
    ShiftOpcode::RightDword.emit(code, LEFT_ODD, Format::Half.bits() as u8);
    packed(code, Host::MoveAligned, RIGHT_ODD, lanes::RIGHT);
    ShiftOpcode::RightDword.emit(code, RIGHT_ODD, Format::Half.bits() as u8);
    for source in [lanes::LEFT, lanes::RIGHT, LEFT_ODD, RIGHT_ODD] {
        compact_even_words(code, source);
    }
    packed(code, Host::UnpackLowDword, lanes::LEFT, lanes::RIGHT);
    packed(code, Host::UnpackLowDword, LEFT_ODD, RIGHT_ODD);
    packed(code, Host::MoveAligned, lanes::RIGHT, LEFT_ODD);
}

fn prepare_inputs(code: &mut Vec<u8>, operand: &Operand) {
    match operand.inputs {
        Inputs::Elementwise { left, right } => {
            read_numerical_vector(code, operand.shape, left, lanes::LEFT);
            read_numerical_vector(code, operand.shape, right, lanes::RIGHT);
        }
        Inputs::Indexed {
            left,
            right,
            right_lane,
        } => {
            read_numerical_vector(code, operand.shape, left, lanes::LEFT);
            // Read all of Vm: a 64-bit form may select its upper qword.
            read_numerical_right(code, Format::Half, operand.shape, right, Some(right_lane));
        }
        Inputs::Pairwise { left, right } => {
            read_numerical_vector(code, operand.shape, left, lanes::LEFT);
            read_numerical_vector(code, operand.shape, right, lanes::RIGHT);
            prepare_pairs(code, operand.shape);
        }
        Inputs::PairwiseScalar { source } => {
            read_vector(code, source, lanes::LEFT);
            packed(code, Host::ShuffleLowWord, lanes::RIGHT, lanes::LEFT);
            code.push(SECOND_HALF_WORD);
        }
    }
    if operand.shape == Shape::Scalar && !matches!(operand.inputs, Inputs::PairwiseScalar { .. }) {
        packed(code, Host::MoveAligned, lanes::ORIGINAL_LEFT, lanes::LEFT);
    }
}

fn operation(operation: BinaryOperation) -> (ArithmeticOpcode, lanes::ResultSign) {
    match operation {
        BinaryOperation::Add => (ArithmeticOpcode::Add, lanes::ResultSign::Preserve),
        BinaryOperation::Subtract => (ArithmeticOpcode::Subtract, lanes::ResultSign::Preserve),
        BinaryOperation::Multiply | BinaryOperation::MultiplyExtended => {
            (ArithmeticOpcode::Multiply, lanes::ResultSign::Preserve)
        }
        BinaryOperation::NegatedMultiply => (ArithmeticOpcode::Multiply, lanes::ResultSign::Negate),
        BinaryOperation::AbsoluteDifference => {
            (ArithmeticOpcode::Subtract, lanes::ResultSign::Absolute)
        }
        BinaryOperation::Divide => unreachable!("Half division retains its terminal helper"),
    }
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress, target: TargetCpu) {
    debug_assert_eq!(operand.format, Format::Half);
    let mut helper = Vec::new();
    let mut rollback = Vec::new();
    let packed_product = product::supports(operand);
    let checked_widening =
        !packed_product && operand.shape != Shape::Scalar && target.supports(TargetCpu::F16c);
    if checked_widening {
        code.extend(VZEROUPPER);
    }
    // Ordinary binary keeps retained enables and fresh status under every AH.
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    prepare_inputs(code, operand);
    prepare_vector_input_range(code, Format::Half);
    for source in [lanes::LEFT, lanes::RIGHT] {
        vector_exponent_range(code, Format::Half, operand.shape, source);
        helper.push(branch(code, Condition::NotZero));
    }
    if packed_product {
        product::emit(code, operand.shape, helper, pc);
    } else {
        lanes::allocate_frame(code);
        if checked_widening {
            lanes::set_pack_bias(code);
        } else {
            lanes::set_biases(code, lanes::LeftScale::Identity);
        }
        let loop_start = lanes::start_lanes(code);
        if checked_widening {
            lanes::widen_lane_checked(code, target);
        } else {
            lanes::widen_lane(code);
        }
        // Normal H sums/differences need at most 41 significant bits, products 22.
        // Nonzero results are normal Double values, exact under every caller MXCSR.
        // Cancellation zero and unsafe Half outputs roll back before guest effects.
        let (opcode, sign) = operation(operand.operation);
        packed(code, Host::MoveAligned, lanes::RESULT, lanes::LEFT);
        emit_opcode_to(
            code,
            Format::Double,
            Shape::Scalar,
            opcode,
            lanes::RESULT,
            lanes::RIGHT,
        );
        lanes::pack_lane(code, &mut rollback, lanes::RoundingPolicy::Fpcr, sign);
        lanes::finish_lanes(
            code,
            operand.shape.lane_count(Format::Half) as u8,
            loop_start,
            &helper,
            &rollback,
            pc,
        );
    }
    lanes::commit_inexact(code);
    if operand.shape == Shape::Scalar && !matches!(operand.inputs, Inputs::PairwiseScalar { .. }) {
        lanes::merge_scalar(code);
    }
    // Both the lane frame and packed product path clear inactive output bits.
    commit(code, operand.destination, lanes::LEFT);
}
