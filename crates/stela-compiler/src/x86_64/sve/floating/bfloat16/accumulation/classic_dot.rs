//! Classic BFDOT with round-to-odd intermediates.
use super::{LEFT, RIGHT};
use crate::{
    TargetCpu,
    aarch64::{
        floating::{Format, bfloat16::BFLOAT16_BITS},
        simd::arithmetic::Shape,
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::numerical::{self, Frame},
        simd::numerical::{
            ArithmeticOpcode, Condition, branch, emit_opcode_to, prepare_vector_input_range,
            vector_exponent_range,
        },
    },
};
use alloc::vec::Vec;

const FIRST_RESIDUAL: u8 = 2;
const SECOND_RESIDUAL: u8 = 3;
const ODD_BIT: u8 = 4;
const ZERO: u8 = 5;
const LEFT_ODD: u8 = 6;
const RIGHT_ODD: u8 = 7;
const ORIGINAL_LEFT: u8 = 7;
const BFLOAT_BITS: u8 = BFLOAT16_BITS as u8;
const SIGN_BITS: u8 = 1;
const SINGLE_TOP_BIT: u8 = Format::Single.bits() as u8 - SIGN_BITS;
const GPR_RAX: u8 = 0;
const ALL_SINGLE_LANES: u8 = 15;
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_ROUND_ZERO: u32 = 3 << 13;
const MOV_EAX_IMMEDIATE: u8 = 0xb8;
const TEST_ECX_IMMEDIATE: &[u8] = &[0xf7, 0xc1];
const CMP_EAX_IMMEDIATE: &[u8] = &[0x83, 0xf8];
const COMPARE_EQUAL_SINGLE: &[u8] = &[0x0f, 0xc2];
const REGISTER_DIRECT: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const EQUAL_PREDICATE: u8 = 0;

pub(super) fn install_environment(code: &mut Vec<u8>, frame: &Frame) {
    code.push(MOV_EAX_IMMEDIATE);
    code.extend(MXCSR_ROUND_ZERO.to_le_bytes());
    numerical::install_mxcsr(code, frame);
}

fn arithmetic(code: &mut Vec<u8>, opcode: ArithmeticOpcode, destination: u8, source: u8) {
    emit_opcode_to(
        code,
        Format::Single,
        Shape::Vector128,
        opcode,
        destination,
        source,
    );
}

fn guard_normal(code: &mut Vec<u8>, source: u8, failures: &mut Vec<usize>) {
    vector_exponent_range(code, Format::Single, Shape::Vector128, source);
    failures.push(branch(code, Condition::NotZero));
}

fn guard_normal_or_zero(
    code: &mut Vec<u8>,
    source: u8,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    vector_exponent_range(code, Format::Single, Shape::Vector128, source);
    Host::MoveAligned.register(code, SECOND_RESIDUAL, source, target);
    ShiftOpcode::LeftDword.emit(code, SECOND_RESIDUAL, SIGN_BITS);
    Host::EqualDword.register(code, SECOND_RESIDUAL, ZERO, target);
    Host::Or.register(code, FIRST_RESIDUAL, SECOND_RESIDUAL, target);
    Host::DwordSignMask.register(code, GPR_RAX, FIRST_RESIDUAL, target);
    code.extend(CMP_EAX_IMMEDIATE);
    code.push(ALL_SINGLE_LANES);
    failures.push(branch(code, Condition::NotZero));
}

fn guard_real_status(code: &mut Vec<u8>, frame: &Frame, failures: &mut Vec<usize>) {
    numerical::capture_status(code, frame);
    code.extend(TEST_ECX_IMMEDIATE);
    code.extend(MXCSR_OTHER_STATUS.to_le_bytes());
    failures.push(branch(code, Condition::NotZero));
}

fn compare_equal(code: &mut Vec<u8>, destination: u8, source: u8) {
    code.extend(COMPARE_EQUAL_SINGLE);
    code.extend([
        REGISTER_DIRECT | destination << MODRM_REGISTER_SHIFT | source,
        EQUAL_PREDICATE,
    ]);
}

fn odd_add(code: &mut Vec<u8>, frame: &Frame, failures: &mut Vec<usize>, target: TargetCpu) {
    Host::MoveAligned.register(code, ORIGINAL_LEFT, LEFT, target);
    arithmetic(code, ArithmeticOpcode::Add, LEFT, RIGHT);
    guard_real_status(code, frame, failures);
    prepare_vector_input_range(code, Format::Single);
    guard_normal_or_zero(code, LEFT, failures, target);
    // Both residuals are exact only for an exact sum. For an inexact sum, the
    // dominant operand residual is exact (Sterbenz), and the other differs.
    Host::MoveAligned.register(code, FIRST_RESIDUAL, LEFT, target);
    arithmetic(
        code,
        ArithmeticOpcode::Subtract,
        FIRST_RESIDUAL,
        ORIGINAL_LEFT,
    );
    compare_equal(code, FIRST_RESIDUAL, RIGHT);
    Host::MoveAligned.register(code, SECOND_RESIDUAL, LEFT, target);
    arithmetic(code, ArithmeticOpcode::Subtract, SECOND_RESIDUAL, RIGHT);
    compare_equal(code, SECOND_RESIDUAL, ORIGINAL_LEFT);
    Host::And.register(code, FIRST_RESIDUAL, SECOND_RESIDUAL, target);
    Host::EqualDword.register(code, ODD_BIT, ODD_BIT, target);
    ShiftOpcode::RightDword.emit(code, ODD_BIT, SINGLE_TOP_BIT);
    Host::AndNot.register(code, FIRST_RESIDUAL, ODD_BIT, target);
    Host::Or.register(code, LEFT, FIRST_RESIDUAL, target);
    // Residual status is private scratch, never a real-stage exception.
    numerical::clear_status(code, frame);
}

pub(super) fn pair_sum(
    code: &mut Vec<u8>,
    frame: &Frame,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    for (even, odd) in [(LEFT, LEFT_ODD), (RIGHT, RIGHT_ODD)] {
        Host::MoveAligned.register(code, odd, even, target);
        ShiftOpcode::RightDword.emit(code, odd, BFLOAT_BITS);
        ShiftOpcode::LeftDword.emit(code, odd, BFLOAT_BITS);
        ShiftOpcode::LeftDword.emit(code, even, BFLOAT_BITS);
    }
    prepare_vector_input_range(code, Format::Single);
    for source in [LEFT, RIGHT, LEFT_ODD, RIGHT_ODD] {
        guard_normal(code, source, failures);
    }
    arithmetic(code, ArithmeticOpcode::Multiply, LEFT, RIGHT);
    arithmetic(code, ArithmeticOpcode::Multiply, LEFT_ODD, RIGHT_ODD);
    guard_real_status(code, frame, failures);
    guard_normal(code, LEFT, failures);
    guard_normal(code, LEFT_ODD, failures);
    Host::MoveAligned.register(code, RIGHT, LEFT_ODD, target);
    odd_add(code, frame, failures, target);
}

pub(super) fn add_accumulator(
    code: &mut Vec<u8>,
    frame: &Frame,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    prepare_vector_input_range(code, Format::Single);
    guard_normal_or_zero(code, RIGHT, failures, target);
    odd_add(code, frame, failures, target);
}
