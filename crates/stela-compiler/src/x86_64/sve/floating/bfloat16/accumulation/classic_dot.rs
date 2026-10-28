//! Classic BFDOT with round-to-odd intermediates.
use super::{LEFT, RIGHT};
use crate::x86_64::asm::FloatLanes;
use crate::x86_64::asm::Gpr::{Rax, Rcx};
use crate::x86_64::asm::{Alu, Code, Rm, Size};
use crate::x86_64::simd::numerical::single_vector_arithmetic;
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
            ArithmeticOpcode, Condition, branch, prepare_vector_input_range, vector_exponent_range,
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
const ALL_SINGLE_LANES: u8 = 15;
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_ROUND_ZERO: u32 = 3 << 13;
const EQUAL_PREDICATE: u8 = 0;

pub(super) fn install_environment(code: &mut Code, frame: &Frame) {
    code.asm().mov_imm32(Rax, MXCSR_ROUND_ZERO);
    numerical::install_mxcsr(code, frame);
}

fn guard_normal(code: &mut Code, source: u8, failures: &mut Vec<usize>) {
    vector_exponent_range(code, Format::Single, Shape::Vector128, source);
    failures.push(branch(code, Condition::NotZero));
}

fn guard_normal_or_zero(code: &mut Code, source: u8, failures: &mut Vec<usize>, target: TargetCpu) {
    vector_exponent_range(code, Format::Single, Shape::Vector128, source);
    Host::MoveAligned.register(code, SECOND_RESIDUAL, source, target);
    ShiftOpcode::LeftDword.emit(code, SECOND_RESIDUAL, SIGN_BITS);
    Host::EqualDword.register(code, SECOND_RESIDUAL, ZERO, target);
    Host::Or.register(code, FIRST_RESIDUAL, SECOND_RESIDUAL, target);
    code.asm()
        .simd_to_gpr(Host::DwordSignMask, Rax, FIRST_RESIDUAL, target);
    code.asm()
        .alu_imm8(Alu::Cmp, Size::Dword, Rax, ALL_SINGLE_LANES as i8);
    failures.push(branch(code, Condition::NotZero));
}

fn guard_real_status(code: &mut Code, frame: &Frame, failures: &mut Vec<usize>) {
    numerical::capture_status(code, frame);
    code.asm()
        .test_imm(Size::Dword, Rcx, MXCSR_OTHER_STATUS as i32);
    failures.push(branch(code, Condition::NotZero));
}

fn compare_equal(code: &mut Code, destination: u8, source: u8) {
    code.asm().float_compare(
        FloatLanes::PackedSingle,
        destination,
        Rm::Xmm(source),
        EQUAL_PREDICATE,
    );
}

fn odd_add(code: &mut Code, frame: &Frame, failures: &mut Vec<usize>, target: TargetCpu) {
    Host::MoveAligned.register(code, ORIGINAL_LEFT, LEFT, target);
    single_vector_arithmetic(code, ArithmeticOpcode::Add, LEFT, RIGHT);
    guard_real_status(code, frame, failures);
    prepare_vector_input_range(code, Format::Single);
    guard_normal_or_zero(code, LEFT, failures, target);
    // Both residuals are exact only for an exact sum. For an inexact sum, the
    // dominant operand residual is exact (Sterbenz), and the other differs.
    Host::MoveAligned.register(code, FIRST_RESIDUAL, LEFT, target);
    single_vector_arithmetic(
        code,
        ArithmeticOpcode::Subtract,
        FIRST_RESIDUAL,
        ORIGINAL_LEFT,
    );
    compare_equal(code, FIRST_RESIDUAL, RIGHT);
    Host::MoveAligned.register(code, SECOND_RESIDUAL, LEFT, target);
    single_vector_arithmetic(code, ArithmeticOpcode::Subtract, SECOND_RESIDUAL, RIGHT);
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
    code: &mut Code,
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
    single_vector_arithmetic(code, ArithmeticOpcode::Multiply, LEFT, RIGHT);
    single_vector_arithmetic(code, ArithmeticOpcode::Multiply, LEFT_ODD, RIGHT_ODD);
    guard_real_status(code, frame, failures);
    guard_normal(code, LEFT, failures);
    guard_normal(code, LEFT_ODD, failures);
    Host::MoveAligned.register(code, RIGHT, LEFT_ODD, target);
    odd_add(code, frame, failures, target);
}

pub(super) fn add_accumulator(
    code: &mut Code,
    frame: &Frame,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    prepare_vector_input_range(code, Format::Single);
    guard_normal_or_zero(code, RIGHT, failures, target);
    odd_add(code, frame, failures, target);
}
