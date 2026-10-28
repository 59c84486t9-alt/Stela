//! BFDOT with fixed round-to-odd intermediates.
use super::super::super::isa::ShiftOpcode;
use super::super::numerical::single_vector_arithmetic;
use super::super::numerical::{
    ArithmeticOpcode, Condition, ENVIRONMENT_STACK_BYTES, MXCSR_INEXACT, Rounding, branch,
    capture_environment_status, clear_environment_status, environment_round, jump,
    prepare_vector_input_range, read_numerical_vector, reject_other_status, resolve,
    restore_environment, vector_exponent_range,
};
use super::super::{Host, commit, packed, read_vector, shuffle};
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, Rm, Size};
use crate::x86_64::simd::encode::FloatLanes;
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{
            Format,
            bfloat16::{BFLOAT16_BITS, BFLOAT16_TO_SINGLE_SHIFT},
        },
        simd::{
            arithmetic::Shape,
            bfloat16::{DotOperand, DotSource, MatrixOperand},
        },
    },
    block::ExitKind,
};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const FIRST_RESIDUAL: u8 = 2;
const SECOND_RESIDUAL: u8 = 3;
const ODD_BIT: u8 = 4;
const ZERO: u8 = 5;
const LEFT_ODD: u8 = 6;
const RIGHT_ODD: u8 = 7;
const ORIGINAL_LEFT: u8 = 7;
const EAX: u8 = 0;
const SIGN_BITS: u8 = 1;
const SINGLE_TOP_BIT: u8 = Format::Single.bits() as u8 - SIGN_BITS;
const LOW_SINGLE_LANE_MASK: u8 = 0b0011;
const ALL_SINGLE_LANE_MASK: u8 = 0b1111;
const BROADCAST_DWORD: u8 = 0x55;
const MATRIX_LEFT_PAIRS: u8 = 0xa0; // Dwords [0, 0, 2, 2].
const MATRIX_RIGHT_PAIRS: u8 = 0x88; // Dwords [0, 2, 0, 2].
const MATRIX_STAGES: u8 = 2;
const PAIR_BYTES: u8 = (2 * BFLOAT16_BITS / u8::BITS) as u8;
const EQUAL_PREDICATE: u8 = 0;
const MATRIX_FRAME_BYTES: u8 = 16;
/// R8D counts completed matrix stages.
const MATRIX_COUNTER: Gpr = Gpr::R8;

/// Reserve (`Alu::Sub`) or release (`Alu::Add`) the matrix accumulator frame.
fn matrix_frame(code: &mut Code, op: Alu) {
    code.asm()
        .alu_imm8(op, Size::Qword, Gpr::Rsp, MATRIX_FRAME_BYTES as i8);
}

/// The matrix's private accumulator, above the numerical environment's
/// sixteen-byte save area.
fn accumulator_slot() -> Mem {
    Mem::base_disp8(Gpr::Rsp, ENVIRONMENT_STACK_BYTES as i8)
}

#[derive(Clone, Copy)]
enum SumCheck {
    Residuals,
    ExactVector,
}

fn compare_equal(code: &mut Code, destination: u8, source: u8) {
    code.asm().float_compare(
        FloatLanes::PackedSingle,
        destination,
        Rm::Xmm(source),
        EQUAL_PREDICATE,
    );
}

fn guard_normal(code: &mut Code, shape: Shape, source: u8, rollback: &mut Vec<usize>) {
    vector_exponent_range(code, Format::Single, shape, source);
    rollback.push(branch(code, Condition::NotZero));
}

fn guard_normal_or_zero(code: &mut Code, shape: Shape, source: u8, rollback: &mut Vec<usize>) {
    // The shared classifier leaves its per-lane normal mask in XMM2. Admit
    // only raw signed zeros as well; BF subnormals require architectural flush.
    vector_exponent_range(code, Format::Single, shape, source);
    packed(code, Host::MoveAligned, SECOND_RESIDUAL, source);
    ShiftOpcode::LeftDword.emit(code, SECOND_RESIDUAL, SIGN_BITS);
    packed(code, Host::EqualDword, SECOND_RESIDUAL, ZERO);
    packed(code, Host::Or, FIRST_RESIDUAL, SECOND_RESIDUAL);
    Host::DwordSignMask.register(code, EAX, FIRST_RESIDUAL, TargetCpu::Baseline);
    let mask = match shape {
        Shape::Vector64 => LOW_SINGLE_LANE_MASK,
        Shape::Vector128 => ALL_SINGLE_LANE_MASK,
        Shape::Scalar => unreachable!("BF16 dot requires vector lanes"),
    };
    let mut asm = code.asm();
    if shape == Shape::Vector64 {
        asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rax, mask as i8);
    }
    asm.alu_imm8(Alu::Cmp, Size::Dword, Gpr::Rax, mask as i8);
    rollback.push(branch(code, Condition::NotZero));
}

fn guard_real_status(code: &mut Code, rollback: &mut Vec<usize>) {
    capture_environment_status(code);
    rollback.push(reject_other_status(code));
}

fn widen_pairs(code: &mut Code, shape: Shape) {
    for (even, odd) in [(LEFT, LEFT_ODD), (RIGHT, RIGHT_ODD)] {
        packed(code, Host::MoveAligned, odd, even);
        ShiftOpcode::RightDword.emit(code, odd, BFLOAT16_BITS as u8);
        ShiftOpcode::LeftDword.emit(code, odd, BFLOAT16_TO_SINGLE_SHIFT as u8);
        ShiftOpcode::LeftDword.emit(code, even, BFLOAT16_TO_SINGLE_SHIFT as u8);
        if shape == Shape::Vector64 {
            // Unselected BF inputs must never reach packed FP, even when they
            // contain signaling NaNs. MOVQ clears both inactive Single lanes.
            packed(code, Host::MoveQword, even, even);
            packed(code, Host::MoveQword, odd, odd);
        }
    }
}

fn odd_add(code: &mut Code, shape: Shape, rollback: &mut Vec<usize>, check: SumCheck) {
    packed(code, Host::MoveAligned, ORIGINAL_LEFT, LEFT);
    single_vector_arithmetic(code, ArithmeticOpcode::Add, LEFT, RIGHT);
    // Round-toward-zero overflow can clamp to the largest finite value, so
    // check the host status before the result classifier or residual hides it.
    guard_real_status(code, rollback);
    prepare_vector_input_range(code, Format::Single);
    guard_normal_or_zero(code, shape, LEFT, rollback);

    // ECX still holds the real ADD status. Exact matrix vectors need no jam;
    // inexact vectors retain the per-lane residual check. Keep the preceding
    // result guard: exact subnormal cancellation must still use BF flushing.
    let exact = if matches!(check, SumCheck::ExactVector) {
        code.asm()
            .test_imm(Size::Dword, Gpr::Rcx, MXCSR_INEXACT as i32);
        Some(branch(code, Condition::Zero))
    } else {
        None
    };

    // An exact sum has both exact residuals. For an inexact sum, the dominant
    // operand's residual is exact by Sterbenz and differs from the other input.
    // Numeric equality also admits signed-zero inputs and exact cancellation.
    packed(code, Host::MoveAligned, FIRST_RESIDUAL, LEFT);
    single_vector_arithmetic(
        code,
        ArithmeticOpcode::Subtract,
        FIRST_RESIDUAL,
        ORIGINAL_LEFT,
    );
    compare_equal(code, FIRST_RESIDUAL, RIGHT);
    packed(code, Host::MoveAligned, SECOND_RESIDUAL, LEFT);
    single_vector_arithmetic(code, ArithmeticOpcode::Subtract, SECOND_RESIDUAL, RIGHT);
    compare_equal(code, SECOND_RESIDUAL, ORIGINAL_LEFT);
    packed(code, Host::And, FIRST_RESIDUAL, SECOND_RESIDUAL);
    packed(code, Host::EqualDword, ODD_BIT, ODD_BIT);
    ShiftOpcode::RightDword.emit(code, ODD_BIT, SINGLE_TOP_BIT);
    packed(code, Host::AndNot, FIRST_RESIDUAL, ODD_BIT);
    packed(code, Host::Or, LEFT, FIRST_RESIDUAL);
    // Scratch residuals can overflow or become subnormal. Their host flags
    // are irrelevant, and must not contaminate the next real arithmetic stage.
    let clear_status = code.len();
    if let Some(patch) = exact {
        resolve(code, patch, clear_status);
    }
    clear_environment_status(code);
}

fn pair_sum(code: &mut Code, shape: Shape, rollback: &mut Vec<usize>, check: SumCheck) {
    widen_pairs(code, shape);
    prepare_vector_input_range(code, Format::Single);
    for source in [LEFT, RIGHT, LEFT_ODD, RIGHT_ODD] {
        guard_normal(code, shape, source, rollback);
    }
    single_vector_arithmetic(code, ArithmeticOpcode::Multiply, LEFT, RIGHT);
    single_vector_arithmetic(code, ArithmeticOpcode::Multiply, LEFT_ODD, RIGHT_ODD);
    guard_real_status(code, rollback);
    // BF16 products have at most sixteen significant bits. Every admitted
    // normal Single product is exact; tiny/overflowing stages use the core.
    guard_normal(code, shape, LEFT, rollback);
    guard_normal(code, shape, LEFT_ODD, rollback);
    packed(code, Host::MoveAligned, RIGHT, LEFT_ODD);
    odd_add(code, shape, rollback, check);
}

fn add_accumulator(code: &mut Code, shape: Shape, rollback: &mut Vec<usize>, check: SumCheck) {
    prepare_vector_input_range(code, Format::Single);
    guard_normal_or_zero(code, shape, RIGHT, rollback);
    odd_add(code, shape, rollback, check);
}

fn matrix_accumulator(code: &mut Code, opcode: Host) {
    // The matrix's private accumulator is above the numerical environment's
    // sixteen-byte save area; no guest destination is written between stages.
    opcode.emit(code, LEFT, accumulator_slot(), TargetCpu::Baseline);
}

fn finish(
    code: &mut Code,
    shape: Shape,
    destination: u8,
    pc: GuestAddress,
    rollback: Vec<usize>,
    matrix: bool,
) {
    restore_environment(code);
    if matrix {
        matrix_frame(code, Alu::Add);
    }
    // A successful path must skip the cold helper regardless of arithmetic flags.
    let completed = jump(code);
    let rollback_start = code.len();
    restore_environment(code);
    if matrix {
        matrix_frame(code, Alu::Add);
    }
    super::super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let commit_start = code.len();
    for patch in rollback {
        resolve(code, patch, rollback_start);
    }
    resolve(code, completed, commit_start);
    if shape == Shape::Vector64 {
        packed(code, Host::MoveQword, LEFT, LEFT);
    }
    commit(code, destination, LEFT);
}

pub(in crate::x86_64) fn emit_dot(code: &mut Code, operand: &DotOperand, pc: GuestAddress) {
    let mut rollback = Vec::new();
    environment_round(code, Rounding::Zero);
    read_vector(code, operand.left, LEFT);
    match operand.right {
        DotSource::Vector(source) => read_vector(code, source, RIGHT),
        DotSource::Indexed { register, index } => {
            // Each indexed element is an entire BF16 pair, including pairs in
            // the high half of Vm when the destination has only two lanes.
            read_vector(code, register, RIGHT);
            shuffle(code, RIGHT, RIGHT, index * BROADCAST_DWORD);
        }
    }
    pair_sum(code, operand.shape, &mut rollback, SumCheck::Residuals);
    read_numerical_vector(code, operand.shape, operand.destination, RIGHT);
    add_accumulator(code, operand.shape, &mut rollback, SumCheck::Residuals);
    finish(
        code,
        operand.shape,
        operand.destination,
        pc,
        rollback,
        false,
    );
}

pub(in crate::x86_64) fn emit_matrix(code: &mut Code, operand: &MatrixOperand, pc: GuestAddress) {
    let mut rollback = Vec::new();
    matrix_frame(code, Alu::Sub);
    environment_round(code, Rounding::Zero);
    read_vector(code, operand.destination, LEFT);
    matrix_accumulator(code, Host::StoreUnaligned);
    code.asm()
        .alu(Alu::Xor, Size::Dword, MATRIX_COUNTER, MATRIX_COUNTER);
    let next_stage = code.len();
    // Reloads see the original inputs until the single final commit, including
    // Vd=Vn, Vd=Vm and full aliasing.
    read_vector(code, operand.left, LEFT);
    read_vector(code, operand.right, RIGHT);
    code.asm().test(Size::Dword, MATRIX_COUNTER, MATRIX_COUNTER);
    let first_stage = branch(code, Condition::Zero);
    for source in [LEFT, RIGHT] {
        ShiftOpcode::RightBytes.emit(code, source, PAIR_BYTES);
    }
    let regroup = code.len();
    resolve(code, first_stage, regroup);
    shuffle(code, LEFT, LEFT, MATRIX_LEFT_PAIRS);
    shuffle(code, RIGHT, RIGHT, MATRIX_RIGHT_PAIRS);
    pair_sum(code, Shape::Vector128, &mut rollback, SumCheck::ExactVector);
    // Load the previous accumulator into XMM1, then save the new XMM0 value.
    Host::LoadUnaligned.emit(code, RIGHT, accumulator_slot(), TargetCpu::Baseline);
    add_accumulator(code, Shape::Vector128, &mut rollback, SumCheck::ExactVector);
    matrix_accumulator(code, Host::StoreUnaligned);
    let mut asm = code.asm();
    asm.inc(Size::Dword, MATRIX_COUNTER);
    asm.alu_imm8(Alu::Cmp, Size::Dword, MATRIX_COUNTER, MATRIX_STAGES as i8);
    let repeat = branch(code, Condition::Below);
    resolve(code, repeat, next_stage);
    finish(
        code,
        Shape::Vector128,
        operand.destination,
        pc,
        rollback,
        true,
    );
}
