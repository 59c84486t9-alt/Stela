//! BFMLAL with SSE2 or FMA3.
use super::super::super::isa::ShiftOpcode;
use super::super::numerical::{
    ArithmeticOpcode, Condition, FusedOpcode, VZEROUPPER, branch, commit_ah0_inexact, emit_fma,
    emit_opcode, environment_alternative_nearest, guard_ah0_exceptions, prepare_vector_input_range,
    prepare_vector_result_range, reject_other_status, reject_product_status, resolve,
    restore_environment, restore_environment_with_product, save_product_status,
    vector_exponent_range,
};
use super::super::{commit, read_vector, shuffle};
use crate::x86_64::asm::Code;
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{
            Format,
            bfloat16::{BFLOAT16_BITS, BFLOAT16_TO_SINGLE_SHIFT},
        },
        simd::{
            arithmetic::Shape,
            bfloat16::{MultiplyOperand, MultiplySource, Parity},
        },
    },
    block::ExitKind,
};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const ADDEND: u8 = 6;
const FIRST_LANE: u8 = 0;
const OUTPUT_SHAPE: Shape = Shape::Vector128;
const BFLOAT16_BYTES: u32 = BFLOAT16_BITS / u8::BITS;

fn select_vector(code: &mut Code, source: u8, vector: u8, parity: Parity) {
    read_vector(code, source, vector);
    if parity == Parity::Odd {
        ShiftOpcode::RightDword.emit(code, vector, BFLOAT16_BITS as u8);
    }
    // Discard the other BF16 field before any host numerical operation. The
    // remaining sign/exponent/fraction is already the high sixteen Single bits.
    ShiftOpcode::LeftDword.emit(code, vector, BFLOAT16_TO_SINGLE_SHIFT as u8);
}

fn prepare_sources(code: &mut Code, operand: &MultiplyOperand) {
    select_vector(code, operand.left, LEFT, operand.parity);
    match operand.right {
        MultiplySource::Vector(source) => select_vector(code, source, RIGHT, operand.parity),
        MultiplySource::Indexed { register, index } => {
            // Indexed Vm may name any half-precision lane, whatever the left
            // parity, so snapshot the whole source first.
            read_vector(code, register, RIGHT);
            if index != FIRST_LANE {
                ShiftOpcode::RightBytes.emit(
                    code,
                    RIGHT,
                    (u32::from(index) * BFLOAT16_BYTES) as u8,
                );
            }
            shuffle(code, RIGHT, RIGHT, FIRST_LANE);
            ShiftOpcode::LeftDword.emit(code, RIGHT, BFLOAT16_TO_SINGLE_SHIFT as u8);
        }
    }
    // Vd is an input accumulator, including every source/destination alias.
    // No architectural state is written until all result guards pass.
    read_vector(code, operand.destination, ADDEND);
}

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: &MultiplyOperand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    let native_fma = target.supports(TargetCpu::Fma);
    if native_fma {
        code.extend(VZEROUPPER);
    }
    let mut helper = Vec::new();
    guard_ah0_exceptions(code, &mut helper);
    prepare_sources(code, operand);
    prepare_vector_input_range(code, Format::Single);
    for source in [LEFT, RIGHT] {
        vector_exponent_range(code, Format::Single, OUTPUT_SHAPE, source);
        helper.push(branch(code, Condition::NotZero));
    }
    vector_exponent_range(code, Format::Single, OUTPUT_SHAPE, ADDEND);
    // All input failures and post-math failures share this precise cold exit.
    // The latter can branch back only after restoring caller MXCSR and RSP.
    let accepted = branch(code, Condition::Zero);
    let helper_start = code.len();
    super::super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let accepted_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, accepted, accepted_start);
    environment_alternative_nearest(code);
    if native_fma {
        emit_fma(
            code,
            Format::Single,
            OUTPUT_SHAPE,
            FusedOpcode::MultiplyAdd,
            target,
        );
        restore_environment(code);
    } else {
        emit_opcode(
            code,
            Format::Single,
            OUTPUT_SHAPE,
            ArithmeticOpcode::Multiply,
            RIGHT,
        );
        save_product_status(code);
        emit_opcode(
            code,
            Format::Single,
            OUTPUT_SHAPE,
            ArithmeticOpcode::Add,
            ADDEND,
        );
        restore_environment_with_product(code);
        // BF16 has at most sixteen product significand bits, but its exponent
        // range exceeds Single. Require an exact, nonexceptional intermediate
        // product rather than silently accepting split rounding or overflow.
        let product_failed = reject_product_status(code);
        resolve(code, product_failed, helper_start);
    }
    let status_failed = reject_other_status(code);
    resolve(code, status_failed, helper_start);
    // Avoid target tininess/flush and before-versus-after-rounding boundaries.
    // Zero, subnormal, minimum-binade and special outputs use the complete core.
    prepare_vector_result_range(code);
    vector_exponent_range(code, Format::Single, OUTPUT_SHAPE, LEFT);
    let result_failed = branch(code, Condition::NotZero);
    resolve(code, result_failed, helper_start);
    commit_ah0_inexact(code);
    commit(code, operand.destination, LEFT);
}
