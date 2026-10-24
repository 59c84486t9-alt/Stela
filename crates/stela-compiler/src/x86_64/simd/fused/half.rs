//! Exact finite Half FMA, with one integer rounding to the target format.
use super::super::super::isa::ShiftOpcode;
use super::super::numerical::{
    ArithmeticOpcode, Condition, VZEROUPPER, branch, emit_fma, emit_opcode_to, jump,
    prepare_vector_input_range, resolve, test_control, vector_exponent_range,
};
use super::super::{Host, commit, half as lanes, packed};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, Format},
        simd::{arithmetic::Shape, fused::Operand},
    },
    block::ExitKind,
};
use alloc::vec::Vec;

// Three complete original vectors and a zeroed result remain private until all
// active lanes pass. Only caller-volatile registers are used; RSI is untouched.
const LEFT_SLOT: u8 = 0;
const RIGHT_SLOT: u8 = 16;
const ADDEND_SLOT: u8 = 32;
const RESULT_SLOT: u8 = 48;
const FRAME_BYTES: u8 = 64;
const SIGN_MASK: u8 = 2;
const HALF_EXPONENT_MASK: u8 = 31;
const EXPONENT_SPAN_BIAS: u8 = 16;
const MAXIMUM_BIASED_SPAN: u8 = 71;

fn load_half(code: &mut Vec<u8>, slot: u8) {
    // MOVZX EAX, word [RSP + R11*2 + slot]. R11 is the active lane index.
    code.extend([0x42, 0x0f, 0xb7, 0x44, 0x5c, slot]);
}

fn exponent(code: &mut Vec<u8>, slot: u8) {
    load_half(code, slot);
    code.extend([0xc1, 0xe8, Format::Half.fraction_bits() as u8]); // SHR EAX,10
    code.extend([0x83, 0xe0, HALF_EXPONENT_MASK]);
}

fn exact_span(code: &mut Vec<u8>, rollback: &mut Vec<usize>) {
    exponent(code, LEFT_SLOT);
    code.extend([0x89, 0xc1]); // MOV ECX,EAX
    exponent(code, RIGHT_SLOT);
    code.extend([0x01, 0xc1]); // ADD ECX,EAX
    exponent(code, ADDEND_SLOT);
    code.extend([0x29, 0xc1]); // SUB ECX,EAX
    code.extend([0x83, 0xc1, EXPONENT_SPAN_BIAS]);
    code.extend([0x83, 0xf9, MAXIMUM_BIASED_SPAN]);
    rollback.push(branch(code, Condition::Above));
}

fn widen_sources(code: &mut Vec<u8>, target: TargetCpu) {
    load_half(code, LEFT_SLOT);
    lanes::widen_normal(code, target);
    packed(code, Host::MoveAligned, lanes::LEFT, lanes::RESULT);
    load_half(code, RIGHT_SLOT);
    lanes::widen_normal(code, target);
    packed(code, Host::MoveAligned, lanes::RIGHT, lanes::RESULT);
    load_half(code, ADDEND_SLOT);
    lanes::widen_normal(code, target);
}

fn arithmetic(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    if target.supports(TargetCpu::Fma) {
        // Original signs: the FMA opcode performs the pre-round sign changes.
        emit_fma(
            code,
            Format::Double,
            Shape::Scalar,
            super::fused_opcode(operand.operation),
            target,
        );
    } else {
        if operand.operation.negate_left() {
            packed(code, Host::Xor, lanes::LEFT, SIGN_MASK);
        }
        if operand.operation.negate_addend() {
            packed(code, Host::Xor, lanes::RESULT, SIGN_MASK);
        }
        emit_opcode_to(
            code,
            Format::Double,
            Shape::Scalar,
            ArithmeticOpcode::Multiply,
            lanes::LEFT,
            lanes::RIGHT,
        );
        emit_opcode_to(
            code,
            Format::Double,
            Shape::Scalar,
            ArithmeticOpcode::Add,
            lanes::LEFT,
            lanes::RESULT,
        );
    }
    packed(code, Host::MoveAligned, lanes::RESULT, lanes::LEFT);
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress, target: TargetCpu) {
    debug_assert_eq!(operand.format, Format::Half);
    let mut helper = Vec::new();
    let mut rollback = Vec::new();
    let widening = if operand.shape == Shape::Scalar {
        // Measured whole scalar recipes favor integer field construction on
        // dependent inputs; packed lane loops benefit from checked F16C.
        TargetCpu::Baseline
    } else {
        target
    };
    if widening.supports(TargetCpu::F16c) || target.supports(TargetCpu::Fma) {
        code.extend(VZEROUPPER);
    }
    // FPMulAdd retains enabled exceptions under either AH setting.
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    super::read_numerical_vector(code, operand.shape, operand.left, lanes::LEFT);
    super::read_numerical_vector(code, operand.shape, operand.addend, lanes::RESULT);
    super::prepare_right(code, operand); // Indexed Q0 may read Vm's upper qword.
    if operand.shape == Shape::Scalar {
        packed(code, Host::MoveAligned, lanes::ORIGINAL_LEFT, lanes::RESULT);
    }
    prepare_vector_input_range(code, Format::Half);
    for source in [lanes::LEFT, lanes::RIGHT, lanes::RESULT] {
        vector_exponent_range(code, Format::Half, operand.shape, source);
        helper.push(branch(code, Condition::NotZero));
    }
    code.extend([0x48, 0x83, 0xec, FRAME_BYTES]);
    code.extend([0xf3, 0x0f, 0x7f, 0x04, 0x24]); // MOVDQU [RSP],XMM0
    code.extend([0xf3, 0x0f, 0x7f, 0x4c, 0x24, RIGHT_SLOT]);
    code.extend([0xf3, 0x0f, 0x7f, 0x74, 0x24, ADDEND_SLOT]);
    packed(code, Host::Xor, SIGN_MASK, SIGN_MASK);
    code.extend([0xf3, 0x0f, 0x7f, 0x54, 0x24, RESULT_SLOT]);
    if !target.supports(TargetCpu::Fma)
        && (operand.operation.negate_left() || operand.operation.negate_addend())
    {
        packed(code, Host::EqualDword, SIGN_MASK, SIGN_MASK);
        ShiftOpcode::LeftQword.emit(code, SIGN_MASK, 63);
    }
    lanes::set_pack_bias(code);
    let loop_start = lanes::start_lanes(code);
    // For normal Half x=s*m*2^(e-10), product precision is at most22 bits.
    // With d=eL+eR-eA, -31<=d<=40 bounds the aligned sum to53 bits:
    // max(22+max(d-10,0),11+max(10-d,0))+1 <=53. Both Double operations
    // are exact and far from Double's range limits under every caller MXCSR.
    // Raw exponents give d+31=EL+ER-EA+16; unsigned wrap rejects the low end.
    exact_span(code, &mut rollback);
    widen_sources(code, widening);
    arithmetic(code, operand, target);
    // Zero (including cancellation), tiny/overflow and rounded exponent1 stay
    // on the precise helper. FPCR controls the only rounding, including AH1.
    lanes::pack_normal(
        code,
        &mut rollback,
        lanes::RoundingPolicy::Fpcr,
        lanes::ResultSign::Preserve,
    );
    code.extend([0x66, 0x42, 0x89, 0x44, 0x5c, RESULT_SLOT]);
    code.extend([0x41, 0xff, 0xc3]); // INC R11D
    code.extend([
        0x41,
        0x83,
        0xfb,
        operand.shape.lane_count(Format::Half) as u8,
    ]);
    let more = branch(code, Condition::Below);
    resolve(code, more, loop_start);
    code.extend([0xf3, 0x0f, 0x6f, 0x44, 0x24, RESULT_SLOT]);
    code.extend([0x48, 0x83, 0xc4, FRAME_BYTES]);
    let success = jump(code);
    let rollback_start = code.len();
    code.extend([0x48, 0x83, 0xc4, FRAME_BYTES]);
    let helper_start = code.len();
    super::super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let commit_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    for patch in rollback {
        resolve(code, patch, rollback_start);
    }
    resolve(code, success, commit_start);
    lanes::commit_inexact(code);
    if operand.shape == Shape::Scalar {
        // XMM7 is original unnegated A; EAX is the last (only) packed Half.
        lanes::merge_scalar(code);
    }
    commit(code, operand.destination, lanes::LEFT);
}
