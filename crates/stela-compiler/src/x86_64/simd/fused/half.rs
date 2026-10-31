//! Exact finite Half FMA, with one integer rounding to the target format, or
//! one AVX512-FP16 instruction.
use super::super::super::isa::ShiftOpcode;
use super::super::numerical::{
    ArithmeticOpcode, Condition, branch, emit_fma, emit_opcode_to, jump,
    prepare_vector_input_range, resolve, test_control, vector_exponent_range,
};
use super::super::{Host, commit, half as lanes, packed};
use crate::x86_64::asm::{Alu, Code, Disp, Gpr, Mem, ShiftOp, Size, vector_extensions};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, Format},
        simd::{arithmetic::Shape, fused::Operand},
    },
    block::ExitKind,
};
use alloc::{vec, vec::Vec};

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

use Gpr::{R11, Rax, Rcx, Rsp};

/// `[rsp + r11*2 + slot]`: the active lane, R11, of a frame slot.
fn lane(slot: u8) -> Mem {
    Mem::indexed(Rsp, R11, 2, slot.into()).with_width(Disp::Byte)
}

/// `[rsp + slot]`, a frame slot.
fn frame(slot: u8) -> Mem {
    Mem::base(Rsp, slot.into())
}

fn load_half(code: &mut Code, slot: u8) {
    code.asm().movzx(Size::Dword, Rax, Size::Word, lane(slot));
}

fn exponent(code: &mut Code, slot: u8) {
    load_half(code, slot);
    let mut asm = code.asm();
    asm.shift_imm(
        ShiftOp::Shr,
        Size::Dword,
        Rax,
        Format::Half.fraction_bits() as u8,
    );
    asm.alu_imm8(Alu::And, Size::Dword, Rax, HALF_EXPONENT_MASK as i8);
}

fn exact_span(code: &mut Code, rollback: &mut Vec<usize>) {
    exponent(code, LEFT_SLOT);
    code.asm().mov(Size::Dword, Rcx, Rax);
    exponent(code, RIGHT_SLOT);
    code.asm().alu(Alu::Add, Size::Dword, Rcx, Rax);
    exponent(code, ADDEND_SLOT);
    let mut asm = code.asm();
    asm.alu(Alu::Sub, Size::Dword, Rcx, Rax);
    asm.alu_imm8(Alu::Add, Size::Dword, Rcx, EXPONENT_SPAN_BIAS as i8);
    asm.alu_imm8(Alu::Cmp, Size::Dword, Rcx, MAXIMUM_BIASED_SPAN as i8);
    rollback.push(branch(code, Condition::Above));
}

fn widen_sources(code: &mut Code, target: TargetCpu) {
    load_half(code, LEFT_SLOT);
    lanes::widen_normal(code, target);
    packed(code, Host::MoveAligned, lanes::LEFT, lanes::RESULT);
    load_half(code, RIGHT_SLOT);
    lanes::widen_normal(code, target);
    packed(code, Host::MoveAligned, lanes::RIGHT, lanes::RESULT);
    load_half(code, ADDEND_SLOT);
    lanes::widen_normal(code, target);
}

fn arithmetic(code: &mut Code, operand: &Operand, target: TargetCpu) {
    if target.supports(TargetCpu::Fma) {
        // Original signs: the FMA opcode performs the pre-round sign changes.
        emit_fma(
            code,
            Format::Double,
            Shape::Scalar,
            super::super::numerical::FusedOpcode::from(operand.operation),
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

/// Read all three vectors; `helper` takes enabled exceptions and any active
/// input that is not normal. The scalar form keeps the addend for NEP merging.
fn guarded_inputs(code: &mut Code, operand: &Operand) -> Vec<usize> {
    // FPMulAdd keeps enabled exceptions under either AH setting.
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    let mut helper = vec![branch(code, Condition::NotZero)];
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
    helper
}

/// One AVX512-FP16 instruction, whose single rounding needs no exponent span
/// bound.
fn emit_native(code: &mut Code, operand: &Operand, pc: GuestAddress) {
    let mut helper = guarded_inputs(code, operand);
    lanes::run_native(code, operand.shape, &mut helper, |code| {
        vector_extensions::half_fused(
            code,
            super::super::numerical::FusedOpcode::from(operand.operation) as u8,
            lanes::LEFT,
            lanes::RESULT,
            lanes::RIGHT,
        );
    });
    let merge = operand.shape == Shape::Scalar;
    lanes::finish_native(code, operand.destination, merge, helper, pc);
}

pub(super) fn emit(code: &mut Code, operand: &Operand, pc: GuestAddress, target: TargetCpu) {
    debug_assert_eq!(operand.format, Format::Half);
    if vector_extensions::half_supported(target) {
        emit_native(code, operand, pc);
        return;
    }
    let mut rollback = Vec::new();
    let widening = if operand.shape == Shape::Scalar {
        // Measured whole scalar recipes favor integer field construction on
        // dependent inputs; packed lane loops benefit from checked F16C.
        TargetCpu::Baseline
    } else {
        target
    };
    if widening.supports(TargetCpu::F16c) || target.supports(TargetCpu::Fma) {
        code.asm().vzeroupper();
    }
    let helper = guarded_inputs(code, operand);
    let baseline = TargetCpu::Baseline;
    code.asm()
        .alu_imm8(Alu::Sub, Size::Qword, Rsp, FRAME_BYTES as i8);
    Host::StoreUnaligned.emit(code, lanes::LEFT, frame(LEFT_SLOT), baseline);
    Host::StoreUnaligned.emit(code, lanes::RIGHT, frame(RIGHT_SLOT), baseline);
    Host::StoreUnaligned.emit(code, lanes::RESULT, frame(ADDEND_SLOT), baseline);
    packed(code, Host::Xor, SIGN_MASK, SIGN_MASK);
    Host::StoreUnaligned.emit(code, SIGN_MASK, frame(RESULT_SLOT), baseline);
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
    let mut asm = code.asm();
    asm.mov_store(Size::Word, lane(RESULT_SLOT), Rax);
    asm.inc(Size::Dword, R11);
    asm.alu_imm8(
        Alu::Cmp,
        Size::Dword,
        R11,
        operand.shape.lane_count(Format::Half) as i8,
    );
    let more = branch(code, Condition::Below);
    resolve(code, more, loop_start);
    Host::LoadUnaligned.emit(code, lanes::LEFT, frame(RESULT_SLOT), baseline);
    code.asm()
        .alu_imm8(Alu::Add, Size::Qword, Rsp, FRAME_BYTES as i8);
    let success = jump(code);
    let rollback_start = code.len();
    code.asm()
        .alu_imm8(Alu::Add, Size::Qword, Rsp, FRAME_BYTES as i8);
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
