//! Half-precision FCADD/FCMLA through exact double intermediates.
use super::super::super::isa::ShiftOpcode;
use super::super::numerical::{
    ArithmeticOpcode, Condition, MXCSR_INEXACT, Rounding, branch, emit_opcode_to,
    environment_round, prepare_vector_input_range, restore_environment, test_control,
    vector_exponent_range,
};
use super::super::{Host, commit, half as lanes, packed, read_vector};
use crate::x86_64::asm::{Alu, Code, Gpr, Rm, ShiftOp, Size};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, Format},
        simd::{
            arithmetic::Shape,
            complex::{Kind, Operand},
        },
    },
};
use alloc::vec::Vec;

const HALF_BYTES: u8 = (Format::Half.bits() / u8::BITS) as u8;
const HALF_TO_DOUBLE_FRACTION_SHIFT: u8 =
    (Format::Double.fraction_bits() - Format::Half.fraction_bits()) as u8;
const HALF_TO_DOUBLE_SIGN_SHIFT: u8 = (Format::Double.bits() - Format::Half.bits()) as u8;

fn normal_inputs(code: &mut Code, operand: &Operand, helper: &mut Vec<usize>) {
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    if operand.kind == Kind::MultiplyAdd {
        // Original Vd is a numerical input, independent of all Vn/Vm aliases.
        read_vector(code, operand.destination, lanes::ORIGINAL_LEFT);
    }
    prepare_vector_input_range(code, Format::Half);
    for source in [lanes::LEFT, lanes::RIGHT] {
        vector_exponent_range(code, Format::Half, operand.shape, source);
        helper.push(branch(code, Condition::NotZero));
    }
    if operand.kind == Kind::MultiplyAdd {
        vector_exponent_range(code, Format::Half, operand.shape, lanes::ORIGINAL_LEFT);
        helper.push(branch(code, Condition::NotZero));
    }
    // FPNeg is an ordinary sign toggle only after every effective input is
    // known non-NaN. The parent's mask changes only the selected M components.
    super::rotate_right_sign(code, Format::Half, operand.rotation);
}

fn widen_addend(code: &mut Code, target: TargetCpu) {
    // The addend's private XMM7 snapshot advances one Half per completed lane.
    // R9 is the shared unscaled Half-to-Double bias and survives MXCSR setup.
    code.asm().movd_from_xmm(Gpr::Rax, lanes::ORIGINAL_LEFT);
    if target.supports(TargetCpu::F16c) {
        // Isolate the selected Half before packed conversion: the next lane in
        // XMM7 may be an inactive sNaN. MOVD also zeros every higher Half lane.
        let mut asm = code.asm();
        asm.movzx(Size::Dword, Gpr::Rax, Size::Word, Gpr::Rax);
        asm.movd_to_xmm(lanes::RESULT, Gpr::Rax);
        Host::ConvertHalfToSingle.register(code, lanes::RESULT, lanes::RESULT, target);
        code.asm().cvtss2sd(lanes::RESULT, Rm::Xmm(lanes::RESULT));
        return;
    }
    let sign = Format::Half.sign_mask() as u32;
    let mut asm = code.asm();
    asm.mov(Size::Dword, Gpr::Rdx, Gpr::Rax);
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, (sign - 1) as i32);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Qword,
        Gpr::Rax,
        HALF_TO_DOUBLE_FRACTION_SHIFT,
    );
    asm.alu(Alu::Add, Size::Qword, Gpr::Rax, Gpr::R9);
    asm.alu_imm32(Alu::And, Size::Dword, Gpr::Rdx, sign as i32);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Qword,
        Gpr::Rdx,
        HALF_TO_DOUBLE_SIGN_SHIFT,
    );
    asm.alu(Alu::Or, Size::Qword, Gpr::Rax, Gpr::Rdx);
    asm.movq_to_xmm(lanes::RESULT, Gpr::Rax);
}

fn arithmetic(code: &mut Code, kind: Kind, target: TargetCpu, rollback: &mut Vec<usize>) {
    if kind == Kind::Add {
        packed(code, Host::MoveAligned, lanes::RESULT, lanes::LEFT);
        // Normal Half sums need at most 41 bits; nonzero sums are normal Double.
        // Exact arithmetic cannot depend on caller RC/DAZ/FTZ or raise status.
        // Cancellation zero still uses the core through the shared output guard.
        emit_opcode_to(
            code,
            Format::Double,
            Shape::Scalar,
            ArithmeticOpcode::Add,
            lanes::RESULT,
            lanes::RIGHT,
        );
        return;
    }
    widen_addend(code, target);
    // Products are exact at 22 bits, but adding a distant Half addend can need
    // up to 64 bits. Only exact Double sums may reach architectural Half rounding.
    // Fixed RNE is sufficient for admission and avoids reading guest RC twice.
    environment_round(code, Rounding::NearestEven);
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
        lanes::RESULT,
        lanes::LEFT,
    );
    restore_environment(code);
    // Normal Half inputs bound every Double result to finite normal or exact
    // zero, so PE is the only possible fresh status. Test it after restoration:
    // the shared rollback then drops exactly its own 48-byte frame.
    code.asm()
        .test_imm(Size::Dword, Gpr::Rcx, MXCSR_INEXACT as i32);
    rollback.push(branch(code, Condition::NotZero));
}

pub(super) fn emit(code: &mut Code, operand: &Operand, pc: GuestAddress, target: TargetCpu) {
    debug_assert_eq!(operand.format, Format::Half);
    let mut helper = Vec::new();
    let mut rollback = Vec::new();
    normal_inputs(code, operand, &mut helper);
    lanes::allocate_frame(code);
    let checked_widening = target.supports(TargetCpu::F16c);
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
    arithmetic(code, operand.kind, target, &mut rollback);
    lanes::pack_lane(
        code,
        &mut rollback,
        lanes::RoundingPolicy::Fpcr,
        lanes::ResultSign::Preserve,
    );
    if operand.kind == Kind::MultiplyAdd {
        ShiftOpcode::RightBytes.emit(code, lanes::ORIGINAL_LEFT, HALF_BYTES);
    }
    lanes::finish_lanes(
        code,
        operand.shape.lane_count(Format::Half) as u8,
        loop_start,
        &helper,
        &rollback,
        pc,
    );
    // Complex operations retain guest RC and fresh IXC under either AH value.
    // The shared frame initialized all inactive result lanes to zero; NEP is ignored.
    lanes::commit_inexact(code);
    commit(code, operand.destination, lanes::LEFT);
}
