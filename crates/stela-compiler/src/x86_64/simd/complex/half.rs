//! Half-precision FCADD/FCMLA through exact double intermediates.
use super::super::super::isa::ShiftOpcode;
use super::super::numerical::{
    ArithmeticOpcode, Condition, MXCSR_INEXACT, Rounding, branch, emit_opcode_to,
    environment_round, prepare_vector_input_range, restore_environment, test_control,
    vector_exponent_range,
};
use super::super::{Host, commit, half as lanes, packed, read_vector};
use crate::x86_64::asm::Code;
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
const MOVD_EAX_XMM7: &[u8] = &[0x66, 0x0f, 0x7e, 0xf8];
const MOVZX_EAX_AX: &[u8] = &[0x0f, 0xb7, 0xc0];
const MOVD_XMM6_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xf0];
const CVTSS2SD_XMM6_XMM6: &[u8] = &[0xf3, 0x0f, 0x5a, 0xf6];
const MOV_EDX_EAX: &[u8] = &[0x89, 0xc2];
const AND_EAX_IMM32: u8 = 0x25;
const AND_EDX_IMM32: &[u8] = &[0x81, 0xe2];
const SHL_RAX_IMM8: &[u8] = &[0x48, 0xc1, 0xe0];
const SHL_RDX_IMM8: &[u8] = &[0x48, 0xc1, 0xe2];
const ADD_RAX_R9: &[u8] = &[0x4c, 0x01, 0xc8];
const OR_RAX_RDX: &[u8] = &[0x48, 0x09, 0xd0];
const MOVQ_XMM6_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e, 0xf0];
const TEST_ECX_IMM32: &[u8] = &[0xf7, 0xc1];

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
    code.extend(MOVD_EAX_XMM7);
    if target.supports(TargetCpu::F16c) {
        // Isolate the selected Half before packed conversion: the next lane in
        // XMM7 may be an inactive sNaN. MOVD also zeros every higher Half lane.
        code.extend(MOVZX_EAX_AX);
        code.extend(MOVD_XMM6_EAX);
        Host::ConvertHalfToSingle.register(code, lanes::RESULT, lanes::RESULT, target);
        code.extend(CVTSS2SD_XMM6_XMM6);
        return;
    }
    code.extend(MOV_EDX_EAX);
    code.push(AND_EAX_IMM32);
    code.extend((Format::Half.sign_mask() as u32 - 1).to_le_bytes());
    code.extend(SHL_RAX_IMM8);
    code.push(HALF_TO_DOUBLE_FRACTION_SHIFT);
    code.extend(ADD_RAX_R9);
    code.extend(AND_EDX_IMM32);
    code.extend((Format::Half.sign_mask() as u32).to_le_bytes());
    code.extend(SHL_RDX_IMM8);
    code.push(HALF_TO_DOUBLE_SIGN_SHIFT);
    code.extend(OR_RAX_RDX);
    code.extend(MOVQ_XMM6_RAX);
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
    code.extend(TEST_ECX_IMM32);
    code.extend(MXCSR_INEXACT.to_le_bytes());
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
