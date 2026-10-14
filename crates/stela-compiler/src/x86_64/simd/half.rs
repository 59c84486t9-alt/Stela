//! Exact normal-Half lane fields, private rounding and compact scratch loop.
//! Callers own input classification, arithmetic, exception policy and guest commit.
use super::numerical::{Condition, RESULT_MINIMUM_EXPONENT, branch, resolve, test_control};
use super::{Host, packed};
use crate::{
    GuestAddress, GuestState, TargetCpu,
    aarch64::floating::{FPCR_AH, FPCR_NEP, FPCR_ROUNDING_SHIFT, Format, INEXACT},
    block::ExitKind,
};

pub(super) const LEFT: u8 = 0;
pub(super) const RIGHT: u8 = 1;
pub(super) const RESULT: u8 = 6;
pub(super) const ORIGINAL_LEFT: u8 = 7;
const ZERO: u8 = 2;
const FIRST_LANE: u8 = 0;
const JMP_REL32: u8 = 0xe9;
const SIGN_BITS: u32 = 1;
const FPCR_ROUNDING_LOW: u32 = 1 << FPCR_ROUNDING_SHIFT;
const FPCR_ROUNDING_HIGH: u32 = FPCR_ROUNDING_LOW << 1;
const XOR_EAX_IMM32: u8 = 0x35;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RoundingPolicy {
    Fpcr,
    AhNearestEven,
}

#[derive(Clone, Copy)]
pub(super) enum LeftScale {
    Identity,
    Halved,
}

#[derive(Clone, Copy)]
pub(super) enum ResultSign {
    Preserve,
    Negate,
    Absolute,
}

// Half sources/results remain private until every active lane has passed.
// Only SysV caller-volatile GPRs are used; RSI remains untouched.
const HOST_VECTOR_BYTES: u8 = 16;
const HALF_RIGHT_SLOT: u8 = HOST_VECTOR_BYTES;
const HALF_RESULT_SLOT: u8 = HOST_VECTOR_BYTES * 2;
const HALF_STACK_BYTES: u8 = HALF_RESULT_SLOT + HOST_VECTOR_BYTES;
const SUB_RSP: &[u8] = &[0x48, 0x83, 0xec];
const ADD_RSP: &[u8] = &[0x48, 0x83, 0xc4];
const SAVE_LEFT: &[u8] = &[0xf3, 0x0f, 0x7f, 0x04, 0x24];
const SAVE_RIGHT: &[u8] = &[0xf3, 0x0f, 0x7f, 0x4c, 0x24, HALF_RIGHT_SLOT];
const SAVE_ZERO_RESULT: &[u8] = &[0xf3, 0x0f, 0x7f, 0x54, 0x24, HALF_RESULT_SLOT];
const LOAD_RESULT: &[u8] = &[0xf3, 0x0f, 0x6f, 0x44, 0x24, HALF_RESULT_SLOT];
const LOAD_LEFT_HALF: &[u8] = &[0x42, 0x0f, 0xb7, 0x04, 0x5c];
const LOAD_RIGHT_HALF: &[u8] = &[0x42, 0x0f, 0xb7, 0x4c, 0x5c, HALF_RIGHT_SLOT];
const STORE_RESULT_HALF: &[u8] = &[0x66, 0x42, 0x89, 0x44, 0x5c, HALF_RESULT_SLOT];
const XOR_R10D_R10D: &[u8] = &[0x45, 0x31, 0xd2];
const XOR_R11D_R11D: &[u8] = &[0x45, 0x31, 0xdb];
const INC_R11D: &[u8] = &[0x41, 0xff, 0xc3];
const CMP_R11D: &[u8] = &[0x41, 0x83, 0xfb];
const MOVABS_R8: &[u8] = &[0x49, 0xb8];
const MOVABS_R9: &[u8] = &[0x49, 0xb9];
const MOVABS_RDX: &[u8] = &[0x48, 0xba];
const MOV_EDX_EAX: &[u8] = &[0x89, 0xc2];
const MOV_EDX_ECX: &[u8] = &[0x89, 0xca];
const AND_EAX_IMM32: u8 = 0x25;
const AND_ECX_IMM32: &[u8] = &[0x81, 0xe1];
const AND_EDX_IMM32: &[u8] = &[0x81, 0xe2];
const SHL_RAX: &[u8] = &[0x48, 0xc1, 0xe0];
const SHL_RCX: &[u8] = &[0x48, 0xc1, 0xe1];
const SHL_RDX: &[u8] = &[0x48, 0xc1, 0xe2];
const SHR_RAX: &[u8] = &[0x48, 0xc1, 0xe8];
const SHR_RCX: &[u8] = &[0x48, 0xc1, 0xe9];
const SHR_RDX: &[u8] = &[0x48, 0xc1, 0xea];
const SHR_EDX: &[u8] = &[0xc1, 0xea];
const SHL_EDX: &[u8] = &[0xc1, 0xe2];
const SHL_ECX: &[u8] = &[0xc1, 0xe1];
const ADD_RAX_R8: &[u8] = &[0x4c, 0x01, 0xc0];
const ADD_RCX_R9: &[u8] = &[0x4c, 0x01, 0xc9];
const SUB_RAX_R9: &[u8] = &[0x4c, 0x29, 0xc8];
const OR_RAX_RDX: &[u8] = &[0x48, 0x09, 0xd0];
const OR_RCX_RDX: &[u8] = &[0x48, 0x09, 0xd1];
const OR_EAX_ECX: &[u8] = &[0x09, 0xc8];
const MOVQ_XMM0_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e, 0xc0];
const MOVQ_XMM1_RCX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e, 0xc9];
const MOVD_XMM0_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xc0];
const MOVD_XMM1_ECX: &[u8] = &[0x66, 0x0f, 0x6e, 0xc9];
const CVTSS2SD_XMM0_XMM0: &[u8] = &[0xf3, 0x0f, 0x5a, 0xc0];
const CVTSS2SD_XMM1_XMM1: &[u8] = &[0xf3, 0x0f, 0x5a, 0xc9];
const MOVQ_RAX_XMM6: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xf0];
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const BTR_RAX: &[u8] = &[0x48, 0x0f, 0xba, 0xf0];
const BT_RAX: &[u8] = &[0x48, 0x0f, 0xba, 0xe0];
const SUB_EDX_IMM32: &[u8] = &[0x81, 0xea];
const SUB_EDX_IMM8: &[u8] = &[0x83, 0xea];
const CMP_EDX_IMM8: &[u8] = &[0x83, 0xfa];
const SETNE_DL: &[u8] = &[0x0f, 0x95, 0xc2];
const MOVZX_EDX_DL: &[u8] = &[0x0f, 0xb6, 0xd2];
const OR_R10D_EDX: &[u8] = &[0x41, 0x09, 0xd2];
const ADC_RAX_RDX: &[u8] = &[0x48, 0x11, 0xd0];
const ADD_RAX_RDX: &[u8] = &[0x48, 0x01, 0xd0];
const TEST_ECX_ECX: &[u8] = &[0x85, 0xc9];
const OR_STATE_R10D: &[u8] = &[0x44, 0x09, 0x97];
const PINSRW_XMM7_EAX: &[u8] = &[0x66, 0x0f, 0xc4, 0xf8, FIRST_LANE];
const HALF_TO_DOUBLE_SHIFT: u8 =
    (Format::Double.fraction_bits() - Format::Half.fraction_bits()) as u8;
const HALF_TO_DOUBLE_SIGN_SHIFT: u8 = (Format::Double.bits() - Format::Half.bits()) as u8;
const HALF_TO_DOUBLE_BIAS: u64 = ((Format::Double.exponent_bias() - Format::Half.exponent_bias())
    as u64)
    << Format::Double.fraction_bits();
const HALF_DISCARDED_MASK: u64 = (1u64 << HALF_TO_DOUBLE_SHIFT) - 1;
const HALF_NORMAL_EXPONENT_COUNT: u8 = ((Format::Half.exponent_mask()
    >> Format::Half.fraction_bits())
    - RESULT_MINIMUM_EXPONENT as u64) as u8;

fn jump(code: &mut Vec<u8>) -> usize {
    code.push(JMP_REL32);
    let patch = code.len();
    code.extend(0i32.to_le_bytes());
    patch
}

fn shift(code: &mut Vec<u8>, opcode: &[u8], amount: u8) {
    code.extend(opcode);
    code.push(amount);
}

fn immediate64(code: &mut Vec<u8>, opcode: &[u8], value: u64) {
    code.extend(opcode);
    code.extend(value.to_le_bytes());
}

/// Inputs XMM0/XMM1 are snapshotted before any widened lane overwrites them.
pub(super) fn allocate_frame(code: &mut Vec<u8>) {
    code.extend(SUB_RSP);
    code.push(HALF_STACK_BYTES);
    code.extend(SAVE_LEFT);
    code.extend(SAVE_RIGHT);
    packed(code, Host::Xor, ZERO, ZERO);
    code.extend(SAVE_ZERO_RESULT);
}

pub(super) fn set_biases(code: &mut Vec<u8>, scale: LeftScale) {
    let left_bias = HALF_TO_DOUBLE_BIAS
        - match scale {
            LeftScale::Identity => 0,
            LeftScale::Halved => 1u64 << Format::Double.fraction_bits(),
        };
    immediate64(code, MOVABS_R8, left_bias);
    set_pack_bias(code);
}

/// Checked hardware widening needs only the integer packer's unscaled bias.
pub(super) fn set_pack_bias(code: &mut Vec<u8>) {
    immediate64(code, MOVABS_R9, HALF_TO_DOUBLE_BIAS);
}

/// Family constants may be prepared after biases and before this loop label.
pub(super) fn start_lanes(code: &mut Vec<u8>) -> usize {
    code.extend(XOR_R10D_R10D);
    code.extend(XOR_R11D_R11D);
    code.len()
}

/// Normal Half field construction is exact and cannot raise host FP status.
pub(super) fn widen_lane(code: &mut Vec<u8>) {
    code.extend(LOAD_LEFT_HALF);
    code.extend(MOV_EDX_EAX);
    code.push(AND_EAX_IMM32);
    code.extend((Format::Half.sign_mask() as u32 - 1).to_le_bytes());
    shift(code, SHL_RAX, HALF_TO_DOUBLE_SHIFT);
    code.extend(ADD_RAX_R8);
    code.extend(AND_EDX_IMM32);
    code.extend((Format::Half.sign_mask() as u32).to_le_bytes());
    shift(code, SHL_RDX, HALF_TO_DOUBLE_SIGN_SHIFT);
    code.extend(OR_RAX_RDX);
    code.extend(MOVQ_XMM0_RAX);
    code.extend(LOAD_RIGHT_HALF);
    code.extend(MOV_EDX_ECX);
    code.extend(AND_ECX_IMM32);
    code.extend((Format::Half.sign_mask() as u32 - 1).to_le_bytes());
    shift(code, SHL_RCX, HALF_TO_DOUBLE_SHIFT);
    code.extend(ADD_RCX_R9);
    code.extend(AND_EDX_IMM32);
    code.extend((Format::Half.sign_mask() as u32).to_le_bytes());
    shift(code, SHL_RDX, HALF_TO_DOUBLE_SIGN_SHIFT);
    code.extend(OR_RCX_RDX);
    code.extend(MOVQ_XMM1_RCX);
}

/// Normal Half to Single to Double is exact. MOVZX and MOVD zero all inactive
/// lanes before the packed hardware conversion, including poisoned scalar bits.
pub(super) fn widen_lane_checked(code: &mut Vec<u8>, target: TargetCpu) {
    code.extend(LOAD_LEFT_HALF);
    code.extend(MOVD_XMM0_EAX);
    Host::ConvertHalfToSingle.register(code, LEFT, LEFT, target);
    code.extend(CVTSS2SD_XMM0_XMM0);
    code.extend(LOAD_RIGHT_HALF);
    code.extend(MOVD_XMM1_ECX);
    Host::ConvertHalfToSingle.register(code, RIGHT, RIGHT, target);
    code.extend(CVTSS2SD_XMM1_XMM1);
}

fn round_half_magnitude(code: &mut Vec<u8>, rounding: RoundingPolicy) {
    // RAX holds positive rebased Double fields, RCX the original sign.
    let nearest_ah = if rounding == RoundingPolicy::AhNearestEven {
        test_control(code, FPCR_AH);
        Some(branch(code, Condition::NotZero))
    } else {
        None
    };
    test_control(code, FPCR_ROUNDING_HIGH);
    let high = branch(code, Condition::NotZero);
    test_control(code, FPCR_ROUNDING_LOW);
    let positive = branch(code, Condition::NotZero);
    let nearest = code.len();
    if let Some(patch) = nearest_ah {
        resolve(code, patch, nearest);
    }
    immediate64(code, MOVABS_RDX, HALF_DISCARDED_MASK >> 1);
    shift(code, BT_RAX, HALF_TO_DOUBLE_SHIFT);
    code.extend(ADC_RAX_RDX);
    let nearest_done = jump(code);
    let high_start = code.len();
    resolve(code, high, high_start);
    test_control(code, FPCR_ROUNDING_LOW);
    let truncating = branch(code, Condition::NotZero);
    code.extend(TEST_ECX_ECX);
    let negative_unmatched = branch(code, Condition::Zero);
    let negative_bias = jump(code);
    let positive_start = code.len();
    resolve(code, positive, positive_start);
    code.extend(TEST_ECX_ECX);
    let positive_unmatched = branch(code, Condition::NotZero);
    let bias_start = code.len();
    resolve(code, negative_bias, bias_start);
    immediate64(code, MOVABS_RDX, HALF_DISCARDED_MASK);
    code.extend(ADD_RAX_RDX);
    let end = code.len();
    for patch in [
        nearest_done,
        truncating,
        negative_unmatched,
        positive_unmatched,
    ] {
        resolve(code, patch, end);
    }
    shift(code, SHR_RAX, HALF_TO_DOUBLE_SHIFT);
}

pub(super) fn pack_lane(
    code: &mut Vec<u8>,
    rollback: &mut Vec<usize>,
    rounding: RoundingPolicy,
    sign: ResultSign,
) {
    code.extend(MOVQ_RAX_XMM6);
    code.extend(MOV_RCX_RAX);
    shift(code, SHR_RCX, (Format::Double.bits() - SIGN_BITS) as u8);
    shift(code, BTR_RAX, (Format::Double.bits() - SIGN_BITS) as u8);
    code.extend(MOV_RDX_RAX);
    shift(code, SHR_RDX, Format::Double.fraction_bits() as u8);
    code.extend(SUB_EDX_IMM32);
    code.extend(
        (Format::Double.exponent_bias() - Format::Half.exponent_bias()
            + u32::from(RESULT_MINIMUM_EXPONENT))
        .to_le_bytes(),
    );
    code.extend(CMP_EDX_IMM8);
    code.push(HALF_NORMAL_EXPONENT_COUNT);
    rollback.push(branch(code, Condition::AboveOrEqual));
    code.extend(SUB_RAX_R9);
    code.extend(MOV_RDX_RAX);
    shift(
        code,
        SHL_RDX,
        Format::Double.bits() as u8 - HALF_TO_DOUBLE_SHIFT,
    );
    code.extend(SETNE_DL);
    code.extend(MOVZX_EDX_DL);
    shift(code, SHL_EDX, INEXACT.trailing_zeros() as u8);
    code.extend(OR_R10D_EDX);
    round_half_magnitude(code, rounding);
    code.extend(MOV_EDX_EAX);
    shift(code, SHR_EDX, Format::Half.fraction_bits() as u8);
    code.extend(SUB_EDX_IMM8);
    code.push(RESULT_MINIMUM_EXPONENT);
    code.extend(CMP_EDX_IMM8);
    code.push(HALF_NORMAL_EXPONENT_COUNT);
    rollback.push(branch(code, Condition::AboveOrEqual));
    shift(code, SHL_ECX, (Format::Half.bits() - SIGN_BITS) as u8);
    code.extend(OR_EAX_ECX);
    // Transform the target-rounded bits, preserving directed-rounding order.
    match sign {
        ResultSign::Preserve => {}
        ResultSign::Negate => {
            code.push(XOR_EAX_IMM32);
            code.extend((Format::Half.sign_mask() as u32).to_le_bytes());
        }
        ResultSign::Absolute => {
            code.push(AND_EAX_IMM32);
            code.extend((Format::Half.sign_mask() as u32 - 1).to_le_bytes());
        }
    }
    code.extend(STORE_RESULT_HALF);
}

/// Every failed output guard drops private status/results and restores RSP.
/// Successful lanes return an assembled XMM0, final Half EAX and fresh IXC R10D.
pub(super) fn finish_lanes(
    code: &mut Vec<u8>,
    lanes: u8,
    loop_start: usize,
    helper: &[usize],
    rollback: &[usize],
    pc: GuestAddress,
) {
    code.extend(INC_R11D);
    code.extend(CMP_R11D);
    code.push(lanes);
    let more = branch(code, Condition::Below);
    resolve(code, more, loop_start);
    code.extend(LOAD_RESULT);
    code.extend(ADD_RSP);
    code.push(HALF_STACK_BYTES);
    let success = jump(code);
    let rollback_start = code.len();
    code.extend(ADD_RSP);
    code.push(HALF_STACK_BYTES);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let commit_start = code.len();
    for &patch in helper {
        resolve(code, patch, helper_start);
    }
    for &patch in rollback {
        resolve(code, patch, rollback_start);
    }
    resolve(code, success, commit_start);
}

/// The caller applies instruction-specific AH status policy before this store.
pub(super) fn commit_inexact(code: &mut Vec<u8>) {
    code.extend(OR_STATE_R10D);
    code.extend((std::mem::offset_of!(GuestState, fpsr) as u32).to_le_bytes());
}

/// Original Vn is XMM7. Scalar-pair callers skip NEP merging entirely.
pub(super) fn merge_scalar(code: &mut Vec<u8>) {
    test_control(code, FPCR_NEP);
    let clearing = branch(code, Condition::Zero);
    code.extend(PINSRW_XMM7_EAX);
    packed(code, Host::MoveAligned, LEFT, ORIGINAL_LEFT);
    let merged = code.len();
    resolve(code, clearing, merged);
}
