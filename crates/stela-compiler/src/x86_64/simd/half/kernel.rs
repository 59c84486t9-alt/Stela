//! Half-precision pack arithmetic, without frame or stores.
use super::{
    ADC_RAX_RDX, ADD_RAX_RDX, AND_EAX_IMM32, BT_RAX, BTR_RAX, CMP_EDX_IMM8, Condition, FPCR_AH,
    FPCR_ROUNDING_HIGH, FPCR_ROUNDING_LOW, Format, HALF_DISCARDED_MASK, HALF_NORMAL_EXPONENT_COUNT,
    HALF_TO_DOUBLE_SHIFT, INEXACT, MOV_EDX_EAX, MOV_RCX_RAX, MOV_RDX_RAX, MOVABS_RDX,
    MOVQ_RAX_XMM6, MOVZX_EDX_DL, OR_EAX_ECX, OR_R10D_EDX, RESULT_MINIMUM_EXPONENT, ResultSign,
    RoundingPolicy, SETNE_DL, SHL_ECX, SHL_EDX, SHL_RDX, SHR_EDX, SHR_RAX, SHR_RCX, SHR_RDX,
    SIGN_BITS, SUB_EDX_IMM8, SUB_EDX_IMM32, SUB_RAX_R9, TEST_ECX_ECX, XOR_EAX_IMM32, branch,
    immediate64, jump, resolve, shift, test_control,
};
use crate::x86_64::asm::Code;
use alloc::vec::Vec;

fn round_half_magnitude(code: &mut Code, rounding: RoundingPolicy) {
    // RAX holds the rebased double fields, RCX the sign.
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

pub(in crate::x86_64) fn emit_normal(
    code: &mut Code,
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
}
