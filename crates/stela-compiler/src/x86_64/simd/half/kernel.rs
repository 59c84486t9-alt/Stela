//! Half-precision pack arithmetic, without frame or stores.
use super::{
    Condition, FPCR_AH, FPCR_ROUNDING_HIGH, FPCR_ROUNDING_LOW, Format, HALF_DISCARDED_MASK,
    HALF_NORMAL_EXPONENT_COUNT, HALF_TO_DOUBLE_SHIFT, INEXACT, INEXACT_LANES, PACK_BIAS, RESULT,
    RESULT_MINIMUM_EXPONENT, ResultSign, RoundingPolicy, SIGN_BITS, branch, jump, resolve,
    test_control,
};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, ShiftOp, Size};
use crate::x86_64::simd::encode::BitTest;
use Gpr::{Rax, Rcx, Rdx};
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
    let mut asm = code.asm();
    asm.mov_imm64(Rdx, HALF_DISCARDED_MASK >> 1);
    asm.bit_imm(BitTest::Bt, Size::Qword, Rax, HALF_TO_DOUBLE_SHIFT);
    asm.alu(Alu::Adc, Size::Qword, Rax, Rdx);
    let nearest_done = jump(code);
    let high_start = code.len();
    resolve(code, high, high_start);
    test_control(code, FPCR_ROUNDING_LOW);
    let truncating = branch(code, Condition::NotZero);
    code.asm().test(Size::Dword, Rcx, Rcx);
    let negative_unmatched = branch(code, Condition::Zero);
    let negative_bias = jump(code);
    let positive_start = code.len();
    resolve(code, positive, positive_start);
    code.asm().test(Size::Dword, Rcx, Rcx);
    let positive_unmatched = branch(code, Condition::NotZero);
    let bias_start = code.len();
    resolve(code, negative_bias, bias_start);
    let mut asm = code.asm();
    asm.mov_imm64(Rdx, HALF_DISCARDED_MASK);
    asm.alu(Alu::Add, Size::Qword, Rax, Rdx);
    let end = code.len();
    for patch in [
        nearest_done,
        truncating,
        negative_unmatched,
        positive_unmatched,
    ] {
        resolve(code, patch, end);
    }
    code.asm()
        .shift_imm(ShiftOp::Shr, Size::Qword, Rax, HALF_TO_DOUBLE_SHIFT);
}

pub(in crate::x86_64) fn emit_normal(
    code: &mut Code,
    rollback: &mut Vec<usize>,
    rounding: RoundingPolicy,
    sign: ResultSign,
) {
    let sign_bit = (Format::Double.bits() - SIGN_BITS) as u8;
    let rebase = Format::Double.exponent_bias() - Format::Half.exponent_bias()
        + u32::from(RESULT_MINIMUM_EXPONENT);
    let mut asm = code.asm();
    asm.movq_from_xmm(Rax, RESULT);
    asm.mov(Size::Qword, Rcx, Rax);
    asm.shift_imm(ShiftOp::Shr, Size::Qword, Rcx, sign_bit);
    asm.bit_imm(BitTest::Btr, Size::Qword, Rax, sign_bit);
    asm.mov(Size::Qword, Rdx, Rax);
    asm.shift_imm(
        ShiftOp::Shr,
        Size::Qword,
        Rdx,
        Format::Double.fraction_bits() as u8,
    );
    asm.alu_imm32(Alu::Sub, Size::Dword, Rdx, rebase as i32);
    asm.alu_imm8(Alu::Cmp, Size::Dword, Rdx, HALF_NORMAL_EXPONENT_COUNT as i8);
    rollback.push(branch(code, Condition::AboveOrEqual));
    let mut asm = code.asm();
    asm.alu(Alu::Sub, Size::Qword, Rax, PACK_BIAS);
    asm.mov(Size::Qword, Rdx, Rax);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Qword,
        Rdx,
        Format::Double.bits() as u8 - HALF_TO_DOUBLE_SHIFT,
    );
    asm.setcc(Cond::Ne, Rdx);
    asm.movzx(Size::Dword, Rdx, Size::Byte, Rdx);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Dword,
        Rdx,
        INEXACT.trailing_zeros() as u8,
    );
    asm.alu(Alu::Or, Size::Dword, INEXACT_LANES, Rdx);
    round_half_magnitude(code, rounding);
    let mut asm = code.asm();
    asm.mov(Size::Dword, Rdx, Rax);
    asm.shift_imm(
        ShiftOp::Shr,
        Size::Dword,
        Rdx,
        Format::Half.fraction_bits() as u8,
    );
    asm.alu_imm8(Alu::Sub, Size::Dword, Rdx, RESULT_MINIMUM_EXPONENT as i8);
    asm.alu_imm8(Alu::Cmp, Size::Dword, Rdx, HALF_NORMAL_EXPONENT_COUNT as i8);
    rollback.push(branch(code, Condition::AboveOrEqual));
    let mut asm = code.asm();
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Dword,
        Rcx,
        (Format::Half.bits() - SIGN_BITS) as u8,
    );
    asm.alu(Alu::Or, Size::Dword, Rax, Rcx);
    // Transform the target-rounded bits, preserving directed-rounding order.
    let half_sign = Format::Half.sign_mask() as u32;
    match sign {
        ResultSign::Preserve => {}
        ResultSign::Negate => asm.alu_accumulator_imm32(Alu::Xor, Size::Dword, half_sign as i32),
        ResultSign::Absolute => {
            asm.alu_accumulator_imm32(Alu::And, Size::Dword, (half_sign - 1) as i32)
        }
    }
}
