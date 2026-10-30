//! Rounding selectors shared by the half and BF16 conversions.
use super::super::shuffle;
use super::{Condition, branch, jump, resolve, state};
use crate::GuestState;
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, ShiftOp, Size, Unary};

const ROUND_TOWARD_POSITIVE: u8 = 1;
const REPLICATE_FIRST_DWORD: u8 = 0;

/// The caller-volatile extended rounding registers.
#[repr(u8)]
pub(in crate::x86_64) enum IntegerRoundingRegister {
    Bias = 0,      // R8D
    Direction = 1, // R9D
    Parity = 3,    // R11D
}

impl IntegerRoundingRegister {
    const fn register(self) -> Gpr {
        match self {
            Self::Bias => Gpr::R8,
            Self::Direction => Gpr::R9,
            Self::Parity => Gpr::R11,
        }
    }
}

pub(in crate::x86_64) fn broadcast_integer_rounding(
    code: &mut Code,
    vector: u8,
    register: IntegerRoundingRegister,
) {
    code.asm().movd_to_xmm(vector, register.register());
    shuffle(code, vector, vector, REPLICATE_FIRST_DWORD);
}

/// Prepare integer quantization bias, sign direction and kept-bit parity.
/// R10D starts fresh exception accumulation; ordinary arithmetic keeps guest RC,
/// while BF16 conversion selects nearest-even when alternative handling is set.
pub(in crate::x86_64) fn integer_rounding_policy(
    code: &mut Code,
    discarded_bits: u8,
    alternative_nearest: bool,
) {
    use crate::aarch64::floating::{FPCR_AH, FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT};
    use Gpr::{R8, R9, R10, R11, Rax, Rcx, Rdx};
    use Size::Dword;
    assert!(discarded_bits > 0 && u32::from(discarded_bits) < u32::BITS);
    let discarded_mask = (1u32 << discarded_bits) - 1;
    let nearest_bias = discarded_mask >> 1;
    code.asm()
        .mov_load(Dword, Rcx, state(core::mem::offset_of!(GuestState, fpcr)));
    if alternative_nearest {
        code.asm().test_imm(Dword, Rcx, FPCR_AH as i32);
        let ordinary = branch(code, Condition::Zero);
        code.asm().alu_imm32(
            Alu::And,
            Dword,
            Rcx,
            !(FPCR_ROUNDING_MASK << FPCR_ROUNDING_SHIFT) as i32,
        );
        let ready = code.len();
        resolve(code, ordinary, ready);
    }
    let mut asm = code.asm();
    asm.shift_imm(ShiftOp::Shr, Dword, Rcx, FPCR_ROUNDING_SHIFT as u8);
    asm.alu_imm8(Alu::And, Dword, Rcx, FPCR_ROUNDING_MASK as i8);
    asm.test(Dword, Rcx, Rcx);
    asm.setcc(Cond::E, Rax);
    asm.movzx(Dword, Rax, Size::Byte, Rax);
    asm.mov_load(Dword, R11, Rax);
    // -(((mode+1)>>1)&1) selects both directed modes, independent of sign.
    asm.lea(Dword, Rdx, crate::x86_64::asm::Mem::base(Rcx, 1));
    asm.shift_one(ShiftOp::Shr, Dword, Rdx);
    asm.alu_imm8(Alu::And, Dword, Rdx, 1);
    asm.unary(Unary::Neg, Dword, Rdx);
    asm.alu_imm32(Alu::And, Dword, Rdx, discarded_mask as i32);
    asm.mov(Dword, R9, Rdx);
    asm.alu(Alu::Xor, Dword, R8, R8);
    asm.test(Dword, Rcx, Rcx);
    let not_nearest = branch(code, Condition::NotZero);
    code.asm().mov_imm32(R8, nearest_bias);
    let nearest = jump(code);
    let directed = code.len();
    resolve(code, not_nearest, directed);
    code.asm()
        .alu_imm8(Alu::Cmp, Dword, Rcx, ROUND_TOWARD_POSITIVE as i8);
    let not_positive = branch(code, Condition::NotZero);
    code.asm().mov_imm32(R8, discarded_mask);
    let ready = code.len();
    resolve(code, not_positive, ready);
    resolve(code, nearest, ready);
    code.asm().alu(Alu::Xor, Dword, R10, R10);
}
