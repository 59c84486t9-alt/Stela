//! Integer rounding of single values to BF16.
use super::super::super::isa::ShiftOpcode;
use super::super::{Host, packed};
use super::quantization::{IntegerRoundingRegister, broadcast_integer_rounding};
use crate::aarch64::floating::bfloat16::BFLOAT16_TO_SINGLE_SHIFT;
use crate::x86_64::asm::{Alu, Code, Gpr, ShiftOp, Size, Unary};

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const TEMPORARY: u8 = 2;
const SIGN: u8 = 3;
const ZERO: u8 = 4;
const CONSTANT: u8 = 5;
const GPR_RAX: u8 = 0;
const SINGLE_BITS: u8 = u32::BITS as u8;
const SIGN_BITS: u8 = 1;
const SIGN_POSITION: u8 = SINGLE_BITS - SIGN_BITS;
const DISCARDED_BITS: u8 = BFLOAT16_TO_SINGLE_SHIFT as u8;
const DISCARDED_MASK: u32 = (1 << DISCARDED_BITS) - 1;
const VECTOR_LANES: u32 = 4;
const VECTOR_LANE_MASK: u32 = (1 << VECTOR_LANES) - 1;

/// Record four lanes' discarded bits in R10D and apply shared selectors.
/// XMM0 is output, XMM1 input, XMM2..5 scratch; XMM6/7 and R8/9/11 survive.
pub(in crate::x86_64) fn quantize_bfloat_packed(code: &mut Code) {
    packed(code, Host::MoveAligned, RESULT, SOURCE);
    packed(code, Host::MoveAligned, TEMPORARY, SOURCE);
    ShiftOpcode::LeftDword.emit(code, TEMPORARY, SINGLE_BITS - DISCARDED_BITS);
    packed(code, Host::Xor, ZERO, ZERO);
    packed(code, Host::EqualDword, TEMPORARY, ZERO);
    packed(code, Host::DwordSignMask, GPR_RAX, TEMPORARY);
    let mut asm = code.asm();
    asm.unary(Unary::Not, Size::Dword, Gpr::Rax);
    asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rax, VECTOR_LANE_MASK as i8);
    asm.mov(Size::Dword, Gpr::R10, Gpr::Rax);

    packed(code, Host::MoveAligned, SIGN, SOURCE);
    ShiftOpcode::ArithmeticDword.emit(code, SIGN, SIGN_POSITION);
    packed(code, Host::MoveAligned, TEMPORARY, SOURCE);
    ShiftOpcode::RightDword.emit(code, TEMPORARY, DISCARDED_BITS);
    broadcast_integer_rounding(code, ZERO, IntegerRoundingRegister::Parity);
    packed(code, Host::And, TEMPORARY, ZERO);
    broadcast_integer_rounding(code, ZERO, IntegerRoundingRegister::Direction);
    packed(code, Host::And, ZERO, SIGN);
    broadcast_integer_rounding(code, CONSTANT, IntegerRoundingRegister::Bias);
    packed(code, Host::Xor, ZERO, CONSTANT);
    packed(code, Host::AddDword, TEMPORARY, ZERO);
    packed(code, Host::AddDword, RESULT, TEMPORARY);
}

/// Round the single-precision bits in EAX to BF16, ORing the discarded bits
/// into R10D. ECX/EDX are scratch; XMM registers, state, stack and MXCSR are
/// untouched.
pub(in crate::x86_64) fn quantize_bfloat_scalar_bits(code: &mut Code) {
    use Gpr::{R8, R9, R10, R11, Rax, Rcx, Rdx};
    use Size::Dword;
    let mut asm = code.asm();
    asm.mov(Dword, Rdx, Rax);
    asm.alu_imm32(Alu::And, Dword, Rdx, DISCARDED_MASK as i32);
    asm.alu(Alu::Or, Dword, R10, Rdx);
    asm.mov(Dword, Rdx, Rax);
    asm.shift_imm(ShiftOp::Shr, Dword, Rdx, DISCARDED_BITS);
    asm.alu(Alu::And, Dword, Rdx, R11);
    asm.mov(Dword, Rcx, Rax);
    asm.shift_imm(ShiftOp::Sar, Dword, Rcx, SIGN_POSITION);
    asm.alu(Alu::And, Dword, Rcx, R9);
    asm.alu(Alu::Xor, Dword, Rcx, R8);
    asm.alu(Alu::Add, Dword, Rcx, Rdx);
    asm.alu(Alu::Add, Dword, Rax, Rcx);
}
