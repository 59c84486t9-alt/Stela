//! Integer rounding of single values to BF16.
use super::super::super::isa::ShiftOpcode;
use super::super::{Host, packed};
use super::quantization::{IntegerRoundingRegister, broadcast_integer_rounding};
use crate::aarch64::floating::bfloat16::BFLOAT16_TO_SINGLE_SHIFT;
use crate::x86_64::asm::Code;

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
const NOT_EAX: &[u8] = &[0xf7, 0xd0];
const AND_EAX_IMM8: &[u8] = &[0x83, 0xe0];
const MOV_R10D_EAX: &[u8] = &[0x41, 0x89, 0xc2];
const MOV_EDX_EAX: &[u8] = &[0x89, 0xc2];
const AND_EDX_IMM32: &[u8] = &[0x81, 0xe2];
const OR_R10D_EDX: &[u8] = &[0x41, 0x09, 0xd2];
const SHR_EDX_IMM8: &[u8] = &[0xc1, 0xea];
const AND_EDX_R11D: &[u8] = &[0x44, 0x21, 0xda];
const MOV_ECX_EAX: &[u8] = &[0x89, 0xc1];
const SAR_ECX_IMM8: &[u8] = &[0xc1, 0xf9];
const AND_ECX_R9D: &[u8] = &[0x44, 0x21, 0xc9];
const XOR_ECX_R8D: &[u8] = &[0x44, 0x31, 0xc1];
const ADD_ECX_EDX: &[u8] = &[0x01, 0xd1];
const ADD_EAX_ECX: &[u8] = &[0x01, 0xc8];

/// Record four lanes' discarded bits in R10D and apply shared selectors.
/// XMM0 is output, XMM1 input, XMM2..5 scratch; XMM6/7 and R8/9/11 survive.
pub(in crate::x86_64) fn quantize_bfloat_packed(code: &mut Code) {
    packed(code, Host::MoveAligned, RESULT, SOURCE);
    packed(code, Host::MoveAligned, TEMPORARY, SOURCE);
    ShiftOpcode::LeftDword.emit(code, TEMPORARY, SINGLE_BITS - DISCARDED_BITS);
    packed(code, Host::Xor, ZERO, ZERO);
    packed(code, Host::EqualDword, TEMPORARY, ZERO);
    packed(code, Host::DwordSignMask, GPR_RAX, TEMPORARY);
    code.extend(NOT_EAX);
    code.extend(AND_EAX_IMM8);
    code.push(VECTOR_LANE_MASK as u8);
    code.extend(MOV_R10D_EAX);

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
    code.extend(MOV_EDX_EAX);
    code.extend(AND_EDX_IMM32);
    code.extend(DISCARDED_MASK.to_le_bytes());
    code.extend(OR_R10D_EDX);
    code.extend(MOV_EDX_EAX);
    code.extend(SHR_EDX_IMM8);
    code.push(DISCARDED_BITS);
    code.extend(AND_EDX_R11D);
    code.extend(MOV_ECX_EAX);
    code.extend(SAR_ECX_IMM8);
    code.push(SIGN_POSITION);
    code.extend(AND_ECX_R9D);
    code.extend(XOR_ECX_R8D);
    code.extend(ADD_ECX_EDX);
    code.extend(ADD_EAX_ECX);
}
