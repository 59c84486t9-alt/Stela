//! Integer-only Single-to-BF16 quantization with precise exceptional fallback.
use super::super::super::isa::ShiftOpcode;
use super::super::numerical::{
    Condition, INPUT_MINIMUM_EXPONENT, IntegerRoundingRegister, branch, broadcast_integer_rounding,
    exponent_range, guard_ah0_exceptions, integer_rounding_policy, prepare_vector_input_range,
    resolve, test_control, vector_exponent_range,
};
use super::super::{Host, commit, packed, read_vector};
use crate::{
    GuestAddress, GuestState,
    aarch64::{
        floating::{FPCR_AH, FPCR_NEP, Format, INEXACT, bfloat16::BFLOAT16_TO_SINGLE_SHIFT},
        simd::{
            arithmetic::Shape,
            bfloat16::{ConversionMode, ConversionOperand},
        },
    },
    block::ExitKind,
};

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const TEMPORARY: u8 = 2;
const SIGN: u8 = 3;
const ZERO: u8 = 4;
const CONSTANT: u8 = 5;
const EAX: u8 = 0;
const SINGLE_BITS: u8 = u32::BITS as u8;
const SIGN_BITS: u8 = 1;
const SIGN_POSITION: u8 = SINGLE_BITS - SIGN_BITS;
const DISCARDED_BITS: u8 = BFLOAT16_TO_SINGLE_SHIFT as u8;
const DISCARDED_MASK: u32 = (1 << DISCARDED_BITS) - 1;
const SINGLE_EXPONENT_MASK: u32 = Format::Single.exponent_mask() as u32;
const SINGLE_EXPONENT_BITS: u8 =
    (Format::Single.bits() - Format::Single.fraction_bits() - SIGN_BITS as u32) as u8;
const EXPONENT_TO_LOW_SHIFT: u8 = SINGLE_BITS - SINGLE_EXPONENT_BITS;
const VECTOR_LANES: u32 = 4;
const VECTOR_LANE_MASK: u32 = (1 << VECTOR_LANES) - 1;
const TEST_EAX_IMM32: u8 = 0xa9;
const NOT_EAX: &[u8] = &[0xf7, 0xd0];
const AND_EAX_IMM8: &[u8] = &[0x83, 0xe0];
const MOV_R10D_EAX: &[u8] = &[0x41, 0x89, 0xc2];
const TEST_R10D_R10D: &[u8] = &[0x45, 0x85, 0xd2];
const MOVD_EAX_XMM1: &[u8] = &[0x66, 0x0f, 0x7e, 0xc8];
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
const AND_ECX_IMM32: &[u8] = &[0x81, 0xe1];
const CMP_ECX_IMM32: &[u8] = &[0x81, 0xf9];
const SHR_EAX_IMM8: &[u8] = &[0xc1, 0xe8];
const OR_STATE_IMM32: &[u8] = &[0x81, 0x8f];
const PEXTRW_EAX_XMM0_LOW: &[u8] = &[0x66, 0x0f, 0xc5, 0xc0, 0];
const MOVD_XMM0_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xc0];
const PINSRW_XMM0_EAX_LOW: &[u8] = &[0x66, 0x0f, 0xc4, 0xc0, 0];
const MOVLHPS_XMM1_XMM0: &[u8] = &[0x0f, 0x16, 0xc8];
const JMP_REL32: u8 = 0xe9;

fn input_guard(code: &mut Vec<u8>, mode: ConversionMode, helper: &mut Vec<usize>) {
    if mode == ConversionMode::Scalar {
        exponent_range(code, Format::Single, SOURCE, INPUT_MINIMUM_EXPONENT);
        helper.push(branch(code, Condition::AboveOrEqual));
    } else {
        prepare_vector_input_range(code, Format::Single);
        vector_exponent_range(code, Format::Single, Shape::Vector128, SOURCE);
        helper.push(branch(code, Condition::NotZero));
    }
}

/// Quantize one active Single without packed broadcasts or inactive lane work.
/// Shared selectors remain in R8D/R9D/R11D; R10D records only discarded bits.
fn quantize_scalar(code: &mut Vec<u8>, helper: &mut Vec<usize>) {
    packed(code, Host::Xor, RESULT, RESULT);
    code.extend(MOVD_EAX_XMM1);
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
    // Rounded infinity takes the same precise cold OFC/IXC path as narrowing.
    code.extend(MOV_ECX_EAX);
    code.extend(AND_ECX_IMM32);
    code.extend(SINGLE_EXPONENT_MASK.to_le_bytes());
    code.extend(CMP_ECX_IMM32);
    code.extend(SINGLE_EXPONENT_MASK.to_le_bytes());
    helper.push(branch(code, Condition::Zero));
    code.extend(SHR_EAX_IMM8);
    code.push(DISCARDED_BITS);
    code.extend(PINSRW_XMM0_EAX_LOW);
}

/// Record all four lanes' discarded bits in private R10D, then add their bias.
fn quantize_packed(code: &mut Vec<u8>) {
    packed(code, Host::MoveAligned, RESULT, SOURCE);
    packed(code, Host::MoveAligned, TEMPORARY, SOURCE);
    ShiftOpcode::LeftDword.emit(code, TEMPORARY, SINGLE_BITS - DISCARDED_BITS);
    packed(code, Host::Xor, ZERO, ZERO);
    packed(code, Host::EqualDword, TEMPORARY, ZERO);
    packed(code, Host::DwordSignMask, EAX, TEMPORARY);
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

/// Rounding can carry a finite Single into BF16 infinity. The cold core owns
/// its OFC/IXC policy; no guest state has changed at this guard.
fn packed_overflow_guard(code: &mut Vec<u8>, helper: &mut Vec<usize>) {
    packed(code, Host::MoveAligned, TEMPORARY, RESULT);
    ShiftOpcode::LeftDword.emit(code, TEMPORARY, SIGN_BITS);
    ShiftOpcode::RightDword.emit(code, TEMPORARY, EXPONENT_TO_LOW_SHIFT);
    packed(code, Host::EqualDword, CONSTANT, CONSTANT);
    ShiftOpcode::RightDword.emit(code, CONSTANT, EXPONENT_TO_LOW_SHIFT);
    packed(code, Host::EqualDword, TEMPORARY, CONSTANT);
    packed(code, Host::DwordSignMask, EAX, TEMPORARY);
    code.push(TEST_EAX_IMM32);
    code.extend(VECTOR_LANE_MASK.to_le_bytes());
    helper.push(branch(code, Condition::NotZero));
}

fn helper_section(code: &mut Vec<u8>, helper: &[usize], pc: GuestAddress) {
    code.push(JMP_REL32);
    let completed = code.len();
    code.extend(0i32.to_le_bytes());
    let helper_start = code.len();
    super::super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success = code.len();
    for &patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, completed, success);
}

fn commit_inexact(code: &mut Vec<u8>) {
    test_control(code, FPCR_AH);
    let suppressed = branch(code, Condition::NotZero);
    code.extend(TEST_R10D_R10D);
    let exact = branch(code, Condition::Zero);
    code.extend(OR_STATE_IMM32);
    code.extend((std::mem::offset_of!(GuestState, fpsr) as u32).to_le_bytes());
    code.extend(INEXACT.to_le_bytes());
    let ready = code.len();
    resolve(code, exact, ready);
    resolve(code, suppressed, ready);
}

fn scalar_commit(code: &mut Vec<u8>, destination: u8) {
    // PEXTRW zero-extends the low BF16 encoding before MOVD clears all upper bits.
    code.extend(PEXTRW_EAX_XMM0_LOW);
    code.extend(MOVD_XMM0_EAX);
    test_control(code, FPCR_NEP);
    let clearing = branch(code, Condition::Zero);
    read_vector(code, destination, RESULT);
    code.extend(PINSRW_XMM0_EAX_LOW);
    let ready = code.len();
    resolve(code, clearing, ready);
    commit(code, destination, RESULT);
}

pub(in crate::x86_64) fn emit(code: &mut Vec<u8>, operand: &ConversionOperand, pc: GuestAddress) {
    let mut helper = Vec::new();
    guard_ah0_exceptions(code, &mut helper);
    read_vector(code, operand.source, SOURCE);
    input_guard(code, operand.mode, &mut helper);
    integer_rounding_policy(code, DISCARDED_BITS, true);
    if operand.mode == ConversionMode::Scalar {
        quantize_scalar(code, &mut helper);
    } else {
        quantize_packed(code);
        packed_overflow_guard(code, &mut helper);
        // Arithmetic shift sign-extends each raw BF16 field before PACKSSDW.
        // Logical shift would saturate negative BF16 encodings to positive 0x7fff.
        ShiftOpcode::ArithmeticDword.emit(code, RESULT, DISCARDED_BITS);
        packed(code, Host::PackSignedDwordToWord, RESULT, RESULT);
    }
    helper_section(code, &helper, pc);
    commit_inexact(code);
    match operand.mode {
        ConversionMode::Scalar => scalar_commit(code, operand.destination),
        ConversionMode::Narrow { upper: false } => {
            packed(code, Host::MoveQword, RESULT, RESULT);
            commit(code, operand.destination, RESULT);
        }
        ConversionMode::Narrow { upper: true } => {
            // Original Vd is still available, including when Vd aliases Vn.
            read_vector(code, operand.destination, SOURCE);
            code.extend(MOVLHPS_XMM1_XMM0);
            commit(code, operand.destination, SOURCE);
        }
    }
}
