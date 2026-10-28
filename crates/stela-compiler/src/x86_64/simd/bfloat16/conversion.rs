//! BFCVT/BFCVTN by integer rounding, with a software path for special values.
use super::super::super::isa::ShiftOpcode;
use super::super::numerical::helper_section;
use super::super::numerical::{
    Condition, INPUT_MINIMUM_EXPONENT, branch, exponent_range, guard_ah0_exceptions,
    integer_rounding_policy, prepare_vector_input_range, quantize_bfloat_packed,
    quantize_bfloat_scalar_bits, resolve, test_control, vector_exponent_range,
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
};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const TEMPORARY: u8 = 2;
const CONSTANT: u8 = 5;
const GPR_RAX: u8 = 0;
const SINGLE_BITS: u8 = u32::BITS as u8;
const SIGN_BITS: u8 = 1;
const DISCARDED_BITS: u8 = BFLOAT16_TO_SINGLE_SHIFT as u8;
const SINGLE_EXPONENT_MASK: u32 = Format::Single.exponent_mask() as u32;
const SINGLE_EXPONENT_BITS: u8 =
    (Format::Single.bits() - Format::Single.fraction_bits() - SIGN_BITS as u32) as u8;
const EXPONENT_TO_LOW_SHIFT: u8 = SINGLE_BITS - SINGLE_EXPONENT_BITS;
const VECTOR_LANES: u32 = 4;
const VECTOR_LANE_MASK: u32 = (1 << VECTOR_LANES) - 1;
const TEST_EAX_IMM32: u8 = 0xa9;
const TEST_R10D_R10D: &[u8] = &[0x45, 0x85, 0xd2];
const MOVD_EAX_XMM1: &[u8] = &[0x66, 0x0f, 0x7e, 0xc8];
const MOV_ECX_EAX: &[u8] = &[0x89, 0xc1];
const AND_ECX_IMM32: &[u8] = &[0x81, 0xe1];
const CMP_ECX_IMM32: &[u8] = &[0x81, 0xf9];
const SHR_EAX_IMM8: &[u8] = &[0xc1, 0xe8];
const OR_STATE_IMM32: &[u8] = &[0x81, 0x8f];
const PEXTRW_EAX_XMM0_LOW: &[u8] = &[0x66, 0x0f, 0xc5, 0xc0, 0];
const MOVD_XMM0_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xc0];
const PINSRW_XMM0_EAX_LOW: &[u8] = &[0x66, 0x0f, 0xc4, 0xc0, 0];
const MOVLHPS_XMM1_XMM0: &[u8] = &[0x0f, 0x16, 0xc8];

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
    quantize_bfloat_scalar_bits(code);
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

/// Rounding can carry a finite Single into BF16 infinity. The cold core owns
/// its OFC/IXC policy; no guest state has changed at this guard.
fn packed_overflow_guard(code: &mut Vec<u8>, helper: &mut Vec<usize>) {
    packed(code, Host::MoveAligned, TEMPORARY, RESULT);
    ShiftOpcode::LeftDword.emit(code, TEMPORARY, SIGN_BITS);
    ShiftOpcode::RightDword.emit(code, TEMPORARY, EXPONENT_TO_LOW_SHIFT);
    packed(code, Host::EqualDword, CONSTANT, CONSTANT);
    ShiftOpcode::RightDword.emit(code, CONSTANT, EXPONENT_TO_LOW_SHIFT);
    packed(code, Host::EqualDword, TEMPORARY, CONSTANT);
    packed(code, Host::DwordSignMask, GPR_RAX, TEMPORARY);
    code.push(TEST_EAX_IMM32);
    code.extend(VECTOR_LANE_MASK.to_le_bytes());
    helper.push(branch(code, Condition::NotZero));
}

fn commit_inexact(code: &mut Vec<u8>) {
    test_control(code, FPCR_AH);
    let suppressed = branch(code, Condition::NotZero);
    code.extend(TEST_R10D_R10D);
    let exact = branch(code, Condition::Zero);
    code.extend(OR_STATE_IMM32);
    code.extend((core::mem::offset_of!(GuestState, fpsr) as u32).to_le_bytes());
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
        quantize_bfloat_packed(code);
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

/// Prepare selectors once; preserves every XMM and RSP. R8/R9/R11 retain
/// rounding selectors and R10 starts fresh. AH selects mandatory nearest-even.
pub(in crate::x86_64) fn prepare_conversion_rounding(code: &mut Vec<u8>) {
    integer_rounding_policy(code, DISCARDED_BITS, true);
}

/// Integer-only packed normal-Single guard and BF16 rounding. Source XMM1
/// survives; result XMM0 retains rounded Single fields, XMM2..5 are scratch.
/// R8/R9/R11 selectors survive; R10 records discarded lanes. RAX/RCX/RDX and
/// flags are scratch. No frame, environment, state writes, or packed slot layout.
pub(in crate::x86_64) fn quantize_normal_conversion(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    input_guard(code, ConversionMode::Narrow { upper: false }, failures);
    quantize_bfloat_packed(code);
    packed_overflow_guard(code, failures);
}

/// Callers gate this on any active lane and the effective FA64 policy.
pub(in crate::x86_64) fn guard_conversion_enables(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    guard_ah0_exceptions(code, failures);
}

/// Return approved fresh BF IXC in EAX without committing guest state. AH1
/// suppresses all numerical exceptions; accepted normal lanes can only add IXC.
pub(in crate::x86_64) fn conversion_inexact(code: &mut Vec<u8>) {
    const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
    const MOV_EAX_IMM32: u8 = 0xb8;
    code.extend(XOR_EAX_EAX);
    test_control(code, FPCR_AH);
    let suppressed = branch(code, Condition::NotZero);
    code.extend(TEST_R10D_R10D);
    let exact = branch(code, Condition::Zero);
    code.push(MOV_EAX_IMM32);
    code.extend(INEXACT.to_le_bytes());
    let end = code.len();
    resolve(code, exact, end);
    resolve(code, suppressed, end);
}
