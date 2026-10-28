//! SVE conversions between half precision and integers.
use crate::x86_64::asm::Code;

use super::half_widening::{guard_normal_half_fields, normal_half_to_single_fields};
use crate::{
    TargetCpu,
    aarch64::floating::{
        Format,
        integer::{IntegerFormat, IntegerWidth},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        simd::half,
    },
};
use alloc::vec::Vec;

const INPUT: u8 = 0;
const ZERO_LANES: u8 = 1;
const MAXIMUM_EXPONENT: u8 = 2;
const SINGLE_BIAS: u8 = 3;
const HALF_ONE: u8 = 4;
const GUARD_SCRATCH: [u8; 3] = [5, 6, 7];
const SIGN: u8 = GUARD_SCRATCH[0];
const SCRATCH: u8 = GUARD_SCRATCH[1];
const REJECTIONS: u8 = GUARD_SCRATCH[2];
const INTEGER_FLOAT: u8 = 6;
const EAX: u8 = 0;
const RCX: u8 = 1;
const REPEAT_LOW_DWORD: u8 = 0;
const REGISTER_DIRECT: u8 = 0xc0;
const REGISTER_SHIFT: u8 = 3;
const HALF_BITS: u8 = u16::BITS as u8;
const HALF_MAGNITUDE_TO_TOP: u8 = u32::BITS as u8 - HALF_BITS + 1;
const DWORD_SIGN_BIT: u8 = u32::BITS as u8 - 1;
const QWORD_SIGN_BIT: u8 = u64::BITS as u8 - 1;
const HALF_EXPONENT_MAX: u32 =
    (Format::Half.exponent_mask() >> Format::Half.fraction_bits()) as u32;
const HALF_ONE_BITS: u32 = Format::Half.exponent_bias() << Format::Half.fraction_bits();
const HALF_TO_SINGLE_BIAS: u32 = (Format::Single.exponent_bias() - Format::Half.exponent_bias())
    << Format::Single.fraction_bits();
const SIGNED_HALF_LIMIT_BITS: u32 =
    (Format::Half.exponent_bias() + u16::BITS - 1) << Format::Half.fraction_bits();
const MAXIMUM_FINITE_HALF_INTEGER: u32 = 65_504;
pub(super) const USE_MXCSR_ROUNDING: u8 = 1 << 2;
const MOV_ECX_IMMEDIATE: &[u8] = &[0xb9];
const CVTTPS2DQ: &[u8] = &[0xf3, 0x0f, 0x5b];
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];
const JA_REL32: &[u8] = &[0x0f, 0x87];
const MOVSX_RAX_AX: &[u8] = &[0x48, 0x0f, 0xbf, 0xc0];
const MOVSXD_RAX_EAX: &[u8] = &[0x48, 0x63, 0xc0];
const MOVZX_EAX_AX: &[u8] = &[0x0f, 0xb7, 0xc0];
const MOV_EAX_EAX: &[u8] = &[0x89, 0xc0];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const SAR_RDX_IMMEDIATE: &[u8] = &[0x48, 0xc1, 0xfa];
const XOR_RAX_RDX: &[u8] = &[0x48, 0x31, 0xd0];
const SUB_RAX_RDX: &[u8] = &[0x48, 0x29, 0xd0];
const XOR_EDX_EDX: &[u8] = &[0x31, 0xd2];
const CMP_RAX_IMMEDIATE: &[u8] = &[0x48, 0x3d];
const CVTSI2SD_XMM6_RAX: &[u8] = &[0xf2, 0x48, 0x0f, 0x2a, 0xf0];
const CVTSI2SS_XMM6_RAX: &[u8] = &[0xf3, 0x48, 0x0f, 0x2a, 0xf0];
const MOVQ_RCX_XMM6: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xf1];
const MOVD_ECX_XMM6: &[u8] = &[0x66, 0x0f, 0x7e, 0xf1];
const SHL_RDX_IMMEDIATE: &[u8] = &[0x48, 0xc1, 0xe2];
const SHL_EDX_IMMEDIATE: &[u8] = &[0xc1, 0xe2];
const OR_RCX_RDX: &[u8] = &[0x48, 0x09, 0xd1];
const OR_ECX_EDX: &[u8] = &[0x09, 0xd1];
const MOVQ_XMM6_RCX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e, 0xf1];
const MOVD_XMM6_ECX: &[u8] = &[0x66, 0x0f, 0x6e, 0xf1];
const MOVD_EAX_XMM0: &[u8] = &[0x66, 0x0f, 0x7e, 0xc0];
const AND_EAX_IMMEDIATE: &[u8] = &[0x25];

fn broadcast(code: &mut Code, register: u8, value: u32, target: TargetCpu) {
    code.extend(MOV_ECX_IMMEDIATE);
    code.extend(value.to_le_bytes());
    Host::MoveGprQword.append(code, target);
    code.push(REGISTER_DIRECT | (register << REGISTER_SHIFT) | RCX);
    Host::ShuffleDword.register(code, register, register, target);
    code.push(REPEAT_LOW_DWORD);
}

fn failure(code: &mut Code, opcode: &[u8], failures: &mut Vec<usize>) {
    code.extend(opcode);
    failures.push(code.len());
    code.extend(0_i32.to_le_bytes());
}

fn reject_mask(code: &mut Code, mask: u8, failures: &mut Vec<usize>, target: TargetCpu) {
    Host::ByteSignMask.register(code, EAX, mask, target);
    code.extend(TEST_EAX_EAX);
    failure(code, JNZ_REL32, failures);
}

/// Prepare invariant normal-Half guard, field projection and neutral input.
/// Preserved by to_integer_words; caller may hoist once per guest instruction.
pub(crate) fn prepare_to_integer(code: &mut Code, target: TargetCpu) {
    broadcast(code, MAXIMUM_EXPONENT, HALF_EXPONENT_MAX, target);
    broadcast(code, SINGLE_BIAS, HALF_TO_SINGLE_BIAS, target);
    broadcast(code, HALF_ONE, HALF_ONE_BITS, target);
}

fn signed_half_range(code: &mut Code, failures: &mut Vec<usize>, target: TargetCpu) {
    Host::MoveAligned.register(code, SIGN, INPUT, target);
    ShiftOpcode::LeftDword.emit(code, SIGN, HALF_MAGNITUDE_TO_TOP);
    ShiftOpcode::RightDword.emit(code, SIGN, HALF_MAGNITUDE_TO_TOP);
    broadcast(code, SCRATCH, SIGNED_HALF_LIMIT_BITS, target);
    Host::MoveAligned.register(code, REJECTIONS, SIGN, target);
    Host::GreaterDword.register(code, REJECTIONS, SCRATCH, target);
    Host::EqualDword.register(code, SIGN, SCRATCH, target);
    Host::MoveAligned.register(code, SCRATCH, INPUT, target);
    ShiftOpcode::LeftDword.emit(code, SCRATCH, HALF_BITS);
    ShiftOpcode::ArithmeticDword.emit(code, SCRATCH, DWORD_SIGN_BIT);
    Host::AndNot.register(code, SCRATCH, SIGN, target); // +32768 rejects; -32768 accepts.
    Host::Or.register(code, REJECTIONS, SCRATCH, target);
    reject_mask(code, REJECTIONS, failures, target);
}

/// Convert four half-precision values in the low 16 bits of each dword into
/// four dword integers in XMM0. The caller zeroes inactive lanes first. Normal
/// and zero signed inputs fit W/X, with an exact range guard for signed half;
/// unsigned conversion of a negative nonzero input (even one that would give 0)
/// takes the fallback. Keeps XMM2-4; clobbers XMM0/1/5-7, EAX/ECX and flags.
/// The caller checks for F16C first. Host PE is the only status accepted,
/// mapped to guest inexact by the caller.
pub(crate) fn to_integer_words(
    code: &mut Code,
    destination: IntegerFormat,
    f16c: bool,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    Host::MoveAligned.register(code, ZERO_LANES, INPUT, target);
    ShiftOpcode::LeftDword.emit(code, ZERO_LANES, HALF_MAGNITUDE_TO_TOP);
    Host::Xor.register(code, SIGN, SIGN, target);
    Host::EqualDword.register(code, ZERO_LANES, SIGN, target);
    Host::MoveAligned.register(code, SIGN, ZERO_LANES, target);
    Host::And.register(code, SIGN, HALF_ONE, target);
    Host::Or.register(code, INPUT, SIGN, target);
    guard_normal_half_fields(
        code,
        INPUT,
        MAXIMUM_EXPONENT,
        GUARD_SCRATCH,
        failures,
        target,
    );
    if !destination.signed {
        Host::MoveAligned.register(code, SIGN, INPUT, target);
        ShiftOpcode::LeftDword.emit(code, SIGN, HALF_BITS);
        ShiftOpcode::ArithmeticDword.emit(code, SIGN, DWORD_SIGN_BIT);
        Host::MoveAligned.register(code, SCRATCH, ZERO_LANES, target);
        Host::AndNot.register(code, SCRATCH, SIGN, target);
        reject_mask(code, SCRATCH, failures, target);
    } else if destination.width == IntegerWidth::Bits16 {
        signed_half_range(code, failures, target);
    }
    if f16c {
        ShiftOpcode::LeftDword.emit(code, INPUT, HALF_BITS);
        ShiftOpcode::ArithmeticDword.emit(code, INPUT, HALF_BITS);
        Host::PackSignedDwordToWord.register(code, INPUT, INPUT, target);
        Host::ConvertHalfToSingle.register(code, INPUT, INPUT, target);
    } else {
        normal_half_to_single_fields(code, INPUT, SIGN, SINGLE_BIAS, target);
    }
    // Field widening intentionally biases raw zero. Correct both active zero
    // and sanitized inactive zero before host conversion, preventing false IXC.
    Host::AndNot.register(code, ZERO_LANES, INPUT, target);
    Host::MoveAligned.register(code, INPUT, ZERO_LANES, target);
    code.extend(CVTTPS2DQ);
    code.push(REGISTER_DIRECT | (INPUT << REGISTER_SHIFT) | INPUT);
}

fn normalize_integer(code: &mut Code, source: IntegerFormat) {
    code.extend(match (source.width, source.signed) {
        (IntegerWidth::Bits16, true) => MOVSX_RAX_AX,
        (IntegerWidth::Bits16, false) => MOVZX_EAX_AX,
        (IntegerWidth::Bits32, true) => MOVSXD_RAX_EAX,
        (IntegerWidth::Bits32, false) => MOV_EAX_EAX,
        (IntegerWidth::Bits64, _) => &[],
    });
}

/// Convert one small signed/unsigned integer in RAX to raw IEEE Half in EAX.
/// Guard |n|<=65504 before host conversion: every admitted integer is exactly
/// representable in Single/Double and stays finite under every Half direction.
/// Integer fields OR approved IXC into caller-cleared R10D; selected F16C leaves
/// R10D alone and reports host PE. The caller checks usable F16C before entry.
/// Integer fields read guest RMode through RDI; both paths require private controls.
/// Caller losslessly packs EAX and stages manual R10D IXC after every lane guard.
/// No frame/store/commit/exit; host PE remains a separate pending channel.
/// Clobbers XMM0/6, RAX/RCX/RDX/R9/R10 and flags; preserves other registers.
pub(crate) fn from_integer_lane(
    code: &mut Code,
    source: IntegerFormat,
    f16c: bool,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    normalize_integer(code, source);
    if source.signed {
        code.extend(MOV_RDX_RAX);
        code.extend(SAR_RDX_IMMEDIATE);
        code.push(QWORD_SIGN_BIT);
        code.extend(XOR_RAX_RDX);
        code.extend(SUB_RAX_RDX);
    } else {
        code.extend(XOR_EDX_EDX);
    }
    code.extend(CMP_RAX_IMMEDIATE);
    code.extend(MAXIMUM_FINITE_HALF_INTEGER.to_le_bytes());
    failure(code, JA_REL32, failures);
    Host::Xor.register(code, INTEGER_FLOAT, INTEGER_FLOAT, target);
    if f16c {
        code.extend(CVTSI2SS_XMM6_RAX);
        code.extend(MOVD_ECX_XMM6);
        code.extend(SHL_EDX_IMMEDIATE);
        code.push(DWORD_SIGN_BIT);
        code.extend(OR_ECX_EDX);
        code.extend(MOVD_XMM6_ECX);
        // VCVTPS2PH source is ModRM.reg; destination is ModRM.r/m.
        Host::ConvertSingleToHalf.register(code, INTEGER_FLOAT, INPUT, target);
        code.push(USE_MXCSR_ROUNDING);
        code.extend(MOVD_EAX_XMM0);
        code.extend(AND_EAX_IMMEDIATE);
        code.extend(u32::from(u16::MAX).to_le_bytes());
    } else {
        code.extend(CVTSI2SD_XMM6_RAX);
        code.extend(MOVQ_RCX_XMM6);
        code.extend(SHL_RDX_IMMEDIATE);
        code.push(QWORD_SIGN_BIT);
        code.extend(OR_RCX_RDX);
        code.extend(MOVQ_XMM6_RCX);
        half::emit_normal_or_zero(code, failures);
    }
}
