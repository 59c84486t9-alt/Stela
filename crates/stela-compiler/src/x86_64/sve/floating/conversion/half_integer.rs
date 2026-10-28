//! SVE conversions between half precision and integers.
use crate::x86_64::asm::Gpr::{Rax, Rcx, Rdx};
use crate::x86_64::asm::{Alu, Code, Cond, Rm, ShiftOp, Size};

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
const REPEAT_LOW_DWORD: u8 = 0;
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

fn broadcast(code: &mut Code, register: u8, value: u32, target: TargetCpu) {
    let mut asm = code.asm();
    asm.mov_imm32(Rcx, value);
    asm.simd(Host::MoveGprQword, register, Rcx, target);
    asm.simd_imm(
        Host::ShuffleDword,
        register,
        Rm::Xmm(register),
        REPEAT_LOW_DWORD,
        target,
    );
}

fn failure(code: &mut Code, condition: Cond, failures: &mut Vec<usize>) {
    failures.push(code.asm().jcc(condition).offset());
}

fn reject_mask(code: &mut Code, mask: u8, failures: &mut Vec<usize>, target: TargetCpu) {
    let mut asm = code.asm();
    asm.simd_to_gpr(Host::ByteSignMask, Rax, mask, target);
    asm.test(Size::Dword, Rax, Rax);
    failure(code, Cond::Ne, failures);
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
    code.asm().cvttps2dq(INPUT, Rm::Xmm(INPUT));
}

fn normalize_integer(code: &mut Code, source: IntegerFormat) {
    let mut asm = code.asm();
    match (source.width, source.signed) {
        (IntegerWidth::Bits16, true) => asm.movsx(Size::Qword, Rax, Size::Word, Rax),
        (IntegerWidth::Bits16, false) => asm.movzx(Size::Dword, Rax, Size::Word, Rax),
        (IntegerWidth::Bits32, true) => asm.movsxd(Rax, Rax),
        (IntegerWidth::Bits32, false) => asm.mov(Size::Dword, Rax, Rax),
        (IntegerWidth::Bits64, _) => {}
    }
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
        let mut asm = code.asm();
        asm.mov(Size::Qword, Rdx, Rax);
        asm.shift_imm(ShiftOp::Sar, Size::Qword, Rdx, QWORD_SIGN_BIT);
        asm.alu(Alu::Xor, Size::Qword, Rax, Rdx);
        asm.alu(Alu::Sub, Size::Qword, Rax, Rdx);
    } else {
        code.asm().alu(Alu::Xor, Size::Dword, Rdx, Rdx);
    }
    code.asm()
        .alu_accumulator_imm32(Alu::Cmp, Size::Qword, MAXIMUM_FINITE_HALF_INTEGER as i32);
    failure(code, Cond::A, failures);
    Host::Xor.register(code, INTEGER_FLOAT, INTEGER_FLOAT, target);
    if f16c {
        let mut asm = code.asm();
        asm.cvtsi2ss(Size::Qword, 6, Rax);
        asm.movd_from_xmm(Rcx, 6);
        asm.shift_imm(ShiftOp::Shl, Size::Dword, Rdx, DWORD_SIGN_BIT);
        asm.alu(Alu::Or, Size::Dword, Rcx, Rdx);
        asm.movd_to_xmm(6, Rcx);
        // VCVTPS2PH source is ModRM.reg; destination is ModRM.r/m.
        code.asm().simd_imm(
            Host::ConvertSingleToHalf,
            INTEGER_FLOAT,
            Rm::Xmm(INPUT),
            USE_MXCSR_ROUNDING,
            target,
        );
        let mut asm = code.asm();
        asm.movd_from_xmm(Rax, 0);
        asm.alu_accumulator_imm32(Alu::And, Size::Dword, (u32::from(u16::MAX)) as i32);
    } else {
        let mut asm = code.asm();
        asm.cvtsi2sd(Size::Qword, 6, Rax);
        asm.movq_from_xmm(Rcx, 6);
        asm.shift_imm(ShiftOp::Shl, Size::Qword, Rdx, QWORD_SIGN_BIT);
        asm.alu(Alu::Or, Size::Qword, Rcx, Rdx);
        asm.movq_to_xmm(6, Rcx);
        half::emit_normal_or_zero(code, failures);
    }
}
