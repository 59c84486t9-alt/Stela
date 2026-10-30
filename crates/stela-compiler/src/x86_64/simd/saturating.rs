//! Saturating arithmetic. XMM4 accumulates the per-lane FPSR.QC mask; overflow is
//! detected before clamping.
use super::rearrange::{add_or_subtract, lane_constant};
use super::{Host, commit, greater, packed, read_vector, rearrange::constant, shuffle};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, ShiftOp, Size, vector_extensions};
use crate::x86_64::simd::encode::guest;
use crate::{
    GuestState, TargetCpu,
    aarch64::simd::saturating::{FPSR_QC, Kind, Operand},
    x86_64::isa::ShiftOpcode as Shift,
};

pub(super) fn sign_mask(code: &mut Code, destination: u8, source: u8, lane: u8) {
    if lane == 1 {
        packed(code, Host::Xor, destination, destination);
        packed(code, Host::GreaterByte, destination, source);
    } else {
        packed(code, Host::MoveAligned, destination, source);
        if lane == 2 {
            Shift::ArithmeticWord.emit(code, destination, 15);
        } else {
            Shift::ArithmeticDword.emit(code, destination, 31);
            if lane == 8 {
                shuffle(code, destination, destination, 0xf5);
            }
        }
    }
}
/// XMM0=a, XMM1=b, XMM2=wrapped a+b; produce the unsigned carry mask in XMM4.
fn unsigned_carry(code: &mut Code, lane: u8) {
    packed(code, Host::MoveAligned, 3, 0);
    packed(code, Host::And, 3, 1);
    packed(code, Host::MoveAligned, 4, 0);
    packed(code, Host::Or, 4, 1);
    packed(code, Host::MoveAligned, 5, 2);
    packed(code, Host::AndNot, 5, 4);
    packed(code, Host::Or, 3, 5);
    sign_mask(code, 4, 3, lane);
}
/// Merge wrapped XMM2 and clamping bound XMM5 using saturation mask XMM4.
fn clamp_result(code: &mut Code) {
    packed(code, Host::Xor, 5, 2);
    packed(code, Host::And, 5, 4);
    packed(code, Host::Xor, 2, 5);
    packed(code, Host::MoveAligned, 0, 2);
}
pub(super) fn add_sub(code: &mut Code, lane: u8, signed: bool, sub: bool) {
    packed(code, Host::MoveAligned, 2, 0);
    packed(code, add_or_subtract(lane, sub), 2, 1);
    if lane <= 2 {
        let opcode = match (signed, sub, lane) {
            (true, false, 1) => Host::AddSignedSaturatingByte,
            (true, false, 2) => Host::AddSignedSaturatingWord,
            (false, false, 1) => Host::AddUnsignedSaturatingByte,
            (false, false, 2) => Host::AddUnsignedSaturatingWord,
            (true, true, 1) => Host::SubSignedSaturatingByte,
            (true, true, 2) => Host::SubSignedSaturatingWord,
            (false, true, 1) => Host::SubUnsignedSaturatingByte,
            (false, true, 2) => Host::SubUnsignedSaturatingWord,
            _ => unreachable!(),
        };
        packed(code, opcode, 0, 1);
        packed(code, Host::MoveAligned, 4, 2);
        packed(code, Host::EqualByte, 4, 0);
        packed(code, Host::EqualDword, 3, 3);
        packed(code, Host::Xor, 4, 3);
        return;
    }
    if signed {
        packed(code, Host::MoveAligned, 3, 0);
        packed(code, Host::Xor, 3, 1);
        if !sub {
            packed(code, Host::EqualDword, 5, 5);
            packed(code, Host::Xor, 3, 5);
        }
        packed(code, Host::MoveAligned, 5, 0);
        packed(code, Host::Xor, 5, 2);
        packed(code, Host::And, 3, 5);
        sign_mask(code, 4, 3, lane);
        sign_mask(code, 5, 0, lane);
        lane_constant(code, 3, lane, (1u64 << (lane * 8 - 1)) - 1);
        packed(code, Host::Xor, 5, 3);
        clamp_result(code);
    } else if !sub {
        unsigned_carry(code, lane);
        packed(code, Host::Or, 2, 4);
        packed(code, Host::MoveAligned, 0, 2);
    } else {
        packed(code, Host::MoveAligned, 3, 0);
        packed(code, Host::AndNot, 3, 1);
        packed(code, Host::MoveAligned, 4, 0);
        packed(code, Host::Xor, 4, 1);
        packed(code, Host::AndNot, 4, 2);
        packed(code, Host::Or, 3, 4);
        sign_mask(code, 4, 3, lane);
        packed(code, Host::MoveAligned, 5, 4);
        packed(code, Host::AndNot, 5, 2);
        packed(code, Host::MoveAligned, 0, 5);
    }
}
fn absolute_or_negate(code: &mut Code, lane: u8, negate: bool, target: TargetCpu) {
    lane_constant(code, 4, lane, 1u64 << (lane * 8 - 1));
    packed(
        code,
        match lane {
            1 => Host::EqualByte,
            2 => Host::EqualWord,
            4 | 8 => Host::EqualDword,
            _ => unreachable!(),
        },
        4,
        0,
    );
    if lane == 8 {
        shuffle(code, 3, 4, 0xb1);
        packed(code, Host::And, 4, 3);
    }
    if negate {
        packed(code, Host::Xor, 1, 1);
        packed(code, add_or_subtract(lane, true), 1, 0);
        packed(code, Host::MoveAligned, 0, 1);
    } else if lane <= 4 && target >= TargetCpu::Ssse3 {
        match lane {
            1 => Host::AbsByte,
            2 => Host::AbsWord,
            4 => Host::AbsDword,
            _ => unreachable!(),
        }
        .register(code, 0, 0, target);
    } else {
        sign_mask(code, 1, 0, lane);
        packed(code, Host::Xor, 0, 1);
        packed(code, add_or_subtract(lane, true), 0, 1);
    }
    // Wrapped -MIN/ABS(MIN) is MIN: adding the all-one mask produces MAX.
    packed(code, add_or_subtract(lane, false), 0, 4);
}
fn mixed_add(code: &mut Code, lane: u8, unsigned_result: bool) {
    if !unsigned_result {
        lane_constant(code, 5, lane, 1u64 << (lane * 8 - 1));
        packed(code, Host::Xor, 0, 5);
        add_sub(code, lane, false, false);
        lane_constant(code, 5, lane, 1u64 << (lane * 8 - 1));
        packed(code, Host::Xor, 0, 5);
    } else {
        sign_mask(code, 6, 1, lane);
        packed(code, Host::MoveAligned, 2, 0);
        packed(code, add_or_subtract(lane, false), 2, 1);
        unsigned_carry(code, lane);
        packed(code, Host::Xor, 4, 6);
        packed(code, Host::EqualDword, 5, 5);
        packed(code, Host::Xor, 5, 6);
        clamp_result(code);
    }
}

/// Clamp the wide source lanes into XMM0, marking saturated ones in XMM4.
/// XMM6 holds the upper-bound mask across the second comparison; the compare
/// recipe uses only XMM0-4 and XMM7.
fn narrow(
    code: &mut Code,
    operand: &Operand,
    unsigned_source: bool,
    unsigned_result: bool,
    target: TargetCpu,
) {
    let lane = operand.lane_bytes;
    if vector_extensions::saturating_narrow(
        code,
        lane * 2,
        [!unsigned_source, !unsigned_result],
        1,
        0,
        Some(4),
        target,
    ) {
        packed(code, Host::MoveAligned, 0, 1);
        return;
    }
    let high = if unsigned_result {
        (1u64 << (lane * 8)) - 1
    } else {
        (1u64 << (lane * 8 - 1)) - 1
    };
    let low = if unsigned_result {
        0
    } else {
        0u64.wrapping_sub(1u64 << (lane * 8 - 1))
    };
    lane_constant(code, 1, lane * 2, high);
    greater(code, lane * 2, unsigned_source, target);
    packed(code, Host::MoveAligned, 6, 0);
    if !unsigned_source {
        lane_constant(code, 0, lane * 2, low);
        read_vector(code, operand.left, 1);
        greater(code, lane * 2, false, target);
    } else {
        packed(code, Host::Xor, 0, 0);
    }
    read_vector(code, operand.left, 5);
    lane_constant(code, 1, lane * 2, low);
    packed(code, Host::Xor, 1, 5);
    packed(code, Host::And, 1, 0);
    packed(code, Host::Xor, 5, 1);
    lane_constant(code, 1, lane * 2, high);
    packed(code, Host::Xor, 1, 5);
    packed(code, Host::And, 1, 6);
    packed(code, Host::Xor, 5, 1);
    packed(code, Host::MoveAligned, 4, 0);
    packed(code, Host::Or, 4, 6);
    packed(code, Host::MoveAligned, 0, 5);
    match (unsigned_result, lane) {
        (false, 1) => packed(code, Host::PackSignedWordToByte, 0, 0),
        (true, 1) => packed(code, Host::PackUnsignedWordToByte, 0, 0),
        (false, 2) => packed(code, Host::PackSignedDwordToWord, 0, 0),
        (true, 2) if target >= TargetCpu::Sse41 => {
            Host::PackUnsignedDwordToWord.register(code, 0, 0, target)
        }
        (true, 2) => {
            Shift::LeftDword.emit(code, 0, 16);
            Shift::ArithmeticDword.emit(code, 0, 16);
            packed(code, Host::PackSignedDwordToWord, 0, 0);
        }
        (_, 4) => shuffle(code, 0, 0, 0x88),
        _ => unreachable!("allocated narrowing width"),
    }
}
pub(super) fn publish_qc(code: &mut Code, active_bytes: u8) {
    Host::ByteSignMask.register(code, 1, 4, TargetCpu::Baseline); // pmovmskb ecx,xmm4
    use Gpr::Rcx;
    let mut asm = code.asm();
    // The active byte mask: inactive lanes cannot set QC.
    asm.alu_imm32(
        Alu::And,
        Size::Dword,
        Rcx,
        ((1u32 << active_bytes) - 1) as i32,
    );
    asm.setcc(Cond::Ne, Rcx);
    asm.movzx(Size::Dword, Rcx, Size::Byte, Rcx);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Dword,
        Rcx,
        FPSR_QC.trailing_zeros() as u8,
    );
    // Sticky QC, preserving every other bit.
    asm.alu(
        Alu::Or,
        Size::Dword,
        guest(core::mem::offset_of!(GuestState, fpsr) as u32),
        Rcx,
    );
}

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu) {
    let Operand {
        kind,
        destination,
        left,
        right,
        lane_bytes: lane,
        bytes,
    } = *operand;
    if matches!(kind, Kind::MixedAdd { .. }) {
        read_vector(code, destination, 0);
        read_vector(code, left, 1);
    } else {
        read_vector(code, left, 0);
        if matches!(kind, Kind::Add { .. } | Kind::Sub { .. }) {
            read_vector(code, right, 1);
        }
    }
    let mut active_mask_bytes = bytes;
    let mut result = 0;
    match kind {
        Kind::Add { signed } => add_sub(code, lane, signed, false),
        Kind::Sub { signed } => add_sub(code, lane, signed, true),
        Kind::Abs => absolute_or_negate(code, lane, false, target),
        Kind::Neg => absolute_or_negate(code, lane, true, target),
        Kind::MixedAdd { unsigned_result } => mixed_add(code, lane, unsigned_result),
        Kind::Narrow {
            unsigned_source,
            unsigned_result,
            upper,
        } => {
            narrow(code, operand, unsigned_source, unsigned_result, target);
            active_mask_bytes = bytes * 2;
            if upper {
                read_vector(code, destination, 1);
                packed(code, Host::UnpackLowQword, 1, 0);
                result = 1;
            }
        }
    }
    if result == 0 && bytes < 16 {
        constant(
            code,
            1,
            core::array::from_fn(|i| if i < usize::from(bytes) { 255 } else { 0 }),
        );
        packed(code, Host::And, 0, 1);
    }
    publish_qc(code, active_mask_bytes);
    commit(code, destination, result);
}
