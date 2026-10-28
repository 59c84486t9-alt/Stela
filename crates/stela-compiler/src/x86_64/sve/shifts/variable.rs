//! Per-lane variable shifts by unsigned counts.
use super::repeated_constant;
use crate::x86_64::simd::shifts::{
    logical_shift as shared_logical_shift, right_shift as shared_right_shift,
};
use crate::{
    TargetCpu,
    aarch64::{
        scalable::ElementSize,
        sve::shifts::{Count, Kind},
    },
    x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host, VexShiftOpcode},
};
use alloc::vec::Vec;

/// Only complete unsigned per-element counts map directly. Wide counts,
/// signed bidirectional/rounded shifts and narrower lanes retain their own
/// recipes. The target-independent DIT profile gate remains conservative.
pub(super) fn avx2_opcode(
    kind: Kind,
    element: ElementSize,
    count: Count,
    target: TargetCpu,
) -> Option<VexShiftOpcode> {
    if !target.supports(TargetCpu::Avx2) || !matches!(count, Count::Elements(_)) {
        return None;
    }
    match (kind, element) {
        (Kind::LogicalLeft, ElementSize::Word) => Some(VexShiftOpcode::LeftDword),
        (Kind::LogicalRight, ElementSize::Word) => Some(VexShiftOpcode::RightDword),
        (Kind::ArithmeticRight, ElementSize::Word) => Some(VexShiftOpcode::ArithmeticDword),
        (Kind::LogicalLeft, ElementSize::Doubleword) => Some(VexShiftOpcode::LeftQword),
        (Kind::LogicalRight, ElementSize::Doubleword) => Some(VexShiftOpcode::RightQword),
        _ => None,
    }
}
const ADJACENT_DWORDS: u8 = 0xb1;
const HIGH_DWORD_SIGN: u8 = 0xf5;
const DWORD_SIGN_SHIFT: u8 = u32::BITS as u8 - 1;
const WORD_SIGN_SHIFT: u8 = u16::BITS as u8 - 1;
fn packed(code: &mut Vec<u8>, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}
/// Byte logical masks use one repeated qword constant, avoiding two-limb setup.
fn logical_shift(code: &mut Vec<u8>, xmm: u8, lane: u8, amount: u8, left: bool) {
    if lane != 1 {
        shared_logical_shift(code, xmm, lane, amount, left);
        return;
    }
    if amount == 0 {
        return;
    }
    let opcode = if left {
        Shift::LeftWord
    } else {
        Shift::RightWord
    };
    opcode.emit(code, xmm, amount);
    let mask = if left {
        (u16::from(u8::MAX) << amount) & u16::from(u8::MAX)
    } else {
        u16::from(u8::MAX) >> amount
    };
    repeated_constant(code, 5, ElementSize::Byte, u64::from(mask));
    packed(code, Host::And, xmm, 5);
}
/// Arithmetic word shifts independently sign-extend each even and odd byte.
/// XMM4 is scratch; XMM1, XMM2 and old mergeXMM6 survive unchanged.
fn right_shift(code: &mut Vec<u8>, xmm: u8, lane: u8, amount: u8, signed: bool) {
    if !signed {
        logical_shift(code, xmm, lane, amount, false);
        return;
    }
    if lane != 1 {
        shared_right_shift(code, xmm, lane, amount, signed);
        return;
    }
    if amount == 0 {
        return;
    }
    const BYTE_BITS: u8 = u8::BITS as u8;
    packed(code, Host::MoveAligned, 4, xmm);
    Shift::LeftWord.emit(code, xmm, BYTE_BITS);
    Shift::ArithmeticWord.emit(code, xmm, BYTE_BITS + amount);
    Shift::LeftWord.emit(code, xmm, BYTE_BITS);
    Shift::RightWord.emit(code, xmm, BYTE_BITS);
    Shift::ArithmeticWord.emit(code, 4, amount);
    Shift::RightWord.emit(code, 4, BYTE_BITS);
    Shift::LeftWord.emit(code, 4, BYTE_BITS);
    packed(code, Host::Or, xmm, 4);
}
fn equal_zero(code: &mut Vec<u8>, xmm: u8, element: ElementSize) {
    packed(code, Host::Xor, 4, 4);
    let op = match element {
        ElementSize::Byte => Host::EqualByte,
        ElementSize::Halfword => Host::EqualWord,
        ElementSize::Word | ElementSize::Doubleword => Host::EqualDword,
        _ => unreachable!(),
    };
    packed(code, op, xmm, 4);
    if element == ElementSize::Doubleword {
        packed(code, Host::ShuffleDword, 5, xmm);
        code.push(ADJACENT_DWORDS);
        packed(code, Host::And, xmm, 5);
    }
}
fn sign_mask(code: &mut Vec<u8>, element: ElementSize) {
    if element == ElementSize::Byte {
        packed(code, Host::Xor, 3, 3);
        packed(code, Host::GreaterByte, 3, 0);
        return;
    }
    packed(code, Host::MoveAligned, 3, 0);
    match element {
        ElementSize::Halfword => Shift::ArithmeticWord.emit(code, 3, WORD_SIGN_SHIFT),
        ElementSize::Word => Shift::ArithmeticDword.emit(code, 3, DWORD_SIGN_SHIFT),
        ElementSize::Doubleword => {
            Shift::ArithmeticDword.emit(code, 3, DWORD_SIGN_SHIFT);
            packed(code, Host::ShuffleDword, 3, 3);
            code.push(HIGH_DWORD_SIGN);
        }
        _ => unreachable!(),
    }
}
pub(super) fn chunk(code: &mut Vec<u8>, kind: Kind, element: ElementSize) {
    assert!(matches!(
        kind,
        Kind::LogicalLeft | Kind::LogicalRight | Kind::ArithmeticRight
    ));
    let bits = element.bits();
    let lane = element.bytes() as u8;
    let mut amount = 1;
    while amount < bits {
        packed(code, Host::MoveAligned, 2, 1);
        let count_bit = amount.trailing_zeros() as u8;
        let shift = bits as u8 - 1 - count_bit;
        match element {
            ElementSize::Byte => {
                Shift::LeftWord.emit(code, 2, shift);
                packed(code, Host::Xor, 4, 4);
                packed(code, Host::GreaterByte, 4, 2);
                packed(code, Host::MoveAligned, 2, 4);
            }
            ElementSize::Halfword => {
                Shift::LeftWord.emit(code, 2, shift);
                Shift::ArithmeticWord.emit(code, 2, WORD_SIGN_SHIFT);
            }
            ElementSize::Word => {
                Shift::LeftDword.emit(code, 2, shift);
                Shift::ArithmeticDword.emit(code, 2, DWORD_SIGN_SHIFT);
            }
            ElementSize::Doubleword => {
                Shift::LeftQword.emit(code, 2, shift);
                Shift::ArithmeticDword.emit(code, 2, DWORD_SIGN_SHIFT);
                packed(code, Host::ShuffleDword, 2, 2);
                code.push(HIGH_DWORD_SIGN);
            }
            _ => unreachable!(),
        }
        packed(code, Host::MoveAligned, 3, 0);
        if kind == Kind::ArithmeticRight {
            right_shift(code, 3, lane, amount as u8, true);
        } else {
            logical_shift(code, 3, lane, amount as u8, kind == Kind::LogicalLeft);
        }
        packed(code, Host::Xor, 3, 0);
        packed(code, Host::And, 3, 2);
        packed(code, Host::Xor, 0, 3);
        amount *= 2;
    }
    packed(code, Host::MoveAligned, 2, 1);
    if element == ElementSize::Byte {
        repeated_constant(code, 5, element, u64::from(u8::MAX) ^ (bits as u64 - 1));
        packed(code, Host::And, 2, 5);
    } else {
        logical_shift(code, 2, lane, bits.trailing_zeros() as u8, false);
    }
    equal_zero(code, 2, element);
    if kind == Kind::ArithmeticRight {
        sign_mask(code, element);
        packed(code, Host::Xor, 3, 0);
        packed(code, Host::AndNot, 2, 3);
        packed(code, Host::Xor, 0, 2);
    } else {
        packed(code, Host::And, 0, 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avx2_route_excludes_different_count_semantics_and_missing_widths() {
        for (kind, element, count, target) in [
            (
                Kind::LogicalLeft,
                ElementSize::Word,
                Count::Elements(1),
                TargetCpu::Baseline,
            ),
            (
                Kind::LogicalLeft,
                ElementSize::Word,
                Count::Doublewords(1),
                TargetCpu::Avx2,
            ),
            (
                Kind::LogicalLeft,
                ElementSize::Word,
                Count::Immediate(1),
                TargetCpu::Avx2,
            ),
            (
                Kind::LogicalLeft,
                ElementSize::Byte,
                Count::Elements(1),
                TargetCpu::Avx2,
            ),
            (
                Kind::LogicalRight,
                ElementSize::Halfword,
                Count::Elements(1),
                TargetCpu::Avx2,
            ),
            (
                Kind::ArithmeticRight,
                ElementSize::Doubleword,
                Count::Elements(1),
                TargetCpu::Avx2,
            ),
            (
                Kind::RoundingSigned,
                ElementSize::Word,
                Count::Elements(1),
                TargetCpu::Avx2,
            ),
            (
                Kind::SaturatingUnsigned,
                ElementSize::Word,
                Count::Elements(1),
                TargetCpu::Avx2,
            ),
        ] {
            assert_eq!(avx2_opcode(kind, element, count, target), None);
        }
        assert_eq!(
            avx2_opcode(
                Kind::ArithmeticRight,
                ElementSize::Word,
                Count::Elements(1),
                TargetCpu::Avx2
            ),
            Some(VexShiftOpcode::ArithmeticDword),
        );
    }
}
