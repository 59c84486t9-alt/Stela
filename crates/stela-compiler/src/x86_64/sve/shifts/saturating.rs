//! SVE saturating shifts by signed counts.
use super::{repeated_constant, stack_vector};
use crate::x86_64::asm::{Code, Rm};
use crate::{
    TargetCpu,
    aarch64::{scalable::ElementSize, sve::shifts::Kind},
    x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host},
};
const SOURCE_SLOT: u8 = 0;
const COUNTS_SLOT: u8 = 16;
const LEFT_SLOT: u8 = 32;
const QUOTIENT_SLOT: u8 = 48;
pub(super) const STACK_BYTES: u8 = 64;
const DWORD_SIGN_SHIFT: u8 = u32::BITS as u8 - 1;
const WORD_SIGN_SHIFT: u8 = u16::BITS as u8 - 1;
const DUPLICATE_HIGH_DWORDS: u8 = 0xf5;
const ADJACENT_DWORDS: u8 = 0xb1;
fn packed(code: &mut Code, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}
fn add(element: ElementSize) -> Host {
    match element {
        ElementSize::Byte => Host::AddByte,
        ElementSize::Halfword => Host::AddWord,
        ElementSize::Word => Host::AddDword,
        ElementSize::Doubleword => Host::AddQword,
        _ => unreachable!(),
    }
}
fn subtract(element: ElementSize) -> Host {
    match element {
        ElementSize::Byte => Host::SubByte,
        ElementSize::Halfword => Host::SubWord,
        ElementSize::Word => Host::SubDword,
        ElementSize::Doubleword => Host::SubQword,
        _ => unreachable!(),
    }
}
fn sign_mask(code: &mut Code, destination: u8, source: u8, element: ElementSize) {
    if element == ElementSize::Byte {
        let input = if source == destination {
            packed(code, Host::MoveAligned, 4, source);
            4
        } else {
            source
        };
        packed(code, Host::Xor, destination, destination);
        packed(code, Host::GreaterByte, destination, input);
    } else {
        packed(code, Host::MoveAligned, destination, source);
        match element {
            ElementSize::Halfword => Shift::ArithmeticWord.emit(code, destination, WORD_SIGN_SHIFT),
            ElementSize::Word => Shift::ArithmeticDword.emit(code, destination, DWORD_SIGN_SHIFT),
            ElementSize::Doubleword => {
                Shift::ArithmeticDword.emit(code, destination, DWORD_SIGN_SHIFT);
                code.asm().simd_imm(
                    Host::ShuffleDword,
                    destination,
                    Rm::Xmm(destination),
                    DUPLICATE_HIGH_DWORDS,
                    TargetCpu::Baseline,
                );
            }
            _ => unreachable!(),
        }
    }
}
fn equal(code: &mut Code, element: ElementSize) {
    let opcode = match element {
        ElementSize::Byte => Host::EqualByte,
        ElementSize::Halfword => Host::EqualWord,
        ElementSize::Word | ElementSize::Doubleword => Host::EqualDword,
        _ => unreachable!(),
    };
    packed(code, opcode, 0, 3);
    if element == ElementSize::Doubleword {
        code.asm().simd_imm(
            Host::ShuffleDword,
            4,
            Rm::Xmm(0),
            ADJACENT_DWORDS,
            TargetCpu::Baseline,
        );
        packed(code, Host::And, 0, 4);
    }
    packed(code, Host::MoveAligned, 2, 0);
}
/// Inputs XMM0=data, XMM1=full signed counts; preserve counts1 and old merge6.
/// Caller owns a64-byte stack scratch frame at RSP.
pub(super) fn chunk(code: &mut Code, kind: Kind, element: ElementSize) {
    let signed = matches!(
        kind,
        Kind::SaturatingSigned | Kind::SaturatingRoundingSigned
    );
    let rounded = matches!(
        kind,
        Kind::SaturatingRoundingSigned | Kind::SaturatingRoundingUnsigned
    );
    assert!(matches!(
        kind,
        Kind::SaturatingSigned
            | Kind::SaturatingUnsigned
            | Kind::SaturatingRoundingSigned
            | Kind::SaturatingRoundingUnsigned
    ));
    let right = if signed {
        Kind::ArithmeticRight
    } else {
        Kind::LogicalRight
    };
    stack_vector(code, 0, SOURCE_SLOT, true);
    stack_vector(code, 1, COUNTS_SLOT, true);
    // Truncated left shift is exact precisely when its inverse restores input.
    super::variable::chunk(code, Kind::LogicalLeft, element);
    stack_vector(code, 0, LEFT_SLOT, true);
    super::variable::chunk(code, right, element);
    stack_vector(code, 3, SOURCE_SLOT, false);
    equal(code, element);
    if signed {
        sign_mask(code, 3, 3, element);
        repeated_constant(code, 4, element, (1u64 << (element.bits() - 1)) - 1);
        packed(code, Host::Xor, 3, 4);
    } else {
        packed(code, Host::EqualDword, 3, 3);
    }
    stack_vector(code, 0, LEFT_SLOT, false);
    packed(code, Host::And, 0, 2);
    packed(code, Host::AndNot, 2, 3);
    packed(code, Host::Or, 0, 2);
    stack_vector(code, 0, LEFT_SLOT, true);
    // abs(INT_MIN) retains its unsigned-large magnitude; never narrow to low byte.
    sign_mask(code, 2, 1, element);
    packed(code, Host::Xor, 1, 2);
    packed(code, subtract(element), 1, 2);
    stack_vector(code, 0, SOURCE_SLOT, false);
    super::variable::chunk(code, right, element);
    if rounded {
        stack_vector(code, 0, QUOTIENT_SLOT, true);
        repeated_constant(code, 2, element, 1);
        packed(code, subtract(element), 1, 2);
        stack_vector(code, 0, SOURCE_SLOT, false);
        super::variable::chunk(code, right, element);
        repeated_constant(code, 2, element, 1);
        packed(code, Host::And, 0, 2);
        stack_vector(code, 3, QUOTIENT_SLOT, false);
        packed(code, add(element), 0, 3);
    }
    stack_vector(code, 1, COUNTS_SLOT, false);
    sign_mask(code, 2, 1, element);
    stack_vector(code, 3, LEFT_SLOT, false);
    packed(code, Host::Xor, 0, 3);
    packed(code, Host::And, 0, 2);
    packed(code, Host::Xor, 0, 3);
}
