//! SVE widening bottom/top multiplies.
use super::packed;
use crate::TargetCpu;
use crate::aarch64::scalable::ElementSize;
use crate::aarch64::sve::integer_products::{Accumulate, Selection};
use crate::x86_64::asm::Code;
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};

const RESULT: u8 = 0;
const RIGHT: u8 = 1;
const FIRST_PARTIAL: u8 = 2;
const SECOND_PARTIAL: u8 = 3;
const ACCUMULATOR: u8 = 4;
const BYTE_BITS: u8 = 8;
const HALFWORD_BITS: u8 = 16;
const WORD_BITS: u8 = 32;
const WORD_SIGN_SHIFT: u8 = WORD_BITS - 1;
const SELECT_EVEN_DWORDS: u8 = 0x88;
const SELECT_ODD_DWORDS: u8 = 0xdd;

fn select_bytes(code: &mut Code, signed: bool, top: bool) {
    let right = if signed {
        Shift::ArithmeticWord
    } else {
        Shift::RightWord
    };
    for register in [RESULT, RIGHT] {
        if !top {
            Shift::LeftWord.emit(code, register, BYTE_BITS);
        }
        right.emit(code, register, BYTE_BITS);
    }
    packed(code, Host::MultiplyLowWord, RESULT, RIGHT);
}

fn select_halfwords(code: &mut Code, top: bool) {
    // Leave the selected halfword in each dword's low half, with zero above
    // it. Signed PMADDWD adds a zero product; checked PMULLD sees zero extension.
    for register in [RESULT, RIGHT] {
        if !top {
            Shift::LeftDword.emit(code, register, HALFWORD_BITS);
        }
        Shift::RightDword.emit(code, register, HALFWORD_BITS);
    }
}

fn signed_halfwords(code: &mut Code, top: bool) {
    select_halfwords(code, top);
    packed(code, Host::MultiplyAddWords, RESULT, RIGHT);
}

fn unsigned_halfwords(code: &mut Code, top: bool, target: TargetCpu) {
    if target.supports(TargetCpu::Sse41) {
        select_halfwords(code, top);
        Host::MultiplyLowDword.register(code, RESULT, RIGHT, target);
        return;
    }
    // Build all eight full unsigned products, then gather alternating dwords.
    packed(code, Host::MoveAligned, FIRST_PARTIAL, RESULT);
    packed(code, Host::MultiplyLowWord, RESULT, RIGHT);
    packed(code, Host::MultiplyHighUnsignedWord, FIRST_PARTIAL, RIGHT);
    packed(code, Host::MoveAligned, SECOND_PARTIAL, RESULT);
    packed(code, Host::UnpackLowWord, RESULT, FIRST_PARTIAL);
    packed(code, Host::UnpackHighWord, SECOND_PARTIAL, FIRST_PARTIAL);
    let control = if top {
        SELECT_ODD_DWORDS
    } else {
        SELECT_EVEN_DWORDS
    };
    for register in [RESULT, SECOND_PARTIAL] {
        packed(code, Host::ShuffleDword, register, register);
        code.push(control);
    }
    packed(code, Host::UnpackLowQword, RESULT, SECOND_PARTIAL);
}

fn words(code: &mut Code, signed: bool, top: bool, target: TargetCpu) {
    if top {
        Shift::RightQword.emit(code, RESULT, WORD_BITS);
        Shift::RightQword.emit(code, RIGHT, WORD_BITS);
    }
    if signed && target.supports(TargetCpu::Sse41) {
        Host::MultiplySignedDword.register(code, RESULT, RIGHT, target);
        return;
    }
    if signed {
        // Signed products equal unsigned products minus both negative-source
        // corrections shifted by 32. Combining corrections first is exact
        // modulo 64 bits, including a carry out of their low dword.
        packed(code, Host::MoveAligned, FIRST_PARTIAL, RESULT);
        packed(code, Host::MoveAligned, SECOND_PARTIAL, RIGHT);
        Shift::ArithmeticDword.emit(code, FIRST_PARTIAL, WORD_SIGN_SHIFT);
        Shift::ArithmeticDword.emit(code, SECOND_PARTIAL, WORD_SIGN_SHIFT);
        packed(code, Host::And, FIRST_PARTIAL, RIGHT);
        packed(code, Host::And, SECOND_PARTIAL, RESULT);
        packed(code, Host::AddQword, FIRST_PARTIAL, SECOND_PARTIAL);
        Shift::LeftQword.emit(code, FIRST_PARTIAL, WORD_BITS);
        packed(code, Host::MultiplyUnsignedDword, RESULT, RIGHT);
        packed(code, Host::SubQword, RESULT, FIRST_PARTIAL);
    } else {
        packed(code, Host::MultiplyUnsignedDword, RESULT, RIGHT);
    }
}

/// XMM0/XMM1 hold source chunks; indexed multipliers are already broadcast at
/// narrow source width. XMM4 holds the old wide accumulator. Returns XMM0,
/// consumes XMM0..4 and preserves XMM5..7, guest status, RAM and host MXCSR.
pub(super) fn emit_chunk(
    code: &mut Code,
    element: ElementSize,
    signed: bool,
    accumulate: Accumulate,
    selection: Selection,
    target: TargetCpu,
) {
    let top = match selection {
        Selection::Bottom => false,
        Selection::Top => true,
        Selection::Cross => unreachable!("cross long products are saturating"),
    };
    match element {
        ElementSize::Halfword => select_bytes(code, signed, top),
        ElementSize::Word if signed => signed_halfwords(code, top),
        ElementSize::Word => unsigned_halfwords(code, top, target),
        ElementSize::Doubleword => words(code, signed, top, target),
        _ => unreachable!("validated widening destination width"),
    }
    let opcode = match (element, accumulate) {
        (_, Accumulate::None) => return,
        (ElementSize::Halfword, Accumulate::Add) => Host::AddWord,
        (ElementSize::Word, Accumulate::Add) => Host::AddDword,
        (ElementSize::Doubleword, Accumulate::Add) => Host::AddQword,
        (ElementSize::Halfword, Accumulate::Subtract) => Host::SubWord,
        (ElementSize::Word, Accumulate::Subtract) => Host::SubDword,
        (ElementSize::Doubleword, Accumulate::Subtract) => Host::SubQword,
        _ => unreachable!("validated widening destination width"),
    };
    if accumulate == Accumulate::Subtract {
        packed(code, opcode, ACCUMULATOR, RESULT);
        packed(code, Host::MoveAligned, RESULT, ACCUMULATOR);
    } else {
        packed(code, opcode, RESULT, ACCUMULATOR);
    }
}
