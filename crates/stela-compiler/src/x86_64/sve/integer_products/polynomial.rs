//! Carryless products of alternating SVE lanes using only integer SIMD.
use crate::TargetCpu;
use crate::aarch64::scalable::ElementSize;
use crate::aarch64::sve::integer_products::Selection;
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const RESULT: u8 = 2;
const MASK: u8 = 3;
const CONSTANT: u8 = 4;
const BYTE_BITS: u8 = 8;
const DWORD_BITS: u8 = 32;
const DWORD_SIGN_SHIFT: u8 = DWORD_BITS - 1;
const LOW_DWORD_MASK_DUPLICATE: u8 = 0xa0;
const PCLMUL_LOW_QWORDS: u8 = 0x00;
const PCLMUL_HIGH_QWORDS: u8 = 0x11;
const MOV_R10D_IMMEDIATE: [u8; 2] = [0x41, 0xba];
const DEC_R10D: [u8; 3] = [0x41, 0xff, 0xca];
const JNZ_REL32: [u8; 2] = [0x0f, 0x85];
const REL32_BYTES: usize = 4;

fn packed(code: &mut Vec<u8>, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn low_lane_mask(code: &mut Vec<u8>, shift: Shift, bits: u8) {
    packed(code, Host::EqualDword, CONSTANT, CONSTANT);
    shift.emit(code, CONSTANT, bits);
}

/// Eight Horner steps per byte. PADDB doubles modulo x^8 without permitting
/// carries between lanes, and signed-byte comparison extracts each top bit.
fn low_bytes(code: &mut Vec<u8>) {
    packed(code, Host::Xor, RESULT, RESULT);
    for bit in 0..BYTE_BITS {
        if bit != 0 {
            packed(code, Host::AddByte, RESULT, RESULT);
        }
        packed(code, Host::Xor, MASK, MASK);
        packed(code, Host::GreaterByte, MASK, RIGHT);
        packed(code, Host::And, MASK, LEFT);
        packed(code, Host::Xor, RESULT, MASK);
        if bit + 1 != BYTE_BITS {
            packed(code, Host::AddByte, RIGHT, RIGHT);
        }
    }
}

fn widen_bytes(code: &mut Vec<u8>, top: bool) {
    if top {
        Shift::RightWord.emit(code, LEFT, BYTE_BITS);
        Shift::RightWord.emit(code, RIGHT, BYTE_BITS);
    }
    low_lane_mask(code, Shift::RightWord, BYTE_BITS);
    packed(code, Host::And, LEFT, CONSTANT);
    packed(code, Host::And, RIGHT, CONSTANT);
    // The selected byte is in each word's low half. Moving it to the high half
    // lets PCMPGTW produce a complete mask without additional constants.
    Shift::LeftWord.emit(code, RIGHT, BYTE_BITS);
    packed(code, Host::Xor, RESULT, RESULT);
    for bit in 0..BYTE_BITS {
        if bit != 0 {
            packed(code, Host::AddWord, RESULT, RESULT);
        }
        packed(code, Host::Xor, MASK, MASK);
        packed(code, Host::GreaterWord, MASK, RIGHT);
        packed(code, Host::And, MASK, LEFT);
        packed(code, Host::Xor, RESULT, MASK);
        if bit + 1 != BYTE_BITS {
            packed(code, Host::AddWord, RIGHT, RIGHT);
        }
    }
}

fn widen_dwords(code: &mut Vec<u8>, top: bool) {
    if top {
        Shift::RightQword.emit(code, LEFT, DWORD_BITS);
        Shift::RightQword.emit(code, RIGHT, DWORD_BITS);
    }
    low_lane_mask(code, Shift::RightQword, DWORD_BITS);
    packed(code, Host::And, LEFT, CONSTANT);
    packed(code, Host::Xor, RESULT, RESULT);
    code.extend(MOV_R10D_IMMEDIATE);
    code.extend(u32::from(DWORD_BITS).to_le_bytes());
    let loop_start = code.len();
    Shift::LeftQword.emit(code, RESULT, 1);
    packed(code, Host::MoveAligned, MASK, RIGHT);
    Shift::ArithmeticDword.emit(code, MASK, DWORD_SIGN_SHIFT);
    packed(code, Host::ShuffleDword, MASK, MASK);
    code.push(LOW_DWORD_MASK_DUPLICATE);
    packed(code, Host::And, MASK, LEFT);
    packed(code, Host::Xor, RESULT, MASK);
    Shift::LeftDword.emit(code, RIGHT, 1);
    code.extend(DEC_R10D);
    code.extend(JNZ_REL32);
    let displacement = i32::try_from(loop_start as isize - (code.len() + REL32_BYTES) as isize)
        .expect("bounded polynomial loop");
    code.extend(displacement.to_le_bytes());
}

fn widen_dwords_pclmul(code: &mut Vec<u8>, top: bool, target: TargetCpu) {
    if top {
        Shift::RightQword.emit(code, LEFT, DWORD_BITS);
        Shift::RightQword.emit(code, RIGHT, DWORD_BITS);
    } else {
        low_lane_mask(code, Shift::RightQword, DWORD_BITS);
        packed(code, Host::And, LEFT, CONSTANT);
        packed(code, Host::And, RIGHT, CONSTANT);
    }
    packed(code, Host::MoveAligned, RESULT, LEFT);
    Host::CarrylessMultiplyQword.register(code, LEFT, RIGHT, target);
    code.push(PCLMUL_LOW_QWORDS);
    Host::CarrylessMultiplyQword.register(code, RESULT, RIGHT, target);
    code.push(PCLMUL_HIGH_QWORDS);
    packed(code, Host::UnpackLowQword, LEFT, RESULT);
}

/// XMM0/XMM1 contain source chunks; return XMM0 while preserving XMM7, RDI and
/// R15. Each widening result selects even (bottom) or odd (top) narrow lanes.
/// Reject unallocated widths before emitting any bytes. No RAM or FP effects.
pub(super) fn emit_chunk(
    code: &mut Vec<u8>,
    element: ElementSize,
    widening: bool,
    selection: Selection,
    target: TargetCpu,
) -> Result<(), ()> {
    if selection == Selection::Cross {
        return Err(());
    }
    let top = selection == Selection::Top;
    if widening && element == ElementSize::Doubleword && target.supports(TargetCpu::Pclmulqdq) {
        widen_dwords_pclmul(code, top, target);
        return Ok(());
    }
    match (widening, element) {
        (false, ElementSize::Byte) => low_bytes(code),
        (true, ElementSize::Halfword) => widen_bytes(code, top),
        (true, ElementSize::Doubleword) => widen_dwords(code, top),
        _ => return Err(()),
    }
    packed(code, Host::MoveAligned, LEFT, RESULT);
    Ok(())
}
