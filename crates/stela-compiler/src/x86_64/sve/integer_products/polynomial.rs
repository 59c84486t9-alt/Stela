//! SVE PMULLB/PMULLT carryless multiplies.
use crate::TargetCpu;
use crate::aarch64::Unsupported;
use crate::aarch64::scalable::ElementSize;
use crate::aarch64::sve::integer_products::Selection;
use crate::x86_64::asm::Gpr::R10;
use crate::x86_64::asm::{Code, Cond, Rm, Size, resolve};
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};

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

fn packed(code: &mut Code, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn low_lane_mask(code: &mut Code, shift: Shift, bits: u8) {
    packed(code, Host::EqualDword, CONSTANT, CONSTANT);
    shift.emit(code, CONSTANT, bits);
}

/// Eight Horner steps per byte. PADDB doubles modulo x^8 without permitting
/// carries between lanes, and signed-byte comparison extracts each top bit.
fn low_bytes(code: &mut Code) {
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

fn widen_bytes(code: &mut Code, top: bool) {
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

fn widen_dwords(code: &mut Code, top: bool) {
    if top {
        Shift::RightQword.emit(code, LEFT, DWORD_BITS);
        Shift::RightQword.emit(code, RIGHT, DWORD_BITS);
    }
    low_lane_mask(code, Shift::RightQword, DWORD_BITS);
    packed(code, Host::And, LEFT, CONSTANT);
    packed(code, Host::Xor, RESULT, RESULT);
    code.asm().mov_imm32(R10, u32::from(DWORD_BITS));
    let loop_start = code.len();
    Shift::LeftQword.emit(code, RESULT, 1);
    packed(code, Host::MoveAligned, MASK, RIGHT);
    Shift::ArithmeticDword.emit(code, MASK, DWORD_SIGN_SHIFT);
    code.asm().simd_imm(
        Host::ShuffleDword,
        MASK,
        Rm::Xmm(MASK),
        LOW_DWORD_MASK_DUPLICATE,
        TargetCpu::Baseline,
    );
    packed(code, Host::And, MASK, LEFT);
    packed(code, Host::Xor, RESULT, MASK);
    Shift::LeftDword.emit(code, RIGHT, 1);
    let mut asm = code.asm();
    asm.dec(Size::Dword, R10);
    let repeat = asm.jcc(Cond::Ne);
    resolve(code, repeat, loop_start);
}

fn widen_dwords_pclmul(code: &mut Code, top: bool, target: TargetCpu) {
    if top {
        Shift::RightQword.emit(code, LEFT, DWORD_BITS);
        Shift::RightQword.emit(code, RIGHT, DWORD_BITS);
    } else {
        low_lane_mask(code, Shift::RightQword, DWORD_BITS);
        packed(code, Host::And, LEFT, CONSTANT);
        packed(code, Host::And, RIGHT, CONSTANT);
    }
    packed(code, Host::MoveAligned, RESULT, LEFT);
    code.asm().simd_imm(
        Host::CarrylessMultiplyQword,
        LEFT,
        Rm::Xmm(RIGHT),
        PCLMUL_LOW_QWORDS,
        target,
    );
    code.asm().simd_imm(
        Host::CarrylessMultiplyQword,
        RESULT,
        Rm::Xmm(RIGHT),
        PCLMUL_HIGH_QWORDS,
        target,
    );
    packed(code, Host::UnpackLowQword, LEFT, RESULT);
}

/// XMM0/XMM1 contain source chunks; return XMM0 while preserving XMM7, RDI and
/// R15. Each widening result selects even (bottom) or odd (top) narrow lanes.
/// Reject unallocated widths before emitting any bytes. No RAM or FP effects.
pub(super) fn emit_chunk(
    code: &mut Code,
    element: ElementSize,
    widening: bool,
    selection: Selection,
    target: TargetCpu,
) -> Result<(), Unsupported> {
    if selection == Selection::Cross {
        return Err(Unsupported);
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
        _ => return Err(Unsupported),
    }
    packed(code, Host::MoveAligned, LEFT, RESULT);
    Ok(())
}
