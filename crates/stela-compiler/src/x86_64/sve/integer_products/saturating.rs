//! Signed saturating SVE products. Integer-only recipes preserve FPSR.QC.
//!
//! Narrow products widen before rounding or accumulation. Doubleword products
//! retain both halves of IMUL until their final saturation; no host overflow or
//! wrapped intermediate substitutes for the architectural result.
use super::packed;
use crate::TargetCpu;
use crate::aarch64::scalable::ElementSize;
use crate::aarch64::sve::integer_products::{Accumulate, Kind, Selection};
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const RIGHT: u8 = 1;
const UPPER_PRODUCT: u8 = 2;
const SCRATCH: u8 = 3;
const ACCUMULATOR: u8 = 4;
const LEFT_SIGN: u8 = 5;
const RIGHT_SIGN: u8 = 6;
const CHUNK_BYTES: usize = 16;
const BITS_PER_BYTE: u32 = 8;
const WORD_BITS: u8 = 16;
const DWORD_BITS: u8 = 32;
const QWORD_BITS: u32 = 64;
const SIGN_SHIFT: u8 = 63;
const MIN_HALFWORD_PATTERN: u64 = 0x8000_8000_8000_8000;
const STACK_LEFT: usize = 0;
const STACK_RIGHT: usize = CHUNK_BYTES;
const STACK_ACCUMULATOR: usize = CHUNK_BYTES * 2;
const STACK_BYTES: u8 = (CHUNK_BYTES * 3) as u8;
const MODRM_STACK_DISP8: u8 = 0x44;
const MODRM_DIRECT: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const SIB_STACK: u8 = 0x24;
const REX_W: u8 = 0x48;
const REX_WR: u8 = 0x4c;
const WORD_PREFIX: u8 = 0x66;
const MOVSX_BYTE: [u8; 2] = [0x0f, 0xbe];
const MOVSX_WORD: [u8; 2] = [0x0f, 0xbf];
const MOVSXD: u8 = 0x63;
const MOV_LOAD: u8 = 0x8b;
const MOV_STORE: u8 = 0x89;
const MOV_STORE_BYTE: u8 = 0x88;
const MOVABS_RAX: [u8; 2] = [0x48, 0xb8];
const MOVABS_R10: [u8; 2] = [0x49, 0xba];
const MOVABS_R11: [u8; 2] = [0x49, 0xbb];
const SUB_RSP_IMM8: [u8; 3] = [0x48, 0x83, 0xec];
const ADD_RSP_IMM8: [u8; 3] = [0x48, 0x83, 0xc4];
const MOVDQU_STORE: [u8; 3] = [0xf3, 0x0f, 0x7f];
const MOVDQU_LOAD: [u8; 3] = [0xf3, 0x0f, 0x6f];
const IMUL_RCX: [u8; 3] = [0x48, 0xf7, 0xe9];
const NEG_RAX: [u8; 3] = [0x48, 0xf7, 0xd8];
const ADC_RDX_ZERO: [u8; 4] = [0x48, 0x83, 0xd2, 0x00];
const NEG_RDX: [u8; 3] = [0x48, 0xf7, 0xda];
const ADD_RAX_R10: [u8; 3] = [0x4c, 0x01, 0xd0];
const SHRD_RAX_RDX: [u8; 4] = [0x48, 0x0f, 0xac, 0xd0];
const SAR_RDX: [u8; 3] = [0x48, 0xc1, 0xfa];
const MOV_R8_R9: [u8; 3] = [0x4d, 0x89, 0xc8];
const SAR_R8: [u8; 3] = [0x49, 0xc1, 0xf8];
const ADD_RAX_R9: [u8; 3] = [0x4c, 0x01, 0xc8];
const ADC_RDX_R8: [u8; 3] = [0x4c, 0x11, 0xc2];
const MOV_R8_RAX: [u8; 3] = [0x49, 0x89, 0xc0];
const MOV_R10_RDX: [u8; 3] = [0x49, 0x89, 0xd2];
const SAR_R10: [u8; 3] = [0x49, 0xc1, 0xfa];
const XOR_R10_R11: [u8; 3] = [0x4d, 0x31, 0xda];
const CMP_RDX_R8: [u8; 3] = [0x4c, 0x39, 0xc2];
const CMOVNE_RAX_R10: [u8; 4] = [0x49, 0x0f, 0x45, 0xc2];
const CMP_RAX_R10: [u8; 3] = [0x4c, 0x39, 0xd0];
const CMOVG_RAX_R10: [u8; 4] = [0x49, 0x0f, 0x4f, 0xc2];
const CMP_RAX_R11: [u8; 3] = [0x4c, 0x39, 0xd8];
const CMOVL_RAX_R11: [u8; 4] = [0x49, 0x0f, 0x4c, 0xc3];
const SHLD_RDX_RAX_ONE: [u8; 5] = [0x48, 0x0f, 0xa4, 0xc2, 0x01];
const SHL_RAX_ONE: [u8; 3] = [0x48, 0xd1, 0xe0];
const CQO: [u8; 2] = [0x48, 0x99];
const MOV_R10_RAX: [u8; 3] = [0x49, 0x89, 0xc2];
const MOV_RAX_R9: [u8; 3] = [0x4c, 0x89, 0xc8];
const SUB_RAX_R10: [u8; 3] = [0x4c, 0x29, 0xd0];
const SBB_RDX_R8: [u8; 3] = [0x4c, 0x19, 0xc2];

fn constant(code: &mut Vec<u8>, register: u8, value: u64) {
    code.extend(MOVABS_RAX);
    code.extend(value.to_le_bytes());
    Host::MoveGprQword.append(code, TargetCpu::Baseline);
    code.push(MODRM_DIRECT | (register << MODRM_REGISTER_SHIFT));
    packed(code, Host::UnpackLowQword, register, register);
}

fn sign_extend_bytes(code: &mut Vec<u8>, register: u8, upper: u8, sign: u8) {
    packed(code, Host::MoveAligned, upper, register);
    packed(code, Host::Xor, sign, sign);
    packed(code, Host::GreaterByte, sign, register);
    packed(code, Host::UnpackLowByte, register, sign);
    packed(code, Host::UnpackHighByte, upper, sign);
}

fn negate_products(code: &mut Vec<u8>, word: bool) {
    let subtract = if word { Host::SubWord } else { Host::SubDword };
    packed(code, Host::Xor, RIGHT, RIGHT);
    packed(code, subtract, RIGHT, RESULT);
    packed(code, Host::MoveAligned, RESULT, RIGHT);
    packed(code, Host::Xor, SCRATCH, SCRATCH);
    packed(code, subtract, SCRATCH, UPPER_PRODUCT);
    packed(code, Host::MoveAligned, UPPER_PRODUCT, SCRATCH);
}

/// Eight byte products fit in each signed-word half. Sixteen-bit inputs use
/// PMULLW/PMULHW and interleave to retain every bit of each signed-dword product.
fn narrow_high(code: &mut Vec<u8>, element: ElementSize, rounding: bool, subtract: Option<bool>) {
    let bytes = element == ElementSize::Byte;
    if bytes {
        sign_extend_bytes(code, RESULT, UPPER_PRODUCT, LEFT_SIGN);
        sign_extend_bytes(code, RIGHT, SCRATCH, RIGHT_SIGN);
        packed(code, Host::MultiplyLowWord, RESULT, RIGHT);
        packed(code, Host::MultiplyLowWord, UPPER_PRODUCT, SCRATCH);
    } else {
        packed(code, Host::MoveAligned, UPPER_PRODUCT, RESULT);
        packed(code, Host::MultiplyLowWord, UPPER_PRODUCT, RIGHT);
        packed(code, Host::MultiplyHighSignedWord, RESULT, RIGHT);
        packed(code, Host::MoveAligned, SCRATCH, UPPER_PRODUCT);
        packed(code, Host::UnpackLowWord, UPPER_PRODUCT, RESULT);
        packed(code, Host::UnpackHighWord, SCRATCH, RESULT);
        packed(code, Host::MoveAligned, RESULT, UPPER_PRODUCT);
        packed(code, Host::MoveAligned, UPPER_PRODUCT, SCRATCH);
    }
    if subtract == Some(true) {
        negate_products(code, bytes);
    }
    if rounding {
        let lane_bits = element.bits() as u32;
        let round = 1u64 << (lane_bits - 2);
        let wide_bits = lane_bits * 2;
        let repeated = (0..QWORD_BITS / wide_bits)
            .fold(0, |value, lane| value | (round << (lane * wide_bits)));
        constant(code, RIGHT, repeated);
        let add = if bytes { Host::AddWord } else { Host::AddDword };
        packed(code, add, RESULT, RIGHT);
        packed(code, add, UPPER_PRODUCT, RIGHT);
    }
    let shift = if bytes {
        Shift::ArithmeticWord
    } else {
        Shift::ArithmeticDword
    };
    let count = element.bits() as u8 - 1;
    shift.emit(code, RESULT, count);
    shift.emit(code, UPPER_PRODUCT, count);
    if subtract.is_some() {
        if bytes {
            sign_extend_bytes(code, ACCUMULATOR, SCRATCH, LEFT_SIGN);
        } else {
            packed(code, Host::MoveAligned, SCRATCH, ACCUMULATOR);
            packed(code, Host::MoveAligned, LEFT_SIGN, ACCUMULATOR);
            Shift::ArithmeticWord.emit(code, LEFT_SIGN, WORD_BITS - 1);
            packed(code, Host::UnpackLowWord, ACCUMULATOR, LEFT_SIGN);
            packed(code, Host::UnpackHighWord, SCRATCH, LEFT_SIGN);
        }
        let add = if bytes { Host::AddWord } else { Host::AddDword };
        packed(code, add, RESULT, ACCUMULATOR);
        packed(code, add, UPPER_PRODUCT, SCRATCH);
    }
    let pack = if bytes {
        Host::PackSignedWordToByte
    } else {
        Host::PackSignedDwordToWord
    };
    packed(code, pack, RESULT, UPPER_PRODUCT);
}

fn select_narrow(code: &mut Vec<u8>, register: u8, top: bool, element: ElementSize) {
    let (left, right, narrow_bits) = match element {
        ElementSize::Halfword => (Shift::LeftWord, Shift::ArithmeticWord, BITS_PER_BYTE as u8),
        ElementSize::Word => (Shift::LeftDword, Shift::RightDword, WORD_BITS),
        _ => unreachable!("packed doubling-long destination"),
    };
    if !top {
        left.emit(code, register, narrow_bits);
    }
    right.emit(code, register, narrow_bits);
}

fn saturating_dword_accumulate(code: &mut Vec<u8>, subtract: bool) {
    packed(code, Host::MoveAligned, UPPER_PRODUCT, ACCUMULATOR);
    packed(
        code,
        if subtract {
            Host::SubDword
        } else {
            Host::AddDword
        },
        UPPER_PRODUCT,
        RESULT,
    );
    packed(code, Host::MoveAligned, SCRATCH, ACCUMULATOR);
    packed(code, Host::Xor, SCRATCH, UPPER_PRODUCT);
    packed(
        code,
        Host::MoveAligned,
        LEFT_SIGN,
        if subtract { ACCUMULATOR } else { RESULT },
    );
    packed(
        code,
        Host::Xor,
        LEFT_SIGN,
        if subtract { RESULT } else { UPPER_PRODUCT },
    );
    packed(code, Host::And, SCRATCH, LEFT_SIGN);
    Shift::ArithmeticDword.emit(code, SCRATCH, DWORD_BITS - 1);
    packed(code, Host::MoveAligned, LEFT_SIGN, ACCUMULATOR);
    Shift::ArithmeticDword.emit(code, LEFT_SIGN, DWORD_BITS - 1);
    packed(code, Host::EqualDword, RIGHT_SIGN, RIGHT_SIGN);
    Shift::RightDword.emit(code, RIGHT_SIGN, 1);
    packed(code, Host::Xor, LEFT_SIGN, RIGHT_SIGN);
    packed(code, Host::Xor, LEFT_SIGN, UPPER_PRODUCT);
    packed(code, Host::And, LEFT_SIGN, SCRATCH);
    packed(code, Host::Xor, LEFT_SIGN, UPPER_PRODUCT);
    packed(code, Host::MoveAligned, RESULT, LEFT_SIGN);
}

fn narrow_long(
    code: &mut Vec<u8>,
    element: ElementSize,
    accumulate: Accumulate,
    selection: Selection,
) {
    select_narrow(code, RESULT, selection == Selection::Top, element);
    select_narrow(code, RIGHT, selection != Selection::Bottom, element);
    if element == ElementSize::Halfword {
        packed(code, Host::MultiplyLowWord, RESULT, RIGHT);
        packed(code, Host::AddSignedSaturatingWord, RESULT, RESULT);
        match accumulate {
            Accumulate::None => {}
            Accumulate::Add => packed(code, Host::AddSignedSaturatingWord, RESULT, ACCUMULATOR),
            Accumulate::Subtract => {
                packed(code, Host::SubSignedSaturatingWord, ACCUMULATOR, RESULT);
                packed(code, Host::MoveAligned, RESULT, ACCUMULATOR);
            }
        }
    } else {
        // The upper halfword of each source is zero, so PMADDWD contributes one
        // signed product per dword, without the extra sign-extension product.
        packed(code, Host::MultiplyAddWords, RESULT, RIGHT);
        packed(code, Host::MoveAligned, UPPER_PRODUCT, RESULT);
        packed(code, Host::AddDword, RESULT, RESULT);
        packed(code, Host::Xor, UPPER_PRODUCT, RESULT);
        Shift::ArithmeticDword.emit(code, UPPER_PRODUCT, DWORD_BITS - 1);
        packed(code, Host::Xor, RESULT, UPPER_PRODUCT);
        if accumulate != Accumulate::None {
            saturating_dword_accumulate(code, accumulate == Accumulate::Subtract);
        }
    }
}

fn saturate_scalar(code: &mut Vec<u8>, bits: u32) {
    let maximum = (1u64 << (bits - 1)) - 1;
    if bits == QWORD_BITS {
        // A signed result fits iff the high half equals the sign extension of
        // the low half. The high half's sign chooses the appropriate endpoint.
        code.extend(MOV_R8_RAX);
        code.extend(SAR_R8);
        code.push(SIGN_SHIFT);
        code.extend(MOV_R10_RDX);
        code.extend(SAR_R10);
        code.push(SIGN_SHIFT);
        code.extend(MOVABS_R11);
        code.extend(maximum.to_le_bytes());
        code.extend(XOR_R10_R11);
        code.extend(CMP_RDX_R8);
        code.extend(CMOVNE_RAX_R10);
    } else {
        code.extend(MOVABS_R10);
        code.extend(maximum.to_le_bytes());
        code.extend(MOVABS_R11);
        code.extend((!maximum).to_le_bytes());
        code.extend(CMP_RAX_R10);
        code.extend(CMOVG_RAX_R10);
        code.extend(CMP_RAX_R11);
        code.extend(CMOVL_RAX_R11);
    }
}

fn shifted_product(code: &mut Vec<u8>, bits: u32, rounding: bool, subtract: bool) {
    code.extend(IMUL_RCX);
    if subtract {
        code.extend(NEG_RAX);
        code.extend(ADC_RDX_ZERO);
        code.extend(NEG_RDX);
    }
    if rounding {
        code.extend(MOVABS_R10);
        code.extend((1u64 << (bits - 2)).to_le_bytes());
        code.extend(ADD_RAX_R10);
        code.extend(ADC_RDX_ZERO);
    }
    let shift = (bits - 1) as u8;
    code.extend(SHRD_RAX_RDX);
    code.push(shift);
    code.extend(SAR_RDX);
    code.push(shift);
}

/// Exact rounded doubling-high accumulation for a signed lane. Inputs are lhs
/// RAX, rhs RCX and accumulator R9; output RAX, clobber RDX/R8/R10/R11. Keeping
/// the shifted product wide also represents the positive 2^63 min*min quotient.
/// Rounding after adding the integral accumulator is exactly equivalent to
/// adding it after the wide product's arithmetic shift, including subtraction.
pub(super) fn emit_rounded_scalar(code: &mut Vec<u8>, bits: u32, subtract: bool) {
    shifted_product(code, bits, true, subtract);
    code.extend(MOV_R8_R9);
    code.extend(SAR_R8);
    code.push(SIGN_SHIFT);
    code.extend(ADD_RAX_R9);
    code.extend(ADC_RDX_R8);
    saturate_scalar(code, bits);
}

fn scalar_long(code: &mut Vec<u8>, bits: u32, accumulate: Accumulate) {
    code.extend(IMUL_RCX);
    code.extend(SHLD_RDX_RAX_ONE);
    code.extend(SHL_RAX_ONE);
    saturate_scalar(code, bits);
    if accumulate == Accumulate::None {
        return;
    }
    if accumulate == Accumulate::Add {
        code.extend(CQO);
        code.extend(MOV_R8_R9);
        code.extend(SAR_R8);
        code.push(SIGN_SHIFT);
        code.extend(ADD_RAX_R9);
        code.extend(ADC_RDX_R8);
    } else {
        code.extend(MOV_R10_RAX);
        code.extend(MOV_R8_RAX);
        code.extend(SAR_R8);
        code.push(SIGN_SHIFT);
        code.extend(MOV_RAX_R9);
        code.extend(CQO);
        code.extend(SUB_RAX_R10);
        code.extend(SBB_RDX_R8);
    }
    saturate_scalar(code, bits);
}

#[derive(Clone, Copy)]
enum ScalarInput {
    Left,
    Right,
    Accumulator,
}

fn load_scalar(code: &mut Vec<u8>, input: ScalarInput, bytes: usize, offset: usize) {
    let (rex, register) = match input {
        ScalarInput::Left => (REX_W, 0),
        ScalarInput::Right => (REX_W, 1),
        ScalarInput::Accumulator => (REX_WR, 1),
    };
    code.push(rex);
    match bytes {
        1 => code.extend(MOVSX_BYTE),
        2 => code.extend(MOVSX_WORD),
        4 => code.push(MOVSXD),
        8 => code.push(MOV_LOAD),
        _ => unreachable!("allocated signed lane width"),
    }
    code.extend([
        MODRM_STACK_DISP8 | (register << MODRM_REGISTER_SHIFT),
        SIB_STACK,
        offset as u8,
    ]);
}

fn store_scalar(code: &mut Vec<u8>, bytes: usize, offset: usize) {
    match bytes {
        1 => code.push(MOV_STORE_BYTE),
        2 => code.extend([WORD_PREFIX, MOV_STORE]),
        4 => code.push(MOV_STORE),
        8 => code.extend([REX_W, MOV_STORE]),
        _ => unreachable!("allocated result lane width"),
    }
    code.extend([MODRM_STACK_DISP8, SIB_STACK, offset as u8]);
}

fn stack_chunk(code: &mut Vec<u8>, register: u8, offset: usize, load: bool) {
    code.extend(if load { MOVDQU_LOAD } else { MOVDQU_STORE });
    code.extend([
        MODRM_STACK_DISP8 | (register << MODRM_REGISTER_SHIFT),
        SIB_STACK,
        offset as u8,
    ]);
}

fn scalar_chunk(code: &mut Vec<u8>, kind: Kind, element: ElementSize) {
    code.extend(SUB_RSP_IMM8);
    code.push(STACK_BYTES);
    stack_chunk(code, RESULT, STACK_LEFT, false);
    stack_chunk(code, RIGHT, STACK_RIGHT, false);
    stack_chunk(code, ACCUMULATOR, STACK_ACCUMULATOR, false);
    let bytes = element.bytes();
    let bits = element.bits() as u32;
    for lane in 0..CHUNK_BYTES / bytes {
        let (source_bytes, left_offset, right_offset) = match kind {
            Kind::Long { selection, .. } => {
                let narrow = bytes / 2;
                (
                    narrow,
                    lane * bytes
                        + if selection == Selection::Top {
                            narrow
                        } else {
                            0
                        },
                    lane * bytes
                        + if selection == Selection::Bottom {
                            0
                        } else {
                            narrow
                        },
                )
            }
            _ => (bytes, lane * bytes, lane * bytes),
        };
        load_scalar(
            code,
            ScalarInput::Left,
            source_bytes,
            STACK_LEFT + left_offset,
        );
        load_scalar(
            code,
            ScalarInput::Right,
            source_bytes,
            STACK_RIGHT + right_offset,
        );
        if kind.accumulating() {
            load_scalar(
                code,
                ScalarInput::Accumulator,
                bytes,
                STACK_ACCUMULATOR + lane * bytes,
            );
        }
        match kind {
            Kind::DoublingHigh { rounding } => {
                shifted_product(code, bits, rounding, false);
                saturate_scalar(code, bits);
            }
            Kind::RoundedHighAccumulate { subtract } => emit_rounded_scalar(code, bits, subtract),
            Kind::Long { accumulate, .. } => scalar_long(code, bits, accumulate),
            _ => unreachable!("saturating product kind"),
        }
        store_scalar(code, bytes, STACK_LEFT + lane * bytes);
    }
    stack_chunk(code, RESULT, STACK_LEFT, true);
    code.extend(ADD_RSP_IMM8);
    code.push(STACK_BYTES);
}

/// Chunk ABI: XMM0/1 are staged sources, XMM4 the old accumulator; XMM7 is
/// preserved for the caller's merge. Indexed operands are already broadcast at
/// source width. Result XMM0; scratch XMM1..6 and caller-saved integer registers.
pub(crate) fn emit_chunk(code: &mut Vec<u8>, kind: Kind, element: ElementSize) {
    match kind {
        Kind::DoublingHigh { rounding } if element.bytes() <= 2 => {
            narrow_high(code, element, rounding, None)
        }
        Kind::RoundedHighAccumulate { subtract } if element.bytes() <= 2 => {
            narrow_high(code, element, true, Some(subtract))
        }
        Kind::Long {
            doubling: true,
            accumulate,
            selection,
            ..
        } if element.bytes() <= 4 => narrow_long(code, element, accumulate, selection),
        Kind::DoublingHigh { .. }
        | Kind::RoundedHighAccumulate { .. }
        | Kind::Long { doubling: true, .. } => scalar_chunk(code, kind, element),
        _ => unreachable!("caller selects saturating product kinds"),
    }
}

/// The checked SSSE3 rounded-halfword recipe also needs the positive min*min
/// endpoint repaired: PMULHRSW wraps that unique result to -32768. All other
/// rounded products are within [-32767, 32767], so equality identifies it
/// exactly. Flipping that lane's bits produces the required saturated +32767.
pub(super) fn emit_chunk_for_target(
    code: &mut Vec<u8>,
    kind: Kind,
    element: ElementSize,
    target: TargetCpu,
) {
    if kind == (Kind::DoublingHigh { rounding: true })
        && element == ElementSize::Halfword
        && target.supports(TargetCpu::Ssse3)
    {
        Host::MultiplyHighRoundedScaledWord.register(code, RESULT, RIGHT, target);
        constant(code, UPPER_PRODUCT, MIN_HALFWORD_PATTERN);
        packed(code, Host::EqualWord, UPPER_PRODUCT, RESULT);
        packed(code, Host::Xor, RESULT, UPPER_PRODUCT);
    } else {
        emit_chunk(code, kind, element);
    }
}
