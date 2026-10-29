//! SVE signed saturating multiplies. Narrow products widen before rounding;
//! doubleword products keep both IMUL halves until saturation.
use super::packed;
use crate::TargetCpu;
use crate::aarch64::scalable::ElementSize;
use crate::aarch64::sve::integer_products::{Accumulate, Kind, Selection};
use crate::x86_64::asm::Gpr::{R8, R9, R10, R11, Rax, Rcx, Rdx, Rsp};
use crate::x86_64::asm::{Alu, Code, Cond, Mem, ShiftOp, Size, Unary};
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};

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

fn constant(code: &mut Code, register: u8, value: u64) {
    let mut asm = code.asm();
    asm.mov_imm64(Rax, value);
    asm.simd(Host::MoveGprQword, register, Rax, TargetCpu::Baseline);
    packed(code, Host::UnpackLowQword, register, register);
}

fn sign_extend_bytes(code: &mut Code, register: u8, upper: u8, sign: u8) {
    packed(code, Host::MoveAligned, upper, register);
    packed(code, Host::Xor, sign, sign);
    packed(code, Host::GreaterByte, sign, register);
    packed(code, Host::UnpackLowByte, register, sign);
    packed(code, Host::UnpackHighByte, upper, sign);
}

fn negate_products(code: &mut Code, word: bool) {
    let subtract = if word { Host::SubWord } else { Host::SubDword };
    packed(code, Host::Xor, RIGHT, RIGHT);
    packed(code, subtract, RIGHT, RESULT);
    packed(code, Host::MoveAligned, RESULT, RIGHT);
    packed(code, Host::Xor, SCRATCH, SCRATCH);
    packed(code, subtract, SCRATCH, UPPER_PRODUCT);
    packed(code, Host::MoveAligned, UPPER_PRODUCT, SCRATCH);
}

/// Eight byte products fit in each signed-word half. Sixteen-bit inputs use
/// PMULLW/PMULHW and interleave to keep every bit of each signed-dword product.
fn narrow_high(code: &mut Code, element: ElementSize, rounding: bool, subtract: Option<bool>) {
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

fn select_narrow(code: &mut Code, register: u8, top: bool, element: ElementSize) {
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

fn saturating_dword_accumulate(code: &mut Code, subtract: bool) {
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
    code: &mut Code,
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

fn saturate_scalar(code: &mut Code, bits: u32) {
    let maximum = (1u64 << (bits - 1)) - 1;
    if bits == QWORD_BITS {
        // A signed result fits iff the high half equals the sign extension of
        // the low half. The high half's sign chooses the appropriate endpoint.
        let mut asm = code.asm();
        asm.mov(Size::Qword, R8, Rax);
        asm.shift_imm(ShiftOp::Sar, Size::Qword, R8, SIGN_SHIFT);
        asm.mov(Size::Qword, R10, Rdx);
        asm.shift_imm(ShiftOp::Sar, Size::Qword, R10, SIGN_SHIFT);
        asm.mov_imm64(R11, maximum);
        asm.alu(Alu::Xor, Size::Qword, R10, R11);
        asm.alu(Alu::Cmp, Size::Qword, Rdx, R8);
        asm.cmov(Cond::Ne, Size::Qword, Rax, R10);
    } else {
        let mut asm = code.asm();
        asm.mov_imm64(R10, maximum);
        asm.mov_imm64(R11, !maximum);
        asm.alu(Alu::Cmp, Size::Qword, Rax, R10);
        asm.cmov(Cond::G, Size::Qword, Rax, R10);
        asm.alu(Alu::Cmp, Size::Qword, Rax, R11);
        asm.cmov(Cond::L, Size::Qword, Rax, R11);
    }
}

fn shifted_product(code: &mut Code, bits: u32, rounding: bool, subtract: bool) {
    code.asm().unary(Unary::Imul, Size::Qword, Rcx);
    if subtract {
        let mut asm = code.asm();
        asm.unary(Unary::Neg, Size::Qword, Rax);
        asm.alu_imm8(Alu::Adc, Size::Qword, Rdx, 0);
        asm.unary(Unary::Neg, Size::Qword, Rdx);
    }
    if rounding {
        let mut asm = code.asm();
        asm.mov_imm64(R10, 1u64 << (bits - 2));
        asm.alu(Alu::Add, Size::Qword, Rax, R10);
        asm.alu_imm8(Alu::Adc, Size::Qword, Rdx, 0);
    }
    let shift = (bits - 1) as u8;
    let mut asm = code.asm();
    asm.shrd_imm(Size::Qword, Rax, Rdx, shift);
    asm.shift_imm(ShiftOp::Sar, Size::Qword, Rdx, shift);
}

/// Exact rounded doubling-high accumulation for a signed lane. Inputs are lhs
/// RAX, rhs RCX and accumulator R9; output RAX, clobber RDX/R8/R10/R11. Keeping
/// the shifted product wide also represents the positive 2^63 min*min quotient.
/// Rounding after adding the integral accumulator is exactly equivalent to
/// adding it after the wide product's arithmetic shift, including subtraction.
pub(super) fn emit_rounded_scalar(code: &mut Code, bits: u32, subtract: bool) {
    shifted_product(code, bits, true, subtract);
    let mut asm = code.asm();
    asm.mov(Size::Qword, R8, R9);
    asm.shift_imm(ShiftOp::Sar, Size::Qword, R8, SIGN_SHIFT);
    asm.alu(Alu::Add, Size::Qword, Rax, R9);
    asm.alu(Alu::Adc, Size::Qword, Rdx, R8);
    saturate_scalar(code, bits);
}

fn scalar_long(code: &mut Code, bits: u32, accumulate: Accumulate) {
    let mut asm = code.asm();
    asm.unary(Unary::Imul, Size::Qword, Rcx);
    asm.shld_imm(Size::Qword, Rdx, Rax, 1);
    asm.shift_one(ShiftOp::Shl, Size::Qword, Rax);
    saturate_scalar(code, bits);
    if accumulate == Accumulate::None {
        return;
    }
    if accumulate == Accumulate::Add {
        let mut asm = code.asm();
        asm.sign_extend_accumulator(Size::Qword);
        asm.mov(Size::Qword, R8, R9);
        asm.shift_imm(ShiftOp::Sar, Size::Qword, R8, SIGN_SHIFT);
        asm.alu(Alu::Add, Size::Qword, Rax, R9);
        asm.alu(Alu::Adc, Size::Qword, Rdx, R8);
    } else {
        let mut asm = code.asm();
        asm.mov(Size::Qword, R10, Rax);
        asm.mov(Size::Qword, R8, Rax);
        asm.shift_imm(ShiftOp::Sar, Size::Qword, R8, SIGN_SHIFT);
        asm.mov(Size::Qword, Rax, R9);
        asm.sign_extend_accumulator(Size::Qword);
        asm.alu(Alu::Sub, Size::Qword, Rax, R10);
        asm.alu(Alu::Sbb, Size::Qword, Rdx, R8);
    }
    saturate_scalar(code, bits);
}

#[derive(Clone, Copy)]
enum ScalarInput {
    Left,
    Right,
    Accumulator,
}

fn stack(offset: usize) -> Mem {
    Mem::base_disp8(Rsp, offset as i8)
}

fn load_scalar(code: &mut Code, input: ScalarInput, bytes: usize, offset: usize) {
    let destination = match input {
        ScalarInput::Left => Rax,
        ScalarInput::Right => Rcx,
        ScalarInput::Accumulator => R9,
    };
    let source = stack(offset);
    let mut asm = code.asm();
    match bytes {
        1 => asm.movsx(Size::Qword, destination, Size::Byte, source),
        2 => asm.movsx(Size::Qword, destination, Size::Word, source),
        4 => asm.movsxd(destination, source),
        8 => asm.mov_load(Size::Qword, destination, source),
        _ => unreachable!("allocated signed lane width"),
    }
}

fn store_scalar(code: &mut Code, bytes: usize, offset: usize) {
    let size = match bytes {
        1 => Size::Byte,
        2 => Size::Word,
        4 => Size::Dword,
        8 => Size::Qword,
        _ => unreachable!("allocated result lane width"),
    };
    code.asm().mov_store(size, stack(offset), Rax);
}

fn stack_chunk(code: &mut Code, register: u8, offset: usize, load: bool) {
    let mut asm = code.asm();
    if load {
        asm.movdqu_load(register, stack(offset));
    } else {
        asm.movdqu_store(stack(offset), register);
    }
}

fn scalar_chunk(code: &mut Code, kind: Kind, element: ElementSize) {
    code.asm()
        .alu_imm8(Alu::Sub, Size::Qword, Rsp, STACK_BYTES as i8);
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
    code.asm()
        .alu_imm8(Alu::Add, Size::Qword, Rsp, STACK_BYTES as i8);
}

/// Chunk ABI: XMM0/1 are staged sources, XMM4 the old accumulator; XMM7 is
/// preserved for the caller's merge. Indexed operands are already broadcast at
/// source width. Result XMM0; scratch XMM1..6 and caller-saved integer registers.
pub(crate) fn emit_chunk(code: &mut Code, kind: Kind, element: ElementSize) {
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
    code: &mut Code,
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
