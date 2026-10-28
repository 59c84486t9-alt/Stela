//! SME2 integer dot products, including 16-to-64-bit products.
use crate::x86_64::asm::{Alu, Code, Gpr, ShiftOp, Size};
use crate::x86_64::simd::encode::guest;
use crate::{
    GuestState, TargetCpu,
    aarch64::{
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sme::integer_dots::{Kind, Operand, RightSource},
    },
    x86_64::{
        isa::{ShiftOpcode as Shift, SimdOpcode as Host},
        scalable::load_z_chunk,
        scalable_matrix::{load_za_chunk_at_r8, load_za_pointer_r8, store_za_chunk_at_r8},
        sme::integer_products::{
            PRODUCT_HIGH as UPPER_RIGHT, PRODUCT_LEFT as LEFT, PRODUCT_RIGHT as RIGHT,
            PRODUCT_TEMPORARY as UPPER_LEFT, word_products,
        },
    },
};

const ACCUMULATOR: u8 = 2;
const TEMPORARY: u8 = 5;
const SIGN_MASK: u8 = 6;
const VERTICAL_MASK: u8 = 7;
const SWAP_ADJACENT_DWORDS: u8 = 0xb1;
const PACK_EVEN_DWORDS: u8 = 0x88;
const SWAP_QWORDS: u8 = 0x4e;
const REPEAT_LOW_DWORD: u8 = 0;
const REPEAT_LOW_QWORD: u8 = 0x44;
const REPEAT_HIGH_QWORD: u8 = 0xee;
const DWORD_SIGN_SHIFT: u8 = 31;
const GPR_BYTES: u32 = core::mem::size_of::<u64>() as u32;
const BROADCAST_DWORD_INDEX: u8 = 0x55;
// At 16 bytes the longer SSE2 reduction wins for ordinary dots; 64-byte
// candidates favor PHADDD. Unmeasured 32-byte ordinary shapes stay on SSE2.
const MIN_PHADDD_VECTOR_BYTES: usize = 64;

fn copy(code: &mut Code, destination: u8, source: u8, target: TargetCpu) {
    Host::MoveAligned.register(code, destination, source, target);
}

fn shuffle(code: &mut Code, destination: u8, source: u8, control: u8, target: TargetCpu) {
    Host::ShuffleDword.register_imm(code, destination, source, control, target);
}

/// ZA pointer stays in caller-saved R8; shared Z helpers clobber only RDX.
fn za_pointer(code: &mut Code, operand: &Operand, length: VectorLength) {
    load_za_pointer_r8(code);
    let mut asm = code.asm();
    asm.mov_load(
        Size::Dword,
        Gpr::Rcx,
        guest(
            core::mem::offset_of!(GuestState, x) as u32 + u32::from(operand.selector) * GPR_BYTES,
        ),
    );
    // Partition rows are powers of two dividing 2^32. ECX wrap therefore
    // preserves (UInt(Wselector)+offset) modulo the selected partition.
    if operand.offset != 0 {
        asm.alu_imm8(Alu::Add, Size::Dword, Gpr::Rcx, operand.offset as i8);
    }
    let partition_rows = length.bytes() / usize::from(operand.groups);
    asm.alu_imm32(Alu::And, Size::Dword, Gpr::Rcx, (partition_rows - 1) as i32);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Qword,
        Gpr::Rcx,
        length.bytes().trailing_zeros() as u8,
    );
    asm.alu(Alu::Add, Size::Qword, Gpr::R8, Gpr::Rcx);
}

fn vertical_mask(code: &mut Code, operand: &Operand, target: TargetCpu) {
    let source_bits = operand.accumulator.bits() / usize::from(operand.terms);
    let mut asm = code.asm();
    asm.mov_imm32(Gpr::Rax, (1u32 << source_bits) - 1);
    asm.movd_to_xmm(VERTICAL_MASK, Gpr::Rax);
    shuffle(
        code,
        VERTICAL_MASK,
        VERTICAL_MASK,
        if operand.accumulator == ElementSize::Doubleword {
            REPEAT_LOW_QWORD
        } else {
            REPEAT_LOW_DWORD
        },
        target,
    );
}

fn left_chunk(
    code: &mut Code,
    operand: &Operand,
    group: u8,
    chunk: usize,
    length: VectorLength,
    target: TargetCpu,
) {
    if operand.kind == Kind::Dot {
        load_z_chunk(
            code,
            operand.left_register(group, 0),
            chunk,
            LEFT,
            length,
            target,
        );
        return;
    }
    let source_bits = (operand.accumulator.bits() / usize::from(operand.terms)) as u8;
    let (right_shift, left_shift) = if operand.accumulator == ElementSize::Doubleword {
        (Shift::RightQword, Shift::LeftQword)
    } else {
        (Shift::RightDword, Shift::LeftDword)
    };
    for term in 0..operand.terms {
        let destination = if term == 0 { LEFT } else { UPPER_LEFT };
        load_z_chunk(
            code,
            operand.left_register(group, term),
            chunk,
            destination,
            length,
            target,
        );
        if group != 0 {
            right_shift.emit(code, destination, source_bits * group);
        }
        Host::And.register(code, destination, VERTICAL_MASK, target);
        if term != 0 {
            left_shift.emit(code, destination, source_bits * term);
            Host::Or.register(code, LEFT, destination, target);
        }
    }
}

fn adjacent_pair_sums(code: &mut Code, low: u8, high: u8, target: TargetCpu, horizontal: bool) {
    if horizontal {
        Host::HorizontalAddDword.register(code, low, high, target);
        return;
    }
    shuffle(code, RIGHT, low, SWAP_ADJACENT_DWORDS, target);
    Host::AddDword.register(code, low, RIGHT, target);
    shuffle(code, UPPER_RIGHT, high, SWAP_ADJACENT_DWORDS, target);
    Host::AddDword.register(code, high, UPPER_RIGHT, target);
    shuffle(code, low, low, PACK_EVEN_DWORDS, target);
    shuffle(code, high, high, PACK_EVEN_DWORDS, target);
    Host::UnpackLowQword.register(code, low, high, target);
}

fn extend_bytes(code: &mut Code, low: u8, high: u8, signed: bool, target: TargetCpu) {
    copy(code, high, low, target);
    Host::Xor.register(code, SIGN_MASK, SIGN_MASK, target);
    if signed {
        Host::GreaterByte.register(code, SIGN_MASK, low, target);
    }
    Host::UnpackLowByte.register(code, low, SIGN_MASK, target);
    Host::UnpackHighByte.register(code, high, SIGN_MASK, target);
}

/// Four exact 32-bit products become a duplicated 64-bit sum. Widen first:
/// PMADDWD's 0x8000*0x8000 pair overflow cannot be sign-extended to 64 bits.
fn reduce_four_products(code: &mut Code, source: u8, signed: bool, target: TargetCpu) {
    if signed {
        copy(code, SIGN_MASK, source, target);
        Shift::ArithmeticDword.emit(code, SIGN_MASK, DWORD_SIGN_SHIFT);
    } else {
        Host::Xor.register(code, SIGN_MASK, SIGN_MASK, target);
    }
    copy(code, TEMPORARY, source, target);
    Host::UnpackLowDword.register(code, source, SIGN_MASK, target);
    Host::UnpackHighDword.register(code, TEMPORARY, SIGN_MASK, target);
    Host::AddQword.register(code, source, TEMPORARY, target);
    shuffle(code, TEMPORARY, source, SWAP_QWORDS, target);
    Host::AddQword.register(code, source, TEMPORARY, target);
}

/// XMM0/1 inputs, XMM2 accumulator, XMM0 result; XMM3..6 scratch, XMM7 preserved.
fn dot_chunk(code: &mut Code, operand: &Operand, target: TargetCpu, horizontal: bool) {
    if operand.accumulator == ElementSize::Doubleword {
        word_products(code, operand.left_signed, target);
        reduce_four_products(code, LEFT, operand.left_signed, target);
        reduce_four_products(code, UPPER_RIGHT, operand.left_signed, target);
        Host::UnpackLowQword.register(code, LEFT, UPPER_RIGHT, target);
        Host::AddQword.register(code, LEFT, ACCUMULATOR, target);
    } else if operand.terms == 2 && operand.left_signed {
        Host::MultiplyAddWords.register(code, LEFT, RIGHT, target);
        Host::AddDword.register(code, LEFT, ACCUMULATOR, target);
    } else if operand.terms == 2 {
        word_products(code, false, target);
        // High products occupy XMM4, which the reduction uses as scratch.
        copy(code, UPPER_LEFT, UPPER_RIGHT, target);
        adjacent_pair_sums(code, LEFT, UPPER_LEFT, target, horizontal);
        Host::AddDword.register(code, LEFT, ACCUMULATOR, target);
    } else {
        extend_bytes(code, LEFT, UPPER_LEFT, operand.left_signed, target);
        extend_bytes(code, RIGHT, UPPER_RIGHT, operand.right_signed, target);
        Host::MultiplyAddWords.register(code, LEFT, RIGHT, target);
        Host::MultiplyAddWords.register(code, UPPER_LEFT, UPPER_RIGHT, target);
        adjacent_pair_sums(code, LEFT, UPPER_LEFT, target, horizontal);
        Host::AddDword.register(code, LEFT, ACCUMULATOR, target);
    }
}

/// Caller validates SME2, SM+ZA, SVL and I16I64 before entry. This unpredicated
/// family touches only selected ZA vectors; all Z/P/flags/control state survives.
pub(crate) fn emit(code: &mut Code, operand: &Operand, length: VectorLength, target: TargetCpu) {
    za_pointer(code, operand, length);
    if operand.kind == Kind::VerticalDot {
        vertical_mask(code, operand, target);
    }
    let horizontal = target.supports(TargetCpu::Ssse3)
        && operand.terms == 4
        && operand.accumulator == ElementSize::Word
        && (operand.kind == Kind::VerticalDot || length.bytes() >= MIN_PHADDD_VECTOR_BYTES);
    let partition_bytes = length.bytes() * length.bytes() / usize::from(operand.groups);
    for group in 0..operand.groups {
        for chunk in 0..length.chunks() {
            left_chunk(code, operand, group, chunk, length, target);
            load_z_chunk(
                code,
                operand.right_register(group),
                chunk,
                RIGHT,
                length,
                target,
            );
            if let RightSource::Indexed { index, .. } = operand.right {
                let control = if operand.accumulator == ElementSize::Doubleword {
                    if index == 0 {
                        REPEAT_LOW_QWORD
                    } else {
                        REPEAT_HIGH_QWORD
                    }
                } else {
                    index * BROADCAST_DWORD_INDEX
                };
                shuffle(code, RIGHT, RIGHT, control, target);
            }
            let displacement =
                (usize::from(group) * partition_bytes + chunk * VECTOR_CHUNK_BYTES) as u32;
            load_za_chunk_at_r8(code, ACCUMULATOR, displacement, target);
            dot_chunk(code, operand, target, horizontal);
            store_za_chunk_at_r8(code, LEFT, displacement, target);
        }
    }
}
