//! LUTI2/LUTI4 from ZT0 with scalar gathers, SSE2 selects and SSSE3 shuffles.
//! ZT0 entries always have a 32-bit stride. Scratch registers are XMM0-7.
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, ShiftOp, Size};
use crate::x86_64::simd::encode::stack;

pub(super) mod lut_v2;

use super::{allocate_frame, release_frame, stack_chunk, stage};
use crate::TargetCpu;
use crate::aarch64::scalable::{
    BITS_PER_BYTE, ElementSize, LOOKUP_TABLE_BYTES, VECTOR_CHUNK_BYTES, VectorLength,
};
use crate::aarch64::sme::tables::Operand;
use crate::context::{EXECUTION_CONTEXT_SCALABLE_OFFSET, SCALABLE_ZT0_OFFSET};
use crate::x86_64::isa::{ShiftOpcode, SimdOpcode as Host};
use crate::x86_64::scalable::store_z_chunk;

const LUTI2_INDEX_BITS: u8 = 2;
const LUTI4_INDEX_BITS: u8 = 4;
const LUTI2_TABLE_ENTRIES: u8 = 1 << LUTI2_INDEX_BITS;
const ZT0_CHUNKS: u8 = (LOOKUP_TABLE_BYTES / VECTOR_CHUNK_BYTES) as u8;
const REPEAT_FIRST_ELEMENT: u8 = 0;
const DWORD_REPEAT_SELECTORS: [u8; 4] = [0x00, 0x55, 0xaa, 0xff];
const BYTE_SIGN_BIT: u8 = u8::BITS as u8 - 1;
const HALFWORD_SIGN_BIT: u8 = u16::BITS as u8 - 1;
const FIRST_INDEX_SPREAD_SHIFT: u8 = 12;
const SECOND_INDEX_SPREAD_SHIFT: u8 = 6;
const TABLE_ENTRY_BYTE_SHIFT: u8 = 2;
const NIBBLE_BITS: u8 = 4;
const XMM0: u8 = 0;
const XMM1: u8 = 1;
const XMM2: u8 = 2;
const XMM3: u8 = 3;
const XMM4: u8 = 4;
const XMM5: u8 = 5;
const XMM6: u8 = 6;
const XMM7: u8 = 7;
/// R8 points at ZT0 while a lookup runs.
const TABLE: Gpr = Gpr::R8;

const INDEX_SPLIT_NIBBLE_MASK: u32 = 0x000f_000f;
const TWO_BIT_BYTE_MASK: u32 = 0x0303_0303;
const FOUR_BIT_BYTE_MASK: u32 = 0x0f0f_0f0f;
const LOW_DWORD_BYTE_MASK: u32 = 0x0000_00ff;
const HALFWORD_BYTE_OFFSETS: u32 = 0x0100_0100;
const DWORD_BYTE_OFFSETS: u32 = 0x0302_0100;
const LOCAL_BYTE_TRANSPOSE_LOW: u64 = 0x0d09_0501_0c08_0400;
const LOCAL_BYTE_TRANSPOSE_HIGH: u64 = 0x0f0b_0703_0e0a_0602;

// Four output chunks is the first allocated size where halfword polynomial
// expansion wins both emitted bytes and instructions; two chunks remain scalar.
const MIN_POLYNOMIAL_HALFWORD_OUTPUT_CHUNKS: usize = 4;

fn stage_source_and_table(
    code: &mut Code,
    source: u8,
    frame_bytes: usize,
    length: VectorLength,
    target: TargetCpu,
) {
    allocate_frame(code, frame_bytes);
    stage(code, &[source], length, target);
    table_pointer(code);
}

/// `mov r8, [r15 + scalable]; mov r8, [r8 + zt0]`: R8 points at ZT0.
fn table_pointer(code: &mut Code) {
    let mut asm = code.asm();
    asm.mov_load(
        Size::Qword,
        TABLE,
        Mem::base_disp8(Gpr::R15, EXECUTION_CONTEXT_SCALABLE_OFFSET as i8),
    );
    asm.mov_load(
        Size::Qword,
        TABLE,
        Mem::base_disp8(TABLE, SCALABLE_ZT0_OFFSET as i8),
    );
}

fn lookup_scalar(
    code: &mut Code,
    operand: &Operand,
    source: u8,
    index_bits: u8,
    immediate: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    let frame_bytes = length.bytes() + VECTOR_CHUNK_BYTES;
    let output_offset = length.bytes();
    stage_source_and_table(code, source, frame_bytes, length, target);
    let elements = length.lanes(operand.element);
    let count = usize::from(operand.destination.count);
    let segments = operand.element.bits() / (usize::from(index_bits) * count);
    let segment = usize::from(immediate) % segments;
    for destination_index in 0..count {
        let base = (segment * count + destination_index) * elements;
        for chunk in 0..length.chunks() {
            for lane in 0..VECTOR_CHUNK_BYTES / operand.element.bytes() {
                let global_lane = chunk * (VECTOR_CHUNK_BYTES / operand.element.bytes()) + lane;
                let index_bit = (base + global_lane) * usize::from(index_bits);
                let mut asm = code.asm();
                asm.movzx(
                    Size::Dword,
                    Gpr::Rax,
                    Size::Byte,
                    stack(index_bit / BITS_PER_BYTE),
                );
                if !index_bit.is_multiple_of(BITS_PER_BYTE) {
                    asm.shift_imm(
                        ShiftOp::Shr,
                        Size::Dword,
                        Gpr::Rax,
                        (index_bit % BITS_PER_BYTE) as u8,
                    );
                }
                asm.alu_imm8(
                    Alu::And,
                    Size::Dword,
                    Gpr::Rax,
                    ((1 << index_bits) - 1) as i8,
                );
                // All ZT0 entries are 32 bits, even for Byte/Halfword outputs.
                asm.mov_load(Size::Dword, Gpr::Rdx, Mem::indexed(TABLE, Gpr::Rax, 4, 0));
                let size = match operand.element {
                    ElementSize::Byte => Size::Byte,
                    ElementSize::Halfword => Size::Word,
                    ElementSize::Word => Size::Dword,
                    _ => unreachable!("LUTI output is at most Word"),
                };
                asm.mov_store(
                    size,
                    stack(output_offset + lane * operand.element.bytes()),
                    Gpr::Rdx,
                );
            }
            stack_chunk(code, true, output_offset, XMM0, target);
            store_z_chunk(
                code,
                operand.destination.register(destination_index as u8),
                chunk,
                XMM0,
                length,
                target,
            );
        }
    }
    release_frame(code, frame_bytes);
}

fn splat_dword(code: &mut Code, xmm: u8, value: u32, target: TargetCpu) {
    let mut asm = code.asm();
    asm.mov_imm32(Gpr::Rax, value);
    asm.movd_to_xmm(xmm, Gpr::Rax);
    Host::ShuffleDword.register_imm(code, xmm, xmm, REPEAT_FIRST_ELEMENT, target);
}
fn qword_constant(code: &mut Code, xmm: u8, value: u64) {
    let mut asm = code.asm();
    asm.mov_imm64(Gpr::Rax, value);
    asm.movq_to_xmm(xmm, Gpr::Rax);
}
fn transpose_constant(code: &mut Code, target: TargetCpu) {
    qword_constant(code, XMM0, LOCAL_BYTE_TRANSPOSE_LOW);
    qword_constant(code, XMM1, LOCAL_BYTE_TRANSPOSE_HIGH);
    Host::UnpackLowQword.register(code, XMM0, XMM1, target);
}
fn load_table_chunk(code: &mut Code, xmm: u8, offset: u8) {
    Host::LoadUnaligned.emit(
        code,
        xmm,
        Mem::base_disp8(TABLE, offset as i8),
        TargetCpu::Baseline,
    );
}
fn prepare_planes(code: &mut Code, element: ElementSize, target: TargetCpu) {
    for i in 0..ZT0_CHUNKS {
        load_table_chunk(code, XMM4 + i, i * VECTOR_CHUNK_BYTES as u8);
    }
    if element == ElementSize::Byte {
        splat_dword(code, XMM0, LOW_DWORD_BYTE_MASK, target);
        for i in XMM4..=XMM7 {
            Host::And.register(code, i, XMM0, target);
        }
        Host::PackSignedDwordToWord.register(code, XMM4, XMM5, target);
        Host::PackSignedDwordToWord.register(code, XMM6, XMM7, target);
        Host::PackUnsignedWordToByte.register(code, XMM4, XMM6, target);
        return;
    }
    transpose_constant(code, target);
    for i in XMM4..=XMM7 {
        Host::ByteShuffle.register(code, i, XMM0, target);
    }
    if element == ElementSize::Halfword {
        Host::UnpackLowDword.register(code, XMM4, XMM5, target);
        Host::UnpackLowDword.register(code, XMM6, XMM7, target);
        Host::MoveAligned.register(code, XMM5, XMM4, target);
        Host::UnpackLowQword.register(code, XMM4, XMM6, target);
        Host::UnpackHighQword.register(code, XMM5, XMM6, target);
    } else {
        Host::MoveAligned.register(code, XMM0, XMM4, target);
        Host::UnpackLowDword.register(code, XMM4, XMM5, target);
        Host::UnpackHighDword.register(code, XMM0, XMM5, target);
        Host::MoveAligned.register(code, XMM1, XMM6, target);
        Host::UnpackLowDword.register(code, XMM6, XMM7, target);
        Host::UnpackHighDword.register(code, XMM1, XMM7, target);
        Host::MoveAligned.register(code, XMM5, XMM4, target);
        Host::UnpackLowQword.register(code, XMM4, XMM6, target);
        Host::UnpackHighQword.register(code, XMM5, XMM6, target);
        Host::MoveAligned.register(code, XMM6, XMM0, target);
        Host::UnpackLowQword.register(code, XMM6, XMM1, target);
        Host::UnpackHighQword.register(code, XMM0, XMM1, target);
        Host::MoveAligned.register(code, XMM7, XMM0, target);
    }
}
fn load_packed_indexes(code: &mut Code, bytes: usize, offset: usize) {
    match bytes {
        1 | 2 => {
            let from = if bytes == 1 { Size::Byte } else { Size::Word };
            let mut asm = code.asm();
            asm.movzx(Size::Dword, Gpr::Rax, from, stack(offset));
            asm.movd_to_xmm(XMM0, Gpr::Rax);
        }
        4 => code.asm().movd_to_xmm(XMM0, stack(offset)),
        8 => Host::MoveQword.emit(code, XMM0, stack(offset), TargetCpu::Baseline),
        _ => unreachable!("LUTI packs one, two, four or eight source bytes per output chunk"),
    }
}
fn shuffle_lookup_chunk(code: &mut Code, element: ElementSize, index_bits: u8, target: TargetCpu) {
    let zero = if index_bits == LUTI4_INDEX_BITS && element == ElementSize::Word {
        Host::Xor.register(code, XMM2, XMM2, target);
        splat_dword(code, XMM3, FOUR_BIT_BYTE_MASK, target);
        XMM2
    } else {
        XMM7
    };
    Host::UnpackLowByte.register(code, XMM0, zero, target);
    if index_bits == LUTI2_INDEX_BITS {
        Host::UnpackLowWord.register(code, XMM0, zero, target);
        for (shift, mask) in [
            (FIRST_INDEX_SPREAD_SHIFT, XMM6),
            (SECOND_INDEX_SPREAD_SHIFT, XMM5),
        ] {
            Host::MoveAligned.register(code, XMM1, XMM0, target);
            ShiftOpcode::LeftDword.emit(code, XMM1, shift);
            Host::Or.register(code, XMM0, XMM1, target);
            Host::And.register(code, XMM0, mask, target);
        }
        if element != ElementSize::Byte {
            Host::UnpackLowByte.register(code, XMM0, XMM0, target);
        }
        if element == ElementSize::Word {
            Host::UnpackLowWord.register(code, XMM0, XMM0, target);
        }
        ShiftOpcode::LeftDword.emit(code, XMM0, TABLE_ENTRY_BYTE_SHIFT);
        if element != ElementSize::Byte {
            Host::Or.register(code, XMM0, XMM3, target);
        }
        Host::MoveAligned.register(code, XMM1, XMM4, target);
        Host::ByteShuffle.register(code, XMM1, XMM0, target);
    } else {
        Host::MoveAligned.register(code, XMM1, XMM0, target);
        ShiftOpcode::LeftWord.emit(code, XMM1, NIBBLE_BITS);
        Host::Or.register(code, XMM0, XMM1, target);
        Host::And.register(
            code,
            XMM0,
            if element == ElementSize::Word {
                XMM3
            } else {
                XMM6
            },
            target,
        );
        Host::MoveAligned.register(code, XMM1, XMM4, target);
        Host::ByteShuffle.register(code, XMM1, XMM0, target);
        if element != ElementSize::Byte {
            Host::MoveAligned.register(code, XMM2, XMM5, target);
            Host::ByteShuffle.register(code, XMM2, XMM0, target);
            Host::UnpackLowByte.register(code, XMM1, XMM2, target);
        }
        if element == ElementSize::Word {
            Host::MoveAligned.register(code, XMM2, XMM6, target);
            Host::ByteShuffle.register(code, XMM2, XMM0, target);
            Host::MoveAligned.register(code, XMM3, XMM7, target);
            Host::ByteShuffle.register(code, XMM3, XMM0, target);
            Host::UnpackLowByte.register(code, XMM2, XMM3, target);
            Host::UnpackLowWord.register(code, XMM1, XMM2, target);
        }
    }
}

fn lookup_simd(
    code: &mut Code,
    operand: &Operand,
    source: u8,
    index_bits: u8,
    immediate: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    let frame_bytes = length.bytes();
    stage_source_and_table(code, source, frame_bytes, length, target);
    if index_bits == LUTI2_INDEX_BITS {
        load_table_chunk(code, XMM4, 0);
        Host::Xor.register(code, XMM7, XMM7, target);
        splat_dword(code, XMM6, INDEX_SPLIT_NIBBLE_MASK, target);
        splat_dword(code, XMM5, TWO_BIT_BYTE_MASK, target);
        match operand.element {
            ElementSize::Halfword => splat_dword(code, XMM3, HALFWORD_BYTE_OFFSETS, target),
            ElementSize::Word => splat_dword(code, XMM3, DWORD_BYTE_OFFSETS, target),
            _ => (),
        }
    } else {
        prepare_planes(code, operand.element, target);
        if operand.element != ElementSize::Word {
            Host::Xor.register(code, XMM7, XMM7, target);
            splat_dword(code, XMM6, FOUR_BIT_BYTE_MASK, target);
        }
    }
    let elements = length.lanes(operand.element);
    let lanes = VECTOR_CHUNK_BYTES / operand.element.bytes();
    let count = usize::from(operand.destination.count);
    let segment =
        usize::from(immediate) % (operand.element.bits() / (usize::from(index_bits) * count));
    for destination_index in 0..count {
        let base = (segment * count + destination_index) * elements;
        for chunk in 0..length.chunks() {
            let offset = ((base + chunk * lanes) * usize::from(index_bits)) / BITS_PER_BYTE;
            load_packed_indexes(
                code,
                lanes * usize::from(index_bits) / BITS_PER_BYTE,
                offset,
            );
            shuffle_lookup_chunk(code, operand.element, index_bits, target);
            store_z_chunk(
                code,
                operand.destination.register(destination_index as u8),
                chunk,
                XMM1,
                length,
                target,
            );
        }
    }
    release_frame(code, frame_bytes);
}

/// Expand packed two-bit indices and evaluate the two-variable table polynomial.
/// Table coefficients occupy XMM4..7; return the result's scratch register.
fn polynomial_lookup_chunk(code: &mut Code, element: ElementSize, target: TargetCpu) -> u8 {
    Host::Xor.register(code, XMM2, XMM2, target);
    Host::UnpackLowByte.register(code, XMM0, XMM2, target);
    Host::UnpackLowWord.register(code, XMM0, XMM2, target);
    for (shift, mask) in [
        (FIRST_INDEX_SPREAD_SHIFT, INDEX_SPLIT_NIBBLE_MASK),
        (SECOND_INDEX_SPREAD_SHIFT, TWO_BIT_BYTE_MASK),
    ] {
        Host::MoveAligned.register(code, XMM1, XMM0, target);
        ShiftOpcode::LeftDword.emit(code, XMM1, shift);
        Host::Or.register(code, XMM0, XMM1, target);
        splat_dword(code, XMM3, mask, target);
        Host::And.register(code, XMM0, XMM3, target);
    }
    if element != ElementSize::Byte {
        Host::UnpackLowByte.register(code, XMM0, XMM2, target);
    }
    if element == ElementSize::Byte {
        Host::MoveAligned.register(code, XMM1, XMM0, target);
        ShiftOpcode::LeftWord.emit(code, XMM1, BYTE_SIGN_BIT);
        Host::GreaterByte.register(code, XMM2, XMM1, target);
        ShiftOpcode::LeftWord.emit(code, XMM0, BYTE_SIGN_BIT - 1);
        Host::Xor.register(code, XMM1, XMM1, target);
        Host::GreaterByte.register(code, XMM1, XMM0, target);
        Host::MoveAligned.register(code, XMM0, XMM7, target);
        Host::And.register(code, XMM0, XMM2, target);
        Host::Xor.register(code, XMM0, XMM6, target);
        Host::And.register(code, XMM0, XMM1, target);
        Host::MoveAligned.register(code, XMM1, XMM5, target);
        Host::And.register(code, XMM1, XMM2, target);
        Host::Xor.register(code, XMM0, XMM1, target);
        Host::Xor.register(code, XMM0, XMM4, target);
        XMM0
    } else {
        Host::MoveAligned.register(code, XMM2, XMM0, target);
        ShiftOpcode::LeftWord.emit(code, XMM2, HALFWORD_SIGN_BIT);
        ShiftOpcode::ArithmeticWord.emit(code, XMM2, HALFWORD_SIGN_BIT);
        ShiftOpcode::LeftWord.emit(code, XMM0, HALFWORD_SIGN_BIT - 1);
        ShiftOpcode::ArithmeticWord.emit(code, XMM0, HALFWORD_SIGN_BIT);
        Host::MoveAligned.register(code, XMM1, XMM7, target);
        Host::And.register(code, XMM1, XMM2, target);
        Host::Xor.register(code, XMM1, XMM6, target);
        Host::And.register(code, XMM1, XMM0, target);
        Host::MoveAligned.register(code, XMM0, XMM5, target);
        Host::And.register(code, XMM0, XMM2, target);
        Host::Xor.register(code, XMM1, XMM0, target);
        Host::Xor.register(code, XMM1, XMM4, target);
        XMM1
    }
}

fn lookup_sse2_poly(
    code: &mut Code,
    operand: &Operand,
    source: u8,
    immediate: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    debug_assert!(matches!(
        operand.element,
        ElementSize::Byte | ElementSize::Halfword
    ));
    stage_source_and_table(code, source, length.bytes(), length, target);
    load_table_chunk(code, XMM0, 0);
    for i in 0..LUTI2_TABLE_ENTRIES {
        Host::ShuffleDword.register_imm(
            code,
            XMM4 + i,
            XMM0,
            DWORD_REPEAT_SELECTORS[usize::from(i)],
            target,
        );
        match operand.element {
            ElementSize::Byte => {
                Host::UnpackLowByte.register(code, XMM4 + i, XMM4 + i, target);
                Host::UnpackLowWord.register(code, XMM4 + i, XMM4 + i, target);
                Host::ShuffleDword.register_imm(
                    code,
                    XMM4 + i,
                    XMM4 + i,
                    REPEAT_FIRST_ELEMENT,
                    target,
                );
            }
            ElementSize::Halfword => {
                Host::ShuffleLowWord.register_imm(
                    code,
                    XMM4 + i,
                    XMM4 + i,
                    REPEAT_FIRST_ELEMENT,
                    target,
                );
                Host::UnpackLowQword.register(code, XMM4 + i, XMM4 + i, target);
            }
            _ => unreachable!("Polynomial lookup has Byte/Halfword output"),
        }
    }
    // Boolean-polynomial coefficients T0, T0^T1, T0^T2, T0^T1^T2^T3.
    Host::Xor.register(code, XMM7, XMM6, target);
    Host::Xor.register(code, XMM7, XMM5, target);
    Host::Xor.register(code, XMM7, XMM4, target);
    Host::Xor.register(code, XMM5, XMM4, target);
    Host::Xor.register(code, XMM6, XMM4, target);
    let elements = length.lanes(operand.element);
    let lanes = VECTOR_CHUNK_BYTES / operand.element.bytes();
    let count = usize::from(operand.destination.count);
    let segment =
        usize::from(immediate) % (operand.element.bits() / (usize::from(LUTI2_INDEX_BITS) * count));
    for destination_index in 0..count {
        let base = (segment * count + destination_index) * elements;
        for chunk in 0..length.chunks() {
            let offset = (base + chunk * lanes) * usize::from(LUTI2_INDEX_BITS) / BITS_PER_BYTE;
            load_packed_indexes(
                code,
                lanes * usize::from(LUTI2_INDEX_BITS) / BITS_PER_BYTE,
                offset,
            );
            let output = polynomial_lookup_chunk(code, operand.element, target);
            store_z_chunk(
                code,
                operand.destination.register(destination_index as u8),
                chunk,
                output,
                length,
                target,
            );
        }
    }
    release_frame(code, length.bytes());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Recipe {
    Scalar,
    Boolean,
    Shuffle,
}

pub(super) fn recipe(
    operand: &Operand,
    index_bits: u8,
    length: VectorLength,
    target: TargetCpu,
) -> Recipe {
    let total_output_chunks = usize::from(operand.destination.count) * length.chunks();
    // Keep the tiny single Word lookup compact and favor its dependent latency.
    // Halfword keeps SSSE3 for smaller code and higher independent throughput.
    let prefer_scalar_single_chunk = index_bits == LUTI2_INDEX_BITS
        && operand.element == ElementSize::Word
        && total_output_chunks == 1;
    if target.supports(TargetCpu::Ssse3) && !prefer_scalar_single_chunk {
        Recipe::Shuffle
    } else if index_bits == LUTI2_INDEX_BITS
        && (operand.element == ElementSize::Byte
            || (operand.element == ElementSize::Halfword
                && total_output_chunks >= MIN_POLYNOMIAL_HALFWORD_OUTPUT_CHUNKS))
    {
        Recipe::Boolean
    } else {
        Recipe::Scalar
    }
}

pub(super) fn emit(
    code: &mut Code,
    operand: &Operand,
    source: u8,
    index_bits: u8,
    immediate: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    match recipe(operand, index_bits, length, target) {
        Recipe::Shuffle => {
            lookup_simd(code, operand, source, index_bits, immediate, length, target)
        }
        Recipe::Boolean => lookup_sse2_poly(code, operand, source, immediate, length, target),
        Recipe::Scalar => {
            lookup_scalar(code, operand, source, index_bits, immediate, length, target)
        }
    }
}
