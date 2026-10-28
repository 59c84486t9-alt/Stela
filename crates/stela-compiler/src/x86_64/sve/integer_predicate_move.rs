//! PMOV between predicates and vector bitmaps.
use crate::aarch64::sve::integer_predicate_move::Operand;
use crate::x86_64::asm::Gpr::{R8, R9, Rax, Rcx};
use crate::x86_64::asm::{Alu, Code, ShiftOp, Size};
use crate::x86_64::isa::SimdOpcode as Host;
use crate::x86_64::scalable::{clear_z_upper, load_z_chunk, read_predicate_chunk, store_z_chunk};
use crate::{
    TargetCpu,
    aarch64::scalable::{BITS_PER_BYTE, ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
};

const QWORD_BITS: usize = u64::BITS as usize;
const QWORD_BYTES: usize = core::mem::size_of::<u64>();
const CHUNK_BITS: usize = VECTOR_CHUNK_BYTES * BITS_PER_BYTE;
const RESULT: u8 = 0;
const HIGH: u8 = 1;
const MASK: u8 = 2;
const PREVIOUS: u8 = 3;
const BYTE_LOW_BITS: u64 = 0x0101_0101_0101_0101;
const BYTE_GATHER_MULTIPLIER: u64 = 0x0102_0408_1020_4080;
const BYTE_GATHER_SHIFT: usize = QWORD_BITS - BITS_PER_BYTE;

fn packed(code: &mut Code, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn mask_rax(code: &mut Code, mask: u64) {
    if mask <= u64::from(u32::MAX) {
        code.asm()
            .alu_accumulator_imm32(Alu::And, Size::Dword, mask as i32);
    } else {
        let mut asm = code.asm();
        asm.mov_imm64(Rcx, mask);
        asm.alu(Alu::And, Size::Qword, Rax, Rcx);
    }
}

fn compact_mask(stride: usize, group: usize) -> u64 {
    let mut mask = 0;
    for start in (0..QWORD_BITS).step_by(stride * group) {
        mask |= ((1u64 << group) - 1) << start;
    }
    mask
}

/// Compress each element-leading P bit in RAX to consecutive low bits.
fn compact(code: &mut Code, element: ElementSize, input_bits: usize) {
    let stride = element.bytes();
    if stride == 1 {
        return;
    }
    if element == ElementSize::Doubleword {
        mask_rax(code, BYTE_LOW_BITS);
        let mut asm = code.asm();
        asm.mov_imm64(Rcx, BYTE_GATHER_MULTIPLIER);
        asm.imul(Size::Qword, Rax, Rcx);
        asm.shift_imm(ShiftOp::Shr, Size::Qword, Rax, BYTE_GATHER_SHIFT as u8);
        return;
    }
    let input_mask = u64::MAX >> (QWORD_BITS - input_bits);
    mask_rax(code, compact_mask(stride, 1) & input_mask);
    let mut group = 1;
    while group < input_bits / stride {
        let mut asm = code.asm();
        asm.mov(Size::Qword, Rcx, Rax);
        asm.shift_imm(ShiftOp::Shr, Size::Qword, Rcx, ((stride - 1) * group) as u8);
        asm.alu(Alu::Or, Size::Qword, Rax, Rcx);
        group *= 2;
        mask_rax(code, compact_mask(stride, group) & input_mask);
    }
}

fn constant_half(code: &mut Code, value: u64, destination: u8) {
    code.asm().mov_imm64(Rax, value);
    code.asm()
        .simd(Host::MoveGprQword, destination, Rax, TargetCpu::Baseline);
}

/// No guest RAM, flags or other register-bank effects. P/Z are separate banks,
/// so each P chunk may be read immediately before its Z chunk is committed.
pub fn emit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
    let stride = operand.element_size.bytes();
    assert!(stride <= QWORD_BYTES);
    assert!(usize::from(operand.portion) < stride);
    let elements = length.lanes(operand.element_size);
    let start = elements * usize::from(operand.portion);
    let end = start + elements;
    if operand.portion == 0 {
        // P and Z occupy independent banks; clearing tails before the P reads
        // is safe and lets the shared helper prepare their base pointer once.
        clear_z_upper(code, operand.destination, RESULT, length, target);
    }
    for destination_chunk in 0..length.chunks() {
        let chunk_start = destination_chunk * CHUNK_BITS;
        if chunk_start >= end || chunk_start + CHUNK_BITS <= start {
            continue;
        }
        let mut asm = code.asm();
        asm.alu(Alu::Xor, Size::Dword, R8, R8);
        asm.alu(Alu::Xor, Size::Dword, R9, R9);
        for source_chunk in 0..length.predicate_bytes().div_ceil(QWORD_BYTES) {
            let bit_position = start + source_chunk * (QWORD_BITS / stride);
            if bit_position / CHUNK_BITS != destination_chunk {
                continue;
            }
            read_predicate_chunk(code, operand.predicate, source_chunk, length);
            let input_bits = length.predicate_bytes().min(QWORD_BYTES) * BITS_PER_BYTE;
            compact(code, operand.element_size, input_bits);
            let shift = bit_position % QWORD_BITS;
            if shift != 0 {
                code.asm()
                    .shift_imm(ShiftOp::Shl, Size::Qword, Rax, shift as u8);
            }
            let destination = if bit_position % CHUNK_BITS < QWORD_BITS {
                R8
            } else {
                R9
            };
            code.asm().alu(Alu::Or, Size::Qword, destination, Rax);
        }
        let mut asm = code.asm();
        asm.movq_to_xmm(0, R8);
        asm.movq_to_xmm(1, R9);
        packed(code, Host::UnpackLowQword, RESULT, HIGH);
        if operand.portion != 0 {
            let mut mask = 0u128;
            for bit in start.max(chunk_start)..end.min(chunk_start + CHUNK_BITS) {
                mask |= 1u128 << (bit - chunk_start);
            }
            constant_half(code, mask as u64, MASK);
            constant_half(code, (mask >> QWORD_BITS) as u64, HIGH);
            packed(code, Host::UnpackLowQword, MASK, HIGH);
            load_z_chunk(
                code,
                operand.destination,
                destination_chunk,
                PREVIOUS,
                length,
                target,
            );
            packed(code, Host::AndNot, MASK, PREVIOUS);
            packed(code, Host::Or, RESULT, MASK);
        }
        store_z_chunk(
            code,
            operand.destination,
            destination_chunk,
            RESULT,
            length,
            target,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_masks_keep_only_group_leading_bits() {
        assert_eq!(compact_mask(2, 1), 0x5555_5555_5555_5555);
        assert_eq!(compact_mask(2, 16), 0x0000_ffff_0000_ffff);
        assert_eq!(compact_mask(4, 2), 0x0303_0303_0303_0303);
        assert_eq!(compact_mask(4, 16), 0xffff);
    }
}
