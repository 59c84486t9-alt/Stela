//! Packed predicate bitmap compaction and bit-portion insertion, baseline only.
use crate::aarch64::sve::integer_predicate_move::Operand;
use crate::x86_64::isa::SimdOpcode as Host;
use crate::x86_64::scalable::{clear_z_upper, load_z_chunk, read_predicate_chunk, store_z_chunk};
use crate::{
    TargetCpu,
    aarch64::scalable::{BITS_PER_BYTE, ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
};

const QWORD_BITS: usize = u64::BITS as usize;
const QWORD_BYTES: usize = std::mem::size_of::<u64>();
const CHUNK_BITS: usize = VECTOR_CHUNK_BYTES * BITS_PER_BYTE;
const RESULT: u8 = 0;
const HIGH: u8 = 1;
const MASK: u8 = 2;
const PREVIOUS: u8 = 3;
const XOR_R8D_R8D: &[u8] = &[0x45, 0x31, 0xc0];
const XOR_R9D_R9D: &[u8] = &[0x45, 0x31, 0xc9];
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const MOVABS_RAX: &[u8] = &[0x48, 0xb8];
const MOVABS_RCX: &[u8] = &[0x48, 0xb9];
const AND_RAX_RCX: &[u8] = &[0x48, 0x21, 0xc8];
const AND_EAX_IMM32: &[u8] = &[0x25];
const OR_RAX_RCX: &[u8] = &[0x48, 0x09, 0xc8];
const SHR_RCX_IMM8: &[u8] = &[0x48, 0xc1, 0xe9];
const SHR_RAX_IMM8: &[u8] = &[0x48, 0xc1, 0xe8];
const SHL_RAX_IMM8: &[u8] = &[0x48, 0xc1, 0xe0];
const OR_R8_RAX: &[u8] = &[0x49, 0x09, 0xc0];
const OR_R9_RAX: &[u8] = &[0x49, 0x09, 0xc1];
const MOVQ_XMM0_R8: &[u8] = &[0x66, 0x49, 0x0f, 0x6e, 0xc0];
const MOVQ_XMM1_R9: &[u8] = &[0x66, 0x49, 0x0f, 0x6e, 0xc9];
const IMUL_RAX_RCX: &[u8] = &[0x48, 0x0f, 0xaf, 0xc1];
const BYTE_LOW_BITS: u64 = 0x0101_0101_0101_0101;
const BYTE_GATHER_MULTIPLIER: u64 = 0x0102_0408_1020_4080;
const BYTE_GATHER_SHIFT: usize = QWORD_BITS - BITS_PER_BYTE;
const MODRM_REGISTER: u8 = 0xc0;
const REGISTER_SHIFT: u8 = 3;

fn packed(code: &mut Vec<u8>, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn mask_rax(code: &mut Vec<u8>, mask: u64) {
    if mask <= u64::from(u32::MAX) {
        code.extend(AND_EAX_IMM32);
        code.extend((mask as u32).to_le_bytes());
    } else {
        code.extend(MOVABS_RCX);
        code.extend(mask.to_le_bytes());
        code.extend(AND_RAX_RCX);
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
fn compact(code: &mut Vec<u8>, element: ElementSize, input_bits: usize) {
    let stride = element.bytes();
    if stride == 1 {
        return;
    }
    if element == ElementSize::Doubleword {
        mask_rax(code, BYTE_LOW_BITS);
        code.extend(MOVABS_RCX);
        code.extend(BYTE_GATHER_MULTIPLIER.to_le_bytes());
        code.extend(IMUL_RAX_RCX);
        code.extend(SHR_RAX_IMM8);
        code.push(BYTE_GATHER_SHIFT as u8);
        return;
    }
    let input_mask = u64::MAX >> (QWORD_BITS - input_bits);
    mask_rax(code, compact_mask(stride, 1) & input_mask);
    let mut group = 1;
    while group < input_bits / stride {
        code.extend(MOV_RCX_RAX);
        code.extend(SHR_RCX_IMM8);
        code.push(((stride - 1) * group) as u8);
        code.extend(OR_RAX_RCX);
        group *= 2;
        mask_rax(code, compact_mask(stride, group) & input_mask);
    }
}

fn constant_half(code: &mut Vec<u8>, value: u64, destination: u8) {
    code.extend(MOVABS_RAX);
    code.extend(value.to_le_bytes());
    Host::MoveGprQword.append(code, TargetCpu::Baseline);
    code.push(MODRM_REGISTER | (destination << REGISTER_SHIFT));
}

/// No guest RAM, flags or other register-bank effects. P/Z are separate banks,
/// so each P chunk may be read immediately before its Z chunk is committed.
pub fn emit(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
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
        code.extend(XOR_R8D_R8D);
        code.extend(XOR_R9D_R9D);
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
                code.extend(SHL_RAX_IMM8);
                code.push(shift as u8);
            }
            code.extend(if bit_position % CHUNK_BITS < QWORD_BITS {
                OR_R8_RAX
            } else {
                OR_R9_RAX
            });
        }
        code.extend(MOVQ_XMM0_R8);
        code.extend(MOVQ_XMM1_R9);
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
