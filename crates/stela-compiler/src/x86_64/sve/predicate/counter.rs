//! Expansion of compressed PN counters into packed predicate chunks.
use super::{CHUNK_BITS, bind, jump};
use crate::aarch64::scalable::VectorLength;
use alloc::vec::Vec;

const XOR_R9D_R9D: &[u8] = &[0x45, 0x31, 0xc9];
const XOR_R10D_R10D: &[u8] = &[0x45, 0x31, 0xd2];
const COUNTER_FORMAT_MASK: u8 = 15;
const COUNTER_INVERT_BIT: u8 = 15;
const ALL_LEADING_BITS: u64 = u64::MAX;
const HALFWORD_LEADING_BITS: u64 = 0x5555_5555_5555_5555;
const WORD_LEADING_BITS: u64 = 0x1111_1111_1111_1111;
const DOUBLEWORD_LEADING_BITS: u64 = 0x0101_0101_0101_0101;
const MOVZX_R8D_AX: &[u8] = &[0x44, 0x0f, 0xb7, 0xc0];
const MOV_ECX_R8D: &[u8] = &[0x44, 0x89, 0xc1];
const AND_ECX_IMM8: &[u8] = &[0x83, 0xe1];
const BSF_ECX_ECX: &[u8] = &[0x0f, 0xbc, 0xc9];
const MOV_EDX_ONE: &[u8] = &[0xba, 1, 0, 0, 0];
const SHL_EDX_CL: &[u8] = &[0xd3, 0xe2];
const MOV_R9D_R8D: &[u8] = &[0x45, 0x89, 0xc1];
const AND_R9D_IMM32: &[u8] = &[0x41, 0x81, 0xe1];
const SHR_R9D_ONE: &[u8] = &[0x41, 0xd1, 0xe9];
const NEG_EDX: &[u8] = &[0xf7, 0xda];
const AND_R9D_EDX: &[u8] = &[0x41, 0x21, 0xd1];
const MOVABS_R10: &[u8] = &[0x49, 0xba];
const MOVABS_R11: &[u8] = &[0x49, 0xbb];
const CMP_CL_IMM8: &[u8] = &[0x80, 0xf9];
const CMOVAE_R10_R11: &[u8] = &[0x4d, 0x0f, 0x43, 0xd3];
const MOV_EAX_R9D: &[u8] = &[0x44, 0x89, 0xc8];
const SUB_EAX_IMM32: &[u8] = &[0x2d];
const CMP_EAX_CHUNK_BITS: &[u8] = &[0x83, 0xf8, CHUNK_BITS as u8];
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const MOV_ECX_EAX: &[u8] = &[0x89, 0xc1];
const MOV_EAX_ONE: &[u8] = &[0xb8, 1, 0, 0, 0];
const SHL_RAX_CL: &[u8] = &[0x48, 0xd3, 0xe0];
const DEC_RAX: &[u8] = &[0x48, 0xff, 0xc8];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const MOV_RAX_ALL_BITS: &[u8] = &[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff];
const BT_R8D_IMM8: &[u8] = &[0x41, 0x0f, 0xba, 0xe0];
const SBB_R11_R11: &[u8] = &[0x4d, 0x19, 0xdb];
const XOR_RAX_R11: &[u8] = &[0x4c, 0x31, 0xd8];
const AND_RAX_R10: &[u8] = &[0x4c, 0x21, 0xd0];
const JZ: &[u8] = &[0x0f, 0x84];
const JGE: &[u8] = &[0x0f, 0x8d];
const JLE: &[u8] = &[0x0f, 0x8e];
const JMP: &[u8] = &[0xe9];

/// Input RAX is the compressed low16 counter. Output RAX is one64-bit chunk of
/// its PL*4-bit expansion, where PL is the vector length in bytes. Other high
/// input bits are ignored. Clobbers RCX/RDX/R8..R11; preserves RDI/R15 and XMM.
/// The instruction's own element size is deliberately absent: a consumer samples
/// this mask using its independent stride, including mismatched counter sizes.
/// This baseline mapping uses no optional host capability or guest RAM access.
pub(crate) fn emit_counter_chunk(code: &mut Vec<u8>, chunk: usize, length: VectorLength) {
    prepare_counter(code, length);
    emit_prepared_counter_chunk(code, chunk, length);
}

/// Decode one compressed counter before producing multiple chunks. R8 keeps
/// low16 input, R9 the exclusive active-bit boundary, R10 the leading-bit pattern.
/// Zero format initializes a zero pattern regardless of the inversion bit.
/// Clobbers RAX/RCX/RDX/R8..R11; preserves RDI/R15 and all XMMs.
pub(crate) fn prepare_counter(code: &mut Vec<u8>, length: VectorLength) {
    let expanded_bits = length.bytes() * 4;
    let counter_bits = expanded_bits.ilog2() + 1;
    let count_mask = (1u32 << counter_bits) - 1;
    code.extend(MOVZX_R8D_AX);
    code.extend(MOV_ECX_R8D);
    code.extend(AND_ECX_IMM8);
    code.push(COUNTER_FORMAT_MASK);
    let empty_format = jump(code, JZ);
    code.extend(BSF_ECX_ECX);
    code.extend(MOV_EDX_ONE);
    code.extend(SHL_EDX_CL);
    code.extend(MOV_R9D_R8D);
    code.extend(AND_R9D_IMM32);
    code.extend(count_mask.to_le_bytes());
    code.extend(SHR_R9D_ONE);
    code.extend(NEG_EDX);
    code.extend(AND_R9D_EDX);
    code.extend(MOVABS_R10);
    code.extend(ALL_LEADING_BITS.to_le_bytes());
    for (minimum_size, mask) in [
        (1, HALFWORD_LEADING_BITS),
        (2, WORD_LEADING_BITS),
        (3, DOUBLEWORD_LEADING_BITS),
    ] {
        code.extend(MOVABS_R11);
        code.extend(mask.to_le_bytes());
        code.extend(CMP_CL_IMM8);
        code.push(minimum_size);
        code.extend(CMOVAE_R10_R11);
    }
    let ready = jump(code, JMP);
    bind(code, empty_format);
    code.extend(XOR_R9D_R9D);
    code.extend(XOR_R10D_R10D);
    bind(code, ready);
}

/// Produce a chunk from prepare_counter state without changing R8/R9/R10.
/// Clobbers RAX/RCX/R11 and host flags; preserves RDX/RDI/R15 and XMMs.
pub(crate) fn emit_prepared_counter_chunk(code: &mut Vec<u8>, chunk: usize, length: VectorLength) {
    assert!(chunk < length.bytes() * 4 / CHUNK_BITS);
    code.extend(MOV_EAX_R9D);
    if chunk != 0 {
        code.extend(SUB_EAX_IMM32);
        code.extend(((chunk * CHUNK_BITS) as u32).to_le_bytes());
    }
    code.extend(CMP_EAX_CHUNK_BITS);
    let full_chunk = jump(code, JGE);
    code.extend(TEST_EAX_EAX);
    let empty_chunk = jump(code, JLE);
    code.extend(MOV_ECX_EAX);
    code.extend(MOV_EAX_ONE);
    code.extend(SHL_RAX_CL);
    code.extend(DEC_RAX);
    let partial_ready = jump(code, JMP);
    bind(code, empty_chunk);
    code.extend(XOR_EAX_EAX);
    let empty_ready = jump(code, JMP);
    bind(code, full_chunk);
    code.extend(MOV_RAX_ALL_BITS);
    bind(code, partial_ready);
    bind(code, empty_ready);
    code.extend(BT_R8D_IMM8);
    code.push(COUNTER_INVERT_BIT);
    code.extend(SBB_R11_R11);
    code.extend(XOR_RAX_R11);
    code.extend(AND_RAX_R10);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn every_streaming_length_emits_bounded_chunks_without_optional_instructions() {
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            for chunk in 0..bytes * 4 / CHUNK_BITS {
                let mut code = Vec::new();
                emit_counter_chunk(&mut code, chunk, length);
                assert!(code.starts_with(MOVZX_R8D_AX));
                assert!(code.ends_with(AND_RAX_R10));
                assert!(code.len() < 256);
            }
        }
    }
}
