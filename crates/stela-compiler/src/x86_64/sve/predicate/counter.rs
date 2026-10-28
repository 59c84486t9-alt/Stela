//! Expanding predicate-as-counter registers into packed predicate chunks.
use super::CHUNK_BITS;
use crate::aarch64::scalable::VectorLength;
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::Gpr::{R8, R9, R10, R11, Rax, Rcx, Rdx};
use crate::x86_64::asm::{Alu, Code, Cond, ShiftOp, Size, Unary};

const COUNTER_FORMAT_MASK: u8 = 15;
const COUNTER_INVERT_BIT: u8 = 15;
const ALL_LEADING_BITS: u64 = u64::MAX;
const HALFWORD_LEADING_BITS: u64 = 0x5555_5555_5555_5555;
const WORD_LEADING_BITS: u64 = 0x1111_1111_1111_1111;
const DOUBLEWORD_LEADING_BITS: u64 = 0x0101_0101_0101_0101;

/// Input RAX is the compressed low16 counter. Output RAX is one64-bit chunk of
/// its PL*4-bit expansion, where PL is the vector length in bytes. Other high
/// input bits are ignored. Clobbers RCX/RDX/R8..R11; preserves RDI/R15 and XMM.
/// The instruction's own element size is deliberately absent: a consumer samples
/// this mask using its independent stride, including mismatched counter sizes.
/// This baseline mapping uses no optional host capability or guest RAM access.
pub(crate) fn emit_counter_chunk(code: &mut Code, chunk: usize, length: VectorLength) {
    prepare_counter(code, length);
    emit_prepared_counter_chunk(code, chunk, length);
}

/// Decode one compressed counter before producing multiple chunks. R8 keeps
/// low16 input, R9 the exclusive active-bit boundary, R10 the leading-bit pattern.
/// Zero format initializes a zero pattern regardless of the inversion bit.
/// Clobbers RAX/RCX/RDX/R8..R11; preserves RDI/R15 and all XMMs.
pub(crate) fn prepare_counter(code: &mut Code, length: VectorLength) {
    let expanded_bits = length.bytes() * 4;
    let counter_bits = expanded_bits.ilog2() + 1;
    let count_mask = (1u32 << counter_bits) - 1;
    let mut asm = code.asm();
    asm.movzx(Size::Dword, R8, Size::Word, Rax);
    asm.mov(Size::Dword, Rcx, R8);
    asm.alu_imm8(Alu::And, Size::Dword, Rcx, COUNTER_FORMAT_MASK as i8);
    let empty_format = code.asm().jcc(Cond::E);
    let mut asm = code.asm();
    asm.bsf(Size::Dword, Rcx, Rcx);
    asm.mov_imm32(Rdx, 1);
    asm.shift_cl(ShiftOp::Shl, Size::Dword, Rdx);
    asm.mov(Size::Dword, R9, R8);
    asm.alu_imm32(Alu::And, Size::Dword, R9, count_mask as i32);
    asm.shift_one(ShiftOp::Shr, Size::Dword, R9);
    asm.unary(Unary::Neg, Size::Dword, Rdx);
    asm.alu(Alu::And, Size::Dword, R9, Rdx);
    asm.mov_imm64(R10, ALL_LEADING_BITS);
    for (minimum_size, mask) in [
        (1, HALFWORD_LEADING_BITS),
        (2, WORD_LEADING_BITS),
        (3, DOUBLEWORD_LEADING_BITS),
    ] {
        let mut asm = code.asm();
        asm.mov_imm64(R11, mask);
        asm.alu_byte_imm(Alu::Cmp, Rcx, minimum_size);
        asm.cmov(Cond::Ae, Size::Qword, R10, R11);
    }
    let ready = code.asm().jmp();
    code.asm().bind(empty_format);
    let mut asm = code.asm();
    asm.alu(Alu::Xor, Size::Dword, R9, R9);
    asm.alu(Alu::Xor, Size::Dword, R10, R10);
    code.asm().bind(ready);
}

/// Produce a chunk from prepare_counter state without changing R8/R9/R10.
/// Clobbers RAX/RCX/R11 and host flags; preserves RDX/RDI/R15 and XMMs.
pub(crate) fn emit_prepared_counter_chunk(code: &mut Code, chunk: usize, length: VectorLength) {
    assert!(chunk < length.bytes() * 4 / CHUNK_BITS);
    code.asm().mov(Size::Dword, Rax, R9);
    if chunk != 0 {
        code.asm()
            .alu_accumulator_imm32(Alu::Sub, Size::Dword, (chunk * CHUNK_BITS) as i32);
    }
    code.asm()
        .alu_imm8(Alu::Cmp, Size::Dword, Rax, CHUNK_BITS as i8);
    let full_chunk = code.asm().jcc(Cond::Ge);
    code.asm().test(Size::Dword, Rax, Rax);
    let empty_chunk = code.asm().jcc(Cond::Le);
    let mut asm = code.asm();
    asm.mov(Size::Dword, Rcx, Rax);
    asm.mov_imm32(Rax, 1);
    asm.shift_cl(ShiftOp::Shl, Size::Qword, Rax);
    asm.dec(Size::Qword, Rax);
    let partial_ready = code.asm().jmp();
    code.asm().bind(empty_chunk);
    code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
    let empty_ready = code.asm().jmp();
    code.asm().bind(full_chunk);
    code.asm().mov_rm_imm32(Size::Qword, Rax, -1);
    code.asm().bind(partial_ready);
    code.asm().bind(empty_ready);
    let mut asm = code.asm();
    asm.bit_imm(BitTest::Bt, Size::Dword, R8, COUNTER_INVERT_BIT);
    asm.alu(Alu::Sbb, Size::Qword, R11, R11);
    asm.alu(Alu::Xor, Size::Qword, Rax, R11);
    asm.alu(Alu::And, Size::Qword, Rax, R10);
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOVZX_R8D_AX: &[u8] = &[0x44, 0x0f, 0xb7, 0xc0];
    const AND_RAX_R10: &[u8] = &[0x4c, 0x21, 0xd0];

    #[test]
    fn every_streaming_length_emits_bounded_chunks_without_optional_instructions() {
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            for chunk in 0..bytes * 4 / CHUNK_BITS {
                let mut code = Code::new();
                emit_counter_chunk(&mut code, chunk, length);
                assert!(code.starts_with(MOVZX_R8D_AX));
                assert!(code.ends_with(AND_RAX_R10));
                assert!(code.len() < 256);
            }
        }
    }
}
