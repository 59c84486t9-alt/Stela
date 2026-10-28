//! Incremental NZCV for predicate-setting instructions (PTEST semantics).
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::Gpr::{R8, R9, R10, R11, Rax, Rcx, Rdi, Rdx};
use crate::x86_64::asm::{Alu, Code, Cond, Mem, ShiftOp, Size};

use super::CHUNK_BITS;

const NZCV_N_SHIFT: u8 = 31;
const NZCV_Z_SHIFT: u8 = 30;
const NZCV_C_SHIFT: u8 = 29;

pub(crate) fn leading_bits(element: crate::aarch64::scalable::ElementSize) -> u64 {
    (0..CHUNK_BITS)
        .step_by(element.bytes())
        .fold(0, |mask, bit| mask | (1 << bit))
}

pub(crate) fn begin_predtest(code: &mut Code) {
    let mut asm = code.asm();
    asm.mov_imm32(R8, 1u32 << NZCV_C_SHIFT);
    asm.alu(Alu::Xor, Size::Dword, R9, R9);
    asm.alu(Alu::Xor, Size::Dword, R10, R10);
}

pub(crate) fn accumulate_predtest(code: &mut Code, element: crate::aarch64::scalable::ElementSize) {
    code.asm().mov(Size::Qword, Rdx, R11);
    if element != crate::aarch64::scalable::ElementSize::Byte {
        let mut asm = code.asm();
        asm.mov_imm64(Rcx, leading_bits(element));
        asm.alu(Alu::And, Size::Qword, Rdx, Rcx);
    }
    code.asm().test(Size::Qword, Rdx, Rdx);
    let empty = code.asm().jcc(Cond::E);
    let mut asm = code.asm();
    asm.mov(Size::Qword, Rcx, Rax);
    asm.alu(Alu::And, Size::Qword, Rcx, Rdx);
    asm.alu(Alu::Or, Size::Qword, R9, Rcx);
    asm.test(Size::Dword, R10, R10);
    let seen = code.asm().jcc(Cond::Ne);
    let mut asm = code.asm();
    asm.bsf(Size::Qword, Rcx, Rdx);
    asm.bit(BitTest::Bt, Size::Qword, Rax, Rcx);
    asm.setcc(Cond::B, Rcx);
    asm.movzx(Size::Dword, Rcx, Size::Byte, Rcx);
    asm.shift_imm(ShiftOp::Shl, Size::Dword, Rcx, NZCV_N_SHIFT);
    asm.alu(Alu::Or, Size::Dword, R8, Rcx);
    code.asm().bind(seen);
    let mut asm = code.asm();
    asm.bsr(Size::Qword, Rcx, Rdx);
    asm.bit(BitTest::Bt, Size::Qword, Rax, Rcx);
    asm.setcc(Cond::Ae, Rcx);
    asm.movzx(Size::Dword, Rcx, Size::Byte, Rcx);
    asm.shift_imm(ShiftOp::Shl, Size::Dword, Rcx, NZCV_C_SHIFT);
    asm.alu_imm32(Alu::And, Size::Dword, R8, (!(1u32 << NZCV_C_SHIFT)) as i32);
    asm.alu(Alu::Or, Size::Dword, R8, Rcx);
    asm.mov_imm32(R10, 1);
    code.asm().bind(empty);
}

pub(crate) fn finish_predtest(code: &mut Code) {
    let mut asm = code.asm();
    asm.test(Size::Qword, R9, R9);
    asm.setcc(Cond::E, Rax);
    asm.movzx(Size::Dword, Rax, Size::Byte, Rax);
    asm.shift_imm(ShiftOp::Shl, Size::Dword, Rax, NZCV_Z_SHIFT);
    asm.alu(Alu::Or, Size::Dword, Rax, R8);
    asm.mov_store(
        Size::Dword,
        Mem::base_disp32(Rdi, (core::mem::offset_of!(crate::GuestState, nzcv)) as i32),
        Rax,
    );
}
