//! Scalar leading-bit counts. BSR's result is undefined for zero and is fixed up.
use crate::aarch64::scalable::ElementSize;
use crate::x86_64::asm::Gpr::{Rax, Rcx, Rdx, Rsp};
use crate::x86_64::asm::{Alu, Code, Cond, Mem, ShiftOp, Size};

const CHUNK_BYTES: usize = 16;
const RESULT_SLOT: u8 = CHUNK_BYTES as u8;
const STACK_BYTES: u8 = 2 * CHUNK_BYTES as u8;

fn stack(slot: u8) -> Mem {
    Mem::base_disp8(Rsp, slot as i8)
}

pub(super) fn chunk(code: &mut Code, element: ElementSize, sign: bool) {
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Sub, Size::Qword, Rsp, STACK_BYTES as i8);
    asm.movdqu_store(stack(0), 0);
    for offset in (0..CHUNK_BYTES).step_by(element.bytes()) {
        let lane = stack(offset as u8);
        match (element, sign) {
            (ElementSize::Byte, false) => asm.movzx(Size::Dword, Rax, Size::Byte, lane),
            (ElementSize::Byte, true) => asm.movsx(Size::Qword, Rax, Size::Byte, lane),
            (ElementSize::Halfword, false) => asm.movzx(Size::Dword, Rax, Size::Word, lane),
            (ElementSize::Halfword, true) => asm.movsx(Size::Qword, Rax, Size::Word, lane),
            (ElementSize::Word, false) => asm.mov_load(Size::Dword, Rax, lane),
            (ElementSize::Word, true) => asm.movsxd(Rax, lane),
            (ElementSize::Doubleword, _) => asm.mov_load(Size::Qword, Rax, lane),
            _ => unreachable!(),
        }
        if sign {
            asm.mov(Size::Qword, Rdx, Rax);
            asm.shift_imm(ShiftOp::Sar, Size::Qword, Rdx, u64::BITS as u8 - 1);
            asm.alu(Alu::Xor, Size::Qword, Rax, Rdx);
        }
        asm.bsr(Size::Qword, Rdx, Rax);
        // MOV preserves BSR's ZF. Zero maps to -1 before any arithmetic uses it.
        asm.mov_rm_imm32(Size::Qword, Rcx, -1);
        asm.cmov(Cond::E, Size::Qword, Rdx, Rcx);
        asm.mov_imm32(Rax, element.bits() as u32 - 1 - u32::from(sign));
        asm.alu(Alu::Sub, Size::Qword, Rax, Rdx);
        let size = match element {
            ElementSize::Byte => Size::Byte,
            ElementSize::Halfword => Size::Word,
            ElementSize::Word => Size::Dword,
            ElementSize::Doubleword => Size::Qword,
            _ => unreachable!(),
        };
        asm.mov_store(size, stack(RESULT_SLOT + offset as u8), Rax);
    }
    asm.movdqu_load(0, stack(RESULT_SLOT));
    asm.alu_imm8(Alu::Add, Size::Qword, Rsp, STACK_BYTES as i8);
}
