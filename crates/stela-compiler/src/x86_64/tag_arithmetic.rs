//! MTE tag arithmetic under the fixed guest tag controls.
use super::{Register, Shift, Width, load, offset, right_operand, store};
use crate::x86_64::asm::{Alu, BitTest, Code, Cond, Gpr, Mem, ShiftOp, Size};
use crate::{
    GuestState,
    aarch64::tag_arithmetic::{Kind, Operand},
};

const HIGH_BYTE_OFFSET: u32 = 7;
const TOP_BYTE_ROTATE: u8 = 8;
const SIGN_EXTEND_SHIFT: u8 = 8;
const TAG_MASK: u8 = 15;
const MASK_BIT: u32 = 1;
const TOP_NIBBLE_MASK: u8 = 0xf0;
const NZCV_OFFSET: u32 = core::mem::offset_of!(GuestState, nzcv) as u32;
const N_SHIFT: u8 = 31;
const Z_SHIFT: u8 = 30;
const C_SHIFT: u8 = 29;

/// The guest state field at `offset` from RDI.
const fn state(offset: u32) -> Mem {
    Mem::base_disp32(Gpr::Rdi, offset as i32)
}

pub(super) fn emit(code: &mut Code, operand: &Operand) {
    if operand.destination == Register::Zero
        && !matches!(operand.kind, Kind::Difference { flags: true, .. })
    {
        code.asm().nop();
        return;
    }
    match operand.kind {
        Kind::Offset {
            source,
            subtract,
            address_offset,
            tag_offset,
        } => {
            emit_offset(
                code,
                operand.destination,
                source,
                subtract,
                address_offset,
                tag_offset,
            );
        }
        Kind::Difference { left, right, flags } => {
            load(code, left);
            right_operand(code, right, Width::X64, Shift::Lsl, 0);
            // Each signed56 input must be extended independently: their difference
            // requires57 bits and cannot be recovered from a wrapped shifted SUB.
            let mut asm = code.asm();
            for register in [Gpr::Rax, Gpr::Rcx] {
                asm.shift_imm(ShiftOp::Shl, Size::Qword, register, SIGN_EXTEND_SHIFT);
                asm.shift_imm(ShiftOp::Sar, Size::Qword, register, SIGN_EXTEND_SHIFT);
            }
            asm.alu(Alu::Sub, Size::Qword, Gpr::Rax, Gpr::Rcx);
            store(code, operand.destination);
            if flags {
                emit_difference_flags(code);
            }
        }
        Kind::Mask { address, mask } => {
            emit_mask(code, operand.destination, address, mask);
        }
    }
}

fn tag_input(code: &mut Code, source: Register, increment: u8) {
    let source_offset = offset(source).expect("tag address source is GPR or SP");
    let mut asm = code.asm();
    asm.movzx(
        Size::Dword,
        Gpr::Rcx,
        Size::Byte,
        state(source_offset + HIGH_BYTE_OFFSET),
    );
    if increment != 0 {
        asm.alu_imm8(Alu::Add, Size::Dword, Gpr::Rcx, increment as i8);
    }
    asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rcx, TAG_MASK as i8);
}

fn emit_offset(
    code: &mut Code,
    destination: Register,
    source: Register,
    subtract: bool,
    address_offset: u16,
    tag_offset: u8,
) {
    if address_offset == 0 && tag_offset == 0 {
        if destination == source {
            code.asm().nop();
        } else {
            load(code, source);
            store(code, destination);
        }
        return;
    }
    load(code, source);
    // Extract the tag before the address arithmetic; the carry or borrow may
    // cross the tag field and must still reach the preserved high nibble.
    tag_input(code, source, tag_offset);
    let mut asm = code.asm();
    if address_offset != 0 {
        let displacement = i32::from(address_offset) * if subtract { -1 } else { 1 };
        if let Ok(displacement) = i8::try_from(displacement) {
            asm.lea(
                Size::Qword,
                Gpr::Rax,
                Mem::base_disp8(Gpr::Rax, displacement),
            );
        } else {
            let op = if subtract { Alu::Sub } else { Alu::Add };
            asm.alu_accumulator_imm32(op, Size::Qword, i32::from(address_offset));
        }
    }
    asm.shift_imm(ShiftOp::Rol, Size::Qword, Gpr::Rax, TOP_BYTE_ROTATE);
    asm.alu_accumulator_imm8(Alu::And, TOP_NIBBLE_MASK);
    asm.alu(Alu::Or, Size::Byte, Gpr::Rax, Gpr::Rcx);
    asm.shift_imm(ShiftOp::Ror, Size::Qword, Gpr::Rax, TOP_BYTE_ROTATE);
    store(code, destination);
}

fn emit_mask(code: &mut Code, destination: Register, address: Register, mask: Register) {
    if destination == mask {
        // Read the tag before any in-place update, including when the address
        // aliases the mask. EDX's high half stays zero for tags 0-15.
        tag_input(code, address, 0);
        let mask = offset(mask).expect("discarded GMI was handled before emission");
        let mut asm = code.asm();
        asm.mov_imm32(Gpr::Rdx, MASK_BIT);
        asm.shift_cl(ShiftOp::Shl, Size::Dword, Gpr::Rdx);
        asm.alu(Alu::Or, Size::Qword, state(mask), Gpr::Rdx);
    } else {
        load(code, mask);
        tag_input(code, address, 0);
        code.asm()
            .bit(BitTest::Bts, Size::Qword, Gpr::Rax, Gpr::Rcx);
        store(code, destination);
    }
}

fn emit_difference_flags(code: &mut Code) {
    // Signed56 differences cannot overflow signed64, so guest V is always0.
    // Capture all three predicates before shifts/ORs alter the host flags.
    let flags = [
        (Cond::S, Gpr::Rax, N_SHIFT),
        (Cond::E, Gpr::Rcx, Z_SHIFT),
        (Cond::Ae, Gpr::Rdx, C_SHIFT),
    ];
    let mut asm = code.asm();
    for (condition, register, _) in flags {
        asm.setcc(condition, register);
    }
    for (_, register, _) in flags {
        asm.movzx(Size::Dword, register, Size::Byte, register);
    }
    for (_, register, amount) in flags {
        asm.shift_imm(ShiftOp::Shl, Size::Dword, register, amount);
    }
    asm.alu(Alu::Or, Size::Dword, Gpr::Rax, Gpr::Rcx);
    asm.alu(Alu::Or, Size::Dword, Gpr::Rax, Gpr::Rdx);
    asm.mov_store(Size::Dword, state(NZCV_OFFSET), Gpr::Rax);
}
