//! FlagM/FlagM2 on the in-memory guest NZCV.
use super::load;
use crate::x86_64::asm::{
    Alu, Code, Cond,
    Gpr::{Rax, Rcx, Rdx},
    Mem, ShiftOp,
    Size::{self, Dword, Qword},
};
use crate::{
    GuestState,
    aarch64::Register,
    aarch64::flags::{Operand, SetWidth},
};

const NZCV_OFFSET: u32 = core::mem::offset_of!(GuestState, nzcv) as u32;
const NZCV_SHIFT: u8 = 28;
const NEGATIVE_BIT: u8 = 3;
const ZERO_BIT: u8 = 2;
const CARRY_BIT: u8 = 1;
const OVERFLOW_BIT: u8 = 0;
const NEGATIVE: u32 = 1 << NEGATIVE_BIT;
const ZERO: u32 = 1 << ZERO_BIT;
const CARRY: u32 = 1 << CARRY_BIT;
const OVERFLOW: u32 = 1 << OVERFLOW_BIT;
const CARRY_MASK: u32 = CARRY << NZCV_SHIFT;
const NZCV_NIBBLE: u8 = (NEGATIVE | ZERO | CARRY | OVERFLOW) as u8;
const TABLE_ENTRY_BITS: u32 = 4;
const TABLE_STRIDE_SHIFT: u8 = 2;
const EXTERNAL_INDEX_SHIFT: u8 = NZCV_SHIFT + CARRY_BIT - TABLE_STRIDE_SHIFT;
const EXTERNAL_INDEX_MASK: u32 = ((ZERO | CARRY) >> CARRY_BIT) << TABLE_STRIDE_SHIFT;
const ARM_INDEX_SHIFT: u8 = NZCV_SHIFT - TABLE_STRIDE_SHIFT;
const ARM_INDEX_MASK: u32 = (ZERO | CARRY | OVERFLOW) << TABLE_STRIDE_SHIFT;
// AXFLAG's index is (Z << 2) | (C << 1) | V. Input N is ignored.
const ARM_TO_EXTERNAL_TABLE: u32 = (ZERO << TABLE_ENTRY_BITS)
    | (CARRY << (2 * TABLE_ENTRY_BITS))
    | (ZERO << (3 * TABLE_ENTRY_BITS))
    | (ZERO << (4 * TABLE_ENTRY_BITS))
    | (ZERO << (5 * TABLE_ENTRY_BITS))
    | ((ZERO | CARRY) << (6 * TABLE_ENTRY_BITS))
    | (ZERO << (7 * TABLE_ENTRY_BITS));
// XAFLAG's input index is (Z << 1) | C; each nibble is its complete NZCV result.
const EXTERNAL_TO_ARM_TABLE: u32 = NEGATIVE
    | (CARRY << TABLE_ENTRY_BITS)
    | ((CARRY | OVERFLOW) << (2 * TABLE_ENTRY_BITS))
    | ((ZERO | CARRY) << (3 * TABLE_ENTRY_BITS));

pub(super) fn emit(code: &mut Code, operand: &Operand) {
    match *operand {
        Operand::InvertCarry => {
            code.asm()
                .alu_imm32(Alu::Xor, Dword, nzcv(), CARRY_MASK as i32);
            return;
        }
        Operand::RotateMask {
            source,
            rotation,
            mask,
        } => {
            if mask == 0 {
                // Every instruction keeps a non-empty source-map range.
                code.asm().nop();
                return;
            }
            let keep = !(u32::from(mask) << NZCV_SHIFT) as i32;
            if source == Register::Zero {
                code.asm().alu_imm32(Alu::And, Dword, nzcv(), keep);
                return;
            }
            load(code, source);
            let mut asm = code.asm();
            if rotation != 0 {
                asm.shift_imm(ShiftOp::Ror, Qword, Rax, rotation);
            }
            asm.alu_accumulator_imm32(Alu::And, Dword, i32::from(mask));
            asm.shift_imm(ShiftOp::Shl, Dword, Rax, NZCV_SHIFT);
            asm.mov_load(Dword, Rcx, nzcv());
            asm.alu_imm32(Alu::And, Dword, Rcx, keep);
            asm.alu(Alu::Or, Dword, Rax, Rcx);
        }
        Operand::Set { source, width } => {
            if source == Register::Zero {
                let mut asm = code.asm();
                asm.mov_load(Dword, Rax, nzcv());
                asm.alu_accumulator_imm32(Alu::And, Dword, CARRY_MASK as i32);
                asm.alu_accumulator_imm32(Alu::Or, Dword, (ZERO << NZCV_SHIFT) as i32);
                asm.mov_store(Dword, nzcv(), Rax);
                return;
            }
            load(code, source);
            let mut asm = code.asm();
            // TEST observes only the architectural byte/halfword; SETZ's
            // partial write is zero-extended before the full-register use.
            asm.mov(Dword, Rcx, Rax);
            asm.shift_imm(ShiftOp::Shr, Dword, Rcx, width.bits() - 1);
            asm.alu_imm32(Alu::And, Dword, Rcx, 1);
            asm.shift_imm(ShiftOp::Shl, Dword, Rcx, NZCV_SHIFT + NEGATIVE_BIT);
            let tested = match width {
                SetWidth::Byte => Size::Byte,
                SetWidth::Halfword => Size::Word,
            };
            asm.test(tested, Rax, Rax);
            asm.setcc(Cond::E, Rdx);
            asm.movzx(Dword, Rdx, Size::Byte, Rdx);
            asm.shift_imm(ShiftOp::Shl, Dword, Rdx, NZCV_SHIFT + ZERO_BIT);
            asm.alu(Alu::Or, Dword, Rcx, Rdx);
            asm.mov(Dword, Rdx, Rax);
            asm.shift_imm(ShiftOp::Shr, Dword, Rdx, width.bits() - 1);
            asm.mov(Dword, Rax, Rdx);
            asm.shift_imm(ShiftOp::Shr, Dword, Rax, 1);
            asm.alu(Alu::Xor, Dword, Rax, Rdx);
            asm.alu_accumulator_imm32(Alu::And, Dword, OVERFLOW as i32);
            asm.shift_imm(ShiftOp::Shl, Dword, Rax, NZCV_SHIFT);
            asm.alu(Alu::Or, Dword, Rax, Rcx);
            asm.mov_load(Dword, Rcx, nzcv());
            asm.alu_imm32(Alu::And, Dword, Rcx, CARRY_MASK as i32);
            asm.alu(Alu::Or, Dword, Rax, Rcx);
        }
        Operand::ArmToExternal => {
            emit_conversion(code, ARM_TO_EXTERNAL_TABLE, ARM_INDEX_SHIFT, ARM_INDEX_MASK);
        }
        Operand::ExternalToArm => {
            emit_conversion(
                code,
                EXTERNAL_TO_ARM_TABLE,
                EXTERNAL_INDEX_SHIFT,
                EXTERNAL_INDEX_MASK,
            );
        }
    }
    code.asm().mov_store(Dword, nzcv(), Rax);
}

/// The guest NZCV word.
fn nzcv() -> Mem {
    super::frame(NZCV_OFFSET)
}

fn emit_conversion(code: &mut Code, table: u32, index_shift: u8, index_mask: u32) {
    let mut asm = code.asm();
    asm.mov_load(Dword, Rcx, nzcv());
    // Each architectural flag result occupies one nibble of the immediate.
    asm.shift_imm(ShiftOp::Shr, Dword, Rcx, index_shift);
    asm.alu_imm32(Alu::And, Dword, Rcx, index_mask as i32);
    asm.mov_imm32(Rax, table);
    asm.shift_cl(ShiftOp::Shr, Dword, Rax);
    asm.alu_accumulator_imm32(Alu::And, Dword, i32::from(NZCV_NIBBLE));
    asm.shift_imm(ShiftOp::Shl, Dword, Rax, NZCV_SHIFT);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_table_matches_all_architectural_flag_inputs() {
        for flags in 0..=u32::from(NZCV_NIBBLE) {
            let zero = flags & ZERO != 0;
            let carry = flags & CARRY != 0;
            let expected = (if !carry && !zero { NEGATIVE } else { 0 })
                | (if zero && carry { ZERO } else { 0 })
                | (if carry || zero { CARRY } else { 0 })
                | (if !carry && zero { OVERFLOW } else { 0 });
            let index = ((flags & (ZERO | CARRY)) >> CARRY_BIT) * TABLE_ENTRY_BITS;
            assert_eq!(
                (EXTERNAL_TO_ARM_TABLE >> index) & u32::from(NZCV_NIBBLE),
                expected
            );
            let overflow = flags & OVERFLOW != 0;
            let expected = (if zero || overflow { ZERO } else { 0 })
                | (if carry && !overflow { CARRY } else { 0 });
            let index = (flags & (ZERO | CARRY | OVERFLOW)) * TABLE_ENTRY_BITS;
            assert_eq!(
                (ARM_TO_EXTERNAL_TABLE >> index) & u32::from(NZCV_NIBBLE),
                expected
            );
        }
    }

    #[test]
    fn zero_rotate_mask_keeps_a_nonempty_mapping_interval() {
        let mut code = Code::new();
        emit(
            &mut code,
            &Operand::RotateMask {
                source: crate::aarch64::Register::Zero,
                rotation: 63,
                mask: 0,
            },
        );
        assert_eq!(code, [0x90]);
    }
}
