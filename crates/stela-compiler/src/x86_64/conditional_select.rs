//! Branchless conditional select from the saved guest NZCV.
use super::{capture_nzcv, condition_holds, flag_word, load, right_operand, store, store_nzcv};
use crate::aarch64::{
    Shift, Width,
    conditional_select::{CompareOperand, CompareRight, Operand, Otherwise},
};
use crate::x86_64::asm::{
    Alu, Code, Cond,
    Gpr::{R8, Rax, Rcx, Rdx},
    Size, Unary,
};

const NZCV_SHIFT: u8 = 28;

/// The comparison runs on both arms and a CMOV picks its flags or the
/// fallback, so the timing depends on neither the condition nor the data.
pub(super) fn emit_compare(code: &mut Code, operand: &CompareOperand) {
    let predicate = condition_holds(code, operand.condition, false);
    if let Some(cond) = predicate {
        // R8 is scratch under the native leaf ABI.
        code.asm().setcc(cond, R8);
    }
    load(code, operand.left);
    match operand.right {
        CompareRight::Register(register) => {
            right_operand(code, register, operand.width, Shift::Lsl, 0)
        }
        CompareRight::Immediate(value) => code.asm().mov_imm32(Rcx, u32::from(value)),
    }
    let op = if operand.subtract { Alu::Sub } else { Alu::Add };
    code.asm()
        .alu(op, Size::of(operand.width == Width::X64), Rax, Rcx);
    let pinned = code.is_pinned();
    if pinned {
        flag_word::capture_in_rax(code, operand.subtract);
    } else {
        capture_nzcv(code, operand.subtract);
    }
    let fallback = flag_word::constant(code, u32::from(operand.fallback) << NZCV_SHIFT);
    let mut asm = code.asm();
    if predicate.is_some() {
        // The fallback NZCV word where the condition fails.
        asm.mov_imm32(Rdx, fallback);
        asm.test(Size::Byte, R8, R8);
        asm.cmov(Cond::E, Size::Dword, Rax, Rdx);
    }
    if pinned {
        flag_word::store(&mut asm, Rax);
    } else {
        store_nzcv(&mut asm);
    }
}

pub(super) fn emit(code: &mut Code, operand: &Operand) {
    let predicate = condition_holds(code, operand.condition, false);
    if let Some(cond) = predicate {
        // Save the condition before zero-register loads or false-arm arithmetic
        // clobber host flags. R8 is scratch under the native leaf ABI.
        code.asm().setcc(cond, R8);
    }
    load(code, operand.left);
    let size = Size::of(operand.width == Width::X64);
    if operand.width == Width::W32 {
        // Clear Xd's upper half on both arms.
        code.asm().mov(Size::Dword, Rax, Rax);
    }
    if predicate.is_some() {
        right_operand(code, operand.right, operand.width, Shift::Lsl, 0);
        let mut asm = code.asm();
        match operand.otherwise {
            Otherwise::Increment => asm.inc(size, Rcx),
            Otherwise::Invert => asm.unary(Unary::Not, size, Rcx),
            Otherwise::Negate => asm.unary(Unary::Neg, size, Rcx),
            Otherwise::Unchanged => {}
        }
        asm.test(Size::Byte, R8, R8);
        asm.cmov(Cond::E, size, Rax, Rcx);
    }
    // AL and NV both satisfy ConditionHolds: select Rn without transforming Rm.
    store(code, operand.destination);
}
