//! Branchless conditional select from the saved guest NZCV.
use super::{capture_nzcv, condition, load, right_operand, store};
use crate::aarch64::{
    Shift, Width,
    conditional_select::{CompareOperand, CompareRight, Operand, Otherwise},
};
use crate::x86_64::asm::Code;

/// MOV EDX,imm32: the fallback NZCV word.
const MOV_EDX_IMM32: u8 = 0xba;
/// SETcc R8B (the condition's opcode plus this) and TEST R8B,R8B.
const SET_FROM_JUMP: u8 = 0x10;
const TEST_R8B: [u8; 3] = [0x45, 0x84, 0xc0];
const CMOVZ_EAX_EDX: [u8; 3] = [0x0f, 0x44, 0xc2];
const STORE_EAX_NZCV: [u8; 2] = [0x89, 0x87];
const STATE_NZCV_OFFSET: u32 = core::mem::offset_of!(crate::GuestState, nzcv) as u32;
const NZCV_SHIFT: u8 = 28;

/// The comparison runs on both arms and a CMOV picks its flags or the
/// fallback, so the timing depends on neither the condition nor the data.
pub(super) fn emit_compare(code: &mut Code, operand: &CompareOperand) {
    let predicate = condition(code, operand.condition);
    if let Some(jcc) = predicate {
        // R8 is scratch under the native leaf ABI.
        code.extend([0x41, 0x0f, jcc + SET_FROM_JUMP, 0xc0]); // setcc r8b
    }
    load(code, operand.left);
    match operand.right {
        CompareRight::Register(register) => {
            right_operand(code, register, operand.width, Shift::Lsl, 0)
        }
        CompareRight::Immediate(value) => {
            code.push(0xb9);
            code.extend(u32::from(value).to_le_bytes());
        }
    }
    if operand.width == Width::X64 {
        code.push(0x48);
    }
    code.extend([if operand.subtract { 0x29 } else { 0x01 }, 0xc8]);
    capture_nzcv(code, operand.subtract);
    if predicate.is_some() {
        code.push(MOV_EDX_IMM32);
        code.extend((u32::from(operand.fallback) << NZCV_SHIFT).to_le_bytes());
        code.extend(TEST_R8B);
        code.extend(CMOVZ_EAX_EDX);
    }
    code.extend(STORE_EAX_NZCV);
    code.extend(STATE_NZCV_OFFSET.to_le_bytes());
}

pub(super) fn emit(code: &mut Code, operand: &Operand) {
    let predicate = condition(code, operand.condition);
    if let Some(jcc) = predicate {
        // Save the condition before zero-register loads or false-arm arithmetic
        // clobber host flags. R8 is scratch under the native leaf ABI.
        code.extend([0x41, 0x0f, jcc + SET_FROM_JUMP, 0xc0]); // setcc r8b
    }
    load(code, operand.left);
    if operand.width == Width::W32 {
        code.extend([0x89, 0xc0]); // mov eax,eax: clear Xd's upper half on both arms
    }
    if predicate.is_some() {
        right_operand(code, operand.right, operand.width, Shift::Lsl, 0);
        if operand.otherwise != Otherwise::Unchanged {
            if operand.width == Width::X64 {
                code.push(0x48);
            }
            match operand.otherwise {
                Otherwise::Increment => code.extend([0xff, 0xc1]), // inc (e/r)cx
                Otherwise::Invert => code.extend([0xf7, 0xd1]),    // not (e/r)cx
                Otherwise::Negate => code.extend([0xf7, 0xd9]),    // neg (e/r)cx
                Otherwise::Unchanged => unreachable!(),
            }
        }
        code.extend([0x45, 0x84, 0xc0]); // test r8b,r8b
        if operand.width == Width::X64 {
            code.push(0x48);
        }
        code.extend([0x0f, 0x44, 0xc1]); // cmovz (e/r)ax,(e/r)cx
    }
    // AL and NV both satisfy ConditionHolds: select Rn without transforming Rm.
    store(code, operand.destination);
}
