//! Branchless selection from the saved guest NZCV, independent of host flags.
use super::{condition, load, nzcv, right_operand, store};
use crate::aarch64::{
    Shift, Width,
    conditional_select::{CompareOperand, CompareRight, Operand, Otherwise},
};
use alloc::vec::Vec;

pub(super) fn emit_compare(code: &mut Vec<u8>, operand: &CompareOperand) {
    let branch = condition(code, operand.condition).map(|jcc| {
        code.extend([0x0f, jcc ^ 1]); // false predicate skips arithmetic
        let offset = code.len();
        code.extend([0; 4]);
        offset
    });
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
    nzcv(code, operand.subtract);
    if let Some(offset) = branch {
        // The fallback is a constant NZCV nibble and never writes a GPR.
        code.extend([0xeb, 10]);
        let delta = i32::try_from(code.len() - (offset + 4)).expect("bounded conditional compare");
        code[offset..offset + 4].copy_from_slice(&delta.to_le_bytes());
        code.extend([0xc7, 0x87, 0, 1, 0, 0]);
        code.extend((u32::from(operand.fallback) << 28).to_le_bytes());
    }
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    let predicate = condition(code, operand.condition);
    if let Some(jcc) = predicate {
        // Save the condition before zero-register loads or false-arm arithmetic
        // clobber host flags. R8 is scratch under the native leaf ABI.
        code.extend([0x41, 0x0f, jcc + 0x10, 0xc0]); // setcc r8b
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
