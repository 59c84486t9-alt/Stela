//! Branchless selection from the saved guest NZCV, independent of host flags.
use super::{condition, load, right_operand, store};
use crate::aarch64::{
    Shift, Width,
    conditional_select::{Operand, Otherwise},
};

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
