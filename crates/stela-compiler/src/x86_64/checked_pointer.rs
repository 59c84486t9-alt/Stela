//! FEAT_CPA checked pointer arithmetic. Clobbers caller-saved GPRs and host flags
//! only.
use super::{Register, Shift, Width, load, right_operand, store};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Size, Unary};
use crate::{
    aarch64::checked_pointer::{Kind, Operand},
    context::pointer::EffectivePointerChecks,
};

pub(crate) fn emit(code: &mut Code, operand: &Operand, checks: EffectivePointerChecks) {
    // These arithmetic checks mark a pointer and cannot fault by themselves.
    // Feature/control admission must precede this discarded-result shortcut.
    if operand.destination == Register::Zero {
        code.asm().nop();
        return;
    }
    let unchanged_base = match operand.kind {
        Kind::Offset {
            base,
            offset: Register::Zero,
            ..
        } => Some(base),
        Kind::Product {
            left, right, base, ..
        } if left == Register::Zero || right == Register::Zero => Some(base),
        _ => None,
    };
    if let Some(base) = unchanged_base {
        // Zero offset/product cannot change the top byte or overflow a product.
        // An already marked base has bit54=NOT bit55, so marking is idempotent.
        if operand.destination == base {
            code.asm().nop();
        } else {
            load(code, base);
            store(code, operand.destination);
        }
        return;
    }
    let checking = checks != EffectivePointerChecks::Unchecked;
    let multiply_checking = checks == EffectivePointerChecks::AdditionAndMultiplication;
    let product = match operand.kind {
        Kind::Offset {
            base,
            offset,
            amount,
            subtract,
        } => {
            load(code, base);
            if checking {
                code.asm().mov(Size::Qword, Gpr::Rdx, Gpr::Rax);
            }
            right_operand(code, offset, Width::X64, Shift::Lsl, amount);
            let op = if subtract { Alu::Sub } else { Alu::Add };
            code.asm().alu(op, Size::Qword, Gpr::Rax, Gpr::Rcx);
            false
        }
        Kind::Product {
            left,
            right,
            base,
            subtract,
        } => {
            load(code, left);
            right_operand(code, right, Width::X64, Shift::Lsl, 0);
            let mut asm = code.asm();
            if multiply_checking {
                asm.alu(Alu::Xor, Size::Dword, Gpr::R8, Gpr::R8);
            }
            asm.imul(Size::Qword, Gpr::Rax, Gpr::Rcx);
            if multiply_checking {
                // IMUL OF is exactly full signed product != sign_extend(low64).
                // Capture it before NEG, ZR materialization or ADD changes flags.
                asm.setcc(Cond::O, Gpr::R8);
            }
            if subtract {
                asm.unary(Unary::Neg, Size::Qword, Gpr::Rax);
            }
            if checking || base != Register::Zero {
                right_operand(code, base, Width::X64, Shift::Lsl, 0);
                let mut asm = code.asm();
                if checking {
                    asm.mov(Size::Qword, Gpr::Rdx, Gpr::Rcx);
                }
                if base != Register::Zero {
                    asm.alu(Alu::Add, Size::Qword, Gpr::Rax, Gpr::Rcx);
                }
            }
            true
        }
    };
    if checking {
        super::pointer_checks::emit(code, product && multiply_checking);
    }
    // Every source was consumed before this one destination commit, including aliases.
    store(code, operand.destination);
}
