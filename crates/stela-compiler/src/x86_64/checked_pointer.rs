//! Baseline x86-64 CPA arithmetic using owner-resolved effective check effects.
//!
//! The entry owner proves FEAT_CPA and validates its control lease before entry.
//! RDI remains the guest state pointer. Only caller-saved GPRs/host flags change;
//! no guest flags, floating state, RAM or system registers are touched.
use super::{Register, Shift, Width, load, right_operand, store};
use crate::{
    aarch64::checked_pointer::{Kind, Operand},
    context::pointer::EffectivePointerChecks,
};

const NOP: u8 = 0x90;
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const MOV_RDX_RCX: &[u8] = &[0x48, 0x89, 0xca];
const XOR_R8D_R8D: &[u8] = &[0x45, 0x31, 0xc0];
const ADD_RAX_RCX: &[u8] = &[0x48, 0x01, 0xc8];
const SUB_RAX_RCX: &[u8] = &[0x48, 0x29, 0xc8];
const IMUL_RAX_RCX: &[u8] = &[0x48, 0x0f, 0xaf, 0xc1];
const NEG_RAX: &[u8] = &[0x48, 0xf7, 0xd8];
const SETO_R8B: &[u8] = &[0x41, 0x0f, 0x90, 0xc0];

pub(crate) fn emit(code: &mut Vec<u8>, operand: &Operand, checks: EffectivePointerChecks) {
    // These arithmetic checks mark a pointer and cannot fault by themselves.
    // Feature/control admission must precede this discarded-result shortcut.
    if operand.destination == Register::Zero {
        code.push(NOP);
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
            code.push(NOP);
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
                code.extend(MOV_RDX_RAX);
            }
            right_operand(code, offset, Width::X64, Shift::Lsl, amount);
            code.extend(if subtract { SUB_RAX_RCX } else { ADD_RAX_RCX });
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
            if multiply_checking {
                code.extend(XOR_R8D_R8D);
            }
            code.extend(IMUL_RAX_RCX);
            if multiply_checking {
                // IMUL OF is exactly full signed product != sign_extend(low64).
                // Capture it before NEG, ZR materialization or ADD changes flags.
                code.extend(SETO_R8B);
            }
            if subtract {
                code.extend(NEG_RAX);
            }
            if checking || base != Register::Zero {
                right_operand(code, base, Width::X64, Shift::Lsl, 0);
                if checking {
                    code.extend(MOV_RDX_RCX);
                }
                if base != Register::Zero {
                    code.extend(ADD_RAX_RCX);
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
