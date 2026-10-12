//! Baseline x86-64 integer products; ARM NZCV stays in GuestState unchanged.
use super::{Register, Shift, Width, load, right_operand, store};
use crate::aarch64::multiply::{Kind, Operand};

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    load(code, operand.left);
    right_operand(code, operand.right, Width::X64, Shift::Lsl, 0);
    let width = match operand.kind {
        Kind::High { signed } => {
            // One-operand x86 multiply produces the complete RDX:RAX product.
            code.extend([0x48, 0xf7, if signed { 0xe9 } else { 0xe1 }]);
            code.extend([0x48, 0x89, 0xd0]); // mov rax,rdx
            store(code, operand.destination);
            return;
        }
        Kind::Long { signed } => {
            if signed {
                code.extend([0x48, 0x63, 0xc0, 0x48, 0x63, 0xc9]); // movsxd rax,eax; rcx,ecx
            } else {
                code.extend([0x89, 0xc0, 0x89, 0xc9]); // zero-extend both W operands
            }
            Width::X64
        }
        Kind::Low { width } => width,
    };
    if width == Width::X64 {
        code.push(0x48);
    }
    code.extend([0x0f, 0xaf, 0xc1]); // imul (e/r)ax,(e/r)cx: low product
    if operand.subtract {
        if width == Width::X64 {
            code.push(0x48);
        }
        code.extend([0xf7, 0xd8]); // neg (e/r)ax, modulo destination width
    }
    // Guest sources are memory-backed and no destination has been committed,
    // so Rd may alias Rn, Rm or Ra without destroying a still-needed source.
    if operand.accumulator != Register::Zero {
        right_operand(code, operand.accumulator, width, Shift::Lsl, 0);
        if width == Width::X64 {
            code.push(0x48);
        }
        code.extend([0x01, 0xc8]); // add (e/r)ax,(e/r)cx
    }
    store(code, operand.destination);
}
