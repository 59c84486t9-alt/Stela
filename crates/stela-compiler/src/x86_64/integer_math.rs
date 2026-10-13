//! Baseline x86-64 integer math; guest NZCV stays unchanged.
use super::{Register, Shift, Width, load, right_operand, store};
use crate::aarch64::integer_math::{Kind, Operand};

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    load(code, operand.left);
    match operand.kind {
        Kind::LeadingZeros { width } => {
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([0x0f, 0xbd, 0xc0]); // bsr (r/e)ax,(r/e)ax
            let bits = if width == Width::X64 { 64u32 } else { 32 };
            code.push(0xb9); // mov ecx,2*width-1: preserves BSR ZF
            code.extend((2 * bits - 1).to_le_bytes());
            if width == Width::X64 {
                code.push(0x48);
            }
            // BSR's zero-input destination is undefined: replace it before use.
            code.extend([0x0f, 0x44, 0xc1]); // cmovz (r/e)ax,(r/e)cx
            if width == Width::X64 {
                code.push(0x48);
            }
            // Nonzero: (width-1)-MSB. Zero: (2*width-1) XOR (width-1)=width.
            code.extend([0x83, 0xf0, (bits - 1) as u8]);
            store(code, operand.destination);
            return;
        }
        Kind::ReverseBytes { halfwords } => {
            code.extend([0x0f, 0xc8]); // bswap eax, always clears upper X half
            if halfwords {
                // Full reversal plus halfword rotation swaps each byte pair.
                code.extend([0xc1, 0xc8, 16]); // ror eax,16
            }
            store(code, operand.destination);
            return;
        }
        _ => {}
    }
    right_operand(code, operand.right, Width::X64, Shift::Lsl, 0);
    if let Kind::Divide { signed, width } = operand.kind {
        divide(code, signed, width);
        store(code, operand.destination);
        return;
    }
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
        Kind::Divide { .. } | Kind::LeadingZeros { .. } | Kind::ReverseBytes { .. } => {
            unreachable!("division and unary operations emitted above")
        }
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

fn branch(code: &mut Vec<u8>, opcode: Option<u8>) -> usize {
    if let Some(opcode) = opcode {
        code.extend([0x0f, opcode]);
    } else {
        code.push(0xe9);
    }
    let displacement = code.len();
    code.extend([0; 4]);
    displacement
}

fn bind(code: &mut [u8], displacement: usize, target: usize) {
    let offset = i32::try_from(target as i64 - (displacement + 4) as i64)
        .expect("bounded integer division lowering");
    code[displacement..displacement + 4].copy_from_slice(&offset.to_le_bytes());
}

/// RAX and RCX hold the original operands. x86 DIV/IDIV would fault on a zero
/// divisor and IDIV on MIN/-1. Arm instead returns zero or the wrapped MIN.
/// Negating for divisor -1 handles that overflow without issuing IDIV.
fn divide(code: &mut Vec<u8>, signed: bool, width: Width) {
    if width == Width::W32 {
        code.extend([0x89, 0xc0]); // mov eax,eax: clear discarded high dividend
    } else {
        code.push(0x48);
    }
    code.extend([0x85, 0xc9]); // test (r/e)cx,(r/e)cx
    let zero = branch(code, Some(0x84));
    let mut minus_one_done = None;
    if signed {
        if width == Width::X64 {
            code.push(0x48);
        }
        code.extend([0x83, 0xf9, 0xff]); // cmp (r/e)cx,-1
        let ordinary = branch(code, Some(0x85));
        if width == Width::X64 {
            code.push(0x48);
        }
        code.extend([0xf7, 0xd8]); // neg (r/e)ax, including MIN wraparound
        minus_one_done = Some(branch(code, None));
        let target = code.len();
        bind(code, ordinary, target);
        if width == Width::X64 {
            code.push(0x48);
        }
        code.push(0x99); // cqo or cdq: signed high dividend
    } else {
        code.extend([0x31, 0xd2]); // xor edx,edx: unsigned high dividend
    }
    if width == Width::X64 {
        code.push(0x48);
    }
    code.extend([0xf7, if signed { 0xf9 } else { 0xf1 }]); // idiv/div (r/e)cx
    let ordinary_done = branch(code, None);
    let target = code.len();
    bind(code, zero, target);
    code.extend([0x31, 0xc0]); // zero divisor produces zero, never native #DE
    let target = code.len();
    bind(code, ordinary_done, target);
    if let Some(displacement) = minus_one_done {
        bind(code, displacement, target);
    }
}
