//! Integer multiply, divide, shifts and bit operations. Guest NZCV is unchanged.
use super::{
    Register, Shift, Width,
    asm::{Alu, Asm, Cond, Gpr, ShiftOp, Size, Unary},
    integer_unary, load_with, right_operand_with, store_with,
};
use crate::{
    TargetCpu,
    aarch64::integer_math::{Kind, Operand},
};
use alloc::vec::Vec;

use Gpr::{Rax, Rcx, Rdx};

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    emit_with(&mut Asm::new(code), operand, target);
}

fn size(width: Width) -> Size {
    Size::of(width == Width::X64)
}

pub(super) fn emit_with(asm: &mut Asm, operand: &Operand, target: TargetCpu) {
    load_with(asm, operand.left);
    match operand.kind {
        Kind::LeadingZeros { width } | Kind::LeadingSignBits { width } => {
            let sign_bits = matches!(operand.kind, Kind::LeadingSignBits { .. });
            let size = size(width);
            if sign_bits {
                // XOR with the sign mask: the value or its complement, nonnegative.
                asm.mov(size, Rcx, Rax);
                asm.shift_imm(ShiftOp::Sar, size, Rcx, size.bits() as u8 - 1);
                asm.alu(Alu::Xor, size, Rax, Rcx);
            }
            if target.data_independent_timing() {
                leading_zeros_without_bsr(asm, size, sign_bits);
            } else {
                let bits = size.bits();
                asm.bsr(size, Rax, Rax);
                // MOV preserves BSR's ZF; BSR leaves a zero input's
                // destination undefined, so CMOVZ replaces it before use.
                asm.mov_imm32(Rcx, 2 * bits - 1);
                asm.cmov(Cond::E, size, Rax, Rcx);
                // Nonzero: (width-1)-MSB. Zero: (2*width-1) XOR (width-1)=width.
                asm.alu_imm8(Alu::Xor, size, Rax, (bits - 1) as i8);
                if sign_bits {
                    // Omit the sign bit itself.
                    asm.alu_imm8(Alu::Sub, Size::Dword, Rax, 1);
                }
            }
            store_with(asm, operand.destination);
            return;
        }
        Kind::ReverseBits { width } => {
            for (shift, mask) in [
                (1, 0x5555555555555555),
                (2, 0x3333333333333333),
                (4, 0x0f0f0f0f0f0f0f0f),
            ] {
                swap_groups(asm, width, shift, mask);
            }
            // BSWAP completes the reversal of the independently reversed bytes.
            asm.bswap(size(width), Rax);
            store_with(asm, operand.destination);
            return;
        }
        Kind::ReverseBytes { width, group_bytes } => {
            if width == Width::X64 && group_bytes == 2 {
                swap_groups(asm, width, 8, 0x00ff00ff00ff00ff);
            } else {
                asm.bswap(size(width), Rax);
                let rotate = match (width, group_bytes) {
                    (Width::W32, 2) => Some(16),
                    (Width::X64, 4) => Some(32),
                    _ => None,
                };
                if let Some(amount) = rotate {
                    // ROR restores container order.
                    asm.shift_imm(ShiftOp::Ror, size(width), Rax, amount);
                }
            }
            store_with(asm, operand.destination);
            return;
        }
        _ => {}
    }
    right_operand_with(asm, operand.right, Width::X64, Shift::Lsl, 0);
    match operand.kind {
        Kind::VariableShift { width, shift } => {
            // A zero shift must still clear Xd's upper half for a W result,
            // so the W form starts with a zero-extending move.
            if width == Width::W32 {
                asm.mov(Size::Dword, Rax, Rax);
            }
            // CL masking implements Arm's modulo-width count.
            let op = match shift {
                Shift::Lsl => ShiftOp::Shl,
                Shift::Lsr => ShiftOp::Shr,
                Shift::Asr => ShiftOp::Sar,
                Shift::Ror => ShiftOp::Ror,
            };
            asm.shift_cl(op, size(width), Rax);
            store_with(asm, operand.destination);
            return;
        }
        Kind::Extract { width, amount } => {
            asm.shrd_imm(size(width), Rcx, Rax, amount);
            // The W move also clears the upper half at shift zero.
            asm.mov(size(width), Rax, Rcx);
            store_with(asm, operand.destination);
            return;
        }
        _ => {}
    }
    if let Kind::Divide { signed, width } = operand.kind {
        divide(asm, signed, width);
        store_with(asm, operand.destination);
        return;
    }
    let width = match operand.kind {
        Kind::High { signed } => {
            // One-operand x86 multiply produces the complete RDX:RAX product.
            let op = if signed { Unary::Imul } else { Unary::Mul };
            asm.unary(op, Size::Qword, Rcx);
            asm.mov(Size::Qword, Rax, Rdx);
            store_with(asm, operand.destination);
            return;
        }
        Kind::Long { signed } => {
            if signed {
                asm.movsxd(Rax, Rax);
                asm.movsxd(Rcx, Rcx);
            } else {
                asm.mov(Size::Dword, Rax, Rax);
                asm.mov(Size::Dword, Rcx, Rcx);
            }
            Width::X64
        }
        Kind::Low { width } => width,
        Kind::VariableShift { .. }
        | Kind::Extract { .. }
        | Kind::Divide { .. }
        | Kind::LeadingZeros { .. }
        | Kind::LeadingSignBits { .. }
        | Kind::ReverseBits { .. }
        | Kind::ReverseBytes { .. } => {
            unreachable!("division and unary operations emitted above")
        }
    };
    asm.imul(size(width), Rax, Rcx);
    if operand.subtract {
        // Negation modulo the destination width.
        asm.unary(Unary::Neg, size(width), Rax);
    }
    // Guest sources are memory-backed and no destination has been committed,
    // so Rd may alias Rn, Rm or Ra without destroying a still-needed source.
    if operand.accumulator != Register::Zero {
        right_operand_with(asm, operand.accumulator, width, Shift::Lsl, 0);
        asm.alu(Alu::Add, size(width), Rax, Rcx);
    }
    store_with(asm, operand.destination);
}

/// CLZ (or, after the sign fold, CLS) without BSR or LZCNT, neither on
/// Intel's data operand independent timing list: every bit below the
/// highest set one is set by shifted ORs, so the count is the width less the
/// population count of the smear.
fn leading_zeros_without_bsr(asm: &mut Asm, size: Size, sign_bits: bool) {
    let bits = size.bits() as u8;
    let mut shift = 1;
    while shift < bits {
        asm.mov(size, Rcx, Rax);
        asm.shift_imm(ShiftOp::Shr, size, Rcx, shift);
        asm.alu(Alu::Or, size, Rax, Rcx);
        shift *= 2;
    }
    integer_unary::population_count(asm, size == Size::Qword);
    // The count fits 32 bits: bits - popcount (less the sign bit for CLS).
    asm.unary(Unary::Neg, Size::Dword, Rax);
    asm.alu_imm8(
        Alu::Add,
        Size::Dword,
        Rax,
        (bits - u8::from(sign_bits)) as i8,
    );
}

/// Swap adjacent `shift`-bit groups of RAX with baseline shifts and masks;
/// RCX and RDX are scratch.
fn swap_groups(asm: &mut Asm, width: Width, shift: u8, mask: u64) {
    let size = size(width);
    asm.mov(size, Rcx, Rax);
    asm.shift_imm(ShiftOp::Shr, size, Rax, shift);
    if width == Width::X64 {
        asm.mov_imm64(Rdx, mask);
        asm.alu(Alu::And, size, Rax, Rdx);
        asm.alu(Alu::And, size, Rcx, Rdx);
    } else {
        asm.alu_accumulator_imm32(Alu::And, size, mask as u32 as i32);
        asm.alu_imm32(Alu::And, size, Rcx, mask as u32 as i32);
    }
    asm.shift_imm(ShiftOp::Shl, size, Rcx, shift);
    asm.alu(Alu::Or, size, Rax, Rcx);
}

/// RAX and RCX hold the operands. x86 DIV/IDIV fault on a zero divisor, and
/// IDIV also on MIN / -1, where Arm returns zero or the wrapped MIN. A divisor
/// of -1 is handled by negation instead of IDIV.
fn divide(asm: &mut Asm, signed: bool, width: Width) {
    let size = size(width);
    if width == Width::W32 {
        // Clear the discarded high dividend.
        asm.mov(Size::Dword, Rax, Rax);
    }
    asm.test(size, Rcx, Rcx);
    let zero = asm.jcc(Cond::E);
    let mut minus_one_done = None;
    if signed {
        asm.alu_imm8(Alu::Cmp, size, Rcx, -1);
        let ordinary = asm.jcc(Cond::Ne);
        // Negation, including MIN wraparound.
        asm.unary(Unary::Neg, size, Rax);
        minus_one_done = Some(asm.jmp());
        asm.bind(ordinary);
        asm.sign_extend_accumulator(size);
    } else {
        // Unsigned high dividend.
        asm.alu(Alu::Xor, Size::Dword, Rdx, Rdx);
    }
    let op = if signed { Unary::Idiv } else { Unary::Div };
    asm.unary(op, size, Rcx);
    let ordinary_done = asm.jmp();
    asm.bind(zero);
    // A zero divisor produces zero, never a native #DE.
    asm.alu(Alu::Xor, Size::Dword, Rax, Rax);
    asm.bind(ordinary_done);
    if let Some(patch) = minus_one_done {
        asm.bind(patch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operand(kind: Kind) -> Operand {
        Operand {
            kind,
            subtract: false,
            destination: Register::X(0),
            left: Register::X(1),
            right: Register::X(2),
            accumulator: Register::Zero,
        }
    }

    /// The smear-and-count model of the DIT lowering, on every leading-zero
    /// count of both widths.
    #[test]
    fn the_smear_counts_leading_zeros_and_sign_bits_without_bsr() {
        for bits in [32u32, 64] {
            for leading in 0..=bits {
                let value = if leading == bits {
                    0
                } else {
                    u64::MAX >> (64 - bits + leading)
                };
                let mut smear = value;
                let mut shift = 1;
                while shift < bits {
                    smear |= smear >> shift;
                    shift *= 2;
                }
                assert_eq!(bits - smear.count_ones(), leading);
            }
        }
        for width in [Width::W32, Width::X64] {
            for kind in [
                Kind::LeadingZeros { width },
                Kind::LeadingSignBits { width },
            ] {
                let mut ordinary = Vec::new();
                emit(&mut ordinary, &operand(kind), TargetCpu::Baseline);
                let mut timed = Vec::new();
                emit(&mut timed, &operand(kind), TargetCpu::DataIndependentTiming);
                let bsr = |code: &[u8]| code.windows(2).any(|pair| pair == [0x0f, 0xbd]);
                assert!(bsr(&ordinary));
                assert!(!bsr(&timed));
            }
        }
    }
}
