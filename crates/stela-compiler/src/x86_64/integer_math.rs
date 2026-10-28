//! Integer multiply, divide, shifts and bit operations. Guest NZCV is unchanged.
use super::{
    Register, Shift, Width,
    asm::{Alu, Asm, Cond, Gpr, Rm, ShiftOp, Size, Unary},
    integer_unary, load_with, right_operand_with, store_with,
};
use crate::x86_64::asm::Code;
use crate::{
    TargetCpu,
    aarch64::integer_math::{Kind, Operand},
};

use Gpr::{Rax, Rcx, Rdx};

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu) {
    emit_with(&mut code.asm(), operand, target);
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
            } else if target.supports(TargetCpu::Lzcnt) {
                // LZCNT counts a zero input as the operand width.
                asm.lzcnt(size, Rax, Rax);
                if sign_bits {
                    // Omit the sign bit itself.
                    asm.alu_imm8(Alu::Sub, Size::Dword, Rax, 1);
                }
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
        Kind::ReverseBits { width }
            if target.supports(TargetCpu::Gfni) && !target.data_independent_timing() =>
        {
            // The affine transform by the anti-diagonal bit matrix reverses
            // each byte's bits. XMM0 and XMM1 are scratch: no guest vector
            // stays in them across an integer instruction. The DIT
            // lowering keeps to the audited shifts and masks.
            const REVERSE_EACH_BYTE: u64 = 0x8040_2010_0804_0201;
            asm.movq_to_xmm(0, Rax);
            asm.mov_imm64(Rdx, REVERSE_EACH_BYTE);
            asm.movq_to_xmm(1, Rdx);
            asm.gf2p8affineqb(0, Rm::Xmm(1), 0);
            asm.movq_from_xmm(Rax, 0);
            asm.bswap(size(width), Rax);
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
        Kind::VariableShift { width, shift }
            if shift != Shift::Ror
                && target.supports(TargetCpu::Bmi2)
                && !target.data_independent_timing() =>
        {
            // One flagless uop; SHL r,CL is three on Skylake-family cores. The
            // count is modulo the width, as Arm's, and a 32-bit result
            // clears Xd's upper half. The DIT lowering keeps to the audited
            // CL shifts.
            let op = match shift {
                Shift::Lsl => ShiftOp::Shl,
                Shift::Lsr => ShiftOp::Shr,
                _ => ShiftOp::Sar,
            };
            asm.shift_x(op, size(width), Rax, Rax, Rcx);
            store_with(asm, operand.destination);
            return;
        }
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
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    use crate::GuestState;

    const VALUES: [u64; 12] = [
        0,
        1,
        0x7fff,
        0x8000_0000,
        0xffff_ffff,
        0x1_0000_0000,
        0x0000_0001_ffff_ffff,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
        0xffff_ffff_0000_0000,
        0x0123_4567_89ab_cdef,
        u64::MAX,
    ];

    /// The result of `kind` on X1 = `value` after running its code on the
    /// host.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    fn run(kind: Kind, target: TargetCpu, value: u64, right: u64) -> u64 {
        let mut code = Code::new();
        emit(&mut code, &operand(kind), target);
        let mut state = GuestState::default();
        state.x[1] = value;
        state.x[2] = right;
        super::super::native::run(&code, &mut state);
        state.x[0]
    }

    fn lzcnt(code: &[u8]) -> bool {
        code.windows(3).any(|bytes| bytes == [0xf3, 0x0f, 0xbd])
            || code
                .windows(4)
                .any(|bytes| bytes == [0xf3, 0x48, 0x0f, 0xbd])
    }

    #[test]
    fn leading_counts_use_lzcnt_only_where_the_host_has_it() {
        for width in [Width::W32, Width::X64] {
            for kind in [
                Kind::LeadingZeros { width },
                Kind::LeadingSignBits { width },
            ] {
                let code = |target| {
                    let mut code = Code::new();
                    emit(&mut code, &operand(kind), target);
                    code
                };
                let (fast, fallback) = (code(TargetCpu::Lzcnt), code(TargetCpu::X86_64_V2));
                assert!(lzcnt(&fast) && !lzcnt(&fallback), "{kind:?}");
                assert!(fast.len() < fallback.len());
                assert!(!lzcnt(&code(
                    TargetCpu::Lzcnt.with_data_independent_timing()
                )));
            }
        }
    }

    /// SHLX/SHRX/SARX's VEX opcode byte (map 0F38, opcode F7).
    fn shift_x(code: &[u8]) -> bool {
        code.windows(4)
            .any(|bytes| bytes[0] == 0xc4 && bytes[1] & 0x1f == 2 && bytes[3] == 0xf7)
    }

    #[test]
    fn variable_shifts_use_bmi2_except_rotation() {
        for width in [Width::W32, Width::X64] {
            for shift in [Shift::Lsl, Shift::Lsr, Shift::Asr, Shift::Ror] {
                let kind = Kind::VariableShift { width, shift };
                let code = |target| {
                    let mut code = Code::new();
                    emit(&mut code, &operand(kind), target);
                    code
                };
                let (fast, fallback) = (code(TargetCpu::Bmi2), code(TargetCpu::X86_64_V2));
                assert!(!shift_x(&fallback));
                assert_eq!(shift_x(&fast), shift != Shift::Ror, "{kind:?}");
                if shift == Shift::Ror {
                    assert_eq!(fast, fallback);
                }
            }
        }
    }

    /// The variable shifts on the host with and without BMI2, against Arm's
    /// modulo-width counts.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn variable_shifts_match_on_the_host() {
        let host = TargetCpu::detect();
        for target in [TargetCpu::X86_64_V2, TargetCpu::Bmi2] {
            if !host.supports(target) {
                continue;
            }
            for value in VALUES {
                for count in [0u64, 1, 31, 32, 33, 63, 64, 65, 0xffff_ffff_ffff_ffc1] {
                    let narrow = value as u32;
                    let (w, x) = ((count % 32) as u32, (count % 64) as u32);
                    for (width, shift, expected) in [
                        (Width::W32, Shift::Lsl, u64::from(narrow << w)),
                        (Width::W32, Shift::Lsr, u64::from(narrow >> w)),
                        (
                            Width::W32,
                            Shift::Asr,
                            u64::from((narrow as i32 >> w) as u32),
                        ),
                        (Width::W32, Shift::Ror, u64::from(narrow.rotate_right(w))),
                        (Width::X64, Shift::Lsl, value << x),
                        (Width::X64, Shift::Lsr, value >> x),
                        (Width::X64, Shift::Asr, (value as i64 >> x) as u64),
                        (Width::X64, Shift::Ror, value.rotate_right(x)),
                    ] {
                        let kind = Kind::VariableShift { width, shift };
                        assert_eq!(
                            run(kind, target, value, count),
                            expected,
                            "{kind:?} {value:#x} {count} {target:?}"
                        );
                    }
                }
            }
        }
    }

    /// GF2P8AFFINEQB (66 0F 3A CE).
    fn gfni(code: &[u8]) -> bool {
        code.windows(3).any(|bytes| bytes == [0x3a, 0xce, 0xc1])
    }

    #[test]
    fn bit_reversal_uses_gfni_only_where_the_host_has_it() {
        for width in [Width::W32, Width::X64] {
            let kind = Kind::ReverseBits { width };
            let code = |target| {
                let mut code = Code::new();
                emit(&mut code, &operand(kind), target);
                code
            };
            let (fast, fallback) = (code(TargetCpu::Gfni), code(TargetCpu::X86_64_V2));
            assert!(gfni(&fast) && !gfni(&fallback), "{kind:?}");
            assert!(fast.len() < fallback.len());
        }
    }

    /// RBIT on the host with and without GFNI, against Rust's reversal.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn bit_reversal_matches_on_the_host() {
        let host = TargetCpu::detect();
        for target in [TargetCpu::X86_64_V2, TargetCpu::Gfni] {
            if !host.supports(target) {
                continue;
            }
            for value in VALUES {
                let narrow = Kind::ReverseBits { width: Width::W32 };
                let wide = Kind::ReverseBits { width: Width::X64 };
                assert_eq!(
                    run(narrow, target, value, 0),
                    u64::from((value as u32).reverse_bits()),
                    "{value:#x} {target:?}"
                );
                assert_eq!(run(wide, target, value, 0), value.reverse_bits());
            }
        }
    }

    /// CLZ and CLS on the host through LZCNT, BSR and the DIT smear, against
    /// Rust's counts.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn leading_counts_match_on_the_host() {
        let host = TargetCpu::detect();
        for target in [
            TargetCpu::X86_64_V2,
            TargetCpu::Lzcnt,
            TargetCpu::DataIndependentTiming,
        ] {
            if !host.supports(target) {
                continue;
            }
            for value in VALUES {
                let narrow = value as u32;
                let wide_fold = value ^ ((value as i64 >> 63) as u64);
                let narrow_fold = narrow ^ ((narrow as i32 >> 31) as u32);
                for (kind, expected) in [
                    (
                        Kind::LeadingZeros { width: Width::W32 },
                        narrow.leading_zeros(),
                    ),
                    (
                        Kind::LeadingZeros { width: Width::X64 },
                        value.leading_zeros(),
                    ),
                    (
                        Kind::LeadingSignBits { width: Width::W32 },
                        narrow_fold.leading_zeros() - 1,
                    ),
                    (
                        Kind::LeadingSignBits { width: Width::X64 },
                        wide_fold.leading_zeros() - 1,
                    ),
                ] {
                    assert_eq!(
                        run(kind, target, value, 0),
                        u64::from(expected),
                        "{kind:?} {value:#x} {target:?}"
                    );
                }
            }
        }
    }

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
                let mut ordinary = Code::new();
                emit(&mut ordinary, &operand(kind), TargetCpu::Baseline);
                let mut timed = Code::new();
                emit(&mut timed, &operand(kind), TargetCpu::DataIndependentTiming);
                let bsr = |code: &[u8]| code.windows(2).any(|pair| pair == [0x0f, 0xbd]);
                assert!(bsr(&ordinary));
                assert!(!bsr(&timed));
            }
        }
    }
}
