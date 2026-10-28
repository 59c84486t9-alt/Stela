//! FEAT_CSSC ABS, CNT and CTZ.
use super::{
    Register, Width,
    asm::{Alu, Asm, Cond, Gpr, Mem, ShiftOp, Size, Unary},
    load_with, offset, store_with,
};
use crate::{
    TargetCpu,
    aarch64::integer_unary::{Kind, Operand},
};
use alloc::vec::Vec;

use Gpr::{Rax, Rcx, Rdi, Rdx};

const PAIR_MASK: u64 = 0x5555_5555_5555_5555;
const TWO_BIT_MASK: u64 = 0x3333_3333_3333_3333;
const NIBBLE_MASK: u64 = 0x0f0f_0f0f_0f0f_0f0f;
const BYTE_SUM_MULTIPLIER: u64 = 0x0101_0101_0101_0101;
const TWO_BIT_SHIFT: u8 = 2;
const NIBBLE_SHIFT: u8 = 4;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    emit_with(&mut Asm::new(code), operand, target);
}

fn size(width: Width) -> Size {
    Size::of(width == Width::X64)
}

pub(super) fn emit_with(asm: &mut Asm, operand: &Operand, target: TargetCpu) {
    let size = size(operand.width);
    if operand.destination == Register::Zero {
        // NOP keeps the source-map interval nonempty.
        asm.nop();
        return;
    }
    if operand.source == Register::Zero {
        match operand.kind {
            Kind::Absolute | Kind::PopulationCount => asm.alu(Alu::Xor, Size::Dword, Rax, Rax),
            Kind::TrailingZeros => asm.mov_imm32(Rax, size.bits()),
        }
        store_with(asm, operand.destination);
        return;
    }
    match operand.kind {
        Kind::Absolute => {
            load_with(asm, operand.source);
            asm.mov(size, Rcx, Rax);
            asm.unary(Unary::Neg, size, Rax);
            asm.cmov(Cond::S, size, Rax, Rcx);
        }
        // POPCNT, TZCNT and BSF are not on Intel's data operand
        // independent timing list.
        Kind::PopulationCount | Kind::TrailingZeros if target.data_independent_timing() => {
            load_with(asm, operand.source);
            if operand.kind == Kind::TrailingZeros {
                // (x & -x) - 1 sets exactly the trailing zeros (all bits for 0).
                asm.mov(size, Rcx, Rax);
                asm.unary(Unary::Neg, size, Rcx);
                asm.alu(Alu::And, size, Rax, Rcx);
                asm.alu_imm8(Alu::Sub, size, Rax, 1);
            }
            population_count(asm, operand.width == Width::X64);
        }
        Kind::PopulationCount if target.supports(TargetCpu::Popcnt) => {
            memory_count(asm, operand, |asm, size, to, from| {
                asm.popcnt(size, to, from)
            });
        }
        Kind::PopulationCount => {
            load_with(asm, operand.source);
            population_count(asm, operand.width == Width::X64);
        }
        Kind::TrailingZeros if target.supports(TargetCpu::Bmi1) => {
            memory_count(asm, operand, |asm, size, to, from| {
                asm.tzcnt(size, to, from)
            });
        }
        Kind::TrailingZeros => {
            memory_count(asm, operand, |asm, size, to, from| asm.bsf(size, to, from));
            // MOV preserves BSF's ZF. Replace its undefined zero-input result
            // before use; a 32-bit CMOV is sufficient for either count width.
            asm.mov_imm32(Rcx, size.bits());
            asm.cmov(Cond::E, Size::Dword, Rax, Rcx);
        }
    }
    store_with(asm, operand.destination);
}

/// A count of the guest source read straight from the frame.
fn memory_count(asm: &mut Asm, operand: &Operand, count: fn(&mut Asm, Size, Gpr, Mem)) {
    // Break the count destination dependency before its folded memory read.
    // The memory read precedes the guest destination write, including aliases.
    asm.alu(Alu::Xor, Size::Dword, Rax, Rax);
    let source = offset(operand.source).expect("nonzero scalar count source");
    count(
        asm,
        size(operand.width),
        Rax,
        Mem::base_disp32(Rdi, source as i32),
    );
}

/// The population count of RAX (EAX unless `wide`) in EAX, from integer
/// operations only. Clobbers RCX and RDX.
pub(super) fn population_count(asm: &mut Asm, wide: bool) {
    let size = Size::of(wide);
    // A wide mask goes through RDX; a narrow one is an imm32.
    let mask_copy = |asm: &mut Asm, value: u64| {
        if wide {
            asm.mov_imm64(Rdx, value);
            asm.alu(Alu::And, size, Rcx, Rdx);
        } else {
            asm.alu_imm32(Alu::And, size, Rcx, value as u32 as i32);
        }
    };
    let mask_accumulator = |asm: &mut Asm, value: u64, loaded: bool| {
        if wide {
            if !loaded {
                asm.mov_imm64(Rdx, value);
            }
            asm.alu(Alu::And, size, Rax, Rdx);
        } else {
            asm.alu_accumulator_imm32(Alu::And, size, value as u32 as i32);
        }
    };
    // Each subtraction produces a two-bit count without borrowing across pairs.
    asm.mov(size, Rcx, Rax);
    asm.shift_one(ShiftOp::Shr, size, Rcx);
    mask_copy(asm, PAIR_MASK);
    asm.alu(Alu::Sub, size, Rax, Rcx);

    asm.mov(size, Rcx, Rax);
    asm.shift_imm(ShiftOp::Shr, size, Rcx, TWO_BIT_SHIFT);
    mask_copy(asm, TWO_BIT_MASK);
    mask_accumulator(asm, TWO_BIT_MASK, true);
    asm.alu(Alu::Add, size, Rax, Rcx);

    asm.mov(size, Rcx, Rax);
    asm.shift_imm(ShiftOp::Shr, size, Rcx, NIBBLE_SHIFT);
    asm.alu(Alu::Add, size, Rax, Rcx);
    mask_accumulator(asm, NIBBLE_MASK, false);

    if wide {
        asm.mov_imm64(Rdx, BYTE_SUM_MULTIPLIER);
        asm.imul(size, Rax, Rdx);
    } else {
        asm.imul_imm32(size, Rax, Rax, BYTE_SUM_MULTIPLIER as u32 as i32);
    }
    asm.shift_imm(ShiftOp::Shr, size, Rax, (size.bits() - u8::BITS) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOP: u8 = 0x90;
    const BSF_EAX_RDI_DISP32: &[u8] = &[0x0f, 0xbc, 0x87];
    const POPCNT_EAX_RDI_DISP32: &[u8] = &[0x0f, 0xb8, 0x87];
    use alloc::vec::Vec;

    fn emitted(kind: Kind, width: Width, source: Register, target: TargetCpu) -> Vec<u8> {
        let mut code = Vec::new();
        emit(
            &mut code,
            &Operand {
                kind,
                width,
                destination: Register::X(0),
                source,
            },
            target,
        );
        code
    }

    #[test]
    fn data_independent_counts_use_neither_popcnt_nor_tzcnt_nor_bsf() {
        let source = Register::X(1);
        for width in [Width::W32, Width::X64] {
            for kind in [Kind::PopulationCount, Kind::TrailingZeros] {
                let full = TargetCpu::Baseline.with_popcnt().with_bmi1();
                let timed = emitted(kind, width, source, full.with_data_independent_timing());
                assert_eq!(
                    emitted(kind, width, source, TargetCpu::DataIndependentTiming),
                    timed
                );
                for opcode in [POPCNT_EAX_RDI_DISP32, BSF_EAX_RDI_DISP32] {
                    assert!(!timed.windows(2).any(|pair| pair == &opcode[..2]));
                }
            }
        }
        // (x & -x) - 1 marks the trailing zeros, all of them for zero.
        for value in [0u64, 1, 2, 0x8000_0000_0000_0000, 0x0123_4567_89ab_cdf0] {
            let mask = value.isolate_lowest_one().wrapping_sub(1);
            assert_eq!(mask.count_ones(), value.trailing_zeros());
        }
    }

    #[test]
    fn optional_count_features_are_independent() {
        let baseline = TargetCpu::Baseline;
        let source = Register::X(1);
        for width in [Width::W32, Width::X64] {
            for (kind, required, unrelated) in [
                (Kind::PopulationCount, TargetCpu::Popcnt, TargetCpu::Bmi1),
                (Kind::TrailingZeros, TargetCpu::Bmi1, TargetCpu::Popcnt),
            ] {
                let ordinary = emitted(kind, width, source, baseline);
                let checked = emitted(kind, width, source, required);
                assert_eq!(emitted(kind, width, source, unrelated), ordinary);
                assert_eq!(
                    emitted(kind, width, source, baseline.with_popcnt().with_bmi1()),
                    checked
                );
                assert!(checked.len() < ordinary.len());
            }
        }
    }

    #[test]
    fn known_zero_source_uses_the_same_short_path_for_every_target() {
        for kind in [Kind::Absolute, Kind::PopulationCount, Kind::TrailingZeros] {
            for width in [Width::W32, Width::X64] {
                let constant = emitted(kind, width, Register::Zero, TargetCpu::Baseline);
                assert!(
                    constant.len()
                        < emitted(kind, width, Register::X(1), TargetCpu::Baseline).len()
                );
                for target in [
                    TargetCpu::Popcnt,
                    TargetCpu::Bmi1,
                    TargetCpu::Baseline.with_popcnt().with_bmi1(),
                ] {
                    assert_eq!(emitted(kind, width, Register::Zero, target), constant);
                }
            }
        }
    }

    #[test]
    fn discard_is_a_nonempty_no_effect_interval_for_every_target() {
        for kind in [Kind::Absolute, Kind::PopulationCount, Kind::TrailingZeros] {
            for width in [Width::W32, Width::X64] {
                for target in [
                    TargetCpu::Baseline,
                    TargetCpu::Baseline.with_popcnt().with_bmi1(),
                ] {
                    let mut code = Vec::new();
                    emit(
                        &mut code,
                        &Operand {
                            kind,
                            width,
                            destination: Register::Zero,
                            source: Register::X(1),
                        },
                        target,
                    );
                    assert_eq!(code, [NOP]);
                }
            }
        }
    }
}
