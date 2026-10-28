//! FEAT_EBF16 BFDOT over one 128-bit chunk.
//!
//! The caller installs the guest rounding mode with DAZ/FTZ clear in a private
//! MXCSR and restores it afterwards; host status is discarded. Inputs: XMM0/XMM1
//! hold eight BF16 values, XMM6 four single accumulators. Output: XMM0 holds four
//! singles. Clobbers XMM2-5, XMM7, RAX, RCX and flags.
use crate::TargetCpu;
use crate::x86_64::asm::Gpr::{Rax, Rcx};
use crate::x86_64::asm::{Alu, Code, Cond, Rm, ShiftOp, Size};
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};

use crate::x86_64::scalable::numerical;
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const WORK_LEFT: u8 = 2;
const WORK_RIGHT: u8 = 3;
const WORK_PAIR: u8 = 4;
const OUTPUT: u8 = 5;
const ACCUMULATOR: u8 = 6;
const WORK_MASK: u8 = 7;
const SIGN_DISCARD_SHIFT: u8 = 1;
const DOUBLE_SIGN_BIT: u8 = 63;
const DWORD_BITS: u8 = 32;
const BFLOAT_EXPONENT_PAIR: u32 = 0x7f80_7f80;
const SINGLE_EXPONENT: u32 = 0x7f80_0000;
const SINGLE_MAGNITUDE: u32 = 0x7fff_ffff;
const SINGLE_MINIMUM_NORMAL: u32 = 0x0080_0000;
const SINGLE_MINIMUM_NORMAL_AS_DOUBLE: u64 = 0x3810_0000_0000_0000;
const BFLOAT_TO_SINGLE_SHIFT: u8 = 16;
const HALF_CHUNK_BYTES: u8 = 8;
const UPPER_TWO_SINGLES: u8 = 0xee;
const SPLAT_LOW_DWORD: u8 = 0;

fn vector(code: &mut Code, opcode: Host, destination: u8, source: u8) {
    code.asm()
        .simd(opcode, destination, Rm::Xmm(source), TargetCpu::Baseline);
}

fn shuffle(code: &mut Code, destination: u8, source: u8, lanes: u8) {
    code.asm().simd_imm(
        Host::ShuffleDword,
        destination,
        Rm::Xmm(source),
        lanes,
        TargetCpu::Baseline,
    );
}

fn mask(code: &mut Code, value: u32) {
    let mut asm = code.asm();
    asm.mov_imm32(Rax, value);
    asm.movd_to_xmm(WORK_MASK, Rax);
    shuffle(code, WORK_MASK, WORK_MASK, SPLAT_LOW_DWORD);
}

fn reject_mask(code: &mut Code, register: u8, failures: &mut Vec<usize>) {
    let mut asm = code.asm();
    asm.simd_to_gpr(Host::ByteSignMask, Rax, register, TargetCpu::Baseline);
    asm.test(Size::Dword, Rax, Rax);
    failures.push(asm.jcc(Cond::Ne).offset());
}

fn guard_bfloat(code: &mut Code, source: u8, failures: &mut Vec<usize>) {
    vector(code, Host::MoveAligned, WORK_LEFT, source);
    vector(code, Host::And, WORK_LEFT, WORK_MASK);
    vector(code, Host::MoveAligned, WORK_RIGHT, WORK_LEFT);
    vector(code, Host::EqualWord, WORK_RIGHT, WORK_MASK);
    vector(code, Host::EqualWord, WORK_LEFT, OUTPUT);
    vector(code, Host::MoveAligned, WORK_PAIR, source);
    Shift::LeftWord.emit(code, WORK_PAIR, SIGN_DISCARD_SHIFT);
    vector(code, Host::EqualWord, WORK_PAIR, OUTPUT);
    vector(code, Host::AndNot, WORK_PAIR, WORK_LEFT);
    vector(code, Host::Or, WORK_RIGHT, WORK_PAIR);
    reject_mask(code, WORK_RIGHT, failures);
}

fn guard_accumulator(code: &mut Code, failures: &mut Vec<usize>) {
    vector(code, Host::MoveAligned, WORK_LEFT, ACCUMULATOR);
    Shift::LeftDword.emit(code, WORK_LEFT, SIGN_DISCARD_SHIFT);
    vector(code, Host::EqualDword, WORK_LEFT, OUTPUT);
    vector(code, Host::MoveAligned, WORK_RIGHT, ACCUMULATOR);
    vector(code, Host::And, WORK_RIGHT, WORK_MASK);
    vector(code, Host::MoveAligned, WORK_PAIR, WORK_RIGHT);
    vector(code, Host::EqualDword, WORK_RIGHT, OUTPUT);
    vector(code, Host::AndNot, WORK_LEFT, WORK_RIGHT);
    vector(code, Host::EqualDword, WORK_PAIR, WORK_MASK);
    vector(code, Host::Or, WORK_LEFT, WORK_PAIR);
    reject_mask(code, WORK_LEFT, failures);
}

fn guard_double(code: &mut Code, register: u8, failures: &mut Vec<usize>) {
    // All inputs/products/sums are finite Double. Unsigned magnitude bits sort
    // numerically. Strict > excludes pre-round tininess obscured by directed
    // rounding up to min-normal; exact signed zero is admitted separately.
    let mut asm = code.asm();
    asm.movq_from_xmm(Rax, register);
    asm.btr_imm(Size::Qword, Rax, DOUBLE_SIGN_BIT);
    asm.test(Size::Qword, Rax, Rax);
    let zero = asm.jcc(Cond::E);
    asm.mov_imm64(Rcx, SINGLE_MINIMUM_NORMAL_AS_DOUBLE);
    asm.alu(Alu::Cmp, Size::Qword, Rax, Rcx);
    failures.push(asm.jcc(Cond::Be).offset());
    asm.bind(zero);
}

fn guard_single(code: &mut Code, failures: &mut Vec<usize>) {
    let mut asm = code.asm();
    asm.mov(Size::Dword, Rcx, Rax);
    asm.alu_imm32(Alu::And, Size::Dword, Rcx, SINGLE_MAGNITUDE as i32);
    asm.test(Size::Dword, Rcx, Rcx);
    let zero = asm.jcc(Cond::E);
    asm.alu_imm32(Alu::Cmp, Size::Dword, Rcx, SINGLE_MINIMUM_NORMAL as i32);
    failures.push(asm.jcc(Cond::B).offset());
    asm.bind(zero);
}

fn product_pair(code: &mut Code, upper: bool) {
    vector(code, Host::Xor, WORK_MASK, WORK_MASK);
    vector(code, Host::MoveAligned, WORK_LEFT, LEFT);
    vector(code, Host::MoveAligned, WORK_RIGHT, RIGHT);
    if upper {
        Shift::RightBytes.emit(code, WORK_LEFT, HALF_CHUNK_BYTES);
        Shift::RightBytes.emit(code, WORK_RIGHT, HALF_CHUNK_BYTES);
    }
    for register in [WORK_LEFT, WORK_RIGHT] {
        vector(code, Host::UnpackLowWord, register, WORK_MASK);
        Shift::LeftDword.emit(code, register, BFLOAT_TO_SINGLE_SHIFT);
    }
    let mut asm = code.asm();
    asm.cvtps2pd(WORK_PAIR, Rm::Xmm(WORK_LEFT));
    asm.cvtps2pd(WORK_MASK, Rm::Xmm(WORK_RIGHT));
    asm.mulpd(WORK_PAIR, Rm::Xmm(WORK_MASK));
    shuffle(code, WORK_LEFT, WORK_LEFT, UPPER_TWO_SINGLES);
    shuffle(code, WORK_RIGHT, WORK_RIGHT, UPPER_TWO_SINGLES);
    let mut asm = code.asm();
    asm.cvtps2pd(WORK_LEFT, Rm::Xmm(WORK_LEFT));
    asm.cvtps2pd(WORK_RIGHT, Rm::Xmm(WORK_RIGHT));
    asm.mulpd(WORK_LEFT, Rm::Xmm(WORK_RIGHT));
    asm.simd(
        Host::MoveAligned,
        WORK_RIGHT,
        Rm::Xmm(WORK_PAIR),
        TargetCpu::Baseline,
    );
    asm.unpcklpd(WORK_RIGHT, Rm::Xmm(WORK_LEFT));
    asm.unpckhpd(WORK_PAIR, Rm::Xmm(WORK_LEFT));
    asm.addpd(WORK_RIGHT, Rm::Xmm(WORK_PAIR));
}

/// Shared-frame guarded enhanced branch. Failures target the outer frame's
/// common cleanup; pending guest FPSR must remain zero throughout this branch.
pub(super) fn emit_chunk(code: &mut Code, _frame: &numerical::Frame, failures: &mut Vec<usize>) {
    vector(code, Host::Xor, OUTPUT, OUTPUT);
    mask(code, BFLOAT_EXPONENT_PAIR);
    guard_bfloat(code, LEFT, failures);
    guard_bfloat(code, RIGHT, failures);
    mask(code, SINGLE_EXPONENT);
    guard_accumulator(code, failures);
    for upper in [false, true] {
        product_pair(code, upper);
        guard_double(code, WORK_RIGHT, failures);
        vector(code, Host::MoveAligned, WORK_PAIR, WORK_RIGHT);
        code.asm().unpckhpd(WORK_PAIR, Rm::Xmm(WORK_PAIR));
        guard_double(code, WORK_PAIR, failures);
        code.asm().cvtpd2ps(WORK_RIGHT, Rm::Xmm(WORK_RIGHT));
        if upper {
            shuffle(code, WORK_PAIR, ACCUMULATOR, UPPER_TWO_SINGLES);
            code.asm().addps(WORK_RIGHT, Rm::Xmm(WORK_PAIR));
        } else {
            code.asm().addps(WORK_RIGHT, Rm::Xmm(ACCUMULATOR));
        }
        code.asm().movq_from_xmm(Rax, WORK_RIGHT);
        guard_single(code, failures);
        code.asm()
            .shift_imm(ShiftOp::Shr, Size::Qword, Rax, DWORD_BITS);
        guard_single(code, failures);
        let mut asm = code.asm();
        if upper {
            asm.unpcklpd(OUTPUT, Rm::Xmm(WORK_RIGHT));
        } else {
            asm.movq_xmm(OUTPUT, Rm::Xmm(WORK_RIGHT));
        }
    }
    vector(code, Host::MoveAligned, LEFT, OUTPUT);
}
