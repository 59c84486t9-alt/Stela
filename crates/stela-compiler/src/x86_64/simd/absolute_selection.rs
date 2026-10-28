//! Integer magnitude selection for FAMIN/FAMAX, exact under any host MXCSR.
use crate::x86_64::asm::{Code, Cond, Gpr, Size};
use crate::{
    TargetCpu,
    aarch64::floating::{Format, absolute_minmax::AbsoluteMinMaxOperation},
    x86_64::isa::{ShiftOpcode, SimdOpcode as Host},
};
use alloc::vec::Vec;

const RAX: u8 = 0;
const HIGH_DWORDS: u8 = 0xf5;
const LOW_DWORDS: u8 = 0xa0;
const REPEAT_LOW_DWORD: u8 = 0;

fn shuffle(code: &mut Code, register: u8, order: u8, target: TargetCpu) {
    Host::ShuffleDword.register_imm(code, register, register, order, target);
}

fn infinity(code: &mut Code, format: Format, register: u8, target: TargetCpu) {
    let bits = match format {
        Format::Half => format.exponent_mask() | format.exponent_mask() << Format::Half.bits(),
        _ => format.exponent_mask(),
    };
    code.asm().mov_imm64(Gpr::Rcx, bits);
    Host::MoveGprQword.emit(code, register, Gpr::Rcx, target);
    if format == Format::Double {
        Host::UnpackLowQword.register(code, register, register, target);
    } else {
        shuffle(code, register, REPEAT_LOW_DWORD, target);
    }
}

fn magnitude(code: &mut Code, format: Format, register: u8) {
    let (left, right) = match format {
        Format::Half => (ShiftOpcode::LeftWord, ShiftOpcode::RightWord),
        Format::Single => (ShiftOpcode::LeftDword, ShiftOpcode::RightDword),
        Format::Double => (ShiftOpcode::LeftQword, ShiftOpcode::RightQword),
    };
    left.emit(code, register, 1);
    right.emit(code, register, 1);
}

/// Convert both inputs to magnitudes and reject any NaN before selection. All
/// scratch registers must be distinct from each other and the two inputs. NaN
/// edges are rel32 displacements for the owner's transactional completion exit.
pub(in crate::x86_64) fn guard_and_magnitudes(
    code: &mut Code,
    format: Format,
    left: u8,
    right: u8,
    scratch: [u8; 4],
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    let [greater, equal, low, constant] = scratch;
    for input in [left, right] {
        magnitude(code, format, input);
        infinity(code, format, constant, target);
        Host::MoveAligned.register(code, greater, input, target);
        match format {
            Format::Half => Host::GreaterWord.register(code, greater, constant, target),
            Format::Single => Host::GreaterDword.register(code, greater, constant, target),
            Format::Double if target.supports(TargetCpu::Sse42) => {
                Host::GreaterQword.register(code, greater, constant, target)
            }
            Format::Double => {
                Host::GreaterDword.register(code, greater, constant, target);
                shuffle(code, greater, HIGH_DWORDS, target);
                Host::MoveAligned.register(code, equal, input, target);
                Host::EqualDword.register(code, equal, constant, target);
                shuffle(code, equal, HIGH_DWORDS, target);
                Host::MoveAligned.register(code, low, input, target);
                ShiftOpcode::LeftQword.emit(code, low, 32);
                Host::Xor.register(code, constant, constant, target);
                Host::EqualDword.register(code, low, constant, target);
                shuffle(code, low, HIGH_DWORDS, target);
                Host::AndNot.register(code, low, equal, target);
                Host::Or.register(code, greater, low, target);
            }
        }
        Host::ByteSignMask.register(code, RAX, greater, target);
        let mut asm = code.asm();
        asm.test(Size::Dword, Gpr::Rax, Gpr::Rax);
        failures.push(asm.jcc(Cond::Ne).offset());
    }
}

/// Inputs must be sign-cleared, non-NaN magnitudes. Produces the result in left,
/// preserves right, and clobbers four scratch XMMs. No guest or host FP effects.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    format: Format,
    operation: AbsoluteMinMaxOperation,
    left: u8,
    right: u8,
    scratch: [u8; 4],
    target: TargetCpu,
) {
    let minimum = operation == AbsoluteMinMaxOperation::Minimum;
    match format {
        Format::Half => {
            if minimum {
                Host::MinSignedWord
            } else {
                Host::MaxSignedWord
            }
            .register(code, left, right, target);
            return;
        }
        Format::Single if target.supports(TargetCpu::Sse41) => {
            if minimum {
                Host::MinSignedDword
            } else {
                Host::MaxSignedDword
            }
            .register(code, left, right, target);
            return;
        }
        _ => {}
    }
    let [greater, equal, low, bias] = scratch;
    // A minimum chooses right iff left>right; maximum reverses that comparison.
    let (a, b) = if minimum {
        (left, right)
    } else {
        (right, left)
    };
    Host::MoveAligned.register(code, greater, a, target);
    if format == Format::Single {
        Host::GreaterDword.register(code, greater, b, target);
    } else if target.supports(TargetCpu::Sse42) {
        Host::GreaterQword.register(code, greater, b, target);
    } else {
        Host::GreaterDword.register(code, greater, b, target);
        shuffle(code, greater, HIGH_DWORDS, target);
        Host::MoveAligned.register(code, equal, a, target);
        Host::EqualDword.register(code, equal, b, target);
        shuffle(code, equal, HIGH_DWORDS, target);
        // The low dwords need an unsigned comparison: flip bit 31, compare
        // signed, then restore the bits before selecting.
        Host::EqualDword.register(code, bias, bias, target);
        ShiftOpcode::RightQword.emit(code, bias, 63);
        ShiftOpcode::LeftQword.emit(code, bias, 31);
        Host::MoveAligned.register(code, low, a, target);
        Host::Xor.register(code, low, bias, target);
        Host::Xor.register(code, b, bias, target);
        Host::GreaterDword.register(code, low, b, target);
        Host::Xor.register(code, b, bias, target);
        shuffle(code, low, LOW_DWORDS, target);
        Host::And.register(code, low, equal, target);
        Host::Or.register(code, greater, low, target);
    }
    Host::MoveAligned.register(code, low, greater, target);
    Host::And.register(code, greater, right, target);
    Host::AndNot.register(code, low, left, target);
    Host::MoveAligned.register(code, left, greater, target);
    Host::Or.register(code, left, low, target);
}
