//! Integer guards selecting which lanes may use native FP. Inactive operands are
//! replaced with +0 before classification.
use crate::x86_64::asm::Gpr::{Rax, Rcx, Rdi};
use crate::x86_64::asm::{Code, Cond, Mem, Rm, Size};

use crate::{
    GuestState, TargetCpu,
    aarch64::floating::{FPCR_EXCEPTION_ENABLE_MASK, Format, features::NumericalFeatures},
    x86_64::isa::SimdOpcode as Host,
};
use alloc::vec::Vec;

const XMM_REGISTER_COUNT: u8 = 8;
const REPEAT_LOW_DWORD: u8 = 0;
const SWAP_ADJACENT_DWORDS: u8 = 0xb1;
const REPEAT_HIGH_DWORDS: u8 = 0xf5;

fn shuffle(code: &mut Code, destination: u8, source: u8, order: u8, target: TargetCpu) {
    code.asm().simd_imm(
        Host::ShuffleDword,
        destination,
        Rm::Xmm(source),
        order,
        target,
    );
}

fn broadcast(code: &mut Code, format: Format, value: u64, destination: u8, target: TargetCpu) {
    if format == Format::Single {
        code.asm().mov_imm32(Rcx, value as u32);
    } else {
        code.asm().mov_imm64(Rcx, value);
    }
    code.asm()
        .simd(Host::MoveGprQword, destination, Rcx, target);
    if format == Format::Single {
        shuffle(code, destination, destination, REPEAT_LOW_DWORD, target);
    } else {
        Host::UnpackLowQword.register(code, destination, destination, target);
    }
}

fn sign_mask(code: &mut Code, source: u8, target: TargetCpu) {
    code.asm()
        .simd_to_gpr(Host::ByteSignMask, Rax, source, target);
}

/// Masks remain live in these caller-selected XMMs for one whole instruction.
/// The descriptor is compiler bookkeeping, never architectural or stack state.
#[derive(Clone, Copy)]
pub(in crate::x86_64) struct Classification {
    format: Format,
    fraction_mask: u8,
    exponent_mask: u8,
}

/// Load invariant masks once, rather than rebroadcasting them for every source
/// in every vector chunk. Callers preserve these XMMs until staging is finished.
pub(in crate::x86_64) fn prepare_classification(
    code: &mut Code,
    format: Format,
    registers: [u8; 2],
    target: TargetCpu,
) -> Classification {
    assert!(matches!(format, Format::Single | Format::Double));
    let [fraction_mask, exponent_mask] = registers;
    assert!(fraction_mask < XMM_REGISTER_COUNT && exponent_mask < XMM_REGISTER_COUNT);
    assert_ne!(fraction_mask, exponent_mask);
    broadcast(code, format, format.fraction_mask(), fraction_mask, target);
    broadcast(code, format, format.exponent_mask(), exponent_mask, target);
    Classification {
        format,
        fraction_mask,
        exponent_mask,
    }
}

/// Append one rejection edge when any input lane is a NaN or nonzero subnormal.
/// Signed zero, finite normals and infinities pass. `input` is preserved, as are
/// all XMM registers except the three distinct scratch registers. Clobbers
/// RAX/RCX and host arithmetic flags, without touching MXCSR or guest state.
/// Failure indices identify rel32 displacements consumed by numerical::finish.
pub(in crate::x86_64) fn guard_normal_zero_or_infinity(
    code: &mut Code,
    classification: Classification,
    input: u8,
    scratch: [u8; 3],
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    let Classification {
        format,
        fraction_mask,
        exponent_mask,
    } = classification;
    assert!(input < XMM_REGISTER_COUNT);
    assert!(input != fraction_mask && input != exponent_mask);
    for (index, register) in scratch.iter().enumerate() {
        assert!(*register < XMM_REGISTER_COUNT && *register != input);
        assert!(*register != fraction_mask && *register != exponent_mask);
        assert!(!scratch[..index].contains(register));
    }
    let [fraction_zero, exponent, maximum_exponent] = scratch;

    Host::MoveAligned.register(code, fraction_zero, input, target);
    Host::And.register(code, fraction_zero, fraction_mask, target);
    Host::Xor.register(code, exponent, exponent, target);
    Host::EqualDword.register(code, fraction_zero, exponent, target);
    if format == Format::Double {
        // A Double fraction is zero only if both of its dwords are zero.
        shuffle(code, exponent, fraction_zero, SWAP_ADJACENT_DWORDS, target);
        Host::And.register(code, fraction_zero, exponent, target);
    }

    Host::MoveAligned.register(code, exponent, input, target);
    Host::And.register(code, exponent, exponent_mask, target);
    Host::MoveAligned.register(code, maximum_exponent, exponent_mask, target);
    Host::EqualDword.register(code, maximum_exponent, exponent, target);
    if format == Format::Double {
        shuffle(
            code,
            maximum_exponent,
            maximum_exponent,
            REPEAT_HIGH_DWORDS,
            target,
        );
    }

    // Exponent bits are nonnegative signed dwords. Comparing them against the
    // fraction-zero mask (-1 or 0) accepts every positive exponent and both
    // signed zeros; it rejects exactly the zero-exponent nonzero fractions.
    Host::GreaterDword.register(code, exponent, fraction_zero, target);
    if format == Format::Double {
        shuffle(code, exponent, exponent, REPEAT_HIGH_DWORDS, target);
    }
    Host::AndNot.register(code, fraction_zero, maximum_exponent, target);
    Host::EqualDword.register(code, maximum_exponent, maximum_exponent, target);
    Host::Xor.register(code, exponent, maximum_exponent, target);
    Host::Or.register(code, exponent, fraction_zero, target);
    sign_mask(code, exponent, target);
    let mut asm = code.asm();
    asm.test(Size::Dword, Rax, Rax);
    failures.push(asm.jcc(Cond::Ne).offset());
}

/// Active numerical work with kept guest exception enables takes the whole
/// instruction fallback. Ordinary streaming without FullA64 masks these enables
/// through its established effective-control policy and needs no rejection.
/// All-inactive work bypasses the raw control read. Preserves every XMM register;
/// clobbers RAX and host arithmetic flags only.
pub(in crate::x86_64) fn guard_active_exception_enables(
    code: &mut Code,
    active: u8,
    features: NumericalFeatures,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    assert!(active < XMM_REGISTER_COUNT);
    if !features.full_a64() {
        return;
    }
    sign_mask(code, active, target);
    let mut asm = code.asm();
    asm.test(Size::Dword, Rax, Rax);
    let inactive = asm.jcc(Cond::E);
    asm.test_imm(
        Size::Dword,
        Mem::base_disp32(Rdi, core::mem::offset_of!(GuestState, fpcr) as i32),
        FPCR_EXCEPTION_ENABLE_MASK as i32,
    );
    failures.push(asm.jcc(Cond::Ne).offset());
    asm.bind(inactive);
}
