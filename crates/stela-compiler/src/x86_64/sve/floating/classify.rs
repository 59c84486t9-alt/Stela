//! Integer-only admission guards for exact native floating-point lanes.
//!
//! Callers replace inactive operands with positive zero before classification.
//! Accepted host operations must preserve complete caller MXCSR and guest FPSR;
//! these guards do not install an environment or grant any exceptional outcome.

use crate::{
    GuestState, TargetCpu,
    aarch64::floating::{FPCR_EXCEPTION_ENABLE_MASK, Format, features::NumericalFeatures},
    x86_64::isa::SimdOpcode as Host,
};
use alloc::vec::Vec;

const XMM_REGISTER_COUNT: u8 = 8;
const MODRM_REGISTER: u8 = 0xc0;
const REGISTER_SHIFT: u8 = 3;
const RCX_REGISTER: u8 = 1;
const RAX_REGISTER: u8 = 0;
const MOV_ECX_IMMEDIATE: &[u8] = &[0xb9];
const MOV_RCX_IMMEDIATE: &[u8] = &[0x48, 0xb9];
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const TEST_STATE_IMMEDIATE: &[u8] = &[0xf7, 0x87];
const JZ_REL32: &[u8] = &[0x0f, 0x84];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];
const REPEAT_LOW_DWORD: u8 = 0;
const SWAP_ADJACENT_DWORDS: u8 = 0xb1;
const REPEAT_HIGH_DWORDS: u8 = 0xf5;

fn branch(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let displacement = code.len();
    code.extend(0_i32.to_le_bytes());
    displacement
}

fn resolve(code: &mut [u8], displacement: usize, destination: usize) {
    let next = displacement + size_of::<i32>();
    let distance = i64::try_from(destination).expect("guard destination fits i64")
        - i64::try_from(next).expect("guard source fits i64");
    code[displacement..next].copy_from_slice(
        &i32::try_from(distance)
            .expect("bounded floating guard branch")
            .to_le_bytes(),
    );
}

fn shuffle(code: &mut Vec<u8>, destination: u8, source: u8, order: u8, target: TargetCpu) {
    Host::ShuffleDword.register(code, destination, source, target);
    code.push(order);
}

fn broadcast(code: &mut Vec<u8>, format: Format, value: u64, destination: u8, target: TargetCpu) {
    if format == Format::Single {
        code.extend(MOV_ECX_IMMEDIATE);
        code.extend((value as u32).to_le_bytes());
    } else {
        code.extend(MOV_RCX_IMMEDIATE);
        code.extend(value.to_le_bytes());
    }
    Host::MoveGprQword.append(code, target);
    code.push(MODRM_REGISTER | (destination << REGISTER_SHIFT) | RCX_REGISTER);
    if format == Format::Single {
        shuffle(code, destination, destination, REPEAT_LOW_DWORD, target);
    } else {
        Host::UnpackLowQword.register(code, destination, destination, target);
    }
}

fn sign_mask(code: &mut Vec<u8>, source: u8, target: TargetCpu) {
    Host::ByteSignMask.append(code, target);
    code.push(MODRM_REGISTER | (RAX_REGISTER << REGISTER_SHIFT) | source);
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
    code: &mut Vec<u8>,
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
    code: &mut Vec<u8>,
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
    code.extend(TEST_EAX_EAX);
    failures.push(branch(code, JNZ_REL32));
}

/// Active numerical work with retained guest exception enables takes the whole
/// instruction fallback. Ordinary streaming without FullA64 masks these enables
/// through its established effective-control policy and needs no rejection.
/// All-inactive work bypasses the raw control read. Preserves every XMM register;
/// clobbers RAX and host arithmetic flags only.
pub(in crate::x86_64) fn guard_active_exception_enables(
    code: &mut Vec<u8>,
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
    code.extend(TEST_EAX_EAX);
    let inactive = branch(code, JZ_REL32);
    code.extend(TEST_STATE_IMMEDIATE);
    code.extend((core::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
    code.extend(FPCR_EXCEPTION_ENABLE_MASK.to_le_bytes());
    failures.push(branch(code, JNZ_REL32));
    let next = code.len();
    resolve(code, inactive, next);
}
