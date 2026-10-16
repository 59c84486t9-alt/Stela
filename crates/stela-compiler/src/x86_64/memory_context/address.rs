//! Original-SP checks and modular address arithmetic for checked memory leaves.
//!
//! SP callers bind SpAlignmentRequirement::Enabled at complete-body preflight.
//! These helpers never infer effective CPU controls from register alignment.
use super::{fault, patch_branch};
use crate::x86_64::{load, right_operand};
use crate::{
    aarch64::{AddressMode, Register, Shift, Width, register_offset::IndexExtend},
    context::memory::{MemoryStatus, address::AddressAddChecks},
};
use alloc::vec::Vec;

const STACK_ALIGNMENT_MASK: u8 = 15;
const TEST_AL_IMM8: u8 = 0xa8;
const JE_REL32: &[u8] = &[0x0f, 0x84];
const JMP_REL32: u8 = 0xe9;
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const JE_REL8: u8 = 0x74;
const RET: u8 = 0xc3;
const LEA_RAX_RAX_DISP8: &[u8] = &[0x48, 0x8d, 0x40];
const LEA_RAX_RAX_DISP32: &[u8] = &[0x48, 0x8d, 0x80];
const LEA_RDX_RAX_DISP8: &[u8] = &[0x48, 0x8d, 0x50];
const LEA_RDX_RAX_DISP32: &[u8] = &[0x48, 0x8d, 0x90];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const MOV_RAX_RDX: &[u8] = &[0x48, 0x89, 0xd0];
const MOV_R8_RAX: &[u8] = &[0x49, 0x89, 0xc0];
const MOV_RAX_R8: &[u8] = &[0x4c, 0x89, 0xc0];
const MOV_ECX_ECX: &[u8] = &[0x89, 0xc9];
const MOVSXD_RCX_ECX: &[u8] = &[0x48, 0x63, 0xc9];
const SHL_RCX_IMM8: &[u8] = &[0x48, 0xc1, 0xe1];
const LEA_RAX_RAX_RCX: &[u8] = &[0x48, 0x8d, 0x04, 0x08];

/// Check original SP before offset arithmetic. Patch the returned rel32 failure
/// displacement to the leaf's one scratch cleanup. RAX contains raw fault SP.
/// Clobbers RAX/RCX/RDX and host flags; no GuestState field changes.
pub(crate) fn check_sp(code: &mut Vec<u8>, base: Register, pc: u64) -> Option<usize> {
    if base != Register::Sp {
        return None;
    }
    load(code, Register::Sp);
    code.extend([TEST_AL_IMM8, STACK_ALIGNMENT_MASK]);
    code.extend(JE_REL32);
    let aligned = code.len();
    code.extend(0_i32.to_le_bytes());
    fault(code, MemoryStatus::StackAlignment, pc);
    code.push(JMP_REL32);
    let failed = code.len();
    code.extend(0_i32.to_le_bytes());
    let destination = code.len();
    patch_branch(code, aligned, destination);
    Some(failed)
}

/// Return only after scratch cleanup. The checked outer CALL wrapper owns R15.
/// The runtime inspects the fault view before interpreting native block returns.
pub(crate) fn return_if_failed(code: &mut Vec<u8>) {
    code.extend(TEST_EAX_EAX);
    code.extend([JE_REL8, 1, RET]);
}

/// Unchecked arithmetic AFTER check_sp. RAX=EA. Pre/Post also produce
/// RDX=pending base writeback; Offset leaves RDX unspecified. Snapshot pending
/// writeback before callbacks; commit only on full success. LEA is modulo64.
pub(crate) fn immediate(code: &mut Vec<u8>, base: Register, displacement: i32, mode: AddressMode) {
    load(code, base);
    if mode == AddressMode::Offset && displacement == 0 {
        return;
    }
    if mode != AddressMode::Offset && displacement == 0 {
        code.extend(MOV_RDX_RAX);
    } else {
        let compact = i8::try_from(displacement).ok();
        code.extend(match (mode == AddressMode::Offset, compact.is_some()) {
            (true, true) => LEA_RAX_RAX_DISP8,
            (true, false) => LEA_RAX_RAX_DISP32,
            (false, true) => LEA_RDX_RAX_DISP8,
            (false, false) => LEA_RDX_RAX_DISP32,
        });
        if let Some(value) = compact {
            code.push(value as u8);
        } else {
            code.extend(displacement.to_le_bytes());
        }
    }
    if mode == AddressMode::PreIndex && displacement != 0 {
        code.extend(MOV_RAX_RDX);
    }
}

/// Source AddressAdd, using the actual access level's resolved specialization.
/// Original-SP checks and store staging precede this helper. RAX is the access
/// address; Pre/Post also produce RDX=pending writeback. No guest effect occurs.
/// PostIndex retains the original access address while marking only writeback.
pub(crate) fn immediate_with_checks(
    code: &mut Vec<u8>,
    base: Register,
    displacement: i32,
    mode: AddressMode,
    checks: AddressAddChecks,
) {
    // Zero-offset marking is idempotent, including an already marked base.
    // The containing body must still retain its actual control requirement.
    if checks == AddressAddChecks::Disabled || displacement == 0 {
        immediate(code, base, displacement, mode);
        return;
    }
    load(code, base);
    code.extend(MOV_RDX_RAX);
    if mode == AddressMode::PostIndex {
        code.extend(MOV_R8_RAX);
    }
    if let Ok(compact) = i8::try_from(displacement) {
        code.extend(LEA_RAX_RAX_DISP8);
        code.push(compact as u8);
    } else {
        code.extend(LEA_RAX_RAX_DISP32);
        code.extend(displacement.to_le_bytes());
    }
    // The common CPA recipe preserves original RDX and, without multiplication,
    // R8. Only RAX/RCX/R9/R10/R11 and host flags are scratch.
    crate::x86_64::pointer_checks::emit(code, false);
    if mode != AddressMode::Offset {
        code.extend(MOV_RDX_RAX);
    }
    if mode == AddressMode::PostIndex {
        code.extend(MOV_RAX_R8);
    }
}

/// Unchecked arithmetic AFTER check_sp. RAX=EA; no base writeback. Operands are
/// the existing validated decoder types, including W extension and ZR index.
pub(crate) fn register_offset(
    code: &mut Vec<u8>,
    base: Register,
    index: Register,
    extend: IndexExtend,
    shift: u8,
) {
    load(code, base);
    right_operand(code, index, Width::X64, Shift::Lsl, 0);
    match extend {
        IndexExtend::Uxtw => code.extend(MOV_ECX_ECX),
        IndexExtend::Sxtw => code.extend(MOVSXD_RCX_ECX),
        IndexExtend::Lsl | IndexExtend::Sxtx => {}
    }
    if shift != 0 {
        code.extend(SHL_RCX_IMM8);
        code.push(shift);
    }
    code.extend(LEA_RAX_RAX_RCX);
}

/// Source AddressAdd for a decoded extended/shifted register offset. RAX=EA;
/// RDX retains original base across the shared marker. No writeback is present.
pub(crate) fn register_offset_with_checks(
    code: &mut Vec<u8>,
    base: Register,
    index: Register,
    extend: IndexExtend,
    shift: u8,
    checks: AddressAddChecks,
) {
    if checks == AddressAddChecks::Disabled {
        register_offset(code, base, index, extend, shift);
        return;
    }
    load(code, base);
    if index == Register::Zero {
        return;
    }
    code.extend(MOV_RDX_RAX);
    right_operand(code, index, Width::X64, Shift::Lsl, 0);
    match extend {
        IndexExtend::Uxtw => code.extend(MOV_ECX_ECX),
        IndexExtend::Sxtw => code.extend(MOVSXD_RCX_ECX),
        IndexExtend::Lsl | IndexExtend::Sxtx => {}
    }
    if shift != 0 {
        code.extend(SHL_RCX_IMM8);
        code.push(shift);
    }
    code.extend(LEA_RAX_RAX_RCX);
    crate::x86_64::pointer_checks::emit(code, false);
}
