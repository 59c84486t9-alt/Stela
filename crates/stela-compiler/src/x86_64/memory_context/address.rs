//! SP alignment checks and address arithmetic for checked accesses.
use super::{fault, patch_branch};
use crate::x86_64::asm::Code;
use crate::x86_64::load;
use crate::{
    aarch64::{AddressMode, Register, register_offset::IndexExtend},
    context::memory::{MemoryStatus, address::AddressAddChecks},
};

const STACK_ALIGNMENT_MASK: u8 = 15;
const TEST_AL_IMM8: u8 = 0xa8;
const JE_REL32: &[u8] = &[0x0f, 0x84];
const JMP_REL32: u8 = 0xe9;
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const JE_REL8: u8 = 0x74;
const RET: u8 = 0xc3;
const LEA_RAX_RAX_DISP8: &[u8] = &[0x48, 0x8d, 0x40];
const LEA_RAX_RAX_DISP32: &[u8] = &[0x48, 0x8d, 0x80];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const MOV_R8_RAX: &[u8] = &[0x49, 0x89, 0xc0];
const MOV_RAX_R8: &[u8] = &[0x4c, 0x89, 0xc0];

/// Check SP before the offset is applied. The caller patches the returned rel32
/// to its cleanup. On failure RAX holds the faulting SP. Clobbers RAX/RCX/RDX
/// and flags.
pub(crate) fn check_sp(code: &mut Code, base: Register, pc: u64) -> Option<usize> {
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
pub(crate) fn return_if_failed(code: &mut Code) {
    code.extend(TEST_EAX_EAX);
    code.extend([JE_REL8, 1, RET]);
}

/// Unchecked arithmetic AFTER check_sp ([`crate::x86_64::address_add`]).
/// Snapshot pending writeback before callbacks; commit only on full success.
pub(crate) fn immediate(code: &mut Code, base: Register, displacement: i32, mode: AddressMode) {
    load(code, base);
    crate::x86_64::address_add(code, displacement, mode);
}

/// AddressAdd at the access level's resolved specialization, after the SP check
/// and store staging. RAX is the access address; pre- and post-index forms also
/// leave the pending writeback in RDX. Post-index keeps the original access
/// address and marks only the writeback.
pub(crate) fn immediate_with_checks(
    code: &mut Code,
    base: Register,
    displacement: i32,
    mode: AddressMode,
    checks: AddressAddChecks,
) {
    // Marking a zero offset is idempotent, even on an already marked base.
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
    // The CPA recipe preserves RDX and, without multiplication, R8.
    // RAX/RCX/R9/R10/R11 and flags are scratch.
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
    code: &mut Code,
    base: Register,
    index: Register,
    extend: IndexExtend,
    shift: u8,
) {
    load(code, base);
    crate::x86_64::register_offset::index_add(code, index, extend, shift);
}

/// AddressAdd for an extended or shifted register offset. RAX is the effective
/// address and RDX keeps the base. There is no writeback.
pub(crate) fn register_offset_with_checks(
    code: &mut Code,
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
    crate::x86_64::register_offset::index_add(code, index, extend, shift);
    crate::x86_64::pointer_checks::emit(code, false);
}
