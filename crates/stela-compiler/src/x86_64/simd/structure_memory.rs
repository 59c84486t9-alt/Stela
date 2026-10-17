//! Structured loads and stores, with an element-by-element path across page
//! boundaries.
use super::{commit, vector_offset};
use crate::TargetCpu;
use crate::aarch64::simd::structure_memory::{
    Access, Direction, Layout, LoadCommit, Operand, PostIndex,
};
use crate::aarch64::{AddressMode, Register};
use alloc::vec::Vec;

mod multiple;
mod single;

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const STACK_ALIGNMENT_BYTES: u8 = 16;
const OPERAND_SIZE_PREFIX: u8 = 0x66;
const REX_W: u8 = 0x48;
const MOV_BYTE_STORE: u8 = 0x88;
const MOV_STORE: u8 = 0x89;
const MOV_LOAD: u8 = 0x8b;
const MODRM_RCX_STATE_DISP32: u8 = 0x8f;
const MODRM_RCX_RAX: u8 = 0x08;
const MODRM_DISP8: u8 = 0x40;
const MOVZX_ECX_BYTE: &[u8] = &[0x0f, 0xb6];
const MOVZX_ECX_HALFWORD: &[u8] = &[0x0f, 0xb7];
const LEA_RDX_RAX_DISP32: &[u8] = &[0x48, 0x8d, 0x90];
const ADD_RDX_RCX: &[u8] = &[0x48, 0x01, 0xca];
const ADD_RAX_IMM8: &[u8] = &[0x48, 0x83, 0xc0];
const LEA_R10D_RAX_DISP8: &[u8] = &[0x44, 0x8d, 0x50];
const XOR_R10D_EAX: &[u8] = &[0x41, 0x31, 0xc2];
const TEST_R10D_IMM32: &[u8] = &[0x41, 0xf7, 0xc2];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];
const JMP_REL32: u8 = 0xe9;
const MOV_ZERO_QWORD_STATE: &[u8] = &[0x48, 0xc7, 0x87];

pub(super) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    target: TargetCpu,
    checks: super::super::MemoryChecks,
) {
    // This reuses the incoming-SP check before any guest RAM access.
    // SCTLR_ELx.A checks each element: all are aligned when the first is.
    super::super::memory_address(
        code,
        checks,
        operand.base,
        0,
        AddressMode::Offset,
        operand.element_bytes,
    );
    match operand.post_index {
        PostIndex::None => {}
        PostIndex::TransferredBytes => {
            code.extend(LEA_RDX_RAX_DISP32);
            code.extend(i32::from(operand.transferred_bytes()).to_le_bytes());
        }
        PostIndex::Register(index) => {
            scalar_state_transfer(
                code,
                false,
                QWORD_BYTES,
                super::super::offset(Register::X(index)).expect("post-index is X0..X30"),
            );
            code.extend(ADD_RDX_RCX);
        }
    }
    // A checked SP is 16-byte aligned; an unchecked one is an ordinary base.
    let aligned_sp = operand.base == Register::Sp && checks.stack_alignment;
    if operand.transferred_bytes() == BYTE_BYTES
        || (aligned_sp && operand.transferred_bytes() <= STACK_ALIGNMENT_BYTES)
    {
        packed(code, operand, target);
    } else {
        // N <= 64: bit12 changes exactly when this footprint crosses a 4KiB
        // boundary, including wrapping addresses. No memory is read by the guard.
        code.extend(LEA_R10D_RAX_DISP8);
        code.push(operand.transferred_bytes() - 1);
        code.extend(XOR_R10D_EAX);
        code.extend(TEST_R10D_IMM32);
        code.extend(super::super::memory_store::PROTECTION_GRANULE_BYTES.to_le_bytes());
        code.extend(JNZ_REL32);
        let crossing_jump = branch_placeholder(code);
        packed(code, operand, target);
        code.push(JMP_REL32);
        let complete_jump = branch_placeholder(code);
        patch_jump(code, crossing_jump);
        ordered(code, operand, aligned_sp);
        patch_jump(code, complete_jump);
    }
    if operand.post_index != PostIndex::None {
        super::super::memory_writeback(code, operand.base, AddressMode::PostIndex);
    }
}

fn packed(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    match operand.layout {
        Layout::Multiple { .. } => multiple::packed(code, operand, target),
        Layout::Lane { .. } | Layout::Replicate { .. } => single::packed(code, operand, target),
    }
}

/// Source-width accesses and immediate successful assignments. RDX/RDI survive;
/// RAX advances through the footprint, RCX/R10/XMM0 are scratch.
fn ordered(code: &mut Vec<u8>, operand: &Operand, aligned_sp: bool) {
    let count = operand.transferred_bytes() / operand.element_bytes;
    for (ordinal, access) in operand.accesses().enumerate() {
        transfer_access(code, operand, access, 0, false, aligned_sp);
        if ordinal + 1 != usize::from(count) {
            code.extend(ADD_RAX_IMM8);
            code.push(operand.element_bytes);
        }
    }
}

/// The whole footprint is within one granule, so elements are accessed at fixed
/// displacements without per-element store guards.
fn ordered_in_granule(code: &mut Vec<u8>, operand: &Operand) {
    for access in operand.accesses() {
        transfer_access(code, operand, access, access.byte_offset, true, false);
    }
}

fn transfer_access(
    code: &mut Vec<u8>,
    operand: &Operand,
    access: Access,
    displacement: u8,
    in_granule: bool,
    aligned_sp: bool,
) {
    match (operand.direction, access.commit) {
        (Direction::Load, LoadCommit::Lane { index, clear_upper }) => {
            element_load(code, operand.element_bytes, displacement);
            scalar_state_transfer(
                code,
                true,
                operand.element_bytes,
                vector_offset(access.vector) + u32::from(index * operand.element_bytes),
            );
            if clear_upper {
                code.extend(MOV_ZERO_QWORD_STATE);
                code.extend((vector_offset(access.vector) + u32::from(QWORD_BYTES)).to_le_bytes());
                code.extend(0i32.to_le_bytes());
            }
        }
        (Direction::Load, LoadCommit::Replicate { vector_bytes }) => {
            element_load(code, operand.element_bytes, displacement);
            single::broadcast(code, operand.element_bytes, vector_bytes);
            commit(code, access.vector, 0);
        }
        (Direction::Store, LoadCommit::Lane { index, .. }) => {
            scalar_state_transfer(
                code,
                false,
                operand.element_bytes,
                vector_offset(access.vector) + u32::from(index * operand.element_bytes),
            );
            if in_granule {
                element_store(code, operand.element_bytes, displacement);
            } else {
                super::super::memory_store::emit(
                    code,
                    operand.element_bytes,
                    0,
                    super::super::memory_store::Source::Rcx,
                    aligned_sp,
                );
            }
        }
        (Direction::Store, LoadCommit::Replicate { .. }) => {
            unreachable!("replicate encodings are load-only")
        }
    }
}

/// Exact-width RAM read into zero-extended RCX; no guest state commit yet.
fn element_load(code: &mut Vec<u8>, bytes: u8, displacement: u8) {
    match bytes {
        BYTE_BYTES => code.extend(MOVZX_ECX_BYTE),
        HALFWORD_BYTES => code.extend(MOVZX_ECX_HALFWORD),
        DWORD_BYTES => code.push(MOV_LOAD),
        QWORD_BYTES => code.extend([REX_W, MOV_LOAD]),
        _ => unreachable!("decoder validates scalar structure width"),
    }
    code.push(MODRM_RCX_RAX | if displacement == 0 { 0 } else { MODRM_DISP8 });
    if displacement != 0 {
        code.push(displacement);
    }
}

/// Exact scalar RCX store, used only after the whole-footprint granule proof.
fn element_store(code: &mut Vec<u8>, bytes: u8, displacement: u8) {
    if bytes == HALFWORD_BYTES {
        code.push(OPERAND_SIZE_PREFIX);
    } else if bytes == QWORD_BYTES {
        code.push(REX_W);
    }
    code.push(if bytes == BYTE_BYTES {
        MOV_BYTE_STORE
    } else {
        MOV_STORE
    });
    code.push(MODRM_RCX_RAX | if displacement == 0 { 0 } else { MODRM_DISP8 });
    if displacement != 0 {
        code.push(displacement);
    }
}

/// true writes RCX to the selected state lane; false reads it into RCX.
fn scalar_state_transfer(code: &mut Vec<u8>, load: bool, bytes: u8, state_offset: u32) {
    if !load && bytes <= HALFWORD_BYTES {
        code.extend(if bytes == BYTE_BYTES {
            MOVZX_ECX_BYTE
        } else {
            MOVZX_ECX_HALFWORD
        });
    } else {
        if bytes == HALFWORD_BYTES {
            code.push(OPERAND_SIZE_PREFIX);
        } else if bytes == QWORD_BYTES {
            code.push(REX_W);
        }
        code.push(if !load {
            MOV_LOAD
        } else if bytes == BYTE_BYTES {
            MOV_BYTE_STORE
        } else {
            MOV_STORE
        });
    }
    code.push(MODRM_RCX_STATE_DISP32);
    code.extend(state_offset.to_le_bytes());
}

fn branch_placeholder(code: &mut Vec<u8>) -> usize {
    let offset = code.len();
    code.extend(0i32.to_le_bytes());
    offset
}

fn patch_jump(code: &mut [u8], offset: usize) {
    let displacement = i32::try_from(code.len() - offset - size_of::<i32>())
        .expect("bounded structure-transfer body");
    code[offset..offset + size_of::<i32>()].copy_from_slice(&displacement.to_le_bytes());
}
