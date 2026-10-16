//! LD1-4/ST1-4 (single lane) and LD1R-4R within one page.
use super::super::{commit, vector_offset};
use super::{element_load, element_store, scalar_state_transfer};
use crate::{
    TargetCpu,
    aarch64::simd::structure_memory::{Direction, Layout, Operand},
    x86_64::isa::SimdOpcode as Host,
};
use alloc::vec::Vec;

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const VECTOR_BYTES: u8 = 16;
const VECTOR_REGISTER_MASK: u8 = 31;
const RESULT_XMM: u8 = 0;
const BROADCAST_MASK_XMM: u8 = 1;
const ECX: u8 = 1;
const MOVD_XMM0_ECX: [u8; 4] = [0x66, 0x0f, 0x6e, 0xc1];
const REPEAT_LOW_ELEMENT: u8 = 0;

/// RAX is the address; the pending writeback in RDX and the state in RDI
/// survive.
pub(super) fn packed(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    match operand.layout {
        Layout::Lane { structures, index } => lane(code, operand, structures, index),
        Layout::Replicate {
            structures,
            vector_bytes,
        } => {
            replicate(code, operand, structures, vector_bytes, target);
        }
        Layout::Multiple { .. } => unreachable!("single-structure dispatch"),
    }
}

fn lane(code: &mut Vec<u8>, operand: &Operand, structures: u8, index: u8) {
    let load = operand.direction == Direction::Load;
    for structure in 0..structures {
        let vector = (operand.first_vector + structure) & VECTOR_REGISTER_MASK;
        let memory_byte = structure * operand.element_bytes;
        let state_byte = vector_offset(vector) + u32::from(index * operand.element_bytes);
        if load {
            element_load(code, operand.element_bytes, memory_byte);
            scalar_state_transfer(code, true, operand.element_bytes, state_byte);
        } else {
            scalar_state_transfer(code, false, operand.element_bytes, state_byte);
            element_store(code, operand.element_bytes, memory_byte);
        }
    }
}

fn replicate(
    code: &mut Vec<u8>,
    operand: &Operand,
    structures: u8,
    vector_bytes: u8,
    target: TargetCpu,
) {
    // A zero PSHUFB control broadcasts byte zero. Build it once per guest
    // instruction; no table loads or extra guest memory reads are needed.
    let byte_shuffle = operand.element_bytes == BYTE_BYTES
        && vector_bytes == VECTOR_BYTES
        && target.supports(TargetCpu::Ssse3);
    if byte_shuffle {
        Host::Xor.register(
            code,
            BROADCAST_MASK_XMM,
            BROADCAST_MASK_XMM,
            TargetCpu::Baseline,
        );
    }
    for structure in 0..structures {
        let displacement = structure * operand.element_bytes;
        match operand.element_bytes {
            BYTE_BYTES | HALFWORD_BYTES => {
                element_load(code, operand.element_bytes, displacement);
                code.extend(MOVD_XMM0_ECX);
            }
            DWORD_BYTES | QWORD_BYTES => super::super::memory::wide_transfer(
                code,
                true,
                operand.element_bytes,
                RESULT_XMM,
                displacement,
                true,
            ),
            _ => unreachable!("decoded replicate element width"),
        }
        if byte_shuffle {
            Host::ByteShuffle.register(code, RESULT_XMM, BROADCAST_MASK_XMM, target);
        } else {
            broadcast_xmm(code, operand.element_bytes, vector_bytes);
        }
        let vector = (operand.first_vector + structure) & VECTOR_REGISTER_MASK;
        commit(code, vector, RESULT_XMM);
    }
}

/// Ordered fallback: a completed exact-width read is zero-extended in RCX.
/// Construct XMM0 without touching the address or pending writeback.
pub(super) fn broadcast(code: &mut Vec<u8>, bytes: u8, vector_bytes: u8) {
    if bytes == QWORD_BYTES {
        Host::MoveGprQword.register(code, RESULT_XMM, ECX, TargetCpu::Baseline);
    } else {
        code.extend(MOVD_XMM0_ECX);
    }
    broadcast_xmm(code, bytes, vector_bytes);
}

fn broadcast_xmm(code: &mut Vec<u8>, bytes: u8, vector_bytes: u8) {
    let full_vector = vector_bytes == VECTOR_BYTES;
    match bytes {
        BYTE_BYTES => {
            Host::UnpackLowByte.register(code, RESULT_XMM, RESULT_XMM, TargetCpu::Baseline);
            if full_vector {
                Host::UnpackLowWord.register(code, RESULT_XMM, RESULT_XMM, TargetCpu::Baseline);
                shuffle(code, Host::ShuffleDword);
            } else {
                shuffle(code, Host::ShuffleLowWord);
            }
        }
        HALFWORD_BYTES => {
            if full_vector {
                Host::UnpackLowWord.register(code, RESULT_XMM, RESULT_XMM, TargetCpu::Baseline);
                shuffle(code, Host::ShuffleDword);
            } else {
                shuffle(code, Host::ShuffleLowWord);
            }
        }
        DWORD_BYTES if full_vector => shuffle(code, Host::ShuffleDword),
        DWORD_BYTES => {
            Host::UnpackLowDword.register(code, RESULT_XMM, RESULT_XMM, TargetCpu::Baseline);
        }
        QWORD_BYTES if full_vector => {
            Host::UnpackLowQword.register(code, RESULT_XMM, RESULT_XMM, TargetCpu::Baseline);
        }
        QWORD_BYTES => {}
        _ => unreachable!("decoded replicate element width"),
    }
}

fn shuffle(code: &mut Vec<u8>, opcode: Host) {
    opcode.register(code, RESULT_XMM, RESULT_XMM, TargetCpu::Baseline);
    code.push(REPEAT_LOW_ELEMENT);
}
