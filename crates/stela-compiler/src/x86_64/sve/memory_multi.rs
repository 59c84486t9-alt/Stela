//! Callback candidate for exact reached-element multi-vector memory transfers.
//!
//! Private staging keeps every load destination unchanged until the complete
//! tuple succeeds. Stores submit ascending elements without rolling back RAM.
use super::super::{isa::SimdOpcode as Host, scalable};
use super::memory as common;
use super::predicate::{emit_prepared_counter_chunk, prepare_counter};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sve::memory_multi::Operand,
    },
    context::memory::{
        MEMORY_REQUEST_BYTES, MEMORY_REQUEST_DATA_OFFSET, MemoryRequirements,
        SpAlignmentRequirement, flags, host_caps, profile_requirements,
    },
};
use alloc::vec::Vec;

const HOST_QWORD_BYTES: u32 = size_of::<u64>() as u32;
const STACK_ALIGNMENT: u32 = 16;
const PACKED_CHUNK_BITS: usize = u64::BITS as usize;
const REQUEST_OFFSET: u32 = 0;
const ADDRESS_OFFSET: u32 = MEMORY_REQUEST_BYTES as u32;
const INDEX_OFFSET: u32 = ADDRESS_OFFSET + HOST_QWORD_BYTES;
const MASK_OFFSET: u32 = INDEX_OFFSET + HOST_QWORD_BYTES;
const VECTOR_TEMPORARY: u8 = 0;
const SUB_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xec];
const ADD_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xc4];
const MOV_RSP_DISP32_RAX: &[u8] = &[0x48, 0x89, 0x84, 0x24];
const MOV_RAX_RSP_DISP32: &[u8] = &[0x48, 0x8b, 0x84, 0x24];
const MOV_RCX_RSP_DISP32: &[u8] = &[0x48, 0x8b, 0x8c, 0x24];
const MOV_RSP_DISP32_IMM32: &[u8] = &[0x48, 0xc7, 0x84, 0x24];
const ADD_RAX_RCX: &[u8] = &[0x48, 0x01, 0xc8];
const BT_RSP_DISP32_RCX: &[u8] = &[0x48, 0x0f, 0xa3, 0x8c, 0x24];
const ADD_RSP_DISP32_RCX: &[u8] = &[0x48, 0x01, 0x8c, 0x24];
const ADD_RSP_DISP32_IMM8: &[u8] = &[0x48, 0x83, 0x84, 0x24];
const CMP_RSP_DISP32_IMM32: &[u8] = &[0x48, 0x81, 0xbc, 0x24];
const JNC_REL32: &[u8] = &[0x0f, 0x83];
const JB_REL32: &[u8] = &[0x0f, 0x82];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const STACK_MEMORY_MODRM: u8 = 0x84;
const STACK_SIB: u8 = 0x24;

#[derive(Debug, Clone, Copy)]
struct Scratch {
    data: u32,
    bytes: u32,
}

impl Scratch {
    fn new(tuple_bytes: usize) -> Self {
        let mask_bytes = tuple_bytes.div_ceil(PACKED_CHUNK_BITS) as u32 * HOST_QWORD_BYTES;
        let data = MASK_OFFSET + mask_bytes.next_multiple_of(STACK_ALIGNMENT);
        Self {
            data,
            bytes: data + tuple_bytes as u32,
        }
    }
}

fn stack_vector(code: &mut Vec<u8>, offset: u32, loading: bool, target: TargetCpu) {
    let opcode = if loading {
        Host::LoadUnaligned
    } else {
        Host::StoreUnaligned
    };
    opcode.append(code, target);
    code.extend([STACK_MEMORY_MODRM, STACK_SIB]);
    code.extend(offset.to_le_bytes());
}

fn branch(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let displacement = code.len();
    code.extend(0_i32.to_le_bytes());
    displacement
}

fn prepare_iteration(code: &mut Vec<u8>, operand: &Operand, length: VectorLength) {
    common::address(code, operand.address, length);
    code.extend(MOV_RSP_DISP32_RAX);
    code.extend(ADDRESS_OFFSET.to_le_bytes());
    code.extend(MOV_RSP_DISP32_IMM32);
    code.extend(INDEX_OFFSET.to_le_bytes());
    code.extend(0_u32.to_le_bytes());
}

fn prepare_vector_staging(
    code: &mut Vec<u8>,
    operand: &Operand,
    scratch: Scratch,
    length: VectorLength,
    target: TargetCpu,
) {
    if operand.loading {
        Host::Xor.register(code, VECTOR_TEMPORARY, VECTOR_TEMPORARY, target);
    }
    for register in 0..operand.registers {
        for chunk in 0..length.chunks() {
            if !operand.loading {
                scalable::load_z_chunk(
                    code,
                    operand.first + register,
                    chunk,
                    VECTOR_TEMPORARY,
                    length,
                    target,
                );
            }
            let position = usize::from(register) * length.bytes() + chunk * VECTOR_CHUNK_BYTES;
            stack_vector(code, scratch.data + position as u32, false, target);
        }
    }
}

/// Decode PN once, then spill its packed mask before any memory callback.
/// The published chunk helper preserves R8/R9/R10 preparation state. Only
/// private-stack stores intervene, so no callback clobber crosses that interval.
fn prepare_predicate_staging(code: &mut Vec<u8>, operand: &Operand, length: VectorLength) {
    let predicate_bits = usize::from(operand.registers) * length.bytes();
    scalable::read_predicate_chunk(code, operand.predicate, 0, length);
    prepare_counter(code, length);
    for chunk in 0..predicate_bits.div_ceil(PACKED_CHUNK_BITS) {
        emit_prepared_counter_chunk(code, chunk, length);
        code.extend(MOV_RSP_DISP32_RAX);
        code.extend((MASK_OFFSET + chunk as u32 * HOST_QWORD_BYTES).to_le_bytes());
    }
}

fn commit_load(
    code: &mut Vec<u8>,
    operand: &Operand,
    scratch: Scratch,
    length: VectorLength,
    target: TargetCpu,
) {
    for register in 0..operand.registers {
        for chunk in 0..length.chunks() {
            let position = usize::from(register) * length.bytes() + chunk * VECTOR_CHUNK_BYTES;
            stack_vector(code, scratch.data + position as u32, true, target);
            scalable::store_z_chunk(
                code,
                operand.first + register,
                chunk,
                VECTOR_TEMPORARY,
                length,
                target,
            );
        }
    }
}

fn access_flags(operand: &Operand) -> u32 {
    // These PN-governed forms call the four-argument CreateAccDescSVE overload,
    // which sets descriptor.predicated=false independently of the PN mask.
    (if operand.loading { 0 } else { flags::WRITE })
        | if operand.tag_checked() {
            flags::TAG_CHECKED
        } else {
            0
        }
        | if operand.non_temporal {
            flags::NON_TEMPORAL
        } else {
            0
        }
}

/// Requirements of this complete body, admitted before any guest effect.
/// The shared SP check specializes SA-enabled execution: tuple-scaled immediate
/// and element-scaled register offsets keep every SP-base element naturally
/// aligned. Generic multibyte loads may need an enclosing atomic16 snapshot.
/// Scalar stores use XCHG and need no optional host capability.
pub(crate) fn requirements(operand: &Operand) -> MemoryRequirements {
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: Default::default(),
        required_sp_alignment: if operand.address.base == Register::Sp {
            SpAlignmentRequirement::Enabled
        } else {
            SpAlignmentRequirement::Any
        },
        required_flags: access_flags(operand),
        required_host_caps: if operand.loading
            && operand.element != ElementSize::Byte
            && operand.address.base != Register::Sp
        {
            host_caps::ATOMIC_LOAD16
        } else {
            0
        },
        required_profile: profile_requirements::NATIVE_ACCESS
            | if operand.tag_checked() {
                profile_requirements::TAG_GRANULES | profile_requirements::SCALABLE_TAG_CHECKS
            } else {
                0
            },
    }
}

/// Candidate context-memory emission. Entry has RDI=State, R15=Context and
/// RSP=8 modulo16. Failure restores scratch then returns the inner body to its
/// outer context wrapper; success has EAX=0 and falls through. RDI/R15 survive.
pub(crate) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
    pc: u64,
) {
    use scalable::memory;
    let tuple_bytes = usize::from(operand.registers) * length.bytes();
    let scratch = Scratch::new(tuple_bytes);
    code.extend(SUB_RSP_IMM32);
    code.extend(scratch.bytes.to_le_bytes());
    memory::begin(code);
    let alignment_failure = common::check_sp(code, operand.address.base, pc);
    prepare_iteration(code, operand, length);
    prepare_vector_staging(code, operand, scratch, length, target);
    prepare_predicate_staging(code, operand, length);
    let loop_start = code.len();
    code.extend(MOV_RCX_RSP_DISP32);
    code.extend(INDEX_OFFSET.to_le_bytes());
    code.extend(BT_RSP_DISP32_RCX);
    code.extend(MASK_OFFSET.to_le_bytes());
    let inactive = branch(code, JNC_REL32);
    code.extend(MOV_RAX_RSP_DISP32);
    code.extend(ADDRESS_OFFSET.to_le_bytes());
    code.extend(ADD_RAX_RCX);
    memory::request(
        code,
        REQUEST_OFFSET,
        scratch.data,
        operand.element.bytes() as u32,
        access_flags(operand),
        pc,
    );
    // request() clobbers RCX/RDX. Reload the saved linear byte offset before
    // selecting this element's private staging, never an architectural Z slot.
    code.extend(MOV_RCX_RSP_DISP32);
    code.extend(INDEX_OFFSET.to_le_bytes());
    code.extend(ADD_RSP_DISP32_RCX);
    code.extend((REQUEST_OFFSET + MEMORY_REQUEST_DATA_OFFSET).to_le_bytes());
    memory::call(code, REQUEST_OFFSET);
    let callback_failure = memory::branch_failed(code);
    let next_element = code.len();
    memory::patch_branch(code, inactive, next_element);
    code.extend(ADD_RSP_DISP32_IMM8);
    code.extend(INDEX_OFFSET.to_le_bytes());
    code.push(operand.element.bytes() as u8);
    code.extend(CMP_RSP_DISP32_IMM32);
    code.extend(INDEX_OFFSET.to_le_bytes());
    code.extend((tuple_bytes as u32).to_le_bytes());
    let repeat = branch(code, JB_REL32);
    memory::patch_branch(code, repeat, loop_start);
    if operand.loading {
        commit_load(code, operand, scratch, length, target);
    }
    code.extend(XOR_EAX_EAX);
    let cleanup = code.len();
    memory::patch_branch(code, callback_failure, cleanup);
    if let Some(failure) = alignment_failure {
        memory::patch_branch(code, failure, cleanup);
    }
    code.extend(ADD_RSP_IMM32);
    code.extend(scratch.bytes.to_le_bytes());
    common::return_if_failed(code);
}

#[cfg(test)]
mod tests;
