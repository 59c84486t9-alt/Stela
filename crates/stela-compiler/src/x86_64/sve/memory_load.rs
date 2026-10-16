//! Callback candidate for SVE loads with a private, fault-atomic destination.
//!
//! Guest RAM is accessed only through the versioned memory service. Its exact
//! element decomposition and writer-domain participation are runtime-owned.
use super::super::{isa::SimdOpcode as Host, scalable};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sve::{
            memory::Extension,
            memory_load::{Kind, Operand},
        },
    },
    context::memory::{
        MEMORY_REQUEST_BYTES, MemoryRequirements, SpAlignmentRequirement, flags, host_caps,
        profile_requirements,
    },
};
use alloc::vec::Vec;

const STACK_ALIGNMENT: u32 = 16;
const QWORD_BYTES: u32 = size_of::<u64>() as u32;
const PREDICATE_WORD_BITS: usize = u64::BITS as usize;
const SUB_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xec];
const ADD_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xc4];
const ADD_RAX_IMM32: &[u8] = &[0x48, 0x05];
const MOV_RAX_RSP_DISP32: &[u8] = &[0x48, 0x8b, 0x84, 0x24];
const MOV_EAX_RSP_DISP32: &[u8] = &[0x8b, 0x84, 0x24];
const MOVZX_EAX_BYTE_RSP_DISP32: &[u8] = &[0x0f, 0xb6, 0x84, 0x24];
const MOVZX_EAX_WORD_RSP_DISP32: &[u8] = &[0x0f, 0xb7, 0x84, 0x24];
const MOVSX_RAX_BYTE_RSP_DISP32: &[u8] = &[0x48, 0x0f, 0xbe, 0x84, 0x24];
const MOVSX_RAX_WORD_RSP_DISP32: &[u8] = &[0x48, 0x0f, 0xbf, 0x84, 0x24];
const MOVSXD_RAX_RSP_DISP32: &[u8] = &[0x48, 0x63, 0x84, 0x24];
const MOV_RSP_DISP32_RAX: &[u8] = &[0x48, 0x89, 0x84, 0x24];
const MOV_RSP_DISP32_EAX: &[u8] = &[0x89, 0x84, 0x24];
const MOV_RSP_DISP32_AX: &[u8] = &[0x66, 0x89, 0x84, 0x24];
const MOV_RSP_DISP32_AL: &[u8] = &[0x88, 0x84, 0x24];
const MOVDQU_RSP_DISP32_XMM0: &[u8] = &[0xf3, 0x0f, 0x7f, 0x84, 0x24];
const MOVDQU_RSP_DISP32_XMM3: &[u8] = &[0xf3, 0x0f, 0x7f, 0x9c, 0x24];
const SIMD_MODRM_REGISTER: u8 = 0xc0;
const REPEAT_LOW_DWORD: u8 = 0;
const MOVDQU_XMM0_RSP_DISP32: &[u8] = &[0xf3, 0x0f, 0x6f, 0x84, 0x24];
const PXOR_XMM0_XMM0: &[u8] = &[0x66, 0x0f, 0xef, 0xc0];
const BT_RAX_IMM8: &[u8] = &[0x48, 0x0f, 0xba, 0xe0];
const TEST_RAX_RAX: &[u8] = &[0x48, 0x85, 0xc0];
const MOVABS_RCX_IMM64: &[u8] = &[0x48, 0xb9];
const AND_RAX_RCX: &[u8] = &[0x48, 0x21, 0xc8];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];
const JNC_REL32: &[u8] = &[0x0f, 0x83];
const JMP_REL32: &[u8] = &[0xe9];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];

#[derive(Clone, Copy)]
struct Scratch {
    predicate: u32,
    address: u32,
    scalar: u32,
    request: u32,
    bytes: u32,
}

impl Scratch {
    fn new(length: VectorLength) -> Self {
        let predicate = length.bytes() as u32;
        let predicate_bytes =
            (length.predicate_bytes() as u32).div_ceil(STACK_ALIGNMENT) * STACK_ALIGNMENT;
        let address = predicate + predicate_bytes;
        let scalar = address + QWORD_BYTES;
        let request = scalar + QWORD_BYTES;
        Self {
            predicate,
            address,
            scalar,
            request,
            bytes: request + MEMORY_REQUEST_BYTES as u32,
        }
    }
}

fn displacement(code: &mut Vec<u8>, opcode: &[u8], offset: u32) {
    code.extend(opcode);
    code.extend(offset.to_le_bytes());
}

fn branch(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let position = code.len();
    code.extend(0_i32.to_le_bytes());
    position
}

fn add_immediate(code: &mut Vec<u8>, value: i32) {
    if value != 0 {
        code.extend(ADD_RAX_IMM32);
        code.extend(value.to_le_bytes());
    }
}

fn predicate(code: &mut Vec<u8>, operand: Operand, length: VectorLength, scratch: Scratch) {
    if let Some(predicate) = operand.predicate {
        for word in 0..length.predicate_bytes().div_ceil(QWORD_BYTES as usize) {
            scalable::read_predicate_chunk(code, predicate, word, length);
            displacement(
                code,
                MOV_RSP_DISP32_RAX,
                scratch.predicate + word as u32 * QWORD_BYTES,
            );
        }
    }
}

fn inactive_branch(code: &mut Vec<u8>, bit: usize, scratch: Scratch) -> usize {
    let word = bit / PREDICATE_WORD_BITS;
    displacement(
        code,
        MOV_RAX_RSP_DISP32,
        scratch.predicate + word as u32 * QWORD_BYTES,
    );
    code.extend(BT_RAX_IMM8);
    code.push((bit % PREDICATE_WORD_BITS) as u8);
    branch(code, JNC_REL32)
}

fn access_flags(operand: Operand) -> u32 {
    (if operand.tag_checked {
        flags::TAG_CHECKED
    } else {
        0
    }) | (if operand.non_temporal {
        flags::NON_TEMPORAL
    } else {
        0
    }) | (if operand.predicate.is_some() {
        flags::SVE_PREDICATED
    } else {
        0
    })
}

/// Requirements for the complete consumed artifact, validated before entry.
/// Original SP16 plus encoded element-scaled offsets makes SP-base elements
/// naturally aligned; unconstrained multibyte GPR-base reads may cross8 inside16.
pub(crate) fn requirements(operand: Operand) -> MemoryRequirements {
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: Default::default(),
        required_sp_alignment: if operand.address.base == Register::Sp {
            SpAlignmentRequirement::Enabled
        } else {
            SpAlignmentRequirement::Any
        },
        required_flags: access_flags(operand),
        required_host_caps: if operand.memory_element != ElementSize::Byte
            && operand.address.base != Register::Sp
        {
            host_caps::ATOMIC_LOAD16
        } else {
            0
        },
        required_profile: profile_requirements::NATIVE_ACCESS
            | if operand.tag_checked {
                profile_requirements::TAG_GRANULES | profile_requirements::SCALABLE_TAG_CHECKS
            } else {
                0
            },
    }
}

fn request(
    code: &mut Vec<u8>,
    operand: Operand,
    scratch: Scratch,
    source_offset: usize,
    destination_offset: u32,
    pc: u64,
    failed: &mut Vec<usize>,
) {
    displacement(code, MOV_RAX_RSP_DISP32, scratch.address);
    add_immediate(code, source_offset as i32);
    scalable::memory::request(
        code,
        scratch.request,
        destination_offset,
        operand.memory_element.bytes() as u32,
        access_flags(operand),
        pc,
    );
    scalable::memory::call(code, scratch.request);
    failed.push(scalable::memory::branch_failed(code));
}

fn read_value(code: &mut Vec<u8>, source: u32, element: ElementSize, extension: Extension) {
    let opcode = match (element, extension) {
        (ElementSize::Byte, Extension::Zero) => MOVZX_EAX_BYTE_RSP_DISP32,
        (ElementSize::Halfword, Extension::Zero) => MOVZX_EAX_WORD_RSP_DISP32,
        (ElementSize::Word, Extension::Zero) => MOV_EAX_RSP_DISP32,
        (ElementSize::Byte, Extension::Sign) => MOVSX_RAX_BYTE_RSP_DISP32,
        (ElementSize::Halfword, Extension::Sign) => MOVSX_RAX_WORD_RSP_DISP32,
        (ElementSize::Word, Extension::Sign) => MOVSXD_RAX_RSP_DISP32,
        (ElementSize::Doubleword, _) => MOV_RAX_RSP_DISP32,
        (ElementSize::Quadword, _) => unreachable!("SVE load scalar element is at most64 bits"),
    };
    displacement(code, opcode, source);
}

fn write_value(code: &mut Vec<u8>, destination: u32, element: ElementSize) {
    let opcode = match element {
        ElementSize::Byte => MOV_RSP_DISP32_AL,
        ElementSize::Halfword => MOV_RSP_DISP32_AX,
        ElementSize::Word => MOV_RSP_DISP32_EAX,
        ElementSize::Doubleword => MOV_RSP_DISP32_RAX,
        ElementSize::Quadword => unreachable!("SVE load scalar element is at most64 bits"),
    };
    displacement(code, opcode, destination);
}

fn lanes(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    scratch: Scratch,
    pc: u64,
    failed: &mut Vec<usize>,
) {
    let bytes = if operand.kind == Kind::ReplicateQuad {
        VECTOR_CHUNK_BYTES
    } else {
        length.bytes()
    };
    for lane in 0..bytes / operand.element.bytes() {
        let destination = (lane * operand.element.bytes()) as u32;
        let inactive = inactive_branch(code, lane * operand.element.bytes(), scratch);
        request(
            code,
            operand,
            scratch,
            lane * operand.memory_element.bytes(),
            destination,
            pc,
            failed,
        );
        if operand.extension == Extension::Sign {
            read_value(code, destination, operand.memory_element, operand.extension);
            write_value(code, destination, operand.element);
        }
        let end = code.len();
        scalable::memory::patch_branch(code, inactive, end);
    }
}

fn scalar_replicate(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    scratch: Scratch,
    pc: u64,
    failed: &mut Vec<usize>,
    target: TargetCpu,
) {
    let mut active = Vec::new();
    for word in 0..length.predicate_bytes().div_ceil(QWORD_BYTES as usize) {
        displacement(
            code,
            MOV_RAX_RSP_DISP32,
            scratch.predicate + word as u32 * QWORD_BYTES,
        );
        let first_bit = word * PREDICATE_WORD_BITS;
        let valid_bits = (length.bytes() - first_bit).min(PREDICATE_WORD_BITS);
        let mask = (0..valid_bits)
            .step_by(operand.element.bytes())
            .fold(0_u64, |mask, bit| mask | 1_u64 << bit);
        if mask != u64::MAX {
            code.extend(MOVABS_RCX_IMM64);
            code.extend(mask.to_le_bytes());
            code.extend(AND_RAX_RCX);
        }
        code.extend(TEST_RAX_RAX);
        active.push(branch(code, JNZ_REL32));
    }
    let empty = branch(code, JMP_REL32);
    let start = code.len();
    for active in active {
        scalable::memory::patch_branch(code, active, start);
    }
    request(code, operand, scratch, 0, scratch.scalar, pc, failed);
    read_value(
        code,
        scratch.scalar,
        operand.memory_element,
        operand.extension,
    );
    Host::MoveGprQword.append(code, target);
    code.push(SIMD_MODRM_REGISTER);
    match operand.element {
        ElementSize::Byte => {
            Host::UnpackLowByte.register(code, 0, 0, target);
            Host::UnpackLowWord.register(code, 0, 0, target);
            Host::ShuffleDword.register(code, 0, 0, target);
            code.push(REPEAT_LOW_DWORD);
        }
        ElementSize::Halfword => {
            Host::UnpackLowWord.register(code, 0, 0, target);
            Host::ShuffleDword.register(code, 0, 0, target);
            code.push(REPEAT_LOW_DWORD);
        }
        ElementSize::Word => {
            Host::ShuffleDword.register(code, 0, 0, target);
            code.push(REPEAT_LOW_DWORD);
        }
        ElementSize::Doubleword => Host::UnpackLowQword.register(code, 0, 0, target),
        ElementSize::Quadword => unreachable!("scalar replicate element is at most64 bits"),
    }
    for chunk in 0..length.chunks() {
        scalable::read_predicate_mask(
            code,
            operand.predicate.expect("replicate is predicated"),
            chunk,
            operand.element,
            1,
            2,
            length,
            target,
        );
        Host::MoveAligned.register(code, 3, 0, target);
        Host::And.register(code, 3, 1, target);
        displacement(
            code,
            MOVDQU_RSP_DISP32_XMM3,
            (chunk * VECTOR_CHUNK_BYTES) as u32,
        );
    }
    let end = code.len();
    scalable::memory::patch_branch(code, empty, end);
}

fn commit(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    if operand.kind == Kind::WholePredicate {
        for word in 0..length.predicate_bytes().div_ceil(QWORD_BYTES as usize) {
            displacement(code, MOV_RAX_RSP_DISP32, word as u32 * QWORD_BYTES);
            scalable::write_predicate_chunk(code, operand.data, word, length);
        }
    } else {
        if operand.kind == Kind::ReplicateQuad {
            displacement(code, MOVDQU_XMM0_RSP_DISP32, 0);
        }
        for chunk in 0..length.chunks() {
            if operand.kind != Kind::ReplicateQuad {
                displacement(
                    code,
                    MOVDQU_XMM0_RSP_DISP32,
                    (chunk * VECTOR_CHUNK_BYTES) as u32,
                );
            }
            scalable::store_z_chunk(code, operand.data, chunk, 0, length, target);
        }
    }
}

/// Emit one callback-backed instruction. Failure cleans up before returning
/// through the shared inner-body epilogue; success falls through. Both paths
/// restore the exact private stack allocation.
/// The declared data profile has SCTLR.A=0; original SP alignment remains checked.
pub(crate) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    target: TargetCpu,
    pc: u64,
) {
    let scratch = Scratch::new(length);
    displacement(code, SUB_RSP_IMM32, scratch.bytes);
    scalable::memory::begin(code);
    let zero_chunks = match operand.kind {
        Kind::WholeVector | Kind::WholePredicate => 0,
        Kind::ReplicateQuad => 1,
        Kind::Contiguous | Kind::ReplicateScalar => length.chunks(),
    };
    if zero_chunks != 0 {
        code.extend(PXOR_XMM0_XMM0);
    }
    for chunk in 0..zero_chunks {
        displacement(
            code,
            MOVDQU_RSP_DISP32_XMM0,
            (chunk * VECTOR_CHUNK_BYTES) as u32,
        );
    }
    predicate(code, operand, length, scratch);
    let mut failed = Vec::new();
    if let Some(fault) = super::memory::check_sp(code, operand.address.base, pc) {
        failed.push(fault);
    }
    super::memory::address(code, operand.address, length);
    displacement(code, MOV_RSP_DISP32_RAX, scratch.address);
    match operand.kind {
        Kind::Contiguous | Kind::ReplicateQuad => {
            lanes(code, operand, length, scratch, pc, &mut failed)
        }
        Kind::ReplicateScalar => {
            scalar_replicate(code, operand, length, scratch, pc, &mut failed, target)
        }
        Kind::WholeVector | Kind::WholePredicate => {
            let bytes = if operand.kind == Kind::WholePredicate {
                length.predicate_bytes()
            } else {
                length.bytes()
            };
            for byte in 0..bytes {
                request(code, operand, scratch, byte, byte as u32, pc, &mut failed);
            }
        }
    }
    commit(code, operand, length, target);
    code.extend(XOR_EAX_EAX);
    let cleanup = code.len();
    for failed in failed {
        scalable::memory::patch_branch(code, failed, cleanup);
    }
    displacement(code, ADD_RSP_IMM32, scratch.bytes);
    super::memory::return_if_failed(code);
}

#[cfg(test)]
mod tests;
