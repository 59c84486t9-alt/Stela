//! SVE extraction and broadcast (SSE2) and insertion (SSSE3).
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VECTOR_REGISTER_COUNT, VectorLength},
        sve::rearrange_extract::{Destination, Kind, LastPosition, Operand},
    },
    x86_64::{
        isa::{ShiftOpcode as Shift, SimdOpcode as Host},
        load,
        scalable::{clear_z_upper, load_z_chunk, read_predicate_chunk, store_z_chunk},
        store,
    },
};
use alloc::vec::Vec;

const VALUE_XMM: u8 = 0;
const INSERT_XMM: u8 = 1;
const PREVIOUS_XMM: u8 = 2;
const ZERO_XMM: u8 = 3;
const RAX_REGISTER: u8 = 0;
const LOW_DWORD_CONTROL: u8 = 0;
const PREDICATE_CHUNK_BITS: usize = u64::BITS as usize;
const PREDICATE_CHUNK_BYTES: usize = core::mem::size_of::<u64>();
const STAGING_FRAME_BYTES: u8 = VECTOR_CHUNK_BYTES as u8;
const CHUNK_OFFSET_MASK: u8 = (VECTOR_CHUNK_BYTES - 1) as u8;
const GOVERNING_PREDICATE_COUNT: u8 = 8;
const INDEXED_SOURCE_BYTES: usize = 64;
const JUMP_REL32: u8 = 0xe9;
const JZ_REL32: &[u8] = &[0x0f, 0x84];
const JB_REL32: &[u8] = &[0x0f, 0x82];
const MOV_RAX_SIGNED_IMM32: &[u8] = &[0x48, 0xc7, 0xc0];
const MOV_EAX_IMM32: u8 = 0xb8;
const MOV_RCX_IMM64: &[u8] = &[0x48, 0xb9];
const AND_RAX_RCX: &[u8] = &[0x48, 0x21, 0xc8];
const TEST_RAX_RAX: &[u8] = &[0x48, 0x85, 0xc0];
const BSR_R8_RAX: &[u8] = &[0x4c, 0x0f, 0xbd, 0xc0];
const OR_R8D_IMM32: &[u8] = &[0x41, 0x81, 0xc8];
const ADD_R8D_IMM8: &[u8] = &[0x41, 0x83, 0xc0];
const AND_R8D_IMM32: &[u8] = &[0x41, 0x81, 0xe0];
const AND_R8D_IMM8: &[u8] = &[0x41, 0x83, 0xe0];
const CMP_R8D_IMM32: &[u8] = &[0x41, 0x81, 0xf8];
const MOV_R8D_IMM32: &[u8] = &[0x41, 0xb8];
const XOR_R8D_R8D: &[u8] = &[0x45, 0x31, 0xc0];
const SUB_RSP_IMM8: &[u8] = &[0x48, 0x83, 0xec];
const ADD_RSP_IMM8: &[u8] = &[0x48, 0x83, 0xc4];
const MOVDQU_STACK_XMM0: &[u8] = &[0xf3, 0x0f, 0x7f, 0x04, 0x24];
const MOVZX_EAX_STACK_R8_BYTE: &[u8] = &[0x42, 0x0f, 0xb6, 0x04, 0x04];
const MOVZX_EAX_STACK_R8_WORD: &[u8] = &[0x42, 0x0f, 0xb7, 0x04, 0x04];
const MOV_EAX_STACK_R8: &[u8] = &[0x42, 0x8b, 0x04, 0x04];
const MOV_RAX_STACK_R8: &[u8] = &[0x4a, 0x8b, 0x04, 0x04];
const MOVZX_EAX_AL: &[u8] = &[0x0f, 0xb6, 0xc0];
const MOVZX_EAX_AX: &[u8] = &[0x0f, 0xb7, 0xc0];
const MOV_EAX_EAX: &[u8] = &[0x89, 0xc0];
const NOP: u8 = 0x90;

fn jump(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend_from_slice(opcode);
    let displacement = code.len();
    code.extend(0i32.to_le_bytes());
    displacement
}

fn resolve(code: &mut [u8], displacement: usize, target: usize) {
    let next = displacement + core::mem::size_of::<i32>();
    let offset = i32::try_from(target as i64 - next as i64).expect("bounded extraction body");
    code[displacement..next].copy_from_slice(&offset.to_le_bytes());
}

fn packed(code: &mut Vec<u8>, opcode: Host, destination: u8, source: u8, target: TargetCpu) {
    opcode.register(code, destination, source, target);
}

fn narrow_general(code: &mut Vec<u8>, element: ElementSize) {
    code.extend_from_slice(match element {
        ElementSize::Byte => MOVZX_EAX_AL,
        ElementSize::Halfword => MOVZX_EAX_AX,
        ElementSize::Word => MOV_EAX_EAX,
        ElementSize::Doubleword => &[],
        ElementSize::Quadword => unreachable!("general extraction has at most 64 bits"),
    });
}

fn broadcast(code: &mut Vec<u8>, element: ElementSize, target: TargetCpu) {
    match element {
        ElementSize::Byte => {
            packed(code, Host::UnpackLowByte, VALUE_XMM, VALUE_XMM, target);
            packed(code, Host::UnpackLowWord, VALUE_XMM, VALUE_XMM, target);
        }
        ElementSize::Halfword => {
            packed(code, Host::UnpackLowWord, VALUE_XMM, VALUE_XMM, target);
        }
        ElementSize::Word => {}
        ElementSize::Doubleword => {
            packed(code, Host::UnpackLowQword, VALUE_XMM, VALUE_XMM, target);
            return;
        }
        ElementSize::Quadword => return,
    }
    packed(code, Host::ShuffleDword, VALUE_XMM, VALUE_XMM, target);
    code.push(LOW_DWORD_CONTROL);
}

fn broadcast_last(code: &mut Vec<u8>, element: ElementSize, target: TargetCpu) {
    if element == ElementSize::Byte && target.supports(TargetCpu::Ssse3) {
        packed(code, Host::Xor, ZERO_XMM, ZERO_XMM, target);
        packed(code, Host::ByteShuffle, VALUE_XMM, ZERO_XMM, target);
    } else {
        broadcast(code, element, target);
    }
}

fn store_broadcast(code: &mut Vec<u8>, destination: u8, length: VectorLength, target: TargetCpu) {
    for chunk in 0..length.chunks() {
        store_z_chunk(code, destination, chunk, VALUE_XMM, length, target);
    }
}

fn predicate_start_mask(element: ElementSize) -> u64 {
    let mut mask = 0;
    for bit in (0..PREDICATE_CHUNK_BITS).step_by(element.bytes()) {
        mask |= 1u64 << bit;
    }
    mask
}

fn emit_last(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    let Kind::Last {
        source,
        predicate,
        position,
        conditional,
    } = operand.kind
    else {
        unreachable!("extraction recipe requires LAST operands");
    };
    if operand.destination == Destination::General(Register::Zero) {
        // Shared instruction permission checks still precede this recipe.
        code.push(NOP);
        return;
    }
    let mut found = Vec::new();
    let mut finished = Vec::new();
    let chunks = length.predicate_bytes().div_ceil(PREDICATE_CHUNK_BYTES);
    for chunk in (0..chunks).rev() {
        read_predicate_chunk(code, predicate, chunk, length);
        if operand.element_size != ElementSize::Byte {
            code.extend(MOV_RCX_IMM64);
            code.extend(predicate_start_mask(operand.element_size).to_le_bytes());
            code.extend(AND_RAX_RCX);
        }
        code.extend(TEST_RAX_RAX);
        let empty = jump(code, JZ_REL32);
        code.extend(BSR_R8_RAX);
        if chunk != 0 {
            code.extend(OR_R8D_IMM32);
            code.extend(((chunk * PREDICATE_CHUNK_BITS) as u32).to_le_bytes());
        }
        found.push(jump(code, &[JUMP_REL32]));
        let next = code.len();
        resolve(code, empty, next);
    }
    let mut scalar_fallback = None;
    let mut unconditional_fallback = None;
    if conditional {
        match operand.destination {
            Destination::Vector(_) => finished.push(jump(code, &[JUMP_REL32])),
            Destination::General(destination) => {
                load(code, destination);
                narrow_general(code, operand.element_size);
                store(code, destination);
                finished.push(jump(code, &[JUMP_REL32]));
            }
            Destination::Scalar(destination) => {
                load_z_chunk(code, destination, 0, VALUE_XMM, length, target);
                code.extend(XOR_R8D_R8D);
                scalar_fallback = Some(jump(code, &[JUMP_REL32]));
            }
        }
    } else {
        code.extend(MOV_R8D_IMM32);
        let offset = if position == LastPosition::LastActive {
            length.bytes() - operand.element_size.bytes()
        } else {
            0
        };
        code.extend((offset as u32).to_le_bytes());
        unconditional_fallback = Some(jump(code, &[JUMP_REL32]));
    }
    let active = code.len();
    for branch in found {
        resolve(code, branch, active);
    }
    if position == LastPosition::AfterLastActive {
        code.extend(ADD_R8D_IMM8);
        code.push(operand.element_size.bytes() as u8);
        code.extend(AND_R8D_IMM32);
        code.extend(((length.bytes() - 1) as u32).to_le_bytes());
    }
    let select = code.len();
    if let Some(branch) = unconditional_fallback {
        resolve(code, branch, select);
    }
    let mut loaded = Vec::new();
    for chunk in (1..length.chunks()).rev() {
        code.extend(CMP_R8D_IMM32);
        code.extend(((chunk * VECTOR_CHUNK_BYTES) as u32).to_le_bytes());
        let lower = jump(code, JB_REL32);
        load_z_chunk(code, source, chunk, VALUE_XMM, length, target);
        loaded.push(jump(code, &[JUMP_REL32]));
        let next = code.len();
        resolve(code, lower, next);
    }
    load_z_chunk(code, source, 0, VALUE_XMM, length, target);
    let staging = code.len();
    for branch in loaded.into_iter().chain(scalar_fallback) {
        resolve(code, branch, staging);
    }
    code.extend(AND_R8D_IMM8);
    code.push(CHUNK_OFFSET_MASK);
    // Only the selected 16-byte chunk is staged, in the same bounded frame for
    // every path.
    code.extend(SUB_RSP_IMM8);
    code.push(STAGING_FRAME_BYTES);
    code.extend(MOVDQU_STACK_XMM0);
    code.extend_from_slice(match operand.element_size {
        ElementSize::Byte => MOVZX_EAX_STACK_R8_BYTE,
        ElementSize::Halfword => MOVZX_EAX_STACK_R8_WORD,
        ElementSize::Word => MOV_EAX_STACK_R8,
        ElementSize::Doubleword => MOV_RAX_STACK_R8,
        ElementSize::Quadword => unreachable!("LAST excludes 128-bit elements"),
    });
    code.extend(ADD_RSP_IMM8);
    code.push(STAGING_FRAME_BYTES);
    match operand.destination {
        Destination::General(destination) => store(code, destination),
        Destination::Scalar(destination) => {
            packed(code, Host::MoveGprQword, VALUE_XMM, RAX_REGISTER, target);
            store_z_chunk(code, destination, 0, VALUE_XMM, length, target);
            clear_z_upper(code, destination, ZERO_XMM, length, target);
        }
        Destination::Vector(destination) => {
            packed(code, Host::MoveGprQword, VALUE_XMM, RAX_REGISTER, target);
            broadcast_last(code, operand.element_size, target);
            store_broadcast(code, destination, length, target);
        }
    }
    let end = code.len();
    for branch in finished {
        resolve(code, branch, end);
    }
}

fn emit_insert(
    code: &mut Vec<u8>,
    destination: u8,
    element: ElementSize,
    length: VectorLength,
    target: TargetCpu,
) {
    let width = element.bytes() as u8;
    let carry = VECTOR_CHUNK_BYTES as u8 - width;
    for chunk in (1..length.chunks()).rev() {
        load_z_chunk(code, destination, chunk, VALUE_XMM, length, target);
        load_z_chunk(code, destination, chunk - 1, PREVIOUS_XMM, length, target);
        if target.supports(TargetCpu::Ssse3) {
            packed(code, Host::AlignBytes, VALUE_XMM, PREVIOUS_XMM, target);
            code.push(carry);
        } else {
            Shift::LeftBytes.emit(code, VALUE_XMM, width);
            Shift::RightBytes.emit(code, PREVIOUS_XMM, carry);
            packed(code, Host::Or, VALUE_XMM, PREVIOUS_XMM, target);
        }
        store_z_chunk(code, destination, chunk, VALUE_XMM, length, target);
    }
    load_z_chunk(code, destination, 0, VALUE_XMM, length, target);
    Shift::LeftBytes.emit(code, VALUE_XMM, width);
    packed(code, Host::Or, VALUE_XMM, INSERT_XMM, target);
    store_z_chunk(code, destination, 0, VALUE_XMM, length, target);
}

fn valid(operand: Operand) -> bool {
    let vector = |register| register < VECTOR_REGISTER_COUNT;
    let general =
        |register| !matches!(register, Register::X(index) if index >= VECTOR_REGISTER_COUNT - 1);
    match operand.destination {
        Destination::General(register) if !general(register) || register == Register::Sp => {
            return false;
        }
        Destination::Scalar(register) | Destination::Vector(register) if !vector(register) => {
            return false;
        }
        _ => {}
    }
    if operand.element_size == ElementSize::Quadword
        && !matches!(operand.kind, Kind::DuplicateElement { .. })
    {
        return false;
    }
    match operand.kind {
        Kind::Last {
            source,
            predicate,
            conditional,
            ..
        } => {
            vector(source)
                && predicate < GOVERNING_PREDICATE_COUNT
                && (conditional || !matches!(operand.destination, Destination::Vector(_)))
        }
        Kind::DuplicateImmediate(_) => matches!(operand.destination, Destination::Vector(_)),
        Kind::DuplicateGeneral(register) => {
            general(register)
                && register != Register::Zero
                && matches!(operand.destination, Destination::Vector(_))
        }
        Kind::DuplicateElement { source, index } => {
            vector(source)
                && usize::from(index) < INDEXED_SOURCE_BYTES / operand.element_size.bytes()
                && matches!(operand.destination, Destination::Vector(_))
        }
        Kind::InsertGeneral(register) => {
            general(register)
                && register != Register::Sp
                && matches!(operand.destination, Destination::Vector(_))
        }
        Kind::InsertScalar(source) => {
            vector(source) && matches!(operand.destination, Destination::Vector(_))
        }
    }
}

/// Emit a decoded register-only operation after shared streaming permission checks.
/// Uses caller-saved RAX/RCX/RDX/R8 and XMM0..3, preserving RDI/R15 and MXCSR.
pub fn emit(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    assert!(
        valid(operand),
        "extraction emitter requires validated operands"
    );
    if matches!(operand.kind, Kind::Last { .. }) {
        emit_last(code, operand, length, target);
        return;
    }
    let Destination::Vector(destination) = operand.destination else {
        unreachable!("validated broadcast/insertion destination");
    };
    match operand.kind {
        Kind::DuplicateImmediate(immediate) => {
            if operand.element_size == ElementSize::Doubleword {
                code.extend(MOV_RAX_SIGNED_IMM32);
            } else {
                code.push(MOV_EAX_IMM32);
            }
            code.extend(i32::from(immediate).to_le_bytes());
            packed(code, Host::MoveGprQword, VALUE_XMM, RAX_REGISTER, target);
        }
        Kind::DuplicateGeneral(source) => {
            load(code, source);
            packed(code, Host::MoveGprQword, VALUE_XMM, RAX_REGISTER, target);
        }
        Kind::DuplicateElement { source, index } => {
            let offset = usize::from(index) * operand.element_size.bytes();
            if offset < length.bytes() {
                load_z_chunk(
                    code,
                    source,
                    offset / VECTOR_CHUNK_BYTES,
                    VALUE_XMM,
                    length,
                    target,
                );
                if !offset.is_multiple_of(VECTOR_CHUNK_BYTES) {
                    Shift::RightBytes.emit(code, VALUE_XMM, (offset % VECTOR_CHUNK_BYTES) as u8);
                }
            } else {
                packed(code, Host::Xor, VALUE_XMM, VALUE_XMM, target);
            }
        }
        Kind::InsertGeneral(source) => {
            load(code, source);
            narrow_general(code, operand.element_size);
            packed(code, Host::MoveGprQword, INSERT_XMM, RAX_REGISTER, target);
            emit_insert(code, destination, operand.element_size, length, target);
            return;
        }
        Kind::InsertScalar(source) => {
            load_z_chunk(code, source, 0, INSERT_XMM, length, target);
            let shift = (VECTOR_CHUNK_BYTES - operand.element_size.bytes()) as u8;
            Shift::LeftBytes.emit(code, INSERT_XMM, shift);
            Shift::RightBytes.emit(code, INSERT_XMM, shift);
            emit_insert(code, destination, operand.element_size, length, target);
            return;
        }
        Kind::Last { .. } => unreachable!("extraction handled above"),
    }
    broadcast(code, operand.element_size, target);
    store_broadcast(code, destination, length, target);
}
