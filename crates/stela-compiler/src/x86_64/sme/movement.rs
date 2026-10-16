//! ZA moves and zeroing. R8 holds the selected ZA address across helper calls,
//! which clobber only RAX/RCX/RDX.

use super::super::{
    isa::{ShiftOpcode, SimdOpcode as Host},
    scalable::{load_z_chunk, read_predicate_mask, store_z_chunk},
    scalable_matrix::{load_za_chunk_at_r8, load_za_pointer_r8, store_za_chunk_at_r8},
};
use crate::{
    GuestState, TargetCpu,
    aarch64::{
        scalable::{ElementSize, Predication, VECTOR_CHUNK_BYTES, VectorLength},
        sme::movement::{Direction, Kind, Operand},
    },
    context::{EXECUTION_CONTEXT_SCALABLE_OFFSET, SCALABLE_ZT0_OFFSET},
};
use alloc::vec::Vec;

const VALUE: u8 = 0;
const PREVIOUS: u8 = 1;
const GATHER_SCRATCH: u8 = 2;
const GATHER_HIGH: u8 = 3;
const MASK: u8 = 4;
const MASK_SCRATCH: u8 = 5;
const ZERO: u8 = 6;
const MODRM_DISP32_R8: u8 = 0x80;
const MODRM_REGISTER: u8 = 0xc0;
const REGISTER_SHIFT: u8 = 3;
const PREFIX_WORD: u8 = 0x66;
const PREFIX_REP: u8 = 0xf3;
const REX_R8_BASE: u8 = 0x41;
const GPR_BYTES: usize = core::mem::size_of::<u64>();
const D_TILE_COUNT: usize = 8;
const ZT0_BYTES: usize = 64;
const MOV_R8_CONTEXT_DISP8: &[u8] = &[0x4d, 0x8b, 0x47];
const MOV_R8_R8_DISP8: &[u8] = &[0x4d, 0x8b, 0x40];
const MOV_EAX_STATE_DISP32: &[u8] = &[0x8b, 0x87];
const ADD_EAX_IMM32: &[u8] = &[0x05];
const AND_EAX_IMM32: &[u8] = &[0x25];
const SHL_EAX_IMM8: &[u8] = &[0xc1, 0xe0];
const ADD_R8_RAX: &[u8] = &[0x49, 0x01, 0xc0];
const ADD_R8_IMM32: &[u8] = &[0x49, 0x81, 0xc0];
const MOV_ECX_IMM32: &[u8] = &[0xb9];
const DEC_ECX: &[u8] = &[0xff, 0xc9];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];
const MOVZX_EAX_BYTE_R8_DISP32: &[u8] = &[0x41, 0x0f, 0xb6, 0x80];
const MOVZX_ECX_BYTE_R8_DISP32: &[u8] = &[0x41, 0x0f, 0xb6, 0x88];
const SHL_ECX_BYTE: &[u8] = &[0xc1, 0xe1, 8];
const OR_EAX_ECX: &[u8] = &[0x09, 0xc8];
const PINSRW_XMM_EAX: &[u8] = &[0x66, 0x0f, 0xc4];
const PINSRW_XMM_R8: &[u8] = &[0x66, 0x41, 0x0f, 0xc4];
const MOVD_XMM_R8: &[u8] = &[0x66, 0x41, 0x0f, 0x6e];
const MOVHPS_XMM_R8: &[u8] = &[0x41, 0x0f, 0x16];
const PEXTRW_EAX_XMM: &[u8] = &[0x66, 0x0f, 0xc5];
const MOVD_EAX_XMM: &[u8] = &[0x66, 0x0f, 0x7e];
const MOVQ_RAX_XMM: &[u8] = &[0x66, 0x48, 0x0f, 0x7e];
const SHR_EAX_BYTE: &[u8] = &[0xc1, 0xe8, 8];
const PEXTRQ_R8_XMM: &[u8] = &[0x66, 0x49, 0x0f, 0x3a, 0x16];
const MOV_BYTE_R8_AL: &[u8] = &[0x41, 0x88, 0x80];
const MOV_WORD_R8_AX: &[u8] = &[0x66, 0x41, 0x89, 0x80];
const MOV_DWORD_R8_EAX: &[u8] = &[0x41, 0x89, 0x80];
const MOV_QWORD_R8_RAX: &[u8] = &[0x49, 0x89, 0x80];

pub(crate) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
) -> Result<(), &'static str> {
    if length.bits() < usize::from(operand.requirements.minimum_current_svl_bits) {
        return Err("SME movement requires a larger current streaming vector length");
    }
    if matches!(operand.kind, Kind::TableGpr { .. }) {
        return Err("MOVT GPR/ZT0 requires a halted debug execution context");
    }
    match operand.kind {
        Kind::Tile {
            direction,
            element,
            tile,
            vertical,
            index,
            offset,
            vector,
            count,
            predication,
            zero_source,
        } => {
            load_za_pointer_r8(code);
            let dimension = length.lanes(element);
            index_offset(code, index, offset, usize::from(count), dimension);
            let index_scale = if vertical {
                element.bytes()
            } else {
                element.bytes() * length.bytes()
            };
            scale_index(code, index_scale);
            add_address(code, usize::from(tile) * length.bytes());
            code.extend(ADD_R8_RAX);
            for register in 0..count {
                for chunk in 0..length.chunks() {
                    if direction == Direction::ToZa {
                        load_z_chunk(code, vector + register, chunk, VALUE, length, target);
                    } else {
                        load_slice(code, VALUE, chunk, element, vertical, length, target);
                    }
                    if let Predication::Merging(predicate) = predication {
                        if direction == Direction::ToZa {
                            load_slice(code, PREVIOUS, chunk, element, vertical, length, target);
                        } else {
                            load_z_chunk(code, vector + register, chunk, PREVIOUS, length, target);
                        }
                        read_predicate_mask(
                            code,
                            predicate,
                            chunk,
                            element,
                            MASK,
                            MASK_SCRATCH,
                            length,
                            target,
                        );
                        Host::And.register(code, VALUE, MASK, target);
                        Host::AndNot.register(code, MASK, PREVIOUS, target);
                        Host::Or.register(code, VALUE, MASK, target);
                    }
                    if direction == Direction::ToZa {
                        store_slice(code, VALUE, chunk, element, vertical, length, target);
                    } else {
                        store_z_chunk(code, vector + register, chunk, VALUE, length, target);
                        if zero_source {
                            Host::Xor.register(code, ZERO, ZERO, target);
                            store_slice(code, ZERO, chunk, element, vertical, length, target);
                        }
                    }
                }
                if register + 1 < count {
                    add_address(code, index_scale);
                }
            }
        }
        Kind::Vectors {
            direction,
            index,
            offset,
            vector,
            count,
            zero_source,
        } => {
            load_za_pointer_r8(code);
            let stride = length.bytes() / usize::from(count);
            index_offset(code, index, offset, 1, stride);
            scale_index(code, length.bytes());
            code.extend(ADD_R8_RAX);
            for register in 0..count {
                for chunk in 0..length.chunks() {
                    if direction == Direction::ToZa {
                        load_z_chunk(code, vector + register, chunk, VALUE, length, target);
                        contiguous(
                            code,
                            Host::StoreUnaligned,
                            VALUE,
                            chunk * VECTOR_CHUNK_BYTES,
                        );
                    } else {
                        contiguous(code, Host::LoadUnaligned, VALUE, chunk * VECTOR_CHUNK_BYTES);
                        store_z_chunk(code, vector + register, chunk, VALUE, length, target);
                        if zero_source {
                            Host::Xor.register(code, ZERO, ZERO, target);
                            contiguous(
                                code,
                                Host::StoreUnaligned,
                                ZERO,
                                chunk * VECTOR_CHUNK_BYTES,
                            );
                        }
                    }
                }
                if register + 1 < count {
                    add_address(code, stride * length.bytes());
                }
            }
        }
        Kind::ZeroVectors {
            index,
            offset,
            vectors_per_group,
            groups,
        } => {
            load_za_pointer_r8(code);
            let stride = length.bytes() / usize::from(groups);
            index_offset(code, index, offset, 1, stride);
            code.extend(AND_EAX_IMM32);
            code.extend((!u32::from(vectors_per_group - 1)).to_le_bytes());
            scale_index(code, length.bytes());
            code.extend(ADD_R8_RAX);
            Host::Xor.register(code, ZERO, ZERO, target);
            for group in 0..groups {
                for chunk in 0..length.chunks() * usize::from(vectors_per_group) {
                    contiguous(code, Host::StoreUnaligned, ZERO, chunk * VECTOR_CHUNK_BYTES);
                }
                if group + 1 < groups {
                    add_address(code, stride * length.bytes());
                }
            }
        }
        Kind::ZeroTiles { mask } => {
            if mask == 0 {
                return Ok(());
            }
            Host::Xor.register(code, ZERO, ZERO, target);
            if mask == u8::MAX {
                load_za_pointer_r8(code);
                zero_rows(code, length.bytes(), length.bytes(), length, ZERO);
            } else {
                for tile in 0..D_TILE_COUNT {
                    if mask & (1 << tile) == 0 {
                        continue;
                    }
                    load_za_pointer_r8(code);
                    add_address(code, tile * length.bytes());
                    zero_rows(
                        code,
                        length.bytes() / D_TILE_COUNT,
                        length.bytes() * D_TILE_COUNT,
                        length,
                        ZERO,
                    );
                }
            }
        }
        Kind::ZeroTable => {
            pointer(code, SCALABLE_ZT0_OFFSET);
            Host::Xor.register(code, ZERO, ZERO, target);
            for chunk in 0..ZT0_BYTES / VECTOR_CHUNK_BYTES {
                contiguous(code, Host::StoreUnaligned, ZERO, chunk * VECTOR_CHUNK_BYTES);
            }
        }
        Kind::TableGpr { .. } => unreachable!("debug MOVT rejected before output"),
    }
    Ok(())
}

/// Only the separate halted-ITR compiler entry calls this mapping. The normal
/// movement emitter above retains its explicit TableGpr rejection unchanged.
pub(crate) fn emit_debug_table_gpr(
    code: &mut Vec<u8>,
    operand: &Operand,
    recipe: crate::extended::debug_movement::Recipe,
) -> Result<(), &'static str> {
    use crate::extended::debug_movement::Recipe;
    const ZERO_REGISTER: u8 = 31;
    const TABLE_LANES: u8 = 8;
    const MOV_RAX_STATE_DISP32: &[u8] = &[0x48, 0x8b, 0x87];
    const MOV_STATE_DISP32_RAX: &[u8] = &[0x48, 0x89, 0x87];
    const MOV_RAX_R8_DISP8: &[u8] = &[0x49, 0x8b, 0x40];
    const MOV_R8_DISP8_RAX: &[u8] = &[0x49, 0x89, 0x40];
    const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
    const MOVQ_XMM0_STATE_DISP32: &[u8] = &[0xf3, 0x0f, 0x7e, 0x87];
    const MOVQ_STATE_DISP32_XMM0: &[u8] = &[0x66, 0x0f, 0xd6, 0x87];
    const MOVQ_XMM0_R8_DISP8: &[u8] = &[0xf3, 0x41, 0x0f, 0x7e, 0x40];
    const MOVQ_R8_DISP8_XMM0: &[u8] = &[0x66, 0x41, 0x0f, 0xd6, 0x40];
    const PXOR_XMM0_XMM0: &[u8] = &[0x66, 0x0f, 0xef, 0xc0];
    let Kind::TableGpr {
        direction,
        register,
        lane,
    } = operand.kind
    else {
        return Err("halted MOVT emitter requires TableGpr operands");
    };
    if register > ZERO_REGISTER || lane >= TABLE_LANES {
        return Err("invalid halted MOVT operands");
    }
    if direction == Direction::FromZa && register == ZERO_REGISTER {
        return Ok(());
    }
    pointer(code, SCALABLE_ZT0_OFFSET);
    let state_offset =
        (core::mem::offset_of!(GuestState, x) + usize::from(register) * GPR_BYTES) as u32;
    let lane_offset = lane * GPR_BYTES as u8;
    match (direction, recipe) {
        (Direction::ToZa, Recipe::Scalar) => {
            if register == ZERO_REGISTER {
                code.extend(XOR_EAX_EAX);
            } else {
                code.extend(MOV_RAX_STATE_DISP32);
                code.extend(state_offset.to_le_bytes());
            }
            code.extend(MOV_R8_DISP8_RAX);
            code.push(lane_offset);
        }
        (Direction::FromZa, Recipe::Scalar) => {
            code.extend(MOV_RAX_R8_DISP8);
            code.push(lane_offset);
            code.extend(MOV_STATE_DISP32_RAX);
            code.extend(state_offset.to_le_bytes());
        }
        (Direction::ToZa, Recipe::Sse2Comparison) => {
            if register == ZERO_REGISTER {
                code.extend(PXOR_XMM0_XMM0);
            } else {
                code.extend(MOVQ_XMM0_STATE_DISP32);
                code.extend(state_offset.to_le_bytes());
            }
            code.extend(MOVQ_R8_DISP8_XMM0);
            code.push(lane_offset);
        }
        (Direction::FromZa, Recipe::Sse2Comparison) => {
            code.extend(MOVQ_XMM0_R8_DISP8);
            code.push(lane_offset);
            code.extend(MOVQ_STATE_DISP32_XMM0);
            code.extend(state_offset.to_le_bytes());
        }
    }
    Ok(())
}

fn pointer(code: &mut Vec<u8>, field: u32) {
    code.extend(MOV_R8_CONTEXT_DISP8);
    code.push(EXECUTION_CONTEXT_SCALABLE_OFFSET as u8);
    code.extend(MOV_R8_R8_DISP8);
    code.push(field as u8);
}

fn index_offset(code: &mut Vec<u8>, register: u8, offset: u8, align: usize, modulus: usize) {
    code.extend(MOV_EAX_STATE_DISP32);
    code.extend(
        (core::mem::offset_of!(GuestState, x) as u32 + u32::from(register) * GPR_BYTES as u32)
            .to_le_bytes(),
    );
    if align > 1 {
        code.extend(AND_EAX_IMM32);
        code.extend((!(align as u32 - 1)).to_le_bytes());
    }
    if offset != 0 {
        code.extend(ADD_EAX_IMM32);
        code.extend(u32::from(offset).to_le_bytes());
    }
    // All supported SME lengths and all divisors here are powers of two. A
    // wrapped 32-bit addition therefore has the same residue as UInt(W)+offset.
    code.extend(AND_EAX_IMM32);
    code.extend((modulus as u32 - 1).to_le_bytes());
}

fn scale_index(code: &mut Vec<u8>, scale: usize) {
    debug_assert!(scale.is_power_of_two());
    if scale > 1 {
        code.extend(SHL_EAX_IMM8);
        code.push(scale.trailing_zeros() as u8);
    }
}

fn add_address(code: &mut Vec<u8>, displacement: usize) {
    if displacement != 0 {
        code.extend(ADD_R8_IMM32);
        code.extend((displacement as u32).to_le_bytes());
    }
}

fn contiguous(code: &mut Vec<u8>, opcode: Host, xmm: u8, displacement: usize) {
    match opcode {
        Host::LoadUnaligned => {
            load_za_chunk_at_r8(code, xmm, displacement as u32, TargetCpu::Baseline);
            return;
        }
        Host::StoreUnaligned => {
            store_za_chunk_at_r8(code, xmm, displacement as u32, TargetCpu::Baseline);
            return;
        }
        Host::MoveQword => {}
        _ => unreachable!("movement memory uses MOVDQU or MOVQ only"),
    }

    let bytes = opcode.encoding();
    debug_assert!(matches!(bytes[0], PREFIX_WORD | PREFIX_REP));
    code.push(bytes[0]);
    code.push(REX_R8_BASE);
    code.extend(&bytes[1..]);
    code.push(MODRM_DISP32_R8 | (xmm << REGISTER_SHIFT));
    code.extend((displacement as u32).to_le_bytes());
}

fn memory(code: &mut Vec<u8>, opcode: &[u8], displacement: usize) {
    code.extend(opcode);
    code.extend((displacement as u32).to_le_bytes());
}

fn simd_memory(code: &mut Vec<u8>, opcode: &[u8], xmm: u8, displacement: usize) {
    code.extend(opcode);
    code.push(MODRM_DISP32_R8 | (xmm << REGISTER_SHIFT));
    code.extend((displacement as u32).to_le_bytes());
}

fn load_slice(
    code: &mut Vec<u8>,
    output: u8,
    chunk: usize,
    element: ElementSize,
    vertical: bool,
    length: VectorLength,
    target: TargetCpu,
) {
    if !vertical || element == ElementSize::Quadword {
        let offset = if vertical {
            chunk * element.bytes() * length.bytes()
        } else {
            chunk * VECTOR_CHUNK_BYTES
        };
        contiguous(code, Host::LoadUnaligned, output, offset);
        return;
    }
    let size = element.bytes();
    let first = chunk * VECTOR_CHUNK_BYTES / size;
    let address = |lane| (first + lane) * size * length.bytes();
    match element {
        ElementSize::Byte => {
            for pair in 0..VECTOR_CHUNK_BYTES / 2 {
                memory(code, MOVZX_EAX_BYTE_R8_DISP32, address(pair * 2));
                memory(code, MOVZX_ECX_BYTE_R8_DISP32, address(pair * 2 + 1));
                code.extend(SHL_ECX_BYTE);
                code.extend(OR_EAX_ECX);
                code.extend(PINSRW_XMM_EAX);
                code.push(MODRM_REGISTER | (output << REGISTER_SHIFT));
                code.push(pair as u8);
            }
        }
        ElementSize::Halfword => {
            for lane in 0..VECTOR_CHUNK_BYTES / size {
                simd_memory(code, PINSRW_XMM_R8, output, address(lane));
                code.push(lane as u8);
            }
        }
        ElementSize::Word => {
            simd_memory(code, MOVD_XMM_R8, output, address(0));
            simd_memory(code, MOVD_XMM_R8, GATHER_SCRATCH, address(1));
            Host::UnpackLowDword.register(code, output, GATHER_SCRATCH, target);
            simd_memory(code, MOVD_XMM_R8, GATHER_SCRATCH, address(2));
            simd_memory(code, MOVD_XMM_R8, GATHER_HIGH, address(3));
            Host::UnpackLowDword.register(code, GATHER_SCRATCH, GATHER_HIGH, target);
            Host::UnpackLowQword.register(code, output, GATHER_SCRATCH, target);
        }
        ElementSize::Doubleword => {
            contiguous(code, Host::MoveQword, output, address(0));
            simd_memory(code, MOVHPS_XMM_R8, output, address(1));
        }
        ElementSize::Quadword => unreachable!("contiguous quadword handled above"),
    }
}

fn store_slice(
    code: &mut Vec<u8>,
    input: u8,
    chunk: usize,
    element: ElementSize,
    vertical: bool,
    length: VectorLength,
    target: TargetCpu,
) {
    if !vertical || element == ElementSize::Quadword {
        let offset = if vertical {
            chunk * element.bytes() * length.bytes()
        } else {
            chunk * VECTOR_CHUNK_BYTES
        };
        contiguous(code, Host::StoreUnaligned, input, offset);
        return;
    }
    let size = element.bytes();
    let first = chunk * VECTOR_CHUNK_BYTES / size;
    let address = |lane| (first + lane) * size * length.bytes();
    if element == ElementSize::Doubleword && target.supports(TargetCpu::Sse41) {
        for lane in 0..VECTOR_CHUNK_BYTES / size {
            simd_memory(code, PEXTRQ_R8_XMM, input, address(lane));
            code.push(lane as u8);
        }
        return;
    }
    match element {
        ElementSize::Byte | ElementSize::Halfword => {
            for pair in 0..VECTOR_CHUNK_BYTES / 2 {
                code.extend(PEXTRW_EAX_XMM);
                code.push(MODRM_REGISTER | input);
                code.push(pair as u8);
                if element == ElementSize::Byte {
                    memory(code, MOV_BYTE_R8_AL, address(pair * 2));
                    code.extend(SHR_EAX_BYTE);
                    memory(code, MOV_BYTE_R8_AL, address(pair * 2 + 1));
                } else {
                    memory(code, MOV_WORD_R8_AX, address(pair));
                }
            }
        }
        ElementSize::Word | ElementSize::Doubleword => {
            for lane in 0..VECTOR_CHUNK_BYTES / size {
                code.extend(if element == ElementSize::Word {
                    MOVD_EAX_XMM
                } else {
                    MOVQ_RAX_XMM
                });
                code.push(MODRM_REGISTER | (input << REGISTER_SHIFT));
                memory(
                    code,
                    if element == ElementSize::Word {
                        MOV_DWORD_R8_EAX
                    } else {
                        MOV_QWORD_R8_RAX
                    },
                    address(lane),
                );
                if lane + 1 < VECTOR_CHUNK_BYTES / size {
                    ShiftOpcode::RightBytes.emit(code, input, size as u8);
                }
            }
        }
        ElementSize::Quadword => unreachable!("contiguous quadword handled above"),
    }
}

fn zero_rows(code: &mut Vec<u8>, count: usize, step: usize, length: VectorLength, zero: u8) {
    code.extend(MOV_ECX_IMM32);
    code.extend((count as u32).to_le_bytes());
    let start = code.len();
    for chunk in 0..length.chunks() {
        contiguous(code, Host::StoreUnaligned, zero, chunk * VECTOR_CHUNK_BYTES);
    }
    add_address(code, step);
    code.extend(DEC_ECX);
    code.extend(JNZ_REL32);
    let relative = start as i64 - (code.len() as i64 + core::mem::size_of::<i32>() as i64);
    code.extend((relative as i32).to_le_bytes());
}

#[cfg(test)]
mod tests;
