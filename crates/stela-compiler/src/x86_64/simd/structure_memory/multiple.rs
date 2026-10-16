//! LD1-4/ST1-4 (multiple structures) within one page.
use super::super::{commit, read_vector};
use crate::TargetCpu;
use crate::aarch64::scalable::ElementSize;
use crate::aarch64::simd::structure_memory::{Direction, Layout, Operand};
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};
use crate::x86_64::scalable::routing;
use alloc::vec::Vec;

const QWORD_BYTES: u8 = 8;
const VECTOR_BYTES: u8 = 16;
const DWORD_BYTES: u8 = 4;
const DWORDS_PER_VECTOR: u8 = VECTOR_BYTES / DWORD_BYTES;
const DWORD_INDEX_BITS: u8 = 2;
const VECTOR_REGISTER_COUNT: u8 = 32;
const THREE_STRUCTURES: u8 = 3;
const RESULT_XMM: u8 = 4;
const PARTIAL_XMM: u8 = 5;
const SCRATCH_XMM: u8 = 6;
const MODRM_REGISTER_SHIFT: u8 = 3;
const MODRM_DISP8: u8 = 0x40;
const MODRM_RIP: u8 = 0x05;
const MOVQ_STORE: &[u8] = &[0x66, 0x0f, 0xd6];
const JMP_REL32: u8 = 0xe9;
const SHUFFLE_ZERO: u8 = 0x80;

/// RAX is the guest address; RDI and the pending writeback in RDX survive.
pub(super) fn packed(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    let Layout::Multiple {
        repetitions,
        structures,
        vector_bytes,
    } = operand.layout
    else {
        unreachable!("multiple-structure child receives its own layout")
    };
    if structures == 1 {
        contiguous(code, operand, repetitions, vector_bytes);
    } else if structures == THREE_STRUCTURES && operand.element_bytes == DWORD_BYTES {
        dword_three(code, operand, vector_bytes);
    } else if structures == THREE_STRUCTURES && operand.element_bytes != QWORD_BYTES {
        if target.supports(TargetCpu::Ssse3) {
            shuffled_interleaved(code, operand, structures, vector_bytes, target);
        } else {
            // SSE2 lacks a byte gather. Preserve the compact source-ordered
            // scalar mapping rather than synthesize many masked shift merges.
            super::ordered_in_granule(code, operand);
        }
    } else if structures == 4
        && vector_bytes == QWORD_BYTES
        && operand.element_bytes < DWORD_BYTES
        && operand.direction == Direction::Load
        && target.supports(TargetCpu::Ssse3)
    {
        shuffled_interleaved(code, operand, structures, vector_bytes, target);
    } else if operand.direction == Direction::Load {
        load_interleaved(code, operand, structures, vector_bytes);
    } else {
        store_interleaved(code, operand, structures, vector_bytes);
    }
}

fn simd(code: &mut Vec<u8>, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn copy(code: &mut Vec<u8>, destination: u8, source: u8) {
    simd(code, Host::MoveAligned, destination, source);
}

fn chunk(code: &mut Vec<u8>, load: bool, bytes: u8, xmm: u8, displacement: u8) {
    match (load, bytes) {
        (true, QWORD_BYTES) => Host::MoveQword.append(code, TargetCpu::Baseline),
        (true, VECTOR_BYTES) => Host::LoadUnaligned.append(code, TargetCpu::Baseline),
        (false, QWORD_BYTES) => code.extend(MOVQ_STORE),
        (false, VECTOR_BYTES) => Host::StoreUnaligned.append(code, TargetCpu::Baseline),
        _ => unreachable!("multiple footprint consists of exact qword/vector chunks"),
    }
    code.push((xmm << MODRM_REGISTER_SHIFT) | if displacement == 0 { 0 } else { MODRM_DISP8 });
    if displacement != 0 {
        code.push(displacement);
    }
}

fn contiguous(code: &mut Vec<u8>, operand: &Operand, repetitions: u8, bytes: u8) {
    for register in 0..repetitions {
        let vector = (operand.first_vector + register) % VECTOR_REGISTER_COUNT;
        let offset = register * bytes;
        if operand.direction == Direction::Load {
            chunk(code, true, bytes, 0, offset);
            commit(code, vector, 0);
        } else {
            read_vector(code, vector, 0);
            chunk(code, false, bytes, 0, offset);
        }
    }
}

/// Gather the low two dwords, repeating that pair in the upper half. Distinct
/// inputs first broadcast their selected lanes, then interleave the low dwords.
fn dword_pair(code: &mut Vec<u8>, destination: u8, first: (u8, u8), second: (u8, u8)) {
    let shuffle = |code: &mut Vec<u8>, destination, source, low, high| {
        simd(code, Host::ShuffleDword, destination, source);
        let control = low
            | high << DWORD_INDEX_BITS
            | low << (2 * DWORD_INDEX_BITS)
            | high << (3 * DWORD_INDEX_BITS);
        code.push(control);
    };
    if first.0 == second.0 {
        shuffle(code, destination, first.0, first.1, second.1);
    } else {
        shuffle(code, destination, first.0, first.1, first.1);
        shuffle(code, SCRATCH_XMM, second.0, second.1, second.1);
        simd(code, Host::UnpackLowDword, destination, SCRATCH_XMM);
    }
}

/// Three-way dword routing uses fewer state/RAM accesses than the scalar stream
/// without SSSE3 masks. Each output combines two independently gathered pairs.
fn dword_three(code: &mut Vec<u8>, operand: &Operand, bytes: u8) {
    let load = operand.direction == Direction::Load;
    let footprint = THREE_STRUCTURES * bytes;
    let memory_chunks = footprint.div_ceil(VECTOR_BYTES);
    let inputs = if load {
        memory_chunks
    } else {
        THREE_STRUCTURES
    };
    for input in 0..inputs {
        if load {
            chunk(
                code,
                true,
                (footprint - input * VECTOR_BYTES).min(VECTOR_BYTES),
                input,
                input * VECTOR_BYTES,
            );
        } else {
            read_vector(
                code,
                (operand.first_vector + input) % VECTOR_REGISTER_COUNT,
                input,
            );
        }
    }
    let outputs = if load {
        THREE_STRUCTURES
    } else {
        memory_chunks
    };
    for output in 0..outputs {
        let output_bytes = if load {
            bytes
        } else {
            (footprint - output * VECTOR_BYTES).min(VECTOR_BYTES)
        };
        let source = |lane| {
            if load {
                let memory_lane = lane * THREE_STRUCTURES + output;
                (
                    memory_lane / DWORDS_PER_VECTOR,
                    memory_lane % DWORDS_PER_VECTOR,
                )
            } else {
                let memory_lane = output * DWORDS_PER_VECTOR + lane;
                (
                    memory_lane % THREE_STRUCTURES,
                    memory_lane / THREE_STRUCTURES,
                )
            }
        };
        dword_pair(code, RESULT_XMM, source(0), source(1));
        if output_bytes == VECTOR_BYTES {
            dword_pair(code, PARTIAL_XMM, source(2), source(3));
            simd(code, Host::UnpackLowQword, RESULT_XMM, PARTIAL_XMM);
        } else if load {
            simd(code, Host::MoveQword, RESULT_XMM, RESULT_XMM);
        }
        if load {
            commit(
                code,
                (operand.first_vector + output) % VECTOR_REGISTER_COUNT,
                RESULT_XMM,
            );
        } else {
            chunk(code, false, output_bytes, RESULT_XMM, output * VECTOR_BYTES);
        }
    }
}

/// Reuse the shared exact-width SSE2 chunk network, preserving the established
/// multiple-structure operand API and complete baseline recipe.
fn split(code: &mut Vec<u8>, first: u8, second: u8, even: u8, odd: u8, bytes: u8) {
    routing::split(
        code,
        first,
        second,
        even,
        odd,
        ElementSize::from_bytes(usize::from(bytes)).unwrap(),
        TargetCpu::Baseline,
    );
}

fn load_interleaved(code: &mut Vec<u8>, operand: &Operand, structures: u8, bytes: u8) {
    let chunks = structures * bytes / VECTOR_BYTES;
    for source in 0..chunks {
        chunk(code, true, VECTOR_BYTES, source, source * VECTOR_BYTES);
    }
    let outputs = if structures == THREE_STRUCTURES {
        // Three .2D structures: [A0 B0] [C0 A1] [B1 C1].
        copy(code, 4, 0);
        copy(code, 5, 1);
        Shift::RightBytes.emit(code, 5, QWORD_BYTES);
        simd(code, Host::UnpackLowQword, 4, 5);
        copy(code, 5, 0);
        Shift::RightBytes.emit(code, 5, QWORD_BYTES);
        simd(code, Host::UnpackLowQword, 5, 2);
        Shift::RightBytes.emit(code, 2, QWORD_BYTES);
        simd(code, Host::UnpackLowQword, 1, 2);
        [4, 5, 1, 0]
    } else if structures == 2 {
        if chunks == 1 {
            simd(code, Host::Xor, 1, 1);
        }
        split(code, 0, 1, 4, 5, operand.element_bytes);
        [4, 5, 0, 0]
    } else {
        split(code, 0, 1, 4, 5, operand.element_bytes);
        if bytes == QWORD_BYTES {
            simd(code, Host::Xor, 0, 0);
            simd(code, Host::Xor, 1, 1);
        } else {
            split(code, 2, 3, 0, 1, operand.element_bytes);
        }
        split(code, 4, 0, 2, 3, operand.element_bytes);
        split(code, 5, 1, 4, 0, operand.element_bytes);
        [2, 4, 3, 0]
    };
    for vector in 0..structures {
        commit(
            code,
            (operand.first_vector + vector) % VECTOR_REGISTER_COUNT,
            outputs[usize::from(vector)],
        );
    }
}

fn merge(code: &mut Vec<u8>, first: u8, second: u8, low: u8, high: u8, bytes: u8) {
    routing::merge(
        code,
        first,
        second,
        low,
        high,
        ElementSize::from_bytes(usize::from(bytes)).unwrap(),
        TargetCpu::Baseline,
    );
}

fn store_interleaved(code: &mut Vec<u8>, operand: &Operand, structures: u8, bytes: u8) {
    for source in 0..structures {
        read_vector(
            code,
            (operand.first_vector + source) % VECTOR_REGISTER_COUNT,
            source,
        );
    }
    let outputs = if structures == THREE_STRUCTURES {
        // Reverse the three-qword load permutation without scalar extraction.
        copy(code, 4, 0);
        simd(code, Host::UnpackLowQword, 4, 1);
        copy(code, 5, 0);
        Shift::RightBytes.emit(code, 5, QWORD_BYTES);
        copy(code, 6, 2);
        simd(code, Host::UnpackLowQword, 6, 5);
        simd(code, Host::UnpackHighQword, 1, 2);
        [4, 6, 1, 0]
    } else if structures == 2 {
        merge(code, 0, 1, 4, 5, operand.element_bytes);
        [4, 5, 0, 0]
    } else {
        merge(code, 0, 2, 4, 5, operand.element_bytes);
        merge(code, 1, 3, 0, 2, operand.element_bytes);
        merge(code, 4, 0, 1, 3, operand.element_bytes);
        if bytes == VECTOR_BYTES {
            merge(code, 5, 2, 4, 0, operand.element_bytes);
        }
        [1, 3, 4, 0]
    };
    for output in 0..structures * bytes / VECTOR_BYTES {
        chunk(
            code,
            false,
            VECTOR_BYTES,
            outputs[usize::from(output)],
            output * VECTOR_BYTES,
        );
    }
}

/// PSHUFB routes three-way byte/halfword transfers and Q0 four-way loads from
/// exact chunks. Embedded masks use MOVDQU: legacy PSHUFB memory operands would
/// impose unwanted alignment. Three-way Q0 transfers have an exact 8-byte tail.
fn shuffled_interleaved(
    code: &mut Vec<u8>,
    operand: &Operand,
    structures: u8,
    bytes: u8,
    target: TargetCpu,
) {
    let load = operand.direction == Direction::Load;
    let footprint = structures * bytes;
    let memory_chunks = footprint.div_ceil(VECTOR_BYTES);
    let inputs = if load { memory_chunks } else { structures };
    for input in 0..inputs {
        if load {
            chunk(
                code,
                true,
                (footprint - input * VECTOR_BYTES).min(VECTOR_BYTES),
                input,
                input * VECTOR_BYTES,
            );
        } else {
            read_vector(
                code,
                (operand.first_vector + input) % VECTOR_REGISTER_COUNT,
                input,
            );
        }
    }
    let outputs = if load { structures } else { memory_chunks };
    let mut masks = Vec::<([u8; 16], usize)>::new();
    for output in 0..outputs {
        let output_bytes = if load {
            bytes
        } else {
            (footprint - output * VECTOR_BYTES).min(VECTOR_BYTES)
        };
        let mut first = true;
        for input in 0..inputs {
            let mut mask = [SHUFFLE_ZERO; 16];
            for byte in 0..output_bytes {
                let element_bytes = operand.element_bytes;
                let (source, source_byte) = if load {
                    let memory_byte = (byte / element_bytes * structures + output) * element_bytes
                        + byte % element_bytes;
                    (memory_byte / VECTOR_BYTES, memory_byte % VECTOR_BYTES)
                } else {
                    let memory_byte = output * VECTOR_BYTES + byte;
                    let element = memory_byte / element_bytes;
                    (
                        element % structures,
                        element / structures * element_bytes + memory_byte % element_bytes,
                    )
                };
                if source == input {
                    mask[usize::from(byte)] = source_byte;
                }
            }
            if mask == [SHUFFLE_ZERO; 16] {
                continue;
            }
            let destination = if first { RESULT_XMM } else { PARTIAL_XMM };
            copy(code, destination, input);
            Host::LoadUnaligned.append(code, TargetCpu::Baseline);
            code.push((SCRATCH_XMM << MODRM_REGISTER_SHIFT) | MODRM_RIP);
            let displacement = code.len();
            code.extend(0i32.to_le_bytes());
            masks.push((mask, displacement));
            Host::ByteShuffle.register(code, destination, SCRATCH_XMM, target);
            if !first {
                simd(code, Host::Or, RESULT_XMM, PARTIAL_XMM);
            }
            first = false;
        }
        if load {
            commit(
                code,
                (operand.first_vector + output) % VECTOR_REGISTER_COUNT,
                RESULT_XMM,
            );
        } else {
            chunk(code, false, output_bytes, RESULT_XMM, output * VECTOR_BYTES);
        }
    }
    // Every mask is exactly sixteen bytes. One unconditional branch skips the
    // trailing mask pool, and each RIP-relative load targets its own mask.
    code.push(JMP_REL32);
    let done = code.len();
    code.extend(0i32.to_le_bytes());
    for (mask, displacement) in masks {
        let target = code.len();
        patch_relative(code, displacement, target);
        code.extend(mask);
    }
    let target = code.len();
    patch_relative(code, done, target);
}

fn patch_relative(code: &mut [u8], displacement: usize, target: usize) {
    let relative =
        i32::try_from(target - displacement - size_of::<i32>()).expect("bounded shuffle pool");
    code[displacement..displacement + size_of::<i32>()].copy_from_slice(&relative.to_le_bytes());
}
