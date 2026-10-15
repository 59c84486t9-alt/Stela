//! SME2 register-group routing specialized to the cache-bound streaming length.
//!
//! Whole-source staging preserves aliases across 128-bit chunks. The bounded
//! private stack frame contains no guest RAM and is restored on the single exit.

use crate::TargetCpu;
use crate::aarch64::scalable::{ElementSize, MAX_VECTOR_BYTES, VECTOR_CHUNK_BYTES, VectorLength};
use crate::aarch64::sme::tables::{Kind, Operand, PermuteSources};
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};
use crate::x86_64::scalable::{load_z_chunk, read_predicate_chunk, routing, store_z_chunk};
use crate::x86_64::sve::predicate::{emit_prepared_counter_mask, prepare_counter};

mod lookup;

const MAX_SOURCE_REGISTERS: usize = 4;
const MAX_PRIVATE_FRAME_BYTES: usize = MAX_SOURCE_REGISTERS * MAX_VECTOR_BYTES;
const MODRM_STACK_DISP32: u8 = 0x84;
const SIB_STACK: u8 = 0x24;
const MODRM_REGISTER_SHIFT: u8 = 3;
const SUB_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xec];
const ADD_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xc4];

fn stack_chunk(code: &mut Vec<u8>, load: bool, offset: usize, xmm: u8, target: TargetCpu) {
    if load {
        Host::LoadUnaligned
    } else {
        Host::StoreUnaligned
    }
    .append(code, target);
    code.extend([
        MODRM_STACK_DISP32 | (xmm << MODRM_REGISTER_SHIFT),
        SIB_STACK,
    ]);
    code.extend((offset as u32).to_le_bytes());
}

fn allocate_frame(code: &mut Vec<u8>, bytes: usize) {
    assert!(bytes <= MAX_PRIVATE_FRAME_BYTES && bytes.is_multiple_of(VECTOR_CHUNK_BYTES));
    code.extend(SUB_RSP_IMM32);
    code.extend((bytes as u32).to_le_bytes());
}

fn release_frame(code: &mut Vec<u8>, bytes: usize) {
    code.extend(ADD_RSP_IMM32);
    code.extend((bytes as u32).to_le_bytes());
}

fn stage(code: &mut Vec<u8>, sources: &[u8], length: VectorLength, target: TargetCpu) {
    assert!(sources.len() <= MAX_SOURCE_REGISTERS);
    for (source_index, register) in sources.iter().enumerate() {
        for chunk in 0..length.chunks() {
            load_z_chunk(code, *register, chunk, 0, length, target);
            stack_chunk(
                code,
                false,
                source_index * length.bytes() + chunk * VECTOR_CHUNK_BYTES,
                0,
                target,
            );
        }
    }
}

fn commit_global_chunk(
    code: &mut Vec<u8>,
    operand: &Operand,
    global_chunk: usize,
    xmm: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    let register = operand
        .destination
        .register((global_chunk / length.chunks()) as u8);
    store_z_chunk(
        code,
        register,
        global_chunk % length.chunks(),
        xmm,
        length,
        target,
    );
}

fn load_source_chunk(
    code: &mut Vec<u8>,
    registers: &[u8],
    source_chunk: usize,
    xmm: u8,
    staged: bool,
    length: VectorLength,
    target: TargetCpu,
) {
    if staged {
        stack_chunk(code, true, source_chunk * VECTOR_CHUNK_BYTES, xmm, target);
    } else {
        load_z_chunk(
            code,
            registers[source_chunk / length.chunks()],
            source_chunk % length.chunks(),
            xmm,
            length,
            target,
        );
    }
}

fn permutation(
    code: &mut Vec<u8>,
    operand: &Operand,
    sources: PermuteSources,
    unzip: bool,
    length: VectorLength,
    target: TargetCpu,
) {
    let mut registers = [0; MAX_SOURCE_REGISTERS];
    let count = usize::from(operand.destination.count);
    match sources {
        PermuteSources::Pair { left, right } => registers[..count].copy_from_slice(&[left, right]),
        PermuteSources::Quad { first } => {
            for (index, register) in registers.iter_mut().enumerate() {
                *register = first + index as u8;
            }
        }
    }
    let frame_bytes = count * length.bytes();
    let overlaps = (0..count)
        .any(|index| registers[..count].contains(&operand.destination.register(index as u8)));
    let staged = length.chunks() != 1 && overlaps;
    if staged {
        allocate_frame(code, frame_bytes);
        stage(code, &registers[..count], length, target);
    }
    let shuffled = unzip
        && count == MAX_SOURCE_REGISTERS
        && matches!(operand.element, ElementSize::Byte | ElementSize::Halfword)
        && target.supports(TargetCpu::Ssse3);
    if shuffled {
        routing::prepare_split_masks(code, operand.element, target);
    }
    let split = |code: &mut Vec<u8>, first, second, even, odd| {
        if shuffled {
            routing::split_destructive(code, first, second, even, odd, target);
        } else {
            routing::split(code, first, second, even, odd, operand.element, target);
        }
    };
    if operand.element == ElementSize::Quadword {
        for source_chunk in 0..count * length.chunks() {
            load_source_chunk(
                code,
                &registers[..count],
                source_chunk,
                0,
                staged,
                length,
                target,
            );
            let output_chunk = if unzip {
                (source_chunk % count) * length.chunks() + source_chunk / count
            } else {
                (source_chunk % length.chunks()) * count + source_chunk / length.chunks()
            };
            commit_global_chunk(code, operand, output_chunk, 0, length, target);
        }
    } else {
        for chunk in 0..length.chunks() {
            for input in 0..count {
                let source_chunk = if unzip {
                    chunk * count + input
                } else {
                    input * length.chunks() + chunk
                };
                load_source_chunk(
                    code,
                    &registers[..count],
                    source_chunk,
                    input as u8,
                    staged,
                    length,
                    target,
                );
            }
            let outputs = if unzip {
                if count == 2 {
                    split(code, 0, 1, 4, 5);
                    [4, 5, 0, 0]
                } else {
                    split(code, 0, 1, 4, 5);
                    split(code, 2, 3, 0, 1);
                    split(code, 4, 0, 2, 3);
                    split(code, 5, 1, 4, 0);
                    [2, 4, 3, 0]
                }
            } else if count == 2 {
                routing::merge(code, 0, 1, 0, 4, operand.element, target);
                [0, 4, 0, 0]
            } else {
                routing::merge(code, 0, 2, 0, 4, operand.element, target);
                routing::merge(code, 1, 3, 1, 2, operand.element, target);
                routing::merge(code, 0, 1, 0, 3, operand.element, target);
                routing::merge(code, 4, 2, 4, 1, operand.element, target);
                [0, 3, 4, 1]
            };
            for (output, xmm) in outputs[..count].iter().enumerate() {
                let global_chunk = if unzip {
                    output * length.chunks() + chunk
                } else {
                    chunk * count + output
                };
                commit_global_chunk(code, operand, global_chunk, *xmm, length, target);
            }
        }
    }
    if staged {
        release_frame(code, frame_bytes);
    }
}

fn unpack(
    code: &mut Vec<u8>,
    operand: &Operand,
    source: crate::aarch64::sme::tables::VectorGroup,
    signed: bool,
    length: VectorLength,
    target: TargetCpu,
) {
    let registers = [source.first, source.first + 1];
    let frame_bytes = usize::from(source.count) * length.bytes();
    let sources = &registers[..usize::from(source.count)];
    let overlaps = (0..operand.destination.count)
        .any(|index| sources.contains(&operand.destination.register(index)));
    // A single 128-bit input is loaded completely before either output commits.
    // Two-register aliases still need staging: the first output can clobber the
    // second input before its source chunk is loaded.
    let single_chunk_input = source.count == 1 && length.chunks() == 1;
    let staged = overlaps && !single_chunk_input;
    if staged {
        allocate_frame(code, frame_bytes);
        stage(code, sources, length, target);
    }
    let narrow = ElementSize::from_bytes(operand.element.bytes() / 2).unwrap();
    for source_index in 0..usize::from(source.count) {
        for chunk in 0..length.chunks() {
            load_source_chunk(
                code,
                sources,
                source_index * length.chunks() + chunk,
                0,
                staged,
                length,
                target,
            );
            let outputs = if signed && length.chunks() == 1 && target.supports(TargetCpu::Sse41) {
                let opcode = match narrow {
                    ElementSize::Byte => Host::SignExtendByteToWord,
                    ElementSize::Halfword => Host::SignExtendWordToDword,
                    ElementSize::Word => Host::SignExtendDwordToQword,
                    _ => unreachable!("Unpack source has Byte/Halfword/Word elements"),
                };
                opcode.register(code, 2, 0, target);
                Shift::RightBytes.emit(code, 0, (VECTOR_CHUNK_BYTES / 2) as u8);
                opcode.register(code, 3, 0, target);
                [2, 3]
            } else {
                Host::Xor.register(code, 1, 1, target);
                if signed {
                    match narrow {
                        ElementSize::Byte => Host::GreaterByte,
                        ElementSize::Halfword => Host::GreaterWord,
                        ElementSize::Word => Host::GreaterDword,
                        _ => unreachable!("Unpack source has Byte/Halfword/Word elements"),
                    }
                    .register(code, 1, 0, target);
                }
                routing::merge(code, 0, 1, 0, 3, narrow, target);
                [0, 3]
            };
            for (half, xmm) in outputs.iter().enumerate() {
                commit_global_chunk(
                    code,
                    operand,
                    source_index * 2 * length.chunks() + chunk * 2 + half,
                    *xmm,
                    length,
                    target,
                );
            }
        }
    }
    if staged {
        release_frame(code, frame_bytes);
    }
}

fn select(
    code: &mut Vec<u8>,
    operand: &Operand,
    left: crate::aarch64::sme::tables::VectorGroup,
    right: crate::aarch64::sme::tables::VectorGroup,
    predicate: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    if left != right {
        read_predicate_chunk(code, predicate, 0, length);
        prepare_counter(code, length);
    }
    for register_index in 0..operand.destination.count {
        for chunk in 0..length.chunks() {
            load_z_chunk(
                code,
                left.register(register_index),
                chunk,
                0,
                length,
                target,
            );
            if left != right {
                load_z_chunk(
                    code,
                    right.register(register_index),
                    chunk,
                    1,
                    length,
                    target,
                );
                emit_prepared_counter_mask(
                    code,
                    usize::from(register_index),
                    chunk,
                    operand.element,
                    2,
                    3,
                    length,
                    target,
                );
                Host::And.register(code, 0, 2, target);
                Host::AndNot.register(code, 2, 1, target);
                Host::Or.register(code, 0, 2, target);
            }
            store_z_chunk(
                code,
                operand.destination.register(register_index),
                chunk,
                0,
                length,
                target,
            );
        }
    }
}

/// Scalar LUTI uses protected Z index data in host table addresses. Fixed-load
/// Boolean/shuffle lookup and the other table routes do not have that mismatch.
pub(crate) fn requires_dit_zero(
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
) -> bool {
    match operand.kind {
        Kind::Lookup { index_bits, .. } => {
            lookup::recipe(operand, index_bits, length, target) == lookup::Recipe::Scalar
        }
        _ => false,
    }
}

pub(crate) fn emit(code: &mut Vec<u8>, operand: &Operand, length: VectorLength, target: TargetCpu) {
    assert!(length.bits() >= operand.minimum_svl_bits());
    match operand.kind {
        Kind::Lookup {
            source,
            index_bits,
            segment,
        } => lookup::emit(code, operand, source, index_bits, segment, length, target),
        Kind::Unpack { source, signed } => unpack(code, operand, source, signed, length, target),
        Kind::Permute { sources, unzip } => {
            permutation(code, operand, sources, unzip, length, target)
        }
        Kind::Select {
            left,
            right,
            predicate,
        } => select(code, operand, left, right, predicate, length, target),
    }
}

pub(crate) fn emit_lut_v2(
    code: &mut Vec<u8>,
    operand: &crate::aarch64::sme::lut_v2::Operand,
    length: VectorLength,
    target: TargetCpu,
) {
    lookup::lut_v2::emit(code, operand, length, target);
}
