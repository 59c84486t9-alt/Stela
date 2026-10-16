//! Baseline packed predicate operations with bounded source snapshots.
use super::super::scalable;
use super::predicate;
use crate::{
    TargetCpu,
    aarch64::{
        scalable::{ElementSize, VectorLength},
        sve::predicate_logic::{Boolean, Kind, Operand, Permutation},
    },
};
use alloc::vec::Vec;

const CHUNK_BITS: usize = 64;
const CHUNK_BYTES: usize = 8;
const SOURCE_SLOT_BYTES: usize = 32;
const SNAPSHOT_BYTES: u8 = 64;
const HALF_CHUNK_BITS: usize = 32;
const SUB_RSP_SNAPSHOT: &[u8] = &[0x48, 0x83, 0xec, SNAPSHOT_BYTES];
const ADD_RSP_SNAPSHOT: &[u8] = &[0x48, 0x83, 0xc4, SNAPSHOT_BYTES];
const MOV_STACK_RAX: &[u8] = &[0x48, 0x89, 0x84, 0x24];
const MOV_RAX_STACK: &[u8] = &[0x48, 0x8b, 0x84, 0x24];
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const MOV_R11_RAX: &[u8] = &[0x49, 0x89, 0xc3];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const BSWAP_RAX: &[u8] = &[0x48, 0x0f, 0xc8];
const AND_EAX_IMM32: &[u8] = &[0x25];
const MOV_EAX_EAX: &[u8] = &[0x89, 0xc0];
const AND_RAX_RCX: &[u8] = &[0x48, 0x21, 0xc8];
const OR_RAX_RCX: &[u8] = &[0x48, 0x09, 0xc8];
const XOR_RAX_RCX: &[u8] = &[0x48, 0x31, 0xc8];
const OR_RAX_RDX: &[u8] = &[0x48, 0x09, 0xd0];
const AND_RAX_R11: &[u8] = &[0x4c, 0x21, 0xd8];
const AND_RDX_R11: &[u8] = &[0x4c, 0x21, 0xda];
const XOR_RAX_R11: &[u8] = &[0x4c, 0x31, 0xd8];
const NOT_RAX: &[u8] = &[0x48, 0xf7, 0xd0];
const MOVABS_R11: &[u8] = &[0x49, 0xbb];
const SHR_RAX_IMM8: &[u8] = &[0x48, 0xc1, 0xe8];
const SHL_RAX_IMM8: &[u8] = &[0x48, 0xc1, 0xe0];
const SHR_RDX_IMM8: &[u8] = &[0x48, 0xc1, 0xea];
const SHL_RDX_IMM8: &[u8] = &[0x48, 0xc1, 0xe2];
const MOVDQU_STACK_XMM0: &[u8] = &[0xf3, 0x0f, 0x7f, 0x84, 0x24];
const MOV_ECX_STATE: &[u8] = &[0x8b, 0x8f];
const ADD_ECX_IMM8: &[u8] = &[0x83, 0xc1];
const AND_ECX_IMM32: &[u8] = &[0x81, 0xe1];
const SHL_ECX_IMM8: &[u8] = &[0xc1, 0xe1];
const BT_STACK_RCX: &[u8] = &[0x48, 0x0f, 0xa3, 0x0c, 0x24];
const SBB_R8_R8: &[u8] = &[0x4d, 0x19, 0xc0];
const AND_RAX_R8: &[u8] = &[0x4c, 0x21, 0xc0];
const SPREAD_STAGES: [(u8, u64); 5] = [
    (16, 0x0000_ffff_0000_ffff),
    (8, 0x00ff_00ff_00ff_00ff),
    (4, 0x0f0f_0f0f_0f0f_0f0f),
    (2, 0x3333_3333_3333_3333),
    (1, 0x5555_5555_5555_5555),
];

pub(crate) fn emit(code: &mut Vec<u8>, operand: &Operand, length: VectorLength, target: TargetCpu) {
    match operand.kind {
        Kind::Boolean {
            operation,
            flags,
            governor,
            left,
            right,
        } => {
            if flags {
                predicate::begin_predtest(code);
            }
            for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                scalable::read_predicate_chunk(code, left, chunk, length);
                code.extend(MOV_RCX_RAX);
                scalable::read_predicate_chunk(code, right, chunk, length);
                match operation {
                    Boolean::And => code.extend(AND_RAX_RCX),
                    Boolean::BitClear => {
                        code.extend(NOT_RAX);
                        code.extend(AND_RAX_RCX);
                    }
                    Boolean::ExclusiveOr => code.extend(XOR_RAX_RCX),
                    Boolean::Nand => {
                        code.extend(AND_RAX_RCX);
                        code.extend(NOT_RAX);
                    }
                    Boolean::Nor => {
                        code.extend(OR_RAX_RCX);
                        code.extend(NOT_RAX);
                    }
                    Boolean::OrNot => {
                        code.extend(NOT_RAX);
                        code.extend(OR_RAX_RCX);
                    }
                    Boolean::Or => code.extend(OR_RAX_RCX),
                }
                code.extend(MOV_RCX_RAX);
                scalable::read_predicate_chunk(code, governor, chunk, length);
                code.extend(MOV_R11_RAX);
                code.extend(AND_RAX_RCX);
                if flags {
                    predicate::accumulate_predtest(code, ElementSize::Byte);
                }
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
            if flags {
                predicate::finish_predtest(code);
            }
        }
        Kind::Select {
            governor,
            left,
            right,
        } => {
            for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                scalable::read_predicate_chunk(code, left, chunk, length);
                code.extend(MOV_RCX_RAX);
                scalable::read_predicate_chunk(code, right, chunk, length);
                code.extend(MOV_R11_RAX);
                code.extend(XOR_RAX_RCX);
                code.extend(MOV_RCX_RAX);
                scalable::read_predicate_chunk(code, governor, chunk, length);
                code.extend(AND_RAX_RCX);
                code.extend(XOR_RAX_R11);
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
        }
        Kind::SelectIndexed {
            element,
            source,
            selector,
            index_register,
            immediate,
        } => {
            code.extend(SUB_RSP_SNAPSHOT);
            snapshot(code, selector, 0, length);
            code.extend(MOV_ECX_STATE);
            code.extend(
                ((core::mem::offset_of!(crate::GuestState, x)
                    + usize::from(index_register) * CHUNK_BYTES) as u32)
                    .to_le_bytes(),
            );
            if immediate != 0 {
                code.extend(ADD_ECX_IMM8);
                code.push(immediate);
            }
            code.extend(AND_ECX_IMM32);
            code.extend(((length.bytes() / element.bytes() - 1) as u32).to_le_bytes());
            if element != ElementSize::Byte {
                code.extend(SHL_ECX_IMM8);
                code.push(element.bytes().ilog2() as u8);
            }
            code.extend(BT_STACK_RCX);
            code.extend(SBB_R8_R8);
            for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                scalable::read_predicate_chunk(code, source, chunk, length);
                code.extend(AND_RAX_R8);
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
            code.extend(ADD_RSP_SNAPSHOT);
        }
        Kind::ExtractCounter {
            element,
            source,
            part,
            pair,
        } => {
            scalable::read_predicate_chunk(code, source, 0, length);
            predicate::prepare_counter(code, length);
            let outputs = if pair { 2 } else { 1 };
            for output in 0..outputs {
                for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                    let offset = (usize::from(part) * outputs + output) * length.bytes()
                        + chunk * CHUNK_BITS;
                    predicate::emit_prepared_counter_chunk(code, offset / CHUNK_BITS, length);
                    shift(code, SHR_RAX_IMM8, offset % CHUNK_BITS);
                    and_mask(code, predicate::leading_bits(element));
                    scalable::write_predicate_chunk(
                        code,
                        (operand.destination + output as u8) % 16,
                        chunk,
                        length,
                    );
                }
            }
        }
        Kind::MoveVector {
            element,
            source,
            part,
        } => {
            code.extend(SUB_RSP_SNAPSHOT);
            let needed = length.predicate_bytes().div_ceil(16);
            for chunk in 0..needed {
                scalable::load_z_chunk(code, source, chunk, 0, length, target);
                code.extend(MOVDQU_STACK_XMM0);
                code.extend(((chunk * 16) as u32).to_le_bytes());
            }
            for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                let bit = length.bytes() / element.bytes() * usize::from(part)
                    + chunk * CHUNK_BITS / element.bytes();
                load_bits(code, 0, bit);
                dilate(code, element.bytes());
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
            code.extend(ADD_RSP_SNAPSHOT);
        }
        Kind::Permute {
            operation,
            element,
            left,
            right,
        } => {
            code.extend(SUB_RSP_SNAPSHOT);
            snapshot(code, left, 0, length);
            snapshot(code, right, SOURCE_SLOT_BYTES, length);
            for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                permutation(code, operation, element, chunk, length);
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
            code.extend(ADD_RSP_SNAPSHOT);
        }
        Kind::Unpack { high, source } => {
            code.extend(SUB_RSP_SNAPSHOT);
            snapshot(code, source, 0, length);
            for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                load_bits(
                    code,
                    0,
                    usize::from(high) * length.bytes() / 2 + chunk * HALF_CHUNK_BITS,
                );
                spread(code, 1, length.bytes().min(CHUNK_BITS));
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
            code.extend(ADD_RSP_SNAPSHOT);
        }
        Kind::Reverse { element, source } => {
            code.extend(SUB_RSP_SNAPSHOT);
            snapshot(code, source, 0, length);
            let chunks = length.predicate_bytes().div_ceil(CHUNK_BYTES);
            for chunk in 0..chunks {
                load_snapshot(code, (chunks - 1 - chunk) * CHUNK_BYTES);
                for distance in [1, 2, 4].into_iter().filter(|&d| d >= element.bytes()) {
                    code.extend(MOV_RDX_RAX);
                    shift(code, SHR_RDX_IMM8, distance);
                    and_mask(code, low_group_mask(distance));
                    shift(code, SHL_RAX_IMM8, distance);
                    // RDX already contains the opposite half; mask it via R11.
                    code.extend(AND_RDX_R11);
                    code.extend(OR_RAX_RDX);
                }
                code.extend(BSWAP_RAX);
                if length.bytes() < CHUNK_BITS {
                    shift(code, SHR_RAX_IMM8, CHUNK_BITS - length.bytes());
                }
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
            code.extend(ADD_RSP_SNAPSHOT);
        }
    }
}

fn snapshot(code: &mut Vec<u8>, source: u8, slot: usize, length: VectorLength) {
    for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
        scalable::read_predicate_chunk(code, source, chunk, length);
        store_snapshot(code, slot + chunk * CHUNK_BYTES);
    }
}
fn store_snapshot(code: &mut Vec<u8>, offset: usize) {
    code.extend(MOV_STACK_RAX);
    code.extend((offset as u32).to_le_bytes());
}
fn load_snapshot(code: &mut Vec<u8>, offset: usize) {
    code.extend(MOV_RAX_STACK);
    code.extend((offset as u32).to_le_bytes());
}
fn load_bits(code: &mut Vec<u8>, slot: usize, bit: usize) {
    load_snapshot(code, slot + (bit / CHUNK_BITS) * CHUNK_BYTES);
    shift(code, SHR_RAX_IMM8, bit % CHUNK_BITS);
}
fn shift(code: &mut Vec<u8>, opcode: &[u8], bits: usize) {
    if bits != 0 {
        code.extend(opcode);
        code.push(bits as u8);
    }
}
fn and_mask(code: &mut Vec<u8>, mask: u64) {
    code.extend(MOVABS_R11);
    code.extend(mask.to_le_bytes());
    code.extend(AND_RAX_R11);
}
fn low_group_mask(group: usize) -> u64 {
    (0..CHUNK_BITS)
        .filter(|bit| (bit / group).is_multiple_of(2))
        .fold(0, |mask, bit| mask | (1 << bit))
}
fn spread(code: &mut Vec<u8>, group: usize, output_bits: usize) {
    if output_bits < CHUNK_BITS {
        code.extend(AND_EAX_IMM32);
        code.extend(((1u32 << (output_bits / 2)) - 1).to_le_bytes());
    } else {
        code.extend(MOV_EAX_EAX);
    }
    for (distance, mask) in SPREAD_STAGES.into_iter().filter(|&(distance, _)| {
        usize::from(distance) >= group && usize::from(distance) < output_bits / 2
    }) {
        code.extend(MOV_RDX_RAX);
        shift(code, SHL_RDX_IMM8, usize::from(distance));
        code.extend(OR_RAX_RDX);
        and_mask(code, mask);
    }
}
fn compact(code: &mut Vec<u8>, group: usize, odd: bool) {
    shift(code, SHR_RAX_IMM8, usize::from(odd) * group);
    and_mask(code, low_group_mask(group));
    for distance in [1, 2, 4, 8, 16]
        .into_iter()
        .filter(|&distance| distance >= group)
    {
        code.extend(MOV_RDX_RAX);
        shift(code, SHR_RDX_IMM8, distance);
        code.extend(OR_RAX_RDX);
        and_mask(code, low_group_mask(distance * 2));
    }
    code.extend(MOV_EAX_EAX);
}
fn permutation(
    code: &mut Vec<u8>,
    operation: Permutation,
    element: ElementSize,
    chunk: usize,
    length: VectorLength,
) {
    let group = element.bytes();
    match operation {
        Permutation::Zip { high } => {
            let bit = usize::from(high) * length.bytes() / 2 + chunk * HALF_CHUNK_BITS;
            load_bits(code, 0, bit);
            spread(code, group, length.bytes().min(CHUNK_BITS));
            code.extend(MOV_RCX_RAX);
            load_bits(code, SOURCE_SLOT_BYTES, bit);
            spread(code, group, length.bytes().min(CHUNK_BITS));
            shift(code, SHL_RAX_IMM8, group);
            code.extend(OR_RAX_RCX);
        }
        Permutation::Transpose { odd } => {
            load_snapshot(code, chunk * CHUNK_BYTES);
            shift(code, SHR_RAX_IMM8, usize::from(odd) * group);
            and_mask(code, low_group_mask(group));
            code.extend(MOV_RCX_RAX);
            load_snapshot(code, SOURCE_SLOT_BYTES + chunk * CHUNK_BYTES);
            shift(code, SHR_RAX_IMM8, usize::from(odd) * group);
            and_mask(code, low_group_mask(group));
            shift(code, SHL_RAX_IMM8, group);
            code.extend(OR_RAX_RCX);
        }
        Permutation::Unzip { odd } => {
            if length.bytes() <= CHUNK_BITS {
                load_snapshot(code, 0);
                compact(code, group, odd);
                code.extend(MOV_RCX_RAX);
                load_snapshot(code, SOURCE_SLOT_BYTES);
                compact(code, group, odd);
                shift(code, SHL_RAX_IMM8, length.bytes() / 2);
                code.extend(OR_RAX_RCX);
            } else {
                let half = length.bytes() / 2;
                let bit = chunk * CHUNK_BITS;
                let slot = if bit < half { 0 } else { SOURCE_SLOT_BYTES };
                let source_chunk = (bit % half) / HALF_CHUNK_BITS;
                load_snapshot(code, slot + source_chunk * CHUNK_BYTES);
                compact(code, group, odd);
                code.extend(MOV_RCX_RAX);
                load_snapshot(code, slot + (source_chunk + 1) * CHUNK_BYTES);
                compact(code, group, odd);
                shift(code, SHL_RAX_IMM8, HALF_CHUNK_BITS);
                code.extend(OR_RAX_RCX);
            }
        }
    }
}

fn dilate(code: &mut Vec<u8>, stride: usize) {
    if stride == 1 {
        return;
    }
    let input_bits = CHUNK_BITS / stride;
    // The first dilation mask discards unused low32 bits; this clears the
    // only higher bits that could otherwise overlap its retained groups.
    code.extend(MOV_EAX_EAX);
    let mut block = input_bits / 2;
    while block != 0 {
        code.extend(MOV_RDX_RAX);
        shift(code, SHL_RDX_IMM8, (stride - 1) * block);
        code.extend(OR_RAX_RDX);
        let mask = (0..CHUNK_BITS)
            .filter(|bit| bit % (block * stride) < block)
            .fold(0, |mask, bit| mask | (1 << bit));
        and_mask(code, mask);
        block /= 2;
    }
}
