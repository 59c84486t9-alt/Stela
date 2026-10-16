//! Integer ZA vector arithmetic over the checked extended execution context.
use alloc::vec::Vec;
mod long;
mod outer;

use crate::{
    GuestState, TargetCpu,
    aarch64::{
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VECTOR_REGISTER_COUNT, VectorLength},
        sme::integer_matrix::{AddSubOperation, AddSubSources, Operand},
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::load_z_chunk,
        scalable_matrix::{load_za_chunk_at_r8, load_za_pointer_r8, store_za_chunk_at_r8},
    },
};

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const GPR_BYTES: usize = core::mem::size_of::<u64>();
const MOV_ECX_STATE_DISP32: &[u8] = &[0x8b, 0x8f];
const ADD_ECX_IMM8: &[u8] = &[0x83, 0xc1];
const AND_ECX_IMM8: &[u8] = &[0x83, 0xe1];
const SHL_RCX_IMM8: &[u8] = &[0x48, 0xc1, 0xe1];
const ADD_R8_RCX: &[u8] = &[0x49, 0x01, 0xc8];

pub(crate) fn emit(code: &mut Vec<u8>, operand: &Operand, length: VectorLength, target: TargetCpu) {
    match operand {
        Operand::AddSub(operation) => {
            emit_add_sub(code, operation, length, target);
        }
        Operand::Long(operation) => {
            long::emit_long(
                code,
                operation,
                length,
                target,
                long::Recipe::selected(operation, target),
            );
        }
        Operand::Outer(operation) => {
            outer::emit_outer(code, operation, length, target);
        }
    }
}

fn emit_add_sub(
    code: &mut Vec<u8>,
    operand: &AddSubOperation,
    length: VectorLength,
    target: TargetCpu,
) {
    let stride = length.bytes() / usize::from(operand.groups);
    let arithmetic = match (operand.subtract, operand.element_size) {
        (false, ElementSize::Word) => Host::AddDword,
        (false, ElementSize::Doubleword) => Host::AddQword,
        (true, ElementSize::Word) => Host::SubDword,
        (true, ElementSize::Doubleword) => Host::SubQword,
        _ => unreachable!("integer ZA add/sub has 32- or 64-bit elements"),
    };
    load_za_pointer_r8(code);
    code.extend(MOV_ECX_STATE_DISP32);
    code.extend(
        ((core::mem::offset_of!(GuestState, x) + usize::from(operand.selector) * GPR_BYTES) as u32)
            .to_le_bytes(),
    );
    if operand.offset != 0 {
        code.extend(ADD_ECX_IMM8);
        code.push(operand.offset);
    }
    // All accepted SME lengths and group counts are powers of two. Low32
    // addition followed by this mask equals UInt(Wselector)+offset modulo stride.
    code.extend(AND_ECX_IMM8);
    code.push((stride - 1) as u8);
    code.extend(SHL_RCX_IMM8);
    code.push(length.bytes().trailing_zeros() as u8);
    code.extend(ADD_R8_RCX);
    for group in 0..operand.groups {
        for chunk in 0..length.chunks() {
            let displacement =
                (usize::from(group) * stride * length.bytes() + chunk * VECTOR_CHUNK_BYTES) as u32;
            let right = match operand.sources {
                AddSubSources::AccumulatorGroup { right } => {
                    load_za_chunk_at_r8(code, LEFT, displacement, target);
                    right + group
                }
                AddSubSources::GroupSingle { left, right } => {
                    load_z_chunk(
                        code,
                        (left + group) % VECTOR_REGISTER_COUNT,
                        chunk,
                        LEFT,
                        length,
                        target,
                    );
                    right
                }
                AddSubSources::GroupGroup { left, right } => {
                    load_z_chunk(code, left + group, chunk, LEFT, length, target);
                    right + group
                }
            };
            load_z_chunk(code, right, chunk, RIGHT, length, target);
            arithmetic.register(code, LEFT, RIGHT, target);
            store_za_chunk_at_r8(code, LEFT, displacement, target);
        }
    }
}
