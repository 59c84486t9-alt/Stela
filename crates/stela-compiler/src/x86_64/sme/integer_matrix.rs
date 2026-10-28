//! SME integer ZA arithmetic.
use crate::x86_64::asm::{Alu, Code, Gpr, ShiftOp, Size};
use crate::x86_64::simd::encode::guest;
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

pub(crate) fn emit(code: &mut Code, operand: &Operand, length: VectorLength, target: TargetCpu) {
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
    code: &mut Code,
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
    let mut asm = code.asm();
    asm.mov_load(
        Size::Dword,
        Gpr::Rcx,
        guest(
            (core::mem::offset_of!(GuestState, x) + usize::from(operand.selector) * GPR_BYTES)
                as u32,
        ),
    );
    if operand.offset != 0 {
        asm.alu_imm8(Alu::Add, Size::Dword, Gpr::Rcx, operand.offset as i8);
    }
    // All accepted SME lengths and group counts are powers of two. Low32
    // addition followed by this mask equals UInt(Wselector)+offset modulo stride.
    asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rcx, (stride - 1) as i8);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Qword,
        Gpr::Rcx,
        length.bytes().trailing_zeros() as u8,
    );
    asm.alu(Alu::Add, Size::Qword, Gpr::R8, Gpr::Rcx);
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
