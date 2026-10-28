//! SVE LUTI2/LUTI4: fixed-load SSE2 selection or SSSE3 PSHUFB. Neither path
//! branches on or addresses memory with index values.
use crate::x86_64::asm::Gpr::Rsp;
use crate::x86_64::asm::{Alu, Code, Mem, Size};
use crate::{
    TargetCpu,
    aarch64::{
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VECTOR_REGISTER_COUNT, VectorLength},
        sve::tables::Operand,
    },
    x86_64::{
        isa::{ShiftOpcode as Shift, SimdOpcode as Host},
        scalable::{load_z_chunk, store_z_chunk},
    },
};
const LOW_TABLE: u8 = 4;
const HIGH_TABLE: u8 = 5;
const OUTPUT: u8 = 6;

fn stack(code: &mut Code, opcode: Host, xmm: u8, offset: usize, target: TargetCpu) {
    code.asm()
        .simd(opcode, xmm, Mem::base_disp32(Rsp, offset as i32), target);
}
pub(crate) fn emit(code: &mut Code, op: &Operand, length: VectorLength, target: TargetCpu) {
    assert!(length.bits() >= op.minimum_vl_bits());
    code.asm()
        .alu_imm32(Alu::Sub, Size::Qword, Rsp, length.bytes() as i32);
    for chunk in 0..length.chunks() {
        load_z_chunk(code, op.indexes, chunk, 0, length, target);
        stack(
            code,
            Host::StoreUnaligned,
            0,
            chunk * VECTOR_CHUNK_BYTES,
            target,
        );
    }
    load_z_chunk(code, op.table, 0, LOW_TABLE, length, target);
    if op.element == ElementSize::Halfword && op.index_bits == 4 {
        if op.table_registers == 2 {
            load_z_chunk(
                code,
                (op.table + 1) % VECTOR_REGISTER_COUNT,
                0,
                HIGH_TABLE,
                length,
                target,
            );
        } else {
            load_z_chunk(code, op.table, 1, HIGH_TABLE, length, target);
        }
    }
    let packed_bytes_per_chunk =
        VECTOR_CHUNK_BYTES * usize::from(op.index_bits) / (op.element.bytes() * u8::BITS as usize);
    let start = length.lanes(op.element) * usize::from(op.part) * usize::from(op.index_bits)
        / u8::BITS as usize;
    for chunk in 0..length.chunks() {
        let offset = start + chunk * packed_bytes_per_chunk;
        stack(
            code,
            Host::LoadUnaligned,
            0,
            (offset / VECTOR_CHUNK_BYTES) * VECTOR_CHUNK_BYTES,
            target,
        );
        if !offset.is_multiple_of(VECTOR_CHUNK_BYTES) {
            Shift::RightBytes.emit(code, 0, (offset % VECTOR_CHUNK_BYTES) as u8);
        }
        crate::x86_64::scalable::lut::emit_chunk(code, op.index_bits, op.element, target);
        store_z_chunk(code, op.destination, chunk, OUTPUT, length, target);
    }
    code.asm()
        .alu_imm32(Alu::Add, Size::Qword, Rsp, length.bytes() as i32);
}
