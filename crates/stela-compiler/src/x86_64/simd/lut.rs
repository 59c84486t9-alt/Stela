//! Fixed AdvSIMD LUT wrapper around the shared constant-time packed-index core.
//! Read all source vectors before committing the single 128-bit destination.

use super::{commit, read_vector};
use crate::TargetCpu;
use crate::aarch64::scalable::ElementSize;
use crate::aarch64::simd::lut::Operand;
use crate::x86_64::isa::ShiftOpcode;
use crate::x86_64::scalable::lut;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    read_vector(code, operand.indices, 0);
    let offset = operand.index_byte_offset();
    if offset != 0 {
        ShiftOpcode::RightBytes.emit(code, 0, offset as u8);
    }
    read_vector(code, operand.table, 4);
    if operand.table_registers() == 2 {
        read_vector(code, (operand.table + 1) % 32, 5);
    }
    lut::emit_chunk(
        code,
        operand.index_bits,
        ElementSize::from_bytes(usize::from(operand.element_bytes)).unwrap(),
        target,
    );
    commit(code, operand.destination, 6);
}
