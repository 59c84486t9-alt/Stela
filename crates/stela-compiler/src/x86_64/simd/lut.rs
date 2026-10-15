//! Fixed AdvSIMD LUT wrapper around the shared constant-time packed-index core.
//! Read all source vectors before committing the single 128-bit destination.

use super::{commit, read_vector};
use crate::TargetCpu;
use crate::aarch64::scalable::{ElementSize, VECTOR_REGISTER_COUNT};
use crate::aarch64::simd::lut::Operand;
use crate::x86_64::isa::ShiftOpcode;
use crate::x86_64::scalable::lut;

const INDICES_XMM: u8 = 0;
const LOW_TABLE_XMM: u8 = 4;
const HIGH_TABLE_XMM: u8 = 5;
const RESULT_XMM: u8 = 6;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    read_vector(code, operand.indices, INDICES_XMM);
    let offset = operand.index_byte_offset();
    if offset != 0 {
        ShiftOpcode::RightBytes.emit(code, INDICES_XMM, offset as u8);
    }
    read_vector(code, operand.table, LOW_TABLE_XMM);
    if operand.table_registers() == 2 {
        read_vector(
            code,
            (operand.table + 1) % VECTOR_REGISTER_COUNT,
            HIGH_TABLE_XMM,
        );
    }
    lut::emit_chunk(
        code,
        operand.index_bits,
        ElementSize::from_bytes(usize::from(operand.element_bytes)).unwrap(),
        target,
    );
    commit(code, operand.destination, RESULT_XMM);
}
