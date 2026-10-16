//! CRC32/CRC32C: table-driven baseline or SSE4.2 CRC32 (CRC32C only).
use super::isa::{CrcOpcode, CrcTableInstruction as Table};
use super::{Register, Shift, Width, load, right_operand, store};
use crate::{
    TargetCpu,
    aarch64::crc::{DataSize, Operand, Polynomial},
};
use alloc::vec::Vec;

const TABLE_ENTRIES: u32 = 256;
const ENTRY_BYTES: u32 = 4;
const TABLE_BYTES: u32 = TABLE_ENTRIES * ENTRY_BYTES;
const BITS_PER_BYTE: u8 = 8;
const DATA_WORD_BYTES: u8 = 4;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    if operand.destination == Register::Zero {
        Table::Discard.emit(code);
        return;
    }
    // Both inputs are staged before W is written.
    load(code, operand.accumulator);
    right_operand(code, operand.data, Width::X64, Shift::Lsl, 0);
    if operand.polynomial == Polynomial::Castagnoli && target.supports(TargetCpu::Sse42) {
        CrcOpcode::for_bytes(operand.size.bytes()).emit(code, target);
    } else {
        emit_table(code, operand);
    }
    store(code, operand.destination);
}

fn emit_table(code: &mut Vec<u8>, operand: &Operand) {
    match operand.size {
        DataSize::Byte => Table::TruncateByteData.emit(code),
        DataSize::Halfword => Table::TruncateHalfwordData.emit(code),
        DataSize::Word | DataSize::Doubleword => {}
    }
    Table::TableBaseRip.emit(code);
    let table_address = code.len();
    code.extend(0i32.to_le_bytes());
    Table::MergeWordData.emit(code); // W operation also truncates accumulator.
    emit_bytes(code, operand.size.bytes().min(DATA_WORD_BYTES));
    if operand.size == DataSize::Doubleword {
        Table::SelectHighDataWord.emit(code);
        Table::MergeWordData.emit(code);
        emit_bytes(code, DATA_WORD_BYTES);
    }
    Table::JumpOverTable.emit(code);
    code.extend(TABLE_BYTES.to_le_bytes());
    let displacement = i32::try_from(code.len() - table_address - size_of::<i32>())
        .expect("bounded CRC instruction table displacement");
    code[table_address..table_address + size_of::<i32>()]
        .copy_from_slice(&displacement.to_le_bytes());
    // The branch skips this immutable data. All runtime indexes are zero-extended
    // bytes; every read is one dword inside the readable native-code allocation.
    for byte in 0..TABLE_ENTRIES {
        let mut remainder = byte;
        for _ in 0..BITS_PER_BYTE {
            remainder = (remainder >> 1)
                ^ (operand.polynomial.reflected() & 0u32.wrapping_sub(remainder & 1));
        }
        code.extend(remainder.to_le_bytes());
    }
}

fn emit_bytes(code: &mut Vec<u8>, count: u8) {
    for _ in 0..count {
        Table::IndexLowByte.emit(code);
        Table::ShiftAccumulatorByte.emit(code);
        Table::XorTableEntry.emit(code);
    }
}

#[cfg(test)]
mod tests;
