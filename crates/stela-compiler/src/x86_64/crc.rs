//! Scalar CRC remainder recipes: baseline byte tables or checked SSE4.2.
use super::isa::{CrcOpcode, CrcTableInstruction as Table};
use super::{Register, Shift, Width, load, right_operand, store};
use crate::{
    TargetCpu,
    aarch64::crc::{DataSize, Operand, Polynomial},
};

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
    // Both original inputs are staged before writing the W destination.
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
mod tests {
    use super::*;

    #[test]
    fn optional_hardware_is_castagnoli_only_and_discard_preserves_map_interval() {
        for size in [
            DataSize::Byte,
            DataSize::Halfword,
            DataSize::Word,
            DataSize::Doubleword,
        ] {
            for polynomial in [Polynomial::Ieee, Polynomial::Castagnoli] {
                let mut operand = Operand {
                    size,
                    polynomial,
                    destination: Register::X(0),
                    accumulator: Register::X(1),
                    data: Register::X(2),
                };
                let mut baseline = Vec::new();
                let mut checked = Vec::new();
                emit(&mut baseline, &operand, TargetCpu::Baseline);
                emit(&mut checked, &operand, TargetCpu::Sse42);
                if polynomial == Polynomial::Castagnoli {
                    assert!(checked.len() < baseline.len());
                    let mut expected = Vec::new();
                    load(&mut expected, operand.accumulator);
                    right_operand(&mut expected, operand.data, Width::X64, Shift::Lsl, 0);
                    CrcOpcode::for_bytes(size.bytes()).emit(&mut expected, TargetCpu::Sse42);
                    store(&mut expected, operand.destination);
                    assert_eq!(checked, expected);
                } else {
                    assert_eq!(checked, baseline);
                }
                operand.destination = Register::Zero;
                for target in [TargetCpu::Baseline, TargetCpu::Sse42] {
                    let mut discarded = Vec::new();
                    emit(&mut discarded, &operand, target);
                    let mut nop = Vec::new();
                    Table::Discard.emit(&mut nop);
                    assert_eq!(discarded, nop);
                }
            }
        }
    }
}
