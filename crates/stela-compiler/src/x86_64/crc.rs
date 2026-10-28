//! CRC32/CRC32C: table-driven baseline or SSE4.2 CRC32 (CRC32C only), or
//! bit-serial for data-independent timing.
use super::isa::{CrcOpcode, CrcTableInstruction as Table};
use super::{Register, Shift, Width, load, right_operand, store};
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, ShiftOp, Size, Unary};
use crate::{
    TargetCpu,
    aarch64::crc::{DataSize, Operand, Polynomial},
};

const TABLE_ENTRIES: u32 = 256;
const ENTRY_BYTES: u32 = 4;
const TABLE_BYTES: u32 = TABLE_ENTRIES * ENTRY_BYTES;
const BITS_PER_BYTE: u8 = 8;
const DATA_WORD_BYTES: u8 = 4;

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu) {
    if operand.destination == Register::Zero {
        Table::Discard.emit(code);
        return;
    }
    // Both inputs are staged before W is written.
    load(code, operand.accumulator);
    right_operand(code, operand.data, Width::X64, Shift::Lsl, 0);
    if target.data_independent_timing() {
        // Neither the table lookup nor CRC32 is data-independent: CRC32 is
        // not on Intel's data operand independent timing list.
        emit_serial(code, operand);
    } else if operand.polynomial == Polynomial::Castagnoli && target.supports(TargetCpu::Sse42) {
        CrcOpcode::for_bytes(operand.size.bytes()).emit(code, target);
    } else {
        emit_table(code, operand);
    }
    store(code, operand.destination);
}

fn emit_table(code: &mut Code, operand: &Operand) {
    match operand.size {
        DataSize::Byte => Table::TruncateByteData.emit(code),
        DataSize::Halfword => Table::TruncateHalfwordData.emit(code),
        DataSize::Word | DataSize::Doubleword => {}
    }
    // R8 = the table, placed after the jump over it; its displacement is
    // the lea's last field.
    code.asm().lea(Size::Qword, Gpr::R8, Mem::rip(0));
    let table_base = code.len() - size_of::<i32>();
    Table::MergeWordData.emit(code); // W operation also truncates accumulator.
    emit_bytes(code, operand.size.bytes().min(DATA_WORD_BYTES));
    if operand.size == DataSize::Doubleword {
        Table::SelectHighDataWord.emit(code);
        Table::MergeWordData.emit(code);
        emit_bytes(code, DATA_WORD_BYTES);
    }
    let mut asm = code.asm();
    let over = asm.jmp();
    // The branch skips this immutable data. All runtime indexes are zero-extended
    // bytes; every read is one dword inside the readable native-code allocation.
    let table = asm.len();
    for byte in 0..TABLE_ENTRIES {
        let mut remainder = byte;
        for _ in 0..BITS_PER_BYTE {
            remainder = (remainder >> 1)
                ^ (operand.polynomial.reflected() & 0u32.wrapping_sub(remainder & 1));
        }
        asm.data(&remainder.to_le_bytes());
    }
    asm.bind(over);
    debug_assert_eq!(code.len() - table, TABLE_BYTES as usize);
    let displacement = i32::try_from(table - table_base - size_of::<i32>())
        .expect("bounded CRC instruction table displacement");
    code[table_base..table_base + size_of::<i32>()].copy_from_slice(&displacement.to_le_bytes());
}

/// The reflected CRC one data bit at a time over the accumulator XOR the
/// data, as wide as the data: each step shifts right and XORs in the
/// polynomial masked by the bit shifted out, with no branch or table. The
/// data's upper bits enter as they reach the low 32, which is the bytewise
/// CRC by linearity; after the last step the value is 32 bits.
fn emit_serial(code: &mut Code, operand: &Operand) {
    use Gpr::{Rax, Rcx, Rdx};
    use Size::{Byte, Dword, Qword, Word};
    let mut asm = code.asm();
    asm.mov(Dword, Rax, Rax);
    match operand.size {
        DataSize::Byte => asm.movzx(Dword, Rcx, Byte, Rcx),
        DataSize::Halfword => asm.movzx(Dword, Rcx, Word, Rcx),
        DataSize::Word => asm.mov(Dword, Rcx, Rcx),
        DataSize::Doubleword => {}
    }
    asm.alu(Alu::Xor, Qword, Rax, Rcx);
    for _ in 0..operand.size.bytes() * BITS_PER_BYTE {
        // EDX = the polynomial where bit 0 is set, else zero.
        asm.mov(Dword, Rdx, Rax);
        asm.alu_imm8(Alu::And, Dword, Rdx, 1);
        asm.unary(Unary::Neg, Dword, Rdx);
        asm.alu_imm32(Alu::And, Dword, Rdx, operand.polynomial.reflected() as i32);
        asm.shift_one(ShiftOp::Shr, Qword, Rax);
        asm.alu(Alu::Xor, Qword, Rax, Rdx);
    }
}

fn emit_bytes(code: &mut Code, count: u8) {
    for _ in 0..count {
        Table::IndexLowByte.emit(code);
        Table::ShiftAccumulatorByte.emit(code);
        Table::XorTableEntry.emit(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bit-serial model over the full data width matches the bytewise
    /// CRC, and the lowering has no table, jump or CRC32 instruction.
    #[test]
    fn the_serial_crc_matches_the_bytewise_crc_without_a_table() {
        let bytewise = |polynomial: u32, mut crc: u32, data: u64, bytes: u8| {
            for byte in 0..bytes {
                crc ^= (data >> (8 * byte)) as u8 as u32;
                for _ in 0..BITS_PER_BYTE {
                    crc = (crc >> 1) ^ (polynomial & 0u32.wrapping_sub(crc & 1));
                }
            }
            crc
        };
        let serial = |polynomial: u32, crc: u32, data: u64, bytes: u8| {
            let mask = if bytes == 8 {
                u64::MAX
            } else {
                (1u64 << (8 * bytes)) - 1
            };
            let mut value = u64::from(crc) ^ (data & mask);
            for _ in 0..bytes * BITS_PER_BYTE {
                value = (value >> 1) ^ u64::from(polynomial & 0u32.wrapping_sub(value as u32 & 1));
            }
            u32::try_from(value).expect("32-bit after the last step")
        };
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        for polynomial in [Polynomial::Ieee, Polynomial::Castagnoli] {
            for bytes in [1, 2, 4, 8] {
                for _ in 0..64 {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    let (crc, data) = (seed as u32, seed.rotate_left(29));
                    let reflected = polynomial.reflected();
                    assert_eq!(
                        serial(reflected, crc, data, bytes),
                        bytewise(reflected, crc, data, bytes)
                    );
                }
            }
        }
        for size in [
            DataSize::Byte,
            DataSize::Halfword,
            DataSize::Word,
            DataSize::Doubleword,
        ] {
            for polynomial in [Polynomial::Ieee, Polynomial::Castagnoli] {
                let operand = Operand {
                    size,
                    polynomial,
                    destination: Register::X(0),
                    accumulator: Register::X(1),
                    data: Register::X(2),
                };
                let mut timed = Code::new();
                emit(
                    &mut timed,
                    &operand,
                    TargetCpu::Sse42.with_data_independent_timing(),
                );
                let mut baseline = Code::new();
                emit(&mut baseline, &operand, TargetCpu::DataIndependentTiming);
                assert_eq!(timed, baseline);
                // No RIP-relative table base and no CRC32 (F2 0F 38 F0/F1).
                assert!(
                    !timed
                        .windows(3)
                        .any(|w| w == [0x0f, 0x38, 0xf0] || w == [0x0f, 0x38, 0xf1])
                );
                assert!(!timed.windows(3).any(|w| w == [0x4c, 0x8d, 0x05]));
            }
        }
    }

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
                let mut baseline = Code::new();
                let mut checked = Code::new();
                emit(&mut baseline, &operand, TargetCpu::Baseline);
                emit(&mut checked, &operand, TargetCpu::Sse42);
                if polynomial == Polynomial::Castagnoli {
                    assert!(checked.len() < baseline.len());
                    let mut expected = Code::new();
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
                    let mut discarded = Code::new();
                    emit(&mut discarded, &operand, target);
                    let mut nop = Code::new();
                    Table::Discard.emit(&mut nop);
                    assert_eq!(discarded, nop);
                }
            }
        }
    }
}
