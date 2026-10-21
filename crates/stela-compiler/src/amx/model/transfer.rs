//! `ldx ldy ldz ldzi stx sty stz stzi` (corsix `ldst.c`): bit 62 moves two
//! rows; for M2 X and Y loads bit 60 then moves four. X/Y loads ignore
//! bit 61 (M3 non-consecutive) and bit 63. Z uses bit 61 within its row index.
use super::{AmxError, AmxMemory, MemoryFault, Row, effective_address};
use crate::amx::{AmxOperation, AmxRegisters, Generation};

const MULTIPLE: u64 = 1 << 62;
const MULTIPLE_MEANS_FOUR: u64 = 1 << 60;
/// Multi-row transfers were compared with hardware only at this alignment.
const MULTIPLE_ALIGNMENT: u64 = 128;
const INTERLEAVED_LANES: usize = 16;

pub(super) fn execute(
    generation: Generation,
    registers: &mut AmxRegisters,
    operation: AmxOperation,
    operand: u64,
    memory: &mut dyn AmxMemory,
) -> Result<(), AmxError> {
    use AmxOperation::*;
    let address = effective_address(operand);
    match operation {
        LoadX => load(
            &mut registers.x,
            operand,
            address,
            memory,
            generation.m2_extensions(),
        ),
        LoadY => load(
            &mut registers.y,
            operand,
            address,
            memory,
            generation.m2_extensions(),
        ),
        LoadZ => load(&mut registers.z, operand, address, memory, false),
        StoreX => store(&registers.x, operand, address, memory),
        StoreY => store(&registers.y, operand, address, memory),
        StoreZ => store(&registers.z, operand, address, memory),
        LoadZInterleaved => {
            let mut bytes = [0u8; 64];
            memory.read(address, &mut bytes)?;
            let (row, half) = interleaved(operand);
            for lane in 0..INTERLEAVED_LANES {
                let destination = row | (lane & 1);
                let offset = (half + (lane >> 1)) * 4;
                registers.z[destination][offset..offset + 4]
                    .copy_from_slice(&bytes[lane * 4..lane * 4 + 4]);
            }
            Ok(())
        }
        StoreZInterleaved => {
            let (row, half) = interleaved(operand);
            let bytes: Row = core::array::from_fn(|index| {
                let lane = index / 4;
                let source = row | (lane & 1);
                registers.z[source][(half + (lane >> 1)) * 4 + index % 4]
            });
            memory.write(address, &bytes)?;
            Ok(())
        }
        _ => unreachable!("transfer dispatch"),
    }
}

/// The even row of the pair and the lane half selected by bit 56.
fn interleaved(operand: u64) -> (usize, usize) {
    let row = ((operand >> 56) & 63) as usize;
    (row & !1, (row & 1) << 3)
}

fn rows(operand: u64, xy: bool) -> usize {
    match (
        operand & MULTIPLE != 0,
        xy && operand & MULTIPLE_MEANS_FOUR != 0,
    ) {
        (false, _) => 1,
        (true, false) => 2,
        (true, true) => 4,
    }
}

fn aligned(rows: usize, address: u64) -> Result<(), AmxError> {
    if rows > 1 && !address.is_multiple_of(MULTIPLE_ALIGNMENT) {
        return Err(AmxError::Unsupported {
            detail: "multi-row AMX transfer outside 128-byte alignment",
        });
    }
    Ok(())
}

fn load<const N: usize>(
    file: &mut [Row; N],
    operand: u64,
    address: u64,
    memory: &mut dyn AmxMemory,
    xy: bool,
) -> Result<(), AmxError> {
    let count = rows(operand, xy);
    aligned(count, address)?;
    let mut bytes = [0u8; 256];
    memory.read(address, &mut bytes[..count * 64])?;
    let first = (operand >> 56) as usize % N;
    for (index, chunk) in bytes[..count * 64].as_chunks::<64>().0.iter().enumerate() {
        file[(first + index) % N].copy_from_slice(chunk);
    }
    Ok(())
}

fn store<const N: usize>(
    file: &[Row; N],
    operand: u64,
    address: u64,
    memory: &mut dyn AmxMemory,
) -> Result<(), AmxError> {
    let count = if operand & MULTIPLE != 0 { 2 } else { 1 };
    aligned(count, address)?;
    let first = (operand >> 56) as usize % N;
    let mut bytes = [0u8; 128];
    for index in 0..count {
        bytes[index * 64..index * 64 + 64].copy_from_slice(&file[(first + index) % N]);
    }
    memory.write(address, &bytes[..count * 64])?;
    Ok(())
}

impl From<MemoryFault> for AmxError {
    fn from(fault: MemoryFault) -> Self {
        Self::Memory(fault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amx::model::execute;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A flat guest window starting at `base`.
    pub(crate) struct Window {
        pub base: u64,
        pub bytes: Vec<u8>,
        pub accesses: Vec<(u64, usize, bool)>,
    }
    impl AmxMemory for Window {
        fn read(&mut self, address: u64, destination: &mut [u8]) -> Result<(), MemoryFault> {
            self.accesses.push((address, destination.len(), false));
            let start = address.wrapping_sub(self.base) as usize;
            let source = self
                .bytes
                .get(start..start + destination.len())
                .ok_or(MemoryFault {
                    address,
                    write: false,
                })?;
            destination.copy_from_slice(source);
            Ok(())
        }
        fn write(&mut self, address: u64, source: &[u8]) -> Result<(), MemoryFault> {
            self.accesses.push((address, source.len(), true));
            let start = address.wrapping_sub(self.base) as usize;
            let destination =
                self.bytes
                    .get_mut(start..start + source.len())
                    .ok_or(MemoryFault {
                        address,
                        write: true,
                    })?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    fn window() -> Window {
        Window {
            base: 0x10_0000,
            bytes: (0..512).map(|index| index as u8 ^ 0x5a).collect(),
            accesses: vec![],
        }
    }

    #[test]
    fn single_loads_accept_any_alignment_and_wrap_register_indices() {
        let mut memory = window();
        let mut registers = AmxRegisters::zeroed();
        // Register field bits 59:56 with only 58:56 used for X.
        let operand = (0xf << 56) | (memory.base + 3);
        execute(&mut registers, AmxOperation::LoadX, operand, &mut memory).unwrap();
        assert_eq!(registers.x[7][..], memory.bytes[3..67]);
        assert_eq!(memory.accesses, [(memory.base + 3, 64, false)]);
    }

    #[test]
    fn m2_loads_two_or_four_consecutive_rows_and_wrap() {
        let mut memory = window();
        let mut registers = AmxRegisters::zeroed();
        let operand = MULTIPLE | MULTIPLE_MEANS_FOUR | (6 << 56) | (memory.base + 128);
        execute(&mut registers, AmxOperation::LoadY, operand, &mut memory).unwrap();
        for (row, register) in [6, 7, 0, 1].into_iter().enumerate() {
            let start = 128 + row * 64;
            assert_eq!(registers.y[register][..], memory.bytes[start..start + 64]);
        }
        // Z ignores the four-row bit: a pair from row 63 wraps to row 0.
        let operand = MULTIPLE | MULTIPLE_MEANS_FOUR | (63 << 56) | memory.base;
        execute(&mut registers, AmxOperation::LoadZ, operand, &mut memory).unwrap();
        assert_eq!(registers.z[63][..], memory.bytes[..64]);
        assert_eq!(registers.z[0][..], memory.bytes[64..128]);
        assert_eq!(memory.accesses[1], (memory.base, 128, false));
    }

    #[test]
    fn m1_pair_load_ignores_four_row_and_nonconsecutive_bits() {
        let mut memory = window();
        let mut registers = AmxRegisters::zeroed();
        registers.x.fill([0xa5; 64]);
        let operand = MULTIPLE | MULTIPLE_MEANS_FOUR | (1 << 61) | (7 << 56) | memory.base;
        crate::amx::model::execute_for(
            Generation::M1,
            &mut registers,
            AmxOperation::LoadX,
            operand,
            &mut memory,
        )
        .unwrap();
        assert_eq!(registers.x[7][..], memory.bytes[..64]);
        assert_eq!(registers.x[0][..], memory.bytes[64..128]);
        assert_eq!(registers.x[1], [0xa5; 64]);
        assert_eq!(memory.accesses, [(memory.base, 128, false)]);
        let before = registers.clone();
        assert!(matches!(
            crate::amx::model::execute_for(
                Generation::M1,
                &mut registers,
                AmxOperation::LoadX,
                operand + 1,
                &mut memory
            ),
            Err(AmxError::Unsupported { .. })
        ));
        assert_eq!(registers, before);
        assert_eq!(memory.accesses.len(), 1);
    }

    #[test]
    fn stores_move_one_or_two_rows_and_ignore_the_four_row_bit() {
        let mut memory = window();
        let mut registers = AmxRegisters::zeroed();
        registers.x[7] = [1; 64];
        registers.x[0] = [2; 64];
        let operand = MULTIPLE | MULTIPLE_MEANS_FOUR | (7 << 56) | memory.base;
        execute(&mut registers, AmxOperation::StoreX, operand, &mut memory).unwrap();
        assert_eq!(memory.bytes[..64], [1; 64]);
        assert_eq!(memory.bytes[64..128], [2; 64]);
        assert_eq!(memory.bytes[128], 128 ^ 0x5a);
    }

    #[test]
    fn interleaved_pairs_split_even_and_odd_lanes() {
        let mut memory = window();
        let mut registers = AmxRegisters::zeroed();
        // Row 5: pair (4, 5), right half.
        let operand = (5 << 56) | memory.base;
        execute(
            &mut registers,
            AmxOperation::LoadZInterleaved,
            operand,
            &mut memory,
        )
        .unwrap();
        for lane in 0..16 {
            let row = 4 + (lane & 1);
            let offset = (8 + lane / 2) * 4;
            assert_eq!(
                registers.z[row][offset..offset + 4],
                memory.bytes[lane * 4..lane * 4 + 4]
            );
        }
        let operand = (5 << 56) | (memory.base + 256);
        execute(
            &mut registers,
            AmxOperation::StoreZInterleaved,
            operand,
            &mut memory,
        )
        .unwrap();
        let (low, high) = memory.bytes.split_at(256);
        assert_eq!(low[..64], high[..64]);
    }

    #[test]
    fn faults_and_unaligned_pairs_leave_registers_unchanged() {
        let mut memory = window();
        let mut registers = AmxRegisters::zeroed();
        registers.z[1] = [9; 64];
        let before = registers.clone();
        let operand = (1 << 56) | (memory.base + 500);
        assert_eq!(
            execute(&mut registers, AmxOperation::LoadZ, operand, &mut memory),
            Err(AmxError::Memory(MemoryFault {
                address: memory.base + 500,
                write: false
            }))
        );
        let operand = MULTIPLE | (1 << 56) | (memory.base + 64);
        assert!(matches!(
            execute(&mut registers, AmxOperation::LoadZ, operand, &mut memory),
            Err(AmxError::Unsupported { .. })
        ));
        assert!(matches!(
            execute(&mut registers, AmxOperation::StoreZ, operand, &mut memory),
            Err(AmxError::Unsupported { .. })
        ));
        assert!(registers == before);
        assert_eq!(memory.accesses.len(), 1);
    }

    #[test]
    fn bit_55_selects_the_upper_address_range() {
        assert_eq!(
            effective_address(0xc0ff_fe00_0bb9_c330),
            0xffff_fe00_0bb9_c330
        );
        assert_eq!(
            effective_address(0x4000_7fff_1234_5678),
            0x0000_7fff_1234_5678
        );
    }
}
