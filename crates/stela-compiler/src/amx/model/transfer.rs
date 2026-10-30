//! `ldx ldy ldz ldzi stx sty stz stzi` (corsix `ldst.c`): bit 62 moves two
//! rows; M2–M4 X/Y loads can move four with bit 60. M3/M4 bit 61 selects
//! nonconsecutive placement. X/Y ignore bit 63; Z uses bit 61 in its row index.
use super::{AmxError, AmxMemory, MemoryFault, Row, effective_address};
use crate::amx::{AmxOperation, AmxRegisters, Generation};

const MULTIPLE: u64 = 1 << 62;
const NON_CONSECUTIVE: u64 = 1 << 61;
const MULTIPLE_MEANS_FOUR: u64 = 1 << 60;
/// Checked transfer alignment; only M1's misalignment fault is recovered.
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
        LoadX => load(generation, &mut registers.x, operand, address, memory, true),
        LoadY => load(generation, &mut registers.y, operand, address, memory, true),
        LoadZ => load(
            generation,
            &mut registers.z,
            operand,
            address,
            memory,
            false,
        ),
        StoreX => store(generation, &registers.x, operand, address, memory),
        StoreY => store(generation, &registers.y, operand, address, memory),
        StoreZ => store(generation, &registers.z, operand, address, memory),
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

fn aligned(generation: Generation, rows: usize, address: u64, write: bool) -> Result<(), AmxError> {
    if rows > 1 && !address.is_multiple_of(MULTIPLE_ALIGNMENT) {
        if generation == Generation::M1 {
            return Err(AmxError::Alignment {
                address,
                write,
                bytes: 128,
            });
        }
        return Err(AmxError::Unsupported {
            detail: "multi-row AMX transfer outside 128-byte alignment",
        });
    }
    Ok(())
}

fn load<const N: usize>(
    generation: Generation,
    file: &mut [Row; N],
    operand: u64,
    address: u64,
    memory: &mut dyn AmxMemory,
    xy: bool,
) -> Result<(), AmxError> {
    let count = rows(operand, xy && generation.m2_extensions());
    aligned(generation, count, address, false)?;
    let mut bytes = [0u8; 256];
    memory.read(address, &mut bytes[..count * 64])?;
    let first = (operand >> 56) as usize % N;
    let stride = if xy && generation.m3_extensions() && operand & NON_CONSECUTIVE != 0 {
        if operand & MULTIPLE_MEANS_FOUR != 0 {
            2
        } else {
            4
        }
    } else {
        1
    };
    for (index, chunk) in bytes[..count * 64].as_chunks::<64>().0.iter().enumerate() {
        file[(first + index * stride) % N].copy_from_slice(chunk);
    }
    Ok(())
}

fn store<const N: usize>(
    generation: Generation,
    file: &[Row; N],
    operand: u64,
    address: u64,
    memory: &mut dyn AmxMemory,
) -> Result<(), AmxError> {
    let count = if operand & MULTIPLE != 0 { 2 } else { 1 };
    aligned(generation, count, address, true)?;
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
mod tests;
