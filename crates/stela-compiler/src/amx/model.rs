//! Reference semantics of the M2 AMX generation, ported from the corsix/amx
//! emulator at 483714bb (MIT, `LICENSES/corsix-amx.txt`) with
//! `AMX_VER == AMX_VER_M2`. Each operation reads its 64-bit operand and
//! updates only the register file or memory; it never reads FPCR.
//!
//! Floating-point arithmetic follows the configuration corsix compared with
//! hardware: round to nearest even, no flushing and default NaN (FPCR.DN).
//! It is computed with Stela's Arm evaluators. FPSR is not updated; hardware
//! FPSR effects, other FPCR settings and NaN propagation without DN are
//! unverified (docs/research/amx.md).
//!
//! Memory operations stage a complete transfer before any register or memory
//! effect. 128- and 256-byte transfers outside 128-byte alignment were never
//! compared with hardware and are refused.
mod extract;
mod float;
mod fused;
mod integer;
mod lookup;
mod mac16;
mod transfer;
mod vector_float;

use super::{AmxOperation, AmxRegisters};
use serde::Serialize;

/// A guest memory failure at the reached address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MemoryFault {
    pub address: u64,
    pub write: bool,
}

/// Guest memory for AMX transfers. Each call is all-or-nothing: on failure no
/// byte of the range may have been written.
pub trait AmxMemory {
    fn read(&mut self, address: u64, destination: &mut [u8]) -> Result<(), MemoryFault>;
    fn write(&mut self, address: u64, source: &[u8]) -> Result<(), MemoryFault>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AmxError {
    Memory(MemoryFault),
    /// An operand outside the hardware-compared domain.
    Unsupported {
        detail: &'static str,
    },
    /// `set` and `clr` change enablement and are owned by the runtime.
    Enablement,
}

/// Apply one enabled-state operation.
pub fn execute(
    registers: &mut AmxRegisters,
    operation: AmxOperation,
    operand: u64,
    memory: &mut dyn AmxMemory,
) -> Result<(), AmxError> {
    use AmxOperation::*;
    match operation {
        LoadX | LoadY | LoadZ | StoreX | StoreY | StoreZ | LoadZInterleaved | StoreZInterleaved => {
            transfer::execute(registers, operation, operand, memory)
        }
        ExtractX => {
            extract::extract_x(registers, operand);
            Ok(())
        }
        ExtractY => {
            extract::extract_y(registers, operand);
            Ok(())
        }
        Fma64 | Fms64 | Fma32 | Fms32 | Fma16 | Fms16 => {
            fused::execute(registers, operation, operand);
            Ok(())
        }
        Mac16 => {
            mac16::execute(registers, operand);
            Ok(())
        }
        VectorFloat => {
            vector_float::vector(registers, operand);
            Ok(())
        }
        MatrixFloat => {
            vector_float::matrix(registers, operand);
            Ok(())
        }
        VectorInteger => {
            integer::vector(registers, operand);
            Ok(())
        }
        MatrixInteger => {
            integer::matrix(registers, operand);
            Ok(())
        }
        GenerateLookup => {
            lookup::execute(registers, operand);
            Ok(())
        }
        Set | Clear => Err(AmxError::Enablement),
    }
}

/// The 56-bit operand pointer. Bit 55 selects the upper or lower VA range, as
/// 26A434 XNU's AMX save path relies on for kernel addresses; user addresses
/// match corsix's zero extension.
pub const fn effective_address(operand: u64) -> u64 {
    (((operand << 8) as i64) >> 8) as u64
}

type Row = [u8; 64];

/// `load_xy_reg`: 64 bytes from a 512-byte circular pool.
fn load_pool(pool: &[Row; 8], offset: u64) -> Row {
    super::state::pool_row(pool, offset)
}

/// `xy_shuffle`.
fn shuffle(row: &mut Row, shuffle: u64, element_bytes: usize) {
    if shuffle == 0 {
        return;
    }
    let source = *row;
    let step = 64 >> shuffle;
    let mut source_offset = 0;
    let mut destination_offset = 0;
    while destination_offset < 64 {
        row[destination_offset..destination_offset + element_bytes]
            .copy_from_slice(&source[source_offset..source_offset + element_bytes]);
        destination_offset += element_bytes;
        source_offset += step;
        if source_offset & 64 != 0 {
            source_offset += element_bytes;
        }
        source_offset &= 63;
    }
}

/// `parse_writemask`: a per-byte enable of groups of `group` bytes.
fn write_mask(value: u64, group: u32, mask_bits: u32) -> u64 {
    let mut value = value as u32;
    let mode = if mask_bits >= 9 {
        (value >> 6) & 7
    } else {
        (value >> 5) & 3
    };
    if mode != 0 {
        value = value.wrapping_mul(group);
    }
    value &= 0x3f;
    let all = u64::MAX;
    match mode {
        0 => {
            let mut enabled = all;
            if value == 1 || value == 2 {
                let mut group = group;
                // Odd groups for 1, even groups for 2.
                enabled = !(all << group) << (group & 0u32.wrapping_sub(value & 1));
                loop {
                    group <<= 1;
                    if group >= 64 {
                        break;
                    }
                    enabled |= enabled << group;
                }
            }
            if value < if mask_bits >= 9 { 6 } else { 3 } {
                enabled
            } else {
                0
            }
        }
        1 => !(all << group) << value,
        2 if value == 0 => all,
        2 | 4 => !(all << value),
        3 if value == 0 => all,
        3 | 5 => !(all >> value),
        _ => 0,
    }
}

/// `load_xy_reg_indexed`: expand packed `index_bits` lane indices from the
/// start of `row` into `element_bits` lanes of `table`.
fn load_indexed(row: &mut Row, table: &Row, index_bits: u32, element_bits: u32) {
    let mut indices = [0u8; 48];
    indices[..40].copy_from_slice(&row[..40]);
    let element_bytes = (element_bits / 8) as usize;
    let index_mask = (1u64 << index_bits) - 1;
    let mut destination = 0;
    let mut source = 0;
    while destination < 64 {
        let mut bits = u64::from_le_bytes(indices[source..source + 8].try_into().unwrap());
        source += index_bits as usize;
        for _ in 0..8 {
            let table_offset = ((bits & index_mask) as usize * element_bytes) & 0x3f;
            row[destination..destination + element_bytes]
                .copy_from_slice(&table[table_offset..table_offset + element_bytes]);
            bits >>= index_bits;
            destination += element_bytes;
        }
    }
}

/// `bit_select(hi, lo, mask)`.
const fn bit_select(high: u64, low: u64, mask: u64) -> u64 {
    (high & !mask) | (low & mask)
}

/// `load_int`: little-endian bytes, sign-extended when `sign_extend` is the
/// number of high bits to replicate.
fn load_integer(bytes: &[u8], sign_extend: u32) -> i64 {
    let mut value = [0u8; 8];
    value[..bytes.len()].copy_from_slice(bytes);
    let value = i64::from_le_bytes(value);
    if sign_extend == 0 {
        value
    } else {
        (value << sign_extend) >> sign_extend
    }
}

fn store_integer(bytes: &mut [u8], value: i64) {
    let length = bytes.len();
    bytes.copy_from_slice(&value.to_le_bytes()[..length]);
}
