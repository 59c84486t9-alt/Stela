//! Reference semantics of the M1 through M4 AMX generations, ported from the corsix/amx
//! emulator at 483714bb (MIT, Copyright (c) 2022 Peter Cawley; `LICENSES/MIT.txt`) with
//! explicit `AMX_VER_M1` through `AMX_VER_M4`. Each operation reads its 64-bit operand and
//! updates only the register file or memory; it never reads FPCR.
//!
//! Floating-point arithmetic follows the configuration corsix compared with
//! hardware: round to nearest even, no flushing and default NaN (FPCR.DN).
//! It is computed with Stela's Arm evaluators. FPSR is not updated. A bounded
//! M1 Pro native corpus confirms that behavior under RMode/DN/FZ/FZ16/AHP;
//! other fields and later-generation hardware remain unverified (docs/research/amx.md).
//!
//! Memory operations stage a complete transfer before any register or memory
//! effect. M1 pair transfers outside 128-byte alignment raise an alignment
//! fault before any memory access, as observed natively. Later-generation
//! unaligned multi-row transfers remain outside the qualified domain.
mod extract;
mod float;
mod fused;
mod integer;
mod lookup;
mod mac16;
mod transfer;
mod vector_float;

use super::{AmxOperation, AmxRegisters, Generation};
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
    /// A source-qualified transfer alignment fault, before any memory access.
    /// Native M1 reports ISV=0: the width is diagnostic, not an ISS SAS field.
    Alignment {
        address: u64,
        write: bool,
        bytes: u16,
    },
    /// An operand outside the hardware-compared domain.
    Unsupported {
        detail: &'static str,
    },
    /// `set` and `clr` change enablement and are owned by the runtime.
    Enablement,
    /// An unallocated operation: hardware raises an undefined instruction
    /// exception.
    Undefined,
}

/// Apply one enabled-state operation.
pub fn execute(
    registers: &mut AmxRegisters,
    operation: AmxOperation,
    operand: u64,
    memory: &mut dyn AmxMemory,
) -> Result<(), AmxError> {
    execute_for(Generation::M2, registers, operation, operand, memory)
}

/// Apply an operation using the declared semantic generation. All submodes
/// follow that generation of the pinned reference, including source-defined
/// unchanged-state modes. `execute` retains the existing M2 contract.
pub fn execute_for(
    generation: Generation,
    registers: &mut AmxRegisters,
    operation: AmxOperation,
    operand: u64,
    memory: &mut dyn AmxMemory,
) -> Result<(), AmxError> {
    use AmxOperation::*;
    match operation {
        LoadX | LoadY | LoadZ | StoreX | StoreY | StoreZ | LoadZInterleaved | StoreZInterleaved => {
            transfer::execute(generation, registers, operation, operand, memory)
        }
        ExtractX => {
            extract::extract_x(generation, registers, operand);
            Ok(())
        }
        ExtractY => {
            extract::extract_y(generation, registers, operand);
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
            vector_float::vector(generation, registers, operand);
            Ok(())
        }
        MatrixFloat => {
            vector_float::matrix(generation, registers, operand);
            Ok(())
        }
        VectorInteger => {
            integer::vector(generation, registers, operand);
            Ok(())
        }
        MatrixInteger => {
            integer::matrix(generation, registers, operand);
            Ok(())
        }
        GenerateLookup => {
            lookup::execute(generation, registers, operand);
            Ok(())
        }
        Set | Clear => Err(AmxError::Enablement),
        Unallocated => Err(AmxError::Undefined),
    }
}

/// The 56-bit operand pointer. Bit 55 selects the upper or lower VA range, as
/// 26A434 XNU's AMX save path relies on for kernel addresses; user addresses
/// match corsix's zero extension.
pub const fn effective_address(operand: u64) -> u64 {
    (((operand << 8) as i64) >> 8) as u64
}

/// M4 packed-index blocks must fit within one XY row. Scalar broadcasts
/// align to an element; ordinary vector operands align to the full row.
/// This is the pinned vecfp.c/vecint.c mask, including the OR when the index
/// block exceeds one row; it is not a guessed stricter alignment rule.
fn aligned_multiple_offset(
    offset: u64,
    element_bytes: usize,
    z_step: u64,
    index_bits: u32,
    indexed: bool,
    scalar: bool,
) -> u64 {
    const ROW_BYTES: u64 = super::state::ROW_BYTES as u64;
    const GRID_ROWS: u64 = super::state::Z_ROWS as u64;
    const BITS_PER_BYTE: u64 = 8;
    let mask = if indexed {
        let index_bytes = ROW_BYTES * GRID_ROWS * u64::from(index_bits)
            / (BITS_PER_BYTE * element_bytes as u64 * z_step);
        0u64.wrapping_sub(ROW_BYTES) | 0u64.wrapping_sub(index_bytes)
    } else if scalar {
        0u64.wrapping_sub(element_bytes as u64)
    } else {
        0u64.wrapping_sub(ROW_BYTES)
    };
    offset & mask
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

#[cfg(test)]
mod generation_tests {
    use super::*;

    struct NoMemory;
    impl AmxMemory for NoMemory {
        fn read(&mut self, _: u64, _: &mut [u8]) -> Result<(), MemoryFault> {
            panic!("arithmetic must not read guest memory")
        }
        fn write(&mut self, _: u64, _: &[u8]) -> Result<(), MemoryFault> {
            panic!("arithmetic must not write guest memory")
        }
    }

    fn run(
        generation: Generation,
        initial: &AmxRegisters,
        op: AmxOperation,
        operand: u64,
    ) -> AmxRegisters {
        let mut result = initial.clone();
        execute_for(generation, &mut result, op, operand, &mut NoMemory).unwrap();
        result
    }

    fn half(row: &mut Row, value: u16) {
        for lane in row.as_chunks_mut::<2>().0 {
            *lane = value.to_le_bytes();
        }
    }

    #[test]
    fn m1_vector_modes_10_to_12_preserve_all_state_as_the_reference_defines() {
        for operation in [AmxOperation::VectorInteger, AmxOperation::VectorFloat] {
            let mut state = AmxRegisters::zeroed();
            let floating = operation == AmxOperation::VectorFloat;
            half(&mut state.x[0], if floating { 0x4000 } else { 2 });
            half(&mut state.y[0], if floating { 0x4200 } else { 3 });
            half(&mut state.z[0], if floating { 0x4500 } else { 5 });
            for (mode, expected) in [(10, 6), (11, 7), (12, 8)] {
                let operand = (mode << 47) | (2 << 42);
                for multi in [0, 1 << 31] {
                    assert_eq!(
                        run(Generation::M1, &state, operation, operand | multi),
                        state
                    );
                }
                let changed = run(Generation::M2, &state, operation, operand);
                let expected = if floating {
                    match expected {
                        6 => 0x4600,
                        7 => 0x4700,
                        _ => 0x4800,
                    }
                } else {
                    expected
                };
                assert_eq!(
                    u16::from_le_bytes(changed.z[0][..2].try_into().unwrap()),
                    expected
                );
            }
        }
    }

    #[test]
    fn m1_float_types_zero_and_one_are_half_without_bf16_or_widening() {
        let mut state = AmxRegisters::zeroed();
        half(&mut state.x[0], 0x3c00); // half 1.0; bf16 2^-7.
        half(&mut state.y[0], 0x3c00);
        for operation in [AmxOperation::VectorFloat, AmxOperation::MatrixFloat] {
            for kind in [0, 1] {
                let operand = kind << 42;
                let m1 = run(Generation::M1, &state, operation, operand);
                assert_eq!(&m1.z[0][..4], &[0x00, 0x3c, 0x00, 0x3c]);
                let m2 = run(Generation::M2, &state, operation, operand);
                if kind == 0 {
                    assert_eq!(&m2.z[0][..2], &[0x80, 0x38]);
                } else {
                    assert_eq!(&m2.z[0][..4], &0x3880_0000u32.to_le_bytes());
                }
            }
        }
    }

    #[test]
    fn m1_ignores_multirow_bit_for_extract_and_vectors() {
        for operation in [
            AmxOperation::ExtractX,
            AmxOperation::ExtractY,
            AmxOperation::VectorFloat,
            AmxOperation::VectorInteger,
        ] {
            let mut state = AmxRegisters::zeroed();
            for row in &mut state.x {
                half(row, 2);
            }
            for row in &mut state.y {
                half(row, 3);
            }
            for (row, bytes) in state.z.iter_mut().enumerate() {
                *bytes = [row as u8 + 3; 64];
            }
            if operation == AmxOperation::VectorFloat {
                // Normal finite values ensure a changed extra row cannot hide
                // behind a tiny product rounding back to the old accumulator.
                for row in &mut state.x {
                    for lane in row.as_chunks_mut::<4>().0 {
                        *lane = 1.0f32.to_le_bytes();
                    }
                }
                for row in &mut state.y {
                    for lane in row.as_chunks_mut::<4>().0 {
                        *lane = 2.0f32.to_le_bytes();
                    }
                }
                for row in &mut state.z {
                    for lane in row.as_chunks_mut::<4>().0 {
                        *lane = 3.0f32.to_le_bytes();
                    }
                }
            }
            let extract = matches!(operation, AmxOperation::ExtractX | AmxOperation::ExtractY);
            let operand = (33 << 20)
                | if extract {
                    (1 << 26) | (8 << 11)
                } else {
                    4 << 42
                };
            let single = run(Generation::M1, &state, operation, operand);
            assert_eq!(
                single,
                run(Generation::M1, &state, operation, operand | (1 << 31))
            );
            assert_ne!(
                single,
                run(Generation::M2, &state, operation, operand | (1 << 31)),
                "{}",
                operation.mnemonic()
            );
        }
    }

    #[test]
    fn m1_extract_cases_25_and_26_copy_half_width_without_conversion() {
        let mut state = AmxRegisters::zeroed();
        for (row, bytes) in state.z.iter_mut().enumerate() {
            *bytes = [row as u8; 64];
        }
        for kind in [9, 10] {
            let operand = (1 << 63) | (1 << 26) | (kind << 11) | (3 << 20);
            let x = run(Generation::M1, &state, AmxOperation::ExtractX, operand);
            assert_eq!(x.x[0], [3; 64]);
            let y = run(Generation::M1, &state, AmxOperation::ExtractY, operand);
            assert_eq!(y.x[0], core::array::from_fn(|byte| (byte as u8 & !1) | 1));
        }
    }

    #[test]
    fn m3_matrix_type12_widens_both_y_and_accumulator() {
        let mut state = AmxRegisters::zeroed();
        state.x[0].fill(0x80);
        half(&mut state.y[0], 257);
        let operand = (8 << 47) | (12 << 42) | (1 << 63);
        let m2 = run(Generation::M2, &state, AmxOperation::MatrixInteger, operand);
        assert_eq!(i16::from_le_bytes(m2.z[0][..2].try_into().unwrap()), -128);
        for generation in [Generation::M3, Generation::M4] {
            let wide = run(generation, &state, AmxOperation::MatrixInteger, operand);
            assert_eq!(
                i32::from_le_bytes(wide.z[0][..4].try_into().unwrap()),
                -32896
            );
        }
    }

    #[test]
    fn m4_index_alignment_preserves_complete_packed_blocks() {
        assert_eq!(aligned_multiple_offset(63, 4, 16, 2, true, false), 48);
        assert_eq!(aligned_multiple_offset(63, 4, 32, 2, true, false), 56);
        assert_eq!(aligned_multiple_offset(127, 1, 16, 4, true, false), 64);
        assert_eq!(aligned_multiple_offset(127, 2, 16, 2, false, true), 126);
        assert_eq!(aligned_multiple_offset(127, 4, 32, 2, false, true), 124);
        assert_eq!(aligned_multiple_offset(127, 8, 32, 2, false, true), 120);
        assert_eq!(aligned_multiple_offset(127, 4, 16, 2, false, false), 64);
        for (operation, kind, aligned, element_bytes) in [
            (AmxOperation::VectorFloat, 4, 56, 4),
            (AmxOperation::VectorInteger, 2, 48, 2),
        ] {
            let mut state = AmxRegisters::zeroed();
            state.x[0].fill(0x55); // Packed 2-bit indices all select lane 1.
            for index in 0..64 / element_bytes {
                if element_bytes == 4 {
                    state.x[1][index * 4..index * 4 + 4]
                        .copy_from_slice(&((index + 1) as f32).to_le_bytes());
                } else {
                    state.x[1][index * 2..index * 2 + 2]
                        .copy_from_slice(&((index + 1) as u16).to_le_bytes());
                }
            }
            for row in &mut state.y {
                if element_bytes == 4 {
                    for lane in row.as_chunks_mut::<4>().0 {
                        *lane = 1.0f32.to_le_bytes();
                    }
                } else {
                    half(row, 1);
                }
            }
            let base = (1 << 53) | (1 << 49) | (1 << 31) | (kind << 42);
            let unaligned = base | (63 << 10);
            let expected = run(Generation::M3, &state, operation, base | (aligned << 10));
            let m4 = run(Generation::M4, &state, operation, unaligned);
            assert_eq!(m4, expected);
            assert_ne!(m4, run(Generation::M3, &state, operation, unaligned));
        }
    }

    #[test]
    fn m4_scalar_broadcast_aligns_to_element_and_extraction_aligns_to_row() {
        let mut state = AmxRegisters::zeroed();
        for row in &mut state.x {
            for (i, lane) in row.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                *lane = ((i + 1) as f32).to_le_bytes();
            }
        }
        for row in &mut state.y {
            for lane in row.as_chunks_mut::<4>().0 {
                *lane = 1.0f32.to_le_bytes();
            }
        }
        let scalar = (1 << 31) | (6 << 32) | (10 << 47) | (4 << 42) | (7 << 10);
        let m4 = run(Generation::M4, &state, AmxOperation::VectorFloat, scalar);
        for row in [0, 32] {
            for lane in m4.z[row].as_chunks::<4>().0 {
                assert_eq!(*lane, 2.0f32.to_le_bytes());
            }
        }
        for (row, bytes) in state.z.iter_mut().enumerate() {
            *bytes = [row as u8 + 1; 64];
        }
        let operand = (1 << 26) | (8 << 11) | (1 << 31) | (33 << 20) | 63;
        for operation in [AmxOperation::ExtractX, AmxOperation::ExtractY] {
            let m4 = run(Generation::M4, &state, operation, operand);
            assert_eq!(m4, run(Generation::M3, &state, operation, operand & !63));
            assert_ne!(m4, run(Generation::M3, &state, operation, operand));
        }
    }

    #[test]
    fn m1_lookup_ignores_bf16_selection_including_nan_boundary() {
        let mut state = AmxRegisters::zeroed();
        half(&mut state.x[0], 0x7c00); // half infinity, finite bf16.
        half(&mut state.x[1], 0x7d00); // half NaN, greater finite bf16.
        state.x[1][..2].fill(0);
        let operand = (1 << 60) | (1 << 53) | (1 << 25);
        let expected = run(
            Generation::M1,
            &state,
            AmxOperation::GenerateLookup,
            operand,
        );
        assert_eq!(expected.y[0][0], 0xff);
        assert_eq!(
            expected,
            run(
                Generation::M1,
                &state,
                AmxOperation::GenerateLookup,
                operand | (1 << 30)
            )
        );
        let m2 = run(
            Generation::M2,
            &state,
            AmxOperation::GenerateLookup,
            operand | (1 << 30),
        );
        assert_eq!(m2.y[0][0], 0);
    }
}
