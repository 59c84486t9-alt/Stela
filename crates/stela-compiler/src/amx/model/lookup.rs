//! `genlut` (corsix `genlut.c`): modes 0..6 generate packed table indices by a
//! "first greater than" search (M2 mode 1 can compare bf16); modes 7..15
//! perform an indexed load into X, Y or Z.
use super::{
    Row,
    float::{bf16_to_single, greater},
    fused::read_lane,
    load_indexed, load_pool,
};
use crate::{
    aarch64::floating::Format,
    amx::{AmxRegisters, Generation},
};

const TABLE_Y: u64 = 1 << 59;
const BF16: u64 = 1 << 30;
const DESTINATION_Z: u64 = 1 << 26;
const DESTINATION_Y: u64 = 1 << 25;
const SOURCE_Y: u64 = 1 << 10;

/// `find_first_greater_than`: for each source lane, the index of the last
/// table entry before the first one greater than it (255 when none precede).
fn first_greater(
    generation: Generation,
    mode: u64,
    source: &Row,
    table: &Row,
    operand: u64,
) -> [u8; 32] {
    let (bytes, compare): (usize, fn(u64, u64) -> bool) = match mode {
        0 => (4, |a, b| greater(Format::Single, a, b)),
        1 if generation.m2_extensions() && operand & BF16 != 0 => (2, |a, b| {
            greater(
                Format::Single,
                u64::from(bf16_to_single(a as u16)),
                u64::from(bf16_to_single(b as u16)),
            )
        }),
        1 => (2, |a, b| greater(Format::Half, a, b)),
        2 => (8, |a, b| greater(Format::Double, a, b)),
        3 => (4, |a, b| a as u32 as i32 > b as u32 as i32),
        4 => (2, |a, b| a as u16 as i16 > b as u16 as i16),
        5 => (4, |a, b| a > b),
        _ => (2, |a, b| a > b),
    };
    let lanes = 64 / bytes;
    let mut result = [0u8; 32];
    for (lane, output) in result.iter_mut().enumerate().take(lanes) {
        let value = read_lane(source, bytes, lane);
        let first = (0..lanes)
            .find(|&entry| compare(read_lane(table, bytes, entry), value))
            .unwrap_or(lanes);
        *output = (first as u8).wrapping_sub(1);
    }
    result
}

/// `pack_bits`: `index_bits`-wide fields in groups of eight; the rest zero.
fn pack(indices: &[u8; 32], index_bits: u32, element_bits: u32) -> Row {
    let mut row = [0u8; 72];
    let mask = if element_bits == 64 {
        7
    } else {
        (1u64 << index_bits) - 1
    };
    let mut destination = 0;
    for group in 0..(64 / element_bits) as usize {
        let mut packed = 0u64;
        for lane in 0..8 {
            packed |= (u64::from(indices[group * 8 + lane]) & mask) << (lane as u32 * index_bits);
        }
        row[destination..destination + 8].copy_from_slice(&packed.to_le_bytes());
        destination += index_bits as usize;
    }
    row[destination..].fill(0);
    *row.first_chunk::<64>().expect("64-byte row")
}

pub(super) fn execute(generation: Generation, registers: &mut AmxRegisters, mut operand: u64) {
    let mode = (operand >> 53) & 0xf;
    let source_pool = if operand & SOURCE_Y != 0 {
        &registers.y
    } else {
        &registers.x
    };
    let mut row = load_pool(source_pool, operand & 0x1ff);
    let table_pool = if operand & TABLE_Y != 0 {
        &registers.y
    } else {
        &registers.x
    };
    let table = table_pool[((operand >> 60) & 7) as usize];
    let (index_bits, element_bits) = match mode {
        0 | 3 | 5 | 11 => (4, 32),
        1 | 4 | 6 | 14 => (5, 16),
        2 | 10 => (4, 64),
        7 => (2, 32),
        8 => (2, 16),
        9 => (2, 8),
        12 => (4, 16),
        13 => (4, 8),
        _ => (5, 8),
    };
    if mode <= 6 {
        let indices = first_greater(generation, mode, &row, &table, operand);
        row = pack(&indices, index_bits, element_bits);
        operand &= !DESTINATION_Z;
    } else {
        load_indexed(&mut row, &table, index_bits, element_bits);
    }
    let index = operand >> 20;
    if operand & DESTINATION_Z != 0 {
        registers.z[(index & 63) as usize] = row;
    } else if operand & DESTINATION_Y != 0 {
        registers.y[(index & 7) as usize] = row;
    } else {
        registers.x[(index & 7) as usize] = row;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amx::model::fused::write_lane;

    #[test]
    fn generation_finds_intervals_and_packs_nibbles() {
        let mut registers = AmxRegisters::zeroed();
        // Table X row 2: f32 0, 10, 20, ... 150.
        for lane in 0..16 {
            write_lane(
                &mut registers.x[2],
                4,
                lane,
                (lane as f32 * 10.0).to_bits().into(),
            );
        }
        // Sources in X row 0: -1, 5, 155, NaN, then zeros.
        for (lane, value) in [-1.0f32, 5.0, 155.0, f32::NAN].into_iter().enumerate() {
            write_lane(&mut registers.x[0], 4, lane, value.to_bits().into());
        }
        // Mode 0 into Y row 1 (bit 26 is ignored for generation).
        execute(
            Generation::M2,
            &mut registers,
            (2 << 60) | DESTINATION_Z | DESTINATION_Y | (1 << 20),
        );
        // -1 precedes entry 0: index 255 & 0xf; 5 lies in [0, 10): 0; 155
        // exceeds every entry: 15; a NaN is never smaller: 15; zero: 0.
        assert_eq!(registers.y[1][0], 0x0f);
        assert_eq!(registers.y[1][1], 0xff);
        assert_eq!(registers.y[1][2], 0x00);
        assert!(registers.y[1][8..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn lookup_modes_expand_indices_into_any_destination() {
        let mut registers = AmxRegisters::zeroed();
        registers.y[4] = core::array::from_fn(|index| index as u8);
        registers.x[0][0] = 0b11_10_01_00;
        // Mode 9: 2-bit indices into byte lanes of table Y row 4, into Z row 40.
        execute(
            Generation::M2,
            &mut registers,
            (9 << 53) | TABLE_Y | (4 << 60) | DESTINATION_Z | (40 << 20),
        );
        assert_eq!(registers.z[40][..4], [0, 1, 2, 3]);
        assert_eq!(registers.z[40][4], 0);
    }
}
