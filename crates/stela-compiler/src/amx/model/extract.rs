//! `extrx` and `extry` (corsix `extr.c`): Z rows or columns to X or Y, X/Y
//! copies, and the M2 narrowing and multi-row (bit 31) forms.
use super::{
    Row, bit_select,
    float::{single_to_bf16, single_to_half},
    load_integer, store_integer, write_mask,
};
use crate::amx::{AmxRegisters, Generation};

const SIGNED_INPUT: u64 = 1 << 57;
const SIGNED_OUTPUT: u64 = 1 << 56;
const SATURATE: u64 = 1 << 55;
const ROUNDING_SHIFT: u64 = 1 << 54;
const BETWEEN_XY: u64 = 1 << 27;
const HORIZONTAL_VERTICAL: u64 = 1 << 26;
const TO_Y: u64 = 1 << 10;
const MULTIPLE_ROWS: u64 = 1 << 31;
const EVEN_BYTES: u64 = 0x5555_5555_5555_5555;

/// `extr_alu`: narrowing of one Z element.
fn narrow(value: i64, operand: u64, output_bits: u32) -> i64 {
    let shift = (operand >> 58) & 0x1f;
    if operand >> 63 != 0 {
        return if shift >= 16 {
            i64::from(single_to_bf16(value as u32))
        } else {
            i64::from(single_to_half(value as u32))
        };
    }
    let mut value = value;
    if shift != 0 && operand & ROUNDING_SHIFT != 0 {
        value = value.wrapping_add(1 << (shift - 1));
    }
    value >>= shift;
    if operand & SATURATE != 0 {
        let bits = output_bits - u32::from(operand & SIGNED_OUTPUT != 0);
        let high = 1i64 << bits;
        if operand & SIGNED_INPUT != 0 {
            let low = if operand & SIGNED_OUTPUT != 0 {
                -high
            } else {
                0
            };
            if value < low {
                value = low;
            }
            if value >= high {
                value = high - 1;
            }
        } else if value as u64 >= high as u64 {
            value = high - 1;
        }
    }
    value
}

/// X/Y element bytes, Z element bytes and narrowing stride of a
/// horizontal/vertical extraction.
fn layout(generation: Generation, operand: u64) -> (usize, usize, usize) {
    match ((operand >> 63) << 4) | ((operand >> 11) & 0xf) {
        0 => (1, 1, 0),
        8 | 24 => (4, 4, 0),
        9 => (2, 4, 1),
        25 if generation.m2_extensions() => (2, 4, 1),
        10 => (2, 4, 2),
        26 if generation.m2_extensions() => (2, 4, 2),
        11 => (1, 4, 1),
        13 => (1, 2, 1),
        17 => (8, 8, 0),
        _ => (2, 2, 0),
    }
}

/// `store_xy_row`.
fn store_row(pool: &mut [Row; 8], offset: u64, row: &Row, enable: u64) {
    let pool = pool.as_flattened_mut();
    for (index, byte) in row.iter().enumerate() {
        if enable >> index & 1 != 0 {
            pool[(offset as usize + index) & 0x1ff] = *byte;
        }
    }
}

struct Shape {
    to_y: bool,
    offset: u64,
    step: u64,
    enable: u64,
    xy_bytes: usize,
    z_bytes: usize,
    stride: usize,
}

/// Shared prologue; `None` for an X/Y copy, which is complete.
fn shape(
    generation: Generation,
    registers: &mut AmxRegisters,
    operand: &mut u64,
    column: bool,
) -> Option<Shape> {
    let selector = *operand >> 20;
    if *operand & HORIZONTAL_VERTICAL != 0 {
        let (xy_bytes, z_bytes, stride) = layout(generation, *operand);
        let mut step = 64;
        if generation.m2_extensions() && *operand & MULTIPLE_ROWS != 0 {
            *operand &= !(0x1ff << 32);
            step = if selector & 32 != 0 { 16 } else { 32 };
        }
        Some(Shape {
            to_y: *operand & TO_Y != 0,
            offset: if generation.aligned_multiple_offsets() && step < 64 {
                *operand & !(super::super::state::ROW_BYTES as u64 - 1)
            } else {
                *operand
            },
            step,
            enable: write_mask(*operand >> 32, xy_bytes as u32, 9),
            xy_bytes,
            z_bytes,
            stride,
        })
    } else if *operand & BETWEEN_XY != 0 {
        if column {
            registers.y[((*operand >> 6) & 7) as usize] = registers.x[(selector & 7) as usize];
        } else {
            registers.x[((*operand >> 16) & 7) as usize] = registers.y[(selector & 7) as usize];
        }
        None
    } else {
        let mut xy_bytes = 8 >> ((*operand >> 28) & 3);
        let mut enable = u64::MAX;
        if xy_bytes == 1 {
            xy_bytes = 2;
            enable = EVEN_BYTES;
        }
        let (mask_shift, offset) = if column {
            (32, *operand)
        } else {
            (41, *operand >> 10)
        };
        Some(Shape {
            to_y: column,
            offset,
            step: 64,
            enable: enable & write_mask(*operand >> mask_shift, xy_bytes as u32, 7),
            xy_bytes,
            z_bytes: xy_bytes,
            stride: 0,
        })
    }
}

/// `x[i] = f(z[_][i])` and its variants.
pub(super) fn extract_x(generation: Generation, registers: &mut AmxRegisters, mut operand: u64) {
    let Some(mut shape) = shape(generation, registers, &mut operand, false) else {
        return;
    };
    let sign_extend = sign_extension(operand, shape.z_bytes);
    let mut row = (operand >> 20) & (shape.step - 1);
    while row <= 63 {
        let mut buffer = [0u8; 64];
        for index in (0..64).step_by(shape.xy_bytes) {
            let offset = (index & (shape.z_bytes - 1)) / shape.xy_bytes * shape.stride;
            let source = bit_select(row, row + offset as u64, shape.z_bytes as u64 - 1);
            let column = index & !(shape.z_bytes - 1);
            let mut value = load_integer(
                &registers.z[source as usize][column..column + shape.z_bytes],
                sign_extend,
            );
            if shape.stride != 0 {
                value = narrow(value, operand, shape.xy_bytes as u32 * 8);
            }
            store_integer(&mut buffer[index..index + shape.xy_bytes], value);
        }
        if operand & HORIZONTAL_VERTICAL != 0 && (operand >> 32) & 0x1ff == 3 {
            buffer = [0; 64];
        }
        let pool = if shape.to_y {
            &mut registers.y
        } else {
            &mut registers.x
        };
        store_row(pool, shape.offset & 0x1ff, &buffer, shape.enable);
        shape.offset = shape.offset.wrapping_add(64);
        row += shape.step;
    }
}

/// `y[j] = f(z[j][_])` and its variants.
pub(super) fn extract_y(generation: Generation, registers: &mut AmxRegisters, mut operand: u64) {
    let Some(mut shape) = shape(generation, registers, &mut operand, true) else {
        return;
    };
    let sign_extend = sign_extension(operand, shape.z_bytes);
    let mut column = (operand >> 20) & (shape.step - 1);
    while column <= 63 {
        let mut buffer = [0u8; 64];
        for index in (0..64).step_by(shape.xy_bytes) {
            let offset = (index & (shape.z_bytes - 1)) / shape.xy_bytes * shape.stride;
            let source = bit_select(
                index as u64,
                column + offset as u64,
                shape.z_bytes as u64 - 1,
            );
            let byte = column as usize & !(shape.z_bytes - 1);
            let mut value = load_integer(
                &registers.z[source as usize][byte..byte + shape.z_bytes],
                sign_extend,
            );
            if shape.stride != 0 {
                value = narrow(value, operand, shape.xy_bytes as u32 * 8);
            }
            store_integer(&mut buffer[index..index + shape.xy_bytes], value);
        }
        // Unlike extrx, corsix applies this zeroing in every mode.
        if (operand >> 32) & 0x1ff == 3 {
            buffer = [0; 64];
        }
        let pool = if shape.to_y {
            &mut registers.y
        } else {
            &mut registers.x
        };
        store_row(pool, shape.offset & 0x1ff, &buffer, shape.enable);
        shape.offset = shape.offset.wrapping_add(64);
        column += shape.step;
    }
}

fn sign_extension(operand: u64, z_bytes: usize) -> u32 {
    if operand & SIGNED_INPUT != 0 {
        64 - z_bytes as u32 * 8
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numbered() -> AmxRegisters {
        let mut registers = AmxRegisters::zeroed();
        for (row, bytes) in registers.z.iter_mut().enumerate() {
            for (column, byte) in bytes.iter_mut().enumerate() {
                *byte = (row * 64 + column) as u8 ^ (row as u8).rotate_left(3);
            }
        }
        registers
    }

    #[test]
    fn extract_copies_rows_and_columns_with_offsets() {
        let mut registers = numbered();
        // extrx: Z row 5 into X at byte offset 500, wrapping the pool.
        extract_x(Generation::M2, &mut registers, (5 << 20) | (500 << 10));
        let flat = *registers.x.as_flattened().first_chunk::<512>().unwrap();
        for index in 0..64 {
            assert_eq!(flat[(500 + index) % 512], registers.z[5][index]);
        }
        // extry with 32-bit elements: column 8 (bytes 8..12) of every fourth
        // row, i.e. Z[j][column] for j the element's byte index.
        let mut registers = numbered();
        extract_y(Generation::M2, &mut registers, (1 << 28) | (8 << 20));
        for element in 0..16 {
            let row = element * 4;
            assert_eq!(
                registers.y[0][element * 4..element * 4 + 4],
                registers.z[row][8..12]
            );
        }
        // Mode 1 enables only lane 3.
        let mut registers = numbered();
        extract_x(
            Generation::M2,
            &mut registers,
            (1 << 46) | (3 << 41) | (1 << 28) | (2 << 20),
        );
        assert_eq!(registers.x[0][12..16], registers.z[2][12..16]);
        assert!(registers.x[0][..12].iter().all(|&byte| byte == 0));
        assert!(registers.x[0][16..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn byte_elements_use_even_bytes_only() {
        let mut registers = numbered();
        registers.x[0] = [0xee; 64];
        extract_x(Generation::M2, &mut registers, 3 << 28);
        for index in 0..64 {
            let expected = if index % 2 == 0 {
                registers.z[0][index]
            } else {
                0xee
            };
            assert_eq!(registers.x[0][index], expected);
        }
    }

    #[test]
    fn copies_between_x_and_y() {
        let mut registers = numbered();
        registers.y[6] = [7; 64];
        extract_x(
            Generation::M2,
            &mut registers,
            BETWEEN_XY | (6 << 20) | (2 << 16),
        );
        assert_eq!(registers.x[2], [7; 64]);
        registers.x[1] = [9; 64];
        extract_y(
            Generation::M2,
            &mut registers,
            BETWEEN_XY | (1 << 20) | (5 << 6),
        );
        assert_eq!(registers.y[5], [9; 64]);
    }

    #[test]
    fn narrowing_shifts_rounds_and_saturates() {
        let mut registers = AmxRegisters::zeroed();
        // Mode 9: 32-bit Z to 16-bit X, stride 1 across row pairs.
        for row in [0usize, 1] {
            for lane in 0..16 {
                let value: i32 = if row == 0 { 0x0001_8000 } else { -0x0003_0001 };
                registers.z[row][lane * 4..lane * 4 + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        let operand = HORIZONTAL_VERTICAL
            | (9 << 11)
            | SIGNED_INPUT
            | SIGNED_OUTPUT
            | SATURATE
            | ROUNDING_SHIFT
            | (1 << 58);
        extract_x(Generation::M2, &mut registers, operand);
        let lanes: [i16; 32] = core::array::from_fn(|lane| {
            i16::from_le_bytes([registers.x[0][lane * 2], registers.x[0][lane * 2 + 1]])
        });
        // (0x18000 + 1) >> 1 = 0xc000 saturates to 0x7fff; the odd lane reads
        // the next row: (-0x30001 + 1) >> 1 = -0x18000 saturates to -0x8000.
        assert_eq!(lanes[0], 0x7fff);
        assert_eq!(lanes[1], -0x8000);
    }

    #[test]
    fn floating_narrowing_rounds_to_half_or_bf16() {
        let mut registers = AmxRegisters::zeroed();
        registers.z[0][..4].copy_from_slice(&0x3f80_1000u32.to_le_bytes());
        // bit 63 with case 9: f32 to f16.
        extract_x(
            Generation::M2,
            &mut registers,
            (1 << 63) | HORIZONTAL_VERTICAL | (9 << 11),
        );
        assert_eq!(
            u16::from_le_bytes([registers.x[0][0], registers.x[0][1]]),
            0x3c00
        );
        // A shift field of 16 selects bf16.
        extract_x(
            Generation::M2,
            &mut registers,
            (1 << 63) | (16 << 58) | HORIZONTAL_VERTICAL | (9 << 11),
        );
        assert_eq!(
            u16::from_le_bytes([registers.x[0][0], registers.x[0][1]]),
            0x3f80
        );
    }

    #[test]
    fn m2_multiple_rows_step_through_the_grid() {
        let mut registers = numbered();
        // Bit 31 with selector 33: rows 1, 17, 33, 49 go to four X rows.
        extract_x(
            Generation::M2,
            &mut registers,
            MULTIPLE_ROWS | HORIZONTAL_VERTICAL | (8 << 11) | (33 << 20) | (3 << 32),
        );
        for (index, row) in [1usize, 17, 33, 49].into_iter().enumerate() {
            assert_eq!(registers.x[index], registers.z[row]);
        }
    }
}
