//! `vecint` and `matint` (corsix `vecint.c`, `matint.c`): M2 adds vector ALU
//! modes 10..12 and bit-31 multi-row forms. M3 widens matrix mode-8 type 12;
//! M4 aligns multi-row vector offsets.
use super::{
    Row, aligned_multiple_offset, bit_select, load_indexed, load_integer, load_pool, shuffle,
    store_integer, write_mask,
};
use crate::amx::{AmxRegisters, Generation};

const ROUNDING_SHIFT: u64 = 1 << 29;
const SATURATE: u64 = 1 << 30;
const SIGNED_OUTPUT: u64 = 1 << 26;
/// Bit 63 means signed Z in mode 4 and signed X otherwise.
const SIGNED_Z_OR_X: u64 = 1 << 63;
const SIGNED_Y: u64 = 1 << 26;
const INDEXED_LOAD: u64 = 1 << 53;
const INDEXED_LOAD_Y: u64 = 1 << 47;
const INDEXED_LOAD_4BIT: u64 = 1 << 48;
const MATRIX_INDEXED_MODE_8: u64 = 1 << 54;
const ENABLE_MASK_IS_Y: u64 = 1 << 25;
const MULTIPLE_ROWS: u64 = 1 << 31;

/// `vecint_alu_mode4`: rounding right shift, then optional saturation.
fn reduce(value: i64, saturation_bits: u32, operand: u64) -> i64 {
    let shift = (operand >> 58) & 0x1f;
    let mut value = value;
    if shift != 0 && operand & ROUNDING_SHIFT != 0 {
        value = value.wrapping_add((1u64 << (shift - 1)) as i64);
    }
    value >>= shift;
    if operand & SATURATE != 0 {
        let bits = saturation_bits - u32::from(operand & SIGNED_OUTPUT != 0);
        let high = 1i64 << bits;
        if operand & SIGNED_Z_OR_X != 0 {
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

/// `vecint_alu`.
fn alu(x: i64, y: i64, z: i64, mode: u64, shift: u32) -> i64 {
    let mut value = x.wrapping_mul(y);
    match mode {
        5 | 6 => value = value.wrapping_add((1u64 << (shift - 1)) as i64),
        2 | 3 => value = x.wrapping_add(y),
        9 => {
            let matches = ((!(x ^ y)) as u64).wrapping_shl(shift).count_ones();
            return z.wrapping_add(i64::from(matches));
        }
        11 => value = x,
        12 => value = y,
        _ => {}
    }
    value >>= shift;
    if matches!(mode, 1 | 3 | 6) {
        value = value.wrapping_neg();
    }
    if mode != 10 {
        value = value.wrapping_add(z);
    }
    if matches!(mode, 5 | 6) {
        value = value.clamp(-32768, 32767);
    }
    value
}

const fn sign_extension(signed: bool, bits: u32) -> u32 {
    if signed { 64 - bits } else { 0 }
}

fn zero_lanes(write: bool, value: i64) -> i64 {
    if write { value } else { 0 }
}

pub(super) fn vector(generation: Generation, registers: &mut AmxRegisters, mut operand: u64) {
    if (operand >> 54) & 7 != 0 {
        return;
    }
    let mut z_row = operand >> 20;
    let mut z_step = 64;
    let mut x_step = 64u64;
    let mut y_step = 64u64;
    let mut x_lane_mask = usize::MAX;
    if generation.m2_extensions() && operand & MULTIPLE_ROWS != 0 {
        let broadcast = (operand >> 32) & 7;
        operand &= !(0x1ff << 32);
        match broadcast {
            1 => operand |= 3 << 32,
            2 => x_step = 0,
            3 => y_step = 0,
            4 => operand |= 4 << 32,
            5 => operand |= 5 << 32,
            6 => {
                x_step = 0;
                x_lane_mask = 0;
            }
            7 => {
                y_step = 0;
                operand |= 1 << 38;
            }
            _ => {}
        }
        z_step = if z_row & 32 != 0 { 16 } else { 32 };
    }
    z_row &= z_step - 1;
    let write = (operand >> 32) & 0x1ff != 3;
    let broadcast_y = (operand >> 38) & 7 == 1;
    let mode = if operand & INDEXED_LOAD != 0 {
        0
    } else {
        (operand >> 47) & 0x3f
    };
    let mut shift = ((operand >> 58) & 0x1f) as u32;
    let kind = (operand >> 42) & 0xf;

    if mode == 4 {
        let (z_bits, saturation_bits) = match kind {
            3 => (32, 16),
            4 => (32, 32),
            9 => (8, 8),
            10 => (32, 8),
            11 => (16, 8),
            _ => (16, 16),
        };
        let z_bytes = (z_bits / 8) as usize;
        let signed = sign_extension(operand & SIGNED_Z_OR_X != 0, z_bits);
        let enable = if broadcast_y {
            u64::MAX
        } else {
            write_mask(operand >> 32, z_bytes as u32, 9)
        };
        while z_row <= 63 {
            for index in (0..64).step_by(z_bytes) {
                if (enable >> index) & 1 == 0 {
                    continue;
                }
                let cell = &mut registers.z[z_row as usize][index..index + z_bytes];
                let value = reduce(load_integer(cell, signed), saturation_bits, operand);
                store_integer(cell, zero_lanes(write, value));
            }
            z_row += z_step;
        }
        return;
    }
    if mode >= 7 && !(generation.m2_extensions() && matches!(mode, 10..=12)) {
        return;
    }
    let (x_bits, y_bits, z_bits) = if mode == 5 || mode == 6 {
        shift = 15;
        (16, 16, 16)
    } else {
        match kind {
            3 => (16, 16, 32),
            10 => (8, 8, 32),
            11 => (8, 8, 16),
            12 => (8, 16, 32),
            13 => (16, 8, 32),
            _ => (16, 16, 16),
        }
    };
    let x_bytes = (x_bits / 8) as usize;
    let y_bytes = (y_bits / 8) as usize;
    let z_bytes = (z_bits / 8) as usize;
    let mut x_offset = operand >> 10;
    let mut y_offset = operand;
    let index_bits = if operand & INDEXED_LOAD_4BIT != 0 {
        4
    } else {
        2
    };
    if operand & INDEXED_LOAD != 0 {
        if operand & INDEXED_LOAD_Y != 0 {
            y_step = y_step * u64::from(index_bits) / u64::from(y_bits);
        } else {
            x_step = x_step * u64::from(index_bits) / u64::from(x_bits);
        }
    }
    if generation.aligned_multiple_offsets() && z_step < 64 {
        let indexed = operand & INDEXED_LOAD != 0;
        let indexed_y = operand & INDEXED_LOAD_Y != 0;
        x_offset = aligned_multiple_offset(
            x_offset,
            x_bytes,
            z_step,
            index_bits,
            indexed && !indexed_y,
            x_lane_mask == 0,
        );
        y_offset = aligned_multiple_offset(
            y_offset,
            y_bytes,
            z_step,
            index_bits,
            indexed && indexed_y,
            broadcast_y,
        );
    }
    while z_row <= 63 {
        let mut x = load_pool(&registers.x, x_offset & 0x1ff);
        x_offset = x_offset.wrapping_add(x_step);
        let mut y = load_pool(&registers.y, y_offset & 0x1ff);
        y_offset = y_offset.wrapping_add(y_step);
        if operand & INDEXED_LOAD != 0 {
            let source = ((operand >> 49) & 7) as usize;
            if operand & INDEXED_LOAD_Y != 0 {
                load_indexed(&mut y, &registers.y[source], index_bits, y_bits);
            } else {
                load_indexed(&mut x, &registers.x[source], index_bits, x_bits);
            }
        }
        shuffle(&mut x, (operand >> 29) & 3, x_bytes);
        shuffle(&mut y, (operand >> 27) & 3, y_bytes);

        let (mut x_enable, mut y_enable) = (
            write_mask(operand >> 32, x_bytes as u32, 9),
            write_mask(operand >> 32, y_bytes as u32, 9),
        );
        if broadcast_y {
            x_enable = u64::MAX;
            y_enable = u64::MAX;
        } else if (operand >> 38) & 7 == 0 {
            match (operand >> 32) & 0x3f {
                4 => x = [0; 64],
                5 => y = [0; 64],
                _ => {}
            }
        }
        let x_signed = sign_extension(operand & SIGNED_Z_OR_X != 0, x_bits);
        let y_signed = sign_extension(operand & SIGNED_Y != 0, y_bits);
        let z_signed = 64 - z_bits;
        let step = x_bytes.min(y_bytes);
        let z_mask = (z_bytes / step - 1) as u64;
        for index in (0..64).step_by(step) {
            let xi = index & !(x_bytes - 1) & x_lane_mask;
            if (x_enable >> xi) & 1 == 0 {
                continue;
            }
            let yj = if broadcast_y {
                (((operand >> 32) as usize).wrapping_mul(y_bytes)) & 0x3f
            } else {
                index & !(y_bytes - 1)
            };
            if (y_enable >> yj) & 1 == 0 {
                continue;
            }
            let x_value = load_integer(&x[xi..xi + x_bytes], x_signed);
            let y_value = load_integer(&y[yj..yj + y_bytes], y_signed);
            let row = bit_select(z_row, (index / step) as u64, z_mask) as usize;
            let column = index & !(z_bytes - 1);
            let cell = &mut registers.z[row][column..column + z_bytes];
            let result = alu(x_value, y_value, load_integer(cell, z_signed), mode, shift);
            store_integer(cell, zero_lanes(write, result));
        }
        z_row += z_step;
    }
}

pub(super) fn matrix(generation: Generation, registers: &mut AmxRegisters, operand: u64) {
    if (operand >> 55) & 3 != 0 {
        return;
    }
    if operand & MATRIX_INDEXED_MODE_8 != 0 && operand & INDEXED_LOAD == 0 {
        return;
    }
    let z_row = (operand >> 20) & 3;
    let write = (operand >> 32) & 0x1ff != 3;
    let mode = if operand & INDEXED_LOAD != 0 {
        (operand & MATRIX_INDEXED_MODE_8) >> 51
    } else {
        (operand >> 47) & 0x3f
    };
    let mut shift = ((operand >> 58) & 0x1f) as u32;
    let kind = (operand >> 42) & 0xf;

    if mode == 4 {
        let (z_bits, saturation_bits) = match kind {
            3 => (32, 16),
            4 => (32, 32),
            10 => (32, 8),
            11 => (16, 8),
            _ => (16, 16),
        };
        let z_bytes = (z_bits / 8) as usize;
        let signed = sign_extension(operand & SIGNED_Z_OR_X != 0, z_bits);
        let enable = write_mask(operand >> 32, z_bytes as u32, 9);
        for j in (0..64).step_by(z_bytes) {
            for i in (0..64).step_by(z_bytes) {
                let selector = if operand & ENABLE_MASK_IS_Y != 0 {
                    j
                } else {
                    i
                };
                if (enable >> selector) & 1 == 0 {
                    continue;
                }
                let row = bit_select(j as u64, z_row, z_bytes as u64 - 1) as usize;
                let cell = &mut registers.z[row][i..i + z_bytes];
                let value = reduce(load_integer(cell, signed), saturation_bits, operand);
                store_integer(cell, zero_lanes(write, value));
            }
        }
        return;
    }
    if mode == 7 || mode >= 10 {
        return;
    }
    let (x_bits, y_bits, z_bits) = match mode {
        5 | 6 => {
            shift = 15;
            (16, 16, 16)
        }
        8 => match kind {
            12 if generation.m3_extensions() => (8, 16, 32),
            10 => (8, 8, 32),
            _ => (8, 8, 16),
        },
        9 => {
            let types = match kind {
                3 => (16, 16, 32),
                4 => (32, 32, 32),
                _ => (16, 16, 16),
            };
            shift = 64 - types.0;
            types
        }
        _ => match kind {
            3 => (16, 16, 32),
            _ => (16, 16, 16),
        },
    };
    let x_bytes = (x_bits / 8) as usize;
    let y_bytes = (y_bits / 8) as usize;
    let z_bytes = (z_bits / 8) as usize;
    let mut x = load_pool(&registers.x, (operand >> 10) & 0x1ff);
    let mut y = load_pool(&registers.y, operand & 0x1ff);
    if operand & INDEXED_LOAD != 0 {
        let source = ((operand >> 49) & 7) as usize;
        let index_bits = if operand & INDEXED_LOAD_4BIT != 0 {
            4
        } else {
            2
        };
        if operand & INDEXED_LOAD_Y != 0 {
            load_indexed(&mut y, &registers.y[source], index_bits, y_bits);
        } else {
            load_indexed(&mut x, &registers.x[source], index_bits, x_bits);
        }
    }
    shuffle(&mut x, (operand >> 29) & 3, x_bytes);
    shuffle(&mut y, (operand >> 27) & 3, y_bytes);
    let mask_is_y = operand & ENABLE_MASK_IS_Y != 0;
    let (x_enable, y_enable) = if mask_is_y {
        (u64::MAX, write_mask(operand >> 32, y_bytes as u32, 9))
    } else {
        (write_mask(operand >> 32, x_bytes as u32, 9), u64::MAX)
    };
    if (operand >> 38) & 7 == 0 && matches!((operand >> 32) & 0x3f, 4 | 5) {
        let zeroed: &mut Row = if mask_is_y { &mut y } else { &mut x };
        *zeroed = [0; 64];
    }
    let x_signed = sign_extension(operand & SIGNED_Z_OR_X != 0, x_bits);
    let y_signed = sign_extension(operand & SIGNED_Y != 0, y_bits);
    let z_signed = 64 - z_bits;
    let z_mask = (z_bytes / x_bytes - 1) as u64;
    let step = if x_bytes == 1 { z_bytes } else { x_bytes };
    for j in (0..64).step_by(step) {
        if (y_enable >> j) & 1 == 0 {
            continue;
        }
        for i in (0..64).step_by(x_bytes) {
            if (x_enable >> i) & 1 == 0 {
                continue;
            }
            let x_value = load_integer(&x[i..i + x_bytes], x_signed);
            let y_value = load_integer(&y[j..j + y_bytes], y_signed);
            let row = bit_select(
                bit_select(j as u64, z_row, x_bytes as u64 - 1),
                (i / x_bytes) as u64,
                z_mask,
            ) as usize;
            let column = i & !(z_bytes - 1);
            let cell = &mut registers.z[row][column..column + z_bytes];
            let result = alu(x_value, y_value, load_integer(cell, z_signed), mode, shift);
            store_integer(cell, zero_lanes(write, result));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amx::model::fused::{read_lane, write_lane};

    #[test]
    fn alu_modes_follow_corsix() {
        assert_eq!(alu(3, 4, 10, 0, 0), 22);
        assert_eq!(alu(3, 4, 10, 1, 0), -2);
        assert_eq!(alu(3, 4, 10, 2, 0), 17);
        assert_eq!(alu(3, 4, 10, 3, 0), 3);
        assert_eq!(alu(3, 4, 10, 10, 1), 6);
        assert_eq!(alu(3, 4, 10, 11, 0), 13);
        assert_eq!(alu(3, 4, 10, 12, 0), 14);
        // SQRDMLAH: (x*y + 2^14) >> 15 accumulated and saturated.
        assert_eq!(alu(0x4000, 0x4000, 32767, 5, 15), 32767);
        assert_eq!(alu(0x4000, 0x4000, 0, 6, 15), -8192);
        // Mode 9 counts equal bits within the element: 16 - popcount(3 ^ 5).
        assert_eq!(alu(3, 5, 1, 9, 48), 1 + 14);
        assert_eq!(
            reduce(-5, 8, SATURATE | SIGNED_Z_OR_X | SIGNED_OUTPUT | (1 << 58)),
            -3
        );
        assert_eq!(reduce(1000, 8, SATURATE), 255);
        assert_eq!(reduce(-1, 8, SATURATE), 255);
        assert_eq!(reduce(7, 8, ROUNDING_SHIFT | (1 << 58)), 4);
    }

    #[test]
    fn vector_widening_products_interleave_rows() {
        let mut registers = AmxRegisters::zeroed();
        for lane in 0..32 {
            write_lane(&mut registers.x[0], 2, lane, lane as u64);
            write_lane(&mut registers.y[0], 2, lane, 3);
        }
        // Type 3: i16 x i16 -> i32 across rows 6/7.
        vector(Generation::M2, &mut registers, (3 << 42) | (6 << 20));
        assert_eq!(read_lane(&registers.z[6], 4, 5), 30);
        assert_eq!(read_lane(&registers.z[7], 4, 5), 33);
    }

    #[test]
    fn matrix_int8_accumulates_every_fourth_y_lane() {
        let mut registers = AmxRegisters::zeroed();
        registers.x[0] = [2; 64];
        registers.y[0] = core::array::from_fn(|index| index as u8);
        // Indexed bit 54 is mode 8 only with an indexed load; without it the
        // instruction is ignored.
        matrix(Generation::M2, &mut registers, MATRIX_INDEXED_MODE_8);
        assert!(
            registers
                .z
                .iter()
                .all(|row| row.iter().all(|&byte| byte == 0))
        );
        // Mode 8, type 10: u8 x u8 -> i32, Y lanes 0, 4, 8, ...
        matrix(Generation::M2, &mut registers, (8 << 47) | (10 << 42));
        // Row j | (i & 3), lane i / 4: y[8] * 2 into row 8 + (5 & 3).
        assert_eq!(read_lane(&registers.z[9], 4, 1), 16);
    }

    #[test]
    fn mode_4_reduces_z_in_place() {
        let mut registers = AmxRegisters::zeroed();
        write_lane(&mut registers.z[2], 2, 0, (-300i16) as u16 as u64);
        // Signed 16-bit shift by 2 with signed 8-bit saturation (type 11).
        vector(
            Generation::M2,
            &mut registers,
            (4 << 47)
                | (11 << 42)
                | (2 << 20)
                | (2 << 58)
                | SATURATE
                | SIGNED_OUTPUT
                | SIGNED_Z_OR_X,
        );
        assert_eq!(read_lane(&registers.z[2], 2, 0) as u16 as i16, -75);
        write_lane(&mut registers.z[2], 2, 0, 1000);
        vector(
            Generation::M2,
            &mut registers,
            (4 << 47) | (11 << 42) | (2 << 20) | SATURATE | SIGNED_OUTPUT | SIGNED_Z_OR_X,
        );
        assert_eq!(read_lane(&registers.z[2], 2, 0), 127);
    }
}
