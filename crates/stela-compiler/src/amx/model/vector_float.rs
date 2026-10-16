//! `vecfp` and `matfp` (corsix `vecfp.c`, `matfp.c`) for M2: bf16 types 0/1,
//! ALU modes 10..12 and the bit-31 multi-row vector forms.
use super::{
    Row, bit_select,
    float::{
        self, BF16_ONE, bf16_fma, bf16_maximum, bf16_minimum, bf16_to_single, half_to_single,
        not_positive,
    },
    fused::{read_lane, write_lane},
    load_indexed, load_pool, shuffle, write_mask,
};
use crate::{aarch64::floating::Format, amx::AmxRegisters};

const INDEXED_LOAD: u64 = 1 << 53;
const INDEXED_LOAD_Y: u64 = 1 << 47;
const INDEXED_LOAD_4BIT: u64 = 1 << 48;
const MULTIPLE_ROWS: u64 = 1 << 31;

/// `vecfp_alu_bf16`.
fn alu_bf16(x: u16, y: u16, z: u16, mode: u64) -> u16 {
    match mode {
        0 => bf16_fma(x, y, z),
        1 => bf16_fma(x ^ 0x8000, y, z),
        4 => {
            if x == 0 || x as i16 <= -128 {
                0
            } else {
                y
            }
        }
        5 => bf16_minimum(x, z),
        7 => bf16_maximum(x, z),
        10 => bf16_fma(x, y, 0x8000),
        11 => bf16_fma(x, BF16_ONE, z),
        12 => bf16_fma(BF16_ONE, y, z),
        _ => z,
    }
}

/// `vecfp_alu16/32/64`.
fn alu(format: Format, x: u64, y: u64, z: u64, mode: u64) -> u64 {
    match mode {
        0 => float::fused(format, false, z, x, y),
        1 => float::fused(format, true, z, x, y),
        4 => {
            if not_positive(format, x) {
                0
            } else {
                y
            }
        }
        5 => float::minimum(format, x, z),
        7 => float::maximum(format, x, z),
        10 => float::multiply(format, x, y),
        11 => float::add(format, z, x),
        12 => float::add(format, z, y),
        _ => z,
    }
}

/// X/Y bits, Z bits and bf16 for the type field 45:42.
fn types(operand: u64) -> (u32, u32, bool) {
    match (operand >> 42) & 0xf {
        0 => (16, 16, true),
        1 => (16, 32, true),
        3 => (16, 32, false),
        4 => (32, 32, false),
        7 => (64, 64, false),
        _ => (16, 16, false),
    }
}

fn format(bits: u32) -> Format {
    match bits {
        16 => Format::Half,
        32 => Format::Single,
        _ => Format::Double,
    }
}

/// One Z lane: either the result or zero when `omask` clears it.
#[allow(clippy::too_many_arguments)]
fn lane(
    registers: &mut AmxRegisters,
    row: usize,
    x: &Row,
    y: &Row,
    (i, xi, j): (usize, usize, usize),
    (xy_bits, z_bits, bf16): (u32, u32, bool),
    write: bool,
    mode: u64,
) {
    let z_bytes = (z_bits / 8) as usize;
    let xy_bytes = (xy_bits / 8) as usize;
    let z_lane = if z_bits == 32 && xy_bits == 16 {
        i >> 1
    } else {
        i
    };
    let z = read_lane(&registers.z[row], z_bytes, z_lane);
    let result = if !write {
        0
    } else if z_bits == 16 && bf16 {
        u64::from(alu_bf16(
            read_lane(x, 2, xi) as u16,
            read_lane(y, 2, j) as u16,
            z as u16,
            mode,
        ))
    } else if z_bits == 32 && xy_bits == 16 {
        let widen = |bits: u64| {
            u64::from(if bf16 {
                bf16_to_single(bits as u16)
            } else {
                half_to_single(bits as u16)
            })
        };
        alu(
            Format::Single,
            widen(read_lane(x, 2, xi)),
            widen(read_lane(y, 2, j)),
            z,
            mode,
        )
    } else {
        alu(
            format(xy_bits),
            read_lane(x, xy_bytes, xi),
            read_lane(y, xy_bytes, j),
            z,
            mode,
        )
    };
    write_lane(&mut registers.z[row], z_bytes, z_lane, result);
}

pub(super) fn vector(registers: &mut AmxRegisters, mut operand: u64) {
    if (operand >> 54) & 7 != 0 {
        return;
    }
    operand &= !(1 << 37);
    let mode = if operand & INDEXED_LOAD != 0 {
        0
    } else {
        (operand >> 47) & 0x3f
    };
    if !matches!(mode, 0 | 1 | 4 | 5 | 7 | 10 | 11 | 12) {
        return;
    }
    let (xy_bits, z_bits, bf16) = types(operand);
    let xy_bytes = (xy_bits / 8) as usize;
    let mut z_row = operand >> 20;
    let mut z_step = 64;
    let mut x_step = 64;
    let mut y_step = 64;
    let mut x_lane_mask = usize::MAX;
    let mut x_offset = operand >> 10;
    let mut y_offset = operand;
    let index_bits = if operand & INDEXED_LOAD_4BIT != 0 {
        4
    } else {
        2
    };
    if operand & MULTIPLE_ROWS != 0 {
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
    if operand & INDEXED_LOAD != 0 {
        if operand & INDEXED_LOAD_Y != 0 {
            y_step = y_step * u64::from(index_bits) / u64::from(xy_bits);
        } else {
            x_step = x_step * u64::from(index_bits) / u64::from(xy_bits);
        }
    }
    z_row &= z_step - 1;
    while z_row <= 63 {
        let mut x = load_pool(&registers.x, x_offset & 0x1ff);
        x_offset = x_offset.wrapping_add(x_step);
        let mut y = load_pool(&registers.y, y_offset & 0x1ff);
        y_offset = y_offset.wrapping_add(y_step);
        if operand & INDEXED_LOAD != 0 {
            let source = ((operand >> 49) & 7) as usize;
            if operand & INDEXED_LOAD_Y != 0 {
                load_indexed(&mut y, &registers.y[source], index_bits, xy_bits);
            } else {
                load_indexed(&mut x, &registers.x[source], index_bits, xy_bits);
            }
        }
        shuffle(&mut x, (operand >> 29) & 3, xy_bytes);
        shuffle(&mut y, (operand >> 27) & 3, xy_bytes);

        let mut x_enable = write_mask(operand >> 32, xy_bytes as u32, 9);
        let broadcast_y = (operand >> 38) & 7 == 1;
        let mut write = true;
        if broadcast_y {
            x_enable = u64::MAX;
        } else if (operand >> 38) & 7 == 0 {
            match (operand >> 32) & 0x3f {
                3 => write = false,
                4 => x = [0; 64],
                5 => y = [0; 64],
                _ => {}
            }
        }
        let lanes = 64 / xy_bytes;
        let y_lane_mask = (lanes - 1) as u64;
        for i in 0..lanes {
            if (x_enable >> (i * xy_bytes)) & 1 == 0 {
                continue;
            }
            let j = if broadcast_y {
                ((operand >> 32) & y_lane_mask) as usize
            } else {
                i
            };
            let row = if z_bits == 32 && xy_bits == 16 {
                bit_select(z_row, i as u64, 1)
            } else {
                z_row
            } as usize;
            lane(
                registers,
                row,
                &x,
                &y,
                (i, i & x_lane_mask, j),
                (xy_bits, z_bits, bf16),
                write,
                mode,
            );
        }
        z_row += z_step;
    }
}

pub(super) fn matrix(registers: &mut AmxRegisters, mut operand: u64) {
    if (operand >> 54) & 7 != 0 {
        return;
    }
    operand &= !(1 << 37);
    operand &= !(1 << 63);
    let mode = if operand & INDEXED_LOAD != 0 {
        0
    } else {
        (operand >> 47) & 0x3f
    };
    if !matches!(mode, 0 | 1 | 4) {
        return;
    }
    let (xy_bits, z_bits, bf16) = types(operand);
    let xy_bytes = (xy_bits / 8) as usize;
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
            load_indexed(&mut y, &registers.y[source], index_bits, xy_bits);
        } else {
            load_indexed(&mut x, &registers.x[source], index_bits, xy_bits);
        }
    }
    shuffle(&mut x, (operand >> 29) & 3, xy_bytes);
    shuffle(&mut y, (operand >> 27) & 3, xy_bytes);
    let x_enable = write_mask(operand >> 32, xy_bytes as u32, 9);
    let y_enable = write_mask(
        (((operand >> 23) & 7) << 6) | (operand >> 58),
        xy_bytes as u32,
        9,
    );
    let mut write = true;
    if (operand >> 38) & 7 == 0 {
        match (operand >> 32) & 0x3f {
            3 => write = false,
            4 | 5 => x = [0; 64],
            _ => {}
        }
    }
    if (operand >> 23) & 7 == 0 {
        match (operand >> 58) & 0x3f {
            3 => write = false,
            4 | 5 => y = [0; 64],
            _ => {}
        }
    }
    let z_row = (operand >> 20) & 7;
    let lanes = 64 / xy_bytes;
    for j in 0..lanes {
        if (y_enable >> (j * xy_bytes)) & 1 == 0 {
            continue;
        }
        for i in 0..lanes {
            if (x_enable >> (i * xy_bytes)) & 1 == 0 {
                continue;
            }
            let row = match (xy_bits, z_bits) {
                (16, 16) => bit_select(j as u64 * 2, z_row, 1),
                (16, 32) => bit_select(j as u64 * 2, i as u64, 1),
                (32, _) => bit_select(j as u64 * 4, z_row, 3),
                _ => bit_select(j as u64 * 8, z_row, 7),
            } as usize;
            lane(
                registers,
                row,
                &x,
                &y,
                (i, i, j),
                (xy_bits, z_bits, bf16),
                write,
                mode,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn splat(row: &mut Row, bytes: usize, value: u64) {
        for lane in 0..64 / bytes {
            write_lane(row, bytes, lane, value);
        }
    }

    #[test]
    fn vector_f32_fma_and_selection_modes() {
        let mut registers = AmxRegisters::zeroed();
        splat(&mut registers.x[0], 4, 2.0f32.to_bits().into());
        splat(&mut registers.y[0], 4, 5.0f32.to_bits().into());
        splat(&mut registers.z[4], 4, 1.0f32.to_bits().into());
        let base = (4 << 42) | (4 << 20);
        vector(&mut registers, base);
        assert_eq!(read_lane(&registers.z[4], 4, 0), 11.0f32.to_bits().into());
        // Mode 1: z - x*y.
        vector(&mut registers, base | (1 << 47));
        assert_eq!(read_lane(&registers.z[4], 4, 7), 1.0f32.to_bits().into());
        // Mode 4: x <= 0 ? 0 : y.
        vector(&mut registers, base | (4 << 47));
        assert_eq!(read_lane(&registers.z[4], 4, 3), 5.0f32.to_bits().into());
        // Reserved bits 56:54 make the instruction a no-op.
        vector(&mut registers, base | (1 << 55) | (11 << 47));
        assert_eq!(read_lane(&registers.z[4], 4, 3), 5.0f32.to_bits().into());
        // Mode 11 (M2): z + x.
        vector(&mut registers, base | (11 << 47));
        assert_eq!(read_lane(&registers.z[4], 4, 3), 7.0f32.to_bits().into());
    }

    #[test]
    fn m2_multiple_rows_and_broadcasts() {
        let mut registers = AmxRegisters::zeroed();
        for row in 0..8 {
            splat(&mut registers.x[row], 4, (row as f32).to_bits().into());
            splat(&mut registers.y[row], 4, 1.0f32.to_bits().into());
        }
        // Bit 31 with selector 0: rows 0 and 32, consecutive X and Y rows,
        // mode 10 (x*y, M2).
        vector(&mut registers, MULTIPLE_ROWS | (10 << 47) | (4 << 42));
        assert_eq!(read_lane(&registers.z[0], 4, 0), 0.0f32.to_bits().into());
        assert_eq!(read_lane(&registers.z[32], 4, 0), 1.0f32.to_bits().into());
        // Broadcast 2 reuses X row 0 for rows 2, 18, 34, 50 (selector 34).
        vector(
            &mut registers,
            MULTIPLE_ROWS | (2 << 32) | (10 << 47) | (4 << 42) | (34 << 20),
        );
        for row in [2, 18, 34, 50] {
            assert_eq!(read_lane(&registers.z[row], 4, 0), 0.0f32.to_bits().into());
        }
        // Broadcast 1 writes zeros.
        splat(&mut registers.z[1], 4, 9);
        vector(
            &mut registers,
            MULTIPLE_ROWS | (1 << 32) | (4 << 42) | (1 << 20),
        );
        assert_eq!(read_lane(&registers.z[1], 4, 3), 0);
    }

    #[test]
    fn mixed_width_and_bf16_vectors() {
        let mut registers = AmxRegisters::zeroed();
        splat(&mut registers.x[0], 2, 0x4000); // f16/bf16 2.0 bit patterns
        splat(&mut registers.y[0], 2, 0x4200);
        // Type 3: f16 -> f32 interleaved across rows 0/1: 2 * 3.
        vector(&mut registers, 3 << 42);
        assert_eq!(read_lane(&registers.z[0], 4, 0), 6.0f32.to_bits().into());
        assert_eq!(read_lane(&registers.z[1], 4, 15), 6.0f32.to_bits().into());
        // Type 1 (M2 bf16 -> f32): 0x4000 is 2.0, 0x4200 is 32.0.
        vector(&mut registers, (1 << 42) | (2 << 20));
        assert_eq!(read_lane(&registers.z[2], 4, 0), 64.0f32.to_bits().into());
        // Type 0 (M2 bf16): 2 * 32 + 0.
        vector(&mut registers, 4 << 20);
        assert_eq!(read_lane(&registers.z[4], 2, 0), 0x4280);
    }

    #[test]
    fn matrix_outer_products_and_y_masks() {
        let mut registers = AmxRegisters::zeroed();
        for lane in 0..8 {
            write_lane(&mut registers.x[0], 8, lane, (lane as f64).to_bits());
            write_lane(&mut registers.y[0], 8, lane, 2.0f64.to_bits());
        }
        // f64, Z offset 3, Y mode 2 (first n=2 lanes): rows 3 and 11 only.
        let operand = (7 << 42) | (3 << 20) | (2 << 23) | (2 << 58);
        matrix(&mut registers, operand);
        assert_eq!(read_lane(&registers.z[3], 8, 5), 10.0f64.to_bits());
        assert_eq!(read_lane(&registers.z[11], 8, 7), 14.0f64.to_bits());
        assert_eq!(read_lane(&registers.z[19], 8, 7), 0);
        // Mode 2/3 and >= 5 are no-ops.
        matrix(&mut registers, (7 << 42) | (3 << 20) | (5 << 47));
        assert_eq!(read_lane(&registers.z[19], 8, 7), 0);
    }

    #[test]
    fn indexed_x_expands_two_bit_lane_indices() {
        let mut registers = AmxRegisters::zeroed();
        // Table X row 3: f32 lanes 0..3 = 10, 20, 30, 40.
        for lane in 0..4 {
            write_lane(
                &mut registers.x[3],
                4,
                lane,
                ((lane + 1) as f32 * 10.0).to_bits().into(),
            );
        }
        // Indices 3, 2, 1, 0, ... packed at X offset 0.
        registers.x[0][..4].copy_from_slice(&[0x1b, 0x1b, 0x1b, 0x1b]);
        splat(&mut registers.y[0], 4, 1.0f32.to_bits().into());
        vector(
            &mut registers,
            INDEXED_LOAD | (3 << 49) | (4 << 42) | (1 << 52),
        );
        // Indexed loads force ALU mode 0 (bit 52 alone would select a
        // no-op mode): z + x*y with z = 0.
        assert_eq!(read_lane(&registers.z[0], 4, 0), 40.0f32.to_bits().into());
        assert_eq!(read_lane(&registers.z[0], 4, 3), 10.0f32.to_bits().into());
    }
}
