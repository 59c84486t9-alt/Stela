//! `mac16` (corsix `mac16.c`): 16-bit (or i8 from the low byte) integer
//! products, right-shifted by bits 59:55 and accumulated modulo the Z width.
use super::{
    fused::{VECTOR, WIDEN_16_32, read_lane, write_lane},
    load_pool, write_mask,
};
use crate::amx::AmxRegisters;

const Y_INT8: u64 = 1 << 60;
const X_INT8: u64 = 1 << 61;
const SKIP_Z_INPUT: u64 = 1 << 27;

fn alu(x: i64, y: i64, z: i64, operand: u64) -> i64 {
    let x = if operand & X_INT8 != 0 {
        x as i8 as i64
    } else {
        x
    };
    let y = if operand & Y_INT8 != 0 {
        y as i8 as i64
    } else {
        y
    };
    let mut value = match (operand >> 28) & 3 {
        0 => x * y,
        1 => x,
        2 => y,
        _ => 0,
    };
    value >>= (operand >> 55) & 0x1f;
    if operand & SKIP_Z_INPUT == 0 {
        value = value.wrapping_add(z);
    }
    value
}

pub(super) fn execute(registers: &mut AmxRegisters, operand: u64) {
    let x_row = load_pool(&registers.x, (operand >> 10) & 0x1ff);
    let y_row = load_pool(&registers.y, operand & 0x1ff);
    let x_enable = write_mask(operand >> 41, 2, 7);
    let y_enable = write_mask(operand >> 32, 2, 7);
    let z_row = ((operand >> 20) & 63) as usize;
    let lane = |row: &[u8; 64], index: usize| i64::from(read_lane(row, 2, index) as u16 as i16);
    for i in 0..32 {
        if (x_enable >> (i * 2)) & 1 == 0 {
            continue;
        }
        let x = lane(&x_row, i);
        if operand & VECTOR != 0 {
            let z = lane(&registers.z[z_row], i);
            let result = alu(x, lane(&y_row, i), z, operand);
            write_lane(&mut registers.z[z_row], 2, i, result as u64);
            continue;
        }
        for j in 0..32 {
            if (y_enable >> (j * 2)) & 1 == 0 {
                continue;
            }
            let y = lane(&y_row, j);
            if operand & WIDEN_16_32 != 0 {
                let row = j * 2 + (i & 1);
                let z = i64::from(read_lane(&registers.z[row], 4, i >> 1) as u32 as i32);
                write_lane(
                    &mut registers.z[row],
                    4,
                    i >> 1,
                    alu(x, y, z, operand) as u64,
                );
            } else {
                let row = j * 2 + (z_row & 1);
                let z = lane(&registers.z[row], i);
                write_lane(&mut registers.z[row], 2, i, alu(x, y, z, operand) as u64);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widened_products_accumulate_signed_and_shift() {
        let mut registers = AmxRegisters::zeroed();
        for lane in 0..32 {
            write_lane(&mut registers.x[0], 2, lane, (-300i16) as u16 as u64);
            write_lane(&mut registers.y[0], 2, lane, 200);
        }
        for row in 0..64 {
            for lane in 0..16 {
                write_lane(&mut registers.z[row], 4, lane, 7);
            }
        }
        // (-300 * 200) >> 2 + 7 = -15000 + 7.
        execute(&mut registers, WIDEN_16_32 | (2 << 55));
        assert_eq!(read_lane(&registers.z[63], 4, 15) as u32 as i32, -14993);
    }

    #[test]
    fn int8_inputs_use_the_low_byte_and_vectors_wrap() {
        let mut registers = AmxRegisters::zeroed();
        write_lane(&mut registers.x[0], 2, 0, 0x01ff); // i8 -1
        write_lane(&mut registers.y[0], 2, 0, 0x7fff);
        write_lane(&mut registers.z[3], 2, 0, 0x8000);
        // Vector, x as i8: -1 * 32767 + (-32768) wraps to 1.
        execute(&mut registers, VECTOR | X_INT8 | (3 << 20));
        assert_eq!(read_lane(&registers.z[3], 2, 0), 1);
        // Skip X and Y inputs with Z: z + 0.
        execute(&mut registers, VECTOR | (3 << 28) | (3 << 20));
        assert_eq!(read_lane(&registers.z[3], 2, 0), 1);
    }
}
