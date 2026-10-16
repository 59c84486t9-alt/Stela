//! `fma16 fma32 fma64 fms16 fms32 fms64` (corsix `fma.c`, `fms.c`).
//!
//! Bit 63 selects a vector (pointwise) product; otherwise each enabled X lane
//! multiplies each enabled Y lane into the Z grid. Bits 29:27 drop X, Y or Z
//! inputs. `fma16` bit 62 accumulates into f32 interleaved row pairs and
//! `fma32` bits 61/60 read the even f16 lanes of X/Y.
use super::{
    Row,
    float::{self, half_to_single, sign_mask},
    load_pool, write_mask,
};
use crate::{
    aarch64::floating::Format,
    amx::{AmxOperation, AmxRegisters},
};

pub(crate) const VECTOR: u64 = 1 << 63;
pub(crate) const WIDEN_16_32: u64 = 1 << 62;
pub(crate) const X_HALF: u64 = 1 << 61;
pub(crate) const Y_HALF: u64 = 1 << 60;

/// One lane of `fma*_alu` or `fms*_alu`.
pub(crate) fn alu(format: Format, subtract: bool, x: u64, y: u64, z: u64, operand: u64) -> u64 {
    let sign = sign_mask(format);
    match ((operand >> 27) & 7, subtract) {
        (0, _) => float::fused(format, subtract, z, x, y),
        (1, false) => float::multiply(format, x, y),
        (1, true) => float::fused(format, true, sign, x, y),
        (2, false) => float::add(format, z, x),
        (2, true) => float::subtract(format, z, x),
        (3, false) => x,
        (3, true) => x ^ sign,
        (4, false) => float::add(format, z, y),
        (4, true) => float::subtract(format, z, y),
        (5, false) => y,
        (5, true) => y ^ sign,
        (6, _) => z,
        (7, false) => 0,
        (7, true) => sign,
        _ => unreachable!("three-bit field"),
    }
}

pub(crate) fn read_lane(row: &Row, bytes: usize, lane: usize) -> u64 {
    let mut value = [0u8; 8];
    value[..bytes].copy_from_slice(&row[lane * bytes..lane * bytes + bytes]);
    u64::from_le_bytes(value)
}

pub(crate) fn write_lane(row: &mut Row, bytes: usize, lane: usize, value: u64) {
    row[lane * bytes..lane * bytes + bytes].copy_from_slice(&value.to_le_bytes()[..bytes]);
}

/// The even f16 lanes widened to f32; `fms32` negates a resulting NaN.
fn widen_halves(row: &Row, negate_nan: bool) -> [u64; 16] {
    core::array::from_fn(|lane| {
        let value = half_to_single(read_lane(row, 4, lane) as u16);
        let nan = value & 0x7fff_ffff > 0x7f80_0000;
        u64::from(if negate_nan && nan {
            value ^ 0x8000_0000
        } else {
            value
        })
    })
}

pub(super) fn execute(registers: &mut AmxRegisters, operation: AmxOperation, operand: u64) {
    let (format, subtract) = match operation {
        AmxOperation::Fma64 => (Format::Double, false),
        AmxOperation::Fms64 => (Format::Double, true),
        AmxOperation::Fma32 => (Format::Single, false),
        AmxOperation::Fms32 => (Format::Single, true),
        AmxOperation::Fma16 => (Format::Half, false),
        AmxOperation::Fms16 => (Format::Half, true),
        _ => unreachable!("fused dispatch"),
    };
    let bytes = (format.bits() / 8) as usize;
    let lanes = 64 / bytes;
    let x_row = load_pool(&registers.x, (operand >> 10) & 0x1ff);
    let y_row = load_pool(&registers.y, operand & 0x1ff);
    let x_enable = write_mask(operand >> 41, bytes as u32, 7);
    let y_enable = write_mask(operand >> 32, bytes as u32, 7);
    let z_row = ((operand >> 20) & 63) as usize;
    let (x, y): ([u64; 32], [u64; 32]) = if format == Format::Single {
        let mut x = [0; 32];
        let mut y = [0; 32];
        let wide = |row: &Row, half: bool| {
            if half {
                widen_halves(row, subtract)
            } else {
                core::array::from_fn(|lane| read_lane(row, 4, lane))
            }
        };
        x[..16].copy_from_slice(&wide(&x_row, operand & X_HALF != 0));
        y[..16].copy_from_slice(&wide(&y_row, operand & Y_HALF != 0));
        (x, y)
    } else {
        (
            core::array::from_fn(|lane| {
                if lane < lanes {
                    read_lane(&x_row, bytes, lane)
                } else {
                    0
                }
            }),
            core::array::from_fn(|lane| {
                if lane < lanes {
                    read_lane(&y_row, bytes, lane)
                } else {
                    0
                }
            }),
        )
    };
    for i in 0..lanes {
        if (x_enable >> (i * bytes)) & 1 == 0 {
            continue;
        }
        if operand & VECTOR != 0 {
            let z = read_lane(&registers.z[z_row], bytes, i);
            let result = alu(format, subtract, x[i], y[i], z, operand);
            write_lane(&mut registers.z[z_row], bytes, i, result);
            continue;
        }
        for (j, &y_lane) in y.iter().enumerate().take(lanes) {
            if (y_enable >> (j * bytes)) & 1 == 0 {
                continue;
            }
            if format == Format::Half && operand & WIDEN_16_32 != 0 {
                // Interleaved f32 pairs: even X lanes in even rows.
                let widen = |half: u64| {
                    let value = half_to_single(half as u16);
                    let nan = value & 0x7fff_ffff > 0x7f80_0000;
                    u64::from(if subtract && nan {
                        value ^ 0x8000_0000
                    } else {
                        value
                    })
                };
                let row = j * 2 + (i & 1);
                let z = read_lane(&registers.z[row], 4, i >> 1);
                let result = alu(
                    Format::Single,
                    subtract,
                    widen(x[i]),
                    widen(y_lane),
                    z,
                    operand,
                );
                write_lane(&mut registers.z[row], 4, i >> 1, result);
            } else {
                let row = j * (64 / lanes) + (z_row & (64 / lanes - 1));
                let z = read_lane(&registers.z[row], bytes, i);
                let result = alu(format, subtract, x[i], y_lane, z, operand);
                write_lane(&mut registers.z[row], bytes, i, result);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_F32: u64 = 0x3f80_0000;
    const TWO_F32: u64 = 0x4000_0000;

    fn splat(row: &mut Row, bytes: usize, value: u64) {
        for lane in 0..64 / bytes {
            write_lane(row, bytes, lane, value);
        }
    }

    #[test]
    fn fma32_matrix_is_an_outer_product_on_every_fourth_row() {
        let mut registers = AmxRegisters::zeroed();
        for lane in 0..16 {
            write_lane(
                &mut registers.x[0],
                4,
                lane,
                u64::from((lane as f32).to_bits()),
            );
            write_lane(
                &mut registers.y[0],
                4,
                lane,
                u64::from((lane as f32 + 1.0).to_bits()),
            );
        }
        for row in 0..64 {
            splat(&mut registers.z[row], 4, ONE_F32);
        }
        // Z row offset 2 selects rows 2, 6, 10, ...
        execute(&mut registers, AmxOperation::Fma32, 2 << 20);
        for j in 0..16 {
            for i in 0..16 {
                let expected = 1.0 + i as f32 * (j as f32 + 1.0);
                let value = f32::from_bits(read_lane(&registers.z[j * 4 + 2], 4, i) as u32);
                assert_eq!(value, expected);
                assert_eq!(read_lane(&registers.z[j * 4], 4, i), ONE_F32);
            }
        }
    }

    #[test]
    fn fms64_vector_masks_and_skip_modes() {
        let mut registers = AmxRegisters::zeroed();
        splat(&mut registers.x[1], 8, 2.0f64.to_bits());
        splat(&mut registers.y[1], 8, 3.0f64.to_bits());
        splat(&mut registers.z[9], 8, 10.0f64.to_bits());
        // Vector, X offset 64, Y offset 64, first two lanes (mode 2, n=2).
        let operand = VECTOR | (2 << 46) | (2 << 41) | (9 << 20) | (64 << 10) | 64;
        execute(&mut registers, AmxOperation::Fms64, operand);
        assert_eq!(read_lane(&registers.z[9], 8, 0), 4.0f64.to_bits());
        assert_eq!(read_lane(&registers.z[9], 8, 1), 4.0f64.to_bits());
        assert_eq!(read_lane(&registers.z[9], 8, 2), 10.0f64.to_bits());
        // Skip Z: -0 - x*y.
        execute(&mut registers, AmxOperation::Fms64, operand | (1 << 27));
        assert_eq!(read_lane(&registers.z[9], 8, 0), (-6.0f64).to_bits());
        // Skip all: fms writes -0, fma writes +0.
        execute(&mut registers, AmxOperation::Fms64, operand | (7 << 27));
        assert_eq!(read_lane(&registers.z[9], 8, 0), 1 << 63);
        execute(&mut registers, AmxOperation::Fma64, operand | (7 << 27));
        assert_eq!(read_lane(&registers.z[9], 8, 0), 0);
    }

    #[test]
    fn fma16_widening_interleaves_row_pairs() {
        let mut registers = AmxRegisters::zeroed();
        splat(&mut registers.x[0], 2, 0x4000); // 2.0
        splat(&mut registers.y[0], 2, 0x4200); // 3.0
        execute(&mut registers, AmxOperation::Fma16, WIDEN_16_32);
        for row in 0..64 {
            for lane in 0..16 {
                assert_eq!(read_lane(&registers.z[row], 4, lane), 0x40c0_0000);
            }
        }
    }

    #[test]
    fn fma32_reads_even_halves_and_fms32_negates_their_nans() {
        let mut registers = AmxRegisters::zeroed();
        splat(&mut registers.x[0], 4, 0x1234_3c00); // even half 1.0
        splat(&mut registers.y[0], 4, TWO_F32);
        execute(&mut registers, AmxOperation::Fma32, VECTOR | X_HALF);
        assert_eq!(read_lane(&registers.z[0], 4, 0), TWO_F32);
        // Skip Y and Z: fms32 returns -x, so the negated default NaN flips back.
        splat(&mut registers.x[0], 4, 0x7c01);
        execute(
            &mut registers,
            AmxOperation::Fms32,
            VECTOR | X_HALF | (3 << 27),
        );
        assert_eq!(read_lane(&registers.z[0], 4, 0), 0x7fc0_0000);
        execute(
            &mut registers,
            AmxOperation::Fma32,
            VECTOR | X_HALF | (3 << 27),
        );
        assert_eq!(read_lane(&registers.z[0], 4, 0), 0x7fc0_0000);
        // Raw X passes through unchanged when not widened.
        splat(&mut registers.x[0], 4, 0xff80_0001);
        execute(&mut registers, AmxOperation::Fma32, VECTOR | (3 << 27));
        assert_eq!(read_lane(&registers.z[0], 4, 0), 0xff80_0001);
    }

    #[test]
    fn invalid_products_yield_the_default_nan() {
        let mut registers = AmxRegisters::zeroed();
        splat(&mut registers.x[0], 4, 0x7f80_0000);
        execute(&mut registers, AmxOperation::Fma32, VECTOR);
        assert_eq!(read_lane(&registers.z[0], 4, 5), 0x7fc0_0000);
    }
}
