//! Per-channel number conversions shared by memory instructions, the
//! tilebuffer, texture sampling and the PBE: normalized integers, sRGB, and
//! the packed small-float formats.
//!
//! The definitions are the API ones the hardware implements (Public: the
//! Vulkan/Metal format specifications; Mesa `util/format` for the packed
//! layouts `R10G10B10A2`, `R11G11B10_FLOAT` and `R9G9B9E5_FLOAT`).
//! Float-to-normalized conversion clamps (NaN to 0) and rounds to nearest
//! even, as Metal's conversion rules require.

use crate::platform::apple::agx::isa::float::round_even;
use crate::platform::apple::agx::isa::math;

/// The largest value of an unsigned `bits`-bit integer, as f64.
fn unsigned_max(bits: u32) -> f64 {
    ((1u64 << bits) - 1) as f64
}

pub fn unorm_to_float(value: u32, bits: u32) -> f64 {
    f64::from(value & ((1u64 << bits) - 1) as u32) / unsigned_max(bits)
}

pub fn snorm_to_float(value: u32, bits: u32) -> f64 {
    let shift = 32 - bits;
    let signed = ((value << shift) as i32) >> shift;
    (f64::from(signed) / unsigned_max(bits - 1)).max(-1.0)
}

pub fn float_to_unorm(value: f64, bits: u32) -> u32 {
    round_even(math::saturate(value) * unsigned_max(bits)) as u32
}

pub fn float_to_snorm(value: f64, bits: u32) -> u32 {
    let clamped = if value.is_nan() {
        0.0
    } else {
        value.clamp(-1.0, 1.0)
    };
    let integer = round_even(clamped * unsigned_max(bits - 1)) as i32;
    (integer as u32) & ((1u64 << bits) - 1) as u32
}

/// `x^y` for `x > 0`.
fn power(x: f64, y: f64) -> f64 {
    math::exp2(y * math::log2(x))
}

/// The sRGB electro-optical transfer function.
pub fn srgb_to_linear(value: f64) -> f64 {
    if value <= 0.04045 {
        value / 12.92
    } else {
        power((value + 0.055) / 1.055, 2.4)
    }
}

/// Its inverse, on a value clamped to [0, 1] (NaN to 0).
pub fn linear_to_srgb(value: f64) -> f64 {
    let value = math::saturate(value);
    if value <= 0.003_130_8 {
        value * 12.92
    } else {
        1.055 * power(value, 1.0 / 2.4) - 0.055
    }
}

/// An unsigned float with a five-bit exponent (bias 15) and `mantissa`
/// bits: the R11G11B10 channels.
pub fn unsigned_small_float_to_float(value: u32, mantissa: u32) -> f64 {
    let exponent = (value >> mantissa) & 0x1f;
    let fraction = value & ((1 << mantissa) - 1);
    let scale = f64::from(1u32 << mantissa);
    match exponent {
        0 => f64::from(fraction) / scale * math_pow2(-14),
        0x1f if fraction == 0 => f64::INFINITY,
        0x1f => f64::NAN,
        _ => (1.0 + f64::from(fraction) / scale) * math_pow2(exponent as i32 - 15),
    }
}

/// Encode an unsigned small float, to nearest even or toward zero.
/// Negative values become 0, NaN keeps a NaN encoding, and values past the
/// largest finite one become infinity (nearest) or that maximum (toward
/// zero).
pub fn float_to_unsigned_small_float(value: f64, mantissa: u32, toward_zero: bool) -> u32 {
    let infinity = 0x1f << mantissa;
    if value.is_nan() {
        return infinity | 1;
    }
    if value <= 0.0 {
        return 0;
    }
    let largest = infinity - 1;
    if value.is_infinite() {
        return if toward_zero { largest } else { infinity };
    }
    let scale = f64::from(1u32 << mantissa);
    // The step at the value's binade (subnormals share 2^-14's).
    let exponent = binade(value).max(-14);
    let step = math_pow2(exponent) / scale;
    let units = value / step;
    let units = if toward_zero {
        math::floor(units)
    } else {
        round_even(units)
    };
    // `units` counts steps within the binade starting at 2^exponent; rebuild
    // the encoding, carrying into the next binade when rounding overflowed.
    let encoded = if exponent == -14 && units < scale {
        units as u32
    } else {
        let biased = (exponent + 15) as u32;
        (biased << mantissa) + (units as u32 - (1 << mantissa))
    };
    if encoded > largest {
        if toward_zero { largest } else { infinity }
    } else {
        encoded
    }
}

/// floor(log2(value)) for a positive finite value.
fn binade(value: f64) -> i32 {
    let bits = value.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    if exponent == 0 {
        // f64 subnormals are far below any small float.
        -1074
    } else {
        exponent - 1023
    }
}

fn math_pow2(exponent: i32) -> f64 {
    crate::platform::apple::agx::isa::float::pow2_f64(exponent)
}

/// R11G11B10_FLOAT channel widths of mantissa.
pub const R11_MANTISSA: u32 = 6;
pub const B10_MANTISSA: u32 = 5;

pub fn unpack_r11g11b10(word: u32) -> [f64; 3] {
    [
        unsigned_small_float_to_float(word & 0x7ff, R11_MANTISSA),
        unsigned_small_float_to_float(word >> 11 & 0x7ff, R11_MANTISSA),
        unsigned_small_float_to_float(word >> 22 & 0x3ff, B10_MANTISSA),
    ]
}

pub fn pack_r11g11b10(rgb: [f64; 3], toward_zero: bool) -> u32 {
    float_to_unsigned_small_float(rgb[0], R11_MANTISSA, toward_zero)
        | float_to_unsigned_small_float(rgb[1], R11_MANTISSA, toward_zero) << 11
        | float_to_unsigned_small_float(rgb[2], B10_MANTISSA, toward_zero) << 22
}

/// RGB9E5: three nine-bit mantissas sharing a five-bit exponent (bias 15).
const RGB9E5_MANTISSA: u32 = 9;
const RGB9E5_BIAS: i32 = 15;
const RGB9E5_MAX_EXPONENT: i32 = 31;

pub fn unpack_rgb9e5(word: u32) -> [f64; 3] {
    let exponent = (word >> 27) as i32 - RGB9E5_BIAS - RGB9E5_MANTISSA as i32;
    let scale = math_pow2(exponent);
    [
        f64::from(word & 0x1ff) * scale,
        f64::from(word >> 9 & 0x1ff) * scale,
        f64::from(word >> 18 & 0x1ff) * scale,
    ]
}

/// The shared-exponent encoding (the GL `EXT_texture_shared_exponent`
/// algorithm), rounding the mantissas to nearest or toward zero.
pub fn pack_rgb9e5(rgb: [f64; 3], toward_zero: bool) -> u32 {
    let max_mantissa = f64::from((1u32 << RGB9E5_MANTISSA) - 1);
    let largest = max_mantissa / f64::from(1u32 << RGB9E5_MANTISSA)
        * math_pow2(RGB9E5_MAX_EXPONENT - RGB9E5_BIAS);
    let clamp = |c: f64| {
        if c.is_nan() {
            0.0
        } else {
            c.clamp(0.0, largest)
        }
    };
    let [r, g, b] = rgb.map(clamp);
    let maximum = r.max(g).max(b);
    let mut shared = if maximum == 0.0 {
        -RGB9E5_BIAS - 1
    } else {
        binade(maximum)
    }
    .max(-RGB9E5_BIAS - 1)
        + 1
        + RGB9E5_BIAS;
    let quantize = |c: f64, shared: i32| {
        let units = c / math_pow2(shared - RGB9E5_BIAS - RGB9E5_MANTISSA as i32);
        if toward_zero {
            math::floor(units)
        } else {
            round_even(units)
        }
    };
    if quantize(maximum, shared) > max_mantissa {
        shared += 1;
    }
    let [r, g, b] = [r, g, b].map(|c| quantize(c, shared).min(max_mantissa) as u32);
    (shared as u32) << 27 | b << 18 | g << 9 | r
}

pub fn unpack_rgb10a2(word: u32) -> [f64; 4] {
    [
        unorm_to_float(word, 10),
        unorm_to_float(word >> 10, 10),
        unorm_to_float(word >> 20, 10),
        unorm_to_float(word >> 30, 2),
    ]
}

pub fn pack_rgb10a2(rgba: [f64; 4]) -> u32 {
    float_to_unorm(rgba[0], 10)
        | float_to_unorm(rgba[1], 10) << 10
        | float_to_unorm(rgba[2], 10) << 20
        | float_to_unorm(rgba[3], 2) << 30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_integers_round_trip_and_clamp() {
        assert_eq!(unorm_to_float(255, 8), 1.0);
        assert_eq!(float_to_unorm(0.5, 8), 128);
        assert_eq!(float_to_unorm(f64::NAN, 8), 0);
        assert_eq!(float_to_unorm(2.0, 8), 255);
        assert_eq!(snorm_to_float(0x80, 8), -1.0);
        assert_eq!(snorm_to_float(0x81, 8), -1.0);
        assert_eq!(snorm_to_float(0x7f, 8), 1.0);
        assert_eq!(float_to_snorm(-1.0, 8), 0x81);
        assert_eq!(float_to_snorm(1.0, 16), 0x7fff);
    }

    #[test]
    fn srgb_matches_the_transfer_function() {
        for i in 0..=255u32 {
            let encoded = f64::from(i) / 255.0;
            let back = linear_to_srgb(srgb_to_linear(encoded));
            assert!((back - encoded).abs() < 1e-12, "{i}");
        }
        assert!((srgb_to_linear(0.5) - 0.214_041_140_482_232_5).abs() < 1e-12);
    }

    #[test]
    fn small_floats_round_trip() {
        for (value, encoded) in [(1.0, 0x3c0), (0.5, 0x380), (65024.0, 0x7bf), (0.0, 0)] {
            assert_eq!(
                float_to_unsigned_small_float(value, R11_MANTISSA, false),
                encoded
            );
            assert_eq!(unsigned_small_float_to_float(encoded, R11_MANTISSA), value);
        }
        assert_eq!(float_to_unsigned_small_float(-3.0, R11_MANTISSA, false), 0);
        assert_eq!(
            float_to_unsigned_small_float(1e9, R11_MANTISSA, false),
            0x7c0
        );
        assert_eq!(
            float_to_unsigned_small_float(1e9, R11_MANTISSA, true),
            0x7bf
        );
        // 1 + 1/128 is halfway between 1 and 1 + 1/64: ties to even.
        assert_eq!(
            float_to_unsigned_small_float(1.0 + 1.0 / 128.0, R11_MANTISSA, false),
            0x3c0
        );
        let packed = pack_r11g11b10([1.0, 2.0, 0.25], false);
        assert_eq!(unpack_r11g11b10(packed), [1.0, 2.0, 0.25]);
    }

    #[test]
    fn shared_exponent_round_trips() {
        for rgb in [[1.0, 0.5, 0.25], [0.0, 0.0, 0.0], [3.0, 100.0, 0.25]] {
            assert_eq!(unpack_rgb9e5(pack_rgb9e5(rgb, false)), rgb);
        }
        let rgba = [1.0, 0.0, 1.0 / 1023.0, 1.0];
        assert_eq!(unpack_rgb10a2(pack_rgb10a2(rgba)), rgba);
    }
}
