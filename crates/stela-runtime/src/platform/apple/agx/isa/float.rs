//! Number formats the AGX2 ALUs read and write: Mesa's 8-bit minifloat
//! immediates, IEEE half conversions, and a fused multiply-add rounded once.

/// Mesa `agx_minifloat_decode`: sign, 3 exponent and 4 mantissa bits.
pub fn minifloat(value: u8) -> f32 {
    let sign = if value & 0x80 != 0 { -1.0 } else { 1.0 };
    let exponent = i32::from((value >> 4) & 7);
    let mantissa = f32::from(value & 0xf);
    let (significand, scale) = if exponent != 0 {
        (mantissa + 16.0, exponent - 7)
    } else {
        (mantissa, -6)
    };
    sign * significand * pow2(scale)
}

fn pow2(exponent: i32) -> f32 {
    f32::from_bits(((127 + exponent) as u32) << 23)
}

/// An IEEE half as f32 (exact).
pub fn half_to_f32(half: u16) -> f32 {
    let sign = u32::from(half >> 15) << 31;
    let exponent = u32::from((half >> 10) & 0x1f);
    let mantissa = u32::from(half & 0x3ff);
    let bits = match (exponent, mantissa) {
        (0, 0) => sign,
        (0, _) => {
            // Subnormal: normalize.
            let shift = mantissa.leading_zeros() - 21;
            let mantissa = (mantissa << shift) & 0x3ff;
            sign | (127 - 15 + 1 - shift) << 23 | mantissa << 13
        }
        (0x1f, 0) => sign | 0xff << 23,
        (0x1f, _) => sign | 0xff << 23 | mantissa << 13 | 1 << 22,
        _ => sign | (exponent + 127 - 15) << 23 | mantissa << 13,
    };
    f32::from_bits(bits)
}

/// f32 rounded to an IEEE half, nearest even.
pub fn f32_to_half(value: f32) -> u16 {
    let bits = value.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exponent = ((bits >> 23) & 0xff) as i32;
    let mantissa = bits & 0x7f_ffff;
    if exponent == 0xff {
        return sign | 0x7c00 | if mantissa != 0 { 0x200 } else { 0 };
    }
    let unbiased = exponent - 127;
    if unbiased > 15 {
        return sign | 0x7c00;
    }
    // The significand with its implicit bit, and how far to shift it right
    // to land on the half's mantissa (subnormals shift further).
    let (significand, shift) = if exponent == 0 {
        (mantissa, 126 - 14 + 13)
    } else if unbiased >= -14 {
        (mantissa | 1 << 23, 13)
    } else {
        (mantissa | 1 << 23, 13 + (-14 - unbiased) as u32)
    };
    if shift > 24 {
        return sign;
    }
    let kept = significand >> shift;
    let rest = significand & ((1 << shift) - 1);
    let half_way = 1 << (shift - 1);
    let rounded = kept + u32::from(rest > half_way || (rest == half_way && kept & 1 != 0));
    let magnitude = if unbiased >= -14 {
        // Normal: the exponent field adds; a mantissa carry bumps it.
        (((unbiased + 15) as u32) << 10) + (rounded - (1 << 10))
    } else {
        rounded
    };
    sign | magnitude as u16
}

/// `a * b + c` rounded once to f32: the f64 product is exact, the f64 sum is
/// made round-to-odd, and rounding that to f32 is then correct.
pub fn fused_multiply_add(a: f32, b: f32, c: f32) -> f32 {
    let product = f64::from(a) * f64::from(b);
    let addend = f64::from(c);
    let sum = product + addend;
    if !sum.is_finite() || !product.is_finite() {
        return sum as f32;
    }
    // Two-sum: the exact error of `sum`.
    let virtual_addend = sum - product;
    let virtual_product = sum - virtual_addend;
    let error = (product - virtual_product) + (addend - virtual_addend);
    let bits = sum.to_bits();
    if error != 0.0 && bits & 1 == 0 {
        let toward_zero = (error > 0.0) != (sum > 0.0) && sum != 0.0;
        let odd = if toward_zero { bits - 1 } else { bits + 1 };
        return f64::from_bits(odd) as f32;
    }
    sum as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fused_multiply_add_rounds_once() {
        // (1 + 2^-23)^2 - (1 + 2^-22) = 2^-46, which a rounded product loses.
        let a = 1.0 + f32::EPSILON;
        let c = -(1.0 + 2.0 * f32::EPSILON);
        assert_eq!(fused_multiply_add(a, a, c), f32::EPSILON * f32::EPSILON);
        assert_eq!(a * a + c, 0.0);
        assert_eq!(fused_multiply_add(2.0, 3.0, 1.0), 7.0);
        assert!(fused_multiply_add(f32::INFINITY, 0.0, 1.0).is_nan());
    }

    #[test]
    fn half_conversions_are_exact_and_round_to_nearest_even() {
        for (half, value) in [
            (0x3c00, 1.0),
            (0xc000, -2.0),
            (0x0001, 5.960_464_5e-8),
            (0x03ff, 6.097_555e-5),
            (0x7bff, 65504.0),
            (0x7c00, f32::INFINITY),
        ] {
            assert_eq!(half_to_f32(half), value);
            assert_eq!(f32_to_half(value), half);
        }
        // 1 + 2^-11 is halfway between 1 and 1 + 2^-10: ties to even (1).
        assert_eq!(f32_to_half(1.0 + 2f32.powi(-11)), 0x3c00);
        assert_eq!(f32_to_half(1.0 + 3.0 * 2f32.powi(-11)), 0x3c02);
        assert_eq!(f32_to_half(70000.0), 0x7c00);
        assert!(half_to_f32(f32_to_half(f32::NAN)).is_nan());
        // The largest half subnormal rounds up into the normal range.
        assert_eq!(f32_to_half(6.102e-5), 0x0400);
        assert_eq!(f32_to_half(6.1e-5), 0x03ff);
    }
}
