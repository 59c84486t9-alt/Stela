//! Lane arithmetic in the AMX floating-point environment: round to nearest
//! even, no flushing, default NaN, no status. IEEE half, single and double use
//! Stela's Arm evaluators with FPCR.DN; bf16 uses the corsix integer routines.
use crate::aarch64::floating::{
    self, BinaryOperation, FPCR_DN, Format,
    fused::{self, FusedOperation},
    minmax::{self, MinMaxOperation},
    precision::{self, PrecisionRounding},
};

/// The only FPCR corsix compared with hardware.
const ENVIRONMENT: u32 = FPCR_DN;
const DISABLED: &str = "the AMX environment enables no FP exception traps";

/// `z + x*y` (FMADD) or `z - x*y` (FMSUB), rounded once.
pub(super) fn fused(format: Format, subtract: bool, z: u64, x: u64, y: u64) -> u64 {
    let operation = if subtract {
        FusedOperation::Subtract
    } else {
        FusedOperation::Add
    };
    fused::evaluate(format, operation, ENVIRONMENT, z, x, y)
        .expect(DISABLED)
        .bits
}

pub(super) fn multiply(format: Format, x: u64, y: u64) -> u64 {
    floating::evaluate(format, BinaryOperation::Multiply, ENVIRONMENT, x, y)
        .expect(DISABLED)
        .bits
}

pub(super) fn add(format: Format, x: u64, y: u64) -> u64 {
    floating::evaluate(format, BinaryOperation::Add, ENVIRONMENT, x, y)
        .expect(DISABLED)
        .bits
}

pub(super) fn subtract(format: Format, x: u64, y: u64) -> u64 {
    floating::evaluate(format, BinaryOperation::Subtract, ENVIRONMENT, x, y)
        .expect(DISABLED)
        .bits
}

/// FMIN/FMAX: a NaN operand yields the default NaN; -0 orders below +0.
pub(super) fn minimum(format: Format, x: u64, y: u64) -> u64 {
    minmax::evaluate(format, MinMaxOperation::Minimum, ENVIRONMENT, x, y)
        .expect(DISABLED)
        .bits
}

pub(super) fn maximum(format: Format, x: u64, y: u64) -> u64 {
    minmax::evaluate(format, MinMaxOperation::Maximum, ENVIRONMENT, x, y)
        .expect(DISABLED)
        .bits
}

/// FCVT S, H: exact, except that a NaN becomes the default NaN.
pub(super) fn half_to_single(bits: u16) -> u32 {
    precision::evaluate(
        Format::Half,
        Format::Single,
        PrecisionRounding::Fpcr,
        ENVIRONMENT,
        u64::from(bits),
    )
    .expect(DISABLED)
    .bits as u32
}

/// FCVT H, S, rounding to nearest even.
pub(super) fn single_to_half(bits: u32) -> u16 {
    precision::evaluate(
        Format::Single,
        Format::Half,
        PrecisionRounding::Fpcr,
        ENVIRONMENT,
        u64::from(bits),
    )
    .expect(DISABLED)
    .bits as u16
}

fn is_nan(format: Format, bits: u64) -> bool {
    let sign = 1u64 << (format.bits() - 1);
    let magnitude = bits & (sign - 1);
    let infinity = match format {
        Format::Half => 0x7c00,
        Format::Single => 0x7f80_0000,
        Format::Double => 0x7ff0_0000_0000_0000,
    };
    magnitude > infinity
}

/// An order key for non-NaN values; both zeros map to zero.
fn order(format: Format, bits: u64) -> i128 {
    let sign = 1u64 << (format.bits() - 1);
    let magnitude = i128::from(bits & (sign - 1));
    if bits & sign != 0 {
        -magnitude
    } else {
        magnitude
    }
}

/// IEEE `x <= 0`; false for NaN.
pub(super) fn not_positive(format: Format, x: u64) -> bool {
    !is_nan(format, x) && order(format, x) <= 0
}

/// IEEE `a > b`; false when either is NaN.
pub(super) fn greater(format: Format, a: u64, b: u64) -> bool {
    !is_nan(format, a) && !is_nan(format, b) && order(format, a) > order(format, b)
}

pub(super) const fn sign_mask(format: Format) -> u64 {
    1 << (format.bits() - 1)
}

pub(super) const BF16_ONE: u16 = 0x3f80;
pub(super) const BF16_NAN: u16 = 0x7fc0;

const fn bf16_is_nan(x: u16) -> bool {
    x & 0x7fff > 0x7f80
}

/// `bf16_to_f32`: exact, with NaN replaced by the default NaN.
pub(super) const fn bf16_to_single(x: u16) -> u32 {
    let x = if bf16_is_nan(x) { BF16_NAN } else { x };
    (x as u32) << 16
}

/// `bf16_from_f32`: round to nearest even; any NaN becomes the default NaN.
pub(super) const fn single_to_bf16(f: u32) -> u16 {
    if f & 0x7fff_ffff > 0x7f80_0000 {
        return BF16_NAN;
    }
    let low = f & 0xffff;
    let high = f >> 16;
    (high + (low + (high & 1) > 0x8000) as u32) as u16
}

/// corsix `bf16_fma`: `x * y + z` rounded once to bf16 (nearest even), with
/// denormals preserved and default-NaN results.
pub(super) fn bf16_fma(x: u16, y: u16, z: u16) -> u16 {
    fn unpack(value: u16) -> (i32, u32) {
        let mut exponent = i32::from((value >> 7) & 255);
        let mut mantissa = u32::from(value & 127) ^ 128;
        if exponent == 0 {
            mantissa ^= 128;
            exponent = 25 - mantissa.leading_zeros() as i32;
            mantissa <<= 1 - exponent;
        }
        (exponent, mantissa)
    }
    fn sticky_shift(value: &mut u32, amount: i32) {
        if amount >= 32 {
            *value = u32::from(*value != 0);
        } else {
            let original = *value;
            *value >>= amount;
            *value |= u32::from((*value << amount) != original);
        }
    }
    let (x_e, x_m) = unpack(x);
    let (y_e, y_m) = unpack(y);
    let (mut z_e, mut z_m) = unpack(z);
    let z_sign = z & 0x8000;
    let p_sign = (x ^ y) & 0x8000;

    if x_e == 255 || y_e == 255 || z_e == 255 {
        if (x_e == 255 && (x_m != 128 || y_m == 0))
            || (y_e == 255 && (y_m != 128 || x_m == 0))
            || (z_e == 255 && z_m != 128)
            || (z_e == 255 && (x_e == 255 || y_e == 255) && z_sign != p_sign)
        {
            return BF16_NAN;
        } else if z_e == 255 {
            return z;
        } else {
            return p_sign | 0x7f80;
        }
    }

    let mut p_m = x_m * y_m;
    let p_e = x_e + y_e - 7 - 127;
    if p_m == 0 {
        return z & if z_m != 0 { z } else { p_sign };
    }
    z_m <<= 7;
    z_e -= 7;
    p_m <<= 3;
    z_m <<= 3;
    let mut r_e = p_e.max(z_e);
    if p_e < r_e {
        sticky_shift(&mut p_m, r_e - p_e);
    }
    if z_e < r_e {
        sticky_shift(&mut z_m, r_e - z_e);
    }
    let r_sign = if p_m >= z_m { p_sign } else { z_sign };
    if z_sign != r_sign {
        z_m = !z_m;
    }
    if p_sign != r_sign {
        p_m = !p_m;
    }
    let mut r_m = z_m
        .wrapping_add(p_m)
        .wrapping_add(u32::from(p_sign != z_sign));
    if r_m == 0 {
        return z_sign & p_sign;
    }
    let n = 21 - r_m.leading_zeros() as i32;
    r_e += n;
    if n < 0 {
        r_m <<= -n;
    } else {
        sticky_shift(&mut r_m, n);
    }
    if r_e >= 255 {
        return r_sign | 0x7f80;
    }
    if r_e <= 0 {
        sticky_shift(&mut r_m, 1 - r_e);
        r_e = 0;
    }
    let r = r_sign | ((r_e as u16) << 7) | ((r_m >> 3) & 0x7f) as u16;
    r.wrapping_add(u16::from((r_m & 7) + u32::from(r & 1) > 4))
}

/// `ord`: bf16 bits as a signed order key.
const fn bf16_order(x: u16) -> i16 {
    let x = x as i16;
    x ^ ((x >> 15) & 0x7fff)
}

pub(super) const fn bf16_minimum(x: u16, z: u16) -> u16 {
    if bf16_is_nan(x) || bf16_is_nan(z) {
        BF16_NAN
    } else if bf16_order(x) < bf16_order(z) {
        x
    } else {
        z
    }
}

pub(super) const fn bf16_maximum(x: u16, z: u16) -> u16 {
    if bf16_is_nan(x) || bf16_is_nan(z) {
        BF16_NAN
    } else if bf16_order(x) > bf16_order(z) {
        x
    } else {
        z
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_rounds_to_nearest_and_canonicalizes_nan() {
        // 1 + 2^-24 is a tie in single precision: nearest even keeps 1.
        assert_eq!(add(Format::Single, 0x3f80_0000, 0x3380_0000), 0x3f80_0000);
        // Denormals are neither flushed on input nor output.
        assert_eq!(add(Format::Single, 1, 1), 2);
        // A signaling NaN payload becomes the positive default NaN.
        assert_eq!(
            multiply(Format::Single, 0xff80_0001, 0x3f80_0000),
            0x7fc0_0000
        );
        assert_eq!(
            fused(Format::Double, false, 0, 0x7ff0_0000_0000_0000, 0),
            0x7ff8_0000_0000_0000
        );
        assert_eq!(half_to_single(0xfc01), 0x7fc0_0000);
        assert_eq!(half_to_single(0x0001), 0x3380_0000);
        assert_eq!(single_to_half(0x3380_0000), 1);
        assert_eq!(single_to_half(0xffc0_1234), 0x7e00);
    }

    #[test]
    fn fused_operations_round_once() {
        // (1 + 2^-12)^2 - 1 is 2^-11 + 2^-24 exactly; rounding the product
        // first would tie to even and lose the 2^-24 term.
        let x = 0x3f80_0800;
        assert_eq!(multiply(Format::Single, x, x), 0x3f80_1000);
        assert_eq!(fused(Format::Single, false, 0xbf80_0000, x, x), 0x3a00_0400);
        assert_eq!(fused(Format::Single, true, 0x3f80_0000, x, x), 0xba00_0400);
        assert_eq!(
            minimum(Format::Single, 0x8000_0000, 0),
            0x8000_0000,
            "FMIN orders -0 below +0"
        );
        assert_eq!(maximum(Format::Half, 0x7c01, 0x3c00), 0x7e00);
    }

    #[test]
    fn comparisons_follow_ieee_order() {
        assert!(not_positive(Format::Single, 0x8000_0000));
        assert!(not_positive(Format::Single, 0));
        assert!(!not_positive(Format::Single, 0xffc0_0000));
        assert!(greater(Format::Half, 0x3c00, 0xbc00));
        assert!(!greater(Format::Half, 0x0000, 0x8000));
        assert!(!greater(Format::Double, 0x7ff8_0000_0000_0000, 0));
    }

    #[test]
    fn bf16_routines_match_corsix_examples() {
        assert_eq!(bf16_fma(BF16_ONE, BF16_ONE, BF16_ONE), 0x4000);
        assert_eq!(bf16_fma(0x8000, BF16_ONE, 0x8000), 0x8000);
        assert_eq!(bf16_fma(0x0000, BF16_ONE, 0x8000), 0x0000);
        assert_eq!(bf16_fma(0x7f80, 0, 0), BF16_NAN);
        assert_eq!(bf16_fma(0x7f80, BF16_ONE, 0xff80), BF16_NAN);
        assert_eq!(bf16_fma(0x7f80, BF16_ONE, 0x7f80), 0x7f80);
        // Smallest denormal times one plus zero stays exact.
        assert_eq!(bf16_fma(0x0001, BF16_ONE, 0), 0x0001);
        // Overflow saturates to infinity with the product sign.
        assert_eq!(bf16_fma(0x7f7f, 0x4000, 0), 0x7f80);
        // 1 + 2^-8 is a tie between 1 and 1 + 2^-7: nearest even keeps 1.
        assert_eq!(bf16_fma(BF16_ONE, BF16_ONE, 0x3b80), BF16_ONE);
        assert_eq!(single_to_bf16(0x3f80_8000), 0x3f80);
        assert_eq!(single_to_bf16(0x3f81_8000), 0x3f82);
        assert_eq!(single_to_bf16(0x7f80_0001), BF16_NAN);
        assert_eq!(bf16_to_single(0xff81), 0x7fc0_0000);
        assert_eq!(bf16_minimum(0x8000, 0x0000), 0x8000);
        assert_eq!(bf16_maximum(0xbf80, 0x3f80), 0x3f80);
        assert_eq!(bf16_maximum(0x7fc1, 0x3f80), BF16_NAN);
    }
}
