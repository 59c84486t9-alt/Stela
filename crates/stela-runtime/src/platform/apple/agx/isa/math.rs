//! The transcendental and rounding functions of the AGX2 float unit, in f64
//! without a host math library (the runtime builds without std).
//!
//! The hardware's exact approximations are unpublished. Each function here is
//! accurate to far better than an f32 ulp before the result is rounded to the
//! destination, so results meet Metal's precision bounds; the special-case
//! values follow IEEE and Mesa's uses (Inferred where marked).

use super::float::{pow2_f64, round_even};

/// Largest magnitude below which an f64 can have a fraction.
const INTEGRAL: f64 = 4_503_599_627_370_496.0;

pub fn trunc(x: f64) -> f64 {
    if !x.is_finite() || x.abs() >= INTEGRAL {
        return x;
    }
    let rounded = round_even(x);
    // Step toward zero when rounding went away from it.
    if rounded.abs() > x.abs() {
        rounded - x.signum()
    } else {
        rounded
    }
}

/// Round half away from zero.
pub fn round(x: f64) -> f64 {
    let t = trunc(x);
    if (x - t).abs() >= 0.5 {
        t + 1.0f64.copysign(x)
    } else {
        t
    }
}

pub fn floor(x: f64) -> f64 {
    let t = trunc(x);
    if t > x { t - 1.0 } else { t }
}

pub fn ceil(x: f64) -> f64 {
    let t = trunc(x);
    if t < x { t + 1.0 } else { t }
}

/// Clamp to [0, 1]; NaN becomes 0 (applegpu `saturate64`, NIR `fsat`).
pub fn saturate(x: f64) -> f64 {
    if x.is_nan() { 0.0 } else { x.clamp(0.0, 1.0) }
}

/// Square root by Newton's iteration from an exponent-halving estimate.
pub fn sqrt(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 || x.is_infinite() {
        return x;
    }
    // Scale into [1, 4) so the estimate needs few steps.
    let exponent = ((x.to_bits() >> 52) & 0x7ff) as i32 - 1023;
    let (scaled, half) = if x.is_subnormal() {
        let scaled = x * pow2_f64(60);
        let e = ((scaled.to_bits() >> 52) & 0x7ff) as i32 - 1023;
        let even = e & !1;
        (scaled * pow2_f64(-even), (even - 60) / 2)
    } else {
        let even = exponent & !1;
        (x * pow2_f64(-even), even / 2)
    };
    let mut y = 0.5 * (1.0 + scaled);
    for _ in 0..6 {
        y = 0.5 * (y + scaled / y);
    }
    y * pow2_f64(half)
}

pub fn rsqrt(x: f64) -> f64 {
    1.0 / sqrt(x)
}

/// The `rsqrts` form Mesa multiplies by its operand to take a square root
/// (`fsqrt(x) = x * rsqrts(x)`): zero and infinity map to themselves so the
/// product keeps `sqrt`'s values there (Inferred from that use).
pub fn rsqrt_special(x: f64) -> f64 {
    if x == 0.0 {
        0.0
    } else if x == f64::INFINITY {
        f64::INFINITY
    } else {
        rsqrt(x)
    }
}

/// Natural logarithm of a value in [sqrt(1/2), sqrt(2)): 2 atanh((m-1)/(m+1)).
fn ln_reduced(m: f64) -> f64 {
    let s = (m - 1.0) / (m + 1.0);
    let s2 = s * s;
    let mut term = s;
    let mut sum = 0.0;
    let mut n = 1.0;
    while n < 41.0 {
        sum += term / n;
        term *= s2;
        n += 2.0;
    }
    2.0 * sum
}

pub fn log2(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x.is_infinite() {
        return x;
    }
    let (x, bias) = if x.is_subnormal() {
        (x * pow2_f64(60), -60)
    } else {
        (x, 0)
    };
    let bits = x.to_bits();
    let mut exponent = ((bits >> 52) & 0x7ff) as i32 - 1023;
    let mut mantissa = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
    if mantissa > core::f64::consts::SQRT_2 {
        mantissa *= 0.5;
        exponent += 1;
    }
    f64::from(exponent + bias) + ln_reduced(mantissa) / core::f64::consts::LN_2
}

pub fn exp2(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x > 1024.0 {
        return f64::INFINITY;
    }
    if x < -1100.0 {
        return 0.0;
    }
    let whole = round_even(x);
    let fraction = (x - whole) * core::f64::consts::LN_2;
    // e^f for |f| <= ln(2) / 2 by its Taylor series.
    let mut term = 1.0;
    let mut sum = 1.0;
    for n in 1..24 {
        term *= fraction / f64::from(n);
        sum += term;
    }
    let e = whole as i32;
    // Split the scale so neither factor leaves the normal range.
    if e > 1000 {
        sum * pow2_f64(1000) * pow2_f64(e - 1000)
    } else if e < -1000 {
        sum * pow2_f64(-1000) * pow2_f64(e + 1000)
    } else {
        sum * pow2_f64(e)
    }
}

/// `sinr` (Mesa `sin_pt_1`): fold a quadrant angle `q` (sin(q pi/2)) in
/// [0, 4) into [-1, 1] with the same sine: q, 2 - q or q - 4 (Inferred
/// piecewise form of Mesa's description; arguments outside [0, 4) wrap
/// modulo 4).
pub fn sin_quadrant(q: f64) -> f64 {
    if !q.is_finite() {
        return f64::NAN;
    }
    let q = q - 4.0 * floor(q / 4.0);
    if q <= 1.0 {
        q
    } else if q <= 3.0 {
        2.0 - q
    } else {
        q - 4.0
    }
}

/// `sinc` (Mesa `sin_pt_2`): sin(y pi/2) / y for y in [-1, 1], so that
/// `y * sinc(y)` is the sine (pi/2 at y = 0).
pub fn sinc_quarter_turn(y: f64) -> f64 {
    let t = y * core::f64::consts::FRAC_PI_2;
    let t2 = t * t;
    // sin(t)/t = sum (-1)^n t^2n / (2n+1)!
    let mut term = 1.0;
    let mut sum = 1.0;
    for n in 1..20 {
        term *= -t2 / f64::from((2 * n) * (2 * n + 1));
        sum += term;
    }
    sum * core::f64::consts::FRAC_PI_2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounding_functions() {
        for (x, t, f, c) in [
            (2.5, 2.0, 2.0, 3.0),
            (-2.5, -2.0, -3.0, -2.0),
            (-0.25, -0.0, -1.0, -0.0),
            (7.0, 7.0, 7.0, 7.0),
        ] {
            assert_eq!(trunc(x), t, "trunc {x}");
            assert_eq!(
                round(x),
                if x.abs() == 2.5 { t + x.signum() } else { t },
                "round {x}"
            );
            assert_eq!(floor(x), f, "floor {x}");
            assert_eq!(ceil(x), c, "ceil {x}");
        }
        assert!(trunc(f64::NAN).is_nan());
        assert_eq!(saturate(f64::NAN), 0.0);
        assert_eq!(saturate(-3.0), 0.0);
    }

    #[test]
    fn roots_logs_and_exponentials_are_accurate() {
        for x in [1e-300, 2.0, 3.0, 0.1, 1e300, 5e-324] {
            let r = sqrt(x);
            assert!((r * r - x).abs() <= x * 4e-16, "sqrt {x}");
        }
        assert_eq!(sqrt(16.0), 4.0);
        assert_eq!(rsqrt_special(0.0) * 0.0, 0.0);
        assert_eq!(f64::INFINITY * rsqrt_special(f64::INFINITY), f64::INFINITY);
        assert_eq!(log2(8.0), 3.0);
        assert_eq!(log2(0.0), f64::NEG_INFINITY);
        assert!((log2(10.0) - core::f64::consts::LOG2_10).abs() < 1e-15);
        assert_eq!(exp2(10.0), 1024.0);
        assert!((exp2(0.5) - core::f64::consts::SQRT_2).abs() < 1e-15);
        assert_eq!(exp2(2000.0), f64::INFINITY);
        assert_eq!(exp2(-2000.0), 0.0);
    }

    #[test]
    fn sine_parts_reconstruct_the_sine() {
        for i in 0..64 {
            let q = f64::from(i) / 16.0;
            let y = sin_quadrant(q);
            let expected = libm_free_sin(q * core::f64::consts::FRAC_PI_2);
            assert!((y * sinc_quarter_turn(y) - expected).abs() < 1e-14, "{q}");
        }
    }

    /// A reference sine by argument reduction to [-pi, pi] and Taylor.
    fn libm_free_sin(t: f64) -> f64 {
        let tau = 2.0 * core::f64::consts::PI;
        let t = t - tau * round_even(t / tau);
        let mut term = t;
        let mut sum = t;
        for n in 1..30 {
            term *= -t * t / f64::from((2 * n) * (2 * n + 1));
            sum += term;
        }
        sum
    }
}
