//! Double-precision values of MSL's math functions with IEEE 754 and C99
//! Annex F special-value behaviour; the families round them to float or
//! half. A domain error (an invalid operation on ordered operands) gives
//! the quiet NaN.
use super::values::{clamp, libm, max, min};
use std::f64::consts::PI;

const NAN: f64 = f64::NAN;
const INF: f64 = f64::INFINITY;

/// A C library function's value, its NaN made the canonical quiet NaN.
fn c(value: f64) -> f64 {
    if value.is_nan() { NAN } else { value }
}

fn log(f: impl Fn(f64) -> f64, x: f64) -> f64 {
    if x == 0.0 {
        -INF
    } else if x < 0.0 {
        NAN
    } else if x.is_infinite() {
        INF
    } else {
        c(f(x))
    }
}

/// pow for finite operands as C computes it, an infinity from a zero base
/// being a domain error; other operands take C99's special values.
fn pow(x: f64, y: f64) -> f64 {
    let r = libm::pow(x, y);
    if x.is_finite() && y.is_finite() {
        if r.is_nan() || (r.is_infinite() && x == 0.0) {
            return NAN;
        }
        if r.is_infinite() {
            return INF;
        }
    }
    r
}

fn pi_scaled(sine: bool, x: f64) -> f64 {
    // sinpi and cospi reduce their argument exactly before scaling.
    if x.is_infinite() {
        return NAN;
    }
    let r = libm::fmod(x, 2.0);
    if sine && r == r.trunc() {
        return if r == 0.0 {
            0f64.copysign(x)
        } else {
            -(0f64.copysign(x))
        };
    }
    if !sine && (r.abs() == 0.5 || r.abs() == 1.5) {
        return 0.0;
    }
    c(if sine {
        libm::sin(PI * r)
    } else {
        libm::cos(PI * r)
    })
}

fn tanpi(x: f64) -> f64 {
    if x.is_infinite() {
        return NAN;
    }
    let r = libm::fmod(x, 1.0);
    if r.abs() == 0.5 {
        return INF.copysign(r);
    }
    c(libm::tan(PI * r))
}

fn integral(x: f64, f: fn(f64) -> f64) -> f64 {
    if x.is_infinite() || x == 0.0 {
        x
    } else {
        f(x).copysign(x)
    }
}

fn ceil(x: f64) -> f64 {
    if x.is_infinite() || x == 0.0 {
        return x;
    }
    let c = x.ceil();
    if c == 0.0 { c.copysign(x) } else { c }
}

/// fract with its result clamped below 1 at `largest`, the type's
/// greatest value under 1.
pub fn fract(largest: f64, x: f64) -> f64 {
    if x.is_nan() {
        NAN
    } else if x.is_infinite() {
        0.0
    } else {
        min(x - x.floor(), largest)
    }
}

fn fmod(x: f64, y: f64) -> f64 {
    if x.is_infinite() || y == 0.0 {
        NAN
    } else if y.is_infinite() {
        x
    } else {
        libm::fmod(x, y)
    }
}

fn powr(x: f64, y: f64) -> f64 {
    // powr is defined for x >= 0 only.
    if x < 0.0
        || (x == 0.0 && y == 0.0)
        || (x.is_infinite() && y == 0.0)
        || (x == 1.0 && y.is_infinite())
    {
        NAN
    } else {
        pow(x, y)
    }
}

fn divide(x: f64, y: f64) -> f64 {
    if y == 0.0 {
        if x == 0.0 || x.is_nan() {
            return NAN;
        }
        return INF.copysign(x) * 1f64.copysign(y);
    }
    if x.is_infinite() && y.is_infinite() {
        return NAN;
    }
    x / y
}

fn ldexp(x: f64, e: f64) -> f64 {
    if x == 0.0 || x.is_infinite() {
        return x;
    }
    libm::ldexp(x, e.clamp(-100_000.0, 100_000.0) as i32)
}

fn median(x: f64, y: f64, z: f64) -> f64 {
    let mut v = [x, y, z];
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[1]
}

/// The value of MSL function `name` at these operands, None for a name
/// with no reference.
pub fn function(name: &str, a: &[f64]) -> Option<f64> {
    let x = a[0];
    let y = a.get(1).copied().unwrap_or(0.0);
    let z = a.get(2).copied().unwrap_or(0.0);
    let unguarded = matches!(name, "sign" | "fmin" | "fmax" | "copysign" | "divide");
    if !unguarded && a.iter().any(|v| v.is_nan()) {
        return Some(NAN);
    }
    Some(match name {
        "sin" => c(libm::sin(x)),
        "cos" => c(libm::cos(x)),
        "tan" => c(libm::tan(x)),
        "asin" => c(libm::asin(x)),
        "acos" => c(libm::acos(x)),
        "atan" => c(libm::atan(x)),
        "sinh" => c(libm::sinh(x)),
        "cosh" => c(libm::cosh(x)),
        "tanh" => c(libm::tanh(x)),
        "asinh" => c(libm::asinh(x)),
        "acosh" => c(libm::acosh(x)),
        "atanh" => {
            if x.abs() == 1.0 {
                INF.copysign(x)
            } else {
                c(libm::atanh(x))
            }
        }
        "exp" => c(libm::exp(x)),
        "exp2" => pow(2.0, x),
        "exp10" => pow(10.0, x),
        "log" => log(|v| libm::log(v), x),
        "log2" => log(|v| libm::log2(v), x),
        "log10" => log(|v| libm::log10(v), x),
        "sqrt" => {
            if x == 0.0 {
                x
            } else {
                c(libm::sqrt(x))
            }
        }
        "rsqrt" => {
            if x == 0.0 {
                INF.copysign(x)
            } else if x.is_infinite() {
                if x > 0.0 { 0.0 } else { NAN }
            } else {
                let s = c(libm::sqrt(x));
                if s.is_nan() { NAN } else { 1.0 / s }
            }
        }
        "sinpi" => pi_scaled(true, x),
        "cospi" => pi_scaled(false, x),
        "tanpi" => tanpi(x),
        "ceil" => ceil(x),
        "floor" => {
            if x.is_infinite() || x == 0.0 {
                x
            } else {
                x.floor()
            }
        }
        "round" => integral(x, |v| (v.abs() + 0.5).floor()),
        "rint" => integral(x, |v| v.abs().round_ties_even()),
        "trunc" => integral(x, f64::trunc),
        "fabs" => x.abs(),
        "sign" => {
            if x.is_nan() {
                0.0
            } else if x > 0.0 {
                1.0
            } else if x < 0.0 {
                -1.0
            } else {
                x
            }
        }
        "saturate" => clamp(x, 0.0, 1.0),
        "pow" => {
            if y == 0.0 || x == 1.0 {
                1.0
            } else {
                pow(x, y)
            }
        }
        "powr" => powr(x, y),
        "atan2" => c(libm::atan2(x, y)),
        "fmod" => fmod(x, y),
        "fmin" => {
            if x.is_nan() {
                y
            } else if y.is_nan() {
                x
            } else {
                min(x, y)
            }
        }
        "fmax" => {
            if x.is_nan() {
                y
            } else if y.is_nan() {
                x
            } else {
                max(x, y)
            }
        }
        "copysign" => x.copysign(y),
        "fdim" => {
            if x > y {
                x - y
            } else {
                0.0
            }
        }
        // step(edge, x)
        "step" => {
            if y < x {
                0.0
            } else {
                1.0
            }
        }
        "divide" => divide(x, y),
        "add" => x + y,
        "sub" => x - y,
        "mul" => x * y,
        "ldexp" => ldexp(x, y.trunc()),
        // Unfused, as the C expression x * y + z.
        "fma" => x * y + z,
        "mix" => x + (y - x) * z,
        // clamp(x, min(y, z), max(y, z))
        "clamp" => clamp(x, min(y, z), max(y, z)),
        // smoothstep(min(y, z) - 1, max(y, z) + 1, x)
        "smoothstep" => {
            let (e0, e1) = (min(y, z) - 1.0, max(y, z) + 1.0);
            let t = clamp((x - e0) / (e1 - e0), 0.0, 1.0);
            t * t * (3.0 - 2.0 * t)
        }
        "fmax3" => max(max(x, y), z),
        "fmin3" => min(min(x, y), z),
        "fmedian3" => median(x, y, z),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_values_follow_annex_f() {
        assert!(function("sin", &[INF]).unwrap().is_nan());
        assert_eq!(function("log", &[0.0]), Some(-INF));
        assert_eq!(function("rsqrt", &[-0.0]), Some(-INF));
        assert_eq!(
            function("sinpi", &[-2.0]).unwrap().to_bits(),
            (-0.0f64).to_bits()
        );
        assert_eq!(function("cospi", &[0.5]), Some(0.0));
        assert_eq!(function("tanpi", &[-0.5]), Some(-INF));
        assert_eq!(function("pow", &[0.0, -1.0]).map(f64::is_nan), Some(true));
        assert_eq!(function("exp2", &[2000.0]), Some(INF));
        assert_eq!(function("sign", &[NAN]), Some(0.0));
        assert_eq!(function("fmin", &[NAN, 2.0]), Some(2.0));
        assert_eq!(function("ldexp", &[1.5, 3.9]), Some(12.0));
        assert_eq!(function("ldexp", &[1.0, -1074.0]), Some(f64::from_bits(1)));
        assert_eq!(function("round", &[-2.5]), Some(-3.0));
        assert_eq!(function("rint", &[-2.5]), Some(-2.0));
        assert_eq!(
            function("ceil", &[-0.5]).unwrap().to_bits(),
            (-0.0f64).to_bits()
        );
    }
}
