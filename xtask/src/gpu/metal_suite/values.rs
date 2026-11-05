//! Deterministic inputs, IEEE rounding to Metal's types and the element
//! formats of buffers. Transcendental references call the C library's
//! functions, the same correctly-rounded-or-nearly implementation every
//! run of the generator uses, so expectations never drift between hosts
//! of one C library.
use std::f64::consts::PI;

/// xorshift64*, so every run of the plan generator writes the same inputs.
pub struct Random(u64);

impl Random {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1))
    }

    pub fn u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn u32(&mut self) -> u32 {
        (self.u64() >> 32) as u32
    }

    /// `u32() % n` as a signed value, for small ranges.
    pub fn below(&mut self, n: u32) -> i64 {
        i64::from(self.u32() % n)
    }

    pub fn uniform(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * ((self.u64() >> 11) as f64 / 9_007_199_254_740_992.0)
    }

    /// A magnitude spread evenly over binary exponents.
    pub fn log_uniform(&mut self, lo: f64, hi: f64) -> f64 {
        libm::exp(self.uniform(libm::log(lo), libm::log(hi)))
    }
}

/// The C library's math functions.
pub mod libm {
    mod c {
        unsafe extern "C" {
            pub safe fn sin(x: f64) -> f64;
            pub safe fn cos(x: f64) -> f64;
            pub safe fn tan(x: f64) -> f64;
            pub safe fn asin(x: f64) -> f64;
            pub safe fn acos(x: f64) -> f64;
            pub safe fn atan(x: f64) -> f64;
            pub safe fn atan2(y: f64, x: f64) -> f64;
            pub safe fn sinh(x: f64) -> f64;
            pub safe fn cosh(x: f64) -> f64;
            pub safe fn tanh(x: f64) -> f64;
            pub safe fn asinh(x: f64) -> f64;
            pub safe fn acosh(x: f64) -> f64;
            pub safe fn atanh(x: f64) -> f64;
            pub safe fn exp(x: f64) -> f64;
            pub safe fn log(x: f64) -> f64;
            pub safe fn log2(x: f64) -> f64;
            pub safe fn log10(x: f64) -> f64;
            pub safe fn pow(x: f64, y: f64) -> f64;
            pub safe fn sqrt(x: f64) -> f64;
            pub safe fn fmod(x: f64, y: f64) -> f64;
            pub safe fn ldexp(x: f64, e: i32) -> f64;
            pub safe fn frexp(x: f64, e: &mut i32) -> f64;
            pub safe fn modf(x: f64, whole: &mut f64) -> f64;
        }
    }
    pub use c::*;
}

/// x rounded to the nearest single-precision value, ties to even.
pub fn f32r(x: f64) -> f64 {
    f64::from(x as f32)
}

/// The binary16 encoding of x rounded to nearest, ties to even; NaN
/// becomes the quiet NaN of its sign.
pub fn f16_bits(x: f64) -> u16 {
    let sign = if x.is_sign_negative() { 0x8000 } else { 0 };
    let a = x.abs();
    if a.is_nan() {
        return sign | 0x7E00;
    }
    if a < 2f64.powi(-14) {
        // Subnormal: units of 2^-24, which may round up to the smallest
        // normal, whose encoding follows on.
        return sign | (a * 2f64.powi(24)).round_ties_even() as u16;
    }
    if a.is_infinite() {
        return sign | 0x7C00;
    }
    let mut exponent = ((a.to_bits() >> 52) & 0x7FF) as i32 - 1023;
    let scale = 2f64.powi(exponent);
    let mut mantissa = ((a / scale - 1.0) * 1024.0).round_ties_even() as u32;
    if mantissa == 1024 {
        mantissa = 0;
        exponent += 1;
    }
    if exponent > 15 {
        return sign | 0x7C00;
    }
    sign | ((exponent + 15) as u16) << 10 | mantissa as u16
}

pub fn f16_from_bits(bits: u16) -> f64 {
    let sign = if bits & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exponent = i32::from((bits >> 10) & 0x1F);
    let mantissa = f64::from(bits & 0x3FF);
    match exponent {
        0 => sign * mantissa * 2f64.powi(-24),
        31 if mantissa == 0.0 => sign * f64::INFINITY,
        31 => {
            if sign < 0.0 {
                -f64::NAN
            } else {
                f64::NAN
            }
        }
        _ => sign * (1.0 + mantissa / 1024.0) * 2f64.powi(exponent - 15),
    }
}

/// x rounded to the nearest half.
pub fn f16r(x: f64) -> f64 {
    f16_from_bits(f16_bits(x))
}

pub fn bits32(x: f64) -> u32 {
    (x as f32).to_bits()
}

pub fn from_bits32(bits: u32) -> f64 {
    f64::from(f32::from_bits(bits))
}

/// A sum in the order and with the compensation of Python's `sum` of
/// floats (Neumaier's), which the corpus's expectations were first
/// written with.
pub fn sum(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut values = values.into_iter();
    let Some(mut total) = values.next() else {
        return 0.0;
    };
    let mut compensation = 0.0;
    for x in values {
        let t = total + x;
        if total.abs() >= x.abs() {
            compensation += (total - t) + x;
        } else {
            compensation += (x - t) + total;
        }
        total = t;
    }
    if compensation != 0.0 && compensation.is_finite() {
        total += compensation;
    }
    total
}

/// The lesser of two values, the first when unordered.
pub fn min(a: f64, b: f64) -> f64 {
    if b < a { b } else { a }
}

/// The greater of two values, the first when unordered.
pub fn max(a: f64, b: f64) -> f64 {
    if b > a { b } else { a }
}

pub fn clamp(x: f64, lo: f64, hi: f64) -> f64 {
    min(max(x, lo), hi)
}

/// An element format of a buffer, texture or output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dtype {
    F32,
    F16,
    I32,
    U32,
    I16,
    U16,
    I8,
    U8,
    I64,
    U64,
}

impl Dtype {
    pub fn name(self) -> &'static str {
        match self {
            Self::F32 => "f32",
            Self::F16 => "f16",
            Self::I32 => "i32",
            Self::U32 => "u32",
            Self::I16 => "i16",
            Self::U16 => "u16",
            Self::I8 => "i8",
            Self::U8 => "u8",
            Self::I64 => "i64",
            Self::U64 => "u64",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        [
            Self::F32,
            Self::F16,
            Self::I32,
            Self::U32,
            Self::I16,
            Self::U16,
            Self::I8,
            Self::U8,
            Self::I64,
            Self::U64,
        ]
        .into_iter()
        .find(|d| d.name() == name)
    }

    pub fn size(self) -> usize {
        match self {
            Self::I8 | Self::U8 => 1,
            Self::F16 | Self::I16 | Self::U16 => 2,
            Self::F32 | Self::I32 | Self::U32 => 4,
            Self::I64 | Self::U64 => 8,
        }
    }

    /// The float width in bits, or None for integers.
    pub fn float_bits(self) -> Option<u32> {
        match self {
            Self::F32 => Some(32),
            Self::F16 => Some(16),
            _ => None,
        }
    }

    /// Rounds a value to this float type.
    pub fn round(self, x: f64) -> f64 {
        match self {
            Self::F16 => f16r(x),
            _ => f32r(x),
        }
    }
}

/// Floats packed as f32 or f16.
pub fn floats(dtype: Dtype, values: &[f64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * dtype.size());
    for &v in values {
        match dtype {
            Dtype::F32 => out.extend((v as f32).to_le_bytes()),
            Dtype::F16 => out.extend(f16_bits(v).to_le_bytes()),
            _ => panic!("{} is not a float type", dtype.name()),
        }
    }
    out
}

/// Integers packed in a type's width, truncated two's complement.
pub fn ints(dtype: Dtype, values: &[i128]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * dtype.size());
    for &v in values {
        let bytes = (v as u128).to_le_bytes();
        out.extend(&bytes[..dtype.size()]);
    }
    out
}

pub fn u32s(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

pub fn f32s(values: &[f64]) -> Vec<u8> {
    floats(Dtype::F32, values)
}

/// The elements of packed bytes, floats widened and integers sign- or
/// zero-extended.
pub fn elements(dtype: Dtype, data: &[u8]) -> Vec<f64> {
    data.chunks_exact(dtype.size())
        .map(|c| match dtype {
            Dtype::F32 => f64::from(f32::from_le_bytes(c.try_into().unwrap())),
            Dtype::F16 => f16_from_bits(u16::from_le_bytes(c.try_into().unwrap())),
            Dtype::I32 => f64::from(i32::from_le_bytes(c.try_into().unwrap())),
            Dtype::U32 => f64::from(u32::from_le_bytes(c.try_into().unwrap())),
            Dtype::I16 => f64::from(i16::from_le_bytes(c.try_into().unwrap())),
            Dtype::U16 => f64::from(u16::from_le_bytes(c.try_into().unwrap())),
            Dtype::I8 => f64::from(c[0] as i8),
            Dtype::U8 => f64::from(c[0]),
            Dtype::I64 => i64::from_le_bytes(c.try_into().unwrap()) as f64,
            Dtype::U64 => u64::from_le_bytes(c.try_into().unwrap()) as f64,
        })
        .collect()
}

/// Integer elements, exactly.
pub fn int_elements(dtype: Dtype, data: &[u8]) -> Vec<i128> {
    data.chunks_exact(dtype.size())
        .map(|c| {
            let mut wide = [0u8; 16];
            wide[..c.len()].copy_from_slice(c);
            let raw = u128::from_le_bytes(wide);
            let bits = 8 * c.len() as u32;
            let signed = matches!(dtype, Dtype::I8 | Dtype::I16 | Dtype::I32 | Dtype::I64);
            if signed && raw >> (bits - 1) & 1 == 1 {
                raw as i128 - (1i128 << bits)
            } else {
                raw as i128
            }
        })
        .collect()
}

pub const F32_MAX: f64 = f32::MAX as f64;
pub const F32_MIN: f64 = 1.1754943508222875e-38;
pub const F16_MAX: f64 = 65504.0;
pub const F16_MIN: f64 = 6.103515625e-05;

/// Values whose results test a function's edges: zeros, extremes,
/// subnormals, infinities, NaN and the neighbourhoods of small integers
/// and of pi.
fn special_f32() -> Vec<f64> {
    vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.5,
        -0.5,
        2.0,
        -2.0,
        3.0,
        0.25,
        1.5,
        -1.5,
        2.5,
        -2.5,
        10.0,
        100.0,
        1e-7,
        -1e-7,
        1e-20,
        1e20,
        -1e20,
        F32_MAX,
        -F32_MAX,
        F32_MIN,
        -F32_MIN,
        2f64.powi(-149),
        -(2f64.powi(-149)),
        2f64.powi(-130),
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        f32r(PI),
        f32r(-PI),
        f32r(PI / 2.0),
        f32r(PI / 4.0),
        f32r(std::f64::consts::E),
        16777216.0,
        16777217.0,
        8388608.5,
        0.49999997,
        0.50000006,
        1.0000001,
        0.99999994,
        65504.0,
        65520.0,
        6.1e-5,
    ]
}

fn special_f16() -> Vec<f64> {
    vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.5,
        -0.5,
        2.0,
        -2.0,
        0.25,
        1.5,
        -1.5,
        2.5,
        -2.5,
        10.0,
        100.0,
        F16_MAX,
        -F16_MAX,
        F16_MIN,
        -F16_MIN,
        2f64.powi(-24),
        -(2f64.powi(-24)),
        2f64.powi(-20),
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        3.140625,
        -3.140625,
        1.5703125,
        0.7851562,
        2.71875,
        2048.0,
        2049.0,
        0.49975586,
        0.50048828,
        1.0009766,
        0.99951172,
    ]
}

/// `count` inputs from a named domain: its edge values first, then
/// pseudo-random values spread over the domain. Single-precision
/// subnormals are left out: Metal lets a device flush them (Apple's GPUs
/// do, with and without fast math), which the denormal cases cover on
/// their own. Without signed zeros, as fast math allows, -0 becomes 0.
#[expect(
    clippy::approx_constant,
    reason = "0.70710678 is a test input as the corpus has used it, not 1/sqrt(2)"
)]
pub fn domain_values(
    domain: &str,
    dtype: Dtype,
    count: usize,
    seed: u64,
    signed_zeros: bool,
) -> Vec<f64> {
    let mut rng = Random::new(seed);
    let fp16 = dtype == Dtype::F16;
    let top = if fp16 { 60000.0 } else { 1e30 };
    let tiny = if fp16 { 2f64.powi(-13) } else { 1e-30 };
    let specials = if fp16 { special_f16() } else { special_f32() };
    let finite = |v: &f64| v.is_finite();
    let signed = |rng: &mut Random, lo: f64, hi: f64| {
        let magnitude = rng.log_uniform(lo, hi);
        magnitude.copysign(rng.uniform(-1.0, 1.0))
    };
    type Draw = Box<dyn FnMut(&mut Random) -> f64>;
    let (edge, mut draw): (Vec<f64>, Draw) = match domain {
        "any" => (specials, Box::new(move |r| signed(r, tiny, top))),
        "finite" => {
            let bound = if fp16 { F16_MAX } else { 1e20 };
            let hi = if fp16 { 1e4 } else { 1e8 };
            (
                specials
                    .into_iter()
                    .filter(|v| finite(v) && v.abs() <= bound)
                    .collect(),
                Box::new(move |r| signed(r, tiny, hi)),
            )
        }
        "small" => (
            vec![0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 2.0, -3.0, 0.1, -0.1, 7.25],
            Box::new(|r| r.uniform(-16.0, 16.0)),
        ),
        "angle" => (
            vec![
                0.0,
                -0.0,
                PI,
                -PI,
                PI / 2.0,
                -PI / 2.0,
                PI / 4.0,
                1.0,
                -1.0,
                3.0,
                0.1,
            ],
            Box::new(|r| r.uniform(-PI, PI)),
        ),
        "tan_angle" => (
            vec![0.0, -0.0, 1.0, -1.0, 0.5, 1.4, -1.4, 0.1],
            Box::new(|r| r.uniform(-1.5, 1.5)),
        ),
        "wide_angle" => (
            vec![0.0, PI, 10.0, -100.0, 1000.0, 2.0 * PI, 100.0 * PI],
            Box::new(move |r| {
                if fp16 {
                    r.uniform(-100.0, 100.0)
                } else {
                    r.uniform(-1000.0, 1000.0)
                }
            }),
        ),
        "unit" => (
            vec![
                0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 0.99, -0.99, 1e-4, 0.70710678,
            ],
            Box::new(|r| r.uniform(-1.0, 1.0)),
        ),
        "open_unit" => (
            vec![0.0, -0.0, 0.5, -0.5, 0.99, -0.99, 1e-4, 0.70710678],
            Box::new(|r| r.uniform(-0.999, 0.999)),
        ),
        "positive" => (
            specials
                .into_iter()
                .filter(|v| finite(v) && *v > 0.0)
                .collect(),
            Box::new(move |r| r.log_uniform(tiny, top)),
        ),
        "normal_positive" => (
            vec![1.0, 0.5, 2.0, 0.25, 10.0, 100.0, 1e-3, 1e4],
            Box::new(move |r| {
                if fp16 {
                    r.log_uniform(1e-3, 1e4)
                } else {
                    r.log_uniform(1e-20, 1e20)
                }
            }),
        ),
        "ge1" => (
            vec![1.0, 1.5, 2.0, 10.0, 1e3],
            Box::new(|r| r.log_uniform(1.0, 1e4)),
        ),
        "exp" => {
            let limit = if fp16 { 10.0 } else { 80.0 };
            (
                vec![0.0, -0.0, 1.0, -1.0, 0.5, limit, -limit, 2.0],
                Box::new(move |r| r.uniform(-limit, limit)),
            )
        }
        "exp2" => {
            let limit = if fp16 { 15.0 } else { 120.0 };
            (
                vec![0.0, -0.0, 1.0, -1.0, 0.5, limit, -limit, 2.0, 10.0],
                Box::new(move |r| r.uniform(-limit, limit)),
            )
        }
        "exp10" => {
            let limit = if fp16 { 4.0 } else { 35.0 };
            (
                vec![0.0, 1.0, -1.0, 2.0, 0.5, limit, -limit],
                Box::new(move |r| r.uniform(-limit, limit)),
            )
        }
        "pow_base" => (
            vec![1.0, 2.0, 0.5, 10.0, 0.1, 3.0],
            Box::new(|r| r.log_uniform(1e-2, 1e2)),
        ),
        "pow_exponent" => (
            vec![0.0, 1.0, 2.0, -1.0, 0.5, -0.5, 3.0],
            Box::new(|r| r.uniform(-4.0, 4.0)),
        ),
        "divisor" => (
            vec![1.0, -1.0, 2.0, 3.0, 0.5, 7.0, -0.1, 1e-3, 1e3],
            Box::new(move |r| signed(r, 1e-3, 1e3)),
        ),
        "unorm" => (
            vec![0.0, 1.0, 0.5, 0.25, 0.75, 1.0 / 255.0, 254.0 / 255.0],
            Box::new(|r| r.uniform(0.0, 1.0)),
        ),
        _ => panic!("unknown domain {domain}"),
    };
    let mut values: Vec<f64> = edge.into_iter().take(count).collect();
    while values.len() < count {
        values.push(draw(&mut rng));
    }
    values
        .into_iter()
        .map(|v| dtype.round(v))
        .map(|v| {
            if dtype == Dtype::F32 && v != 0.0 && v.abs() < F32_MIN {
                1.0
            } else {
                v
            }
        })
        .map(|v| if !signed_zeros && v == 0.0 { 0.0 } else { v })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_rounds_to_nearest_even() {
        assert_eq!(f16_bits(1.0), 0x3C00);
        assert_eq!(f16_bits(65504.0), 0x7BFF);
        assert_eq!(f16_bits(65519.0), 0x7BFF);
        assert_eq!(f16_bits(65520.0), 0x7C00);
        assert_eq!(f16_bits(2f64.powi(-24)), 1);
        assert_eq!(f16_bits(2f64.powi(-25)), 0);
        assert_eq!(f16_bits(3.0 * 2f64.powi(-25)), 2);
        assert_eq!(f16_bits(1.0 + 2f64.powi(-11)), 0x3C00);
        assert_eq!(f16_bits(1.0 + 3.0 * 2f64.powi(-11)), 0x3C02);
        assert_eq!(f16_bits(-0.0), 0x8000);
        assert_eq!(f16_bits(f64::NAN), 0x7E00);
        for bits in 0..0x7C00u16 {
            assert_eq!(f16_bits(f16_from_bits(bits)), bits);
        }
    }

    #[test]
    fn compensated_sum_recovers_cancellation() {
        assert_eq!(sum([1e16, 1.0, -1e16]), 1.0);
        assert_eq!(sum([]), 0.0);
    }

    #[test]
    fn random_is_xorshift64_star() {
        let mut r = Random::new(1);
        let first = r.u64();
        assert_eq!(first, Random::new(1).u64());
        assert_ne!(first, r.u64());
    }
}
