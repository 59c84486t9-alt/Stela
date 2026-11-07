//! Apple's extended-range 10-bit codes and the half floats that store them.
//!
//! A code `c` of `BGR10_XR` or `BGRA10_XR` reads as `(c - 384) / 510`, so
//! codes 0 through 1023 span [-0.7529, 1.2529]; the `sRGB` variants pass that
//! value through the sRGB curve, mirrored below zero. Alpha uses the same
//! codes, clamped to [0, 1]. `BGR10_XR` packs blue, green and red from bit 0
//! in ten bits each, and writes ones to its two top bits; `BGRA10_XR` keeps
//! each of blue, green, red and alpha in the top ten bits of a 16-bit word,
//! writing zeros below. Writes round to the nearest code, ties to even.
//!
//! Vulkan has no such format. The device stores these textures as
//! `R16G16B16A16_SFLOAT` holding the values a read returns (linear values for
//! the `sRGB` variants), which filtering and blending treat as Metal does;
//! every code survives the round trip. Bytes cross between the two layouts
//! here, wherever the CPU reads or writes a texture.

/// The values of one image texel: red, green, blue, alpha.
type Texel = [f32; 4];

/// Bytes of one stored texel.
pub const STORED_BYTES: usize = 8;

/// The lowest code alpha holds, reading 0, and the highest, reading 1.
const ALPHA_ZERO: u32 = 384;
const ALPHA_ONE: u32 = 894;

/// A format's codes: whether it has alpha and whether its color passes
/// through the sRGB curve.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Codes {
    pub alpha: bool,
    pub srgb: bool,
}

impl Codes {
    /// Bytes of one Metal texel.
    pub const fn metal_bytes(self) -> usize {
        if self.alpha { 8 } else { 4 }
    }

    /// Converts whole Metal texels to stored texels.
    pub fn store(self, metal: &[u8], stored: &mut [u8]) {
        let texels = metal.chunks_exact(self.metal_bytes());
        for (texel, out) in texels.zip(stored.as_chunks_mut::<STORED_BYTES>().0) {
            let value = self.read(texel);
            for (channel, half) in value.iter().zip(out.as_chunks_mut::<2>().0) {
                *half = f16_bits(*channel).to_le_bytes();
            }
        }
    }

    /// Converts whole stored texels to Metal texels.
    pub fn load(self, stored: &[u8], metal: &mut [u8]) {
        let texels = stored.as_chunks::<STORED_BYTES>().0;
        for (texel, out) in texels
            .iter()
            .zip(metal.chunks_exact_mut(self.metal_bytes()))
        {
            let mut value = [0.0; 4];
            for (channel, half) in value.iter_mut().zip(texel.as_chunks::<2>().0) {
                *channel = f16_value(u16::from_le_bytes(*half));
            }
            self.write(value, out);
        }
    }

    /// What a texel written with `value` reads as.
    pub fn quantize(self, value: Texel) -> Texel {
        let mut texel = [0; 8];
        self.write(value, &mut texel);
        self.read(&texel)
    }

    /// The values a shader reads from one Metal texel.
    fn read(self, texel: &[u8]) -> Texel {
        let (blue, green, red, alpha) = if self.alpha {
            let word = |at: usize| u32::from(u16::from_le_bytes([texel[at], texel[at + 1]])) >> 6;
            (word(0), word(2), word(4), word(6))
        } else {
            let bits = u32::from_le_bytes([texel[0], texel[1], texel[2], texel[3]]);
            (
                bits & 0x3ff,
                bits >> 10 & 0x3ff,
                bits >> 20 & 0x3ff,
                ALPHA_ONE,
            )
        };
        [
            self.color(red),
            self.color(green),
            self.color(blue),
            linear(alpha.clamp(ALPHA_ZERO, ALPHA_ONE)),
        ]
    }

    /// The Metal texel a write of `value` stores.
    fn write(self, value: Texel, out: &mut [u8]) {
        let [red, green, blue, alpha] = value;
        let color = |value: f32| self.code(value);
        let alpha = nearest(f64::from(alpha) * 510.0 + 384.0, ALPHA_ZERO, ALPHA_ONE);
        if self.alpha {
            for (at, code) in [
                (0, color(blue)),
                (2, color(green)),
                (4, color(red)),
                (6, alpha),
            ] {
                out[at..at + 2].copy_from_slice(&((code << 6) as u16).to_le_bytes());
            }
        } else {
            let bits = color(blue) | color(green) << 10 | color(red) << 20 | 3 << 30;
            out[..4].copy_from_slice(&bits.to_le_bytes());
        }
    }

    /// The color value of a code.
    fn color(self, code: u32) -> f32 {
        if self.srgb {
            SRGB_VALUES[code as usize]
        } else {
            linear(code)
        }
    }

    /// The code nearest a color value, measured in codes.
    fn code(self, value: f32) -> u32 {
        if !self.srgb {
            return nearest(f64::from(value) * 510.0 + 384.0, 0, 1023);
        }
        // The values rise with the codes; code c holds those between the
        // values of c - 1/2 and c + 1/2.
        let value = if value.is_nan() { 0.0 } else { value };
        SRGB_MIDPOINTS.partition_point(|&midpoint| midpoint < value) as u32
    }
}

fn linear(code: u32) -> f32 {
    (code as f32 - 384.0) / 510.0
}

/// The code nearest `x`, ties to even, within `low..=high`; NaN reads low.
fn nearest(x: f64, low: u32, high: u32) -> u32 {
    if x.is_nan() || x <= f64::from(low) {
        return low;
    }
    if x >= f64::from(high) {
        return high;
    }
    let floor = x as u32;
    let fraction = x - f64::from(floor);
    let up = fraction > 0.5 || fraction == 0.5 && floor & 1 == 1;
    floor + u32::from(up)
}

/// The sRGB curve, mirrored below zero, of the extended value at `code`.
const fn srgb_at(code: f64) -> f64 {
    let encoded = (code - 384.0) / 510.0;
    let magnitude = if encoded < 0.0 { -encoded } else { encoded };
    let decoded = if magnitude <= 0.04045 {
        magnitude / 12.92
    } else {
        exp(2.4 * ln((magnitude + 0.055) / 1.055))
    };
    if encoded < 0.0 { -decoded } else { decoded }
}

/// Each code's sRGB value.
static SRGB_VALUES: [f32; 1024] = {
    let mut values = [0.0; 1024];
    let mut code = 0;
    while code < 1024 {
        values[code] = srgb_at(code as f64) as f32;
        code += 1;
    }
    values
};

/// The sRGB value halfway between each pair of neighboring codes.
static SRGB_MIDPOINTS: [f32; 1023] = {
    let mut midpoints = [0.0; 1023];
    let mut code = 0;
    while code < 1023 {
        midpoints[code] = srgb_at(code as f64 + 0.5) as f32;
        code += 1;
    }
    midpoints
};

/// The natural logarithm of a positive finite `x`, to within a few units in
/// the last place, for building the tables.
pub(super) const fn ln(x: f64) -> f64 {
    // x = m * 2^e with m in [sqrt(1/2), sqrt(2)); ln m = 2 atanh((m - 1) / (m + 1)).
    let mut m = x;
    let mut e = 0.0;
    while m >= core::f64::consts::SQRT_2 {
        m /= 2.0;
        e += 1.0;
    }
    while m < core::f64::consts::FRAC_1_SQRT_2 {
        m *= 2.0;
        e -= 1.0;
    }
    let s = (m - 1.0) / (m + 1.0);
    let s2 = s * s;
    let mut term = s;
    let mut sum = 0.0;
    let mut k = 1.0;
    while k < 60.0 {
        sum += term / k;
        term *= s2;
        k += 2.0;
    }
    2.0 * sum + e * core::f64::consts::LN_2
}

/// `e^x` for the tables' small arguments.
pub(super) const fn exp(x: f64) -> f64 {
    // e^x = (e^(x / 2^8))^(2^8), the inner one by its series.
    let y = x / 256.0;
    let mut term = 1.0;
    let mut sum = 1.0;
    let mut k = 1.0;
    while k < 20.0 {
        term *= y / k;
        sum += term;
        k += 1.0;
    }
    let mut squarings = 0;
    while squarings < 8 {
        sum *= sum;
        squarings += 1;
    }
    sum
}

/// The half float nearest `value`, ties to even.
pub fn f16_bits(value: f32) -> u16 {
    let bits = value.to_bits();
    let sign = (bits >> 16 & 0x8000) as u16;
    let exponent = (bits >> 23 & 0xff) as i32;
    let mantissa = bits & 0x7f_ffff;
    if exponent == 0xff {
        return sign | 0x7c00 | if mantissa != 0 { 0x200 } else { 0 };
    }
    let unbiased = exponent - 127;
    if unbiased > 15 {
        return sign | 0x7c00;
    }
    // The half's mantissa with its implicit bit, and the bits shifted out.
    let (shift, full) = if unbiased >= -14 {
        (13, mantissa)
    } else {
        // Subnormal halves: shift the implicit bit in as well.
        let shift = (-14 - unbiased) as u32 + 13;
        if shift > 24 {
            return sign;
        }
        (shift, mantissa | 0x80_0000)
    };
    let kept = full >> shift;
    let rest = full & ((1 << shift) - 1);
    let half_way = 1 << (shift - 1);
    let rounded = kept + u32::from(rest > half_way || rest == half_way && kept & 1 == 1);
    let biased = if unbiased >= -14 {
        // A carry out of the mantissa raises the exponent, to infinity at most.
        (((unbiased + 15) as u32) << 10) + rounded
    } else {
        rounded
    };
    sign | biased.min(0x7c00) as u16
}

/// The value of a half float.
pub fn f16_value(bits: u16) -> f32 {
    let sign = u32::from(bits & 0x8000) << 16;
    let exponent = u32::from(bits >> 10 & 0x1f);
    let mantissa = u32::from(bits & 0x3ff);
    let magnitude = match exponent {
        0 => {
            // Subnormal: mantissa * 2^-24.
            let value = mantissa as f32 * (1.0 / 16_777_216.0);
            return if sign != 0 { -value } else { value };
        }
        0x1f => 0x7f80_0000 | mantissa << 13,
        _ => (exponent + 112) << 23 | mantissa << 13,
    };
    f32::from_bits(sign | magnitude)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINEAR: Codes = Codes {
        alpha: false,
        srgb: false,
    };
    const SRGB: Codes = Codes {
        alpha: false,
        srgb: true,
    };
    const ALPHA: Codes = Codes {
        alpha: true,
        srgb: false,
    };

    fn packed(red: u32, green: u32, blue: u32) -> [u8; 4] {
        (blue | green << 10 | red << 20 | 3 << 30).to_le_bytes()
    }

    #[test]
    fn reads_match_an_apple_gpu() {
        // Values an M-series GPU read (macOS 27.2): code -> red.
        for (code, value) in [
            (1, -0.7509804),
            (383, -0.0019608),
            (384, 0.0),
            (510, 0.2470588),
            (894, 1.0),
            (1023, 1.2529411),
        ] {
            let read = LINEAR.read(&packed(code, 384, 384));
            assert!((read[0] - value).abs() < 1e-6, "{code}: {}", read[0]);
            assert_eq!(read[3], 1.0);
        }
        // sRGB: the GPU's values are within 1/8192.
        for (code, value) in [
            (1, -0.5240479),
            (385, 0.0001221),
            (510, 0.0496826),
            (640, 0.2158203),
            (895, 1.0045166),
            (1023, 1.6749268),
        ] {
            let read = SRGB.read(&packed(code, 384, 384));
            assert!((read[0] - value).abs() < 1.3e-4, "{code}: {}", read[0]);
        }
    }

    #[test]
    fn alpha_and_words_match_an_apple_gpu() {
        // Blue 384, green 894 with stray low bits, red 1023, alpha 640.
        let mut texel = [0u8; 8];
        for (at, word) in [
            (0, 384 << 6),
            (2, 894 << 6 | 63),
            (4, 1023 << 6),
            (6, 640 << 6),
        ] {
            texel[at..at + 2].copy_from_slice(&(word as u16).to_le_bytes());
        }
        let read = ALPHA.read(&texel);
        assert!((read[0] - 1.2529411).abs() < 1e-6);
        assert_eq!(read[1], 1.0);
        assert_eq!(read[2], 0.0);
        assert!((read[3] - 0.5019608).abs() < 1e-6);
        // Alpha codes outside [384, 894] read clamped.
        texel[6..8].copy_from_slice(&((1 << 6) as u16).to_le_bytes());
        assert_eq!(ALPHA.read(&texel)[3], 0.0);
    }

    #[test]
    fn writes_match_an_apple_gpu() {
        // Value -> code an M-series GPU wrote, ties to even (0.75 -> 766).
        for (value, code) in [
            (-1.0, 0),
            (-0.5, 129),
            (0.0, 384),
            (0.001, 385),
            (0.0009, 384),
            (0.5, 639),
            (0.75, 766),
            (1.0, 894),
            (1.2509804, 1022),
            (2.0, 1023),
            (-0.1, 333),
        ] {
            let mut out = [0; 4];
            LINEAR.write([value, 0.0, 0.0, 1.0], &mut out);
            assert_eq!(u32::from_le_bytes(out) >> 20 & 0x3ff, code, "{value}");
            assert_eq!(u32::from_le_bytes(out) >> 30, 3);
        }
        for (value, code) in [
            (-0.5, 9),
            (0.5, 759),
            (1.2509804, 947),
            (2.0, 1023),
            (0.25, 658),
        ] {
            let mut out = [0; 4];
            SRGB.write([value, 0.0, 0.0, 1.0], &mut out);
            assert_eq!(u32::from_le_bytes(out) >> 20 & 0x3ff, code, "{value}");
        }
        let mut out = [0; 8];
        ALPHA.write([0.0, 0.0, 0.0, 2.0], &mut out);
        assert_eq!(u16::from_le_bytes([out[6], out[7]]), 894 << 6);
        ALPHA.write([0.0, 0.0, 0.0, -1.0], &mut out);
        assert_eq!(u16::from_le_bytes([out[6], out[7]]), 384 << 6);
    }

    #[test]
    fn every_code_survives_half_float_storage() {
        for codes in [
            LINEAR,
            SRGB,
            ALPHA,
            Codes {
                alpha: true,
                srgb: true,
            },
        ] {
            for code in 0..1024u32 {
                let alpha = code.clamp(ALPHA_ZERO, ALPHA_ONE);
                let mut metal = [0u8; 8];
                if codes.alpha {
                    for (at, word) in [(0, code), (2, code), (4, code), (6, alpha)] {
                        metal[at..at + 2].copy_from_slice(&((word << 6) as u16).to_le_bytes());
                    }
                } else {
                    metal[..4].copy_from_slice(&packed(code, code, code));
                }
                let metal = &metal[..codes.metal_bytes()];
                let mut stored = [0; STORED_BYTES];
                codes.store(metal, &mut stored);
                let mut back = [0; 8];
                codes.load(&stored, &mut back[..codes.metal_bytes()]);
                assert_eq!(&back[..codes.metal_bytes()], metal, "{codes:?} {code}");
            }
        }
    }

    #[test]
    fn half_floats_round_to_nearest_even() {
        for (value, bits) in [
            (0.0, 0x0000),
            (-0.0, 0x8000),
            (1.0, 0x3c00),
            (-2.0, 0xc000),
            (65504.0, 0x7bff),
            (65520.0, 0x7c00),
            (1.0 + 1.0 / 2048.0, 0x3c00),
            (1.0 + 3.0 / 2048.0, 0x3c02),
            (6.1035156e-5, 0x0400),
            (5.9604645e-8, 0x0001),
            (2.9802322e-8, 0x0000),
            (f32::INFINITY, 0x7c00),
        ] {
            assert_eq!(f16_bits(value), bits, "{value}");
        }
        for bits in (0..=0xffffu16).filter(|bits| bits & 0x7c00 != 0x7c00) {
            assert_eq!(f16_bits(f16_value(bits)), bits, "{bits:#x}");
        }
    }
}
