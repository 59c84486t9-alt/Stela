//! The formats shader memory instructions name (`AGX2.xml` enum `format`,
//! Mesa `ail_isa_format`): how `load`/`store`, the stack, threadgroup memory
//! and the tilebuffer convert between memory bytes and registers.
//!
//! Each unpacked format stores one element per component (i8, i16, i32,
//! f16, the 8- and 16-bit normalized integers, sRGB RGBA8); the packed ones
//! (RGB10A2, R11G11B10F, RGB9E5) store every component in one 32-bit word
//! and take no partial masks (Mesa `ail_isa_format_supports_mask`).
//! Normalized and float formats produce f16 in a 16-bit register and f32 in
//! a 32-bit one; integer formats zero-extend into wider registers and
//! truncate into narrower ones (Inferred: Mesa only pairs each format with
//! its natural register size). sRGB converts R, G and B and leaves alpha
//! linear. The `_rtz` small-float variants round toward zero when storing.

use super::pixel;
use crate::platform::apple::agx::isa::float::{
    f32_to_half, f64_to_f32_ftz, f64_to_half, half_to_f32,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsaFormat {
    I8,
    I16,
    I32,
    F16,
    U8Norm,
    S8Norm,
    U16Norm,
    S16Norm,
    Rgb10A2,
    Srgba8,
    Rg11B10F { toward_zero: bool },
    Rgb9E5 { toward_zero: bool },
}

impl IsaFormat {
    /// The format of a `format` field value.
    pub fn from_field(value: u32) -> Option<Self> {
        Some(match value {
            0 => IsaFormat::I8,
            1 => IsaFormat::I16,
            2 => IsaFormat::I32,
            3 => IsaFormat::F16,
            4 => IsaFormat::U8Norm,
            5 => IsaFormat::S8Norm,
            6 => IsaFormat::U16Norm,
            7 => IsaFormat::S16Norm,
            8 => IsaFormat::Rgb10A2,
            10 => IsaFormat::Srgba8,
            12 => IsaFormat::Rg11B10F { toward_zero: false },
            13 => IsaFormat::Rgb9E5 { toward_zero: false },
            14 => IsaFormat::Rg11B10F { toward_zero: true },
            15 => IsaFormat::Rgb9E5 { toward_zero: true },
            _ => return None,
        })
    }

    /// One word holds every component.
    pub fn packed(self) -> bool {
        matches!(
            self,
            IsaFormat::Rgb10A2 | IsaFormat::Rg11B10F { .. } | IsaFormat::Rgb9E5 { .. }
        )
    }

    /// Bytes per element: per component when unpacked, per word when packed.
    pub fn element_bytes(self) -> usize {
        match self {
            IsaFormat::I8 | IsaFormat::U8Norm | IsaFormat::S8Norm | IsaFormat::Srgba8 => 1,
            IsaFormat::I16 | IsaFormat::F16 | IsaFormat::U16Norm | IsaFormat::S16Norm => 2,
            _ => 4,
        }
    }

    /// Components a packed word holds.
    pub fn packed_components(self) -> usize {
        match self {
            IsaFormat::Rgb10A2 => 4,
            _ => 3,
        }
    }

    /// Register bits for component `component` of an unpacked element
    /// (`bytes`, little-endian) in a register of `register_bits`.
    pub fn load(self, component: usize, bytes: &[u8], register_bits: u32) -> u64 {
        let raw = bytes
            .iter()
            .take(self.element_bytes())
            .enumerate()
            .fold(0u32, |value, (i, byte)| value | u32::from(*byte) << (8 * i));
        let float = |value: f64| float_register(value, register_bits);
        match self {
            IsaFormat::I8 | IsaFormat::I16 | IsaFormat::I32 => {
                u64::from(raw) & ((1u64 << register_bits) - 1)
            }
            IsaFormat::F16 => {
                if register_bits == 16 {
                    u64::from(raw as u16)
                } else {
                    u64::from(half_to_f32(raw as u16).to_bits())
                }
            }
            IsaFormat::U8Norm => float(pixel::unorm_to_float(raw, 8)),
            IsaFormat::S8Norm => float(pixel::snorm_to_float(raw, 8)),
            IsaFormat::U16Norm => float(pixel::unorm_to_float(raw, 16)),
            IsaFormat::S16Norm => float(pixel::snorm_to_float(raw, 16)),
            IsaFormat::Srgba8 => {
                let value = pixel::unorm_to_float(raw, 8);
                float(if component < 3 {
                    pixel::srgb_to_linear(value)
                } else {
                    value
                })
            }
            _ => unreachable!("packed formats load through load_packed"),
        }
    }

    /// The bytes of component `component` of an unpacked element from
    /// register bits.
    pub fn store(self, component: usize, value: u64, register_bits: u32) -> [u8; 4] {
        let read_float = || register_float(value, register_bits);
        let raw: u32 = match self {
            IsaFormat::I8 | IsaFormat::I16 | IsaFormat::I32 => value as u32,
            IsaFormat::F16 => {
                if register_bits == 16 {
                    u32::from(value as u16)
                } else {
                    u32::from(f32_to_half(f32::from_bits(value as u32)))
                }
            }
            IsaFormat::U8Norm => pixel::float_to_unorm(read_float(), 8),
            IsaFormat::S8Norm => pixel::float_to_snorm(read_float(), 8),
            IsaFormat::U16Norm => pixel::float_to_unorm(read_float(), 16),
            IsaFormat::S16Norm => pixel::float_to_snorm(read_float(), 16),
            IsaFormat::Srgba8 => {
                let linear = read_float();
                let encoded = if component < 3 {
                    pixel::linear_to_srgb(linear)
                } else {
                    linear
                };
                pixel::float_to_unorm(encoded, 8)
            }
            _ => unreachable!("packed formats store through store_packed"),
        };
        raw.to_le_bytes()
    }

    /// The register bits of every component of a packed word.
    pub fn load_packed(self, word: u32, register_bits: u32) -> [u64; 4] {
        let mut values = [0.0f64; 4];
        match self {
            IsaFormat::Rgb10A2 => values = pixel::unpack_rgb10a2(word),
            IsaFormat::Rg11B10F { .. } => {
                values[..3].copy_from_slice(&pixel::unpack_r11g11b10(word))
            }
            _ => values[..3].copy_from_slice(&pixel::unpack_rgb9e5(word)),
        }
        values.map(|value| float_register(value, register_bits))
    }

    /// A packed word from the register bits of its components.
    pub fn store_packed(self, components: [u64; 4], register_bits: u32) -> u32 {
        let values = components.map(|value| register_float(value, register_bits));
        match self {
            IsaFormat::Rgb10A2 => pixel::pack_rgb10a2(values),
            IsaFormat::Rg11B10F { toward_zero } => {
                pixel::pack_r11g11b10([values[0], values[1], values[2]], toward_zero)
            }
            IsaFormat::Rgb9E5 { toward_zero } => {
                pixel::pack_rgb9e5([values[0], values[1], values[2]], toward_zero)
            }
            _ => unreachable!("unpacked formats store per component"),
        }
    }
}

/// A float as register bits of the register's size.
pub fn float_register(value: f64, register_bits: u32) -> u64 {
    if register_bits == 16 {
        u64::from(f64_to_half(value))
    } else {
        u64::from(f64_to_f32_ftz(value).to_bits())
    }
}

/// Register bits as a float.
pub fn register_float(value: u64, register_bits: u32) -> f64 {
    if register_bits == 16 {
        f64::from(half_to_f32(value as u16))
    } else {
        f64::from(f32::from_bits(value as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpacked_formats_convert_per_component() {
        assert_eq!(
            IsaFormat::U8Norm.load(0, &[255], 32),
            u64::from(1.0f32.to_bits())
        );
        assert_eq!(IsaFormat::U8Norm.load(0, &[0], 16), 0);
        assert_eq!(IsaFormat::S16Norm.load(0, &[0x01, 0x80], 16), 0xbc00);
        assert_eq!(IsaFormat::I8.load(0, &[0xff], 32), 0xff);
        assert_eq!(IsaFormat::I32.load(0, &[1, 2, 3, 4], 16), 0x0201);
        assert_eq!(IsaFormat::U8Norm.store(0, 0x3800, 16)[0], 128);
        // sRGB: alpha stays linear.
        let half = u64::from(0.5f32.to_bits());
        assert_eq!(IsaFormat::Srgba8.store(3, half, 32)[0], 128);
        assert_eq!(IsaFormat::Srgba8.store(0, half, 32)[0], 188);
    }

    #[test]
    fn packed_formats_hold_every_component_in_a_word() {
        let one = u64::from(1.0f32.to_bits());
        let word = IsaFormat::Rgb10A2.store_packed([one, 0, one, one], 32);
        assert_eq!(word, 0xc000_03ff | 0x3ff << 20);
        assert_eq!(IsaFormat::Rgb10A2.load_packed(word, 32), [one, 0, one, one]);
        let rtz = IsaFormat::from_field(14).unwrap();
        assert_eq!(rtz, IsaFormat::Rg11B10F { toward_zero: true });
        assert!(rtz.packed());
        assert_eq!(IsaFormat::from_field(9), None);
    }
}
