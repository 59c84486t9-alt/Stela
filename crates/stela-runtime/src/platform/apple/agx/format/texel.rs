//! Texel formats: a descriptor's `Channels` and `Texture Type` as element
//! bytes and values (cmdbuf.xml enums; the per-format channel lists of Mesa
//! `layout/formats.c`).
//!
//! Channels pack least significant bit first, as Gallium names them (R5G6B5
//! has R in bits 0..4). Components a layout lacks read as 0 (colour) and 1
//! (alpha) before the descriptor's swizzle. Unorm/snorm convert to [0, 1] and
//! [-1, 1], floats widen exactly, integers keep their value. sRGB decodes R,
//! G and B of 8-bit unorm layouts (G of a two-channel layout only with
//! `sRGB 2-channel`). Extended-range (`XR`) types, the 4:2:2 layouts (whose
//! component order no public source records) and PVRTC refuse by name;
//! block-compressed layouts decode through [`super::block`].

use super::{block, pixel};
use crate::platform::apple::agx::isa::float::half_to_f32;

/// `Channels` values.
pub mod channels {
    pub const R8: u32 = 0x00;
    pub const R16: u32 = 0x09;
    pub const R8G8: u32 = 0x0a;
    pub const R5G6B5: u32 = 0x0b;
    pub const R4G4B4A4: u32 = 0x0c;
    pub const A1R5G5B5: u32 = 0x0d;
    pub const R5G5B5A1: u32 = 0x0e;
    pub const R32: u32 = 0x21;
    pub const R16G16: u32 = 0x23;
    pub const R11G11B10: u32 = 0x25;
    pub const R10G10B10A2: u32 = 0x26;
    pub const R9G9B9E5: u32 = 0x27;
    pub const R8G8B8A8: u32 = 0x28;
    pub const R32G32: u32 = 0x31;
    pub const R16G16B16A16: u32 = 0x32;
    pub const R32G32B32_EMULATED: u32 = 0x36;
    pub const R32G32B32A32: u32 = 0x38;
    pub const GBGR_422: u32 = 0x40;
    pub const BGRG_422: u32 = 0x41;
    pub const PVRTC_2BPP: u32 = 0x50;
    pub const PVRTC_4BPP: u32 = 0x51;
    pub const ETC2_RGB8: u32 = 0x58;
    pub const ETC2_RGBA8: u32 = 0x59;
    pub const ETC2_RGB8A1: u32 = 0x5a;
    pub const EAC_R11: u32 = 0x5b;
    pub const EAC_RG11: u32 = 0x5c;
    pub const ASTC_FIRST: u32 = 0x60;
    pub const ASTC_LAST: u32 = 0x6d;
    pub const BC1: u32 = 0x74;
    pub const BC2: u32 = 0x75;
    pub const BC3: u32 = 0x76;
    pub const BC4: u32 = 0x77;
    pub const BC5: u32 = 0x78;
    pub const BC6H: u32 = 0x79;
    pub const BC6H_UFLOAT: u32 = 0x7a;
    pub const BC7: u32 = 0x7b;
}

/// `Texture Type` values.
pub mod ty {
    pub const UNORM: u32 = 0;
    pub const SNORM: u32 = 1;
    pub const UINT: u32 = 2;
    pub const SINT: u32 = 3;
    pub const FLOAT: u32 = 4;
    pub const XR: u32 = 5;
}

/// How a texel's values are read by the shader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Normalized or float: filterable.
    Float,
    Uint,
    Sint,
}

/// One texel before swizzling: four components, absent ones defaulted.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Texel {
    pub kind: Kind,
    pub value: [f64; 4],
}

/// A texel format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Format {
    pub channels: u32,
    pub ty: u32,
    pub srgb: bool,
    pub srgb_2_channel: bool,
}

/// Bit widths of a packed or per-component layout.
fn widths(channels: u32) -> Option<&'static [u32]> {
    use channels::*;
    Some(match channels {
        R8 => &[8],
        R16 => &[16],
        R8G8 => &[8, 8],
        R5G6B5 => &[5, 6, 5],
        R4G4B4A4 => &[4, 4, 4, 4],
        R5G5B5A1 => &[5, 5, 5, 1],
        R32 => &[32],
        R16G16 => &[16, 16],
        R10G10B10A2 => &[10, 10, 10, 2],
        R8G8B8A8 => &[8, 8, 8, 8],
        R32G32 => &[32, 32],
        R16G16B16A16 => &[16, 16, 16, 16],
        R32G32B32A32 => &[32, 32, 32, 32],
        _ => return None,
    })
}

impl Format {
    /// Block width, height (pixels) and bytes.
    pub fn block(&self) -> Result<(u32, u32, u32), &'static str> {
        use channels::*;
        Ok(match self.channels {
            R11G11B10 | R9G9B9E5 | A1R5G5B5 => {
                (1, 1, if self.channels == A1R5G5B5 { 2 } else { 4 })
            }
            ETC2_RGB8 | ETC2_RGB8A1 | EAC_R11 | BC1 | BC4 => (4, 4, 8),
            ETC2_RGBA8 | EAC_RG11 | BC2 | BC3 | BC5 | BC6H | BC6H_UFLOAT | BC7 => (4, 4, 16),
            R32G32B32_EMULATED => return Err("the emulated R32G32B32 layout is software-only"),
            GBGR_422 | BGRG_422 => return Err("4:2:2 layouts (component order unrecorded)"),
            PVRTC_2BPP | PVRTC_4BPP => return Err("PVRTC is not modeled"),
            ASTC_FIRST..=ASTC_LAST => return Err("ASTC is not modeled"),
            other => {
                let widths = widths(other).ok_or("a channel layout the enumeration lacks")?;
                (1, 1, widths.iter().sum::<u32>() / 8)
            }
        })
    }

    pub fn block_compressed(&self) -> bool {
        self.block().is_ok_and(|(w, _, _)| w > 1)
    }

    pub fn kind(&self) -> Kind {
        match self.ty {
            ty::UINT => Kind::Uint,
            ty::SINT => Kind::Sint,
            _ => Kind::Float,
        }
    }

    /// Decode an uncompressed element.
    pub fn decode(&self, bytes: &[u8]) -> Result<Texel, &'static str> {
        use channels::*;
        if self.ty == ty::XR {
            return Err("extended-range (XR) types are not modeled");
        }
        let word = |i: usize| -> u64 {
            let mut v = 0u64;
            for (k, byte) in bytes.iter().skip(8 * i).take(8).enumerate() {
                v |= u64::from(*byte) << (8 * k);
            }
            v
        };
        let mut value = [0.0, 0.0, 0.0, 1.0];
        let float = self.ty == ty::FLOAT;
        match self.channels {
            R11G11B10 if float => {
                value[..3].copy_from_slice(&pixel::unpack_r11g11b10(word(0) as u32))
            }
            R9G9B9E5 if float => value[..3].copy_from_slice(&pixel::unpack_rgb9e5(word(0) as u32)),
            R11G11B10 | R9G9B9E5 => return Err("a small-float layout with a non-float type"),
            A1R5G5B5 => {
                let w = word(0) as u32;
                let fields = [w >> 1 & 0x1f, w >> 6 & 0x1f, w >> 11 & 0x1f, w & 1];
                for (c, (field, bits)) in fields.iter().zip([5, 5, 5, 1]).enumerate() {
                    value[c] = self.scalar(*field, bits)?;
                }
            }
            other => {
                let widths = widths(other).ok_or("a channel layout the enumeration lacks")?;
                let mut position = 0u32;
                for (c, &bits) in widths.iter().enumerate() {
                    let raw = read_bits(bytes, position, bits);
                    value[c] = self.scalar(raw, bits)?;
                    position += bits;
                }
            }
        }
        self.apply_srgb(&mut value);
        Ok(Texel {
            kind: self.kind(),
            value,
        })
    }

    /// Decode texel `at` of a compressed block.
    pub fn decode_block(&self, block: &[u8], at: block::Position) -> Result<Texel, &'static str> {
        use channels::*;
        let signed = match self.ty {
            ty::UNORM => false,
            ty::SNORM => true,
            _ => return Err("a block-compressed layout with a type other than unorm or snorm"),
        };
        let mut value = match (self.channels, signed) {
            (BC1, false) => block::bc1(block, at),
            (BC2, false) => block::bc2(block, at),
            (BC3, false) => block::bc3(block, at),
            (BC4, _) => block::bc4(block, at, signed),
            (BC5, _) => block::bc5(block, at, signed),
            (ETC2_RGB8, false) => block::etc2(block, at, false),
            (ETC2_RGB8A1, false) => block::etc2(block, at, true),
            (ETC2_RGBA8, false) => block::etc2_rgba8(block, at),
            (EAC_R11, _) => [block::eac11(block, at, signed), 0.0, 0.0, 1.0],
            (EAC_RG11, _) => [
                block::eac11(block, at, signed),
                block::eac11(&block[8..], at, signed),
                0.0,
                1.0,
            ],
            (BC6H | BC6H_UFLOAT | BC7, _) => return Err("BC6H and BC7 decoding is not modeled"),
            _ => return Err("a block-compressed layout and type pair the formats lack"),
        };
        if matches!(
            self.channels,
            BC1 | BC2 | BC3 | ETC2_RGB8 | ETC2_RGB8A1 | ETC2_RGBA8
        ) {
            self.apply_srgb(&mut value);
        }
        Ok(Texel {
            kind: Kind::Float,
            value,
        })
    }

    /// One component's value.
    fn scalar(&self, raw: u32, bits: u32) -> Result<f64, &'static str> {
        Ok(match self.ty {
            ty::UNORM => pixel::unorm_to_float(raw, bits),
            ty::SNORM => pixel::snorm_to_float(raw, bits),
            ty::UINT => f64::from(raw),
            ty::SINT => {
                let shift = 32 - bits;
                f64::from(((raw << shift) as i32) >> shift)
            }
            ty::FLOAT => match bits {
                16 => f64::from(half_to_f32(raw as u16)),
                32 => f64::from(f32::from_bits(raw)),
                _ => return Err("a float type on a component that is not 16 or 32 bits"),
            },
            _ => return Err("a texture type the enumeration lacks"),
        })
    }

    /// A custom border colour's channels (in memory order, before the
    /// swizzle). Each 32-bit word holds its channel encoded like memory at
    /// that channel's width: integers as-is, floats of 16 bits or fewer as
    /// halves, normalized values at the channel width, sRGB colour channels
    /// as 12-bit unorm (taken as the final value), BC4/BC5 as 14-bit and
    /// EAC as 11-bit normalized (Public: Mesa `agx_border.c`).
    pub fn border(&self, words: [u32; 4]) -> Result<[f64; 4], &'static str> {
        use channels::*;
        if self.ty == ty::XR {
            return Err("extended-range (XR) types are not modeled");
        }
        let half = |w: u32| f64::from(half_to_f32(w as u16));
        let unorm = |w: u32, bits| pixel::unorm_to_float(w, bits);
        let snorm = |w: u32, bits| pixel::snorm_to_float(w, bits);
        let signed = self.ty == ty::SNORM;
        let normalized = |w: u32, bits| {
            if signed {
                snorm(w, bits)
            } else {
                unorm(w, bits)
            }
        };
        let mut value = [0.0; 4];
        let srgb = self.srgb && self.ty == ty::UNORM;
        let colour_bits = |bits| if srgb { 12 } else { bits };
        match self.channels {
            R11G11B10 | R9G9B9E5 | BC6H | BC6H_UFLOAT => {
                for c in 0..3 {
                    value[c] = half(words[c]);
                }
            }
            BC1 | BC2 | BC3 | BC7 | ETC2_RGB8 | ETC2_RGBA8 | ETC2_RGB8A1 => {
                for c in 0..3 {
                    value[c] = unorm(words[c], colour_bits(8));
                }
                value[3] = unorm(words[3], 8);
            }
            BC4 | BC5 => {
                for c in 0..if self.channels == BC4 { 1 } else { 2 } {
                    value[c] = normalized(words[c], 14);
                }
            }
            EAC_R11 | EAC_RG11 => {
                for c in 0..if self.channels == EAC_R11 { 1 } else { 2 } {
                    value[c] = normalized(words[c], 11);
                }
            }
            other => {
                let widths: &[u32] = if other == A1R5G5B5 {
                    &[5, 5, 5, 1]
                } else {
                    widths(other)
                        .ok_or("a border for a channel layout without recorded channel widths")?
                };
                let colour_channels = if widths.len() == 2 && !self.srgb_2_channel {
                    1
                } else {
                    3
                };
                for (c, &bits) in widths.iter().enumerate() {
                    let w = words[c];
                    value[c] = match self.ty {
                        ty::UNORM if srgb && c < colour_channels => unorm(w, 12),
                        ty::UNORM => unorm(w, bits),
                        ty::SNORM => snorm(w, bits),
                        ty::UINT => f64::from(w),
                        ty::SINT => f64::from(w as i32),
                        ty::FLOAT if bits <= 16 => half(w),
                        ty::FLOAT => f64::from(f32::from_bits(w)),
                        _ => return Err("a texture type the enumeration lacks"),
                    };
                }
            }
        }
        Ok(value)
    }

    fn apply_srgb(&self, value: &mut [f64; 4]) {
        if !self.srgb || self.ty != ty::UNORM {
            return;
        }
        let components = widths(self.channels).map_or(3, |w| w.len());
        let converted = match components {
            1 => 1,
            2 if self.srgb_2_channel => 2,
            2 => 1,
            _ => 3,
        };
        for v in value.iter_mut().take(converted) {
            *v = pixel::srgb_to_linear(*v);
        }
    }

    /// Encode an element from component values (already in memory order).
    /// Floats round to nearest even, normalized values clamp and round,
    /// integers wrap to their width (Inferred: the PBE's integer overflow
    /// behaviour is unrecorded; Metal leaves it undefined).
    pub fn encode(&self, value: [f64; 4], out: &mut [u8]) -> Result<(), &'static str> {
        use channels::*;
        if self.ty == ty::XR {
            return Err("extended-range (XR) types are not modeled");
        }
        let mut value = value;
        if self.srgb && self.ty == ty::UNORM {
            let components = widths(self.channels).map_or(3, |w| w.len());
            let converted = match components {
                1 => 1,
                2 if self.srgb_2_channel => 2,
                2 => 1,
                _ => 3,
            };
            for v in value.iter_mut().take(converted) {
                *v = pixel::linear_to_srgb(*v);
            }
        }
        let float = self.ty == ty::FLOAT;
        match self.channels {
            R11G11B10 if float => {
                let w = pixel::pack_r11g11b10([value[0], value[1], value[2]], false);
                out[..4].copy_from_slice(&w.to_le_bytes());
            }
            R9G9B9E5 if float => {
                let w = pixel::pack_rgb9e5([value[0], value[1], value[2]], false);
                out[..4].copy_from_slice(&w.to_le_bytes());
            }
            R11G11B10 | R9G9B9E5 => return Err("a small-float layout with a non-float type"),
            A1R5G5B5 => {
                let f = |c: usize, bits| self.unscalar(value[c], bits);
                let w = f(3, 1)? | f(0, 5)? << 1 | f(1, 5)? << 6 | f(2, 5)? << 11;
                out[..2].copy_from_slice(&(w as u16).to_le_bytes());
            }
            other => {
                let widths = widths(other).ok_or("a channel layout the enumeration lacks")?;
                let mut position = 0u32;
                for (c, &bits) in widths.iter().enumerate() {
                    write_bits(out, position, bits, self.unscalar(value[c], bits)?);
                    position += bits;
                }
            }
        }
        Ok(())
    }

    fn unscalar(&self, value: f64, bits: u32) -> Result<u32, &'static str> {
        let mask = ((1u64 << bits) - 1) as u32;
        Ok(match self.ty {
            ty::UNORM => pixel::float_to_unorm(value, bits),
            ty::SNORM => pixel::float_to_snorm(value, bits),
            ty::UINT | ty::SINT => (value as i64 as u32) & mask,
            ty::FLOAT => match bits {
                16 => u32::from(crate::platform::apple::agx::isa::float::f64_to_half(value)),
                32 => (value as f32).to_bits(),
                _ => return Err("a float type on a component that is not 16 or 32 bits"),
            },
            _ => return Err("a texture type the enumeration lacks"),
        })
    }
}

fn read_bits(bytes: &[u8], start: u32, size: u32) -> u32 {
    (0..size).fold(0u32, |v, i| {
        let bit = start + i;
        v | u32::from(bytes[(bit / 8) as usize] >> (bit % 8) & 1) << i
    })
}

fn write_bits(bytes: &mut [u8], start: u32, size: u32, value: u32) {
    for i in 0..size {
        let bit = start + i;
        let byte = &mut bytes[(bit / 8) as usize];
        *byte = (*byte & !(1 << (bit % 8))) | (((value >> i) & 1) as u8) << (bit % 8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format(channels: u32, ty: u32) -> Format {
        Format {
            channels,
            ty,
            srgb: false,
            srgb_2_channel: false,
        }
    }

    #[test]
    fn packed_and_per_component_layouts_decode() {
        let rgba8 = format(channels::R8G8B8A8, ty::UNORM);
        let t = rgba8.decode(&[255, 0, 51, 255]).unwrap();
        assert_eq!(t.value, [1.0, 0.0, 0.2, 1.0]);
        let r5g6b5 = format(channels::R5G6B5, ty::UNORM);
        let t = r5g6b5.decode(&0xf800u16.to_le_bytes()).unwrap();
        assert_eq!(t.value, [0.0, 0.0, 1.0, 1.0]);
        let rg16f = format(channels::R16G16, ty::FLOAT);
        let t = rg16f.decode(&[0x00, 0x3c, 0x00, 0xc0]).unwrap();
        assert_eq!(t.value, [1.0, -2.0, 0.0, 1.0]);
        let r32i = format(channels::R32, ty::SINT);
        assert_eq!(r32i.decode(&(-5i32).to_le_bytes()).unwrap().value[0], -5.0);
        assert_eq!(r32i.decode(&[0; 4]).unwrap().kind, Kind::Sint);
    }

    #[test]
    fn srgb_decodes_colour_not_alpha_and_round_trips() {
        let srgb = Format {
            channels: channels::R8G8B8A8,
            ty: ty::UNORM,
            srgb: true,
            srgb_2_channel: false,
        };
        let t = srgb.decode(&[188, 0, 255, 128]).unwrap();
        assert!((t.value[0] - 0.5).abs() < 0.003);
        assert_eq!(t.value[3], 128.0 / 255.0);
        let mut out = [0u8; 4];
        srgb.encode(t.value, &mut out).unwrap();
        assert_eq!(out, [188, 0, 255, 128]);
    }

    #[test]
    fn unmodeled_layouts_refuse() {
        assert!(format(channels::GBGR_422, ty::UNORM).block().is_err());
        assert!(format(channels::ASTC_FIRST, ty::UNORM).block().is_err());
        assert!(format(channels::R8, ty::XR).decode(&[0]).is_err());
        assert_eq!(format(channels::BC3, ty::UNORM).block(), Ok((4, 4, 16)));
    }
}
