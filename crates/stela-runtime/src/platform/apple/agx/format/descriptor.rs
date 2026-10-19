//! Texture, PBE and sampler descriptors (cmdbuf.xml `Texture`, `PBE`,
//! `Sampler`, `Border`; Mesa `hk_image_view.c` and `agx_state.c` show how
//! each field is filled).
//!
//! Field notes (Public, from those fillers):
//! - Texture `Stride` holds a linear stride minus 16 in 16-byte units, the
//!   PBE `Stride` a linear stride minus 4 in bytes; linear arrays carry
//!   `Depth (linear)` and `Layer stride (linear)` (minus 0x80, 128-byte
//!   units) in the extended word.
//! - `Address`/`Buffer` point at layer 0 level 0; `First level`/`Last level`
//!   (texture) and `Level` (PBE) select within the miptree, whose shape the
//!   hardware derives from the dimensions (Mesa: "hardware strides are based
//!   on the maximum number of levels"). `Unk mipmapped` marks an allocated
//!   full chain (Inferred: Mesa sets it exactly when the image has levels).
//! - `Compressed` with `Extended` adds the acceleration (metadata) buffer.

/// `size` bits from `start` of a little-endian descriptor.
pub fn bits(bytes: &[u8], start: u32, size: u32) -> u64 {
    let mut value = 0u64;
    for i in 0..size {
        let bit = start + i;
        let byte = bytes[(bit / 8) as usize];
        value |= u64::from(byte >> (bit % 8) & 1) << i;
    }
    value
}

/// `Texture dimension`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dimension {
    D1,
    D1Array,
    D2,
    D2Array,
    D2Multisampled,
    D3,
    Cube,
    CubeArray,
    D2ArrayMultisampled,
}

impl Dimension {
    pub fn from_field(value: u64) -> Option<Self> {
        Some(match value {
            0 => Dimension::D1,
            1 => Dimension::D1Array,
            2 => Dimension::D2,
            3 => Dimension::D2Array,
            4 => Dimension::D2Multisampled,
            5 => Dimension::D3,
            6 => Dimension::Cube,
            7 => Dimension::CubeArray,
            8 => Dimension::D2ArrayMultisampled,
            _ => return None,
        })
    }

    pub fn multisampled(self) -> bool {
        matches!(
            self,
            Dimension::D2Multisampled | Dimension::D2ArrayMultisampled
        )
    }

    pub fn arrayed(self) -> bool {
        matches!(
            self,
            Dimension::D1Array
                | Dimension::D2Array
                | Dimension::CubeArray
                | Dimension::D2ArrayMultisampled
        )
    }

    pub fn cube(self) -> bool {
        matches!(self, Dimension::Cube | Dimension::CubeArray)
    }
}

/// `Layout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tiling {
    Linear,
    Twiddled,
    Gpu,
}

fn tiling(value: u64) -> Result<Tiling, &'static str> {
    match value {
        0 => Ok(Tiling::Linear),
        1 => Ok(Tiling::Twiddled),
        2 => Ok(Tiling::Gpu),
        _ => Err("the interchange layout is not described publicly"),
    }
}

/// `Channel` of a swizzle: a component or a constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Component(usize),
    One,
    Zero,
}

fn channel(value: u64) -> Result<Channel, &'static str> {
    match value {
        0..=3 => Ok(Channel::Component(value as usize)),
        4 => Ok(Channel::One),
        5 => Ok(Channel::Zero),
        _ => Err("a swizzle channel the enumeration lacks"),
    }
}

/// `Image Mode`.
const MODE_NORMAL: u64 = 0;

/// A decoded texture descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Texture {
    pub dimension: Dimension,
    pub tiling: Tiling,
    pub channels: u32,
    pub ty: u32,
    pub swizzle: [Channel; 4],
    pub width: u32,
    pub height: u32,
    pub first_level: u32,
    pub last_level: u32,
    pub samples: u32,
    pub address: u64,
    pub mipmapped: bool,
    pub compressed: bool,
    pub srgb: bool,
    pub srgb_2_channel: bool,
    /// Layers (or depth for 3D).
    pub depth: u32,
    pub page_aligned_layers: bool,
    /// Linear layouts: bytes per row, and per layer for arrays.
    pub linear_stride: u32,
    pub linear_layer_stride: Option<u64>,
    pub acceleration_buffer: Option<u64>,
}

/// `Sample Count`.
fn samples(value: u64) -> u32 {
    if value == 0 { 2 } else { 4 }
}

impl Texture {
    pub fn decode(bytes: &[u8; 24]) -> Result<Self, &'static str> {
        let field = |start, size| bits(bytes, start, size);
        let dimension = Dimension::from_field(field(0, 4))
            .ok_or("a texture dimension the enumeration lacks")?;
        let tiling = tiling(field(4, 2))?;
        if field(104, 2) != MODE_NORMAL {
            return Err("sparse and counter image modes are not modeled");
        }
        let extended = field(127, 1) != 0;
        let compressed = field(103, 1) != 0;
        if field(106, 2) != 0 {
            return Err("a texture compression field other than 0 (unrecorded)");
        }
        let linear = tiling == Tiling::Linear;
        let (depth, linear_layer_stride) = if linear && extended && !compressed {
            (
                field(128, 11) as u32 + 1,
                Some((field(139, 27) << 7) + 0x80),
            )
        } else if linear {
            (1, None)
        } else {
            (field(110, 14) as u32 + 1, None)
        };
        Ok(Texture {
            dimension,
            tiling,
            channels: field(6, 7) as u32,
            ty: field(13, 3) as u32,
            swizzle: [
                channel(field(16, 3))?,
                channel(field(19, 3))?,
                channel(field(22, 3))?,
                channel(field(25, 3))?,
            ],
            width: field(28, 14) as u32 + 1,
            height: field(42, 14) as u32 + 1,
            first_level: field(56, 4) as u32,
            last_level: field(60, 4) as u32,
            samples: if dimension.multisampled() {
                samples(field(64, 1))
            } else {
                1
            },
            address: field(66, 36) << 4,
            mipmapped: field(102, 1) != 0,
            compressed,
            srgb: field(108, 1) != 0,
            srgb_2_channel: field(109, 1) != 0,
            depth,
            page_aligned_layers: field(126, 1) != 0,
            linear_stride: ((field(110, 18) << 4) + 16) as u32,
            linear_layer_stride,
            acceleration_buffer: (compressed && extended).then(|| field(128, 64) << 4),
        })
    }
}

/// A decoded PBE descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pbe {
    pub dimension: Dimension,
    pub tiling: Tiling,
    pub channels: u32,
    pub ty: u32,
    /// Where each component of the value goes (`Swizzle R` names the
    /// memory component R is stored from).
    pub swizzle: [usize; 4],
    pub width: u32,
    pub height: u32,
    pub rotate_90: bool,
    pub flip_vertical: bool,
    pub samples: u32,
    pub mipmapped: bool,
    pub compressed: bool,
    pub buffer: u64,
    pub level: u32,
    pub levels: u32,
    pub layers: u32,
    pub page_aligned_layers: bool,
    pub srgb: bool,
    pub linear_stride: u32,
    pub linear_layer_stride: Option<u64>,
    pub acceleration_buffer: Option<u64>,
}

impl Pbe {
    pub fn decode(bytes: &[u8; 24]) -> Result<Self, &'static str> {
        let field = |start, size| bits(bytes, start, size);
        let dimension =
            Dimension::from_field(field(0, 4)).ok_or("a PBE dimension the enumeration lacks")?;
        let tiling = tiling(field(4, 2))?;
        if field(60, 2) != MODE_NORMAL {
            return Err("sparse and counter image modes are not modeled");
        }
        let extended = field(127, 1) != 0;
        let compressed = field(59, 1) != 0;
        let linear = tiling == Tiling::Linear;
        let (layers, linear_layer_stride) = if linear && extended && !compressed {
            (
                field(128, 11) as u32 + 1,
                Some((field(139, 27) << 7) + 0x80),
            )
        } else if linear {
            (1, None)
        } else {
            (field(108, 14) as u32 + 1, None)
        };
        Ok(Pbe {
            dimension,
            tiling,
            channels: field(6, 7) as u32,
            ty: field(13, 3) as u32,
            swizzle: [field(16, 2), field(18, 2), field(20, 2), field(22, 2)].map(|v| v as usize),
            width: field(24, 14) as u32 + 1,
            height: field(38, 14) as u32 + 1,
            rotate_90: field(53, 1) != 0,
            flip_vertical: field(54, 1) != 0,
            samples: if dimension.multisampled() {
                samples(field(56, 1))
            } else {
                1
            },
            mipmapped: field(58, 1) != 0,
            compressed,
            buffer: field(64, 36) << 4,
            level: field(100, 4) as u32,
            levels: if linear { 1 } else { field(104, 4) as u32 + 1 },
            layers,
            page_aligned_layers: field(124, 1) != 0,
            srgb: field(125, 1) != 0,
            linear_stride: field(104, 21) as u32 + 4,
            linear_layer_stride,
            acceleration_buffer: (compressed && extended).then(|| field(128, 64) << 4),
        })
    }
}

/// `Wrap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrap {
    ClampToEdge,
    Repeat,
    MirroredRepeat,
    ClampToBorder,
    /// GL's `GL_CLAMP`: clamp the coordinate to [0, 1] and filter with the
    /// border.
    ClampGl,
    MirroredClampToEdge,
}

/// `Filter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    Nearest,
    Linear,
}

/// `Mip filter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MipFilter {
    None,
    Nearest,
    Linear,
}

/// `Border colour`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Border {
    TransparentBlack,
    OpaqueBlack,
    OpaqueWhite,
    /// The four 32-bit channels of the extended state.
    Custom([u32; 4]),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sampler {
    pub min_lod: f32,
    pub max_lod: f32,
    pub max_anisotropy: u32,
    pub magnify: Filter,
    pub minify: Filter,
    pub mip: MipFilter,
    pub wrap: [Wrap; 3],
    pub pixel_coordinates: bool,
    /// `Compare func` when compare is enabled.
    pub compare: Option<u32>,
    pub border: Border,
    pub seamful_cube_maps: bool,
}

/// cmdbuf.xml `lod`: unsigned 4.6 fixed point.
fn lod(value: u64) -> f32 {
    value as f32 / 64.0
}

fn filter(value: u64) -> Result<Filter, &'static str> {
    match value {
        0 => Ok(Filter::Nearest),
        1 => Ok(Filter::Linear),
        2 => Err("bicubic filtering is not modeled"),
        _ => Err("a filter the enumeration lacks"),
    }
}

fn wrap(value: u64) -> Result<Wrap, &'static str> {
    Ok(match value {
        0 => Wrap::ClampToEdge,
        1 => Wrap::Repeat,
        2 => Wrap::MirroredRepeat,
        3 => Wrap::ClampToBorder,
        4 => Wrap::ClampGl,
        5 => Wrap::MirroredClampToEdge,
        _ => return Err("a wrap mode the enumeration lacks"),
    })
}

impl Sampler {
    /// `state` is the 8-byte sampler, followed by its 16-byte border when
    /// `extended`.
    pub fn decode(state: &[u8; 24], extended: bool) -> Result<Self, &'static str> {
        let field = |start, size| bits(state, start, size);
        let border = match field(55, 2) {
            0 => Border::TransparentBlack,
            1 => Border::OpaqueBlack,
            2 => Border::OpaqueWhite,
            _ if extended => {
                Border::Custom([0, 1, 2, 3].map(|i| bits(state, 64 + 32 * i, 32) as u32))
            }
            _ => return Err("a custom border colour without extended sampler states"),
        };
        Ok(Sampler {
            min_lod: lod(field(0, 10)),
            max_lod: lod(field(10, 10)),
            max_anisotropy: 1 << field(20, 3),
            magnify: filter(field(23, 2))?,
            minify: filter(field(25, 2))?,
            mip: match field(27, 2) {
                0 => MipFilter::None,
                1 => MipFilter::Nearest,
                2 => MipFilter::Linear,
                _ => return Err("a mip filter the enumeration lacks"),
            },
            wrap: [
                wrap(field(29, 3))?,
                wrap(field(32, 3))?,
                wrap(field(35, 3))?,
            ],
            pixel_coordinates: field(38, 1) != 0,
            compare: (field(42, 1) != 0).then(|| field(39, 3) as u32),
            border,
            seamful_cube_maps: field(57, 1) != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Set `size` bits of `bytes` at `start`.
    pub(crate) fn put(bytes: &mut [u8], start: u32, size: u32, value: u64) {
        for i in 0..size {
            let bit = start + i;
            let byte = &mut bytes[(bit / 8) as usize];
            *byte &= !(1 << (bit % 8));
            *byte |= ((value >> i & 1) as u8) << (bit % 8);
        }
    }

    #[test]
    fn a_linear_texture_descriptor_decodes() {
        let mut d = [0u8; 24];
        put(&mut d, 0, 4, 2); // 2D
        put(&mut d, 6, 7, 0x28); // R8G8B8A8
        put(&mut d, 16, 3, 2); // R <- B
        put(&mut d, 19, 3, 1);
        put(&mut d, 22, 3, 0);
        put(&mut d, 25, 3, 4); // A = 1
        put(&mut d, 28, 14, 63);
        put(&mut d, 42, 14, 31);
        put(&mut d, 66, 36, 0x1_0000_0000 >> 4);
        put(&mut d, 110, 18, (256 - 16) >> 4);
        let t = Texture::decode(&d).unwrap();
        assert_eq!(
            (t.width, t.height, t.linear_stride, t.address),
            (64, 32, 256, 0x1_0000_0000)
        );
        assert_eq!(
            t.swizzle,
            [
                Channel::Component(2),
                Channel::Component(1),
                Channel::Component(0),
                Channel::One
            ]
        );
        assert_eq!(t.tiling, Tiling::Linear);
    }

    #[test]
    fn samplers_decode_filters_wraps_and_borders() {
        let mut s = [0u8; 24];
        put(&mut s, 10, 10, 4 * 64); // max LOD 4
        put(&mut s, 23, 2, 1);
        put(&mut s, 25, 2, 1);
        put(&mut s, 27, 2, 2);
        put(&mut s, 29, 3, 1);
        put(&mut s, 32, 3, 3);
        put(&mut s, 55, 2, 3);
        put(&mut s, 64, 32, 0x3f80_0000);
        let sampler = Sampler::decode(&s, true).unwrap();
        assert_eq!(sampler.max_lod, 4.0);
        assert_eq!(sampler.wrap[..2], [Wrap::Repeat, Wrap::ClampToBorder]);
        assert_eq!(sampler.mip, MipFilter::Linear);
        assert_eq!(sampler.border, Border::Custom([0x3f80_0000, 0, 0, 0]));
        assert!(Sampler::decode(&s, false).is_err());
    }
}
