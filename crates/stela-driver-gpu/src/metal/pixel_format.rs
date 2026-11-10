//! Every `MTLPixelFormat`: its storage layout, numeric class and the Vulkan
//! format and view that realize it.
//!
//! Metal names packed formats from the least significant bits (`B5G6R5Unorm`
//! keeps blue in bits 0-4); Vulkan names them from the most significant bits,
//! so the realizations reverse the component order. A format without an
//! exact Vulkan equivalent is stored in another format that holds every
//! value it encodes ([`Encoding`]), or records why it has none.
use super::vulkan::{ComponentSwizzle, Format as VkFormat, ImageAspects};

pub mod extended_range;

raw_enum! {
    /// `MTLPixelFormat`, excluding `Invalid` (0) and the Metal 4 pipeline
    /// placeholder `Unspecialized` (263), which name no texture format.
    pub enum PixelFormat: u64 {
        A8Unorm = 1,
        R8Unorm = 10,
        R8UnormSrgb = 11,
        R8Snorm = 12,
        R8Uint = 13,
        R8Sint = 14,
        R16Unorm = 20,
        R16Snorm = 22,
        R16Uint = 23,
        R16Sint = 24,
        R16Float = 25,
        Rg8Unorm = 30,
        Rg8UnormSrgb = 31,
        Rg8Snorm = 32,
        Rg8Uint = 33,
        Rg8Sint = 34,
        B5G6R5Unorm = 40,
        A1Bgr5Unorm = 41,
        Abgr4Unorm = 42,
        Bgr5A1Unorm = 43,
        Rgb8Unorm = 45,
        Rgb8Snorm = 46,
        Rgb8Uint = 47,
        Rgb8Sint = 48,
        R32Uint = 53,
        R32Sint = 54,
        R32Float = 55,
        Rg16Unorm = 60,
        Rg16Snorm = 62,
        Rg16Uint = 63,
        Rg16Sint = 64,
        Rg16Float = 65,
        Rgba8Unorm = 70,
        Rgba8UnormSrgb = 71,
        Rgba8Snorm = 72,
        Rgba8Uint = 73,
        Rgba8Sint = 74,
        Bgra8Unorm = 80,
        Bgra8UnormSrgb = 81,
        Rgb10A2Unorm = 90,
        Rgb10A2Uint = 91,
        Rg11B10Float = 92,
        Rgb9E5Float = 93,
        Bgr10A2Unorm = 94,
        Rgb16Unorm = 95,
        Rgb16Snorm = 96,
        Rgb16Uint = 97,
        Rgb16Sint = 98,
        Rgb16Float = 99,
        Rg32Uint = 103,
        Rg32Sint = 104,
        Rg32Float = 105,
        Rgba16Unorm = 110,
        Rgba16Snorm = 112,
        Rgba16Uint = 113,
        Rgba16Sint = 114,
        Rgba16Float = 115,
        Rgb32Uint = 120,
        Rgb32Sint = 121,
        Rgb32Float = 122,
        Rgba32Uint = 123,
        Rgba32Sint = 124,
        Rgba32Float = 125,
        Bc1Rgba = 130,
        Bc1RgbaSrgb = 131,
        Bc2Rgba = 132,
        Bc2RgbaSrgb = 133,
        Bc3Rgba = 134,
        Bc3RgbaSrgb = 135,
        Bc4RUnorm = 140,
        Bc4RSnorm = 141,
        Bc5RgUnorm = 142,
        Bc5RgSnorm = 143,
        Bc6hRgbFloat = 150,
        Bc6hRgbUfloat = 151,
        Bc7RgbaUnorm = 152,
        Bc7RgbaUnormSrgb = 153,
        PvrtcRgb2bpp = 160,
        PvrtcRgb2bppSrgb = 161,
        PvrtcRgb4bpp = 162,
        PvrtcRgb4bppSrgb = 163,
        PvrtcRgba2bpp = 164,
        PvrtcRgba2bppSrgb = 165,
        PvrtcRgba4bpp = 166,
        PvrtcRgba4bppSrgb = 167,
        EacR11Unorm = 170,
        EacR11Snorm = 172,
        EacRg11Unorm = 174,
        EacRg11Snorm = 176,
        EacRgba8 = 178,
        EacRgba8Srgb = 179,
        Etc2Rgb8 = 180,
        Etc2Rgb8Srgb = 181,
        Etc2Rgb8A1 = 182,
        Etc2Rgb8A1Srgb = 183,
        Astc4x4Srgb = 186,
        Astc5x4Srgb = 187,
        Astc5x5Srgb = 188,
        Astc6x5Srgb = 189,
        Astc6x6Srgb = 190,
        Astc8x5Srgb = 192,
        Astc8x6Srgb = 193,
        Astc8x8Srgb = 194,
        Astc10x5Srgb = 195,
        Astc10x6Srgb = 196,
        Astc10x8Srgb = 197,
        Astc10x10Srgb = 198,
        Astc12x10Srgb = 199,
        Astc12x12Srgb = 200,
        Astc4x4Ldr = 204,
        Astc5x4Ldr = 205,
        Astc5x5Ldr = 206,
        Astc6x5Ldr = 207,
        Astc6x6Ldr = 208,
        Astc8x5Ldr = 210,
        Astc8x6Ldr = 211,
        Astc8x8Ldr = 212,
        Astc10x5Ldr = 213,
        Astc10x6Ldr = 214,
        Astc10x8Ldr = 215,
        Astc10x10Ldr = 216,
        Astc12x10Ldr = 217,
        Astc12x12Ldr = 218,
        Astc4x4Hdr = 222,
        Astc5x4Hdr = 223,
        Astc5x5Hdr = 224,
        Astc6x5Hdr = 225,
        Astc6x6Hdr = 226,
        Astc8x5Hdr = 228,
        Astc8x6Hdr = 229,
        Astc8x8Hdr = 230,
        Astc10x5Hdr = 231,
        Astc10x6Hdr = 232,
        Astc10x8Hdr = 233,
        Astc10x10Hdr = 234,
        Astc12x10Hdr = 235,
        Astc12x12Hdr = 236,
        Gbgr422 = 240,
        Bgrg422 = 241,
        Depth16Unorm = 250,
        Depth32Float = 252,
        Stencil8 = 253,
        Depth24UnormStencil8 = 255,
        Depth32FloatStencil8 = 260,
        X32Stencil8 = 261,
        X24Stencil8 = 262,
        /// Apple's private two-plane YCbCr formats of IOSurfaces: luma in
        /// the first plane's byte, Cb and Cr in the second's two, which
        /// holds one texel per 2 x 2, 2 x 1 or 1 x 1 of the first. Shaders
        /// read them as RGB through full-range BT.601, which Apple GPUs use
        /// for full-range surfaces such as '444f'; video-range ones such
        /// as '420v' they convert in video range.
        Ycbcr8_420_2p = 500,
        Ycbcr8_422_2p = 502,
        Ycbcr8_444_2p = 503,
        /// Their 10-bit twins ('x420' and its kin): each component is the
        /// high 10 bits of a 16-bit word. Apple GPUs convert YCbCr in the
        /// range the surface's pixel format names, full for '444f' and
        /// video for 'x420', rounded to 1/2048.
        Ycbcr10_420_2p = 505,
        Ycbcr10_422_2p = 506,
        Ycbcr10_444_2p = 507,
        /// Apple's private two-plane RGB formats of IOSurfaces: green in
        /// the first plane's byte, blue and red in the second's two, which
        /// holds one texel per 2 x 2, 2 x 1 or 1 x 1 of the first.
        Rgb8_420_2p = 540,
        Rgb8_422_2p = 541,
        Rgb8_444_2p = 542,
        /// Their 10-bit twins: each component is the high 10 bits of a
        /// 16-bit word.
        Rgb10_420_2p = 543,
        Rgb10_422_2p = 544,
        Rgb10_444_2p = 545,
        /// Apple's private extended-range two-plane format of WindowServer's
        /// framebuffers ('&b38' surfaces) and Core Animation's surfaces:
        /// `BGR10_XR`'s codes in a plane of 32-bit words, the top two bits
        /// zero, and 8-bit alpha in a plane of its own
        /// ([`extended_range`]).
        Rgb10A8_2pXr10 = 550,
        Rgb10A8_2pXr10Srgb = 551,
        Bgra10Xr = 552,
        Bgra10XrSrgb = 553,
        Bgr10Xr = 554,
        Bgr10XrSrgb = 555,
    }
    decode with decode_indexed;
}

const RAW_COUNT: usize = {
    let mut index = 0;
    let mut max = 0;
    while index < PixelFormat::ALL.len() {
        let raw = PixelFormat::ALL[index].raw() as usize;
        if raw > max {
            max = raw;
        }
        index += 1;
    }
    max + 1
};

static INDICES: [u8; RAW_COUNT] = {
    assert!(PixelFormat::ALL.len() <= u8::MAX as usize + 1);
    let mut indices = [0; RAW_COUNT];
    let mut index = 0;
    while index < PixelFormat::ALL.len() {
        indices[PixelFormat::ALL[index].raw() as usize] = index as u8;
        index += 1;
    }
    indices
};

/// How shaders read a color format's components.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Numeric {
    Unorm,
    Snorm,
    Uint,
    Sint,
    Float,
}

impl Numeric {
    pub const fn is_integer(self) -> bool {
        matches!(self, Self::Uint | Self::Sint)
    }
}

/// How Apple GPUs filter a format's texels through Metal's bicubic sampler
/// filter, which shaders apply in Vulkan's place.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FilterClass {
    /// Filtered as they are.
    #[default]
    Float = 0,
    /// Filtered, clamped to [0, 1].
    Unorm = 1,
    /// Filtered, clamped to [-1, 1].
    Snorm = 2,
    /// The nearest texel: 32-bit float channels, which an M1 Pro (Apple7)
    /// does not filter bicubically.
    Nearest = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Color(Numeric),
    Depth,
    Stencil,
    DepthStencil,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Compression {
    None,
    Bc,
    Pvrtc,
    Etc2Eac,
    AstcLdr,
    AstcHdr,
    /// 4:2:2 subsampled pairs, two texels per block.
    Subsampled,
    /// Two planes ([`PixelFormat::planes`]); the block is the first's.
    TwoPlanes,
}

/// A two-plane format's second plane: texels of the first across and down
/// per texel of it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Planes {
    /// 4:4:4, one per texel.
    Full = 1,
    /// 4:2:2, one per two across.
    Horizontal = 2,
    /// 4:2:0, one per 2 x 2.
    Both = 3,
}

impl Planes {
    /// Texels of the first plane per texel of the second, across and down.
    pub const fn ratio(self) -> (u32, u32) {
        match self {
            Self::Full => (1, 1),
            Self::Horizontal => (2, 1),
            Self::Both => (2, 2),
        }
    }

    /// The second plane's width and height for a first of `width` by
    /// `height`, rounded up.
    pub const fn second(self, width: u64, height: u64) -> (u64, u64) {
        let (across, down) = self.ratio();
        (width.div_ceil(across as u64), height.div_ceil(down as u64))
    }
}

/// One block's footprint: texels across, texels down and bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Block {
    pub width: u32,
    pub height: u32,
    pub bytes: u32,
}

impl Block {
    const fn texel(bytes: u32) -> Self {
        Self {
            width: 1,
            height: 1,
            bytes,
        }
    }

    /// Blocks covering `texels` texels across.
    pub const fn columns(self, texels: u64) -> u64 {
        texels.div_ceil(self.width as u64)
    }

    /// Blocks covering `texels` texels down.
    pub const fn rows(self, texels: u64) -> u64 {
        texels.div_ceil(self.height as u64)
    }
}

/// Why a Metal format has no Vulkan realization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unrealized {
    /// Vulkan samples 4:2:2 formats only through an immutable Y'CbCr
    /// conversion sampler, which Metal's separate texture and sampler
    /// bindings cannot supply.
    YcbcrConversion,
}

/// The Vulkan image format, the aspects a view selects and the view swizzle
/// that together reproduce the Metal format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Realization {
    pub format: VkFormat,
    pub view_aspects: ImageAspects,
    pub swizzle: [ComponentSwizzle; 4],
    pub encoding: Encoding,
}

impl Realization {
    pub fn is_identity(&self) -> bool {
        self.swizzle == IDENTITY
    }

    /// Whether views and attachments may write through the realization: its
    /// swizzle is the identity, or makes a format without alpha read opaque.
    /// Only the decode kernels write decoded texels, which mean blocks.
    pub fn writes_through(&self) -> bool {
        self.swizzle == IDENTITY && !matches!(self.encoding, Encoding::Decoded(_))
            || self.swizzle == OPAQUE
                && matches!(self.encoding, Encoding::ExtendedRange(codes) if !codes.alpha)
            || self.swizzle == PADDED && self.encoding == Encoding::Padded
    }
}

/// How the image's texels hold the Metal format's.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Encoding {
    /// The image holds the Metal format's own bytes.
    Exact,
    /// Apple's extended-range codes, held as the half floats they read as
    /// ([`extended_range`]).
    ExtendedRange(extended_range::Codes),
    /// A 16-bit texel rotated right by one bit, so a channel in its lowest
    /// bit moves to its highest: `A1BGR5Unorm`'s alpha, which no NVIDIA
    /// layout keeps in bit 0, held as `A1R5G5B5`'s.
    Rotated,
    /// Two 8-bit channels held in a four-channel image whose blue reads
    /// zero and alpha one: `RG8Unorm_sRGB`, which NVIDIA has no two-channel
    /// sRGB format for, as `R8G8B8A8_SRGB`.
    Padded,
    /// A compressed format's blocks decoded to texels, for a format the
    /// device samples no blocks of: the CPU and buffer copies reach a copy
    /// of the blocks, which the decode kernels expand into the image.
    Decoded(Codec),
}

/// A compressed format the decode kernels expand into an image: the
/// kernels' `enum stela_metal_block_codec`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Codec {
    Etc2Rgb8 = 1,
    Etc2Rgb8A1,
    EacRgba8,
    EacR11,
    EacR11Snorm,
    EacRg11,
    EacRg11Snorm,
    Pvrtc4,
    Pvrtc2,
    Astc,
    AstcSrgb,
    AstcHdr,
}

/// The decode kernel that expands a codec's blocks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BlockKernel {
    /// `stela_metal_decode_etc_kernel`.
    Etc,
    /// `stela_metal_decode_pvrtc_kernel`.
    Pvrtc,
    /// `stela_metal_decode_astc_kernel`.
    Astc,
}

impl Codec {
    pub const fn kernel(self) -> BlockKernel {
        match self {
            Self::Pvrtc4 | Self::Pvrtc2 => BlockKernel::Pvrtc,
            Self::Astc | Self::AstcSrgb | Self::AstcHdr => BlockKernel::Astc,
            _ => BlockKernel::Etc,
        }
    }

    /// Whether each texel depends on blocks around its own, wrapping, so
    /// that only whole levels decode: PVRTC's, whose levels Metal also
    /// copies as runs of blocks in their own order.
    pub const fn whole_levels(self) -> bool {
        matches!(self, Self::Pvrtc4 | Self::Pvrtc2)
    }

    /// Bytes of the decoded texel: 8-bit RGBA, EAC's 16-bit channels, or
    /// linear and HDR ASTC's 16-bit RGBA.
    pub const fn decoded_bytes(self) -> u32 {
        match self {
            Self::EacR11 | Self::EacR11Snorm => 2,
            Self::Astc | Self::AstcHdr => 8,
            _ => 4,
        }
    }
}

impl Encoding {
    pub const fn is_exact(self) -> bool {
        matches!(self, Self::Exact)
    }

    /// The codec of a decoded encoding.
    pub const fn decoded(self) -> Option<Codec> {
        match self {
            Self::Decoded(codec) => Some(codec),
            _ => None,
        }
    }

    /// The texel kernels' `enum stela_metal_texel_encoding`; zero for the
    /// exact encoding, which they never convert.
    pub const fn texel_kernel(self) -> u32 {
        match self {
            Self::Exact => 0,
            Self::ExtendedRange(extended_range::Codes {
                srgb, planes: true, ..
            }) => 7 + srgb as u32,
            Self::ExtendedRange(extended_range::Codes { alpha, srgb, .. }) => {
                1 + 2 * alpha as u32 + srgb as u32
            }
            Self::Rotated => 5,
            Self::Padded => 6,
            Self::Decoded(codec) => codec as u32,
        }
    }

    /// Bytes of the image's texel holding one of `metal_bytes`.
    pub const fn stored_bytes(self, metal_bytes: u32) -> u32 {
        match self {
            Self::Exact | Self::Rotated => metal_bytes,
            Self::ExtendedRange(_) => extended_range::STORED_BYTES as u32,
            Self::Padded => 2 * metal_bytes,
            Self::Decoded(codec) => codec.decoded_bytes(),
        }
    }

    /// Converts whole Metal texels of `metal_bytes` each to the image's.
    /// A decoded encoding's CPU copy holds its blocks, which only the
    /// decode kernels expand.
    pub fn store(self, metal: &[u8], stored: &mut [u8]) {
        match self {
            Self::Decoded(_) => unreachable!("decoded textures keep their blocks in a CPU copy"),
            Self::Exact => stored.copy_from_slice(metal),
            Self::ExtendedRange(codes) => codes.store(metal, stored),
            Self::Rotated => rotate(metal, stored, u16::rotate_right),
            Self::Padded => {
                let texels = metal.as_chunks::<2>().0;
                for (&[r, g], out) in texels.iter().zip(stored.as_chunks_mut::<4>().0) {
                    *out = [r, g, 0, 0xff];
                }
            }
        }
    }

    /// Converts whole image texels to Metal's.
    pub fn load(self, stored: &[u8], metal: &mut [u8]) {
        match self {
            Self::Decoded(_) => unreachable!("decoded textures keep their blocks in a CPU copy"),
            Self::Exact => metal.copy_from_slice(stored),
            Self::ExtendedRange(codes) => codes.load(stored, metal),
            Self::Rotated => rotate(stored, metal, u16::rotate_left),
            Self::Padded => {
                let texels = stored.as_chunks::<4>().0;
                for (&[r, g, ..], out) in texels.iter().zip(metal.as_chunks_mut::<2>().0) {
                    *out = [r, g];
                }
            }
        }
    }
}

fn rotate(from: &[u8], to: &mut [u8], turn: fn(u16, u32) -> u16) {
    for (texel, out) in from
        .as_chunks::<2>()
        .0
        .iter()
        .zip(to.as_chunks_mut::<2>().0)
    {
        *out = turn(u16::from_le_bytes(*texel), 1).to_le_bytes();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Description {
    pub format: PixelFormat,
    pub kind: Kind,
    pub srgb: bool,
    pub compression: Compression,
    pub block: Block,
    /// Formats Metal accepts only for texture views, never for storage.
    pub view_only: bool,
    pub realization: Result<Realization, Unrealized>,
}

impl Description {
    pub const fn is_compressed(&self) -> bool {
        !matches!(self.compression, Compression::None)
    }

    pub const fn is_color(&self) -> bool {
        matches!(self.kind, Kind::Color(_))
    }

    pub const fn has_depth(&self) -> bool {
        matches!(self.kind, Kind::Depth | Kind::DepthStencil)
    }

    pub const fn has_stencil(&self) -> bool {
        matches!(self.kind, Kind::Stencil | Kind::DepthStencil)
    }

    /// Aspects of a Vulkan image that stores this format.
    pub const fn image_aspects(&self) -> ImageAspects {
        match self.kind {
            Kind::Color(_) => ImageAspects::COLOR,
            Kind::Depth => ImageAspects::DEPTH,
            Kind::Stencil if self.view_only => ImageAspects::DEPTH.union(ImageAspects::STENCIL),
            Kind::Stencil => ImageAspects::STENCIL,
            Kind::DepthStencil => ImageAspects::DEPTH.union(ImageAspects::STENCIL),
        }
    }

    /// Bytes of one tightly packed row of `width` texels.
    pub const fn row_bytes(&self, width: u64) -> u64 {
        self.block.columns(width) * self.block.bytes as u64
    }

    /// The image's encoding of the format's texels.
    pub fn encoding(&self) -> Encoding {
        self.realization
            .map_or(Encoding::Exact, |realization| realization.encoding)
    }

    /// Bytes of one block as the image stores it.
    pub fn stored_block_bytes(&self) -> u32 {
        self.encoding().stored_bytes(self.block.bytes)
    }

    /// For a format whose image holds its blocks decoded, the kernel that
    /// decodes them and its `TexelArguments` encoding: the codec, then the
    /// block's width and height a byte each.
    pub fn decoder(&self) -> Option<(BlockKernel, u32)> {
        match self.encoding() {
            Encoding::Decoded(codec) => Some((
                codec.kernel(),
                codec as u32 | self.block.width << 8 | self.block.height << 16,
            )),
            _ => None,
        }
    }
}

/// The linear value halfway between each pair of neighboring 8-bit sRGB
/// codes, ascending.
static SRGB8_MIDPOINTS: [f64; 255] = {
    let mut midpoints = [0.0; 255];
    let mut code = 0;
    while code < 255 {
        let encoded = (code as f64 + 0.5) / 255.0;
        midpoints[code] = if encoded <= 0.04045 {
            encoded / 12.92
        } else {
            extended_range::exp(2.4 * extended_range::ln((encoded + 0.055) / 1.055))
        };
        code += 1;
    }
    midpoints
};

/// The 8-bit sRGB code of a linear value nearest it once decoded.
fn srgb8(value: f64) -> u32 {
    let value = if value.is_nan() { 0.0 } else { value };
    SRGB8_MIDPOINTS.partition_point(|&midpoint| midpoint < value) as u32
}

/// The `n`-bit unorm code of a value, ties to even.
fn unorm(value: f64, bits: u32) -> u32 {
    let max = (1u32 << bits) - 1;
    let scaled = if value.is_nan() {
        0.0
    } else {
        value.clamp(0.0, 1.0)
    } * f64::from(max);
    let floor = scaled as u32;
    let fraction = scaled - f64::from(floor);
    (floor + u32::from(fraction > 0.5 || fraction == 0.5 && floor & 1 == 1)).min(max)
}

/// Full-range BT.601 luma, Cb and Cr of an RGB color, each in [0, 1], as
/// Apple GPUs store a two-plane YCbCr texel: chroma (C - 128) / 256 times
/// 255 around 128 / 255.
pub fn ycbcr(rgb: [f64; 3]) -> [f64; 3] {
    let [r, g, b] = rgb.map(|v| if v.is_nan() { 0.0 } else { v.clamp(0.0, 1.0) });
    let y = 0.299 * r + 0.587 * g + 0.114 * b;
    let chroma = |difference: f64, scale: f64| 128.0 / 255.0 + difference / scale * 256.0 / 255.0;
    [y, chroma(b - y, 1.772), chroma(r - y, 1.402)]
}

/// A two-plane format's texel of an RGB color: its first plane's value and
/// its second's two (blue and red, or Cb and Cr), each in [0, 1].
fn planes_texel(format: PixelFormat, rgb: [f64; 3]) -> (f64, [f64; 2]) {
    if format.ycbcr() {
        let [y, cb, cr] = ycbcr(rgb);
        (y, [cb, cr])
    } else {
        (rgb[1], [rgb[2], rgb[0]])
    }
}

/// A clear color as a two-plane format's second-plane texel, its first
/// channel in the low byte, in its `Rg8Unorm` image's float clear value.
pub fn second_plane_clear(format: PixelFormat, clear: [f64; 4]) -> Option<[f32; 4]> {
    format.planes()?;
    let (_, second) = planes_texel(format, [clear[0], clear[1], clear[2]]);
    let [a, b] = second.map(|v| unorm(v, 8) as f32 / 255.0);
    Some([a, b, 0.0, 1.0])
}

/// A clear color as the raw texel of a format rendering through its raw
/// texels (`resource::raw_rendered`), in its unsigned integer view; a
/// two-plane format's first plane's texel.
pub fn raw_clear(format: PixelFormat, clear: [f64; 4]) -> Option<u32> {
    let [r, g, b, a] = clear;
    if format.planes().is_some() {
        return Some(unorm(planes_texel(format, [r, g, b]).0, 8));
    }
    Some(match format {
        PixelFormat::R8UnormSrgb => srgb8(r),
        // R4G4B4A4_UNORM_PACK16: red in the top bits, alpha in the bottom.
        PixelFormat::Abgr4Unorm => {
            unorm(r, 4) << 12 | unorm(g, 4) << 8 | unorm(b, 4) << 4 | unorm(a, 4)
        }
        _ => return None,
    })
}

impl PixelFormat {
    /// The format that stores the same bits with the other sRGB encoding;
    /// Metal views between the two without `PixelFormatView` usage.
    pub const fn srgb_pair(self) -> Option<Self> {
        let pairs: &[(Self, Self)] = &[
            (P::R8Unorm, P::R8UnormSrgb),
            (P::Rg8Unorm, P::Rg8UnormSrgb),
            (P::Rgba8Unorm, P::Rgba8UnormSrgb),
            (P::Bgra8Unorm, P::Bgra8UnormSrgb),
            (P::Bc1Rgba, P::Bc1RgbaSrgb),
            (P::Bc2Rgba, P::Bc2RgbaSrgb),
            (P::Bc3Rgba, P::Bc3RgbaSrgb),
            (P::Bc7RgbaUnorm, P::Bc7RgbaUnormSrgb),
            (P::PvrtcRgb2bpp, P::PvrtcRgb2bppSrgb),
            (P::PvrtcRgb4bpp, P::PvrtcRgb4bppSrgb),
            (P::PvrtcRgba2bpp, P::PvrtcRgba2bppSrgb),
            (P::PvrtcRgba4bpp, P::PvrtcRgba4bppSrgb),
            (P::EacRgba8, P::EacRgba8Srgb),
            (P::Etc2Rgb8, P::Etc2Rgb8Srgb),
            (P::Etc2Rgb8A1, P::Etc2Rgb8A1Srgb),
            (P::Astc4x4Ldr, P::Astc4x4Srgb),
            (P::Astc5x4Ldr, P::Astc5x4Srgb),
            (P::Astc5x5Ldr, P::Astc5x5Srgb),
            (P::Astc6x5Ldr, P::Astc6x5Srgb),
            (P::Astc6x6Ldr, P::Astc6x6Srgb),
            (P::Astc8x5Ldr, P::Astc8x5Srgb),
            (P::Astc8x6Ldr, P::Astc8x6Srgb),
            (P::Astc8x8Ldr, P::Astc8x8Srgb),
            (P::Astc10x5Ldr, P::Astc10x5Srgb),
            (P::Astc10x6Ldr, P::Astc10x6Srgb),
            (P::Astc10x8Ldr, P::Astc10x8Srgb),
            (P::Astc10x10Ldr, P::Astc10x10Srgb),
            (P::Astc12x10Ldr, P::Astc12x10Srgb),
            (P::Astc12x12Ldr, P::Astc12x12Srgb),
            (P::Rgb10A8_2pXr10, P::Rgb10A8_2pXr10Srgb),
            (P::Bgra10Xr, P::Bgra10XrSrgb),
            (P::Bgr10Xr, P::Bgr10XrSrgb),
        ];
        let mut index = 0;
        while index < pairs.len() {
            let (linear, srgb) = pairs[index];
            if linear as u64 == self as u64 {
                return Some(srgb);
            }
            if srgb as u64 == self as u64 {
                return Some(linear);
            }
            index += 1;
        }
        None
    }

    /// The linear twin whose storage views hold this uncompressed sRGB
    /// format's texels: no Vulkan device stores sRGB images, and Apple GPUs
    /// write them from shaders, which then encode and decode the color
    /// channels themselves (`ResourceId::SRGB_STORAGE`).
    pub fn srgb_storage(self) -> Option<Self> {
        let description = self.describe();
        if !description.srgb || description.is_compressed() {
            return None;
        }
        let linear = self.srgb_pair()?;
        let exact = |format: Self| {
            format
                .describe()
                .realization
                .as_ref()
                .is_ok_and(|realization| {
                    realization.encoding.is_exact() && realization.is_identity()
                })
        };
        (exact(self) && exact(linear)).then_some(linear)
    }

    /// How Metal's bicubic filter treats this format's texels.
    pub fn filter_class(self) -> FilterClass {
        match self {
            Self::R32Float
            | Self::Rg32Float
            | Self::Rgba32Float
            | Self::Depth32Float
            | Self::Depth32FloatStencil8 => FilterClass::Nearest,
            Self::Depth16Unorm | Self::Depth24UnormStencil8 => FilterClass::Unorm,
            _ => match self.describe().kind {
                Kind::Color(Numeric::Unorm) => FilterClass::Unorm,
                Kind::Color(Numeric::Snorm) => FilterClass::Snorm,
                _ => FilterClass::Float,
            },
        }
    }

    pub fn describe(self) -> &'static Description {
        &DESCRIPTIONS[self.index()]
    }

    /// A two-plane format's second plane: the first is
    /// [`Rgb8_444_2p`](Self::Rgb8_444_2p)'s green as `R8Unorm`, the second
    /// blue and red as `Rg8Unorm` ([`Self::plane_formats`]).
    pub const fn planes(self) -> Option<Planes> {
        match self {
            Self::Rgb8_420_2p | Self::Ycbcr8_420_2p | Self::Rgb10_420_2p | Self::Ycbcr10_420_2p => {
                Some(Planes::Both)
            }
            Self::Rgb8_422_2p | Self::Ycbcr8_422_2p | Self::Rgb10_422_2p | Self::Ycbcr10_422_2p => {
                Some(Planes::Horizontal)
            }
            Self::Rgb8_444_2p | Self::Ycbcr8_444_2p | Self::Rgb10_444_2p | Self::Ycbcr10_444_2p => {
                Some(Planes::Full)
            }
            _ => None,
        }
    }

    /// Whether a two-plane format's planes hold luma and chroma, which
    /// shaders convert to RGB, rather than green and blue-red.
    pub const fn ycbcr(self) -> bool {
        matches!(
            self,
            Self::Ycbcr8_420_2p
                | Self::Ycbcr8_422_2p
                | Self::Ycbcr8_444_2p
                | Self::Ycbcr10_420_2p
                | Self::Ycbcr10_422_2p
                | Self::Ycbcr10_444_2p
        )
    }

    /// Whether a two-plane format's components are 10 bits, the high ones
    /// of 16-bit words, rather than bytes.
    pub const fn ten_bit_planes(self) -> bool {
        matches!(
            self,
            Self::Rgb10_420_2p
                | Self::Rgb10_422_2p
                | Self::Rgb10_444_2p
                | Self::Ycbcr10_420_2p
                | Self::Ycbcr10_422_2p
                | Self::Ycbcr10_444_2p
        )
    }

    /// The formats of a two-plane format's planes' images: one component,
    /// then two, of a byte or a 16-bit word each.
    pub const fn plane_formats(self) -> Option<[Self; 2]> {
        match self.planes() {
            None => None,
            Some(_) if self.ten_bit_planes() => Some([Self::R16Unorm, Self::Rg16Unorm]),
            Some(_) => Some([Self::R8Unorm, Self::Rg8Unorm]),
        }
    }

    /// The planes of an IOSurface's `RGB10A8_2P_XR10` texture: its codes'
    /// 32-bit words, which shaders read through `RGB10A2Unorm`, and its
    /// 8-bit alpha. Its other textures, and every pipeline, hold its
    /// texels as half floats ([`extended_range`]).
    pub const fn extended_planes(self) -> Option<[Self; 2]> {
        match self {
            Self::Rgb10A8_2pXr10 | Self::Rgb10A8_2pXr10Srgb => {
                Some([Self::Rgb10A2Unorm, Self::R8Unorm])
            }
            _ => None,
        }
    }

    pub(super) fn index(self) -> usize {
        usize::from(INDICES[self.raw() as usize])
    }

    fn decode_indexed(raw: u64) -> Option<Self> {
        let index = *INDICES.get(usize::try_from(raw).ok()?)?;
        let format = Self::ALL[usize::from(index)];
        // Holes contain the first format's index, so check its raw value.
        (format.raw() == raw).then_some(format)
    }
}

use ComponentSwizzle as S;
use PixelFormat as P;
use VkFormat as V;

const IDENTITY: [ComponentSwizzle; 4] = [S::Identity, S::Identity, S::Identity, S::Identity];
const OPAQUE: [ComponentSwizzle; 4] = [S::Identity, S::Identity, S::Identity, S::One];
const PADDED: [ComponentSwizzle; 4] = [S::Identity, S::Identity, S::Zero, S::One];

const fn vk(format: VkFormat, view_aspects: ImageAspects) -> Result<Realization, Unrealized> {
    Ok(Realization {
        format,
        view_aspects,
        swizzle: IDENTITY,
        encoding: Encoding::Exact,
    })
}

const fn plain(
    format: PixelFormat,
    numeric: Numeric,
    srgb: bool,
    bytes: u32,
    realization: VkFormat,
) -> Description {
    Description {
        format,
        kind: Kind::Color(numeric),
        srgb,
        compression: Compression::None,
        block: Block::texel(bytes),
        view_only: false,
        realization: vk(realization, ImageAspects::COLOR),
    }
}

const fn color(
    format: PixelFormat,
    numeric: Numeric,
    bytes: u32,
    realization: VkFormat,
) -> Description {
    plain(format, numeric, false, bytes, realization)
}

const fn srgb(format: PixelFormat, bytes: u32, realization: VkFormat) -> Description {
    plain(format, Numeric::Unorm, true, bytes, realization)
}

#[allow(clippy::too_many_arguments)]
const fn compressed(
    format: PixelFormat,
    compression: Compression,
    numeric: Numeric,
    srgb: bool,
    width: u32,
    height: u32,
    bytes: u32,
    realization: VkFormat,
    swizzle: [ComponentSwizzle; 4],
    encoding: Encoding,
) -> Description {
    Description {
        format,
        kind: Kind::Color(numeric),
        srgb,
        compression,
        block: Block {
            width,
            height,
            bytes,
        },
        view_only: false,
        realization: Ok(Realization {
            format: realization,
            view_aspects: ImageAspects::COLOR,
            swizzle,
            encoding,
        }),
    }
}

const fn bc(
    format: PixelFormat,
    numeric: Numeric,
    srgb: bool,
    bytes: u32,
    realization: VkFormat,
) -> Description {
    compressed(
        format,
        Compression::Bc,
        numeric,
        srgb,
        4,
        4,
        bytes,
        realization,
        IDENTITY,
        Encoding::Exact,
    )
}

/// Devices without ETC2 and EAC sampling hold the blocks decoded
/// ([`Encoding::Decoded`]) in `decoded`.
const fn etc(
    format: PixelFormat,
    numeric: Numeric,
    srgb: bool,
    bytes: u32,
    codec: Codec,
    decoded: VkFormat,
) -> Description {
    compressed(
        format,
        Compression::Etc2Eac,
        numeric,
        srgb,
        4,
        4,
        bytes,
        decoded,
        IDENTITY,
        Encoding::Decoded(codec),
    )
}

/// PVRTC1 blocks are 4x4 texels at 4 bpp and 8x4 at 2 bpp; Metal's RGB
/// variants ignore the encoded alpha. Devices without PVRTC sampling hold
/// the blocks decoded to 8-bit RGBA ([`Encoding::Decoded`]).
const fn pvrtc(format: PixelFormat, srgb: bool, two_bpp: bool, alpha: bool) -> Description {
    let width = if two_bpp { 8 } else { 4 };
    let swizzle = if alpha { IDENTITY } else { OPAQUE };
    let (codec, realization) = (
        if two_bpp {
            Codec::Pvrtc2
        } else {
            Codec::Pvrtc4
        },
        if srgb {
            V::R8G8B8A8Srgb
        } else {
            V::R8G8B8A8Unorm
        },
    );
    compressed(
        format,
        Compression::Pvrtc,
        Numeric::Unorm,
        srgb,
        width,
        4,
        8,
        realization,
        swizzle,
        Encoding::Decoded(codec),
    )
}

/// Devices sample no ASTC LDR blocks as Apple's GPUs decode them, so the
/// blocks are held decoded ([`Encoding::Decoded`]): Apple reads a linear
/// texel's top 12 bits of the Khronos UNORM16 result, which 16-bit unorm
/// channels hold, and an sRGB texel's 8.
const fn astc(format: PixelFormat, srgb: bool, width: u32, height: u32) -> Description {
    let (codec, realization) = if srgb {
        (Codec::AstcSrgb, V::R8G8B8A8Srgb)
    } else {
        (Codec::Astc, V::R16G16B16A16Unorm)
    };
    compressed(
        format,
        Compression::AstcLdr,
        Numeric::Unorm,
        srgb,
        width,
        height,
        16,
        realization,
        IDENTITY,
        Encoding::Decoded(codec),
    )
}

/// ASTC HDR blocks, held decoded to half floats ([`Encoding::Decoded`]) as
/// LDR ones are: few devices sample HDR blocks, and Apple's decode of them
/// is the Khronos one.
const fn astc_hdr(format: PixelFormat, width: u32, height: u32) -> Description {
    compressed(
        format,
        Compression::AstcHdr,
        Numeric::Float,
        false,
        width,
        height,
        16,
        V::R16G16B16A16Sfloat,
        IDENTITY,
        Encoding::Decoded(Codec::AstcHdr),
    )
}

/// An extended-range format, held as half floats; one without alpha reads
/// opaque. The two-plane `RGB10A8_2P_XR10` formats render, read and sample
/// the same way; a texture over an IOSurface's planes keeps its texels in
/// them (`device::extended_planes`).
const fn extended(format: PixelFormat, alpha: bool, srgb: bool) -> Description {
    let planes = matches!(
        format,
        PixelFormat::Rgb10A8_2pXr10 | PixelFormat::Rgb10A8_2pXr10Srgb
    );
    let codes = extended_range::Codes {
        alpha,
        srgb,
        planes,
    };
    Description {
        format,
        kind: Kind::Color(Numeric::Float),
        srgb,
        compression: Compression::None,
        block: Block::texel(codes.metal_bytes() as u32),
        view_only: false,
        realization: Ok(Realization {
            format: V::R16G16B16A16Sfloat,
            view_aspects: ImageAspects::COLOR,
            swizzle: if alpha { IDENTITY } else { OPAQUE },
            encoding: Encoding::ExtendedRange(codes),
        }),
    }
}

/// A two-channel sRGB format held in a four-channel one
/// ([`Encoding::Padded`]).
const fn padded(format: PixelFormat, realization: VkFormat) -> Description {
    Description {
        format,
        kind: Kind::Color(Numeric::Unorm),
        srgb: true,
        compression: Compression::None,
        block: Block::texel(2),
        view_only: false,
        realization: Ok(Realization {
            format: realization,
            view_aspects: ImageAspects::COLOR,
            swizzle: PADDED,
            encoding: Encoding::Padded,
        }),
    }
}

/// A 16-bit format held rotated right by one bit ([`Encoding::Rotated`]).
const fn rotated(format: PixelFormat, realization: VkFormat) -> Description {
    Description {
        format,
        kind: Kind::Color(Numeric::Unorm),
        srgb: false,
        compression: Compression::None,
        block: Block::texel(2),
        view_only: false,
        realization: Ok(Realization {
            format: realization,
            view_aspects: ImageAspects::COLOR,
            swizzle: IDENTITY,
            encoding: Encoding::Rotated,
        }),
    }
}

const fn subsampled(format: PixelFormat) -> Description {
    Description {
        format,
        kind: Kind::Color(Numeric::Unorm),
        srgb: false,
        compression: Compression::Subsampled,
        block: Block {
            width: 2,
            height: 1,
            bytes: 4,
        },
        view_only: false,
        realization: Err(Unrealized::YcbcrConversion),
    }
}

/// A two-plane format, realized by its first plane's image, `R8Unorm` or
/// for 10-bit components `R16Unorm`; the second plane is an image of its
/// own ([`PixelFormat::plane_formats`]).
const fn two_planes(format: PixelFormat) -> Description {
    let (bytes, realization) = if format.ten_bit_planes() {
        (2, V::R16Unorm)
    } else {
        (1, V::R8Unorm)
    };
    Description {
        format,
        kind: Kind::Color(Numeric::Unorm),
        srgb: false,
        compression: Compression::TwoPlanes,
        block: Block::texel(bytes),
        view_only: false,
        realization: vk(realization, ImageAspects::COLOR),
    }
}

const fn depth_stencil(
    format: PixelFormat,
    kind: Kind,
    bytes: u32,
    view_only: bool,
    realization: VkFormat,
    view_aspects: ImageAspects,
) -> Description {
    Description {
        format,
        kind,
        srgb: false,
        compression: Compression::None,
        block: Block::texel(bytes),
        view_only,
        realization: vk(realization, view_aspects),
    }
}

const DEPTH: ImageAspects = ImageAspects::DEPTH;
const STENCIL: ImageAspects = ImageAspects::STENCIL;
const DEPTH_STENCIL: ImageAspects = ImageAspects::DEPTH.union(ImageAspects::STENCIL);

use Numeric::{Float, Sint, Snorm, Uint, Unorm};

/// One description per [`PixelFormat`], in declaration order.
static DESCRIPTIONS: &[Description] = &[
    color(P::A8Unorm, Unorm, 1, V::A8Unorm),
    color(P::R8Unorm, Unorm, 1, V::R8Unorm),
    srgb(P::R8UnormSrgb, 1, V::R8Srgb),
    color(P::R8Snorm, Snorm, 1, V::R8Snorm),
    color(P::R8Uint, Uint, 1, V::R8Uint),
    color(P::R8Sint, Sint, 1, V::R8Sint),
    color(P::R16Unorm, Unorm, 2, V::R16Unorm),
    color(P::R16Snorm, Snorm, 2, V::R16Snorm),
    color(P::R16Uint, Uint, 2, V::R16Uint),
    color(P::R16Sint, Sint, 2, V::R16Sint),
    color(P::R16Float, Float, 2, V::R16Sfloat),
    color(P::Rg8Unorm, Unorm, 2, V::R8G8Unorm),
    padded(P::Rg8UnormSrgb, V::R8G8B8A8Srgb),
    color(P::Rg8Snorm, Snorm, 2, V::R8G8Snorm),
    color(P::Rg8Uint, Uint, 2, V::R8G8Uint),
    color(P::Rg8Sint, Sint, 2, V::R8G8Sint),
    color(P::B5G6R5Unorm, Unorm, 2, V::R5G6B5UnormPack16),
    rotated(P::A1Bgr5Unorm, V::A1R5G5B5UnormPack16),
    color(P::Abgr4Unorm, Unorm, 2, V::R4G4B4A4UnormPack16),
    color(P::Bgr5A1Unorm, Unorm, 2, V::A1R5G5B5UnormPack16),
    color(P::Rgb8Unorm, Unorm, 3, V::R8G8B8Unorm),
    color(P::Rgb8Snorm, Snorm, 3, V::R8G8B8Snorm),
    color(P::Rgb8Uint, Uint, 3, V::R8G8B8Uint),
    color(P::Rgb8Sint, Sint, 3, V::R8G8B8Sint),
    color(P::R32Uint, Uint, 4, V::R32Uint),
    color(P::R32Sint, Sint, 4, V::R32Sint),
    color(P::R32Float, Float, 4, V::R32Sfloat),
    color(P::Rg16Unorm, Unorm, 4, V::R16G16Unorm),
    color(P::Rg16Snorm, Snorm, 4, V::R16G16Snorm),
    color(P::Rg16Uint, Uint, 4, V::R16G16Uint),
    color(P::Rg16Sint, Sint, 4, V::R16G16Sint),
    color(P::Rg16Float, Float, 4, V::R16G16Sfloat),
    color(P::Rgba8Unorm, Unorm, 4, V::R8G8B8A8Unorm),
    srgb(P::Rgba8UnormSrgb, 4, V::R8G8B8A8Srgb),
    color(P::Rgba8Snorm, Snorm, 4, V::R8G8B8A8Snorm),
    color(P::Rgba8Uint, Uint, 4, V::R8G8B8A8Uint),
    color(P::Rgba8Sint, Sint, 4, V::R8G8B8A8Sint),
    color(P::Bgra8Unorm, Unorm, 4, V::B8G8R8A8Unorm),
    srgb(P::Bgra8UnormSrgb, 4, V::B8G8R8A8Srgb),
    color(P::Rgb10A2Unorm, Unorm, 4, V::A2B10G10R10UnormPack32),
    color(P::Rgb10A2Uint, Uint, 4, V::A2B10G10R10UintPack32),
    color(P::Rg11B10Float, Float, 4, V::B10G11R11UfloatPack32),
    color(P::Rgb9E5Float, Float, 4, V::E5B9G9R9UfloatPack32),
    color(P::Bgr10A2Unorm, Unorm, 4, V::A2R10G10B10UnormPack32),
    color(P::Rgb16Unorm, Unorm, 6, V::R16G16B16Unorm),
    color(P::Rgb16Snorm, Snorm, 6, V::R16G16B16Snorm),
    color(P::Rgb16Uint, Uint, 6, V::R16G16B16Uint),
    color(P::Rgb16Sint, Sint, 6, V::R16G16B16Sint),
    color(P::Rgb16Float, Float, 6, V::R16G16B16Sfloat),
    color(P::Rg32Uint, Uint, 8, V::R32G32Uint),
    color(P::Rg32Sint, Sint, 8, V::R32G32Sint),
    color(P::Rg32Float, Float, 8, V::R32G32Sfloat),
    color(P::Rgba16Unorm, Unorm, 8, V::R16G16B16A16Unorm),
    color(P::Rgba16Snorm, Snorm, 8, V::R16G16B16A16Snorm),
    color(P::Rgba16Uint, Uint, 8, V::R16G16B16A16Uint),
    color(P::Rgba16Sint, Sint, 8, V::R16G16B16A16Sint),
    color(P::Rgba16Float, Float, 8, V::R16G16B16A16Sfloat),
    color(P::Rgb32Uint, Uint, 12, V::R32G32B32Uint),
    color(P::Rgb32Sint, Sint, 12, V::R32G32B32Sint),
    color(P::Rgb32Float, Float, 12, V::R32G32B32Sfloat),
    color(P::Rgba32Uint, Uint, 16, V::R32G32B32A32Uint),
    color(P::Rgba32Sint, Sint, 16, V::R32G32B32A32Sint),
    color(P::Rgba32Float, Float, 16, V::R32G32B32A32Sfloat),
    bc(P::Bc1Rgba, Unorm, false, 8, V::Bc1RgbaUnormBlock),
    bc(P::Bc1RgbaSrgb, Unorm, true, 8, V::Bc1RgbaSrgbBlock),
    bc(P::Bc2Rgba, Unorm, false, 16, V::Bc2UnormBlock),
    bc(P::Bc2RgbaSrgb, Unorm, true, 16, V::Bc2SrgbBlock),
    bc(P::Bc3Rgba, Unorm, false, 16, V::Bc3UnormBlock),
    bc(P::Bc3RgbaSrgb, Unorm, true, 16, V::Bc3SrgbBlock),
    bc(P::Bc4RUnorm, Unorm, false, 8, V::Bc4UnormBlock),
    bc(P::Bc4RSnorm, Snorm, false, 8, V::Bc4SnormBlock),
    bc(P::Bc5RgUnorm, Unorm, false, 16, V::Bc5UnormBlock),
    bc(P::Bc5RgSnorm, Snorm, false, 16, V::Bc5SnormBlock),
    bc(P::Bc6hRgbFloat, Float, false, 16, V::Bc6hSfloatBlock),
    bc(P::Bc6hRgbUfloat, Float, false, 16, V::Bc6hUfloatBlock),
    bc(P::Bc7RgbaUnorm, Unorm, false, 16, V::Bc7UnormBlock),
    bc(P::Bc7RgbaUnormSrgb, Unorm, true, 16, V::Bc7SrgbBlock),
    pvrtc(P::PvrtcRgb2bpp, false, true, false),
    pvrtc(P::PvrtcRgb2bppSrgb, true, true, false),
    pvrtc(P::PvrtcRgb4bpp, false, false, false),
    pvrtc(P::PvrtcRgb4bppSrgb, true, false, false),
    pvrtc(P::PvrtcRgba2bpp, false, true, true),
    pvrtc(P::PvrtcRgba2bppSrgb, true, true, true),
    pvrtc(P::PvrtcRgba4bpp, false, false, true),
    pvrtc(P::PvrtcRgba4bppSrgb, true, false, true),
    etc(P::EacR11Unorm, Unorm, false, 8, Codec::EacR11, V::R16Unorm),
    etc(
        P::EacR11Snorm,
        Snorm,
        false,
        8,
        Codec::EacR11Snorm,
        V::R16Snorm,
    ),
    etc(
        P::EacRg11Unorm,
        Unorm,
        false,
        16,
        Codec::EacRg11,
        V::R16G16Unorm,
    ),
    etc(
        P::EacRg11Snorm,
        Snorm,
        false,
        16,
        Codec::EacRg11Snorm,
        V::R16G16Snorm,
    ),
    etc(
        P::EacRgba8,
        Unorm,
        false,
        16,
        Codec::EacRgba8,
        V::R8G8B8A8Unorm,
    ),
    etc(
        P::EacRgba8Srgb,
        Unorm,
        true,
        16,
        Codec::EacRgba8,
        V::R8G8B8A8Srgb,
    ),
    etc(
        P::Etc2Rgb8,
        Unorm,
        false,
        8,
        Codec::Etc2Rgb8,
        V::R8G8B8A8Unorm,
    ),
    etc(
        P::Etc2Rgb8Srgb,
        Unorm,
        true,
        8,
        Codec::Etc2Rgb8,
        V::R8G8B8A8Srgb,
    ),
    etc(
        P::Etc2Rgb8A1,
        Unorm,
        false,
        8,
        Codec::Etc2Rgb8A1,
        V::R8G8B8A8Unorm,
    ),
    etc(
        P::Etc2Rgb8A1Srgb,
        Unorm,
        true,
        8,
        Codec::Etc2Rgb8A1,
        V::R8G8B8A8Srgb,
    ),
    astc(P::Astc4x4Srgb, true, 4, 4),
    astc(P::Astc5x4Srgb, true, 5, 4),
    astc(P::Astc5x5Srgb, true, 5, 5),
    astc(P::Astc6x5Srgb, true, 6, 5),
    astc(P::Astc6x6Srgb, true, 6, 6),
    astc(P::Astc8x5Srgb, true, 8, 5),
    astc(P::Astc8x6Srgb, true, 8, 6),
    astc(P::Astc8x8Srgb, true, 8, 8),
    astc(P::Astc10x5Srgb, true, 10, 5),
    astc(P::Astc10x6Srgb, true, 10, 6),
    astc(P::Astc10x8Srgb, true, 10, 8),
    astc(P::Astc10x10Srgb, true, 10, 10),
    astc(P::Astc12x10Srgb, true, 12, 10),
    astc(P::Astc12x12Srgb, true, 12, 12),
    astc(P::Astc4x4Ldr, false, 4, 4),
    astc(P::Astc5x4Ldr, false, 5, 4),
    astc(P::Astc5x5Ldr, false, 5, 5),
    astc(P::Astc6x5Ldr, false, 6, 5),
    astc(P::Astc6x6Ldr, false, 6, 6),
    astc(P::Astc8x5Ldr, false, 8, 5),
    astc(P::Astc8x6Ldr, false, 8, 6),
    astc(P::Astc8x8Ldr, false, 8, 8),
    astc(P::Astc10x5Ldr, false, 10, 5),
    astc(P::Astc10x6Ldr, false, 10, 6),
    astc(P::Astc10x8Ldr, false, 10, 8),
    astc(P::Astc10x10Ldr, false, 10, 10),
    astc(P::Astc12x10Ldr, false, 12, 10),
    astc(P::Astc12x12Ldr, false, 12, 12),
    astc_hdr(P::Astc4x4Hdr, 4, 4),
    astc_hdr(P::Astc5x4Hdr, 5, 4),
    astc_hdr(P::Astc5x5Hdr, 5, 5),
    astc_hdr(P::Astc6x5Hdr, 6, 5),
    astc_hdr(P::Astc6x6Hdr, 6, 6),
    astc_hdr(P::Astc8x5Hdr, 8, 5),
    astc_hdr(P::Astc8x6Hdr, 8, 6),
    astc_hdr(P::Astc8x8Hdr, 8, 8),
    astc_hdr(P::Astc10x5Hdr, 10, 5),
    astc_hdr(P::Astc10x6Hdr, 10, 6),
    astc_hdr(P::Astc10x8Hdr, 10, 8),
    astc_hdr(P::Astc10x10Hdr, 10, 10),
    astc_hdr(P::Astc12x10Hdr, 12, 10),
    astc_hdr(P::Astc12x12Hdr, 12, 12),
    subsampled(P::Gbgr422),
    subsampled(P::Bgrg422),
    depth_stencil(P::Depth16Unorm, Kind::Depth, 2, false, V::D16Unorm, DEPTH),
    depth_stencil(P::Depth32Float, Kind::Depth, 4, false, V::D32Sfloat, DEPTH),
    depth_stencil(P::Stencil8, Kind::Stencil, 1, false, V::S8Uint, STENCIL),
    depth_stencil(
        P::Depth24UnormStencil8,
        Kind::DepthStencil,
        4,
        false,
        V::D24UnormS8Uint,
        DEPTH_STENCIL,
    ),
    depth_stencil(
        P::Depth32FloatStencil8,
        Kind::DepthStencil,
        8,
        false,
        V::D32SfloatS8Uint,
        DEPTH_STENCIL,
    ),
    depth_stencil(
        P::X32Stencil8,
        Kind::Stencil,
        8,
        true,
        V::D32SfloatS8Uint,
        STENCIL,
    ),
    depth_stencil(
        P::X24Stencil8,
        Kind::Stencil,
        4,
        true,
        V::D24UnormS8Uint,
        STENCIL,
    ),
    two_planes(P::Ycbcr8_420_2p),
    two_planes(P::Ycbcr8_422_2p),
    two_planes(P::Ycbcr8_444_2p),
    two_planes(P::Ycbcr10_420_2p),
    two_planes(P::Ycbcr10_422_2p),
    two_planes(P::Ycbcr10_444_2p),
    two_planes(P::Rgb8_420_2p),
    two_planes(P::Rgb8_422_2p),
    two_planes(P::Rgb8_444_2p),
    two_planes(P::Rgb10_420_2p),
    two_planes(P::Rgb10_422_2p),
    two_planes(P::Rgb10_444_2p),
    extended(P::Rgb10A8_2pXr10, true, false),
    extended(P::Rgb10A8_2pXr10Srgb, true, true),
    extended(P::Bgra10Xr, true, false),
    extended(P::Bgra10XrSrgb, true, true),
    extended(P::Bgr10Xr, false, false),
    extended(P::Bgr10XrSrgb, false, true),
];

const _: () = {
    assert!(DESCRIPTIONS.len() == PixelFormat::ALL.len());
    let mut index = 0;
    while index < DESCRIPTIONS.len() {
        assert!(DESCRIPTIONS[index].format.raw() == PixelFormat::ALL[index].raw());
        index += 1;
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_format_has_exactly_one_description_in_declaration_order() {
        assert_eq!(DESCRIPTIONS.len(), PixelFormat::ALL.len());
        for (description, format) in DESCRIPTIONS.iter().zip(PixelFormat::ALL) {
            assert_eq!(description.format, *format);
        }
    }

    #[test]
    fn raw_values_round_trip_and_placeholders_are_refused() {
        for raw in (0..=RAW_COUNT as u64).chain([(1 << 32) + 1, u64::MAX]) {
            let listed = PixelFormat::ALL
                .iter()
                .copied()
                .find(|format| format.raw() == raw);
            assert_eq!(PixelFormat::from_raw(raw), listed, "{raw}");
        }
    }

    #[test]
    fn packed_formats_reverse_component_order() {
        let packed = [
            (P::B5G6R5Unorm, V::R5G6B5UnormPack16),
            (P::Abgr4Unorm, V::R4G4B4A4UnormPack16),
            (P::Bgr5A1Unorm, V::A1R5G5B5UnormPack16),
            (P::Rgb10A2Unorm, V::A2B10G10R10UnormPack32),
            (P::Bgr10A2Unorm, V::A2R10G10B10UnormPack32),
            (P::Rg11B10Float, V::B10G11R11UfloatPack32),
        ];
        for (metal, vulkan) in packed {
            assert_eq!(
                metal.describe().realization.unwrap().format,
                vulkan,
                "{metal:?}"
            );
        }
    }

    #[test]
    fn stencil_views_select_the_stencil_aspect_of_their_parent() {
        for (view, parent) in [
            (P::X32Stencil8, P::Depth32FloatStencil8),
            (P::X24Stencil8, P::Depth24UnormStencil8),
        ] {
            let view = view.describe();
            let parent = parent.describe();
            assert!(view.view_only);
            assert_eq!(
                view.realization.unwrap().format,
                parent.realization.unwrap().format
            );
            assert_eq!(
                view.realization.unwrap().view_aspects,
                ImageAspects::STENCIL
            );
            assert_eq!(view.image_aspects(), parent.image_aspects());
        }
    }

    #[test]
    fn astc_ldr_decodes_to_apples_precision_through_its_block_size() {
        // Linear ASTC keeps 12 bits in 16-bit channels, sRGB its 8.
        let linear = P::Astc10x6Ldr.describe();
        assert_eq!(linear.realization.unwrap().format, V::R16G16B16A16Unorm);
        assert_eq!(linear.realization.unwrap().encoding.stored_bytes(16), 8);
        assert_eq!(
            linear.decoder(),
            Some((BlockKernel::Astc, 10 | 10 << 8 | 6 << 16))
        );
        let srgb = P::Astc12x12Srgb.describe();
        assert_eq!(srgb.realization.unwrap().format, V::R8G8B8A8Srgb);
        assert_eq!(
            srgb.decoder(),
            Some((BlockKernel::Astc, 11 | 12 << 8 | 12 << 16))
        );
        // HDR blocks decode to half floats.
        let hdr = P::Astc8x6Hdr.describe();
        assert_eq!(hdr.realization.unwrap().format, V::R16G16B16A16Sfloat);
        assert_eq!(hdr.realization.unwrap().encoding.stored_bytes(16), 8);
        assert_eq!(
            hdr.decoder(),
            Some((BlockKernel::Astc, 12 | 8 << 8 | 6 << 16))
        );
    }

    #[test]
    fn rgb_pvrtc_variants_read_opaque_alpha() {
        assert_eq!(
            P::PvrtcRgb4bpp.describe().realization.unwrap().swizzle[3],
            S::One
        );
        assert!(
            P::PvrtcRgba4bpp
                .describe()
                .realization
                .unwrap()
                .is_identity()
        );
        assert_eq!(
            P::PvrtcRgb2bpp.describe().block,
            Block {
                width: 8,
                height: 4,
                bytes: 8
            }
        );
    }

    #[test]
    fn srgb_pairs_share_storage_and_differ_only_in_encoding() {
        let mut pairs = 0;
        for format in PixelFormat::ALL {
            let Some(pair) = format.srgb_pair() else {
                continue;
            };
            pairs += 1;
            let (a, b) = (format.describe(), pair.describe());
            assert_eq!(pair.srgb_pair(), Some(*format));
            assert_ne!(a.srgb, b.srgb, "{format:?}");
            assert_eq!(
                (a.block, a.compression),
                (b.block, b.compression),
                "{format:?}"
            );
        }
        assert_eq!(pairs, 64);
        assert_eq!(P::Rgba16Float.srgb_pair(), None);
    }

    #[test]
    fn row_bytes_round_partial_blocks_up() {
        assert_eq!(P::Bc1Rgba.describe().row_bytes(5), 16);
        assert_eq!(P::Astc12x12Ldr.describe().row_bytes(13), 32);
        assert_eq!(P::Rgb16Float.describe().row_bytes(3), 18);
    }

    #[test]
    fn raw_clears_pack_the_texel_metal_stores() {
        // Linear 0.5 is sRGB code 188 (0.7354); codes 127 and 128 meet at
        // linear 0.21404.
        assert_eq!(raw_clear(P::R8UnormSrgb, [0.5, 0.0, 0.0, 1.0]), Some(188));
        assert_eq!(
            raw_clear(P::R8UnormSrgb, [0.2141, 0.0, 0.0, 1.0]),
            Some(128)
        );
        assert_eq!(
            raw_clear(P::R8UnormSrgb, [0.2139, 0.0, 0.0, 1.0]),
            Some(127)
        );
        assert_eq!(raw_clear(P::R8UnormSrgb, [-1.0, 0.0, 0.0, 1.0]), Some(0));
        assert_eq!(raw_clear(P::R8UnormSrgb, [2.0, 0.0, 0.0, 1.0]), Some(255));
        assert_eq!(
            raw_clear(P::Abgr4Unorm, [1.0, 0.5, 0.0, 0.2]),
            Some(0xf << 12 | 8 << 8 | 3)
        );
        assert_eq!(raw_clear(P::Rgba8Unorm, [0.0; 4]), None);
    }

    /// The bytes an M1 Pro writes rendering red, green and blue into a
    /// 4:4:4 YCbCr surface: luma, then Cb and Cr.
    #[test]
    fn two_plane_clears_split_a_color_into_its_planes() {
        let bytes = |format, rgb: [f64; 3]| {
            let first = raw_clear(format, [rgb[0], rgb[1], rgb[2], 1.0]).unwrap();
            let second = second_plane_clear(format, [rgb[0], rgb[1], rgb[2], 1.0]).unwrap();
            [
                first,
                (second[0] * 255.0) as u32,
                (second[1] * 255.0) as u32,
            ]
        };
        assert_eq!(bytes(P::Ycbcr8_444_2p, [1.0, 0.0, 0.0]), [76, 85, 255]);
        assert_eq!(bytes(P::Ycbcr8_444_2p, [0.0, 1.0, 0.0]), [150, 43, 21]);
        assert_eq!(bytes(P::Ycbcr8_444_2p, [0.0, 0.0, 1.0]), [29, 255, 107]);
        assert_eq!(bytes(P::Ycbcr8_444_2p, [1.0, 1.0, 1.0]), [255, 128, 128]);
        // Green, then blue and red.
        assert_eq!(bytes(P::Rgb8_444_2p, [1.0, 0.5, 0.25]), [128, 64, 255]);
        assert_eq!(second_plane_clear(P::Rgba8Unorm, [0.0; 4]), None);
    }

    #[test]
    fn rg8_srgb_texels_pad_into_rgba8_srgb() {
        let realization = P::Rg8UnormSrgb.describe().realization.unwrap();
        assert_eq!(realization.format, V::R8G8B8A8Srgb);
        assert_eq!(realization.swizzle, PADDED);
        assert!(realization.writes_through());
        assert_eq!(P::Rg8UnormSrgb.describe().stored_block_bytes(), 4);
        let mut stored = [0; 8];
        Encoding::Padded.store(&[1, 2, 3, 4], &mut stored);
        assert_eq!(stored, [1, 2, 0, 0xff, 3, 4, 0, 0xff]);
        let mut metal = [0; 4];
        Encoding::Padded.load(&[5, 6, 7, 8, 9, 10, 11, 12], &mut metal);
        assert_eq!(metal, [5, 6, 9, 10]);
    }

    #[test]
    fn a1bgr5_texels_rotate_into_a1r5g5b5() {
        let description = P::A1Bgr5Unorm.describe();
        let realization = description.realization.unwrap();
        assert_eq!(realization.format, V::A1R5G5B5UnormPack16);
        assert!(realization.writes_through());
        assert_eq!(description.stored_block_bytes(), 2);
        // Metal's alpha in bit 0, blue, green and red above it; Vulkan's
        // blue from bit 0 and alpha in bit 15.
        let metal = (1u16 | 3 << 1 | 5 << 6 | 7 << 11).to_le_bytes();
        let mut stored = [0; 2];
        Encoding::Rotated.store(&metal, &mut stored);
        assert_eq!(u16::from_le_bytes(stored), 3 | 5 << 5 | 7 << 10 | 1 << 15);
        let mut back = [0; 2];
        Encoding::Rotated.load(&stored, &mut back);
        assert_eq!(back, metal);
    }

    #[test]
    fn extended_range_formats_are_held_as_half_floats() {
        for (format, alpha, srgb, planes, bytes) in [
            (P::Bgra10Xr, true, false, false, 8),
            (P::Bgra10XrSrgb, true, true, false, 8),
            (P::Bgr10Xr, false, false, false, 4),
            (P::Bgr10XrSrgb, false, true, false, 4),
            (P::Rgb10A8_2pXr10, true, false, true, 4),
            (P::Rgb10A8_2pXr10Srgb, true, true, true, 4),
        ] {
            let description = format.describe();
            let realization = description.realization.unwrap();
            assert_eq!(realization.format, V::R16G16B16A16Sfloat);
            assert_eq!(
                realization.encoding,
                Encoding::ExtendedRange(extended_range::Codes {
                    alpha,
                    srgb,
                    planes
                })
            );
            assert_eq!(format.extended_planes().is_some(), planes);
            assert_eq!(description.block.bytes, bytes);
            assert_eq!(
                realization.swizzle[3],
                if alpha { S::Identity } else { S::One }
            );
            assert!(realization.writes_through());
        }
        assert!(
            P::Rgba8Unorm
                .describe()
                .realization
                .unwrap()
                .encoding
                .is_exact()
        );
        assert!(
            !P::PvrtcRgb4bpp
                .describe()
                .realization
                .unwrap()
                .writes_through()
        );
    }

    #[test]
    fn formats_without_vulkan_equivalents_say_why() {
        assert_eq!(
            P::Gbgr422.describe().realization,
            Err(Unrealized::YcbcrConversion)
        );
    }
}
