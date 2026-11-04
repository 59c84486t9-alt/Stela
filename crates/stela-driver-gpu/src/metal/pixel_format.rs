//! Every `MTLPixelFormat`: its storage layout, numeric class and the Vulkan
//! format and view that realize it.
//!
//! Metal names packed formats from the least significant bits (`B5G6R5Unorm`
//! keeps blue in bits 0-4); Vulkan names them from the most significant bits,
//! so the realizations reverse the component order. A format without an
//! exact Vulkan equivalent records why instead of approximating it.
use super::vulkan::{ComponentSwizzle, Format as VkFormat, ImageAspects};

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
    /// Apple's extended-range 10-bit encodings have no Vulkan format.
    ExtendedRange,
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
}

impl Realization {
    pub fn is_identity(&self) -> bool {
        self.swizzle == IDENTITY
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

    pub fn describe(self) -> &'static Description {
        &DESCRIPTIONS[self.index()]
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

const fn vk(format: VkFormat, view_aspects: ImageAspects) -> Result<Realization, Unrealized> {
    Ok(Realization {
        format,
        view_aspects,
        swizzle: IDENTITY,
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
    )
}

const fn etc(
    format: PixelFormat,
    numeric: Numeric,
    srgb: bool,
    bytes: u32,
    realization: VkFormat,
) -> Description {
    compressed(
        format,
        Compression::Etc2Eac,
        numeric,
        srgb,
        4,
        4,
        bytes,
        realization,
        IDENTITY,
    )
}

/// PVRTC1 blocks are 4x4 texels at 4 bpp and 8x4 at 2 bpp; Metal's RGB
/// variants ignore the encoded alpha.
const fn pvrtc(
    format: PixelFormat,
    srgb: bool,
    two_bpp: bool,
    alpha: bool,
    realization: VkFormat,
) -> Description {
    let width = if two_bpp { 8 } else { 4 };
    let swizzle = if alpha { IDENTITY } else { OPAQUE };
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
    )
}

const fn astc(
    format: PixelFormat,
    kind: u8,
    width: u32,
    height: u32,
    realization: VkFormat,
) -> Description {
    let (compression, numeric, srgb) = match kind {
        b'h' => (Compression::AstcHdr, Numeric::Float, false),
        b's' => (Compression::AstcLdr, Numeric::Unorm, true),
        _ => (Compression::AstcLdr, Numeric::Unorm, false),
    };
    compressed(
        format,
        compression,
        numeric,
        srgb,
        width,
        height,
        16,
        realization,
        IDENTITY,
    )
}

const fn unrealized(
    format: PixelFormat,
    srgb: bool,
    bytes: u32,
    reason: Unrealized,
) -> Description {
    Description {
        format,
        kind: Kind::Color(Numeric::Unorm),
        srgb,
        compression: Compression::None,
        block: Block::texel(bytes),
        view_only: false,
        realization: Err(reason),
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
    srgb(P::Rg8UnormSrgb, 2, V::R8G8Srgb),
    color(P::Rg8Snorm, Snorm, 2, V::R8G8Snorm),
    color(P::Rg8Uint, Uint, 2, V::R8G8Uint),
    color(P::Rg8Sint, Sint, 2, V::R8G8Sint),
    color(P::B5G6R5Unorm, Unorm, 2, V::R5G6B5UnormPack16),
    color(P::A1Bgr5Unorm, Unorm, 2, V::R5G5B5A1UnormPack16),
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
    pvrtc(
        P::PvrtcRgb2bpp,
        false,
        true,
        false,
        V::Pvrtc12bppUnormBlockImg,
    ),
    pvrtc(
        P::PvrtcRgb2bppSrgb,
        true,
        true,
        false,
        V::Pvrtc12bppSrgbBlockImg,
    ),
    pvrtc(
        P::PvrtcRgb4bpp,
        false,
        false,
        false,
        V::Pvrtc14bppUnormBlockImg,
    ),
    pvrtc(
        P::PvrtcRgb4bppSrgb,
        true,
        false,
        false,
        V::Pvrtc14bppSrgbBlockImg,
    ),
    pvrtc(
        P::PvrtcRgba2bpp,
        false,
        true,
        true,
        V::Pvrtc12bppUnormBlockImg,
    ),
    pvrtc(
        P::PvrtcRgba2bppSrgb,
        true,
        true,
        true,
        V::Pvrtc12bppSrgbBlockImg,
    ),
    pvrtc(
        P::PvrtcRgba4bpp,
        false,
        false,
        true,
        V::Pvrtc14bppUnormBlockImg,
    ),
    pvrtc(
        P::PvrtcRgba4bppSrgb,
        true,
        false,
        true,
        V::Pvrtc14bppSrgbBlockImg,
    ),
    etc(P::EacR11Unorm, Unorm, false, 8, V::EacR11UnormBlock),
    etc(P::EacR11Snorm, Snorm, false, 8, V::EacR11SnormBlock),
    etc(P::EacRg11Unorm, Unorm, false, 16, V::EacR11G11UnormBlock),
    etc(P::EacRg11Snorm, Snorm, false, 16, V::EacR11G11SnormBlock),
    etc(P::EacRgba8, Unorm, false, 16, V::Etc2R8G8B8A8UnormBlock),
    etc(P::EacRgba8Srgb, Unorm, true, 16, V::Etc2R8G8B8A8SrgbBlock),
    etc(P::Etc2Rgb8, Unorm, false, 8, V::Etc2R8G8B8UnormBlock),
    etc(P::Etc2Rgb8Srgb, Unorm, true, 8, V::Etc2R8G8B8SrgbBlock),
    etc(P::Etc2Rgb8A1, Unorm, false, 8, V::Etc2R8G8B8A1UnormBlock),
    etc(P::Etc2Rgb8A1Srgb, Unorm, true, 8, V::Etc2R8G8B8A1SrgbBlock),
    astc(P::Astc4x4Srgb, b's', 4, 4, V::Astc4x4SrgbBlock),
    astc(P::Astc5x4Srgb, b's', 5, 4, V::Astc5x4SrgbBlock),
    astc(P::Astc5x5Srgb, b's', 5, 5, V::Astc5x5SrgbBlock),
    astc(P::Astc6x5Srgb, b's', 6, 5, V::Astc6x5SrgbBlock),
    astc(P::Astc6x6Srgb, b's', 6, 6, V::Astc6x6SrgbBlock),
    astc(P::Astc8x5Srgb, b's', 8, 5, V::Astc8x5SrgbBlock),
    astc(P::Astc8x6Srgb, b's', 8, 6, V::Astc8x6SrgbBlock),
    astc(P::Astc8x8Srgb, b's', 8, 8, V::Astc8x8SrgbBlock),
    astc(P::Astc10x5Srgb, b's', 10, 5, V::Astc10x5SrgbBlock),
    astc(P::Astc10x6Srgb, b's', 10, 6, V::Astc10x6SrgbBlock),
    astc(P::Astc10x8Srgb, b's', 10, 8, V::Astc10x8SrgbBlock),
    astc(P::Astc10x10Srgb, b's', 10, 10, V::Astc10x10SrgbBlock),
    astc(P::Astc12x10Srgb, b's', 12, 10, V::Astc12x10SrgbBlock),
    astc(P::Astc12x12Srgb, b's', 12, 12, V::Astc12x12SrgbBlock),
    astc(P::Astc4x4Ldr, b'l', 4, 4, V::Astc4x4UnormBlock),
    astc(P::Astc5x4Ldr, b'l', 5, 4, V::Astc5x4UnormBlock),
    astc(P::Astc5x5Ldr, b'l', 5, 5, V::Astc5x5UnormBlock),
    astc(P::Astc6x5Ldr, b'l', 6, 5, V::Astc6x5UnormBlock),
    astc(P::Astc6x6Ldr, b'l', 6, 6, V::Astc6x6UnormBlock),
    astc(P::Astc8x5Ldr, b'l', 8, 5, V::Astc8x5UnormBlock),
    astc(P::Astc8x6Ldr, b'l', 8, 6, V::Astc8x6UnormBlock),
    astc(P::Astc8x8Ldr, b'l', 8, 8, V::Astc8x8UnormBlock),
    astc(P::Astc10x5Ldr, b'l', 10, 5, V::Astc10x5UnormBlock),
    astc(P::Astc10x6Ldr, b'l', 10, 6, V::Astc10x6UnormBlock),
    astc(P::Astc10x8Ldr, b'l', 10, 8, V::Astc10x8UnormBlock),
    astc(P::Astc10x10Ldr, b'l', 10, 10, V::Astc10x10UnormBlock),
    astc(P::Astc12x10Ldr, b'l', 12, 10, V::Astc12x10UnormBlock),
    astc(P::Astc12x12Ldr, b'l', 12, 12, V::Astc12x12UnormBlock),
    astc(P::Astc4x4Hdr, b'h', 4, 4, V::Astc4x4SfloatBlock),
    astc(P::Astc5x4Hdr, b'h', 5, 4, V::Astc5x4SfloatBlock),
    astc(P::Astc5x5Hdr, b'h', 5, 5, V::Astc5x5SfloatBlock),
    astc(P::Astc6x5Hdr, b'h', 6, 5, V::Astc6x5SfloatBlock),
    astc(P::Astc6x6Hdr, b'h', 6, 6, V::Astc6x6SfloatBlock),
    astc(P::Astc8x5Hdr, b'h', 8, 5, V::Astc8x5SfloatBlock),
    astc(P::Astc8x6Hdr, b'h', 8, 6, V::Astc8x6SfloatBlock),
    astc(P::Astc8x8Hdr, b'h', 8, 8, V::Astc8x8SfloatBlock),
    astc(P::Astc10x5Hdr, b'h', 10, 5, V::Astc10x5SfloatBlock),
    astc(P::Astc10x6Hdr, b'h', 10, 6, V::Astc10x6SfloatBlock),
    astc(P::Astc10x8Hdr, b'h', 10, 8, V::Astc10x8SfloatBlock),
    astc(P::Astc10x10Hdr, b'h', 10, 10, V::Astc10x10SfloatBlock),
    astc(P::Astc12x10Hdr, b'h', 12, 10, V::Astc12x10SfloatBlock),
    astc(P::Astc12x12Hdr, b'h', 12, 12, V::Astc12x12SfloatBlock),
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
    unrealized(P::Bgra10Xr, false, 8, Unrealized::ExtendedRange),
    unrealized(P::Bgra10XrSrgb, true, 8, Unrealized::ExtendedRange),
    unrealized(P::Bgr10Xr, false, 4, Unrealized::ExtendedRange),
    unrealized(P::Bgr10XrSrgb, true, 4, Unrealized::ExtendedRange),
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
            (P::A1Bgr5Unorm, V::R5G5B5A1UnormPack16),
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
        assert_eq!(pairs, 62);
        assert_eq!(P::Rgba16Float.srgb_pair(), None);
    }

    #[test]
    fn row_bytes_round_partial_blocks_up() {
        assert_eq!(P::Bc1Rgba.describe().row_bytes(5), 16);
        assert_eq!(P::Astc12x12Ldr.describe().row_bytes(13), 32);
        assert_eq!(P::Rgb16Float.describe().row_bytes(3), 18);
    }

    #[test]
    fn formats_without_exact_vulkan_equivalents_say_why() {
        assert_eq!(
            P::Bgra10Xr.describe().realization,
            Err(Unrealized::ExtendedRange)
        );
        assert_eq!(
            P::Gbgr422.describe().realization,
            Err(Unrealized::YcbcrConversion)
        );
    }
}
