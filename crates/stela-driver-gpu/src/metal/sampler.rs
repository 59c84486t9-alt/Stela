//! `MTLSamplerState` lowered to Vulkan samplers.
//!
//! Metal samplers are independent of the texture's format, but a Vulkan
//! border color is either float or integer. A sampler that can sample a
//! nonzero border therefore has an integer twin that differs only in its
//! border color; shaders sampling integer textures use the twin.
use super::{
    abi::{
        CompareFunction, SamplerAddressMode, SamplerBorderColor, SamplerMinMagFilter,
        SamplerMipFilter, SamplerReductionMode,
    },
    capabilities::Capabilities,
    error::{Error, Result, ensure, require},
    vulkan::{
        BorderColor, CompareOp, Filter, SamplerAddressMode as VkAddressMode, SamplerMipmapMode,
        SamplerReductionMode as VkReductionMode, object::SamplerInfo,
    },
};

/// `MTLSamplerDescriptor`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SamplerDescriptor {
    pub min_filter: SamplerMinMagFilter,
    pub mag_filter: SamplerMinMagFilter,
    pub mip_filter: SamplerMipFilter,
    pub max_anisotropy: u64,
    pub address_modes: [SamplerAddressMode; 3],
    pub border_color: SamplerBorderColor,
    pub reduction_mode: SamplerReductionMode,
    pub normalized_coordinates: bool,
    pub lod_min_clamp: f32,
    pub lod_max_clamp: f32,
    pub compare_function: CompareFunction,
}

impl Default for SamplerDescriptor {
    /// Metal's defaults.
    fn default() -> Self {
        Self {
            min_filter: SamplerMinMagFilter::Nearest,
            mag_filter: SamplerMinMagFilter::Nearest,
            mip_filter: SamplerMipFilter::NotMipmapped,
            max_anisotropy: 1,
            address_modes: [SamplerAddressMode::ClampToEdge; 3],
            border_color: SamplerBorderColor::TransparentBlack,
            reduction_mode: SamplerReductionMode::WeightedAverage,
            normalized_coordinates: true,
            lod_min_clamp: 0.0,
            lod_max_clamp: f32::MAX,
            compare_function: CompareFunction::Never,
        }
    }
}

impl SamplerDescriptor {
    /// The sampler a constexpr sampler's state encodes: the first word of
    /// the `[2 x i64]` Apple's compiler emits for it into AIR, whose bits
    /// from the low end are three 3-bit address modes (s, t, r), 2-bit mag,
    /// min and mip filters, the pixel-coordinates flag, a 4-bit compare
    /// function, the anisotropy less one in 4 bits, the half LOD minimum
    /// and maximum clamps, and 2-bit border color and reduction mode.
    pub fn from_constexpr(state: u64) -> Result<Self> {
        let field = |shift: u32, bits: u32| state >> shift & ((1 << bits) - 1);
        let invalid = Error::Invalid("constexpr sampler state");
        ensure(state >> 60 == 0, "constexpr sampler state")?;
        let address = |shift| match field(shift, 3) {
            // clamp_to_zero is clamp_to_border with the default border.
            0 => Ok(SamplerAddressMode::ClampToBorderColor),
            1 => Ok(SamplerAddressMode::ClampToEdge),
            2 => Ok(SamplerAddressMode::Repeat),
            3 => Ok(SamplerAddressMode::MirrorRepeat),
            _ => Err(invalid),
        };
        let filter = |shift| match field(shift, 2) {
            2 => Err(Error::Unsupported("bicubic sampler filtering")),
            raw => SamplerMinMagFilter::from_raw(raw).ok_or(invalid),
        };
        let compare_function = match field(16, 4) {
            1 => CompareFunction::Less,
            2 => CompareFunction::LessEqual,
            3 => CompareFunction::Greater,
            4 => CompareFunction::GreaterEqual,
            5 => CompareFunction::Equal,
            6 => CompareFunction::NotEqual,
            7 => CompareFunction::Always,
            8 => CompareFunction::Never,
            _ => return Err(invalid),
        };
        Ok(Self {
            address_modes: [address(0)?, address(3)?, address(6)?],
            mag_filter: filter(9)?,
            min_filter: filter(11)?,
            mip_filter: SamplerMipFilter::from_raw(field(13, 2)).ok_or(invalid)?,
            normalized_coordinates: field(15, 1) == 0,
            compare_function,
            max_anisotropy: field(20, 4) + 1,
            lod_min_clamp: half(field(24, 16)),
            lod_max_clamp: half(field(40, 16)),
            border_color: SamplerBorderColor::from_raw(field(56, 2)).ok_or(invalid)?,
            reduction_mode: SamplerReductionMode::from_raw(field(58, 2)).ok_or(invalid)?,
        })
    }
}

/// The value of an IEEE half's bits.
fn half(bits: u64) -> f32 {
    let (exponent, mantissa) = ((bits >> 10 & 0x1f) as u32, (bits & 0x3ff) as u32);
    let magnitude = match exponent {
        0 => mantissa as f32 * f32::from_bits((127 - 24) << 23),
        0x1f => f32::from_bits(0xff << 23 | mantissa << 13),
        _ => f32::from_bits((exponent + 127 - 15) << 23 | mantissa << 13),
    };
    if bits >> 15 & 1 == 1 {
        -magnitude
    } else {
        magnitude
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SamplerPlan {
    pub float: SamplerInfo,
    /// The integer-border twin, present when the border is not zero.
    pub integer: Option<SamplerInfo>,
}

/// Vulkan's suggested emulation of unmipmapped sampling: nearest mip
/// selection clamped below level 1 keeps the min/mag filter choice.
const UNMIPMAPPED_MAX_LOD: f32 = 0.25;

pub fn sampler(capabilities: &Capabilities, descriptor: &SamplerDescriptor) -> Result<SamplerPlan> {
    ensure(
        (1..=16).contains(&descriptor.max_anisotropy),
        "maxAnisotropy is between 1 and 16",
    )?;
    ensure(
        descriptor.lod_min_clamp >= 0.0 && descriptor.lod_min_clamp <= descriptor.lod_max_clamp,
        "LOD clamps are ordered and nonnegative",
    )?;

    let uses = |mode: SamplerAddressMode| descriptor.address_modes.contains(&mode);
    let border = match (
        uses(SamplerAddressMode::ClampToZero),
        uses(SamplerAddressMode::ClampToBorderColor),
    ) {
        (true, true) if descriptor.border_color != SamplerBorderColor::TransparentBlack => {
            // Vulkan samplers have one border color for every axis.
            return Err(Error::Unsupported(
                "clamp-to-zero combined with a nonzero border color",
            ));
        }
        (true, _) => Some(SamplerBorderColor::TransparentBlack),
        (false, true) => Some(descriptor.border_color),
        (false, false) => None,
    };
    if uses(SamplerAddressMode::MirrorClampToEdge) {
        require(
            capabilities.sampler_mirror_clamp_to_edge,
            "mirror-clamp-to-edge addressing",
        )?;
    }
    if descriptor.reduction_mode != SamplerReductionMode::WeightedAverage {
        require(
            capabilities.sampler_reduction_modes,
            "sampler reduction modes",
        )?;
    }

    if !descriptor.normalized_coordinates {
        // The shared rules of Metal pixel-coordinate samplers and Vulkan
        // unnormalized samplers.
        ensure(
            descriptor.min_filter == descriptor.mag_filter,
            "pixel-coordinate samplers use one filter",
        )?;
        ensure(
            descriptor.mip_filter == SamplerMipFilter::NotMipmapped,
            "pixel-coordinate samplers are unmipmapped",
        )?;
        ensure(
            descriptor.max_anisotropy == 1,
            "pixel-coordinate samplers are isotropic",
        )?;
        ensure(
            descriptor.compare_function == CompareFunction::Never,
            "pixel-coordinate samplers do not compare",
        )?;
        ensure(
            descriptor.address_modes.iter().all(|mode| {
                matches!(
                    mode,
                    SamplerAddressMode::ClampToEdge
                        | SamplerAddressMode::ClampToZero
                        | SamplerAddressMode::ClampToBorderColor
                )
            }),
            "pixel-coordinate samplers clamp",
        )?;
    }

    let (mipmap_mode, min_lod, max_lod) = match descriptor.mip_filter {
        SamplerMipFilter::NotMipmapped => (SamplerMipmapMode::Nearest, 0.0, UNMIPMAPPED_MAX_LOD),
        SamplerMipFilter::Nearest => (
            SamplerMipmapMode::Nearest,
            descriptor.lod_min_clamp,
            descriptor.lod_max_clamp,
        ),
        SamplerMipFilter::Linear => (
            SamplerMipmapMode::Linear,
            descriptor.lod_min_clamp,
            descriptor.lod_max_clamp,
        ),
    };
    let (min_lod, max_lod) = if descriptor.normalized_coordinates {
        (min_lod, max_lod)
    } else {
        (0.0, 0.0)
    };
    let anisotropy = (descriptor.max_anisotropy > 1)
        .then(|| (descriptor.max_anisotropy as f32).min(capabilities.max_sampler_anisotropy))
        .filter(|anisotropy| *anisotropy > 1.0);

    let float = SamplerInfo {
        mag_filter: filter(descriptor.mag_filter),
        min_filter: filter(descriptor.min_filter),
        mipmap_mode,
        address_modes: descriptor.address_modes.map(address_mode),
        anisotropy,
        compare: compare_op(descriptor.compare_function),
        min_lod,
        max_lod,
        border_color: border_color(
            border.unwrap_or(SamplerBorderColor::TransparentBlack),
            false,
        ),
        unnormalized_coordinates: !descriptor.normalized_coordinates,
        reduction_mode: match descriptor.reduction_mode {
            SamplerReductionMode::WeightedAverage => VkReductionMode::WeightedAverage,
            SamplerReductionMode::Minimum => VkReductionMode::Min,
            SamplerReductionMode::Maximum => VkReductionMode::Max,
        },
    };
    let integer = border
        .filter(|color| *color != SamplerBorderColor::TransparentBlack)
        .map(|color| SamplerInfo {
            border_color: border_color(color, true),
            ..float
        });
    Ok(SamplerPlan { float, integer })
}

const fn filter(filter: SamplerMinMagFilter) -> Filter {
    match filter {
        SamplerMinMagFilter::Nearest => Filter::Nearest,
        SamplerMinMagFilter::Linear => Filter::Linear,
    }
}

const fn address_mode(mode: SamplerAddressMode) -> VkAddressMode {
    match mode {
        SamplerAddressMode::ClampToEdge => VkAddressMode::ClampToEdge,
        SamplerAddressMode::MirrorClampToEdge => VkAddressMode::MirrorClampToEdge,
        SamplerAddressMode::Repeat => VkAddressMode::Repeat,
        SamplerAddressMode::MirrorRepeat => VkAddressMode::MirroredRepeat,
        SamplerAddressMode::ClampToZero | SamplerAddressMode::ClampToBorderColor => {
            VkAddressMode::ClampToBorder
        }
    }
}

const fn border_color(color: SamplerBorderColor, integer: bool) -> BorderColor {
    match (color, integer) {
        (SamplerBorderColor::TransparentBlack, false) => BorderColor::FloatTransparentBlack,
        (SamplerBorderColor::TransparentBlack, true) => BorderColor::IntTransparentBlack,
        (SamplerBorderColor::OpaqueBlack, false) => BorderColor::FloatOpaqueBlack,
        (SamplerBorderColor::OpaqueBlack, true) => BorderColor::IntOpaqueBlack,
        (SamplerBorderColor::OpaqueWhite, false) => BorderColor::FloatOpaqueWhite,
        (SamplerBorderColor::OpaqueWhite, true) => BorderColor::IntOpaqueWhite,
    }
}

/// Metal's `Never` is the default of samplers that do not compare.
pub const fn compare_op(function: CompareFunction) -> Option<CompareOp> {
    Some(match function {
        CompareFunction::Never => return None,
        CompareFunction::Less => CompareOp::Less,
        CompareFunction::Equal => CompareOp::Equal,
        CompareFunction::LessEqual => CompareOp::LessOrEqual,
        CompareFunction::Greater => CompareOp::Greater,
        CompareFunction::NotEqual => CompareOp::NotEqual,
        CompareFunction::GreaterEqual => CompareOp::GreaterOrEqual,
        CompareFunction::Always => CompareOp::Always,
    })
}

/// The Vulkan compare operation for depth and stencil tests, where `Never`
/// is a real test.
pub const fn test_op(function: CompareFunction) -> CompareOp {
    match compare_op(function) {
        Some(op) => op,
        None => CompareOp::Never,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::nvidia::fixture::capabilities;

    #[test]
    fn defaults_sample_level_zero_with_nearest_filters() {
        let plan = sampler(&capabilities(), &SamplerDescriptor::default()).unwrap();
        assert_eq!(
            (plan.float.min_lod, plan.float.max_lod),
            (0.0, UNMIPMAPPED_MAX_LOD)
        );
        assert_eq!(plan.float.mipmap_mode, SamplerMipmapMode::Nearest);
        assert_eq!(plan.float.anisotropy, None);
        assert_eq!(plan.float.compare, None);
        assert_eq!(plan.integer, None);
    }

    #[test]
    fn trilinear_anisotropic_comparison_samplers() {
        let descriptor = SamplerDescriptor {
            min_filter: SamplerMinMagFilter::Linear,
            mag_filter: SamplerMinMagFilter::Linear,
            mip_filter: SamplerMipFilter::Linear,
            max_anisotropy: 16,
            lod_min_clamp: 1.0,
            lod_max_clamp: 4.0,
            compare_function: CompareFunction::LessEqual,
            address_modes: [
                SamplerAddressMode::Repeat,
                SamplerAddressMode::MirrorRepeat,
                SamplerAddressMode::MirrorClampToEdge,
            ],
            ..SamplerDescriptor::default()
        };
        let plan = sampler(&capabilities(), &descriptor).unwrap().float;
        assert_eq!(plan.mipmap_mode, SamplerMipmapMode::Linear);
        assert_eq!(plan.anisotropy, Some(16.0));
        assert_eq!((plan.min_lod, plan.max_lod), (1.0, 4.0));
        assert_eq!(plan.compare, Some(CompareOp::LessOrEqual));
        assert_eq!(
            plan.address_modes,
            [
                VkAddressMode::Repeat,
                VkAddressMode::MirroredRepeat,
                VkAddressMode::MirrorClampToEdge
            ]
        );
    }

    #[test]
    fn nonzero_borders_get_an_integer_twin() {
        let descriptor = SamplerDescriptor {
            address_modes: [SamplerAddressMode::ClampToBorderColor; 3],
            border_color: SamplerBorderColor::OpaqueWhite,
            ..SamplerDescriptor::default()
        };
        let plan = sampler(&capabilities(), &descriptor).unwrap();
        assert_eq!(plan.float.border_color, BorderColor::FloatOpaqueWhite);
        assert_eq!(
            plan.integer.unwrap().border_color,
            BorderColor::IntOpaqueWhite
        );
        assert_eq!(
            SamplerInfo {
                border_color: plan.float.border_color,
                ..plan.integer.unwrap()
            },
            plan.float
        );

        let zero = SamplerDescriptor {
            address_modes: [SamplerAddressMode::ClampToZero; 3],
            border_color: SamplerBorderColor::OpaqueWhite,
            ..SamplerDescriptor::default()
        };
        let plan = sampler(&capabilities(), &zero).unwrap();
        assert_eq!(
            (plan.float.border_color, plan.integer),
            (BorderColor::FloatTransparentBlack, None)
        );

        let conflicting = SamplerDescriptor {
            address_modes: [
                SamplerAddressMode::ClampToZero,
                SamplerAddressMode::ClampToBorderColor,
                SamplerAddressMode::Repeat,
            ],
            border_color: SamplerBorderColor::OpaqueBlack,
            ..SamplerDescriptor::default()
        };
        assert!(matches!(
            sampler(&capabilities(), &conflicting),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn pixel_coordinate_samplers_follow_both_apis_rules() {
        let pixel = SamplerDescriptor {
            normalized_coordinates: false,
            ..SamplerDescriptor::default()
        };
        let plan = sampler(&capabilities(), &pixel).unwrap().float;
        assert!(plan.unnormalized_coordinates);
        assert_eq!((plan.min_lod, plan.max_lod), (0.0, 0.0));
        let repeating = SamplerDescriptor {
            address_modes: [SamplerAddressMode::Repeat; 3],
            ..pixel
        };
        assert!(matches!(
            sampler(&capabilities(), &repeating),
            Err(Error::Invalid(_))
        ));
        let mipmapped = SamplerDescriptor {
            mip_filter: SamplerMipFilter::Linear,
            ..pixel
        };
        assert!(matches!(
            sampler(&capabilities(), &mipmapped),
            Err(Error::Invalid(_))
        ));
    }

    /// States Apple's compiler emitted for MSL constexpr samplers.
    #[test]
    fn constexpr_states_decode_as_apples_compiler_encodes_them() {
        let default = SamplerDescriptor {
            lod_max_clamp: 65504.0,
            ..SamplerDescriptor::default()
        };
        assert_eq!(
            SamplerDescriptor::from_constexpr(0x007b_ff00_0008_0049),
            Ok(default)
        );
        // filter::linear, mip_filter::linear, max_anisotropy(8)
        assert_eq!(
            SamplerDescriptor::from_constexpr(0x007b_ff00_0078_4a49),
            Ok(SamplerDescriptor {
                min_filter: SamplerMinMagFilter::Linear,
                mag_filter: SamplerMinMagFilter::Linear,
                mip_filter: SamplerMipFilter::Linear,
                max_anisotropy: 8,
                ..default
            })
        );
        // s_address::clamp_to_border, border_color::opaque_white
        let border = SamplerDescriptor::from_constexpr(0x027b_ff00_0008_0048).unwrap();
        assert_eq!(
            (border.address_modes, border.border_color),
            (
                [
                    SamplerAddressMode::ClampToBorderColor,
                    SamplerAddressMode::ClampToEdge,
                    SamplerAddressMode::ClampToEdge
                ],
                SamplerBorderColor::OpaqueWhite
            )
        );
        // coord::pixel, compare_func::less_equal, lod_clamp(1, MAXHALF)
        let pixel = SamplerDescriptor::from_constexpr(0x007b_ff3c_0002_8049).unwrap();
        assert_eq!(
            (
                pixel.normalized_coordinates,
                pixel.compare_function,
                pixel.lod_min_clamp
            ),
            (false, CompareFunction::LessEqual, 1.0)
        );
        // filter::bicubic
        assert_eq!(
            SamplerDescriptor::from_constexpr(0x007b_ff00_0008_1449),
            Err(Error::Unsupported("bicubic sampler filtering"))
        );
        for reserved in [1 << 60, 0x007b_ff00_0000_0049, 0x007b_ff00_0008_004c] {
            assert!(matches!(
                SamplerDescriptor::from_constexpr(reserved),
                Err(Error::Invalid(_))
            ));
        }
    }

    #[test]
    fn invalid_ranges_are_refused() {
        let anisotropic = SamplerDescriptor {
            max_anisotropy: 17,
            ..SamplerDescriptor::default()
        };
        assert!(sampler(&capabilities(), &anisotropic).is_err());
        let inverted = SamplerDescriptor {
            lod_min_clamp: 2.0,
            lod_max_clamp: 1.0,
            ..SamplerDescriptor::default()
        };
        assert!(sampler(&capabilities(), &inverted).is_err());
        assert_eq!(test_op(CompareFunction::Never), CompareOp::Never);
    }
}
