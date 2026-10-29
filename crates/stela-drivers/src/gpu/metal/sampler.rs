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
    use crate::gpu::metal::nvidia::fixture::capabilities;

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
