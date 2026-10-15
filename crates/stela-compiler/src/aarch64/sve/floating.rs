//! Reviewed streaming numerical families share one source-admitted completion boundary.

pub mod arithmetic;
pub mod bfloat16;
pub mod comparison;
pub mod control;
pub mod conversion;
pub mod faminmax;
pub mod fp8;
pub mod rounding;

use super::dot;
use crate::aarch64::{
    floating::features::NumericalFeatures,
    scalable::features::{FeatureRequirement, ScalableFeature, ScalableFeatures},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Arithmetic(arithmetic::Operand),
    Comparison(comparison::Operand),
    Conversion(conversion::Operand),
    FaMinMax(faminmax::Operand),
    Fp8(fp8::Operand),
    Rounding(rounding::Operand),
    Dot(dot::Operand),
    Bfloat16(bfloat16::Operand),
}

impl Operation {
    /// Requirements for this declared SME-derived streaming profile. Source
    /// admission remains separate from allocation and host capabilities.
    pub fn required_streaming_features(self, numerical: NumericalFeatures) -> FeatureRequirement {
        use ScalableFeature as Feature;
        let sme = ScalableFeatures::of(Feature::Sme);
        let required = match self {
            Self::Arithmetic(operand) => match (operand.kind, operand.inputs, operand.shape) {
                (
                    _,
                    arithmetic::Inputs::Reduction { .. },
                    arithmetic::ResultShape::QuadReduction,
                ) => sme.with(Feature::Sme2p1),
                (arithmetic::Kind::Clamp, _, _) => sme.with(Feature::Sme2),
                _ => sme,
            },
            Self::Dot(dot::Operand {
                kind: dot::Kind::HalfDot,
                ..
            }) => sme.with(Feature::Sme2),
            Self::Conversion(conversion::Operand {
                kind: conversion::Kind::Bfloat16 { .. },
                ..
            }) => sme.with(Feature::Bf16),
            Self::Bfloat16(operand) if operand.kind.is_b16b16() => {
                let required = sme.with(Feature::SveB16B16);
                return if numerical.full_a64() {
                    FeatureRequirement::all_and_any(
                        required,
                        ScalableFeatures::of(Feature::Sme2).with(Feature::SmeFa64),
                    )
                } else {
                    FeatureRequirement::all(required.with(Feature::Sme2))
                };
            }
            Self::Bfloat16(bfloat16::Operand {
                kind: bfloat16::Kind::MultiplyLong { subtract: true, .. },
                ..
            }) => sme.with(Feature::Sme2),
            Self::Bfloat16(_) => sme.with(Feature::Bf16),
            Self::FaMinMax(_) => sme.with(Feature::Sme2).with(Feature::FaMinMax),
            Self::Fp8(_) => sme
                .with(Feature::Sme2)
                .with(Feature::Fp8)
                .with(Feature::Fpmr),
            Self::Comparison(_) | Self::Conversion(_) | Self::Rounding(_) | Self::Dot(_) => sme,
        };
        FeatureRequirement::all(required)
    }

    #[allow(clippy::result_unit_err)]
    pub fn decode(word: u32) -> Option<Result<Self, ()>> {
        if let Some(result) = fp8::decode(word) {
            return Some(result.map(Self::Fp8));
        }
        if let Some(result) = faminmax::decode(word) {
            return Some(result.map(Self::FaMinMax));
        }
        // BF allocations overlap the broader ordinary floating size fields.
        if let Some(result) = bfloat16::decode(word) {
            return Some(result.map(Self::Bfloat16));
        }
        if let Some(result) = arithmetic::decode_numerical(word) {
            return Some(result.map(Self::Arithmetic));
        }
        if let Some(result) = comparison::decode(word) {
            return Some(result.map(Self::Comparison));
        }
        if let Some(result) = conversion::decode(word) {
            return Some(result.map(Self::Conversion));
        }
        if let Some(result) = rounding::decode(word) {
            return Some(result.map(Self::Rounding));
        }
        // Published integer DOT/CDOT remain owned by the generic SVE decoder.
        dot::decode(word).and_then(|result| {
            result.ok().and_then(|operand| {
                matches!(
                    operand.kind,
                    dot::Kind::HalfDot | dot::Kind::HalfMultiplyLong { .. }
                )
                .then_some(Ok(Self::Dot(operand)))
            })
        })
    }

    pub const fn requires_numerical_completion(self) -> bool {
        true
    }
}
