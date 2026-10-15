//! Reviewed SVE numerical groups share one source-admitted completion boundary.

pub mod arithmetic;
pub mod comparison;
pub mod control;
pub mod conversion;

use crate::aarch64::{
    floating::features::NumericalFeatures,
    scalable::features::{FeatureRequirement, ScalableFeature, ScalableFeatures},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Arithmetic(arithmetic::Operand),
    Comparison(comparison::Operand),
    Conversion(conversion::Operand),
}

impl Operation {
    /// All 22 selected forms use the SME-derived streaming availability branch.
    pub fn required_streaming_features(self, _numerical: NumericalFeatures) -> FeatureRequirement {
        FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme))
    }

    #[allow(clippy::result_unit_err)]
    pub fn decode(word: u32) -> Option<Result<Self, ()>> {
        arithmetic::decode_core_binary(word)
            .map(|value| value.map(Self::Arithmetic))
            .or_else(|| comparison::decode(word).map(|value| value.map(Self::Comparison)))
            .or_else(|| conversion::decode(word).map(|value| value.map(Self::Conversion)))
    }

    pub const fn requires_numerical_completion(self) -> bool {
        true
    }
}
