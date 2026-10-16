//! Guest SVE/SME feature sets. Construction keeps declarations as given and does
//! not infer dependencies.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScalableFeature {
    Sme,
    Sme2,
    Sme2p1,
    SmeFa64,
    SmeF64F64,
    SmeI16I64,
    SmeB16B16,
    SmeF16F16,
    SmeF8F16,
    SveB16B16,
    Bf16,
    I8mm,
    FaMinMax,
    Fp8,
    Fpmr,
    SmeF8F32,
    SmeLutV2,
    Lut,
}

// Architectural-name order also defines deterministic manifest output.
const FEATURES_BY_NAME: &[ScalableFeature] = &[
    ScalableFeature::Bf16,
    ScalableFeature::FaMinMax,
    ScalableFeature::Fp8,
    ScalableFeature::Fpmr,
    ScalableFeature::I8mm,
    ScalableFeature::Lut,
    ScalableFeature::Sme,
    ScalableFeature::Sme2,
    ScalableFeature::Sme2p1,
    ScalableFeature::SmeB16B16,
    ScalableFeature::SmeF16F16,
    ScalableFeature::SmeF64F64,
    ScalableFeature::SmeF8F16,
    ScalableFeature::SmeF8F32,
    ScalableFeature::SmeFa64,
    ScalableFeature::SmeI16I64,
    ScalableFeature::SmeLutV2,
    ScalableFeature::SveB16B16,
];

impl ScalableFeature {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sme => "FEAT_SME",
            Self::Sme2 => "FEAT_SME2",
            Self::Sme2p1 => "FEAT_SME2p1",
            Self::SmeFa64 => "FEAT_SME_FA64",
            Self::SmeF64F64 => "FEAT_SME_F64F64",
            Self::SmeI16I64 => "FEAT_SME_I16I64",
            Self::SmeB16B16 => "FEAT_SME_B16B16",
            Self::SmeF16F16 => "FEAT_SME_F16F16",
            Self::SmeF8F16 => "FEAT_SME_F8F16",
            Self::SveB16B16 => "FEAT_SVE_B16B16",
            Self::Bf16 => "FEAT_BF16",
            Self::I8mm => "FEAT_I8MM",
            Self::FaMinMax => "FEAT_FAMINMAX",
            Self::Fp8 => "FEAT_FP8",
            Self::Fpmr => "FEAT_FPMR",
            Self::SmeF8F32 => "FEAT_SME_F8F32",
            Self::SmeLutV2 => "FEAT_SME_LUTv2",
            Self::Lut => "FEAT_LUT",
        }
    }

    const fn mask(self) -> u64 {
        1 << self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureNameError {
    Unknown(String),
    Duplicate(ScalableFeature),
}

impl fmt::Display for FeatureNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(name) => write!(formatter, "unknown scalable feature {name:?}"),
            Self::Duplicate(feature) => {
                write!(formatter, "duplicate scalable feature {}", feature.name())
            }
        }
    }
}

impl core::error::Error for FeatureNameError {}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScalableFeatures(u64);

impl ScalableFeatures {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn of(feature: ScalableFeature) -> Self {
        Self(feature.mask())
    }

    pub const fn with(self, feature: ScalableFeature) -> Self {
        self.union(Self::of(feature))
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, feature: ScalableFeature) -> bool {
        self.contains_all(Self::of(feature))
    }

    pub const fn contains_all(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub fn names(self) -> Vec<&'static str> {
        FEATURES_BY_NAME
            .iter()
            .copied()
            .filter(|&feature| self.contains(feature))
            .map(ScalableFeature::name)
            .collect()
    }

    /// Strict manifest parsing: misspellings and duplicate declarations decline.
    pub fn checked_from_names<'a>(
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, FeatureNameError> {
        let mut result = Self::empty();
        for name in names {
            let feature = FEATURES_BY_NAME
                .iter()
                .copied()
                .find(|&feature| feature.name() == name)
                .ok_or_else(|| FeatureNameError::Unknown(name.into()))?;
            if result.contains(feature) {
                return Err(FeatureNameError::Duplicate(feature));
            }
            result = result.with(feature);
        }
        Ok(result)
    }
}

/// A conjunction of required features and, when nonempty, one disjunction.
/// The empty requirement succeeds; an empty `any` set adds no condition.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeatureRequirement {
    all: ScalableFeatures,
    any: ScalableFeatures,
}

impl FeatureRequirement {
    pub const fn all(features: ScalableFeatures) -> Self {
        Self::all_and_any(features, ScalableFeatures::empty())
    }

    pub const fn any(features: ScalableFeatures) -> Self {
        Self::all_and_any(ScalableFeatures::empty(), features)
    }

    pub const fn all_and_any(all: ScalableFeatures, any: ScalableFeatures) -> Self {
        Self { all, any }
    }

    pub const fn all_features(self) -> ScalableFeatures {
        self.all
    }

    pub const fn any_features(self) -> ScalableFeatures {
        self.any
    }

    pub const fn is_satisfied_by(self, features: ScalableFeatures) -> bool {
        features.contains_all(self.all) && (self.any.0 == 0 || features.0 & self.any.0 != 0)
    }
}

#[cfg(test)]
mod tests;
