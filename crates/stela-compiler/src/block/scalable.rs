//! Scalable numerical instructions that exit to a runtime service.

use crate::{
    CompileError, GuestAddress,
    aarch64::{
        floating::{Format, features::NumericalFeatures},
        scalable::features::{FeatureRequirement, ScalableFeature, ScalableFeatures},
        simd::fp8_conversion as fixed_fp8_conversion,
        sme::{extrema_scale, fp_matrix, fp_vector, fp8_conversion, fp8_matrix},
        sve::floating,
    },
    extended::ScalableProfile,
};
use alloc::format;

const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalableNumericalOperation {
    Sve(floating::Operation),
    FixedFp8Conversion(fixed_fp8_conversion::Operand),
    SmeFp8Conversion(fp8_conversion::Operand),
    SmeFp8Matrix(fp8_matrix::Operand),
    SmeExtremaScale(extrema_scale::Operand),
    SmeVector(fp_vector::Operand),
    SmeMatrix(fp_matrix::Operand),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalableNumericalInstruction {
    pub operation: ScalableNumericalOperation,
    pub instruction_pc: GuestAddress,
    pub next_pc: GuestAddress,
    pub word: u32,
}

/// A source-consistent numerical request admitted by an immutable streaming
/// profile. Runtime completion must additionally recover the registered source
/// word and match the current owned state to this exact profile before entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedScalableNumericalInstruction {
    instruction: ScalableNumericalInstruction,
    profile: ScalableProfile,
    numerical_features: NumericalFeatures,
}

impl AdmittedScalableNumericalInstruction {
    pub const fn operation(&self) -> &ScalableNumericalOperation {
        &self.instruction.operation
    }

    pub const fn profile(self) -> ScalableProfile {
        self.profile
    }
    pub const fn numerical_features(self) -> NumericalFeatures {
        self.numerical_features
    }
    pub const fn instruction_pc(self) -> GuestAddress {
        self.instruction.instruction_pc
    }
    pub const fn next_pc(self) -> GuestAddress {
        self.instruction.next_pc
    }
    pub const fn word(self) -> u32 {
        self.instruction.word
    }
}

impl ScalableNumericalOperation {
    /// This profile declares SME-derived streaming execution, with no ordinary
    /// FEAT_SVE availability. General normal-SVE alternatives are not implied.
    pub fn required_streaming_features(
        self,
        numerical_features: NumericalFeatures,
    ) -> FeatureRequirement {
        use ScalableFeature as Feature;
        let sme = ScalableFeatures::of(Feature::Sme);
        let sme2 = sme.with(Feature::Sme2);
        match self {
            Self::Sve(operation) => operation.required_streaming_features(numerical_features),
            Self::SmeExtremaScale(operand) => {
                FeatureRequirement::all(sme2.with(match operand.kind {
                    extrema_scale::Kind::AbsoluteMinMax(_) => Feature::FaMinMax,
                    extrema_scale::Kind::Scale => Feature::Fp8,
                }))
            }
            Self::FixedFp8Conversion(_) => {
                FeatureRequirement::all(ScalableFeatures::of(Feature::Fp8).with(Feature::Fpmr))
            }
            Self::SmeFp8Conversion(_) => {
                FeatureRequirement::all(sme2.with(Feature::Fp8).with(Feature::Fpmr))
            }
            Self::SmeFp8Matrix(operand) => {
                let accumulator = match operand {
                    fp8_matrix::Operand::Vector(operand) => operand.accumulator,
                    fp8_matrix::Operand::Outer(operand) => operand.accumulator,
                };
                let feature = match accumulator {
                    Format::Half => Feature::SmeF8F16,
                    Format::Single => Feature::SmeF8F32,
                    Format::Double => unreachable!("FP8 matrix decoder allocates Half and Single"),
                };
                FeatureRequirement::all(sme.with(feature).with(Feature::Fpmr))
            }
            Self::SmeVector(operand) => FeatureRequirement::all(match operand.feature {
                fp_vector::Feature::Sme2 => sme2,
                fp_vector::Feature::Sme2SveB16B16 => sme2.with(Feature::SveB16B16),
                fp_vector::Feature::SmeF16F16 => sme.with(Feature::SmeF16F16),
            }),
            Self::SmeMatrix(operand) => match operand.required_feature() {
                fp_matrix::RequiredFeature::Sme => FeatureRequirement::all(sme),
                fp_matrix::RequiredFeature::Sme2 => FeatureRequirement::all(sme2),
                fp_matrix::RequiredFeature::F16F16 => {
                    FeatureRequirement::all(sme.with(Feature::SmeF16F16))
                }
                fp_matrix::RequiredFeature::F64F64 => {
                    FeatureRequirement::all(sme.with(Feature::SmeF64F64))
                }
                fp_matrix::RequiredFeature::B16B16 => {
                    FeatureRequirement::all(sme.with(Feature::SmeB16B16))
                }
                fp_matrix::RequiredFeature::F16F16OrF8F16 => FeatureRequirement::all_and_any(
                    sme,
                    ScalableFeatures::of(Feature::SmeF16F16).with(Feature::SmeF8F16),
                ),
                fp_matrix::RequiredFeature::Sme2AndF64F64 => {
                    FeatureRequirement::all(sme2.with(Feature::SmeF64F64))
                }
            },
        }
    }
}

/// Validate decoded metadata rather than trusting an independently constructed
/// operand. No permission is inferred from opcode allocation or host features.
pub fn admit_scalable_numerical_instruction(
    instruction: ScalableNumericalInstruction,
    profile: ScalableProfile,
    numerical_features: NumericalFeatures,
) -> Result<AdmittedScalableNumericalInstruction, CompileError> {
    if decode_scalable_numerical_instruction(instruction.instruction_pc, instruction.word)?
        != Some(instruction)
    {
        return Err(CompileError(
            "scalable numerical source/descriptor mismatch".into(),
        ));
    }
    if matches!(
        instruction.operation,
        ScalableNumericalOperation::FixedFp8Conversion(_)
            | ScalableNumericalOperation::SmeFp8Conversion(_)
            | ScalableNumericalOperation::Sve(floating::Operation::Fp8(_))
            | ScalableNumericalOperation::SmeFp8Matrix(_)
    ) && !profile.controls().fpmr_enabled()
    {
        return Err(CompileError(
            "indirect FPMR access is not enabled in the declared guest profile".into(),
        ));
    }
    let mode = profile.mode();
    let fixed = matches!(
        instruction.operation,
        ScalableNumericalOperation::FixedFp8Conversion(_)
    );
    if (if fixed {
        mode.streaming() && !numerical_features.full_a64()
    } else {
        !mode.streaming()
    }) || (matches!(
        instruction.operation,
        ScalableNumericalOperation::SmeMatrix(_) | ScalableNumericalOperation::SmeFp8Matrix(_)
    ) && !mode.za_enabled())
    {
        return Err(CompileError(format!(
            "scalable numerical mode unavailable at {:#x}",
            instruction.instruction_pc.0
        )));
    }
    if numerical_features.full_a64() && !profile.features().contains(ScalableFeature::SmeFa64) {
        return Err(CompileError(
            "effective FullA64 requires declared FEAT_SME_FA64".into(),
        ));
    }
    profile.require_features(
        instruction
            .operation
            .required_streaming_features(numerical_features),
        instruction.instruction_pc,
    )?;
    Ok(AdmittedScalableNumericalInstruction {
        instruction,
        profile,
        numerical_features,
    })
}

/// A numerical exit identifies the still-unexecuted instruction, including an
/// interior slow path. The runtime must re-fetch this word from registered
/// immutable source before completing its effects and advancing to next_pc.
pub fn decode_scalable_numerical_instruction(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<ScalableNumericalInstruction>, CompileError> {
    if !pc.0.is_multiple_of(INSTRUCTION_BYTES) {
        return Err(CompileError(
            "scalable numerical PC must be aligned to 4 bytes".into(),
        ));
    }
    let operation = if let Some(operand) = fixed_fp8_conversion::decode(word) {
        ScalableNumericalOperation::FixedFp8Conversion(operand)
    } else if let Some(operand) = fp8_conversion::decode(word) {
        ScalableNumericalOperation::SmeFp8Conversion(operand)
    } else if let Some(operand) = fp8_matrix::decode(word) {
        ScalableNumericalOperation::SmeFp8Matrix(operand)
    } else if let Some(operand) = extrema_scale::decode(word) {
        ScalableNumericalOperation::SmeExtremaScale(operand)
    } else if let Some(result) = floating::Operation::decode(word) {
        let operand =
            result.map_err(|()| CompileError("reserved scalable numerical encoding".into()))?;
        if !operand.requires_numerical_completion() {
            return Ok(None);
        }
        ScalableNumericalOperation::Sve(operand)
    } else if let Some(operand) = fp_vector::decode(word) {
        ScalableNumericalOperation::SmeVector(operand)
    } else if let Some(operand) = fp_matrix::decode(word) {
        ScalableNumericalOperation::SmeMatrix(operand)
    } else {
        return Ok(None);
    };
    let next_pc = GuestAddress(
        pc.0.checked_add(INSTRUCTION_BYTES)
            .ok_or_else(|| CompileError("scalable numerical continuation overflow".into()))?,
    );
    Ok(Some(ScalableNumericalInstruction {
        operation,
        instruction_pc: pc,
        next_pc,
        word,
    }))
}

#[cfg(test)]
mod tests;
