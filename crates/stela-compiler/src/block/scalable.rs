//! Typed scalable numerical service boundaries over immutable guest source.
//! Decoding describes operands; it grants no guest feature or mode permission.

use crate::{
    CompileError, GuestAddress,
    aarch64::{
        floating::features::NumericalFeatures,
        scalable::features::{FeatureRequirement, ScalableFeature},
        sve::floating,
    },
    extended::ScalableProfile,
};

const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalableNumericalOperation {
    Sve(floating::Operation),
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
        match self {
            Self::Sve(operation) => operation.required_streaming_features(numerical_features),
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
    let mode = profile.mode();
    if !mode.streaming() {
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
    let operation = if let Some(result) = floating::Operation::decode(word) {
        let operand =
            result.map_err(|()| CompileError("reserved scalable numerical encoding".into()))?;
        if !operand.requires_numerical_completion() {
            return Ok(None);
        }
        ScalableNumericalOperation::Sve(operand)
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
mod tests {
    use super::*;

    const FADD_Z0_S_P0_Z0_Z0: u32 = 0x6580_8000;
    const NOP: u32 = 0xd503_201f;

    #[test]
    fn numerical_boundary_keeps_exact_source_identity() {
        let pc = GuestAddress(0x1000);
        let instruction = decode_scalable_numerical_instruction(pc, FADD_Z0_S_P0_Z0_Z0)
            .unwrap()
            .expect("allocated floating add");
        assert_eq!(instruction.instruction_pc, pc);
        assert_eq!(instruction.next_pc, GuestAddress(0x1004));
        assert_eq!(instruction.word, FADD_Z0_S_P0_Z0_Z0);
        assert!(matches!(
            instruction.operation,
            ScalableNumericalOperation::Sve(_)
        ));
        assert!(
            decode_scalable_numerical_instruction(pc, NOP)
                .unwrap()
                .is_none()
        );
        assert!(decode_scalable_numerical_instruction(GuestAddress(2), NOP).is_err());
        assert!(
            decode_scalable_numerical_instruction(GuestAddress(u64::MAX - 3), FADD_Z0_S_P0_Z0_Z0)
                .is_err()
        );
    }
}

#[cfg(test)]
mod numerical22_scope_tests;
