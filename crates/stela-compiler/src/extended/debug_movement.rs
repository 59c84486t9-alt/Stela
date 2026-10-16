//! MOVT (vector to ZT0) prepared for execution from the halted-debug ITR.
use super::{MOV_R15_RSI, POP_R15, PUSH_R15, RET, ScalableProfile};
use crate::{
    CompileError, GuestAddress,
    aarch64::{
        scalable::{
            execution::{
                GuestMemoryQuantity, InstructionExecutionRequirements, ScalableAccessCheck,
                ScalableAccessRequirements, ScalableExecutionRequirements,
            },
            features::{FeatureRequirement, ScalableFeature, ScalableFeatures},
        },
        sme::movement::{self, Direction, Kind, Operand},
    },
    context::CONTEXT_LEAF_ABI,
    x86_64,
};
use alloc::vec;
use alloc::vec::Vec;

/// Address passed to the scalable checker for diagnostics only; zero means the
/// word was not fetched.
const EXTERNAL_WORD_ANCHOR: GuestAddress = GuestAddress(0);
const EXTERNAL_WORD_ORDINAL: usize = 0;
const ZERO_REGISTER: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipe {
    Scalar,
    Sse2Comparison,
}

/// Both recipes use the x86-64 integer/SSE2 baseline. The comparison recipe is
/// retained for measured selection; choosing it changes no guest requirements.
pub struct PreparedDebugMovement {
    word: u32,
    operand: Operand,
    profile: ScalableProfile,
    recipe: Recipe,
    code: Vec<u8>,
    word_to_native: [(usize, usize); 1],
    requirements: ScalableExecutionRequirements,
}
impl PreparedDebugMovement {
    pub const fn word(&self) -> u32 {
        self.word
    }
    pub const fn operand(&self) -> Operand {
        self.operand
    }
    pub const fn profile(&self) -> ScalableProfile {
        self.profile
    }
    pub const fn recipe(&self) -> Recipe {
        self.recipe
    }
    pub const fn abi(&self) -> &'static str {
        CONTEXT_LEAF_ABI
    }
    pub fn code(&self) -> &[u8] {
        &self.code
    }
    /// External source word ordinal -> native byte offset, never guest PC.
    pub const fn word_to_native(&self) -> &[(usize, usize); 1] {
        &self.word_to_native
    }
    pub const fn execution_requirements(&self) -> &ScalableExecutionRequirements {
        &self.requirements
    }
}

pub fn prepare(
    word: u32,
    profile: ScalableProfile,
    recipe: Recipe,
) -> Result<PreparedDebugMovement, CompileError> {
    let operand = movement::decode(word)
        .ok_or_else(|| CompileError("not an allocated movement instruction".into()))?;
    let Kind::TableGpr {
        direction,
        register,
        ..
    } = operand.kind
    else {
        return Err(CompileError(
            "debug movement accepts only the two MOVT GPR/ZT0 forms".into(),
        ));
    };
    let feature = FeatureRequirement::all(
        ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2),
    );
    profile.require_features(feature, EXTERNAL_WORD_ANCHOR)?;
    if !profile.mode().za_enabled() || !profile.controls().zt0_enabled() {
        return Err(CompileError(
            "halted MOVT specialization requires active ZA and enabled ZT0".into(),
        ));
    }
    let requirements =
        ScalableExecutionRequirements::new(vec![InstructionExecutionRequirements::new(
            EXTERNAL_WORD_ANCHOR,
            vec![feature],
            ScalableAccessRequirements::Known(
                vec![
                    ScalableAccessCheck::SmeEnabled,
                    ScalableAccessCheck::SmeZt0Enabled,
                ]
                .into_boxed_slice(),
            ),
            GuestMemoryQuantity::None,
        )]);
    let mut code = Vec::new();
    let discarded = direction == Direction::FromZa && register == ZERO_REGISTER;
    if !discarded {
        code.extend(PUSH_R15);
        code.extend(MOV_R15_RSI);
    }
    let native_offset = code.len();
    x86_64::sme::movement::emit_debug_table_gpr(&mut code, &operand, recipe)
        .map_err(|error| CompileError(error.into()))?;
    if !discarded {
        code.extend(POP_R15);
    }
    code.push(RET);
    Ok(PreparedDebugMovement {
        word,
        operand,
        profile,
        recipe,
        code,
        word_to_native: [(EXTERNAL_WORD_ORDINAL, native_offset)],
        requirements,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::scalable::{ScalableMode, VectorLength};
    use alloc::vec;
    const FROM_ZT0: u32 = 0xc04c03e0;
    const TO_ZT0: u32 = 0xc04e03e0;
    fn profile(streaming: bool) -> ScalableProfile {
        let length = VectorLength::from_bytes(16).unwrap();
        ScalableProfile::new_with_features(
            length,
            ScalableMode::new(streaming, true),
            ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2),
            crate::aarch64::scalable::profile::ScalableControls::new(length, true),
        )
        .unwrap()
    }
    #[test]
    fn both_modes_keep_literal_access_obligations_even_for_discarded_read() {
        for streaming in [false, true] {
            for word in [FROM_ZT0 | 31, TO_ZT0 | 31] {
                let output = prepare(word, profile(streaming), Recipe::Scalar).unwrap();
                let instruction = &output.execution_requirements().instructions()[0];
                assert_eq!(
                    instruction.access(),
                    &ScalableAccessRequirements::Known(
                        vec![
                            ScalableAccessCheck::SmeEnabled,
                            ScalableAccessCheck::SmeZt0Enabled
                        ]
                        .into_boxed_slice()
                    )
                );
                assert_eq!(
                    instruction.guest_memory_quantity(),
                    GuestMemoryQuantity::None
                );
                assert_eq!(output.word(), word);
                assert_eq!(output.word_to_native()[0].0, EXTERNAL_WORD_ORDINAL);
            }
        }
    }
    #[test]
    fn discarded_read_emits_only_transport_return_after_runtime_checks() {
        for recipe in [Recipe::Scalar, Recipe::Sse2Comparison] {
            let output = prepare(FROM_ZT0 | 31, profile(false), recipe).unwrap();
            assert_eq!(output.code(), &[RET]);
        }
    }
    #[test]
    fn all_lane_endpoints_preserve_shared_decoder_identity() {
        for base in [FROM_ZT0, TO_ZT0] {
            for lane in 0..8 {
                for register in [0, 30, 31] {
                    let word = base | (lane << 12) | register;
                    let output = prepare(word, profile(true), Recipe::Scalar).unwrap();
                    assert_eq!(output.operand(), movement::decode(word).unwrap());
                }
            }
        }
    }
    #[test]
    fn non_debug_forms_and_inactive_za_decline() {
        assert!(prepare(0xd503201f, profile(true), Recipe::Scalar).is_err());
        let length = VectorLength::from_bytes(16).unwrap();
        let no_za = ScalableProfile::new_with_features(
            length,
            ScalableMode::new(true, false),
            ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2),
            crate::aarch64::scalable::profile::ScalableControls::new(length, true),
        )
        .unwrap();
        assert!(prepare(FROM_ZT0, no_za, Recipe::Scalar).is_err());
    }
}
