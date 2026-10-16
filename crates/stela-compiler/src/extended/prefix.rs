//! MOVPRFX pairs compiled as one unit with their follower.

use super::{Decoded, INSTRUCTION_BYTES, ScalableProfile, decode_recording_features};
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        scalable::{
            Predication,
            features::{FeatureRequirement, ScalableFeature, ScalableFeatures},
        },
        sve::{
            integer_logic,
            prefix::{self, DecodedPrefix},
        },
    },
};
use alloc::format;
use alloc::vec::Vec;

pub(super) const PAIR_INSTRUCTIONS: usize = 2;
pub(super) const PAIR_BYTES: usize = PAIR_INSTRUCTIONS * INSTRUCTION_BYTES;

pub(super) struct Pair {
    pub prefix_pc: GuestAddress,
    pub follower_pc: GuestAddress,
    pub prefix: integer_logic::Operand,
    pub follower: Decoded,
    pub prefix_features: FeatureRequirement,
    pub follower_features: Vec<FeatureRequirement>,
}

/// Returns None for an instruction that is not MOVPRFX. A prefix needs both
/// words from the source window, and until restart support exists only
/// register-only followers may run.
pub(super) fn decode_pair(
    source: &[u8],
    offset: usize,
    base: GuestAddress,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<Option<Pair>, CompileError> {
    let end = offset
        .checked_add(INSTRUCTION_BYTES)
        .ok_or_else(|| CompileError("MOVPRFX source offset overflow".into()))?;
    let word = u32::from_le_bytes(
        source
            .get(offset..end)
            .ok_or_else(|| CompileError("incomplete source instruction".into()))?
            .try_into()
            .expect("checked instruction size"),
    );
    let Some(operand) = integer_logic::decode_prefix(word) else {
        return Ok(None);
    };
    let prefix_pc = GuestAddress(
        base.0
            .checked_add(
                u64::try_from(offset)
                    .map_err(|_| CompileError("MOVPRFX source offset overflow".into()))?,
            )
            .ok_or_else(|| CompileError("MOVPRFX source PC overflow".into()))?,
    );
    if !prefix_pc.0.is_multiple_of(INSTRUCTION_BYTES as u64) {
        return Err(CompileError("MOVPRFX PC must be aligned".into()));
    }
    if !profile.mode().streaming() {
        return Err(CompileError(format!(
            "streaming mode required at {:#x}",
            prefix_pc.0
        )));
    }
    let prefix_features = FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme));
    profile.require_features(prefix_features, prefix_pc)?;
    let pair_end = offset
        .checked_add(PAIR_BYTES)
        .ok_or_else(|| CompileError("MOVPRFX pair source extent overflow".into()))?;
    let follower_word = u32::from_le_bytes(
        source
            .get(end..pair_end)
            .ok_or_else(|| {
                CompileError(format!(
                    "MOVPRFX pair validation: follower missing from source window at {:#x}",
                    prefix_pc.0
                ))
            })?
            .try_into()
            .expect("checked follower size"),
    );
    let follower_pc = GuestAddress(
        prefix_pc
            .0
            .checked_add(INSTRUCTION_BYTES as u64)
            .ok_or_else(|| CompileError("MOVPRFX follower PC overflow".into()))?,
    );
    if integer_logic::decode_prefix(follower_word).is_some() {
        return Err(CompileError(format!(
            "MOVPRFX pair validation: follower is another prefix at {:#x}",
            follower_pc.0
        )));
    }
    // Keep unsupported allocation/features/semantics distinct from a known
    // decoded pairing violation. Existing decode errors stay compiler declines.
    let mut follower_features = Vec::new();
    let follower = decode_recording_features(
        follower_pc,
        follower_word,
        profile,
        target,
        &mut follower_features,
    )
    .map_err(|error| {
        CompileError(format!(
            "MOVPRFX pair validation: unsupported follower at {:#x}: {error}",
            follower_pc.0
        ))
    })?;
    follower.require_total_inline_prefix(follower_pc)?;
    let requirement = follower
        .prefix_requirement(follower_word)
        .map_err(|()| CompileError("MOVPRFX follower source/operand mismatch".into()))?
        .ok_or_else(|| {
            CompileError(format!(
                "MOVPRFX pair validation: follower metadata not reviewed at {:#x}",
                follower_pc.0
            ))
        })?;
    let integer_logic::Kind::Copy(integer_logic::CopySource::Vector(source_register)) =
        operand.kind
    else {
        unreachable!("decode_prefix returns only canonical MOVPRFX forms")
    };
    let decoded_prefix = DecodedPrefix {
        destination: operand.destination,
        source: source_register,
        predication: operand.predication,
        element: match operand.predication {
            Predication::Unpredicated => None,
            Predication::Merging(_) | Predication::Zeroing(_) => Some(operand.element_size),
        },
    };
    prefix::validate(decoded_prefix, requirement).map_err(|violation| {
        CompileError(format!(
            "MOVPRFX pair validation failed: reviewed requirement violation at {:#x}: {violation:?}",
            prefix_pc.0
        ))
    })?;
    Ok(Some(Pair {
        prefix_pc,
        follower_pc,
        prefix: operand,
        follower,
        prefix_features,
        follower_features,
    }))
}

#[cfg(test)]
mod tests;
