//! MOVPRFX pairs compiled as one unit with their follower.
use crate::aarch64::Unsupported;

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
        .map_err(|Unsupported| CompileError("MOVPRFX follower source/operand mismatch".into()))?
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
mod tests {
    use super::*;
    use crate::aarch64::scalable::{ScalableMode, VectorLength};
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    mod dispatcher {
        use super::super::super::decode;
        use super::*;
        use crate::aarch64::{
            scalable::{ScalableMode, VectorLength},
            sve::prefix::PrefixRequirement,
        };
        use alloc::vec::Vec;

        const BASE: GuestAddress = GuestAddress(0x1000);
        const PREFIX: u32 = 0x0420_bc20;
        const ABS_MERGING: u32 = 0x0416_a040;
        const EXT_DESTRUCTIVE: u32 = 0x0520_0040;
        const CLASTA_VECTOR: u32 = 0x0528_8040;
        const INTEGER_DOT: u32 = 0x4482_0020;
        const AND_DESTRUCTIVE: u32 = 0x041a_0040;
        const RET: u32 = 0xd65f_03c0;
        const BRANCH_TO_FOLLOWER: u32 = 0x1400_0002;

        fn profile(bytes: usize) -> ScalableProfile {
            ScalableProfile::new(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::new(true, false),
            )
        }

        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }

        #[test]
        fn central_metadata_rechecks_original_words_across_audited_families() {
            for word in [ABS_MERGING, EXT_DESTRUCTIVE, CLASTA_VECTOR] {
                let operand = decode(BASE, word, profile(16), TargetCpu::Baseline).unwrap();
                assert!(operand.require_total_inline_prefix(BASE).is_ok());
                assert!(matches!(
                    operand.prefix_requirement(word),
                    Ok(Some(PrefixRequirement::Vector { .. }))
                ));
                assert!(operand.prefix_requirement(word ^ 1).is_err());
                let pair = decode_pair(
                    &source(&[PREFIX, word, RET]),
                    0,
                    BASE,
                    profile(16),
                    TargetCpu::Baseline,
                )
                .unwrap()
                .expect("reviewed total inline pair");
                assert_eq!(
                    pair.follower_pc,
                    GuestAddress(BASE.0 + INSTRUCTION_BYTES as u64)
                );
            }
        }

        #[test]
        fn unaudited_ordinary_and_dot_variants_cannot_authorize_prefix_effects() {
            for word in [RET, INTEGER_DOT] {
                let operand = decode(BASE, word, profile(16), TargetCpu::Baseline).unwrap();
                assert!(operand.require_total_inline_prefix(BASE).is_err());
                assert_eq!(operand.prefix_requirement(word), Ok(None));
                assert!(
                    decode_pair(
                        &source(&[PREFIX, word, RET]),
                        0,
                        BASE,
                        profile(16),
                        TargetCpu::Baseline,
                    )
                    .is_err()
                );
            }
        }

        #[test]
        fn direct_follower_targets_retain_the_follower_map_entry() {
            for bytes in [16, 32, 64, 128, 256] {
                let native = crate::testing::context_leaf(
                    &source(&[BRANCH_TO_FOLLOWER, PREFIX, AND_DESTRUCTIVE, RET]),
                    BASE,
                    profile(bytes),
                    TargetCpu::Baseline,
                )
                .unwrap();
                assert_eq!(native.source_map.len(), 4);
                assert_eq!(
                    native.source_map[2].0,
                    GuestAddress(BASE.0 + PAIR_BYTES as u64)
                );
                assert!(
                    native
                        .source_map
                        .windows(2)
                        .all(|pair| pair[0].1 < pair[1].1)
                );
            }
        }
    }
    mod window_boundary {
        use super::*;
        use crate::aarch64::scalable::{ScalableMode, VectorLength};
        use alloc::string::ToString;
        use alloc::vec::Vec;

        const BASE: GuestAddress = GuestAddress(0x1000);
        const NOP: u32 = 0xd503_201f;
        const PREFIX: u32 = 0x0420_bc20;
        const AND: u32 = 0x041a_0040;
        const SVC: u32 = 0xd400_2461;

        fn profile() -> ScalableProfile {
            ScalableProfile::new(
                VectorLength::from_bytes(16).unwrap(),
                ScalableMode::new(true, false),
            )
        }

        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }

        #[test]
        fn complete_pair_in_final_two_source_slots_is_distinct_from_missing_follower() {
            let complete = source(&[NOP, PREFIX, AND]);
            let pair = decode_pair(
                &complete,
                INSTRUCTION_BYTES,
                BASE,
                profile(),
                TargetCpu::Baseline,
            )
            .unwrap()
            .expect("complete final pair");
            assert_eq!(pair.follower_pc, GuestAddress(BASE.0 + PAIR_BYTES as u64));
            let missing = source(&[NOP, PREFIX]);
            let error = match decode_pair(
                &missing,
                INSTRUCTION_BYTES,
                BASE,
                profile(),
                TargetCpu::Baseline,
            ) {
                Err(error) => error,
                Ok(_) => panic!("missing follower accepted"),
            };
            assert!(error.to_string().contains("follower missing"));
        }

        #[test]
        fn service_after_completed_pair_is_not_admitted_as_pair_follower() {
            assert!(
                decode_pair(
                    &source(&[PREFIX, AND, SVC]),
                    0,
                    BASE,
                    profile(),
                    TargetCpu::Baseline
                )
                .unwrap()
                .is_some()
            );
            let error = match decode_pair(
                &source(&[PREFIX, SVC]),
                0,
                BASE,
                profile(),
                TargetCpu::Baseline,
            ) {
                Err(error) => error,
                Ok(_) => panic!("service follower accepted"),
            };
            assert!(error.to_string().contains("unsupported follower"));
        }
    }

    const BASE: GuestAddress = GuestAddress(0x1000);
    const UNPREDICATED_PREFIX: u32 = 0x0420_bc20;
    const ZEROING_PREFIX: u32 = 0x0410_2020;
    const MERGING_PREFIX: u32 = 0x0411_2020;
    const AND_DESTRUCTIVE: u32 = 0x041a_0040;
    const AND_CONSTRUCTIVE: u32 = 0x0420_3040;
    const SDOT: u32 = 0x4482_0020;
    const RET: u32 = 0xd65f_03c0;

    fn source(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn profile() -> ScalableProfile {
        ScalableProfile::new(
            VectorLength::from_bytes(16).unwrap(),
            ScalableMode::new(true, false),
        )
    }

    #[test]
    fn valid_total_pairs_preserve_adjacent_original_pc_and_operands() {
        for prefix in [UNPREDICATED_PREFIX, ZEROING_PREFIX, MERGING_PREFIX] {
            let bytes = source(&[RET, prefix, AND_DESTRUCTIVE, RET]);
            let pair = decode_pair(
                &bytes,
                INSTRUCTION_BYTES,
                BASE,
                profile(),
                TargetCpu::Baseline,
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                pair.prefix_pc,
                GuestAddress(BASE.0 + INSTRUCTION_BYTES as u64)
            );
            assert_eq!(pair.follower_pc, GuestAddress(BASE.0 + PAIR_BYTES as u64));
            assert_eq!(pair.prefix, integer_logic::decode(prefix).unwrap().unwrap());
            let Decoded::IntegerLogic(follower) = pair.follower else {
                panic!("logic pair decoded as another family");
            };
            assert_eq!(
                follower,
                integer_logic::decode(AND_DESTRUCTIVE).unwrap().unwrap()
            );
        }
    }

    #[test]
    fn missing_unsupported_and_known_invalid_pairs_decline_distinctly() {
        for (words, expected) in [
            (vec![UNPREDICATED_PREFIX], "follower missing"),
            (
                vec![UNPREDICATED_PREFIX, SDOT],
                "requirements are not reviewed",
            ),
            (
                vec![UNPREDICATED_PREFIX, AND_CONSTRUCTIVE],
                "FollowerNotAuthorized",
            ),
            (vec![UNPREDICATED_PREFIX, MERGING_PREFIX], "another prefix"),
        ] {
            let bytes = source(&words);
            let error = match decode_pair(&bytes, 0, BASE, profile(), TargetCpu::Baseline) {
                Err(error) => error,
                Ok(_) => panic!("unqualified pair was accepted"),
            };
            assert!(error.to_string().contains(expected), "{error}");
        }
    }
}
