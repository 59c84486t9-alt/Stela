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
        let native = super::super::super::compile_for_profile(
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
