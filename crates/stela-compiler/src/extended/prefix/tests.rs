use super::*;
use crate::aarch64::scalable::{ScalableMode, VectorLength};
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

mod dispatcher;
mod window_boundary;

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
