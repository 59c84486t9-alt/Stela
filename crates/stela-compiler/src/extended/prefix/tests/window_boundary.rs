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
