use super::*;
use crate::aarch64::sve::integer_comparison::decode;

#[test]
fn checked_pair_selection_requires_the_comparison_feature() {
    let half_equal = decode(0x2440_2020).unwrap().unwrap();
    let half_greater = decode(0x2440_4030).unwrap().unwrap();
    let word_greater = decode(0x2480_4030).unwrap().unwrap();
    let short = VectorLength::from_bytes(16).unwrap();
    assert_eq!(
        recipe(half_equal, short, TargetCpu::Baseline),
        Recipe::BaselinePairs
    );
    assert_eq!(
        recipe(half_equal, short, TargetCpu::Sse41),
        Recipe::CheckedPairs
    );
    assert_eq!(recipe(half_greater, short, TargetCpu::Sse41), Recipe::Range);
    assert_eq!(
        recipe(half_greater, short, TargetCpu::Sse42),
        Recipe::CheckedPairs
    );
    assert_eq!(
        recipe(word_greater, short, TargetCpu::Sse41),
        Recipe::BaselinePairs
    );
    assert_eq!(
        recipe(word_greater, short, TargetCpu::Sse42),
        Recipe::CheckedPairs
    );
}

#[test]
fn long_mapping_keeps_measured_unsigned_word_less_latency_choice() {
    let word_hi = decode(0x2480_c030).unwrap().unwrap();
    let word_lo = decode(0x2480_e020).unwrap().unwrap();
    let half_equal = decode(0x2440_2020).unwrap().unwrap();
    for bytes in [16, 32, 64, 128, 256] {
        let length = VectorLength::from_bytes(bytes).unwrap();
        assert_eq!(
            recipe(word_lo, length, TargetCpu::Baseline),
            Recipe::BaselinePairs
        );
        assert_eq!(
            recipe(word_hi, length, TargetCpu::Baseline),
            if bytes < LONG_VECTOR_BYTES {
                Recipe::BaselinePairs
            } else {
                Recipe::Range
            }
        );
        assert_eq!(
            recipe(half_equal, length, TargetCpu::Sse42),
            if bytes < LONG_VECTOR_BYTES {
                Recipe::CheckedPairs
            } else {
                Recipe::Range
            }
        );
    }
}
