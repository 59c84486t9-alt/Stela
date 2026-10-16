use super::*;
use alloc::vec::Vec;

fn emitted(word: u32, target: TargetCpu) -> Vec<u8> {
    let operand = crate::aarch64::simd::i8mm::decode(word).unwrap().unwrap();
    let mut code = Vec::new();
    emit(&mut code, &operand, target);
    code
}

#[test]
fn only_checked_matrix_paths_use_horizontal_add() {
    const PHADDD: &[u8] = &[0x66, 0x0f, 0x38, 0x02];
    for word in [0x4e80a400, 0x6e80a400, 0x4e80ac00] {
        let baseline = emitted(word, TargetCpu::Baseline);
        let checked = emitted(word, TargetCpu::Ssse3);
        assert!(!baseline.windows(PHADDD.len()).any(|bytes| bytes == PHADDD));
        assert_eq!(
            checked
                .windows(PHADDD.len())
                .filter(|bytes| *bytes == PHADDD)
                .count(),
            3
        );
        assert!(checked.len() < baseline.len());
    }
    for word in [0x0e809c00, 0x0f80f000, 0x0f00f000] {
        assert_eq!(
            emitted(word, TargetCpu::Baseline),
            emitted(word, TargetCpu::Ssse3)
        );
    }
}

#[test]
fn indexed_q0_uses_full_source_and_clears_upper_destination() {
    const CLEAR_UPPER: &[u8] = &[0xf3, 0x0f, 0x7e, 0xc0];
    for base in [0x0f80f000, 0x0f00f000] {
        for index in 0..4 {
            let word = base | 31 << 16 | 31 << 5 | 31 | (index & 1) << 21 | (index >> 1) << 11;
            let low = emitted(word, TargetCpu::Baseline);
            let full = emitted(word | 1 << 30, TargetCpu::Baseline);
            assert!(
                low.windows(5)
                    .any(|bytes| bytes
                        == [0x66, 0x0f, 0x70, 0xc9, index as u8 * DOT_GROUP_BROADCAST])
            );
            assert!(low.windows(4).any(|bytes| bytes == CLEAR_UPPER));
            assert!(!full.windows(4).any(|bytes| bytes == CLEAR_UPPER));
        }
    }
}
