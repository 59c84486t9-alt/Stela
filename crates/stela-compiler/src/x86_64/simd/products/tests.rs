use super::*;
use alloc::vec::Vec;

#[test]
fn dot_products_use_exact_unsaturated_pairs_on_every_target() {
    for word in [0x4e829420, 0x6e829420, 0x4fa2e820, 0x6fa2e820] {
        let operand = crate::aarch64::simd::products::decode(word)
            .unwrap()
            .unwrap();
        for target in [TargetCpu::Baseline, TargetCpu::Ssse3, TargetCpu::Sse41] {
            let mut code = Vec::new();
            emit(&mut code, &operand, target);
            let count = |opcode: Host| {
                code.windows(opcode.encoding().len())
                    .filter(|bytes| *bytes == opcode.encoding())
                    .count()
            };
            assert_eq!(count(Host::MultiplyAddWords), 2);
            assert_eq!(count(Host::MultiplyAddUnsignedBytes), 0);
            assert_eq!(
                count(Host::ByteSignMask),
                0,
                "dot accumulation preserves QC"
            );
        }
    }
}

#[test]
fn rounded_accumulation_clamps_only_the_final_sum_and_checks_dword_multiply() {
    for word in [0x6e428420, 0x6e428c20, 0x6e828420, 0x6e828c20] {
        let operand = crate::aarch64::simd::products::decode(word)
            .unwrap()
            .unwrap();
        for target in [TargetCpu::Baseline, TargetCpu::Sse41] {
            let mut code = Vec::new();
            emit(&mut code, &operand, target);
            let count = |opcode: Host| {
                code.windows(opcode.encoding().len())
                    .filter(|bytes| *bytes == opcode.encoding())
                    .count()
            };
            assert_eq!(
                count(Host::ByteSignMask),
                2,
                "one final QC decision per half"
            );
            assert_eq!(count(Host::AddSignedSaturatingWord), 0);
            assert_eq!(count(Host::SubSignedSaturatingWord), 0);
            assert_eq!(
                count(Host::MultiplySignedDword),
                if operand.lane_bytes == 4 && target >= TargetCpu::Sse41 {
                    2
                } else {
                    0
                }
            );
            assert_eq!(
                count(Host::MultiplyHighSignedWord),
                if operand.lane_bytes == 2 { 2 } else { 0 }
            );
        }
    }
}

#[test]
fn indexed_products_share_packed_lowering_and_checked_dword_multiply() {
    for (word, lane, widen, signed) in [
        (0x4f628820, 2, false, false),
        (0x0f62a820, 2, true, true),
        (0x2f62a820, 2, true, false),
        (0x4f62a820, 2, true, true),
        (0x6f62a820, 2, true, false),
        (0x4fa28820, 4, false, false),
        (0x4fa2a820, 4, true, true),
        (0x6fa2a820, 4, true, false),
    ] {
        let operand = crate::aarch64::simd::products::decode(word)
            .unwrap()
            .unwrap();
        for target in [TargetCpu::Baseline, TargetCpu::Sse41] {
            let mut code = Vec::new();
            emit(&mut code, &operand, target);
            let has = |opcode: Host| {
                code.windows(opcode.encoding().len())
                    .any(|w| w == opcode.encoding())
            };
            let extended_words = lane == 2 && widen && !operand.upper && target >= TargetCpu::Sse41;
            assert_eq!(
                has(Host::MultiplyLowDword),
                lane == 4 && !widen && target >= TargetCpu::Sse41 || extended_words
            );
            assert_eq!(
                has(Host::MultiplySignedDword),
                lane == 4 && widen && signed && target >= TargetCpu::Sse41
            );
            assert_eq!(has(Host::MultiplyLowWord), lane == 2 && !extended_words);
            assert_eq!(has(Host::SignExtendWordToDword), extended_words && signed);
            assert_eq!(has(Host::ZeroExtendWordToDword), extended_words && !signed);
            assert_eq!(
                has(Host::MultiplyHighSignedWord),
                lane == 2 && widen && signed && !extended_words
            );
            assert_eq!(
                has(Host::MultiplyHighUnsignedWord),
                lane == 2 && widen && !signed && !extended_words
            );
            if lane == 4 && widen {
                assert!(
                    !has(Host::UnpackLowDword),
                    "PMULUDQ/PMULDQ consume only the selected even dwords"
                );
            }
            assert_eq!(
                code.windows(Host::LoadUnaligned.encoding().len())
                    .filter(|w| *w == Host::LoadUnaligned.encoding())
                    .count(),
                2
            );
            assert!(
                !has(Host::ByteSignMask),
                "ordinary multiplication preserves FPSR/QC"
            );
            assert!(code.len() < 160, "bounded whole-vector packed product");
        }
    }
}

#[test]
fn word_high_products_use_one_packed_pair_and_only_checked_rounding_extension() {
    for (word, rounded) in [(0x4e62b420, false), (0x6e62b420, true)] {
        let operand = crate::aarch64::simd::products::decode(word)
            .unwrap()
            .unwrap();
        for target in [TargetCpu::Baseline, TargetCpu::Ssse3, TargetCpu::Pclmulqdq] {
            let mut code = Vec::new();
            emit(&mut code, &operand, target);
            let has = |opcode: Host| {
                code.windows(opcode.encoding().len())
                    .any(|w| w == opcode.encoding())
            };
            let direct = rounded && target.supports(TargetCpu::Ssse3);
            assert_eq!(has(Host::MultiplyHighRoundedScaledWord), direct);
            assert_eq!(has(Host::MultiplyHighSignedWord), !direct);
            assert_eq!(has(Host::MultiplyLowWord), !direct);
            assert!(!has(Host::PackSignedDwordToWord));
            assert!(!has(Host::UnpackLowWord));
            let loads = code
                .windows(Host::LoadUnaligned.encoding().len())
                .filter(|w| *w == Host::LoadUnaligned.encoding())
                .count();
            assert_eq!(loads, 2, "whole128 high products read each input once");
            assert!(has(Host::ByteSignMask));
            assert!(code.len() < 160, "packed high products stay compact");
        }
    }
}
