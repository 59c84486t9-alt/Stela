use super::*;
use crate::{GuestAddress, Lifter};

#[test]
fn known_llvm_words_preserve_each_operand_and_lane() {
    for (word, kind) in [
        (0xce62c020, Kind::Schedule1),
        (0xce62c420, Kind::Schedule2),
        (0xce420c20, Kind::Sum { third: 3 }),
        (
            0xce428020,
            Kind::Round {
                second: false,
                nonlinear: false,
                lane: 0,
            },
        ),
        (
            0xce429420,
            Kind::Round {
                second: false,
                nonlinear: true,
                lane: 1,
            },
        ),
        (
            0xce42a820,
            Kind::Round {
                second: true,
                nonlinear: false,
                lane: 2,
            },
        ),
        (
            0xce42bc20,
            Kind::Round {
                second: true,
                nonlinear: true,
                lane: 3,
            },
        ),
    ] {
        assert_eq!(
            decode(word),
            Some(Ok(Operand {
                kind,
                destination: 0,
                left: 1,
                right: 2
            }))
        );
        assert_eq!(
            crate::aarch64::Decoder
                .lift(GuestAddress(0x1000), word)
                .unwrap()
                .operation,
            crate::aarch64::Operation::Simd(crate::aarch64::simd::Operand::Sm3(
                decode(word).unwrap().unwrap()
            ))
        );
    }
}

#[test]
fn all_register_fields_and_indexed_lanes_remain_data_including_v31() {
    for destination in 0..32 {
        for left in 0..32 {
            for right in 0..32 {
                for base in [0xce60c000, 0xce60c400, 0xce400000, 0xce408000] {
                    let word = base | destination | (left << 5) | (right << 16);
                    let operand = decode(word).unwrap().unwrap();
                    assert_eq!(
                        (operand.destination, operand.left, operand.right),
                        (destination as u8, left as u8, right as u8)
                    );
                }
            }
        }
    }
    for third in 0..32 {
        assert_eq!(
            decode(0xce400000 | (third << 10)).unwrap().unwrap().kind,
            Kind::Sum { third: third as u8 }
        );
    }
    for lane in 0..4 {
        for second in [false, true] {
            for nonlinear in [false, true] {
                let word = 0xce408000
                    | (lane << 12)
                    | (u32::from(second) << 11)
                    | (u32::from(nonlinear) << 10);
                assert_eq!(
                    decode(word).unwrap().unwrap().kind,
                    Kind::Round {
                        second,
                        nonlinear,
                        lane: lane as u8
                    }
                );
            }
        }
    }
}

#[test]
fn neighbors_and_fixed_bit_mutations_do_not_expand_the_family() {
    for word in [0xce608000, 0xce608c00, 0xcec08400, 0xce60c800, 0x4e608000] {
        assert!(decode(word).is_none(), "{word:08x}");
    }
    for (base, mask) in [
        (0xce60c000_u32, 0xffe0fc00_u32),
        (0xce60c400, 0xffe0fc00),
        (0xce400000, 0xffe08000),
        (0xce408000, 0xffe0c000),
    ] {
        for bit in 0..32 {
            if mask & (1 << bit) != 0 {
                let mutated = base ^ (1 << bit);
                // An opcode mutation may select a valid sibling, but never
                // alter a reserved width or consume the adjacent SM4/SHA512 class.
                if ![0xce60c000, 0xce60c400, 0xce400000, 0xce408000].contains(&mutated) {
                    assert!(decode(mutated).is_none(), "{mutated:08x}");
                }
            }
        }
    }
}

#[test]
fn complete_family_compiles_with_precise_source_maps_in_ordinary_and_system_blocks() {
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, Features},
    };
    let words = [
        0xce62c020_u32,
        0xce62c420,
        0xce420c20,
        0xce428020,
        0xce429420,
        0xce42a820,
        0xce42bc20,
        0xd65f03c0,
    ];
    let source: alloc::vec::Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    for profile in [
        BlockProfile::ORDINARY,
        BlockProfile::new(Features::SYSTEM_MODE),
    ] {
        let mut baseline = None;
        for target in [
            TargetCpu::Baseline,
            TargetCpu::Baseline.with_data_independent_timing(),
        ] {
            let block = crate::compile(
                &source,
                GuestAddress(0x4000),
                &Options::new(profile, target),
            )
            .unwrap();
            assert_eq!(block.source_bytes, source.len());
            assert_eq!(block.native.source_map.len(), words.len());
            for (index, (pc, _)) in block.native.source_map.iter().enumerate() {
                assert_eq!(*pc, GuestAddress(0x4000 + index as u64 * 4));
            }
            if let Some(expected) = &baseline {
                assert_eq!(&block.native.x86_64_code, expected);
            } else {
                baseline = Some(block.native.x86_64_code);
            }
        }
    }
}
