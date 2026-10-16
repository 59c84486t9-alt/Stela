use super::*;
use alloc::vec;

#[test]
fn full_width_nonround_narrowing_omits_qc_only_when_bounds_prove_it() {
    for lane in [1, 2, 4] {
        for scalar in [false, true] {
            for upper in [false, true] {
                if scalar && upper {
                    continue;
                }
                for (signed_source, unsigned_result) in [(true, false), (false, true), (true, true)]
                {
                    for round in [false, true] {
                        let operand = Operand {
                            kind: Kind::SaturatingNarrow {
                                signed_source,
                                unsigned_result,
                                round,
                                upper,
                            },
                            destination: 31,
                            source: 31,
                            lane_bytes: lane,
                            amount: lane * BITS_PER_BYTE,
                            bytes: if scalar { lane } else { VECTOR_BYTES },
                        };
                        let mut code = vec![];
                        emit(&mut code, &operand, TargetCpu::Baseline);
                        let mut qc = vec![];
                        Host::ByteSignMask.register(&mut qc, 1, 4, TargetCpu::Baseline);
                        assert_eq!(
                            code.windows(qc.len()).any(|w| w == qc),
                            round || signed_source == unsigned_result
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn saturating_narrow_packs_keep_checked_features_and_active_qc_masks() {
    for lane in [1, 2, 4] {
        for scalar in [false, true] {
            for target in [TargetCpu::Baseline, TargetCpu::Sse41, TargetCpu::Sse42] {
                let operand = Operand {
                    kind: Kind::SaturatingNarrow {
                        signed_source: false,
                        unsigned_result: true,
                        round: true,
                        upper: !scalar,
                    },
                    destination: 31,
                    source: 31,
                    lane_bytes: lane,
                    amount: 1,
                    bytes: if scalar { lane } else { VECTOR_BYTES },
                };
                let mut code = vec![];
                emit(&mut code, &operand, target);
                let mut checked_pack = vec![];
                Host::PackUnsignedDwordToWord.register(&mut checked_pack, 0, 0, TargetCpu::Sse41);
                assert_eq!(
                    code.windows(checked_pack.len()).any(|w| w == checked_pack),
                    lane == 2 && target >= TargetCpu::Sse41,
                );
                let active_bytes = if scalar { lane * 2 } else { VECTOR_BYTES };
                let mut active_mask = vec![0x81, 0xe1]; // AND ECX, active mask
                active_mask.extend(((1u32 << active_bytes) - 1).to_le_bytes());
                assert!(code.windows(active_mask.len()).any(|w| w == active_mask));
            }
        }
    }
}

fn immediate(lane_bytes: u8, bytes: u8, amount: u8, signed: bool) -> Operand {
    Operand {
        kind: Kind::SaturatingImmediate {
            signed_source: signed,
            unsigned_result: !signed,
        },
        destination: 1,
        source: 1, // Exercise the in-place emission shape too.
        lane_bytes,
        amount,
        bytes,
    }
}

#[test]
fn nonsaturating_zero_immediates_keep_a_real_minimal_write_interval() {
    for bytes in [8, 16] {
        for lane in [1, 2, 4, 8] {
            if bytes == 8 && lane == 8 {
                continue;
            }
            for signed in [false, true] {
                let mut code = vec![];
                emit(
                    &mut code,
                    &immediate(lane, bytes, 0, signed),
                    TargetCpu::Baseline,
                );
                // Load, optional upper clearing, store. No FPSR write and
                // no empty source-map interval for an in-place identity.
                assert_eq!(code.len(), if bytes == 8 { 20 } else { 16 });
            }
        }
    }
}

#[test]
fn byte_and_word_immediate_doubling_use_baseline_saturating_adds() {
    for (lane, signed, opcode) in [
        (1, true, Host::AddSignedSaturatingByte),
        (2, true, Host::AddSignedSaturatingWord),
        (1, false, Host::AddUnsignedSaturatingByte),
        (2, false, Host::AddUnsignedSaturatingWord),
    ] {
        for bytes in [8, 16] {
            let mut code = vec![];
            emit(
                &mut code,
                &immediate(lane, bytes, 1, signed),
                TargetCpu::Baseline,
            );
            let mut saturating_add = vec![];
            packed(&mut saturating_add, opcode, 0, 0);
            assert!(
                code.windows(saturating_add.len())
                    .any(|w| w == saturating_add)
            );
            // Includes full sticky QC publication and the active-byte
            // mask; excludes the harness RET supplied by the caller.
            let body_bytes = if signed {
                57
            } else if lane == 1 {
                49
            } else {
                54
            };
            assert_eq!(code.len(), body_bytes + if bytes == 8 { 4 } else { 0 });
        }
    }
}

#[test]
fn identity_insert_immediates_preserve_destination_clearing() {
    for bytes in [8, 16] {
        for lane in [1, 2, 4, 8] {
            if bytes == 8 && lane == 8 {
                continue;
            }
            for kind in [
                Kind::Left { insert: true },
                Kind::Right {
                    signed: false,
                    round: false,
                    accumulate: false,
                    insert: true,
                },
            ] {
                let mut operand = immediate(lane, bytes, 0, false);
                operand.kind = kind;
                if matches!(kind, Kind::Right { .. }) {
                    operand.amount = lane * 8;
                }
                let mut code = vec![];
                emit(&mut code, &operand, TargetCpu::Baseline);
                assert_eq!(code.len(), if bytes == 8 { 20 } else { 16 });
            }
        }
    }
}
