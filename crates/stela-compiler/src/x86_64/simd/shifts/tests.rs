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
                        let mut code = Code::new();
                        emit(&mut code, &operand, TargetCpu::Baseline);
                        let mut qc = Code::new();
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
                let mut code = Code::new();
                emit(&mut code, &operand, target);
                let mut checked_pack = Code::new();
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
                let mut code = Code::new();
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
            let mut code = Code::new();
            emit(
                &mut code,
                &immediate(lane, bytes, 1, signed),
                TargetCpu::Baseline,
            );
            let mut saturating_add = Code::new();
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
                let mut code = Code::new();
                emit(&mut code, &operand, TargetCpu::Baseline);
                assert_eq!(code.len(), if bytes == 8 { 20 } else { 16 });
            }
        }
    }
}
#[test]
fn avx2_register_shifts_keep_other_recipes_and_reduce_code() {
    for lane in [1, 2, 4, 8] {
        for bytes in [8, 16] {
            for (round, saturating) in [(false, false), (true, false), (false, true), (true, true)]
            {
                let operand = Operand {
                    kind: Kind::Register {
                        signed: true,
                        round,
                        saturating,
                        counts: 1,
                    },
                    destination: 2,
                    source: 0,
                    lane_bytes: lane,
                    amount: 0,
                    bytes,
                };
                let mut baseline = Code::new();
                emit(&mut baseline, &operand, TargetCpu::Baseline);
                let mut avx2 = Code::new();
                emit(&mut avx2, &operand, TargetCpu::Avx2);
                if lane == 4 && bytes == 16 && !round && !saturating {
                    assert!(avx2.len() < baseline.len());
                    assert!(avx2.windows(3).any(|w| w == [0xc5, 0xf8, 0x77]));
                } else {
                    assert_eq!(avx2, baseline);
                }
                let mut dit = Code::new();
                emit(
                    &mut dit,
                    &operand,
                    TargetCpu::Avx2.with_data_independent_timing(),
                );
                assert_eq!(dit, baseline);
            }
        }
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn avx2_register_shifts_match_signed_byte_counts_with_aliases() {
    use crate::x86_64::asm::vector_extensions::execution::Native;
    use crate::{GuestState, context::ExecutionContext};
    if !TargetCpu::detect().supports(TargetCpu::Avx2) {
        return;
    }
    fn reference(
        input: [u64; 2],
        counts: [u64; 2],
        lane: usize,
        bytes: usize,
        signed: bool,
    ) -> [u64; 2] {
        let input: [u8; 16] = core::array::from_fn(|i| input[i / 8].to_le_bytes()[i % 8]);
        let counts: [u8; 16] = core::array::from_fn(|i| counts[i / 8].to_le_bytes()[i % 8]);
        let mut out = [0u8; 16];
        for at in (0..bytes).step_by(lane) {
            let mut x = [0u8; 8];
            x[..lane].copy_from_slice(&input[at..at + lane]);
            let x = u64::from_le_bytes(x);
            let count = counts[at] as i8 as i32;
            let bits = (lane * 8) as u32;
            let result = if count >= 0 {
                if count as u32 >= bits {
                    0
                } else {
                    x << (count as u32)
                }
            } else if signed {
                let x = if lane == 4 { x as i32 as i64 } else { x as i64 };
                (x >> ((-count as u32).min(bits - 1))) as u64
            } else if -count as u32 >= bits {
                0
            } else {
                x >> (-count as u32)
            };
            out[at..at + lane].copy_from_slice(&result.to_le_bytes()[..lane]);
        }
        [
            u64::from_le_bytes(out[..8].try_into().unwrap()),
            u64::from_le_bytes(out[8..].try_into().unwrap()),
        ]
    }
    for lane in [4u8, 8] {
        for bytes in [8u8, 16] {
            for signed in [false, true] {
                for (destination, source, counts) in
                    [(2u8, 0u8, 1u8), (0, 0, 1), (1, 0, 1), (0, 0, 0)]
                {
                    let operand = Operand {
                        kind: Kind::Register {
                            signed,
                            round: false,
                            saturating: false,
                            counts,
                        },
                        destination,
                        source,
                        lane_bytes: lane,
                        amount: 0,
                        bytes,
                    };
                    let mut candidate = Code::new();
                    assert!(emit_avx2_register_shift_candidate(
                        &mut candidate,
                        &operand,
                        counts,
                        signed,
                        TargetCpu::Avx2
                    ));
                    let mut selected = Code::new();
                    emit(&mut selected, &operand, TargetCpu::Avx2);
                    for mut code in [candidate, selected] {
                        code.asm().ret();
                        let native = Native::new(&code);
                        for raw in 0..=u8::MAX {
                            let mut state = GuestState {
                                fpsr: 0x0800_001f,
                                nzcv: 0xa000_0000,
                                ..GuestState::default()
                            };
                            let data = match raw % 5 {
                                0 => 0,
                                1 => u64::MAX,
                                2 => 0x8000_0000_8000_0000,
                                3 => 1,
                                _ => 0x0123_4567_89ab_cdef,
                            };
                            state.v[usize::from(source)] = [data, !data];
                            if counts != source {
                                let c: [u8; 16] = core::array::from_fn(|i| {
                                    if i % usize::from(lane) == 0 {
                                        raw.wrapping_add((i * 13) as u8)
                                    } else {
                                        0xd3
                                    }
                                });
                                state.v[usize::from(counts)] = [
                                    u64::from_le_bytes(c[..8].try_into().unwrap()),
                                    u64::from_le_bytes(c[8..].try_into().unwrap()),
                                ];
                            }
                            let expected = reference(
                                state.v[usize::from(source)],
                                state.v[usize::from(counts)],
                                usize::from(lane),
                                usize::from(bytes),
                                signed,
                            );
                            native.run(&mut state, &mut ExecutionContext::default());
                            assert_eq!(
                                state.v[usize::from(destination)],
                                expected,
                                "{lane} {bytes} {signed} {destination}/{source}/{counts} {raw}"
                            );
                            assert_eq!(state.fpsr, 0x0800_001f);
                            assert_eq!(state.nzcv, 0xa000_0000);
                        }
                    }
                }
            }
        }
    }
}
