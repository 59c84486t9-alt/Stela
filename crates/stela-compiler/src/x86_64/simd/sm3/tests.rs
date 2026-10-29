mod oracle;
use super::*;
use crate::{
    GuestState, context::ExecutionContext, x86_64::asm::vector_extensions::execution::Native,
};

// Literal lane-wise Arm operation model. It does not share the
// emitted recipe's register allocation, staging, packing or Boolean identities.
fn reference(
    kind: Kind,
    old: [u32; 4],
    left: [u32; 4],
    right: [u32; 4],
    third: [u32; 4],
) -> [u32; 4] {
    let p1 = |x: u32| x ^ x.rotate_left(15) ^ x.rotate_left(23);
    match kind {
        Kind::Schedule1 => {
            let mut result = [0; 4];
            for i in 0..3 {
                result[i] = p1(old[i] ^ left[i] ^ right[i + 1].rotate_left(15));
            }
            result[3] = p1(old[3] ^ left[3] ^ result[0].rotate_left(15));
            result
        }
        Kind::Schedule2 => {
            let t = core::array::from_fn::<_, 4, _>(|i| left[i] ^ right[i].rotate_left(7));
            let mut result = core::array::from_fn(|i| old[i] ^ t[i]);
            result[3] ^= p1(t[0].rotate_left(15));
            result
        }
        Kind::Sum { .. } => [
            0,
            0,
            0,
            left[3]
                .rotate_left(12)
                .wrapping_add(right[3])
                .wrapping_add(third[3])
                .rotate_left(7),
        ],
        Kind::Round {
            second,
            nonlinear,
            lane,
        } => {
            let [d, c, b, a] = old;
            let boolean = match (second, nonlinear) {
                (_, false) => a ^ b ^ c,
                (false, true) => (a & c) | (a & b) | (c & b),
                (true, true) => (a & b) | (!a & c),
            };
            let sum = if second {
                left[3]
            } else {
                left[3] ^ a.rotate_left(12)
            };
            let value = boolean
                .wrapping_add(d)
                .wrapping_add(sum)
                .wrapping_add(right[usize::from(lane)]);
            [
                c,
                b.rotate_left(if second { 19 } else { 9 }),
                a,
                if second {
                    value ^ value.rotate_left(9) ^ value.rotate_left(17)
                } else {
                    value
                },
            ]
        }
    }
}

fn words(vector: [u64; 2]) -> [u32; 4] {
    [
        vector[0] as u32,
        (vector[0] >> 32) as u32,
        vector[1] as u32,
        (vector[1] >> 32) as u32,
    ]
}
fn vector(words: [u32; 4]) -> [u64; 2] {
    [
        u64::from(words[0]) | (u64::from(words[1]) << 32),
        u64::from(words[2]) | (u64::from(words[3]) << 32),
    ]
}

#[test]
fn actual_baseline_recipes_match_lane_model_under_all_source_alias_partitions() {
    let mut cases = 0;
    let mut random = 0x6a09e667f3bcc908_u64;
    // Restricted-growth tuples enumerate all15 equality partitions of four
    // operand roles; adding31 covers the architectural last vector as data.
    for destination in [0, 31] {
        for left in [destination, 1] {
            for right in [destination, left, 2] {
                for third in [destination, left, right, 3] {
                    let mut kinds =
                        alloc::vec![Kind::Schedule1, Kind::Schedule2, Kind::Sum { third }];
                    for lane in 0..4 {
                        for second in [false, true] {
                            for nonlinear in [false, true] {
                                kinds.push(Kind::Round {
                                    second,
                                    nonlinear,
                                    lane,
                                });
                            }
                        }
                    }
                    for kind in kinds {
                        let operand = Operand {
                            kind,
                            destination,
                            left,
                            right,
                        };
                        let mut code = Code::new();
                        emit(&mut code, &operand);
                        code.asm().ret();
                        let native = Native::new(&code);
                        for sample in 0..64 {
                            let mut state = GuestState {
                                nzcv: 0xa0000000,
                                fpsr: 0x0800001f,
                                fpcr: 0x1234,
                                ..GuestState::default()
                            };
                            for v in &mut state.v {
                                for word in v {
                                    random ^= random << 13;
                                    random ^= random >> 7;
                                    random ^= random << 17;
                                    *word = match sample {
                                        0 => 0,
                                        1 => u64::MAX,
                                        2 => 0x8000000080000000,
                                        3 => 0x7fffffff7fffffff,
                                        _ => random,
                                    };
                                }
                            }
                            state.x = core::array::from_fn(|i| random.wrapping_mul(i as u64 + 1));
                            let mut expected = state.clone();
                            expected.v[usize::from(destination)] = vector(reference(
                                kind,
                                words(state.v[usize::from(destination)]),
                                words(state.v[usize::from(left)]),
                                words(state.v[usize::from(right)]),
                                words(state.v[usize::from(third)]),
                            ));
                            native.run(&mut state, &mut ExecutionContext::default());
                            assert_eq!(state, expected, "{operand:?} sample={sample}");
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    std::println!(
        "SM3_NATIVE_BASELINE_CASES={cases} SOURCE_SHA256={}",
        crate::SOURCE_SHA256
    );
}
