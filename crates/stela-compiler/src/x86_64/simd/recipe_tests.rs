//! Recipe tiers run natively against scalar Arm references over edge values.
//! Each tier this host lacks is skipped (by CPUID), never emulated.
use super::*;
use crate::GuestState;
use crate::TargetCpu;
use alloc::vec::Vec;

/// SSE2, SSE4.1, x86-64-v2, v3 (AVX2), v3 with AVX-VNNI, v4 (AVX-512), v4
/// with AVX-512 VNNI only (the EVEX dot form) and with both, and the DIT
/// profile's reviewed recipes.
fn tiers() -> Vec<TargetCpu> {
    let host = TargetCpu::detect();
    [
        TargetCpu::Baseline,
        TargetCpu::Sse41,
        TargetCpu::X86_64_V2,
        TargetCpu::X86_64_V3,
        TargetCpu::X86_64_V3.with_avx_vnni(),
        TargetCpu::X86_64_V4,
        TargetCpu::X86_64_V4.with_avx512vnni(),
        TargetCpu::X86_64_V4.with_avx512vnni().with_avx_vnni(),
        TargetCpu::X86_64_V4.with_gfni().with_avx512vbmi(),
        TargetCpu::X86_64_V4.with_data_independent_timing(),
        TargetCpu::X86_64_V2.with_data_independent_timing(),
    ]
    .into_iter()
    .filter(|tier| host.supports(*tier))
    .collect()
}

pub(super) struct Values(u64);
impl Values {
    pub(super) fn new() -> Self {
        Self(0x9e37_79b9_7f4a_7c15)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 ^ self.0 >> 29
    }
    /// A vector whose `lane` lanes are each an edge value (0, 1, -1, the
    /// signed and unsigned extremes and their neighbours) or random.
    pub(super) fn vector(&mut self, lane: u8) -> [u64; 2] {
        let bits = u32::from(lane) * 8;
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1 << bits) - 1
        };
        let min = 1u64 << (bits - 1);
        let mut bytes = [0u8; 16];
        for at in (0..16).step_by(usize::from(lane)) {
            let value = match self.next() % 12 {
                0 => 0,
                1 => 1,
                2 => mask,
                3 => min,
                4 => min - 1,
                5 => min + 1,
                6 => mask - 1,
                7 => 2,
                _ => self.next(),
            } & mask;
            bytes[at..at + usize::from(lane)]
                .copy_from_slice(&value.to_le_bytes()[..usize::from(lane)]);
        }
        [
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..].try_into().unwrap()),
        ]
    }
}

/// Lane `index` of `vector`, `lane` bytes wide, sign- or zero-extended.
pub(super) fn get(vector: [u64; 2], lane: u8, index: usize, signed: bool) -> i128 {
    let bytes: [u8; 16] = bytemuck(vector);
    let at = index * usize::from(lane);
    let mut raw = [0u8; 16];
    raw[..usize::from(lane)].copy_from_slice(&bytes[at..at + usize::from(lane)]);
    let value = u128::from_le_bytes(raw);
    let bits = u32::from(lane) * 8;
    if signed && value >> (bits - 1) & 1 == 1 {
        (value | (u128::MAX << bits)) as i128
    } else {
        value as i128
    }
}

/// `vector` with lane `index` set to the low bits of `value`.
pub(super) fn set(vector: &mut [u64; 2], lane: u8, index: usize, value: i128) {
    let mut bytes: [u8; 16] = bytemuck(*vector);
    let at = index * usize::from(lane);
    bytes[at..at + usize::from(lane)].copy_from_slice(&value.to_le_bytes()[..usize::from(lane)]);
    *vector = [
        u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..].try_into().unwrap()),
    ];
}

fn bytemuck(vector: [u64; 2]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&vector[0].to_le_bytes());
    bytes[8..].copy_from_slice(&vector[1].to_le_bytes());
    bytes
}

/// Emit `operand` for each tier and run it on `cases` states, comparing
/// every V register, FPSR and FPCR with `reference`.
pub(super) fn check(
    name: &str,
    operand: &Operand,
    cases: usize,
    mut state_for: impl FnMut(&mut Values) -> GuestState,
    reference: impl Fn(&GuestState) -> GuestState,
) {
    let mut values = Values::new();
    let states: Vec<GuestState> = (0..cases).map(|_| state_for(&mut values)).collect();
    for target in tiers() {
        let mut code = Code::new();
        emit_for_target(&mut code, operand, target, MemoryChecks::DEFAULT);
        for initial in &states {
            let expected = reference(initial);
            let mut state = initial.clone();
            crate::x86_64::native::run(&code, &mut state);
            assert_eq!(
                (state.v, state.fpsr, state.fpcr),
                (expected.v, expected.fpsr, expected.fpcr),
                "{name} on {target:?} from {:x?}",
                initial.v
            );
        }
    }
}

mod products {
    use super::*;
    use crate::aarch64::simd::products::{Accumulate, Kind, Operand as Product};

    const D: u8 = 2;
    const L: u8 = 5;
    const R: u8 = 9;

    fn reference(operand: &Product, state: &GuestState) -> GuestState {
        let Kind::Product {
            signed,
            widen,
            accumulate,
        } = operand.kind
        else {
            unreachable!()
        };
        let lane = operand.lane_bytes;
        let out_lane = if widen { lane * 2 } else { lane };
        let lanes = usize::from(operand.bytes / out_lane);
        let first = if widen && operand.upper { lanes } else { 0 };
        let mut result = [0u64; 2];
        let old = state.v[usize::from(operand.destination)];
        for i in 0..lanes {
            let left = get(state.v[usize::from(operand.left)], lane, first + i, signed);
            let right_index = operand.index.map_or(first + i, usize::from);
            let right = get(
                state.v[usize::from(operand.right)],
                lane,
                right_index,
                signed,
            );
            let product = left.wrapping_mul(right);
            let acc = get(old, out_lane, i, false);
            let value = match accumulate {
                Accumulate::None => product,
                Accumulate::Add => acc.wrapping_add(product),
                Accumulate::Subtract => acc.wrapping_sub(product),
            };
            set(&mut result, out_lane, i, value);
        }
        let mut expected = state.clone();
        expected.v[usize::from(operand.destination)] = result;
        expected
    }

    /// SMULL/UMULL/SMLAL/UMLAL/SMLSL/UMLSL (and their upper halves) of
    /// bytes, halfwords and words, by vector and by each element; MUL, MLA
    /// and MLS by element.
    #[test]
    fn long_and_indexed_products_match_arm_on_every_tier() {
        for widen in [true, false] {
            for lane in [1u8, 2, 4] {
                for signed in [true, false] {
                    if !widen && !signed {
                        continue;
                    }
                    for accumulate in [Accumulate::None, Accumulate::Add, Accumulate::Subtract] {
                        for upper in [false, true] {
                            if !widen && upper {
                                continue;
                            }
                            let indices: Vec<Option<u8>> = if lane == 1 {
                                alloc::vec![None]
                            } else {
                                core::iter::once(None)
                                    .chain((0..16 / lane).map(Some))
                                    .collect()
                            };
                            for index in indices {
                                if !widen && index.is_none() {
                                    continue;
                                }
                                for bytes in [8u8, 16] {
                                    if widen && bytes == 8 {
                                        continue;
                                    }
                                    let operand = Product {
                                        kind: Kind::Product {
                                            signed,
                                            widen,
                                            accumulate,
                                        },
                                        destination: D,
                                        left: L,
                                        right: R,
                                        lane_bytes: lane,
                                        bytes,
                                        upper,
                                        index,
                                    };
                                    check(
                                        &alloc::format!("{:?}", operand.kind),
                                        &Operand::Product(operand),
                                        48,
                                        |values| {
                                            let mut state = GuestState::default();
                                            state.v[usize::from(D)] = values.vector(lane * 2);
                                            state.v[usize::from(L)] = values.vector(lane);
                                            state.v[usize::from(R)] = values.vector(lane);
                                            state.fpsr = 0x0800_0000 & values.next() as u32;
                                            state
                                        },
                                        |state| reference(&operand, state),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

mod shifts {
    use super::*;
    use crate::aarch64::simd::saturating::FPSR_QC;
    use crate::aarch64::simd::shifts::{Kind, Operand as Shift};

    const D: u8 = 3;
    const S: u8 = 7;

    fn state(values: &mut Values, lane: u8) -> GuestState {
        let mut state = GuestState::default();
        state.v[usize::from(D)] = values.vector(lane);
        state.v[usize::from(S)] = values.vector(lane);
        state.fpsr = FPSR_QC & values.next() as u32;
        state
    }

    /// `(x + rounding) >> amount` without overflow.
    fn shifted(x: i128, amount: u8, round: bool) -> i128 {
        (x + if round { 1i128 << (amount - 1) } else { 0 }) >> amount
    }

    fn reference(operand: &Shift, state: &GuestState) -> GuestState {
        let mut expected = state.clone();
        let source = state.v[usize::from(operand.source)];
        let old = state.v[usize::from(operand.destination)];
        let lane = operand.lane_bytes;
        let mut result = [0u64; 2];
        match operand.kind {
            Kind::Right {
                signed,
                round,
                accumulate,
                insert: false,
            } => {
                for i in 0..usize::from(operand.bytes / lane) {
                    let value = shifted(get(source, lane, i, signed), operand.amount, round);
                    let value = if accumulate {
                        value.wrapping_add(get(old, lane, i, false))
                    } else {
                        value
                    };
                    set(&mut result, lane, i, value);
                }
            }
            Kind::Narrow { round, upper } => {
                if upper {
                    result[0] = old[0];
                }
                let first = if upper { 8 / usize::from(lane) } else { 0 };
                for i in 0..8 / usize::from(lane) {
                    let value = shifted(get(source, lane * 2, i, false), operand.amount, round);
                    set(&mut result, lane, first + i, value);
                }
            }
            Kind::SaturatingNarrow {
                signed_source,
                unsigned_result,
                round,
                upper,
            } => {
                if upper {
                    result[0] = old[0];
                }
                let bits = u32::from(lane) * 8;
                let (low, high) = if unsigned_result {
                    (0i128, (1i128 << bits) - 1)
                } else {
                    (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
                };
                let lanes = if operand.bytes == lane {
                    1
                } else {
                    8 / usize::from(lane)
                };
                let first = if upper { 8 / usize::from(lane) } else { 0 };
                for i in 0..lanes {
                    let value = shifted(
                        get(source, lane * 2, i, signed_source),
                        operand.amount,
                        round,
                    );
                    let clamped = value.clamp(low, high);
                    if clamped != value {
                        expected.fpsr |= FPSR_QC;
                    }
                    set(&mut result, lane, first + i, clamped);
                }
            }
            _ => unreachable!(),
        }
        expected.v[usize::from(operand.destination)] = result;
        expected
    }

    fn run(operand: Shift, wide: u8) {
        check(
            &alloc::format!("{operand:?}"),
            &Operand::Shift(operand),
            40,
            |values| state(values, wide),
            |state| reference(&operand, state),
        );
    }

    /// SRSHR, URSHR, SRSRA, URSRA (and the unrounded forms) of every lane
    /// size and amount, both widths.
    #[test]
    fn rounding_right_shifts_match_arm_on_every_tier() {
        for lane in [1u8, 2, 4, 8] {
            for amount in 1..=lane * 8 {
                for (signed, round, accumulate) in [
                    (true, true, false),
                    (false, true, false),
                    (true, true, true),
                    (false, true, true),
                    (true, false, false),
                ] {
                    for bytes in [8u8, 16] {
                        if lane == 8 && bytes == 8 {
                            continue;
                        }
                        let kind = Kind::Right {
                            signed,
                            round,
                            accumulate,
                            insert: false,
                        };
                        run(
                            Shift {
                                kind,
                                destination: D,
                                source: S,
                                lane_bytes: lane,
                                amount,
                                bytes,
                            },
                            lane,
                        );
                    }
                }
            }
        }
    }

    /// RSHRN/SHRN and SQSHRN, SQRSHRN, SQSHRUN, SQRSHRUN, UQSHRN, UQRSHRN
    /// into either half, vector and scalar, with QC.
    #[test]
    fn narrowing_shifts_match_arm_with_qc_on_every_tier() {
        for lane in [1u8, 2, 4] {
            for amount in 1..=lane * 8 {
                for upper in [false, true] {
                    for round in [false, true] {
                        run(
                            Shift {
                                kind: Kind::Narrow { round, upper },
                                destination: D,
                                source: S,
                                lane_bytes: lane,
                                amount,
                                bytes: 16,
                            },
                            lane * 2,
                        );
                        for (signed_source, unsigned_result) in
                            [(true, false), (true, true), (false, true)]
                        {
                            for bytes in [16, lane] {
                                if upper && bytes == lane {
                                    continue;
                                }
                                let kind = Kind::SaturatingNarrow {
                                    signed_source,
                                    unsigned_result,
                                    round,
                                    upper,
                                };
                                run(
                                    Shift {
                                        kind,
                                        destination: D,
                                        source: S,
                                        lane_bytes: lane,
                                        amount,
                                        bytes,
                                    },
                                    lane * 2,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
