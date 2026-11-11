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
