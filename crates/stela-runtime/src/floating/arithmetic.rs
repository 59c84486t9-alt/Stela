//! Completion of elementwise, indexed and pairwise arithmetic.
#[cfg(all(test, target_arch = "x86_64"))]
mod native_tests;

use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{FPCR_NEP, UnsupportedControl, evaluate},
        simd::arithmetic::{Inputs, Operand, Shape},
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

const PAIR_LANES: u32 = 2;

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let (left, right) = match operand.inputs {
        Inputs::Elementwise { left, right }
        | Inputs::Indexed { left, right, .. }
        | Inputs::Pairwise { left, right } => {
            (state.v[usize::from(left)], state.v[usize::from(right)])
        }
        Inputs::PairwiseScalar { source } => {
            let source = state.v[usize::from(source)];
            (source, source)
        }
    };
    let mut result = if operand.shape == Shape::Scalar
        && !matches!(operand.inputs, Inputs::PairwiseScalar { .. })
        && state.fpcr & FPCR_NEP != 0
    {
        left
    } else {
        [0; VECTOR_LIMBS]
    };
    let lanes = operand.shape.lane_count(operand.format);
    let bits = operand.format.bits();
    let mut exceptions = 0;
    for lane in 0..lanes {
        let (left_bits, right_bits) = match operand.inputs {
            Inputs::Elementwise { .. } => {
                (read_lane(&left, bits, lane), read_lane(&right, bits, lane))
            }
            Inputs::Indexed { right_lane, .. } => (
                read_lane(&left, bits, lane),
                read_lane(&right, bits, u32::from(right_lane)),
            ),
            Inputs::Pairwise { .. } => {
                let pairs_per_source = lanes / PAIR_LANES;
                let (source, pair) = if lane < pairs_per_source {
                    (&left, lane)
                } else {
                    (&right, lane - pairs_per_source)
                };
                (
                    read_lane(source, bits, pair * PAIR_LANES),
                    read_lane(source, bits, pair * PAIR_LANES + 1),
                )
            }
            Inputs::PairwiseScalar { .. } => {
                (read_lane(&left, bits, 0), read_lane(&right, bits, 1))
            }
        };
        let outcome = evaluate(
            operand.format,
            operand.operation,
            state.fpcr,
            left_bits,
            right_bits,
        )?;
        write_lane(&mut result, bits, lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(operand.destination)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::floating::{
        BinaryOperation, DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_EXCEPTION_ENABLE_SHIFT, FPSR_QC,
        Format, INVALID,
    };

    const LAST_VECTOR_REGISTER: u8 = 31;

    fn state() -> GuestState {
        GuestState {
            x: std::array::from_fn(|index| 0x1234_5678_9abc_def0 ^ index as u64),
            sp: 0x1111_2222_3333_4444,
            nzcv: 0xa000_0000,
            reserved: 0xa5c3_9e71,
            v: std::array::from_fn(|index| {
                [
                    0x0123_4567_89ab_cdef ^ index as u64,
                    0xfedc_ba98_7654_3210 ^ index as u64,
                ]
            }),
            fpcr: FPCR_NEP,
            fpsr: FPSR_QC | DIVIDE_BY_ZERO,
        }
    }

    #[test]
    fn indexed_half_q0_uses_the_upper_source_lane_before_aliased_commit() {
        for destination in [1, LAST_VECTOR_REGISTER] {
            let mut actual = state();
            actual.fpcr |= FPCR_AH;
            actual.v[usize::from(LAST_VECTOR_REGISTER)] = [
                0x4400_4200_4000_3c00, // 1, 2, 3, 4
                0x7c01_7c01_7c01_7c01,
            ];
            actual.v[1] = [0x7c01_7c01_7c01_7c01, 0x4200_7c01_7c01_7c01];
            let mut expected = actual.clone();
            expected.v[usize::from(destination)] = [0x4a00_4880_4600_4200, 0]; // 3, 6, 9, 12
            complete(
                &mut actual,
                &Operand {
                    operation: BinaryOperation::MultiplyExtended,
                    format: Format::Half,
                    shape: Shape::Vector64,
                    destination,
                    inputs: Inputs::Indexed {
                        left: LAST_VECTOR_REGISTER,
                        right: 1,
                        right_lane: 7,
                    },
                },
            )
            .unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn vector_pairs_keep_adjacent_order_and_snapshot_both_aliased_sources() {
        for destination in [0, LAST_VECTOR_REGISTER] {
            let mut actual = state();
            actual.v[usize::from(LAST_VECTOR_REGISTER)] = [
                0x4000_0000_3f80_0000, // 1, 2
                0x4100_0000_4080_0000, // 4, 8
            ];
            actual.v[0] = [
                0x4200_0000_4180_0000, // 16, 32
                0x4300_0000_4280_0000, // 64, 128
            ];
            let mut expected = actual.clone();
            expected.v[usize::from(destination)] = [
                0x4140_0000_4040_0000, // 3, 12
                0x4340_0000_4240_0000, // 48, 192
            ];
            complete(
                &mut actual,
                &Operand {
                    operation: BinaryOperation::Add,
                    format: Format::Single,
                    shape: Shape::Vector128,
                    destination,
                    inputs: Inputs::Pairwise {
                        left: LAST_VECTOR_REGISTER,
                        right: 0,
                    },
                },
            )
            .unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn scalar_half_pair_ignores_nep_and_never_evaluates_other_source_lanes() {
        for ah in [0, FPCR_AH] {
            for nep in [0, FPCR_NEP] {
                let mut actual = state();
                actual.fpcr = ah | nep;
                actual.v[usize::from(LAST_VECTOR_REGISTER)] =
                    [0x7c01_7c01_4000_3c00, 0x7c01_7c01_7c01_7c01];
                let mut expected = actual.clone();
                expected.v[usize::from(LAST_VECTOR_REGISTER)] = [0x4200, 0];
                complete(
                    &mut actual,
                    &Operand {
                        operation: BinaryOperation::Add,
                        format: Format::Half,
                        shape: Shape::Scalar,
                        destination: LAST_VECTOR_REGISTER,
                        inputs: Inputs::PairwiseScalar {
                            source: LAST_VECTOR_REGISTER,
                        },
                    },
                )
                .unwrap();
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn scalar_post_sign_merges_original_left_and_keeps_fresh_ah_invalid() {
        for operation in [
            BinaryOperation::NegatedMultiply,
            BinaryOperation::AbsoluteDifference,
        ] {
            let mut actual = state();
            actual.fpcr |= FPCR_AH;
            actual.v[usize::from(LAST_VECTOR_REGISTER)][0] = 0x1234_5678_ff80_0123;
            actual.v[1][0] = 0x3f80_0000;
            let mut expected = actual.clone();
            expected.v[0] = actual.v[usize::from(LAST_VECTOR_REGISTER)];
            expected.v[0][0] = 0x1234_5678_ffc0_0123;
            expected.fpsr |= INVALID;
            complete(
                &mut actual,
                &Operand {
                    operation,
                    format: Format::Single,
                    shape: Shape::Scalar,
                    destination: 0,
                    inputs: Inputs::Elementwise {
                        left: LAST_VECTOR_REGISTER,
                        right: 1,
                    },
                },
            )
            .unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn every_routing_mode_refuses_retained_enables_without_partial_effects() {
        for inputs in [
            Inputs::Elementwise {
                left: LAST_VECTOR_REGISTER,
                right: 1,
            },
            Inputs::Indexed {
                left: LAST_VECTOR_REGISTER,
                right: 1,
                right_lane: 3,
            },
            Inputs::Pairwise {
                left: LAST_VECTOR_REGISTER,
                right: 1,
            },
            Inputs::PairwiseScalar {
                source: LAST_VECTOR_REGISTER,
            },
        ] {
            for ah in [0, FPCR_AH] {
                let mut actual = state();
                actual.fpcr |= ah | (EXCEPTIONS << FPCR_EXCEPTION_ENABLE_SHIFT);
                let expected = actual.clone();
                let shape = if matches!(inputs, Inputs::PairwiseScalar { .. }) {
                    Shape::Scalar
                } else {
                    Shape::Vector128
                };
                assert_eq!(
                    complete(
                        &mut actual,
                        &Operand {
                            operation: BinaryOperation::Add,
                            format: Format::Single,
                            shape,
                            destination: 1,
                            inputs,
                        }
                    ),
                    Err(UnsupportedControl {
                        enabled_exceptions: EXCEPTIONS
                    })
                );
                assert_eq!(actual, expected);
            }
        }
    }
}
