//! Completion of elementwise, pairwise and across-lane min/max.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{FPCR_NEP, Format, UnsupportedControl, minmax},
        simd::{
            arithmetic::Shape,
            minmax::{BinaryMode, Operand},
        },
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

const PAIR_LANES: u32 = 2;
const MAX_REDUCTION_LANES: usize = VECTOR_LIMBS * u64::BITS as usize / Format::Half.bits() as usize;

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let format = operand.format();
    let operation = operand.operation();
    let mut result = [0; VECTOR_LIMBS];
    let mut exceptions = 0;
    match *operand {
        Operand::Binary {
            shape,
            mode,
            left,
            right,
            ..
        } => {
            let left = state.v[usize::from(left)];
            let right = state.v[usize::from(right)];
            if shape == Shape::Scalar && state.fpcr & FPCR_NEP != 0 {
                result = left;
            }
            let lanes = shape.lane_count(format);
            for lane in 0..lanes {
                let (left_bits, right_bits) = match mode {
                    BinaryMode::Elementwise => (
                        read_lane(&left, format.bits(), lane),
                        read_lane(&right, format.bits(), lane),
                    ),
                    BinaryMode::Pairwise => {
                        let half = lanes / PAIR_LANES;
                        let (source, pair) = if lane < half {
                            (&left, lane)
                        } else {
                            (&right, lane - half)
                        };
                        (
                            read_lane(source, format.bits(), pair * PAIR_LANES),
                            read_lane(source, format.bits(), pair * PAIR_LANES + 1),
                        )
                    }
                };
                let outcome =
                    minmax::evaluate(format, operation, state.fpcr, left_bits, right_bits)?;
                write_lane(&mut result, format.bits(), lane, outcome.bits);
                exceptions |= outcome.exceptions;
            }
        }
        Operand::PairwiseScalar { source, .. } => {
            let source = state.v[usize::from(source)];
            let outcome = minmax::evaluate(
                format,
                operation,
                state.fpcr,
                read_lane(&source, format.bits(), 0),
                read_lane(&source, format.bits(), 1),
            )?;
            write_lane(&mut result, format.bits(), 0, outcome.bits);
            exceptions |= outcome.exceptions;
        }
        Operand::Reduction { shape, source, .. } => {
            let source = state.v[usize::from(source)];
            let mut lanes = shape.lane_count(format);
            let mut values = [0; MAX_REDUCTION_LANES];
            for (lane, value) in values.iter_mut().enumerate().take(lanes as usize) {
                *value = read_lane(&source, format.bits(), lane as u32);
            }
            // Adjacent pairs form each level of Arm's balanced reduction tree.
            // Intermediate NaN results and their exceptions must survive to
            // the next level; a left fold can choose a different final value.
            while lanes > 1 {
                for pair in 0..lanes / PAIR_LANES {
                    let outcome = minmax::evaluate(
                        format,
                        operation,
                        state.fpcr,
                        values[(pair * PAIR_LANES) as usize],
                        values[(pair * PAIR_LANES + 1) as usize],
                    )?;
                    values[pair as usize] = outcome.bits;
                    exceptions |= outcome.exceptions;
                }
                lanes /= PAIR_LANES;
            }
            write_lane(&mut result, format.bits(), 0, values[0]);
        }
    }
    state.v[usize::from(operand.destination())] = result;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::floating::{
        DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FZ, FPSR_QC,
        INEXACT, INPUT_DENORMAL, INVALID, OVERFLOW, UNDERFLOW, minmax::MinMaxOperation,
    };

    const LAST_VECTOR_REGISTER: u8 = 31;
    const SINGLE_ONE: u64 = 0x3f80_0000;
    const SINGLE_SNAN: u64 = 0x7f80_0001;
    const SINGLE_SNAN_PAIR: u64 = 0x7f80_0001_7f80_0001;

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
            fpcr: 0,
            fpsr: FPSR_QC,
        }
    }

    #[test]
    fn scalar_binary_snapshots_aliases_and_merges_original_left_under_nep() {
        for (format, one, two) in [
            (Format::Half, 0x3c00, 0x4000),
            (Format::Single, SINGLE_ONE, 0x4000_0000),
            (Format::Double, 0x3ff0_0000_0000_0000, 0x4000_0000_0000_0000),
        ] {
            for (operation, bits) in [
                (MinMaxOperation::Minimum, one),
                (MinMaxOperation::MinimumNumber, one),
                (MinMaxOperation::Maximum, two),
                (MinMaxOperation::MaximumNumber, two),
            ] {
                for nep in [false, true] {
                    for destination in [0, 1, LAST_VECTOR_REGISTER] {
                        let mut state = state();
                        state.fpcr = if nep { FPCR_NEP } else { 0 };
                        write_lane(
                            &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                            format.bits(),
                            0,
                            one,
                        );
                        write_lane(&mut state.v[1], format.bits(), 0, two);
                        let mut expected = state.clone();
                        let mut result = if nep {
                            state.v[usize::from(LAST_VECTOR_REGISTER)]
                        } else {
                            [0; VECTOR_LIMBS]
                        };
                        write_lane(&mut result, format.bits(), 0, bits);
                        expected.v[usize::from(destination)] = result;
                        let operand = Operand::Binary {
                            operation,
                            format,
                            shape: Shape::Scalar,
                            mode: BinaryMode::Elementwise,
                            destination,
                            left: LAST_VECTOR_REGISTER,
                            right: 1,
                        };
                        complete(&mut state, &operand).unwrap();
                        assert_eq!(state, expected, "{operand:?}, NEP={nep}");
                    }
                }
            }
        }
    }

    #[test]
    fn vector_pairwise_orders_each_source_half_and_ignores_inactive_nan_lanes() {
        for shape in [Shape::Vector64, Shape::Vector128] {
            for destination in [0, 1, LAST_VECTOR_REGISTER] {
                let mut state = state();
                state.fpcr = FPCR_NEP;
                state.v[usize::from(LAST_VECTOR_REGISTER)] =
                    [0x4080_0000_3f80_0000, 0x4040_0000_4000_0000];
                state.v[1] = [0x40c0_0000_40e0_0000, 0x4100_0000_40a0_0000];
                let result = if shape == Shape::Vector64 {
                    state.v[usize::from(LAST_VECTOR_REGISTER)][1] = SINGLE_SNAN_PAIR;
                    state.v[1][1] = SINGLE_SNAN_PAIR;
                    [0x40e0_0000_4080_0000, 0]
                } else {
                    [0x4040_0000_4080_0000, 0x4100_0000_40e0_0000]
                };
                let mut expected = state.clone();
                expected.v[usize::from(destination)] = result;
                let operand = Operand::Binary {
                    operation: MinMaxOperation::Maximum,
                    format: Format::Single,
                    shape,
                    mode: BinaryMode::Pairwise,
                    destination,
                    left: LAST_VECTOR_REGISTER,
                    right: 1,
                };
                complete(&mut state, &operand).unwrap();
                assert_eq!(state, expected, "{operand:?}");
            }
        }
    }

    #[test]
    fn pairwise_scalar_consumes_only_first_two_lanes_and_clears_other_destination_bits() {
        for (format, one, two, snan) in [
            (Format::Half, 0x3c00, 0x4000, 0x7c01),
            (Format::Single, SINGLE_ONE, 0x4000_0000, SINGLE_SNAN),
            (
                Format::Double,
                0x3ff0_0000_0000_0000,
                0x4000_0000_0000_0000,
                0x7ff0_0000_0000_0001,
            ),
        ] {
            let mut state = state();
            state.fpcr = FPCR_NEP;
            for lane in 0..Shape::Vector128.lane_count(format) {
                let bits = match lane {
                    0 => one,
                    1 => two,
                    _ => snan,
                };
                write_lane(
                    &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                    format.bits(),
                    lane,
                    bits,
                );
            }
            let mut expected = state.clone();
            expected.v[usize::from(LAST_VECTOR_REGISTER)] = [two, 0];
            let operand = Operand::PairwiseScalar {
                operation: MinMaxOperation::Maximum,
                format,
                destination: LAST_VECTOR_REGISTER,
                source: LAST_VECTOR_REGISTER,
            };
            complete(&mut state, &operand).unwrap();
            assert_eq!(state, expected, "{operand:?}");
        }
    }

    #[test]
    fn number_reductions_use_balanced_tree_and_preserve_intermediate_invalid_status() {
        for (format, shape, minimum_lanes, maximum_lanes, minimum, maximum) in [
            (
                Format::Single,
                Shape::Vector128,
                [
                    SINGLE_SNAN,
                    0x3f80_0000,
                    0x4000_0000,
                    0x4040_0000,
                    0,
                    0,
                    0,
                    0,
                ],
                [
                    SINGLE_SNAN,
                    0x40e0_0000,
                    0x40c0_0000,
                    0x40a0_0000,
                    0,
                    0,
                    0,
                    0,
                ],
                0x4000_0000,
                0x40c0_0000,
            ),
            (
                Format::Half,
                Shape::Vector64,
                [0x7c01, 0x3c00, 0x4000, 0x4200, 0, 0, 0, 0],
                [0x7c01, 0x4700, 0x4600, 0x4500, 0, 0, 0, 0],
                0x4000,
                0x4600,
            ),
            (
                Format::Half,
                Shape::Vector128,
                [
                    0x7c01, 0x3c00, 0x4000, 0x4200, 0x4400, 0x4500, 0x4600, 0x4700,
                ],
                [
                    0x7c01, 0x4700, 0x4600, 0x4500, 0x3c00, 0x4000, 0x4200, 0x4400,
                ],
                0x4000,
                0x4600,
            ),
        ] {
            for (operation, lanes, bits) in [
                (MinMaxOperation::MinimumNumber, minimum_lanes, minimum),
                (MinMaxOperation::MaximumNumber, maximum_lanes, maximum),
            ] {
                let mut state = state();
                state.fpcr = FPCR_NEP;
                for lane in 0..shape.lane_count(format) {
                    write_lane(
                        &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                        format.bits(),
                        lane,
                        lanes[lane as usize],
                    );
                }
                let mut expected = state.clone();
                expected.v[usize::from(LAST_VECTOR_REGISTER)] = [bits, 0];
                expected.fpsr |= INVALID;
                let operand = Operand::Reduction {
                    operation,
                    format,
                    shape,
                    destination: LAST_VECTOR_REGISTER,
                    source: LAST_VECTOR_REGISTER,
                };
                complete(&mut state, &operand).unwrap();
                assert_eq!(state, expected, "{operand:?}");
            }
        }
    }

    #[test]
    fn reduction_unions_flushing_denormal_and_nan_status_from_different_children() {
        let mut state = state();
        state.fpcr = FPCR_AH | FPCR_FZ | FPCR_NEP;
        state.v[usize::from(LAST_VECTOR_REGISTER)] = [0x0000_0002_0000_0001, 0x3f80_0000_7f80_0001];
        let mut expected = state.clone();
        expected.v[usize::from(LAST_VECTOR_REGISTER)] = [0; VECTOR_LIMBS];
        expected.fpsr |= INVALID | UNDERFLOW | INEXACT | INPUT_DENORMAL;
        let operand = Operand::Reduction {
            operation: MinMaxOperation::MinimumNumber,
            format: Format::Single,
            shape: Shape::Vector128,
            destination: LAST_VECTOR_REGISTER,
            source: LAST_VECTOR_REGISTER,
        };
        complete(&mut state, &operand).unwrap();
        assert_eq!(state, expected);
    }

    #[test]
    fn enabled_exceptions_decline_all_shapes_before_any_register_or_status_commit() {
        let operands = [
            Operand::Binary {
                operation: MinMaxOperation::Minimum,
                format: Format::Single,
                shape: Shape::Scalar,
                mode: BinaryMode::Elementwise,
                destination: LAST_VECTOR_REGISTER,
                left: LAST_VECTOR_REGISTER,
                right: LAST_VECTOR_REGISTER,
            },
            Operand::Binary {
                operation: MinMaxOperation::Maximum,
                format: Format::Double,
                shape: Shape::Vector128,
                mode: BinaryMode::Pairwise,
                destination: LAST_VECTOR_REGISTER,
                left: LAST_VECTOR_REGISTER,
                right: LAST_VECTOR_REGISTER,
            },
            Operand::PairwiseScalar {
                operation: MinMaxOperation::MinimumNumber,
                format: Format::Half,
                destination: LAST_VECTOR_REGISTER,
                source: LAST_VECTOR_REGISTER,
            },
            Operand::Reduction {
                operation: MinMaxOperation::MaximumNumber,
                format: Format::Half,
                shape: Shape::Vector128,
                destination: LAST_VECTOR_REGISTER,
                source: LAST_VECTOR_REGISTER,
            },
        ];
        for enabled in [
            INVALID,
            DIVIDE_BY_ZERO,
            OVERFLOW,
            UNDERFLOW,
            INEXACT,
            INPUT_DENORMAL,
            EXCEPTIONS,
        ] {
            for operand in operands {
                let mut state = state();
                state.fpcr = FPCR_NEP | (enabled << FPCR_EXCEPTION_ENABLE_SHIFT);
                let expected = state.clone();
                assert_eq!(
                    complete(&mut state, &operand),
                    Err(UnsupportedControl {
                        enabled_exceptions: enabled
                    })
                );
                assert_eq!(state, expected, "{operand:?}");
            }
        }
    }
}
