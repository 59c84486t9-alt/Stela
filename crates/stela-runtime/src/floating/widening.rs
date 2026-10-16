//! Completion of FMLAL and FMLSL.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{Format, UnsupportedControl, widening},
        simd::widening::Operand,
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let addend = state.v[usize::from(operand.destination)];
    let left = state.v[usize::from(operand.left)];
    let right = state.v[usize::from(operand.right)];
    let fpcr = state.fpcr;
    let source_start = operand.part.source_lane_offset(operand.shape);
    let mut result = [0; VECTOR_LIMBS];
    let mut exceptions = 0;
    for lane in 0..operand.shape.lane_count(Format::Single) {
        let source_lane = source_start + lane;
        let right_lane = operand.right_lane.map_or(source_lane, u32::from);
        let outcome = widening::evaluate(
            operand.operation,
            fpcr,
            read_lane(&addend, Format::Single.bits(), lane) as u32,
            read_lane(&left, Format::Half.bits(), source_lane) as u16,
            read_lane(&right, Format::Half.bits(), right_lane) as u16,
        )?;
        write_lane(&mut result, Format::Single.bits(), lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(operand.destination)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::{
        floating::{
            DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_AHP, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FZ,
            FPCR_NEP, FPCR_ROUNDING_SHIFT, FPSR_QC, INEXACT, INPUT_DENORMAL, INVALID, OVERFLOW,
            UNDERFLOW, widening::WideningOperation,
        },
        simd::{arithmetic::Shape, widening::Part},
    };

    const LAST_VECTOR_REGISTER: u8 = 31;
    const LAST_INDEXED_REGISTER: u8 = 15;
    const FPSR_RESERVED_POISON: u32 = 1 << 31;
    const HALF_ONE: u64 = 0x3c00;
    const HALF_SIGNALING_NAN: u64 = 0x7c01;
    const HALF_MAXIMUM: u64 = 0x7bff;
    const SINGLE_ONE: u64 = 0x3f80_0000;
    const SINGLE_TWO: u64 = 0x4000_0000;
    const SINGLE_SIGNALING_NAN: u64 = 0x7f80_0001;
    const SINGLE_MAXIMUM: u64 = 0x7f7f_ffff;
    const SINGLE_SIGN: u64 = 0x8000_0000;
    const ROUND_POSITIVE: u32 = 1;
    const HALF_VALUES: [u64; 8] = [
        0x3c00, 0x4000, 0x4200, 0x4400, 0x4500, 0x4600, 0x4700, 0x4800,
    ];
    const SINGLE_VALUES: [u64; 8] = [
        0x3f80_0000,
        0x4000_0000,
        0x4040_0000,
        0x4080_0000,
        0x40a0_0000,
        0x40c0_0000,
        0x40e0_0000,
        0x4100_0000,
    ];
    const OPERATIONS: [WideningOperation; 2] =
        [WideningOperation::Add, WideningOperation::Subtract];
    const SHAPES: [Shape; 2] = [Shape::Vector64, Shape::Vector128];
    const PARTS: [Part; 2] = [Part::Lower, Part::Upper];

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
            fpsr: FPSR_QC | DIVIDE_BY_ZERO | FPSR_RESERVED_POISON,
        }
    }

    fn halves(value: u64) -> [u64; VECTOR_LIMBS] {
        let mut vector = [0; VECTOR_LIMBS];
        for lane in 0..Shape::Vector128.lane_count(Format::Half) {
            write_lane(&mut vector, Format::Half.bits(), lane, value);
        }
        vector
    }

    fn singles(values: &[u64]) -> [u64; VECTOR_LIMBS] {
        let mut vector = [0; VECTOR_LIMBS];
        for (lane, value) in values.iter().copied().enumerate() {
            write_lane(&mut vector, Format::Single.bits(), lane as u32, value);
        }
        vector
    }

    #[test]
    fn both_source_parts_follow_active_width_with_distinct_exact_lane_results() {
        for (shape, part, added, subtracted) in [
            (
                Shape::Vector64,
                Part::Lower,
                [0x4130_0000, 0x41b0_0000, 0, 0],
                [0x4110_0000, 0x4190_0000, 0, 0],
            ),
            (
                Shape::Vector64,
                Part::Upper,
                [0x4150_0000, 0x41c0_0000, 0, 0],
                [0x40e0_0000, 0x4180_0000, 0, 0],
            ),
            (
                Shape::Vector128,
                Part::Lower,
                [0x4130_0000, 0x41b0_0000, 0x4204_0000, 0x4230_0000],
                [0x4110_0000, 0x4190_0000, 0x41d8_0000, 0x4210_0000],
            ),
            (
                Shape::Vector128,
                Part::Upper,
                [0x4170_0000, 0x41d0_0000, 0x4214_0000, 0x4240_0000],
                [0x40a0_0000, 0x4160_0000, 0x41b8_0000, 0x4200_0000],
            ),
        ] {
            for operation in OPERATIONS {
                for ah in [0, FPCR_AH] {
                    let mut actual = state();
                    actual.fpcr |= ah | FPCR_AHP;
                    actual.v[usize::from(LAST_VECTOR_REGISTER)] =
                        singles(&[0x4120_0000, 0x41a0_0000, 0x41f0_0000, 0x4220_0000]); // Original Single accumulators: 10, 20, 30, 40.
                    actual.v[0] = [0x4400_4200_4000_3c00, 0x4800_4700_4600_4500];
                    actual.v[usize::from(LAST_INDEXED_REGISTER)] = halves(HALF_ONE);
                    let mut expected = actual.clone();
                    expected.v[usize::from(LAST_VECTOR_REGISTER)] =
                        singles(&if operation == WideningOperation::Add {
                            added
                        } else {
                            subtracted
                        });
                    let operand = Operand {
                        operation,
                        shape,
                        destination: LAST_VECTOR_REGISTER,
                        left: 0,
                        right: LAST_INDEXED_REGISTER,
                        right_lane: None,
                        part,
                    };
                    complete(&mut actual, &operand).unwrap();
                    assert_eq!(actual, expected, "{operand:?}, AH={ah:#x}");
                }
            }
        }
    }

    #[test]
    fn indexed_selection_reads_all_eight_half_lanes_and_ignores_source_poison() {
        for shape in SHAPES {
            for part in PARTS {
                for operation in OPERATIONS {
                    for (index, (half, single)) in
                        HALF_VALUES.into_iter().zip(SINGLE_VALUES).enumerate()
                    {
                        let mut actual = state();
                        actual.fpcr |= FPCR_AH;
                        actual.v[usize::from(LAST_VECTOR_REGISTER)] =
                            singles(&[0, 0, SINGLE_SIGNALING_NAN, SINGLE_SIGNALING_NAN]);
                        if shape == Shape::Vector128 {
                            actual.v[usize::from(LAST_VECTOR_REGISTER)] = [0; VECTOR_LIMBS];
                        }
                        actual.v[0] = halves(HALF_SIGNALING_NAN);
                        actual.v[usize::from(LAST_INDEXED_REGISTER)] = halves(HALF_SIGNALING_NAN);
                        let source_start = part.source_lane_offset(shape);
                        for lane in 0..shape.lane_count(Format::Single) {
                            write_lane(
                                &mut actual.v[0],
                                Format::Half.bits(),
                                source_start + lane,
                                HALF_ONE,
                            );
                        }
                        write_lane(
                            &mut actual.v[usize::from(LAST_INDEXED_REGISTER)],
                            Format::Half.bits(),
                            index as u32,
                            half,
                        );
                        let mut expected = actual.clone();
                        let value = single
                            | if operation == WideningOperation::Subtract {
                                SINGLE_SIGN
                            } else {
                                0
                            };
                        let mut result = [0; VECTOR_LIMBS];
                        for lane in 0..shape.lane_count(Format::Single) {
                            write_lane(&mut result, Format::Single.bits(), lane, value);
                        }
                        expected.v[usize::from(LAST_VECTOR_REGISTER)] = result;
                        let operand = Operand {
                            operation,
                            shape,
                            destination: LAST_VECTOR_REGISTER,
                            left: 0,
                            right: LAST_INDEXED_REGISTER,
                            right_lane: Some(index as u8),
                            part,
                        };
                        complete(&mut actual, &operand).unwrap();
                        assert_eq!(actual, expected, "{operand:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn aliased_accumulator_and_half_sources_are_snapshotted_before_any_lane_write() {
        // Adding 1 to Single lane 0 changes the Half lane 1 bit pattern. Reading
        // a later multiplicand from the destination would corrupt lane 1.
        for (destination, left, right) in [
            (
                LAST_VECTOR_REGISTER,
                LAST_VECTOR_REGISTER,
                LAST_INDEXED_REGISTER,
            ),
            (LAST_VECTOR_REGISTER, 0, LAST_VECTOR_REGISTER),
            (
                LAST_VECTOR_REGISTER,
                LAST_VECTOR_REGISTER,
                LAST_VECTOR_REGISTER,
            ),
        ] {
            let mut actual = state();
            actual.v[0] = halves(HALF_ONE);
            actual.v[usize::from(LAST_INDEXED_REGISTER)] = halves(HALF_ONE);
            actual.v[usize::from(LAST_VECTOR_REGISTER)] =
                [0x4000_3c00_3c00_3c00, 0x7c01_7c01_7c01_7c01];
            let mut expected = actual.clone();
            expected.v[usize::from(destination)] = [0x4040_3c00_3f81_0078, 0];
            let operand = Operand {
                operation: WideningOperation::Add,
                shape: Shape::Vector64,
                destination,
                left,
                right,
                right_lane: None,
                part: Part::Lower,
            };
            complete(&mut actual, &operand).unwrap();
            assert_eq!(actual, expected, "{operand:?}");
        }
    }

    #[test]
    fn indexed_right_alias_preserves_high_lane_until_every_q0_output_is_complete() {
        let mut actual = state();
        actual.v[usize::from(LAST_INDEXED_REGISTER)] = singles(&[
            SINGLE_ONE,
            SINGLE_TWO,
            SINGLE_SIGNALING_NAN,
            SINGLE_SIGNALING_NAN,
        ]);
        write_lane(
            &mut actual.v[usize::from(LAST_INDEXED_REGISTER)],
            Format::Half.bits(),
            7,
            0x4000,
        );
        actual.v[usize::from(LAST_VECTOR_REGISTER)] = halves(HALF_SIGNALING_NAN);
        for lane in [2, 3] {
            write_lane(
                &mut actual.v[usize::from(LAST_VECTOR_REGISTER)],
                Format::Half.bits(),
                lane,
                HALF_ONE,
            );
        }
        let mut expected = actual.clone();
        expected.v[usize::from(LAST_INDEXED_REGISTER)] = [0x4080_0000_4040_0000, 0];
        let operand = Operand {
            operation: WideningOperation::Add,
            shape: Shape::Vector64,
            destination: LAST_INDEXED_REGISTER,
            left: LAST_VECTOR_REGISTER,
            right: LAST_INDEXED_REGISTER,
            right_lane: Some(7),
            part: Part::Upper,
        };
        complete(&mut actual, &operand).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn mixed_lanes_commit_exception_union_once_and_retain_qc_and_existing_flags() {
        let mut actual = state();
        actual.fpcr |= FPCR_AH | FPCR_FZ | (ROUND_POSITIVE << FPCR_ROUNDING_SHIFT);
        actual.v[usize::from(LAST_VECTOR_REGISTER)] = singles(&[0, SINGLE_ONE, 1, SINGLE_MAXIMUM]);
        actual.v[0] = halves(HALF_SIGNALING_NAN);
        actual.v[usize::from(LAST_INDEXED_REGISTER)] = halves(HALF_SIGNALING_NAN);
        for (lane, left, right) in [
            (0, HALF_SIGNALING_NAN, HALF_ONE),
            (1, 1, 1),
            (2, 0, HALF_ONE),
            (3, HALF_MAXIMUM, HALF_MAXIMUM),
        ] {
            write_lane(&mut actual.v[0], Format::Half.bits(), lane, left);
            write_lane(
                &mut actual.v[usize::from(LAST_INDEXED_REGISTER)],
                Format::Half.bits(),
                lane,
                right,
            );
        }
        let mut expected = actual.clone();
        expected.v[usize::from(LAST_VECTOR_REGISTER)] =
            [0x3f80_0001_7fc0_2000, 0x7f80_0000_0000_0000];
        expected.fpsr |= INVALID | INEXACT | INPUT_DENORMAL | UNDERFLOW | OVERFLOW;
        let operand = Operand {
            operation: WideningOperation::Add,
            shape: Shape::Vector128,
            destination: LAST_VECTOR_REGISTER,
            left: 0,
            right: LAST_INDEXED_REGISTER,
            right_lane: None,
            part: Part::Lower,
        };
        complete(&mut actual, &operand).unwrap();
        assert_eq!(actual, expected);

        actual.v[usize::from(LAST_VECTOR_REGISTER)] = [0; VECTOR_LIMBS];
        actual.v[0] = halves(HALF_ONE);
        actual.v[usize::from(LAST_INDEXED_REGISTER)] = halves(HALF_ONE);
        let mut expected = actual.clone();
        expected.v[usize::from(LAST_VECTOR_REGISTER)] = singles(&[SINGLE_ONE; 4]);
        complete(&mut actual, &operand).unwrap();
        assert_eq!(
            actual, expected,
            "later exact instruction preserves sticky status"
        );
    }

    #[test]
    fn every_retained_enable_refuses_both_ah_modes_without_any_state_mutation() {
        for enabled in [
            INVALID,
            DIVIDE_BY_ZERO,
            OVERFLOW,
            UNDERFLOW,
            INEXACT,
            INPUT_DENORMAL,
            EXCEPTIONS,
        ] {
            for ah in [0, FPCR_AH] {
                for (operation, shape, part, right_lane) in [
                    (WideningOperation::Add, Shape::Vector64, Part::Lower, None),
                    (
                        WideningOperation::Subtract,
                        Shape::Vector64,
                        Part::Upper,
                        Some(7),
                    ),
                    (
                        WideningOperation::Subtract,
                        Shape::Vector128,
                        Part::Lower,
                        None,
                    ),
                    (
                        WideningOperation::Add,
                        Shape::Vector128,
                        Part::Upper,
                        Some(0),
                    ),
                ] {
                    let mut actual = state();
                    actual.fpcr |= ah | (enabled << FPCR_EXCEPTION_ENABLE_SHIFT);
                    let expected = actual.clone();
                    let operand = Operand {
                        operation,
                        shape,
                        destination: LAST_VECTOR_REGISTER,
                        left: LAST_VECTOR_REGISTER,
                        right: LAST_INDEXED_REGISTER,
                        right_lane,
                        part,
                    };
                    assert_eq!(
                        complete(&mut actual, &operand),
                        Err(UnsupportedControl {
                            enabled_exceptions: enabled
                        })
                    );
                    assert_eq!(
                        actual, expected,
                        "{operand:?}, AH={ah:#x}, enabled={enabled:#x}"
                    );
                }
            }
        }
    }
}
