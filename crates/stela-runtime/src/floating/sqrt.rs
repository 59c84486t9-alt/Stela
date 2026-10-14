//! Transactional scalar/vector square-root completion.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{FPCR_NEP, UnsupportedControl, sqrt},
        simd::{arithmetic::Shape, sqrt::Operand},
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let source = state.v[usize::from(operand.source)];
    let destination = state.v[usize::from(operand.destination)];
    let fpcr = state.fpcr;
    let mut result = if operand.shape == Shape::Scalar && fpcr & FPCR_NEP != 0 {
        destination
    } else {
        [0; VECTOR_LIMBS]
    };
    let mut exceptions = 0;
    for lane in 0..operand.shape.lane_count(operand.format) {
        let outcome = sqrt::evaluate(
            operand.format,
            fpcr,
            read_lane(&source, operand.format.bits(), lane),
        )?;
        write_lane(&mut result, operand.format.bits(), lane, outcome.bits);
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
        DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FIZ, FPCR_FZ,
        FPCR_FZ16, FPCR_ROUNDING_SHIFT, FPSR_QC, Format, INEXACT, INPUT_DENORMAL, INVALID,
        OVERFLOW, UNDERFLOW,
    };

    const LAST_VECTOR_REGISTER: u8 = 31;
    const ROUND_TIES_EVEN: u32 = 0;
    const ROUND_POSITIVE: u32 = 1;
    const ROUND_NEGATIVE: u32 = 2;
    const ROUND_ZERO: u32 = 3;
    const VALUES: [(Format, u64, u64, u64, u64); 3] = [
        (Format::Half, 0x3c00, 0x4000, 0x4400, 0x7e00),
        (
            Format::Single,
            0x3f80_0000,
            0x4000_0000,
            0x4080_0000,
            0x7fc0_0000,
        ),
        (
            Format::Double,
            0x3ff0_0000_0000_0000,
            0x4000_0000_0000_0000,
            0x4010_0000_0000_0000,
            0x7ff8_0000_0000_0000,
        ),
    ];

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
            fpsr: FPSR_QC | (1 << 31),
        }
    }

    #[test]
    fn scalar_nep_merges_original_destination_across_aliases_and_v31() {
        for (format, _, two, four, _) in VALUES {
            for nep in [false, true] {
                for (destination, source) in [
                    (0, LAST_VECTOR_REGISTER),
                    (LAST_VECTOR_REGISTER, 0),
                    (LAST_VECTOR_REGISTER, LAST_VECTOR_REGISTER),
                ] {
                    let mut state = state();
                    state.fpcr = if nep { FPCR_NEP } else { 0 };
                    write_lane(&mut state.v[usize::from(source)], format.bits(), 0, four);
                    let mut expected = state.clone();
                    let mut result = if nep {
                        state.v[usize::from(destination)]
                    } else {
                        [0; VECTOR_LIMBS]
                    };
                    write_lane(&mut result, format.bits(), 0, two);
                    expected.v[usize::from(destination)] = result;
                    let operand = Operand {
                        format,
                        shape: Shape::Scalar,
                        destination,
                        source,
                    };
                    complete(&mut state, &operand).unwrap();
                    assert_eq!(state, expected, "{operand:?}, NEP={nep}");
                }
            }
        }
    }

    #[test]
    fn live_rounding_and_significand_carry_work_in_every_arrangement() {
        for (format, _, two, four, _) in VALUES {
            for shape in [Shape::Scalar, Shape::Vector64, Shape::Vector128] {
                if format == Format::Double && shape == Shape::Vector64 {
                    continue;
                }
                for mode in [ROUND_TIES_EVEN, ROUND_POSITIVE, ROUND_NEGATIVE, ROUND_ZERO] {
                    let mut state = state();
                    state.fpcr = FPCR_NEP | (mode << FPCR_ROUNDING_SHIFT);
                    let mut expected_result = if shape == Shape::Scalar {
                        state.v[0]
                    } else {
                        [0; VECTOR_LIMBS]
                    };
                    for lane in 0..shape.lane_count(format) {
                        let exact = shape != Shape::Scalar && lane % 2 != 0;
                        let input = if exact { four } else { four - 1 };
                        let output = if exact || mode == ROUND_POSITIVE {
                            two
                        } else {
                            two - 1
                        };
                        write_lane(
                            &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                            format.bits(),
                            lane,
                            input,
                        );
                        write_lane(&mut expected_result, format.bits(), lane, output);
                    }
                    let mut expected = state.clone();
                    expected.v[0] = expected_result;
                    expected.fpsr |= INEXACT;
                    let operand = Operand {
                        format,
                        shape,
                        destination: 0,
                        source: LAST_VECTOR_REGISTER,
                    };
                    complete(&mut state, &operand).unwrap();
                    assert_eq!(state, expected, "{operand:?}, mode={mode}");
                }
            }
        }
    }

    #[test]
    fn positive_and_negative_denormals_take_distinct_ah_status_paths() {
        for (format, subnormal, root, default_nan) in [
            (Format::Single, 2, 0x1a80_0000, 0x7fc0_0000),
            (
                Format::Double,
                1,
                0x1e60_0000_0000_0000,
                0x7ff8_0000_0000_0000,
            ),
        ] {
            let sign = 1 << (format.bits() - 1);
            for (control, flush, input_status, positive_status) in [
                (0, false, 0, 0),
                (FPCR_AH, false, 0, INPUT_DENORMAL),
                (FPCR_AH | FPCR_FZ, false, 0, INPUT_DENORMAL),
                (FPCR_FZ, true, INPUT_DENORMAL, 0),
                (FPCR_FIZ, true, 0, 0),
                (FPCR_AH | FPCR_FIZ, true, 0, 0),
            ] {
                for negative in [false, true] {
                    let mut state = state();
                    state.fpcr = control | FPCR_NEP;
                    let input = subnormal | if negative { sign } else { 0 };
                    write_lane(
                        &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                        format.bits(),
                        0,
                        input,
                    );
                    let (bits, exceptions) = if flush {
                        (if negative { sign } else { 0 }, input_status)
                    } else if negative {
                        (
                            default_nan | if control & FPCR_AH != 0 { sign } else { 0 },
                            INVALID,
                        )
                    } else {
                        (root, positive_status)
                    };
                    let mut expected = state.clone();
                    write_lane(&mut expected.v[0], format.bits(), 0, bits);
                    expected.fpsr |= exceptions;
                    let operand = Operand {
                        format,
                        shape: Shape::Scalar,
                        destination: 0,
                        source: LAST_VECTOR_REGISTER,
                    };
                    complete(&mut state, &operand).unwrap();
                    assert_eq!(
                        state, expected,
                        "{operand:?}, control={control:#x}, negative={negative}"
                    );
                }
            }
        }
        for (control, negative, bits, exceptions) in [
            (FPCR_AH | FPCR_FIZ | FPCR_FZ, false, 0x0c00, 0),
            (FPCR_AH | FPCR_FIZ | FPCR_FZ, true, 0xfe00, INVALID),
            (FPCR_AH | FPCR_FZ16, false, 0, 0),
            (FPCR_AH | FPCR_FZ16, true, 0x8000, 0),
        ] {
            let mut state = state();
            state.fpcr = control;
            write_lane(
                &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                Format::Half.bits(),
                0,
                if negative { 0x8001 } else { 1 },
            );
            let mut expected = state.clone();
            expected.v[usize::from(LAST_VECTOR_REGISTER)] = [bits, 0];
            expected.fpsr |= exceptions;
            let operand = Operand {
                format: Format::Half,
                shape: Shape::Scalar,
                destination: LAST_VECTOR_REGISTER,
                source: LAST_VECTOR_REGISTER,
            };
            complete(&mut state, &operand).unwrap();
            assert_eq!(
                state, expected,
                "Half control={control:#x}, negative={negative}"
            );
        }
    }

    #[test]
    fn q0_ignores_upper_poison_and_preserves_active_negative_zero() {
        for (format, one, two, four, _) in VALUES {
            if format == Format::Double {
                continue;
            }
            let mut state = state();
            state.fpcr = FPCR_NEP;
            let sign = 1 << (format.bits() - 1);
            let inputs = [four, sign, one, 0];
            let outputs = [two, sign, one, 0];
            let mut result = [0; VECTOR_LIMBS];
            for lane in 0..Shape::Vector64.lane_count(format) {
                write_lane(
                    &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                    format.bits(),
                    lane,
                    inputs[lane as usize],
                );
                write_lane(&mut result, format.bits(), lane, outputs[lane as usize]);
            }
            state.v[usize::from(LAST_VECTOR_REGISTER)][1] = match format {
                Format::Half => 0xbc00_7c01_bc00_7c01,
                Format::Single => 0xbf80_0000_7f80_0001,
                Format::Double => unreachable!(),
            };
            let mut expected = state.clone();
            expected.v[usize::from(LAST_VECTOR_REGISTER)] = result;
            let operand = Operand {
                format,
                shape: Shape::Vector64,
                destination: LAST_VECTOR_REGISTER,
                source: LAST_VECTOR_REGISTER,
            };
            complete(&mut state, &operand).unwrap();
            assert_eq!(state, expected, "{operand:?}");
        }
    }

    #[test]
    fn vector_nan_invalid_and_inexact_lanes_commit_one_sticky_union() {
        let mut state = state();
        state.fpcr = FPCR_NEP;
        state.fpsr |= DIVIDE_BY_ZERO;
        state.v[usize::from(LAST_VECTOR_REGISTER)] = [0xbf80_0000_4080_0000, 0x4000_0000_7f80_0123];
        let mut expected = state.clone();
        expected.v[usize::from(LAST_VECTOR_REGISTER)] =
            [0x7fc0_0000_4000_0000, 0x3fb5_04f3_7fc0_0123];
        expected.fpsr |= INVALID | INEXACT;
        let operand = Operand {
            format: Format::Single,
            shape: Shape::Vector128,
            destination: LAST_VECTOR_REGISTER,
            source: LAST_VECTOR_REGISTER,
        };
        complete(&mut state, &operand).unwrap();
        assert_eq!(state, expected);
    }

    #[test]
    fn retained_enables_refuse_before_any_lane_or_status_commit() {
        for (format, _, _, four, _) in VALUES {
            for shape in [Shape::Scalar, Shape::Vector128] {
                for enabled in [
                    INVALID,
                    DIVIDE_BY_ZERO,
                    OVERFLOW,
                    UNDERFLOW,
                    INEXACT,
                    INPUT_DENORMAL,
                    EXCEPTIONS,
                ] {
                    let mut state = state();
                    state.fpcr = FPCR_NEP | (enabled << FPCR_EXCEPTION_ENABLE_SHIFT);
                    write_lane(
                        &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                        format.bits(),
                        0,
                        four,
                    );
                    let expected = state.clone();
                    let operand = Operand {
                        format,
                        shape,
                        destination: LAST_VECTOR_REGISTER,
                        source: LAST_VECTOR_REGISTER,
                    };
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
}
