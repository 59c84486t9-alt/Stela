use super::*;
use stela_compiler::aarch64::{
    floating::{
        DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FIZ, FPCR_FZ,
        FPCR_FZ16, FPCR_ROUNDING_SHIFT, FPSR_QC, Format, INEXACT, INPUT_DENORMAL, INVALID,
        OVERFLOW, UNDERFLOW,
    },
    simd::refinement::Kind,
};

const LAST_VECTOR_REGISTER: u8 = 31;
const ROUND_POSITIVE: u32 = 1;
const ROUND_NEGATIVE: u32 = 2;
const KINDS: [Kind; 2] = [Kind::Reciprocal, Kind::ReciprocalSquareRoot];
const VALUES: [(Format, u64, u64, u64, u64, u64); 3] = [
    (Format::Half, 0x3c00, 0x4000, 0x4200, 0x3e00, 0x7c00),
    (
        Format::Single,
        0x3f80_0000,
        0x4000_0000,
        0x4040_0000,
        0x3fc0_0000,
        0x7f80_0000,
    ),
    (
        Format::Double,
        0x3ff0_0000_0000_0000,
        0x4000_0000_0000_0000,
        0x4008_0000_0000_0000,
        0x3ff8_0000_0000_0000,
        0x7ff0_0000_0000_0000,
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
        fpsr: FPSR_QC | UNDERFLOW | (1 << 31),
    }
}

#[test]
fn scalar_nep_uses_original_left_source_for_every_alias_role() {
    for kind in KINDS {
        for (format, one, _, _, _, _) in VALUES {
            for nep in [false, true] {
                for (destination, left, right) in [
                    (0, 1, LAST_VECTOR_REGISTER),
                    (LAST_VECTOR_REGISTER, 0, 1),
                    (0, 0, LAST_VECTOR_REGISTER),
                    (LAST_VECTOR_REGISTER, 0, LAST_VECTOR_REGISTER),
                    (
                        LAST_VECTOR_REGISTER,
                        LAST_VECTOR_REGISTER,
                        LAST_VECTOR_REGISTER,
                    ),
                ] {
                    let mut state = state();
                    state.fpcr = if nep { FPCR_NEP } else { 0 };
                    write_lane(&mut state.v[usize::from(left)], format.bits(), 0, one);
                    write_lane(&mut state.v[usize::from(right)], format.bits(), 0, one);
                    let mut expected = state.clone();
                    let mut result = if nep {
                        state.v[usize::from(left)]
                    } else {
                        [0; VECTOR_LIMBS]
                    };
                    write_lane(&mut result, format.bits(), 0, one);
                    expected.v[usize::from(destination)] = result;
                    let operand = Operand {
                        kind,
                        format,
                        shape: Shape::Scalar,
                        destination,
                        left,
                        right,
                    };
                    complete(&mut state, &operand).unwrap();
                    assert_eq!(state, expected, "{operand:?}, NEP={nep}");
                }
            }
        }
    }
}

#[test]
fn vector_special_cases_ignore_inactive_nan_poison_and_clear_q0_upper_half() {
    for kind in KINDS {
        for (format, _, two, _, one_half, infinity) in VALUES {
            for shape in [Shape::Vector64, Shape::Vector128] {
                if format == Format::Double && shape == Shape::Vector64 {
                    continue;
                }
                let mut state = state();
                state.fpcr = FPCR_NEP;
                let mut result = [0; VECTOR_LIMBS];
                for lane in 0..Shape::Vector128.lane_count(format) {
                    let active = lane < shape.lane_count(format);
                    write_lane(
                        &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                        format.bits(),
                        lane,
                        if active { 0 } else { infinity | 1 },
                    );
                    write_lane(&mut state.v[1], format.bits(), lane, infinity);
                    if active {
                        write_lane(
                            &mut result,
                            format.bits(),
                            lane,
                            if kind == Kind::Reciprocal {
                                two
                            } else {
                                one_half
                            },
                        );
                    }
                }
                let mut expected = state.clone();
                expected.v[usize::from(LAST_VECTOR_REGISTER)] = result;
                let operand = Operand {
                    kind,
                    format,
                    shape,
                    destination: LAST_VECTOR_REGISTER,
                    left: LAST_VECTOR_REGISTER,
                    right: 1,
                };
                complete(&mut state, &operand).unwrap();
                assert_eq!(state, expected, "{operand:?}");
            }
        }
    }
}

#[test]
fn mixed_vector_lanes_preserve_nan_negation_and_commit_fresh_status_once() {
    for kind in KINDS {
        for ah in [0, FPCR_AH] {
            for rounding in 0..4 {
                let mut state = state();
                state.fpcr = FPCR_NEP | ah | (rounding << FPCR_ROUNDING_SHIFT);
                state.v[usize::from(LAST_VECTOR_REGISTER)] =
                    [0x3f80_0001_7f80_0123, 0x3f80_0000_7f80_0000];
                state.v[1] = [0x3f7f_fffe_3f80_0000, 0x3f80_0000_0000_0000];
                let mut expected = state.clone();
                let selected_nan = if ah == 0 { 0xffc0_0123 } else { 0x7fc0_0123 };
                let rounded = if ah == 0 && rounding == ROUND_POSITIVE {
                    0x3f80_0001
                } else {
                    0x3f80_0000
                };
                let special = if kind == Kind::Reciprocal {
                    0x4000_0000
                } else {
                    0x3fc0_0000
                };
                expected.v[usize::from(LAST_VECTOR_REGISTER)] = [
                    selected_nan | (rounded << 32),
                    special | (0x3f80_0000 << 32),
                ];
                if ah == 0 {
                    expected.fpsr |= INVALID | INEXACT;
                }
                let operand = Operand {
                    kind,
                    format: Format::Single,
                    shape: Shape::Vector128,
                    destination: LAST_VECTOR_REGISTER,
                    left: LAST_VECTOR_REGISTER,
                    right: 1,
                };
                complete(&mut state, &operand).unwrap();
                assert_eq!(
                    state, expected,
                    "{operand:?}, AH={ah:#x}, rounding={rounding}"
                );
            }
        }
    }
}

#[test]
fn exact_cancellation_obeys_effective_rounding_and_source_merge() {
    for kind in KINDS {
        for (format, one, two, three, _, _) in VALUES {
            for ah in [0, FPCR_AH] {
                for rounding in 0..4 {
                    let mut state = state();
                    state.fpcr = FPCR_NEP | ah | (rounding << FPCR_ROUNDING_SHIFT);
                    write_lane(
                        &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                        format.bits(),
                        0,
                        one,
                    );
                    write_lane(
                        &mut state.v[1],
                        format.bits(),
                        0,
                        if kind == Kind::Reciprocal { two } else { three },
                    );
                    let mut expected = state.clone();
                    let mut result = state.v[usize::from(LAST_VECTOR_REGISTER)];
                    write_lane(
                        &mut result,
                        format.bits(),
                        0,
                        if ah == 0 && rounding == ROUND_NEGATIVE {
                            1 << (format.bits() - 1)
                        } else {
                            0
                        },
                    );
                    expected.v[0] = result;
                    let operand = Operand {
                        kind,
                        format,
                        shape: Shape::Scalar,
                        destination: 0,
                        left: LAST_VECTOR_REGISTER,
                        right: 1,
                    };
                    complete(&mut state, &operand).unwrap();
                    assert_eq!(
                        state, expected,
                        "{operand:?}, AH={ah:#x}, rounding={rounding}"
                    );
                }
            }
        }
    }
}

#[test]
fn half_fz16_is_independent_of_ah_for_zero_times_infinity_special_case() {
    for kind in KINDS {
        for flush in [false, true] {
            let mut state = state();
            state.fpcr = FPCR_AH
                | (EXCEPTIONS << FPCR_EXCEPTION_ENABLE_SHIFT)
                | if flush { FPCR_FZ16 } else { 0 };
            write_lane(
                &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                Format::Half.bits(),
                0,
                1,
            );
            write_lane(&mut state.v[1], Format::Half.bits(), 0, 0x7c00);
            let mut expected = state.clone();
            expected.v[0] = [
                if flush {
                    if kind == Kind::Reciprocal {
                        0x4000
                    } else {
                        0x3e00
                    }
                } else {
                    0xfc00
                },
                0,
            ];
            let operand = Operand {
                kind,
                format: Format::Half,
                shape: Shape::Scalar,
                destination: 0,
                left: LAST_VECTOR_REGISTER,
                right: 1,
            };
            complete(&mut state, &operand).unwrap();
            assert_eq!(state, expected, "{operand:?}, FZ16={flush}");
        }
    }
}

#[test]
fn sd_input_flush_status_remains_separate_from_refinement_arithmetic() {
    for kind in KINDS {
        for (format, _, two, _, one_half, infinity) in VALUES {
            if format == Format::Half {
                continue;
            }
            for (control, flushed, exceptions) in [
                (0, false, 0),
                (FPCR_FZ, true, INPUT_DENORMAL),
                (FPCR_FIZ, true, 0),
                (FPCR_AH, true, 0),
                (FPCR_AH | FPCR_FZ, true, 0),
            ] {
                let mut state = state();
                state.fpcr = control;
                write_lane(
                    &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                    format.bits(),
                    0,
                    1,
                );
                write_lane(&mut state.v[1], format.bits(), 0, infinity);
                let mut expected = state.clone();
                expected.v[0] = [
                    if flushed {
                        if kind == Kind::Reciprocal {
                            two
                        } else {
                            one_half
                        }
                    } else {
                        infinity | (1 << (format.bits() - 1))
                    },
                    0,
                ];
                expected.fpsr |= exceptions;
                let operand = Operand {
                    kind,
                    format,
                    shape: Shape::Scalar,
                    destination: 0,
                    left: LAST_VECTOR_REGISTER,
                    right: 1,
                };
                complete(&mut state, &operand).unwrap();
                assert_eq!(state, expected, "{operand:?}, control={control:#x}");
            }
        }
    }
}

#[test]
fn tiny_half_outputs_flush_without_losing_prior_status_or_ah_suppression() {
    for (kind, left, right, tiny) in [
        (Kind::Reciprocal, 0x3c01, 0x3ffe, 0x0020),
        (Kind::ReciprocalSquareRoot, 0x3c02, 0x41fd, 0x0060),
    ] {
        for ah in [0, FPCR_AH] {
            for flush in [false, true] {
                let mut state = state();
                state.fpcr = FPCR_NEP | ah | if flush { FPCR_FZ16 } else { 0 };
                state.fpsr = FPSR_QC | DIVIDE_BY_ZERO;
                write_lane(
                    &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                    Format::Half.bits(),
                    0,
                    left,
                );
                write_lane(&mut state.v[1], Format::Half.bits(), 0, right);
                let mut expected = state.clone();
                write_lane(
                    &mut expected.v[usize::from(LAST_VECTOR_REGISTER)],
                    Format::Half.bits(),
                    0,
                    if flush { 0 } else { tiny },
                );
                if ah == 0 && flush {
                    expected.fpsr |= UNDERFLOW;
                }
                let operand = Operand {
                    kind,
                    format: Format::Half,
                    shape: Shape::Scalar,
                    destination: LAST_VECTOR_REGISTER,
                    left: LAST_VECTOR_REGISTER,
                    right: 1,
                };
                complete(&mut state, &operand).unwrap();
                assert_eq!(state, expected, "{operand:?}, AH={ah:#x}, FZ16={flush}");
            }
        }
    }
}

#[test]
fn ah0_refuses_and_ah1_accepts_each_kept_enable_without_status_loss() {
    for kind in KINDS {
        for (format, one, _, _, _, _) in VALUES {
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
                    for ah in [0, FPCR_AH] {
                        let mut state = state();
                        state.fpcr = FPCR_NEP | ah | (enabled << FPCR_EXCEPTION_ENABLE_SHIFT);
                        for lane in 0..shape.lane_count(format) {
                            write_lane(
                                &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                                format.bits(),
                                lane,
                                one,
                            );
                            write_lane(&mut state.v[1], format.bits(), lane, one);
                        }
                        let mut expected = state.clone();
                        let operand = Operand {
                            kind,
                            format,
                            shape,
                            destination: 0,
                            left: LAST_VECTOR_REGISTER,
                            right: 1,
                        };
                        if ah == 0 {
                            assert_eq!(
                                complete(&mut state, &operand),
                                Err(UnsupportedControl {
                                    enabled_exceptions: enabled
                                })
                            );
                        } else {
                            let mut result = if shape == Shape::Scalar {
                                state.v[usize::from(LAST_VECTOR_REGISTER)]
                            } else {
                                [0; VECTOR_LIMBS]
                            };
                            for lane in 0..shape.lane_count(format) {
                                write_lane(&mut result, format.bits(), lane, one);
                            }
                            expected.v[0] = result;
                            complete(&mut state, &operand).unwrap();
                        }
                        assert_eq!(
                            state, expected,
                            "{operand:?}, AH={ah:#x}, enables={enabled:#x}"
                        );
                    }
                }
            }
        }
    }
}
