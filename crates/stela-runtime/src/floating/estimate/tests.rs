use super::*;
use stela_compiler::aarch64::{
    floating::{
        DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, FPSR_QC, Format,
        INEXACT, INPUT_DENORMAL, INVALID, OVERFLOW, UNDERFLOW,
    },
    simd::estimate::Kind,
};

const LAST_VECTOR_REGISTER: u8 = 31;
const FLOATING_KINDS: [Kind; 3] = [
    Kind::Reciprocal,
    Kind::ReciprocalSquareRoot,
    Kind::ReciprocalExponent,
];
const VALUES: [(Format, u64, u64, u64); 3] = [
    (Format::Half, 0x7c00, 0x7c01, 0x7e01),
    (Format::Single, 0x7f80_0000, 0x7f80_0001, 0x7fc0_0001),
    (
        Format::Double,
        0x7ff0_0000_0000_0000,
        0x7ff0_0000_0000_0001,
        0x7ff8_0000_0000_0001,
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
fn scalar_nep_merges_old_destination_for_all_floating_kinds_and_aliases() {
    for kind in FLOATING_KINDS {
        for (format, infinity, _, _) in VALUES {
            for nep in [false, true] {
                for (destination, source) in [
                    (0, LAST_VECTOR_REGISTER),
                    (LAST_VECTOR_REGISTER, 0),
                    (LAST_VECTOR_REGISTER, LAST_VECTOR_REGISTER),
                ] {
                    let mut state = state();
                    state.fpcr = if nep { FPCR_NEP } else { 0 };
                    write_lane(
                        &mut state.v[usize::from(source)],
                        format.bits(),
                        0,
                        infinity,
                    );
                    let mut expected = state.clone();
                    let mut result = if nep {
                        state.v[usize::from(destination)]
                    } else {
                        [0; VECTOR_LIMBS]
                    };
                    write_lane(&mut result, format.bits(), 0, 0);
                    expected.v[usize::from(destination)] = result;
                    let operand = Operand {
                        kind,
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
}

#[test]
fn vector_active_zero_and_snan_lanes_commit_one_sticky_status_union() {
    for kind in [Kind::Reciprocal, Kind::ReciprocalSquareRoot] {
        for (format, infinity, signaling, quiet) in VALUES {
            for shape in [Shape::Vector64, Shape::Vector128] {
                if format == Format::Double && shape == Shape::Vector64 {
                    continue;
                }
                let mut state = state();
                state.fpcr = FPCR_NEP;
                let count = shape.lane_count(format);
                let mut result = [0; VECTOR_LIMBS];
                for lane in 0..count {
                    let (input, output) = if lane == 0 {
                        (0, infinity)
                    } else if lane + 1 == count {
                        (signaling, quiet)
                    } else {
                        (infinity, 0)
                    };
                    write_lane(
                        &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                        format.bits(),
                        lane,
                        input,
                    );
                    write_lane(&mut result, format.bits(), lane, output);
                }
                let mut expected = state.clone();
                expected.v[usize::from(LAST_VECTOR_REGISTER)] = result;
                expected.fpsr |= DIVIDE_BY_ZERO | INVALID;
                let operand = Operand {
                    kind,
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
}

#[test]
fn q0_never_evaluates_poisoned_inactive_lanes() {
    for kind in [Kind::Reciprocal, Kind::ReciprocalSquareRoot] {
        for (format, infinity, signaling, _) in VALUES {
            if format == Format::Double {
                continue;
            }
            let mut state = state();
            state.fpcr = FPCR_NEP;
            for lane in 0..Shape::Vector128.lane_count(format) {
                write_lane(
                    &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                    format.bits(),
                    lane,
                    if lane < Shape::Vector64.lane_count(format) {
                        infinity
                    } else {
                        signaling
                    },
                );
            }
            let mut expected = state.clone();
            expected.v[usize::from(LAST_VECTOR_REGISTER)] = [0; VECTOR_LIMBS];
            let operand = Operand {
                kind,
                format,
                shape: Shape::Vector64,
                destination: LAST_VECTOR_REGISTER,
                source: LAST_VECTOR_REGISTER,
            };
            complete(&mut state, &operand).unwrap();
            assert_eq!(state, expected, "{operand:?}");
        }
    }
}

#[test]
fn ah1_accepts_retained_enables_and_preserves_every_existing_status_bit() {
    for kind in FLOATING_KINDS {
        for (format, infinity, signaling, quiet) in VALUES {
            for shape in [Shape::Scalar, Shape::Vector128] {
                if kind == Kind::ReciprocalExponent && shape != Shape::Scalar {
                    continue;
                }
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
                    state.fpcr =
                        FPCR_AH | FPCR_DN | FPCR_NEP | (enabled << FPCR_EXCEPTION_ENABLE_SHIFT);
                    let mut result = if shape == Shape::Scalar {
                        state.v[0]
                    } else {
                        [0; VECTOR_LIMBS]
                    };
                    let default_nan = infinity | (1 << (format.bits() - 1)) | (quiet ^ signaling);
                    for lane in 0..shape.lane_count(format) {
                        write_lane(
                            &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                            format.bits(),
                            lane,
                            signaling,
                        );
                        write_lane(&mut result, format.bits(), lane, default_nan);
                    }
                    let mut expected = state.clone();
                    expected.v[0] = result;
                    let operand = Operand {
                        kind,
                        format,
                        shape,
                        destination: 0,
                        source: LAST_VECTOR_REGISTER,
                    };
                    complete(&mut state, &operand).unwrap();
                    assert_eq!(state, expected, "{operand:?}, enables={enabled:#x}");
                }
            }
        }
    }
}

#[test]
fn unsigned_estimates_ignore_all_controls_and_preserve_fpsr() {
    for kind in [Kind::UnsignedReciprocal, Kind::UnsignedReciprocalSquareRoot] {
        for shape in [Shape::Vector64, Shape::Vector128] {
            for controls in [0, FPCR_NEP, u32::MAX] {
                let mut state = state();
                state.fpcr = controls;
                state.fpsr = u32::MAX;
                state.v[usize::from(LAST_VECTOR_REGISTER)] =
                    [0x3fff_ffff_0000_0000, 0xff80_0000_ffff_ffff];
                let mut expected = state.clone();
                expected.v[usize::from(LAST_VECTOR_REGISTER)] = [
                    u64::MAX,
                    if shape == Shape::Vector128 {
                        0x8000_0000_8000_0000
                    } else {
                        0
                    },
                ];
                let operand = Operand {
                    kind,
                    format: Format::Single,
                    shape,
                    destination: LAST_VECTOR_REGISTER,
                    source: LAST_VECTOR_REGISTER,
                };
                complete(&mut state, &operand).unwrap();
                assert_eq!(state, expected, "{operand:?}, controls={controls:#x}");
            }
        }
    }
}

#[test]
fn ah0_enable_refusal_preserves_the_complete_pre_instruction_state() {
    for kind in FLOATING_KINDS {
        for (format, _, signaling, _) in VALUES {
            for shape in [Shape::Scalar, Shape::Vector128] {
                if kind == Kind::ReciprocalExponent && shape != Shape::Scalar {
                    continue;
                }
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
                        signaling,
                    );
                    let expected = state.clone();
                    let operand = Operand {
                        kind,
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
