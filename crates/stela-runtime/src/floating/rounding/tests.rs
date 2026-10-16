use super::*;
use stela_compiler::aarch64::floating::{
    DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_ROUNDING_SHIFT, FPSR_QC, Format,
    INEXACT, INPUT_DENORMAL, INVALID, OVERFLOW, UNDERFLOW, rounding::RoundingOperation,
};

const LAST_VECTOR_REGISTER: u8 = 31;
const ROUND_TIES_EVEN: u32 = 0;
const ROUND_POSITIVE: u32 = 1;
const ROUND_NEGATIVE: u32 = 2;
const ROUND_ZERO: u32 = 3;
const VALUES: [(Format, u64, u64, u64, u64); 3] = [
    (Format::Half, 0x3c00, 0x4000, 0x3e00, 0x3400),
    (
        Format::Single,
        0x3f80_0000,
        0x4000_0000,
        0x3fc0_0000,
        0x3e80_0000,
    ),
    (
        Format::Double,
        0x3ff0_0000_0000_0000,
        0x4000_0000_0000_0000,
        0x3ff8_0000_0000_0000,
        0x3fd0_0000_0000_0000,
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
        fpsr: FPSR_QC | UNDERFLOW,
    }
}

#[test]
fn scalar_merging_uses_old_destination_for_distinct_and_aliased_sources() {
    for (format, one, _, fraction, _) in VALUES {
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
                    fraction,
                );
                let mut expected = state.clone();
                let mut result = if nep {
                    state.v[usize::from(destination)]
                } else {
                    [0; VECTOR_LIMBS]
                };
                write_lane(&mut result, format.bits(), 0, one);
                expected.v[usize::from(destination)] = result;
                let operand = Operand {
                    operation: RoundingOperation::TowardZero,
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
fn vectors_union_exact_status_preserve_zero_signs_and_ignore_inactive_nan_lanes() {
    for (format, one, _, fraction, quarter) in VALUES {
        for shape in [Shape::Vector64, Shape::Vector128] {
            if format == Format::Double && shape == Shape::Vector64 {
                continue;
            }
            let mut state = state();
            state.fpcr = FPCR_NEP | (ROUND_ZERO << FPCR_ROUNDING_SHIFT);
            let sign = 1 << (format.bits() - 1);
            let inputs = [fraction, fraction | sign, quarter, quarter | sign];
            let outputs = [one, one | sign, 0, sign];
            let mut result = [0; VECTOR_LIMBS];
            for lane in 0..shape.lane_count(format) {
                let index = lane as usize % inputs.len();
                write_lane(
                    &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                    format.bits(),
                    lane,
                    inputs[index],
                );
                write_lane(&mut result, format.bits(), lane, outputs[index]);
            }
            if shape == Shape::Vector64 {
                state.v[usize::from(LAST_VECTOR_REGISTER)][1] = match format {
                    Format::Half => 0x7c01_7c01_7c01_7c01,
                    Format::Single => 0x7f80_0001_7f80_0001,
                    Format::Double => unreachable!(),
                };
            }
            let mut expected = state.clone();
            expected.v[usize::from(LAST_VECTOR_REGISTER)] = result;
            expected.fpsr |= INEXACT;
            let operand = Operand {
                operation: RoundingOperation::CurrentExact,
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
fn current_rounding_reads_live_fpcr_and_distinguishes_requested_inexact_status() {
    for (format, one, two, fraction, _) in VALUES {
        for (operation, exceptions) in [
            (RoundingOperation::Current, 0),
            (RoundingOperation::CurrentExact, INEXACT),
        ] {
            for (mode, bits) in [
                (ROUND_TIES_EVEN, two),
                (ROUND_POSITIVE, two),
                (ROUND_NEGATIVE, one),
                (ROUND_ZERO, one),
            ] {
                let mut state = state();
                state.fpcr = mode << FPCR_ROUNDING_SHIFT;
                write_lane(
                    &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                    format.bits(),
                    0,
                    fraction,
                );
                let mut expected = state.clone();
                expected.v[0] = [bits, 0];
                expected.fpsr |= exceptions;
                let operand = Operand {
                    operation,
                    format,
                    shape: Shape::Scalar,
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
fn bounded_vector_keeps_valid_lane_inexact_when_other_lanes_are_invalid() {
    let mut state = state();
    state.fpcr = FPCR_NEP;
    state.v[usize::from(LAST_VECTOR_REGISTER)] = [0x4f00_0000_3fc0_0000, 0xbe80_0000_7fc0_0001];
    let mut expected = state.clone();
    expected.v[usize::from(LAST_VECTOR_REGISTER)] = [0xcf00_0000_3f80_0000, 0x8000_0000_cf00_0000];
    expected.fpsr |= INVALID | INEXACT;
    let operand = Operand {
        operation: RoundingOperation::Signed32Zero,
        format: Format::Single,
        shape: Shape::Vector128,
        destination: LAST_VECTOR_REGISTER,
        source: LAST_VECTOR_REGISTER,
    };
    complete(&mut state, &operand).unwrap();
    assert_eq!(state, expected);
}

#[test]
fn enabled_exceptions_decline_every_operation_without_any_state_mutation() {
    let operations = [
        RoundingOperation::NearestEven,
        RoundingOperation::NearestAway,
        RoundingOperation::TowardPositive,
        RoundingOperation::TowardNegative,
        RoundingOperation::TowardZero,
        RoundingOperation::Current,
        RoundingOperation::CurrentExact,
        RoundingOperation::Signed32Zero,
        RoundingOperation::Signed32Current,
        RoundingOperation::Signed64Zero,
        RoundingOperation::Signed64Current,
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
        for operation in operations {
            for shape in [Shape::Scalar, Shape::Vector128] {
                let mut state = state();
                state.fpcr = FPCR_NEP | (enabled << FPCR_EXCEPTION_ENABLE_SHIFT);
                state.v[usize::from(LAST_VECTOR_REGISTER)] =
                    [0x7f80_0001_3fc0_0000, 0x4f00_0000_0000_0000];
                let expected = state.clone();
                let operand = Operand {
                    operation,
                    format: Format::Single,
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
