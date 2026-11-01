//! Completion of NZCV and predicate comparisons.
use stela_compiler::{
    GuestState,
    aarch64::{
        flags::{NZCV_SHIFT, condition_holds},
        floating::{FPCR_NEP, Format, UnsupportedControl, comparison},
        simd::{
            arithmetic::Shape,
            comparison::{CompareSource, Operand},
        },
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

fn source(state: &GuestState, operand: CompareSource) -> [u64; VECTOR_LIMBS] {
    match operand {
        CompareSource::Register(register) => state.v[usize::from(register)],
        CompareSource::Zero => [0; VECTOR_LIMBS],
    }
}

fn complete_flags(
    state: &mut GuestState,
    format: Format,
    left: u8,
    right: CompareSource,
    signal_all_nans: bool,
) -> Result<(), UnsupportedControl> {
    let left = read_lane(&state.v[usize::from(left)], format.bits(), 0);
    let right = read_lane(&source(state, right), format.bits(), 0);
    let outcome = comparison::flags(format, signal_all_nans, state.fpcr, left, right)?;
    state.nzcv = outcome.nzcv;
    state.fpsr |= outcome.exceptions;
    Ok(())
}

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    match *operand {
        Operand::Flags {
            format,
            left,
            right,
            signal_all_nans,
        } => complete_flags(state, format, left, right, signal_all_nans),
        Operand::ConditionalFlags {
            format,
            left,
            right,
            signal_all_nans,
            condition,
            fallback,
        } => {
            if !condition_holds(condition, state.nzcv) {
                // A false condition does not execute FP arithmetic or inspect
                // exception enables, and leaves sticky status untouched.
                state.nzcv = u32::from(fallback) << NZCV_SHIFT;
                return Ok(());
            }
            complete_flags(
                state,
                format,
                left,
                CompareSource::Register(right),
                signal_all_nans,
            )
        }
        Operand::Predicate {
            operation,
            format,
            shape,
            destination,
            left,
            right,
        } => {
            let left = state.v[usize::from(left)];
            let right_value = source(state, right);
            let mut result = if shape == Shape::Scalar
                && matches!(right, CompareSource::Register(_))
                && state.fpcr & FPCR_NEP != 0
            {
                right_value
            } else {
                [0; VECTOR_LIMBS]
            };
            let mut exceptions = 0;
            for lane in 0..shape.lane_count(format) {
                let outcome = comparison::predicate(
                    format,
                    operation,
                    state.fpcr,
                    read_lane(&left, format.bits(), lane),
                    read_lane(&right_value, format.bits(), lane),
                )?;
                write_lane(&mut result, format.bits(), lane, outcome.bits);
                exceptions |= outcome.exceptions;
            }
            state.v[usize::from(destination)] = result;
            state.fpsr |= exceptions;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::{
        flags::{NZCV_C, NZCV_N, NZCV_V, NZCV_Z},
        floating::{
            DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_EXCEPTION_ENABLE_SHIFT, FPSR_QC, INEXACT,
            INPUT_DENORMAL, INVALID, OVERFLOW, UNDERFLOW, comparison::Predicate,
        },
    };

    const LAST_VECTOR_REGISTER: u8 = 31;
    const CONDITION_EQUAL: u8 = 0;
    const SINGLE_ONE: u64 = 0x3f80_0000;
    const SINGLE_TWO: u64 = 0x4000_0000;
    const SINGLE_QNAN: u64 = 0x7fc0_0001;
    const SINGLE_SNAN_PAIR: u64 = 0x7f80_0001_7f80_0001;

    fn state() -> GuestState {
        GuestState {
            x: std::array::from_fn(|index| 0x1234_5678_9abc_def0 ^ index as u64),
            sp: 0x1111_2222_3333_4444,
            nzcv: NZCV_N | NZCV_V,
            exclusive_bytes: 0xa5c3_9e71,
            exclusive_address: 0,
            exclusive_value: 0,
            daif: 0,
            pending: 0,
            v: std::array::from_fn(|index| {
                [
                    0x0123_4567_89ab_cdef ^ index as u64,
                    0xfedc_ba98_7654_3210 ^ index as u64,
                ]
            }),
            fpcr: 0,
            fpsr: FPSR_QC | INEXACT,
            ..Default::default()
        }
    }

    #[test]
    fn false_conditional_comparisons_bypass_all_enables_and_commit_only_fallback() {
        for fallback in 0..16 {
            for signal_all_nans in [false, true] {
                let mut state = state();
                state.fpcr = EXCEPTIONS << FPCR_EXCEPTION_ENABLE_SHIFT;
                state.v[0] = [SINGLE_SNAN_PAIR; VECTOR_LIMBS];
                state.v[usize::from(LAST_VECTOR_REGISTER)] = [SINGLE_SNAN_PAIR; VECTOR_LIMBS];
                let mut expected = state.clone();
                expected.nzcv = u32::from(fallback) << NZCV_SHIFT;
                let operand = Operand::ConditionalFlags {
                    format: Format::Single,
                    left: 0,
                    right: LAST_VECTOR_REGISTER,
                    signal_all_nans,
                    condition: CONDITION_EQUAL,
                    fallback,
                };
                complete(&mut state, &operand).unwrap();
                assert_eq!(state, expected, "{operand:?}");
            }
        }
    }

    #[test]
    fn flags_use_v31_or_zero_and_signal_quiet_nans_only_when_requested() {
        for (format, one, two, qnan) in [
            (Format::Half, 0x3c00, 0x4000, 0x7e01),
            (Format::Single, SINGLE_ONE, SINGLE_TWO, SINGLE_QNAN),
            (
                Format::Double,
                0x3ff0_0000_0000_0000,
                0x4000_0000_0000_0000,
                0x7ff8_0000_0000_0001,
            ),
        ] {
            for (left, right, signal_all_nans, nzcv, exceptions) in [
                (one, CompareSource::Register(0), false, NZCV_N, 0),
                (one, CompareSource::Zero, true, NZCV_C, 0),
                (qnan, CompareSource::Zero, false, NZCV_C | NZCV_V, 0),
                (qnan, CompareSource::Zero, true, NZCV_C | NZCV_V, INVALID),
            ] {
                let mut state = state();
                write_lane(
                    &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                    format.bits(),
                    0,
                    left,
                );
                write_lane(&mut state.v[0], format.bits(), 0, two);
                let mut expected = state.clone();
                expected.nzcv = nzcv;
                expected.fpsr |= exceptions;
                let operand = Operand::Flags {
                    format,
                    left: LAST_VECTOR_REGISTER,
                    right,
                    signal_all_nans,
                };
                complete(&mut state, &operand).unwrap();
                assert_eq!(state, expected, "{operand:?}");
            }
        }
        let mut state = state();
        state.nzcv = NZCV_Z;
        state.v[0][0] = SINGLE_ONE;
        state.v[usize::from(LAST_VECTOR_REGISTER)][0] = SINGLE_TWO;
        let mut expected = state.clone();
        expected.nzcv = NZCV_N;
        complete(
            &mut state,
            &Operand::ConditionalFlags {
                format: Format::Single,
                left: 0,
                right: LAST_VECTOR_REGISTER,
                signal_all_nans: false,
                condition: CONDITION_EQUAL,
                fallback: 15,
            },
        )
        .unwrap();
        assert_eq!(state, expected);
    }

    #[test]
    fn scalar_predicates_merge_original_right_but_zero_forms_clear_all_other_bits() {
        for nep in [false, true] {
            for destination in [0, 1, LAST_VECTOR_REGISTER] {
                for right in [CompareSource::Register(1), CompareSource::Zero] {
                    let mut state = state();
                    state.fpcr = if nep { FPCR_NEP } else { 0 };
                    write_lane(
                        &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                        Format::Single.bits(),
                        0,
                        SINGLE_TWO,
                    );
                    write_lane(&mut state.v[1], Format::Single.bits(), 0, SINGLE_ONE);
                    let mut expected = state.clone();
                    let mut result = if nep && matches!(right, CompareSource::Register(_)) {
                        state.v[1]
                    } else {
                        [0; VECTOR_LIMBS]
                    };
                    write_lane(&mut result, Format::Single.bits(), 0, u64::from(u32::MAX));
                    expected.v[usize::from(destination)] = result;
                    let operand = Operand::Predicate {
                        operation: Predicate::Greater,
                        format: Format::Single,
                        shape: Shape::Scalar,
                        destination,
                        left: LAST_VECTOR_REGISTER,
                        right,
                    };
                    complete(&mut state, &operand).unwrap();
                    assert_eq!(state, expected, "{operand:?}, NEP={nep}");
                }
            }
        }
    }

    #[test]
    fn vector_predicates_snapshot_aliases_union_status_and_ignore_inactive_lanes() {
        for destination in [0, 1, LAST_VECTOR_REGISTER] {
            let mut state = state();
            state.fpcr = FPCR_NEP;
            state.v[usize::from(LAST_VECTOR_REGISTER)] =
                [0x7fc0_0001_4000_0000, 0x0000_0000_bf80_0000];
            state.v[1] = [0x3f80_0000_3f80_0000, 0x8000_0000_3f80_0000];
            let mut expected = state.clone();
            expected.v[usize::from(destination)] = [0x0000_0000_ffff_ffff, 0xffff_ffff_0000_0000];
            expected.fpsr |= INVALID;
            complete(
                &mut state,
                &Operand::Predicate {
                    operation: Predicate::GreaterEqual,
                    format: Format::Single,
                    shape: Shape::Vector128,
                    destination,
                    left: LAST_VECTOR_REGISTER,
                    right: CompareSource::Register(1),
                },
            )
            .unwrap();
            assert_eq!(state, expected, "destination={destination}");
        }
        let mut state = state();
        state.fpcr = FPCR_NEP;
        state.v[usize::from(LAST_VECTOR_REGISTER)] = [0xbf80_0000_4000_0000, SINGLE_SNAN_PAIR];
        state.v[1] = [0x3f80_0000_3f80_0000, SINGLE_SNAN_PAIR];
        let mut expected = state.clone();
        expected.v[usize::from(LAST_VECTOR_REGISTER)] = [u64::from(u32::MAX), 0];
        complete(
            &mut state,
            &Operand::Predicate {
                operation: Predicate::Greater,
                format: Format::Single,
                shape: Shape::Vector64,
                destination: LAST_VECTOR_REGISTER,
                left: LAST_VECTOR_REGISTER,
                right: CompareSource::Register(1),
            },
        )
        .unwrap();
        assert_eq!(state, expected);
    }

    #[test]
    fn executed_comparisons_decline_enabled_exceptions_before_any_state_change() {
        let operands = [
            Operand::Flags {
                format: Format::Half,
                left: LAST_VECTOR_REGISTER,
                right: CompareSource::Zero,
                signal_all_nans: true,
            },
            Operand::ConditionalFlags {
                format: Format::Double,
                left: LAST_VECTOR_REGISTER,
                right: LAST_VECTOR_REGISTER,
                signal_all_nans: true,
                condition: CONDITION_EQUAL,
                fallback: 0,
            },
            Operand::Predicate {
                operation: Predicate::Equal,
                format: Format::Single,
                shape: Shape::Vector128,
                destination: LAST_VECTOR_REGISTER,
                left: LAST_VECTOR_REGISTER,
                right: CompareSource::Register(LAST_VECTOR_REGISTER),
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
                state.nzcv = NZCV_Z;
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
