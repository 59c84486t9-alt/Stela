//! Floating-point comparisons and predicate lanes.
use core::cmp::Ordering;

use super::{
    Class, Control, Format, INVALID, Outcome, UnsupportedControl, compare_operands,
    process_denormals, unpack,
};
use crate::aarch64::flags::{NZCV_C, NZCV_N, NZCV_V, NZCV_Z};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Predicate {
    Equal,
    GreaterEqual,
    Greater,
    LessEqual,
    Less,
    AbsoluteGreaterEqual,
    AbsoluteGreater,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagsOutcome {
    pub nzcv: u32,
    pub exceptions: u32,
}

fn compare(
    format: Format,
    signal_all_nans: bool,
    absolute: bool,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<(Option<Ordering>, u32), UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let mut exceptions = 0;
    let mut left = unpack(format, left, control, &mut exceptions);
    let mut right = unpack(format, right, control, &mut exceptions);
    if left.class.nan() || right.class.nan() {
        if signal_all_nans
            || left.class == Class::SignalingNaN
            || right.class == Class::SignalingNaN
        {
            exceptions |= INVALID;
        }
        // AH0 input flushing has already contributed IDC. The NaN branch
        // suppresses post-comparison AH1 denormal processing.
        return Ok((None, exceptions));
    }
    if absolute {
        // Arm FPAbs preserves NaN signs under AH1, without raising status.
        // NaNs have already returned, so clearing both remaining signs is
        // equivalent and preserves the unpacked denormal classes for IDC.
        left.bits &= !format.sign_mask();
        right.bits &= !format.sign_mask();
        left.negative = false;
        right.negative = false;
    }
    let ordering = compare_operands(left, right);
    process_denormals(format, control, left, right, &mut exceptions);
    Ok((Some(ordering), exceptions))
}

/// FCMP/E comparison outcome. Conditional instructions call this only when
/// their condition holds; false conditions bypass numerical enable checks.
pub fn flags(
    format: Format,
    signal_all_nans: bool,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<FlagsOutcome, UnsupportedControl> {
    let (ordering, exceptions) = compare(format, signal_all_nans, false, fpcr, left, right)?;
    let nzcv = match ordering {
        None => NZCV_C | NZCV_V,
        Some(Ordering::Less) => NZCV_N,
        Some(Ordering::Equal) => NZCV_Z | NZCV_C,
        Some(Ordering::Greater) => NZCV_C,
    };
    Ok(FlagsOutcome { nzcv, exceptions })
}

/// One scalar or vector predicate lane. EQ signals only SNaNs; all ordered
/// inequalities signal any NaN. Destination merging and sticky FPSR are caller duties.
pub fn predicate(
    format: Format,
    operation: Predicate,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<Outcome, UnsupportedControl> {
    let absolute = matches!(
        operation,
        Predicate::AbsoluteGreaterEqual | Predicate::AbsoluteGreater
    );
    let (ordering, exceptions) = compare(
        format,
        operation != Predicate::Equal,
        absolute,
        fpcr,
        left,
        right,
    )?;
    let passed = match operation {
        Predicate::Equal => ordering == Some(Ordering::Equal),
        Predicate::GreaterEqual | Predicate::AbsoluteGreaterEqual => {
            matches!(ordering, Some(Ordering::Greater | Ordering::Equal))
        }
        Predicate::Greater | Predicate::AbsoluteGreater => ordering == Some(Ordering::Greater),
        Predicate::LessEqual => matches!(ordering, Some(Ordering::Less | Ordering::Equal)),
        Predicate::Less => ordering == Some(Ordering::Less),
    };
    Ok(Outcome {
        bits: if passed {
            u64::MAX >> (u64::BITS - format.bits())
        } else {
            0
        },
        exceptions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::floating::{
        DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT,
        FPCR_FIZ, FPCR_FZ, FPCR_FZ16, FPCR_NEP, FPCR_ROUNDING_SHIFT, INEXACT, INPUT_DENORMAL,
        OVERFLOW, UNDERFLOW,
    };

    const PREDICATES: [Predicate; 7] = [
        Predicate::Equal,
        Predicate::GreaterEqual,
        Predicate::Greater,
        Predicate::LessEqual,
        Predicate::Less,
        Predicate::AbsoluteGreaterEqual,
        Predicate::AbsoluteGreater,
    ];
    const VALUES: [(Format, u64, u64); 3] = [
        (Format::Half, 0x3c00, 0x4000),
        (Format::Single, 0x3f800000, 0x40000000),
        (Format::Double, 0x3ff0000000000000, 0x4000000000000000),
    ];

    fn flag_result(format: Format, fpcr: u32, left: u64, right: u64) -> FlagsOutcome {
        flags(format, false, fpcr, left, right).unwrap()
    }

    #[test]
    fn flag_ordering_handles_both_zero_signs_negative_values_and_infinities() {
        for (format, one, two) in VALUES {
            let sign = format.sign_mask();
            let infinity = format.infinity(false);
            for (left, right, nzcv) in [
                (one, two, NZCV_N),
                (two, one, NZCV_C),
                (one, one, NZCV_Z | NZCV_C),
                (two | sign, one | sign, NZCV_N),
                (one | sign, two | sign, NZCV_C),
                (0, sign, NZCV_Z | NZCV_C),
                (sign, 0, NZCV_Z | NZCV_C),
                (infinity, infinity, NZCV_Z | NZCV_C),
                (infinity | sign, infinity | sign, NZCV_Z | NZCV_C),
                (infinity | sign, two | sign, NZCV_N),
                (infinity, two, NZCV_C),
            ] {
                assert_eq!(
                    flag_result(format, 0, left, right),
                    FlagsOutcome {
                        nzcv,
                        exceptions: 0
                    }
                );
            }
        }
    }

    #[test]
    fn predicate_masks_cover_relations_and_absolute_ordering() {
        for (format, one, two) in VALUES {
            let sign = format.sign_mask();
            let full_mask = u64::MAX >> (u64::BITS - format.bits());
            for (left, right, expected) in [
                (one, two, [false, false, false, true, true, false, false]),
                (one, one, [true, true, false, true, false, true, false]),
                (
                    two | sign,
                    one,
                    [false, false, false, true, true, true, true],
                ),
                (
                    one | sign,
                    two | sign,
                    [false, true, true, false, false, false, false],
                ),
                (sign, 0, [true, true, false, true, false, true, false]),
            ] {
                for (operation, passed) in PREDICATES.into_iter().zip(expected) {
                    assert_eq!(
                        predicate(format, operation, 0, left, right).unwrap(),
                        Outcome {
                            bits: if passed { full_mask } else { 0 },
                            exceptions: 0
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn quiet_and_signaling_nan_policies_remain_distinct() {
        for (format, one, _) in VALUES {
            let infinity = format.infinity(false);
            for negative in [false, true] {
                let sign = if negative { format.sign_mask() } else { 0 };
                for (nan, signaling) in [
                    (infinity | format.quiet_bit() | sign | 1, false),
                    (infinity | sign | 1, true),
                ] {
                    for (left, right) in [(nan, one), (one, nan), (nan, nan)] {
                        for signal_all in [false, true] {
                            assert_eq!(
                                flags(format, signal_all, FPCR_AH | FPCR_DN, left, right).unwrap(),
                                FlagsOutcome {
                                    nzcv: NZCV_C | NZCV_V,
                                    exceptions: if signaling || signal_all { INVALID } else { 0 }
                                }
                            );
                        }
                        for operation in PREDICATES {
                            assert_eq!(
                                predicate(format, operation, FPCR_AH | FPCR_DN, left, right)
                                    .unwrap(),
                                Outcome {
                                    bits: 0,
                                    exceptions: if signaling || operation != Predicate::Equal {
                                        INVALID
                                    } else {
                                        0
                                    }
                                }
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn nan_branch_suppresses_only_post_comparison_denormal_status() {
        for format in [Format::Single, Format::Double] {
            let quiet = format.infinity(false) | format.quiet_bit();
            for (left, right) in [(quiet, 1), (1, quiet)] {
                for (control, exceptions) in [
                    (FPCR_AH, 0),
                    (FPCR_AH | FPCR_FZ, 0),
                    (FPCR_FZ, INPUT_DENORMAL),
                    (FPCR_FZ | FPCR_FIZ, INPUT_DENORMAL),
                    (FPCR_FIZ, 0),
                ] {
                    assert_eq!(
                        flag_result(format, control, left, right),
                        FlagsOutcome {
                            nzcv: NZCV_C | NZCV_V,
                            exceptions
                        }
                    );
                    assert_eq!(
                        predicate(format, Predicate::Equal, control, left, right).unwrap(),
                        Outcome {
                            bits: 0,
                            exceptions
                        }
                    );
                    assert_eq!(
                        predicate(format, Predicate::GreaterEqual, control, left, right).unwrap(),
                        Outcome {
                            bits: 0,
                            exceptions: exceptions | INVALID
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn denormal_input_controls_change_order_and_status_without_rounding() {
        for format in [Format::Single, Format::Double] {
            for (control, nzcv, exceptions) in [
                (0, NZCV_C, 0),
                (FPCR_AH, NZCV_C, INPUT_DENORMAL),
                (FPCR_AH | FPCR_FZ, NZCV_C, INPUT_DENORMAL),
                (FPCR_FIZ, NZCV_Z | NZCV_C, 0),
                (FPCR_FZ, NZCV_Z | NZCV_C, INPUT_DENORMAL),
                (FPCR_FIZ | FPCR_FZ, NZCV_Z | NZCV_C, INPUT_DENORMAL),
            ] {
                assert_eq!(
                    flag_result(format, control, 1, 0),
                    FlagsOutcome { nzcv, exceptions }
                );
                assert_eq!(
                    predicate(
                        format,
                        Predicate::AbsoluteGreater,
                        control,
                        format.sign_mask() | 1,
                        0
                    )
                    .unwrap(),
                    Outcome {
                        bits: if nzcv == NZCV_C {
                            u64::MAX >> (u64::BITS - format.bits())
                        } else {
                            0
                        },
                        exceptions
                    }
                );
            }
        }
    }

    #[test]
    fn half_observes_fz16_and_ignores_alternative_half_representation() {
        assert_eq!(
            flag_result(Format::Half, FPCR_AHP, 0x7c00, 0x7bff),
            FlagsOutcome {
                nzcv: NZCV_C,
                exceptions: 0
            }
        );
        for (control, nzcv) in [
            (FPCR_FIZ | FPCR_FZ | FPCR_AH, NZCV_C),
            (FPCR_FZ16 | FPCR_AHP | FPCR_AH, NZCV_Z | NZCV_C),
        ] {
            assert_eq!(
                flag_result(Format::Half, control, 1, 0),
                FlagsOutcome {
                    nzcv,
                    exceptions: 0
                }
            );
        }
    }

    #[test]
    fn lane_width_and_irrelevant_controls_cannot_leak_into_comparison() {
        for (format, one, two) in VALUES {
            let mask = u64::MAX >> (u64::BITS - format.bits());
            for rounding in 0..4 {
                let control = FPCR_AHP | FPCR_DN | FPCR_NEP | (rounding << FPCR_ROUNDING_SHIFT);
                assert_eq!(
                    flag_result(format, control, one | !mask, two | !mask),
                    FlagsOutcome {
                        nzcv: NZCV_N,
                        exceptions: 0
                    }
                );
            }
        }
    }

    #[test]
    fn all_retained_enables_decline_even_for_exact_or_unordered_inputs() {
        for (format, one, _) in VALUES {
            for exception in [
                INVALID,
                DIVIDE_BY_ZERO,
                OVERFLOW,
                UNDERFLOW,
                INEXACT,
                INPUT_DENORMAL,
                EXCEPTIONS,
            ] {
                let control = exception << FPCR_EXCEPTION_ENABLE_SHIFT;
                let expected = UnsupportedControl {
                    enabled_exceptions: exception,
                };
                assert_eq!(flags(format, false, control, one, one), Err(expected));
                for operation in PREDICATES {
                    assert_eq!(
                        predicate(
                            format,
                            operation,
                            control,
                            format.infinity(false) | format.quiet_bit(),
                            one
                        ),
                        Err(expected)
                    );
                }
            }
        }
    }
}
