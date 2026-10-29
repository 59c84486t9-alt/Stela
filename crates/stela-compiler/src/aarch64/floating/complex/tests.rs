use super::*;
use crate::aarch64::floating::{
    DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FIZ,
    FPCR_FZ, FPCR_FZ16, FPCR_NEP, FPCR_ROUNDING_SHIFT, INEXACT, INPUT_DENORMAL, INVALID, OVERFLOW,
    UNDERFLOW,
};

const FORMATS: [Format; 3] = [Format::Half, Format::Single, Format::Double];
const ROTATIONS: [Rotation; 4] = [
    Rotation::Degrees0,
    Rotation::Degrees90,
    Rotation::Degrees180,
    Rotation::Degrees270,
];
const ROUND_NEAREST: u32 = 0;
const ROUND_POSITIVE: u32 = 1;
const ROUND_NEGATIVE: u32 = 2;
const ROUND_ZERO: u32 = 3;
const ROUNDINGS: [u32; 4] = [ROUND_NEAREST, ROUND_POSITIVE, ROUND_NEGATIVE, ROUND_ZERO];

// Every expected integer here is small enough to encode exactly in H/S/D.
fn integer(format: Format, value: i32) -> u64 {
    if value == 0 {
        return 0;
    }
    let magnitude = u64::from(value.unsigned_abs());
    let exponent = magnitude.ilog2();
    let fraction = magnitude << (format.fraction_bits() - exponent);
    u64::from(format.exponent_bias() + exponent) << format.fraction_bits()
        | fraction & format.fraction_mask()
        | if value < 0 { format.sign_mask() } else { 0 }
}

fn outcome(bits: [u64; COMPONENTS], exceptions: u32) -> Result<PairOutcome, UnsupportedControl> {
    Ok(PairOutcome { bits, exceptions })
}

#[test]
fn rotation_selects_only_the_architectural_left_component() {
    for (rotation, component) in [
        (Rotation::Degrees0, REAL),
        (Rotation::Degrees90, IMAGINARY),
        (Rotation::Degrees180, REAL),
        (Rotation::Degrees270, IMAGINARY),
    ] {
        assert_eq!(rotation.left_component(), component);
    }
}

#[test]
fn asymmetric_integer_pairs_distinguish_every_rotation_and_role() {
    for format in FORMATS {
        let left = [integer(format, 2), integer(format, 3)];
        let right = [integer(format, 5), integer(format, 7)];
        let addend = [integer(format, 11), integer(format, 13)];
        for ah in [0, FPCR_AH] {
            for round in ROUNDINGS {
                let fpcr = ah | round << FPCR_ROUNDING_SHIFT;
                for (rotation, expected) in [
                    (Rotation::Degrees90, [-5, 8]),
                    (Rotation::Degrees270, [9, -2]),
                ] {
                    assert_eq!(
                        add_pair(format, rotation, fpcr, left, right),
                        outcome(expected.map(|value| integer(format, value)), 0)
                    );
                }
                for (rotation, expected) in [
                    (Rotation::Degrees0, [21, 27]),
                    (Rotation::Degrees90, [-10, 28]),
                    (Rotation::Degrees180, [1, -1]),
                    (Rotation::Degrees270, [32, -2]),
                ] {
                    assert_eq!(
                        multiply_add_pair(format, rotation, fpcr, addend, left, right),
                        outcome(expected.map(|value| integer(format, value)), 0)
                    );
                }
            }
        }
    }
}

#[test]
fn unselected_left_nan_infinity_and_denormal_cannot_affect_multiply_add() {
    for format in FORMATS {
        let right = [integer(format, 5), integer(format, 7)];
        let addend = [integer(format, 3), integer(format, 4)];
        for (rotation, expected) in [
            (Rotation::Degrees0, [13, 18]),
            (Rotation::Degrees90, [-11, 14]),
            (Rotation::Degrees180, [-7, -10]),
            (Rotation::Degrees270, [17, -6]),
        ] {
            for poison in [format.infinity(false) | 1, format.infinity(false), 1] {
                let mut left = [poison; COMPONENTS];
                left[rotation.left_component()] = integer(format, 2);
                for ah in [0, FPCR_AH] {
                    assert_eq!(
                        multiply_add_pair(
                            format,
                            rotation,
                            ah | FPCR_FIZ | FPCR_FZ | FPCR_FZ16,
                            addend,
                            left,
                            right
                        ),
                        outcome(expected.map(|value| integer(format, value)), 0)
                    );
                }
            }
        }
    }
}

#[test]
fn add_rotates_original_m_nan_sign_and_preserves_n_priority() {
    for format in FORMATS {
        let quiet_n = format.infinity(false) | format.quiet_bit() | 1;
        let signaling_m = format.infinity(true) | 2;
        let quiet_m = format.infinity(true) | format.quiet_bit() | 3;
        let left = [quiet_n, integer(format, 1)];
        let right = [quiet_m, signaling_m];
        for (rotation, ordinary_real, ordinary_imaginary) in [
            (
                Rotation::Degrees90,
                signaling_m ^ format.sign_mask() | format.quiet_bit(),
                quiet_m,
            ),
            (
                Rotation::Degrees270,
                signaling_m | format.quiet_bit(),
                quiet_m ^ format.sign_mask(),
            ),
        ] {
            assert_eq!(
                add_pair(format, rotation, 0, left, right),
                outcome([ordinary_real, ordinary_imaginary], INVALID)
            );
            assert_eq!(
                add_pair(format, rotation, FPCR_AH, left, right),
                outcome([quiet_n, quiet_m], INVALID)
            );
            for ah in [0, FPCR_AH] {
                let default = format.infinity(ah != 0) | format.quiet_bit();
                assert_eq!(
                    add_pair(format, rotation, ah | FPCR_DN, left, right),
                    outcome([default; COMPONENTS], INVALID)
                );
            }
        }
    }
}

#[test]
fn multiply_add_preserves_addend_n_m_nan_roles_after_rotation() {
    for format in FORMATS {
        let addend = [format.infinity(false) | 1, format.infinity(false) | 2];
        let quiet_n = format.infinity(true) | format.quiet_bit() | 3;
        let right = [
            format.infinity(false) | format.quiet_bit() | 4,
            format.infinity(false) | format.quiet_bit() | 5,
        ];
        for rotation in ROTATIONS {
            let mut left = [integer(format, 1); COMPONENTS];
            left[rotation.left_component()] = quiet_n;
            assert_eq!(
                multiply_add_pair(format, rotation, 0, addend, left, right),
                outcome(addend.map(|bits| bits | format.quiet_bit()), INVALID)
            );
            assert_eq!(
                multiply_add_pair(format, rotation, FPCR_AH, addend, left, right),
                outcome([quiet_n; COMPONENTS], INVALID)
            );
        }
    }
}

#[test]
fn quiet_addend_invalid_product_override_is_not_suppressed_under_ordinary_mode() {
    for format in FORMATS {
        let quiet_addend = format.infinity(false) | format.quiet_bit() | 7;
        let addend = [quiet_addend, integer(format, 1)];
        let left = [format.infinity(false) | 1, 0];
        let right = [0, format.infinity(true)];
        assert_eq!(
            multiply_add_pair(format, Rotation::Degrees90, 0, addend, left, right),
            outcome(
                [
                    format.infinity(false) | format.quiet_bit(),
                    integer(format, 1)
                ],
                INVALID
            )
        );
        assert_eq!(
            multiply_add_pair(format, Rotation::Degrees90, FPCR_AH, addend, left, right),
            outcome([quiet_addend, integer(format, 1)], 0)
        );
    }
}

#[test]
fn each_component_unions_fresh_status_without_alternative_suppression() {
    for (format, half_ulp) in [
        (Format::Half, 0x1000),
        (Format::Single, 0x3380_0000),
        (Format::Double, 0x3ca0_0000_0000_0000),
    ] {
        let one = integer(format, 1);
        let signaling_n = format.infinity(false) | 1;
        for ah in [0, FPCR_AH] {
            for round in ROUNDINGS {
                assert_eq!(
                    add_pair(
                        format,
                        Rotation::Degrees90,
                        ah | round << FPCR_ROUNDING_SHIFT,
                        [signaling_n, one],
                        [half_ulp, one]
                    ),
                    outcome(
                        [
                            signaling_n | format.quiet_bit(),
                            one + u64::from(round == ROUND_POSITIVE)
                        ],
                        INVALID | INEXACT
                    )
                );
            }
        }
    }
}

#[test]
fn fused_residual_is_not_rounded_as_a_separate_product() {
    for (format, left_bits, right_bits, residual) in [
        (Format::Half, 0x3c01, 0x3bfe, 0x8010),
        (Format::Single, 0x3f80_0001, 0x3f7f_fffe, 0xa880_0000),
        (
            Format::Double,
            0x3ff0_0000_0000_0001,
            0x3fef_ffff_ffff_fffe,
            0xb970_0000_0000_0000,
        ),
    ] {
        for ah in [0, FPCR_AH] {
            for round in ROUNDINGS {
                assert_eq!(
                    multiply_add_pair(
                        format,
                        Rotation::Degrees0,
                        ah | round << FPCR_ROUNDING_SHIFT,
                        [integer(format, -1), 0],
                        [left_bits, format.infinity(false) | 1],
                        [right_bits, 0]
                    ),
                    outcome([residual, 0], 0)
                );
            }
        }
    }
}

#[test]
fn rotated_signed_zero_products_retain_component_rounding_boundaries() {
    for format in FORMATS {
        let negative = format.sign_mask();
        for ah in [0, FPCR_AH] {
            for round in ROUNDINGS {
                let cancellation = if round == ROUND_NEGATIVE { negative } else { 0 };
                let fpcr = ah | round << FPCR_ROUNDING_SHIFT;
                assert_eq!(
                    add_pair(
                        format,
                        Rotation::Degrees90,
                        fpcr,
                        [0; COMPONENTS],
                        [negative, 0]
                    ),
                    outcome([cancellation; COMPONENTS], 0)
                );
                assert_eq!(
                    add_pair(
                        format,
                        Rotation::Degrees270,
                        fpcr,
                        [0; COMPONENTS],
                        [negative, 0]
                    ),
                    outcome([0; COMPONENTS], 0)
                );
                for (rotation, expected) in [
                    (Rotation::Degrees0, [negative, cancellation]),
                    (Rotation::Degrees90, [negative, negative]),
                    (Rotation::Degrees180, [cancellation, negative]),
                    (Rotation::Degrees270, [cancellation, cancellation]),
                ] {
                    assert_eq!(
                        multiply_add_pair(
                            format,
                            rotation,
                            fpcr,
                            [negative; COMPONENTS],
                            [0; COMPONENTS],
                            [negative, 0]
                        ),
                        outcome(expected, 0)
                    );
                }
            }
        }
    }
}

#[test]
fn active_denormal_controls_and_status_are_forwarded_unchanged() {
    for format in [Format::Single, Format::Double] {
        let one = integer(format, 1);
        for (fpcr, result, exceptions) in [
            (0, 1, 0),
            (FPCR_FIZ, 0, 0),
            (FPCR_FZ, 0, INPUT_DENORMAL),
            (FPCR_AH, 1, INPUT_DENORMAL),
            (FPCR_AH | FPCR_FIZ, 0, 0),
            (FPCR_AH | FPCR_FZ, 0, UNDERFLOW | INEXACT | INPUT_DENORMAL),
        ] {
            assert_eq!(
                add_pair(format, Rotation::Degrees90, fpcr, [1, one], [0; COMPONENTS]),
                outcome([result, one], exceptions)
            );
        }
    }
    for ah in [0, FPCR_AH] {
        let one = integer(Format::Half, 1);
        assert_eq!(
            add_pair(
                Format::Half,
                Rotation::Degrees90,
                ah | FPCR_FZ16,
                [1, one],
                [0; COMPONENTS]
            ),
            outcome([0, one], 0)
        );
    }
}

#[test]
fn pair_arithmetic_ignores_ahp_nep_and_narrow_lane_poison() {
    for format in FORMATS {
        let left = [integer(format, 2), integer(format, 3)];
        let right = [integer(format, 5), integer(format, 7)];
        let addend = [integer(format, 11), integer(format, 13)];
        let poison = !(format.sign_mask() | (format.sign_mask() - 1));
        for ah in [0, FPCR_AH] {
            let control = ah | FPCR_AHP | FPCR_NEP;
            assert_eq!(
                add_pair(
                    format,
                    Rotation::Degrees90,
                    control,
                    left.map(|bits| bits | poison),
                    right.map(|bits| bits | poison)
                ),
                outcome([integer(format, -5), integer(format, 8)], 0)
            );
            for rotation in ROTATIONS {
                assert_eq!(
                    multiply_add_pair(
                        format,
                        rotation,
                        control,
                        addend.map(|bits| bits | poison),
                        left.map(|bits| bits | poison),
                        right.map(|bits| bits | poison)
                    ),
                    multiply_add_pair(format, rotation, ah, addend, left, right)
                );
            }
        }
    }
}

#[test]
fn all_retained_enables_refuse_under_both_alternative_modes() {
    for format in FORMATS {
        for ah in [0, FPCR_AH] {
            for enabled in [
                INVALID,
                DIVIDE_BY_ZERO,
                OVERFLOW,
                UNDERFLOW,
                INEXACT,
                INPUT_DENORMAL,
                EXCEPTIONS,
            ] {
                let fpcr = ah | enabled << FPCR_EXCEPTION_ENABLE_SHIFT;
                let expected = Err(UnsupportedControl {
                    enabled_exceptions: enabled,
                });
                for rotation in [Rotation::Degrees90, Rotation::Degrees270] {
                    assert_eq!(
                        add_pair(format, rotation, fpcr, [0; COMPONENTS], [0; COMPONENTS]),
                        expected
                    );
                }
                for rotation in ROTATIONS {
                    assert_eq!(
                        multiply_add_pair(
                            format,
                            rotation,
                            fpcr,
                            [0; COMPONENTS],
                            [0; COMPONENTS],
                            [0; COMPONENTS]
                        ),
                        expected
                    );
                }
            }
        }
    }
}

#[test]
#[should_panic(expected = "FCADD requires 90 or 270 degrees")]
fn add_rejects_unallocated_zero_rotation() {
    let _ = add_pair(
        Format::Single,
        Rotation::Degrees0,
        0,
        [0; COMPONENTS],
        [0; COMPONENTS],
    );
}

#[test]
#[should_panic(expected = "FCADD requires 90 or 270 degrees")]
fn add_rejects_unallocated_half_turn_rotation() {
    let _ = add_pair(
        Format::Single,
        Rotation::Degrees180,
        0,
        [0; COMPONENTS],
        [0; COMPONENTS],
    );
}
